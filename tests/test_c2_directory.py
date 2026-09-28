"""C2: sign-in through the customer's directory, and one identity model across tenants.

Gate lines this pins with code evidence: role removal takes effect; duplicate username
across tenants has defined behaviour. "Pilot users sign in through the customer's
directory" needs the customer's directory - these tests run the real sign-in code against
ldap3's in-memory MOCK_SYNC server (and real sockets for outage and certificate
failure), which is code evidence, not that live gate.
"""

from __future__ import annotations

import json
import socket
import ssl
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient
from ldap3 import MOCK_SYNC, NONE, Connection, Server

from backend import directory, identity, security, store
from backend.app import app

BASE = "dc=corp,dc=example"
ADMINS = f"cn=sentro-admins,ou=groups,{BASE}"
ANALYSTS = f"cn=sentro-analysts,ou=groups,{BASE}"
OTHERS = f"cn=marketing,ou=groups,{BASE}"
SERVICE_DN = f"cn=svc-sentro,ou=service,{BASE}"
SERVICE_PASSWORD = "Svc-directory-pass-7"
MAPPINGS = [{"group_dn": ADMINS, "role": "admin"}, {"group_dn": ANALYSTS, "role": "analyst"}]


def _mock_server(people: dict) -> Server:
    """A directory: a service account, and people {login: (password, groups, uac, guid)}."""
    server = Server("mock-ad.corp.example", get_info=NONE)
    seed = Connection(server, user=SERVICE_DN, password=SERVICE_PASSWORD, client_strategy=MOCK_SYNC)
    seed.strategy.add_entry(SERVICE_DN, {"userPassword": SERVICE_PASSWORD, "objectClass": ["person", "user"],
                                         "sAMAccountName": "svc-sentro"})
    for login, (password, groups, uac, guid) in people.items():
        seed.strategy.add_entry(f"cn={login},ou=users,{BASE}", {
            "userPassword": password, "objectClass": ["person", "user"], "sAMAccountName": login,
            "objectGUID": guid, "memberOf": list(groups), "userAccountControl": str(uac),
            "displayName": login.title()})
    return server


def _use(server: Server):
    """Point backend.directory at `server`, keeping its real sign-in logic."""
    return mock.patch.multiple(
        directory,
        _server=lambda config: server,
        _connection=lambda srv, user, password, config: Connection(
            srv, user=user, password=password, client_strategy=MOCK_SYNC, raise_exceptions=False),
    )


class _Case(unittest.TestCase):
    PEOPLE = {
        "alice": ("Alice-pass-1", [ADMINS], 512, "guid-alice"),
        "bob": ("Bob-pass-12", [ANALYSTS], 512, "guid-bob"),
        "carol": ("Carol-pass-3", [ANALYSTS], 514, "guid-carol"),  # disabled in AD
        "dave": ("Dave-pass-45", [OTHERS], 512, "guid-dave"),       # in no mapped group
    }

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "directory.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        for tenant in ("t-dir", "t-other"):
            store.create_tenant(tenant, tenant)
        store.create_user("local-boss", security.hash_password("Local-boss-pass-9"), "admin", "t-dir")
        self.server = _mock_server(dict(self.PEOPLE))
        patcher = _use(self.server)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = TestClient(app)
        self.admin = {"Authorization": f"Bearer {security.create_token('local-boss', 'admin', 't-dir')}"}
        for key in ("bob", "alice", "dave", "carol"):
            store.clear_login_failures(f"login:{key}")

    def _configure(self, tenant_admin: dict | None = None, **overrides) -> dict:
        body = {"enabled": True, "host": "mock-ad.corp.example", "security": "ldaps", "trust": "system",
                "base_dn": BASE, "bind_dn": SERVICE_DN, "bind_password": SERVICE_PASSWORD,
                "user_attribute": "sAMAccountName", "mappings": MAPPINGS, **overrides}
        response = self.client.put("/api/settings/directory", json=body, headers=tenant_admin or self.admin)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def _login(self, username: str, password: str, workspace: str = "t-dir"):
        return self.client.post("/api/auth/login", json={"username": username, "password": password,
                                                          "workspace": workspace})

    def _audit(self, action: str, tenant: str = "t-dir") -> list[dict]:
        return [row for row in store.read_audit_log(tenant, 300) if row["action"] == action]


class ADirectoryUserSignsInTest(_Case):

    def test_a_directory_user_signs_in_with_the_role_their_group_maps_to(self) -> None:
        self._configure()
        response = self._login("bob", "Bob-pass-12")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual((body["role"], body["tenant_id"]), ("analyst", "t-dir"))
        account = store.find_user_by_login("t-dir", "bob")
        self.assertEqual((account["auth_source"], account["external_id"]), ("ldap", "guid-bob"))
        self.assertEqual(account["password_hash"], identity.DIRECTORY_PASSWORD_HASH)
        created = self._audit("auth.directory_account_created")
        self.assertEqual(created[-1]["detail"]["group"], ANALYSTS)

    def test_the_admin_group_maps_to_an_administrator_who_then_needs_mfa(self) -> None:
        self._configure()
        response = self._login("alice", "Alice-pass-1")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["mfa_enrollment_required"])
        self.assertEqual(store.find_user_by_login("t-dir", "alice")["role"], "admin")

    def test_a_wrong_password_is_refused_and_recorded_with_its_reason(self) -> None:
        self._configure()
        self.assertEqual(self._login("bob", "not-bobs-password").status_code, 401)
        failed = self._audit("auth.login_failed")[-1]["detail"]
        self.assertEqual((failed["source"], failed["reason"]), ("ldap", "invalid_credentials"))
        self.assertIsNone(store.find_user_by_login("t-dir", "bob"), "no account for a failed first sign-in")

    def test_an_empty_password_never_reaches_the_directory(self) -> None:
        self._configure()
        with mock.patch.object(directory, "_bind", side_effect=AssertionError("the directory was asked")):
            outcome = directory.authenticate(store.get_directory_settings("t-dir")["config"], SERVICE_PASSWORD, "bob", "")
        self.assertEqual(outcome.status, "invalid_credentials")

    def test_the_bind_itself_refuses_an_empty_password(self) -> None:
        # The second guard: every bind - the service account's in lookup and test too - and
        # not only a person's sign-in. An empty password is an anonymous bind, which many
        # directories accept as a success.
        config = directory.validate({"host": "dc.example.test", "base_dn": BASE, "bind_dn": SERVICE_DN,
                                     "mappings": MAPPINGS}, None, lambda role: True)
        with mock.patch.object(directory, "_connection", side_effect=AssertionError("a connection was made")):
            with self.assertRaises(directory._Failure) as refused:
                directory._bind(config, SERVICE_DN, "")
        self.assertEqual(refused.exception.status, "invalid_credentials")

    def test_a_disabled_directory_account_is_refused(self) -> None:
        self._configure()
        self.assertEqual(self._login("carol", "Carol-pass-3").status_code, 401)
        self.assertEqual(self._audit("auth.login_failed")[-1]["detail"]["reason"], "disabled")

    def test_an_account_in_no_mapped_group_is_refused(self) -> None:
        self._configure()
        self.assertEqual(self._login("dave", "Dave-pass-45").status_code, 401)
        self.assertEqual(self._audit("auth.login_failed")[-1]["detail"]["reason"], "no_mapped_group")

    def test_a_directory_accounts_password_is_not_reset_locally(self) -> None:
        self._configure()
        self.assertEqual(self._login("bob", "Bob-pass-12").status_code, 200)
        key = store.find_user_by_login("t-dir", "bob")["username"]
        refused = self.client.post(f"/api/users/{key}/reset-password", json={"password": "A-local-pass-4471"},
                                   headers=self.admin)
        self.assertEqual(refused.status_code, 400)
        self.assertEqual(store.get_user(key)["password_hash"], identity.DIRECTORY_PASSWORD_HASH)

    def test_mappings_are_ordered_and_the_first_held_group_decides(self) -> None:
        config = {"mappings": MAPPINGS}
        self.assertEqual(directory.map_role(config, [ANALYSTS.upper(), ADMINS]), ("admin", ADMINS))
        self.assertEqual(directory.map_role(config, [OTHERS]), ("", ""))


class GroupChangesTakeEffectTest(_Case):

    def _age(self, login: str) -> dict:
        account = store.find_user_by_login("t-dir", login)
        store.update_directory_account(account["username"], role=account["role"], login_name=login,
                                       full_name=account["full_name"], synced_at=1, active=True)
        return account

    def test_a_removed_group_ends_the_sessions_at_the_next_refresh(self) -> None:
        self._configure()
        self.assertEqual(self._login("bob", "Bob-pass-12").status_code, 200)
        account = self._age("bob")
        # bob leaves the analysts group in the directory
        editor = Connection(self.server, user=SERVICE_DN, password=SERVICE_PASSWORD, client_strategy=MOCK_SYNC)
        editor.bind()
        editor.modify(f"cn=bob,ou=users,{BASE}", {"memberOf": [("MODIFY_REPLACE", [OTHERS])]})
        refreshed = self.client.post("/api/auth/refresh")
        self.assertEqual(refreshed.status_code, 401)
        self.assertFalse(store.get_user(account["username"])["is_active"])
        self.assertEqual(self._audit("auth.directory_account_disabled")[-1]["detail"]["reason"], "no_mapped_group")
        self.assertEqual(self._login("bob", "Bob-pass-12").status_code, 401)

    def test_a_changed_group_changes_the_role_at_refresh(self) -> None:
        self._configure()
        self.assertEqual(self._login("bob", "Bob-pass-12").status_code, 200)
        account = self._age("bob")
        editor = Connection(self.server, user=SERVICE_DN, password=SERVICE_PASSWORD, client_strategy=MOCK_SYNC)
        editor.bind()
        editor.modify(f"cn=bob,ou=users,{BASE}", {"memberOf": [("MODIFY_REPLACE", [ADMINS])]})
        # promoted to admin by the directory: the unverified session is not renewed as an admin
        self.assertEqual(self.client.post("/api/auth/refresh").status_code, 401)
        self.assertEqual(store.get_user(account["username"])["role"], "admin")
        changed = self._audit("auth.directory_role_changed")[-1]["detail"]
        self.assertEqual({key: changed[key] for key in ("from", "to", "group")},
                         {"from": "analyst", "to": "admin", "group": ADMINS})

    def test_groups_younger_than_the_window_are_not_re_read(self) -> None:
        self._configure()
        self.assertEqual(self._login("bob", "Bob-pass-12").status_code, 200)
        with mock.patch.object(directory, "lookup", side_effect=AssertionError("re-read too early")):
            self.assertEqual(self.client.post("/api/auth/refresh").status_code, 200)

    def test_turning_directory_sign_in_off_stops_directory_accounts(self) -> None:
        self._configure()
        self.assertEqual(self._login("bob", "Bob-pass-12").status_code, 200)
        self._configure(enabled=False)
        response = self._login("bob", "Bob-pass-12")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self._audit("auth.login_failed")[-1]["detail"]["reason"], "directory_disabled")


class OneNameInTwoWorkspacesTest(_Case):

    def test_the_same_directory_name_in_two_workspaces_is_two_accounts(self) -> None:
        self._configure()
        other_admin_name = "other-boss"
        store.create_user(other_admin_name, security.hash_password("Other-boss-pass-9"), "admin", "t-other")
        other_admin = {"Authorization": f"Bearer {security.create_token(other_admin_name, 'admin', 't-other')}"}
        self._configure(tenant_admin=other_admin)
        first = self._login("bob", "Bob-pass-12", "t-dir")
        second = self._login("bob", "Bob-pass-12", "t-other")
        self.assertEqual((first.status_code, second.status_code), (200, 200))
        a, b = store.find_user_by_login("t-dir", "bob"), store.find_user_by_login("t-other", "bob")
        self.assertNotEqual(a["username"], b["username"])
        self.assertEqual({a["username"], b["username"]}, {"bob", "bob@t-other"})
        self.assertEqual((a["tenant_id"], b["tenant_id"]), ("t-dir", "t-other"))
        # each session is its own workspace's
        token_b = second.json()["access_token"]
        profile = self.client.get("/api/profile", headers={"Authorization": f"Bearer {token_b}"}).json()["user"]
        self.assertEqual((profile["tenant_id"], profile["login_name"]), ("t-other", "bob"))

    def test_registration_in_a_second_workspace_neither_fails_nor_reveals_the_first(self) -> None:
        store.create_user("erin", security.hash_password("Erin-pass-123"), "viewer", "t-dir")
        code = store.get_tenant("t-other")["registration_code"] if hasattr(store, "get_tenant") else None
        if code is None:
            code = next(t for t in store.list_tenants() if t["tenant_id"] == "t-other")["registration_code"]
        registered = self.client.post("/api/auth/register", json={
            "username": "erin", "password": "Sparrow-pass-771", "tenant_id": "t-other", "registration_code": code})
        self.assertEqual(registered.status_code, 200, registered.text)
        user = registered.json()["user"]
        self.assertEqual((user["login_name"], user["tenant_id"], user["username"]), ("erin", "t-other", "erin@t-other"))
        # with a workspace, each signs in to its own; without one, the name is the account key
        own = self.client.post("/api/auth/login", json={"username": "erin", "password": "Sparrow-pass-771",
                                                         "workspace": "t-other"})
        self.assertEqual((own.status_code, own.json()["tenant_id"]), (200, "t-other"))
        legacy = self.client.post("/api/auth/login", json={"username": "erin", "password": "Erin-pass-123"})
        self.assertEqual((legacy.status_code, legacy.json()["tenant_id"]), (200, "t-dir"))
        crossed = self.client.post("/api/auth/login", json={"username": "erin", "password": "Erin-pass-123",
                                                             "workspace": "t-other"})
        self.assertEqual(crossed.status_code, 401, "one workspace's password opens only its own account")

    def test_a_name_taken_in_the_same_workspace_is_refused(self) -> None:
        response = self.client.post("/api/users", headers=self.admin, json={
            "username": "local-boss", "password": "Another-pass-1", "role": "viewer", "tenant_id": "t-dir"})
        self.assertEqual(response.status_code, 409)

    def test_a_local_account_takes_precedence_over_the_directory(self) -> None:
        # The installation stays recoverable: a local account is never shadowed by a
        # directory entry of the same name, and its password is the local one.
        self._configure()
        store.create_user("bob-local", security.hash_password("Bob-local-pass-1"), "viewer", "t-dir", login_name="bob")
        response = self._login("bob", "Bob-pass-12")
        self.assertEqual(response.status_code, 401, "the directory password does not open the local account")
        self.assertEqual(self._login("bob", "Bob-local-pass-1").status_code, 200)


class WhenTheDirectoryFailsTest(_Case):

    def test_an_unreachable_directory_refuses_and_says_so(self) -> None:
        self._configure()
        with mock.patch.object(directory, "_connection",
                               side_effect=OSError("connection refused")):
            response = self._login("bob", "Bob-pass-12")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self._audit("auth.login_failed")[-1]["detail"]["reason"], "unavailable")

    def test_an_outage_does_not_lock_out_the_local_administrator(self) -> None:
        self._configure()
        with mock.patch.object(directory, "_connection", side_effect=OSError("connection refused")):
            response = self._login("local-boss", "Local-boss-pass-9")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["mfa_enrollment_required"])

    def test_a_refresh_during_an_outage_is_refused_not_trusted(self) -> None:
        self._configure()
        self.assertEqual(self._login("bob", "Bob-pass-12").status_code, 200)
        account = store.find_user_by_login("t-dir", "bob")
        store.update_directory_account(account["username"], role="analyst", login_name="bob", full_name="Bob",
                                       synced_at=1, active=True)
        with mock.patch.object(directory, "_connection", side_effect=OSError("connection refused")):
            self.assertEqual(self.client.post("/api/auth/refresh").status_code, 401)
        self.assertTrue(store.get_user(account["username"])["is_active"], "an outage is not a removal")


class TheDirectorysCertificateIsCheckedTest(unittest.TestCase):
    """A real TLS listener whose certificate no trusted CA signed: the sign-in fails."""

    @classmethod
    def setUpClass(cls) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                .sign(key, hashes.SHA256()))
        cls.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cert_path, key_path = Path(cls.temp.name) / "cert.pem", Path(cls.temp.name) / "key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        cls.cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        cls.listener = socket.socket()
        cls.listener.bind(("127.0.0.1", 0))
        cls.listener.listen(8)
        cls.port = cls.listener.getsockname()[1]
        cls.stop = threading.Event()

        def serve() -> None:
            cls.listener.settimeout(0.2)
            while not cls.stop.is_set():
                try:
                    conn, _ = cls.listener.accept()
                except OSError:
                    continue
                try:
                    with context.wrap_socket(conn, server_side=True) as tls:
                        tls.recv(1024)  # a verified client would send a bind here
                except (ssl.SSLError, OSError):
                    pass

        cls.thread = threading.Thread(target=serve, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stop.set()
        cls.listener.close()
        cls.temp.cleanup()

    def _config(self, **overrides) -> dict:
        return {"host": "localhost", "port": self.port, "security": "ldaps", "trust": "system", "base_dn": BASE,
                "bind_dn": SERVICE_DN, "user_attribute": "sAMAccountName", "group_search": "memberof",
                "timeout_seconds": 3, "mappings": MAPPINGS, **overrides}

    def test_an_untrusted_certificate_fails_the_sign_in(self) -> None:
        started = time.monotonic()
        outcome = directory.authenticate(self._config(), SERVICE_PASSWORD, "bob", "Bob-pass-12")
        self.assertEqual(outcome.status, "tls_failure")
        self.assertLess(time.monotonic() - started, 10)

    def test_trusting_the_right_ca_gets_past_the_certificate(self) -> None:
        # With the listener's own certificate as the CA, TLS verifies; what fails next is
        # the LDAP exchange this bare listener cannot speak - not the certificate.
        outcome = directory.authenticate(self._config(trust="custom", ca_pem=self.cert_pem), SERVICE_PASSWORD,
                                         "bob", "Bob-pass-12")
        self.assertNotEqual(outcome.status, "tls_failure")

    def test_nothing_listening_is_unavailable(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            free_port = probe.getsockname()[1]
        outcome = directory.authenticate(self._config(port=free_port), SERVICE_PASSWORD, "bob", "Bob-pass-12")
        self.assertEqual(outcome.status, "unavailable")


class TheSettingsTest(_Case):

    def test_the_service_password_is_never_returned_and_follows_the_secret_rules(self) -> None:
        saved = self._configure()
        self.assertTrue(saved["bind_password_configured"])
        self.assertNotIn(SERVICE_PASSWORD, json.dumps(saved))
        read = self.client.get("/api/settings/directory", headers=self.admin)
        self.assertNotIn(SERVICE_PASSWORD, read.text)
        ref = store.get_directory_settings("t-dir")["bind_secret_ref"]
        # omitted: kept
        self.client.put("/api/settings/directory", headers=self.admin, json={"host": "dc2.corp.example"})
        self.assertEqual(store.get_directory_settings("t-dir")["bind_secret_ref"], ref)
        # a new value: replaced, and the old vault entry is gone
        self.client.put("/api/settings/directory", headers=self.admin, json={"bind_password": "New-svc-pass-8"})
        new_ref = store.get_directory_settings("t-dir")["bind_secret_ref"]
        self.assertNotEqual(new_ref, ref)
        self.assertIsNone(store.read_secret("t-dir", ref))
        # removed: deleted, and directory sign-in cannot stay on without it
        refused = self.client.put("/api/settings/directory", headers=self.admin, json={"remove_bind_password": True})
        self.assertEqual(refused.status_code, 400)
        off = self.client.put("/api/settings/directory", headers=self.admin,
                              json={"remove_bind_password": True, "enabled": False})
        self.assertEqual(off.status_code, 200)
        self.assertFalse(off.json()["bind_password_configured"])
        self.assertIsNone(store.read_secret("t-dir", new_ref))
        audit = json.dumps(store.read_audit_log("t-dir", 300))
        for secret in (SERVICE_PASSWORD, "New-svc-pass-8"):
            self.assertNotIn(secret, audit)
        changes = [row["detail"]["bind_password"] for row in self._audit("directory.settings_changed")]
        self.assertEqual(changes, ["set", "kept", "replaced", "removed"])

    def test_plain_ldap_and_unknown_roles_are_refused(self) -> None:
        for body, expected in (({"security": "ldap"}, "LDAPS or StartTLS"),
                               ({"mappings": [{"group_dn": ADMINS, "role": "overlord"}]}, "Unknown role"),
                               ({"mappings": []}, "Map at least one"),
                               ({"base_dn": "not a dn"}, "distinguished name")):
            with self.subTest(body=body):
                full = {"enabled": False, "host": "dc.corp.example", "security": "ldaps", "base_dn": BASE,
                        "bind_dn": SERVICE_DN, "mappings": MAPPINGS, **body}
                response = self.client.put("/api/settings/directory", headers=self.admin, json=full)
                self.assertEqual(response.status_code, 400)
                self.assertIn(expected, response.json()["detail"])

    def test_the_test_button_reports_the_role_a_person_would_get(self) -> None:
        self._configure()
        report = self.client.post("/api/settings/directory/test", headers=self.admin, json={"login": "bob"}).json()
        self.assertEqual((report["ok"], report["role"], report["matched_group"]), (True, "analyst", ANALYSTS))
        self.assertIsNone(store.find_user_by_login("t-dir", "bob"), "a test provisions nobody")
        tested = self._audit("directory.tested")[-1]["detail"]
        self.assertEqual({key: tested[key] for key in ("ok", "status", "with_user")},
                         {"ok": True, "status": "ok", "with_user": True})

    def test_only_a_verified_administrator_manages_it(self) -> None:
        viewer_name = "vic"
        store.create_user(viewer_name, security.hash_password("Vic-view-pass-1"), "viewer", "t-dir")
        viewer = {"Authorization": f"Bearer {security.create_token(viewer_name, 'viewer', 't-dir')}"}
        self.assertEqual(self.client.get("/api/settings/directory", headers=viewer).status_code, 403)
        unverified = {"Authorization": "Bearer " + security.create_token("local-boss", "admin", "t-dir",
                                                                         mfa_verified=False)}
        refused = self.client.put("/api/settings/directory", headers=unverified, json={"enabled": False})
        self.assertEqual(refused.status_code, 403)

    def test_removing_the_configuration_deletes_its_secret(self) -> None:
        self._configure()
        ref = store.get_directory_settings("t-dir")["bind_secret_ref"]
        removed = self.client.delete("/api/settings/directory", headers=self.admin)
        self.assertEqual(removed.status_code, 200)
        self.assertIsNone(store.get_directory_settings("t-dir"))
        self.assertIsNone(store.read_secret("t-dir", ref))
        self.assertTrue(self._audit("directory.removed"))


if __name__ == "__main__":
    unittest.main()
