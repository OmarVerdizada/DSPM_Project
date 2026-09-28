"""C12: the vault's keys are versioned, rotated without losing a value, and recoverable.

Gate line: "every saved credential decrypts after rotation and recovery drill; preflight
flags excessive privilege; no key or secret appears in logs." The drill the product owner
asked for runs here end to end: a fresh install saves credentials, the key is rotated,
everything still opens; a rotation fails half-way and nothing is lost; it resumes; it is
rolled back; the key ring is lost and recovered from its escrow; everything opens again.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from backend import credential_preflight, security, store, vault, vault_keys
from backend.app import app

PASSPHRASE = "correct horse battery staple 42"


class _Case(unittest.TestCase):
    """A fresh install: its own database, its own single vault key, a key ring path."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        original = store.DB_PATH
        store.DB_PATH = self.tmp / "vault.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        for tenant in ("t-one", "t-two"):
            store.create_tenant(tenant, tenant)
        self.first_key = Fernet.generate_key().decode()
        self.ring_file = self.tmp / "secrets" / "vault_keyring.json"
        patcher = mock.patch.dict(os.environ, {"DSPM_VAULT_KEY": self.first_key,
                                               "DSPM_VAULT_KEYRING": str(self.ring_file)})
        patcher.start()
        self.addCleanup(patcher.stop)
        vault_keys._CACHE.update({"stamp": None, "ring": None})
        self.vault = vault.CredentialVault()
        self.saved = {
            ("t-one", self.vault.store("t-one", "svc-scan", "Scan-pass-771", "CORP")): "Scan-pass-771",
            ("t-one", self.vault.store("t-one", "svc-files", "Files-pass-772", "CORP")): "Files-pass-772",
            ("t-two", self.vault.store("t-two", "svc-other", "Other-pass-773", "OTHER")): "Other-pass-773",
        }
        self.mfa_seed = "JBSWY3DPEHPK3PXP"
        self.mfa_sealed = vault.encrypt_text(self.mfa_seed)

    def assert_everything_opens(self) -> None:
        for (tenant, ref), password in self.saved.items():
            self.assertEqual(self.vault.resolve(tenant, ref)["password"], password)
        self.assertEqual(vault.decrypt_text(self.mfa_sealed_now()), self.mfa_seed)

    def mfa_sealed_now(self) -> str:
        # the seed the rotation re-sealed, as the table holds it
        return self._mfa_row or self.mfa_sealed

    _mfa_row: str | None = None

    def kids_in_use(self) -> set[str]:
        return {vault_keys.split(value)[0] for value in store.vault_sealed_values()}


class TheRotationDrillTest(_Case):

    def setUp(self) -> None:
        super().setUp()
        # an MFA seed in the table too, so rotation must re-seal both kinds of value
        store.create_user("drill-user", security.hash_password("Drill-user-pass-9"), "analyst", "t-one")
        store.begin_mfa_enrollment("t-one", "drill-user", self.mfa_sealed, 2_000_000_000)

    def mfa_sealed_now(self) -> str:
        return store.get_user_mfa("drill-user")["pending_ciphertext"]

    def test_the_drill(self) -> None:
        first_kid = vault_keys.key_id(self.first_key)
        self.assertEqual(self.kids_in_use(), {first_kid}, "sealed values name their key")

        # 1. rotate: a new key is active, every value is re-sealed with it, all open
        report = vault.rotate(actor="drill")
        second_kid = report["to"]
        self.assertNotEqual(second_kid, first_kid)
        self.assertEqual(report["resealed"], 4)
        self.assertEqual(self.kids_in_use(), {second_kid})
        self.assert_everything_opens()
        self.assertEqual(vault.status()["rotation"]["state"], "idle")

        # 2. a rotation that dies half-way: the transaction leaves every value as it was,
        #    the ring holds both keys, and everything still opens
        real = store.reseal_vault_values
        calls = {"n": 0}

        def dies_half_way(transform):
            def failing(value):
                calls["n"] += 1
                if calls["n"] == 3:
                    raise RuntimeError("power cut")
                return transform(value)
            return real(failing)

        with mock.patch.object(store, "reseal_vault_values", side_effect=dies_half_way):
            with self.assertRaises(RuntimeError):
                vault.rotate(actor="drill")
        state = vault.status()
        self.assertEqual(state["rotation"]["state"], "rekeying")
        third_kid = state["active"]
        self.assertEqual(self.kids_in_use(), {second_kid}, "nothing committed from the failed pass")
        self.assert_everything_opens()

        # 3. resume finishes it
        resumed = vault.rotate(resume=True, actor="drill")
        self.assertEqual((resumed["from"], resumed["to"]), (second_kid, third_kid))
        self.assertEqual(self.kids_in_use(), {third_kid})
        self.assert_everything_opens()

        # 4. roll back: the previous key is active again, everything re-sealed with it
        rolled = vault.rollback(actor="drill")
        self.assertEqual(rolled["to"], second_kid)
        self.assertEqual(self.kids_in_use(), {second_kid})
        self.assert_everything_opens()

        # 5. escrow, lose the ring, recover it, everything opens
        escrow = self.tmp / "escrow.json"
        vault.export_escrow(escrow, PASSPHRASE, actor="drill")
        self.ring_file.unlink()
        vault_keys._CACHE.update({"stamp": None, "ring": None})
        with mock.patch.dict(os.environ, {"DSPM_VAULT_KEY": Fernet.generate_key().decode()}):
            with self.assertRaises(vault_keys.VaultKeyError) as lost:
                self.vault.resolve(*next(iter(self.saved)))
            self.assertIn("escrow recover", str(lost.exception))
            vault.recover_escrow(escrow, PASSPHRASE, self.ring_file, actor="drill")
            self.assert_everything_opens()

        actions = [row["action"] for row in store.read_audit_log("default", 100)]
        for action in ("vault.key_rotated", "vault.key_rotation_resumed", "vault.key_rolled_back",
                       "vault.escrow_exported", "vault.escrow_recovered"):
            self.assertIn(action, actions)


class TheRingTest(_Case):

    def test_a_value_sealed_before_key_ids_still_opens(self) -> None:
        legacy = Fernet(self.first_key.encode()).encrypt(b'{"username":"u","password":"legacy-pw","domain":"D"}').decode()
        store.save_secret("t-one", "legacy-ref", legacy)
        self.assertEqual(self.vault.resolve("t-one", "legacy-ref")["password"], "legacy-pw")
        vault.rotate(actor="test")
        self.assertEqual(self.vault.resolve("t-one", "legacy-ref")["password"], "legacy-pw")
        self.assertTrue(store.read_secret("t-one", "legacy-ref").startswith(vault_keys.PREFIX), "and it gains a key id")

    def test_the_ring_file_is_written_atomically_and_holds_the_keys_the_values_name(self) -> None:
        vault.rotate(actor="test")
        document = json.loads(self.ring_file.read_text(encoding="utf-8"))
        self.assertEqual(document["format"], vault_keys.RING_FORMAT)
        self.assertEqual({item["kid"] for item in document["keys"]} >= self.kids_in_use(), True)
        self.assertEqual([p.name for p in self.ring_file.parent.iterdir() if p.suffix == ".tmp"], [])

    def test_rollback_needs_a_previous_key(self) -> None:
        with self.assertRaises(vault_keys.VaultKeyError):
            vault.rollback(actor="test")


class TheEscrowTest(_Case):

    def test_the_escrow_holds_no_key_in_the_clear(self) -> None:
        vault.rotate(actor="test")
        escrow = self.tmp / "escrow.json"
        vault.export_escrow(escrow, PASSPHRASE, actor="test")
        text = escrow.read_text(encoding="utf-8")
        for item in json.loads(self.ring_file.read_text(encoding="utf-8"))["keys"]:
            self.assertNotIn(item["key"], text)
        self.assertEqual(vault.verify_escrow(escrow, PASSPHRASE)["ok"], True)

    def test_a_wrong_passphrase_or_an_altered_file_is_refused(self) -> None:
        escrow = self.tmp / "escrow.json"
        vault.export_escrow(escrow, PASSPHRASE, actor="test")
        with self.assertRaises(vault_keys.VaultKeyError):
            vault.verify_escrow(escrow, "not the passphrase at all")
        document = json.loads(escrow.read_text(encoding="utf-8"))
        document["ring"] = document["ring"][:-8] + "AAAAAAAA"
        escrow.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(vault_keys.VaultKeyError):
            vault.verify_escrow(escrow, PASSPHRASE)

    def test_a_short_passphrase_is_refused(self) -> None:
        with self.assertRaises(vault_keys.VaultKeyError):
            vault.export_escrow(self.tmp / "escrow.json", "short", actor="test")

    def test_an_escrow_that_misses_a_key_in_use_says_so(self) -> None:
        escrow = self.tmp / "escrow.json"
        vault.export_escrow(escrow, PASSPHRASE, actor="test")   # holds only the first key
        vault.rotate(actor="test")                               # values now under a newer one
        report = vault.verify_escrow(escrow, PASSPHRASE)
        self.assertFalse(report["ok"])
        self.assertTrue(report["missing"])

    def test_recovery_will_not_overwrite_a_ring_without_being_told(self) -> None:
        escrow = self.tmp / "escrow.json"
        vault.rotate(actor="test")
        vault.export_escrow(escrow, PASSPHRASE, actor="test")
        with self.assertRaises(vault_keys.VaultKeyError):
            vault.recover_escrow(escrow, PASSPHRASE, self.ring_file, actor="test")


class NoKeyInTheLogsTest(_Case):

    def test_rotation_escrow_and_recovery_log_no_key(self) -> None:
        records: list[str] = []

        class Collect(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(self.format(record))

        handler = Collect(level=logging.DEBUG)
        root = logging.getLogger()
        previous = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.removeHandler, handler)
        self.addCleanup(root.setLevel, previous)
        vault.rotate(actor="test")
        escrow = self.tmp / "escrow.json"
        vault.export_escrow(escrow, PASSPHRASE, actor="test")
        vault.verify_escrow(escrow, PASSPHRASE)
        keys = [item["key"] for item in json.loads(self.ring_file.read_text(encoding="utf-8"))["keys"]]
        text = "\n".join(records) + json.dumps(store.read_audit_log("default", 100))
        for secret in [*keys, PASSPHRASE, *self.saved.values()]:
            self.assertNotIn(secret, text)


class TheCredentialMetadataTest(_Case):

    def test_created_last_used_rotated_and_reminder(self) -> None:
        tenant, ref = next(iter(self.saved))
        listing = {item["credential_ref"]: item for item in store.list_secret_metadata(tenant)}
        entry = listing[ref]
        self.assertEqual(entry["label"], "CORP\\svc-scan")
        self.assertIsNone(entry["last_used_at"])
        self.assertNotIn("ciphertext", entry)
        self.vault.resolve(tenant, ref)
        self.assertIsNotNone({i["credential_ref"]: i for i in store.list_secret_metadata(tenant)}[ref]["last_used_at"])
        self.vault.replace(tenant, ref, "svc-scan", "Scan-pass-774", "CORP")
        entry = {i["credential_ref"]: i for i in store.list_secret_metadata(tenant)}[ref]
        self.assertIsNotNone(entry["rotated_at"])
        self.assertEqual(self.vault.resolve(tenant, ref)["password"], "Scan-pass-774")
        # the reminder: due once the interval has passed since the last rotation
        old = (datetime.now(timezone.utc) - timedelta(days=91)).isoformat()
        with store._connect() as conn:
            conn.execute("UPDATE secrets SET created_at = ?, rotated_at = NULL WHERE tenant_id = ? AND secret_id = ?",
                         (old, tenant, ref))
        entry = {i["credential_ref"]: i for i in vault.credential_listing(tenant)}[ref]
        self.assertTrue(entry["rotation_due"])
        with mock.patch.dict(os.environ, {"DSPM_CREDENTIAL_ROTATION_DAYS": "180"}):
            self.assertFalse({i["credential_ref"]: i for i in vault.credential_listing(tenant)}[ref]["rotation_due"])

    def test_a_workspace_sees_only_its_own_credentials(self) -> None:
        refs = {item["credential_ref"] for item in store.list_secret_metadata("t-two")}
        self.assertEqual(refs, {ref for (tenant, ref) in self.saved if tenant == "t-two"})


class ThePreflightTest(unittest.TestCase):

    def test_names_that_say_administrator(self) -> None:
        for name in ("Administrator", "CORP\\administrator", "admin@corp.example", "adm-jdoe", "svc_admin"):
            with self.subTest(name=name):
                self.assertTrue(credential_preflight.by_name(name))
        self.assertEqual(credential_preflight.by_name("svc-dspm-read"), [])

    def test_directory_groups_and_admin_count_make_it_excessive(self) -> None:
        from backend import directory

        outcome = directory.Outcome("no_mapped_group", groups=("CN=Domain Admins,CN=Users,DC=corp,DC=example",))
        with mock.patch("backend.identity.directory_settings", return_value={"config": {}}), \
                mock.patch("backend.identity.bind_password", return_value="pw"), \
                mock.patch.object(directory, "lookup", return_value=outcome):
            result = credential_preflight.assess("t-one", "CORP\\svc-scan")
        self.assertEqual(result["level"], "excessive")
        self.assertIn("Domain Admins", result["findings"][0])
        flagged = directory.Outcome("no_mapped_group", groups=(), admin_count=True)
        with mock.patch("backend.identity.directory_settings", return_value={"config": {}}), \
                mock.patch("backend.identity.bind_password", return_value="pw"), \
                mock.patch.object(directory, "lookup", return_value=flagged):
            flagged_result = credential_preflight.assess("t-one", "svc-scan")
        self.assertEqual(flagged_result["level"], "excessive")
        self.assertTrue(any("adminCount=1" in finding for finding in flagged_result["findings"]),
                        "the operator is told why, not only that")
        clean = directory.Outcome("no_mapped_group", groups=("CN=File Readers,DC=corp,DC=example",))
        with mock.patch("backend.identity.directory_settings", return_value={"config": {}}), \
                mock.patch("backend.identity.bind_password", return_value="pw"), \
                mock.patch.object(directory, "lookup", return_value=clean):
            self.assertEqual(credential_preflight.assess("t-one", "svc-scan")["level"], "ok")


class TheCredentialRoutesTest(_Case):

    def setUp(self) -> None:
        super().setUp()
        self.client = TestClient(app)
        store.create_user("cm", security.hash_password("Cred-manager-pass-9"), "admin", "t-one")
        self.admin = {"Authorization": f"Bearer {security.create_token('cm', 'admin', 't-one', mfa_verified=True)}"}

    def test_the_list_shows_metadata_and_never_a_secret(self) -> None:
        listing = self.client.get("/api/credentials", headers=self.admin)
        self.assertEqual(listing.status_code, 200, listing.text)
        text = listing.text
        for password in self.saved.values():
            self.assertNotIn(password, text)
        self.assertNotIn("vk1.", text, "not even the sealed value")
        refs = {item["credential_ref"] for item in listing.json()["credentials"]}
        self.assertEqual(refs, {ref for (tenant, ref) in self.saved if tenant == "t-one"})

    def test_rotating_a_credential_replaces_it_and_is_audited(self) -> None:
        tenant, ref = next(iter(self.saved))
        with mock.patch.object(credential_preflight, "assess", return_value={"level": "ok", "findings": []}):
            response = self.client.put(f"/api/credentials/{ref}", headers=self.admin,
                                       json={"username": "svc-scan", "password": "Scan-pass-775", "domain": "CORP"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.vault.resolve(tenant, ref)["password"], "Scan-pass-775")
        rows = [row for row in store.read_audit_log("t-one", 50) if row["action"] == "credential.rotated"]
        self.assertTrue(rows)
        self.assertNotIn("Scan-pass-775", json.dumps(rows))

    def test_saving_a_privileged_account_warns_and_records_it(self) -> None:
        response = self.client.post("/api/credentials", headers=self.admin,
                                    json={"username": "Administrator", "password": "Admin-pass-776", "domain": "CORP"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["privilege"]["level"], "warning")
        ref = response.json()["credential_ref"]
        entry = {i["credential_ref"]: i for i in self.client.get("/api/credentials", headers=self.admin).json()["credentials"]}[ref]
        self.assertEqual(entry["privilege"]["level"], "warning")
        audited = [row for row in store.read_audit_log("t-one", 50) if row["action"] == "credential.stored"]
        self.assertEqual(audited[-1]["detail"]["privilege"], "warning")

    def test_the_directory_service_password_is_changed_only_in_directory_settings(self) -> None:
        ref = self.vault.store("t-one", "CN=svc-sentro,DC=corp", "Bind-pass-778", "", kind="directory",
                               label="CN=svc-sentro,DC=corp")
        listed = {i["credential_ref"]: i for i in self.client.get("/api/credentials", headers=self.admin).json()["credentials"]}
        self.assertEqual(listed[ref]["kind"], "directory")
        replaced = self.client.put(f"/api/credentials/{ref}", headers=self.admin,
                                   json={"username": "x", "password": "Other-pass-779", "domain": "D"})
        self.assertEqual(replaced.status_code, 400)
        self.assertEqual(self.client.delete(f"/api/credentials/{ref}", headers=self.admin).status_code, 400)
        self.assertEqual(self.vault.resolve("t-one", ref, kind="directory")["password"], "Bind-pass-778")

    def test_only_a_verified_credential_manager_sees_or_changes_them(self) -> None:
        # the role is read from the account, not the token: a viewer needs its own account
        store.create_user("cm-viewer", security.hash_password("Cred-viewer-pass-9"), "viewer", "t-one")
        viewer = {"Authorization": f"Bearer {security.create_token('cm-viewer', 'viewer', 't-one', mfa_verified=True)}"}
        unverified = {"Authorization": f"Bearer {security.create_token('cm', 'admin', 't-one', mfa_verified=False)}"}
        for headers in (viewer, unverified):
            self.assertEqual(self.client.get("/api/credentials", headers=headers).status_code, 403)
        _tenant, ref = next(iter(self.saved))
        foreign = next(ref for (tenant, ref) in self.saved if tenant == "t-two")
        self.assertEqual(self.client.delete(f"/api/credentials/{foreign}", headers=self.admin).status_code, 404)
        self.assertEqual(self.client.delete(f"/api/credentials/{ref}", headers=self.admin).status_code, 200)
        self.assertIsNone(store.read_secret("t-one", ref))


@unittest.skipIf(os.getenv("DSPM_DB_URL"), "the CLI runs against its own SQLite configuration file, while this "
                 "process's store is the suite's PostgreSQL - the credential it saves would not be the CLI's")
class TheCommandLineTest(unittest.TestCase):
    """`main.py vault ...` as an operator runs it: against the install's configuration file,
    the passphrase from a file, and neither a key nor the passphrase in what it prints."""

    def test_status_rotate_escrow_and_recover(self) -> None:
        import subprocess
        import sys

        root = Path(__file__).resolve().parents[1]
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        key = Fernet.generate_key().decode()
        (tmp / "vault_key").write_text(key, encoding="utf-8")
        (tmp / "passphrase").write_text(PASSPHRASE + "\n", encoding="utf-8")
        ring = tmp / "vault_keyring.json"
        config = tmp / "sentro.toml"
        config.write_text("\n".join([
            "[settings]", f"DSPM_DB_PATH = '{tmp / 'cli.sqlite'}'", f"DSPM_VAULT_KEY_FILE = '{tmp / 'vault_key'}'",
            f"DSPM_VAULT_KEYRING = '{ring}'", f"DSPM_LOCAL_JWT_SECRET_PATH = '{tmp / 'jwt'}'",
            f"DSPM_LOCAL_EVIDENCE_KEY_PATH = '{tmp / 'evidence'}'", f"DSPM_ARTIFACT_DIR = '{tmp / 'artifacts'}'",
            f"DSPM_LOCAL_ARTIFACT_KEY_PATH = '{tmp / 'artifact_key'}'", ""]), encoding="utf-8")
        env = {name: value for name, value in os.environ.items() if not name.startswith("DSPM_")}

        def run(*args: str) -> subprocess.CompletedProcess:
            return subprocess.run([sys.executable, str(root / "main.py"), "--config", str(config), *args], cwd=root,
                                  env=env, capture_output=True, encoding="utf-8", errors="replace", timeout=300)

        self.assertEqual(run("migrate", "upgrade").returncode, 0)
        original = store.DB_PATH
        store.DB_PATH = tmp / "cli.sqlite"
        try:
            with mock.patch.dict(os.environ, {"DSPM_VAULT_KEY": key, "DSPM_VAULT_KEYRING": str(ring)}):
                vault_keys._CACHE.update({"stamp": None, "ring": None})
                store.create_tenant("t-cli", "cli")
                ref = vault.CredentialVault().store("t-cli", "svc", "Cli-pass-881", "CORP")
            outputs = []
            for args in (("vault", "status", "--json"), ("vault", "rotate", "--json"),
                         ("vault", "escrow", "export", "--out", str(tmp / "escrow.json"),
                          "--passphrase-file", str(tmp / "passphrase"), "--json"),
                         ("vault", "escrow", "verify", str(tmp / "escrow.json"), "--passphrase-file",
                          str(tmp / "passphrase"), "--json")):
                done = run(*args)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                outputs.append(done.stdout + done.stderr)
            ring.unlink()
            recovered = run("vault", "escrow", "recover", str(tmp / "escrow.json"), "--out", str(ring),
                            "--passphrase-file", str(tmp / "passphrase"), "--json")
            self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
            outputs.append(recovered.stdout + recovered.stderr)
            with mock.patch.dict(os.environ, {"DSPM_VAULT_KEY": key, "DSPM_VAULT_KEYRING": str(ring)}):
                vault_keys._CACHE.update({"stamp": None, "ring": None})
                self.assertEqual(vault.CredentialVault().resolve("t-cli", ref)["password"], "Cli-pass-881")
        finally:
            store.DB_PATH = original
            vault_keys._CACHE.update({"stamp": None, "ring": None})
        text = "\n".join(outputs)
        for item in json.loads(ring.read_text(encoding="utf-8"))["keys"]:
            self.assertNotIn(item["key"], text)
        self.assertNotIn(PASSPHRASE, text)
        self.assertIn('"resealed": 1', text.replace(" ", " "))


class ExitReviewKeyOperationsTest(_Case):
    """Defects the M3 exit review found in the key operations, each pinned."""

    def test_a_second_key_operation_waits_its_turn(self) -> None:
        # two rotations interleaving could each save a ring the other never saw
        vault.rotate(actor="test")
        before = json.loads(self.ring_file.read_text(encoding="utf-8"))
        with vault_keys.RingLock(self.ring_file):
            for operation in (lambda: vault.rotate(actor="test"), lambda: vault.rollback(actor="test")):
                with self.assertRaises(vault_keys.VaultKeyError) as refused:
                    operation()
                self.assertIn("Another vault key operation", str(refused.exception))
        self.assertEqual(json.loads(self.ring_file.read_text(encoding="utf-8")), before, "nothing changed")
        vault.rotate(actor="test")  # and once it is free, it runs
        self.assert_everything_opens()

    def test_recovery_refuses_an_escrow_older_than_the_last_rotation(self) -> None:
        escrow = self.tmp / "escrow.json"
        vault.export_escrow(escrow, PASSPHRASE, actor="test")
        vault.rotate(actor="test")
        self.ring_file.unlink()
        with self.assertRaises(vault_keys.VaultKeyError) as refused:
            vault.recover_escrow(escrow, PASSPHRASE, self.ring_file, actor="test")
        self.assertIn("predates a rotation", str(refused.exception))
        self.assertFalse(self.ring_file.exists(), "nothing was written")
        report = vault.recover_escrow(escrow, PASSPHRASE, self.ring_file, accept_missing=True, actor="test")
        self.assertTrue(report["missing"])

    def test_recovering_over_a_ring_keeps_the_ring_it_replaces(self) -> None:
        vault.rotate(actor="test")
        escrow = self.tmp / "escrow.json"
        vault.export_escrow(escrow, PASSPHRASE, actor="test")
        replaced = self.ring_file.read_text(encoding="utf-8")
        report = vault.recover_escrow(escrow, PASSPHRASE, self.ring_file, force=True, actor="test")
        kept = Path(report["replaced_ring_kept_at"])
        self.assertTrue(kept.exists())
        self.assertEqual(kept.parent, self.ring_file.parent, "beside it, in the protected folder")
        self.assertEqual(kept.read_text(encoding="utf-8"), replaced)
        vault_keys._CACHE.update({"stamp": None, "ring": None})
        self.assert_everything_opens()

    def test_a_value_no_key_opens_stops_a_rotation_before_anything_changes(self) -> None:
        vault.rotate(actor="test")  # the ring file exists from here
        foreign = Fernet(Fernet.generate_key()).encrypt(b'{"username":"u","password":"p","domain":"D"}').decode()
        store.save_secret("t-one", "orphan-ref", foreign)
        ring_before = self.ring_file.read_text(encoding="utf-8")
        with self.assertRaises(vault_keys.VaultKeyError) as refused:
            vault.rotate(actor="test")
        message = str(refused.exception)
        self.assertIn("secrets tenant_id=t-one secret_id=orphan-ref", message)
        self.assertIn("Nothing was changed", message)
        self.assertNotIn(foreign, message)
        self.assertEqual(self.ring_file.read_text(encoding="utf-8"), ring_before, "no half-started rotation")
        done = vault.rotate(actor="test", skip_unreadable=True)
        self.assertEqual(done["left_unreadable"], ["secrets tenant_id=t-one secret_id=orphan-ref"])
        self.assertEqual(store.read_secret("t-one", "orphan-ref"), foreign, "left exactly as it was")
        self.assert_everything_opens()

    def test_a_hostile_escrow_cannot_name_an_expensive_key_derivation(self) -> None:
        escrow = self.tmp / "escrow.json"
        vault.export_escrow(escrow, PASSPHRASE, actor="test")
        # p=60000 fits scrypt's 128 MiB limit and would run for most of an hour: the bounds
        # must refuse it before any derivation starts, so the derivation must never be called.
        for change in ({"p": 60_000}, {"n": 2 ** 24}, {"n": 3 * 2 ** 14}, {"r": 10 ** 30}):
            document = json.loads(escrow.read_text(encoding="utf-8"))
            document["kdf"].update(change)
            altered = self.tmp / "altered.json"
            altered.write_text(json.dumps(document), encoding="utf-8")
            with self.subTest(change=change), \
                    mock.patch.object(vault_keys, "_derive", side_effect=AssertionError("derived with " + str(change))), \
                    self.assertRaises(vault_keys.VaultKeyError):
                vault.verify_escrow(altered, PASSPHRASE)

    def test_a_passphrase_file_with_a_byte_order_mark_is_the_typed_passphrase(self) -> None:
        with_bom = self.tmp / "passphrase-bom.txt"
        with_bom.write_text(PASSPHRASE + "\r\n", encoding="utf-8-sig")  # what PowerShell 5.1 writes
        self.assertEqual(vault_keys.read_passphrase(str(with_bom)), PASSPHRASE)
        with mock.patch("getpass.getpass", return_value=PASSPHRASE + " "):
            self.assertEqual(vault_keys.read_passphrase(None), PASSPHRASE, "trimmed the same way as a file")

    def test_verify_opens_what_is_sealed_not_only_its_key_ids(self) -> None:
        # a value from before key ids names no key; another install's escrow must not pass
        legacy = Fernet(self.first_key.encode()).encrypt(b'{"username":"u","password":"legacy","domain":"D"}')
        store.save_secret("t-one", "legacy-ref", legacy.decode())
        other_key = Fernet.generate_key()
        other = vault_keys.Ring(vault_keys.key_id(other_key), {vault_keys.key_id(other_key): other_key},
                                {vault_keys.key_id(other_key): "active"}, {vault_keys.key_id(other_key): ""})
        foreign = self.tmp / "foreign-escrow.json"
        foreign.write_text(json.dumps(vault_keys.export_escrow(other, PASSPHRASE)), encoding="utf-8")
        report = vault.verify_escrow(foreign, PASSPHRASE)
        self.assertFalse(report["ok"])
        self.assertGreaterEqual(report["unopenable"], 1)

    def test_a_ring_that_cannot_be_renamed_into_place_leaves_no_key_file_behind(self) -> None:
        ring = vault.ring()
        with mock.patch("os.replace", side_effect=PermissionError("in use")), mock.patch("time.sleep"):
            with self.assertRaises(PermissionError):
                vault_keys.save_ring(ring, self.tmp / "secrets" / "ring-under-test.json")
        self.assertEqual([p.name for p in (self.tmp / "secrets").glob("*.tmp")], [])


class ExitReviewCredentialKindTest(_Case):

    def test_a_scan_cannot_use_the_directory_service_accounts_password(self) -> None:
        ref = self.vault.store("t-one", "cn=svc-sentro", "Bind-pass-8812", "", kind="directory")
        with self.assertRaises(KeyError):
            self.vault.resolve("t-one", ref)  # what a scan asks for
        self.assertEqual(self.vault.resolve("t-one", ref, kind="directory")["password"], "Bind-pass-8812")
        self.assertEqual(self.vault.resolve("t-one", ref, kind=None)["username"], "cn=svc-sentro")

    def test_a_scan_request_naming_it_is_refused(self) -> None:
        from backend import app as app_module

        ref = self.vault.store("t-one", "cn=svc-sentro", "Bind-pass-8812", "", kind="directory")
        payload = app_module.ScanRequest(server="files.corp.example", credential_ref=ref)
        with self.assertRaises(KeyError):
            app_module._to_config(payload, "t-one")

    def test_revision_29_marks_a_bind_password_saved_before_credential_kinds(self) -> None:
        ref = self.vault.store("t-one", "cn=svc-sentro", "Bind-pass-8812", "")  # the old default: scan
        store.save_directory_settings("t-one", True, {"base_dn": "dc=corp,dc=example"}, ref, "test")
        with store._connect() as conn:
            store.classify_directory_secrets(conn)
            store.classify_directory_secrets(conn)  # and again: idempotent
        self.assertEqual(store.read_secret_record("t-one", ref)["kind"], "directory")
        with self.assertRaises(KeyError):
            self.vault.resolve("t-one", ref)
        others = {item["credential_ref"]: item["kind"] for item in store.list_secret_metadata("t-one")}
        self.assertEqual(sorted(kind for key, kind in others.items() if key != ref), ["scan", "scan"])


class ExitReviewPreflightDomainTest(unittest.TestCase):

    def test_an_account_of_another_domain_is_not_looked_up_in_this_one(self) -> None:
        from backend import directory

        settings = {"config": {"base_dn": "DC=corp,DC=example"}}
        with mock.patch("backend.identity.directory_settings", return_value=settings), \
                mock.patch("backend.identity.bind_password", return_value="pw"), \
                mock.patch.object(directory, "lookup", side_effect=AssertionError("looked up in the wrong domain")):
            for account, domain in (("OTHERDOM\\svc-scan", ""), ("svc-scan@other.example", ""),
                                    ("svc-scan", "OTHERDOM"), ("FILESRV01\\svc-scan", "")):
                with self.subTest(account=account, domain=domain):
                    result = credential_preflight.assess("t-one", account, domain)
                    self.assertNotEqual(result["level"], "ok")
                    self.assertTrue(any("does not answer for" in finding for finding in result["findings"]))

    def test_this_domains_names_are_still_looked_up(self) -> None:
        from backend import directory

        settings = {"config": {"base_dn": "DC=corp,DC=example"}}
        clean = directory.Outcome("no_mapped_group", groups=("CN=File Readers,DC=corp,DC=example",))
        for account, domain in (("CORP\\svc-scan", ""), ("svc-scan@corp.example", ""), ("svc-scan", "CORP"),
                                ("svc-scan", "WORKGROUP"), ("svc-scan", "")):
            with self.subTest(account=account, domain=domain), \
                    mock.patch("backend.identity.directory_settings", return_value=settings), \
                    mock.patch("backend.identity.bind_password", return_value="pw"), \
                    mock.patch.object(directory, "lookup", return_value=clean) as lookup:
                self.assertEqual(credential_preflight.assess("t-one", account, domain)["level"], "ok")
                lookup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
