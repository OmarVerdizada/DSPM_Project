"""M2/C4: SIEM Integration, configured in the console - Settings -> Features.

The engine (outbox, retries, TLS, delivery) is tests/test_siem_forwarding.py's subject.
This file is the configuration surface: its states, what it persists, what it refuses,
what it never gives back, who may change it, what it records - and that none of it
weakens delivery. Real receivers throughout: a TCP syslog listener, and a TLS one behind
a throwaway private CA.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from backend import security, siem, siem_settings, store
from backend.app import app
from tests.test_siem_forwarding import _Receiver, _TlsReceiver, _private_ca

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
SMOKE = ROOT / "tests" / "js" / "refresh_retry_smoke.js"
PASSWORD = "a-siem-settings-pass-3"


class _Case(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "siem-settings.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        env = mock.patch.dict(os.environ, {"DSPM_SIEM_URL": "", "DSPM_SIEM_CA_FILE": ""})
        env.start()
        self.addCleanup(env.stop)
        store.init_db()
        if store.get_tenant("default") is None:
            store.create_tenant("default", "Default")
        store.create_tenant("tenant-siem", "Siem")
        password_hash = security.hash_password(PASSWORD)
        if store.get_user("admin") is None:
            store.create_user("admin", password_hash, "admin", "default")
        store.create_user("siem-tenant-admin", password_hash, "admin", "tenant-siem")
        store.create_user("siem-analyst", password_hash, "analyst", "tenant-siem")
        store._forget_revocation()
        security._session_last_seen.clear()
        self.addCleanup(store._forget_revocation)
        self.addCleanup(security._session_last_seen.clear)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.admin = self._as("admin", "admin", "default")

    def _as(self, user: str, role: str, tenant: str = "tenant-siem") -> dict:
        return {"Authorization": f"Bearer {security.create_token(user, role, tenant)}"}

    def _get(self) -> dict:
        response = self.client.get("/api/settings/siem", headers=self.admin)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def _save(self, **fields) -> dict:
        response = self.client.put("/api/settings/siem", headers=self.admin, json=fields)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def _enable(self, enabled: bool) -> dict:
        response = self.client.put("/api/settings/siem/enabled", headers=self.admin, json={"enabled": enabled})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def _actions(self) -> list[dict]:
        return [event for event in store.read_audit_log("default", 200) if event["action"].startswith("settings.siem")]

    def _settings_rows(self) -> str:
        with store._connect() as conn:
            return json.dumps([dict(row) for row in conn.execute("SELECT key, value FROM app_settings").fetchall()])


class TheStatesTest(_Case):

    def test_it_starts_disabled_and_unconfigured(self) -> None:
        view = self._get()
        self.assertEqual((view["enabled"], view["configured"], view["state"]), (False, False, "disabled"))
        self.assertEqual(view["queue"]["pending"], 0)

    def test_enabled_is_not_configured_and_configured_is_not_connected(self) -> None:
        self.assertEqual(self._enable(True)["state"], "not_configured")
        receiver = _Receiver()
        self.addCleanup(receiver.stop)
        view = self._save(transport="tcp", host="127.0.0.1", port=receiver.port, format="cef")
        self.assertEqual((view["enabled"], view["configured"], view["state"]), (True, True, "not_connected"),
                         "enabled and configured, but nothing has reached the receiver yet")

    def test_a_delivery_makes_it_connected(self) -> None:
        receiver = _Receiver()
        self.addCleanup(receiver.stop)
        self._save(transport="tcp", host="127.0.0.1", port=receiver.port)
        self._enable(True)
        store.audit("tenant-siem", "alice", "auth.login", {})
        self.assertGreaterEqual(siem.drain()["sent"], 1)
        view = self._get()
        self.assertEqual(view["state"], "connected")
        self.assertTrue(view["status"]["last_delivery_at"])

    def test_events_that_cannot_be_delivered_make_it_degraded_and_retry_recovers(self) -> None:
        receiver = _Receiver()
        port = receiver.port
        receiver.stop()                                   # the receiver is down
        self._save(transport="tcp", host="127.0.0.1", port=port)
        self._enable(True)
        for index in range(3):
            store.audit("tenant-siem", "alice", "auth.login_failed", {"n": index})
        siem.drain()
        view = self._get()
        self.assertEqual(view["state"], "degraded")
        self.assertGreaterEqual(view["queue"]["failing"], 3)
        self.assertIn("refused the connection", view["status"]["last_error"])
        back = _Receiver(port=port)                       # it comes back
        self.addCleanup(back.stop)
        retried = self.client.post("/api/settings/siem/retry", headers=self.admin).json()
        self.assertEqual(retried["retry"]["failed"], 0)
        self.assertEqual(retried["queue"]["pending"], 0, "nothing left behind")
        self.assertEqual(retried["state"], "connected")
        self.assertTrue(any("auth.login_failed" in line for line in back.wait_for(3)), "the queued events arrived")


class PersistingTheConfigurationTest(_Case):

    def test_it_survives_a_reload_and_a_restart(self) -> None:
        self._save(transport="tls", host="siem.corp.local", port=6514, format="json", trust="system")
        self.client.close()
        self.client = TestClient(app)                      # a fresh page, a fresh process view
        view = self._get()
        self.assertEqual({k: view["config"][k] for k in ("transport", "host", "port", "format", "trust")},
                         {"transport": "tls", "host": "siem.corp.local", "port": 6514, "format": "json", "trust": "system"})

    def test_turning_it_off_keeps_the_configuration_and_on_again_restores_it(self) -> None:
        receiver = _Receiver()
        self.addCleanup(receiver.stop)
        self._save(transport="tcp", host="127.0.0.1", port=receiver.port, format="json")
        self._enable(True)
        off = self._enable(False)
        self.assertEqual((off["enabled"], off["state"], off["config"]["host"], off["config"]["format"]),
                         (False, "disabled", "127.0.0.1", "json"))
        store.audit("tenant-siem", "alice", "while.off", {})
        self.assertEqual(store.audit_outbox_status()["pending"], 0, "off means nothing is queued")
        on = self._enable(True)
        self.assertEqual((on["enabled"], on["config"]["port"], on["config"]["format"]), (True, receiver.port, "json"))

    def test_turning_it_off_tells_the_siem_first(self) -> None:
        receiver = _Receiver()
        self.addCleanup(receiver.stop)
        self._save(transport="tcp", host="127.0.0.1", port=receiver.port)
        self._enable(True)
        self._enable(False)
        self.assertTrue(any("settings.siem_disabled" in line for line in receiver.wait_for(2)),
                        "the last thing the SIEM hears is that it was turned off, and by whom")

    def test_removing_it_deletes_the_configuration_and_keeps_the_queue(self) -> None:
        receiver = _Receiver()
        port = receiver.port
        receiver.stop()
        self._save(transport="tcp", host="127.0.0.1", port=port)
        self._enable(True)
        store.audit("tenant-siem", "alice", "queued.before.removal", {})
        response = self.client.delete("/api/settings/siem", headers=self.admin)
        self.assertEqual(response.status_code, 200, response.text)
        view = response.json()
        self.assertEqual((view["enabled"], view["configured"], view["state"]), (False, False, "disabled"))
        self.assertGreaterEqual(view["queue"]["pending"], 1, "queued events are not thrown away")
        self.assertNotIn("127.0.0.1", self._settings_rows())

    def test_an_environment_configuration_is_imported_once(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_SIEM_URL": "tcp://siem.old.local:1514", "DSPM_SIEM_FORMAT": "json"}):
            view = self._get()
            self.assertEqual((view["enabled"], view["config"]["host"], view["config"]["port"], view["config"]["format"]),
                             (True, "siem.old.local", 1514, "json"))
            self.client.delete("/api/settings/siem", headers=self.admin)
            self.assertFalse(self._get()["configured"], "a removed configuration does not come back from the environment")


class TheCertificateTest(_Case):
    """The only stored material: a CA certificate. Public, but still never given back,
    kept when omitted, replaced when sent, deleted only on request."""

    def setUp(self) -> None:
        super().setUp()
        one, two = Path(self.temp_dir.name) / "one", Path(self.temp_dir.name) / "two"
        one.mkdir()
        two.mkdir()
        self.ca_one = _private_ca(one)[0]
        self.ca_two = _private_ca(two)[0]

    def _pem(self, path: Path) -> str:
        return path.read_text(encoding="utf-8")

    def test_the_certificate_is_described_never_returned(self) -> None:
        view = self._save(transport="tls", host="localhost", port=6514, trust="custom",
                          ca_pem=self._pem(self.ca_one), ca_name="corp-root.pem")
        ca = view["config"]["ca"]
        self.assertTrue(view["config"]["ca_configured"])
        self.assertEqual(ca["name"], "corp-root.pem")
        self.assertRegex(ca["fingerprint"], r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")
        self.assertTrue(ca["subject"] and ca["not_after"])
        for response in (json.dumps(view), json.dumps(self._get()),
                         json.dumps(self.client.get("/api/settings/features", headers=self.admin).json())):
            self.assertNotIn("BEGIN CERTIFICATE", response)

    def test_an_omitted_certificate_is_kept_and_a_new_one_replaces_it(self) -> None:
        first = self._save(transport="tls", host="localhost", port=6514, trust="custom",
                           ca_pem=self._pem(self.ca_one), ca_name="one.pem")["config"]["ca"]["fingerprint"]
        kept = self._save(transport="tls", host="localhost", port=7514, trust="custom")["config"]
        self.assertEqual((kept["ca"]["fingerprint"], kept["port"]), (first, 7514), "not sent, not changed")
        replaced = self._save(transport="tls", host="localhost", port=7514, trust="custom",
                              ca_pem=self._pem(self.ca_two), ca_name="two.pem")["config"]["ca"]
        self.assertNotEqual(replaced["fingerprint"], first)
        self.assertEqual(replaced["name"], "two.pem")

    def test_only_an_explicit_removal_deletes_it(self) -> None:
        self._save(transport="tls", host="localhost", trust="custom", ca_pem=self._pem(self.ca_one), ca_name="one.pem")
        refused = self.client.put("/api/settings/siem", headers=self.admin,
                                  json={"transport": "tls", "host": "localhost", "trust": "custom", "remove_ca": True})
        self.assertEqual(refused.status_code, 400, "a private CA with no certificate is not a configuration")
        view = self._save(transport="tls", host="localhost", trust="system", remove_ca=True)
        self.assertFalse(view["config"]["ca_configured"])
        self.assertNotIn("BEGIN CERTIFICATE", self._settings_rows())

    def test_a_private_key_is_refused_and_never_stored(self) -> None:
        key = (Path(self.temp_dir.name) / "one" / "server.key").read_text(encoding="utf-8")
        bundle = self._pem(self.ca_one) + key
        response = self.client.put("/api/settings/siem", headers=self.admin,
                                   json={"transport": "tls", "host": "localhost", "trust": "custom", "ca_pem": bundle})
        self.assertEqual(response.status_code, 400)
        self.assertIn("private key", response.json()["detail"])
        self.assertNotIn("PRIVATE KEY", self._settings_rows())
        self.assertNotIn("PRIVATE KEY", json.dumps(store.read_audit_log("default", 200)))

    def test_what_the_form_cannot_be(self) -> None:
        for fields, words in (
            ({"host": "tls://siem:6514"}, "only the host"),
            ({"host": "not a host"}, "only the host"),
            ({"host": "siem", "port": 70000}, None),
            ({"host": "siem", "transport": "http"}, "TLS, TCP or UDP"),
            ({"host": "siem", "format": "leef"}, "CEF or JSON"),
            ({"host": ""}, "host name"),
        ):
            with self.subTest(fields=fields):
                response = self.client.put("/api/settings/siem", headers=self.admin, json=fields)
                self.assertIn(response.status_code, (400, 422), response.text)
                if words:
                    self.assertIn(words, response.json()["detail"])


class TheConnectionTestTest(_Case):

    def test_a_receiver_that_answers(self) -> None:
        receiver = _Receiver()
        self.addCleanup(receiver.stop)
        self._enable(True)
        data = self.client.post("/api/settings/siem/test", headers=self.admin,
                                json={"transport": "tcp", "host": "127.0.0.1", "port": receiver.port}).json()
        self.assertTrue(data["test"]["ok"], data["test"])
        self.assertTrue(any("siem.connection_test" in line for line in receiver.wait_for(1)))
        self.assertFalse(data["configured"], "testing does not save")
        self.assertEqual(store.audit_outbox_status()["pending"], 0, "the test line is not an audit event")

    def test_a_tls_receiver_whose_certificate_is_not_trusted(self) -> None:
        ca, certfile, keyfile = _private_ca(Path(self.temp_dir.name))
        receiver = _TlsReceiver(certfile, keyfile)
        self.addCleanup(receiver.stop)
        failed = self.client.post("/api/settings/siem/test", headers=self.admin,
                                  json={"transport": "tls", "host": "localhost", "port": receiver.port, "trust": "system"}).json()
        self.assertFalse(failed["test"]["ok"])
        self.assertIn("not trusted", failed["test"]["message"])
        self.assertNotIn("Traceback", json.dumps(failed))
        trusted = self.client.post("/api/settings/siem/test", headers=self.admin, json={
            "transport": "tls", "host": "localhost", "port": receiver.port, "trust": "custom",
            "ca_pem": ca.read_text(encoding="utf-8"), "ca_name": "ca.pem"}).json()
        self.assertTrue(trusted["test"]["ok"], trusted["test"])
        self.assertIn("verified its certificate", trusted["test"]["message"])

    def test_a_passed_test_of_the_saved_configuration_makes_it_connected(self) -> None:
        receiver = _Receiver()
        self.addCleanup(receiver.stop)
        self._save(transport="tcp", host="127.0.0.1", port=receiver.port)
        self._enable(True)
        data = self.client.post("/api/settings/siem/test", headers=self.admin, json={}).json()
        self.assertTrue(data["test"]["ok"])
        self.assertEqual(data["state"], "connected")


class WhoMayTest(_Case):

    def test_nobody_but_the_installation_admin_changes_or_reads_it(self) -> None:
        for headers in (self._as("siem-tenant-admin", "admin"), self._as("siem-analyst", "analyst")):
            for method, path, body in (("get", "/api/settings/siem", None), ("put", "/api/settings/siem", {"host": "x"}),
                                       ("put", "/api/settings/siem/enabled", {"enabled": True}),
                                       ("post", "/api/settings/siem/test", {}), ("post", "/api/settings/siem/retry", None),
                                       ("delete", "/api/settings/siem", None)):
                with self.subTest(path=path, method=method):
                    kwargs = {"json": body} if body is not None else {}
                    response = getattr(self.client, method)(path, headers=headers, **kwargs)
                    self.assertEqual(response.status_code, 403)
        self.assertFalse(self._get()["enabled"], "nothing changed")

    def test_everyone_sees_the_state_and_nothing_else(self) -> None:
        self._save(transport="tcp", host="siem.hidden.local", port=1514)
        self._enable(True)
        features = self.client.get("/api/settings/features", headers=self._as("siem-analyst", "analyst")).json()
        self.assertEqual(features["features"]["siem"], {"enabled": True, "state": "not_connected", "editable": False})
        self.assertNotIn("siem.hidden.local", json.dumps(features))


class WhatIsRecordedTest(_Case):

    def test_every_change_is_in_the_trail_and_no_certificate_is(self) -> None:
        ca = _private_ca(Path(self.temp_dir.name))[0]
        receiver = _Receiver()
        self.addCleanup(receiver.stop)
        self._save(transport="tls", host="localhost", trust="custom", ca_pem=ca.read_text(encoding="utf-8"), ca_name="ca.pem")
        self._enable(True)
        self.client.post("/api/settings/siem/test", headers=self.admin,
                         json={"transport": "tcp", "host": "127.0.0.1", "port": receiver.port})
        self.client.post("/api/settings/siem/test", headers=self.admin, json={"transport": "tcp", "host": "127.0.0.1", "port": 9})
        self._enable(False)
        self.client.delete("/api/settings/siem", headers=self.admin)
        actions = [event["action"] for event in self._actions()]
        for expected in ("settings.siem_changed", "settings.siem_enabled", "settings.siem_test_succeeded",
                         "settings.siem_test_failed", "settings.siem_disabled", "settings.siem_removed"):
            self.assertIn(expected, actions)
        trail = json.dumps(self._actions())
        self.assertNotIn("BEGIN CERTIFICATE", trail)
        changed = next(event for event in self._actions() if event["action"] == "settings.siem_changed")
        self.assertEqual(changed["actor"], "admin")
        self.assertIn("ca_fingerprint", changed["detail"])


@unittest.skipUnless(NODE, "Node is not installed; the settings-page smoke needs it")
class TheSettingsPageTest(unittest.TestCase):
    """The real profile.js in Node: the sentence each state gets, and what a save sends."""

    def _evaluate(self, expressions: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "scenario.json"
            fixture.write_text(json.dumps({"script": "profile.js", "drive": "evaluate", "evaluate": expressions}),
                               encoding="utf-8")
            result = subprocess.run([NODE, str(SMOKE), str(fixture)], cwd=ROOT, capture_output=True,
                                    encoding="utf-8", timeout=180, check=False)
        report = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertIsNone(report.get("error"), report.get("error"))
        return report["values"]

    def test_on_is_never_connected_and_each_state_says_what_it_is(self) -> None:
        view = "{state: '%s', config: {host: 'siem.corp.local', port: 6514}, queue: {pending: 4}, status: {last_delivery_at: new Date().toISOString()}}"
        values = self._evaluate({state: f"siemStateLine({view % state})" for state in
                                 ("disabled", "not_configured", "not_connected", "connected", "degraded")})
        self.assertIn("configuration for siem.corp.local:6514 is kept", values["disabled"])
        self.assertIn("no receiver configured", values["not_configured"])
        self.assertIn("not connected", values["not_connected"])
        self.assertTrue(values["connected"].startswith("Connected to siem.corp.local:6514"))
        self.assertIn("4 events queued", values["degraded"])
        self.assertNotIn("Connected", values["not_connected"])

    def test_a_save_sends_a_certificate_only_when_one_was_chosen(self) -> None:
        fields = "{host: ' siem.corp.local ', port: '6514', transport: 'tls', format: 'cef', trust: 'custom'}"
        values = self._evaluate({
            "untouched": f"JSON.stringify(siemRequestBody({fields}, null, false))",
            "chosen": f"JSON.stringify(siemRequestBody({fields}, {{pem: '-----BEGIN CERTIFICATE-----x', name: 'new.pem'}}, false))",
            "removed": f"JSON.stringify(siemRequestBody({fields}, null, true))",
            "udp": "JSON.stringify(siemRequestBody({host: 'h', port: '', transport: 'udp', format: 'json', trust: 'custom'}, null, false))",
        })
        untouched = json.loads(values["untouched"])
        self.assertEqual(untouched, {"transport": "tls", "host": "siem.corp.local", "port": 6514, "format": "cef", "trust": "custom"},
                         "nothing stands in for the stored certificate")
        self.assertEqual(json.loads(values["chosen"])["ca_name"], "new.pem")
        self.assertIs(json.loads(values["removed"])["remove_ca"], True)
        self.assertNotIn("ca_pem", json.loads(values["removed"]))
        self.assertEqual(json.loads(values["udp"]), {"transport": "udp", "host": "h", "port": None, "format": "json", "trust": "system"})


if __name__ == "__main__":
    unittest.main()
