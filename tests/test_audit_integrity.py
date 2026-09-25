"""M2/C4: an audit trail you can hand to an auditor.

Three of the gate's lines are here: "tampered row fails `audit verify`" and "a 1,000-attempt
test writes bounded rows", plus the coverage the item lists - report creation and download,
full-report fetch, the DLP policy and browser-built exports - failed sign-ins recorded
against the tenant the name belongs to, and the client address taken from a trusted proxy.
(The SIEM half of the gate is tests/test_siem_forwarding.py.)
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi.testclient import TestClient

from backend import app as app_module
from backend import audit_chain, db, migrations, security, store
from backend.app import app
from backend.client_address import client_address, request_address
from backend.reporting import artifacts
from tests.test_evidence_scope import FRAMEWORKS, _scan_report

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
SMOKE = ROOT / "tests" / "js" / "refresh_retry_smoke.js"
TENANT = "tenant-audit"
OTHER = "tenant-audit-other"
PASSWORD = "an-audit-trail-pass-5"


class _TempDatabase(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        self.path = Path(self.temp_dir.name) / "audit.sqlite"
        original = store.DB_PATH
        store.DB_PATH = self.path
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        for tenant in (TENANT, OTHER):
            store.create_tenant(tenant, tenant)

    def _raw(self):
        """A connection that edits the rows behind the store's back - the tamperer's.
        On PostgreSQL the suite's database is the shared one, reached the store's way."""
        if db.is_postgres():
            opened = store._connect()
            conn = opened.__enter__()
            self.addCleanup(opened.__exit__, None, None, None)
            return conn
        conn = sqlite3.connect(self.path)
        self.addCleanup(conn.close)
        return conn

    def _verify(self, tenant: str = TENANT) -> dict:
        return store.verify_audit_chain(tenant)[0]


class TheChainTest(_TempDatabase):

    def setUp(self) -> None:
        super().setUp()
        for index in range(6):
            store.audit(TENANT, "alice", f"test.step_{index}", {"n": index})
        store.audit(OTHER, "bob", "test.elsewhere", {})

    def test_each_tenant_has_its_own_chain_and_it_verifies(self) -> None:
        rows = self._raw().execute(
            "SELECT tenant_id, seq, prev_hash, row_hash FROM audit_events ORDER BY id").fetchall()
        mine = [row for row in rows if row[0] == TENANT]
        self.assertEqual([row[1] for row in mine], [1, 2, 3, 4, 5, 6])
        self.assertEqual(mine[0][2], "", "the first row of a chain follows nothing")
        self.assertTrue(all(later[2] == earlier[3] for earlier, later in zip(mine, mine[1:])))
        self.assertEqual([row[1] for row in rows if row[0] == OTHER], [1])
        self.assertTrue(all(result["ok"] for result in store.verify_audit_chain()))

    def test_a_changed_row_is_reported(self) -> None:
        conn = self._raw()
        conn.execute("UPDATE audit_events SET detail_json = '{\"n\": 99}' WHERE tenant_id = ? AND seq = 3", (TENANT,))
        conn.commit()
        result = self._verify()
        self.assertFalse(result["ok"])
        self.assertEqual([p["seq"] for p in result["problems"]], [3])
        self.assertIn("changed", result["problems"][0]["problem"])

    def test_a_changed_actor_is_reported(self) -> None:
        conn = self._raw()
        conn.execute("UPDATE audit_events SET actor = 'mallory' WHERE tenant_id = ? AND seq = 5", (TENANT,))
        conn.commit()
        self.assertFalse(self._verify()["ok"])

    def test_a_deleted_row_is_reported(self) -> None:
        conn = self._raw()
        conn.execute("DELETE FROM audit_events WHERE tenant_id = ? AND seq = 2", (TENANT,))
        conn.commit()
        result = self._verify()
        self.assertFalse(result["ok"])
        self.assertIn("missing", json.dumps(result["problems"]))

    def test_cutting_off_the_newest_rows_is_reported(self) -> None:
        conn = self._raw()
        conn.execute("DELETE FROM audit_events WHERE tenant_id = ? AND seq >= 5", (TENANT,))
        conn.commit()
        result = self._verify()
        self.assertFalse(result["ok"])
        self.assertIn("newest rows are missing", json.dumps(result["problems"]))

    def test_deleting_the_head_as_well_is_reported(self) -> None:
        conn = self._raw()
        conn.execute("DELETE FROM audit_events WHERE tenant_id = ? AND seq >= 5", (TENANT,))
        conn.execute("DELETE FROM audit_chain_heads WHERE tenant_id = ?", (TENANT,))
        conn.commit()
        result = self._verify()
        self.assertFalse(result["ok"])
        self.assertIn("no chain head", result["problems"][0]["problem"])

    def test_a_forged_row_is_reported(self) -> None:
        conn = self._raw()
        conn.execute("INSERT INTO audit_events (tenant_id, timestamp, actor, action, detail_json, seq, prev_hash, row_hash) "
                     "VALUES (?, '2026-01-01T00:00:00+00:00', 'mallory', 'user.created', '{}', 7, 'x', 'y')", (TENANT,))
        conn.commit()
        self.assertFalse(self._verify()["ok"])

    def test_rows_swapped_in_order_are_reported(self) -> None:
        conn = self._raw()
        conn.execute("UPDATE audit_events SET seq = 100 WHERE tenant_id = ? AND seq = 3", (TENANT,))
        conn.execute("UPDATE audit_events SET seq = 3 WHERE tenant_id = ? AND seq = 4", (TENANT,))
        conn.execute("UPDATE audit_events SET seq = 4 WHERE tenant_id = ? AND seq = 100", (TENANT,))
        conn.commit()
        self.assertFalse(self._verify()["ok"])

    def test_the_command_line_says_so_and_fails(self) -> None:
        # The gate's words: "tampered row fails `audit verify`".
        env = {**os.environ, "DSPM_DB_PATH": str(self.path), "DSPM_ADMIN_PASSWORD": "cli-verify-harbour-7"}
        clean = subprocess.run([sys.executable, "main.py", "audit", "verify"], cwd=ROOT, env=env,
                               capture_output=True, text=True, timeout=180)
        self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
        self.assertIn(f"OK     {TENANT}: 6 rows", clean.stdout)
        conn = self._raw()
        conn.execute("UPDATE audit_events SET action = 'test.nothing_to_see' WHERE tenant_id = ? AND seq = 4", (TENANT,))
        conn.commit()
        tampered = subprocess.run([sys.executable, "main.py", "audit", "verify"], cwd=ROOT, env=env,
                                  capture_output=True, text=True, timeout=180)
        self.assertEqual(tampered.returncode, 1, tampered.stdout)
        self.assertIn(f"BROKEN {TENANT}", tampered.stdout)
        self.assertIn("seq 4", tampered.stdout)
        self.assertIn(f"OK     {OTHER}", tampered.stdout, "the other tenant's chain is not implicated")


class WritersDoNotForkTheChainTest(_TempDatabase):

    def test_threads_in_one_process(self) -> None:
        def write(worker: int) -> None:
            for index in range(25):
                store.audit(TENANT, f"thread-{worker}", "test.concurrent", {"i": index})

        threads = [threading.Thread(target=write, args=(worker,)) for worker in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        result = self._verify()
        self.assertTrue(result["ok"], result["problems"][:3])
        self.assertEqual(result["rows"], 200)

    def test_several_processes_on_one_database(self) -> None:
        # Each child imports the store, which converges the schema of the database it is
        # pointed at; bring it up to date here, or three children race the same upgrade.
        migrations.upgrade()
        script = (
            "import os, sys; from pathlib import Path; from backend import store; "
            "store.DB_PATH = Path(os.environ['DSPM_DB_PATH']); "
            "[store.audit(sys.argv[1], 'proc-' + sys.argv[2], 'test.concurrent', {'i': i}) for i in range(30)]"
        )
        env = {**os.environ, "DSPM_DB_PATH": str(self.path), "DSPM_ADMIN_PASSWORD": "cli-verify-harbour-7"}
        processes = [subprocess.Popen([sys.executable, "-c", script, TENANT, str(n)], cwd=ROOT, env=env)
                     for n in range(3)]
        for process in processes:
            self.assertEqual(process.wait(timeout=180), 0)
        result = self._verify()
        self.assertTrue(result["ok"], result["problems"][:3])
        self.assertEqual(result["rows"], 90)


@unittest.skipIf(db.is_postgres(), "builds an older SQLite file; the PostgreSQL upgrade path is scripted in C0.5")
class RevisionTwentyTwoTest(unittest.TestCase):
    """An install whose audit rows predate the chain: sealed at upgrade, and said to be."""

    def test_existing_rows_are_sealed_and_later_edits_show(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            original = store.DB_PATH
            store.DB_PATH = Path(tmp) / "r21.sqlite"
            try:
                migrations.upgrade()
                with store._connect() as conn:
                    conn.execute("DROP TABLE audit_chain_heads")
                    conn.execute("DELETE FROM schema_migrations WHERE revision >= 22")
                raw = sqlite3.connect(store.DB_PATH)
                raw.executemany(
                    "INSERT INTO audit_events (tenant_id, timestamp, actor, action, detail_json) VALUES (?, ?, ?, ?, ?)",
                    [("default", f"2026-01-0{n}T00:00:00+00:00", "old", f"old.event_{n}", "{}") for n in range(1, 5)],
                )
                raw.execute("UPDATE audit_events SET seq = NULL, prev_hash = '', row_hash = ''")
                raw.commit()
                raw.close()
                migrations.upgrade()
                result = store.verify_audit_chain("default")[0]
                self.assertTrue(result["ok"], result["problems"])
                self.assertEqual(result["sealed_through_seq"], 4)
                self.assertTrue(result["sealed_at"])
                store.audit("default", "new", "new.event")
                self.assertTrue(store.verify_audit_chain("default")[0]["ok"], "the chain continues past the seal")
                raw = sqlite3.connect(store.DB_PATH)
                raw.execute("UPDATE audit_events SET actor = 'mallory' WHERE seq = 2")
                raw.commit()
                raw.close()
                self.assertFalse(store.verify_audit_chain("default")[0]["ok"])
            finally:
                store.DB_PATH = original


class RetentionKeepsTheChainTest(_TempDatabase):

    def test_pruning_the_oldest_rows_leaves_a_chain_that_verifies(self) -> None:
        old = (datetime.now(timezone.utc) - timedelta(days=900)).isoformat()
        with mock.patch("backend.store.datetime") as clock:
            clock.now.return_value = datetime.fromisoformat(old)
            for index in range(3):
                store.audit(TENANT, "alice", "test.ancient", {"n": index})
        for index in range(2):
            store.audit(TENANT, "alice", "test.recent", {"n": index})
        results = store.prune_event_tables(apply=True, overrides={"audit_events": 730})
        audit_result = next(r for r in results if r["data_class"] == "audit_events")
        self.assertEqual(audit_result["removed_rows"], 3)
        result = self._verify()
        self.assertTrue(result["ok"], result["problems"])
        self.assertEqual((result["rows"], result["pruned_through_seq"]), (2, 3))
        conn = self._raw()
        conn.execute("UPDATE audit_events SET actor = 'mallory' WHERE tenant_id = ? AND seq = 4", (TENANT,))
        conn.commit()
        self.assertFalse(self._verify()["ok"], "and it still catches an edit")

    def test_erasing_a_tenant_erases_its_chain_head(self) -> None:
        store.audit(TENANT, "alice", "test.step")
        store.delete_tenant_with_data(TENANT)
        self.assertIn("audit_chain_heads", store._TENANT_ERASURE_TABLES)
        self.assertEqual(store.verify_audit_chain(TENANT)[0]["rows"], 0)


class _HttpCase(_TempDatabase):

    def setUp(self) -> None:
        super().setUp()
        password_hash = security.hash_password(PASSWORD)
        store.create_user("audit-analyst", password_hash, "analyst", TENANT)
        store.create_user("audit-viewer", password_hash, "viewer", TENANT)
        store._forget_revocation()
        security._session_last_seen.clear()
        self.addCleanup(store._forget_revocation)
        self.addCleanup(security._session_last_seen.clear)
        root = mock.patch.object(artifacts, "ARTIFACT_ROOT", Path(self.temp_dir.name) / "artifacts")
        root.start()
        self.addCleanup(root.stop)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def _as(self, user: str, role: str) -> dict:
        return {"Authorization": f"Bearer {security.create_token(user, role, TENANT)}"}

    def _actions(self, tenant: str = TENANT) -> list[str]:
        return [event["action"] for event in store.read_audit_log(tenant, 500)]


class EveryExportIsRecordedTest(_HttpCase):
    report: dict

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = _scan_report()

    def setUp(self) -> None:
        super().setUp()
        payload = app_module.ScanRequest(save_report=True, compliance_enabled=True, compliance_frameworks=FRAMEWORKS)
        data = json.loads(json.dumps(self.report))
        app_module._persist_compliance_scan(data, payload, security.Principal("audit-analyst", "analyst", TENANT))
        self.scan_id = data["scan_id"]
        self.analyst = self._as("audit-analyst", "analyst")

    def test_a_filed_report_and_its_download(self) -> None:
        filed = self.client.post("/api/v1/reports", headers=self.analyst, json={"severities": ["HIGH"]})
        self.assertEqual(filed.status_code, 200, filed.text)
        artifact_id = filed.json()["artifact_id"]
        downloaded = self.client.get(f"/api/v1/reports/artifacts/{artifact_id}", headers=self.analyst)
        self.assertEqual(downloaded.status_code, 200)
        events = {event["action"]: event["detail"] for event in store.read_audit_log(TENANT, 100)}
        self.assertEqual(events["report.created"]["artifact_id"], artifact_id)
        self.assertEqual(events["report.created"]["scope"], "severity")
        self.assertEqual(events["report.downloaded"]["artifact_id"], artifact_id)

    def test_a_full_report_fetch_but_not_the_console_s_compact_one(self) -> None:
        self.client.get(f"/api/history/{self.scan_id}/report?include_files=false", headers=self.analyst)
        self.assertNotIn("scan_report.viewed", self._actions())
        self.client.get(f"/api/history/{self.scan_id}/report", headers=self.analyst)
        self.client.get("/api/history/latest/report", headers=self._as("audit-viewer", "viewer"))
        viewed = [e["detail"] for e in store.read_audit_log(TENANT, 100) if e["action"] == "scan_report.viewed"]
        self.assertEqual([detail["evidence_included"] for detail in viewed], [True, False])

    def test_the_dlp_policy(self) -> None:
        self.assertEqual(self.client.post("/api/dlp-policy", headers=self.analyst, json={}).status_code, 200)
        self.assertIn("dlp_policy.exported", self._actions())

    def test_a_report_built_in_the_browser_is_asked_for_first(self) -> None:
        recorded = self.client.post("/api/audit/browser-export", headers=self.analyst,
                                    json={"format": "excel", "report_type": "Executive", "rows": 12})
        self.assertEqual(recorded.status_code, 200, recorded.text)
        refused = self.client.post("/api/audit/browser-export", headers=self._as("audit-viewer", "viewer"),
                                   json={"format": "word"})
        self.assertEqual(refused.status_code, 403)
        exports = [e["detail"] for e in store.read_audit_log(TENANT, 100) if e["action"] == "report.exported_in_browser"]
        self.assertEqual([detail["format"] for detail in exports], ["excel"])

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_the_console_asks_before_it_builds_and_builds_nothing_if_refused(self) -> None:
        # Driven in the real app.js: the server's answer decides whether a file is built.
        drive = (
            "(async () => {{ const events = []; "
            "fetch = async (url) => {{ events.push('ask ' + url); return {{ ok: {ok}, status: {status}, "
            "json: async () => ({{recorded: true}}), text: async () => '{{\"detail\":\"no\"}}', headers: {{ get: () => null }} }}; }}; "
            "try {{ await buildBrowserReport('word', () => events.push('built')); }} catch (error) {{ events.push('refused'); }} "
            "return events; }})()"
        )
        refused = self._evaluate({"events": drive.format(ok="false", status=403)})["events"]
        allowed = self._evaluate({"events": drive.format(ok="true", status=200)})["events"]
        self.assertEqual(refused, ["ask /api/audit/browser-export", "refused"])
        self.assertEqual(allowed, ["ask /api/audit/browser-export", "built"])
        script = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
        generate = script[script.index("async function generateReport("):]
        generate = generate[:generate.index("\n}\n")]
        for format_name in ("word", "excel"):
            self.assertIn(f'await buildBrowserReport("{format_name}", () => downloadFile(', generate)
        self.assertEqual(generate.count("downloadFile("), 2, "every browser-built file goes through the guard")

    def _evaluate(self, expressions: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "scenario.json"
            fixture.write_text(json.dumps({"drive": "evaluate", "permissions": ["report.create"],
                                           "evaluate": expressions}), encoding="utf-8")
            result = subprocess.run([NODE, str(SMOKE), str(fixture)], cwd=ROOT, capture_output=True,
                                    text=True, timeout=180, check=False)
        return json.loads(result.stdout.strip().splitlines()[-1])["values"]


class SignInAttemptsTest(_HttpCase):

    def _attempt(self, username: str) -> int:
        return self.client.post("/api/auth/login", json={"username": username, "password": "not-the-password-1"}).status_code

    def test_a_failure_is_recorded_in_the_tenant_the_name_belongs_to(self) -> None:
        self._attempt("audit-analyst")
        self._attempt("nobody-by-this-name")
        self.assertIn("auth.login_failed", self._actions(TENANT))
        failed_default = [e for e in store.read_audit_log("default", 100) if e["action"] == "auth.login_failed"]
        self.assertEqual([e["detail"]["username"] for e in failed_default], ["nobody-by-this-name"])

    def test_a_thousand_attempts_write_a_bounded_number_of_rows(self) -> None:
        # The gate's words: "a 1,000-attempt test writes bounded rows".
        statuses = [self._attempt("audit-analyst") for _ in range(1000)]
        self.assertEqual(statuses.count(401), app_module.LOGIN_MAX_ATTEMPTS)
        rows = [e for e in store.read_audit_log(TENANT, 5000) if e["action"].startswith("auth.login_")]
        blocked = [e["detail"]["blocked_attempts"] for e in rows if e["action"] == "auth.login_blocked"]
        self.assertEqual(blocked, [1, 10, 100])
        self.assertLessEqual(len(rows), app_module.LOGIN_MAX_ATTEMPTS + 4)

    def test_a_spray_across_names_is_bounded_too(self) -> None:
        for index in range(300):
            self._attempt(f"sprayed-{index}")
        rows = [e for e in store.read_audit_log("default", 5000) if e["action"].startswith("auth.login_")]
        self.assertLessEqual(len(rows), app_module.LOGIN_IP_MAX_ATTEMPTS + 4)


class TheClientAddressTest(unittest.TestCase):

    def test_without_trusted_proxies_the_header_is_ignored(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_TRUSTED_PROXIES": ""}):
            self.assertEqual(client_address("10.0.0.5", "203.0.113.9"), "10.0.0.5")

    def test_a_trusted_proxy_names_its_client(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_TRUSTED_PROXIES": "10.0.0.5, 10.0.1.0/24"}):
            self.assertEqual(client_address("10.0.0.5", "203.0.113.9"), "203.0.113.9")
            # A chain of trusted proxies is walked from the right.
            self.assertEqual(client_address("10.0.0.5", "203.0.113.9, 10.0.1.7"), "203.0.113.9")
            # Whatever a client put on the left of the header is not believed.
            self.assertEqual(client_address("10.0.0.5", "1.1.1.1, 203.0.113.9"), "203.0.113.9")

    def test_an_untrusted_peer_cannot_claim_an_address(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_TRUSTED_PROXIES": "10.0.0.5"}):
            self.assertEqual(client_address("198.51.100.4", "203.0.113.9"), "198.51.100.4")

    def test_a_value_that_is_not_an_address_is_not_used(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_TRUSTED_PROXIES": "10.0.0.5"}):
            self.assertEqual(client_address("10.0.0.5", "evil<script>"), "10.0.0.5")

    def test_audit_rows_and_throttles_use_it(self) -> None:
        request = SimpleNamespace(client=SimpleNamespace(host="10.0.0.5"),
                                  headers={"x-forwarded-for": "203.0.113.9"})
        with mock.patch.dict(os.environ, {"DSPM_TRUSTED_PROXIES": "10.0.0.5"}):
            self.assertEqual(request_address(request), "203.0.113.9")
            self.assertEqual(app_module._login_ip_rate_key(request), "ip:203.0.113.9")
            self.assertEqual(app_module._client_host(request), "203.0.113.9")
        source = (ROOT / "backend" / "app.py").read_text(encoding="utf-8")
        middleware = source[source.index("async def secure_response_headers("):][:600]
        self.assertIn("request_address(request)", middleware)


class VerifyingFromTheConsoleTest(_HttpCase):
    """C4 polish: whoever reads a workspace's trail can have its chain checked, for that
    workspace only, without shell access to the server."""

    def setUp(self) -> None:
        super().setUp()
        store.create_user("audit-auditor", security.hash_password(PASSWORD), "auditor", TENANT)
        for index in range(5):
            store.audit(TENANT, "alice", f"test.step_{index}", {"n": index})
        store.audit(OTHER, "bob", "test.elsewhere", {})
        self.auditor = self._as("audit-auditor", "auditor")

    def _verify(self, headers: dict | None = None):
        return self.client.get("/api/audit/verify", headers=headers or self.auditor)

    def test_an_intact_trail_says_so(self) -> None:
        response = self._verify()
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual((body["tenant_id"], body["ok"], body["problem_count"]), (TENANT, True, 0))
        self.assertGreaterEqual(body["rows"], 5)
        self.assertTrue(body["verified_at"])

    def test_a_tampered_row_is_named(self) -> None:
        conn = self._raw()
        conn.execute("UPDATE audit_events SET detail_json = '{\"n\": 99}' WHERE tenant_id = ? AND seq = 3", (TENANT,))
        conn.commit()
        body = self._verify().json()
        self.assertFalse(body["ok"])
        self.assertEqual(body["problem_count"], 1)
        self.assertEqual(body["problems"][0]["seq"], 3)

    def test_it_checks_this_workspace_and_says_nothing_of_another(self) -> None:
        conn = self._raw()
        conn.execute("UPDATE audit_events SET actor = 'mallory' WHERE tenant_id = ?", (OTHER,))
        conn.commit()
        body = self._verify().json()
        self.assertTrue(body["ok"], "another workspace's broken chain is not this one's")
        self.assertNotIn(OTHER, json.dumps(body))

    def test_it_needs_the_audit_permission(self) -> None:
        self.assertEqual(self._verify(self._as("audit-analyst", "analyst")).status_code, 403)
        self.assertEqual(self._verify(self._as("audit-viewer", "viewer")).status_code, 403)

    def test_the_check_is_itself_recorded(self) -> None:
        self._verify()
        events = [event for event in store.read_audit_log(TENANT, 50) if event["action"] == "audit.verified"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["actor"], "audit-auditor")
        self.assertEqual(events[0]["detail"]["ok"], True)
        self.assertTrue(self._verify().json()["ok"], "and recording it leaves the chain intact")

    def test_it_is_throttled_per_workspace(self) -> None:
        with mock.patch.object(app_module, "AUDIT_VERIFY_THROTTLE",
                               app_module.RouteThrottle("audit_verify_test", 2, 3600)):
            self.assertEqual([self._verify().status_code for _ in range(3)], [200, 200, 429])

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_the_console_says_what_was_found(self) -> None:
        intact = ("describeAuditIntegrity({ok: true, rows: 1234, problem_count: 0, problems: [], "
                  "sealed_through_seq: 40, sealed_at: '2026-09-24T09:00:00Z', pruned_through_seq: 0, "
                  "verified_at: '2026-09-24T10:00:00Z'})")
        broken = ("describeAuditIntegrity({ok: false, rows: 1234, problem_count: 2, "
                  "problems: [{seq: 17, problem: 'content does not match its hash (the row was changed)'}], "
                  "sealed_through_seq: 0, pruned_through_seq: 0, verified_at: '2026-09-24T10:00:00Z'})")
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "scenario.json"
            fixture.write_text(json.dumps({"drive": "evaluate", "permissions": ["audit.view"],
                                           "evaluate": {"intact": intact, "broken": broken}}), encoding="utf-8")
            # Node writes UTF-8; the Windows default code page would mangle the en dash.
            result = subprocess.run([NODE, str(SMOKE), str(fixture)], cwd=ROOT, capture_output=True,
                                    encoding="utf-8", timeout=180, check=False)
        values = json.loads(result.stdout.strip().splitlines()[-1])["values"]
        self.assertTrue(values["intact"].startswith("Intact: all 1,234 events"), values["intact"])
        self.assertIn("Events 1–40 were sealed", values["intact"])
        self.assertTrue(values["broken"].startswith("Broken: 2 problems in 1,234 events"), values["broken"])
        self.assertIn("event 17: content does not match its hash", values["broken"])


class VerificationStreamsTheTrailTest(_TempDatabase):
    """Verifying read a tenant's whole trail into a list first: 20 MiB at 20,000 rows,
    measured, and it grows with the trail. It is streamed from the cursor now, and a trail
    broken everywhere reports the first PROBLEM_LIMIT problems and how many there were."""

    def test_the_store_hands_the_rows_over_as_they_are_read(self) -> None:
        for index in range(3):
            store.audit(TENANT, "alice", "test.step", {"n": index})
        seen = {}
        real = audit_chain.verify_chain

        def spy(tenant, rows, head):
            seen["type"] = type(rows)
            return real(tenant, rows, head)

        with mock.patch.object(audit_chain, "verify_chain", spy):
            self.assertTrue(self._verify()["ok"])
        self.assertFalse(issubclass(seen["type"], (list, tuple)), "a materialised list, not a stream")

    def test_a_chain_is_read_once(self) -> None:
        rows = [
            {"id": seq, "seq": seq, "timestamp": "t", "actor": "a", "action": "x", "detail_json": "{}",
             "prev_hash": "", "row_hash": ""}
            for seq in range(1, 4)
        ]
        prev = ""
        for row in rows:
            row["prev_hash"] = prev
            row["row_hash"] = prev = audit_chain.row_hash(prev, "t", row["seq"], "t", "a", "x", "{}")
        head = {"last_seq": 3, "last_hash": prev}
        result = audit_chain.verify_chain("t", iter(rows), head)
        self.assertEqual((result["ok"], result["rows"]), (True, 3))

    def test_a_trail_broken_everywhere_is_counted_not_listed(self) -> None:
        rows = ({"id": seq, "seq": seq, "timestamp": "t", "actor": "a", "action": "x", "detail_json": "{}",
                 "prev_hash": "", "row_hash": "wrong"} for seq in range(1, 1501))
        result = audit_chain.verify_chain("t", rows, {"last_seq": 1500, "last_hash": "wrong"})
        self.assertFalse(result["ok"])
        self.assertEqual(len(result["problems"]), audit_chain.PROBLEM_LIMIT)
        self.assertGreater(result["problem_count"], 1500)


class TheChainFunctionTest(unittest.TestCase):

    def test_every_field_is_in_the_hash(self) -> None:
        base = ("prev", "t", 1, "2026-01-01", "actor", "action", "{}")
        digest = audit_chain.row_hash(*base)
        for index in range(len(base)):
            changed = list(base)
            changed[index] = 2 if index == 2 else f"{changed[index]}x"
            self.assertNotEqual(audit_chain.row_hash(*changed), digest, f"field {index} is not covered")


if __name__ == "__main__":
    unittest.main()
