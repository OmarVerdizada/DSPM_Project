"""B5: the backend prunes what grows on its own, and production refuses a plaintext dump.

Retention used to be a tool somebody had to remember to run. It now runs unattended on
the same model as the scan scheduler - claimed through the database so several backends
do it once between them - and the policy has one definition, shared with the tool.

What it may remove is deliberately narrow. Event rows past their window and finished job
records go; scan reports, findings and assets never do; a tenant under legal hold keeps
everything; artifact objects are collected only when an install asks for it by name; and
the plaintext report files Phase A stopped writing - clear-text copies of reports the
encrypted artifact tier keeps - are aged out after 90 days unless the install says 0 (C0.2).
"""

from __future__ import annotations

import os
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from backend import housekeeping, store

DAY = 24 * 3600


class _HousekeepingTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.base = Path(self._dir.name)
        self._previous_path = store.DB_PATH
        store.DB_PATH = self.base / "housekeeping.sqlite"
        self._env = mock.patch.dict(os.environ, {"DSPM_ARTIFACT_DIR": str(self.base / "artifacts")})
        self._env.start()
        store.init_db()
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "housekeeping")
        self.now = datetime(2026, 9, 17, 3, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self._env.stop()
        store.DB_PATH = self._previous_path
        self._dir.cleanup()

    def _event(self, table: str, column: str, tenant: str, age_days: int) -> None:
        stamp = (self.now - timedelta(days=age_days)).isoformat()
        with store._connect() as conn:
            if table == "audit_events":
                conn.execute(
                    f"INSERT INTO audit_events (tenant_id, actor, action, detail_json, {column}) VALUES (?, ?, ?, ?, ?)",
                    (tenant, "analyst", "scan.completed", "{}", stamp),
                )
            else:
                conn.execute(
                    f"INSERT INTO alert_events (tenant_id, scan_id, alerts_json, {column}) VALUES (?, ?, ?, ?)",
                    (tenant, "scan-1", "[]", stamp),
                )

    def _count(self, table: str) -> int:
        with store._connect() as conn:
            return int(conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"])


class ThePolicyTest(_HousekeepingTest):

    def test_old_event_rows_are_counted_and_only_deleted_when_asked(self) -> None:
        self._event("audit_events", "timestamp", self.tenant, age_days=800)
        self._event("audit_events", "timestamp", self.tenant, age_days=10)
        self._event("alert_events", "created_at", self.tenant, age_days=400)

        dry = {row["data_class"]: row for row in store.prune_event_tables(now=self.now)}
        self.assertEqual((dry["audit_events"]["eligible_rows"], dry["audit_events"]["removed_rows"]), (1, 0))
        self.assertEqual((dry["alert_events"]["eligible_rows"], dry["alert_events"]["removed_rows"]), (1, 0))
        self.assertEqual((self._count("audit_events"), self._count("alert_events")), (2, 1))

        applied = {row["data_class"]: row for row in store.prune_event_tables(now=self.now, apply=True)}
        self.assertEqual(applied["audit_events"]["removed_rows"], 1)
        self.assertEqual((self._count("audit_events"), self._count("alert_events")), (1, 0),
                         "a row inside its window was removed")

    def test_a_tenant_under_legal_hold_keeps_everything(self) -> None:
        other = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(other, "held")
        self._event("audit_events", "timestamp", self.tenant, age_days=800)
        self._event("audit_events", "timestamp", other, age_days=800)
        store.set_legal_hold(other, True, reason="litigation")

        applied = {row["data_class"]: row for row in store.prune_event_tables(now=self.now, apply=True)}
        self.assertEqual(applied["audit_events"]["removed_rows"], 1)
        self.assertEqual(applied["audit_events"]["held_tenants"], 1)
        with store._connect() as conn:
            left = [str(row["tenant_id"]) for row in conn.execute("SELECT tenant_id FROM audit_events").fetchall()]
        self.assertEqual(left, [other], "the held tenant lost rows, or the other kept them")

    def test_the_window_comes_from_the_environment(self) -> None:
        self._event("audit_events", "timestamp", self.tenant, age_days=40)
        with mock.patch.dict(os.environ, {"DSPM_RETAIN_AUDIT_DAYS": "30"}):
            applied = {row["data_class"]: row for row in store.prune_event_tables(now=self.now, apply=True)}
        self.assertEqual(applied["audit_events"]["retention_days"], 30)
        self.assertEqual(self._count("audit_events"), 0)


class TheClaimTest(_HousekeepingTest):

    def test_one_backend_runs_it_per_interval(self) -> None:
        self.assertTrue(store.claim_housekeeping_run("retention", interval_seconds=DAY, now=self.now))
        self.assertFalse(store.claim_housekeeping_run("retention", interval_seconds=DAY, now=self.now),
                         "two backends both ran the daily housekeeping")
        self.assertFalse(store.claim_housekeeping_run(
            "retention", interval_seconds=DAY, now=self.now + timedelta(hours=23)))
        self.assertTrue(store.claim_housekeeping_run(
            "retention", interval_seconds=DAY, now=self.now + timedelta(hours=25)))

    def test_a_restart_does_not_restart_the_day(self) -> None:
        self.assertTrue(housekeeping.run_if_due(now=self.now) is not None)
        self.assertIsNone(housekeeping.run_if_due(now=self.now + timedelta(hours=1)))

    def test_it_can_be_turned_off(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_RETENTION_INTERVAL_SECONDS": "0"}):
            self.assertIsNone(housekeeping.run_if_due(now=self.now))
            self.assertFalse(housekeeping.start_housekeeping())


class TheHousekeepingPassTest(_HousekeepingTest):

    def test_it_prunes_events_and_finished_jobs_and_leaves_the_rest_alone(self) -> None:
        self._event("audit_events", "timestamp", self.tenant, age_days=800)
        store.record_job({"id": "job-old", "tenant_id": self.tenant, "status": "completed", "progress": 100,
                          "message": "Completed", "created_at": (self.now - timedelta(days=60)).isoformat(),
                          "finished_at": (self.now - timedelta(days=60)).isoformat()})
        with store._connect() as conn:
            conn.execute("UPDATE scan_jobs SET updated_at = ? WHERE id = 'job-old'",
                         ((self.now - timedelta(days=60)).isoformat(),))

        summary = housekeeping.run_retention(now=self.now)
        classes = {row["data_class"]: row for row in summary["data_classes"]}
        self.assertTrue(summary["applied"])
        self.assertEqual(classes["audit_events"]["removed_rows"], 1)
        self.assertEqual(classes["scan_jobs"]["removed_rows"], 1)
        # W3.5: artifact collection is on by default; nothing here is unreferenced.
        self.assertEqual((classes["artifacts"]["skipped"], classes["artifacts"]["removed_rows"]), (False, 0))
        self.assertIsNone(store.read_job(self.tenant, "job-old"))

    def test_artifact_objects_are_collected_unless_turned_off(self) -> None:
        from backend import artifacts

        with mock.patch.dict(os.environ), mock.patch.object(artifacts, "prune", return_value=3) as prune:
            os.environ.pop("DSPM_RETENTION_PRUNE_ARTIFACTS", None)
            summary = housekeeping.run_retention(now=self.now)
        classes = {row["data_class"]: row for row in summary["data_classes"]}
        self.assertEqual((classes["artifacts"]["removed_rows"], classes["artifacts"]["skipped"]), (3, False))
        prune.assert_called_once()
        with mock.patch.dict(os.environ, {"DSPM_RETENTION_PRUNE_ARTIFACTS": "0"}), \
                mock.patch.object(artifacts, "prune", return_value=3) as off:
            summary = housekeeping.run_retention(now=self.now)
        classes = {row["data_class"]: row for row in summary["data_classes"]}
        self.assertTrue(classes["artifacts"]["skipped"])
        off.assert_not_called()

    def test_plaintext_report_files_are_kept_only_when_zero_days_says_so(self) -> None:
        """C0.2 made the window finite by default (90 days); 0 still keeps every file."""
        reports = self.base / "reports"
        reports.mkdir()
        old = reports / "1_20260101000000.json"
        recent = reports / "1_20260916000000.json"
        for path, age_days in ((old, 400), (recent, 1)):
            path.write_text("{}", encoding="utf-8")
            stamp = (self.now - timedelta(days=age_days)).timestamp()
            os.utime(path, (stamp, stamp))

        with mock.patch.dict(os.environ, {"DSPM_RETAIN_REPORT_FILE_DAYS": "0"}):
            kept = housekeeping.run_retention(now=self.now, report_dir=reports)
        self.assertNotIn("report_files", [row["data_class"] for row in kept["data_classes"]])
        self.assertTrue(old.exists(), "a report file was deleted with retention set to keep them")

        with mock.patch.dict(os.environ, {"DSPM_RETAIN_REPORT_FILE_DAYS": ""}):
            os.environ.pop("DSPM_RETAIN_REPORT_FILE_DAYS")
            summary = housekeeping.run_retention(now=self.now, report_dir=reports)
        classes = {row["data_class"]: row for row in summary["data_classes"]}
        self.assertEqual(classes["report_files"]["removed_rows"], 1)
        self.assertFalse(old.exists())
        self.assertTrue(recent.exists(), "a report file inside the window was deleted")
        self.assertEqual([path.name for path in housekeeping.plaintext_report_files(reports)], [recent.name])


class ProductionRefusesAPlaintextDumpTest(unittest.TestCase):

    def test_startup_refuses_the_export_switch_in_production(self) -> None:
        from fastapi.testclient import TestClient

        from backend import app as app_module

        with mock.patch.object(app_module, "ENVIRONMENT", "production"), \
                mock.patch.object(app_module, "PLAINTEXT_REPORT_EXPORT", True):
            with self.assertRaises(RuntimeError) as refused:
                with TestClient(app_module.app):
                    pass
        self.assertIn("DSPM_PLAINTEXT_REPORT_EXPORT", str(refused.exception))

    def test_local_development_may_still_enable_it(self) -> None:
        from fastapi.testclient import TestClient

        from backend import app as app_module

        with mock.patch.object(app_module, "ENVIRONMENT", "local"), \
                mock.patch.object(app_module, "PLAINTEXT_REPORT_EXPORT", True):
            with TestClient(app_module.app) as client:
                self.assertEqual(client.get("/api/health").status_code, 200)


class TheRetentionToolStillWorksTest(_HousekeepingTest):

    def test_the_tool_and_the_sweep_share_one_definition(self) -> None:
        import io
        import sys

        import scripts.db_retention as tool

        self._event("audit_events", "timestamp", self.tenant, age_days=800)
        captured = io.StringIO()
        with mock.patch.object(sys, "argv", ["db_retention.py"]), mock.patch.object(sys, "stdout", captured):
            self.assertEqual(tool.main(), 0)
        printed = captured.getvalue()
        self.assertIn("audit_events", printed)
        self.assertIn("would remove 1", printed)
        self.assertEqual(self._count("audit_events"), 1, "a dry run deleted a row")


if __name__ == "__main__":
    unittest.main()
