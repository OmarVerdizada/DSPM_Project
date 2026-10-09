"""C0.4: "a process started at revision N refuses a live N+1 database within one bounded
check interval; no further writes land."

The data routes were already refused (tests/test_c11_backup_and_schema.py). What still
wrote were the backend's own threads. Each now asks backend.schema_guard - the one state
the HTTP guard and the scan worker read - at the top of its pass, and a pass on an N+1
database writes nothing: the scan scheduler, the scan resumer, the SIEM forwarder, the
alert deliverer, the installation's own alerts, the search reconciler, housekeeping and
the scan worker. Without a mismatch each works as before. The database is asked at most
once per DSPM_SCHEMA_CHECK_SECONDS, so a database moved ahead is noticed within one.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from cryptography.fernet import Fernet

from backend import (
    alert_delivery, backup, housekeeping, migrations, ops_alerts, partition_worker, scan_resumer, scan_scheduler,
    schema_guard, search, siem, store,
)


class _Writers(unittest.TestCase):
    """A database of its own, the guard forgotten before and after each test."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="sentro-c04-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = mock.patch.dict(os.environ, {
            "DSPM_DB_URL": "", "DSPM_ENV": "local", "DSPM_BACKUP_DIR": str(self.tmp / "backups"),
            "DSPM_ARTIFACT_DIR": str(self.tmp / "artifacts"), "DSPM_BACKUP_KEY": Fernet.generate_key().decode(),
            "DSPM_SCHEMA_CHECK_SECONDS": "30"})
        patcher.start()
        self.addCleanup(patcher.stop)
        original = store.DB_PATH
        store.DB_PATH = self.tmp / "dspm.sqlite"
        self.addCleanup(setattr, store, "DB_PATH", original)
        migrations.upgrade()
        if store.get_tenant("default") is None:
            store.create_tenant("default", "Default")
        schema_guard.reset()
        self.addCleanup(schema_guard.reset)
        self.watcher = sqlite3.connect(store.DB_PATH)
        self.addCleanup(self.watcher.close)

    def newer(self) -> int:
        """Another release upgrades the database; the guard's next question sees it."""
        future = migrations.expected_revision() + 1
        with store._connect() as conn:
            conn.execute("INSERT INTO schema_migrations (revision, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                         (future, "from a newer release", "x", "2026-10-01T00:00:00+00:00"))
        schema_guard.reset()
        return future

    def version(self) -> int:
        """SQLite's data_version: it changes when any other connection commits a write."""
        return self.watcher.execute("PRAGMA data_version").fetchone()[0]


class TheScanSchedulerTest(_Writers):

    def setUp(self) -> None:
        super().setUp()
        self.schedule = store.create_scan_schedule("default", name="nightly", request={"scan_type": "local"})

    def test_a_due_schedule_waits_on_a_newer_schema(self) -> None:
        self.newer()
        before, start = self.version(), mock.Mock()
        self.assertEqual(scan_scheduler.run_due_schedules(start), [])
        start.assert_not_called()
        self.assertEqual(self.version(), before, "the scheduler claimed a schedule on the N+1 database")
        [schedule] = store.list_scan_schedules("default")
        self.assertEqual(schedule["next_run_at"], self.schedule["next_run_at"])

    def test_and_starts_as_before_otherwise(self) -> None:
        start = mock.Mock()
        self.assertEqual(scan_scheduler.run_due_schedules(start), [self.schedule["schedule_id"]])
        start.assert_called_once()


class TheScanResumerTest(_Writers):

    RECORD = {"tenant_id": "default", "scan_id": "scan-c04", "job_id": "job-c04", "resumable": True,
              "request": {"scan_type": "local"}}

    def _sweep(self) -> mock.Mock:
        resume = mock.Mock()
        with mock.patch.object(store, "list_unfinished_partitioned_scans", return_value=[dict(self.RECORD)]) as listed, \
                mock.patch.object(store, "claim_partitioned_scan_resume", return_value=True) as claimed:
            scan_resumer.resume_stale_scans(resume)
        self.listed, self.claimed = listed, claimed
        return resume

    def test_no_scan_is_taken_over_on_a_newer_schema(self) -> None:
        self.newer()
        before = self.version()
        resume = self._sweep()
        resume.assert_not_called()
        self.claimed.assert_not_called()
        self.assertEqual(self.version(), before)

    def test_and_one_is_taken_over_as_before_otherwise(self) -> None:
        self._sweep().assert_called_once()
        self.claimed.assert_called_once()


class TheSiemForwarderTest(_Writers):

    TARGET = {"scheme": "tcp", "host": "127.0.0.1", "port": 6514, "format": "cef"}

    def test_nothing_is_claimed_on_a_newer_schema(self) -> None:
        self.newer()
        before = self.version()
        with mock.patch.object(siem, "siem_target", return_value=dict(self.TARGET)) as target, \
                mock.patch.object(store, "claim_audit_outbox", return_value=[]) as claim:
            result = siem.drain()
        self.assertTrue(result["paused"])
        claim.assert_not_called()
        target.assert_not_called()
        self.assertEqual(self.version(), before)

    def test_and_the_outbox_is_claimed_as_before_otherwise(self) -> None:
        with mock.patch.object(siem, "siem_target", return_value=dict(self.TARGET)), \
                mock.patch.object(store, "claim_audit_outbox", return_value=[]) as claim:
            self.assertEqual(siem.drain()["sent"], 0)
        claim.assert_called_once()


class TheAlertDelivererTest(_Writers):

    def setUp(self) -> None:
        super().setUp()
        store.save_alert_channel("default", "webhook", enabled=True,
                                 config={"url": "https://hooks.example.test/sentro", "min_severity": "LOW"},
                                 secret_ref="", actor="test")
        store.save_alerts("default", "scan-c04", [{"severity": "HIGH", "title": "c04 alert"}])

    def _pass(self) -> mock.Mock:
        with mock.patch.object(alert_delivery, "deliver", return_value="delivered") as deliver, \
                mock.patch.object(ops_alerts, "maybe_evaluate"):
            alert_delivery.run_pass()
        return deliver

    def test_no_delivery_is_claimed_on_a_newer_schema(self) -> None:
        self.newer()
        before = self.version()
        self._pass().assert_not_called()
        self.assertEqual(self.version(), before, "the deliverer leased a delivery on the N+1 database")
        [alert] = store.read_alerts("default")
        self.assertEqual([item["status"] for item in alert["deliveries"]], ["pending"])

    def test_and_it_is_delivered_as_before_otherwise(self) -> None:
        self._pass().assert_called_once()


class TheInstallationsOwnAlertsTest(_Writers):

    def setUp(self) -> None:
        super().setUp()
        backup.record_attempt(False, "OSError", stage="create", trigger="schedule")
        ops_alerts._last_run = float("-inf")
        self.addCleanup(setattr, ops_alerts, "_last_run", float("-inf"))

    def test_no_alert_is_raised_on_a_newer_schema(self) -> None:
        self.newer()
        before = self.version()
        with mock.patch.object(alert_delivery, "kick"):
            ops_alerts.maybe_evaluate()
        self.assertEqual(store.read_alerts("default"), [])
        self.assertEqual(self.version(), before)

    def test_and_the_failed_backup_is_raised_as_before_otherwise(self) -> None:
        with mock.patch.object(alert_delivery, "kick"):
            ops_alerts.maybe_evaluate()
        self.assertEqual([alert["title"] for alert in store.read_alerts("default")], ["The last backup failed"])


class TheSearchReconcilerTest(_Writers):

    def test_nothing_is_compared_or_recorded_on_a_newer_schema(self) -> None:
        self.newer()
        with mock.patch.object(search, "run_search_reconciliation", return_value={"status": "in_sync"}) as run:
            self.assertIsNone(search.reconcile_pass())
        run.assert_not_called()

    def test_and_it_reconciles_as_before_otherwise(self) -> None:
        with mock.patch.object(search, "run_search_reconciliation", return_value={"status": "in_sync"}) as run:
            self.assertEqual(search.reconcile_pass(), {"status": "in_sync"})
        run.assert_called_once()


class TheHousekeepingTest(_Writers):

    def test_neither_retention_nor_a_backup_runs_on_a_newer_schema(self) -> None:
        self.newer()
        with mock.patch.object(housekeeping, "run_if_due") as retention, \
                mock.patch.object(housekeeping, "run_backup_if_due") as backup_run:
            self.assertIn("skipped", housekeeping.run_due_jobs())
        retention.assert_not_called()
        backup_run.assert_not_called()

    def test_and_both_are_looked_at_as_before_otherwise(self) -> None:
        with mock.patch.object(housekeeping, "run_if_due", return_value=None) as retention, \
                mock.patch.object(housekeeping, "run_backup_if_due", return_value=None) as backup_run:
            self.assertEqual(housekeeping.run_due_jobs(), {"retention": None, "backup": None})
        retention.assert_called_once()
        backup_run.assert_called_once()


class TheScanWorkerTest(_Writers):

    class Queue:
        def __init__(self) -> None:
            self.taken = 0

        def take(self, *args, **kwargs):
            self.taken += 1
            return None

    def test_no_partition_is_taken_on_a_newer_schema(self) -> None:
        self.newer()
        queue, stop = self.Queue(), threading.Event()
        threading.Timer(0.3, stop.set).start()
        with mock.patch.object(partition_worker, "_maintain", return_value=[]) as maintain:
            partition_worker.run_worker(queue, lambda request: None, worker_id="c04", stop=stop, idle_seconds=0.05)
        self.assertEqual(queue.taken, 0)
        maintain.assert_not_called()

    def test_and_work_is_taken_as_before_otherwise(self) -> None:
        queue = self.Queue()
        with mock.patch.object(partition_worker, "_maintain", return_value=[]):
            partition_worker.run_worker(queue, lambda request: None, worker_id="c04", stop_when_idle=True)
        self.assertEqual(queue.taken, 1)


class TheSharedGuardTest(_Writers):

    def test_one_state_for_the_http_guard_the_worker_and_the_writers(self) -> None:
        from backend import app as app_module

        self.assertIs(app_module._SCHEMA_GUARD, schema_guard.STATE)
        self.assertIs(partition_worker._SCHEMA_STATE, schema_guard.STATE)
        future = self.newer()
        self.assertTrue(schema_guard.stand_down("scan scheduler"))
        self.assertIn(f"revision {future}", app_module.schema_problem())
        self.assertEqual(schema_guard.revision(), {"applied": future, "expected": migrations.expected_revision()})

    def test_a_database_moved_ahead_is_noticed_within_one_bounded_interval(self) -> None:
        clock = [1000.0]
        asked = mock.Mock(wraps=schema_guard._revision)
        with mock.patch.dict(os.environ, {"DSPM_SCHEMA_CHECK_SECONDS": "5"}), \
                mock.patch.object(schema_guard.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(schema_guard, "_revision", asked):
            self.assertFalse(schema_guard.stand_down("scan scheduler"))
            future = migrations.expected_revision() + 1
            with store._connect() as conn:
                conn.execute("INSERT INTO schema_migrations (revision, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                             (future, "from a newer release", "x", "2026-10-01T00:00:00+00:00"))
            for moment in (1001.0, 1003.0, 1004.9):
                clock[0] = moment
                self.assertFalse(schema_guard.stand_down("scan scheduler"), "asked again inside the interval")
            self.assertEqual(asked.call_count, 1, "one database question per interval, not one per pass")
            clock[0] = 1005.0
            self.assertTrue(schema_guard.stand_down("scan scheduler"), "not noticed within one interval")
            self.assertEqual(asked.call_count, 2)

    def test_a_writer_says_once_that_it_paused_and_once_that_it_resumed(self) -> None:
        future = self.newer()
        with self.assertLogs("backend.schema_guard", level="WARNING") as logged:
            for _pass in range(3):
                self.assertTrue(schema_guard.stand_down("SIEM forwarder"))
            with store._connect() as conn:
                conn.execute("DELETE FROM schema_migrations WHERE revision = ?", (future,))
            schema_guard.STATE["checked"] = float("-inf")   # the interval has passed
            for _pass in range(3):
                self.assertFalse(schema_guard.stand_down("SIEM forwarder"))
        paused = [line for line in logged.output if "SIEM forwarder is paused" in line]
        resumed = [line for line in logged.output if "SIEM forwarder resumed" in line]
        self.assertEqual((len(paused), len(resumed)), (1, 1), logged.output)
        self.assertIn(f"revision {future}", paused[0])
        self.assertNotIn(os.environ["DSPM_BACKUP_KEY"], "\n".join(logged.output))


if __name__ == "__main__":
    unittest.main()
