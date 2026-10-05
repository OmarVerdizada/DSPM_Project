"""W2.4: a job's row says who runs it and whether they are alive; recovery takes over
only the jobs whose owner is gone.

The executor is in memory, and startup used to mark every queued or running row failed -
the jobs a live queue worker or a second backend was running included. A scan that
paused (no progress, a full disk) and would be resumed was recorded failed. A cancel
reached only the process holding the job, a schedule could start while its last run was
still going, and the ledger queue gave every worker the oldest scan's partition.
"""
from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from backend import db, jobs, store
from backend.partitioned_scan import ScanPaused

REQUEST = {"local_path": "estate", "max_depth": 4}


def _wait(predicate, seconds: float = 10.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


class _Database(unittest.TestCase):
    def setUp(self) -> None:
        # A job's last row write can trail its in-memory state by a moment.
        self._dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._previous_path = store.DB_PATH
        if not db.is_postgres():
            store.DB_PATH = Path(self._dir.name) / "jobs.sqlite"
        self._env = mock.patch.dict(os.environ, {"DSPM_ARTIFACT_DIR": str(Path(self._dir.name) / "artifacts")})
        self._env.start()
        store.init_db()
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "jobs")

    def tearDown(self) -> None:
        self._env.stop()
        store.DB_PATH = self._previous_path
        self._dir.cleanup()

    def _row(self, job_id: str, status: str = "running", *, host: str = "other-host", pid: int = 4242,
             instance: str = "other-instance", beat_age: float = 0.0) -> None:
        now = datetime.now(timezone.utc)
        store.record_job({"id": job_id, "tenant_id": self.tenant, "status": status, "progress": 40,
                          "message": "Running", "created_at": now.isoformat(),
                          "owner_host": host, "owner_pid": pid, "owner_instance": instance})
        if beat_age:
            with db.tenant_scope(self.tenant), store._connect() as conn:
                conn.execute("UPDATE scan_jobs SET heartbeat_at = ? WHERE id = ? AND tenant_id = ?",
                             ((now - timedelta(seconds=beat_age)).isoformat(), job_id, self.tenant))

    def _status(self, job_id: str) -> str:
        return store.read_job(self.tenant, job_id)["status"]


class WhoseJobIsItTest(unittest.TestCase):

    def test_the_owner_states(self) -> None:
        now = datetime.now(timezone.utc)
        fresh, stale = now.isoformat(), (now - timedelta(seconds=600)).isoformat()

        def state(row, alive=True):
            return store.job_owner_state(row, this_instance="me", this_host="here", now=now,
                                         stale_after_seconds=120, pid_alive=lambda _pid: alive)

        self.assertEqual(state({"owner_instance": "me"}), "alive")
        self.assertEqual(state({"owner_instance": ""}), "gone", "a row without an owner is orphaned")
        same_host = {"owner_instance": "x", "owner_host": "here", "owner_pid": 7, "heartbeat_at": fresh}
        self.assertEqual(state(same_host, alive=True), "alive")
        self.assertEqual(state(same_host, alive=False), "gone", "its process is not running")
        self.assertEqual(state({**same_host, "heartbeat_at": stale}, alive=True), "gone", "a reused pid")
        other = {"owner_instance": "x", "owner_host": "elsewhere", "owner_pid": 7}
        self.assertEqual(state({**other, "heartbeat_at": fresh}, alive=False), "alive")
        self.assertEqual(state({**other, "heartbeat_at": stale}), "gone")
        self.assertEqual(state({**other, "heartbeat_at": "garbage"}), "gone")


class RecoveryTakesOverOnlyOrphansTest(_Database):

    def test_a_live_owners_job_is_left_alone_and_a_dead_ones_is_recovered(self) -> None:
        self._row("job-live", host="other-host", beat_age=5)
        self._row("job-dead", host="other-host", beat_age=900)
        self._row("job-legacy", host="", pid=0, instance="")
        recovered = store.recover_interrupted_jobs(this_instance="new", this_host="here")
        self.assertEqual(recovered, 2)
        self.assertEqual(self._status("job-live"), "running", "a live worker's job was taken over")
        self.assertEqual(self._status("job-dead"), "failed")
        self.assertEqual(self._status("job-legacy"), "failed")

    def test_a_job_on_this_host_whose_process_is_gone_is_recovered_at_once(self) -> None:
        self._row("job-local", host="here", pid=999_999, beat_age=1)
        store.recover_interrupted_jobs(this_instance="new", this_host="here", pid_alive=lambda _pid: False)
        self.assertEqual(self._status("job-local"), "failed")

    def test_a_cancel_asked_for_ends_cancelled_and_a_resumable_scan_pauses(self) -> None:
        self._row("job-cancel", beat_age=900)
        self.assertTrue(store.request_job_cancel(self.tenant, "job-cancel"))
        self._row("job-resume", beat_age=900)
        store.register_partitioned_scan(self.tenant, "scan-r", job_id="job-resume", request=REQUEST,
                                        header={"timestamp": "t"})
        store.recover_interrupted_jobs(this_instance="new", this_host="here")
        self.assertEqual(self._status("job-cancel"), "cancelled")
        record = store.read_job(self.tenant, "job-resume")
        self.assertEqual(record["status"], "paused", "a scan the sweep continues is not failed")
        self.assertIsNone(record["finished_at"])
        self.assertIn("continues automatically", record["error"])

    def test_with_resuming_off_a_resumable_scan_asks_for_a_re_run(self) -> None:
        self._row("job-resume", beat_age=900)
        store.register_partitioned_scan(self.tenant, "scan-r", job_id="job-resume", request=REQUEST,
                                        header={"timestamp": "t"})
        store.recover_interrupted_jobs(resuming=False, this_instance="new", this_host="here")
        self.assertEqual(self._status("job-resume"), "failed")

    def test_a_paused_job_takes_its_scans_outcome(self) -> None:
        for job_id, scan_id in (("job-done", "scan-done"), ("job-fail", "scan-fail")):
            self._row(job_id, beat_age=900)
            store.register_partitioned_scan(self.tenant, scan_id, job_id=job_id, request=REQUEST,
                                            header={"timestamp": "t"})
        store.recover_interrupted_jobs(this_instance="new", this_host="here")
        store.mark_partitioned_scan(self.tenant, "scan-done", "done")
        store.mark_partitioned_scan(self.tenant, "scan-fail", "failed", error="share went away")
        self.assertEqual(store.reconcile_paused_jobs(), 2)
        done = store.read_job(self.tenant, "job-done")
        self.assertEqual((done["status"], done["scan_id"], done["progress"]), ("completed", "scan-done", 100))
        failed = store.read_job(self.tenant, "job-fail")
        self.assertEqual((failed["status"], failed["error"]), ("failed", "share went away"))


class ThisProcessRunsItsJobsTest(_Database):

    def test_a_job_names_this_process_and_its_heartbeat_moves(self) -> None:
        release = threading.Event()
        job = jobs.create_job(self.tenant, lambda job: release.wait(10) and {"scan_id": "scan-x"})
        try:
            self.assertTrue(_wait(lambda: job.status == "running"))
            record = store.read_job(self.tenant, job.id)
            self.assertEqual((record["owner_host"], record["owner_pid"]), (jobs.HOST, jobs.PID))
            with db.tenant_scope(self.tenant), store._connect() as conn:
                conn.execute("UPDATE scan_jobs SET heartbeat_at = '2000-01-01T00:00:00+00:00' WHERE id = ?",
                             (job.id,))
            self.assertEqual(jobs.heartbeat_once(), 1)
            self.assertNotEqual(store.read_job(self.tenant, job.id)["heartbeat_at"], "2000-01-01T00:00:00+00:00")
            # A restart elsewhere does not take over a job whose owner is alive.
            store.recover_interrupted_jobs(this_instance="another", this_host=jobs.HOST)
            self.assertEqual(self._status(job.id), "running")
        finally:
            release.set()
        self.assertTrue(_wait(lambda: self._status(job.id) == "completed"))
        self.assertEqual(store.read_job(self.tenant, job.id)["scan_id"], "scan-x", "the result pointer")

    def test_a_cancel_asked_through_the_row_is_carried_out_by_the_owner(self) -> None:
        job = jobs.create_job(self.tenant, lambda job: _wait(lambda: job.cancel_requested, 10) and {})
        self.assertTrue(_wait(lambda: job.status == "running"))
        # Another backend asks: it has no copy of the job, only its row.
        with mock.patch.object(jobs, "get_job", return_value=None):
            self.assertTrue(jobs.request_cancel(self.tenant, job.id))
        self.assertEqual(job.status, "running", "nothing in this process was told yet")
        jobs.heartbeat_once()
        self.assertTrue(_wait(lambda: self._status(job.id) == "cancelled"))

    def test_a_paused_scan_is_paused_not_failed_and_resumes_under_its_id(self) -> None:
        def pauses(job):
            raise ScanPaused("Scan paused: no part of it finished for a long time")

        job = jobs.create_job(self.tenant, pauses)
        self.assertTrue(_wait(lambda: self._status(job.id) == "paused"))
        self.assertEqual(jobs.active_job_count(self.tenant), 0, "a paused job holds no slot")
        again = jobs.create_job(self.tenant, lambda job: {"scan_id": "scan-y"}, job_id=job.id)
        self.assertTrue(_wait(lambda: self._status(job.id) == "completed"))
        self.assertEqual(again.resumes, 1)
        self.assertEqual(store.read_job(self.tenant, job.id)["resumes"], 1)

    def test_a_paused_job_is_cancelled_with_its_scan(self) -> None:
        def pauses(job):
            raise ScanPaused("Scan paused: free disk on the data volume is low")

        job = jobs.create_job(self.tenant, pauses)
        store.register_partitioned_scan(self.tenant, "scan-p", job_id=job.id, request=REQUEST,
                                        header={"timestamp": "t"})
        self.assertTrue(_wait(lambda: self._status(job.id) == "paused"))
        self.assertTrue(jobs.request_cancel(self.tenant, job.id))
        self.assertEqual((job.status, self._status(job.id)), ("cancelled", "cancelled"))
        self.assertEqual(store.read_partitioned_scan(self.tenant, "scan-p")["status"], "failed",
                         "the sweep would have resumed a cancelled scan")


class ASchedulesRunsDoNotOverlapTest(_Database):

    def test_a_schedule_whose_last_run_is_still_going_is_skipped(self) -> None:
        from backend import app as app_module

        schedule = store.create_scan_schedule(self.tenant, name="nightly", request=REQUEST, interval_seconds=3600,
                                              first_run_at=datetime.now(timezone.utc), created_by="t")
        self._row("job-still-running", beat_age=1)
        store.record_schedule_run(self.tenant, schedule["schedule_id"], status="started", job_id="job-still-running")
        schedule = store.read_scan_schedule(self.tenant, schedule["schedule_id"])
        with mock.patch.object(app_module, "create_job", side_effect=AssertionError("a second run started")):
            app_module._start_scheduled_scan(schedule)
        after = store.read_scan_schedule(self.tenant, schedule["schedule_id"])
        self.assertEqual((after["last_status"], after["last_job_id"]), ("skipped", "job-still-running"))
        self.assertIn("still going", after["last_error"])


class TheLedgerQueueTakesTurnsTest(unittest.TestCase):

    def test_workspaces_then_scans_take_turns(self) -> None:
        from backend import work_queue

        scans = [{"tenant_id": tenant, "scan_id": scan, "status": "running"}
                 for tenant, scan in (("a", "a1"), ("a", "a2"), ("b", "b1"))]
        queue = work_queue.LedgerQueue()
        with mock.patch.object(work_queue.store, "list_unfinished_partitioned_scans", return_value=scans), \
                mock.patch.object(work_queue.store, "first_queued_partition", side_effect=lambda t, s: f"{s}-p"), \
                mock.patch("backend.partitioned_scan.runs_here", return_value=True):
            taken = [queue.take("w").scan_id for _ in range(6)]
        self.assertEqual(taken, ["a1", "b1", "a2", "b1", "a1", "b1"])


if __name__ == "__main__":
    unittest.main()
