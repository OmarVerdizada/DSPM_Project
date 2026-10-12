"""B3: a scan the console starts is run by workers, and the console only follows the ledger.

The fundamentals put workers on the ledger (`tests/test_work_queue.py`). This is the
other half: with ``DSPM_SCAN_EXECUTION=queue`` the request plans the scan, publishes its
partitions and returns a job that watches the ledger, while `python main.py worker`
processes do the scanning - and the answer is the same report inline execution writes.

What must stay true whatever the queue does:

- a queue that cannot be reached costs the scan nothing: the plan is already written, so
  the scan runs in this process instead, and the audit trail says so;
- cancelling the job stops the workers, because they read the scan's status before they
  run anything;
- waiting too long is the job's problem, not the scan's: the scan is left alone, since a
  worker may still be running it.
"""

from __future__ import annotations

import os
import threading
import time
import unittest
from unittest import mock
from unittest.mock import MagicMock

from backend import app as app_module, partition_worker, partitioned_scan, store, work_queue
from backend.work_queue import Delivery, LedgerQueue
from discovery.discovery_engine import ScanConfig
from tests.test_partitioned_local_scan import TENANT, _LocalTest

REQUEST_PATH = "enterprise_test_data"


class _QueuedTest(_LocalTest):
    """A console scan of the temp estate, with the request the API would have validated."""

    def _settings(self, name: str) -> dict:
        return dict(
            tenant_id=TENANT, local_path=str(self.estate), max_depth=4, walk_local_path=True,
            persistent_cache_enabled=False, incremental_enabled=False, max_workers=2,
            cache_dir=str(self.base / f"{name}-cache"),
        )

    def _scan_config(self, name: str) -> ScanConfig:
        return ScanConfig(**self._settings(name))

    def _rebuild(self, name: str):
        # A worker rebuilds the engine from the stored request; here the estate is a
        # temp folder, so the test hands the worker the same configuration instead.
        return lambda record: self._scan_config(name)

    def _payload(self) -> object:
        return app_module.ScanRequest(local_path=REQUEST_PATH, scan_label="estate", async_scan=True)

    def _principal(self) -> object:
        return app_module.Principal(subject="analyst@corp", role="analyst", tenant_id=TENANT, auth_type="jwt")

    def _job(self, **overrides) -> MagicMock:
        state = {"id": "job-queued", "cancel_requested": False, "progress": 0, "message": ""}
        state.update(overrides)
        return MagicMock(**state)

    def _queued(self, queue) -> tuple:
        """Queue execution, a small partition budget, and this queue - as a set of patches."""
        return (
            mock.patch.dict(os.environ, {"DSPM_SCAN_EXECUTION": "queue"}),
            mock.patch.object(partitioned_scan, "partition_max_files", return_value=3),
            mock.patch.object(work_queue, "work_queue_from_env", return_value=queue),
            mock.patch.object(app_module, "evaluate_alerts", return_value=[]),
        )


class TheConsoleHandsTheScanToWorkersTest(_QueuedTest):

    def test_a_queued_scan_is_published_and_a_worker_finishes_it(self) -> None:
        self._use_database("queued")
        queue = LedgerQueue()
        job = self._job()
        answered: list[dict] = []
        failed: list[BaseException] = []

        def console() -> None:
            patches = self._queued(queue)
            for started in patches:
                started.start()
            try:
                answered.append(app_module._run_partitioned_scan_payload(
                    self._scan_config("queued"), self._payload(), self._principal(), job))
            except BaseException as exc:  # surfaced by the assertions below
                failed.append(exc)
            finally:
                for started in reversed(patches):
                    started.stop()

        thread = threading.Thread(target=console, name="console-job")
        thread.start()
        try:
            deadline = time.monotonic() + 120
            while queue.take("probe") is None and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertIsNotNone(queue.take("probe"), f"nothing was queued for the workers: {failed}")
            # The console is following the ledger, not scanning: the work is the worker's.
            partition_worker.run_worker(queue, self._rebuild("queued"), worker_id="worker-a", stop_when_idle=True)
        finally:
            thread.join(timeout=180)
        self.assertFalse(failed, f"the console job failed: {failed}")
        self.assertFalse(thread.is_alive(), "the console job never noticed the scan had finished")

        (report,) = answered
        scan_id = report["scan_id"]
        self.assertEqual(store.read_partitioned_scan(TENANT, scan_id)["status"], "done")
        self.assertEqual({unit["status"] for unit in store.list_scan_partitions(TENANT, scan_id)}, {"done"})
        walked, _ = self._single_walk(self._scan_config("queued"))
        self.assertEqual([f["path"] for f in store.read_scan_report(TENANT, scan_id)["files"]], walked)
        self.assertEqual(report["file_count"], len(walked))
        self.assertGreater(job.progress, 7)

    def test_a_queue_it_cannot_reach_runs_the_scan_here(self) -> None:
        self._use_database("unreachable-queue")
        job = self._job()
        with mock.patch.dict(os.environ, {"DSPM_SCAN_EXECUTION": "queue"}), \
                mock.patch.object(partitioned_scan, "partition_max_files", return_value=3), \
                mock.patch.object(work_queue, "work_queue_from_env",
                                  side_effect=RuntimeError("DSPM_WORK_QUEUE must be ledger, not 'kafka'")), \
                mock.patch.object(app_module, "evaluate_alerts", return_value=[]):
            report = app_module._run_partitioned_scan_payload(
                self._scan_config("unreachable-queue"), self._payload(), self._principal(), job)
        scan_id = report["scan_id"]
        self.assertEqual(store.read_partitioned_scan(TENANT, scan_id)["status"], "done")
        walked, _ = self._single_walk(self._scan_config("unreachable-queue"))
        self.assertEqual([f["path"] for f in store.read_scan_report(TENANT, scan_id)["files"]], walked)

    def test_a_synchronous_request_is_never_queued(self) -> None:
        self._use_database("sync")
        queue = MagicMock()
        with mock.patch.dict(os.environ, {"DSPM_SCAN_EXECUTION": "queue"}), \
                mock.patch.object(partitioned_scan, "partition_max_files", return_value=3), \
                mock.patch.object(work_queue, "work_queue_from_env", return_value=queue), \
                mock.patch.object(app_module, "evaluate_alerts", return_value=[]):
            report = app_module._run_partitioned_scan_payload(
                self._scan_config("sync"), self._payload(), self._principal())
        queue.publish.assert_not_called()
        self.assertEqual(store.read_partitioned_scan(TENANT, report["scan_id"])["status"], "done")


class FollowingTheLedgerTest(_QueuedTest):

    def _planned(self, name: str) -> dict:
        self._use_database(name)
        record = partitioned_scan.start_partitioned_scan(
            TENANT, self._scan_config(name), request={"local_path": REQUEST_PATH}, scan_label="estate", max_files=3)
        self.assertIsNotNone(record)
        # The plan grows while units run (W3.1); these tests count every unit.
        self.assertEqual(partitioned_scan.wait_for_plan(TENANT, record["scan_id"], 60), "planned")
        return record

    def test_cancelling_the_job_marks_the_scan_cancelled_and_the_workers_drop_it(self) -> None:
        record = self._planned("cancelled")
        with self.assertRaisesRegex(partitioned_scan.ScanCancelled, "cancelled"):
            partitioned_scan.follow_partitioned_scan(
                TENANT, record["scan_id"], job=self._job(cancel_requested=True), poll_seconds=0.01)
        stored = store.read_partitioned_scan(TENANT, record["scan_id"])
        # W3.2: durable on the record - no sweep or worker ever resumes a cancelled scan.
        self.assertEqual((stored["status"], stored["error"]), ("cancelled", "Scan cancelled"))

        queue = LedgerQueue()
        self.assertIsNone(queue.take("worker-a"), "a cancelled scan was still handed to the workers")
        unit = store.list_scan_partitions(TENANT, record["scan_id"])[0]
        delivery = Delivery(tenant_id=TENANT, scan_id=record["scan_id"], partition_id=unit["partition_id"])
        self.assertEqual(partition_worker.handle_delivery(queue, delivery, self._rebuild("cancelled"),
                                                          worker_id="worker-a"), "dropped")
        self.assertEqual({u["status"] for u in store.list_scan_partitions(TENANT, record["scan_id"])}, {"queued"})

    def test_waiting_too_long_is_the_jobs_problem_and_leaves_the_scan_alone(self) -> None:
        record = self._planned("no-worker")
        with self.assertRaisesRegex(partitioned_scan.ScanStopped, "no worker finished"):
            partitioned_scan.follow_partitioned_scan(
                TENANT, record["scan_id"], job=self._job(), poll_seconds=0.01, wait_seconds=1)
        self.assertEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "running",
                         "the job gave up, and took the scan with it")

    def test_it_reports_what_the_ledger_says_and_returns_the_report(self) -> None:
        record = self._planned("following")
        scan_id = record["scan_id"]
        job = self._job()
        seen: list[str] = []

        def run_the_partitions() -> None:
            # One worker, started once the follower is watching.
            time.sleep(0.2)
            partition_worker.run_worker(work_queue.LedgerQueue(), self._rebuild("following"),
                                        worker_id="worker-a", stop_when_idle=True)

        job.message = ""
        watcher = threading.Thread(target=run_the_partitions, name="worker")
        watcher.start()
        try:
            report = partitioned_scan.follow_partitioned_scan(TENANT, scan_id, job=job, poll_seconds=0.05)
        finally:
            watcher.join(timeout=180)
            seen.append(str(job.message))
        self.assertEqual(report["scan_id"], scan_id)
        self.assertEqual(store.read_partitioned_scan(TENANT, scan_id)["status"], "done")
        self.assertTrue(any("worker" in message.lower() or "finalizing" in message.lower() for message in seen),
                        f"the job never said what the ledger was doing: {seen}")

    def test_only_queued_partitions_are_published(self) -> None:
        record = self._planned("republish")
        units = store.list_scan_partitions(TENANT, record["scan_id"])
        self.assertEqual(partitioned_scan.run_queued_partition(
            record, self._scan_config("republish"), units[0]["partition_id"], worker_id="worker-a"), "written")
        queue = MagicMock()
        queue.publish.side_effect = lambda _tenant, _scan, ids: len(list(ids))
        self.assertEqual(partitioned_scan.enqueue_partitioned_scan(record, queue), len(units) - 1)
        published = list(queue.publish.call_args[0][2])
        self.assertNotIn(units[0]["partition_id"], published, "a partition already written was queued again")


class TheSettingsTest(unittest.TestCase):

    def test_execution_is_inline_unless_the_environment_says_queue(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_SCAN_EXECUTION", None)
            self.assertFalse(partitioned_scan.queued_execution())
        with mock.patch.dict(os.environ, {"DSPM_SCAN_EXECUTION": "queue"}):
            self.assertTrue(partitioned_scan.queued_execution())
        with mock.patch.dict(os.environ, {"DSPM_SCAN_EXECUTION": "workers"}):
            self.assertFalse(partitioned_scan.queued_execution())

    def test_the_queue_wait_is_a_day_by_default_and_always_a_sane_number(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_SCAN_QUEUE_MAX_SECONDS", None)
            self.assertEqual(partitioned_scan.queue_wait_seconds(), 86_400)
        for value, expected in (("not-a-number", 86_400), ("0", 1), ("99999999", 30 * 24 * 3600)):
            with self.subTest(value=value), mock.patch.dict(os.environ, {"DSPM_SCAN_QUEUE_MAX_SECONDS": value}):
                self.assertEqual(partitioned_scan.queue_wait_seconds(), expected)


if __name__ == "__main__":
    unittest.main()
