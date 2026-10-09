"""Backend audit, 2026-10, the scan pipeline: each defect the review found, pinned by the
behaviour that was wrong.

Local scans here walk a folder of the system temp directory, never one under the
checkout: the worktree path holds a dot-folder, and the walker treats everything under
one as hidden. The temp directory is under AppData, which the collector skips, so every
test that walks patches `is_skipped_scan_path`.
"""
from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch
from uuid import uuid4

from backend import app as app_module, jobs, partition_worker, partitioned_scan, scan_resumer, store
from backend.work_queue import LedgerQueue
from collectors import file_scanner
from discovery import discovery_engine
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from tests.test_partitioned_local_scan import TENANT
from tests.test_queued_scan import REQUEST_PATH, _QueuedTest


def _estate(root: Path, files: int, text: str = "nothing to see here\n") -> Path:
    estate = root / "estate"
    estate.mkdir()
    for index in range(files):
        (estate / f"file-{index:03d}.txt").write_text(f"{index} {text}", encoding="utf-8")
    return estate


class _LocalScanTest(unittest.TestCase):
    """A temp folder outside the checkout, walked with the collector's skip rules off."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="audit-pipeline-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.cache = self.root / "cache"
        for patcher in (patch.object(file_scanner, "is_skipped_scan_path", return_value=False),
                        patch.object(file_scanner, "file_owner", MagicMock(return_value="tester"))):
            patcher.start()
            self.addCleanup(patcher.stop)


# ---- 1: a stopped scan is never a complete one ----------------------------------------------------


class AStoppedScanIsNeverCompleteTest(_LocalScanTest):
    """A cancelled or over-budget scan returned a partial report that said
    `incremental.complete=True` whenever everything already submitted had finished: the
    pipelined path marked truncation only when it caught a future still running, and the
    local walk had no cancel hook. Saved, that report pruned every file it never analyzed."""

    def test_a_walk_asked_to_stop_stops_and_says_so(self) -> None:
        estate = _estate(self.root, 40)
        asked = {"n": 0}

        def stop_after_ten() -> bool:
            asked["n"] += 1
            return asked["n"] > 10

        diagnostics: dict = {}
        records = file_scanner.scan_directory(estate, diagnostics=diagnostics, cancel_check=stop_after_ten)
        self.assertEqual(len(records), 10, "the walk went on reading files after it was told to stop")
        self.assertTrue(diagnostics.get("walk_cancelled"))

    def test_a_scan_cancelled_while_it_walks_is_truncated_and_incomplete(self) -> None:
        estate = _estate(self.root, 80)
        cancelled = threading.Event()

        def progress(stage: str, completed: int, _total: int) -> None:
            if stage == "pipelining" and completed >= 10:
                cancelled.set()

        config = ScanConfig(
            tenant_id="audit-stop", local_path=str(estate), walk_local_path=True, max_workers=2,
            persistent_cache_enabled=False, incremental_scope="scope-stop",
            cancel_check=cancelled.is_set, progress_callback=progress,
        )
        report = DSPMDiscoveryEngine(config).run().to_dict()
        diagnostics = report["scan_diagnostics"]
        self.assertLess(len(report["files"]), 80, "the cancel never reached the scan")
        self.assertTrue(diagnostics.get("scan_truncated"), "a cancelled scan was not marked truncated")
        self.assertFalse(diagnostics["incremental"]["complete"], "a cancelled scan called itself complete")

    def test_records_the_pipeline_never_submitted_mark_the_scan_truncated(self) -> None:
        # A collector without a cancel hook - the SMB one hands over what it has - with
        # everything that was submitted already finished when the results are read.
        cancelled = threading.Event()
        finished = {"n": 0}

        def progress(stage: str, completed: int, _total: int) -> None:
            if stage == "pipelining":
                finished["n"] = completed

        config = ScanConfig(tenant_id="audit-stop", walk_local_path=False, max_workers=2,
                            persistent_cache_enabled=False, incremental_scope="scope-stop",
                            cancel_check=cancelled.is_set, progress_callback=progress)
        engine = DSPMDiscoveryEngine(config)

        def collect(record_callback=None) -> list[dict]:
            records = [
                {"source": "local", "path": str(self.root / f"r{index}.txt"), "name": f"r{index}.txt",
                 "extension": ".txt", "size": 5, "content": "hello", "modified_at": "2026-10-01T00:00:00+00:00"}
                for index in range(80)
            ]
            for index, record in enumerate(records):
                if index == 10:
                    cancelled.set()
                    # Everything submitted finishes before the results are read.
                    deadline = time.monotonic() + 30
                    while finished["n"] < 10 and time.monotonic() < deadline:
                        time.sleep(0.01)
                if record_callback is not None:
                    record_callback(record)
            engine.last_scan_diagnostics = {"mode": "test", "records": len(records)}
            return records

        engine._collect_records = collect
        report = engine.run().to_dict()
        diagnostics = report["scan_diagnostics"]
        self.assertEqual(len(report["files"]), 10)
        self.assertTrue(diagnostics.get("scan_truncated"), "70 records were never analyzed and nothing said so")
        self.assertEqual((diagnostics.get("scan_truncated_analyzed"), diagnostics.get("scan_truncated_total")), (10, 80))
        self.assertFalse(diagnostics["incremental"]["complete"])


# ---- 3: a failed analysis is read again, not replayed ---------------------------------------------


class AFailedAnalysisIsReadAgainTest(_LocalScanTest):
    """A record whose analysis raised (scan_error, detector_metrics.record_failed, no
    findings) went into the durable baseline like any other, and the next scan reused it
    as unchanged: the file stayed blind - "nothing found" - until someone modified it."""

    def setUp(self) -> None:
        super().setUp()
        self.tenant = f"audit-failed-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "audit failed analysis")
        self.estate = self.root / "estate"
        self.estate.mkdir()
        (self.estate / "contacts.txt").write_text("alice.wonder@example.com\nbob.builder@example.com\n", encoding="utf-8")
        (self.estate / "plain.txt").write_text("nothing to see here\n", encoding="utf-8")
        self.scope = f"scope-{uuid4().hex[:8]}"

    def _scan(self) -> dict:
        config = ScanConfig(
            tenant_id=self.tenant, local_path=str(self.estate), walk_local_path=True, max_workers=1,
            persistent_cache_enabled=False, incremental_enabled=True, incremental_scope=self.scope,
            baseline_probe=lambda key, size, mtime, version: store.probe_incremental_object(
                self.tenant, self.scope, key, size, mtime, version),
        )
        report = DSPMDiscoveryEngine(config).run().to_dict()
        store.save_scan_history(self.tenant, report)
        return report

    @staticmethod
    def _file(report: dict, name: str) -> dict:
        return next(item for item in report["files"] if item["name"] == name)

    def test_the_next_scan_reads_a_file_whose_analysis_failed(self) -> None:
        real = DSPMDiscoveryEngine._run_detectors

        def fails_on_contacts(engine, content, record, framework_ids):
            if record.get("name") == "contacts.txt":
                raise RuntimeError("detector crashed")
            return real(engine, content, record, framework_ids)

        with patch.object(DSPMDiscoveryEngine, "_run_detectors", fails_on_contacts):
            first = self._scan()
        failed = self._file(first, "contacts.txt")
        self.assertTrue(failed["detector_metrics"].get("record_failed"))
        self.assertEqual(failed["findings"], [])
        with store._connect() as conn:
            versions = {
                str(row["object_key"]).rsplit("\\", 1)[-1]: str(row["version_signature"])
                for row in conn.execute(
                    "SELECT object_key, version_signature FROM scan_object_baselines WHERE tenant_id = ? AND scope_key = ?",
                    (self.tenant, self.scope),
                ).fetchall()
            }
        self.assertEqual(set(versions), {"contacts.txt", "plain.txt"}, "the failed file left the scope's objects")
        self.assertEqual(versions["contacts.txt"], "", "the failed analysis was stored as reusable")
        self.assertTrue(versions["plain.txt"])

        second = self._file(self._scan(), "contacts.txt")
        self.assertNotEqual(second.get("incremental_scan_reason"), "durable_baseline_unchanged_file",
                            "the failed analysis was replayed as the file's result")
        self.assertTrue(second["findings"], "the file whose analysis failed stayed blind")

    def test_a_failed_row_an_older_build_wrote_is_not_offered_for_reuse(self) -> None:
        config = ScanConfig(tenant_id=self.tenant, local_path=str(self.estate), incremental_scope=self.scope)
        version = DSPMDiscoveryEngine(config).version_signature()
        record = {
            "source": "local", "path": str(self.estate / "contacts.txt"), "name": "contacts.txt",
            "extension": ".txt", "size": 52, "modified_at": "2026-10-01T00:00:00+00:00",
            "content_hash": "c" * 64, "findings": [], "risk": {"score": 0, "level": "NONE"},
            "scan_error": "RuntimeError", "detector_metrics": {"record_failed": True},
        }
        with store._lock, store._connect() as conn:
            conn.execute(
                "INSERT INTO scan_object_baselines (tenant_id, scope_key, object_key, asset_id, size, mtime, "
                "content_hash, version_signature, last_scan_id, last_seen_at, updated_at, snapshot_json) "
                "VALUES (?, ?, ?, 'a1', 52, ?, ?, ?, 's1', 'now', 'now', ?)",
                (self.tenant, self.scope, record["path"], record["modified_at"], record["content_hash"], version,
                 store.json.dumps(record)),
            )
        probed = store.probe_incremental_object(self.tenant, self.scope, record["path"], 52, record["modified_at"], version)
        self.assertEqual(probed["state"], "changed")

    def test_a_failed_analysis_in_the_reuse_index_is_read_again(self) -> None:
        # The L1 index was rehydrated from such a durable row by the scan that replayed it.
        config = ScanConfig(tenant_id=self.tenant, local_path=str(self.estate), persistent_cache_enabled=True,
                            cache_dir=str(self.cache), incremental_enabled=True)
        stamp = "2026-10-01T00:00:00+00:00"

        def record(name: str, **extra) -> dict:
            return {"source": "local", "path": str(self.estate / name), "name": name, "extension": ".txt",
                    "size": 52, "modified_at": stamp, "content_hash": "c" * 64, "findings": [],
                    "risk": {"score": 0, "level": "NONE"}, **extra}

        writer = DSPMDiscoveryEngine(config)
        writer._write_meta_sidecar(record("plain.txt"))
        writer._write_meta_sidecar(record("contacts.txt", scan_error="RuntimeError",
                                          detector_metrics={"record_failed": True}))
        writer.close_meta_index()
        reader = DSPMDiscoveryEngine(config)
        self.addCleanup(reader.close_meta_index)
        self.assertIsInstance(reader._reuse_probe(str(self.estate / "plain.txt"), 52, stamp), dict,
                              "the index entry was never written, so the next assertion proves nothing")
        self.assertIsNone(reader._reuse_probe(str(self.estate / "contacts.txt"), 52, stamp))


# ---- partitioned and queued scans: 4, 8, 11, 13, 15 ----------------------------------------------


class _Partitioned(_QueuedTest):
    """The partitioned-scan fixtures: a temp estate, a private database per test."""

    def _planned(self, name: str, *, request: dict | None = None, label: str = "estate") -> dict:
        self._use_database(name)
        record = partitioned_scan.start_partitioned_scan(
            TENANT, self._scan_config(name), request=request if request is not None else {"local_path": REQUEST_PATH},
            scan_label=label, max_files=3)
        self.assertIsNotNone(record)
        return record


class AQueuedScanNoWorkerCanRebuildRunsHereTest(_Partitioned):
    """4: with DSPM_SCAN_EXECUTION=queue a scan whose credential is a typed password is
    recorded as not resumable, workers take only resumable scans, and the resume sweep
    failed it a lease later "because its credential was a typed password" - it never ran."""

    def test_a_typed_password_scan_runs_in_the_process_that_holds_the_password(self) -> None:
        self._use_database("typed-password")
        payload = app_module.ScanRequest(local_path=REQUEST_PATH, server="fs01.corp.local", username="svc",
                                         password="typed-not-stored", scan_label="estate", async_scan=True)
        queue = MagicMock(wraps=LedgerQueue())
        patches = (*self._queued(queue), mock.patch.dict(os.environ, {"DSPM_SCAN_QUEUE_MAX_SECONDS": "20"}))
        for started in patches:
            started.start()
        try:
            report = app_module._run_partitioned_scan_payload(
                self._scan_config("typed-password"), payload, self._principal(), self._job())
        finally:
            for started in reversed(patches):
                started.stop()
        stored = store.read_partitioned_scan(TENANT, report["scan_id"])
        self.assertFalse(stored["resumable"])
        self.assertEqual(stored["status"], "done", "nothing ran a scan no worker could rebuild")
        queue.publish.assert_not_called()


class TheResumeSweepLeavesAnotherHostsScanTest(_Partitioned):
    """8: the sweep never asked `runs_here`: host B resumed host A's local scan of D:\\Shares
    and walked its own disk into A's estate - or failed it for good."""

    def test_a_local_scan_planned_elsewhere_is_not_resumed_here(self) -> None:
        record = self._planned("elsewhere")
        with store._connect() as conn:
            header = store.json.loads(conn.execute(
                "SELECT header_json FROM partitioned_scans WHERE tenant_id = ? AND scan_id = ?",
                (TENANT, record["scan_id"])).fetchone()[0])
            header["host"] = "another-host.corp.local"
            conn.execute("UPDATE partitioned_scans SET header_json = ? WHERE tenant_id = ? AND scan_id = ?",
                         (store.json.dumps(header), TENANT, record["scan_id"]))
        resume = MagicMock()
        self.assertEqual(scan_resumer.resume_stale_scans(resume, stale_after_seconds=0), [])
        resume.assert_not_called()
        self.assertEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "running")

    def test_this_hosts_scan_is_still_resumed(self) -> None:
        record = self._planned("here")
        resume = MagicMock()
        self.assertEqual(scan_resumer.resume_stale_scans(resume, stale_after_seconds=0), [record["scan_id"]])
        resume.assert_called_once()


class APartitionedScanHasItsOwnBudgetTest(unittest.TestCase):
    """11: an inline partitioned scan - the path for the largest estates - got the half hour
    a single scan gets; past it the scan was failed for good with its partitions in the
    estate and no report. It then got a day (W1.5); since W1.1 it has no wall clock at all:
    each unit has a budget, and a scan that stops making progress is paused."""

    def test_the_whole_scan_has_no_wall_clock(self) -> None:
        job = MagicMock(cancel_requested=False)
        stop_reason = partitioned_scan._stop_check(job)
        with patch.object(partitioned_scan.time, "monotonic", return_value=time.monotonic() + 30 * 86400):
            self.assertIsNone(stop_reason())
        job.cancel_requested = True
        self.assertEqual(stop_reason(), "Scan cancelled")

    def test_each_unit_carries_its_own_budget(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_SECONDS": "120"}):
            config = partitioned_scan._unit_config(
                discovery_engine.ScanConfig(local_path="."), {"local_path": ".", "max_depth": 1}, ".")
        self.assertEqual(config.max_seconds, 120)


class AFailedPartitionWaitsBeforeItsNextAttemptTest(_Partitioned):
    """13: a failed partition was queued again at once, so a share unreachable for twenty
    seconds used up all three attempts in those seconds and failed the scan."""

    def test_the_wait_grows_with_each_failure(self) -> None:
        record = self._planned("backoff")
        scan_id = record["scan_id"]
        unit = store.claim_next_partition(TENANT, scan_id, worker_id="w")
        store.fail_scan_partition(TENANT, scan_id, unit["partition_id"], "OSError", attempt=unit["attempt"])
        failed_at = datetime.fromisoformat(store.read_scan_partition(TENANT, scan_id, unit["partition_id"])["finished_at"])

        def requeued(after: float) -> int:
            return store.requeue_failed_partitions(TENANT, scan_id, max_attempts=3, backoff_seconds=30,
                                                   now=failed_at + timedelta(seconds=after))

        self.assertEqual(requeued(5), 0, "a failed partition was queued again at once")
        self.assertEqual(requeued(31), 1)
        unit = store.claim_next_partition(TENANT, scan_id, worker_id="w")
        self.assertEqual(unit["attempt"], 2)
        store.fail_scan_partition(TENANT, scan_id, unit["partition_id"], "OSError", attempt=unit["attempt"])
        failed_at = datetime.fromisoformat(store.read_scan_partition(TENANT, scan_id, unit["partition_id"])["finished_at"])
        self.assertEqual(requeued(31), 0, "the second wait did not grow")
        self.assertEqual(requeued(61), 1)

    def test_an_inline_scan_waits_before_running_a_failed_partition_again(self) -> None:
        self._use_database("inline-backoff")
        real_run = partitioned_scan.DSPMDiscoveryEngine.run
        failed_at: list[float] = []
        started: list[float] = []

        def the_last_partition_blinks_once(engine):
            # The last partition, so no other partition's run stands in for the wait.
            nothing_queued = not any(store.first_queued_partition(TENANT, scan["scan_id"])
                                     for scan in store.list_unfinished_partitioned_scans())
            if nothing_queued and not failed_at:
                failed_at.append(time.monotonic())
                raise OSError("the share blinked")
            started.append(time.monotonic())
            return real_run(engine)

        with patch.object(partitioned_scan, "partition_retry_seconds", return_value=1.0), \
                patch.object(partitioned_scan.DSPMDiscoveryEngine, "run", the_last_partition_blinks_once):
            compact = partitioned_scan.run_partitioned_scan(TENANT, self._scan_config("inline-backoff"),
                                                            request={"local_path": REQUEST_PATH}, max_files=3)
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")
        self.assertTrue(failed_at)
        self.assertGreaterEqual(started[-1] - failed_at[0], 1.0, "the failed partition ran again at once")

    def test_a_workers_maintenance_queues_it_again_once_the_wait_is_over(self) -> None:
        record = self._planned("worker-backoff")
        queue = LedgerQueue()
        with patch.object(partitioned_scan, "partition_retry_seconds", return_value=0.3), \
                patch.object(partitioned_scan.DSPMDiscoveryEngine, "run", side_effect=OSError("locked")):
            first = queue.take("worker-a")
            self.assertEqual(partition_worker.handle_delivery(queue, first, self._rebuild("worker-backoff"),
                                                              worker_id="worker-a"), "retry")
            failed = store.read_scan_partition(TENANT, record["scan_id"], first.partition_id)
            self.assertEqual(failed["status"], "failed", "the failed partition was queued again at once")
            time.sleep(0.4)
            partition_worker._maintain(queue, self._rebuild("worker-backoff"), "worker-a", 300)
        again = store.read_scan_partition(TENANT, record["scan_id"], first.partition_id)
        self.assertEqual(again["status"], "queued", "no one queued the partition again after its wait")


class ACancelledQueuedScanStopsItsWorkersTest(_Partitioned):
    """15: workers ran partitions with no stop check and no engine cancel hook, and the
    write never asked whether the scan was still running: a cancelled queued scan kept
    writing estate rows for up to half an hour."""

    def test_a_partition_running_when_its_scan_is_cancelled_is_not_written(self) -> None:
        record = self._planned("cancel-worker")
        scan_id = record["scan_id"]
        unit = store.list_scan_partitions(TENANT, scan_id)[0]
        real_run = partitioned_scan.DSPMDiscoveryEngine.run
        seen: dict = {}

        def cancelled_while_running(engine):
            store.mark_partitioned_scan(TENANT, scan_id, "failed", error="Scan cancelled")
            seen["engine_stops"] = bool(engine.config.cancel_check and engine.config.cancel_check())
            return real_run(engine)

        with patch.object(partitioned_scan.DSPMDiscoveryEngine, "run", cancelled_while_running):
            outcome = partitioned_scan.run_queued_partition(record, self._scan_config("cancel-worker"),
                                                            unit["partition_id"], worker_id="worker-a")
        self.assertEqual(outcome, "dropped")
        self.assertTrue(seen["engine_stops"], "the partition's engine was never told the scan was cancelled")
        self.assertNotEqual(store.read_scan_partition(TENANT, scan_id, unit["partition_id"])["status"], "done")
        with store._connect() as conn:
            written = conn.execute("SELECT COUNT(*) FROM assets WHERE tenant_id = ? AND current_scan_id = ?",
                                   (TENANT, scan_id)).fetchone()[0]
        self.assertEqual(written, 0, "a cancelled scan's partition wrote estate rows")

    def test_the_write_refuses_a_scan_that_is_no_longer_running(self) -> None:
        record = self._planned("refuse-write")
        scan_id = record["scan_id"]
        unit = store.claim_next_partition(TENANT, scan_id, worker_id="w")
        store.mark_partitioned_scan(TENANT, scan_id, "failed", error="Scan cancelled")
        header = {"timestamp": "2026-10-02T00:00:00+00:00", "source": "local", "summary": {}, "scan_diagnostics": {}}
        record_row = {"source": "local", "path": str(self.estate / "a_root.txt"), "name": "a_root.txt",
                      "extension": ".txt", "size": 1, "findings": [], "risk": {"score": 0, "level": "NONE"}}
        with self.assertRaises(store.ScanNotRunning):
            store.persist_partition(TENANT, scan_id, unit["partition_id"], unit["attempt"], header, [record_row],
                                    write_estate=True)
        with store._connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM assets WHERE tenant_id = ?", (TENANT,)).fetchone()[0], 0)


# ---- 14: a job that is saving is not cancelled -----------------------------------------------------


class AJobThatIsSavingIsNotCancelledTest(unittest.TestCase):
    """14: cancel_job marked the job cancelled - and freed its slot - while its result was
    being saved; the save still landed, under a job that said it was cancelled."""

    def test_a_cancel_during_the_save_is_refused_and_the_job_completes(self) -> None:
        saving = threading.Event()
        release = threading.Event()
        tenant = f"audit-jobs-{uuid4().hex[:8]}"

        def on_complete(_data: dict) -> None:
            saving.set()
            release.wait(10)

        engine = MagicMock()
        engine.return_value.run.return_value = MagicMock(to_dict=MagicMock(return_value={"files": []}))
        with patch.object(jobs, "DSPMDiscoveryEngine", engine):
            job = jobs.create_scan_job(tenant, ScanConfig(tenant_id=tenant), on_complete)
            self.assertTrue(saving.wait(10), "the job never reached its save")
            cancelled = jobs.cancel_job(job.id)
            active = jobs.active_job_count(tenant)
            release.set()
            deadline = time.monotonic() + 10
            while job.status in {"queued", "running"} and time.monotonic() < deadline:
                time.sleep(0.01)
        self.assertFalse(cancelled, "a job whose result was being written was called cancelled")
        self.assertEqual(active, 1, "the slot was freed while the save still ran")
        self.assertEqual(job.status, "completed")

    def test_a_cancel_before_the_save_still_cancels(self) -> None:
        job = jobs.ScanJob(id=f"job-{uuid4().hex[:8]}", tenant_id="audit-jobs", status="running")
        with jobs._lock:
            jobs._jobs[job.id] = job
        self.addCleanup(jobs._jobs.pop, job.id, None)
        self.assertTrue(jobs.cancel_job(job.id))
        self.assertFalse(jobs.begin_saving(job))


if __name__ == "__main__":
    unittest.main()
