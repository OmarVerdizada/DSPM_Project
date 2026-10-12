"""W3.2: no failure costs more than one unit (roadmap section 23.9).

An infrastructure failure - the database, the scan's target, the disk - spends no unit
attempt and never marks a scan failed: it is retried, then the scan pauses. A unit out of
attempts is quarantined and named, and the scan finishes incomplete. A cancel is on the
scan's record. A finalize continues from the step it reached. A file whose parser hangs is
stopped at its deadline in a worker that is killed. A unit past its budget stops renewing
its lease. A prune never removes what a newer scan of the same label saw.

Fake transports where the real one cannot be broken on demand: the fake SMB server of the
W1.2 tests, and named functions a real worker process runs (tests/fault_helpers.py).
"""
from __future__ import annotations

import importlib.util
import os
import sqlite3
import subprocess
import sys
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from unittest.mock import MagicMock, patch

from backend import failures, partitioned_scan, scan_resumer, store
from collectors import content_policy, extract_worker
from discovery import detector_pool
from discovery.discovery_engine import DSPMDiscoveryEngine
from tests.test_partitioned_local_scan import TENANT, _LocalTest
from tests.test_w12_smb_range_units import _RangeTest

REQUEST = {"local_path": "estate"}
FAST = {"DSPM_INFRA_RETRY_SECONDS": "0", "DSPM_PARTITION_RETRY_SECONDS": "0"}
LOCKED = "database is locked"


def _paths(compact: dict) -> set[str]:
    report = store.read_scan_report(TENANT, compact["scan_id"])
    return {str(record["path"]) for record in report["files"]}


def _failed_marks(spy: MagicMock) -> list:
    return [call for call in spy.call_args_list if len(call.args) > 2 and call.args[2] == "failed"]


class FailuresAreClassifiedTest(unittest.TestCase):

    def test_infrastructure_and_data_failures(self) -> None:
        infrastructure = [
            sqlite3.OperationalError(LOCKED), sqlite3.OperationalError("disk I/O error"),
            ConnectionResetError(), ConnectionRefusedError(), TimeoutError(),
            failures.TargetUnreachable("x"), failures.DiskBelowFloor("x"),
            partitioned_scan.PartitionConnectionLost("reset"),
        ]
        data = [ValueError("bad pdf"), PermissionError(), sqlite3.OperationalError("no such table: x"),
                KeyError("k"), OSError("locked")]
        for exc in infrastructure:
            self.assertTrue(failures.is_infrastructure(exc), repr(exc))
        for exc in data:
            self.assertFalse(failures.is_infrastructure(exc), repr(exc))

    def test_the_cause_chain_decides(self) -> None:
        try:
            try:
                raise ConnectionResetError()
            except ConnectionResetError as inner:
                raise RuntimeError("wrapped") from inner
        except RuntimeError as outer:
            self.assertTrue(failures.is_infrastructure(outer))
        self.assertTrue(failures.is_target_unreachable(ConnectionRefusedError()))
        self.assertFalse(failures.is_target_unreachable(sqlite3.OperationalError(LOCKED)))


class AnOutageCostsNoAttemptTest(_LocalTest):

    def _clean(self) -> set[str]:
        self._use_database("clean")
        return _paths(partitioned_scan.run_partitioned_scan(TENANT, self._config("clean"), request=REQUEST,
                                                            max_files=3))

    def test_a_database_blip_during_a_write_spends_no_attempt_and_the_scan_completes(self) -> None:
        reference = self._clean()
        self._use_database("blip")
        real = store.persist_partition
        calls = {"n": 0}

        def flaky(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 2:
                raise sqlite3.OperationalError(LOCKED)
            return real(*args, **kwargs)

        # One attempt per unit: before W3.2 the blip spent it, and the scan failed.
        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_ATTEMPTS": "1", **FAST}), \
                patch.object(store, "persist_partition", side_effect=flaky):
            compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("blip"), request=REQUEST,
                                                            max_files=3)
        units = store.list_scan_partitions(TENANT, compact["scan_id"])
        self.assertEqual({unit["status"] for unit in units}, {"done"})
        self.assertEqual(sum(unit["interruptions"] for unit in units), 1)
        self.assertEqual({store.data_attempts(unit) for unit in units}, {1})
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")
        self.assertEqual(_paths(compact), reference, "estate parity with an uninterrupted run")

    def test_a_long_outage_pauses_the_scan_and_never_marks_it_failed(self) -> None:
        reference = self._clean()
        self._use_database("outage")
        record = partitioned_scan.start_partitioned_scan(TENANT, self._config("outage"), request=REQUEST,
                                                         max_files=3)
        self.assertEqual(partitioned_scan.wait_for_plan(TENANT, record["scan_id"], 60), "planned")
        marks = MagicMock(wraps=store.mark_partitioned_scan)
        with mock.patch.dict(os.environ, {"DSPM_INFRA_RETRIES": "3", **FAST}), \
                patch.object(store, "persist_partition", side_effect=sqlite3.OperationalError(LOCKED)), \
                patch.object(store, "mark_partitioned_scan", marks):
            with self.assertRaisesRegex(partitioned_scan.ScanPaused, "infrastructure"):
                partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("outage"))
        self.assertEqual(_failed_marks(marks), [], "a failed mark was attempted during an outage")
        stored = store.read_partitioned_scan(TENANT, record["scan_id"])
        self.assertEqual(stored["status"], "running")
        self.assertTrue(store.scan_is_paused(stored))
        units = store.list_scan_partitions(TENANT, record["scan_id"])
        self.assertEqual({store.data_attempts(unit) for unit in units}, {0}, "the outage spent unit attempts")
        self.assertEqual({unit["status"] for unit in units}, {"queued"})
        # The outage ends; the scan continues from where it was and ends as an uninterrupted one.
        compact = partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("outage"))
        self.assertEqual(_paths(compact), reference)

    def test_an_outage_in_the_control_loop_pauses_instead_of_failing(self) -> None:
        self._use_database("loop")
        record = partitioned_scan.start_partitioned_scan(TENANT, self._config("loop"), request=REQUEST, max_files=3)
        self.assertEqual(partitioned_scan.wait_for_plan(TENANT, record["scan_id"], 60), "planned")
        marks = MagicMock(wraps=store.mark_partitioned_scan)
        with mock.patch.dict(os.environ, {"DSPM_INFRA_RETRIES": "2", **FAST}), \
                patch.object(store, "claim_next_partition", side_effect=sqlite3.OperationalError(LOCKED)), \
                patch.object(store, "mark_partitioned_scan", marks):
            with self.assertRaises(partitioned_scan.ScanPaused):
                partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("loop"))
        self.assertEqual(_failed_marks(marks), [])
        self.assertEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "running")

    def test_a_restart_spends_no_attempt(self) -> None:
        self._use_database("restart")
        record = partitioned_scan.start_partitioned_scan(TENANT, self._config("restart"), request=REQUEST,
                                                         max_files=3)
        self.assertEqual(partitioned_scan.wait_for_plan(TENANT, record["scan_id"], 60), "planned")
        unit = store.claim_next_partition(TENANT, record["scan_id"], worker_id="died")
        store.requeue_interrupted_partitions(TENANT)
        again = store.read_scan_partition(TENANT, record["scan_id"], unit["partition_id"])
        self.assertEqual((again["status"], again["interruptions"], store.data_attempts(again)), ("queued", 1, 0))

    def test_an_outage_while_resuming_leaves_the_scan_for_the_next_sweep(self) -> None:
        self._use_database("resume-outage")
        record = partitioned_scan.start_partitioned_scan(TENANT, self._config("resume-outage"), request=REQUEST,
                                                         max_files=3)
        self.assertEqual(partitioned_scan.wait_for_plan(TENANT, record["scan_id"], 60), "planned")
        with store._connect() as conn:
            conn.execute("UPDATE partitioned_scans SET updated_at = ? WHERE tenant_id = ? AND scan_id = ?",
                         ((datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(), TENANT, record["scan_id"]))
        resume = MagicMock(side_effect=sqlite3.OperationalError(LOCKED))
        self.assertEqual(scan_resumer.resume_stale_scans(resume, stale_after_seconds=0), [record["scan_id"]])
        self.assertEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "running",
                         "an outage while resuming gave the scan up")


class TheTargetsBreakerTest(_LocalTest):

    def test_a_worker_that_cannot_reach_the_target_pauses_the_scan_and_spends_no_attempt(self) -> None:
        from backend.work_queue import LedgerQueue

        self._use_database("breaker")
        record = partitioned_scan.start_partitioned_scan(TENANT, self._config("breaker"), request=REQUEST,
                                                         max_files=3)
        self.assertEqual(partitioned_scan.wait_for_plan(TENANT, record["scan_id"], 60), "planned")
        unit = store.list_scan_partitions(TENANT, record["scan_id"])[0]
        with patch.object(partitioned_scan.DSPMDiscoveryEngine, "run", side_effect=ConnectionRefusedError()):
            outcome = partitioned_scan.run_queued_partition(record, self._config("breaker"), unit["partition_id"],
                                                            worker_id="w1")
        self.assertEqual(outcome, "interrupted")
        stored = store.read_partitioned_scan(TENANT, record["scan_id"])
        self.assertTrue(store.scan_is_paused(stored))
        again = store.read_scan_partition(TENANT, record["scan_id"], unit["partition_id"])
        self.assertEqual((again["status"], store.data_attempts(again)), ("queued", 0))
        self.assertIsNone(LedgerQueue().take("w2"), "a paused scan's units were handed out")
        self.assertFalse(store.claim_partitioned_scan_resume(TENANT, record["scan_id"], job_id="sweep",
                                                             stale_after_seconds=0),
                         "the resume sweep took a scan up before its pause ended")
        self.assertEqual(partitioned_scan.run_queued_partition(stored, self._config("breaker"), unit["partition_id"],
                                                               worker_id="w2"), "paused")


class FinalizeContinuesFromItsStepTest(_LocalTest):

    def test_a_finalize_interrupted_after_its_body_continues_without_writing_it_again(self) -> None:
        # The verbatim body is opt-in since W3.5 (DSPM_STORE_REPORT_BODY=1); with it, the body
        # is a recorded step of its own.
        with mock.patch.dict(os.environ, {"DSPM_STORE_REPORT_BODY": "1"}):
            self._interrupted_finalize_continues(step="body", state_key="body_ref")

    def test_a_finalize_interrupted_after_its_fold_continues_without_folding_again(self) -> None:
        # W3.5 (D3): by default a scan is its summary and a manifest - no body step; the last
        # recorded step before the store transaction is the fold of its sections.
        self._interrupted_finalize_continues(step="folded", state_key="sections_ref")

    def _interrupted_finalize_continues(self, *, step: str, state_key: str) -> None:
        self._use_database("clean")
        reference = _paths(partitioned_scan.run_partitioned_scan(TENANT, self._config("clean"), request=REQUEST,
                                                                 max_files=3))
        self._use_database("steps")
        record = partitioned_scan.start_partitioned_scan(TENANT, self._config("steps"), request=REQUEST,
                                                         max_files=3)
        self.assertEqual(partitioned_scan.wait_for_plan(TENANT, record["scan_id"], 60), "planned")
        real = store.finalize_partitioned_scan
        with mock.patch.dict(os.environ, FAST), \
                patch.object(store, "finalize_partitioned_scan", side_effect=sqlite3.OperationalError(LOCKED)):
            with self.assertRaises(partitioned_scan.ScanPaused):
                partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("steps"))
        stored = store.read_partitioned_scan(TENANT, record["scan_id"])
        self.assertEqual(stored["status"], "finalizing", "an outage in finalize failed the scan")
        self.assertEqual(stored["finalize_step"], step)
        self.assertTrue(stored["finalize_state"].get(state_key))
        # The sweep takes the quiet finalize over; the new finalize starts at its step.
        self.assertTrue(store.claim_partitioned_scan_resume(TENANT, record["scan_id"], job_id="j2",
                                                            stale_after_seconds=0, finalizing_stale_after_seconds=0))
        bodies = MagicMock(wraps=store._store_report_body)
        reads = MagicMock(wraps=store.iter_partition_records)
        with patch.object(store, "_store_report_body", bodies), patch.object(store, "iter_partition_records", reads), \
                patch.object(store, "finalize_partitioned_scan", side_effect=real):
            compact = partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("steps"))
        bodies.assert_not_called()
        reads.assert_not_called()
        self.assertEqual(_paths(compact), reference)
        self.assertEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "done")


class APruneNeverRemovesWhatANewerScanSawTest(_LocalTest):

    def _stored(self) -> set[str]:
        with store._connect() as conn:
            return {str(row["path"]) for row in conn.execute(
                "SELECT path FROM assets WHERE tenant_id = ?", (TENANT,)).fetchall()}

    def test_an_older_scan_finalized_later_prunes_nothing(self) -> None:
        # "Older" is when a scan started; ids are not compared - not every id is a timestamp.
        self._use_database("newer")
        newer = DSPMDiscoveryEngine(self._config("newer")).run().to_dict()
        newer.update(scan_id="scan-a", scan_label="estate", timestamp="2099-01-01T00:00:02+00:00")
        store.save_scan_history(TENANT, newer)
        kept = {str(record["path"]) for record in newer["files"]}
        (self.estate / "a_root.txt").unlink()
        older = DSPMDiscoveryEngine(self._config("older")).run().to_dict()
        older.update(scan_id="scan-b", scan_label="estate", timestamp="2099-01-01T00:00:01Z")
        self.assertTrue(older["scan_diagnostics"]["incremental"]["complete"])
        store.save_scan_history(TENANT, older)
        self.assertEqual(self._stored(), kept, "the older scan pruned what the newer one saw")

    def test_a_newer_scan_still_running_stops_the_prune_too(self) -> None:
        # Its units stamp assets before it has a report: its record is what says it is newer.
        # No depth limit: a depth-limited scan prunes nothing at all (W3.6), and the prune is
        # what this test watches.
        self._use_database("running")
        first = DSPMDiscoveryEngine(self._config("first", max_depth=None)).run().to_dict()
        first.update(scan_id="scan-1", scan_label="estate", timestamp="2099-01-01T00:00:00+00:00")
        store.save_scan_history(TENANT, first)
        kept = self._stored()
        store.register_partitioned_scan(TENANT, "scan-3", job_id="", request={}, header={"scan_label": "estate"})
        (self.estate / "a_root.txt").unlink()
        older = DSPMDiscoveryEngine(self._config("older", max_depth=None)).run().to_dict()
        older.update(scan_id="scan-2", scan_label="estate", timestamp="2000-01-01T00:00:00+00:00")
        store.save_scan_history(TENANT, older)
        self.assertEqual(self._stored(), kept, "an older scan pruned while a newer one of its label was running")
        store.mark_partitioned_scan(TENANT, "scan-3", "cancelled")
        older.update(scan_id="scan-4", timestamp="2099-06-01T00:00:00+00:00")
        store.save_scan_history(TENANT, older)
        self.assertLess(len(self._stored()), len(kept), "with nothing newer, the scan prunes")


class AWorkerDoesNotOutliveItsParentTest(unittest.TestCase):

    @unittest.skipUnless(importlib.util.find_spec("psutil"), "psutil is needed to watch the worker")
    def test_a_worker_inside_a_hung_parse_ends_when_its_parent_is_killed(self) -> None:
        import psutil

        root = str(Path(__file__).resolve().parents[1])
        script = (
            "import sys, time\n"
            f"sys.path.insert(0, {root!r})\n"
            "from collectors import extract_worker\n"
            "worker = extract_worker._Worker()\n"
            "print(worker.process.pid, flush=True)\n"
            "worker.conn.send((b'x', '.pdf', 10, {}, 'tests.fault_helpers:hang_extracting'))\n"
            "time.sleep(600)\n"
        )
        helper = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True, cwd=root)
        try:
            pid = int(helper.stdout.readline())
            time.sleep(2)  # inside the hung call
            self.assertTrue(psutil.pid_exists(pid))
        finally:
            helper.kill()
            helper.wait(30)
        deadline = time.monotonic() + 30
        while psutil.pid_exists(pid) and time.monotonic() < deadline:
            time.sleep(0.2)
        alive = psutil.pid_exists(pid)
        if alive:
            psutil.Process(pid).kill()
        self.assertFalse(alive, "an extraction worker outlived its killed parent")


class AHungParserIsStoppedTest(_LocalTest):

    def test_a_document_whose_parser_hangs_is_failed_at_its_deadline_and_the_scan_completes(self) -> None:
        self._use_database("hang")
        (self.estate / "b_dept" / "contract.docx").write_bytes(b"PK not really a document")
        started = time.monotonic()
        with mock.patch.dict(os.environ, {"DSPM_FILE_DEADLINE_SECONDS": "2", **FAST}), \
                patch.object(extract_worker, "EXTRACT_TARGET", "tests.fault_helpers:hang_extracting"):
            killed_before = extract_worker.killed_workers()
            compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("hang"), request=REQUEST,
                                                            max_files=3)
            killed = extract_worker.killed_workers() - killed_before
        self.addCleanup(extract_worker.shutdown)
        self.assertLess(time.monotonic() - started, 120, "the hung parser held the scan")
        self.assertGreaterEqual(killed, 1, "the hung worker was not killed")
        report = store.read_scan_report(TENANT, compact["scan_id"])
        (record,) = [item for item in report["files"] if str(item["path"]).endswith("contract.docx")]
        self.assertEqual(record["content_status"], "deadline_exceeded")
        self.assertEqual(content_policy.coverage_state(record), content_policy.FAILED)
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")

    def test_a_quick_document_goes_through_the_worker_unchanged(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_FILE_DEADLINE_SECONDS": "30"}), \
                patch.object(extract_worker, "EXTRACT_TARGET", "tests.fault_helpers:quick_extracting"):
            self.addCleanup(extract_worker.shutdown)
            self.assertEqual(extract_worker.extract_bytes_detail(b"card 4111", ".docx"), ("card 4111", "", False))


class TheDetectorPoolSurvivesADeadlineTest(unittest.TestCase):

    def test_a_hung_classification_kills_its_worker_and_the_pool_carries_on(self) -> None:
        pool = detector_pool.DetectorPool(1)
        self.addCleanup(pool.shutdown)
        pool.start()
        deadline = time.monotonic() + 90
        while not pool.ready and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertTrue(pool.ready, "the pool never warmed")
        from tests import fault_helpers

        with mock.patch.dict(os.environ, {"DSPM_FILE_DEADLINE_SECONDS": "2"}), \
                patch.object(detector_pool, "run_detector_stage", fault_helpers.hang_detecting):
            result = pool.run({"content": "x"})
        self.assertEqual(result, detector_pool.DEADLINE_EXCEEDED)
        diagnostics = pool.diagnostics()
        self.assertTrue(diagnostics["enabled"], "a deadline disabled the shared pool")
        self.assertEqual(diagnostics["deadline_kills"], 1)
        self.assertEqual(diagnostics["disabled_reason"], "")


class ALeaseStopsRenewingPastItsBudgetTest(unittest.TestCase):

    def test_a_unit_past_its_budget_is_left_to_its_lease(self) -> None:
        scan = SimpleNamespace(tenant_id=TENANT, scan_id="s", worker="w", lease_seconds=1)
        renewals: list[float] = []
        started = time.monotonic()

        def renew(*_args, **_kwargs) -> bool:
            renewals.append(time.monotonic() - started)
            return True

        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_SECONDS": "1"}), \
                patch.object(store, "renew_partition_lease", side_effect=renew), \
                patch.object(store, "touch_partitioned_scan", return_value=True):
            with partitioned_scan._holding_lease(scan, {"partition_id": "p00000", "attempt": 1}):
                time.sleep(5.5)
        self.assertTrue(renewals)
        self.assertLess(max(renewals), 3.8, "a unit past its budget kept its lease")


class TheDiskFloorHoldsInEveryExecutorTest(_LocalTest):

    def test_a_queue_worker_and_a_finalize_pause_below_the_floor(self) -> None:
        self._use_database("disk")
        record = partitioned_scan.start_partitioned_scan(TENANT, self._config("disk"), request=REQUEST, max_files=3)
        self.assertEqual(partitioned_scan.wait_for_plan(TENANT, record["scan_id"], 60), "planned")
        unit = store.list_scan_partitions(TENANT, record["scan_id"])[0]
        low = "free disk on the data volume is 10 MB, below the floor"
        with patch.object(partitioned_scan.disk_guard, "low_space_reason", return_value=low):
            self.assertEqual(partitioned_scan.run_queued_partition(record, self._config("disk"), unit["partition_id"],
                                                                   worker_id="w"), "paused")
        self.assertEqual(store.read_scan_partition(TENANT, record["scan_id"], unit["partition_id"])["attempt"], 0,
                         "a unit was run below the disk floor")
        self.assertTrue(store.scan_is_paused(store.read_partitioned_scan(TENANT, record["scan_id"])))
        # Every unit done, then the disk fills: finalize waits.
        with store._connect() as conn:
            conn.execute("UPDATE partitioned_scans SET paused_until = '' WHERE tenant_id = ? AND scan_id = ?",
                         (TENANT, record["scan_id"]))
        scan = partitioned_scan._scan_from_record(store.read_partitioned_scan(TENANT, record["scan_id"]),
                                                  self._config("disk"))
        partitioned_scan._run_partitions(scan, job=None, stop_reason=lambda: None, poll_seconds=0.01)
        with patch.object(partitioned_scan.disk_guard, "low_space_reason", return_value=low):
            self.assertIsNone(partitioned_scan.settle_if_finished(store.read_partitioned_scan(TENANT, record["scan_id"]),
                                                                  self._config("disk")))
            with self.assertRaisesRegex(partitioned_scan.ScanPaused, "free disk"):
                partitioned_scan._finalize(scan)
        self.assertNotEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "failed")


class AnSmbUnitOverItsBudgetIsTruncatedTest(_RangeTest):

    def test_the_walk_stops_where_it_is_and_says_so(self) -> None:
        calls = {"n": 0}

        def spent(_engine) -> bool:
            calls["n"] += 1
            return calls["n"] > 3

        with patch.object(DSPMDiscoveryEngine, "_deadline_passed", spent):
            report = DSPMDiscoveryEngine(self._config("over")).run().to_dict()
        diagnostics = report["scan_diagnostics"]
        self.assertEqual(diagnostics.get("scan_aborted_reason"), "time_budget")
        self.assertFalse(diagnostics["incremental"]["complete"], "a truncated walk called itself complete")

    def test_a_unit_over_its_budget_on_its_last_attempt_is_written_incomplete_not_cancelled(self) -> None:
        self._use_database("over-budget")
        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_ATTEMPTS": "1", **FAST}), \
                patch.object(DSPMDiscoveryEngine, "_deadline_passed", lambda _engine: True):
            compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("over-budget"),
                                                            request={"server": "fs"}, max_files=10)
        record = store.read_partitioned_scan(TENANT, compact["scan_id"])
        self.assertEqual(record["status"], "done")
        report = store.read_scan_report(TENANT, compact["scan_id"])
        self.assertFalse(report["scan_diagnostics"]["incremental"]["complete"])
        self.assertNotIn("cancel", str(report["scan_diagnostics"]).lower())


class AnEmptyUnitIsNotCompleteTest(unittest.TestCase):

    def test_an_endpoint_page_that_answers_nothing_is_a_failure_not_an_empty_complete_page(self) -> None:
        # Roadmap N13: an empty answer was taken as a page with no files - complete, with no
        # subfolders to hand on - and the scan then pruned everything under them.
        from collectors import winrm_endpoint_scanner as winrm

        scanner = winrm.WinRMEndpointScanner(winrm.WinRMEndpointConfig(host="ws-17", username="svc", password="x"))
        silent = SimpleNamespace(status_code=0, std_out=b"", std_err=b"")
        page = {"folders": [{"path": "C:\\Users\\ana", "depth": 0, "after": "", "root": True}],
                "page_size": 100, "max_folders": 10}
        with patch.object(winrm.WinRMEndpointScanner, "_run_ps_file", return_value=silent):
            with self.assertRaises(winrm.EmptyCollectorOutput):
                scanner.scan(page=page)
        self.assertFalse(failures.is_infrastructure(winrm.EmptyCollectorOutput("x")),
                         "a silent page is the page's failure: it spends attempts and is quarantined")


if __name__ == "__main__":
    unittest.main()
