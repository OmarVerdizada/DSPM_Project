"""W1.1 (scaling roadmap, 2026-10): partitioned scanning as the scan path - estate writes
that do not hold the process, units that cannot cancel their scan by running long, and
a scan that pauses rather than fails when it stops making progress.
"""
from __future__ import annotations

import os
import threading
import time
import unittest
from unittest import mock
from unittest.mock import MagicMock, patch
from uuid import uuid4

from backend import db, jobs, partitioned_scan, store
from tests.test_partitioned_local_scan import TENANT, _LocalTest


def _file(path: str) -> dict:
    name = path.rsplit("/", 1)[-1]
    return {"path": path, "name": name, "extension": ".txt", "size": 10,
            "modified_at": "2026-09-01T00:00:00+00:00", "risk": {"level": "HIGH", "score": 80},
            "findings": [{"finding_id": f"f-{name}", "type": "email", "risk": "HIGH",
                          "framework": "gdpr", "count": 1, "status": "OPEN"}]}


class _Held:
    """Hold one workspace's estate write open in a thread until released."""

    def __init__(self, tenant_id: str) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.thread = threading.Thread(target=self._hold, args=(tenant_id,), daemon=True)

    def _hold(self, tenant_id: str) -> None:
        with store._estate_write(tenant_id):
            self.started.set()
            self.release.wait(10)

    def __enter__(self) -> "_Held":
        self.thread.start()
        assert self.started.wait(5), "the estate write never started"
        return self

    def __exit__(self, *exc) -> None:
        self.release.set()
        self.thread.join(10)


@unittest.skipUnless(db.is_postgres(), "on SQLite the process lock still orders every write, by design")
class AnEstateWriteDoesNotHoldTheProcessTest(unittest.TestCase):
    """On PostgreSQL every save, partition and finalize held the process-wide store lock
    for its whole length, and every other write queued behind it - an analyst's click,
    a sibling scan's lease renewal. A per-workspace advisory lock in the transaction
    serializes estate writes instead, across processes, and nothing else."""

    def setUp(self) -> None:
        self.tenant = f"w11-lock-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "Lock")
        store.save_scan_history(self.tenant, {
            "scan_id": "s1", "source": "smb", "summary": {}, "timestamp": "2026-09-01T00:00:00+00:00",
            "files": [_file("//fs01/finance/a.txt")]})
        with store._connect() as conn:
            self.finding_id = str(conn.execute("SELECT id FROM findings WHERE tenant_id = ?",
                                               (self.tenant,)).fetchone()["id"])

    def test_the_process_lock_stays_free_while_an_estate_write_is_open(self) -> None:
        # Lease renewals, the scan record's sign of life and every short write take it.
        with _Held(self.tenant):
            self.assertTrue(store._lock.acquire(timeout=2), "an estate write held the process lock")
            store._lock.release()

    def test_a_click_lands_while_a_long_estate_write_is_open(self) -> None:
        with _Held(self.tenant):
            started = time.monotonic()
            store.update_finding_lifecycle(self.tenant, self.finding_id, "comment", {"comment": "now"}, "analyst")
            self.assertLess(time.monotonic() - started, 3.0)

    def test_estate_writes_queue_per_workspace_and_only_there(self) -> None:
        other = f"w11-lock-{uuid4().hex[:8]}"
        store.create_tenant(other, "Other")
        acquired = threading.Event()

        def second_write() -> None:
            with store._estate_write(self.tenant):
                acquired.set()

        with _Held(self.tenant):
            started = time.monotonic()
            with store._estate_write(other):
                pass
            self.assertLess(time.monotonic() - started, 3.0, "another workspace waited")
            waiter = threading.Thread(target=second_write, daemon=True)
            waiter.start()
            self.assertFalse(acquired.wait(0.5), "two writes to one estate ran at once")
        waiter.join(10)
        self.assertTrue(acquired.is_set())


REQUEST = {"local_path": "estate", "max_depth": 4}


def _truncated(report):
    """What an engine that ran out of its time returns: its report, cut short."""
    diagnostics = dict(report.scan_diagnostics or {})
    diagnostics["scan_truncated"] = True
    incremental = dict(diagnostics.get("incremental") or {})
    incremental["complete"] = False
    diagnostics["incremental"] = incremental
    report.scan_diagnostics = diagnostics
    return report


class AUnitThatRunsLongDoesNotEndTheScanTest(_LocalTest):
    """A unit's engine ran under the job heartbeat's half-hour deadline, measured per unit:
    past it the heartbeat failed the job and the cancel it set stopped the whole scan for
    good. Now each unit has its own budget: a unit that runs out is tried again, and on its
    last attempt what it read is kept and the scan ends incomplete - never failed."""

    def test_a_unit_over_its_budget_is_tried_again_and_the_scan_completes(self) -> None:
        self._use_database("overrun")
        real_run = partitioned_scan.DSPMDiscoveryEngine.run
        calls = {"n": 0}

        def second_run_overruns(engine):
            calls["n"] += 1
            report = real_run(engine)
            return _truncated(report) if calls["n"] == 2 else report

        with patch.object(partitioned_scan.DSPMDiscoveryEngine, "run", second_run_overruns):
            compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("overrun"), request=REQUEST, max_files=3)
        units = store.list_scan_partitions(TENANT, compact["scan_id"])
        self.assertEqual({unit["status"] for unit in units}, {"done"})
        self.assertEqual(units[1]["attempt"], 2, "the over-budget unit was not tried again")
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")

    def test_on_its_last_attempt_what_it_read_is_kept_and_the_scan_is_incomplete(self) -> None:
        self._use_database("overrun-last")
        real_run = partitioned_scan.DSPMDiscoveryEngine.run
        seen: dict = {}

        def first_unit_always_overruns(engine):
            key = (engine.config.local_path, engine.config.local_entry_names)
            seen.setdefault("key", key)
            report = real_run(engine)
            return _truncated(report) if key == seen["key"] else report

        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_ATTEMPTS": "2"}), \
                patch.object(partitioned_scan.DSPMDiscoveryEngine, "run", first_unit_always_overruns):
            compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("overrun-last"), request=REQUEST,
                                                            max_files=3)
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")
        incremental = store.read_scan_report(TENANT, compact["scan_id"])["scan_diagnostics"]["incremental"]
        self.assertFalse(incremental["complete"], "a scan with a unit cut short called itself complete")

    def test_the_job_heartbeat_no_longer_fails_a_long_partitioned_scan(self) -> None:
        self._use_database("heartbeat")
        job = jobs.ScanJob(id=f"job-{uuid4().hex[:6]}", tenant_id=TENANT, status="running")
        real_run = partitioned_scan.DSPMDiscoveryEngine.run

        def slow(engine):
            time.sleep(0.3)
            return real_run(engine)

        with patch.object(jobs, "SCAN_MAX_SECONDS", 0.1), patch.object(jobs, "COLLECT_HEARTBEAT_SECONDS", 0.05), \
                patch.object(partitioned_scan.DSPMDiscoveryEngine, "run", slow):
            compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("heartbeat"), request=REQUEST,
                                                            job=job, max_files=3)
        self.assertEqual(job.status, "running", job.error)
        self.assertFalse(job.cancel_requested)
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")


class AScanThatStopsMakingProgressIsPausedTest(_LocalTest):
    """With no wall clock over the whole scan, a runner left waiting - for units another
    worker holds, or for a retry back-off - would wait for ever. When no unit finishes for
    DSPM_SCAN_STALL_SECONDS the runner lets the scan go: unfinished, not failed, for the
    resume sweep to continue under the same job."""

    def _planned(self, name: str, *, request) -> dict:
        self._use_database(name)
        record = partitioned_scan.start_partitioned_scan(TENANT, self._config(name), request=request, max_files=3)
        self.assertEqual(partitioned_scan.wait_for_plan(TENANT, record["scan_id"], 60), "planned")
        self.assertIsNotNone(record)
        for unit in store.list_scan_partitions(TENANT, record["scan_id"]):
            # Another worker holds every unit, with leases far from running out.
            store.claim_partition(TENANT, record["scan_id"], unit["partition_id"], worker_id="elsewhere",
                                  lease_seconds=3600)
        return record

    def test_a_stalled_scan_is_paused_and_left_for_the_resume_sweep(self) -> None:
        record = self._planned("stalled", request=REQUEST)
        with mock.patch.dict(os.environ, {"DSPM_SCAN_STALL_SECONDS": "1"}):
            with self.assertRaisesRegex(partitioned_scan.ScanPaused, "continues automatically"):
                partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("stalled"),
                                                           poll_seconds=0.2)
        row = store.read_partitioned_scan(TENANT, record["scan_id"])
        self.assertEqual(row["status"], "running", row.get("error"))
        self.assertFalse(partitioned_scan.is_running_here(TENANT, record["scan_id"]))
        self.assertIn("continues automatically", jobs._safe_job_error(partitioned_scan.ScanPaused("Scan paused: x")))

    def test_a_stalled_scan_that_cannot_be_resumed_is_failed_and_says_why(self) -> None:
        record = self._planned("stalled-once", request=None)
        with mock.patch.dict(os.environ, {"DSPM_SCAN_STALL_SECONDS": "1"}):
            with self.assertRaises(partitioned_scan.ScanPaused):
                partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("stalled-once"),
                                                           poll_seconds=0.2)
        row = store.read_partitioned_scan(TENANT, record["scan_id"])
        self.assertEqual(row["status"], "failed")
        self.assertIn("cannot be resumed", row["error"])


class UnitsRunTogetherWhenAskedTest(_LocalTest):
    """Inline partitions ran one after another. With DSPM_PARTITION_WORKERS above one they
    run on a pool of their own; the report is the same, in the same order, because finalize
    orders the partitions by their place in the plan, not by when they finished."""

    def test_two_workers_overlap_and_the_report_is_unchanged(self) -> None:
        self._use_database("workers")
        real_run = partitioned_scan.DSPMDiscoveryEngine.run
        lock = threading.Lock()
        state = {"now": 0, "most": 0}

        def overlapping(engine):
            with lock:
                state["now"] += 1
                state["most"] = max(state["most"], state["now"])
            try:
                time.sleep(0.2)
                return real_run(engine)
            finally:
                with lock:
                    state["now"] -= 1

        config = self._config("workers", persistent_cache_enabled=True, incremental_enabled=True)
        with mock.patch.dict(os.environ, {"DSPM_PARTITION_WORKERS": "2"}), \
                patch.object(partitioned_scan.DSPMDiscoveryEngine, "run", overlapping):
            compact = partitioned_scan.run_partitioned_scan(TENANT, config, request=REQUEST, max_files=3)
        self.assertEqual(state["most"], 2, "the units never ran at the same time")
        units = store.list_scan_partitions(TENANT, compact["scan_id"])
        self.assertEqual({unit["status"] for unit in units}, {"done"})
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")
        walked, _ = self._single_walk(self._config("workers-walk"))
        self.assertEqual([f["path"] for f in store.read_scan_report(TENANT, compact["scan_id"])["files"]], walked)

    def test_a_cancel_stops_every_running_unit_and_claims_no_more(self) -> None:
        self._use_database("workers-cancel")
        job = MagicMock(id="job-workers", cancel_requested=False, progress=0, message="")
        real_persist = store.persist_partition

        def persist_then_cancel(*args, **kwargs):
            result = real_persist(*args, **kwargs)
            job.cancel_requested = True
            return result

        with mock.patch.dict(os.environ, {"DSPM_PARTITION_WORKERS": "2"}), \
                patch.object(store, "persist_partition", side_effect=persist_then_cancel):
            with self.assertRaisesRegex(partitioned_scan.ScanStopped, "cancelled"):
                partitioned_scan.run_partitioned_scan(TENANT, self._config("workers-cancel"), request=REQUEST,
                                                      job=job, max_files=3)
        with store._connect() as conn:
            reports = conn.execute("SELECT COUNT(*) FROM scan_reports WHERE tenant_id = ?", (TENANT,)).fetchone()[0]
        self.assertEqual(reports, 0)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            states = {row["status"] for row in self._units()}
            if "running" not in states:
                break
            time.sleep(0.2)
        self.assertNotIn("running", {row["status"] for row in self._units()}, "a unit was left claimed")

    def _units(self) -> list[dict]:
        with store._connect() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT status FROM scan_partitions WHERE tenant_id = ?", (TENANT,)).fetchall()]


class PartitionedIsTheDefaultPathTest(unittest.TestCase):
    """G0 passed on PostgreSQL (W1.1): partitioned scanning is on - since W4.6 whatever the
    retired DSPM_PARTITIONED_SCANS says, which the catalogue lists as no longer read."""

    def test_on_whatever_the_retired_switch_says(self) -> None:
        from backend import config

        self.assertIn("DSPM_PARTITIONED_SCANS", config.REMOVED)
        for value, expected in ((None, True), ("", True), ("1", True), ("0", True), ("false", True)):
            with self.subTest(value=value):
                env = {} if value is None else {"DSPM_PARTITIONED_SCANS": value}
                with mock.patch.dict(os.environ, env, clear=False):
                    if value is None:
                        os.environ.pop("DSPM_PARTITIONED_SCANS", None)
                    self.assertEqual(partitioned_scan.partitioned_scans_enabled(), expected)

    def test_one_unit_at_a_time_unless_raised(self) -> None:
        # W1.1: each unit's engine leases the detector pool, and N units at once had cost N
        # pools before it was shared; one stays the default (roadmap section 6 note 9).
        for value, expected in ((None, 1), ("", 1), ("abc", 1), ("0", 1), ("2", 2), ("20", 8)):
            with self.subTest(value=value):
                with mock.patch.dict(os.environ, {} if value is None else {"DSPM_PARTITION_WORKERS": value}):
                    if value is None:
                        os.environ.pop("DSPM_PARTITION_WORKERS", None)
                    self.assertEqual(partitioned_scan.partition_workers(), expected)
