"""The Wave 3 fault gate (scaling roadmap 23.9 and 24): every failure ends in its guaranteed state,
with the estate an uninterrupted run of the same target leaves.

One scenario per row of 23.9. Each runs the scan uninterrupted first and keeps its estate (the
assets and their finding counts), then runs it again into an empty workspace with the fault,
recovers the way the product does, and compares. Run on PostgreSQL (``sentro_test`` only) and
on SQLite.

Transports: the local scans read real folders. The SMB server is the fake of the W1.2 tests
(tests/test_w12_smb_range_units.py) and the endpoint the fake of the W1.3 tests
(tests/test_w13_endpoint_frontier.py): an SMB disconnect, a server offline, a hung WinRM
command and an endpoint offline cannot be produced on demand otherwise. A process death is
an exception no handler takes (KeyboardInterrupt) raised where the process would stop.
"""
from __future__ import annotations

import os
import sqlite3
import unittest
from unittest import mock
from unittest.mock import patch

from backend import app as app_module
from backend import db, partitioned_scan, scan_resumer, store
from backend.security import Principal
from collectors.winrm_endpoint_scanner import WinRMCommandTimedOut, WinRMEndpointScanner
from discovery.discovery_engine import DSPMDiscoveryEngine
from tests.test_partitioned_local_scan import TENANT, _LocalTest
from tests.test_w12_smb_range_units import _RangeTest
from tests.test_w13_endpoint_frontier import _Endpoint, _EndpointTest, _tree
from tests.test_w31_bounded_path import _unpause

REQUEST = {"local_path": "estate"}
FAST = {"DSPM_INFRA_RETRY_SECONDS": "0", "DSPM_PARTITION_RETRY_SECONDS": "0"}
LOCKED = "database is locked"


def _database_down() -> BaseException:
    """What the database driver raises when the server is gone, on the backend under test."""
    if db.is_postgres():
        import psycopg

        return psycopg.OperationalError("connection to server at 127.0.0.1, port 5442 failed: Connection refused")
    return sqlite3.OperationalError(LOCKED)


class _Gate:
    """An isolated workspace per run, and the estate a run leaves in it."""

    tenant = TENANT

    def _fresh(self, name: str) -> None:
        self._use_database(name)
        if db.is_postgres():
            store.delete_tenant_with_data(self.tenant)
            store.create_tenant(self.tenant, self.tenant)

    def _estate(self) -> list[tuple[str, int]]:
        with db.tenant_scope(self.tenant):
            with store._connect() as conn:
                return sorted((str(row["path"]), int(row["finding_count"] or 0)) for row in conn.execute(
                    "SELECT path, finding_count FROM assets WHERE tenant_id = ?", (self.tenant,)).fetchall())

    def _units(self, scan_id: str) -> list[dict]:
        return store.list_scan_partitions(self.tenant, scan_id)

    def _assert_no_attempt_spent(self, scan_id: str) -> None:
        for unit in self._units(scan_id):
            self.assertLessEqual(store.data_attempts(unit), 1, f"{unit['partition_id']} spent an attempt on the fault")


class _LocalGate(_Gate, _LocalTest):

    def _reference(self, **config) -> list[tuple[str, int]]:
        self._fresh("reference")
        partitioned_scan.run_partitioned_scan(TENANT, self._config("reference", **config), request=REQUEST,
                                              max_files=3)
        return self._estate()

    def _started(self, name: str, **config) -> dict:
        self._fresh(name)
        record = partitioned_scan.start_partitioned_scan(TENANT, self._config(name, **config), request=REQUEST,
                                                         max_files=3)
        self.assertEqual(partitioned_scan.wait_for_plan(TENANT, record["scan_id"], 60), "planned")
        return record


# ── backend restart ──────────────────────────────────────────────────────────────────────
class ARestartMidUnitTest(_LocalGate):

    def test_one_unit_is_redone_and_no_attempt_is_spent(self) -> None:
        reference = self._reference()
        record = self._started("mid-unit")
        real_run = DSPMDiscoveryEngine.run
        calls = {"n": 0}

        def dies_in_the_second_unit(engine):
            calls["n"] += 1
            if calls["n"] == 2:
                raise KeyboardInterrupt("the backend stopped")
            return real_run(engine)

        with patch.object(partitioned_scan.DSPMDiscoveryEngine, "run", dies_in_the_second_unit):
            with self.assertRaises(KeyboardInterrupt):
                partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("mid-unit"))
        partitioned_scan._forget_running(TENANT, record["scan_id"]) if hasattr(partitioned_scan, "_forget_running") \
            else None
        # The next start: whatever it was running goes back to the queue, without an attempt.
        store.requeue_interrupted_partitions(TENANT)
        interrupted = [unit for unit in self._units(record["scan_id"]) if int(unit["interruptions"] or 0)]
        self.assertEqual(len(interrupted), 1)
        self.assertEqual(store.data_attempts(interrupted[0]), 0)
        compact = partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("mid-unit"))
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")
        self._assert_no_attempt_spent(record["scan_id"])
        self.assertEqual(self._estate(), reference)


class ARestartMidFinalizeTest(_LocalGate):

    def test_finalize_resumes_at_its_step(self) -> None:
        reference = self._reference()
        record = self._started("mid-finalize")
        real = store.finalize_partitioned_scan
        with patch.object(store, "finalize_partitioned_scan", side_effect=KeyboardInterrupt("the backend stopped")):
            with self.assertRaises(KeyboardInterrupt):
                partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("mid-finalize"))
        stored = store.read_partitioned_scan(TENANT, record["scan_id"])
        self.assertEqual((stored["status"], stored["finalize_step"]), ("finalizing", "folded"))
        self.assertTrue(store.claim_partitioned_scan_resume(TENANT, record["scan_id"], job_id="restart",
                                                            stale_after_seconds=0, finalizing_stale_after_seconds=0))
        folds = mock.MagicMock(wraps=store.iter_partition_records)
        with patch.object(store, "iter_partition_records", folds), \
                patch.object(store, "finalize_partitioned_scan", side_effect=real):
            partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("mid-finalize"))
        folds.assert_not_called()
        self.assertEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "done")
        self.assertEqual(self._estate(), reference)


class ARestartMidPlanningTest(_LocalGate):

    def test_planning_resumes_from_the_units_already_written(self) -> None:
        reference = self._reference()
        self._fresh("mid-plan")
        real_append = store.append_planned_units
        calls = {"n": 0}

        def stops_after_two(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 3:
                raise KeyboardInterrupt("the backend stopped")
            return real_append(*args, **kwargs)

        with patch.object(store, "append_planned_units", stops_after_two), \
                patch.object(partitioned_scan, "_PLAN_BATCH_UNITS", 1):
            record = partitioned_scan.start_partitioned_scan(TENANT, self._config("mid-plan"), request=REQUEST,
                                                             max_files=3)
            partitioned_scan.join_planners(60)
        stored = store.read_partitioned_scan(TENANT, record["scan_id"])
        self.assertEqual((stored["status"], stored["plan_state"]), ("running", "planning"))
        written = len(self._units(record["scan_id"]))
        self.assertGreaterEqual(written, 1)
        partitioned_scan._forget_planner(TENANT, record["scan_id"]) if hasattr(partitioned_scan, "_forget_planner") \
            else None
        compact = partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("mid-plan"))
        ordinals = [unit["ordinal"] for unit in self._units(record["scan_id"])]
        self.assertEqual(ordinals, list(range(len(ordinals))), "a unit was planned twice or skipped")
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")
        self.assertEqual(self._estate(), reference)


# ── worker crash ─────────────────────────────────────────────────────────────────────────
class AWorkerCrashTest(_LocalGate):

    def test_its_unit_is_requeued_when_the_lease_runs_out_without_an_attempt(self) -> None:
        from backend.work_queue import LedgerQueue

        reference = self._reference()
        record = self._started("crash")
        crashed = store.claim_next_partition(TENANT, record["scan_id"], worker_id="worker-that-died")
        with db.tenant_scope(TENANT):
            with store._connect() as conn:
                conn.execute("UPDATE scan_partitions SET lease_expires_at = '2000-01-01T00:00:00+00:00' "
                             "WHERE tenant_id = ? AND scan_id = ? AND partition_id = ?",
                             (TENANT, record["scan_id"], crashed["partition_id"]))
        store.requeue_expired_partitions()
        again = store.read_scan_partition(TENANT, record["scan_id"], crashed["partition_id"])
        self.assertEqual((again["status"], store.data_attempts(again)), ("queued", 0))
        queue = LedgerQueue()
        while True:
            taken = queue.take("worker-2")
            if taken is None:
                break
            partitioned_scan.run_queued_partition(store.read_partitioned_scan(TENANT, record["scan_id"]),
                                                  self._config("crash"), taken.partition_id, worker_id="worker-2")
        compact = partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("crash"))
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")
        self._assert_no_attempt_spent(record["scan_id"])
        self.assertEqual(self._estate(), reference)


# ── the database unavailable ─────────────────────────────────────────────────────────────
class TheDatabaseUnavailableTest(_LocalGate):

    def test_a_short_blip_is_retried_and_spends_nothing(self) -> None:
        reference = self._reference()
        self._fresh("blip")
        real = store.persist_partition
        calls = {"n": 0}

        def blip(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 2:
                raise _database_down()
            return real(*args, **kwargs)

        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_ATTEMPTS": "1", **FAST}), \
                patch.object(store, "persist_partition", side_effect=blip):
            compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("blip"), request=REQUEST,
                                                            max_files=3)
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")
        self.assertEqual(sum(int(unit["interruptions"] or 0) for unit in self._units(compact["scan_id"])), 1)
        self._assert_no_attempt_spent(compact["scan_id"])
        self.assertEqual(self._estate(), reference)

    def test_a_long_outage_pauses_never_fails_and_continues(self) -> None:
        reference = self._reference()
        record = self._started("outage")
        marks = mock.MagicMock(wraps=store.mark_partitioned_scan)
        with mock.patch.dict(os.environ, {"DSPM_INFRA_RETRIES": "3", **FAST}), \
                patch.object(store, "persist_partition", side_effect=_database_down()), \
                patch.object(store, "mark_partitioned_scan", marks):
            with self.assertRaises(partitioned_scan.ScanPaused):
                partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("outage"))
        self.assertFalse([call for call in marks.call_args_list if len(call.args) > 2 and call.args[2] == "failed"])
        stored = store.read_partitioned_scan(TENANT, record["scan_id"])
        self.assertEqual(stored["status"], "running")
        self.assertTrue(store.scan_is_paused(stored))
        self.assertEqual({store.data_attempts(unit) for unit in self._units(record["scan_id"])}, {0})
        _unpause(record["scan_id"])
        compact = partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("outage"))
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")
        self.assertEqual(self._estate(), reference)


# ── the disk below its floor ─────────────────────────────────────────────────────────────
class TheDiskBelowItsFloorTest(_LocalGate):

    def test_the_scan_pauses_in_every_executor_and_before_finalize_then_continues(self) -> None:
        reference = self._reference()
        record = self._started("disk")
        low = "free disk on the data volume is 10 MB, below the floor"
        unit = self._units(record["scan_id"])[0]
        with patch.object(partitioned_scan.disk_guard, "low_space_reason", return_value=low):
            self.assertEqual(partitioned_scan.run_queued_partition(record, self._config("disk"), unit["partition_id"],
                                                                   worker_id="w"), "paused")
            with self.assertRaises(partitioned_scan.ScanPaused):
                partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("disk"))
        self.assertNotEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "failed")
        self.assertEqual({store.data_attempts(unit) for unit in self._units(record["scan_id"])}, {0})
        _unpause(record["scan_id"])
        compact = partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("disk"))
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")
        self.assertEqual(self._estate(), reference)


# ── cancel ───────────────────────────────────────────────────────────────────────────────
class ACancelTest(_LocalGate):

    def test_a_cancel_is_durable_keeps_what_was_written_and_prunes_nothing(self) -> None:
        reference = self._reference()
        record = self._started("cancel")

        def cancelled_after_two_units():
            done = [unit for unit in self._units(record["scan_id"]) if unit["status"] == "done"]
            return partitioned_scan.CANCEL_REASON if len(done) >= 2 else None

        with self.assertRaises(partitioned_scan.ScanStopped):
            partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("cancel"),
                                                       stop_reason=cancelled_after_two_units, poll_seconds=0.01)
        stored = store.read_partitioned_scan(TENANT, record["scan_id"])
        self.assertEqual(stored["status"], "cancelled", "the cancel is not on the scan's record")
        written = self._estate()
        self.assertTrue(written and set(written) <= set(reference), "what was written before the cancel was lost")
        self.assertEqual(scan_resumer.resume_stale_scans(mock.MagicMock(), stale_after_seconds=0), [],
                         "a cancelled scan was resumed")
        self.assertEqual(self._estate(), written, "a cancelled scan pruned")


# ── one unit failing repeatedly ──────────────────────────────────────────────────────────
class AUnitThatAlwaysFailsTest(_LocalGate):

    def test_it_is_quarantined_and_named_the_scan_is_incomplete_and_nothing_is_pruned(self) -> None:
        reference = self._reference()
        # The same workspace scanned again with one unit failing every attempt.
        real_run = DSPMDiscoveryEngine.run
        bad = {"unit": None}

        def fails_one(engine):
            # A unit is its folder and the run of names it holds: the first one fails, always.
            unit = (str(engine.config.local_path), tuple(engine.config.local_entry_names or ()))
            if bad["unit"] is None:
                bad["unit"] = unit
            if unit == bad["unit"]:
                raise ValueError("a parser defect in this unit")
            return real_run(engine)

        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_ATTEMPTS": "2", **FAST}), \
                patch.object(partitioned_scan.DSPMDiscoveryEngine, "run", fails_one):
            compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("reference"), request=REQUEST,
                                                            max_files=3)
        units = self._units(compact["scan_id"])
        self.assertEqual(sorted(unit["status"] for unit in units if unit["status"] != "done"), ["quarantined"])
        report = store.read_scan_report_compact(TENANT, compact["scan_id"])
        self.assertFalse(report["scan_diagnostics"]["incremental"]["complete"])
        self.assertEqual(len(report["scan_diagnostics"]["quarantined_units"]), 1)
        self.assertEqual(self._estate(), reference, "what the quarantined unit missed was treated as deleted")


# ── a file that hangs its parser ─────────────────────────────────────────────────────────
class AHungParserTest(_LocalGate):

    def test_the_file_is_failed_at_its_deadline_and_the_unit_completes(self) -> None:
        from collectors import content_policy, extract_worker

        hung = self.estate / "b_dept" / "contract.docx"
        hung.write_bytes(b"PK not really a document")
        reference = self._reference()
        self._fresh("hang")
        self.addCleanup(extract_worker.shutdown)
        with mock.patch.dict(os.environ, {"DSPM_FILE_DEADLINE_SECONDS": "2", **FAST}),                 patch.object(extract_worker, "EXTRACT_TARGET", "tests.fault_helpers:hang_extracting"):
            killed_before = extract_worker.killed_workers()
            compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("hang"), request=REQUEST,
                                                            max_files=3)
            killed = extract_worker.killed_workers() - killed_before
        self.assertGreaterEqual(killed, 1, "the hung worker was not killed")
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")
        report = store.read_scan_report(TENANT, compact["scan_id"])
        (record,) = [item for item in report["files"] if str(item["path"]).endswith("contract.docx")]
        self.assertEqual(content_policy.coverage_state(record), content_policy.FAILED)
        # Every other file as the uninterrupted run has it; the hung one present, its read failed.
        estate = dict(self._estate())
        others = {path: count for path, count in reference if not path.endswith("contract.docx")}
        self.assertEqual({path: estate[path] for path in others}, others)
        self.assertTrue(any(path.endswith("contract.docx") for path in estate))


# ── SMB: disconnect, and the server offline ──────────────────────────────────────────────
class _SmbGate(_Gate, _RangeTest):

    def _run(self, name: str) -> dict:
        self._fresh(name)
        return partitioned_scan.run_partitioned_scan(TENANT, self._config(name), request={"server": "fs"},
                                                     max_files=10)


class AnSmbDisconnectTest(_SmbGate):

    def test_a_reset_is_retried_without_an_attempt_and_the_estate_is_whole(self) -> None:
        self._run("reference")
        reference = self._estate()
        self.server.reset_folders[("Big", "/deep")] = 1
        with mock.patch.dict(os.environ, FAST):
            compact = self._run("reset")
        self.assertEqual(self.server.reset_folders[("Big", "/deep")], 0, "the reset never happened")
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")
        self._assert_no_attempt_spent(compact["scan_id"])
        self.assertEqual(self._estate(), reference)


class AnSmbServerOfflineTest(_SmbGate):

    def test_the_breaker_pauses_the_scan_units_keep_their_attempts_and_it_continues(self) -> None:
        self._run("reference")
        reference = self._estate()
        self._fresh("offline")
        record = partitioned_scan.start_partitioned_scan(TENANT, self._config("offline"), request={"server": "fs"},
                                                         max_files=10)
        self.assertEqual(partitioned_scan.wait_for_plan(TENANT, record["scan_id"], 60), "planned")
        with patch.object(partitioned_scan.DSPMDiscoveryEngine, "run", side_effect=ConnectionRefusedError()), \
                mock.patch.dict(os.environ, FAST):
            with self.assertRaises(partitioned_scan.ScanPaused):
                partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("offline"))
        stored = store.read_partitioned_scan(TENANT, record["scan_id"])
        self.assertTrue(store.scan_is_paused(stored))
        self.assertNotEqual(stored["status"], "failed")
        self.assertEqual({store.data_attempts(unit) for unit in self._units(record["scan_id"])}, {0})
        _unpause(record["scan_id"])
        compact = partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("offline"))
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")
        self.assertEqual(self._estate(), reference)


# ── WinRM: a hung command, and the endpoint offline ──────────────────────────────────────
class _EndpointGate(_EndpointTest):
    ENV = {"DSPM_PARTITION_MAX_FILES": "10", "DSPM_ENDPOINT_PAGE_FOLDERS": "2", **FAST}

    def _estate_now(self) -> list[tuple[str, int]]:
        return self._estate()

    def _reference(self, files) -> list[tuple[str, int]]:
        with mock.patch.dict(os.environ, self.ENV):
            self._scan(_Endpoint(files))
        reference = self._estate()
        store.delete_tenant_with_data(self.tenant)
        store.create_tenant(self.tenant, "Endpoint")
        return reference


class AHungWinrmCommandTest(_EndpointGate):

    def test_a_hung_command_costs_one_page(self) -> None:
        files = _tree(files_per_folder=12, folders=3)
        reference = self._reference(files)
        endpoint = _Endpoint(files)
        real = endpoint.run
        hung = {"left": 1}

        def hangs_once(script):
            if hung["left"] and "ConvertFrom-Json" in script:
                hung["left"] -= 1
                raise WinRMCommandTimedOut("the command ran past its wall clock")
            return real(script)

        endpoint.run = hangs_once  # type: ignore[method-assign]
        with mock.patch.dict(os.environ, self.ENV):
            compact = self._scan(endpoint)
        self.assertEqual(hung["left"], 0, "no command hung")
        units = store.list_scan_partitions(self.tenant, compact["scan_id"])
        self.assertEqual(store.read_partitioned_scan(self.tenant, compact["scan_id"])["status"], "done")
        self.assertEqual(sum(max(0, store.data_attempts(unit) - 1) for unit in units), 1,
                         "the hung command cost more than its page")
        self.assertEqual(self._estate(), reference)


class AnEndpointOfflineTest(_EndpointGate):

    def test_an_unreachable_endpoint_pauses_the_scan_and_it_continues(self) -> None:
        files = _tree(files_per_folder=12, folders=3)
        reference = self._reference(files)
        principal = Principal(subject="tester", role="admin", tenant_id=self.tenant, auth_type="session")
        payload = self._payload()
        config = app_module._to_endpoint_config(payload, self.tenant)

        def offline(_scanner, _script):
            raise ConnectionRefusedError("[WinError 10061] No connection could be made")

        with mock.patch.dict(os.environ, self.ENV), patch.object(WinRMEndpointScanner, "_run_ps_file", offline):
            with self.assertRaises(partitioned_scan.ScanPaused):
                app_module._run_endpoint_scan_payload(config, payload, principal)
        (record,) = [found for found in store.list_unfinished_partitioned_scans() if found["tenant_id"] == self.tenant]
        self.assertNotEqual(record["status"], "failed")
        self.assertTrue(store.scan_is_paused(store.read_partitioned_scan(self.tenant, record["scan_id"])))
        self.assertEqual({store.data_attempts(unit) for unit in store.list_scan_partitions(self.tenant,
                                                                                         record["scan_id"])}, {0})
        with db.tenant_scope(self.tenant):
            with store._connect() as conn:
                conn.execute("UPDATE partitioned_scans SET paused_until = '', pause_reason = '' WHERE tenant_id = ? "
                             "AND scan_id = ?", (self.tenant, record["scan_id"]))
        app_module._ENDPOINT_RUNS.clear()
        with mock.patch.dict(os.environ, self.ENV), self._serve(_Endpoint(files)):
            app_module._continue_endpoint_scan(record["scan_id"], payload, principal, None)
        self.assertEqual(store.read_partitioned_scan(self.tenant, record["scan_id"])["status"], "done")
        self.assertEqual(self._estate(), reference)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
