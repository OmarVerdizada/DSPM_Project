"""W4.6: scans are admitted in the ledger, and a node profile sets the budget together.

Nothing bounded how many scans ran at once across an installation's processes. A scan's
runner now takes one of ``DSPM_MAX_RUNNING_SCANS`` slots, counted in the ledger under one
lock - admitted, unfinished, unpaused and alive scans - before it claims a unit; over the
limit it pauses, saying how many are running, and runs once a slot is free. A runner that
died gives its slot back once it has looked idle as long as a dead finalize does.

``DSPM_NODE_PROFILE`` (16gb, 32gb) fills admission, detector processes, workers and the
database pools that neither the environment nor the file set.
"""
from __future__ import annotations

import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from backend import config, partitioned_scan, store
from tests.test_partitioned_local_scan import TENANT, _LocalTest


class TheLedgerAdmitsScansTest(_LocalTest):

    def _start(self, config_):
        record = partitioned_scan.start_partitioned_scan(TENANT, config_, scan_label="estate", max_files=3,
                                                         request={"local_path": str(self.estate)})
        scan_id = str(record["scan_id"])
        partitioned_scan.wait_for_plan(TENANT, scan_id, 60)
        return scan_id

    def test_over_the_limit_a_scan_waits_paused_then_runs(self) -> None:
        self._use_database("admission")
        config_ = self._config("admission")
        with mock.patch.dict(os.environ, {"DSPM_MAX_RUNNING_SCANS": "1"}):
            first, second = self._start(config_), self._start(config_)
            admitted, others = store.admit_partitioned_scan(TENANT, first, limit=1, alive_seconds=60)
            self.assertEqual((admitted, others), (True, 0))
            with self.assertRaises(partitioned_scan.ScanPaused):
                partitioned_scan.continue_partitioned_scan(TENANT, second, config_)
            waiting = store.read_partitioned_scan(TENANT, second)
            self.assertTrue(store.scan_is_paused(waiting))
            self.assertEqual(waiting["pause_reason"], "waiting for a scan slot: 1 of 1 scans are running on this "
                                                      "installation (DSPM_MAX_RUNNING_SCANS)")
            with store._connect() as conn:
                claimed = conn.execute("SELECT COUNT(*) FROM scan_partitions WHERE tenant_id = ? AND scan_id = ? "
                                       "AND status <> 'queued'", (TENANT, second)).fetchone()[0]
            self.assertEqual(claimed, 0, "a scan waiting for a slot claimed a unit")
            # The first runs - the waiting one holds no slot - and finishes; then the second.
            partitioned_scan.continue_partitioned_scan(TENANT, first, config_)
            with store._connect() as conn:
                conn.execute("UPDATE partitioned_scans SET paused_until = '' WHERE tenant_id = ? AND scan_id = ?",
                             (TENANT, second))
            partitioned_scan.continue_partitioned_scan(TENANT, second, config_)
        partitioned_scan.join_planners(60)
        for scan_id in (first, second):
            self.assertEqual(store.read_partitioned_scan(TENANT, scan_id)["status"], "done")

    def test_a_runner_that_died_gives_its_slot_back(self) -> None:
        self._use_database("admission-dead")
        config_ = self._config("admission-dead")
        first, second = self._start(config_), self._start(config_)
        self.assertTrue(store.admit_partitioned_scan(TENANT, first, limit=1, alive_seconds=60)[0])
        self.assertFalse(store.admit_partitioned_scan(TENANT, second, limit=1, alive_seconds=60)[0])
        stale = (datetime.now(timezone.utc) - timedelta(seconds=600)).isoformat()
        with store._connect() as conn:
            conn.execute("UPDATE partitioned_scans SET updated_at = ? WHERE tenant_id = ? AND scan_id = ?",
                         (stale, TENANT, first))
        self.assertTrue(store.admit_partitioned_scan(TENANT, second, limit=1, alive_seconds=60)[0])
        # ... and a paused scan holds none either.
        store.pause_partitioned_scan(TENANT, second, "disk", seconds=600)
        self.assertTrue(store.admit_partitioned_scan(TENANT, first, limit=1, alive_seconds=60)[0])
        partitioned_scan.join_planners(60)

    def test_the_limit_defaults_to_two_and_is_bounded(self) -> None:
        for value, expected in ((None, 2), ("1", 1), ("0", 1), ("500", 64), ("x", 2)):
            with self.subTest(value=value), mock.patch.dict(os.environ, {} if value is None
                                                            else {"DSPM_MAX_RUNNING_SCANS": value}):
                if value is None:
                    os.environ.pop("DSPM_MAX_RUNNING_SCANS", None)
                self.assertEqual(partitioned_scan.max_running_scans(), expected)


class NodeProfilesTest(unittest.TestCase):

    def test_a_profile_fills_what_is_not_set(self) -> None:
        effective = config.resolve({"DSPM_NODE_PROFILE": "16gb", "DSPM_JOB_WORKERS": "5"})
        self.assertEqual(effective.errors, [])
        self.assertEqual((effective.get("DSPM_MAX_RUNNING_SCANS"), effective.values["DSPM_MAX_RUNNING_SCANS"].source),
                         ("1", "profile"))
        self.assertEqual(effective.get("DSPM_DETECTOR_PROCESSES"), "6")
        self.assertEqual((effective.get("DSPM_JOB_WORKERS"), effective.values["DSPM_JOB_WORKERS"].source),
                         ("5", "environment"), "what the environment sets wins")
        bigger = config.resolve({"DSPM_NODE_PROFILE": "32gb"})
        self.assertEqual((bigger.get("DSPM_MAX_RUNNING_SCANS"), bigger.get("DSPM_DB_POOL_MAX")), ("2", "16"))
        self.assertEqual(config.resolve({}).get("DSPM_MAX_RUNNING_SCANS"), "2", "no profile: the default")

    def test_applied_into_the_environment_the_product_reads(self) -> None:
        environ = {"DSPM_NODE_PROFILE": "32gb"}
        config.apply(config.resolve(environ), environ)
        self.assertEqual((environ["DSPM_MAX_RUNNING_SCANS"], environ["DSPM_DB_POOL_MAX_API"]), ("2", "16"))

    def test_an_unknown_profile_is_refused(self) -> None:
        effective = config.resolve({"DSPM_NODE_PROFILE": "8gb"})
        self.assertTrue(any("DSPM_NODE_PROFILE must be one of" in error for error in effective.errors))

    def test_partition_workers_stay_at_one_until_w43_measures_them(self) -> None:
        for profile in config.NODE_PROFILES.values():
            self.assertEqual(profile["DSPM_PARTITION_WORKERS"], "1")


if __name__ == "__main__":
    unittest.main()
