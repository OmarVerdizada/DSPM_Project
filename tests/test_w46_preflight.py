"""W4.6: a scan projected not to fit the disk is refused, with the numbers.

The disk floor (DSPM_MIN_FREE_DISK_MB) stopped a scan once a volume was already below it.
The pre-flight projects, as the plan grows, what the units still to read will write - the
measured per-file figures, a quarter again - onto each watched volume, and pauses the scan
while that would leave a volume below its floor. The reason says how many megabytes, for how
many files, on which volume, against how much free. The resume sweep tries it again; once
the space is there it runs.
"""
from __future__ import annotations

import os
import shutil
import unittest
from collections import namedtuple
from pathlib import Path
from unittest import mock

from backend import disk_guard, partitioned_scan, store
from tests.test_partitioned_local_scan import TENANT, _LocalTest
from tests.test_w42_unchanged_units_skipped import SKIP, _Parity

_Usage = namedtuple("_Usage", "total used free")
GIB = 1024 ** 3


class TheProjectionTest(unittest.TestCase):

    def test_what_will_not_fit_is_said_with_its_numbers(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_MIN_FREE_DISK_MB": "2048", "DSPM_DB_URL": ""}), \
                mock.patch.object(disk_guard, "watched_paths", return_value=[("data", Path("C:/"))]), \
                mock.patch.object(shutil, "disk_usage", return_value=_Usage(100 * GIB, 97 * GIB, 3 * GIB)):
            self.assertIsNone(disk_guard.preflight_reason(10_000))   # 10,000 x 32 KiB x 1.25: 390 MB
            reason = disk_guard.preflight_reason(100_000)             # 3.8 GB into 1 GB above the floor
        self.assertIsNotNone(reason)
        for fragment in ("3906 MB", "100000 files", "3072 MB free", "2048 MB floor", "DSPM_MIN_FREE_DISK_MB"):
            self.assertIn(fragment, reason)

    def test_postgresql_projects_its_tables_and_wal_onto_its_own_volumes(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_DB_URL": "postgresql://x@127.0.0.1/sentro_test"}):
            projected = disk_guard.projected_bytes(1000)
        self.assertEqual(projected["data"], 0)
        self.assertEqual(projected["postgresql data"], 64 * 1024 * 1000)
        self.assertEqual(projected["wal archive"], 32 * 1024 * 1000)

    def test_volumes_holding_several_things_add_them_up(self) -> None:
        paths = [("data", Path("C:/a")), ("artifacts", Path("C:/b"))]
        with mock.patch.dict(os.environ, {"DSPM_MIN_FREE_DISK_MB": "1", "DSPM_DB_URL": ""}), \
                mock.patch.object(disk_guard, "watched_paths", return_value=paths), \
                mock.patch.object(shutil, "disk_usage", return_value=_Usage(10 * GIB, 10 * GIB - 49 * 1024 * 1024,
                                                                            49 * 1024 * 1024)):
            # 1,000 files: 39 MB of database and 9.8 MB of artifacts, a quarter again included -
            # 48.8 MB on one 49 MB volume with a 1 MB floor. Either alone would fit.
            reason = disk_guard.preflight_reason(1000)
        self.assertIsNotNone(reason)
        self.assertIn("data and artifacts", reason)

    def test_no_floor_no_projection(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_MIN_FREE_DISK_MB": "0"}):
            self.assertIsNone(disk_guard.preflight_reason(10 ** 9))


class APlannedScanThatWillNotFitPausesTest(_LocalTest):

    def test_paused_with_the_numbers_then_run_once_it_fits(self) -> None:
        self._use_database("preflight")
        config = self._config("preflight")
        with mock.patch.dict(os.environ, {"DSPM_PREFLIGHT_LOCAL_KIB_PER_FILE": str(10 ** 9),
                                          "DSPM_PREFLIGHT_DB_KIB_PER_FILE": str(10 ** 9)}):
            record = partitioned_scan.start_partitioned_scan(TENANT, config, scan_label="estate", max_files=3,
                                                             request={"local_path": str(self.estate)})
            scan_id = str(record["scan_id"])
            partitioned_scan.wait_for_plan(TENANT, scan_id, 60)
            partitioned_scan.join_planners(60)
        paused = store.read_partitioned_scan(TENANT, scan_id)
        self.assertTrue(store.scan_is_paused(paused), paused)
        reason = str(paused["pause_reason"])
        self.assertTrue(reason.startswith("pre-flight: the scan is projected to write"), reason)
        self.assertIn("files it has to read", reason)
        with store._connect() as conn:
            written = conn.execute("SELECT COUNT(*) FROM assets WHERE tenant_id = ?", (TENANT,)).fetchone()[0]
        self.assertEqual(written, 0, "a refused scan wrote rows")
        # The space is there now, and the pause has run out: it runs to the end.
        with store._connect() as conn:
            conn.execute("UPDATE partitioned_scans SET paused_until = '' WHERE tenant_id = ? AND scan_id = ?",
                         (TENANT, scan_id))
        compact = partitioned_scan.continue_partitioned_scan(TENANT, scan_id, config)
        self.assertEqual(store.read_partitioned_scan(TENANT, scan_id)["status"], "done")
        self.assertGreater(int((compact.get("summary") or {}).get("total_files") or 0), 0)


class AnUnchangedRescanProjectsNothingTest(_Parity):
    """A unit skipped as unchanged writes nothing, so the pre-flight does not count it: a
    rescan that changes nothing runs on a disk that could not take the first scan."""

    def test_skipped_units_are_not_projected(self) -> None:
        self._scan(SKIP)
        with mock.patch.dict(os.environ, {"DSPM_PREFLIGHT_LOCAL_KIB_PER_FILE": str(10 ** 9),
                                          "DSPM_PREFLIGHT_DB_KIB_PER_FILE": str(10 ** 9)}):
            unchanged = self._scan(SKIP)
        scan_id = str(unchanged["scan_id"])
        self.assertEqual(store.read_partitioned_scan(SKIP, scan_id)["status"], "done")
        self.assertGreater(int((unchanged.get("scan_diagnostics") or {}).get("units_skipped") or 0), 0)
        self.assertEqual(store.pending_read_files(SKIP, scan_id, 1000), 0)


if __name__ == "__main__":
    unittest.main()
