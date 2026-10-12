"""Disk floor and WAL archive health (WAL/archive workstream, 2026-10).

The test cluster's WAL archive grew to 30 GB with no base backup and no retention, and a
benchmark once left the system drive with 40 MB - PostgreSQL stops when it cannot write
WAL, and every scan and click stops with it. A scan now refuses to start, and a running
partitioned scan pauses, while a volume it writes to is below the floor; and the archive's
own state - not only the archiver's - is reported.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from collections import namedtuple
from pathlib import Path
from unittest import mock
from unittest.mock import patch

from backend import disk_guard, observability, partitioned_scan, store
from tests.test_partitioned_local_scan import TENANT, _LocalTest

_Usage = namedtuple("_Usage", "total used free")


def _usage(free_mb: int):
    return lambda _path: _Usage(100 * 1024 ** 3, 0, free_mb * 1024 * 1024)


class TheDiskFloorTest(unittest.TestCase):

    def test_below_the_floor_says_which_volume_and_by_how_much(self) -> None:
        with patch.object(disk_guard.shutil, "disk_usage", _usage(500)), \
                mock.patch.dict(os.environ, {"DSPM_MIN_FREE_DISK_MB": "2048"}):
            reason = disk_guard.low_space_reason()
        self.assertIn("500 MB", reason)
        self.assertIn("2048 MB floor", reason)

    def test_above_the_floor_or_with_the_floor_off_says_nothing(self) -> None:
        with patch.object(disk_guard.shutil, "disk_usage", _usage(5000)):
            self.assertIsNone(disk_guard.low_space_reason())
        with patch.object(disk_guard.shutil, "disk_usage", _usage(10)), \
                mock.patch.dict(os.environ, {"DSPM_MIN_FREE_DISK_MB": "0"}):
            self.assertIsNone(disk_guard.low_space_reason())

    def test_the_database_and_archive_volumes_are_watched_when_configured(self) -> None:
        with tempfile.TemporaryDirectory() as pgdata, tempfile.TemporaryDirectory() as archive, \
                mock.patch.dict(os.environ, {"DSPM_PG_DATA_DIR": pgdata, "DSPM_WAL_ARCHIVE_DIR": archive}):
            labels = {label for label, _path in disk_guard.watched_paths()}
        self.assertLessEqual({"data", "artifacts", "postgresql data", "wal archive"}, labels)


class AScanNeedsRoomTest(unittest.TestCase):

    def test_a_scan_is_refused_with_507_below_the_floor(self) -> None:
        from fastapi import HTTPException

        from backend import app as app_module

        with patch.object(disk_guard.shutil, "disk_usage", _usage(100)),                 self.assertRaises(HTTPException) as refused:
            app_module._require_scan_licence()
        self.assertEqual(refused.exception.status_code, 507)
        self.assertIn("Scan not started", refused.exception.detail)
        # The way out is room on the volume; lowering the floor is not advice to give.
        self.assertNotIn("lower DSPM_MIN_FREE_DISK_MB", refused.exception.detail)


class APartitionedScanPausesOnALowDiskTest(_LocalTest):

    def test_it_pauses_unfinished_and_the_job_says_why(self) -> None:
        from backend import jobs

        self._use_database("low-disk")
        record = partitioned_scan.start_partitioned_scan(TENANT, self._config("low-disk"),
                                                         request={"local_path": "estate"}, max_files=3)
        self.assertEqual(partitioned_scan.wait_for_plan(TENANT, record["scan_id"], 60), "planned")
        with patch.object(disk_guard.shutil, "disk_usage", _usage(100)),                 self.assertRaisesRegex(partitioned_scan.ScanPaused, "free disk") as paused:
            partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("low-disk"))
        self.assertEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "running")
        self.assertEqual({unit["status"] for unit in store.list_scan_partitions(TENANT, record["scan_id"])}, {"queued"},
                         "a unit was written into a full disk")
        self.assertIn("free disk space is low", jobs._safe_job_error(paused.exception))


class TheArchiveIsWatchedTest(unittest.TestCase):

    def _archive(self, root: Path, segments: int, *, base_backup: bool) -> None:
        for index in range(segments):
            (root / f"00000001000000000000{index:04X}").write_bytes(b"\0" * 1024)
        if base_backup:
            (root / "000000010000000000000002.00000028.backup").write_text("START WAL LOCATION: 0/2000028")

    def test_an_archive_without_a_base_backup_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as root, mock.patch.dict(os.environ, {"DSPM_WAL_ARCHIVE_DIR": root}):
            self._archive(Path(root), 5, base_backup=False)
            metrics = observability.wal_archive_dir_metrics()
            warnings = observability._warnings({"wal_archive_dir": metrics})
        self.assertEqual((metrics["segments"], metrics["base_backups"]), (5, 0))
        self.assertTrue(any("no base backup" in warning for warning in warnings), warnings)

    def test_an_archive_with_a_base_backup_and_room_is_quiet(self) -> None:
        with tempfile.TemporaryDirectory() as root, mock.patch.dict(os.environ, {"DSPM_WAL_ARCHIVE_DIR": root}), \
                patch.object(observability.shutil, "disk_usage", _usage(50_000)):
            self._archive(Path(root), 5, base_backup=True)
            warnings = observability._warnings({"wal_archive_dir": observability.wal_archive_dir_metrics()})
        self.assertEqual(warnings, [])

    def test_an_archive_past_its_size_bound_is_reported(self) -> None:
        metrics = {"configured": True, "exists": True, "segments": 3000, "base_backups": 1,
                   "bytes": 48 * 1024 ** 3, "volume_free_ratio": 0.5}
        with mock.patch.dict(os.environ, {"DSPM_WAL_ARCHIVE_WARN_GB": "20"}):
            warnings = observability._warnings({"wal_archive_dir": metrics})
        self.assertTrue(any("48.0 GB" in warning for warning in warnings), warnings)

    def test_not_configured_is_not_a_warning(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_WAL_ARCHIVE_DIR": ""}):
            self.assertEqual(observability.wal_archive_dir_metrics(), {"configured": False})


class TheTuningAdvisorCountsEveryPoolTest(unittest.TestCase):
    """scripts/pg_tuning_advisor.py sized max_connections from DSPM_DB_POOL_MAX alone; since
    W3.4 a process has a pool per workload - scan, api and heavy - and all three can be full."""

    def test_max_connections_covers_the_three_pools_of_each_process(self) -> None:
        from scripts import pg_tuning_advisor

        names = ("DSPM_DB_POOL_MAX", "DSPM_DB_POOL_MAX_API", "DSPM_DB_POOL_MAX_HEAVY")
        with mock.patch.dict(os.environ, dict.fromkeys(names, "")):
            self.assertEqual(pg_tuning_advisor.per_process_pool(), 10 + 8 + 2)
        with mock.patch.dict(os.environ, {"DSPM_DB_POOL_MAX": "6", "DSPM_DB_POOL_MAX_API": "4",
                                          "DSPM_DB_POOL_MAX_HEAVY": "1"}):
            pool = 4 * pg_tuning_advisor.per_process_pool()
        advice = pg_tuning_advisor.recommend(16 * 1024 ** 3, 6, True, pool)
        self.assertEqual(advice["max_connections"][0], str(4 * 11 + 20))
