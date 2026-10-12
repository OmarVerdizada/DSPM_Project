"""W4.2: when a unit is skipped, and when it is read instead.

Each condition of ``store._skip_unchanged_units`` is one a read would not survive, and each
is shown here doing its job - beside the parity tests (test_w42_unchanged_units_skipped):
an interrupted scan resumed answers as an uninterrupted one; a row or the records gone
since the last read make the unit a read, never a replay without them; an ACL with explicit
entries, or one due for its refresh, makes it a read (E14); the switches turn it off. And
the known limit, documented: a content change that keeps size and modified time is missed,
as per-file reuse misses it, until a scan with incremental reuse off reads everything.
"""
from __future__ import annotations

import os
import time
import unittest
from unittest import mock

from backend import partitioned_scan, store
from collectors import file_scanner
from tests.test_w42_unchanged_units_skipped import READ, SKIP, _incremental, _Parity


class _ProcessDied(BaseException):
    """What a killed process leaves: the scan recorded as running, its unit given back."""


def _skipped(compact: dict) -> int:
    return int((compact.get("scan_diagnostics") or {}).get("units_skipped") or 0)


def _units(compact: dict) -> int:
    return int(((compact.get("scan_diagnostics") or {}).get("partitioned") or {}).get("partitions") or 0)


class AnInterruptedScanResumesAsOneThatWasNotTest(_Parity):

    def test_a_scan_stopped_after_its_first_read_unit_resumes_into_the_same_answer(self) -> None:
        self._step("first scan")
        self._touch("b_dept/b1.txt", "\nand maria.lopez@example.com too\n")
        self._touch("h_mixed/sub_b/s3.txt", "\nquarterly budget notes, nothing sensitive\n")
        config = self._config(SKIP, tenant_id=SKIP, persistent_cache_enabled=False, max_depth=None, incremental_enabled=True,
                              incremental_scope="scope-w42",
                              baseline_probe=lambda key, size, mtime, version: store.probe_incremental_object(
                                  SKIP, "scope-w42", key, size, mtime, version))
        with mock.patch.dict(os.environ, {"DSPM_UNCHANGED_UNIT_SKIP": "1"}):
            record = partitioned_scan.start_partitioned_scan(
                SKIP, config, scan_label="estate", compliance_enabled=True, compliance_frameworks=list(self.frameworks),
                max_files=3, request={"local_path": str(self.estate)})
            scan_id = str(record["scan_id"])
            partitioned_scan.wait_for_plan(SKIP, scan_id, 60)
            written = []
            real = store.persist_partition

            def persist_once(*args, **kwargs):
                if written:
                    raise _ProcessDied("killed after its first read unit")
                written.append(real(*args, **kwargs))
                return written[-1]

            with mock.patch.object(store, "persist_partition", side_effect=persist_once):
                with self.assertRaises(_ProcessDied):
                    partitioned_scan.continue_partitioned_scan(SKIP, scan_id, config)
            units = store.list_scan_partitions(SKIP, scan_id)
            self.assertTrue(any(unit["skipped"] for unit in units), "nothing was skipped before the stop")
            self.assertTrue(any(unit["status"] == "queued" for unit in units), "the stop came too late")
            skipping = partitioned_scan.continue_partitioned_scan(SKIP, scan_id, config)
        partitioned_scan.join_planners(60)
        reading = self._scan(READ)
        mine, theirs = self._state(SKIP, skipping), self._state(READ, reading)
        for key in mine:
            self.assertEqual(mine[key], theirs[key], f"resumed: {key} differs")


class TheSizeAndModifiedTimeLimitTest(_Parity):
    """Documented, not fixed: a change that keeps size and modified time is invisible to a
    listing - to the unit skip and to per-file reuse alike. A scan with incremental reuse
    off reads every file and finds it."""

    def test_a_same_size_same_mtime_change_waits_for_a_full_scan(self) -> None:
        self._step("first scan")
        path = self.estate / "b_dept" / "b1.txt"
        before = path.stat()
        text = path.read_text(encoding="utf-8")
        path.write_text("contact zz@example.org" + text[len("contact zz@example.org"):], encoding="utf-8")
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(path.stat().st_size, before.st_size)
        skipping, _ = self._step("content changed under the same size and time")
        self.assertEqual(_skipped(skipping), _units(skipping), "the limit moved: update this test and the docs")
        full = partitioned_scan.run_partitioned_scan(
            SKIP, self._config(SKIP, tenant_id=SKIP, persistent_cache_enabled=False, max_depth=None, incremental_enabled=False,
                               incremental_scope="scope-w42"),
            scan_label="estate", compliance_enabled=True, compliance_frameworks=list(self.frameworks), max_files=3)
        partitioned_scan.join_planners(60)
        self.assertEqual(_skipped(full), 0)
        self.assertGreater(_incremental(full).get("content_reads") or 0, 0)


class WhatIsGoneMakesAReadTest(_Parity):

    def test_a_row_gone_from_a_skipped_units_coverage_reads_the_unit(self) -> None:
        first, _ = self._step("first scan")
        with store._connect() as conn:
            row = conn.execute("SELECT id, path FROM assets WHERE tenant_id = ? AND path LIKE ?",
                               (SKIP, "%d_flat%f04.txt")).fetchone()
            for table in ("asset_access", "findings"):
                conn.execute(f"DELETE FROM {table} WHERE tenant_id = ? AND asset_id = ?",  # noqa: S608
                             (SKIP, row["id"]))
            conn.execute("DELETE FROM assets WHERE tenant_id = ? AND id = ?", (SKIP, row["id"]))
        skipping = self._scan(SKIP)
        self.assertEqual(_skipped(skipping), _units(first) - 1, "a unit missing a row was replayed")
        with store._connect() as conn:
            self.assertIsNotNone(conn.execute("SELECT 1 FROM assets WHERE tenant_id = ? AND path = ?",
                                              (SKIP, row["path"])).fetchone(), "the row did not come back")

    def test_records_gone_from_the_store_read_the_unit(self) -> None:
        from backend import artifacts

        first, _ = self._step("first scan")
        with store._connect() as conn:
            ref = conn.execute("SELECT records_ref FROM scan_unit_manifest WHERE tenant_id = ? AND records_ref <> '' "
                               "ORDER BY unit_key LIMIT 1", (SKIP,)).fetchone()["records_ref"]
        artifacts.object_path(SKIP, str(ref)).unlink()
        skipping = self._scan(SKIP)
        self.assertLess(_skipped(skipping), _units(first), "a unit was replayed without its records")


class AclRulesTest(_Parity):

    def test_a_file_with_explicit_entries_keeps_its_unit_read(self) -> None:
        real = file_scanner.local_acl
        target = str((self.estate / "d_flat" / "f00.txt").resolve())

        def acl(path):
            value = real(path) or {}
            if str(path) == target or str(getattr(path, "resolve", lambda: path)()) == target:
                return {**value, "entries": [*(value.get("entries") or []), {"principal": "x", "inherited": False}]}
            return value

        with mock.patch.object(file_scanner, "local_acl", side_effect=acl):
            first, _ = self._step("first scan")
            again, _ = self._step("unchanged")
        self.assertEqual(_skipped(again), _units(first) - 1, "a unit with an explicit ACL entry was skipped")

    def test_an_acl_refresh_that_is_due_reads_the_units(self) -> None:
        first, _ = self._step("first scan")
        with store._connect() as conn:
            # A unit holding only folders with no file in them has no ACL to refresh.
            no_acl = int(conn.execute("SELECT COUNT(*) FROM scan_unit_manifest WHERE tenant_id = ? "
                                      "AND acl_checked_at = ''", (SKIP,)).fetchone()[0])
        self.assertLess(no_acl, _units(first))
        with mock.patch.dict(os.environ, {"DSPM_ACL_FULL_REFRESH_DAYS": "0.00002"}):  # 1.7 s
            time.sleep(2.0)
            due, _ = self._step("refresh due")
        self.assertEqual(_skipped(due), no_acl)
        with mock.patch.dict(os.environ, {"DSPM_ACL_FULL_REFRESH_DAYS": "0"}):
            every, _ = self._step("read on every scan")
        self.assertEqual(_skipped(every), 0)


class WhatAReadCannotStandForTest(_Parity):

    def test_a_file_whose_analysis_failed_keeps_its_unit_read(self) -> None:
        from discovery import discovery_engine

        real = discovery_engine.DSPMDiscoveryEngine._analyze_record
        target = "h3.txt"

        def analyze(engine, record):
            if str(record.get("path") or "").endswith(target):
                raise RuntimeError("the detector crashed")
            return real(engine, record)

        with mock.patch.object(discovery_engine.DSPMDiscoveryEngine, "_analyze_record", analyze):
            first, _ = self._step("first scan")
            again, _ = self._step("unchanged")
        self.assertEqual(_skipped(again), _units(first) - 1, "a failed analysis was replayed")

    def test_an_unreadable_folder_keeps_its_unit_read(self) -> None:
        from pathlib import Path

        real = Path.iterdir

        def iterdir(path):
            if path.name == "sub_b":
                raise PermissionError("access is denied")
            return real(path)

        with mock.patch.object(Path, "iterdir", iterdir):
            first, _ = self._step("first scan")
            again, _ = self._step("unchanged")
        self.assertLess(_skipped(again), _units(first), "a unit holding an unreadable folder was skipped")

    def test_a_change_that_keeps_size_but_moves_mtime_is_read(self) -> None:
        self._step("first scan")
        path = self.estate / "b_dept" / "b1.txt"
        text = path.read_text(encoding="utf-8")
        time.sleep(0.05)
        path.write_text("contact zz@example.org" + text[len("contact zz@example.org"):], encoding="utf-8")
        skipping, _ = self._step("same size, new time")
        self.assertEqual(_incremental(skipping).get("content_reads"), 1)

    def test_the_runs_drawer_answers_a_skipped_file_from_its_row(self) -> None:
        self._step("first scan")
        again, _ = self._step("unchanged")
        with store._connect() as conn:
            asset = conn.execute("SELECT id FROM assets WHERE tenant_id = ? ORDER BY id LIMIT 1", (SKIP,)).fetchone()
        with mock.patch.object(store, "_run_file_record", side_effect=AssertionError("walked the run's records")):
            detail = store.get_inventory_asset(SKIP, str(asset["id"]), scan_id=str(again["scan_id"]))
        self.assertEqual(detail["scan_id"], str(again["scan_id"]))


class PercentagesOfChangeTest(_Parity):
    """Section 25 W4.2: parity at 0, 1, 10 and 100% change - on an estate of 300 files in
    30 folders, where those are 3, 30 and 300 files."""

    def setUp(self) -> None:
        super().setUp()
        import shutil

        for child in list(self.estate.iterdir()):
            shutil.rmtree(child) if child.is_dir() else child.unlink()
        for index in range(300):
            folder = self.estate / f"dept{index % 6}" / f"team{index % 30:02d}"
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f"doc_{index:04d}.txt").write_text(
                f"contact person{index}@example.com about invoice {index}\n", encoding="utf-8")

    def _change(self, every: int, salt: str) -> None:
        time.sleep(0.02)
        for index in range(0, 300, every):
            path = self.estate / f"dept{index % 6}" / f"team{index % 30:02d}" / f"doc_{index:04d}.txt"
            path.write_text(path.read_text(encoding="utf-8") + f"changed {salt} owner{index}@example.org\n",
                            encoding="utf-8")

    def _scan(self, tenant: str) -> dict:
        # Units of 20 files, so a change lands in some units and not others.
        real = partitioned_scan.run_partitioned_scan

        def bounded(*args, **kwargs):
            kwargs["max_files"] = 20
            return real(*args, **kwargs)

        with mock.patch.object(partitioned_scan, "run_partitioned_scan", bounded):
            return super()._scan(tenant)

    def test_parity_at_every_percentage(self) -> None:
        first, _ = self._step("first scan")
        none, _ = self._step("0% changed")
        self.assertEqual(_skipped(none), _units(first))
        self._change(100, "one")
        one, _ = self._step("1% changed")
        self.assertEqual(_incremental(one).get("content_reads"), 3)
        self.assertGreater(_skipped(one), 0)
        self._change(10, "ten")
        ten, _ = self._step("10% changed")
        self.assertEqual(_incremental(ten).get("content_reads"), 30)
        self._change(1, "all")
        everything, _ = self._step("100% changed")
        self.assertEqual(_incremental(everything).get("content_reads"), 300)


class OverlappingScansOfOneLabelTest(_Parity):
    """Two scans of one label at once: the later one is planned - and skips - while the
    earlier is still running; the earlier finishes last and prunes nothing (W3.2); both
    answer as scans that read every unit."""

    def _overlap(self, tenant: str) -> tuple[dict, dict]:
        config = self._config(tenant, tenant_id=tenant, persistent_cache_enabled=False, max_depth=None,
                              incremental_enabled=True, incremental_scope="scope-w42",
                              baseline_probe=lambda key, size, mtime, version: store.probe_incremental_object(
                                  tenant, "scope-w42", key, size, mtime, version))
        with mock.patch.dict(os.environ, {"DSPM_UNCHANGED_UNIT_SKIP": "1" if tenant == SKIP else "0"}):
            started = []
            for _ in range(2):
                record = partitioned_scan.start_partitioned_scan(
                    tenant, config, scan_label="estate", compliance_enabled=True,
                    compliance_frameworks=list(self.frameworks), max_files=3, request={"local_path": str(self.estate)})
                partitioned_scan.wait_for_plan(tenant, str(record["scan_id"]), 60)
                started.append(str(record["scan_id"]))
                time.sleep(0.01)
            later = partitioned_scan.continue_partitioned_scan(tenant, started[1], config)
            earlier = partitioned_scan.continue_partitioned_scan(tenant, started[0], config)
        partitioned_scan.join_planners(60)
        return earlier, later

    def test_the_earlier_finishing_last_changes_nothing_the_later_saw(self) -> None:
        self._step("first scan")
        self._touch("b_dept/b1.txt", "\nand maria.lopez@example.com too\n")
        shutil_rmtree = __import__("shutil").rmtree
        shutil_rmtree(self.estate / "h_mixed" / "sub_a")
        (_skip_earlier, skip_later), (_read_earlier, read_later) = self._overlap(SKIP), self._overlap(READ)
        self.assertGreater(_skipped(skip_later), 0, "the later scan skipped nothing")
        mine, theirs = self._state(SKIP, skip_later), self._state(READ, read_later)
        for key in ("assets", "findings", "baselines", "records", "summary", "sections"):
            self.assertEqual(mine[key], theirs[key], f"overlapping: {key} differs")


class TheSwitchesTest(_Parity):

    def test_off_incremental_off_and_a_stored_body_read_every_unit(self) -> None:
        first, _ = self._step("first scan")
        for name, env in (("switch off", {"DSPM_UNCHANGED_UNIT_SKIP": "0"}),
                          ("report body stored", {"DSPM_STORE_REPORT_BODY": "1"})):
            with mock.patch.dict(os.environ, env):
                config = self._config(SKIP, tenant_id=SKIP, persistent_cache_enabled=False, max_depth=None, incremental_enabled=True,
                                      incremental_scope="scope-w42",
                                      baseline_probe=lambda key, size, mtime, version: store.probe_incremental_object(
                                          SKIP, "scope-w42", key, size, mtime, version))
                compact = partitioned_scan.run_partitioned_scan(
                    SKIP, config, scan_label="estate", compliance_enabled=True,
                    compliance_frameworks=list(self.frameworks), max_files=3)
                partitioned_scan.join_planners(60)
            self.assertEqual(_skipped(compact), 0, name)
        full = partitioned_scan.run_partitioned_scan(
            SKIP, self._config(SKIP, tenant_id=SKIP, persistent_cache_enabled=False, max_depth=None, incremental_enabled=False,
                               incremental_scope="scope-w42"),
            scan_label="estate", compliance_enabled=True, compliance_frameworks=list(self.frameworks), max_files=3)
        partitioned_scan.join_planners(60)
        self.assertEqual(_skipped(full), 0, "incremental off")
        # ... and with it on, everything unchanged is skipped again.
        again, _ = self._step("on again")
        self.assertEqual(_skipped(again), _units(first))


if __name__ == "__main__":
    unittest.main()
