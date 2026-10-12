"""W3.1 (scaling roadmap, section 24): no exit from the bounded path.

A scan larger than one unit used to run whole - unbounded - when planning hit an SMB reset,
when its shares overlapped, when a file was named ``_manifest.json``, and past 2,147 units
the planner doubled its budgets instead. Planning held the whole plan before the first unit
ran, and an interrupted plan started over.

Now: the plan has no ceiling; it is cut by a streaming cutter and appended to the ledger
while it is made, so the first unit runs before planning ends and an interrupted plan
continues from its cursor; a planning failure is retried and then pauses the scan;
overlapping shares are paired inside units; a folder is listed once for all the units cut
from it; and a unit weighs only the bytes the scan reads, local units included.

Fake transports: the fake SMB servers of the B2.3 and W1.2 tests, and an injected database
error for an outage while planning.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
import unittest
from unittest import mock
from unittest.mock import patch

from backend import db, partitioned_scan, store
from collectors import content_policy, file_scanner
from collectors.smb_scanner import SMBScanner, _SmbConnectionLost
from discovery.cutter import AFTER, END, Cutter, Entry
from discovery.discovery_engine import DSPMDiscoveryEngine
from discovery.partition import plan_bounded_partitions, plan_share_partitions, share_nesting
from tests.test_partitioned_local_scan import TENANT, _LocalTest, _write
from tests.test_partitioned_smb_scan import POLICY, PAYROLL, _SmbTest
from tests.test_w12_smb_range_units import _RangeTest

REQUEST = {"local_path": "estate"}
SMB_REQUEST = {"server": "fs", "username": "svc", "domain": "CORP"}
FAST = {"DSPM_INFRA_RETRY_SECONDS": "0", "DSPM_PARTITION_RETRY_SECONDS": "0"}


def _unpause(scan_id: str) -> None:
    """The pause has run its course."""
    with store._connect() as conn:
        conn.execute("UPDATE partitioned_scans SET paused_until = '', pause_reason = '' WHERE tenant_id = ? "
                     "AND scan_id = ?", (TENANT, scan_id))


def _report_paths(compact: dict) -> list[str]:
    return [str(record["path"]) for record in store.read_scan_report(TENANT, compact["scan_id"])["files"]]


class AUnitWeighsWhatTheScanReadsTest(unittest.TestCase):

    def test_types_the_scan_does_not_read_weigh_nothing(self) -> None:
        weigh = file_scanner.inspected_bytes
        text_cap, document_cap = content_policy.text_cap_bytes(), content_policy.document_cap_bytes()
        self.assertEqual(weigh(".bin", 5 << 30), 0)
        self.assertEqual(weigh(".mp4", 5 << 30), 0)
        self.assertEqual(weigh(".txt", 100), 100)
        self.assertEqual(weigh(".txt", text_cap * 10), text_cap, "a text file is read up to its cap")
        self.assertEqual(weigh(".pdf", document_cap), document_cap, "a document within its cap is read whole")
        self.assertEqual(weigh(".pdf", document_cap + 1), 0, "a document over its cap is not read")
        self.assertEqual(weigh(".txt", 100, read_content=False), 0, "an inventory scan reads nothing")
        self.assertEqual(weigh(".txt", 100, allowed={".pdf"}), 0, "a type the policy leaves out")
        self.assertEqual(weigh(".zip", 100), 0)
        self.assertEqual(weigh(".zip", 100, inspect_archives=True), 100)


class TheCutterTest(unittest.TestCase):
    """The cutter alone, over a tree of nested dicts: a folder is a dict, a file its weight."""

    TREE = {
        "a": {f"f{index}": 10 for index in range(5)},
        "b.txt": 10,
        "c": {"d": {f"g{index}": 10 for index in range(4)}, "e.txt": 10},
        "z.txt": 10,
    }

    def _run(self, tree: dict, *, files: int = 2, cursor: tuple = (), keep_gaps=None, crash_after: int | None = None):
        units: list[tuple] = []

        def node_of(path: tuple):
            node = tree
            for name in path:
                node = node[name]
            return node

        def list_folder(path, _depth):
            for name, node in sorted(node_of(path).items()):
                if isinstance(node, dict):
                    yield Entry(name, name, True), path + (name,)
                else:
                    yield Entry(name, name, False, 1, node), None

        def make_unit(path, _depth, entries, low, high):
            return ("/".join(path), low, high, tuple(entry.name for entry in entries))

        def emit(unit, unit_cursor):
            if crash_after is not None and len(units) >= crash_after:
                raise ConnectionError("the planner died here")
            units.append((unit, unit_cursor))

        cutter = Cutter(files_budget=files, bytes_budget=1 << 40, list_folder=list_folder, make_unit=make_unit,
                        emit=emit, cursor=cursor, keep_gaps=keep_gaps)
        try:
            cutter.run(())
        except ConnectionError:
            pass
        return units

    def test_there_is_no_ceiling_on_the_units(self) -> None:
        flat = {f"f{index:05d}": 1 for index in range(3_000)}
        units = self._run(flat, files=1)
        self.assertEqual(len(units), 3_000, "the plan was capped or its budget doubled")

    def test_a_plan_continued_from_its_cursor_writes_nothing_twice(self) -> None:
        whole = [unit for unit, _cursor in self._run(self.TREE)]
        self.assertGreater(len(whole), 4)
        for crash_after in range(1, len(whole)):
            first = self._run(self.TREE, crash_after=crash_after)
            rest = self._run(self.TREE, cursor=first[-1][1])
            self.assertEqual([unit for unit, _cursor in first] + [unit for unit, _cursor in rest], whole,
                             f"continued after unit {crash_after}")

    def test_an_empty_range_is_not_a_unit_unless_the_folder_listing_is_not_known(self) -> None:
        tree = {"a": {f"f{index}": 1 for index in range(3)}, "b": {f"g{index}": 1 for index in range(3)}}
        root_units = [unit for unit, _cursor in self._run(tree) if unit[0] == ""]
        self.assertEqual(root_units, [], "a range that held nothing when it was listed became a unit")
        gaps = [unit[1:3] for unit, _cursor in self._run(tree, keep_gaps=lambda path: path == ()) if unit[0] == ""]
        self.assertEqual(gaps, [("", "a"), ("a" + AFTER, "b"), ("b" + AFTER, END)],
                         "a folder whose listing is not known left names between two units")


class TheLocalPlanTest(_LocalTest):

    def test_local_units_get_the_byte_budget(self) -> None:
        folder = self.base / "bytes"
        for index in range(8):
            (folder / f"f{index}.txt").parent.mkdir(parents=True, exist_ok=True)
            (folder / f"f{index}.txt").write_bytes(b"x" * 1000)
        (folder / "movie.mp4").write_bytes(b"x" * 50_000)
        plan = plan_bounded_partitions(self._config(local_path=str(folder)), max_files=1000, max_bytes=2500)
        self.assertIsNotNone(plan, "eight 1,000-byte text files fit one unit by files alone")
        weights = [sum(file_scanner.inspected_bytes(file_scanner.detect_extension(name), (folder / name).stat().st_size)
                       for name in unit["names"]) for unit in plan["units"]]
        self.assertEqual(weights, [2000, 2000, 2000, 2000], "the media file weighed in, or the bytes did not bound")

    def test_a_plan_of_two_units_runs_partitioned(self) -> None:
        self._use_database("two")
        folder = self.base / "two"
        for index in range(4):
            _write(folder / f"f{index}.txt", index)
        compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("two", local_path=str(folder)),
                                                        request=REQUEST, max_files=2)
        self.assertIsNotNone(compact, "a target of two units ran whole")
        self.assertEqual(len(store.list_scan_partitions(TENANT, compact["scan_id"])), 2)

    def test_a_target_that_fits_one_unit_runs_whole_and_leaves_no_record(self) -> None:
        self._use_database("one")
        folder = self.base / "one"
        for index in range(2):
            _write(folder / f"f{index}.txt", index)
        self.assertIsNone(partitioned_scan.run_partitioned_scan(TENANT, self._config("one", local_path=str(folder)),
                                                                request=REQUEST, max_files=3))
        with store._connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM partitioned_scans").fetchone()[0], 0,
                             "the record of a scan that ran whole was left for the resume sweep")

    def test_units_run_before_planning_ends(self) -> None:
        self._use_database("overlap")
        whole = DSPMDiscoveryEngine(self._config("whole")).run().to_dict()
        real_emit = partitioned_scan._LedgerPlanner._emit
        seen = {"emitted": 0, "ran_while_planning": False}

        def held_emit(planner, unit, cursor):
            seen["emitted"] += 1
            if seen["emitted"] == 5:
                # Hold the planner until a unit it already wrote has run.
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    if store.scan_partition_summary(TENANT, planner.scan_id)["done"]:
                        seen["ran_while_planning"] = True
                        break
                    time.sleep(0.05)
            return real_emit(planner, unit, cursor)

        with patch.object(partitioned_scan._LedgerPlanner, "_emit", held_emit):
            compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("overlap"), request=REQUEST,
                                                            max_files=3)
        self.assertTrue(seen["ran_while_planning"], "no unit ran before planning ended")
        self.assertEqual(_report_paths(compact), [str(record["path"]) for record in whole["files"]])
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["plan_state"], "planned")

    def test_an_interrupted_plan_continues_from_its_cursor(self) -> None:
        self._use_database("cursor")
        expected = plan_bounded_partitions(self._config("cursor"), max_files=3)["units"]
        whole = DSPMDiscoveryEngine(self._config("whole")).run().to_dict()
        real_append = store.append_planned_units
        outage = {"on": True, "calls": 0}

        def append(*args, **kwargs):
            outage["calls"] += 1
            if outage["on"] and outage["calls"] >= 2:
                raise sqlite3.OperationalError("database is locked")
            return real_append(*args, **kwargs)

        with mock.patch.dict(os.environ, {**FAST, "DSPM_INFRA_RETRIES": "2"}), \
                patch.object(store, "append_planned_units", append), \
                patch.object(partitioned_scan, "_PLAN_BATCH_UNITS", 1):
            record = partitioned_scan.start_partitioned_scan(TENANT, self._config("cursor"), request=REQUEST,
                                                             max_files=3)
            with self.assertRaisesRegex(partitioned_scan.ScanPaused, "planning stopped"):
                partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("cursor"))
            stored = store.read_partitioned_scan(TENANT, record["scan_id"])
            self.assertEqual((stored["status"], stored["plan_state"]), ("running", "planning"),
                             "an outage while planning failed the scan or ended its plan")
            self.assertEqual(len(store.list_scan_partitions(TENANT, record["scan_id"])), 2)
            outage["on"] = False
            _unpause(record["scan_id"])
            compact = partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("cursor"))
        units = store.list_scan_partitions(TENANT, record["scan_id"])
        self.assertEqual([unit["spec"] for unit in units], expected, "the continued plan is not the plan")
        self.assertEqual([unit["ordinal"] for unit in units], list(range(len(expected))))
        self.assertEqual(_report_paths(compact), [str(record["path"]) for record in whole["files"]])

    def test_a_plan_interrupted_before_its_first_unit_is_continued_as_one_unit(self) -> None:
        # The record is written before planning. A planner that died before it wrote a unit
        # is continued by the resume, which may find the target fits one unit: it runs as
        # that one unit, over the whole folder - not as nothing.
        self._use_database("early")
        folder = self.base / "early"
        for index in range(2):
            _write(folder / f"f{index}.txt", index)
        scan_id = "20990101000000000000"
        store.register_partitioned_scan(TENANT, scan_id, job_id="", request=REQUEST, planning=True, header={
            "source": "local", "local_path": str(folder), "max_depth": 4, "scan_root": str(folder.resolve()),
            "max_files": 3, "timestamp": "2099-01-01T00:00:00+00:00"})
        compact = partitioned_scan.continue_partitioned_scan(TENANT, scan_id,
                                                             self._config("early", local_path=str(folder)))
        self.assertEqual(sorted(os.path.basename(path) for path in _report_paths(compact)), ["f0.txt", "f1.txt"])
        (unit,) = store.list_scan_partitions(TENANT, scan_id)
        self.assertNotIn("names", unit["spec"])

    def test_a_planning_defect_fails_the_scan_and_does_not_run_it_whole(self) -> None:
        self._use_database("defect")
        with patch.object(partitioned_scan, "plan_bounded_partitions", side_effect=ValueError("a planner defect")):
            with self.assertRaisesRegex(partitioned_scan.ScanStopped, "Planning the scan failed"):
                partitioned_scan.run_partitioned_scan(TENANT, self._config("defect"), request=REQUEST, max_files=3)
        with store._connect() as conn:
            statuses = [str(row[0]) for row in conn.execute("SELECT status FROM partitioned_scans").fetchall()]
        self.assertEqual(statuses, ["failed"])


class TheLedgerFencesThePlanTest(_LocalTest):

    def _planning(self) -> str:
        self._use_database("fence")
        store.register_partitioned_scan(TENANT, "scan-p", job_id="", request={}, header={}, planning=True)
        return "scan-p"

    def test_only_the_planner_at_the_cursor_appends(self) -> None:
        scan_id = self._planning()
        self.assertEqual(store.append_planned_units(TENANT, scan_id, [{"n": 1}], cursor={"path": ["a"]},
                                                    expected_cursor=None), ["p00000"])
        self.assertIsNone(store.append_planned_units(TENANT, scan_id, [{"n": 2}], cursor={"path": ["b"]},
                                                     expected_cursor=None), "a second planner appended")
        self.assertFalse(store.finish_planning(TENANT, scan_id, expected_cursor=None))
        self.assertEqual(len(store.list_scan_partitions(TENANT, scan_id)), 1)
        self.assertTrue(store.finish_planning(TENANT, scan_id, expected_cursor={"path": ["a"]}))

    def test_a_scan_still_being_planned_does_not_finalize(self) -> None:
        scan_id = self._planning()
        store.append_planned_units(TENANT, scan_id, [{"n": 1}], cursor={"path": ["a"]}, expected_cursor=None)
        with store._connect() as conn:
            conn.execute("UPDATE scan_partitions SET status = 'done' WHERE tenant_id = ?", (TENANT,))
        self.assertFalse(store.claim_scan_finalize(TENANT, scan_id), "a scan with units to come was finalized")
        with self.assertRaises(store.PartitionsNotFinished):
            store.finalize_partitioned_scan(TENANT, scan_id, {"files": [], "summary": {}}, write_estate=False,
                                            file_count=0, sample_count=0)

    def test_a_record_with_a_unit_is_never_discarded(self) -> None:
        scan_id = self._planning()
        store.append_planned_units(TENANT, scan_id, [{"n": 1}], cursor={"path": ["a"]}, expected_cursor=None)
        self.assertFalse(store.discard_partitioned_scan(TENANT, scan_id))
        self.assertIsNotNone(store.read_partitioned_scan(TENANT, scan_id))


class AnSmbPlanTest(_RangeTest):

    def test_a_reset_while_planning_pauses_the_scan_instead_of_running_it_whole(self) -> None:
        self._use_database("plan-reset")
        whole = DSPMDiscoveryEngine(self._config("whole")).run().to_dict()
        self.server.reset_folders[("Big", "/deep")] = 10_000
        with mock.patch.dict(os.environ, {**FAST, "DSPM_INFRA_RETRIES": "2"}):
            with self.assertRaises(partitioned_scan.ScanPaused):
                partitioned_scan.run_partitioned_scan(TENANT, self._config("plan-reset"), request=SMB_REQUEST,
                                                      scan_label="fileserver", max_files=10)
        (record,) = store.list_unfinished_partitioned_scans()
        self.assertEqual(record["plan_state"], "planning")
        self.server.reset_folders.clear()
        _unpause(record["scan_id"])
        compact = partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("plan-reset"))
        partitioned = store.read_scan_report(TENANT, compact["scan_id"])
        self.assertEqual([(f["share"], f["path"]) for f in partitioned["files"]],
                         [(f["share"], f["path"]) for f in whole["files"]])
        self.assertTrue(partitioned["scan_diagnostics"]["incremental"]["complete"])

    def test_listing_slices_are_kept_until_the_scan_finalizes(self) -> None:
        self._use_database("slices")
        record = partitioned_scan.start_partitioned_scan(TENANT, self._config("slices"), request=SMB_REQUEST,
                                                         scan_label="fileserver", max_files=10)
        self.assertEqual(partitioned_scan.wait_for_plan(TENANT, record["scan_id"], 60), "planned")
        refs = {unit["listing_ref"] for unit in store.list_scan_partitions(TENANT, record["scan_id"])} - {""}
        self.assertTrue(refs, "no unit kept its listing slice")
        self.assertLessEqual({(TENANT, ref) for ref in refs}, store.referenced_artifact_ids(),
                             "retention could collect a slice a unit still needs")
        partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config("slices"))
        self.assertEqual({unit["listing_ref"] for unit in store.list_scan_partitions(TENANT, record["scan_id"])}, {""},
                         "a finalized scan still holds its listing slices")


class _GeneratedShare:
    """One share of text files of one size, generated when read: nothing is held."""

    def __init__(self, count: int, size: int) -> None:
        from tests.test_w12_smb_range_units import _Entry

        self.size = size
        self.entries = [_Entry(f"f{index:04d}.txt", size) for index in range(count)]
        self.read = 0
        self.root = _Entry

    def listShares(self):  # noqa: N802 - pysmb's name
        from tests.test_w12_smb_range_units import _Share

        return [_Share("Big")]

    def listPath(self, share: str, folder: str):  # noqa: N802
        if folder.strip("/"):
            raise Exception(f"Failed to list {folder} on {share}: Unable to open directory")
        return [self.root(".", is_dir=True), self.root("..", is_dir=True), *self.entries]

    def retrieveFileFromOffset(self, _share, _path, buffer, offset: int = 0, max_length: int = 0):  # noqa: N802
        count = max(0, min(max_length or self.size, self.size - offset))
        self.read += count
        buffer.write(b"a" * count)
        return None, count

    def close(self) -> None:
        return None


class AUnitOfLargeFilesTest(_RangeTest):
    """Section 24, exit 3: a unit of 2,000 files of 16 MiB runs inside the byte budget."""

    def _connected(self, share: _GeneratedShare):
        def connect(scanner) -> bool:
            scanner.connection = share
            scanner.server_used = "fs"
            return True

        return patch.object(SMBScanner, "connect", connect)

    def test_two_thousand_files_of_16_mib_are_cut_inside_the_byte_budget(self) -> None:
        mib = 1024 * 1024
        share = _GeneratedShare(2_000, 16 * mib)
        with self._connected(share):
            plan = plan_share_partitions(self._config(), max_files=2_000, max_bytes=512 * mib)
        weights = [sum(min(int(entry["s"]), content_policy.text_cap_bytes()) for item in unit["ranges"]
                       for entry in item["entries"]) for unit in plan["units"]]
        self.assertEqual(sum(len(item["entries"]) for unit in plan["units"] for item in unit["ranges"]), 2_000)
        self.assertLessEqual(max(weights), 512 * mib, "a unit would read more than its byte budget")
        self.assertEqual(len(plan["units"]), 63, "2,000 files of 16 MiB are 32 a unit under 512 MiB")
        self.assertEqual(share.read, 0, "planning read file content")

    def test_a_unit_reads_no_more_than_its_byte_budget(self) -> None:
        # The same ratio at a sixteenth of the size, so the test reads 32 MiB, not 512.
        mib = 1024 * 1024
        share = _GeneratedShare(200, mib)
        with self._connected(share):
            plan = plan_share_partitions(self._config(), max_files=2_000, max_bytes=32 * mib)
            first = plan["units"][0]
            records = self._unit_records(first)
        self.assertEqual(len(records), 32)
        self.assertLessEqual(share.read, 32 * mib, "the unit read past its byte budget")
        self.assertGreater(share.read, 0)


class NestedSharesTest(_SmbTest):
    """A chain of nested shares - Benefits inside HR inside Shares - cut with a tiny budget."""

    CHAIN = {
        "Benefits": {"/plan.txt": PAYROLL, "/x.txt": POLICY},
        "HR": {"/Benefits/plan.txt": PAYROLL, "/Benefits/x.txt": POLICY, "/a.txt": b"hr notes one\n",
               "/policy.txt": b"hr policy two\n"},
        "Shares": {"/HR/Benefits/plan.txt": PAYROLL, "/HR/Benefits/x.txt": POLICY, "/HR/a.txt": b"hr notes one\n",
                   "/HR/policy.txt": b"hr policy two\n", "/Team/plan.txt": b"password=Winter2026 for the vpn\n"},
    }

    def test_the_nesting_pairs_every_place_a_share_is_reached(self) -> None:
        nesting = share_nesting(["Benefits", "HR", "Shares"],
                                {"Benefits": {}, "HR": {"benefits": "Benefits"}, "Shares": {"hr": "HR", "team": "Team"}})
        self.assertEqual(nesting["pairs"], {"Benefits": [("HR", "/Benefits"), ("Shares", "/HR/Benefits")],
                                            "HR": [("Shares", "/HR")], "Shares": []})

    def test_units_cut_small_collapse_what_one_scan_collapses(self) -> None:
        self.server.tree = dict(self.CHAIN)
        self._use_database("chain")
        single = DSPMDiscoveryEngine(self._smb_config("chain-single")).run().to_dict()
        record = partitioned_scan.start_partitioned_scan(TENANT, self._smb_config("chain"), request=SMB_REQUEST,
                                                         scan_label="fileserver", max_files=1)
        self.assertIsNotNone(record)
        compact = partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._smb_config("chain"))
        partitioned = store.read_scan_report(TENANT, compact["scan_id"])
        self.assertEqual([(f["share"], f["path"]) for f in partitioned["files"]],
                         [(f["share"], f["path"]) for f in single["files"]])
        self.assertEqual([f.get("also_accessible_via") for f in partitioned["files"]],
                         [f.get("also_accessible_via") for f in single["files"]])
        self.assertEqual(partitioned["scan_diagnostics"]["overlapping_share_duplicates_collapsed"],
                         single["scan_diagnostics"]["overlapping_share_duplicates_collapsed"])
        units = store.list_scan_partitions(TENANT, record["scan_id"])
        self.assertGreater(len(units), 3)
        self.assertLessEqual(max(int(unit["files"]) for unit in units), 3,
                             "a unit held more than one name in each of the three places it is reached")

    def test_a_root_that_fails_once_while_its_overlaps_are_read_stops_the_plan(self) -> None:
        # The layout decides which shares are paired. A root that timed out there - and
        # lists fine a moment later - would hide an overlap and plan the shares unpaired;
        # the plan is refused instead, and retried.
        from tests.test_partitioned_smb_scan import _Connection

        self.server.tree = dict(self.CHAIN)
        real = _Connection.listPath
        failed: list[str] = []

        def once(connection, share, folder):
            if share == "Shares" and folder in ("", "/") and not failed:
                failed.append(share)
                raise TimeoutError("timed out")
            return real(connection, share, folder)

        with patch.object(_Connection, "listPath", once):
            with self.assertRaises(_SmbConnectionLost):
                plan_share_partitions(self._smb_config())
        self.assertEqual(failed, ["Shares"])

    def test_shares_that_reach_each_other_are_each_walked_once(self) -> None:
        # Two shares whose roots each hold a folder named like the other: the edge closing
        # the cycle is not followed, and every file is walked exactly once.
        self.server.tree = {"A": {"/B/one.txt": b"first\n", "/own.txt": b"second\n"},
                            "B": {"/A/two.txt": b"third\n", "/mine.txt": b"fourth\n"}}
        plan = plan_share_partitions(self._smb_config())
        walked: list[tuple[str, str]] = []
        for unit in plan["units"]:
            config = partitioned_scan._share_unit_config(self._smb_config("unit"), unit)
            walked.extend((r["share"], r["path"]) for r in DSPMDiscoveryEngine(config).run().to_dict()["files"])
        self.assertEqual(sorted(walked), sorted([("A", "/B/one.txt"), ("A", "/own.txt"), ("B", "/A/two.txt"),
                                                 ("B", "/mine.txt")]))


@unittest.skipUnless(db.is_postgres(), "the seq columns are four bytes only on PostgreSQL")
class TheOrderColumnsAre64BitTest(unittest.TestCase):

    def test_revision_0045_widened_them(self) -> None:
        with store._connect() as conn:
            types = {str(row[0]): str(row[1]).lower() for row in conn.execute(
                "SELECT table_name, data_type FROM information_schema.columns WHERE table_schema = current_schema() "
                "AND column_name = 'seq' AND table_name IN ('findings', 'finding_index')").fetchall()}
        self.assertEqual(types, {"findings": "bigint", "finding_index": "bigint"})


if __name__ == "__main__":
    unittest.main()
