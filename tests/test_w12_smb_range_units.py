"""W1.2 (scaling roadmap, 2026-10): a share of any size is scanned as bounded units.

A partitioned SMB scan's smallest unit was a share, so its memory and its time followed
the largest share on the server. A share alone is now cut into ranges of its folders'
entries - by files and by the bytes the scan reads - and each range is a unit the
ledger persists, checkpoints, releases and retries on its own.
"""
from __future__ import annotations

import os
import tracemalloc
import unittest
from unittest import mock
from unittest.mock import patch

from backend import db, partitioned_scan, store
from collectors.smb_scanner import SMBConfig, SMBScanner
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.parallelism import reset_host_admission_budget
from discovery.partition import plan_share_partitions
from tests.test_partitioned_local_scan import TENANT, _LocalTest

_MTIME = 1_751_500_000.0


class _Entry:
    def __init__(self, filename: str, size: int = 0, is_dir: bool = False) -> None:
        self.filename = filename
        self.isDirectory = is_dir
        self.isHidden = False
        self.isSystem = False
        self.file_size = size
        self.create_time = _MTIME - 1000
        self.last_write_time = _MTIME


class _Share:
    def __init__(self, name: str) -> None:
        self.name = name


class _Server:
    """A file server: share -> {path: bytes}; listPath is indexed, so a large folder is cheap."""

    def __init__(self, tree: dict[str, dict[str, bytes]]) -> None:
        self.tree = tree
        self.listings: dict[tuple[str, str], list[_Entry]] = {}
        for share, files in tree.items():
            self.listings.setdefault((share, "/"), [])
            seen: set[tuple[str, str]] = set()
            for path, data in files.items():
                parts = path.strip("/").split("/")
                for depth in range(len(parts)):
                    folder = "/" + "/".join(parts[:depth]) if depth else "/"
                    name = parts[depth]
                    is_dir = depth < len(parts) - 1
                    key = (folder, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    self.listings.setdefault((share, folder), []).append(_Entry(name, 0 if is_dir else len(data), is_dir))
        # Folders are listed in an order that is not sorted, as a real server may.
        for entries in self.listings.values():
            entries.reverse()
        self.reset_folders: dict[tuple[str, str], int] = {}
        self.listed: list[tuple[str, str]] = []


class _Connection:
    def __init__(self, server: _Server) -> None:
        self.server = server

    def listShares(self):
        return [_Share(name) for name in self.server.tree]

    def listPath(self, share: str, folder: str):
        folder = folder if folder.startswith("/") else "/" + folder
        folder = "/" + folder.strip("/") if folder != "/" else "/"
        self.server.listed.append((share, folder))
        remaining = self.server.reset_folders.get((share, folder), 0)
        if remaining:
            self.server.reset_folders[(share, folder)] = remaining - 1
            raise ConnectionResetError("[WinError 10054] An existing connection was forcibly closed")
        if (share, folder) not in self.server.listings:
            raise Exception(f"Failed to list {folder} on {share}: Unable to open directory")
        return [_Entry(".", is_dir=True), _Entry("..", is_dir=True), *self.server.listings[(share, folder)]]

    def retrieveFileFromOffset(self, share: str, path: str, buffer, offset: int = 0, max_length: int = 0):
        data = self.server.tree[share][path]
        buffer.write(data[offset:offset + max_length] if max_length else data[offset:])

    def close(self) -> None:
        return None


def _acl(*_args) -> dict:
    return {"owner": r"CORP\owner", "principals": [r"CORP\owner"], "permissions": ["FullControl"]}


def _tree() -> dict[str, dict[str, bytes]]:
    big: dict[str, bytes] = {}
    for index in range(23):
        big[f"/flat/file{index:02d}.txt"] = f"contact user{index}@example.com about it\n".encode()
    for index in range(6):
        big[f"/deep/a/b/n{index}.txt"] = b"card 4111 1111 1111 1111 exp 09/29\n"
    big["/deep/top.txt"] = b"nothing sensitive here\n"
    big["/readme.txt"] = b"welcome\n"
    return {"Big": big, "Small": {"/one.txt": b"ssn 123-45-6789 employee\n"}}


class _RangeTest(_LocalTest):
    def setUp(self) -> None:
        super().setUp()
        self.server = _Server(_tree())
        server = self.server

        def connect(scanner) -> bool:
            scanner.connection = _Connection(server)
            scanner.server_used = "fs"
            return True

        self._patches = [
            mock.patch.dict(os.environ, {"DSPM_SMB_PARALLEL": "1", "DSPM_SMB_FILE_PARALLEL": "1", "DSPM_SMB_ACL_BATCH": "1",
                                         "DSPM_PARTITION_RETRY_SECONDS": "0"}),
            patch.object(SMBScanner, "connect", connect),
            patch.object(SMBScanner, "_acl_for_path", lambda _self, _share, _path: _acl()),
            patch.object(SMBScanner, "_acl_batch_for_paths", lambda _self, _share, paths: {path: _acl() for path in paths}),
        ]
        for started in self._patches:
            started.start()
        reset_host_admission_budget(4)

    def tearDown(self) -> None:
        reset_host_admission_budget()
        for started in reversed(self._patches):
            started.stop()
        super().tearDown()

    def _config(self, name: str = "smb", **overrides) -> ScanConfig:
        settings = dict(tenant_id=TENANT, server="fs", username="svc", password="", domain="CORP", max_depth=6,
                        persistent_cache_enabled=False, incremental_enabled=False, max_workers=2,
                        cache_dir=str(self.base / f"{name}-cache"))
        settings.update(overrides)
        return ScanConfig(**settings)

    def _unit_records(self, unit: dict) -> list[tuple[str, str]]:
        config = partitioned_scan._share_unit_config(self._config("unit"), unit)
        report = DSPMDiscoveryEngine(config).run().to_dict()
        return [(record["share"], record["path"]) for record in report["files"]]


class AShareIsCutIntoRangesTest(_RangeTest):

    def test_a_large_share_becomes_bounded_contiguous_ranges(self) -> None:
        plan = plan_share_partitions(self._config(), max_files=10, max_bytes=1 << 30)
        units = plan["units"]
        self.assertEqual(units[-1], {"kind": "shares", "shares": ["Small"]}, "a share that fits stays whole")
        ranges = [unit for unit in units if unit["kind"] == "smb_range"]
        self.assertGreater(len(ranges), 3)
        self.assertEqual({unit["share"] for unit in ranges}, {"Big"})
        by_folder: dict[str, list[dict]] = {}
        for unit in ranges:
            by_folder.setdefault(unit["folder"], []).append(unit)
        for folder, cuts in by_folder.items():
            self.assertEqual(cuts[0]["name_from"], "", f"{folder} does not start open")
            self.assertEqual(cuts[-1]["name_to"], "", f"{folder} does not end open")
        whole = DSPMDiscoveryEngine(self._config("whole")).run().to_dict()
        walked = [(record["share"], record["path"]) for record in whole["files"]]
        pieced: list[tuple[str, str]] = []
        for unit in units:
            records = self._unit_records(unit)
            self.assertLessEqual(len(records), 10, f"a unit holds more than its budget: {unit}")
            pieced.extend(records)
        self.assertEqual(pieced, walked, "the units in sequence are not the single scan")

    def test_the_bytes_a_unit_reads_bound_it_too(self) -> None:
        self.server = _Server({"Big": {f"/f{index}.bin": b"x" * 1000 for index in range(8)},
                               "Small": {"/one.txt": b"x"}})
        server = self.server
        with patch.object(SMBScanner, "connect", lambda scanner: setattr(scanner, "connection", _Connection(server)) or True):
            plan = plan_share_partitions(self._config(), max_files=100, max_bytes=2500)
            ranges = [unit for unit in plan["units"] if unit["kind"] == "smb_range"]
            self.assertEqual(len(ranges), 4, "eight 1,000-byte files under a 2,500-byte budget")
            self.assertEqual([len(self._unit_records(unit)) for unit in ranges], [2, 2, 2, 2])

    def test_a_connection_lost_while_cutting_gives_no_plan(self) -> None:
        self.server.reset_folders[("Big", "/deep")] = 1
        self.assertIsNone(plan_share_partitions(self._config(), max_files=10, max_bytes=1 << 30))

    def test_a_file_created_after_planning_is_still_in_a_range(self) -> None:
        plan = plan_share_partitions(self._config(), max_files=10, max_bytes=1 << 30)
        self.server.tree["Big"]["/flat/file05b.txt"] = b"late arrival hr@example.com\n"
        self.server.listings[("Big", "/flat")].append(_Entry("file05b.txt", 28))
        pieced = [record for unit in plan["units"] for record in self._unit_records(unit)]
        self.assertEqual(pieced.count(("Big", "/flat/file05b.txt")), 1)


class ARangePartitionedScanTest(_RangeTest):
    REQUEST = {"server": "fs", "username": "svc", "domain": "CORP"}

    def _rows(self) -> dict:
        with store._connect() as conn:
            assets = sorted((row["path"], row["finding_count"]) for row in conn.execute(
                "SELECT path, finding_count FROM assets WHERE tenant_id = ?", (TENANT,)).fetchall())
            findings = conn.execute("SELECT COUNT(*) FROM findings WHERE tenant_id = ? AND is_current = 1",
                                    (TENANT,)).fetchone()[0]
        return {"assets": assets, "findings": findings}

    def _scan(self, name: str, *, resets: int = 0) -> dict:
        record = partitioned_scan.start_partitioned_scan(TENANT, self._config(name), request=self.REQUEST,
                                                         scan_label="fileserver", max_files=10)
        self.assertIsNotNone(record, "the server was not partitioned")
        if resets:
            # Planned cleanly; the session resets once the units run.
            self.server.reset_folders[("Big", "/deep/a")] = resets
        return partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._config(name))

    def test_the_units_report_what_one_scan_reports(self) -> None:
        self._use_database("ranges")
        compact = self._scan("ranges")
        units = store.list_scan_partitions(TENANT, compact["scan_id"])
        self.assertGreater(sum(1 for unit in units if unit["spec"]["kind"] == "smb_range"), 3)
        partitioned = store.read_scan_report(TENANT, compact["scan_id"])
        whole = DSPMDiscoveryEngine(self._config("whole")).run().to_dict()
        self.assertEqual([(f["share"], f["path"]) for f in partitioned["files"]],
                         [(f["share"], f["path"]) for f in whole["files"]])
        self.assertEqual(partitioned["summary"]["total_files"], whole["summary"]["total_files"])
        diagnostics = partitioned["scan_diagnostics"]
        self.assertEqual(diagnostics["shares_scanned"], ["Big", "Small"])
        self.assertEqual(diagnostics["records"], whole["scan_diagnostics"]["records"])
        self.assertTrue(diagnostics["incremental"]["complete"])

    def test_a_reset_in_one_unit_retries_that_unit_and_nothing_doubles(self) -> None:
        self._use_database("reset")
        clean = self._scan("clean")
        clean_rows = self._rows()
        store.delete_tenant_with_data(TENANT)
        store.create_tenant(TENANT, TENANT)
        # Both of the collector's own attempts reset, twice over: the unit is failed and
        # retried, and its third attempt reads the folder.
        compact = self._scan("reset", resets=4)
        units = store.list_scan_partitions(TENANT, compact["scan_id"])
        self.assertEqual({unit["status"] for unit in units}, {"done"})
        self.assertTrue(any(unit["attempt"] > 1 for unit in units), "no unit was retried")
        self.assertEqual(self._rows(), clean_rows, "the retried unit left a different estate")
        report = store.read_scan_report(TENANT, compact["scan_id"])
        self.assertTrue(report["scan_diagnostics"]["incremental"]["complete"])
        self.assertEqual(clean["file_count"], compact["file_count"])

    def test_a_unit_that_resets_on_every_attempt_leaves_the_scan_incomplete(self) -> None:
        self._use_database("reset-always")
        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_ATTEMPTS": "2"}):
            compact = self._scan("reset-always", resets=10_000)
        report = store.read_scan_report(TENANT, compact["scan_id"])
        self.assertFalse(report["scan_diagnostics"]["incremental"]["complete"],
                         "a scan that never read a folder called itself complete, licensing the prunes")

    def test_scanning_the_same_units_again_leaves_the_same_estate(self) -> None:
        self._use_database("again")
        self._scan("first")
        first = self._rows()
        self._scan("second")
        self.assertEqual(self._rows(), first)


class AHugeFlatFolderTest(_RangeTest):
    """A folder of 100,000 entries is cut into units; one unit's enumeration holds only
    its own files, so its memory follows the unit, not the folder."""

    ENTRIES = 100_000

    def test_one_unit_of_a_huge_flat_folder_holds_only_its_share(self) -> None:
        files = {f"/huge/f{index:06d}.txt": b"" for index in range(self.ENTRIES)}
        self.server = _Server({"Big": files, "Small": {"/one.txt": b"x"}})
        server = self.server
        with patch.object(SMBScanner, "connect", lambda scanner: setattr(scanner, "connection", _Connection(server)) or True):
            plan = plan_share_partitions(self._config(), max_files=2000, max_bytes=1 << 30)
            ranges = [unit for unit in plan["units"] if unit["kind"] == "smb_range" and unit["folder"] == "/huge"]
            self.assertEqual(len(ranges), self.ENTRIES // 2000)
            # The root keeps a range on either side of /huge, so a name that appears there
            # later is still walked; both are empty today.
            self.assertEqual(len(plan["units"]) - len(ranges), 3, "two root ranges and the Small share")

            def enumerate_unit(unit=None) -> int:
                scanner = SMBScanner(SMBConfig(server="fs", max_depth=6, share_range=unit))
                scanner.connect()
                if unit is None:
                    built = scanner._enumerate_share_plan("Big", "/", 0)
                else:
                    built = scanner._enumerate_share_plan(
                        "Big", unit["folder"], int(unit["depth"]), name_range=(unit["name_from"], unit["name_to"]))
                return len(built.slots)

            tracemalloc.start()
            self.assertEqual(enumerate_unit(ranges[7]), 2000)
            _current, unit_peak = tracemalloc.get_traced_memory()
            tracemalloc.reset_peak()
            self.assertEqual(enumerate_unit(), self.ENTRIES)
            _current, whole_peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        self.assertLess(unit_peak * 10, whole_peak,
                        f"one unit peaked at {unit_peak} bytes against {whole_peak} for the whole folder")


@unittest.skipIf(db.is_postgres(), "the collector alone")
class TheAclBatchFitsACommandLineTest(unittest.TestCase):
    """E6: the batch's payload rides in the command line, which Windows caps at 32,767
    characters. 32 paths of 80 characters came to 41,536: the launch failed and every
    path fell back to a PowerShell process of its own."""

    def test_a_batch_too_long_for_one_command_is_split_until_each_fits(self) -> None:
        import json
        import subprocess

        from collectors import smb_scanner

        scanner = SMBScanner(SMBConfig(server="fs", username="svc", password="pw", domain="CORP"))
        paths = [f"/department/{'long-folder-name-' * 4}{index:03d}/file.txt" for index in range(32)]
        commands: list[str] = []

        def run(args, **_kwargs):
            commands.append(args[-1])
            script = __import__("base64").b64decode(args[-1]).decode("utf-16le")
            payload = script.split("FromBase64String('", 1)[1].split("'", 1)[0]
            items = json.loads(__import__("base64").b64decode(payload))["items"]
            rows = [{"path": item["path"], "ok": True, "owner": "CORP\\owner", "principals": ["CORP\\owner"],
                     "permissions": ["FullControl"], "types": ["Allow"]} for item in items]
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps({"results": rows}), stderr="")

        with patch.object(smb_scanner.subprocess, "run", side_effect=run):
            result = scanner._acl_batch_for_paths("Share", paths)
        self.assertEqual(set(result), set(paths))
        self.assertGreater(len(commands), 1)
        self.assertTrue(all(len(command) <= smb_scanner.ACL_BATCH_COMMAND_LIMIT for command in commands),
                        [len(command) for command in commands])

    def test_a_path_too_long_alone_falls_back_by_itself(self) -> None:
        from collectors import smb_scanner

        scanner = SMBScanner(SMBConfig(server="fs"))
        with patch.object(smb_scanner.subprocess, "run") as run:
            self.assertEqual(scanner._acl_batch_for_paths("Share", ["/" + "x" * 20_000]), {})
        run.assert_not_called()
