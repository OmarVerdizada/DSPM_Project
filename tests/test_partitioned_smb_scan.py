"""B2.3: an SMB scan runs one group of shares at a time and reports what one scan reports.

A partitioned local scan cuts its walk into runs (B2.2b). An SMB scan's natural unit
is the share, and exactly one thing crosses shares: the overlapping-share collapse,
which reports a file seen through a nested share and through its parent share once.
So a partition is a group of shares that keeps together every pair that can overlap -
one share's root lists a folder named like the other - contiguous in the server's
listing order, so the groups in sequence are the single scan's order.

The collapse had to change for that to be exact. It compared each set of identical
files with only the shortest path, so a third copy elsewhere hid a real overlap in a
single scan but not inside a group; it now checks every pair. And a share whose
session reset on every attempt used to leave a scan "complete", so the prunes deleted
what that share held.
"""

from __future__ import annotations

import os
import unittest
from unittest import mock
from unittest.mock import patch

from backend import partitioned_scan, store
from backend.compliance_service import enrich_report_with_compliance
from collectors.smb_scanner import SMBConfig, SMBScanner
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.parallelism import reset_host_admission_budget
from discovery.parity import accuracy_projection
from discovery.partition import plan_share_partitions
from tests.test_partitioned_local_scan import ALL_FRAMEWORKS, TENANT, _LocalTest

_MTIME = 1_751_500_000.0
PAYROLL = b"employee payroll ssn 123-45-6789 salary 91000\n"
POLICY = b"leave policy questions to hr@example.com\n"
SECTIONS = ("compliance_summary", "pci_scope_summary", "gdpr_report", "nist_sp800_60_enterprise_report")

# share -> {path: bytes}, folders implied by the paths, listed in this order. Executive's
# root cannot be read. HR is also exported inside Shares, and Archive holds a genuine
# second copy of the payroll file - with the shortest path of the three.
TREE: dict[str, dict[str, bytes] | None] = {
    "Archive": {"/payroll_copy.txt": PAYROLL, "/old/card.txt": b"card 4111 1111 1111 1111 exp 09/29\n"},
    "Executive": None,
    "Finance": {"/q1/budget.txt": b"budget owner cfo@example.com\n", "/q1/notes.txt": b"nothing sensitive here\n"},
    "HR": {"/Benefits/payroll.txt": PAYROLL, "/policy.txt": POLICY},
    "Public": {"/readme.txt": b"welcome to the file server\n"},
    "Shares": {
        "/HR/Benefits/payroll.txt": PAYROLL,
        "/HR/policy.txt": POLICY,
        "/Team/plan.txt": b"password=Winter2026 for the vpn\n",
    },
    "IPC$": {},
}
GROUPS = [["Archive"], ["Executive"], ["Finance"], ["HR", "Public", "Shares"]]


class _Share:
    def __init__(self, name: str) -> None:
        self.name = name


class _Entry:
    def __init__(self, filename: str, size: int = 0, is_dir: bool = False) -> None:
        self.filename = filename
        self.isDirectory = is_dir
        self.isHidden = False
        self.isSystem = False
        self.file_size = size
        self.create_time = _MTIME - 1000
        self.last_write_time = _MTIME


class _Server:
    """One file server; every connection to it sees the same shares."""

    def __init__(self, tree: dict) -> None:
        self.tree = dict(tree)
        self.reset_shares: set[str] = set()
        self.timeout_shares: set[str] = set()


class _Connection:
    def __init__(self, server: _Server) -> None:
        self.server = server

    def listShares(self):
        return [_Share(name) for name in self.server.tree]

    def listPath(self, share: str, folder: str):
        if share in self.server.reset_shares:
            raise ConnectionResetError("[WinError 10054] An existing connection was forcibly closed")
        if share in self.server.timeout_shares:
            raise TimeoutError("timed out")
        files = self.server.tree.get(share)
        if files is None:
            raise Exception(f"Failed to list {folder} on {share}: Unable to open directory")
        prefix = "" if folder in ("", "/") else folder.rstrip("/")
        entries = [_Entry(".", is_dir=True), _Entry("..", is_dir=True)]
        folders: set[str] = set()
        for path, data in files.items():
            if not path.startswith(prefix + "/"):
                continue
            head, nested, _rest = path[len(prefix) + 1:].partition("/")
            if not nested:
                entries.append(_Entry(head, size=len(data)))
            elif head not in folders:
                folders.add(head)
                entries.append(_Entry(head, is_dir=True))
        return entries

    def retrieveFileFromOffset(self, share: str, path: str, buffer, offset: int = 0, max_length: int = 0):
        data = self.server.tree[share][path]
        buffer.write(data[offset:offset + max_length] if max_length else data[offset:])

    def close(self) -> None:
        return None


def _acl(*_args) -> dict:
    return {"owner": r"CORP\owner", "principals": [r"CORP\owner"], "permissions": ["FullControl"]}


class _SmbTest(_LocalTest):
    def setUp(self) -> None:
        super().setUp()
        self.server = _Server(TREE)
        server = self.server

        def connect(scanner) -> bool:
            scanner.connection = _Connection(server)
            scanner.server_used = "fs"
            return True

        self._patches = [
            mock.patch.dict(os.environ, {"DSPM_SMB_PARALLEL": "1", "DSPM_SMB_FILE_PARALLEL": "1", "DSPM_SMB_ACL_BATCH": "1"}),
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

    def _smb_config(self, name: str = "smb") -> ScanConfig:
        return ScanConfig(
            tenant_id=TENANT, server="fs", username="svc", password="", domain="CORP", max_depth=4,
            persistent_cache_enabled=False, incremental_enabled=False, max_workers=2,
            cache_dir=str(self.base / f"{name}-cache"),
        )

    def _scanner(self, **overrides) -> SMBScanner:
        return SMBScanner(SMBConfig(server="fs", username="svc", domain="CORP", io_workers=4, **overrides))


class TheCollectorWalksWhatItIsGivenTest(_SmbTest):

    def test_a_share_selection_walks_only_those_shares_in_listing_order(self) -> None:
        scanner = self._scanner(allowed_shares=("Shares", "Finance"))
        with patch.object(scanner, "_emit_collection_progress"):
            records = scanner.scan()
        self.assertEqual([(r["share"], r["path"]) for r in records], [
            ("Finance", "/q1/budget.txt"), ("Finance", "/q1/notes.txt"),
            ("Shares", "/HR/Benefits/payroll.txt"), ("Shares", "/HR/policy.txt"), ("Shares", "/Team/plan.txt"),
        ])
        diagnostics = scanner.last_scan_diagnostics
        self.assertEqual(diagnostics["shares_scanned"], ["Finance", "Shares"])
        self.assertEqual(diagnostics["shares_skipped"], ["IPC$"], "a share another partition walks was reported skipped")
        self.assertEqual(diagnostics["shares_discovered"], list(TREE))

    def test_share_groups_keep_every_overlapping_pair_together_and_in_order(self) -> None:
        self.assertEqual(self._scanner().plan_share_groups(), GROUPS)
        plan = plan_share_partitions(self._smb_config())
        self.assertEqual([unit["shares"] for unit in plan["units"]], GROUPS)

    def test_a_server_whose_shares_all_overlap_is_not_partitioned(self) -> None:
        self.server.tree = {"HR": TREE["HR"], "Shares": TREE["Shares"]}
        self.assertEqual(self._scanner().plan_share_groups(), [["HR", "Shares"]])
        self.assertIsNone(plan_share_partitions(self._smb_config()))

    def test_a_connection_lost_while_planning_gives_no_plan(self) -> None:
        self.server.reset_shares = {"Public"}
        self.assertIsNone(self._scanner().plan_share_groups())
        self.assertIsNone(plan_share_partitions(self._smb_config()))

    def test_a_root_that_times_out_while_planning_gives_no_plan(self) -> None:
        # A timeout is not a refusal: the root may list fine when the scan runs, and the
        # overlap it hid would split shares that must stay together (B2.3 review).
        self.server.timeout_shares = {"Shares"}
        self.assertIsNone(self._scanner().plan_share_groups())
        self.assertIsNone(plan_share_partitions(self._smb_config()))

    def test_a_stop_while_planning_stops_it(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "time budget"):
            self._scanner().plan_share_groups(lambda: "Scan exceeded its time budget")


class AShareThatKeepsResettingTest(_SmbTest):

    def test_it_leaves_the_scan_incomplete_so_nothing_under_it_is_pruned(self) -> None:
        self.server.tree = {name: files for name, files in TREE.items() if files is not None}
        self.server.reset_shares = {"Finance"}
        report = DSPMDiscoveryEngine(self._smb_config("reset")).run().to_dict()
        diagnostics = report["scan_diagnostics"]
        self.assertEqual(diagnostics["shares_connection_reset"], ["Finance"])
        self.assertFalse(diagnostics.get("list_errors"))
        self.assertFalse(diagnostics["incremental"]["complete"],
                         "a scan that never read Finance called itself complete, licensing the prunes")


class APartitionedSmbScanReportsWhatOneScanReportsTest(_SmbTest):

    def test_the_same_records_order_collapse_sections_and_estate(self) -> None:
        self._use_database("smb-single")
        data = DSPMDiscoveryEngine(self._smb_config("smb-single")).run().to_dict()
        enrich_report_with_compliance(data, True, ALL_FRAMEWORKS)
        data["scan_label"] = "fileserver"
        store.save_scan_history(TENANT, data)
        single = store.read_scan_report(TENANT, data["scan_id"])
        single_rows = self._rows()

        self._use_database("smb-partitioned")
        written: list[list[str]] = []
        real_persist = store.persist_partition

        def watching(*args, **kwargs):
            written.append(sorted({record["share"] for record in args[5]}))
            return real_persist(*args, **kwargs)

        with patch.object(store, "persist_partition", side_effect=watching):
            record = partitioned_scan.start_partitioned_scan(
                TENANT, self._smb_config("smb-partitioned"),
                request={"server": "fs", "username": "svc", "domain": "CORP"},
                scan_label="fileserver", compliance_enabled=True, compliance_frameworks=ALL_FRAMEWORKS,
            )
            self.assertIsNotNone(record, "the server was not partitioned")
            self.assertTrue(record["resumable"])
            # The groups continue from the ledger, which is all a restart has.
            compact = partitioned_scan.continue_partitioned_scan(TENANT, record["scan_id"], self._smb_config("smb-partitioned"))
        partitioned = store.read_scan_report(TENANT, compact["scan_id"])

        self.assertEqual([unit["spec"]["shares"] for unit in store.list_scan_partitions(TENANT, record["scan_id"])], GROUPS)
        self.assertEqual(written, [["Archive"], [], ["Finance"], ["HR", "Public", "Shares"]])

        located = [(f["share"], f["path"]) for f in single["files"]]
        self.assertNotIn(("Shares", "/HR/Benefits/payroll.txt"), located, "the overlapping copy was not collapsed")
        self.assertIn(("Archive", "/payroll_copy.txt"), located, "a genuine second copy was collapsed")
        self.assertEqual([(f["share"], f["path"]) for f in partitioned["files"]], located)
        self.assertEqual([f.get("also_accessible_via") for f in partitioned["files"]],
                         [f.get("also_accessible_via") for f in single["files"]])
        self.assertEqual(accuracy_projection(partitioned), accuracy_projection(single))
        self.assertEqual(partitioned["summary"], single["summary"])
        for key in SECTIONS:
            self.assertEqual(partitioned[key], single[key], f"{key} differs")
        for key in ("records", "files_discovered", "shares_discovered", "shares_scanned", "shares_skipped",
                    "shares_access_denied", "shares_connection_reset", "overlapping_share_duplicates_collapsed"):
            self.assertEqual(partitioned["scan_diagnostics"].get(key), single["scan_diagnostics"].get(key), key)
        self.assertEqual(single["scan_diagnostics"]["shares_access_denied"], ["Executive"])
        self.assertEqual(partitioned["scan_diagnostics"]["incremental"]["complete"],
                         single["scan_diagnostics"]["incremental"]["complete"])
        self.assertEqual((partitioned["source"], partitioned["scan_diagnostics"]["partitioned"]["partitions"]), ("smb", 4))
        self.assertEqual(self._rows(), single_rows, "the estate differs")
        self.assertGreater(single_rows["findings"][0], 0)


if __name__ == "__main__":
    unittest.main()
