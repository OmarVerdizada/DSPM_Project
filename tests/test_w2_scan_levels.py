"""W2.6: a scan says how much of each file it reads - inventory, standard or full -
and its incremental reuse never crosses levels.

Every scan read content within the caps; an operator who wanted only an inventory of an
estate (names, owners, access) paid for reading it, and nothing said what a scan had
not read. The levels map onto knobs that already exist; the summary counts each
coverage state, and an inventory scan's "nothing found" is never replayed into a
content scan.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

from collectors import file_scanner
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

EMAIL = "contact alice.martin@example.com about the invoice\n"


class _Estate(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.estate = self.root / "estate"
        self.estate.mkdir()
        for patcher in (patch.object(file_scanner, "is_skipped_scan_path", return_value=False),
                        patch.object(file_scanner, "file_owner", MagicMock(return_value="tester")),
                        patch.object(file_scanner, "local_acl", MagicMock(return_value={}))):
            patcher.start()
            self.addCleanup(patcher.stop)
        (self.estate / "notes.txt").write_text(EMAIL * 20, encoding="utf-8")
        (self.estate / "export.csv").write_text(EMAIL * 5, encoding="utf-8")
        (self.estate / "disk.vhdx").write_bytes(b"\0" * 4096)

    def run_engine(self, *, read_content: bool) -> dict:
        config = ScanConfig(tenant_id="w26-levels", local_path=str(self.estate), walk_local_path=True,
                            persistent_cache_enabled=False, cache_dir=str(self.root / "cache"), max_workers=1,
                            read_content=read_content)
        return DSPMDiscoveryEngine(config).run().to_dict()


class AnInventoryScanReadsNoContentTest(_Estate):

    def test_it_reads_nothing_finds_nothing_and_says_so(self) -> None:
        file_scanner.take_read_bytes()
        report = self.run_engine(read_content=False)
        self.assertEqual(file_scanner.take_read_bytes(), 0, "an inventory scan read content")
        files = {item["name"]: item for item in report["files"]}
        self.assertEqual({name: item["content_coverage"] for name, item in files.items()},
                         {"notes.txt": "SKIPPED_POLICY", "export.csv": "SKIPPED_POLICY", "disk.vhdx": "METADATA_ONLY"})
        self.assertEqual(files["notes.txt"]["scan_completeness"], "NONE", "a text file not read must not say FULL")
        self.assertEqual(sum(len(item.get("findings") or []) for item in files.values()), 0)
        summary = report["summary"]
        self.assertEqual((summary["content_skipped_policy"], summary["content_metadata_only"], summary["content_full"]),
                         (2, 1, 0))

    def test_a_standard_scan_of_the_same_files_reads_them(self) -> None:
        report = self.run_engine(read_content=True)
        summary = report["summary"]
        self.assertEqual((summary["content_full"], summary["content_metadata_only"]), (2, 1))
        self.assertTrue(any(item.get("findings") for item in report["files"]))


class TheLevelsMapOntoTheKnobsTest(unittest.TestCase):

    def test_each_level(self) -> None:
        from backend.app import ScanRequest, _apply_scan_level

        base = {"local_path": "estate", "inspect_archives": False, "compliance_enabled": True,
                "compliance_frameworks": ["gdpr"]}
        inventory = _apply_scan_level(ScanRequest(**base, scan_level="inventory"))
        self.assertEqual((inventory.inspect_archives, inventory.compliance_enabled, inventory.compliance_frameworks),
                         (False, False, []))
        standard = _apply_scan_level(ScanRequest(**base))
        self.assertEqual((standard.inspect_archives, standard.compliance_frameworks), (False, ["gdpr"]))
        full = _apply_scan_level(ScanRequest(**{**base, "compliance_frameworks": []}, scan_level="full"))
        self.assertTrue(full.inspect_archives and full.compliance_enabled)
        self.assertGreater(len(full.compliance_frameworks), 1, "full applies every framework when none is named")

    def test_the_configuration_reads_no_content_at_inventory(self) -> None:
        from backend.app import ScanRequest, _to_config

        with mock.patch.dict(os.environ, {}):
            self.assertFalse(_to_config(ScanRequest(local_path="estate", scan_level="inventory"), "t").read_content)
            self.assertTrue(_to_config(ScanRequest(local_path="estate"), "t").read_content)


class ReuseNeverCrossesLevelsTest(unittest.TestCase):

    def test_inventory_and_full_keep_their_own_baselines_and_standard_keeps_its_old_one(self) -> None:
        from backend.app import ScanRequest, _file_scan_scope
        from discovery.incremental import incremental_scope_key

        def scope(level: str) -> str:
            payload = ScanRequest(local_path="estate", scan_level=level)
            return _file_scan_scope(payload, "", [], False)

        self.assertEqual(len({scope("inventory"), scope("standard"), scope("full")}), 3)
        payload = ScanRequest(local_path="estate")
        from backend.app import BASE_DIR

        before_w26 = incremental_scope_key("local", str((BASE_DIR / "estate").resolve()), {
            "max_depth": payload.max_depth, "allowed_extensions": [], "extension_filter_enabled": False,
            "include_hidden": payload.include_hidden, "include_system": payload.include_system,
            "hidden_filter_enabled": payload.hidden_filter_enabled,
            "system_filter_enabled": payload.system_filter_enabled,
            "include_admin_shares": payload.include_admin_shares, "inspect_archives": payload.inspect_archives})
        self.assertEqual(scope("standard"), before_w26, "a standard scan's baseline would be orphaned")

    def test_the_reuse_signature_changes_with_what_a_scan_reads(self) -> None:
        def signature(**config) -> str:
            return DSPMDiscoveryEngine(ScanConfig(tenant_id="w26-sig", persistent_cache_enabled=False,
                                                  **config)).version_signature()

        standard = signature()
        self.assertNotEqual(signature(read_content=False), standard)
        with mock.patch.dict(os.environ, {"DSPM_TEXT_SCAN_MAX_BYTES": str(4 * 1024 * 1024)}):
            self.assertNotEqual(signature(), standard)
        with mock.patch.dict(os.environ, {"DSPM_HASH_POLICY": "full"}):
            self.assertNotEqual(signature(), standard)


if __name__ == "__main__":
    unittest.main()
