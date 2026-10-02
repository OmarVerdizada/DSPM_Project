"""Backend audit, 2026-10: the defects the tool sweep and the review found, each pinned by
the behaviour that was wrong.
"""
from __future__ import annotations

import tempfile
import unittest
from contextlib import suppress
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.compliance_service import allowed_framework_ids
from classification.compliance.canonical_model import apply_canonical_finding_model
from collectors import file_scanner
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig


class EveryAcceptedFrameworkCanBeScannedTest(unittest.TestCase):
    """The scan API accepts every profile in compliance_profiles.json. HIPAA, NIST CSF and
    ISO 27001 have no keyword catalog, and the engine asked the keyword library for one:
    the scan walked the whole estate and then failed at 95% with "Unsupported compliance
    framework"."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.estate = root / "estate"
        self.estate.mkdir()
        (self.estate / "patients.txt").write_text(
            "patient alice@example.com\nmedical record number MRN 448812\ncard 4111 1111 1111 1111\n", encoding="utf-8")
        self.cache = root / "cache"
        for patcher in (patch.object(file_scanner, "is_skipped_scan_path", return_value=False),
                        patch.object(file_scanner, "file_owner", MagicMock(return_value="tester"))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _scan(self, frameworks: list[str]) -> dict:
        config = ScanConfig(tenant_id="audit-frameworks", local_path=str(self.estate), walk_local_path=True,
                            persistent_cache_enabled=True, cache_dir=str(self.cache), max_workers=1,
                            compliance_enabled=True, compliance_frameworks=frameworks)
        return DSPMDiscoveryEngine(config).run().to_dict()

    def test_the_overlay_frameworks_scan_on_their_own(self) -> None:
        for framework in ("hipaa", "nist_csf", "iso27001"):
            with self.subTest(framework=framework):
                report = self._scan([framework])
                self.assertEqual(report["summary"]["total_files"], 1)

    def test_every_framework_the_api_accepts_scans_together(self) -> None:
        report = self._scan(sorted(allowed_framework_ids()))
        self.assertEqual(report["summary"]["total_files"], 1)
        found = {finding.get("type") for item in report["files"] for finding in item.get("findings") or []}
        self.assertTrue(found, "the detectors still ran beside the overlays")


    def test_a_first_sighting_starts_in_one_state_whatever_found_it(self) -> None:
        report = self._scan(["gdpr", "pci_dss", "nist_sp800_60_enterprise"])
        statuses = {(finding.get("framework"), finding.get("status"))
                    for item in report["files"] for finding in item.get("findings") or []}
        self.assertIn("pci_dss", {framework for framework, _ in statuses})
        self.assertEqual({status for _, status in statuses}, {"OPEN"}, statuses)


class AScanNeverDecidesTriageTest(unittest.TestCase):
    """A detector's review_status was read as the analyst lifecycle: PCI's "unreviewed"
    landed as NEW beside OPEN GDPR findings, and a NIST match scoring 85+ as CONFIRMED -
    a state that says a person validated it."""

    def test_a_detectors_review_state_is_not_the_lifecycle(self) -> None:
        for review in ("unreviewed", "CONFIRMED", "NEEDS_REVIEW"):
            with self.subTest(review_status=review):
                finding = apply_canonical_finding_model(
                    {"type": "pan", "risk": "HIGH", "review_status": review},
                    {"path": "C:/share/x.txt", "name": "x.txt", "source": "local"})
                self.assertEqual(finding["status"], "OPEN")
                self.assertEqual(finding["review_status"], review, "the detector's own reading is kept")


class DemoDataNeverReplacesWhatItDidNotWriteTest(unittest.TestCase):
    """POST /api/demo-data/generate (scan.run) took any project-local folder and the
    generator rmtree'd it: "." was the install, "data" the database and its backups."""

    def test_the_install_and_its_data_folder_are_refused(self) -> None:
        from fastapi import HTTPException

        from backend.app import _safe_demo_output

        for output in (".", "data", "data/backups", "./"):
            with self.subTest(output=output), self.assertRaises(HTTPException) as refused:
                _safe_demo_output(output)
            self.assertEqual(refused.exception.status_code, 400)

    def test_a_folder_of_other_files_is_refused(self) -> None:
        from fastapi import HTTPException

        from backend.app import _safe_demo_output

        for output in ("backend", "frontend", "docs"):
            with self.subTest(output=output), self.assertRaises(HTTPException) as refused:
                _safe_demo_output(output)
            self.assertEqual(refused.exception.status_code, 409)

    def test_a_new_folder_and_a_generated_one_are_allowed(self) -> None:
        from backend.app import _safe_demo_output

        self.assertTrue(str(_safe_demo_output("audit-demo-not-created")).endswith("audit-demo-not-created"))

    def test_the_generator_itself_will_not_replace_a_foreign_folder(self) -> None:
        from scripts.generate_enterprise_test_data import NotAGeneratedDataset, generate, is_generated_dataset

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "share"
            root.mkdir()
            keep = root / "quarterly.xlsx"
            keep.write_bytes(b"real data")
            with self.assertRaises(NotAGeneratedDataset):
                generate(root, 1)
            self.assertTrue(keep.exists(), "the generator deleted a folder it did not write")
            keep.unlink()
            self.assertTrue(is_generated_dataset(root), "an empty folder may be filled")
            (root / "_manifest.json").write_text("{}", encoding="utf-8")
            (root / "old.csv").write_text("x", encoding="utf-8")
            self.assertTrue(is_generated_dataset(root), "a dataset it wrote may be replaced")
            with suppress(OSError):
                (root / "_manifest.json").unlink()
            self.assertFalse(is_generated_dataset(root))


if __name__ == "__main__":
    unittest.main()
