import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from collectors.binary_extractor import extract_binary_text
from collectors.file_scanner import scan_directory
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig


class PlatformRegressionTests(unittest.TestCase):
    def test_one_mb_full_content_scan_detects_boundary_pattern(self):
        content = ("x" * (1024 * 1024 - 40)) + "\nEmail address: user@example.com"
        record = {
            "source": "local",
            "path": "large-boundary.txt",
            "name": "large-boundary.txt",
            "size": len(content),
            "extension": ".txt",
            "content": content,
            "acl": {},
        }

        analyzed = DSPMDiscoveryEngine(ScanConfig(compliance_enabled=True, compliance_frameworks=["gdpr"]))._analyze_record(record)
        email = next(item for item in analyzed["findings"] if item["type"] == "gdpr_email_address")

        self.assertEqual(email["scan_completeness"], "UNKNOWN")
        self.assertFalse(email["truncated"])
        self.assertGreater(email["occurrences"][0]["offset_start"], 1024 * 1024 - 80)

    def test_ten_mb_full_content_scan_detects_boundary_pattern(self):
        content = ("x" * (10 * 1024 * 1024 - 40)) + "\nEmail address: user@example.com"
        record = {
            "source": "local",
            "path": "large-10mb-boundary.txt",
            "name": "large-10mb-boundary.txt",
            "size": len(content),
            "extension": ".txt",
            "content": content,
            "acl": {},
        }

        analyzed = DSPMDiscoveryEngine(ScanConfig(compliance_enabled=True, compliance_frameworks=["gdpr"]))._analyze_record(record)
        email = next(item for item in analyzed["findings"] if item["type"] == "gdpr_email_address")

        self.assertFalse(email["truncated"])
        self.assertGreater(email["occurrences"][0]["offset_start"], 10 * 1024 * 1024 - 80)

    @unittest.skipUnless(os.getenv("DSPM_RUN_LARGE_TESTS") == "1", "set DSPM_RUN_LARGE_TESTS=1 to run 100 MB scan test")
    def test_hundred_mb_full_content_scan_detects_boundary_pattern(self):
        content = ("x" * (100 * 1024 * 1024 - 40)) + "\nEmail address: user@example.com"
        record = {
            "source": "local",
            "path": "large-100mb-boundary.txt",
            "name": "large-100mb-boundary.txt",
            "size": len(content),
            "extension": ".txt",
            "content": content,
            "acl": {},
        }

        analyzed = DSPMDiscoveryEngine(ScanConfig(compliance_enabled=True, compliance_frameworks=["gdpr"]))._analyze_record(record)
        email = next(item for item in analyzed["findings"] if item["type"] == "gdpr_email_address")

        self.assertFalse(email["truncated"])
        self.assertGreater(email["occurrences"][0]["offset_start"], 100 * 1024 * 1024 - 80)

    def test_scan_completeness_marks_partial_large_file(self):
        record = {
            "source": "local",
            "path": "partial-card.txt",
            "name": "partial-card.txt",
            "size": 10 * 1024 * 1024,
            "extension": ".txt",
            "content": "card_number: 4111111111111111",
            "acl": {},
            "scan_completeness": "PARTIAL",
            "bytes_scanned": 1024 * 1024,
            "total_bytes": 10 * 1024 * 1024,
            "truncated": True,
        }

        analyzed = DSPMDiscoveryEngine(ScanConfig(compliance_enabled=True, compliance_frameworks=["pci_dss"]))._analyze_record(record)
        pan = next(item for item in analyzed["findings"] if item["type"] == "pci_chd_pan")

        self.assertEqual(pan["scan_completeness"], "PARTIAL")
        self.assertEqual(pan["bytes_scanned"], 1024 * 1024)
        self.assertTrue(pan["truncated"])

    def test_local_scanner_reads_text_beyond_old_preview_limit(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            path = Path(temp_dir) / "full-file-scan.txt"
            path.write_text(("x" * (300 * 1024)) + "\nEmail address: user@example.com", encoding="utf-8")

            records = scan_directory(temp_dir, allowed_extensions=[".txt"], extension_filter_enabled=True)
            analyzed = DSPMDiscoveryEngine(ScanConfig(compliance_enabled=True, compliance_frameworks=["gdpr"]))._analyze_record(records[0])
            email = next(item for item in analyzed["findings"] if item["type"] == "gdpr_email_address")

            self.assertEqual(records[0]["scan_completeness"], "FULL")
            self.assertFalse(records[0]["truncated"])
            self.assertGreater(email["occurrences"][0]["offset_start"], 256 * 1024)

    def test_xlsx_extraction_preserves_sheet_row_cell_boundaries(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            path = Path(temp_dir) / "cards.xlsx"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(
                    "xl/workbook.xml",
                    """<?xml version="1.0" encoding="UTF-8"?>
                    <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
                      xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
                      <sheets><sheet name="Payments" sheetId="1" r:id="rId1"/></sheets>
                    </workbook>""",
                )
                archive.writestr(
                    "xl/_rels/workbook.xml.rels",
                    """<?xml version="1.0" encoding="UTF-8"?>
                    <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
                      <Relationship Id="rId1" Type="worksheet" Target="worksheets/sheet1.xml"/>
                    </Relationships>""",
                )
                archive.writestr(
                    "xl/worksheets/sheet1.xml",
                    """<?xml version="1.0" encoding="UTF-8"?>
                    <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
                      <sheetData>
                        <row r="1"><c r="A1" t="inlineStr"><is><t>PAN</t></is></c></row>
                        <row r="200"><c r="B200" t="inlineStr"><is><t>CVV 123</t></is></c></row>
                      </sheetData>
                    </worksheet>""",
                )

            text = extract_binary_text(path)

            self.assertIn("[xlsx sheet=Payments row=1] A1=PAN", text)
            self.assertIn("[xlsx sheet=Payments row=200] B200=CVV 123", text)

    def test_persistent_scan_cache_reuses_findings_across_engine_instances(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            cache_dir = Path(temp_dir) / "cache"
            record = {
                "source": "local",
                "path": "cached-customer.txt",
                "name": "cached-customer.txt",
                "size": 80,
                "extension": ".txt",
                "content": "Email address: user@example.com",
                "acl": {},
                "sha256": "same-file-hash",
                "content_hash": "same-content-hash",
            }
            config = ScanConfig(
                compliance_enabled=True,
                compliance_frameworks=["gdpr"],
                cache_dir=str(cache_dir),
                persistent_cache_enabled=True,
            )

            first = DSPMDiscoveryEngine(config)._analyze_record(dict(record))
            second = DSPMDiscoveryEngine(config)._analyze_record(dict(record))

            self.assertEqual(first["incremental_scan_reason"], "cache_miss_new_or_changed_file")
            self.assertEqual(second["incremental_scan_reason"], "cache_hit_unchanged_file")
            self.assertTrue(second["detector_metrics"]["cache_hit"])
            self.assertTrue(list(cache_dir.glob("*.json")))

    def test_run_uses_worker_pool_when_configured(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            root = Path(temp_dir)
            (root / "a.txt").write_text("Email address: alpha@example.com", encoding="utf-8")
            (root / "b.txt").write_text("Email address: beta@example.com", encoding="utf-8")
            engine = DSPMDiscoveryEngine(
                ScanConfig(
                    local_path=str(root),
                    compliance_enabled=True,
                    compliance_frameworks=["gdpr"],
                    max_workers=2,
                    cache_dir=str(root / "cache"),
                )
            )

            report = engine.run()
            second_report = DSPMDiscoveryEngine(
                ScanConfig(
                    local_path=str(root),
                    compliance_enabled=True,
                    compliance_frameworks=["gdpr"],
                    max_workers=2,
                    cache_dir=str(root / "cache"),
                )
            ).run()

            self.assertEqual(report.summary.total_files, 2)
            self.assertEqual(second_report.summary.total_files, 2)
            self.assertTrue(report.scan_diagnostics["worker_pool"]["enabled"])
            self.assertEqual(report.scan_diagnostics["worker_pool"]["max_workers"], 2)

    def test_record_parser_failure_does_not_fail_entire_scan(self):
        record = {
            "source": "local",
            "path": "bad-encoded.txt",
            "name": "bad-encoded.txt",
            "size": 16,
            "extension": ".txt",
            "content": "emv payload: 5780",
            "acl": {},
        }
        engine = DSPMDiscoveryEngine(ScanConfig(compliance_enabled=True, compliance_frameworks=["pci_dss"], persistent_cache_enabled=False))

        # The detectors moved into discovery.detector_stage so they can run in
        # a worker process; this patches where they are actually called.
        with patch("discovery.detector_stage.classify_pci_content", side_effect=ValueError("invalid literal for int() with base 16: ''")):
            analyzed = engine._analyze_record_safe(dict(record))

        self.assertEqual(analyzed["findings"], [])
        self.assertTrue(analyzed["detector_metrics"]["slow_detector_degraded_mode"])
        pci_row = next(item for item in analyzed["detector_metrics"]["detectors"] if item["name"] == "pci_dss")
        self.assertTrue(pci_row["degraded_mode"])
        self.assertIn("invalid literal", pci_row["error"])


if __name__ == "__main__":
    unittest.main()
