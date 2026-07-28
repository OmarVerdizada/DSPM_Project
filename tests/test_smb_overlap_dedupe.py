"""Overlapping-share dedup: the same physical file exported through a nested
share and its parent share must be scanned/reported once - without collapsing
genuine data proliferation (identical bytes in two different real locations)."""

from __future__ import annotations

import unittest

from collectors.smb_scanner import SMBConfig, SMBScanner


def _rec(share: str, path: str, sha: str, size: int = 709) -> dict:
    return {
        "source": "smb",
        "share": share,
        "path": path,
        "name": path.rsplit("/", 1)[-1],
        "size": size,
        "sha256": sha,
        "is_dir": False,
    }


class SmbOverlapDedupeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = SMBScanner(SMBConfig(server="fs", username="u", password="p", domain="CORP"))
        self.scanner.last_scan_diagnostics = {}

    def test_overlapping_share_duplicate_is_collapsed(self) -> None:
        # The exact reported case: HR (nested) + Shares (parent) expose one file.
        records = [
            _rec("HR", "/Benefits/2023/Q1/payroll_salary_export_benefits_004.docx", "abc123"),
            _rec("Shares", "/HR/Benefits/2023/Q1/payroll_salary_export_benefits_004.docx", "abc123"),
        ]
        out = self.scanner._dedupe_overlapping_shares(records)
        self.assertEqual(len(out), 1)
        # Keep the most-specific (nested) share; record the redundant location.
        self.assertEqual(out[0]["share"], "HR")
        self.assertEqual(out[0]["path"], "/Benefits/2023/Q1/payroll_salary_export_benefits_004.docx")
        self.assertEqual(
            out[0]["also_accessible_via"],
            [{"share": "Shares", "path": "/HR/Benefits/2023/Q1/payroll_salary_export_benefits_004.docx"}],
        )
        self.assertEqual(self.scanner.last_scan_diagnostics["overlapping_share_duplicates_collapsed"], 1)

    def test_same_bytes_in_two_real_locations_is_NOT_collapsed(self) -> None:
        # Data proliferation: two DIFFERENT physical files with identical content.
        # A DLP tool must keep both visible.
        records = [
            _rec("HR", "/Benefits/payroll.docx", "abc123"),
            _rec("Finance", "/Reports/payroll.docx", "abc123"),
        ]
        self.assertEqual(len(self.scanner._dedupe_overlapping_shares(records)), 2)

    def test_unique_file_untouched(self) -> None:
        records = [_rec("HR", "/Benefits/payroll.docx", "abc123")]
        self.assertEqual(len(self.scanner._dedupe_overlapping_shares(records)), 1)

    def test_without_content_hash_nothing_is_collapsed(self) -> None:
        # Cannot prove "same physical file" without a hash -> keep both.
        records = [_rec("HR", "/Benefits/f.docx", ""), _rec("Shares", "/HR/Benefits/f.docx", "")]
        self.assertEqual(len(self.scanner._dedupe_overlapping_shares(records)), 2)


if __name__ == "__main__":
    unittest.main()
