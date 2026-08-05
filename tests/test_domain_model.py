"""Phase 1 DATA-001: normalized domain model + report mapper."""

from __future__ import annotations

import unittest

from backend.domain import (
    Asset,
    Finding,
    NormalizedScan,
    ScanRun,
    asset_identity,
    finding_identity,
    normalize_scan_report,
)


_REPORT = {
    "scan_id": "scan-001",
    "source": "smb",
    "timestamp": "2026-07-22T00:00:00Z",
    "summary": {"total_files": 2, "critical": 1, "high": 1},
    "files": [
        {
            "name": "prod_passwords.txt",
            "path": r"\\fs\share\IT\prod_passwords.txt",
            "size": 2048,
            "modified_at": "2026-07-01T10:00:00Z",
            "content_hash": "abc123",
            "scan_completeness": "FULL",
            "findings": [
                {"type": "password", "risk": "CRITICAL", "occurrence_count": 42, "count": 42,
                 "category": "credentials", "secure_value_fingerprints": ["fp-a"]},
                {"type": "email", "risk": "LOW", "occurrence_count": 3, "category": "pii"},
            ],
        },
        {
            "name": "notes.md",
            "path": r"\\fs\share\HR\notes.md",
            "size": 512,
            "findings": [],
        },
    ],
}


class DomainIdentityTests(unittest.TestCase):
    def test_asset_identity_is_stable_and_path_independent_when_object_id_present(self) -> None:
        a = asset_identity("t1", "smb", "obj-9", "/old/path")
        b = asset_identity("t1", "smb", "obj-9", "/new/renamed/path")
        self.assertEqual(a, b)  # rename preserves identity via stable_object_id

    def test_finding_identity_ignores_sample_value(self) -> None:
        fid = finding_identity("t1", "asset-1", "password", "/x")
        self.assertEqual(fid, finding_identity("t1", "asset-1", "password", "/x"))
        self.assertNotEqual(fid, finding_identity("t1", "asset-1", "email", "/x"))


class NormalizeReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scan = normalize_scan_report("tenant-x", _REPORT)

    def test_scan_run_is_immutable_and_populated(self) -> None:
        self.assertIsInstance(self.scan, NormalizedScan)
        self.assertEqual(self.scan.scan_run.id, "scan-001")
        self.assertEqual(self.scan.scan_run.tenant_id, "tenant-x")
        self.assertEqual(self.scan.scan_run.total_files, 2)
        with self.assertRaises(Exception):
            self.scan.scan_run.status = "tampered"  # frozen

    def test_assets_and_versions_derived_per_file(self) -> None:
        self.assertEqual(len(self.scan.assets), 2)
        self.assertEqual(len(self.scan.asset_versions), 2)
        v = next(v for a, v in zip(self.scan.assets, self.scan.asset_versions) if a.name == "prod_passwords.txt")
        self.assertEqual(v.content_hash, "abc123")
        self.assertEqual(v.coverage, "FULL")

    def test_findings_have_stable_identity_and_true_occurrence_count(self) -> None:
        self.assertEqual(len(self.scan.findings), 2)  # password + email; notes.md has none
        pw = next(f for f in self.scan.findings if f.rule == "password")
        occ = next(o for o in self.scan.occurrences if o.finding_id == pw.id)
        self.assertEqual(occ.occurrence_count, 42)  # not capped at the sample limit
        self.assertEqual(occ.fingerprint, "fp-a")
        self.assertEqual(pw.severity, "CRITICAL")
        # finding id is reproducible from identity inputs
        self.assertEqual(pw.id, finding_identity("tenant-x", pw.asset_id, "password", r"\\fs\share\IT\prod_passwords.txt"))

    def test_empty_report_yields_empty_scan(self) -> None:
        scan = normalize_scan_report("t", {})
        self.assertEqual(scan.assets, [])
        self.assertEqual(scan.findings, [])
        self.assertEqual(scan.scan_run.total_files, 0)


if __name__ == "__main__":
    unittest.main()
