"""Top-N / extension report-scope preservation tests.

Verifies that the report model preserves the explicit
top-N limit, severity scope, extension scope, and single-finding scope — and
that ``.pdf`` extension *file listings* remain listings, never reports.
"""
from __future__ import annotations

import unittest

from backend.reporting.report_model import build_report_model


def _file(name: str, extension: str, score: int, level: str, finding_type: str) -> dict:
    return {
        "name": name,
        "path": f"C:\\sensitive-root\\{name}",
        "extension": extension,
        "source": "local",
        "share": "security",
        "risk": {
            "score": score,
            "level": level,
            "reasons": [f"{finding_type} signal"],
            "remediation": {"actions": [f"Review {finding_type} exposure"]},
            "dlp_recommendations": [f"Restrict {finding_type} data movement"],
        },
        "findings": [
            {"type": finding_type, "risk": level, "description": f"Detected {finding_type}", "count": 1}
        ],
        "permissions": {},
    }


_FILES = (
    [_file(f"crit{i}.txt", ".txt", 99 - i, "CRITICAL", "api_key") for i in range(8)]
    + [_file(f"high{i}.csv", ".csv", 80 - i, "HIGH", "credit_card") for i in range(12)]
    + [_file(f"med{i}.json", ".json", 60 - i, "MEDIUM", "email") for i in range(4)]
    + [_file(f"doc{i}.pdf", ".pdf", 70 - i, "HIGH" if i < 3 else "MEDIUM", "confidential_keyword") for i in range(7)]
)

_REPORT = {
    "scan_id": "scan-topn-001",
    "timestamp": "2026-07-15T00:00:00+00:00",
    "source": "local-test",
    "summary": {},
    "files": _FILES,
}


class ReportModelTopNTests(unittest.TestCase):
    def test_severity_scope_with_limit_caps_all_scoped_sections(self) -> None:
        model = build_report_model(_REPORT, {"kind": "severity", "severities": ["CRITICAL"], "limit": 5})
        self.assertEqual(len(model["evidence_register"]), 5)
        self.assertEqual(model["scoped_summary"]["total_files"], 5)
        self.assertEqual(model["scope"]["label"], "Top 5 CRITICAL")
        self.assertTrue(all(row["severity"] == "CRITICAL" for row in model["evidence_register"]))
        # Highest-risk first: the cap keeps the top of the sorted set.
        self.assertEqual(model["evidence_register"][0]["name"], "crit0.txt")
        # Full-scan summary is untouched by the cap.
        self.assertEqual(model["full_summary"]["critical"], 8)

    def test_severity_scope_without_limit_is_uncapped(self) -> None:
        model = build_report_model(_REPORT, {"kind": "severity", "severities": ["MEDIUM"]})
        self.assertEqual(len(model["evidence_register"]), 8)  # 4 json + 4 medium pdfs
        self.assertEqual(model["scope"]["label"], "MEDIUM")
        self.assertNotIn("limit", model["scope"])

    def test_combined_severity_scope_remains_combined(self) -> None:
        model = build_report_model(_REPORT, {"kind": "severity", "severities": ["CRITICAL", "HIGH"]})
        self.assertEqual(model["scope"]["label"], "CRITICAL + HIGH")
        self.assertEqual(len(model["evidence_register"]), 8 + 12 + 3)

    def test_extension_scope_with_limit(self) -> None:
        model = build_report_model(_REPORT, {"kind": "extension", "extension": ".pdf", "limit": 5})
        self.assertEqual(len(model["evidence_register"]), 5)
        self.assertEqual(model["scope"]["label"], "Top 5 .pdf files")
        self.assertTrue(all(row["name"].endswith(".pdf") for row in model["evidence_register"]))

    def test_single_finding_scope_is_exactly_one_row(self) -> None:
        model = build_report_model(_REPORT, {"kind": "finding", "finding_ref": "crit3.txt"})
        self.assertEqual(len(model["evidence_register"]), 1)
        self.assertEqual(model["evidence_register"][0]["name"], "crit3.txt")

    def test_full_scope_has_no_implicit_cap(self) -> None:
        model = build_report_model(_REPORT, None)
        self.assertEqual(len(model["evidence_register"]), len(_FILES))
        self.assertEqual(model["scope"]["label"], "Full scan")


if __name__ == "__main__":
    unittest.main()
