"""Top-N / extension report-scope preservation tests.

Verifies that the report model and the Copilot report flow preserve the explicit
top-N limit, severity scope, extension scope, and single-finding scope — and
that ``.pdf`` extension *file listings* remain listings, never reports.
"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from backend import store
from backend.copilot import memory, session_context
from backend.copilot.llm_client import LLMError
from backend.copilot.report_model import build_report_model
from backend.copilot.service import handle_chat
from backend.security import Principal


def _run(awaitable):
    return asyncio.run(awaitable)


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


class CopilotTopNReportFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db_patch = patch.object(store, "DB_PATH", self.root / "dspm.sqlite")
        self.memory_patch = patch.object(memory, "DATA_DIR", self.root)
        self.session_patch = patch.object(session_context, "DATA_DIR", self.root)
        self.db_patch.start()
        self.memory_patch.start()
        self.session_patch.start()
        store.init_db()
        self.tenant = "topn-tenant"
        self.principal = Principal("topn-viewer", "viewer", self.tenant)
        store.save_scan_history(self.tenant, dict(_REPORT))
        self.down = AsyncMock(side_effect=LLMError("provider down"))
        self.provider_patches = [
            patch("backend.copilot.service.call_ollama", new=self.down),
            patch("backend.copilot.controlled_verbalizer.call_ollama", new=self.down),
            patch("backend.copilot.planner.call_ollama", new=self.down),
            patch("backend.copilot.language_understanding.call_ollama", new=self.down),
        ]
        for provider_patch in self.provider_patches:
            provider_patch.start()
        self._scopes: list = []

    def tearDown(self) -> None:
        for provider_patch in reversed(self.provider_patches):
            provider_patch.stop()
        self.session_patch.stop()
        self.memory_patch.stop()
        self.db_patch.stop()
        self.temp.cleanup()

    def chat(self, message: str, conversation_id: str):
        def fake_artifact(principal, session_state, scan_id, selected, scope=None):
            self._scopes.append(scope)
            model = build_report_model(_REPORT, scope)
            return {
                "artifact_id": "a" * 32,
                "filename": "dspm_report.pdf",
                "download_url": "/api/v1/copilot/artifacts/" + "a" * 32,
                "type": "pdf",
                "source_scan_id": "scan-topn-001",
                "scope": model["scope"],
            }

        with patch("backend.copilot.service.create_report_artifact", side_effect=fake_artifact):
            return _run(handle_chat(message, self.principal, conversation_id, None))

    def last_scope(self) -> dict:
        self.assertTrue(self._scopes, "a report artifact should have been created")
        return self._scopes[-1] or {}

    def register_len(self) -> int:
        return len(build_report_model(_REPORT, self.last_scope())["evidence_register"])

    def test_top5_critical_as_pdf_scopes_to_exactly_five(self) -> None:
        response = self.chat("top 5 critical files as PDF report", "topn-direct")
        self.assertIsNotNone(response.artifact)
        scope = self.last_scope()
        self.assertEqual(scope.get("severities"), ["CRITICAL"])
        self.assertEqual(scope.get("limit"), 5)
        self.assertEqual(self.register_len(), 5)

    def test_that_as_report_preserves_top5_critical(self) -> None:
        conv = "topn-inherit"
        self.chat("give me top 5 critical files", conv)
        response = self.chat("give me that as a pdf report", conv)
        self.assertIsNotNone(response.artifact)
        scope = self.last_scope()
        self.assertEqual(scope.get("severities"), ["CRITICAL"])
        self.assertEqual(scope.get("limit"), 5)
        self.assertEqual(self.register_len(), 5)

    def test_top10_high_as_pdf_preserves_limit(self) -> None:
        self.chat("top 10 high files as PDF", "topn-high")
        scope = self.last_scope()
        self.assertEqual(scope.get("severities"), ["HIGH"])
        self.assertEqual(scope.get("limit"), 10)
        self.assertEqual(self.register_len(), 10)

    def test_medium_alerts_pdf_stays_uncapped_medium(self) -> None:
        self.chat("give me pdf about only medium alerts", "topn-medium")
        scope = self.last_scope()
        self.assertEqual(scope.get("severities"), ["MEDIUM"])
        self.assertFalse(scope.get("limit"))

    def test_critical_plus_high_report_stays_combined(self) -> None:
        self.chat("critical + high PDF report", "topn-combined")
        scope = self.last_scope()
        self.assertEqual(scope.get("severities"), ["CRITICAL", "HIGH"])

    def test_top5_pdf_files_is_still_a_file_listing(self) -> None:
        response = self.chat("give me top 5 pdf files", "topn-pdf-files")
        self.assertEqual(response.task_type, "file_query_list")
        self.assertIsNone(response.artifact)
        self.assertEqual(self._scopes, [])
        self.assertIn("doc0.pdf", response.answer)

    def test_pdf_listing_then_report_preserves_extension_and_limit(self) -> None:
        conv = "topn-pdf-inherit"
        listing = self.chat("give me top 5 pdf files", conv)
        self.assertEqual(listing.task_type, "file_query_list")
        response = self.chat("give me that as a pdf report", conv)
        self.assertIsNotNone(response.artifact)
        scope = self.last_scope()
        self.assertEqual(scope.get("kind"), "extension")
        self.assertEqual(scope.get("extension"), ".pdf")
        self.assertEqual(scope.get("limit"), 5)
        self.assertEqual(self.register_len(), 5)

    def test_direct_dotted_pdf_files_as_report(self) -> None:
        self.chat("top 5 .pdf files as report", "topn-dotted")
        scope = self.last_scope()
        self.assertEqual(scope.get("kind"), "extension")
        self.assertEqual(scope.get("extension"), ".pdf")
        self.assertEqual(scope.get("limit"), 5)

    def test_pdf_extension_correction_still_lists_files(self) -> None:
        response = self.chat("dont give pdf report i need .pdf extension files top 5", "topn-correction")
        self.assertEqual(response.task_type, "file_query_list")
        self.assertIsNone(response.artifact)
        self.assertIn("doc0.pdf", response.answer)


if __name__ == "__main__":
    unittest.main()
