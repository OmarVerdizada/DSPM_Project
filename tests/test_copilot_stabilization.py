"""Regression tests for the DSPM system-stabilization pass.

Covers the real Copilot regressions from the required transcript:

* evidence-backed "most critical files" answers;
* previous-result -> scoped PDF report conversion (bare "pdf" / "give as a
  pdf" / "that as a pdf report");
* PDF *report* intent vs ``.pdf`` *extension* file intent;
* medium/high/critical scoped report requests;
* dashboard risk-summary minus/delta question routed to explanation, not
  navigation (and no "Dashboaard" typo);
* English conversation never leaking Azerbaijani report labels;
* deterministic behavior with the provider forced down.
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


_ARTIFACT = {
    "artifact_id": "a" * 32,
    "filename": "dspm_report.pdf",
    "download_url": "/api/v1/copilot/artifacts/" + "a" * 32,
    "type": "pdf",
    "source_scan_id": "scan-stab-001",
}


class CopilotStabilizationTests(unittest.TestCase):
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
        self.tenant = "stab-tenant"
        self.principal = Principal("stab-viewer", "viewer", self.tenant)
        store.save_scan_history(
            self.tenant,
            {
                "scan_id": "scan-stab-001",
                "timestamp": "2026-07-14T00:00:00+00:00",
                "source": "local-test",
                "summary": {},
                "files": [
                    _file("secrets-critical.txt", ".txt", 98, "CRITICAL", "api_key"),
                    _file("db-dump.sql", ".sql", 95, "CRITICAL", "password"),
                    _file("customers.csv", ".csv", 92, "HIGH", "credit_card"),
                    _file("policy.pdf", ".pdf", 88, "HIGH", "confidential_keyword"),
                    _file("handbook.pdf", ".pdf", 70, "MEDIUM", "email"),
                    _file("config.json", ".json", 55, "MEDIUM", "password"),
                    _file("notes-low.txt", ".txt", 30, "LOW", "email"),
                ],
            },
        )
        self.down = AsyncMock(side_effect=LLMError("provider down"))
        self.provider_patches = [
            patch("backend.copilot.service.call_ollama", new=self.down),
            patch("backend.copilot.controlled_verbalizer.call_ollama", new=self.down),
            patch("backend.copilot.planner.call_ollama", new=self.down),
            patch("backend.copilot.language_understanding.call_ollama", new=self.down),
        ]
        for provider_patch in self.provider_patches:
            provider_patch.start()
        self._captured_scopes: list = []

    def tearDown(self) -> None:
        for provider_patch in reversed(self.provider_patches):
            provider_patch.stop()
        self.session_patch.stop()
        self.memory_patch.stop()
        self.db_patch.stop()
        self.temp.cleanup()

    def chat(self, message: str, conversation_id: str = "stab-conv"):
        """Send a message with report-artifact creation stubbed so we can assert
        on the resolved report scope without generating a real PDF."""
        def fake_artifact(principal, session_state, scan_id, selected, scope=None):
            self._captured_scopes.append(scope)
            art = dict(_ARTIFACT)
            art["scope"] = scope or {"kind": "full", "label": "Full scan"}
            return art

        with patch("backend.copilot.service.create_report_artifact", side_effect=fake_artifact):
            return _run(handle_chat(message, self.principal, conversation_id, None))

    def last_scope(self):
        return self._captured_scopes[-1] if self._captured_scopes else None

    # ------------------------------------------------------------------ A
    def test_what_are_the_most_critical_files_is_evidence_backed(self) -> None:
        response = self.chat("What are the most critical files?", "most-critical")
        self.assertTrue(response.task_type.startswith("file_query"))
        self.assertIn("secrets-critical.txt", response.answer)
        self.assertIn("CRITICAL", response.answer)
        self.assertIsNone(response.artifact)

    # ------------------------------------------------------------------ B/C
    def test_that_as_pdf_report_preserves_previous_critical_scope(self) -> None:
        conv = "critical-then-report"
        first = self.chat("Give me top 5 critical files", conv)
        self.assertTrue(first.task_type.startswith("file_query"))
        report = self.chat("give me that as a pdf report", conv)
        self.assertIsNotNone(report.artifact)
        scope = self.last_scope()
        self.assertEqual(scope.get("kind"), "severity")
        self.assertEqual(scope.get("severities"), ["CRITICAL"])
        self.assertNotIn("Extension: .pdf", report.answer)

    def test_top5_critical_files_as_pdf_report_is_not_pdf_extension_listing(self) -> None:
        response = self.chat(
            "you must give top 5 critical files as a pdf report", "critical-as-report"
        )
        self.assertNotEqual(response.task_type, "file_query_list")
        self.assertIsNotNone(response.artifact)
        self.assertNotIn("Extension: .pdf", response.answer)
        self.assertNotIn("policy.pdf", response.answer)
        scope = self.last_scope()
        self.assertEqual(scope.get("kind"), "severity")
        self.assertEqual(scope.get("severities"), ["CRITICAL"])

    def test_pdf_about_only_medium_alerts_generates_medium_report(self) -> None:
        response = self.chat("give me pdf about only medium alerts", "medium-report")
        self.assertNotEqual(response.task_type, "file_query_list")
        self.assertIsNotNone(response.artifact)
        self.assertNotIn("Extension: .pdf", response.answer)
        scope = self.last_scope()
        self.assertEqual(scope.get("kind"), "severity")
        self.assertEqual(scope.get("severities"), ["MEDIUM"])

    def test_bare_pdf_after_medium_inherits_medium_scope_in_english(self) -> None:
        conv = "medium-then-bare-pdf"
        self.chat("give me pdf about only medium alerts", conv)
        response = self.chat("pdf", conv)
        self.assertIsNotNone(response.artifact)
        scope = self.last_scope()
        self.assertEqual(scope.get("kind"), "severity")
        self.assertEqual(scope.get("severities"), ["MEDIUM"])
        # English conversation must not leak Azerbaijani report labels.
        self.assertNotIn("PDF hazırdır", response.answer)
        self.assertNotIn("Skan", response.answer)
        self.assertIn("Your PDF is ready", response.answer)

    # ------------------------------------------------------------------ pdf files
    def test_top5_pdf_files_still_lists_pdf_extension_files(self) -> None:
        response = self.chat("give me top 5 pdf files", "pdf-files")
        self.assertEqual(response.task_type, "file_query_list")
        self.assertIsNone(response.artifact)
        self.assertIn("policy.pdf", response.answer)
        self.assertIn("Extension: .pdf", response.answer)

    def test_correction_to_pdf_extension_files_still_lists_files(self) -> None:
        response = self.chat(
            "dont give pdf report i need .pdf extension files top 5", "pdf-correction"
        )
        self.assertEqual(response.task_type, "file_query_list")
        self.assertIsNone(response.artifact)
        self.assertIn("policy.pdf", response.answer)

    # ------------------------------------------------------------------ D
    def test_dashboard_minus_question_routes_to_delta_explanation(self) -> None:
        response = self.chat(
            "In Dashboard page risk summary part why show some alerts with minus? "
            "For example: Critical: -1, High: -2",
            "dashboard-minus",
        )
        self.assertEqual(response.task_type, "risk_summary_delta_explanation")
        self.assertIn("delta", response.answer.lower())
        # It must explain the data, not tell the user how to navigate.
        self.assertNotIn("left sidebar", response.answer)
        self.assertNotIn("Dashboaard", response.answer)

    def test_answer_me_after_dashboard_does_not_repeat_navigation(self) -> None:
        conv = "dashboard-answer-me"
        self.chat(
            "In Dashboard page risk summary part why show some alerts with minus? "
            "For example: Critical: -1, High: -2",
            conv,
        )
        response = self.chat("answer me", conv)
        self.assertNotEqual(response.task_type, "navigation_help")
        self.assertNotIn("Dashboaard", response.answer)
        self.assertNotIn("open the Dashboard page from", response.answer)

    # ------------------------------------------------------------------ language
    def test_english_report_reply_has_no_azerbaijani_labels(self) -> None:
        response = self.chat("give me a pdf report", "english-report")
        self.assertIsNotNone(response.artifact)
        self.assertNotIn("PDF hazırdır", response.answer)
        self.assertNotIn("Skan", response.answer)
        self.assertNotIn("hazırdır", response.answer)
        self.assertIn("Your PDF is ready", response.answer)

    # ------------------------------------------------------------------ provider down
    def test_provider_down_keeps_report_and_evidence_deterministic(self) -> None:
        # Provider is already forced down in setUp; both an explicit report and
        # an evidence file query must still resolve deterministically.
        report = self.chat("give me a critical files pdf report", "prov-down-report")
        self.assertIsNotNone(report.artifact)
        scope = self.last_scope()
        self.assertEqual(scope.get("severities"), ["CRITICAL"])

        files = self.chat("how many pdf files exist?", "prov-down-files")
        self.assertEqual(files.task_type, "file_query_count")
        self.assertIn("2 .pdf files", files.answer)
        self.assertNotIn("cannot generate", files.answer.lower())


if __name__ == "__main__":
    unittest.main()
