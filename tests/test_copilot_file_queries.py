from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from backend import store
from backend.copilot import memory, session_context
from backend.copilot.llm_client import LLMError
from backend.copilot.evidence_sensitivity import classify_evidence_sensitivity
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
            {
                "type": finding_type,
                "risk": level,
                "description": f"Detected {finding_type}",
                "count": 1,
            }
        ],
        "permissions": {},
    }


class CopilotFileQueryTests(unittest.TestCase):
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
        self.tenant = "file-query-tenant"
        self.principal = Principal("file-query-viewer", "viewer", self.tenant)
        store.save_scan_history(
            self.tenant,
            {
                "scan_id": "scan-file-query-001",
                "timestamp": "2026-07-14T00:00:00+00:00",
                "source": "local-test",
                "summary": {},
                "files": [
                    _file("notes-low.txt", ".txt", 35, "LOW", "email"),
                    _file("secrets-critical.txt", ".txt", 98, "CRITICAL", "api_key"),
                    _file("customers.csv", ".csv", 92, "HIGH", "credit_card"),
                    _file("archive.csv", ".csv", 44, "MEDIUM", "email"),
                    _file("policy.pdf", ".pdf", 88, "HIGH", "confidential_keyword"),
                    _file("config.json", ".json", 74, "MEDIUM", "password"),
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

    def tearDown(self) -> None:
        for provider_patch in reversed(self.provider_patches):
            provider_patch.stop()
        self.session_patch.stop()
        self.memory_patch.stop()
        self.db_patch.stop()
        self.temp.cleanup()

    def chat(self, message: str, conversation_id: str = "file-query-conversation"):
        return _run(handle_chat(message, self.principal, conversation_id, None))

    def test_txt_list_uses_extension_filtered_evidence(self) -> None:
        response = self.chat("give me top 5 txt files")

        self.assertEqual(response.task_type, "file_query_list")
        self.assertEqual(response.tools_used, ["query_files"])
        self.assertIn("secrets-critical.txt", response.answer)
        self.assertIn("notes-low.txt", response.answer)
        self.assertIn("Extension: .txt", response.answer)
        self.assertIn("Origin: local", response.answer)
        self.assertIn("Signals: api_key", response.answer)
        self.assertIn("Recommended action:", response.answer)
        self.assertNotIn("customers.csv", response.answer)
        self.assertLess(response.answer.index("secrets-critical.txt"), response.answer.index("notes-low.txt"))
        self.assertNotIn("C:\\sensitive-root", response.answer)

    def test_missing_extension_is_an_evidence_backed_zero(self) -> None:
        response = self.chat("are there any yaml files?", "file-query-zero")

        self.assertEqual(response.task_type, "file_query_existence")
        self.assertIn("0 .yaml files", response.answer)
        self.assertIn("scan-file-query-001", response.answer)
        self.assertNotIn("/path/to/", response.answer)

    def test_pdf_files_are_not_a_report_request(self) -> None:
        response = self.chat("give me top 5 pdf files", "file-query-pdf")

        self.assertEqual(response.task_type, "file_query_list")
        self.assertIsNone(response.artifact)
        self.assertIn("policy.pdf", response.answer)
        self.assertNotIn("Your PDF is ready", response.answer)

    def test_explicit_pdf_report_still_uses_report_flow(self) -> None:
        artifact = {
            "artifact_id": "a" * 32,
            "filename": "dspm_report.pdf",
            "download_url": "/api/v1/copilot/artifacts/" + "a" * 32,
            "type": "pdf",
            "source_scan_id": "scan-file-query-001",
        }
        with patch("backend.copilot.service.create_report_artifact", return_value=artifact):
            response = self.chat("give me a PDF report", "explicit-pdf-report")

        self.assertIn(response.task_type, {"artifact_create", "artifact_export", "report_generation"})
        self.assertIsNotNone(response.artifact)
        self.assertIn("PDF", response.answer)

    def test_report_correction_reroutes_to_pdf_extension_files(self) -> None:
        response = self.chat(
            "dont give pdf report i need .pdf extension files top 5",
            "file-query-pdf-correction",
        )

        self.assertEqual(response.task_type, "file_query_list")
        self.assertIn("policy.pdf", response.answer)
        self.assertIsNone(response.artifact)

    def test_nevermind_with_csv_request_executes_new_request(self) -> None:
        response = self.chat("nevermind just give top 5 csv files", "file-query-cancel-new")

        self.assertEqual(response.task_type, "file_query_list")
        self.assertIn("customers.csv", response.answer)
        self.assertIn("archive.csv", response.answer)
        self.assertNotIn("set that aside", response.answer)

    def test_provider_down_does_not_change_deterministic_file_answer(self) -> None:
        response = self.chat("how many csv files exist?", "file-query-provider-down")

        self.assertEqual(response.task_type, "file_query_count")
        self.assertIn("2 .csv files", response.answer)
        self.assertNotIn("model", response.answer.lower())
        self.assertNotIn("cannot generate", response.answer.lower())

    def test_nonexistent_file_correction_rechecks_previous_query(self) -> None:
        conversation_id = "file-query-made-up-correction"
        first = self.chat("give me top 5 txt files", conversation_id)
        correction = self.chat("those files do not exist, you made them up", conversation_id)

        self.assertEqual(first.task_type, "file_query_list")
        self.assertEqual(correction.task_type, "file_query_correction")
        self.assertIn("re-checked", correction.answer.lower())
        self.assertIn("secrets-critical.txt", correction.answer)
        self.assertNotIn("/path/to/", correction.answer)

    def test_why_after_file_query_explains_actual_evidence_result(self) -> None:
        conversation_id = "file-query-why"
        first = self.chat("give me top 5 yaml files", conversation_id)
        why = self.chat("why?", conversation_id)

        self.assertIn("0 .yaml files", first.answer)
        self.assertEqual(why.task_type, "file_query_explanation")
        self.assertIn("latest scan", why.answer.lower())
        self.assertIn("0 .yaml files", why.answer)

    def test_general_top_files_behavior_remains_evidence_backed(self) -> None:
        response = self.chat("give me top 3 files", "file-query-general-top")

        self.assertEqual(response.task_type, "file_query_list")
        self.assertIn("secrets-critical.txt", response.answer)
        self.assertIn("customers.csv", response.answer)
        self.assertIn("policy.pdf", response.answer)
        self.assertNotIn("notes-low.txt", response.answer)

    def test_large_scan_rows_do_not_corrupt_the_structured_file_payload(self) -> None:
        files = []
        for index in range(12):
            item = _file(f"large-{index:02d}.csv", ".csv", 100 - index, "HIGH", "confidential_keyword")
            item["findings"][0]["description"] = "sensitive evidence " * 250
            item["risk"]["reasons"] = ["risk reason " * 200]
            item["risk"]["dlp_recommendations"] = ["recommendation " * 200]
            item["risk"]["remediation"]["actions"] = ["remediation action " * 200]
            files.append(item)
        store.save_scan_history(
            self.tenant,
            {
                "scan_id": "scan-file-query-large",
                "timestamp": "2026-07-14T00:01:00+00:00",
                "source": "local-test",
                "summary": {},
                "files": files,
            },
        )

        response = self.chat("give me top 10 csv files", "file-query-large-payload")

        self.assertIn("scan-file-query-large", response.answer)
        self.assertIn("Showing 10", response.answer)
        self.assertIn("large-00.csv", response.answer)
        self.assertIn("large-09.csv", response.answer)
        self.assertNotIn("scan=unknown", response.answer)

    def test_file_evidence_sensitivity_uses_whole_words(self) -> None:
        self.assertTrue(classify_evidence_sensitivity("show top 5 csv files").required)
        self.assertFalse(classify_evidence_sensitivity("show profile settings").required)


if __name__ == "__main__":
    unittest.main()
