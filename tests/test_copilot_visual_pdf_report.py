from __future__ import annotations

import tempfile
import unittest
import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from backend import store
from backend.copilot import artifacts
from backend.copilot.artifacts import artifact_file, create_report_artifact
from backend.copilot.report_pdf import REPORT_TEMPLATE_ID, SENTRO_BLUE, SENTRO_INDIGO, SENTRO_NAVY
from backend.security import Principal, verify_artifact_download_token


def _file(name: str, level: str, score: int, finding_type: str) -> dict:
    return {
        "name": name,
        "path": f"C:\\authorized-scan\\{name}",
        "source": "local",
        "risk": {
            "level": level,
            "score": score,
            "reasons": [f"{finding_type} evidence requires owner review"],
            "remediation": {"actions": [f"Restrict access to {name}"]},
        },
        "findings": [{"type": finding_type, "count": 1, "risk": level}],
    }


def _pdf_page_count(payload: bytes) -> int:
    return len(re.findall(rb"/Type\s*/Page\b", payload))


def _pdf_text(payload: bytes) -> str:
    chunks = re.findall(rb"\(((?:\\.|[^\\)])*)\)\s*Tj", payload)
    decoded = []
    for chunk in chunks:
        value = chunk.decode("latin-1", "replace")
        value = value.replace("\\(", "(").replace("\\)", ")").replace("\\\\", "\\")
        decoded.append(value)
    return "\n".join(decoded)


class CopilotVisualPdfReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db_patch = patch.object(store, "DB_PATH", self.root / "dspm.sqlite")
        self.artifact_patch = patch.object(artifacts, "ARTIFACT_ROOT", self.root / "copilot")
        self.db_patch.start()
        self.artifact_patch.start()
        store.init_db()
        self.tenant = "visual-report-tenant"
        self.principal = Principal("visual-viewer", "viewer", self.tenant)
        files = [
            _file("critical-secrets.env", "CRITICAL", 99, "api_key"),
            _file("high-customers.csv", "HIGH", 91, "credit_card"),
            _file("medium-policy.docx", "MEDIUM", 67, "confidential_keyword"),
            _file("low-notes.txt", "LOW", 22, "email"),
        ]
        for index in range(18):
            files.append(_file(f"medium-evidence-{index:02d}.json", "MEDIUM", 66 - index, "email"))
        store.save_scan_history(
            self.tenant,
            {
                "scan_id": "scan-visual-report-001",
                "timestamp": "2026-07-14T01:00:00+00:00",
                "source": "local-test",
                "summary": {"critical": 1, "high": 1, "medium": 19, "low": 1, "total_files": 22},
                "files": files,
            },
        )

    def tearDown(self) -> None:
        self.artifact_patch.stop()
        self.db_patch.stop()
        self.temp.cleanup()

    def _create(self, scope: dict | None = None) -> tuple[dict, Path, str]:
        result = create_report_artifact(self.principal, {}, scope=scope)
        pdf_path, metadata = artifact_file(self.principal, result["artifact_id"], "pdf")
        payload = pdf_path.read_bytes()
        text = _pdf_text(payload)
        return {**result, "page_count": _pdf_page_count(payload), "metadata": metadata}, pdf_path, text

    def test_full_pdf_is_visual_paginated_and_contains_composer_sections(self) -> None:
        result, pdf_path, text = self._create()
        payload = pdf_path.read_bytes()

        self.assertEqual(result["render_style"], "visual_composer")
        self.assertEqual(result["template_id"], REPORT_TEMPLATE_ID)
        self.assertIn("inline=1", result["preview_url"])
        self.assertGreaterEqual(result["page_count"], 3)
        self.assertIn(b" re ", payload, "visual PDF must draw cards, bars, or table cells")
        self.assertIn(b" rg\n", payload, "visual PDF must use fill colors")
        self.assertIn(b"/F2", payload, "visual PDF must use a distinct heading font")
        for heading in (
            "Executive summary",
            "Risk posture",
            "Risk distribution",
            "Detection signals",
            "Remediation plan",
            "Scan comparison",
            "Priority file queue",
            "Full evidence register",
        ):
            self.assertIn(heading, text)
        self.assertNotIn("Report truncated", text)

    def test_unified_template_uses_sentro_navy_blue_indigo_theme(self) -> None:
        self.assertEqual(REPORT_TEMPLATE_ID, "sentro-dspm-unified-v1")
        self.assertEqual(SENTRO_NAVY, (0.043, 0.090, 0.224))
        self.assertEqual(SENTRO_BLUE, (0.145, 0.388, 0.922))
        self.assertEqual(SENTRO_INDIGO, (0.310, 0.275, 0.898))
        _, pdf_path, _ = self._create()
        payload = pdf_path.read_bytes()
        for color in (SENTRO_NAVY, SENTRO_BLUE, SENTRO_INDIGO):
            command = (" ".join(f"{component:.3f}" for component in color) + " rg").encode("ascii")
            self.assertIn(command, payload)

    def test_visual_operations_stay_inside_landscape_page_bounds(self) -> None:
        _, pdf_path, _ = self._create()
        payload = pdf_path.read_bytes()
        rectangles = re.findall(rb"(-?\d+(?:\.\d+)?) (-?\d+(?:\.\d+)?) (\d+(?:\.\d+)?) (\d+(?:\.\d+)?) re [fB]", payload)
        text_positions = re.findall(rb"(-?\d+(?:\.\d+)?) (-?\d+(?:\.\d+)?) Td", payload)

        self.assertGreater(len(rectangles), 20)
        self.assertGreater(len(text_positions), 40)
        for raw_x, raw_y, raw_width, raw_height in rectangles:
            x, y, width, height = map(float, (raw_x, raw_y, raw_width, raw_height))
            self.assertGreaterEqual(x, 0)
            self.assertGreaterEqual(y, 0)
            self.assertLessEqual(x + width, 842.01)
            self.assertLessEqual(y + height, 595.01)
        for raw_x, raw_y in text_positions:
            x, y = float(raw_x), float(raw_y)
            self.assertGreaterEqual(x, 0)
            self.assertGreaterEqual(y, 0)
            self.assertLessEqual(x, 842.01)
            self.assertLessEqual(y, 595.01)

    def test_medium_report_contains_only_medium_evidence_rows(self) -> None:
        result, _, text = self._create({"kind": "severity", "severities": ["MEDIUM"]})

        self.assertEqual(result["scope"]["severities"], ["MEDIUM"])
        self.assertIn("medium-policy.docx", text)
        self.assertIn("medium-evidence-00.json", text)
        self.assertNotIn("critical-secrets.env", text)
        self.assertNotIn("high-customers.csv", text)
        self.assertNotIn("low-notes.txt", text)

    def test_critical_high_report_preserves_combined_scope(self) -> None:
        result, _, text = self._create({"kind": "severity", "severities": ["CRITICAL", "HIGH"]})

        self.assertEqual(result["scope"]["severities"], ["CRITICAL", "HIGH"])
        self.assertIn("critical-secrets.env", text)
        self.assertIn("high-customers.csv", text)
        self.assertNotIn("medium-policy.docx", text)

    def test_single_finding_report_contains_only_selected_file(self) -> None:
        result, _, text = self._create({"kind": "finding", "finding_ref": "high-customers.csv"})

        self.assertEqual(result["scope"]["kind"], "finding")
        self.assertIn("high-customers.csv", text)
        self.assertNotIn("critical-secrets.env", text)
        self.assertNotIn("medium-policy.docx", text)

    def test_signed_download_token_still_resolves_the_stored_artifact(self) -> None:
        result, pdf_path, _ = self._create({"kind": "severity", "severities": ["HIGH"]})
        token = parse_qs(urlsplit(result["download_url"]).query)["dl_token"][0]
        token_principal = verify_artifact_download_token(token, result["artifact_id"])

        self.assertIsNotNone(token_principal)
        self.assertEqual(token_principal.tenant_id, self.tenant)
        resolved = artifact_file(token_principal, result["artifact_id"], "pdf")
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved[0], pdf_path)


if __name__ == "__main__":
    unittest.main()
