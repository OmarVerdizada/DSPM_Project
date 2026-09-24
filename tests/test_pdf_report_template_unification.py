from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from backend.reporting.report_pdf import REPORT_TEMPLATE_ID
from backend.reporting.router import ReportArtifactRequest, create_report
from backend.security import Principal


class PdfReportTemplateUnificationTests(unittest.IsolatedAsyncioTestCase):
    async def test_dashboard_endpoint_uses_the_shared_artifact_renderer(self) -> None:
        principal = Principal("dashboard-viewer", "viewer", "tenant-a")
        artifact = {
            "artifact_id": "a" * 32,
            "template_id": REPORT_TEMPLATE_ID,
            "preview_url": "/api/v1/reports/artifacts/" + "a" * 32 + "?dl_token=signed&inline=1",
        }
        with patch("backend.reporting.router.create_report_artifact", return_value=artifact) as create:
            result = await create_report(ReportArtifactRequest(scan_id="scan-123"), principal)

        self.assertEqual(result, artifact)
        create.assert_called_once_with(
            principal,
            {},
            scan_id="scan-123",
            scope={"kind": "full"},
        )

    def test_dashboard_pdf_composer_consumes_shared_signed_preview(self) -> None:
        app_js = Path("frontend/app.js").read_text(encoding="utf-8")

        self.assertIn('const UNIFIED_PDF_TEMPLATE_ID = "sentro-dspm-unified-v1"', app_js)
        self.assertIn('fetch("/api/v1/reports"', app_js)
        # Reporting outlived Copilot's removal; it must not point back at it.
        self.assertNotIn("copilot", app_js.lower())
        # C8: the console opens the artifact by fetching it with its one-time token in
        # a header and showing a same-origin blob; the signed query URL it used to fall
        # back to no longer exists.
        self.assertIn('"X-Artifact-Token": token', app_js)
        self.assertIn("artifact.artifact_path", app_js)
        self.assertNotIn("dl_token", app_js)
        self.assertNotIn("function buildExecutiveReportHtml", app_js)


if __name__ == "__main__":
    unittest.main()
