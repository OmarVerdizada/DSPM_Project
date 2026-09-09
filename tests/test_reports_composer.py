"""The Reports page: one composer, four documents, three formats.

These are contract tests, not rendering tests. They defend the promises the
page makes to whoever reads what it produces:

  * a report counts the estate the server holds, not the page of rows the
    Findings workspace happens to have loaded;
  * every finding it prints carries a status, a reason, and an action;
  * the build line above the button describes the file that comes out of it.
"""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend import store
from backend.app import app
from backend.security import Principal, require_principal
from risk.risk_engine import finding_reason, finding_recommendation

SCRIPT = Path("frontend/app.js").read_text(encoding="utf-8")
MARKUP = Path("frontend/index.html").read_text(encoding="utf-8")
SHEET = Path("frontend/styles/reports.css").read_text(encoding="utf-8")


def reports_block() -> str:
    start = SCRIPT.index("// ---- Reports ---")
    return SCRIPT[start:SCRIPT.index("function buildReportModel()", start)]


class ReportScopeTests(unittest.TestCase):
    """A report covers the scan, not the workspace slice."""

    def test_rows_come_from_the_findings_api_not_the_loaded_files(self) -> None:
        block = reports_block()
        self.assertIn("/api/findings?", block)
        # latestFiles is the 200-row inventory slice the Findings page holds.
        # Building a report from it silently reports on part of the estate.
        self.assertNotIn("latestFiles", block)

    def test_every_page_of_the_scope_is_fetched_for_the_file(self) -> None:
        block = reports_block()
        self.assertIn("next_cursor", block)
        self.assertIn("REPORT_ROW_CEILING", block)
        self.assertIn("loadReportRows({ complete: true })", block)

    def test_the_document_states_what_it_could_not_carry(self) -> None:
        block = reports_block()
        self.assertIn("function reportCoverageLine()", block)
        self.assertIn("highest-scoring of them", block)

    def test_scope_controls_map_onto_the_query_the_server_understands(self) -> None:
        for element in ("report-coverage", "report-severity", "report-status"):
            self.assertIn(f'id="{element}"', MARKUP)
        block = reports_block()
        for param in ('params.set("scope"', 'params.set("status"', 'params.set("severity"'):
            self.assertIn(param, block)

    def test_a_narrowed_scope_says_what_its_aggregates_were_counted_from(self) -> None:
        block = reports_block()
        self.assertIn("function reportScopeIsWhole()", block)
        self.assertIn("function reportSampleNote()", block)


class ReportContentTests(unittest.TestCase):
    """Status, reason and recommendation travel with every finding."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_db = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "reports.sqlite"
        store.init_db()
        self.tenant_id = "tenant_reports_composer"
        store.create_tenant(self.tenant_id, "Reports Tenant")
        store.save_scan_history(self.tenant_id, {
            "scan_id": "reports-a",
            "timestamp": "2026-09-04T12:00:00+00:00",
            "source": "local",
            "scan_label": "Reports scope",
            "summary": {"total_files": 1},
            "files": [{
                "path": "/reports/cards.csv", "name": "cards.csv", "source": "local",
                "risk": {"level": "CRITICAL", "score": 95},
                "findings": [{
                    "finding_id": "finding_reports_00001",
                    "type": "credit_card",
                    "display_name": "Credit card",
                    "status": "OPEN",
                    "risk": {"level": "CRITICAL", "score": 95},
                    "frameworks": ["PCI_DSS"],
                    "occurrence_count": 3,
                }],
            }],
        })
        app.dependency_overrides[require_principal] = lambda: Principal(
            subject="admin", role="admin",
            tenant_id=self.tenant_id, home_tenant_id=self.tenant_id,
        )
        self.client = TestClient(app)

    def tearDown(self) -> None:
        app.dependency_overrides.pop(require_principal, None)
        store.DB_PATH = self.original_db
        self.temp_dir.cleanup()

    def test_the_findings_row_carries_its_own_risk_story(self) -> None:
        response = self.client.get("/api/findings?scope=all&status=all&limit=10")
        self.assertEqual(response.status_code, 200)
        rows = response.json().get("items", [])
        self.assertTrue(rows, "the fixture produced no findings to report on")
        for row in rows:
            # Reading these from a file's detail blob costs one request per
            # finding, which a report of thousands cannot pay.
            self.assertTrue(row.get("reason"))
            self.assertTrue(row.get("recommendation"))
            self.assertTrue(row.get("status"))

    def test_the_engine_answers_for_a_finding_alone(self) -> None:
        signal = {"type": "credit_card", "label": "Credit card", "count": 2}
        self.assertTrue(finding_reason(signal))
        self.assertTrue(finding_recommendation(signal, "HIGH"))

    def test_a_framework_category_gets_a_reason_not_a_rule_name(self) -> None:
        # Without a category reason these fell back to printing the rule id.
        for category in ("pci_cardholder_data", "biometric_data", "Audit and Compliance"):
            reason = finding_reason({
                "type": "unmapped_rule", "label": "Example finding",
                "description": "Example finding", "category": category, "count": 1,
            })
            self.assertNotIn("unmapped_rule", reason)
            self.assertIn("indicates", reason)

    def test_the_register_prints_status_reason_and_action(self) -> None:
        block = reports_block()
        register = block[block.index('case "register":'):block.index('case "remediation":')]
        for column in ("Status", "Why it is a risk", "Recommended action"):
            self.assertIn(f'"{column}"', register)


class ReportCompositionTests(unittest.TestCase):
    """Four documents, three formats, and a build line that tells the truth."""

    def test_each_document_names_its_reader(self) -> None:
        block = reports_block()
        for report in ("executive", "register", "inventory", "compliance"):
            self.assertIn(f'id: "{report}"', block)
        self.assertEqual(block.count("audience:"), 4)
        self.assertEqual(block.count("blurb:"), 4)

    def test_every_section_offered_can_be_built(self) -> None:
        block = reports_block()
        declared = set(re.findall(r"^  (\w+): \{ label:", block, re.MULTILINE))
        handled = set(re.findall(r'case "(\w+)":', block))
        self.assertTrue(declared)
        self.assertEqual(declared - handled, set(), "a section is offered but never rendered")

    def test_every_section_a_document_lists_is_declared(self) -> None:
        block = reports_block()
        listed = set(re.findall(r'sections: \[([^\]]+)\]', block))
        wanted = {name.strip().strip('"') for group in listed for name in group.split(",") if name.strip()}
        declared = set(re.findall(r"^  (\w+): \{ label:", block, re.MULTILINE))
        self.assertEqual(wanted - declared, set(), "a document lists a section that does not exist")

    def test_all_three_formats_are_produced(self) -> None:
        block = reports_block()
        for fmt in ("pdf", "word", "excel"):
            self.assertIn(f'id: "{fmt}"', block)
        self.assertIn("application/msword", block)
        self.assertIn("application/vnd.ms-excel", block)

    def test_the_build_line_promises_the_file_not_the_scope(self) -> None:
        block = reports_block()
        line = block[block.index("function renderReportBuildLine()"):]
        line = line[:line.index("\n}\n")]
        self.assertIn("REPORT_ROW_CEILING", line)
        self.assertIn("of ${stats.findings.toLocaleString()} findings", line)

    def test_the_preview_and_the_file_are_built_by_one_function(self) -> None:
        block = reports_block()
        for builder in ("buildReportDocumentHtml", "buildReportWorkbookHtml", "renderReportPreview"):
            body = block[block.index(f"function {builder}") if f"function {builder}" in block
                         else block.index(f"async function {builder}"):]
            self.assertIn("reportSectionBlocks()", body[:body.index("\n}\n")])


class ReportLayoutTests(unittest.TestCase):
    """The rail holds every control at once; the document is a page."""

    def test_the_page_sizes_to_the_window(self) -> None:
        self.assertIn("#tab-reports.tab-panel.active", SHEET)
        self.assertIn("height: 100dvh", SHEET)
        self.assertIn("@media (max-height: 640px)", SHEET)

    def test_only_the_section_list_scrolls_in_the_rail(self) -> None:
        rail = SHEET[SHEET.index(".report-composer {"):]
        rail = rail[:rail.index("\n}")]
        self.assertIn("grid-template-rows:", rail)
        self.assertIn("overflow: hidden", rail)
        section_list = SHEET[SHEET.index(".report-section-list {"):]
        self.assertIn("overflow-y: auto", section_list[:section_list.index("\n}")])

    def test_the_document_wraps_rather_than_scrolling_sideways(self) -> None:
        table = SHEET[SHEET.index(".report-table {"):]
        table = table[:table.index("\n}")]
        # styles.css floors every table at 1180px for the inventory grid; a
        # printed page is 760px wide.
        self.assertIn("table-layout: fixed", table)
        self.assertIn("min-width: 0", table)

    def test_the_composer_reads_in_the_order_it_is_answered(self) -> None:
        panel = MARKUP[MARKUP.index('id="report-composer"'):MARKUP.index('id="report-preview"')]
        order = [panel.index(marker) for marker in (
            'id="report-type-list"', 'id="report-coverage"', 'id="report-sections"',
            'id="report-format"', 'id="report-build-line"', 'id="report-generate"',
        )]
        self.assertEqual(order, sorted(order))


if __name__ == "__main__":
    unittest.main()
