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


def declared_sections() -> set:
    """The section catalogue only - REPORT_DEPTHS shares its literal shape."""
    block = reports_block()
    catalogue = block[block.index("const REPORT_SECTIONS = {"):]
    catalogue = catalogue[:catalogue.index("\n};")]
    return set(re.findall(r"^  (\w+): \{ label:", catalogue, re.MULTILINE))


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
        declared = declared_sections()
        handled = set(re.findall(r'case "(\w+)":', reports_block()))
        self.assertTrue(declared)
        self.assertEqual(declared - handled, set(), "a section is offered but never rendered")

    def test_every_section_a_document_lists_is_declared(self) -> None:
        block = reports_block()
        listed = set(re.findall(r'sections: \[([^\]]+)\]', block))
        wanted = {name.strip().strip('"') for group in listed for name in group.split(",") if name.strip()}
        self.assertEqual(wanted - declared_sections(), set(), "a document lists a section that does not exist")

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
    """A rail beside a document, holding every control at once."""

    def test_the_page_sizes_to_the_window_and_only_two_things_scroll(self) -> None:
        panel = SHEET[SHEET.index("#tab-reports.tab-panel.active {"):]
        panel = panel[:panel.index("\n}")]
        self.assertIn("height: 100dvh", panel)
        self.assertIn("overflow: hidden", panel)
        # The rail itself must not scroll - it is meant to hold everything.
        rail = SHEET[SHEET.index(".report-composer {"):]
        self.assertIn("overflow: hidden", rail[:rail.index("\n}")])
        # The section list and the document do.
        for selector in (".report-section-list {", ".report-preview {"):
            block = SHEET[SHEET.index(selector):]
            self.assertIn("overflow-y: auto", block[:block.index("\n}")])
        # And a short window gives up on all of it rather than clipping.
        self.assertIn("@media (max-height: 620px)", SHEET)

    def test_only_the_section_list_gives_up_height(self) -> None:
        # Letting every group shrink compressed each below its content and the
        # rows drew on top of each other.
        group = SHEET[SHEET.index(".composer-group {"):]
        self.assertIn("flex: 0 0 auto", group[:group.index("\n}")])
        grow = SHEET[SHEET.index(".composer-group-grow {"):]
        self.assertIn("flex: 1 1 auto", grow[:grow.index("\n}")])

    def test_the_rows_absorb_the_remainder_instead_of_leaving_a_gap(self) -> None:
        row = SHEET[SHEET.index(".report-section-row {"):]
        row = row[:row.index("\n}")]
        self.assertIn("flex: 1 1 auto", row)
        self.assertIn("min-height:", row)
        self.assertIn("max-height:", row)

    def test_the_legacy_button_floor_is_stated_back(self) -> None:
        # styles.css floors every button at 40px for touch, which cost the rail
        # 64px across four type rows before this.
        for selector in (".report-type {", ".report-format-option {"):
            block = SHEET[SHEET.index(selector):]
            self.assertIn("min-height: 0", block[:block.index("\n}")])

    def test_one_explainer_answers_for_the_whole_list(self) -> None:
        # Fifteen hint lines cost 300px of rail and are read once.
        self.assertIn('id="report-section-explainer"', MARKUP)
        block = reports_block()
        self.assertIn("function reportSectionExplain(", block)
        self.assertIn("function reportSectionDefaultHint(", block)
        # Reserved height, so moving the pointer never shifts the list under it.
        legend = SHEET[SHEET.index(".composer-legend-live {"):]
        self.assertIn("min-height:", legend[:legend.index("\n}")])

    def test_pointing_at_a_row_lights_the_section_it_makes(self) -> None:
        block = reports_block()
        self.assertIn("function reportLinkSection(", block)
        self.assertIn(".report-section-block.is-linked", SHEET)
        self.assertIn('addEventListener("pointerover"', block)
        self.assertIn('addEventListener("focusin"', block)

    def test_the_carrier_prints_what_the_document_prints(self) -> None:
        self.assertIn('id="report-carrier-title"', MARKUP)
        self.assertIn('id="report-carrier-scope"', MARKUP)
        block = reports_block()
        carrier = block[block.index("function renderReportCarrier()"):]
        carrier = carrier[:carrier.index("\n}")]
        self.assertIn("reportType().label", carrier)
        self.assertIn("reportCarrierScopeLabel()", carrier)

    def test_the_document_is_on_the_page_not_in_a_pane(self) -> None:
        document = SHEET[SHEET.index(".report-document {"):]
        document = document[:document.index("\n}")]
        # Any border is an edge and an edge is a box, and a max-width would put
        # the dead white back either side of it.
        self.assertNotIn("border:", document)
        self.assertNotIn("box-shadow", document)
        self.assertNotIn("max-width", document)

    def test_the_document_wraps_rather_than_scrolling_sideways(self) -> None:
        table = SHEET[SHEET.index(".report-table {"):]
        table = table[:table.index("\n}")]
        # styles.css floors every table at 1180px for the inventory grid.
        self.assertIn("table-layout: fixed", table)
        self.assertIn("min-width: 0", table)

    def test_a_document_table_header_does_not_peel_off(self) -> None:
        # styles.css makes every `thead th` sticky for the tables that live in a
        # .table-wrap. This document has none, so its headers would stack at the
        # top of the preview as you read.
        header = SHEET[SHEET.index(".report-table th {"):]
        self.assertIn("position: static", header[:header.index("\n}")])

    def test_every_token_the_sheet_names_exists(self) -> None:
        # --radius-md, --radius-sm and --elev-1 were all invented, and a var()
        # that resolves to nothing silently drops the whole declaration - which
        # is how the document had square corners nobody had asked for.
        tokens = Path("frontend/styles/tokens.css").read_text(encoding="utf-8")
        local = set(re.findall(r"^\s*(--[a-z0-9-]+):", SHEET, re.MULTILINE))
        local |= set(re.findall(r"--report-[a-z-]+", SHEET))
        for name in sorted(set(re.findall(r"var\((--[a-z0-9-]+)", SHEET)) - local):
            self.assertIn(f"{name}:", tokens, f"{name} is not defined in tokens.css")

    def test_a_section_this_scan_cannot_build_says_so_before_it_is_ticked(self) -> None:
        block = reports_block()
        self.assertIn("REPORT_SECTION_AVAILABILITY", block)
        self.assertIn("Not part of this scan.", block)
        self.assertIn("reportSectionIsAvailable(id)", block)
        # The PDF-inert pass must not clear the flag the unavailable pass set.
        self.assertIn("fixed || !reportSectionIsAvailable(", block)

    def test_the_composer_reads_in_the_order_it_is_answered(self) -> None:
        panel = MARKUP[MARKUP.index('id="report-composer"'):MARKUP.index('id="report-preview"')]
        order = [panel.index(marker) for marker in (
            'id="report-type-list"', 'id="report-coverage"', 'id="report-depth"',
            'id="report-sections"', 'id="report-format"',
            'id="report-carrier-title"', 'id="report-build-line"', 'id="report-generate"',
        )]
        self.assertEqual(order, sorted(order))


class ReportMotionTests(unittest.TestCase):
    """The answer arrives; it does not teleport."""

    def test_the_document_announces_itself_when_it_changes(self) -> None:
        self.assertIn("@keyframes report-document-in", SHEET)
        animation = SHEET[SHEET.index(".report-document { animation:"):]
        animation = animation[:animation.index("}")]
        self.assertIn("var(--motion-base)", animation)

    def test_no_content_is_held_hostage_by_an_animation(self) -> None:
        # `both` would hold the document at the keyframe's opacity: 0 until the
        # animation plays, and where frames are throttled it never does - which
        # hides the whole report behind a decoration.
        animation = SHEET[SHEET.index(".report-document { animation:"):]
        animation = animation[:animation.index("}")]
        self.assertNotIn("both", animation)
        self.assertNotIn("forwards", animation)
        self.assertNotIn("backwards", animation)

    def test_the_page_being_replaced_steps_back_while_it_is_counted(self) -> None:
        self.assertIn(".report-preview.is-loading", SHEET)
        block = reports_block()
        self.assertIn('reportPreview.classList.add("is-loading")', block)
        # And it must come off on the failure path too, or the page stays dim.
        self.assertEqual(block.count('reportPreview.classList.remove("is-loading")'), 2)

    def test_every_duration_comes_from_the_motion_contract(self) -> None:
        # The contract collapses these under prefers-reduced-motion; a hardcoded
        # duration would not collapse with them.
        for value in re.findall(r"transition:[^;]+;|animation:[^;]+;", SHEET):
            self.assertNotIn("ms", value.replace("var(--motion-fast)", "").replace("var(--motion-base)", ""),
                             f"hardcoded duration in: {value.strip()}")


class ReportDetailTests(unittest.TestCase):
    """The two fields that do not fit a cell get blocks of their own."""

    def test_the_count_is_clamped_to_twenty_whatever_the_markup_says(self) -> None:
        block = reports_block()
        clamp = block[block.index("function reportDetailCount()"):]
        self.assertIn("Math.min(20", clamp[:clamp.index("\n}")])

    def test_a_detail_block_reaches_all_three_destinations(self) -> None:
        block = reports_block()
        self.assertIn("function reportDetailMarkup(", block)
        self.assertIn("function reportDetailWordHtml(", block)
        self.assertIn("function reportDetailWorkbookHtml(", block)
        self.assertIn("block.detail", block)

    def test_a_detail_block_carries_the_reason_and_the_action(self) -> None:
        block = reports_block()
        markup = block[block.index("function reportDetailMarkup("):]
        markup = markup[:markup.index("\nfunction ")]
        self.assertIn("Why it is a risk", markup)
        self.assertIn("Recommended action", markup)
        self.assertIn("entry.reason", markup)
        self.assertIn("entry.recommendation", markup)

    def test_only_the_facts_a_finding_carries_are_printed(self) -> None:
        block = reports_block()
        facts = block[block.index("function reportDetailFacts("):]
        facts = facts[:facts.index("\n}")]
        self.assertIn("reportCellIsEmpty", facts)


class ReportColumnTests(unittest.TestCase):
    """A column nobody answered is not a column."""

    def test_a_blank_is_a_blank_and_an_answer_is_not(self) -> None:
        block = reports_block()
        cells = block[block.index("const REPORT_EMPTY_CELLS"):]
        cells = cells[:cells.index("\n")]
        # "Owner: unknown" is a finding, not a gap. Dropping a column because
        # every row said "unknown" deletes a true statement.
        self.assertNotIn("unknown", cells)
        self.assertNotIn("none", cells)
        self.assertIn('"-"', cells)

    def test_the_identity_column_is_never_dropped(self) -> None:
        block = reports_block()
        factory = block[block.index("function reportTable("):]
        factory = factory[:factory.index("\n}")]
        self.assertIn("keep[0] = true;", factory)

    def test_dropping_happens_in_the_one_factory_every_section_uses(self) -> None:
        # Later - in reportTableMarkup - and Word and Excel keep the dead column,
        # breaking the promise that the preview is what the file contains.
        block = reports_block()
        self.assertIn("function reportTable(headers, bodyRows)", block)
        self.assertIn("dropped:", block)

    def test_the_omission_is_stated_in_every_destination(self) -> None:
        block = reports_block()
        preview = block[block.index("function reportTableMarkup("):]
        self.assertIn("reportDroppedNote(table)", preview[:preview.index("\n}")])
        self.assertEqual(block.count("reportDroppedText(block.table)"), 2)
        self.assertIn("reportDroppedNote(block.table)", block)


if __name__ == "__main__":
    unittest.main()
