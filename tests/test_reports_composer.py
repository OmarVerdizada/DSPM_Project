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
        self.assertIn("function reportCoverageLine(", block)
        self.assertIn("highest-scoring of them", block)
        # Depth caps every table, so the cover states the rows it prints rather
        # than the findings it could have reached.
        self.assertIn("prints ${printed.toLocaleString()} rows", block)

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

    def test_the_build_line_counts_the_rows_it_is_about_to_print(self) -> None:
        """It counted the findings in SCOPE, so at Standard depth - where every
        table is capped at 60 rows - it promised "5,000 of 6,831 findings" over
        a file that held 106."""
        block = reports_block()
        self.assertIn("function reportPrintedRows(", block)
        stats = block[block.index("function reportBuildStats()"):]
        stats = stats[:stats.index(chr(10) + "}" + chr(10))]
        self.assertIn("reportSectionBlocks()", stats)
        self.assertNotIn("REPORT_ROW_CEILING", stats)

    def test_the_preview_and_the_file_are_built_by_one_function(self) -> None:
        block = reports_block()
        for builder in ("buildReportDocumentHtml", "buildReportWorkbookHtml", "renderReportPreview"):
            body = block[block.index(f"function {builder}") if f"function {builder}" in block
                         else block.index(f"async function {builder}"):]
            self.assertIn("reportSectionBlocks()", body[:body.index("\n}\n")])


class ReportLayoutTests(unittest.TestCase):
    """A rail with a first move, and a document with no dead space in it."""

    def test_the_page_sizes_to_the_window(self) -> None:
        panel = SHEET[SHEET.index("#tab-reports.tab-panel.active {"):]
        panel = panel[:panel.index("\n}")]
        self.assertIn("height: 100dvh", panel)
        self.assertIn("overflow: hidden", panel)
        self.assertIn("@media (max-height: 620px)", SHEET)

    def test_the_rail_ends_where_its_content_ends(self) -> None:
        """Stretched to the column it left 300px of nothing under the button.

        With both drawers shut the rail needs about 550px of an 800px column,
        so it is a card that stops, and scrolls only if opening a drawer takes
        it past the window.
        """
        rail = SHEET[SHEET.index(".report-composer {"):]
        rail = rail[:rail.index("\n}")]
        self.assertIn("align-self: start", rail)
        self.assertIn("max-height: 100%", rail)
        self.assertIn("overflow-y: auto", rail)

    def test_the_two_quiet_groups_are_drawers_that_state_their_answer(self) -> None:
        """Six selects and nine checkboxes shown at once gave the rail no first
        move: every group looked equally like the place to start."""
        for element in ("report-scope-toggle", "report-sections-toggle",
                        "report-scope-summary", "report-sections-summary"):
            self.assertIn(f'id="{element}"', MARKUP)
        block = reports_block()
        self.assertIn("function renderComposerSummaries()", block)
        self.assertIn("function toggleComposerDrawer(", block)
        # Shut, they are one row each - and the row says what it is set to.
        self.assertIn("reportCarrierScopeLabel()", block)

    def test_a_shut_drawer_is_actually_shut(self) -> None:
        # `[hidden]` is a UA rule at specificity zero and both bodies carry a
        # class rule that sets `display`, so it has to be stated back.
        self.assertIn(".composer-fields[hidden]", SHEET)
        self.assertIn(".composer-drawer-body[hidden]", SHEET)

    def test_a_report_row_looks_like_something_you_press(self) -> None:
        # Four rows of plain text gave no sign they were choices, which is half
        # of "nothing to click on arrival".
        self.assertIn("report-type-mark", reports_block())
        self.assertIn('.report-type[aria-checked="true"] .report-type-mark', SHEET)

    def test_the_rail_says_each_thing_once(self) -> None:
        # The carrier used to print the report's name and its scope a finger's
        # width from the card that names it and the row that states it.
        block = reports_block()
        self.assertNotIn("renderReportCarrier", block)
        self.assertNotIn('id="report-carrier-title"', MARKUP)
        self.assertNotIn('id="report-carrier-scope"', MARKUP)
        # What is left is the one line nothing else says.
        self.assertIn('id="report-build-line"', MARKUP)

    def test_the_document_is_on_the_page_not_in_a_pane(self) -> None:
        document = SHEET[SHEET.index(".report-document {"):]
        document = document[:document.index("\n}")]
        self.assertNotIn("border:", document)
        self.assertNotIn("box-shadow", document)
        self.assertNotIn("max-width", document)

    def test_a_column_is_as_wide_as_what_it_holds(self) -> None:
        """`table-layout: fixed` divides the width equally, which gave an
        eight-character Severity column the same 259px as a 144-character
        sentence - the sentence wrapped to eight lines and the row stood 127px
        tall, a quarter of it blank."""
        block = reports_block()
        self.assertIn("REPORT_COLUMN_KINDS", block)
        self.assertIn("function reportColumnKind(", block)
        self.assertIn("<colgroup>", block)
        for kind in ("sev", "num", "name", "path"):
            self.assertIn(f".report-table col.col-{kind}", SHEET)

    def test_a_pair_of_facts_is_not_a_full_width_grid(self) -> None:
        # As a table this ran the page's whole width to print "9 / 100" beside
        # "Posture score" - 518px of column for seven characters.
        block = reports_block()
        self.assertIn("function reportTableIsFacts(", block)
        self.assertIn("function reportFactsMarkup(", block)
        self.assertIn(".report-facts {", SHEET)

    def test_the_document_wraps_rather_than_scrolling_sideways(self) -> None:
        table = SHEET[SHEET.index(".report-table {"):]
        table = table[:table.index("\n}")]
        self.assertIn("table-layout: fixed", table)
        self.assertIn("min-width: 0", table)

    def test_a_document_table_header_does_not_peel_off(self) -> None:
        header = SHEET[SHEET.index(".report-table th {"):]
        self.assertIn("position: static", header[:header.index("\n}")])

    def test_every_token_the_sheet_names_exists(self) -> None:
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
        self.assertIn("fixed || !reportSectionIsAvailable(", block)

    def test_the_composer_reads_in_the_order_it_is_answered(self) -> None:
        panel = MARKUP[MARKUP.index('id="report-composer"'):MARKUP.index('id="report-preview"')]
        order = [panel.index(marker) for marker in (
            'id="report-type-list"', 'id="report-scope-toggle"', 'id="report-depth"',
            'id="report-sections-toggle"', 'id="report-format"',
            'id="report-build-line"', 'id="report-generate"',
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
