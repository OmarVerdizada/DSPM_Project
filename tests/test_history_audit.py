"""History & audit: the page answers what happened, and whether it got worse.

The page shipped as scan history alone - absolute counts, a raw scan id in the
column headed "Scan", and four KPI tiles - while the audit half its own name
promises sat on the Administration page. These defend the remaster.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

SCRIPT = Path("frontend/app.js").read_text(encoding="utf-8")
MARKUP = Path("frontend/index.html").read_text(encoding="utf-8")
SHEET = Path("frontend/styles/history.css").read_text(encoding="utf-8")
LEGACY = Path("frontend/styles.css").read_text(encoding="utf-8")


def history_panel() -> str:
    start = MARKUP.index('<section id="tab-history"')
    return MARKUP[start:MARKUP.index('<section id="tab-endpoint"', start)]


class HistoryPageTests(unittest.TestCase):
    """Both halves, on the page named for both."""

    def test_the_audit_trail_is_on_the_page_named_after_it(self) -> None:
        panel = history_panel()
        self.assertIn('id="audit-section"', panel)
        self.assertIn('id="audit-body"', panel)
        # And is no longer duplicated on Administration.
        admin = MARKUP[MARKUP.index('<section id="tab-security"'):MARKUP.index('<section id="tab-admin"')]
        self.assertNotIn('id="audit-body"', admin)

    def test_the_trail_is_fetched_by_the_page_that_shows_it(self) -> None:
        loader = SCRIPT[SCRIPT.index("async function loadHistory()"):]
        self.assertIn("loadAudit()", loader[:loader.index("\n}\n")])

    def test_the_trail_is_hidden_from_anyone_who_cannot_read_it(self) -> None:
        # /api/audit requires admin, so a viewer is shown no table rather than
        # one that will never fill.
        self.assertIn("function syncAuditVisibility()", SCRIPT)
        self.assertIn("isAdminRole()", SCRIPT[SCRIPT.index("function syncAuditVisibility()"):][:220])
        self.assertIn('id="audit-section" hidden', history_panel())

    def test_the_four_kpi_tiles_are_gone(self) -> None:
        # Posture score, Tenant, Reports, Open critical. Tenant repeated the
        # sidebar and the rest are the dashboard's job.
        self.assertNotIn('id="executive-summary"', MARKUP)
        self.assertNotIn("renderExecutiveDashboard", SCRIPT)
        self.assertNotIn("history-card", MARKUP)


class HistoryChangeTests(unittest.TestCase):
    """The column that turns a list of counts into a history."""

    def test_change_is_measured_only_against_a_comparable_scan(self) -> None:
        # A 2-file endpoint check following a 539-file sweep would otherwise
        # read as "174 critical resolved" - an improvement that never happened.
        body = SCRIPT[SCRIPT.index("function historyComparableIndex("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("POSTURE_COMPARABLE_RATIO", body)

    def test_it_uses_the_same_rule_as_the_dashboard(self) -> None:
        # One constant, so the two surfaces can never disagree about whether
        # two scans are comparable.
        self.assertEqual(SCRIPT.count("const POSTURE_COMPARABLE_RATIO"), 1)

    def test_a_scan_with_no_comparable_predecessor_says_so(self) -> None:
        cell = SCRIPT[SCRIPT.index("function historyChangeCell("):]
        cell = cell[:cell.index("\n}\n")]
        self.assertIn("Baseline", cell)
        self.assertIn("No change", cell)
        # And the page explains the rule rather than leaving it to be guessed.
        self.assertIn("comparable ground", history_panel())

    def test_up_is_worse_and_down_is_better(self) -> None:
        self.assertIn('.history-change[data-move="up"]', SHEET)
        up = SHEET[SHEET.index('.history-change[data-move="up"]'):]
        self.assertIn("--sev-critical", up[:up.index("}")])
        down = SHEET[SHEET.index('.history-change[data-move="down"]'):]
        self.assertIn("--sev-low", down[:down.index("}")])


class HistoryTableTests(unittest.TestCase):
    """Sortable, and saying more than it did."""

    def test_both_tables_sort_on_the_product_s_own_contract(self) -> None:
        # The same data-sort / aria-sort pair the findings queue uses.
        self.assertIn("function sortableHeader(", SCRIPT)
        header = SCRIPT[SCRIPT.index("function sortableHeader("):]
        header = header[:header.index("\n}\n")]
        self.assertIn("data-sort=", header)
        self.assertIn("aria-sort=", header)
        self.assertIn('th[data-sort]', SHEET)

    def test_clicking_a_sorted_column_turns_it_around(self) -> None:
        toggle = SCRIPT[SCRIPT.index("function toggleSort("):]
        toggle = toggle[:toggle.index("\n}\n")]
        self.assertIn("sort.dir * -1", toggle)
        # A number column opens biggest-first; a name column A-to-Z.
        self.assertIn("column.text ? 1 : -1", toggle)

    def test_a_column_sorts_by_what_it_shows(self) -> None:
        # `name` is empty for an unnamed run, so sorting on it put every
        # unnamed row first while every cell read "Unnamed run".
        columns = SCRIPT[SCRIPT.index("const HISTORY_COLUMNS = ["):]
        columns = columns[:columns.index("];")]
        self.assertIn('"Unnamed run"', columns)

    def test_the_table_says_more_than_four_severities(self) -> None:
        columns = SCRIPT[SCRIPT.index("const HISTORY_COLUMNS = ["):]
        columns = columns[:columns.index("];")]
        for label in ("When", "Scan", "Source", "Files", "Critical", "High", "Medium", "Low", "Change"):
            self.assertIn(f'label: "{label}"', columns)

    def test_the_scan_column_names_a_run_rather_than_identifying_it(self) -> None:
        # It used to print scan_id: twenty digits of timestamp, in the column
        # headed "Scan".
        body = SCRIPT[SCRIPT.index("function renderHistoryTable("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("shortScanId(row.scanId)", body)
        self.assertNotIn("escapeHtml(row.scanId)}</td>", body)


class AuditReadabilityTests(unittest.TestCase):
    """An action string and a JSON blob become a sentence."""

    def test_every_recorded_action_has_a_plain_language_label(self) -> None:
        catalogue = SCRIPT[SCRIPT.index("const AUDIT_ACTIONS = {"):]
        catalogue = catalogue[:catalogue.index("\n};")]
        labelled = set(re.findall(r'"([a-z_.]+)":', catalogue))
        emitted = set(re.findall(r'audit\(\s*[^,]+,\s*[^,]+,\s*"([a-z_.]+)"', LEGACY_FREE_BACKEND))
        self.assertTrue(emitted, "no audit actions found in the backend")
        self.assertEqual(emitted - labelled, set(), "an action the product records has no label")

    def test_an_unmapped_action_still_reads_as_a_sentence(self) -> None:
        fallback = SCRIPT[SCRIPT.index("function auditActionLabel("):]
        fallback = fallback[:fallback.index("\n}\n")]
        self.assertIn('replace(/[._]/g, " ")', fallback)
        self.assertIn("toUpperCase()", fallback)

    def test_the_detail_is_labelled_rather_than_stringified(self) -> None:
        self.assertIn("function auditDetailPairs(", SCRIPT)
        body = SCRIPT[SCRIPT.index("function renderAuditTable("):]
        body = body[:body.index("\n}\n")]
        self.assertNotIn("JSON.stringify", body)
        self.assertIn("audit-pair", body)


class HistoryChromeTests(unittest.TestCase):
    """The previous design's chrome is deleted, not out-specified."""

    def test_the_page_has_a_contract_sheet_and_is_loaded(self) -> None:
        self.assertIn("/static/styles/history.css", MARKUP)

    def test_the_old_chrome_is_gone_from_the_legacy_sheet(self) -> None:
        """No rule in styles.css exists only to dress this page any more.

        86 did, including a "premium toolbar card" with sweep animations. The
        invariant is about rules DEDICATED to the page: a few of the old class
        names survive inside selector lists shared with other pages, and
        trimming a name out of a shared list edits lines that belong to
        somebody else - which is how a previous pass made the token gate blame
        this change for pre-existing violations.
        """
        hooks = (".history-card", ".history-grid", ".history-toolbar", ".history-controls",
                 ".toolbar-fx", "#executive-summary", "#history-body", ".audit-action",
                 ".audit-controls", "#audit-body")
        dedicated = []
        for match in re.finditer(r"(?m)^([^{}/@][^{}]*?)\{", LEGACY):
            parts = [part.strip() for part in match.group(1).split(",") if part.strip()]
            if parts and all(any(hook in part for hook in hooks) for part in parts):
                dedicated.append(match.group(1).strip()[:70])
        self.assertEqual(dedicated, [], f"still dressing this page: {dedicated}")

        # One rule stays on purpose, and it is not chrome: a panel whose SVGs
        # have no `.f-ico` rule draws every icon as a black fill, no stroke.
        self.assertIn("#tab-history .f-ico", LEGACY)
        # And nothing on the page wears the old card classes.
        for gone in ("history-card", "history-grid"):
            self.assertNotIn(gone, MARKUP)

    def test_the_per_column_colours_of_the_old_table_are_gone(self) -> None:
        # They painted columns 3-6 when those were Critical..Low. Column 3 is
        # Source now, and it was rendering red.
        self.assertNotIn("#history-body td:nth-child", LEGACY)

    def test_severity_uses_the_ramp_and_a_zero_does_not(self) -> None:
        self.assertIn('.history-count[data-severity="CRITICAL"]', SHEET)
        self.assertIn("[data-zero]", SHEET)

    def test_a_table_header_does_not_peel_off(self) -> None:
        header = SHEET[SHEET.index(".ledger-table th {"):]
        self.assertIn("position: static", header[:header.index("\n}")])

    def test_every_token_the_sheet_names_exists(self) -> None:
        tokens = Path("frontend/styles/tokens.css").read_text(encoding="utf-8")
        local = set(re.findall(r"^\s*(--[a-z0-9-]+):", SHEET, re.MULTILINE))
        for name in sorted(set(re.findall(r"var\((--[a-z0-9-]+)", SHEET)) - local):
            self.assertIn(f"{name}:", tokens, f"{name} is not defined in tokens.css")


LEGACY_FREE_BACKEND = "\n".join(
    path.read_text(encoding="utf-8")
    for path in sorted(Path("backend").rglob("*.py"))
)


if __name__ == "__main__":
    unittest.main()
