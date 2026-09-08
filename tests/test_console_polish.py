"""Round L: the things that were still wrong after the facets landed.

Nine of them, and what each one turned out to be:

1. Top risks left a hand's width of dead space, because it was counting a
   200-row window instead of the estate.
2. The facet menu outlived the page it was opened on.
3. Clear filters fell to a line of its own under Search.
4. Every facet menu carried a Clear button for a list of checkboxes.
5. The queue's table sat 58px outside the box that was meant to hold it.
6. The queue's spacing ran 24 / 40 / 28 where Findings runs 12 / 12 / 6.
7. The scrollbar answered to the list, not to the widget around it.
8. Sorting Findings printed its result on the File Server scan page.
9. Clicking a queue row left the queue for a file listing.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

APP_JS = Path("frontend/app.js").read_text(encoding="utf-8")
INDEX = Path("frontend/index.html").read_text(encoding="utf-8")
SHELL_CSS = Path("frontend/styles/shell.css").read_text(encoding="utf-8")
REMEDIATION_CSS = Path("frontend/styles/remediation.css").read_text(encoding="utf-8")
STYLES_CSS = Path("frontend/styles.css").read_text(encoding="utf-8")


def body_of(source: str, opening: str) -> str:
    block = source[source.index(opening):]
    return block[:block.index(chr(10) + "}" + chr(10))]


def code_of(source: str, opening: str) -> str:
    """The body with its comment lines removed, so an assertion about what the
    code does is not answered by a comment about what it used to do."""
    return chr(10).join(
        line for line in body_of(source, opening).splitlines()
        if not line.lstrip().startswith("//")
    )


def category_entry(block: str, key: str) -> str:
    entry = block[block.index(f'key: "{key}"'):]
    nxt = entry.find('key: "', 6)
    return entry if nxt < 0 else entry[:nxt]


class TopRisksCountTheEstateTests(unittest.TestCase):
    """`latestFiles` is a 200-row window sorted by risk score. Counting there
    read "Locked or unreadable" as zero on an estate that has locked files,
    could never surface "Health records", and capped the four rows that did
    appear at whatever the window happened to hold - four rows in a card with
    room for seven."""

    def test_every_category_says_how_the_estate_answers_it(self) -> None:
        block = APP_JS[APP_JS.index("const RISK_CATEGORIES = ["):]
        block = block[:block.index(chr(10) + "];")]
        for key in ("credentials", "unprotected", "payment", "health", "regulated", "locked"):
            with self.subTest(category=key):
                self.assertIn("estate:", category_entry(block, key))
        # "Changed since last scan" is the exception: it needs the hash
        # comparison between two saved runs, which is a different read.
        self.assertNotIn("estate:", category_entry(block, "changed"))

    def test_the_counts_are_asked_for_once_and_cached(self) -> None:
        gate = body_of(APP_JS, "async function refreshRiskCategoryCounts()")
        self.assertIn("if (key && key === riskCategoryCountsKey) return riskCategoryCounts;", gate)
        self.assertIn("if (riskCategoryCountsInFlight) return riskCategoryCountsInFlight;", gate)
        # Together, not one after another.
        self.assertIn("await Promise.all(RISK_CATEGORIES.map(", gate)
        # And the card repaints when they land.
        self.assertIn("renderPostureCard(", gate)

    def test_both_paths_that_set_the_facets_ask_for_them(self) -> None:
        """The boot path assigns estateFacets directly rather than going
        through refreshEstateSummary(), so asking in only one of them left the
        card on the window counts for the whole session."""
        self.assertEqual(APP_JS.count("refreshRiskCategoryCounts().catch(() => {});"), 2)

    def test_the_card_prefers_the_estate_number(self) -> None:
        rows = body_of(APP_JS, "function riskCategories(limit = 6)")
        self.assertIn("riskCategoryCounts?.[item.key] ?? counts.get(item.key)", rows)

    def test_a_class_category_asks_for_all_of_its_classes_at_once(self) -> None:
        """Which is what a multi-value finding_type filter is for."""
        query = body_of(APP_JS, "function classQuery(classes, predicate)")
        self.assertIn('{ finding_type: wanted.join(",") }', query)


class FacetMenuTests(unittest.TestCase):
    def test_the_menu_does_not_outlive_its_page(self) -> None:
        """It is positioned against a control on the page being left, and it
        lives on the body so no card can clip it - which also means nothing
        hides it when that page does."""
        switch = APP_JS[APP_JS.index("function switchTab(tabName) {"):]
        self.assertIn("closeFacetMenu();", switch[:switch.index("const destination")])

    def test_no_clear_button_inside_a_list_of_checkboxes(self) -> None:
        self.assertNotIn("facet-menu-clear", APP_JS)
        self.assertNotIn(".facet-menu-clear", SHELL_CSS)
        # What is worth saying is how many are ticked.
        self.assertIn("facet-menu-chosen", APP_JS)
        self.assertIn(".facet-menu-chosen", SHELL_CSS)
        # And the page-level reset still clears every facet at once.
        self.assertIn('id="clear-inventory-filters"', INDEX)

    def test_search_and_clear_are_one_pair(self) -> None:
        actions = INDEX[INDEX.index('<div class="facet-actions">'):]
        actions = actions[:actions.index("</div>")]
        self.assertIn('id="inventory-apply-filters"', actions)
        self.assertIn('id="clear-inventory-filters"', actions)
        self.assertIn(".facet-actions {", SHELL_CSS)
        self.assertIn("#inventory-workspace .inventory-facet-row > .facet-actions { margin-left: auto; }", SHELL_CSS)


class FindingsFacetRowTests(unittest.TestCase):
    """Label beside control cost each facet its label's width as well as its
    own: five facets and two buttons came to 1,571px in a 1,314px row, so
    Folder / path and both buttons dropped to a second, otherwise empty line."""

    def test_the_label_sits_above_its_control(self) -> None:
        rule = SHELL_CSS[SHELL_CSS.index(":root:root:root:root #inventory-workspace .inventory-facet-row > label"):]
        rule = rule[:rule.index("}")]
        self.assertIn("display: grid;", rule)
        self.assertIn("max-width: 184px;", rule)

    def test_the_grid_pins_that_forced_two_columns_are_gone(self) -> None:
        """Deleted rather than out-specified: a fifth opinion about this row
        would not have settled the argument."""
        squeezed = re.sub(r"\s+", " ", STYLES_CSS)
        self.assertNotIn("#inventory-workspace .inventory-facet-row > label { display: inline-flex !important; flex-flow: row nowrap !important;", squeezed)
        self.assertNotIn(":root:root #inventory-workspace .inventory-facet-row > label { display: grid !important; grid-template-columns: auto minmax(0, 1fr) !important;", squeezed)
        # And the select is capped again, or it sizes to its longest option -
        # "Org chart, employee directory, or reporting hierarchy" made Finding
        # type 411px wide on its own.
        self.assertNotIn("max-width: none !important; } :root:root #inventory-workspace .inventory-facet-row > .inventory-scan-facet", squeezed)


class RemediationLayoutTests(unittest.TestCase):
    def test_the_table_is_not_a_second_box(self) -> None:
        """Four blocks written for a card list this page has not had since the
        queue became a table, each pinned with !important and each disagreeing
        with the last: display:block against the flex column remediation.css
        declares, a 430px cap, and a second border, background, radius and
        padding drawn inside the workspace's own."""
        squeezed = re.sub(r"\s+", " ", STYLES_CSS)
        self.assertNotIn("#tab-risk .remediation-workflow { display: block !important;", squeezed)
        self.assertNotIn("#tab-risk .remediation-workflow { min-height: 0 !important; max-height: 430px !important;", squeezed)
        self.assertNotIn(":root:root #tab-risk #remediation-workflow { scrollbar-gutter: auto !important;", squeezed)
        # remediation.css owns the panel now, and it fills the workspace.
        self.assertIn("#remediation-workspace > .remediation-workflow {", REMEDIATION_CSS)
        self.assertIn("flex: 1 1 auto;", REMEDIATION_CSS)

    def test_the_gap_is_the_only_spacing(self) -> None:
        self.assertIn("#remediation-workspace > .table-toolbar { margin-bottom: 0; }", REMEDIATION_CSS)
        self.assertIn("#remediation-workspace > .inventory-command-bar {", REMEDIATION_CSS)

    def test_the_context_strip_belongs_to_the_table(self) -> None:
        """Five figures about the queue, in a transparent line closer to the
        filters than to the rows they describe, packed into the left three
        quarters of a 1,330px row."""
        rule = REMEDIATION_CSS[REMEDIATION_CSS.rindex("#remediation-workspace .inventory-context-metrics {"):]
        rule = rule[:rule.index("}")]
        self.assertIn("justify-content: space-between;", rule)
        self.assertIn("background: var(--surface);", rule)


class ScrollbarTests(unittest.TestCase):
    def test_the_widget_reveals_the_bar_inside_it(self) -> None:
        """`:hover` on a scrolling element means the pointer is inside THAT
        element - over the list, not over the card's header or its padding."""
        self.assertIn(".dash-card, .workspace, .modal-box, .sheet, .remediation-drawer-panel,", SHELL_CSS)
        block = SHELL_CSS[SHELL_CSS.index("The widget reveals its own bar"):]
        self.assertIn("::-webkit-scrollbar-thumb", block[:1800])
        self.assertIn("scrollbar-color: color-mix(in srgb, var(--ink) 34%, transparent) transparent;", block[:1800])

    def test_no_rule_sets_out_to_keep_a_scrollbar_visible(self) -> None:
        self.assertNotIn("make key risk-dashboard scrollbars visible on purpose", STYLES_CSS)
        self.assertNotIn("--risk-scrollbar-thumb", STYLES_CSS)

    def test_the_gutter_is_reserved_on_the_side_the_bar_is_on(self) -> None:
        """`stable both-edges` reserved the bar's width on the side it appears
        AND on the side it never does - a second empty channel down the left
        of every table and chart."""
        live = [line for line in STYLES_CSS.splitlines() if "stable both-edges" in line]
        # One survivor, on a panel this page has not rendered for two refits.
        self.assertLessEqual(len(live), 1, live)


class SortAnnouncementTests(unittest.TestCase):
    def test_the_sort_result_lands_on_the_page_it_is_about(self) -> None:
        """setStatus() writes to #connection-status, which is the File Server
        scan page's result box - so sorting the inventory printed "Sorted every
        file by risk score, lowest first." over the last scan's outcome, on a
        different page."""
        apply_body = code_of(APP_JS, "async function applyInventorySort(key)")
        self.assertNotIn("setStatus(", apply_body)
        self.assertIn("announceInventorySort(", apply_body)
        self.assertIn('id="inventory-sort-status"', INDEX)
        region = INDEX[INDEX.index('id="inventory-sort-status"'):]
        self.assertIn('role="status"', region[:160])
        self.assertIn("visually-hidden", INDEX[INDEX.index('id="inventory-sort-status"') - 60:])

    def test_a_name_sorts_a_to_z_not_lowest_first(self) -> None:
        apply_body = body_of(APP_JS, "async function applyInventorySort(key)")
        self.assertIn('"A to Z"', apply_body)
        self.assertIn('"highest first"', apply_body)


class QueueRowOpensItsFindingTests(unittest.TestCase):
    """A queue row is a unit of WORK, not a file: it is where a finding is
    assigned, commented on, validated and closed."""

    def test_the_row_no_longer_leaves_the_queue(self) -> None:
        self.assertNotIn("openFileInInventory(queueRow.dataset.remediationFile)", APP_JS)
        self.assertIn('const row = event.target.closest?.("[data-remediation-finding]");', APP_JS)
        handler = APP_JS[APP_JS.index('const row = event.target.closest?.("[data-remediation-finding]");'):]
        self.assertIn("openRemediationFinding(row.dataset.remediationFinding)", handler[:400])

    def test_the_file_is_still_one_click_away(self) -> None:
        menu = body_of(APP_JS, "function remediationActionMenu(finding = {})")
        self.assertIn("data-remediation-file-open", menu)
        self.assertIn("Open file in Findings", menu)
        self.assertIn('event.target.closest?.("[data-remediation-file-open]")', APP_JS)


if __name__ == "__main__":
    unittest.main()
