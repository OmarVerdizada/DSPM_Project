"""Round M: one standard for every page, and every figure lands where it says.

Seven things, and what each turned out to be:

1. Findings was the only panel with a padding override, so it sat 8px closer
   to the sidebar than the other ten.
2. History & audit and Risk logic were the only panels that were themselves
   cards, which put their page title inside the box.
3. The header cluster reserved 640px of every page's title row for controls
   that answer the dashboard's questions.
4. The admin tenant list printed a tenant's name and its id, which an upgraded
   database sets equal for every tenant it discovers.
5. Assessment coverage's three columns were buttons bound to a class name the
   markup has never carried.
6. Two of those three carried the same jump, which cleared a facet rather than
   setting one - there was no filter for "carries a finding" or "read and
   found nothing".
7. A Top risks row counted files and opened a queue of findings.
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import store  # noqa: E402

APP_JS = Path("frontend/app.js").read_text(encoding="utf-8")
INDEX = Path("frontend/index.html").read_text(encoding="utf-8")
SHELL_CSS = Path("frontend/styles/shell.css").read_text(encoding="utf-8")
PAGES_CSS = Path("frontend/styles/pages.css").read_text(encoding="utf-8")
STYLES_CSS = Path("frontend/styles.css").read_text(encoding="utf-8")


class OnePageStandardTests(unittest.TestCase):
    def test_every_panel_takes_the_same_gutter(self) -> None:
        """`.tab-panel { padding: 24px }` is the console's only page gutter -
        main is flushed to 0 - and exactly one panel overrode it."""
        self.assertIn(".tab-panel { padding: 24px; display: none; }", STYLES_CSS)
        self.assertNotIn("#tab-findings { padding-left: 16px", STYLES_CSS)
        for panel in re.findall(r"#tab-[a-z-]+\s*\{[^}]*padding[^}]*\}", STYLES_CSS):
            with self.subTest(rule=panel[:40]):
                self.assertNotIn("padding-left", panel)

    def test_no_panel_is_its_own_card(self) -> None:
        """A panel that carries .workspace is both the page and the box on it,
        which is what put History's title inside the card and gave Risk logic
        an outer surface around five sections that are already boxes."""
        for panel in ("tab-history", "tab-logic"):
            with self.subTest(panel=panel):
                opening = INDEX[INDEX.index(f'<section id="{panel}"'):]
                opening = opening[:opening.index(">")]
                self.assertNotIn("workspace", opening)
        # History's content still sits on inner surfaces - two of them now, one
        # per table, since the remaster gave the page its audit half back.
        history = INDEX[INDEX.index('<section id="tab-history"'):INDEX.index('<section id="tab-endpoint"')]
        self.assertEqual(history.count('class="panel history-panel"'), 2)
        self.assertIn("#history-workspace {", PAGES_CSS)
        # The overflow clip that depended on the class it lost.
        self.assertIn("#tab-logic.risk-logic {", STYLES_CSS)
        self.assertNotIn("#tab-logic.workspace.risk-logic", STYLES_CSS)

    def test_one_title_rhythm(self) -> None:
        """A 20px !important margin under every title row meant shell.css's own
        value never took, and the flex pages added their gap on top of it."""
        header = STYLES_CSS[STYLES_CSS.index(".section-header, .asset-header, .report-header,"):]
        header = header[:header.index("}")]
        self.assertNotIn("margin", header)
        self.assertIn("align-items: center;", STYLES_CSS[STYLES_CSS.index("#tab-reports .report-header,"):][:400])

    def test_a_box_inside_a_box_has_one_inset(self) -> None:
        # A white block with a 34px shadow, drawn on the card it already sits in.
        self.assertNotIn("border-color: #cfdeeb !important;", STYLES_CSS)
        # Risk logic's sections: a card, inside a card, inside a card.
        self.assertNotIn('''.logic-section {
  border: 1px solid var(--line);''', STYLES_CSS)
        # Administration and Settings padded their panels 20px inside a card
        # that pads nothing.
        security = STYLES_CSS[STYLES_CSS.index("#tab-security .security-grid > section {"):]
        self.assertNotIn("padding: 20px !important;", security[:security.index("}")])
        # Two stacked workspaces with nothing between them.
        self.assertIn("#tab-security > .workspace + .workspace", PAGES_CSS)


class HeaderClusterTests(unittest.TestCase):
    def test_the_active_page_is_readable_from_css(self) -> None:
        switch = APP_JS[APP_JS.index("function switchTab(tabName) {"):]
        self.assertIn("document.body.dataset.tab = resolvedTab;", switch[:2000])

    def test_the_cluster_belongs_to_the_dashboard(self) -> None:
        self.assertIn('body[data-tab]:not([data-tab="overview"]) .topbar { display: none; }', SHELL_CSS)
        # Guarded on PRESENCE too: a load straight onto the dashboard never
        # calls switchTab, so the attribute is absent there and a bare :not()
        # would hide the cluster on the one page it belongs to.
        self.assertNotIn(':not([data-tab="overview"]) .topbar { display: none; }\n\nbody:not', SHELL_CSS)
        # And the 640px each title row reserved for it comes back.
        self.assertIn("--shell-head-reserve", SHELL_CSS)
        reserve = SHELL_CSS[SHELL_CSS.index('body[data-tab]:not([data-tab="overview"]) :is('):]
        self.assertIn("padding-right: 0;", reserve[:260])


class TenantNameTests(unittest.TestCase):
    def test_a_name_is_printed_once(self) -> None:
        """create_tenant falls back to the id when the display name is blank,
        and the schema backfill sets the two equal for every tenant it finds on
        an upgraded database - so the list printed the same string twice on
        every row."""
        self.assertIn("function tenantLabel(tenant = {}) {", APP_JS)
        row = APP_JS[APP_JS.index("<strong>${escapeHtml(tenantLabel(tenant))}</strong>"):]
        row = row[:400]
        self.assertIn("toLowerCase()", row, "Default over default is the same string to a reader")
        self.assertIn('? ""', row)

    def test_the_backfill_that_makes_them_equal_is_real(self) -> None:
        source = Path("backend/store.py").read_text(encoding="utf-8")
        self.assertIn("INSERT OR IGNORE INTO tenants", source)
        self.assertIn('name = display_name.strip() or tenant_id', source.replace('"', "'").replace("'", "'"))

    def test_no_filler_line_under_a_username(self) -> None:
        self.assertNotIn('"No full name"', APP_JS)


class CoverageStateTests(unittest.TestCase):
    """The three states the Assessment coverage card counts are now three
    entries in the Finding type facet, so each column opens the list it
    counted."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls._orig = store.DB_PATH
        store.DB_PATH = Path(cls._tmp.name) / "coverage.sqlite"
        store.init_db()
        cls.tid = f"t-{uuid4().hex[:8]}"
        store.create_tenant(cls.tid, "COVER")

        def _file(name, findings, protected=False):
            return {
                "path": f"/share/{name}", "name": name, "extension": ".txt", "size": 10,
                "owner": "ops", "modified_at": "2026-06-01T00:00:00+00:00",
                "risk": {"level": "HIGH" if findings else "LOW", "score": 70 if findings else 10},
                "findings": [{"type": v, "framework": "GDPR"} for v in findings],
                "protected": protected,
            }

        store.save_scan_history(cls.tid, {"scan_id": "s1", "source": "local", "summary": {}, "files": [
            _file("a.txt", ["Email"]), _file("b.txt", ["Email"]), _file("c.txt", ["Credit card"]),
            _file("d.txt", []), _file("e.txt", []),
            _file("locked.txt", [], protected=True),
        ]})

    @classmethod
    def tearDownClass(cls) -> None:
        store.DB_PATH = cls._orig
        cls._tmp.cleanup()

    def total(self, **kwargs) -> int:
        return store.list_inventory(self.tid, limit=1, **kwargs)["total"]

    def test_the_three_states_partition_the_estate(self) -> None:
        classified = self.total(finding_type="Classified")
        clear = self.total(finding_type="Clear")
        locked = self.total(finding_type="Protected / locked")
        self.assertEqual((classified, clear, locked), (3, 2, 1))
        self.assertEqual(classified + clear + locked, self.total())

    def test_a_state_joins_the_facet_it_was_ticked_in(self) -> None:
        """They are entries in the Finding type facet, so they OR with the data
        classes beside them rather than narrowing to nothing."""
        self.assertEqual(self.total(finding_type="Credit card,Clear"), 3)
        self.assertEqual(self.total(finding_type="Classified,Clear"), 5)

    def test_both_facet_builders_offer_them(self) -> None:
        """One path is SQL aggregates, the other walks rows. An option missing
        from the live one is an option that does not exist in production."""
        rows = {str(item["value"]): int(item.get("file_count") or 0)
                for item in store.inventory_facets(self.tid).get("finding_types", [])}
        for value, expected in (("Classified", 3), ("Clear", 2), ("Protected / locked", 1)):
            with self.subTest(value=value):
                self.assertEqual(rows.get(value), expected)
        for builder in ('finding_counts["Classified"] = classified_count',
                        'finding_counts["Clear"] = clear_count'):
            with self.subTest(builder=builder):
                self.assertEqual(Path("backend/store.py").read_text(encoding="utf-8").count(builder), 2)

    def test_they_are_not_listed_as_data_classes(self) -> None:
        """"Classified" counts every file with a finding, so a list headed Top
        data classes would always start with it."""
        self.assertIn("const COVERAGE_FACET_VALUES = new Set([", APP_JS)
        self.assertIn("function isDataClass(value) {", APP_JS)
        # Three consumers now: the dashboard card, its View all modal, and the
        # Reports page's data-class sections. Every one of them reaches the
        # finding_types facet through the same predicate, which is the point.
        self.assertEqual(APP_JS.count("filter((item) => isDataClass(item.value))"), 3,
                         "a data-class list read the facet without the coverage filter")


class DashboardRoutingTests(unittest.TestCase):
    def test_the_coverage_columns_route(self) -> None:
        """The handler looked for `.coverage-item`; the markup emits
        `.col-item`. All three columns were focusable buttons that did
        nothing."""
        self.assertNotIn('closest(".coverage-item', APP_JS)
        self.assertNotIn("coverage-item", PAGES_CSS)
        self.assertIn('data-coverage-jump="${escapeHtml(jump)}"', APP_JS)
        self.assertIn('event.target.closest("[data-coverage-jump]")', APP_JS)
        columns = APP_JS[APP_JS.index('["classified", classified, "Classified"'):]
        columns = columns[:columns.index("];")]
        self.assertNotIn('"ALL"', columns, "two of three used to carry the same non-filter")

    def test_a_top_risk_opens_the_files_it_counted(self) -> None:
        """The row's number is a count of FILES, computed by asking the
        inventory. The row asks it again."""
        self.assertIn("function applyRiskCategoryToFindings(category) {", APP_JS)
        route = APP_JS[APP_JS.index("function applyRiskCategoryToFindings(category) {"):]
        route = route[:route.index(chr(10) + "}" + chr(10))]
        for key in ("risk", "finding_type", "framework"):
            with self.subTest(key=key):
                self.assertIn(f"query.{key}", route)
        # `protected` is the one part of a category's question no facet shows.
        self.assertIn("inventoryProtectedFacet", route)
        self.assertIn('params.set("protected", inventoryProtectedFacet)', APP_JS)
        handler = APP_JS[APP_JS.index('const topRisk = event.target.closest("[data-risk-jump-key]");'):]
        self.assertIn("if (applyRiskCategoryToFindings(category)) return;", handler[:900])

    def test_all_files_means_all_files(self) -> None:
        body = APP_JS[APP_JS.index("function applyInventoryRisk(level) {"):]
        body = body[:body.index(chr(10) + "}" + chr(10))]
        self.assertIn("FACET_GROUPS.findings.forEach((id) => setFacetSelection(id, []));", body)
        self.assertIn("inventoryProtectedFacet = null;", body)

    def test_a_band_with_no_filter_is_not_a_button(self) -> None:
        """The three age bands carried data-age-jump and no handler anywhere
        reads it - and there is no age parameter to read it into."""
        self.assertNotIn("data-age-jump", APP_JS)
        band = PAGES_CSS[PAGES_CSS.index(".gauge-band {"):]
        self.assertNotIn("cursor: pointer;", band[:band.index("}")])

    def test_a_location_row_shows_what_it_filtered(self) -> None:
        handler = APP_JS[APP_JS.index('const place = event.target.closest("[data-location-jump]");'):]
        handler = handler[:handler.index("return;") + 7]
        self.assertIn("inventoryFolderSelect.value = wanted;", handler)
        # It announced the full path and filtered on the last segment.
        self.assertIn('aria-label="${escapeHtml(entry.label)}, ${entry.total} files', APP_JS)


if __name__ == "__main__":
    unittest.main()
