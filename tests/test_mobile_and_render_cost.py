"""The console on a phone, and what each change to the page costs.

Measured on the verify instance with a 3,083-file scan, Lighthouse mobile (4x CPU, slow 4G):
performance 35, layout shift 0.976. The shift was the whole page jumping sideways after
sentro-fx.js collapsed the nav a frame too late; the cost was a :has() anchored on <body>,
which made every DOM change anywhere restyle the whole document (4 ms per text change on a
laptop: each table row written, each frame of a count-up), and dashboard cards that
measured their own height once per card per render. Below 1180px the dashboard's cards
kept their desktop grid places, so the browser invented the missing columns and a phone
drew the posture card 30px wide. After: performance 60-63 (what is left is the 353 KB of
CSS and script on a simulated slow 4G link), layout shift 0, accessibility 100.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
APP_JS = (FRONTEND / "app.js").read_text(encoding="utf-8")
INDEX = (FRONTEND / "index.html").read_text(encoding="utf-8")
PAGES = (FRONTEND / "styles" / "pages.css").read_text(encoding="utf-8")
SHELL = (FRONTEND / "styles" / "shell.css").read_text(encoding="utf-8")
SHEETS = sorted((FRONTEND / "styles").glob("*.css")) + [FRONTEND / "styles.css", FRONTEND / "login.css"]


def media_block(css: str, query: str, occurrence: int = 0) -> str:
    """The body of the `occurrence`-th `@media <query> { ... }` block, braces balanced."""
    starts = [match.end() for match in re.finditer(r"@media\s*" + re.escape(query) + r"\s*\{", css)]
    start = starts[occurrence]
    depth = 1
    for index in range(start, len(css)):
        if css[index] == "{":
            depth += 1
        elif css[index] == "}":
            depth -= 1
            if depth == 0:
                return css[start:index]
    raise AssertionError(f"unbalanced @media {query}")


def function_body(source: str, name: str) -> str:
    body = source[source.index(f"function {name}("):]
    return body[:body.index("\n}\n") + 2]


class RenderCostTests(unittest.TestCase):
    def test_no_stylesheet_hangs_a_has_selector_off_the_document(self) -> None:
        """A :has() on <body> or <html> is re-checked for every insertion anywhere under it, and
        restyles the whole document when it is: 4 ms per text change measured, 0.8 ms
        without it. The drawer/dialog lift it served is a class set by app.js."""
        for sheet in SHEETS:
            css = re.sub(r"/\*.*?\*/", "", sheet.read_text(encoding="utf-8"), flags=re.S)
            self.assertIsNone(re.search(r"(^|[\s,>+~(])(body|html|:root)(\[[^\]]*\]|\.[\w-]+)*:has\(", css),
                              f"{sheet.name} anchors :has() on the document")
        sync = function_body(APP_JS, "syncRemediationOverlay")
        self.assertIn('document.body.classList.toggle("remediation-overlay-open", open)', sync)
        self.assertIn("remediationDrawerToggle?.checked", sync)
        self.assertIn("#tab-risk dialog[open]", sync)
        remediation_css = (FRONTEND / "styles" / "remediation.css").read_text(encoding="utf-8")
        self.assertIn("body.remediation-overlay-open .app-shell > main {", remediation_css)
        # Every way in and out keeps the class true: open/close helpers, the drawer's own
        # change event, a dialog closing itself, and the two places that set the toggle.
        for caller in ("remediationShowModal", "closeRemediationModal"):
            self.assertIn("syncRemediationOverlay();", function_body(APP_JS, caller))
        self.assertIn('dialog.addEventListener("close", syncRemediationOverlay)', APP_JS)
        self.assertIn("remediationDrawerToggle.checked = true;\n  syncRemediationOverlay();", APP_JS)
        self.assertIn("remediationDrawerToggle.checked = false;\n  syncRemediationOverlay();", APP_JS)
        listener = APP_JS[APP_JS.index('remediationDrawerToggle?.addEventListener("change"'):]
        self.assertIn("syncRemediationOverlay();", listener[:listener.index("});")])

    def test_dashboard_lists_measure_once_and_not_at_all_in_flow(self) -> None:
        capacity = function_body(APP_JS, "dashListCapacity")
        # In flow the card is as tall as its content - measuring it says nothing and forced
        # a style pass of the document per card per render.
        self.assertLess(capacity.index("dashFlowLayout?.matches"), capacity.index("document.querySelector"))
        self.assertIn('window.matchMedia?.("(max-width: 1180px), (max-height: 640px)")', APP_JS)
        self.assertIn("@media (max-width: 1180px), (max-height: 640px) {", PAGES)
        flow = re.search(r"const DASH_FLOW_ROWS = \{([^}]*)\}", APP_JS).group(1)
        for card in ("#data-classes-card", "#locations-card", "#posture-card"):
            self.assertIn(f'"{card}"', flow)
        # One-screen layout: the three heights are read together, before any card is
        # written, and forgotten when the task ends.
        heights = function_body(APP_JS, "dashBodyHeight")
        self.assertIn("for (const selector of Object.keys(DASH_FLOW_ROWS))", heights)
        self.assertIn("queueMicrotask(() => { dashBodyHeights = null; })", heights)
        self.assertIn("dashBodyHeight(body)", capacity)
        # Whether the board shows is a class, not a geometry read.
        refit = function_body(APP_JS, "refitDashboardLists")
        self.assertNotIn("clientHeight", refit)
        self.assertIn('panelIsVisible("tab-overview")', refit)


class NarrowLayoutTests(unittest.TestCase):
    def test_the_nav_is_collapsed_before_the_first_frame(self) -> None:
        """sentro-fx.js collapses the nav below 1025px, but it runs after app.js and the
        shell had painted with the nav stacked over the page: layout shift 0.976."""
        reveal = APP_JS[APP_JS.index("if (accessToken) {\n  document.body.classList.remove(\"auth-locked\");"):]
        reveal = reveal[:reveal.index("} else {")]
        self.assertIn('window.matchMedia?.("(max-width: 1024px)")?.matches) document.body.classList.add("sidebar-collapsed")',
                      reveal)
        self.assertIn('var mq = window.matchMedia("(max-width: 1024px)");', (FRONTEND / "sentro-fx.js").read_text(encoding="utf-8"))
        # Collapsed for the window, not as a preference: the toggles say so, nothing is stored.
        self.assertIn('} else if (document.body.classList.contains("sidebar-collapsed")) {', APP_JS)

    def test_the_open_nav_is_a_drawer_over_the_page(self) -> None:
        block = media_block(SHELL, "(max-width: 860px)", occurrence=-1)
        self.assertIn("body:not(.sidebar-collapsed) .app-shell > .sidebar {", block)
        self.assertIn("position: fixed !important;", block)
        self.assertIn("body:not(.sidebar-collapsed) .app-shell > main { grid-column: 2; }", block)
        self.assertIn("background: var(--scrim);", block)
        # It closes as other overlays do, and none of those closes is remembered.
        self.assertIn("function navDrawerOpen()", APP_JS)
        self.assertIn('setSidebarCollapsed(true, { remember: false })', APP_JS)
        self.assertIn('if (remember) safeSessionSet("dspm-sidebar-collapsed"', APP_JS)

    def test_every_dashboard_card_has_a_place_at_every_width(self) -> None:
        """Placing the cards by name means every width must name their places again:
        overriding only the column count left them at columns 3 and 4 of a two-column grid."""
        cards = ("posture", "locations", "classes", "frameworks", "coverage", "stale")
        two = media_block(PAGES, "(max-width: 1180px)", occurrence=-1)
        self.assertIn(".dash-board { grid-template-columns: repeat(2, minmax(0, 1fr)); }", two)
        for card in cards:
            area = re.search(rf"\.dash-card-{card}\s*\{{\s*grid-area:\s*(\d+)\s*/\s*(\d+);", two)
            self.assertIsNotNone(area, card)
            self.assertLessEqual(int(area.group(2)), 2, f"{card} is placed outside a two-column grid")
        one = media_block(PAGES, "(max-width: 900px)", occurrence=-1)
        self.assertIn(".dash-board { grid-template-columns: minmax(0, 1fr); }", one)
        self.assertIn(".dash-board > .dash-card { grid-area: auto; }", one)
        flow = media_block(PAGES, "(max-width: 1180px), (max-height: 640px)")
        self.assertIn("#tab-overview.tab-panel.active { height: auto; overflow: visible; }", flow)
        self.assertIn(".dash-board { grid-template-rows: none; }", flow)

    def test_card_grids_never_ask_for_more_than_the_screen(self) -> None:
        self.assertIn("minmax(min(270px, 100%), 1fr)", PAGES)
        self.assertIn("minmax(min(320px, 100%), 1fr)", PAGES)
        self.assertIn("#endpoint-scan-deck { grid-template-columns: minmax(0, 1fr); }", PAGES)
        self.assertIn("#report-preview { overflow-x: auto; }", media_block(PAGES, "(max-width: 860px)"))
        phone = PAGES[PAGES.index("Filters two to a row on a phone"):]
        self.assertIn("#remediation-workspace #remediation-filters { grid-template-columns: repeat(2, minmax(0, 1fr)); }", phone)

    def test_the_phone_header_is_two_rows(self) -> None:
        self.assertIn('<span class="tb-primary-label">New Scan</span>', INDEX)
        block = media_block(SHELL, "(max-width: 560px)")
        self.assertIn(".tb-primary-label {", block)
        self.assertIn("clip-path: inset(50%);", block)
        self.assertNotIn("display: none", block[block.index(".tb-primary-label {"):])


class AccessibleNamesTests(unittest.TestCase):
    def test_visible_text_is_part_of_each_name(self) -> None:
        ledger = INDEX[INDEX.index('<section class="ledger-row"'):INDEX.index("</section>", INDEX.index('<section class="ledger-row"'))]
        self.assertEqual(ledger.count('class="ledger-cell plain-btn"'), 6)
        self.assertNotIn("aria-label=", ledger.replace('aria-label="Findings by severity"', ""))
        self.assertEqual(ledger.count('<span class="sr-only">files, open in Findings</span>'), 6)
        coverage = function_body(APP_JS, "renderCoverageCard")
        self.assertIn('class="col-chart" role="group"', coverage)
        self.assertIn('aria-label="${count.toLocaleString()} ${escapeHtml(label)} files, open in Findings"', coverage)

    def test_headings_and_regions(self) -> None:
        for card in ("posture", "frameworks", "classes", "coverage", "stale", "locations"):
            self.assertIn(f'<h3 id="{card}-card-title">', INDEX)
            self.assertNotIn(f'<h4 id="{card}-card-title">', INDEX)
        self.assertIn('id="notice-host" class="notice-host" role="region" aria-live="polite"', INDEX)
        # The rail's names are hidden from sight only.
        rail = SHELL[SHELL.index("body.sidebar-collapsed .side-nav .tab > span {"):]
        rail = rail[:rail.index("}")]
        self.assertIn("display: block !important;", rail)
        self.assertIn("clip-path: inset(50%);", rail)

    def test_every_page_names_its_icon(self) -> None:
        self.assertTrue((FRONTEND / "favicon.svg").is_file())
        for page in ("index.html", "login.html", "profile.html", "register.html"):
            self.assertIn('<link rel="icon" type="image/svg+xml" href="/static/favicon.svg?v=1" />',
                          (FRONTEND / page).read_text(encoding="utf-8"), page)


if __name__ == "__main__":
    unittest.main()
