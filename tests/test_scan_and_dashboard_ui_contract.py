"""Frontend source-contract tests for the stabilization pass.

This frontend has no browser test runner, so these assert the fixed behavior at
the source-contract level. They guard:

* the scan poller tolerating transient poll errors instead of abandoning a
  live scan (the stuck-progress class of bug);
* the dashboard risk-summary delta having a human-readable tooltip/label so the
  negative values are self-explanatory.
* the operator-density information architecture requested for Dashboard,
  discovery, and Remediation.
"""
from __future__ import annotations

import math
import unittest
import re
from pathlib import Path



# ---- Colour maths for the ramp assertions -------------------------------
# Kept here rather than in the product: these measure what the stylesheet
# claims, and a helper the stylesheet also used could agree with itself.

def _rgb(value: str) -> tuple[int, int, int]:
    value = value.lstrip("#")
    return tuple(int(value[index:index + 2], 16) for index in (0, 2, 4))


def _linear(channel: float) -> float:
    channel /= 255
    return channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4


def _luminance(value: str) -> float:
    red, green, blue = (_linear(channel) for channel in _rgb(value))
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _contrast(first: str, second: str) -> float:
    high, low = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def _lab(value: str) -> tuple[float, float, float]:
    red, green, blue = (_linear(channel) for channel in _rgb(value))
    x = red * 0.4124564 + green * 0.3575761 + blue * 0.1804375
    y = red * 0.2126729 + green * 0.7151522 + blue * 0.0721750
    z = red * 0.0193339 + green * 0.1191920 + blue * 0.9503041

    def f(t: float) -> float:
        return t ** (1 / 3) if t > 216 / 24389 else (841 / 108) * t + 4 / 29

    fx, fy, fz = f(x / 0.95047), f(y), f(z / 1.08883)
    return 116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)


def _delta_e_2000(first: str, second: str) -> float:
    l1, a1, b1 = _lab(first)
    l2, a2, b2 = _lab(second)
    c1, c2 = math.hypot(a1, b1), math.hypot(a2, b2)
    c_bar = (c1 + c2) / 2
    g = 0.5 * (1 - math.sqrt(c_bar ** 7 / (c_bar ** 7 + 25 ** 7))) if c_bar else 0.0
    a1p, a2p = (1 + g) * a1, (1 + g) * a2
    c1p, c2p = math.hypot(a1p, b1), math.hypot(a2p, b2)
    h1p = math.degrees(math.atan2(b1, a1p)) % 360
    h2p = math.degrees(math.atan2(b2, a2p)) % 360
    delta_l, delta_c = l2 - l1, c2p - c1p
    delta_h = 0.0 if c1p * c2p == 0 else ((h2p - h1p + 180) % 360) - 180
    delta_hp = 2 * math.sqrt(c1p * c2p) * math.sin(math.radians(delta_h / 2))
    l_bar, c_bar_p = (l1 + l2) / 2, (c1p + c2p) / 2
    if c1p * c2p == 0:
        h_bar = h1p + h2p
    elif abs(h1p - h2p) > 180:
        h_bar = (h1p + h2p + 360) / 2
    else:
        h_bar = (h1p + h2p) / 2
    t_term = (1 - 0.17 * math.cos(math.radians(h_bar - 30))
              + 0.24 * math.cos(math.radians(2 * h_bar))
              + 0.32 * math.cos(math.radians(3 * h_bar + 6))
              - 0.20 * math.cos(math.radians(4 * h_bar - 63)))
    s_l = 1 + (0.015 * (l_bar - 50) ** 2) / math.sqrt(20 + (l_bar - 50) ** 2)
    s_c, s_h = 1 + 0.045 * c_bar_p, 1 + 0.015 * c_bar_p * t_term
    r_t = (-2 * math.sqrt(c_bar_p ** 7 / (c_bar_p ** 7 + 25 ** 7))
           * math.sin(math.radians(60 * math.exp(-(((h_bar - 275) / 25) ** 2)))))
    return math.sqrt((delta_l / s_l) ** 2 + (delta_c / s_c) ** 2 + (delta_hp / s_h) ** 2
                     + r_t * (delta_c / s_c) * (delta_hp / s_h))


def _severity_ramp(tokens: str, theme: str) -> dict[str, str]:
    """The four ordered ramp steps declared for one theme.

    Light values live in the bare :root block; dark values are everything
    after the theme's own block opens.
    """
    marker = tokens.index('data-theme="dark"')
    body = tokens[:marker] if theme == "light" else tokens[marker:]
    return {
        level: value
        for level, value in re.findall(r"--sev-(low|medium|high|critical):\s*(#[0-9a-fA-F]{6})", body)
    }

class ScanAndDashboardUiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app_js = Path("frontend/app.js").read_text(encoding="utf-8")
        cls.index_html = Path("frontend/index.html").read_text(encoding="utf-8")
        cls.styles_css = Path("frontend/styles.css").read_text(encoding="utf-8")
        cls.sentro_fx = Path("frontend/sentro-fx.js").read_text(encoding="utf-8")

    def test_pollscan_tolerates_transient_errors(self) -> None:
        # A single poll error must not abandon monitoring; the poller retries a
        # bounded number of times before surfacing a failure.
        self.assertIn("MAX_POLL_ERRORS", self.app_js)
        self.assertIn("consecutiveErrors", self.app_js)
        # The api() poll call is wrapped so a transient error is caught.
        poll_start = self.app_js.index("async function pollScan(")
        poll_body = self.app_js[poll_start:poll_start + 1400]
        self.assertIn("try {", poll_body)
        self.assertIn("catch (err)", poll_body)

    def test_scan_comparison_delta_has_explanatory_tooltip(self) -> None:
        self.assertIn("scan-comparison-hint", self.app_js)
        self.assertIn("Change vs previous scan", self.app_js)
        # Each delta value carries a title/aria-label explaining the sign.
        self.assertIn("deltaTitle", self.app_js)
        self.assertIn("fewer", self.app_js)
        self.assertIn("previous scan", self.app_js)

    def test_scan_progress_is_driven_by_backend_progress_and_message(self) -> None:
        # The async poll loop must render the backend's authoritative progress
        # and stage message (which now moves past the old collection ceiling),
        # not a fixed client-side value.
        poll_start = self.app_js.index("async function pollScan(")
        poll_body = self.app_js[poll_start:poll_start + 1600]
        self.assertIn("job.progress", poll_body)
        self.assertIn("job.message", poll_body)
        # Completion pins 100 and failure/cancel surfaces an error (no stale bar).
        self.assertIn('setScanProgress(true, 100', poll_body)
        self.assertIn('job.status === "failed"', poll_body)

    def test_dashboard_command_memo_and_posture_workflow_are_removed(self) -> None:
        self.assertNotIn('class="command-hero"', self.index_html)
        self.assertNotIn("Posture workflow", self.index_html)

    def test_discovery_workspace_context_is_last(self) -> None:
        file_panel = self.index_html[
            self.index_html.index('id="tab-file-servers"'):
            self.index_html.index('id="tab-overview"')
        ]
        endpoint_panel = self.index_html[
            self.index_html.index('id="tab-endpoint"'):
            self.index_html.index('id="tab-security"')
        ]
        self.assertGreater(
            file_panel.index('id="file-server-context"'),
            file_panel.index('class="scan-layout"'),
        )
        self.assertGreater(
            endpoint_panel.index('id="endpoint-context"'),
            endpoint_panel.index('id="endpoint-status"'),
        )

    def test_endpoint_acl_parity_and_coverage_summary_are_default_visible(self) -> None:
        self.assertIn('id="endpoint-read-acl" type="checkbox" checked', self.index_html)
        summary_start = self.app_js.index("function summarizeEndpointDiagnostics(")
        summary = self.app_js[summary_start:summary_start + 2200]
        for label in ("Visited:", "Matched:", "Filtered:", "Roots:"):
            self.assertIn(label, summary)

    def test_scan_wizard_review_board_and_setup_urls(self) -> None:
        # Review & launch is an interactive board: rows jump back to their step,
        # and the wizard runs under a temporary #-setup URL that the router
        # never resolves (direct entry lands on the deck).
        self.assertIn('data-wizard-goto=', self.index_html)
        self.assertIn('id="endpoint-review-rows"', self.index_html)
        self.assertIn("WIZARD_TAB_NAMES[kind]}-setup", self.app_js)
        self.assertIn('endsWith("-setup")', self.app_js)
        self.assertIn("renderEndpointReview", self.app_js)
        # The demo generator lives on the deck, not inside Configuration.
        self.assertIn("deck-demo-utility", self.index_html)
        fs_step2 = self.index_html[
            self.index_html.index('data-wizard-step="2"'):self.index_html.index('data-wizard-step="3"')
        ]
        self.assertIn('aria-label="Compliance mapping"', fs_step2)
        self.assertNotIn("demo-data-card", fs_step2)

    def test_navigation_dismisses_an_open_setup_wizard(self) -> None:
        """A wizard lives INSIDE its scan panel, so switching tabs must close
        it - otherwise the sidebar updates the URL to /scan#file-servers while
        the setup view stays on screen. The guard also runs during boot, when
        SCAN_WIZARD_KINDS is still in its temporal dead zone, so the access is
        wrapped in try/catch rather than a `typeof` check (which throws there)."""
        switch_start = self.app_js.index("function switchTab(")
        switch_body = self.app_js[switch_start:switch_start + 900]
        self.assertIn("closeAnyOpenScanWizard()", switch_body)
        guard_start = self.app_js.index("function closeAnyOpenScanWizard(")
        guard = self.app_js[guard_start:guard_start + 500]
        self.assertIn("try {", guard)
        self.assertIn("catch", guard)
        self.assertNotIn('typeof SCAN_WIZARD_KINDS', guard)

    def test_setup_view_fills_the_viewport_without_page_scroll(self) -> None:
        # The wizard is an app frame: header and footer pinned, only the step
        # body scrolls, so the setup page always fits the screen.
        self.assertIn("#fs-wizard .wizard-step:not(.hidden)", self.styles_css)
        self.assertIn("#tab-file-servers:has(#fs-wizard:not(.hidden))", self.styles_css)
        # Cards are capped to one chip row so both decks stay the same height.
        self.assertIn("spc-chip-more", self.app_js)
        self.assertIn("spc-chip-more", self.styles_css)

    def test_inventory_columns_sort_server_side_and_source_names_the_scan(self) -> None:
        # Column headers sort through the API (whole table) rather than
        # re-ordering the rows already in the browser.
        self.assertIn('data-inventory-sort="name"', self.index_html)
        self.assertIn('data-inventory-sort="risk_score"', self.index_html)
        self.assertIn('data-inventory-sort="scan_label"', self.index_html)
        self.assertIn("let inventorySortKey", self.app_js)
        query_start = self.app_js.index("function inventoryPageQuery(")
        query_body = self.app_js[query_start:query_start + 400]
        self.assertIn('params.set("sort", inventorySortKey)', query_body)
        self.assertIn('params.set("direction", inventorySortDirection)', query_body)
        self.assertNotIn('params.set("sort", "risk_score")', query_body)
        # Applying a sort refetches from the server instead of sorting locally.
        apply_start = self.app_js.index("async function applyInventorySort(")
        apply_body = self.app_js[apply_start:apply_start + 700]
        self.assertIn("resetInventoryPageWindow()", apply_body)
        self.assertIn("refreshInventoryPageWindow()", apply_body)
        self.assertIn("inventorySortDirection = inventorySortDirection === \"asc\" ? \"desc\" : \"asc\"", apply_body)
        # A tenant's named runs and configured profiles are grouped separately
        # from the two stable collector families, so raw protocols do not make
        # the control noisy or leak another tenant's saved scan names.
        self.assertIn("function completedInventoryScanNames(", self.app_js)
        names_start = self.app_js.index("function completedInventoryScanNames(")
        names_body = self.app_js[names_start:names_start + 1000]
        self.assertIn("latestHistoryItems", names_body)
        self.assertIn("item?.scan_label", names_body)
        self.assertNotIn("item?.scan_label || item?.source", names_body)
        self.assertIn("scanProfilesState", names_body)
        self.assertIn('label="Scans"', self.app_js)
        self.assertIn('label="Common scan sources"', self.app_js)
        self.assertIn("File Server Scans", self.app_js)
        self.assertIn("Endpoint Scans", self.app_js)
        self.assertIn("All scans", self.index_html)

    def test_dashboard_widgets_use_the_guarded_tenant_snapshot(self) -> None:
        self.assertIn("publishTenantDashboardAnalytics", self.app_js)
        self.assertIn("sentro:tenant-dashboard", self.app_js)
        self.assertIn("X-Tenant-ID", self.app_js)
        self.assertIn("sentro:tenant-dashboard", self.sentro_fx)
        self.assertIn("renderSnapshot", self.sentro_fx)
        self.assertNotIn('apiGet("/api/history")', self.sentro_fx)
        self.assertNotIn('apiGet("/api/audit")', self.sentro_fx)

    def test_essentials_and_admin_navigation_follow_requested_disclosure(self) -> None:
        essentials = self.app_js[self.app_js.index("function renderEssentialDisclosure"):self.app_js.index("function essentialObjectRows")]
        self.assertNotIn('${open ? "open" : ""}', essentials)
        self.assertIn('data-admin-only>Security ops', self.index_html)
        self.assertIn('data-admin-only>Tenants', self.index_html)
        self.assertIn("function permittedTabName", self.app_js)
        self.assertIn("applyRoleVisibility()", self.app_js)

    def test_remediation_and_findings_inventory_actions_have_distinct_destinations(self) -> None:
        findings_context = self.app_js[self.app_js.index("function renderScanContextPanels"):self.app_js.index("function renderFindingsWorkspace")]
        self.assertIn('data-tab-jump="inventory">Open inventory</button>', findings_context)
        # Traffic runs the other way now: the dashboard's top risks are the
        # entry point to Remediation, so Remediation does not need a link back
        # to a page the reader just came from.
        # A top risk carries the filter that answers the question its row
        # asked: opening the queue unfiltered from a card that names one kind
        # of exposure is the same as not clicking it.
        self.assertIn("function openRemediationFiltered(", self.app_js)
        self.assertIn("[data-risk-jump-key]", self.app_js)
        for expected in ("credentials_secrets", "pci_cardholder_data",
                         "pii,government_ids,biometric_data"):
            with self.subTest(category=expected):
                self.assertIn(f'category: "{expected}"', self.app_js)
        # A changed hash and an unreadable file are properties of a FILE, not
        # of a finding, so they go to the inventory rather than asking the
        # queue a question it cannot answer.
        self.assertIn('go: { to: "inventory", risk: "PROTECTED" }', self.app_js)
        # An applied filter the facets do not list stays visible in its own
        # control instead of being dropped by the next rebuild.
        self.assertIn("select.dataset.appliedLabel", self.app_js)

    def test_tenant_switch_invalidates_every_async_dashboard_surface(self) -> None:
        self.assertIn("let tenantContextVersion = 0", self.app_js)
        self.assertIn("function isCurrentTenantContext(", self.app_js)
        switch_start = self.app_js.index('tenantSwitcher.addEventListener("change"')
        switch_body = self.app_js[switch_start:switch_start + 3000]
        for reset in (
            "tenantContextVersion += 1", "latestDashboard = null", "latestHashComparison = null",
            "latestHistoryItems = []", "latestAuditEvents = []", "estateSummary = null",
            "inventoryFacets = null", "scanProfilesState = []", "latestComplianceKeywordLibraries = {}",
            "inventoryDetailRequests.clear()", "closeAssetDetailModal()", "renderHistory([])",
            "renderAudit([])", "loadAudit()",
        ):
            self.assertIn(reset, switch_body)
        history_start = self.app_js.index("async function loadHistory()")
        history_body = self.app_js[history_start:history_start + 1800]
        self.assertIn("captureTenantContext()", history_body)
        self.assertIn("isCurrentTenantContext(context, dashboard)", history_body)

    def test_inventory_empty_states_distinguish_first_run_from_no_matches(self) -> None:
        # First run gets one composed CTA; a completed scan with filters that
        # match nothing gets only the requested status message.
        self.assertIn("hasCompletedInventoryScan()", self.app_js)
        self.assertIn("Start your first scan", self.app_js)
        self.assertIn("No findings found", self.app_js)
        self.assertIn("inventory-empty-panel is-filtered", self.app_js)
        # The generic effects enhancer must not append the first-scan CTA to
        # loading, load-more, or filtered-empty rows.
        empty_ctas = self.sentro_fx[self.sentro_fx.index("var emptyCtas"):self.sentro_fx.index("emptyCtas.forEach")]
        self.assertNotIn("#results-body", empty_ctas)

    def test_setup_view_uses_the_full_window_with_one_scrollbar(self) -> None:
        # The wizard spans the content area (a centred max-width column left
        # half a wide screen empty, and the legacy .scan-layout
        # align-items:start shrink-wrapped the form)...
        self.assertIn("max-width: none !important", self.styles_css)
        self.assertIn("#fs-wizard > .scan-layout { align-items: stretch !important; }", self.styles_css)
        # ...and scrolls with the PAGE only. The app-frame's capped height plus
        # an inner scroller put a second scrollbar inside the card area, so the
        # cap and the inner overflow are both released for both wizards.
        v8 = self.styles_css[self.styles_css.index("Scan setup v8"):]
        self.assertIn("max-height: none !important", v8)
        self.assertIn("overflow: visible !important", v8)
        for wizard in ("#fs-wizard", "#endpoint-wizard"):
            self.assertIn(wizard, v8)

    def test_scan_wizard_speaks_the_console_type_system(self) -> None:
        """The setup pages must share the console's attributes, not their own
        scale: 15px/600 card headings, 12.5px labels, 13.5px/40px inputs, and
        a live step subtitle in the page head."""
        for wizard in ("fs-wizard", "endpoint-wizard"):
            lo = self.index_html.index(f'id="{wizard}"')
            hi = self.index_html.index("scan-wizard-footer", lo)
            region = self.index_html[lo:hi]
            self.assertEqual(region.count("wizard-step-eyebrow"), 3, wizard)
            self.assertEqual(region.count('class="wizard-current-step"'), 1, wizard)
        v6 = self.styles_css[self.styles_css.index("Scan setup v6"):]
        for probe in (
            "font-size: 15px !important",         # card headings = dashboard h4
            "font-size: 12.5px !important",       # labels = console forms
            "min-height: 40px !important",        # inputs/buttons = console controls
            ".wizard-current-step",               # live page-head step subtitle
        ):
            self.assertIn(probe, v6)
        v9 = self.styles_css[self.styles_css.index("Scan setup v9"):]
        self.assertIn("display: none !important", v9)
        self.assertIn("padding: 2px 0 10px !important", v9)

    def test_wizard_arrives_animated_and_never_scrolls_the_page(self) -> None:
        # Opening rises in (reduced-motion guarded); a step change resets its
        # own scroller instead of scrolling the page - scrollIntoView was the
        # "Configuration jumps down" bug and must not return.
        self.assertIn("@keyframes wizardArrive", self.styles_css)
        self.assertIn("prefers-reduced-motion", self.styles_css)
        step_start = self.app_js.index("function setWizardStep(")
        step_body = self.app_js[step_start:step_start + 1600]
        self.assertNotIn("scrollIntoView", step_body)
        self.assertIn("visiblePanel.scrollTop = 0", step_body)
        self.assertIn("preventScroll: true", self.app_js)
        # The head bar puts back control and title left, progress right,
        # all on one vertically centred line.
        self.assertIn("grid-template-columns: auto auto 1fr !important", self.styles_css)

    def test_every_page_owns_its_heading_and_no_page_repeats_the_scan_line(self) -> None:
        """The per-page scan strip is gone. It said the same sentence on eleven
        pages, which made it furniture rather than information; the one page
        whose rows come from a named scan (Findings) states it above the table
        it belongs to. What every page still owns is exactly one h2."""
        panels = re.findall(r'id="(tab-[a-z-]+)"', self.index_html)
        self.assertGreaterEqual(len(panels), 11)
        for panel in panels:
            with self.subTest(panel=panel):
                start = self.index_html.index(f'id="{panel}"')
                later = [self.index_html.index(f'id="{p}"') for p in panels
                         if self.index_html.index(f'id="{p}"') > start]
                segment = self.index_html[start:min(later) if later else len(self.index_html)]
                self.assertIn('<h2 class="page-title">', segment)
        self.assertNotIn("data-ledger", self.index_html)
        self.assertNotIn("function renderLedger(", self.app_js)
        self.assertIn('id="scan-meta"', self.index_html)

    def test_a_page_change_runs_one_transition_not_three(self) -> None:
        """F2. The console ran a JS animate, a CSS dspmFade and a 450ms
        staggered child rise at the same time, which is why moving between
        pages felt like the UI was assembling itself."""
        self.assertNotIn("animation: dspmFade", self.styles_css)
        # No rule animates panel children individually any more. Rules that
        # DISABLE animation are the reduced-motion guards and must survive.
        self.assertNotIn(".tab-panel.active > *:nth-child", self.styles_css)
        for match in re.finditer(r"[^{}]*\.tab-panel\.active > \*[^{}]*\{([^}]*)\}", self.styles_css):
            body = match.group(1)
            if "animation" in body:
                self.assertIn("animation: none", body,
                              "a rule still animates panel children individually")
        # The single transition reads its duration from the motion tokens, so
        # reduced-motion collapses it in one place.
        self.assertIn("--motion-base", self.app_js)

    def test_the_shell_and_dashboard_come_from_the_token_contract(self) -> None:
        """F1/F3. The 104px floating header is a flush 56px band, and the
        six-tile KPI wall is one ledger row."""
        shell = Path("frontend/styles/shell.css").read_text(encoding="utf-8")
        pages = Path("frontend/styles/pages.css").read_text(encoding="utf-8")
        self.assertIn("height: var(--shell-topbar-h)", shell)
        self.assertIn('class="ledger-row"', self.index_html)
        self.assertNotIn('<section class="metrics"', self.index_html)
        # Severity colour is spent in exactly two places per cell: the column
        # cap and the figure. The 2px tick it replaced is gone.
        self.assertIn("--band", pages)
        self.assertNotIn("--tick", pages)
        # The new sheets consume tokens rather than inventing values: no raw
        # hex outside comments, which is what the F0 gate enforces on change.
        for sheet in (shell, pages):
            body = re.sub(r"/\*.*?\*/", "", sheet, flags=re.S)
            self.assertNotRegex(body, r"#[0-9a-fA-F]{3,8}")

    def test_remediation_is_a_finding_level_workflow_center(self) -> None:
        """Remediation is an operational queue with in-place lifecycle detail,
        not a second analytics dashboard or a file-level card wall."""
        risk_panel = self.index_html[
            self.index_html.index('id="tab-risk"'):
            self.index_html.index('id="tab-settings"')
        ]
        self.assertIn('<h2 class="page-title">Remediation</h2>', risk_panel)
        self.assertIn('class="drawer drawer-end remediation-drawer-shell"', risk_panel)
        self.assertIn('id="remediation-assignment-modal"', risk_panel)
        self.assertIn('id="remediation-risk-modal"', risk_panel)
        self.assertIn('id="remediation-suppression-modal"', risk_panel)
        self.assertIn('id="remediation-false-positive-modal"', risk_panel)
        for facet in ("search", "scope", "status", "owner", "framework", "data", "asset", "sla"):
            self.assertIn(f'id="remediation-{facet}', risk_panel)

        # Two lists that answer "which of these should I look at" should not be
        # two different controls. The queue takes the data inventory's toolbar,
        # its labelled facet shells and its context strip - so a filter learned
        # on one page is the same control on the other.
        for shared in ('class="table-toolbar inventory-toolbar"',
                       'class="inventory-search-box"',
                       'class="inventory-command-bar"',
                       'class="inventory-facet-row"',
                       'class="field-shell facet-shell"',
                       'class="inventory-context-metrics"',
                       'class="secondary-btn mini-btn"'):
            with self.subTest(control=shared):
                self.assertIn(shared, risk_panel)
        # Severity is a select, like every other queue facet - the pill row was
        # the one control on this page that worked differently from its
        # neighbours, and it cost a whole band of chrome to say five words.
        self.assertIn('id="remediation-severity-filter"', risk_panel)
        self.assertIn('id="remediation-category-filter"', risk_panel)
        self.assertNotIn("data-remediation-severity=", risk_panel)

        # Sorting is a column header on the inventory, so it is a column header
        # here too - not a ninth dropdown doing the same job differently.
        self.assertNotIn('id="remediation-sort"', risk_panel)
        self.assertIn("function applyRemediationSort(", self.app_js)
        self.assertIn('data-remediation-sort="${key}"', self.app_js)
        self.assertIn("const REMEDIATION_SORT_LABELS", self.app_js)

        # .inventory-table is NOT borrowable: it freezes its first column and
        # pins it to 380px !important for a file-name column the queue has not
        # got, which files the Finding column behind Affected asset.
        self.assertNotIn('class="inventory-table remediation-table"', self.app_js)

        # The queue reads and mutates durable findings through the lifecycle API.
        self.assertIn("const REMEDIATION_PAGE_SIZE = 50", self.app_js)
        self.assertIn("remediationQueryParams()", self.app_js)
        self.assertIn("data?.summary", self.app_js)
        self.assertIn("data?.total", self.app_js)
        self.assertNotIn("/api/findings?limit=1000", self.app_js)
        for action in ("assign", "comment", "suppress", "false-positive", "risk-acceptance", "resolve", "reopen", "validate"):
            route = f'/${{encodedId}}/{action}' if action != "comment" else '/comment`'
            self.assertIn(route, self.app_js)

        # The old second dashboard and file-card queue stay gone.
        for gone in ("risk-analytics-side", "exposure-insights", "executive-hero",
                     "remediation-workspace-status", "risk-topology",
                     "risk-distribution", "scan-comparison", "top-risky-folders",
                     "remediation-board", "compact-risk-card"):
            with self.subTest(panel=gone):
                self.assertNotIn(gone, risk_panel)

        styles = Path("frontend/styles/remediation.css").read_text(encoding="utf-8")
        self.assertIn("#tab-risk.tab-panel.active.remediation-center", styles)
        self.assertIn(".remediation-mobile-card", styles)
        self.assertIn("@media (max-width: 640px)", styles)
        # An unterminated comment silently swallowed eighty rules once, and the
        # page still loaded - it just lost every style after the typo.
        for sheet in ("tokens", "shell", "pages", "remediation"):
            body = Path(f"frontend/styles/{sheet}.css").read_text(encoding="utf-8")
            with self.subTest(sheet=sheet):
                self.assertEqual(body.count("/*"), body.count("*/"), "unterminated comment")
                self.assertEqual(body.count("{"), body.count("}"), "unbalanced braces")

    def test_the_dashboard_answers_six_questions_and_no_card_is_mostly_empty(self) -> None:
        """Three equal full-height columns left four of the five panels
        two-thirds empty, and the page still could not say how much of the
        estate the numbers covered, or where the risk actually sat.

        Two narrow cards stack on the left, the middle pairs what kind of data
        with how much of the estate was read, and the one card that earns the
        full height - a ranked list of places to go - takes the right."""
        overview = self.index_html[
            self.index_html.index('id="tab-overview"'):
            self.index_html.index('id="tab-findings"')
        ]
        for card in ("dash-card-posture", "dash-card-frameworks", "dash-card-classes",
                     "dash-card-coverage", "dash-card-stale", "dash-card-locations"):
            with self.subTest(card=card):
                self.assertIn(card, overview)

        pages = Path("frontend/styles/pages.css").read_text(encoding="utf-8")
        # Two full-height columns bracket two stacked pairs, and the pairs are
        # matched by height so no card ends well above the one beside it.
        self.assertIn(".dash-card-posture    { grid-area: 1 / 1 / span 2 / 2; }", pages)
        self.assertIn(".dash-card-locations  { grid-area: 1 / 4 / span 2 / 5; }", pages)
        self.assertIn(".dash-card-classes    { grid-area: 1 / 2; }", pages)
        self.assertIn(".dash-card-frameworks { grid-area: 2 / 2; }", pages)
        self.assertIn(".dash-card-coverage   { grid-area: 1 / 3; }", pages)
        self.assertIn(".dash-card-stale      { grid-area: 2 / 3; }", pages)
        # The rows take the window and the lists fill the rows: content-sized
        # rows left a band of page under the whole board, and a fixed row count
        # left a band inside whichever card ran out of rows first. Both ends
        # are handled - the two long lists render as many rows as they were
        # given room for, and the rows share whatever is left over.
        self.assertIn("grid-template-rows: minmax(0, 1fr) minmax(0, 1fr);", pages)
        self.assertIn("function dashListCapacity(", self.app_js)
        self.assertIn("function refitDashboardLists(", self.app_js)
        # A window resize is the common trigger and always fires; the observer
        # additionally catches the board resizing without the window doing so.
        self.assertIn('window.addEventListener("resize", debounce(() => refitDashboardLists()', self.app_js)
        self.assertIn("new ResizeObserver(() => refitDashboardLists())", self.app_js)
        # The capacity divides by these heights, so the two have to agree.
        self.assertIn('dashListCapacity("#data-classes-card", 36', self.app_js)
        self.assertIn("min-height: 36px;", pages)
        self.assertIn('dashListCapacity("#locations-card", 29', self.app_js)
        self.assertIn("min-height: 29px;", pages)
        # No accent rule, and no shadow: six lifted cards is six shadows.
        self.assertNotIn("#tab-overview .dash-card::before", pages)
        self.assertNotIn("0 8px 24px color-mix(in srgb, var(--ink) 4%, transparent)", pages)
        # The data-class card shows what fits rather than a fixed count: five
        # rows on a 768px screen, nine on a 1030px one.
        self.assertIn("allStats.slice(0, shown)", self.app_js)

        # Every card is an estate-wide fact, not preview-file arithmetic.
        for renderer in ("function renderLocationsCard()", "function renderCoverageCard()",
                         "function renderStaleCard()"):
            self.assertIn(renderer, self.app_js)
        locations = self.app_js[self.app_js.index("function renderLocationsCard()"):]
        locations = locations[:locations.index("function renderCoverageCard()")]
        self.assertIn("estateFacets?.locations", locations)
        self.assertNotIn("latestFiles", locations)

        # And they are ways in, like every other figure on the page.
        self.assertIn("[data-location-jump]", self.app_js)
        # The card shows what fits; the count of what it did not show is the
        # way in to the rest.
        self.assertIn("data-open-all-classes", self.app_js)
        self.assertIn("function openAllDataClasses(", self.app_js)
        self.assertIn('id="data-classes-dialog"', self.index_html)
        # A row is one file, and the detail is what a row is for - so the whole
        # row opens it, not only the two buttons on its name.
        self.assertIn("function openInventoryRowDetail(", self.app_js)
        self.assertIn('#results-body tr[data-file-key]', self.app_js)
        # Extension, size, source and flags are one sentence about the file, so
        # they stay on one line and the overflow becomes a +N.
        self.assertIn("const FILE_META_VISIBLE = 3;", self.app_js)
        self.assertIn("file-meta-more", self.app_js)
        # Severity, framework and folder are selects, so the filter state is
        # readable without counting which pills happen to be lit.
        for select in ("inventory-risk-filter", "inventory-framework-select", "inventory-folder-filter"):
            self.assertIn(f'id="{select}"', self.index_html)
        self.assertNotIn('data-risk-filter="CRITICAL"', self.index_html)
        self.assertIn("function applyInventoryRisk(", self.app_js)
        self.assertIn('.coverage-item[data-risk-jump]', self.app_js)

        # A card cannot claim "no scan yet" when the truth is that this build
        # of the service does not send the field. That mis-report sent an
        # operator looking for a scan that had already run.
        for renderer in ("renderLocationsCard", "renderStaleCard"):
            body = self.app_js[self.app_js.index(f"function {renderer}("):]
            body = body[:body.index("\nfunction ", 1)]
            with self.subTest(renderer=renderer):
                self.assertIn("Unavailable", body)

        # Age is ordered, but it is not severity: reusing the ramp would put a
        # third meaning on those five colours.
        for band in ("active", "ageing", "abandoned"):
            self.assertIn(f'[data-age="{band}"]', pages)
        self.assertNotIn('[data-age="critical"]', pages)

    def test_six_cards_use_six_shapes(self) -> None:
        """Five of the six cards drew the same object - a name, a number and a
        stacked bar - so the board read as one widget repeated. Compliance
        frameworks keeps that shape; every other card now takes the form its
        own question needs."""
        pages = Path("frontend/styles/pages.css").read_text(encoding="utf-8")

        # A score and a spline, not a 56x30 thumbnail in a third column.
        self.assertIn("function smoothPath(", self.app_js)
        self.assertIn(".posture-wave-line", pages)
        self.assertNotIn("buildPostureRing", self.app_js)

        # One number per data class, on a shared axis.
        self.assertIn(".lolli-dot", pages)
        self.assertIn('class="lolli"', self.app_js)

        # Coverage is columns; staleness is a dial.
        self.assertIn(".col-chart", pages)
        self.assertIn('class="col-chart"', self.app_js)
        self.assertIn(".gauge-dial", pages)
        self.assertIn('class="gauge-dial"', self.app_js)

        # Only the framework card still stacks severity.
        self.assertIn('.stack i[data-sev="critical"]', pages)
        self.assertIn("${buildStack(entry)}", self.app_js)

        # And the places are a tree, with the indent driven by the server.
        self.assertIn(".tree-rows .place-row[data-depth=\"1\"]", pages)
        self.assertIn('data-depth="${entry.depth}"', self.app_js)
        self.assertIn("def _location_tree(", Path("backend/store.py").read_text(encoding="utf-8"))

    def test_a_data_class_opens_its_facet_rather_than_a_text_search(self) -> None:
        """Typing the class name into the inventory's search box matched it as
        free text against paths and file names too, so "Email" also returned
        every file with "email" in its path. The inventory has a Finding type
        facet holding exactly these values."""
        routing = self.app_js[self.app_js.index('const dataClass = event.target.closest("[data-inventory-search]")'):]
        routing = routing[:routing.index("const framework =")]
        self.assertIn("inventoryFindingFilter.value = wanted", routing)
        self.assertIn('inventoryFindingFilter.dispatchEvent(new Event("change"', routing)
        # The search box is cleared, or the two filters would compound.
        self.assertIn('filterInput.value = ""', routing)

    def test_widget_severity_is_a_step_back_from_the_band(self) -> None:
        """The band across the top is the headline and is meant to be loud. The
        same five values repeated inside every card's bar put six saturated
        blocks on one screen. The cards take the ramp mixed 80% toward the card
        they sit on - measured at 3.37-3.77:1 in light and 4.52-7.89:1 in dark,
        so still above the 3:1 floor for a graphic that carries meaning."""
        tokens = Path("frontend/styles/tokens.css").read_text(encoding="utf-8")
        pages = Path("frontend/styles/pages.css").read_text(encoding="utf-8")
        squeeze = lambda text: re.sub(r"\s+", " ", text)
        for level in ("critical", "high", "medium", "low"):
            with self.subTest(level=level):
                self.assertIn(f"--sev-{level}-soft: color-mix(in srgb, var(--sev-{level}) 80%, var(--surface))",
                              squeeze(tokens))
                self.assertIn(f'.stack i[data-sev="{level}"] {{ background: var(--sev-{level}-soft); }}',
                              squeeze(pages))
        # The band itself keeps the full-strength ramp.
        self.assertIn('.ledger-cell[data-sev="critical"]  { --band: var(--sev-critical);', pages)

    def test_the_scan_page_survives_daisyui_and_reports_compactly(self) -> None:
        """daisyUI's `.status` is an 8px dot; the console's is a full-width text
        box. Loading daisyui.css for the remediation drawer therefore collapsed
        every scan page's status line to 26px, and a finished scan's message
        wrapped one word per line. The message itself was eight diagnostics
        joined with ". "."""
        shell = Path("frontend/styles/shell.css").read_text(encoding="utf-8")
        self.assertIn("aspect-ratio: auto;", shell)
        self.assertIn(".status-fact", shell)
        # The completion line is a headline plus figures, not a paragraph.
        self.assertIn('setStatus(`Scan completed in ${formatElapsedTime(lastScanElapsedSeconds)}`, "ok", diagnostics)',
                      self.app_js)
        self.assertIn("function setStatus(message, tone = \"muted\", facts = [])", self.app_js)
        # And the workspace footer sits on the window's bottom edge.
        self.assertIn("#tab-file-servers.tab-panel.active,", shell)
        self.assertIn("min-height: 100dvh;", shell)

    def test_a_posture_delta_only_compares_scans_that_cover_the_same_ground(self) -> None:
        """A posture score is the mean risk of whatever that scan covered. The
        card compared the newest scan against the OLDEST one in the trend, so a
        539-file estate sweep followed by a 2-file spot check rendered as
        "+68, improving" when nothing had improved - the second scan simply
        looked somewhere smaller and cleaner. Wrong in the flattering
        direction, which is the worst way for a security console to be wrong."""
        self.assertIn("function comparablePosturePoints(", self.app_js)
        self.assertIn("POSTURE_COMPARABLE_RATIO", self.app_js)
        # The delta is a function of the comparable pair, never of points[0].
        card = self.app_js[self.app_js.index("function renderPostureCard("):]
        card = card[:card.index("\nfunction ", 1)]
        self.assertIn("const comparable = comparablePosturePoints(points)", card)
        self.assertNotIn("points[0].score", card)
        # With nothing comparable the card says the band, not a number.
        self.assertIn("delta = comparable ? comparable.latest.score - comparable.earlier.score : null", self.app_js)

    def test_the_queue_is_as_dense_as_the_inventory_it_borrows_from(self) -> None:
        """Measured at 1366x768: the queue put 624px of chrome above its first
        finding where the Findings inventory needs 279, because it borrowed the
        inventory's controls but not the layer that compacts them. Four rows
        were visible; six are now, and each row is 46px rather than 59."""
        styles = Path("frontend/styles/remediation.css").read_text(encoding="utf-8")
        # Nine facets in equal cells. Flowing them packed the line but left it
        # ragged - cells from 155px to 254px wide, and the reset button alone
        # at the end of the second row. A grid lines them up in columns at any
        # width, and only the number of rows changes.
        row = styles[styles.index("#remediation-workspace .inventory-facet-row {"):]
        row = row[:row.index("}")]
        self.assertIn("display: grid;", row)
        self.assertIn("repeat(auto-fit, minmax(", row)
        # The label goes above its control here, unlike the inventory's two:
        # beside it, nine facets leave about 70px for the value. It is 12px on
        # a 28px control, so the pair is 45px - not the 84px that label-above
        # cost when the control was 40px tall.
        block = styles[styles.index("#remediation-workspace .inventory-facet-row label {"):]
        block = block[:block.index("}")]
        self.assertIn("display: grid;", block)
        # The workload figures read on one line, as the inventory's do.
        self.assertIn("#remediation-workspace .inventory-context-metrics > div {", styles)
        self.assertIn("flex-direction: row !important;", styles)
        # Severity filters from a select in the facet row, like every other
        # queue filter. The pill band was the one control on this page that
        # worked differently from its neighbours, and it cost a whole row of
        # chrome to say five words.
        risk_panel = self.index_html[
            self.index_html.index('id="tab-risk"'):
            self.index_html.index('id="tab-settings"')
        ]
        facets = risk_panel[risk_panel.index('class="inventory-facet-row"'):]
        facets = facets[:facets.index("</div>\n\n")]
        self.assertIn('id="remediation-severity-filter"', facets)
        self.assertIn('id="remediation-category-filter"', facets)
        self.assertNotIn('id="remediation-severity-filters"', risk_panel)
        # Every facet names itself, and the two "run it again" buttons share
        # the command line with the search rather than one sitting alone above
        # 1150px of white and the other trailing a wrapped filter row.
        self.assertEqual(9, facets.count('class="facet-name"'))
        toolbar = risk_panel[risk_panel.index('class="inventory-export-actions"'):]
        toolbar = toolbar[:toolbar.index("</div>")]
        self.assertIn('id="remediation-reset-filters"', toolbar)
        self.assertIn('id="refresh-executive-btn"', toolbar)
        self.assertIn("flex-wrap: nowrap !important;", styles)
        # And a fixed-width cell never wraps, or every row in the queue grows.
        self.assertIn("text-overflow: ellipsis;", styles)

    def test_the_risk_cell_says_the_level_once_and_carries_the_override(self) -> None:
        """A four-hue gradient under every badge said nothing the badge had not
        said, and a whole column - 191px of a table that has to show a path -
        held a select almost no row uses."""
        self.assertNotIn("risk-mini-meter", self.app_js)
        self.assertNotIn("<th>Manual risk</th>", self.index_html)
        self.assertNotIn('colspan="7"', self.index_html[
            self.index_html.index('id="tab-findings"'):
            self.index_html.index('id="tab-risk"')
        ])
        # The override is a caret on the badge with the platform's own menu
        # behind it: a real menu, its keyboard and its screen reader, and no
        # open-and-close state of our own to keep.
        self.assertIn('class="risk-override"', self.app_js)
        self.assertIn("risk-override-select", self.app_js)
        pages = Path("frontend/styles/pages.css").read_text(encoding="utf-8")
        block = pages[pages.index(".risk-override select.risk-override-select {"):]
        block = block[:block.index("}")]
        self.assertIn("opacity: 0;", block)
        # A row whose level was set by hand says so where the level is.
        self.assertIn("is-manual", self.app_js)

    def test_one_modal_shape_and_one_scrollbar(self) -> None:
        """The all-classes panel was a <dialog> leaning on ::backdrop, which
        paints nothing on this engine - so the page behind stayed bright and
        the panel read as a white slab with a text Close button. It takes the
        asset detail's shape instead: a real backdrop element, an icon close,
        click-outside and Escape."""
        panel = self.index_html[
            self.index_html.index('id="data-classes-dialog"'):
        ]
        panel = panel[:panel.index("</div>\n\n")]
        self.assertIn("asset-detail-modal classes-modal hidden", panel)
        self.assertIn('class="asset-detail-backdrop" data-close-classes-modal', panel)
        self.assertIn("asset-modal-close", panel)
        self.assertNotIn("<dialog", panel)
        self.assertIn("function closeClassesModal(", self.app_js)
        self.assertIn('event.target.closest("[data-close-classes-modal]")', self.app_js)
        # The panel draws the dashboard's rows from the end of the document,
        # so the dashboard's glyph rule has to name it: an SVG with no rule
        # falls back to a black fill and no stroke, and every coin in the
        # panel rendered as a solid black blob.
        pages = Path("frontend/styles/pages.css").read_text(encoding="utf-8")
        glyphs = pages[pages.index("#tab-overview .f-ico"):]
        glyphs = glyphs[:glyphs.index("}")]
        self.assertIn(".classes-modal .f-ico", glyphs)
        self.assertIn("fill: none;", glyphs)
        self.assertIn("stroke: currentColor;", glyphs)

    def test_a_hovered_row_looks_the_same_on_both_tables(self) -> None:
        """The queue said which row the pointer was on with an indigo wash.
        The inventory did not - styles.css forces `tbody tr:hover td` to a
        near-white one or two percent off the surface, which paints over the
        row's own colour. On 40px queue rows that still reads as a band;
        across 108px inventory rows broken up by chips it disappears."""
        queue = Path("frontend/styles/remediation.css").read_text(encoding="utf-8")
        pages = Path("frontend/styles/pages.css").read_text(encoding="utf-8")
        for sheet, selector in (
            (queue, "#remediation-workflow .remediation-table tbody tr:hover td,"),
            (pages, "#results-body tr[data-file-key]:hover td {"),
        ):
            block = sheet[sheet.index(selector):]
            block = block[:block.index("}")]
            self.assertIn("var(--indigo-wash)", block)
        # Both need the panel id: the rule they beat is written
        # `:root:not([data-theme="dark"]) tbody tr:hover td`, and that :not()
        # counts, so a class and a pseudo-class alone lose to it.
        self.assertIn("#remediation-workflow .remediation-table tbody tr:hover,", queue)

        # One place decides what a scrollbar looks like. styles.css declared it
        # sixty-three times - 8px, 12px, 14px forced - several with a thumb
        # that never faded, which is why the two tables carried a permanent
        # grey stripe and every panel written since carried nothing at all.
        legacy = Path("frontend/styles.css").read_text(encoding="utf-8")
        self.assertNotIn("-webkit-scrollbar", legacy)
        self.assertNotIn("scrollbar-color", legacy)
        shell = Path("frontend/styles/shell.css").read_text(encoding="utf-8")
        self.assertIn("::-webkit-scrollbar-thumb {", shell)
        # The hover sits on the scrolling element: a thumb is a part of that
        # element, so a descendant combinator would match nothing.
        self.assertIn(":hover::-webkit-scrollbar-thumb {", shell)
        self.assertNotIn("*:hover > ::-webkit-scrollbar-thumb", shell)
        # The window keeps a bar for the views that are taller than it.
        html_rule = shell[shell.index("html {"):]
        self.assertIn("scrollbar-width: thin;", html_rule[:html_rule.index("}")])

    def test_findings_is_the_inventory_and_says_so_once(self) -> None:
        """Two panels sat above the table - a detection-signal summary and a
        priority queue - and both restated what the table's own first rows and
        the dashboard's severity band already showed. The page is the
        inventory, so it no longer needs a card that says "Data inventory"."""
        findings = self.index_html[
            self.index_html.index('id="tab-findings"'):
            self.index_html.index('id="tab-risk"')
        ]
        for gone in ("findings-signal-summary", "findings-priority-summary",
                     "executive-grid", "Detection signal mix",
                     "Priority finding queue"):
            with self.subTest(panel=gone):
                self.assertNotIn(gone, findings)
        self.assertNotIn("<h3>Data inventory</h3>", findings)
        self.assertIn('id="inventory-workspace"', findings)
        # The scan line stays: it is the one thing on the page that says which
        # scan these rows came from.
        self.assertIn('id="scan-meta"', findings)
        # The renderer for the two deleted panels went with them.
        self.assertNotIn("findingsSignalSummary", self.app_js)
        self.assertNotIn("findingsPrioritySummary", self.app_js)

    # ---- The register head is a band, not a card -------------------------

    def test_the_register_head_is_attached_on_both_sides(self) -> None:
        """The bar spanned the content width but still read as a floating box:
        a 12px radius, a 1px border, a gradient fill and a 44px drop shadow all
        survived F1 because each was set with !important. On the left it was
        genuinely detached - the shell grid reserved a 236px column for a 220px
        sidebar, leaving a 16px dead strip the bar started after."""
        shell = Path("frontend/styles/shell.css").read_text(encoding="utf-8")
        # The header no longer has a row of its own: its controls sit on each
        # page's title row, positioned in main's own coordinate space and
        # aligned to the same gutter the title uses, and every title row
        # reserves their footprint so the two never overlap.
        self.assertIn(".app-shell > main { position: relative; }", shell)
        topbar = shell[shell.index(".topbar {"):]
        topbar = topbar[:topbar.index("}")]
        self.assertIn("position: absolute;", topbar)
        self.assertIn("top: var(--space-5);", topbar)
        self.assertIn("right: var(--shell-gutter);", topbar)
        self.assertIn("padding-right: var(--shell-head-reserve);", shell)
        self.assertIn("grid-template-columns: var(--shell-sidebar-w) minmax(0, 1fr)", shell)

        # No legacy rule states the expanded sidebar column any more, so the
        # column and the sidebar element cannot disagree again.
        expanded = [m for m in re.findall(
            r"^[^\n]*\.app-shell[^\n{]*\{[^}]*grid-template-columns:\s*\d+px",
            self.styles_css, re.M) if "sidebar-collapsed" not in m]
        self.assertEqual(expanded, [], f"legacy shell widths are back: {expanded}")

        # The topbar is out of the card family: no shared border/gradient rule,
        # no radius, no gradient cap.
        self.assertNotRegex(
            self.styles_css,
            r"\.topbar,\s*\n\.workspace,\s*\n\.visual-panel,",
            "the topbar is back in the bordered-card selector list")
        self.assertNotIn("border-radius: var(--radius-lg) !important;\n  align-items", self.styles_css)
        # The 3px indigo/blue/violet cap painted across the top edge: a
        # register head is not a card with a coloured lid.
        cap = re.search(
            r"([^{}]*)\{[^}]*linear-gradient\(90deg, var\(--accent\), #2563eb, #7c3aed\)",
            self.styles_css)
        self.assertTrue(cap, "the gradient cap rule moved; re-point this check")
        self.assertNotIn(".topbar", cap.group(1))
        self.assertNotIn(".section-header", cap.group(1))

    def test_the_dashboard_fits_one_screen_and_every_figure_is_a_way_in(self) -> None:
        """The whole page is sized to the window: the four panels that used to
        make it 1.9 screens tall (posture trend, recent scans, posture
        intelligence, activity) are gone, and what replaced them is three cards
        that fill whatever height is left. Nothing on it is decoration - the
        severity band opens Findings at that level, a data class opens Findings
        searched for it, a framework opens Findings filtered to it, and a top
        risk opens Remediation."""
        pages = Path("frontend/styles/pages.css").read_text(encoding="utf-8")
        overview = self.index_html[self.index_html.index('id="tab-overview"'):
                                   self.index_html.index('id="tab-findings"')]

        # The page is the scroller of last resort, not the first. The header
        # shares the title row now, so the panel is the whole viewport.
        self.assertIn("#tab-overview.tab-panel.active", pages)
        self.assertIn("height: 100dvh;", pages)
        self.assertIn("overflow-y: auto", pages)

        # The four deleted panels leave no markup behind.
        for gone in ("fx-posture-chart", "fx-recent-scans", "fx-activity",
                     "overview-insights", "insights-grid"):
            with self.subTest(panel=gone):
                self.assertNotIn(gone, overview)

        # The three that replaced them, and their ways in.
        for card in ("posture-card", "data-classes-card", "frameworks-card"):
            self.assertIn(card, overview)
        self.assertIn("data-risk-jump", overview)
        for hook in ("data-inventory-search", "data-framework-jump", "data-risk-jump-key"):
            with self.subTest(hook=hook):
                self.assertIn(hook, self.app_js)
        # A severity cell lands on the matching Findings filter.
        self.assertIn("applyInventoryRisk(cell.dataset.riskJump)", self.app_js)

    def test_severity_reads_as_colour_not_as_a_footnote(self) -> None:
        """The band was right about compactness and wrong about emphasis: a
        10x2px tick beside the label is only visible to someone already reading
        that cell. The column is capped in its severity colour and the figure
        is set in it, which costs no height."""
        pages = Path("frontend/styles/pages.css").read_text(encoding="utf-8")
        self.assertIn(".ledger-cell::before", pages)
        for level in ("critical", "high", "medium", "low", "protected"):
            with self.subTest(level=level):
                self.assertRegex(
                    pages,
                    rf'\.ledger-cell\[data-sev="{level}"\]\s*\{{\s*--band: var\(--sev-{level}\)',
                    "the column cap does not take its severity colour")
                self.assertRegex(
                    pages,
                    rf'\.ledger-cell\[data-sev="{level}"\]\s+\.ledger-cell-value'
                    rf'\s*\{{ color: var\(--sev-{level}\); \}}',
                    "the figure is not set in its severity colour")
        # A total is not a severity, and it is not the accent either: an indigo
        # cap sat nine degrees from the protected violet in the cell next to
        # it, so the two rightmost columns read as one purple pair.
        self.assertRegex(pages, r'\.ledger-cell\[data-sev="total"\]\s*\{\s*--band: var\(--ink\)')

    def test_every_figure_in_the_console_is_set_in_one_face(self) -> None:
        """The severity row was the display face while every other indicator on
        the same screen - posture cards, signal mix, remediation - was the text
        face. A number in a second typeface reads as a different kind of
        number. The display face is rationed to the page title."""
        pages = Path("frontend/styles/pages.css").read_text(encoding="utf-8")
        shell = Path("frontend/styles/shell.css").read_text(encoding="utf-8")
        value_block = pages[pages.index(".ledger-cell-value {"):]
        value_block = value_block[:value_block.index("}")]
        self.assertIn("font-family: var(--font-text)", value_block)
        # The posture score is a figure too, and it sits one card away from the
        # band; it is set in the same face for the same reason.
        score_block = pages[pages.index(".posture-score {"):]
        score_block = score_block[:score_block.index("}")]
        self.assertIn("font-family: var(--font-text)", score_block)
        # And no figure on this page is set in the monospace face: it belongs
        # to paths and hashes, and a count in it reads as a different kind of
        # number from the count in the band beside it.
        self.assertNotIn("font-family: var(--font-data)", pages)
        # Exactly one component still uses the display face.
        users = re.findall(r"([.#][\w-]+)[^{}]*\{[^}]*--font-display", shell + pages)
        self.assertEqual(sorted(set(users)), [".page-title"], users)

    # ---- F4: copy and accessibility --------------------------------------

    def test_no_user_facing_string_describes_the_implementation(self) -> None:
        """F4. "Summary from the normalized inventory index", "a bounded page
        window", "Restart backend to enable import/preview API" - each named a
        part of the system where the reader needed to know what happened."""
        for phrase in ("normalized inventory index", "bounded page window",
                       "Restart backend", "Windowed inventory unavailable",
                       "Static fallback failed", "indexed files from saved scan",
                       '"API online"', '"API unavailable"', "backend-host WinRM",
                       "Backend host WinRM"):
            with self.subTest(phrase=phrase):
                self.assertNotIn(phrase, self.app_js)
        for phrase in ("API checking", "backend WinRM", "Backend host only",
                       "captured by the backend"):
            with self.subTest(phrase=phrase):
                self.assertNotIn(phrase, self.index_html)

    def test_first_use_acronyms_carry_their_expansion(self) -> None:
        """F4. The console says WinRM, SMB and MSSP before it says what they
        are; each is marked up once where it is first met."""
        for acronym, expansion in (("WinRM", "Windows Remote Management"),
                                   ("SMB", "Windows file share"),
                                   ("MSSP", "Managed security service provider")):
            with self.subTest(acronym=acronym):
                self.assertRegex(
                    self.index_html,
                    rf'<abbr title="{expansion}[^"]*">{acronym}</abbr>')

    def test_one_focus_ring_drawn_from_the_token(self) -> None:
        """F4. Six global focus systems were layered on each other, four with
        !important and two pointing at a --focus-ring variable that resolved to
        nothing, so a keyboard user on the sidebar saw no ring at all."""
        shell = Path("frontend/styles/shell.css").read_text(encoding="utf-8")
        self.assertIn("box-shadow: 0 0 0 var(--focus-ring-width) var(--focus-ring-color)", shell)
        self.assertIn(".tb-search:has(input:focus-visible)", shell)
        # The variable that resolved to nothing is no longer consumed.
        self.assertNotIn("box-shadow: var(--focus-ring) !important", self.styles_css)
        # Nothing removes the outline globally any more.
        self.assertNotRegex(
            self.styles_css,
            r"button:focus-visible, a:focus-visible, \[tabindex\]:focus-visible \{")
        # And nothing suppresses the search field's ring.
        self.assertNotIn(".tb-search:focus-within", self.styles_css)

    def test_form_errors_attach_to_the_field_that_caused_them(self) -> None:
        """F4. Every wizard message landed in one footer line - the one place a
        reader is not looking when a field is empty, and a line no screen
        reader associated with the field it was about."""
        self.assertIn("function showFieldError(", self.app_js)
        self.assertIn("function clearFieldErrors(", self.app_js)
        self.assertIn('field.setAttribute("aria-invalid", "true")', self.app_js)
        self.assertIn('field.setAttribute("aria-describedby", id)', self.app_js)
        # The validator names a field, not just a sentence.
        validator = self.app_js[self.app_js.index("function validateWizardStep("):]
        validator = validator[:validator.index("function wizardNext(")]
        self.assertIn("field:", validator)
        self.assertNotRegex(validator, r'return "[A-Z]',
                            "a wizard error is still a bare sentence")
        shell = Path("frontend/styles/shell.css").read_text(encoding="utf-8")
        self.assertIn(".field-error", shell)
        self.assertIn('[aria-invalid="true"]', shell)

    def test_text_contrast_comes_from_values_that_pass(self) -> None:
        """F4. The sidebar's secondary labels were #9ca3af on a white sidebar -
        2.54:1 on the console's primary navigation. The accent also had to be
        both a surface carrying white text and text on a near-black ground,
        which one value cannot do; the role is split."""
        tokens = Path("frontend/styles/tokens.css").read_text(encoding="utf-8")
        shell = Path("frontend/styles/shell.css").read_text(encoding="utf-8")
        self.assertIn("--indigo-ink:", tokens)
        # Two values: the same as --indigo on light paper, lighter on dark.
        dark = tokens[tokens.index(':root[data-theme="dark"]'):]
        self.assertRegex(dark, r"--indigo-ink:\s*#[0-9a-f]{6}")
        self.assertIn("--sidebar-muted: var(--ink-muted)", shell)
        # The active nav label is the accent used AS TEXT, so it takes the
        # text role rather than the surface one.
        self.assertIn("color: var(--indigo-ink) !important", self.styles_css)
        # And the severity ramp is monotonic: medium rendered blue in the
        # legacy badges while the dashboard band renders it amber.
        self.assertIn("--status-medium: var(--sev-medium)", shell)
        # The ramp is pinned by its REQUIREMENTS, not by four hex values. A
        # pinned hex was already wrong once: two adjacent steps drifted to
        # within 9.5 dE2000 in light and 5.1 in dark, and the stacked bar
        # rendered medium and high as one block, while every value still
        # "passed" its contrast check. Both properties are measured here.
        for theme, background in (("light", "#ffffff"), ("dark", "#111827")):
            ramp = _severity_ramp(tokens, theme)
            self.assertEqual(len(ramp), 4, f"{theme} declares four ramp steps")
            for level, value in ramp.items():
                with self.subTest(theme=theme, level=level):
                    self.assertGreaterEqual(
                        _contrast(value, background), 4.5,
                        f"--sev-{level} {value} is used as text on {background}")
            steps = [ramp[level] for level in ("low", "medium", "high", "critical")]
            for first, second in zip(steps, steps[1:]):
                with self.subTest(theme=theme, pair=(first, second)):
                    self.assertGreaterEqual(
                        _delta_e_2000(first, second), 12,
                        "adjacent ramp steps must be separable as adjacent fills")
        # Nothing renders below the 12px floor in the shell or the dashboard,
        # except chart furniture: an axis label or a band caption sits beside
        # a figure that already carries the value, and is never the only place
        # the number appears. Those are listed so the exception stays small.
        chart_furniture = {".col-label", ".gauge-band-label", ".gauge-read small", ".dash-sub",
                           "#inventory-context-metrics", ".inventory-context-metrics"}
        for sheet in (shell, Path("frontend/styles/pages.css").read_text(encoding="utf-8")):
            body = re.sub(r"/\*.*?\*/", "", sheet, flags=re.S)
            for rule in re.findall(r"([^{}]+)\{([^{}]*)\}", body):
                selector, block = rule[0].strip(), rule[1]
                if any(name in selector for name in chart_furniture):
                    continue
                for size in re.findall(r"font-size:\s*(\d+(?:\.\d+)?)px", block):
                    self.assertGreaterEqual(float(size), 12,
                                            f"{size}px is under the floor in {selector[:60]}")


    # ---- Boot resilience -------------------------------------------------

    def test_the_shell_unlocks_on_the_token_not_on_the_whole_file(self) -> None:
        """The blank-page-after-login bug. index.html ships
        `<body class="auth-locked">` and `.auth-locked .app-shell` is
        `display: none`, with no login screen in that document to fall back to
        - so while that class is on, the page is literally empty.

        Removing it used to be the job of setAuthState() called 8,500 lines
        into app.js, after every widget on every page had wired itself up. One
        listener bound to a panel that had been deleted threw a TypeError
        eleven lines earlier, and the whole console became a white screen (and
        the /login redirect never fired either). Whether to show the shell
        depends on one thing - is there a token - so it is decided where the
        token is read."""
        decl = self.app_js.index('let accessToken = safeSessionGet(')
        unlock = self.app_js.index('classList.remove("auth-locked")')
        wiring = self.app_js.index("setAuthState(Boolean(accessToken))")
        self.assertLess(unlock - decl, 1500,
                        "the shell unlock drifted away from the token read")
        self.assertLess(unlock, wiring,
                        "the shell is unlocked only after the widgets wire up")
        # And an unauthenticated visitor still leaves before the rest runs.
        self.assertIn('window.location.replace("/login")', self.app_js[decl:decl + 1500])

    def test_no_top_level_code_touches_an_element_that_no_longer_exists(self) -> None:
        """app.js is one long script: its top-level statements run in file
        order during boot, and the FIRST one that throws kills every statement
        after it. So a handle whose element was deleted from the markup is not
        a dead variable - it is a live fuse, and reading any property off it at
        top level takes the console down.

        Writes to removed panels go through setPanelHtml(), which null-guards
        on purpose. This checks the sites that cannot: a bare `handle.foo` in
        a statement at column 0."""
        handles = dict(re.findall(
            r'^const\s+([A-Za-z_$][\w$]*)\s*=\s*document\.querySelector\(\s*["\']([^"\']+)["\']\s*\)',
            self.app_js, re.M))
        self.assertGreater(len(handles), 50, "handle scan found almost nothing - the regex drifted")

        def in_markup(selector: str) -> bool:
            if selector.startswith("#"):
                return f'id="{selector[1:]}"' in self.index_html
            if selector.startswith("."):
                return selector[1:] in self.index_html
            return selector in self.index_html

        missing = {name for name, sel in handles.items() if not in_markup(sel)}
        fatal = []
        for line_no, line in enumerate(self.app_js.splitlines(), 1):
            if not line or line[0].isspace():
                continue                      # not a top-level statement
            for name in missing:
                if re.search(rf"\b{re.escape(name)}\s*\.", line):
                    fatal.append(f"app.js:{line_no}: {name} ({handles[name]}) -> {line.strip()[:70]}")
        self.assertEqual(fatal, [], "top-level property read on a handle whose element is gone:\n"
                                    + "\n".join(fatal))


    def test_two_scales_two_jobs_two_shapes(self) -> None:
        """The dashboard was painting 16 colours out of 4 hue families, because
        ONE scale - severity - was answering three different questions: how bad
        is it, what kind of data is this, and which framework owns it. Half the
        painted area came out red-orange and the three cards looked like each
        other.

        Severity keeps the ramp and keeps its own shapes (the band's column
        caps, the framework bars, and a word). "What kind of data" gets a
        categorical scale that appears in exactly one shape - the coin."""
        tokens = Path("frontend/styles/tokens.css").read_text(encoding="utf-8")
        pages = Path("frontend/styles/pages.css").read_text(encoding="utf-8")

        # Eight kinds, both themes, declared in the contract.
        for role in ("identity", "contact", "finance", "health",
                     "secret", "legal", "record", "code"):
            with self.subTest(role=role):
                self.assertEqual(tokens.count(f"--cat-{role}:"), 2,
                                 "a category must be declared in both themes")
                self.assertIn(f'.coin[data-cat="{role}"]', pages)

        # The coin is the ONLY thing the categorical scale paints. If it ever
        # spreads to a second component the two scales stop being separable.
        self.assertNotIn(".coin[data-sev", pages)
        # And the row's kind comes from the same table that picks its glyph.
        self.assertIn("function dataClassKind(", self.app_js)
        self.assertIn("const DATA_CLASS_KINDS", self.app_js)
        self.assertNotIn("DATA_CLASS_GLYPHS", self.app_js)

        # Severity is the mix, not a scalar. "Worst seen" was CRITICAL for
        # every one of the top eight classes in a real estate, and so was the
        # dominant level - a column that prints the same word eight times is
        # not a readout. The stacked bar is the only part that varies, and it
        # is the same component the framework rows use.
        self.assertNotIn(".class-row-sev", pages)
        self.assertNotIn("buildCells", self.app_js)
        self.assertIn(".lolli-dot", pages)
        self.assertIn('class="lolli"', self.app_js)

        # The ring is gone entirely - the score is the figure now, and the
        # history is a wave rather than a second small circle.
        self.assertNotIn(".posture-ring-arc", pages)
        self.assertNotIn(".ring-seg", pages)
        self.assertIn(".posture-score", pages)

        # Bar length carries the total, so similar severity mixes stop
        # rendering as the same gradient over and over.
        self.assertIn("width: var(--fw-share, 100%)", pages)
        self.assertEqual(self.app_js.count("--fw-share:"), 2,
                         "frameworks and locations carry a length; classes carry a dot")

        # The bar climbs: least severe first, so colour increases with risk.
        self.assertIn('const SEVERITY_CLIMB = ["low", "medium", "high", "critical"]', self.app_js)


if __name__ == "__main__":
    unittest.main()
