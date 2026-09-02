"""Frontend source-contract tests for the stabilization pass.

This frontend has no browser test runner, so these assert the fixed behavior at
the source-contract level. They guard:

* the scan poller tolerating transient poll errors instead of abandoning a
  live scan (the stuck-progress class of bug);
* the dashboard risk-summary delta having a human-readable tooltip/label so the
  negative values are self-explanatory.
* the operator-density information architecture requested for Dashboard,
  discovery, and Remediation Center.
"""
from __future__ import annotations

import unittest
from pathlib import Path


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
        self.assertNotIn('params.set("sort", "risk_score")', query_body)
        # Applying a sort refetches from the server instead of sorting locally.
        apply_start = self.app_js.index("async function applyInventorySort(")
        apply_body = self.app_js[apply_start:apply_start + 700]
        self.assertIn("resetInventoryPageWindow()", apply_body)
        self.assertIn("refreshInventoryPageWindow()", apply_body)
        # A results filter lists completed named runs, not configurations that
        # have never produced data (which used to create guaranteed blank views).
        self.assertIn("function completedInventoryScanNames(", self.app_js)
        names_start = self.app_js.index("function completedInventoryScanNames(")
        names_body = self.app_js[names_start:names_start + 400]
        self.assertIn("latestHistoryItems", names_body)
        self.assertIn("scan_label", names_body)
        self.assertNotIn("scanProfilesState", names_body)
        self.assertIn("All scans", self.index_html)

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

    def test_remediation_center_uses_compact_queue_first_layout(self) -> None:
        risk_panel = self.index_html[
            self.index_html.index('id="tab-risk"'):
            self.index_html.index('id="tab-settings"')
        ]
        self.assertIn("Remediation Center", risk_panel)
        self.assertIn("remediation-summary", risk_panel)
        self.assertIn("remediation-workspace-status", risk_panel)
        self.assertIn("remediation-queue-panel", risk_panel)
        # The queue and exposure insights are full-width rows BELOW the
        # analytics grid (main column + side rail) - they used to sit inside
        # the narrow main column and left the rail's dead space beside them.
        self.assertLess(
            risk_panel.index('class="risk-analytics-side"'),
            risk_panel.index("remediation-queue-panel"),
        )
        self.assertLess(
            risk_panel.index("remediation-queue-panel"),
            risk_panel.index("exposure-insights"),
        )
        self.assertIn("remediation-row", self.app_js)
        self.assertIn("priority-file-row", self.app_js)
        self.assertIn("Remediation Center — compact", self.styles_css)


if __name__ == "__main__":
    unittest.main()
