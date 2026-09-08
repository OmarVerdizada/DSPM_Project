"""Track S-E source contracts for the bounded inventory page window.

The dashboard is still a vanilla-JavaScript application, so these tests pin the
browser-side paging/cache/fallback contract without introducing a second frontend
toolchain. API behavior and keyset correctness remain covered by
``tests/test_inventory_api.py``.
"""

from __future__ import annotations

import unittest
from pathlib import Path


class InventoryWindowFrontendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = Path("frontend/app.js").read_text(encoding="utf-8")
        cls.styles = Path("frontend/styles.css").read_text(encoding="utf-8")

    def test_inventory_consumes_cursor_pages_from_s_c_api(self) -> None:
        self.assertIn("/api/inventory?", self.script)
        self.assertIn('params.set("after", cursor)', self.script)
        self.assertIn("data.next_cursor", self.script)
        self.assertIn("data.has_more", self.script)
        self.assertIn("pageStarts", self.script)

    def test_browser_cache_and_dom_window_are_bounded(self) -> None:
        self.assertIn("const INVENTORY_SERVER_PAGE_SIZE = 100", self.script)
        self.assertIn("const INVENTORY_MAX_CACHED_PAGES = 3", self.script)
        self.assertIn("trimInventoryPageCache", self.script)
        self.assertIn("inventoryPageWindow.pages.delete", self.script)
        # A server page bypasses the legacy growing slice and is rendered as the
        # entire current page only; navigation swaps that bounded window.
        self.assertIn("const page = serverPage ? visible : visible.slice", self.script)
        self.assertIn('data-inventory-page="previous"', self.script)
        self.assertIn('data-inventory-page="next"', self.script)

    def test_all_facets_stay_on_the_bounded_server_path(self) -> None:
        start = self.script.index("function canUseInventoryPageWindow()")
        body = self.script[start:start + 700]
        self.assertIn("Boolean(accessToken && hasCompletedInventoryScan())", body)
        # Named historical/demo runs can be queried even when no report was
        # restored into the current-estate workspace.
        self.assertIn("latestHistoryItems.length", body)
        # Every facet takes a set of answers and sends all of them.
        self.assertIn('params.set("risk", [...inventoryRiskFacets].join(","))', self.script)
        self.assertIn('params.set("source", [...inventorySourceFacets].join(","))', self.script)
        self.assertIn('params.set("finding_type", [...inventoryFindingFacets].join(","))', self.script)
        self.assertIn('[...inventoryFrameworkFacets].join(",")', self.script)
        # "Protected" is a flag, not a severity, and "Protected / locked" is a
        # flag, not a data class. Translating either into `protected=true` was
        # the browser's job while one answer was all a facet could hold; with
        # several it is an OR inside the facet it was ticked in, which only the
        # query builder can express.
        store = Path("backend/store.py").read_text(encoding="utf-8")
        self.assertIn('protected_risk = "PROTECTED" in risks', store)
        self.assertIn('risk_clauses.append("is_protected = 1")', store)
        self.assertIn('type_clauses.append("is_protected = 1")', store)

    def test_compact_restore_facets_and_detail_are_on_demand(self) -> None:
        self.assertIn("include_files=${includeFiles", self.script)
        self.assertIn('/api/inventory/facets', self.script)
        self.assertIn('/api/inventory/${encodeURIComponent(file.id)}', self.script)
        self.assertIn("__inventory_detail_loaded", self.script)

    def test_page_controls_are_responsive_and_accessible(self) -> None:
        self.assertIn('aria-label="Inventory page controls"', self.script)
        self.assertIn(".inventory-window-controls", self.styles)
        self.assertIn("@media (max-width: 720px)", self.styles)
        self.assertIn('role="status" aria-live="polite"', self.script)

    def test_filter_changes_are_immediate_and_cancel_stale_searches(self) -> None:
        self.assertIn("let inventoryPageAbortController = null", self.script)
        self.assertIn("inventoryPageAbortController?.abort()", self.script)
        self.assertIn("{ signal: controller.signal }", self.script)
        self.assertIn("error?.name === \"AbortError\"", self.script)
        # Severity is a facet now, and both it and the dashboard's band jumps
        # go through one entry point, so the state and the fetch cannot drift.
        # A band jump still searches at once - the operator asked for it by
        # clicking - where ticking a facet waits for the Search button.
        apply_risk = self.script[self.script.index("function applyInventoryRisk("):]
        apply_risk = apply_risk[:apply_risk.index(chr(10) + "}" + chr(10))]
        self.assertLess(apply_risk.index('setFacetSelection("inventory-risk-filter"'),
                        apply_risk.index("applyFindingsFacets()"))
        self.assertIn("inventoryApplyFiltersBtn?.addEventListener", self.script)

    def test_manual_risk_change_rerenders_without_a_database_round_trip(self) -> None:
        start = self.script.index('resultsBody.addEventListener("change"')
        body = self.script[start:self.script.index("exportCsvBtn.addEventListener", start)]
        self.assertIn("renderRows(currentPage.items", body)
        self.assertNotIn("refreshInventoryPageWindow()", body)

    def test_streaming_export_has_busy_and_screen_reader_feedback(self) -> None:
        self.assertIn("inventoryExportStatus", self.script)
        self.assertIn("button.disabled = true", self.script)
        self.assertIn("button.disabled = false", self.script)
        self.assertIn('id="inventory-export-status"', Path("frontend/index.html").read_text(encoding="utf-8"))

    def test_inventory_disclosure_is_scan_and_data_only(self) -> None:
        # The +N dossier owns finding evidence; the row expansion is only
        # about the asset and its scan. No duplicated findings sections.
        self.assertIn('data-inventory-expand=', self.script)
        self.assertIn("openAssetDetailModal", self.script)
        self.assertIn('id="asset-detail-modal"', Path("frontend/index.html").read_text(encoding="utf-8"))
        self.assertIn("ensureInventoryAssetDetail(file)", self.script)
        self.assertIn("renderInventoryExpandedDetails(file)", self.script)
        expansion = self.script.split("function renderInventoryExpandedDetails", 1)[1].split(chr(10) + "async function", 1)[0]
        self.assertNotIn("Findings and redacted evidence", expansion)
        self.assertNotIn("Risk rationale", expansion)
        # Section labels follow the dossier's current naming; the contract is
        # that the expansion covers asset/access/scan context and sanitized
        # preview only - never detection evidence.
        self.assertIn("Identity and location", expansion)
        self.assertIn("Exposure context", expansion)
        self.assertIn("Scan coverage and provenance", expansion)
        self.assertIn("Sanitized content only", expansion)
        # The dossier keeps the grouped evidence.
        self.assertIn("renderFindingDrawerGroups", self.script)

    def test_priority_finding_rows_open_the_asset_popup(self) -> None:
        # Queue rows open the shared asset pop-up on the Findings tab; the
        # deep evidence renderers stay shared with the dossier.
        self.assertIn("finding-open-btn", self.script)
        self.assertIn('openAssetDetailModal(btn.dataset.findingFileKey || "", "findings")', self.script)
        self.assertNotIn("finding-detail-row", self.script)
        self.assertIn("renderChildFindingEvidence", self.script)
        self.assertIn("Exact occurrence locations", self.script)
        self.assertIn("Framework and control mappings", self.script)

    def test_inventory_command_surface_has_compact_even_group_rhythm(self) -> None:
        self.assertIn("complete disclosure", self.styles)
        self.assertIn("margin: 0 !important", self.styles)
        self.assertIn("grid-template-columns: minmax(220px, 240px) minmax(220px, 1fr) minmax(390px, 2fr) auto", self.styles)
        self.assertIn(".inventory-scan-facet .facet-shell select", self.styles)
        self.assertIn("width: 180px !important", self.styles)
        self.assertIn("grid-template-columns: repeat(4, minmax(0, 1fr))", self.styles)
        # `.inventory-expanded-grid` used to be asserted here. Phase 1.4 found
        # that the class appears in no HTML and no JavaScript this product
        # ships, so the two rules for it could never apply; they went with the
        # other 758 unreachable rules. What the row expands into now is the
        # asset detail modal, which has its own contract.
        self.assertNotIn(".inventory-expanded-grid", self.styles)
        self.assertIn(".asset-detail-panel", Path("frontend/styles.css").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
