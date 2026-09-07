"""Phase 0 of docs/PERFORMANCE_AUDIT_AND_ROADMAP_2026-09.md, kept honest.

Each test names the measurement that made the change worth doing, so a later
edit that undoes one fails against the number rather than against an opinion.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

from backend import db, store


class ConnectionSettingsTests(unittest.TestCase):
    """0.6 - a 2MB page cache against a 500MB file evicts the working set
    between requests, and a rollback journal writes every page twice while
    holding readers out of the commit."""

    def test_sqlite_opens_in_wal_with_a_working_set_sized_cache(self) -> None:
        source = Path("backend/db.py").read_text(encoding="utf-8")
        self.assertIn('os.getenv("DSPM_SQLITE_JOURNAL_MODE", "wal")', source)
        self.assertIn("PRAGMA temp_store = MEMORY", source)
        self.assertIn("DSPM_SQLITE_CACHE_KB", source)
        # NORMAL is only safe under WAL; under a rollback journal it would put
        # the file itself at risk, not merely the last transaction.
        synchronous = source[source.index("PRAGMA synchronous = NORMAL") - 300:]
        self.assertIn('_sqlite_journal_mode() == "wal"', synchronous[:400])

    def test_a_live_connection_carries_the_settings(self) -> None:
        with db.connect(store.DB_PATH) as conn:
            self.assertEqual("wal", conn.execute("PRAGMA journal_mode").fetchone()[0])
            self.assertEqual(1, conn.execute("PRAGMA synchronous").fetchone()[0])
            self.assertLessEqual(conn.execute("PRAGMA cache_size").fetchone()[0], -32768)
            self.assertEqual(1, conn.execute("PRAGMA foreign_keys").fetchone()[0])

    def test_the_planner_gets_statistics_after_a_scan(self) -> None:
        # SQLite ships with none until ANALYZE runs, and a scan is the only
        # thing that changes the shape of this data.
        self.assertTrue(hasattr(db, "optimize_sqlite"))
        source = Path("backend/store.py").read_text(encoding="utf-8")
        self.assertIn("db.optimize_sqlite(DB_PATH)", source)


class PerRequestWorkTests(unittest.TestCase):
    def test_the_row_carries_its_own_counts(self) -> None:
        """0.4 - the two numbers in the collapsed table are lengths of two
        lists inside detail_json. Reading them per page fetched and parsed the
        whole blob for every row: 11.3MB and 127ms of a 165ms request."""
        with store._connect() as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(assets)")}
        self.assertIn("reason_count", columns)
        self.assertIn("dlp_count", columns)

        source = Path("backend/store.py").read_text(encoding="utf-8")
        self.assertIn("_detail_counts(asset.detail_json)", source)
        self.assertIn("_INVENTORY_READ_COLS", source)
        # Every read model returns the same shape, or the paths disagree about
        # a row's contents rather than only about their speed.
        for path in ("_list_inventory_blob", "_scan_report_inventory_rows"):
            body = source[source.index(f"def {path}("):]
            body = body[:body.index("\ndef ", 10)]
            self.assertIn("reason_count", body, path)

        app_source = Path("backend/app.py").read_text(encoding="utf-8")
        endpoint = app_source[app_source.index('@app.get("/api/inventory")'):]
        endpoint = endpoint[:endpoint.index("@app.get", 10)]
        # The blob fallback survives for rows an older build wrote, but it must
        # be reached only by rows that actually lack the columns.
        self.assertIn("if missing:", endpoint)

    def test_authentication_does_not_write(self) -> None:
        """0.7 - the revocation check pruned expired rows on every read, which
        turned an authenticated GET into a write transaction."""
        source = Path("backend/store.py").read_text(encoding="utf-8")
        check = source[source.index("def is_token_revoked("):]
        check = check[:check.index("\ndef ", 10)]
        self.assertNotIn("DELETE", check)
        # Expiry is a property of the row, so the query says so.
        self.assertIn("expires_at >= ?", check)
        # ...and revoking clears what this process has remembered.
        revoke = source[source.index("def revoke_token_jti("):]
        self.assertIn("_forget_revocation()", revoke[:revoke.index("\ndef ", 10)])

    def test_the_read_model_gate_is_cached_and_resettable(self) -> None:
        """0.8 - two existence probes ran per inventory read to answer a
        question that changes when a scan is saved."""
        self.assertTrue(callable(store.refresh_read_model_state))
        source = Path("backend/store.py").read_text(encoding="utf-8")
        invalidate = source[source.index("def _invalidate_inventory_query_cache("):]
        invalidate = invalidate[:invalidate.index("\ndef ", 10)]
        self.assertIn("_forget_readiness(tenant_id)", invalidate)
        self.assertIn("_forget_scan_report_rows(tenant_id)", invalidate)

    def test_a_named_scan_is_projected_once(self) -> None:
        """0.5 - selecting a scan in the Source filter decrypted an 8.3MB
        artifact and re-normalised 463 assets on every page: 2.3s, measured."""
        source = Path("backend/store.py").read_text(encoding="utf-8")
        self.assertIn("def latest_scan_id_by_label(", source)
        self.assertIn("def scan_report_inventory_rows_by_label(", source)
        # The cache holds the projection, not the parsed report - the report is
        # an order of magnitude larger.
        cache = source[source.index("def _cached_scan_report_rows("):]
        cache = cache[:cache.index("\ndef ", 10)]
        self.assertIn("_scan_report_rows_cache", cache)


class BootWorkTests(unittest.TestCase):
    APP_JS = Path("frontend/app.js").read_text(encoding="utf-8")

    def test_boot_loads_the_dashboard_and_nothing_else(self) -> None:
        """0.2 - boot made 18 API calls and moved 3.0MB for a page that needs
        three of them. The risk-logic libraries alone were 868KB."""
        boot = self.APP_JS[self.APP_JS.index("if (accessToken) {\n  // Only the dashboard's own data at boot."):]
        boot = boot[:boot.index("}")]
        self.assertIn("loadHistory()", boot)
        for deferred in ("loadAudit(", "loadUsers(", "loadProtectedMetadata(", "loadRemediationFindings("):
            self.assertNotIn(deferred, boot, f"{deferred} runs at boot again")
        # ...and each of them is registered against the tab it paints.
        for tab in ('"logic"', '"security"', '"findings"'):
            self.assertIn(f"onFirstTabOpen({tab}", self.APP_JS)

    def test_hidden_panels_do_not_render(self) -> None:
        """0.3 - 9,685 of the document's 17,492 nodes were the Findings table,
        built for a tab that was not on screen. `display: none` removes a panel
        from layout, not from style resolution."""
        for fn, panel in (("renderRows", "tab-findings"),
                          ("renderFindingsWorkspace", "tab-findings"),
                          ("renderRemediationWorkspace", "tab-risk"),
                          ("renderReportPreview", "tab-reports")):
            body = self.APP_JS[self.APP_JS.index(f"function {fn}("):]
            body = body[:body.index("\n}", 10)]
            self.assertIn(f'deferWhileHidden("{panel}"', body, fn)
        # A deferred render is replayed, not dropped.
        self.assertIn("function flushPanelRenders(", self.APP_JS)
        self.assertIn("flushPanelRenders(`tab-${resolvedTab}`)", self.APP_JS)

    def test_the_deferral_state_exists_before_anything_reads_it(self) -> None:
        """app.js is one script whose top-level statements run in file order,
        and a `const` is in the temporal dead zone until its own line runs. The
        first version of this declared the map beside `switchTab`, two thousand
        lines below a renderer that top-level code calls - which threw, was
        swallowed by a `.catch`, and left the queue showing a loading skeleton
        for the life of the page."""
        declaration = self.APP_JS.index("const pendingPanelRenders = new Map();")
        for reader in ("function renderRows(", "function renderRemediationWorkspace(",
                       "function switchTab("):
            self.assertLess(declaration, self.APP_JS.index(reader), reader)

    def test_an_abandoned_queue_load_does_not_strand_the_page(self) -> None:
        """An aborted request returned without clearing the flag it had set.
        Harmless while boot always followed with another load; fatal once the
        queue stopped loading at boot."""
        body = self.APP_JS[self.APP_JS.index("async function loadRemediationFindings("):]
        body = body[:body.index("\n}\n", 10)]
        self.assertIn('if (error?.name === "AbortError") {', body)
        self.assertIn("requestId === remediationListRequest", body)
        # Opening the tab asks for data whenever it has none; the loader
        # already dedupes with an abort and a request id.
        self.assertIn('if (resolvedTab === "risk" && !remediationLoaded) {', self.APP_JS)


class RenderCostTests(unittest.TestCase):
    """Phase 1 - what an interaction costs once the data has arrived."""

    APP_JS = Path("frontend/app.js").read_text(encoding="utf-8")

    def test_a_row_shows_only_what_it_draws(self) -> None:
        """1.1 - a row was 6,758 bytes and 110 nodes, of which 27 finding
        chips (2,524 bytes, 54 nodes) where only two are ever visible; the +N
        beside them had always been computed against a cap of four that the
        markup did not apply."""
        self.assertIn("const FINDING_CHIPS_SHOWN = 4;", self.APP_JS)
        self.assertIn("visibleFindingChips.slice(0, FINDING_CHIPS_SHOWN)", self.APP_JS)
        self.assertIn("displayFindings.length - shownFindingChips.length", self.APP_JS)
        # Five inline SVGs a row - 744 bytes of path data, a hundred times a
        # page - become two sprite references.
        index = Path("frontend/index.html").read_text(encoding="utf-8")
        for symbol in ('<symbol id="inv-open"', '<symbol id="inv-copy"'):
            self.assertIn(symbol, index)
        row = self.APP_JS[self.APP_JS.index("preview-toggle inventory-row-expand"):]
        row = row[:row.index("</td>")]
        self.assertIn('href="#inv-open"', row)
        self.assertNotIn("<path d=", row)

    def test_a_page_of_rows_is_not_one_task(self) -> None:
        """1.2 - the whole page went in through one `innerHTML`: 63ms after
        the row diet, 320ms before it, and the browser cannot interrupt any of
        it to answer a click."""
        self.assertIn("const ROW_CHUNK_SIZE = 25;", self.APP_JS)
        self.assertIn("function writeRowsInChunks(", self.APP_JS)
        # The first chunk stays synchronous, so the table still appears in the
        # frame it always did.
        chunks = self.APP_JS[self.APP_JS.index("function writeRowsInChunks("):]
        chunks = chunks[:chunks.index("\n}\n", 10)]
        self.assertIn("resultsBody.innerHTML = rowsHtml.slice(0, ROW_CHUNK_SIZE)", chunks)
        # requestAnimationFrame stops firing in a hidden document, which would
        # strand a render part-drawn until the operator came back.
        self.assertIn("if (document.hidden) setTimeout(step, 0);", self.APP_JS)
        # A newer render owns the table; the older one stops where it is.
        self.assertIn("if (token !== rowChunkToken) return;", chunks)

    def test_the_queue_renders_once_per_load(self) -> None:
        """1.3 - three renders of the whole workspace per load, and nine
        selects rebuilt from innerHTML on every keystroke's response."""
        self.assertIn("let remediationFacetSignature", self.APP_JS)
        options = self.APP_JS[self.APP_JS.index("function renderRemediationFilterOptions("):]
        options = options[:options.index("\n}\n", 10)]
        self.assertIn("if (signature === remediationFacetSignature) return;", options)
        # A refresh that already has rows dims them instead of replacing the
        # table with a skeleton and building it back.
        self.assertIn('remediationWorkflow?.classList.add("is-refreshing")', self.APP_JS)
        queue_css = Path("frontend/styles/remediation.css").read_text(encoding="utf-8")
        self.assertIn("#remediation-workflow.is-refreshing", queue_css)

    def test_the_dashboard_renders_only_when_it_is_visible(self) -> None:
        """The renderer 0.3 missed. It ran on every scan restore and every
        workspace hydrate from whichever tab was open: 1,082ms, measured,
        because four cards each write markup and then read a geometry
        property, forcing a full layout of the document apiece."""
        body = self.APP_JS[self.APP_JS.index("function renderExecutiveExperience("):]
        body = body[:body.index("\n}\n", 10)]
        self.assertIn('deferWhileHidden("tab-overview", "dashboard"', body)
        # ...and it asks for the per-file slice its top-risk card counts,
        # rather than relying on boot having fetched it for another tab.
        self.assertIn("hydrateWorkspaceSlice({ force: true })", body)

    def test_the_stylesheet_carries_no_unreachable_rules(self) -> None:
        """1.4 - 758 rules (121KB) named classes and ids that appear in no
        HTML and no JavaScript this product ships, so they could never match.
        Recalculation is nodes x rule complexity, and this is the rule side."""
        css = Path("frontend/styles.css").read_text(encoding="utf-8")
        self.assertLess(len(css), 700_000, "styles.css is growing again")
        for gone in (".inventory-framework-option", ".login-actions", ".auth-panel",
                     ".inventory-expanded-grid", ".chart-legend"):
            self.assertNotIn(gone + " ", css)
        self.assertEqual(css.count("{"), css.count("}"))
        self.assertEqual(css.count("/*"), css.count("*/"))


class ResponseSizeTests(unittest.TestCase):
    def test_responses_and_assets_are_compressed(self) -> None:
        """0.1 - 1.5MB of JS and CSS and 100-200KB JSON pages went out
        uncompressed. app.js is 545KB raw and 129KB on the wire."""
        source = Path("backend/app.py").read_text(encoding="utf-8")
        self.assertIn("from fastapi.middleware.gzip import GZipMiddleware", source)
        self.assertIn("app.add_middleware(GZipMiddleware, minimum_size=1000)", source)
        # Ordering matters: it has to wrap the static mount as well as the API.
        self.assertLess(source.index("GZipMiddleware, minimum_size"),
                        source.index('app.mount("/static"'))


if __name__ == "__main__":
    unittest.main()
