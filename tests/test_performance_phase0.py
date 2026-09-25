"""Phase 0 of docs/PERFORMANCE_AUDIT_AND_ROADMAP_2026-09.md, kept honest.

Each test names the measurement that made the change worth doing, so a later
edit that undoes one fails against the number rather than against an opinion.
"""
from __future__ import annotations

import os
import re
import unittest
from pathlib import Path

from backend import db, store


def _index_names(conn, table: str) -> set[str]:
    if db.is_postgres():
        rows = conn.execute("SELECT indexname FROM pg_indexes WHERE schemaname = current_schema() "
                            "AND tablename = ?", (table,)).fetchall()
        return {row[0] for row in rows}
    return {row[1] for row in conn.execute(f"PRAGMA index_list({table})")}


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

    @unittest.skipIf(db.is_postgres(), "SQLite connection pragmas; PostgreSQL has none of them")
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
            columns = db.table_columns(conn, "assets")
        self.assertIn("reason_count", columns)
        self.assertIn("dlp_count", columns)

        source = Path("backend/store.py").read_text(encoding="utf-8")
        # P2: counted from the record while it is a dict, not parsed back out of
        # its JSON (tests/test_p2_save_derives_once.py compares the two).
        self.assertIn("asset.reason_count, asset.dlp_count", source)
        self.assertIn("_INVENTORY_READ_COLS", source)
        # Every read model returns the same shape, or the paths disagree about
        # a row's contents rather than only about their speed.
        for path in ("_list_inventory_blob", "_inventory_row"):
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
        # C1: verify_token asks through token_state, which is held to the same rule.
        state = source[source.index("def token_state("):]
        state = state[:state.index("\ndef ", 10)]
        self.assertNotIn("DELETE", state)
        self.assertIn("expires_at >= ?", state)
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


class StorageTests(unittest.TestCase):
    """Phase 2 - what the database weighs, and the two queries that grew with it."""

    STORE = Path("backend/store.py").read_text(encoding="utf-8")

    def test_the_write_only_blobs_are_compressed(self) -> None:
        """2.1 - three columns the interface never reads in bulk held 360MB of
        a 523MB database: the finding history (188), the scan baselines (110)
        and the per-asset detail (62)."""
        self.assertIn("_JSON_ZLIB_MAGIC", self.STORE)
        # PostgreSQL TOASTs a large TEXT value itself; storing our own bytes
        # there would trade transparent handling for a private format.
        packer = self.STORE[self.STORE.index("def pack_json_text("):]
        packer = packer[:packer.index(chr(10) + "def ", 10)]
        self.assertIn("if db.is_postgres():", packer)
        # `'{}'` has to stay text: two partial indexes and the read-model gate
        # compare against it literally.
        self.assertIn("_compression_floor()", packer)
        # Every reader accepts text, a compressed blob, or a pre-compression
        # blob - a store that cannot read its own history is not an upgrade.
        reader = self.STORE[self.STORE.index("def unpack_json_text("):]
        reader = reader[:reader.index(chr(10) + "def ", 10)]
        self.assertIn("_JSON_ZLIB_MAGIC", reader)
        self.assertIn("isinstance(value, (bytes, bytearray, memoryview))", reader)

    def test_the_finding_history_has_a_window(self) -> None:
        """Every scan writes one row per finding and nothing reads them in
        bulk, so the projection grew without bound: 188MB for 25 scans."""
        self.assertIn("def _trim_finding_index(", self.STORE)
        self.assertIn("DSPM_FINDING_INDEX_KEEP_SCANS", self.STORE)
        # The window runs in the transaction that adds a scan to it.
        write = self.STORE[self.STORE.index("_write_finding_index(conn, tenant_id, report)"):]
        self.assertIn("_trim_finding_index(conn, tenant_id)", write[:200])
        # A trimmed row means "outside the window", not "no such finding".
        self.assertIn("body = unpack_json_text(row[", self.STORE)

    def test_a_saved_run_keeps_its_inventory_projection(self) -> None:
        """2.2 - selecting a named scan decrypted an 8.3MB artifact and
        re-normalised every asset: 2.3s a page, and O(report) not O(page)."""
        with store._connect() as conn:
            columns = db.table_columns(conn, "scan_reports")
        self.assertIn("rows_json", columns)
        self.assertIn("def _packed_report_rows(", self.STORE)
        # A run saved before the column existed fills it on first read, so the
        # slow path happens once per run rather than once per process.
        build = self.STORE[self.STORE.index("    def build() -> list[dict]:"):]
        build = build[:build.index("return rows") + 11]
        self.assertIn("_stored_report_rows(tenant_id, scan_id)", build)
        self.assertIn("_store_report_rows(tenant_id, scan_id, rows)", build)
        # Failing to build the projection must never cost the operator the scan.
        packed = self.STORE[self.STORE.index("def _packed_report_rows("):]
        self.assertIn("except Exception", packed[:packed.index(chr(10) + "def ", 10)])

    def test_severity_sorts_on_a_number(self) -> None:
        """2.3 - "worst first" sorted on a CASE expression, which no index can
        serve: SQLite read the whole current set into a temp b-tree, 29ms."""
        with store._connect() as conn:
            columns = db.table_columns(conn, "findings")
            indexes = _index_names(conn, "findings")
        self.assertIn("severity_rank", columns)
        self.assertIn("idx_findings_tenant_current_rank_id", indexes)
        self.assertIn('"severity": ("severity_rank", False, "DESC")', self.STORE)
        # Both writers stamp it, or a sort silently loses rows to rank 0.
        self.assertEqual(2, self.STORE.count("severity_rank(severity),"))  # calls, not the def
        # ...and the affected-file count is a predicate, not a CASE inside
        # COUNT(DISTINCT), which could not use the asset index: 34.5 -> 8.2ms.
        self.assertIn("SELECT COUNT(DISTINCT asset_id) AS n FROM findings WHERE", self.STORE)


class PortableSchemaTests(unittest.TestCase):
    """3.1 - the compression work of Phase 2 is SQLite-only, and it nearly took
    the PostgreSQL path with it."""

    STORE = Path("backend/store.py").read_text(encoding="utf-8")

    def test_the_schema_uses_only_types_the_seam_can_translate(self) -> None:
        """`translate_schema` rewrites exactly two constructs - AUTOINCREMENT
        and REAL - so everything else in the DDL has to be valid PostgreSQL as
        written. A `rows_json BLOB` column shipped in Phase 2 and would have
        failed every PostgreSQL install at `init_db`, because PostgreSQL has no
        BLOB type. Nothing caught it, because the live PostgreSQL suite needs a
        reachable server and had never run here.
        """
        skip = ("--", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT")
        declared = set()
        # A table body ends at a `);` on its own indented line; a bare `);`
        # also appears inside one.
        pattern = "CREATE TABLE IF NOT EXISTS (\\w+) \\((.*?)" + chr(10) + "        \\);"
        for table in re.finditer(pattern, self.STORE, re.S):
            for line in table.group(2).splitlines():
                line = line.strip().rstrip(",")
                if not line or line.startswith(skip):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    declared.add(parts[1].upper())
        for _, column_type in re.findall("ADD COLUMN (\\w+) (\\w+)", self.STORE):
            declared.add(column_type.upper())

        self.assertGreater(len(declared), 2, "the schema scan matched nothing")
        portable = {"TEXT", "INTEGER", "BIGINT", "REAL"}
        self.assertEqual(
            set(), declared - portable,
            "non-portable column type in the schema: " + repr(sorted(declared - portable)))

    def test_the_compressed_columns_are_declared_text(self) -> None:
        """SQLite stores a BLOB unchanged in a TEXT-affinity column, so all four
        compressed columns are declared TEXT and work on both backends:
        PostgreSQL keeps plain text there and TOASTs it, SQLite keeps zlib
        bytes."""
        for column in ("detail_json", "snapshot_json", "response_json", "rows_json"):
            self.assertNotIn(column + " BLOB", self.STORE)

    def test_sqlite_only_work_is_gated(self) -> None:
        """Everything Phase 0 and Phase 2 added for SQLite has to be a no-op on
        a server that manages its own storage and statistics."""
        db_source = Path("backend/db.py").read_text(encoding="utf-8")
        optimize = db_source[db_source.index("def optimize_sqlite("):]
        self.assertIn("if is_postgres():", optimize[:optimize.find(chr(10) + "def ", 10)])
        packer = self.STORE[self.STORE.index("def pack_json_text("):]
        self.assertIn("if db.is_postgres():", packer[:packer.find(chr(10) + "def ", 10)])
        # The pragmas are set inside connect()'s SQLite branch only.
        self.assertIn("_apply_sqlite_pragmas(conn)", db_source)
        self.assertNotIn("_apply_sqlite_pragmas(raw)", db_source)



class MultiWorkerSafetyTests(unittest.TestCase):
    """3.3 - Phase 0 bought its speed with caches that live in one process and
    are invalidated by that same process. Several workers each keep their own
    copy, so a write in one is invisible to the others until the entry expires.
    Three of those are a staleness question; the revocation one is a security
    question."""

    MAIN = Path("main.py").read_text(encoding="utf-8")

    def test_asking_for_workers_turns_the_per_process_caches_off(self) -> None:
        self.assertIn("_PER_PROCESS_CACHE_SETTINGS", self.MAIN)
        for setting in ("DSPM_TENANT_EXISTS_CACHE_SECONDS",
                        "DSPM_READINESS_CACHE_SECONDS",
                        "DSPM_INVENTORY_COUNT_CACHE_SECONDS",
                        "DSPM_INVENTORY_FACETS_CACHE_SECONDS"):
            self.assertIn(setting, self.MAIN, setting)
        # Turning them off is not advice printed to a log the operator may not
        # read - it happens before uvicorn starts.
        self.assertIn("_disable_per_process_caches(logger)", self.MAIN)
        # ...and every one of them has to be honoured by the store, or the
        # switch is decoration.
        store_source = Path("backend/store.py").read_text(encoding="utf-8")
        for reader in ("_tenant_exists_cache_seconds",
                       "_readiness_cache_seconds", "_inventory_count_cache_seconds",
                       "_inventory_facets_cache_seconds"):
            self.assertIn("def " + reader + "(", store_source, reader)

    def test_zero_disables_rather_than_shortens(self) -> None:
        """A TTL of 0 has to mean "ask the database every time", not "expire
        immediately and race"."""
        for name, default in (("DSPM_TOKEN_REVOCATION_CACHE_SECONDS", store.is_token_revoked),
                              ("DSPM_TENANT_EXISTS_CACHE_SECONDS", store.tenant_exists)):
            del default  # the setting is what is under test
            previous = os.environ.get(name)
            os.environ[name] = "0"
            try:
                self.assertEqual(0.0, {
                    "DSPM_TOKEN_REVOCATION_CACHE_SECONDS": store._revocation_cache_seconds,
                    "DSPM_TENANT_EXISTS_CACHE_SECONDS": store._tenant_exists_cache_seconds,
                }[name]())
            finally:
                if previous is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = previous

    def test_reload_and_workers_are_refused_together(self) -> None:
        # --reload runs one process; accepting both would silently ignore one.
        self.assertIn("--reload runs a single process", self.MAIN)


class LooseEndTests(unittest.TestCase):
    """The items the phase records marked as not met, and what closed them."""

    STORE = Path("backend/store.py").read_text(encoding="utf-8")
    APP = Path("backend/app.py").read_text(encoding="utf-8")
    APP_JS = Path("frontend/app.js").read_text(encoding="utf-8")

    def test_the_compact_report_is_stored_not_derived(self) -> None:
        """0.5, second half. The console restores the newest report at every
        boot without its files, and deriving that form meant decrypting and
        parsing the whole 8MB artifact to throw the file array away: 1,429ms
        cold, 20ms served, measured."""
        with store._connect() as conn:
            columns = db.table_columns(conn, "scan_reports")
        self.assertIn("compact_json", columns)
        self.assertIn("def compact_scan_report(", self.STORE)
        self.assertIn("def read_scan_report_compact(", self.STORE)
        # Written with the run...
        self.assertIn("_packed_compact_report(report),", self.STORE)
        # ...and filled on first read for runs saved before the column existed.
        reader = self.STORE[self.STORE.index("def read_scan_report_compact("):]
        reader = reader[:reader.find(chr(10) + "def ", 10)]
        self.assertIn("UPDATE scan_reports SET compact_json = ?", reader)
        # app.py keeps its old name but no longer owns the logic.
        self.assertIn("_compact_scan_report = compact_scan_report", self.APP)
        self.assertNotIn("def _compact_scan_report(", self.APP)
        endpoint = self.APP[self.APP.index('@app.get("/api/history/{scan_id}/report")'):]
        endpoint = endpoint[:endpoint.index("@app.get", 10)]
        self.assertIn("read_scan_report_compact(principal.tenant_id, scan_id)", endpoint)

    def test_the_hash_comparison_belongs_to_findings(self) -> None:
        """0.2, last item. Two 8MB artifacts decrypted at every boot - 1.1s of
        server time - for flags on a tab that may never open. Nothing on the
        dashboard reads latestHashComparison."""
        boot = self.APP_JS[self.APP_JS.index("async function loadHistory("):]
        # The function's own closing brace, not the next `async function` -
        # the helper that DOES call loadHashComparison sits right after it.
        boot = boot[:boot.index(chr(10) + "}" + chr(10), 10)]
        self.assertNotIn("loadHashComparison", boot)
        opened = self.APP_JS[self.APP_JS.index('onFirstTabOpen("findings"'):]
        self.assertIn("loadHashFlagsForFindings();", opened[:220])
        # Rows already on screen repaint when it lands, so the flags appear
        # without a reload.
        loader = self.APP_JS[self.APP_JS.index("function loadHashFlagsForFindings("):]
        loader = loader[:loader.find(chr(10) + "}" + chr(10), 10)]
        self.assertIn("renderRows(", loader)
        self.assertIn("renderFindingsWorkspace()", loader)

    def test_the_workspace_slice_is_fetched_once_per_report(self) -> None:
        """Phase 1's `force` path let every dashboard render with an empty
        latestFiles start another fetch: three at boot before the first
        landed, two more when Findings opened. One per report now."""
        self.assertIn("let workspaceSliceInFlight = null;", self.APP_JS)
        self.assertIn("let workspaceSliceScanId = \"\";", self.APP_JS)
        gate = self.APP_JS[self.APP_JS.index("async function hydrateWorkspaceSlice("):]
        gate = gate[:gate.index("async function hydrateWorkspaceSliceNow(")]
        self.assertIn("if (workspaceSliceInFlight) return workspaceSliceInFlight;", gate)
        self.assertIn("scanId === workspaceSliceScanId && latestFiles.length", gate)
        # The landed slice records which report it belongs to.
        self.assertIn("workspaceSliceScanId = scanId;", self.APP_JS)

    def test_statistics_are_refreshed_at_shutdown_too(self) -> None:
        """0.6 said 'after each scan save and at shutdown'; only the first
        half was wired."""
        lifespan = self.APP[self.APP.index("async def app_lifespan("):]
        lifespan = lifespan[:lifespan.index("@app.", 10)] if "@app." in lifespan[10:] else lifespan[:4000]
        after_yield = lifespan[lifespan.index("yield"):]
        self.assertIn("optimize_sqlite(", after_yield)

    def test_no_builder_for_a_panel_the_page_does_not_have(self) -> None:
        """`buildScanComparison` formatted a scan-comparison card the refit
        removed from the page. Nothing called it; a test pinned its tooltip
        text for months without the text ever reaching a screen."""
        # The bare name, deliberately: the one surviving reference was passed
        # BY REFERENCE to setPanelHtml, with no paren for a call-shaped grep
        # to find - and it raised at render time for exactly that reason.
        self.assertNotIn("buildScanComparison", self.APP_JS)


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
