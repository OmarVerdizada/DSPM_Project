# Sentro DSPM — Performance Audit and Roadmap

**Date:** 2026-09-07
**Scope:** the console as it stands on `sentro-ironhack` at `6088151` — FastAPI + SQLite backend, vanilla-JS frontend, tenant `23` (463 assets, 6,831 current findings, 25 scans).
**Status:** the audit below is the state on 2026-09-07 *before* Phase 0. Phase 0 shipped the same day; its results are recorded under §5. Every number below was measured, not estimated; the method is in §2 and the raw figures in Appendix A.

---

## 0. The short version

The console feels slow for five reasons, and they are not the reasons the symptoms suggest. The SQL is fine. The table library is not the problem. The weight is in three places nobody chose deliberately:

| # | Cause | Measured | What it does to the user |
|---|---|---|---|
| 1 | **The browser holds every page at once.** All eleven tab panels are rendered into one document at boot — 17,492 DOM nodes — and the Findings table (9,685 nodes) is built for a tab that is not on screen. | Forced style recalculation: **62 ms**. | Every interaction that touches layout — hover, a select change, typing in a filter — costs ~60 ms before any work starts. The frame budget is 16 ms. That is the "sometimes freezes". |
| 2 | **The stylesheet is an accumulation, not a design.** 4,543 rules; 3,790 `!important`; 477 `:not(…)`; 108 `:has(…)`; 345 `:root:root` prefixes; 988 selectors four or more compounds deep. | Same 62 ms — the recalc cost is nodes × rule complexity. | Multiplies cause 1. Also 745 KB to download, uncompressed. |
| 3 | **Boot fires eighteen API calls for a page that needs three.** History report (1.0 s), hash-changes (1.1 s), two inventory pages (164 + 381 ms), facets, findings, three compliance-keyword payloads (740 KB), users, tenants, audit… all at once, whichever tab opens first. | **32 requests, 3.0 MB uncompressed**, before the dashboard is usable. | Slow first paint; the server is busy for two seconds answering questions no one asked yet. |
| 4 | **The inventory page re-reads 11 MB to produce two integers per row.** `/api/inventory` fetches every row's `detail_json` (avg 45 KB, up to 164 KB) and parses it to count reasons and DLP actions. | **127 ms of a 165 ms request**; 11.3 MB read per page of 100. | Every Findings page, filter, sort and search pays it. Grows linearly with detail size. |
| 5 | **Two paths parse an 8 MB encrypted artifact per request.** Selecting a named scan in the Source filter, and opening a history report, decrypt and JSON-parse the whole scan report every time, with no cache. | **2.1–2.5 s per page** with `source=FileServer1`; **1.2 s** for a history report even with `include_files=false`. | "When you add any filter it takes a lot" — this is the filter it happens on. |

Underneath: a 503 MB SQLite file for 1,369 assets, of which 188 MB is a write-only history projection (`finding_index.response_json`) and 110 MB is baseline snapshots — neither read by the UI — running in DELETE journal mode with a 2 MB page cache and no planner statistics.

**What is *not* the problem:** keyset pagination, the index set, FTS5 trigram search, the query plans (every hot query is index-served; the slowest raw query is 41 ms), the event loop (all 94 routes are sync `def` and run in the threadpool), and scan-time write locking (a 20 MB commit stalls readers ~25 ms, measured).

**On TanStack and external libraries:** not needed, and would not help. The slow parts are DOM size, cascade cost, boot fan-out and payload weight — none of which a table library addresses. The one library worth considering is a row virtualiser (a few KB, vendored locally, no network), and only after the DOM diet in Phase 1 has been done; see §6.

The roadmap (§5) is four phases. Phase 0 is a day of work with no risk and removes most of the perceived slowness. Phase 1 is the real fix for the freezes.

---

## 1. Symptoms as reported, and where each one actually comes from

| Reported | Root cause(s) | Section |
|---|---|---|
| "Widgets, tables, sorting — everything opens slowly" | Boot fan-out (§3.2); hidden-tab pre-render (§3.1); style recalc cost (§3.1); inventory detail re-read (§3.3) | 3.1, 3.2, 3.3 |
| "When you add any filter, it takes a lot" | Named-scan filter parses an 8 MB artifact per page (§3.3); every filter change re-pays the 127 ms detail re-read (§3.3); every re-render pays the 62 ms recalc (§3.1) | 3.1, 3.3 |
| "The site is very slow and freezes sometimes" | 320 ms long task rendering 101 rows (588 KB of markup); 62 ms forced recalc on every layout-affecting interaction; 17.5k-node document | 3.1 |
| "Sorting systems" | Sorting itself is 0.3–27 ms server-side; the cost is the re-render and the detail re-read that follow | 3.1, 3.3 |

---

## 2. Method

- **Server timings** — an authentication-free harness of `backend.app` on a second port, `urllib` wall-clock per endpoint, cold and two warm runs (Appendix A.1).
- **In-process profile** — `cProfile` over `store.list_inventory` to separate query time from endpoint overhead (A.2).
- **Query plans** — `EXPLAIN QUERY PLAN` plus wall time for the twelve hot queries against the real database (A.3).
- **Storage** — per-table and per-column byte totals, pragmas, freelist, statistics tables (A.4).
- **Lock behaviour** — a 20 MB transaction committed from a second connection while a reader loop timed `/api/inventory/facets` (A.5).
- **Browser** — the shipped `index.html` loaded in the embedded browser at 1600×900: resource timing, `PerformanceObserver` long tasks, node counts per panel, CSS rule counts, a forced style recalculation, per-row markup analysis (A.6).
- **Static analysis** — endpoint inventory, middleware, auth path, frontend request fan-out, selector census.

The harness was deleted afterwards. The working tree is unchanged apart from this file.

---

## 3. Findings

### 3.1 Browser — where the freezes are

**3.1.1 Eleven pages in one document.** `index.html` carries every tab panel, and `app.js` renders into most of them at boot. After boot with the Dashboard on screen:

| Hidden panel | Nodes |
|---|---|
| `#tab-findings` | **9,685** |
| `#tab-risk` (Remediation) | 2,623 |
| `#tab-logic` | 1,604 |
| `#tab-endpoint` | 917 |
| `#tab-file-servers` | 915 |
| six others | ~960 |
| **Document total** | **17,492** |

Nine and a half thousand of those nodes are the Findings table, built at boot from a second inventory fetch (`/api/inventory?sort=risk_score&limit=200`, 203 KB) for a tab that is not visible. `display: none` removes a panel from layout, but not from style resolution: the browser still matches every rule against every node whenever a recalc is triggered.

**3.1.2 Style recalculation costs 62 ms.** Toggling one class on `<body>` and reading `offsetHeight` — the minimum forced recalc — took **62.1 ms**. The frame budget at 60 Hz is 16.7 ms. Any interaction that changes a class, an attribute, or `:hover` state on an ancestor pays this before its own work begins. This is the mechanism behind "freezes sometimes": it is not one freeze, it is a 60 ms tax on every interaction, and the ones that stack two or three recalcs (open a select, change it, re-render) cross into visible jank.

Recalc cost is roughly nodes × rule-matching complexity. Both factors are inflated:

| Stylesheet census (`styles.css` alone) | Count |
|---|---|
| Rules (all six sheets, from the CSSOM) | 4,543 |
| `!important` | 3,790 |
| `:not(…)` | 477 |
| `:has(…)` | 108 |
| `:root:root` prefixes | 345 |
| Selectors ≥ 4 compounds deep | 988 |
| Attribute selectors `[data-…]` | 585 |

`:has()` is the expensive one — it forces the engine to evaluate descendants when an ancestor changes, and it appears 108 times. The `:root:root` / `!important` layering is the specificity war documented in the frontend roadmap; here its cost is measured rather than argued.

**3.1.3 A row of the inventory is 6.8 KB and 110 nodes.** Rendering 101 rows writes **588 KB of markup** via `innerHTML` in a single **320 ms long task**. Per row:

| Component | Bytes | Notes |
|---|---|---|
| Finding chips | 2,282 | **26 chips rendered, 0–2 visible** — the rest sit behind the edge fade |
| Inline SVG (5 per row) | 744 | Copy, expand, caret, two detail buttons — same five paths repeated 101 times |
| `aria-label` / `title` text | 341 | Each includes the file name |
| Remaining markup | ~3,400 | Path line, meta line, badges, buttons |
| **Total** | **6,758** | **110 element nodes per row** |

The chip set is the clearest waste: 24 of 26 chips are never visible, yet they are serialised, parsed, styled and laid out on every render.

**3.1.4 The queue renders its workspace three times per load.** `loadRemediationFindings` calls `renderRemediationWorkspace()` before the request (loading state), again on data, and again on settle — each rebuilding the table and nine facet selects through `innerHTML`. Measured as a 94 ms long task per load.

**3.1.5 Assets are uncompressed.** `app.js` 543 KB, `styles.css` 745 KB, `daisyui.css` 123 KB, `index.html` 116 KB — served by `StaticFiles` with no `GZipMiddleware`. 1.5 MB of text that would be ~250 KB gzipped. The `?v=` versioning makes them cache well on repeat visits; first load and every version bump pay it in full.

### 3.2 Boot — eighteen questions before the first answer

On a cold load the console makes **32 requests totalling 3.0 MB**. Eighteen are API calls, fired together regardless of which tab is shown:

| Call | ms | KB | Needed by the first tab (Dashboard)? |
|---|---|---|---|
| `history/{id}/report` (compact) | **1,036** | 89 | No — decrypts and parses the full 8 MB artifact server-side, then strips the files |
| `history/hash-changes` | **1,119** | 69 | No |
| `inventory` (limit 200, for the hidden Findings tab) | 381 | 203 | No |
| `findings` (queue page) | 350 | 76 | No |
| `inventory/facets` | 180 | 9 | Yes |
| `inventory` (limit 100) | 164 | 109 | No |
| `compliance-keywords` ×3 | 101 / 109 / 10 | **740 + 128** | No — settings data |
| `executive-dashboard` | 52 | 1.5 | Yes |
| `history` | 42 | 1 | Yes |
| users, tenants, audit, risk-rules, profile, health, scan-profiles | 12–56 each | small | No (one is auth) |

Three calls are needed to paint the dashboard. Fifteen are speculative pre-loads for tabs the user may never open, two of which take over a second each. Because the server runs a single uvicorn worker with a shared threadpool, these also queue behind each other.

### 3.3 Backend hot paths

**3.3.1 `/api/inventory` — 127 ms of 165 ms is two integers per row.** In-process, `list_inventory` takes **16 ms** (12 ms in `fetchall` of a keyset page). The endpoint then calls `inventory_reason_action_counts`, which `SELECT id, detail_json … WHERE id IN (…)` for the page and `json.loads` each blob to read `len(risk.reasons)` and `len(risk.dlp_recommendations)`. Measured for one page of 100: **127 ms, 11.3 MB of `detail_json` read**. The frontend then makes a *second* request, `/api/inventory-detail-counts`, for any row the first pass missed.

`detail_json` averages 45 KB and reaches 164 KB. The largest one decomposes as: `findings` list 102 KB (26 findings with full match context), `compliance.framework_mapping` 18 KB, `canonical_entities` 27 KB, `compliance.evidence` 9 KB, `risk` 9 KB. None of that is needed to count two arrays.

**3.3.2 Named-scan filter — 2.1–2.5 s per page.** `list_inventory(source="FileServer1")` resolves the scan label to its newest run via `read_latest_scan_report_by_label`, which loads the run's report artifact (`data/artifacts/23/…/….enc`, **8.3 MB**, encrypted at rest), decrypts it, `json.loads` it, normalises every asset in Python (`_scan_report_inventory_rows`), then filters, sorts and pages the resulting list in memory. There is no cache on any step. Every page, every sort change, every keystroke in the search box while that source is selected repeats it. Facets with the same source take the same 2.4 s cold (then hit a 30 s cache).

**3.3.3 History report — 1.2 s with `include_files=false`.** `/api/history/{scan_id}/report` calls `read_scan_report` (full decrypt + parse of the 8 MB artifact) and only *then* compacts. With `include_files=true` the response is **44.9 MB** of JSON.

**3.3.4 Authentication opens two database connections per request.** `verify_token` → `is_token_revoked(jti)` (1.5 ms, new `sqlite3.connect`), and for a platform admin with `X-Tenant-ID`, `tenant_exists` (another connect). Neither is cached. Against a 503 MB file each `connect()` re-reads the schema. Combined with the request itself, a typical `/api/inventory` call opens **six connections**.

**3.3.5 Readiness probes per request.** `_read_inventory_from_normalized` runs two existence queries on every inventory read to decide between the normalised and blob paths (1.5 ms; cheap, but it is a decision that changes once per scan, not once per request).

**3.3.6 Remediation aggregates.** Each queue page load returns `summary` and `facets` alongside the rows. Uncached, those are: summary aggregate **38 ms** (a `COUNT(DISTINCT asset_id)` temp b-tree), frameworks `json_each` **41 ms**, severity `CASE` sort **27 ms** (temp b-tree — the expression is not indexable). A 15 s in-memory cache hides this today; it will not at 10× the findings.

**3.3.7 Two of the listed API payloads are large and repeated.** `compliance-keywords` returns 740 KB and is fetched three times at boot; `inventory` returns 109–203 KB per page uncompressed (the row carries `finding_types`, `framework_keys`, `top_frameworks` as JSON strings plus full paths).

### 3.4 Database

| Measure | Value | Comment |
|---|---|---|
| File size | **503 MB** | for 1,369 assets across three tenants — ~367 KB per asset |
| `finding_index.response_json` | **188 MB** | per-scan copy of every finding's full response, 59,488 rows, ~3.2 KB each. Written on every scan; **never read by any UI path** (history projection). |
| `scan_object_baselines.snapshot_json` | **110 MB** | 3,015 rows, ~37 KB each — incremental-scan baselines. Read only at scan time. |
| `assets.detail_json` | **62 MB** | the per-asset blob from §3.3.1 |
| Everything else | ~25 MB | findings 9.6, occurrences 8.2, FTS 4.4, assets metadata, reports (artifacts live on disk: 46 MB) |
| `journal_mode` | `delete` | rollback journal: every commit writes pages twice, readers block during the commit's exclusive phase |
| `synchronous` | `2` (FULL) | fsync per commit |
| `cache_size` | `-2000` (2 MB) | default; against a 503 MB file the working set is evicted constantly |
| `busy_timeout` | 5,000 ms | set |
| `sqlite_stat1` | **absent** | `ANALYZE` has never run; the planner is guessing (it guesses correctly today because the schema is simple) |
| freelist | 48 pages | no bloat; VACUUM would not help |

The size matters less for query speed (the hot tables are small and index-served) than for the page cache: with 2 MB of cache and a 503 MB file, every cold query pays disk reads, and the 62 MB of `detail_json` that §3.3.1 reads per page is the most-evicted part.

**Locking, measured.** A 20 MB transaction committed from a second connection while a reader loop hit `/api/inventory/facets`: writer commit 262 ms; reader latencies during it **5–25 ms**. In DELETE mode readers are only excluded during the commit's exclusive phase, which is short even for a scan-sized write. A real scan save is one transaction — assets upsert, findings, `finding_index`, baselines, FTS triggers — and writes on the order of 10–20 MB; expect a 100–300 ms reader stall per scan save, not a freeze. Moving to WAL removes even that and halves write I/O.

### 3.5 What is already right

Worth stating so the roadmap does not re-solve it:

- **Keyset pagination** on both tables with composite `(tenant, sort, id)` indexes — every list query is a covering-index range scan, 0.3–3 ms.
- **FTS5 trigram** search on assets — a 3-char substring search is 2.3 ms.
- **Every hot query plan** is index-served; no full scans, no correlated subqueries in the read path.
- **All 94 routes are sync `def`** — FastAPI runs them in the threadpool; the event loop is never blocked by SQLite.
- **Bounded reads everywhere** — page caps, count caps, batch caps, export batches. The design intent is right; the cost is in what happens around the query.
- **Server-side caches** exist for counts (5 s), facets (30 s) and remediation aggregates (15 s), with invalidation on save.

---

## 4. Scale projection

Tenant 23 is small: 463 assets, 6.8k current findings. A realistic customer estate is 10–50× that. What each finding does at 10×:

| Finding | Today | At 10× (≈4.6k assets / 68k findings / ~5 GB DB) |
|---|---|---|
| Style recalc (3.1.2) | 62 ms | unchanged — it is per-document, not per-dataset; still 62 ms |
| Findings render (3.1.3) | 320 ms / page | unchanged per page — but every interaction still pays 3.1.2 |
| Boot fan-out (3.2) | 3.0 MB, ~2 s | history report and hash-changes scale with scan size: 5–10 s |
| Inventory detail re-read (3.3.1) | 127 ms, 11 MB | unchanged per page (bounded to 100 rows), but page cache evictions make it disk-bound: 300–500 ms |
| Named-scan filter (3.3.2) | 2.3 s | artifact 80 MB → **20–30 s per page**; the request will time out |
| History report (3.3.3) | 1.2 s | 10–15 s; `include_files=true` → 450 MB response |
| Remediation aggregates (3.3.6) | 27–41 ms | 300–400 ms each, three per page, cache expiring every 15 s |
| `finding_index` + baselines (3.4) | 298 MB | ~3 GB of write-only history; each scan commit writes 100+ MB |
| Scan commit reader stall (3.4) | ~25 ms | 1–3 s per scan save in DELETE mode |

The two items that go from "slow" to "broken" at scale are the named-scan filter and the history report. Both have the same fix (§5, Phase 0.5).

---

## 5. Roadmap

Ordered by return on effort. Each item names the measure that proves it landed. Nothing here deletes a feature; several items delete *rules* and *work*.

### Phase 0 — a day of work, no design risk

| # | Change | Where | Expected gain | Verify with |
|---|---|---|---|---|
| 0.1 | **Add `GZipMiddleware`** (minimum size ~1 KB). | `backend/app.py` | 1.5 MB of assets → ~250 KB; API payloads −70–80% | resource timing `transferSize` on boot |
| 0.2 | **Gate the boot fan-out to the visible tab.** Boot loads `executive-dashboard`, `inventory/facets`, `history`, `profile`, `health`. Everything else loads when its tab is first shown (a `loadedTabs` set in `switchTab`). Drop the second inventory fetch for the hidden Findings tab. | `app.js` boot block (~9118) and `switchTab` | Boot API calls 18 → 5; ~2.2 s of server work deferred; 9,685 nodes not built | `performance.getEntriesByType('resource')` count on boot; `#tab-findings` node count = 0 until opened |
| 0.3 | **Stop rendering hidden panels.** `renderRows`, `renderRemediationWorkspace`, `renderFindingsWorkspace` etc. return early when their panel is not active; render on activation. | `app.js` render entry points | Document 17.5k → ~4–5k nodes; forced recalc 62 ms → ~15–20 ms | the forced-recalc probe in A.6; long-task count on tab switch |
| 0.4 | **Persist `reason_count` and `dlp_count` on `assets`** at write time (they are derived from `detail_json` that is already in hand when the row is upserted), add them to `_INVENTORY_COLS`, and drop `inventory_reason_action_counts` from the endpoint and the `/api/inventory-detail-counts` follow-up. | `store.py` `_dual_write_normalized`, `_INVENTORY_COLS`, `app.py:2016`; one-off backfill script | `/api/inventory` 165 ms → ~35 ms; 11.3 MB less I/O per page; one fewer request per page | endpoint timing; `bytes read` via the profile in A.2 |
| 0.5 | **Cache parsed report artifacts** in-process, keyed `(tenant, scan_id)`, LRU of ~4 reports. Both `_scan_report_inventory_rows` and `read_scan_report` go through it. Make `include_files=false` skip the `files` parse (store the compact summary alongside the artifact at save time). | `store.py` `_report_body`, `_scan_report_inventory_rows`, `save_scan_history` | Named-scan filter 2.3 s → ~30 ms after first page; history report 1.2 s → ~10 ms | endpoint timing cold/warm |
| 0.6 | **SQLite pragmas on connect:** `journal_mode=WAL` (once, persistent), `synchronous=NORMAL`, `cache_size=-65536` (64 MB), `temp_store=MEMORY`, `mmap_size=268435456`. Run `ANALYZE` after each scan save and `PRAGMA optimize` on close. | `backend/db.py connect()` | readers never block on commits; write I/O halved; cold queries served from cache; planner has statistics | `PRAGMA journal_mode` returns `wal`; reader latency during the A.5 test → 0 stalls |
| 0.7 | **Cache token revocation and tenant existence** for ~30 s in-process (revocation is written by the same process; invalidate on revoke). | `security.py`, `store.py` | −2 connections and ~3 ms per request | connection count per request (A.2) |
| 0.8 | **Cache the readiness probes** per tenant, invalidated on save. | `store.py _inventory_ready`, `_normalized_ready` | −2 queries per read | as above |

Phase 0 leaves the product looking identical. It removes about 70% of the perceived slowness: boot from ~2 s of server work and 3 MB to ~0.3 s and ~0.4 MB; inventory page from 165 to ~35 ms; the named-scan filter from 2.3 s to 30 ms; and — through 0.3 — the freeze tax from 62 ms to ~20.

### Phase 0 — shipped 2026-09-07

All eight items landed. Measured the same way as §2, on tenant 23, after.

| Metric | Before | After | Target | |
|---|---|---|---|---|
| Boot: API calls | 18 | **10** | ≤ 5 | partly |
| Boot: transfer | 3,047 KB | **160 KB** | ≤ 400 KB | met |
| Boot: DOM nodes | 17,492 | **3,360** | ≤ 6,000 | met (beats the Phase 1 target too) |
| Forced style recalc (median of 9) | 62.1 ms | **33.2 ms** | ≤ 25 ms | not met |
| `/api/inventory` (100 rows) | 165 ms / 109 KB | **33 ms / 6.9 KB** | ≤ 40 ms / ≤ 30 KB | met |
| `/api/inventory?source=<scan>` | 2,450 ms | **17 ms** | ≤ 50 ms warm | met |
| `/api/inventory/facets` | 75 ms | **17 ms** | — | |
| `/api/findings` (50 rows) | 190 ms / 76 KB | **14 ms / 8.2 KB** | — | |
| `app.js` / `styles.css` on the wire | 545 / 745 KB | **129 / 114 KB** | — | |
| Reader stall during a 20 MB commit | 25 ms | **8–23 ms typical, 79 ms peak** | 0 | partly |
| Findings panel nodes while hidden | 9,685 | **117** | — | |

**Where the targets were missed, and why.**

*Style recalculation, 33 ms against a 25 ms target.* Halving the document did
not halve the cost, which is the useful finding: recalc is nodes × rule
complexity, and the rule side is untouched — still 4,543 rules with 3,790
`!important`, 477 `:not()` and 108 `:has()`. The remaining nodes are static
markup in `index.html` (`tab-logic` 1,604, `tab-endpoint` 917,
`tab-file-servers` 915) that no render gate can remove. Both are Phase 1 work
(1.4 and, implicitly, moving those panels' markup out of the boot document).

*Boot API calls, 10 against a target of 5.* Five are the dashboard's own
(`profile`, `health`, `history`, `executive-dashboard`, `inventory/facets`)
plus `scan-profiles`, `tenants` and one inventory page. The remaining two —
`history/hash-changes` and the newest saved report, 2.3 s each — still fire,
but they no longer block: they start after the dashboard has painted and
re-render their own panels when they land. Removing them entirely means moving
what they feed onto the tabs that use them.

*Reader stall, 79 ms peak.* WAL removed the commit-phase exclusion, and the
typical reader now sees 8–23 ms during a 20 MB write. The 79 ms outlier is the
first request after the writer's checkpoint. Better than the 25 ms floor
before only in that it no longer scales with the size of the write.

**Two bugs found while doing the work**, both latent before and both exposed by
removing the boot fan-out:

1. `renderRemediationWorkspace` is called by top-level code that runs about two
   thousand lines above where the deferral map was first declared. A `const` is
   in the temporal dead zone until its own line executes, so the render threw,
   the throw was swallowed by a `.catch(() => {})`, and the queue showed a
   loading skeleton for the life of the page. The state is declared with the
   rest of the module's state now. This is the same family as the blank-page
   trap recorded in the frontend roadmap: in one long script, *where* a
   declaration sits is a correctness property.
2. `loadRemediationFindings` returned from its `AbortError` branch without
   clearing the `remediationLoading` flag it had set. Harmless while boot always
   followed with another load; once the queue stopped loading at boot, one
   superseded first attempt left the flag true forever and the tab's own loader
   then declined to run. An abort before the fetch starts also leaves no
   resource-timing entry, which is why the network panel showed no request at
   all. The newest request now owns the flag, and opening the tab asks for data
   whenever it has none.

**Behaviour changes worth knowing:**

- The database is three files now (`dspm.sqlite`, `-wal`, `-shm`). A manual
  copy of `data/` must take all three. WAL needs real file locking, so an
  install whose data directory is on an SMB/NFS share must set
  `DSPM_SQLITE_JOURNAL_MODE=delete`.
- `synchronous=NORMAL` under WAL: a power loss can cost the last transaction,
  never the file.
- Token revocation is cached for 30 s in-process and cleared when this process
  revokes. A multi-worker deployment does not share that cache, so set
  `DSPM_TOKEN_REVOCATION_CACHE_SECONDS=0` there.
- `assets.reason_count` / `assets.dlp_count` are new columns, filled for
  existing rows by `scripts/backfill_asset_detail_counts.py` (run: 1,369 rows).
  The blob fallback stays for anything the backfill has not reached.
- `store.refresh_read_model_state()` resets the cached "is the normalized
  mirror ready" answer. Every in-process transition invalidates it already;
  call it after changing the rows by any other route.

New settings, all bounded and all optional: `DSPM_SQLITE_JOURNAL_MODE`,
`DSPM_SQLITE_CACHE_KB` (64 MB), `DSPM_SQLITE_MMAP_MB` (256),
`DSPM_TOKEN_REVOCATION_CACHE_SECONDS` (30), `DSPM_READINESS_CACHE_SECONDS` (60),
`DSPM_SCAN_REPORT_ROWS_CACHE` (4 projections).

`tests/test_performance_phase0.py` holds the invariants, each naming the
measurement that justified it.

### Phase 1 — the real fix for the freezes (one to two weeks)

| # | Change | Expected gain |
|---|---|---|
| 1.1 | **Row markup diet.** Render only the chips that fit (the meta line already does this with a `+N`; do the same for finding chips — cap at 3 + `+N`); replace the five inline SVGs per row with `<use href="#…">` references to one sprite (already how the dashboard does it); shorten per-row `aria-label`s to the control name (the row's accessible name comes from the row). | 6.8 KB → ~2 KB per row; 110 → ~45 nodes; render long task 320 → ~90 ms |
| 1.2 | **Render in chunks.** Split the 100-row `innerHTML` into 25-row batches across `requestAnimationFrame`, or build with a `DocumentFragment`. | no long task > 50 ms on page load |
| 1.3 | **Render the queue once per load.** Keep the loading state as a class on the existing table rather than replacing the workspace; rebuild facet selects only when the facet payload changed (compare a hash). | 94 ms → ~20 ms per load |
| 1.4 | **The stylesheet diet — finish F3.** The frontend roadmap already moves pages onto the contract sheets and deletes the legacy rules they replace. The cascade census (§3.1.2) is the argument for finishing it: every `:root:root`/`!important` layer deleted is recalc time back. Priority targets, by cost: the 108 `:has()` selectors (replace with a class set from JS where the state is known), the 477 `:not()` chains, the 988 four-plus-compound descendant selectors. Measure the forced recalc after each page's migration. | forced recalc 62 ms → target ≤ 10 ms with the DOM diet; `styles.css` 745 KB → ≤ 200 KB |
| 1.5 | **Split `detail_json`.** Keep a small `detail_json` (risk, compliance summary, preview flags: ~5 KB) and move `findings` (102 KB), `canonical_entities`, `framework_mapping` and `evidence` to a `asset_details` table read only by the detail modal's tabs. | `assets` 62 MB → ~7 MB; the modal's lazy fetch already exists |

### Phase 1 — shipped 2026-09-07 (1.1–1.4; 1.5 not started)

| Metric | Before Phase 1 | After | Target | |
|---|---|---|---|---|
| Inventory row | 6,758 B / 110 nodes | **4,545 B / 63 nodes** | ~2 KB / ~45 | not met |
| Findings tbody (100 rows) | 588 KB | **430 KB** | — | |
| Opening Findings, longest task | 1,156 ms | **101 ms** | ≤ 50 ms | not met |
| Queue filter change, longest task | ~94 ms | **none recorded** | ≤ 20 ms | met |
| Forced style recalc (median of 9) | 33.2 ms | **26.4 ms** | ≤ 10 ms | not met |
| `styles.css` | 718 KB, 4,135 rules | **596 KB, 3,377 rules** | ≤ 200 KB | not met |
| CSS rules in the document | 4,543 | **3,836** | — | |
| Boot transfer / API calls | 160 KB / 10 | **186 KB / 12** | — | +1 call, see below |

**1.1 Row diet.** The finding-chip set rendered every chip — 27 of them, 2,524
bytes and 54 nodes — while the `+N` button beside it had always been computed
against a cap of four that the markup never applied. It applies now, so the row
shows what the count claims. The two inline SVGs per row (five elements, 744
bytes of path data, repeated a hundred times a page) became `<use>` references
to two new sprite symbols with the same geometry, and the per-row `aria-label`s
dropped the file name the row already announces.

**1.2 Chunked render.** 25 rows per write, the first chunk synchronous so the
table still appears in the frame it always did. Two things worth recording:
`requestAnimationFrame` does not fire in a hidden document, so the first version
stalled at 25 rows whenever the operator switched away — the scheduler falls
back to a timeout; and a newer render takes ownership by token, so a re-render
mid-flight abandons the old one instead of interleaving with it.

**1.3 One render per load.** A filter change used to replace the table with a
skeleton and then rebuild it, and rebuild nine facet selects from `innerHTML`
whether or not the facets had changed. The table now dims (`.is-refreshing`)
and keeps its rows; the selects rebuild only when the facet payload differs.
That also removes the change events a rebuild fired, which is what stranded the
queue's loading flag at boot in Phase 0.

**The 1,082 ms nobody had measured.** Opening Findings still cost over a second
after the row diet, and it was not the rows: `renderExecutiveExperience` — the
*dashboard's* renderer — ran on every scan restore and workspace hydrate from
whichever tab was open. Its cost is not markup either. Four cards each write
DOM and then read a geometry property, so each one forces a full style
recalculation and layout: `refitDashboardLists` 340 ms, `renderDataClassesCard`
285, `renderLocationsCard` 272, `renderPostureCard` 269 — suspiciously uniform,
which is the signature of layout thrash rather than of work. It is deferred to
its own tab now, like every other renderer.

That deferral exposed a real coupling: the dashboard's top-risk card counts
*per file*, so it needs the 200-row workspace slice that boot used to fetch for
the Findings tab. Deferring the slice emptied the card. The dashboard asks for
the slice itself now (`hydrateWorkspaceSlice({ force: true })`), which is why
boot is one request larger than after Phase 0 — the honest cost of a card that
needs file-level data.

**1.4 Unreachable CSS.** 758 rules, 121 KB, whose class and id tokens appear in
no HTML and no JavaScript this product ships. Method, and its two corrections,
because the naive versions would have deleted live rules:

- A DOM test ("does this selector match anything on screen") called 2,539 rules
  dead — including every `.login-*` rule, which belongs to a different
  document, and everything a modal or drawer only creates when opened. Replaced
  with a *presence* test over the union of every HTML file that loads this
  sheet and every script that generates markup: a token found anywhere, even
  inside a template string, keeps its rule.
- The rule parser read a comment sitting above a rule as part of its selector,
  so a class name mentioned in prose became a required token. Selectors are
  read from after the last comment close now.
- 16 tokens appear as substrings but not as whole words — the shape of a class
  assembled at runtime (`"remediation-row-" + id`). Weak evidence is enough to
  keep a rule, so they were whitelisted.

One stale contract fell out of it: `.inventory-expanded-grid` was asserted by a
test but exists in no markup — the row expands into the asset detail modal now.

**Where the targets were missed.** The row is 4.5 KB, not 2 KB: what remains is
the path, the name, the meta line, three detail buttons and the badges — data,
not decoration. Opening Findings is 101 ms, not 50: the remaining cost is the
deferred renders landing together plus the layout they force. Recalculation is
26 ms, not 10, and `styles.css` is 596 KB, not 200: deleting what is
unreachable is the safe half of 1.4. The rest — 3,790 `!important`, 477
`:not()`, 108 `:has()`, 345 `:root:root` — is *reachable* CSS that F3 has to
replace page by page, which is the frontend roadmap's own work and cannot be
done by a script.

**Not started: 1.5 (split `detail_json`).** `assets.detail_json` is still 62 MB.
Since Phase 0 the inventory list no longer reads it, so it is storage weight
rather than request latency; it belongs with the Phase 2 storage work.

### Phase 2 — storage and write path (one week)

| # | Change | Expected gain |
|---|---|---|
| 2.1 | **Compress `finding_index.response_json` and `scan_object_baselines.snapshot_json`** (zlib at write, ~6–8× on this JSON) and give `finding_index` a **retention window** (keep the last N scans per tenant in full; older ones keep status rows only). Both are write-only for the UI. | 298 MB → ~40 MB; scan commits 5–8× smaller; DB file ~500 MB → ~120 MB |
| 2.2 | **Report artifacts: store the compact summary and a per-asset index alongside the blob** so `read_latest_scan_report_by_label` can answer a page without decrypting 8 MB. | named-scan filter O(page) instead of O(report), even cold |
| 2.3 | **Remediation aggregates at scale.** Maintain the summary counters incrementally on status change (a small `remediation_counters` table) instead of re-aggregating 68k rows every 15 s; give the severity sort an integer `severity_rank` column with an index. | summary 38 → <1 ms; severity sort 27 → 0.3 ms; holds at 10× |
| 2.4 | **Coalesce facets.** `/api/inventory/facets` runs twelve GROUP BY queries; four can be one query with conditional aggregates. Minor today, matters at 10×. | 75 → ~30 ms cold |

### Phase 2 — shipped 2026-09-07 (2.1–2.3; 2.4 measured and skipped)

| Metric | Before | After | Target | |
|---|---|---|---|---|
| Database file | 523.5 MB | **143.4 MB** | ~120 MB | close |
| `assets.detail_json` | 61.7 MB | **10.0 MB** | ~7 MB (1.5) | met by other means |
| `scan_object_baselines.snapshot_json` | 110.1 MB | **18.4 MB** | — | |
| `finding_index.response_json` | 187.6 MB | **37.1 MB** | — | |
| Severity sort | 29.1 ms | **0.1 ms** | 0.3 ms | met |
| Affected-files count | 34.5 ms | **8.2 ms** | — | |
| `remediation_summary` | 38 ms | **31 ms** | <1 ms | not met |
| Named-scan filter, cold | 2,328 ms | **22 ms** | O(page) | met |

**2.1 Compression, and why not the way the plan assumed.** The plan expected
6–8× from zlib. Measured per row on this data: 5.6× for the baselines, 5.7× for
the detail blobs and only **2.3×** for the finding history, whose rows are
small enough that zlib has little to work with. Base64 — the obvious way to
keep the columns TEXT — would have cost a third of every gain, so these are
BLOBs instead, which SQLite stores unchanged in a TEXT-affinity column.

PostgreSQL is deliberately excluded: TOAST already compresses a large TEXT
value, and storing our own bytes there would trade the server's transparent
handling for a format only `store.py` understands. `pack_json_text` returns the
string unchanged when the backend is Postgres.

Two things the floor protects: `'{}'` must stay text, because two partial
indexes (`idx_assets_tenant_empty_detail`) and the read-model gate compare
against it literally; and below ~2 KB the header costs more than the saving.

The history window did the rest of the work on `finding_index`: keeping the
last five scans per tenant dropped 31,817 response bodies. Older scans keep
their status row, which is what the history views read; only the body goes.

**2.2 A saved run keeps its own projection.** `scan_reports.rows_json` holds
the inventory rows the Source filter pages through, compressed — 0.03 MB for a
run whose report artifact is 8.3 MB. A run saved before the column existed
fills it on first read, so the 2.3-second decrypt-and-normalise happens once
per run rather than once per process. Building it is best-effort: a failure
logs and falls back to the old path rather than costing the operator the scan.

**2.3 Severity as a number.** "Worst first" sorted on a `CASE` expression,
which no index can serve, so SQLite read the whole current set into a temp
b-tree. `findings.severity_rank` with `(tenant_id, is_current, severity_rank,
id)` makes it a range scan: 29.1 ms → 0.1. Both writers stamp it and the
migration backfills existing rows.

The summary's affected-file count was `COUNT(DISTINCT CASE WHEN status IN (…)
THEN asset_id END)`, which cannot use the `(tenant, is_current, asset_id)`
index and built a temp b-tree at 34.5 ms. As a predicate it is an index scan at
8.2 ms.

**The counters table was not built.** The plan called for maintaining the
summary incrementally. `remediation_summary` is 31 ms behind a 15-second cache;
a counters table would have to be updated by every status write, and a counter
that disagrees with the rows is worse than a 31 ms query. It belongs with the
PostgreSQL move, where the aggregate can be a materialised view the database
keeps honest.

**2.4 was measured and skipped.** The twelve facet GROUP BYs total **6.1 ms**,
and the merge the plan suggested — three trivial queries into one conditional
aggregate — measured 0.22 ms against the 0.26 ms they cost separately. Writing
code to save 0.04 ms is not a change, it is noise. The one query worth
remembering is the `source` group-by at 5.7 ms, which cannot use
`idx_assets_tenant_source` because it filters on `COALESCE(scan_label,'') = ''`;
if facets ever become hot, that predicate is the thing to fix.

**1.5 is now closed by other means.** The plan was to split `detail_json` into
an `asset_details` table. Compressing it took 61.7 MB to 10.0 with no schema
change, no migration of the detail modal's read path, and no second table to
keep consistent. The split is still available if the modal ever needs to read
parts of the blob independently, but it is no longer a storage argument.

**Operational:** `scripts/compact_json_columns.py` rewrites existing rows,
applies the window and VACUUMs (it needs room for a second copy of the file
while it runs). Re-runnable. New settings: `DSPM_JSON_COMPRESS_MIN` (2048),
`DSPM_FINDING_INDEX_KEEP_SCANS` (5, 0 disables the window).

### Phase 3 — scale (when a customer estate crosses ~20k assets)

| # | Change |
|---|---|
| 3.1 | **PostgreSQL** — already supported behind `DSPM_DB_URL` with pooling and RLS seams. The SQLite improvements above buy time; Postgres buys concurrency (multiple uvicorn workers) and a real planner. |
| 3.2 | **Row virtualisation** for the inventory and the queue — see §6. Only worthwhile after Phase 1 has cut the per-row cost; virtualising 6.8 KB rows just moves the problem. |
| 3.3 | **Multiple workers** (`uvicorn --workers N`) once the DB is Postgres or WAL SQLite with the in-process caches made process-safe (or dropped in favour of the DB). |

### Phase 3 — started 2026-09-07 (3.1 partly; 3.3 shipped; 3.2 declined)

This phase was written as "when a customer estate crosses ~20k assets". The
estate here is 463. Two of its three items turned out to be worth doing anyway,
for reasons that are not about scale, and the third is worth *not* doing — with
numbers.

**3.1 PostgreSQL — one real bug found, live verification blocked.**

Phases 0–2 added SQLite-specific behaviour (zlib blobs, pragmas, ANALYZE), so
the PostgreSQL path needed re-checking. It did not survive: Phase 2 declared
`scan_reports.rows_json` as **`BLOB`**, and `translate_schema` rewrites exactly
two constructs — `AUTOINCREMENT` and `REAL`. PostgreSQL has no `BLOB` type, so
**every PostgreSQL install would have failed at `init_db`**. The column is
`TEXT` now, like the other three compressed columns: SQLite stores a blob
unchanged in a TEXT-affinity column, and PostgreSQL keeps plain text there
because `pack_json_text` returns the string unchanged on that backend (TOAST
does the compressing).

Nothing caught it because the live PostgreSQL suite requires a reachable
server, and it had never run on this machine. `PortableSchemaTests` now
asserts, offline, that every declared column type is one the seam can
translate — so the next `BLOB` fails in CI rather than at a customer's first
start.

The live run is blocked, not skipped. PostgreSQL 18 is running locally and the
app role connects (`sentro_app@sentro_dev`), but `init_db` stops at
`permission denied for schema public` — PostgreSQL 15+ revoked `CREATE` on
`public` from `PUBLIC`, and this role was never granted it. Fixing that needs
an admin connection, and the test suite additionally refuses to run against a
PostgreSQL DSN without `DSPM_PG_TEST_RESET=1` because it truncates for
isolation. Neither is mine to decide: granting privileges and wiping a database
are the operator's calls.

**3.3 Multiple workers — shipped, as a safety property rather than a speedup.**

`main.py serve` takes `--workers` now. The reason it did not before is that
Phase 0 bought its speed with caches that live in one process and are
invalidated by that same process. With several workers each keeps its own copy,
so a write in one is invisible to the others until the entry expires. Three of
those are a staleness question; **one is a security question** — a token
revoked in worker A would still be accepted by worker B for up to 30 seconds.

So asking for workers turns them off, before uvicorn starts, rather than
printing a warning the operator may not read:
`DSPM_TOKEN_REVOCATION_CACHE_SECONDS`, `DSPM_TENANT_EXISTS_CACHE_SECONDS`,
`DSPM_READINESS_CACHE_SECONDS`, `DSPM_INVENTORY_COUNT_CACHE_SECONDS`,
`DSPM_INVENTORY_FACETS_CACHE_SECONDS`. The tenant-existence cache had a
hard-coded 30-second TTL and no off-switch; it has one now. `--reload` with
`--workers` is refused rather than silently ignoring one of them, and asking
for workers on SQLite says plainly that readers scale while writers still
serialise across processes.

**3.2 Row virtualisation — declined, and the reason is a number.**

The audit said this was "only worthwhile after Phase 1 has cut the per-row
cost". Phase 1 cut it: a row is 4,545 bytes and 63 nodes, and 100 of them
render in 31 ms inside a 101 ms tab open. Virtualising to the ~20 rows on
screen would save perhaps 25 ms of that.

The argument against is stronger than the small saving, though. **The page is
bounded at 100 rows by keyset pagination, whatever the estate holds** — 463
assets or 46,000. So unlike every other item in this roadmap, virtualisation's
benefit does not grow with scale; it is a fixed ~25 ms. Against that it wants
scroll-position management, a sticky header, keyboard navigation and
find-in-page behaviour on a table whose first column is frozen at `left: 0` —
the one component the frontend roadmap already records as un-borrowable.

It becomes worth doing if the page size is raised (the API caps at 500). Until
then it is complexity bought with someone else's money.

### Polish pass — 2026-09-07: the items each phase record marked "not met"

| Item | Before | After |
|---|---|---|
| Saved report at boot (`include_files=false`) — 0.5, second half | 1,429 ms cold (decrypt + parse 8 MB to discard the files) | **20–38 ms**, served from `scan_reports.compact_json` |
| `hash-changes` at boot — 0.2, last item | 1.1 s on the boot path | **not at boot**; loads once when Findings first opens |
| Workspace slice fetches (boot + Findings open) | **5** (3 before the first landed, 2 more on open) | **1** |
| Boot API calls / transfer | 12 / 186 KB | **10 / 329 KB** (see note) |
| Slowest boot call | 2,323 ms (report) | **88 ms** (`inventory/facets`) |
| `PRAGMA optimize` at shutdown — 0.6 | scan-save half only | wired in the lifespan `finally` |

**The compact report is stored, not derived.** `compact_scan_report` moved from
`app.py` into the store so the save path can call it; the metadata-only form
(everything but the file array, ~6 KB on the wire) is written with the run and
filled on first read for runs saved before the column existed — the same
pattern as `rows_json`. Building it is best-effort: a failure logs and the
endpoint falls back to the full read.

**Boot transfer went *up* (186 → 329 KB) while the call count went down.**
That is the 200-row workspace slice now arriving once, at boot, because the
dashboard's top-risk card asks for it (Phase 1) — previously it arrived after
the measured window or several times. One honest fetch of data the visible
card needs, versus three racing ones, is the right trade.

**A deletion that a call-shaped grep could not see.** `buildScanComparison`
formatted a scan-comparison panel the refit had removed from the page; my
"no callers" check (`buildScanComparison(`) found nothing and the removal
guard agreed. Both were blind to `setPanelHtml(scanComparison,
buildScanComparison)` — the builder passed **by reference**, no paren — inside
`renderExecutiveExperience`. `setPanelHtml` null-guards its target, but the
argument is evaluated first, so every dashboard render raised `ReferenceError`
at that line until the call and its orphaned `#scan-comparison` handle were
removed. The suite cannot catch this (nothing executes `app.js`); the browser
did, and the contract now asserts the bare identifier is absent. Rule for the
file: a dead-code check must grep the *name*, not the *call*.

**Two things looked broken and were not.** The "Duplicate hash path" flag is
rendered — as the `+1` on the meta line whose title carries it, exactly as
Request G designed the line; a `.hash-change-chip` count is the wrong probe.
And the hash *summary* text never appeared because its only formatter was the
unmounted builder above; the comparison's live job — flagging rows — was
never affected.

**Left as recorded, deliberately.** `hash-changes` still costs 1.1–1.3 s
server-side when Findings opens: it decrypts the two newest artifacts to diff
path→hash maps. The right fix reads `asset_versions` instead, but that table
is keyed by version rather than by scan, so it is a redesign of the endpoint,
not a polish. `remediationLoading` can still end up `true` after boot from an
abort-before-fetch; the guard no longer reads it, and no top-level caller
could be identified, so it is inert and noted rather than chased. 2.3's
counters table, 2.4 and 3.2 stand declined with their numbers. 3.1's live
PostgreSQL run stays blocked on an admin grant and a truncation consent that
are the operator's to give.

### Sequencing and risk

- Phase 0 items are independent of each other and of everything else; ship them in one release. 0.4 needs a backfill script (`reason_count`/`dlp_count` from existing `detail_json`; a few seconds on this data) — run it in the migration runner the DB roadmap already has.
- 0.6 (WAL) is a one-way switch on the file; take a backup first (the backup module exists). WAL requires the `-wal`/`-shm` sidecars to live next to the DB and be covered by the same 0700 directory permission — `_harden_db_permissions` already does this.
- Phase 1.4 is the only item with regression risk (cascade changes). The frontend contract tests and the "measure the winner before writing a rule" discipline in the frontend roadmap are the guard; migrate one page at a time and re-run the forced-recalc probe after each.
- Nothing in this roadmap removes a feature, a filter, a widget or a table.

---

## 6. On TanStack, virtualisers and external code

**The question was whether to adopt a query/table library.** The measurements say no, for three reasons:

1. **The costs are not in the table.** Server queries are 0.3–41 ms. The slow parts are 17.5k DOM nodes that are not the table, a 4.5k-rule cascade, an 18-call boot, and a 127 ms detail re-read. TanStack Table would sit inside the same document and the same cascade and pay the same 62 ms.
2. **Pagination and sorting are already server-side and correct.** A client-side table model would either duplicate that (two sources of truth for sort/filter state) or be reduced to a renderer, which is the part that needs the diet, not a library.
3. **The frontend has no build step or package manager.** Adopting TanStack means introducing one, or vendoring a UMD build — a large change for a product that is deliberately self-contained.

**The one library worth considering** is a row virtualiser (render only the ~20 rows in view; recycle on scroll). It is small (TanStack Virtual's core is ~4 KB, others similar) and can be vendored as a single local file — no CDN, no network, consistent with the CSP (`script-src 'self'`) and with the sensitivity of what the tables show. It belongs in Phase 3, after Phase 1: virtualising rows that cost 6.8 KB and 110 nodes each helps less than making them cost 2 KB and 45.

**External sources generally.** Every recommendation above is local: gzip in the existing middleware stack, pragmas on the existing connection, caches in the existing process, columns in the existing tables. No new service, no telemetry, no CDN. The one optional dependency (a virtualiser) would be vendored and reviewed like any other file in `frontend/`.

---

## 7. Acceptance targets

Measured the same way as §2, on tenant 23, after each phase:

| Metric | Today | After Phase 0 | After Phase 1 |
|---|---|---|---|
| Boot: API calls / transfer | 18 / 3.0 MB | ≤ 5 / ≤ 0.4 MB | same |
| Boot: DOM nodes (Dashboard visible) | 17,492 | ≤ 6,000 | ≤ 4,000 |
| Forced style recalc | 62 ms | ≤ 25 ms | ≤ 10 ms |
| Findings: open tab, longest task | 320 ms | ≤ 150 ms | ≤ 50 ms |
| `/api/inventory` (page of 100) | 165 ms / 109 KB | ≤ 40 ms / ≤ 30 KB gz | same |
| `/api/inventory?source=<scan>` | 2.3 s | ≤ 50 ms warm | ≤ 50 ms cold (2.2) |
| `/api/history/{id}/report` compact | 1.2 s | ≤ 20 ms | same |
| Reader stall during a 20 MB commit | 25 ms | 0 ms (WAL) | same |
| DB file | 503 MB | same | ~120 MB (2.1) |

---

## Appendix A — raw measurements

### A.1 Endpoint timings (harness, tenant 23, ms; cold then two warm)

```
/api/inventory?limit=100                          165   129   144   111 KB
/api/inventory?limit=100&risk=CRITICAL            145   167   169   111 KB
/api/inventory?limit=100&q=email                  152   154   152   114 KB
/api/inventory?limit=100&finding_type=email       140   135   135   114 KB
/api/inventory?limit=100&source=FileServer1      2450  2083  2198   114 KB
/api/inventory?limit=100&sort=name                 78    82    81    69 KB
/api/inventory/facets                              75    14    17     9 KB
/api/inventory/facets?source=FileServer1         2415    13    16     9 KB   (30 s cache)
/api/findings?limit=50                            190    12    16    78 KB
/api/findings?limit=50&severity=CRITICAL           25    35    15    78 KB
/api/findings?limit=50&q=key                       39    14    13    75 KB
/api/findings?limit=50&sort=severity               45    50    54    77 KB
/api/findings?limit=50&category=credentials_secrets 31   16    16    79 KB
/api/executive-dashboard                           10    23    14   1.5 KB
/api/scan-profiles                                 14    17    25     5 KB
/api/nist/catalog/status                           65    57    57   0.6 KB
/api/history/{newest}/report?include_files=false 1221              0.1 MB
/api/history/{newest}/report?include_files=true  1508             44.9 MB
```

### A.2 In-process profile, `store.list_inventory(limit=100)` ×5

16 ms per call: 12 ms `fetchall`, 1.5 ms `_inventory_ready` (2 queries), 4 `_connect()` per call. Endpoint total 165 ms ⇒ ~127 ms in `inventory_reason_action_counts` (confirmed directly: 127.1 ms, 11.3 MB of `detail_json` for 100 ids) + ~6 ms serialisation (`jsonable_encoder` 4.4 ms, `json.dumps` 1.4 ms) + auth (2 connects).

### A.3 Query plans (wall ms, rows)

```
inventory default sort            0.3   COVERING INDEX idx_assets_tenant_risk_score_id
inventory finding_type LIKE       2.1   INDEX idx_assets_tenant_risk_score_id (LIKE on JSON string column)
inventory q via FTS5 trigram      2.3   COVERING INDEX + FTS virtual table
facets finding_types json_each    6.7   idx_assets_tenant_risk_level + TEMP B-TREE
facets locations expr             1.6   idx_assets_tenant_risk_level + TEMP B-TREE
remediation sort=severity CASE   26.9   idx_findings_tenant_current_status_risk_id + TEMP B-TREE ORDER BY
remediation q LIKE search_text    1.0   idx_findings_tenant_current_risk_id
remediation category IN           2.8   idx_findings_tenant_current_risk_id
remediation summary aggregate    37.8   TEMP B-TREE for COUNT(DISTINCT)
remediation frameworks json_each 40.7   TEMP B-TREE GROUP BY
remediation facets owners         1.7   COVERING INDEX
inventory_ready probe             0.1   two covering indexes
```

### A.4 Storage

```
file 503 MB   page_size 4096   page_count 122,681   freelist 48
journal_mode delete   synchronous 2   cache_size -2000   busy_timeout 5000   sqlite_stat1: none

finding_index            191.8 MB   (response_json 187.6)     59,488 rows
scan_object_baselines    111.4 MB   (snapshot_json 110.1)      3,015 rows
assets                    62.8 MB   (detail_json 61.7)         1,369 rows   avg 45 KB, max 164 KB
findings                   9.6 MB                             26,632 rows (11,445 current)
finding_occurrences        8.2 MB                             59,488 rows
assets_search_fts          4.4 MB
artifacts on disk         46 MB     largest 8.3 MB (.enc)

largest detail_json (164 KB): findings 102 KB (26 items), compliance 31 KB,
  canonical_entities 27 KB (32), risk 9 KB, keyword_catalog_status 1 KB
```

### A.5 Lock test

Writer: `BEGIN IMMEDIATE`, 320 × 64 KB inserts (~20 MB), `COMMIT` — commit took 262 ms. Reader loop on `/api/inventory/facets` during it: `25, 7, 5, 7, 23, 22, 7, 22, 6, 22, 17, 22` ms. A reserved lock alone did not stall readers at all (92–213 ms responses were cold-cache reads, not waits).

### A.6 Browser (embedded Chromium, 1600×900, shipped `index.html`)

```
boot: 32 requests, 3,047 KB transferred, domInteractive 213 ms, domComplete 220 ms
      app.js 543 KB  styles.css 745 KB  daisyui.css 123 KB  (uncompressed)
      18 API calls (see §3.2)
document: 17,492 nodes; 6 sheets, 4,543 rules; JS heap 5 MB
forced style recalc (toggle class on body, read offsetHeight): 62.1 ms
tab -> Findings:    1 long task, 320 ms; tbody innerHTML 588 KB for 101 rows
tab -> Remediation: 1 long task,  94 ms; 50 rows
tab -> Dashboard:   1 long task,  77 ms
hidden panels at boot: findings 9,685 nodes, risk 2,623, logic 1,604, endpoint 917, file-servers 915
one inventory row: 6,758 bytes, 110 nodes, 5 inline SVGs (744 B),
  26 finding chips rendered / 0 visible (2,282 B), aria/title text 341 B
styles.css census: !important 3,790; :not( 477; :has( 108; :root:root 345;
  selectors >= 4 compounds 988; [data-…] 585
```

### A.7 Request fan-out (static)

- Findings page open: `/api/inventory` (page) + `/api/inventory/facets` + `/api/inventory-detail-counts` (follow-up). Filter/sort/search change: `refreshInventoryPageWindow()` → the same three, debounced 300 ms on the search box.
- Queue page open / any filter change: `/api/findings` (rows + summary + facets in one response), workspace rendered three times.
- Post-scan: `applyScanReport` → `updateSummaryFromFiles`, `renderRows`, `refreshEstateSummary` (facets), `refreshInventoryPageWindow` (page).
- Scan polling: `/api/scans/{id}` every 1.2 s; the completed payload has `files` stripped (`_shrink_result`) — correct.
- Auth: every request → `is_token_revoked` (DB) and, for platform admins with a tenant header, `tenant_exists` (DB).
