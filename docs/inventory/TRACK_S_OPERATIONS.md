# Track S operations

This runbook covers the scale data plane from PostgreSQL through normalized inventory, keyset reads, optional Meilisearch, the bounded console, and streaming export. PostgreSQL remains authoritative throughout.

## 1. Prepare and backfill

1. Provision PostgreSQL with `scripts/provision_postgres.py`; this installs `pg_trgm` as the database administrator while keeping the runtime role least-privileged.
2. Deploy the application once so `store.init_db()` creates or migrates the normalized schema and indexes.
3. In a maintenance window, backfill historical reports:

   ```bash
   python scripts/backfill_normalized.py
   # or one tenant
   python scripts/backfill_normalized.py tenant-id
   ```

   Re-run this backfill after the Track S polish upgrade so historical `search_text` values include source, share, risk, finding labels, and framework keys. The operation is idempotent.

4. Confirm `/api/inventory` reports `source: normalized` in staging. Indexed reads are enabled by default on a complete mirror; `DSPM_INVENTORY_FROM_NORMALIZED=0` is the explicit rollback.

Index creation over a multi-million-row existing table can be I/O intensive. Schedule the first post-upgrade startup in a maintenance window. S-C.1 adds composite `(tenant_id, sort, id)` indexes for numeric sorts, exact C-collated expression indexes for text sorts, and a sparse readiness index for missing detail rows.

## 2. Cutover and failure behavior

The default is:

```text
DSPM_INVENTORY_FROM_NORMALIZED=1
```

The readiness gate keeps legacy blob compatibility while the mirror is incomplete, so upgrades remain correct before the maintenance backfill. Once the gate passes and normalized reads are selected, list, facet, and detail failures return HTTP `503` with `Retry-After: 5`; they do not reconstruct an unbounded report blob. An unknown detail ID returns `404` from the indexed lookup without scanning scan history. `DSPM_INVENTORY_COUNT_CACHE_SECONDS` defaults to `5` and reuses a capped filtered total across cursor pages; `0` disables it. Scan saves and backfills invalidate it immediately.

Inventory cursors are opaque, versioned, and bound to the selected sort. Malformed, stale, cross-sort, and Meilisearch cursors safely restart at the first page instead of reaching a database with an invalid comparison type.

To roll back interactive reads, set `DSPM_INVENTORY_FROM_NORMALIZED=0`. This compatibility mode is not the million-object path and should be temporary. PostgreSQL rows remain populated and dual-write continues.

## 3. Verify indexes

PostgreSQL should contain:

```text
idx_assets_tenant_risk_score_id
idx_assets_tenant_size_id
idx_assets_tenant_finding_count_id
idx_assets_tenant_modified_c_id
idx_assets_tenant_name_c_id
idx_assets_tenant_missing_detail
idx_assets_search_trgm
```

The live PostgreSQL tests inspect these definitions and use `EXPLAIN` to prove the default numeric and C-collated text query shapes select their matching indexes.

SQLite compatibility installs an FTS5 trigram index over `search_text` when that tokenizer is available, plus an exact normally-empty partial index for the detail-readiness probe. Both preserve literal substring behavior; a SQLite build without FTS5 safely retains `LIKE`. PostgreSQL `pg_trgm` remains the production-scale path.

## 4. Run the 5M-row acceptance benchmark

Use a disposable database whose name contains `test` or `bench`. The harness refuses every other database name, creates a unique table, and drops only that table in `finally`.

PowerShell:

```powershell
$env:DSPM_DB_URL = 'postgresql://postgres@127.0.0.1:5441/sentro_bench'
$env:DSPM_INVENTORY_BENCHMARK_ALLOW_WRITE = '1'
python -m scripts.inventory_benchmark --documents 5000000 --repeats 20 --output data/benchmarks/track-s-inventory.json
Remove-Item Env:DSPM_INVENTORY_BENCHMARK_ALLOW_WRITE
```

The gate passes only when the corpus contains at least five million rows and first-page, deep-keyset, filtered, and filtered-substring-search p95 are each below 300 ms. The JSON result includes query plans. A smaller corpus is useful as a smoke test but intentionally cannot certify the five-million-row gate.

```powershell
python -m scripts.inventory_benchmark --documents 10000 --repeats 3 --smoke
```

## 5. Bounded browser behavior

The console requests compact scan/history results, holds at most three 100-row page payloads, renders only the current page, and fetches one asset's detail when its drawer opens. Filter changes abort the prior HTTP request, update the selected severity immediately, and reset the cursor stack. A manual row-risk change re-renders the current bounded page without another database query. If normalized inventory is unavailable after a compact restore, the UI reports that no report blob was loaded instead of silently hydrating one.

## 6. Optional Meilisearch valve

Meilisearch is optional and only receives metadata. Keep `DSPM_SEARCH_READ_ENABLED=0` during shadow indexing. Follow [Meilisearch operations](../search/MEILISEARCH_OPERATIONS.md) for rebuild, reconciliation, parity, failure injection, backup, upgrade, and benchmark steps. Search cursors are capped at the configured 10,000-hit API ceiling.

If the engine is unavailable, text search falls back to PostgreSQL `pg_trgm`. S-F.2 remains uncertified until its live suite and million-row comparison run against an operator-started service.

## 7. Streaming export

CSV and NDJSON use normalized, tenant-scoped `id` keysets and bounded response chunks. They never use the report-blob compatibility path. See [Streaming inventory exports](STREAMING_EXPORTS.md) for API examples, browser requirements, proxy buffering, security, and verification.

## 8. Regression commands

```bash
python -m pytest tests/test_inventory_model.py tests/test_inventory_api.py tests/test_inventory_compact_reports.py tests/test_inventory_windowed_frontend.py tests/test_inventory_streaming_export.py tests/test_search_engine.py tests/test_track_s_polish.py -q
```

For PostgreSQL, use a dedicated disposable test database and set `DSPM_PG_TEST_RESET=1`. Never point the test suite at production.
