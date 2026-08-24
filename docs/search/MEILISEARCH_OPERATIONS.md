# Sentro S-F Meilisearch Operations Runbook

## Role and safety boundary

Meilisearch is a rebuildable, metadata-only projection. PostgreSQL remains the
authoritative inventory and evidence store. Only text-bearing `q=...` inventory
requests use the valve; all engine errors fall back to the database. The search
document excludes `detail_json` and finding evidence and always applies tenant ID
plus projection-version filters.

The supported package is `deploy/meilisearch/compose.yaml`, pinned to Meilisearch
v1.52.0. Bind to loopback when Sentro and Meilisearch share a host. For a remote
search host, place TLS and network authentication in front of the service and
allow only the Sentro host through the firewall.

## Install

1. Copy `deploy/meilisearch/meilisearch.env.example` to
   `deploy/meilisearch/.env` and replace the master key with at least 32 random
   bytes. Restrict the file to the service account/administrator.
2. Start the pinned service:

   ```powershell
   docker compose --env-file deploy/meilisearch/.env `
     -f deploy/meilisearch/compose.yaml up -d
   ```

3. Put the application key in the Sentro process secret store, not a command
   argument or global machine environment. The key needs index/settings read and
   update, document read/add/delete, search, stats, and task-read access for
   rebuild and reconciliation. Keep the master key out of the application.
4. Configure Sentro with reads disabled:

   ```text
   DSPM_SEARCH_ENGINE=meilisearch
   DSPM_MEILISEARCH_URL=http://127.0.0.1:7700
   DSPM_MEILISEARCH_API_KEY=<application-key>
   DSPM_SEARCH_READ_ENABLED=0
   DSPM_SEARCH_RECONCILE_SECONDS=300
   DSPM_SEARCH_RECONCILE_REPAIR=1
   ```

## Initial build and cutover

```powershell
python -m scripts.reindex_search --rebuild
python -m scripts.reindex_search --check-drift
python -m scripts.reindex_search
```

Enable `DSPM_SEARCH_READ_ENABLED=1` only when reconciliation reports `in_sync:
true`, `remaining_lag_documents: 0`, health reports `index_ready: true`, and the
index version matches the application. Rebuild after every projection-version
change; the current version is exposed by `/api/health`.

## Drift metrics and repair

The app starts one bounded reconciliation worker when Meilisearch is configured
and `DSPM_SEARCH_RECONCILE_SECONDS` is greater than zero. It:

- streams authoritative assets using database keyset batches;
- compares stable SHA-256 projection hashes in bounded document fetches;
- upserts missing/stale metadata when repair is enabled;
- streams engine IDs by keyset and removes search-only orphans;
- persists counts and timestamps in `search_reconciliation_state`;
- exposes the last result under `/api/health.search.reconciliation`.

Manual commands:

```powershell
python -m scripts.reindex_search --check-drift   # read-only; exit 2 on drift
python -m scripts.reindex_search --repair-drift  # bounded automatic repair
```

Alert when `in_sync` is false, `remaining_lag_documents` is non-zero, the last
`checked_at` is older than twice the configured interval, or `is_indexing` stays
true beyond the normal ingest window. A repeated repair failure is an engine
incident; keep reads on the database until resolved.

## Failure behavior

- **Unavailable/timeout:** inventory search automatically falls back to
  PostgreSQL/SQLite. New scans remain committed to the authoritative DB. The
  reconciler fills the missing projection after service recovery.
- **Stale settings/version:** health reports unavailable and instructs an index
  rebuild. Do not force the read switch.
- **Drift:** run `--repair-drift`; if bounded repair repeatedly fails, set
  `DSPM_SEARCH_READ_ENABLED=0` and run `--rebuild`.
- **Corrupt/lost index:** create a clean data volume or index and rebuild from
  PostgreSQL. No evidence recovery depends on Meilisearch.
- **Credential failure:** rotate the application key in the secret store, restart
  Sentro, and verify health. Errors never include the key or service URL.

## Backup and restore

PostgreSQL backup is mandatory; the projection can always be rebuilt. The Compose
package schedules a daily snapshot for fast same-version recovery. Copy snapshots
off-host with the rest of the backup set and test restores periodically.

Use snapshots only with the same Meilisearch version. Before an upgrade, create a
portable dump and wait for its task to succeed:

```powershell
$headers = @{ Authorization = "Bearer $env:DSPM_MEILISEARCH_API_KEY" }
$task = Invoke-RestMethod -Method Post -Headers $headers `
  -Uri "$env:DSPM_MEILISEARCH_URL/dumps"
Invoke-RestMethod -Headers $headers `
  -Uri "$env:DSPM_MEILISEARCH_URL/tasks/$($task.taskUid)"
```

Restore a same-version snapshot with `--import-snapshot`; restore a cross-version
dump with `--import-dump` into an empty data directory. Because Sentro treats the
index as disposable, a clean `--rebuild` is the preferred recovery whenever the
authoritative DB is available.

## Upgrade

1. Set `DSPM_SEARCH_READ_ENABLED=0` and confirm database fallback.
2. Create and export a dump; retain the PostgreSQL backup and current Compose
   image tag.
3. Review Meilisearch release notes and change the pinned image tag deliberately.
4. Start the new version with an empty volume plus `--import-dump`, or follow the
   vendor's supported same-data upgrade path.
5. Run `--rebuild`, `--check-drift`, live tests, and the benchmark before enabling
   reads. Roll back by restoring the old image plus same-version snapshot, or
   leave reads on PostgreSQL and rebuild.

## Certification

Live functional gate:

```powershell
$env:DSPM_MEILISEARCH_LIVE_URL = "http://127.0.0.1:7700"
$env:DSPM_MEILISEARCH_LIVE_KEY = "<test-key>"
python -m pytest tests/test_search_engine_live.py -q
```

Disposable PostgreSQL/Meilisearch capacity gate (database name must contain
`test` or `bench`):

```powershell
$env:DSPM_SEARCH_BENCHMARK_ALLOW_WRITE = "1"
python -m scripts.search_benchmark --documents 1000000 --repeats 20 `
  --output docs/search/SF2_CERTIFICATION_2026-08-05.json
```

The valve is retained only when exact-query top-100 parity, tenant isolation,
typo tolerance, and both p95-under-300-ms gates pass. The harness uses unique
temporary names and removes its PostgreSQL table and Meilisearch index in
`finally`.
