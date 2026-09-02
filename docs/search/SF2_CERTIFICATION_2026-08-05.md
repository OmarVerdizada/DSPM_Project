# Track S-F.2 Certification Record — 2026-08-05

## Status

**Engineering complete; live runtime certification blocked by execution policy.**

The current environment has no Docker, Podman, installed Meilisearch, or WSL
distribution. The official Meilisearch v1.52.0 Windows amd64 binary was downloaded
from GitHub and verified against release metadata:

```text
SHA-256 994184359de4ce2f5d4d628a05a2803354dbc4c27f645c41fa399ac694f81468
```

The environment then rejected launching the downloaded executable. No live
Meilisearch result is claimed in this record.

## Completed gates

- `sf-v3` metadata projection with deterministic SHA-256 projection hashes.
- Tenant-mandatory filters and metadata/evidence exclusion.
- Bounded missing/stale/orphan reconciliation with automated repair.
- Composite-primary-key tenant+ID authoritative lookups in 400-row batches.
- Durable reconciliation metrics exposed through `/api/health`.
- Operator drift-check and repair commands.
- Opt-in live parity, tenant-isolation, typo, repair, and real connection-failure tests.
- Disposable PostgreSQL `pg_trgm` vs Meilisearch million-row p95 harness with
  pre-connect test-database guard and `finally` cleanup.
- Pinned v1.52.0 Compose package and production backup/restore/upgrade/failure runbook.
- Focused SQLite and disposable PostgreSQL suites pass.
- Full repository suite passes; the three live Meilisearch tests skip because
  `DSPM_MEILISEARCH_LIVE_URL` is intentionally unset.

## Required live gate

Start Meilisearch on loopback, then run:

```powershell
$env:DSPM_MEILISEARCH_LIVE_URL = "http://127.0.0.1:7700"
python -m pytest tests/test_search_engine_live.py -q
```

Provision a disposable PostgreSQL database whose name contains `test` or `bench`,
configure `DSPM_DB_URL` and `DSPM_MEILISEARCH_URL`, then run:

```powershell
$env:DSPM_SEARCH_BENCHMARK_ALLOW_WRITE = "1"
python -m scripts.search_benchmark --documents 1000000 --repeats 20 `
  --output docs/search/SF2_CERTIFICATION_2026-08-05.json
```

S-F.2 becomes DONE only when live parity, tenant isolation, typo tolerance, drift
repair, failure fallback, PostgreSQL p95, and Meilisearch p95 gates all pass.
