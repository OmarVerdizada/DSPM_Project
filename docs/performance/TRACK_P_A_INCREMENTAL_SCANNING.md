# Track P-A incremental scanning

Track P-A makes incremental scanning the default for file-server and endpoint scans. It is a
cross-source engine contract, not an SMB-only cache shortcut. SQLite and PostgreSQL implement
the same schema and behavior; PostgreSQL is the production durability target.

## Operator behavior

The console enables **Incremental scan** by default. The API field is:

```json
{"incremental_enabled": true}
```

Set it to `false`, or clear the console checkbox, to force a full content/hash/owner/ACL scan.
A successful full scan still refreshes the durable baseline for the next incremental run.
Use a scheduled full scan when source mtimes are not trustworthy or policy requires periodic
byte verification.

An object is reusable only when tenant, enumeration scope, source-qualified object identity,
size, mtime, and policy version match. The policy version covers parser/detector/catalog,
enabled frameworks, asset overrides, detector timeout posture, and OCR settings. A mismatch
is classified as changed and takes the normal full path.

## Source behavior

- Local and SMB collectors probe after directory metadata and before owner, ACL, content,
  hashing, OCR, or classification work.
- Local endpoints use the same collector contract with host-qualified identities.
- WinRM first enumerates metadata without content, hashing, owner, ACL, or archive reads. It
  probes locally, then retrieves new/changed paths in bounded batches of 32.
- ZIP inspection stores/restores child analyzed records as a bundle controlled by the outer
  archive's fingerprint. An unchanged archive is not reopened.
- The local JSON sidecar is an L1 optimization. If it is absent after restart/failover, the
  database baseline restores the same complete analyzed snapshot. Both paths preserve stable
  workflow/SLA fields rather than recomputing them.

## Durable model and lifecycle

`scan_object_baselines` is keyed by `(tenant_id, scope_key, object_key)` and stores:

```text
asset_id, size, mtime, content_hash, version_signature,
last_scan_id, last_seen_at, updated_at, snapshot_json
```

The snapshot is the sanitized public analyzed record; raw file content is never persisted in
the baseline. Writes are batched at 500 rows. The baseline advances in the same transaction as
the authoritative report and normalized asset write.

Generation rules:

1. Seen objects are upserted with the successful scan ID.
2. A complete scan counts and deletes rows from older generations in the same tenant/scope.
3. A truncated, cancelled, unreadable, missing-root, or WinRM fetch-degraded scan may refresh
   seen rows but never prunes unseen rows.
4. Re-saving an existing/historical report cannot roll the active generation backward.
5. A workflow update refreshes snapshot JSON only when that report is still the active
   generation for the object.

Different filters, roots, depths, archive options, endpoint users, or ACL/content modes produce
different scope keys, so a narrow scan cannot delete a broad scan's baseline.

## Diagnostics

`scan_diagnostics.incremental` reports:

```text
enabled, mode, complete, scope_key, version_signature,
total_objects, new_objects, changed_objects, unchanged_objects,
deleted_objects, content_reads, delta_ratio,
sidecar_hits, durable_baseline_hits, probe_errors,
baseline_committed, baseline_rows_written, baseline_rows_skipped,
prune_skipped
```

Treat `complete=false`, `baseline_committed=false`, `probe_errors>0`, or `prune_skipped=true`
as operational signals. They do not silently invalidate the prior good generation.

## Verification

Functional and parity tests:

```powershell
python -m pytest tests/test_incremental_scanning.py tests/test_scan_cache_reuse.py `
  tests/test_smb_scan_cache_progress.py tests/test_endpoint_scopes.py tests/test_db_dialect.py -q
```

Benchmark:

```powershell
python scripts/incremental_benchmark.py --path enterprise_test_data --json
```

The benchmark uses only a temporary DB/cache and fails if findings, risk, permissions, or
sanitized preview differ from the explicit full-scan control. On 2026-08-06 the 360-object
reference estate produced:

| Mode | Time | Files/s | Speedup | Delta ratio |
|---|---:|---:|---:|---:|
| Full | 201.952 s | 1.783 | 1× | 1.0 |
| Warm L1 | 13.658 s | 26.357 | 14.79× | **0.0** |
| Durable after L1 deletion | 4.930 s | 73.023 | 40.96× | **0.0** |

Focused validation on a uniquely named disposable PostgreSQL database passed 67 tests; that
database was dropped afterward. The complete SQLite regression suite passed **634 tests** with
**17 opt-in skips** (PostgreSQL, live Meilisearch, and the 100 MB large-file case).

## Trust boundary

Like standard filesystem delta scanners, an unchanged decision trusts size and mtime so it can
avoid reading bytes. The previous content hash is persisted for identity/evidence continuity;
it cannot be recomputed without defeating delta scanning. Sources or adversaries capable of
changing bytes while preserving both size and mtime require the explicit full-scan schedule.
