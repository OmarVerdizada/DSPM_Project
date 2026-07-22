# Phase 1 Kickoff RFC — Normalized Domain Model (DATA-001)

**Status:** In progress. This is the first Phase 1 deliverable and the prerequisite that unblocks DATA-002 (immutable scan runs), which was deferred out of Phase 0 precisely because it needs this.
**Scope of this slice:** define the normalized domain model and a non-breaking mapper from the current report blob. **No runtime path is rewired yet** — the SQLite `scan_reports.report_json` store keeps working exactly as before.

---

## 1. Why

Today a scan is one `report_json` blob per `scan_id` (`backend/store.py`). Findings are re-derived by iterating that blob; lifecycle updates re-save the whole report (which is why a naive INSERT-only DATA-002 fix rejected them). Query, history, concurrency and any future access-graph/live-scan work are all weak against a blob.

The target (from the assessment §9.2) is an immutable, append-only scan/occurrence model with a mutable finding aggregate, and stable asset/finding identity that survives renames and re-scans.

## 2. Entity model (`backend/domain/models.py`)

| Entity | Rule | Key fields |
|---|---|---|
| `ScanRun` | Immutable, append-only | id, tenant_id, source, mode, policy_version, started_at, ended_at, status, total_files, summary |
| `Asset` | Path rename must NOT change identity | id (derived), tenant_id, source, stable_object_id, path, name |
| `AssetVersion` | History / delta basis | asset_id, version, size, mtime, content_hash, coverage |
| `Finding` | Mutable lifecycle, **stable** identity | id (= tenant+asset+rule+locator), tenant_id, asset_id, rule, severity, category, framework, status, first_seen, last_seen |
| `FindingOccurrence` | Append-only evidence | finding_id, scan_id, locator, fingerprint, occurrence_count |
| `Identity` | AD/cloud/service identity | id, type, domain, tenant_id, status |
| `AccessEdge` | Effective access graph | identity_id, asset_id, permission, inherited, source |
| `Event` | Durable event processing (live scan) | source, object_id, version, idempotency_key, state |
| `Checkpoint` | Journal/CDC/cloud state | source, partition, cursor, generation, updated_at |

**Identity rules implemented now:** `asset_id = sha256(tenant|source|stable_object_id-or-path)`, `finding_id = sha256(tenant|asset_id|rule|locator)`. Finding identity is derived from the normalized locator, **never** the sample value — so re-scans update the same finding and rename/move is handled once `stable_object_id` is wired from the connectors (Phase 2).

This slice implements all entities and a `normalize_scan_report(tenant_id, report)` mapper that decomposes an existing report dict into `ScanRun` + assets + versions + findings + occurrences. It is a pure function with no side effects — the DATA-001 building block, and the exact bridge a dual-write persistence path will call.

## 3. Migration strategy (non-breaking, incremental)

1. ✅ **Domain model + report→domain mapper** (pure, additive, tested) — `89f4128`.
2. ✅ **Normalized SQLite tables** created idempotently in `init_db()` alongside `scan_reports` — `fb861e8`.
3. ✅ **Dual-write:** `save_scan_history` mirrors normalized rows via the mapper in the same transaction, savepoint-isolated/best-effort so it never breaks the blob save. Reads still use the blob; zero behavioural change — `fb861e8`.
4. ✅ **Backfill:** `store.backfill_normalized_scans()` + `scripts/backfill_normalized.py` map existing `report_json` rows through the mapper (idempotent, per-scan isolated) — `9585043`.
5. ✅ **Read-switch:** `list_findings` now serves from a materialized `finding_index` when `DSPM_READ_FROM_NORMALIZED=1` (default off, blob fallback on error), avoiding per-scan blob loads. Parity-tested byte-for-byte against the blob path — `90ac42e`. DATA-002's core (immutable runs + stable created_at) already landed in `4e435f1`.
6. ⬜ **Retire the blob** (or keep it as an audit artifact behind a hash). ← last step; needs the flag defaulted on + a soak period first.

Each step is independently shippable and reversible. No step requires the big-bang control/data-plane split — that is a separate Phase 1 workstream.

## 4. Recommended workstream order (Phase 1)

1. **Persistence (this track):** DATA-001 model → dual-write → backfill → read-switch → DATA-002. ← started here.
2. Durable jobs / queue (ARCH-003) — independent, can run in parallel.
3. Control/scan-plane split (ARCH-004) + connector SDK (ARCH-005) — larger, sequence after the model is stable.
4. Streaming pipeline + real cancellation (SCAN-001/002).

## 5. Out of this slice (explicitly)
No Postgres, no Alembic, no queue, no plane split, no connector rewrite, no read-path change. Those are later, separately-reviewed slices. This slice is safe to land because it adds code without touching any existing code path.
