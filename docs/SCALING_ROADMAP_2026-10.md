# Sentro Maximum Scaling & Optimization Roadmap

*2026-10-02 · repo HEAD `15eb23c` (branch `sentro-ironhack`) · roadmap-first: no refactor was made for it.*

> **Reassessed 2026-10-05, after Waves 1 and 2. Part II is AUTHORITATIVE: the revised Wave 3 and Wave 4 were approved by the product owner on 2026-10-05, with the four decisions recorded in §23.0.**
> - **Part I (§0–§22)** is the original roadmap with the delivery status of Waves 1 and 2. It is HISTORICAL: kept as the record of what was measured and decided, not as the plan.
> - **Part II (§23–§31)** is the plan for all future implementation: the reassessment, the revised Wave 3, Wave 4, the capacity model, the gates and the execution order.
>
> Where they differ, Part II wins. It supersedes §7, §12, §14 (as a description of today), §16, §19, §20, §22 and the Final decision. Each of those sections says so where it starts.

**Evidence base.** I read the current code; five independent read-only code audits (SMB, WinRM, engine/content, persistence/PostgreSQL, orchestration) each cite file:line. I also took measurements on this host: 6 vCPU Xeon Silver 4215R, 16 GB RAM, VMware SSD, 0.8–3 GB free disk.

**Labels.**
- **MEASURED**: run today, or recorded with a source file.
- **EXTRAPOLATED**: modelled from measurements.
- **UNVERIFIED**: not checked.
- **UNVERIFIED – REQUIRES SCALE HOST**: this host has under 1 GB of free disk and cannot hold a 200k-file estate. C14 sized that gate at 150 GiB.

Line numbers drift; the function names are the stable anchors.

---

## 0. The answer in one paragraph

> *Written before Wave 1. The bounded path it calls "switched off" has been the default since 2026-10-04 (§5). For where the product stands now, see §23.1.*

Sentro already has the right architecture for 1–2M files. It is switched off, and the half that is on is the half that cannot scale.

**What is switched on: the single in-memory scan path.**
- Every file's record and extracted text stays in RAM until one PostgreSQL transaction writes the whole scan.
- MEASURED: 74 MiB + 30 KiB/file without compliance, 41.5 KiB/file with it. That projects to ≈29–58 GiB for 1–2M small files, before extracted text.
- A 30-minute wall-clock budget fails it.
- A restart loses it.

**What is switched off: the partitioned path (`DSPM_PARTITIONED_SCANS=0`).**
- It is a durable PostgreSQL ledger with compare-and-set claims, leases, retry, resume, finalize-once and a flat Python heap.
- MEASURED: traced heap 16.1 → 16.9 MiB from 1k to 4k files.
- It is idempotent on redelivery.
- It still has three structural gaps:
  - it never splits an SMB share;
  - its time budget turns long scans into permanent failures;
  - it has never been measured on PostgreSQL at scale.

**The shortest correct path:**
1. Make the partitioned path the only path.
2. Make its partition unit a bounded slice *inside* a share or endpoint.
3. Make persistence write only what changed.

Everything else is tuning or Wave 3.

---

## 1. Current architecture summary (what the code actually does)

```
API process (uvicorn, 1 worker expected - backend/jobs.py says so)
 ├─ /api/scan ──► partitioned_scans_enabled()? (default NO, backend/partitioned_scan.py:175)
 │     NO (default) ─► jobs.create_scan_job ─► ThreadPoolExecutor(DSPM_JOB_WORKERS=4), in-memory _jobs
 │                     └─ DSPMDiscoveryEngine.run()
 │                          collector (local walk | SMB two-phase | ...) ─► records[] (with content)
 │                          ─► BoundedSemaphore(72) ─► detector ProcessPool (min(8,CPU-1), compliance only)
 │                          ─► analyzed[] = report["files"]   (whole estate in RAM)
 │                     └─ _persist_compliance_scan ─► enrich_report_with_compliance (whole list)
 │                          ─► store.save_scan_history: ONE transaction under process-global store._lock:
 │                             normalized rows (executemany x1000) + baseline + finding_index + occurrences
 │                             + report body streamed to artifact store + scan_reports.rows_json (whole estate)
 │     YES ─► plan_bounded_partitions (local: runs of ≤2000 files) | plan_share_partitions (SMB: share GROUPS)
 │            ─► scan_partitions ledger (CAS claim, 300 s lease, 3 attempts, resume sweep, finalize-once)
 │            ─► inline (serial, in API process) or DSPM_SCAN_EXECUTION=queue + `python main.py worker`
 │            ─► persist_partition (one txn/partition) ─► finalize_partitioned_scan (streams body)
 ├─ /api/endpoint/scan ─► WinRM: one metadata command (PowerShell walk, $maxRecords = 5000, one reply)
 │                        ─► content batches (32 MB / 256 files, analysed per batch) ─► one save at the end
 ├─ incremental: L1 meta_index.sqlite (per host) + PG scan_object_baselines; key = path+size+mtime+version sig
 └─ reads: inventory keyset (row-value for numeric sorts), derived_cache (generation-stamped), per-process TTL caches
```

**Not part of the current architecture:**
- No USN or change journal.
- No COPY.
- No external queue (Memurai was removed; the PostgreSQL ledger is the queue).
- No per-target bandwidth throttle.

---

## 2. Verified bottleneck map

### 2.1 Scale-breaking

| # | Component | Code | Current behaviour | Root cause | Scale impact | Sev. | Status |
|---|---|---|---|---|---|---|---|
| B1 | Default scan path holds the estate | `discovery_engine.run` → `ScanReport(files=analyzed)`; `jobs._run_scan_job` → `report.to_dict()`; `store.save_scan_history` builds `inventory_rows` + `rows_json` | Five record shells per file (collector list with `content`, `to_dict` list, `normalize_records` list, futures, analyzed list), plus `rows_json`. MEASURED: RSS 74 MiB + 30.2 KiB/file; compliance 41.5 KiB/file; 16 KB files +17.5 KiB/file (one retained text copy). | MEMORY RETENTION | ≈29 GiB @1M, ≈58 GiB @2M (EXTRAPOLATED, tiny files) | P0 | CONFIRMED |
| B2 | Partitioned path off by default | `partitioned_scan.partitioned_scans_enabled` default `"0"` | The bounded path exists but is not used | JOB STATE | All of B1 applies by default | P0 | CONFIRMED |
| B3 | SMB has no intra-share partitioning | `smb_scanner.plan_share_groups`; `partition.plan_share_partitions` ("A share is never split"); fewer than 2 groups → no plan, whole server inline | A 1.5M-file share is one memory, retry and transaction unit. Two-phase scan: enumerate all, acquire all, then analyse; `slot_results` never pruned; `records.extend(share)` | ALGORITHMIC + MEMORY | The near-term target is exactly this case | P0 | CONFIRMED |
| B4 | Whole-scan time budget | `DSPM_SCAN_MAX_SECONDS=1800` in `jobs.collection_heartbeat`, engine `run()` and the partitioned runner (one budget for planning + all partitions) | Async single path: job "failed", nothing saved. Inline partitioned: `ScanStopped`, scan failed permanently, not resumable, partial estate left. Queue: partition truncated and persisted as done. MEASURED: ≈160–250 files/s here, so 1800 s covers ≈200–450k files | RETRY / JOB STATE | 1M files cannot finish with defaults | P0 | CONFIRMED |
| B5 | WinRM 5,000-file cap | `winrm_endpoint_scanner.py` `$maxRecords = 5000`; `Add-DspmFileRecord` drops past it, walk continues | Coverage ceiling: every rescan sees the same first 5,000. Marked incomplete internally; the console does not say so | ALGORITHMIC | One large endpoint is unusable | P0 | CONFIRMED |
| B6 | WinRM metadata is one reply | PowerShell builds the whole listing, starts all runspace instances up front, `ConvertTo-Json` + gzip + base64 in memory; backend holds it whole; 512 MB reply cap | Not pageable; raising the cap alone moves the failure | BUFFERING | Blocks 1M-file endpoints | P0 | CONFIRMED |
| B7 | SMB retry granularity | `_acquire_work_chunk` (chunk = ⌈fresh/workers⌉ ≥ 32 files, ≈31k at 1.5M/48), 2 attempts, then `failed_plans` drops the whole share; partition still persisted **done** | One reset late in a share re-reads ~31k files; a second reset loses the share for this run with no partition retry | RETRY | Million-file shares are unrecoverable on a flaky link | P0 | CONFIRMED |
| B8 | One giant save transaction | `save_scan_history`: whole scan in one PG transaction under process-global `store._lock`, artifact streamed **inside** the transaction; no statement/lock/idle timeouts | Duration grows with scan size; holds xmin (blocks vacuum); blocks `audit`/`record_job`/sessions in the API process | DATABASE + LOCKING | Minutes to hours of stalls at 1M | P0 | CONFIRMED |
| B9 | PostgreSQL plan pathology on first big save | `_prune_unseen_assets`: `UPDATE findings … WHERE asset_id IN (SELECT id FROM assets WHERE … scan_label … current_scan_id <> ?)` | MEASURED today: 20k files / 40k findings, first save into a fresh tenant stalled **> 634 s** in this one statement (killed). EXPLAIN: Nested Loop with rows=1 estimates, because the tables were analysed empty and every row is in the same uncommitted transaction. With statistics refreshed inside the transaction the same save took 40.8 s | DATABASE (QUERY) | Quadratic; a 1M first save on a fresh install never finishes | P0 | CONFIRMED (MEASURED) |
| B10 | One analyst click is O(scan) | `_update_finding_lifecycle` / `_update_finding_workflow` → parse whole body → `save_scan_history(report)` | Re-upserts every finding, re-inserts every occurrence and `finding_index` row, one baseline UPDATE per file, re-encrypts the body | ALGORITHMIC | Minutes and GBs per click at 1M/5M findings | P0 | CONFIRMED |
| B11 | Every rescan rewrites everything | `_write_normalized_rows`: retire `UPDATE findings SET is_current=0 WHERE asset_id IN (…)` (no `AND is_current=1`), then upsert; assets `detail_json` rewritten; baseline `snapshot_json` rewritten | MEASURED (20k synthetic, PG): first save 491 files/s, **unchanged** rescan 312 files/s; findings table 254 MB for 40k findings after two saves. 17 findings / 23 assets indexes; updates are non-HOT | DATABASE (WAL/bloat) | Incremental scans are still O(estate) in DB work and WAL | P1 | CONFIRMED (MEASURED) |
| B12 | Durability limited to partitioned local/SMB | `recover_interrupted_jobs` marks everything failed at every (re)start; `_jobs` dict, cancel flags and `result` in memory; endpoint/SFTP/DB scans never resumable | Restart loses work; a `--workers` respawn fails siblings' live jobs; a completed scan polled through another worker shows "failed" (`result` null) | JOB STATE | Long scans must survive restarts | P1 | CONFIRMED |

### 2.2 Efficiency (cost multipliers, not blockers)

| # | Component | Code | Behaviour | Root cause | Status |
|---|---|---|---|---|---|
| E1 | Full-file SHA-256 of every fresh file, any size, any type | SMB `_acquire_file_data` (`while offset < file_size`); local `read_text_preview_and_sha256` + `sha256_file`; WinRM `Get-FileHash` | 3 TB is read in full on a first scan. MEASURED SHA-256 here: 388 MB/s/core. 1 GbE ≈ 110 MB/s → ≥ 7.6 h (EXTRAPOLATED) | I/O + NETWORK | CONFIRMED |
| E2 | SMB read protocol | pysmb `retrieveFileFromOffset` per 1 MiB = CREATE + QUERY_INFO + READ (one outstanding) + CLOSE | ≈4 round trips per MiB; a 4 GB file = 4,096 opens | NETWORK | CONFIRMED |
| E3 | Large per-file captures | text cap `DEFAULT_TEXT_SCAN_MAX_BYTES` 100 MiB decoded to one `str`; every `.zip` captures 200 MiB even with `inspect_archives` off; PDF `pypdf` loads whole file; WinRM `ReadAllBytes` on whole PDFs, 5 MB `byte[]` per text file | ≈2× capture + string per worker; 64 workers × 100 MiB is not a bound | BUFFERING | CONFIRMED |
| E4 | Binary docs and OCR read twice | `extract_binary_text` then `sha256_file`; OCR hashes before its size check | 2× bytes | I/O | CONFIRMED |
| E5 | Untruthful coverage | Office parts over 50 MB → "" but FULL; zip non-text entries FULL with `bytes_scanned = size`; Office over 100 MiB truncated → empty, FULL | Silent coverage loss | CORRECTNESS | CONFIRMED |
| E6 | ACL batch fallback overflows the command line | `_acl_batch_for_paths` builds one `-EncodedCommand`; overflows 32,767 chars at ≈23 paths (MEASURED) → one PowerShell **per file** | Pathological when the backend identity cannot read ACLs in-process | BUG | CONFIRMED |
| E7 | Single-threaded local collection | `scan_directory`: ≈8 stats + read + hash + ACL per file on one thread | Local/UNC-path scans are I/O-serial | CONCURRENCY | CONFIRMED |
| E8 | Per-partition fixed costs grow with the estate | new detector pool per partition; `_finding_digests` = scandir of the tenant's whole flat findings cache per engine; planner pre-walks whole estate; budget doubles and re-walks past 2,147 partitions | O(partitions × estate) | ALGORITHMIC | CONFIRMED |
| E9 | Unchanged-rescan write amplification | `_reuse_analyzed_record` rewrites every L1 entry (MEASURED 8.4–9 KB/file written on a no-change rescan); no cache eviction; durable probe opens a connection per file under `store._lock` | I/O on the no-change path | I/O + LOCKING | CONFIRMED |
| E10 | Read side O(estate) per refresh | remediation summary + facets (≈13 aggregate passes) in per-process 15 s caches; dashboard `data_retention_summary` uncached `COUNT(*)`; OR-form keyset for text sorts; GIN indexes unusable under FORCE RLS (non-leakproof operators, VERIFIED by EXPLAIN); facets cache invalidated every partition | Console cost grows with estate; search scans the whole tenant | QUERY | CONFIRMED (plans), timings UNVERIFIED |
| E11 | Detector IPC ships full content both ways | `detector_stage` returns the full record incl. `content` (MEASURED 98 KB out / 104 KB back for a 98k-char file); "8 s timeout" not enforced | SERIALIZATION | CONFIRMED |
| E12 | No target-impact controls | only `io_workers` (max(16, 6×CPU) ≤ 64) and a per-process host budget; no bandwidth/IOPS throttle; pysmb opens without `FILE_SHARE_DELETE`; tiered/offline files recalled by full hash; WinRM fixed 8 runspaces, no priority | Can hurt the scanned server | SOURCE-SYSTEM | CONFIRMED |
| E13 | Silent scope loss | `max_depth` API default 4 (max 12) drops deeper folders with no marker (local, SMB, WinRM) | Coverage silently shallow | CORRECTNESS | CONFIRMED |
| E14 | Permission drift invisible on rescan | reuse replays the snapshot's ACL/owner; ACL edits do not change mtime | DSPM correctness | CORRECTNESS | CONFIRMED |

### 2.3 Theoretical, or not blocking the 1–2M target

| Item | Verdict |
|---|---|
| External queue (Redis/Celery/Kafka) | **Not needed.** The PostgreSQL ledger already gives CAS claims, leases, retries, resume and finalize-once (`store.claim_partition`, `persist_partition` attempt CAS, `claim_scan_finalize`; tests `test_work_queue.py:112,146`, `test_partitioned_scan_resume.py:121`). |
| SQLite as an enterprise database | NOT RELEVANT. Production already refuses SQLite (`config.production_problems`, `db.enforce_database_authority`). One gap: a script importing `backend.store` directly under `DSPM_ENV=production` skips both gates (see §8). |
| Partition cap `MAX_SCAN_PARTITIONS = 2147` (int4 `seq`) | Not blocking at 2M (≈4.3M at 2,000/partition). Blocks 50M → Wave 3. |
| Multi-node | Not needed for 1–2M on one file server (§19). |
| USN journal | Valuable later; not needed for 1–2M (§11). |
| COPY ingestion | RLS forbids COPY into FORCE-RLS tables. `executemany` is pipelined (psycopg 3.3.4 pipeline mode verified). Batch size and delta writes matter more. |

---

## 3. What is already good — KEEP

| Subsystem | Verdict | Why |
|---|---|---|
| Partition ledger (`scan_partitions`, `partitioned_scans`, leases, attempts, `claim_scan_finalize`, `ScanAlreadyFinalized`) | **KEEP** | Correct CAS design. Idempotent single-transaction commit, kill-tested (SQLite; re-run on PG in Wave 1). |
| `persist_partition` / streamed `finalize_partitioned_scan` / `iter_report_json` + `artifacts.put_stream` | **KEEP, TUNE** | Bounded per-partition transactions; byte-identical streamed body. Tune transaction scope and statistics. |
| Metadata-first reuse (L1 `meta_index.sqlite` + PG `scan_object_baselines`, version signature incl. rules/suppression/EDM digests) | **KEEP, TUNE** | MEASURED 16× faster rescan, 0 content reads. Tune write amplification (E9) and ACL refresh (E14). |
| SMB two-phase design (445 B/file slots, thread-local connections, single-pass hash+preview+zip head, reset-share → incomplete, 5-reset breaker) | **KEEP the parts; REFACTOR the unit** | The per-file mechanics are sound. The *unit* (share) is wrong. |
| WinRM delivery (gzip+base64 over stdin, session reuse per job, TLS/pinning, B4 byte-bounded content batches analysed per batch) | **KEEP; REPLACE metadata enumeration** | B4 MEASURED: peak follows the 32 MB batch, not scope (400 MB → 32.3 MB). |
| B0 batched writes (`_WRITE_BATCH` 1000 `executemany`, set-based retire, `iter_normalized_chunks`) | **KEEP, TUNE** | 9.0 → 0.009 statements/file. Tune batch size for PG row width; add delta writes. |
| Inventory keyset (row-value for numeric sorts), capped counts, streamed export by id keyset | **KEEP** | Index-bounded (VERIFIED-PLAN). P7 synthetic 5M p95 3–7 ms (no RLS). |
| `derived_cache` (generation-stamped shared cache) | **KEEP, extend** | Add the remediation summary/facets; add single-flight. |
| Detector `ProcessPoolExecutor` (lazy, falls back), compliance accumulators (bounded top-N) | **KEEP** | MEASURED 64–80 MiB/worker; 13.7× win in Sept. |
| Production DB authority gates, schema guard, RLS + tenant FKs | **KEEP** | Correct; do not trade them for throughput. |
| Archive/Office/OCR guards (defusedxml, ratio, per-part caps) | **KEEP** | Security-relevant. Fix only coverage truthfulness. |

---

## 4. Target scanner architecture

```
SOURCE (local path | SMB share | WinRM endpoint | Graph | SFTP)
  │
  ▼
ENUMERATOR (metadata only, streaming, sorted per folder)                 [bounded: 1 folder listing at a time]
  │  emits WORK UNITS as it goes:
  │    unit = {source, root, folder, name_from, name_to, subtree:bool}   ≤ U_files AND ≤ U_bytes
  ▼
DURABLE LEDGER (PostgreSQL scan_partitions)  ◄── claim (CAS) / lease / retry+backoff / cancel flag
  │                                              (enumeration and processing overlap: units are claimable
  │                                               as soon as they are written)
  ▼
UNIT WORKER (1..W per node; per-target concurrency cap)
  ├─ list unit's entries ─► metadata reuse probe (L1 → PG baseline, batched per unit)
  │                          unchanged ─► "touch" (no content, no hash, no row rewrite)
  │                          new/changed ─▼
  ├─ BOUNDED QUEUE (semaphore = pipeline_buffer) ─► READERS (per-target cap, byte-capped, streaming)
  │        hash policy: SHA-256 over what is inspected (≤ cap) + identity for uninspected large binaries
  ├─ PARSER / EXTRACTOR (text cap, Office/PDF caps, truthful FULL/PARTIAL/METADATA_ONLY/SKIPPED/FAILED)
  ├─ CLASSIFIER (detector process pool; send text, return findings only)
  ├─ RESULT ─► drop content immediately
  ▼
BATCH PERSIST (per unit, one transaction, ≤ ~500 files):
  delta upserts (changed rows only) + set-based touch of unchanged + baselines + occurrences
  + unit records artifact ─► mark unit done (attempt CAS)  ─► CHECKPOINT = the ledger row
  ▼
RELEASE (unit memory freed; gc) ─► next unit
  ▼
FINALIZE (once): prune unseen in scope (stats-safe), stream report body, summaries, alerts

FUTURE (Wave 3, only if metrics require):
  CHANGE SOURCE (USN via WinRM on the file server | agent) ─► changed paths ─► same WORK UNITS
  (continuity check: UsnJournalID + FirstUsn ≤ checkpoint; else fall back to metadata enumeration)
```

**Memory invariant.** Peak RAM = fixed engine cost + W × (unit working set) + readers × per-file cap + detector pool. **No term contains N(files).**

---

## 5. WAVE 1 — remove scale-breaking architecture (required for 1–2M)

### Wave 1 delivery status (2026-10-04)

Delivered on `sentro-ironhack` as local commits (not pushed). Every number below is **MEASURED** on this host (6 vCPU, 16 GB) unless marked otherwise. PostgreSQL runs used only the disposable `sentro_test` database.

| Item | Status | Commit | Evidence |
|---|---|---|---|
| W1.5 merge pending fixes | Done (pipeline, collectors, detection). The auth and ops worker branches and the 8 scoring specs are deferred. | 01904d5, b1ab8af, 3e5e8b4, 33e2ec1 | Suites green on SQLite and PostgreSQL |
| W1.4 PostgreSQL correctness | Done, with (d) re-scoped (see below) | a318da4, 3d04ad2 | 5k-file first save: 8.6 s without statistics vs 9.7 s with (0.89×; the target was ≤ 1.2×). Lifecycle click: 20.7 ms median vs 6,688 ms for the old re-save, at 10k findings. A click writes the finding row, its index row and the audit trail only (statement-trace test). |
| W1.1 partitioned path | Done | 6c349fe, f18ed4e | No wall clock on the scan. Per-unit budget with retry, kept on the last attempt. Stall pause leaves the scan to the resume sweep. Estate writes take a per-workspace advisory lock on PostgreSQL instead of the process lock. `DSPM_PARTITION_WORKERS`. |
| W1.2 SMB range units | Done, except the streaming planner | 10ad6d4 | Unit enumeration peak 1.1 / 1.7 / 2.5 MiB vs whole folder 11.8 / 56.2 / 111.6 MiB at 20k / 100k / 200k entries (fake server). Reset unit retry. E6 ACL batch split. |
| G0 10K on PostgreSQL | **PASS** | f18ed4e | Full suite on PostgreSQL: 2,903 passed, 77 skipped. Kill/resume parity on PostgreSQL. `scale_gate.py` 7/7 at 400 files. `DSPM_PARTITIONED_SCANS` is now **on** by default. |
| W1.3 WinRM frontier | Done, except the persistent remote PowerShell | d73a4a0 | Backend heap peak 36.1 MiB at 4k files vs 36.7 MiB at 16k (emulated endpoint). No record cap. One shell per scan. Per-command wall clock. Real-endpoint figures are **UNVERIFIED – REQUIRES REAL ENDPOINT**. |
| Polish | Done | 22a9e44, 2d5acac, ba87f3a | Stale facet test; `access.js` js-dangerous-dom-sink fixed. Final full suites at 2d5acac: SQLite 2,931 passed / 51 skipped; PostgreSQL 2,905 passed / 77 skipped. Both had the same 10 test-side failures (scale_gate's endpoint fake on the new default path; a tracemalloc baseline), fixed in ba87f3a and re-run green on both. `scale_gate.py` on PostgreSQL after W1.3: 7/7. |

**Departures from the plan above, on purpose:**
- **W1.4(d)** does not delete `rows_json` or filter by `assets.scan_label`. That would bring back a fixed regression: a later scan of the same files took them out of the named scan (`tests/test_scan_profiles.py`). Instead, a run above `DSPM_SCAN_RUN_VIEW_MAX_FILES` (20,000) neither builds nor stores its projection, and its name answers from the current estate. Reading a run and projecting it peaks at 5.4–6.5 KiB per file.
- **W1.1 lock.** `store._lock` stays a process lock for everything except the three long estate writes (save, persist partition, finalize) and the click. Some short read-merge-writes, for example the SIEM status, rely on it within one process.
- **W1.1 workers.** `DSPM_PARTITION_WORKERS` defaults to 1. Each unit's engine starts a detector process pool sized for the host, so N workers means N pools until the pool is shared (E8).
- **W1.2 planner.** The plan is built in memory as compact units, with no name lists. The streaming planner, where workers claim units before planning ends, is not done.
- **W1.3 step 7** was already fixed in 3e5e8b4 (PDF `ReadAllBytes`, fixed 5 MB buffer). Shell reuse saves a shell per command, but each command still starts `powershell.exe`. A persistent remote PowerShell (about 1.55 s per command, per the 2026-08 measurement) is not done.

**Open after Wave 1:** G1 200K on a scale host; W2.2 and W2.4 before the pilot (§17); the C: WAL archive on the test cluster (27 GB, `archive_mode=on`); re-running the local Semgrep gate, whose venv was removed with %TEMP% (CI runs it).

### W1.1 One bounded path: partitioned scanning becomes the scan

- **Objective.** Every local/SMB scan runs through the ledger. The single path is retired for scans above a small threshold, or entirely. The time budget becomes per-unit and resumable. `store._lock` no longer wraps PostgreSQL transactions.
- **Modules.**
  - `backend/partitioned_scan.py`: flag default; `_run_partitions`; budget at :300 and :899; `ScanStopped`.
  - `backend/jobs.py`: `collection_heartbeat`.
  - `discovery/discovery_engine.py`: `run` deadline.
  - `backend/app.py`: `/api/scan` routing; `_run_partitioned_scan_payload`.
  - `backend/store.py`: `_lock` usage in `persist_partition`, `finalize_partitioned_scan`, `save_scan_history`.
- **Approach.**
  1. Make `DSPM_PARTITIONED_SCANS` default on once W1.4 has run on PostgreSQL.
  2. Replace the whole-scan `DSPM_SCAN_MAX_SECONDS` with:
     - a per-unit budget: on expiry the unit fails and is retried;
     - a progress-based stall watchdog: no unit progress for T → pause the scan as resumable, never "failed".
     - Keep an optional overall SLA as a *notification*, not a kill.
  3. On PostgreSQL, take `store._lock` only for SQLite. PostgreSQL row locks and the ledger CAS already arbitrate. This removes API stalls during long writes and lease starvation of sibling scans.
  4. Run partitions concurrently inside one node: a small thread or process pool of unit workers, bounded by the per-target cap. Today inline partitions run serially.
- **Risks.**
  - SQLite still needs the lock.
  - Finalize must keep its row lock.
  - Partitioned/single parity tests encode walk order. Deterministic sorted order is better: update the parity tests deliberately.
- **Regression tests.**
  - Existing partition, resume and kill tests, plus the same tests on PostgreSQL (they are skipped there today: `test_work_queue.py:111`, `test_partitioned_scan_resume.py:120`).
  - New: "budget expiry pauses, resume completes, estate equals uninterrupted".
- **Benchmark.** `scripts/scale_gate.py` on PostgreSQL. 200K gate on a scale host.
- **Success criteria.**
  - A 2M-file scan has no wall-clock failure mode.
  - API p95 is unaffected while partitions persist.
  - Kill/resume parity holds on PostgreSQL.
- **Complexity:** MEDIUM.

### W1.2 SMB intra-share work units (the single most important change)

- **Objective.** A share of any size is processed as bounded units. Each unit is persisted, checkpointed, released and retried on its own.
- **Modules.**
  - `collectors/smb_scanner.py`: `_scan_shares_two_phase`, `_enumerate_share_plan`, `_acquire_share_plans`, `_acquire_work_chunk`, `failed_plans`.
  - `discovery/partition.py`: `plan_share_partitions`; reuse the logic of `plan_bounded_partitions`.
  - `backend/partitioned_scan.py`: unit spec.
- **Approach.**
  1. **Unit spec:** `{kind:"smb_range", share, folder, name_from, name_to, subtree}`, using sorted per-folder listings (case-folded).
     - Compact: no name lists in the ledger, unlike today's local `names[]`.
     - Restart-safe: re-list the folder and filter by the range.
     - A huge flat folder splits into name ranges.
     - A subfolder below budget is one `subtree` unit.
  2. **Streaming planner.** The enumeration walk writes units to the ledger in batches as it goes. Workers claim units before planning ends, so planning overlaps acquisition. No whole-estate plan is held in memory.
  3. **Unit size** is bounded by **files AND estimated bytes** (`Σ min(size, read cap)`). Today it is files only; one unit can hold 2,000 × 100 MB.
  4. **Inside a unit**, keep the two-phase per-file mechanics (slots, single-pass read, ACL). Emit analysed records per unit, then drop `content` as soon as the detectors return.
  5. **Retry.**
     - A connection reset fails the **unit**: the ledger retries with exponential backoff. It must not be "done, share missing".
     - The circuit breaker trips per target and pauses the scan, not fails it.
     - A unit retry is idempotent by construction: one transaction per unit, attempt CAS.
  6. Fix E6 (ACL batch command-line overflow) in the same change: cap the batch by encoded length.
- **Risks.**
  - Overlapping-share collapse (`_dedupe_overlapping_shares`) is whole-scan today. Keep share groups as the outer grouping and ranges inside them, or collapse at finalize by `(size, mtime, identity)`.
  - Sorted listing of a 1M-entry flat folder holds ~1M names once (bounded per folder; acceptable). Streaming QUERY_DIRECTORY is Wave 3.
- **Regression tests.**
  - Unit retry after a mid-unit reset gives no duplicate assets, findings or counts, and correct scan status.
  - Same unit executed twice gives an identical estate.
  - Fake SMB server with 100k entries in one folder → bounded RSS.
- **Benchmark.** Synthetic SMB tree (fake connection) of 200k entries: peak RSS flat versus a 20k one. One real share for throughput.
- **Success criteria.**
  - Peak RSS is independent of share size (within ±15% from 50k to 2M entries).
  - A failure loses at most one unit.
- **Complexity:** HIGH. This is the largest item and the highest value.

### W1.3 WinRM: paged enumeration, endpoint scans in the ledger

- **Objective.** One endpoint can hold millions of files. Every page is bounded, persisted and resumable.
- **Modules.**
  - `collectors/winrm_endpoint_scanner.py`: the PowerShell walk, `Add-DspmFileRecord`, the `$maxRecords` truncation, `ConvertTo-Json` of the whole set, `_get_command_output`.
  - `backend/app.py`: `_run_endpoint_scan_payload`, `_endpoint_fetch_batches`.
  - `backend/partitioned_scan.py`.
- **Approach (backend-held folder frontier — stateless on the endpoint).**
  1. Command k lists the immediate children of ≤ F folders taken from a durable frontier stored in the ledger. It returns files plus subfolders, streamed as JSON lines, capped at P records per reply.
  2. A folder with more than P entries returns a `name_after` continuation.
  3. The backend persists each page as a unit (metadata + content fetch via the existing B4 batches) and pushes the subfolders onto the frontier.
  4. Delete `$maxRecords`. Do not raise it. Remove the start-everything `BeginInvoke` pattern (process items as they come).
  5. Keep one WinRS shell open per scan for many commands. This saves ≈1.55 s cold start per command (repo measurement, `docs/perf/ENDPOINT_SCAN_SPEED_ROADMAP_2026-08.md`).
  6. Fix the per-command timeout: a real wall clock that stops the remote process.
  7. Fix PDF `ReadAllBytes` (cap and stream) and the 5 MB `byte[]` per text file (size the buffer to `min(file, cap)`).
- **Risks.**
  - Folder-frontier ordering versus old reports. Choose deterministic sorted order.
  - Windows PowerShell 5.1 memory on very large single folders: page with `name_after`.
- **Regression tests.**
  - An endpoint fake with 50k files gives 50k assets (today 5,000).
  - A page retried twice gives the same estate.
  - Crash mid-endpoint resumes from the frontier.
- **Benchmark.**
  - Fake WinRM transport: 200k files, bounded backend RSS.
  - One real endpoint for remote CPU/RAM impact. **UNVERIFIED – REQUIRES REAL ENDPOINT.**
- **Success criteria.**
  - No record cap.
  - Peak backend RAM independent of endpoint size.
  - Endpoint working set ≤ fixed budget.
- **Complexity:** HIGH.

### W1.4 Persistence correctness at scale (PostgreSQL)

- **Objective.** No transaction or statement whose cost is quadratic or O(scan) on the hot or interactive path.
- **Modules.** `backend/store.py`: `_prune_unseen_assets`, `_write_normalized_rows`, `_update_finding_lifecycle`, `_update_finding_workflow`, `save_scan_history` / `rows_json`, `_trim_finding_index`.
- **Approach.**
  1. **B9 (prune plan).**
     - Rewrite the prune as an id-keyed, chunked operation: select the stale ids with an indexed `(tenant_id, scan_label, current_scan_id)` path, then `UPDATE … WHERE asset_id = ANY(chunk)`.
     - `ANALYZE` the touched tables after the first unit's bulk load in a fresh tenant.
     - Per-unit commits (W1.1) let autovacuum/autoanalyze run during the scan.
     - Add the `(tenant_id, scan_label, current_scan_id)` index on `assets`.
  2. **B10 (O(scan) click).** Lifecycle and workflow actions update the `findings` row, its `finding_index` row and the audit trail **directly**. The memory note "lifecycle belongs to the row" already makes the row authoritative. Stop re-saving the report body; it is a scan-time snapshot.
  3. **Bound every transaction.**
     - Set `statement_timeout` / `lock_timeout` / `idle_in_transaction_session_timeout` on application connections (generous; per role).
     - Move artifact streaming out of the open transaction: write the artifact first (content-addressed), then the row. This is already the order inside; only the transaction scope changes.
  4. Delete `rows_json` (the scan-name filter reads `assets` by `scan_label`; see E10/S9).
- **Regression tests.**
  - A lifecycle click on a 50k-finding scan touches ≤ 3 rows (statement trace).
  - First save on an empty PostgreSQL tenant: the plan uses an index (assert in an EXPLAIN-based test).
  - The S1 older-report and S4 race tests from `test_backend_audit_2026_10.py` stay green.
- **Benchmark.** `pg_write_bench.py` (scratchpad; promote to `scripts/`) at 20k / 200k on PostgreSQL.
- **Success criteria.**
  - The 20k first save no longer depends on statistics (≤ 1.2× the stats-refreshed time).
  - A click is ≤ 50 ms at 1M/5M (synthetic).
- **Complexity:** MEDIUM.

### W1.5 Merge the pending scan-correctness fixes

Five worker branches from the 2026-10 backend audit sit unmerged (`.claude/worktrees/agent-*`):
- **Pipeline:** a truncated or cancelled scan is never "complete"; a failed analysis is not replayed from the baseline.
- **Collectors:** UTF-16 decoding; SMB connection-error classification; PDF/zip coverage truthfulness; `$` shares.
- **Detection:** PAN windows.

These are prerequisites for trusting incremental reuse at scale.
- **Complexity:** LOW–MEDIUM (review + cherry-pick + PostgreSQL re-run).

---

## 6. WAVE 2 — incremental, durable, efficient

### Wave 2 delivery status (2026-10-05)

Delivered on `sentro-ironhack` as local commits; nothing was pushed. Numbers are
**MEASURED** on this host (6 vCPU, 16 GB) unless marked otherwise. PostgreSQL runs
used only the disposable `sentro_test` database.

| Item | Status | Commit | Evidence |
|---|---|---|---|
| Migration safety, revisions 36–40 | Done | 830f3a2 | See note 1. |
| WAL / archive | Done in code; the archive itself needs an operator | 5636cde | See note 2. |
| W2.2 tiered hashing and bounded reads | Done | 671b38e | See note 3. |
| W2.4 durable jobs | Done | 8187c33, ebb89f5, 882adf8 | See note 4. |
| W2.1 delta persistence | Done | 207bd45 | See note 5. |
| W2.3 SMB target protection | Done, except the ACL refresh policy | d415181 | See note 6. |
| W2.5 read side | Done | d080926 | See note 7. |
| W2.6 scan levels | Done | fe82c95 | See note 8. |
| Parallelism (E8) | Shared detector pool done; `DSPM_PARTITION_WORKERS` stays 1 | b57c792 | See note 9. |
| Static gates | ruff, mypy, bandit and eslint pass; semgrep not re-run here | 620bf9b | See note 10. |
| Review of W2.1 and W2.4, plus the full-suite run | 8 defects fixed | 07f10be, f72463f, 3096ea7 | See note 11. |

**Notes:**

1. **Migration safety.** An upgrade from 37 to 40 keeps every row on SQLite and
   PostgreSQL. On SQLite, a failed upgrade used to leave revision 38's drop
   applied while the database said 37; that is fixed and now atomic. Re-running
   revision 36 takes no lock. RLS is unchanged. The test is
   `tests/test_w2_migration_safety.py`, extended through revision 43.
2. **WAL / archive.**
   - The 30 GB archive holds no base backup, so none of it can be replayed, and
     nothing prunes it.
   - New: a disk floor (`DSPM_MIN_FREE_DISK_MB`) that refuses a scan with 507,
     or pauses a running one; archive health in `/api/admin/db-metrics`; and the
     operator procedure in
     `docs/database/POSTGRESQL_WAL_ARCHIVE_AND_TUNING_2026-10.md`.
3. **W2.2 tiered hashing and bounded reads.**
   - Caps are 16 MiB for text and 64 MiB for documents. Identity follows the
     `DSPM_HASH_POLICY` setting (meta / sampled / full).
   - A text file read only up to its cap is named `head:` by the bytes inspected.
   - There are five coverage states. Seven mutations were killed.
   - 2,071 files / 1.4 GB, local: first scan read 1,420 → 180 MiB (7.9×), 33.6
     → 4.9 s, peak RSS +442 → +190 MiB; an unchanged rescan reads 0 bytes.
4. **W2.4 durable jobs.**
   - Revision 41 adds the job's owner (host, pid, instance) and a heartbeat.
     Recovery takes over only jobs whose owner is gone.
   - New states: `paused` (resumable; never shown as failed) and `incomplete`
     (finished with gaps; never shown as completed).
   - Cancel works across backends. Scheduler runs don't overlap, and the ledger
     queue claims fairly across scans.
   - Nine mutations were killed.
5. **W2.1 delta persistence.**
   - Revision 42 adds row digests; presence moves set-based; findings no longer
     flip twice.
   - Presence indexes were dropped so updates can be HOT, with a measured
     fillfactor and toast target.
   - 4,000 files on PostgreSQL, unchanged rescan: WAL 108.6 → 30.0 MiB, 9.1 →
     4.2 s, 8,064 of 12,006 updates HOT.
   - Eight mutations were killed.
6. **W2.3 SMB target protection.**
   - Per server: a session cap, a bandwidth cap and a backoff.
   - Offline and recall files are not read.
   - Read-only opens share DELETE, and the working credential is tried first.
   - Seven mutations were killed. Verified only with a fake server: no real file
     server here.
7. **W2.5 read side.**
   - Single-flight shared cache: remediation summary and facets, retention,
     and access principals.
   - The access files list pages by keyset.
   - A partition write moves the cache generation at most every 15 s.
   - Revision 43 drops four GIN indexes, measured unusable under FORCE RLS.
     First save WAL 76.3 → 48.5 MiB; unchanged rescan 30.0 → 20.8 MiB.
8. **W2.6 scan levels.**
   - Three levels: inventory, standard, full. Reuse never crosses levels, and
     a standard scan keeps its old scope.
   - The reuse signature now covers the content caps.
   - The summary counts coverage states, and the console shows level, cost and
     coverage.
9. **Parallelism (E8).** 4,000 files in 4 partitions with every framework:
   144 → 114 s. Two partition workers save 9% more, which doesn't justify
   doubling the memory.
10. **Static gates.** Thirteen new B608 findings were reviewed into the
    baseline. Semgrep's venv was removed with %TEMP%, and reinstalling it needs
    a download; CI runs it.
11. **Review and full-suite fixes.** An independent review of W2.1 and W2.4 and
    the full SQLite suite found eight defects. Each fix has a test that fails
    without it; ten mutations were killed.
    - A scan paused with nothing to continue it (resuming off, or no stored
      request) left its job paused for ever, and its schedule skipped every
      run. It now fails and says why.
    - A cancel sent to a backend holding a stale paused copy of a job another
      backend had resumed was refused. It now reaches the row.
    - A terminal job write that did not land left the row `running` until a
      restart. The heartbeat now retries it, and a row this process no longer
      runs is judged by its heartbeat.
    - A scheduled run's "started" could overwrite the outcome of a run that had
      already ended. A paused run was recorded as failed.
    - A reconciled paused job was always `completed`. It now takes the report's
      completeness, so it can be `incomplete`.
    - Heartbeats were judged across two hosts' clocks. Both sides now use the
      database clock.
    - A detector-pool lease from a closed pool was counted against the next
      pool, which was then never reaped (the suite's flaky idle-shutdown test).
    - The file view showed an older scan's reuse and cache decisions as if they
      were the latest scan's.
    - Left as they are, with the reason:
      - Duplicate finding ids inside one batch resolve first-wins. B7 already
        merges findings by value, so this cannot happen in a real scan.
      - One path with two object ids in one batch. Paths are unique within a
        scan.

**Not done in Wave 2, and why:**

- **The ACL refresh policy (E14).** A reused file still replays its stored
  ACL. Wave 3.
- **`finding_index` / `finding_occurrences` history.** These are now most of a
  rescan's WAL. Content-addressed response bodies are Wave 3.
- **The streaming SMB planner and a persistent remote PowerShell.** Neither
  could be measured here: there is no file server or endpoint.
- **Search.** For estates where a tenant-wide LIKE is too slow, the answer is
  the optional search projection (`backend.search`), not more indexes.

**G1 200K: HELD FOR SCALE HOST.** The scans below were bounded, and the 200K
gate was not run.

1. **C14 harness at 19,000 files (SQLite).**
   - All eight parity checks pass.
   - Partitioned: 102 files/s. Unchanged incremental: 192 files/s, 0 content
     reads. Compliance: 117 files/s.
   - The harness now projects 14.6 GiB of state for 200K files (it measures
     58 KB/file; the old quality-audit basis was 643 KB/file). So a scale host
     needs roughly 31 GiB free, given the 15.7 GiB reserve. C: had 9.5 GiB.
2. **`scripts/pg_scan_rehearsal.py` on PostgreSQL**, against the G1 criteria:

| Criterion | 4,000 files | 20,000 files | Status |
|---|---|---|---|
| Peak RSS flat at the same unit size | 320 MiB | 295 MiB | holds at bounded scale |
| No transaction over 60 s | longest 11.0 s | longest 15.8 s (19.6 s in a run whose rescan did not reuse) | holds at bounded scale |
| Rescan at least 5× first-save speed | 2.9× end to end | not run | not met end to end |
| API p95 under 300 ms during the scan | 148 ms first scan, 630 ms rescan | 122 ms first scan | sum of four reads, not one request |

- **Rescan speed.** The 5× criterion is met by the database write alone, not
  end to end: the whole-pipeline rescan is 2.9× (see note 5 for the write).
- **Console latency.** Each sample is the sum of four console reads, so it is
  stricter than the per-request API criterion. The rescan sample exceeds it.
- **Why the rescan read is slow.** At 4,000 files and 32,000 findings, a warm
  cache answers the summary and facets in 1 ms and the remediation page in
  63 ms. Right after the generation moves, they take 184, 187 and 304 ms. These
  are O(estate) aggregates: at 1–2M files a recompute takes tens of seconds
  (EXTRAPOLATED). This is a G1/G2 risk. The fix is to serve the previous answer
  while one reader rebuilds, or to keep the counts incrementally; either
  relaxes B3.1's "never serve the estate as it was" contract, so it is a
  product decision.
- **Disk.** These runs took this host's C: from 9.5 to 2.9 GB free, through
  the unpruned WAL archive. The PostgreSQL full suite at HEAD was therefore not
  run; the targeted PostgreSQL suites for every Wave 2 area passed.

### W2.1 Delta persistence (stop rewriting unchanged rows)

- **Objective.** An unchanged rescan does O(changed) row work plus O(units) touches.
- **Approach.**
  1. For a reuse hit whose analysed result is identical, skip the asset, finding, baseline and occurrence rewrites. Mark presence with one set-based statement per unit:
     - either `UPDATE assets SET last_seen_scan = ? WHERE tenant_id=? AND id = ANY(?)`,
     - or a compact `scan_presence(scan_id, asset_id)` table.

     The prune then uses presence.
  2. Retire only `is_current = 1` rows that are not re-asserted (fix the retire filter).
  3. Replace retire-then-reassert with a generation counter where possible.
  4. Make indexes HOT-friendly:
     - drop redundant prefix indexes on `assets` (`risk_score` vs `risk_score_id`, etc.);
     - drop the 4 GIN indexes unusable under RLS, or make search use them (W2.5);
     - set `fillfactor` 80–90 on `assets` and `findings`.
  5. Retention:
     - `finding_occurrences` / `finding_index` per scan;
     - history findings older than N scans;
     - scan bodies and `scan_reports` by policy.
- **Benchmark.** `pg_write_bench` unchanged rescan at 200k. Target: rescan DB time ≤ 10% of first-save time. MEASURED today: 64% (312 vs 491 files/s).
- **Complexity:** MEDIUM–HIGH.

### W2.2 Hash and content policy (bytes read ∝ bytes inspected)

**Why SHA-256 exists today (verified):**

| Use | Where | Needs the whole file? |
|---|---|---|
| Reuse admission | `store.py:3297-3306`: a non-empty `content_hash` is required for a baseline row | No |
| Overlapping-share dedupe | `by_hash` | No; identity suffices |
| Evidence reveal | C13: whole-file SHA-256 + size before re-reading a value | **Yes**, but only for files with findings |
| History "hash changes" page | `/api/history/hash-changes` | No |

**Policy:**
- **Inspected files** (content type, size ≤ cap): one streaming read computes SHA-256 + extraction (already single-pass for text). Fix the double read for Office/PDF/OCR (E4).
- **Uninspected files** (non-content types, or size > cap, e.g. VHDX/ISO/media/PST over the cap):
  - Default: no content read. Identity = `meta:` fingerprint (size + mtime + file id), labelled non-cryptographic.
  - Optional: `DSPM_HASH_LARGE=sampled` (head + tail + size) or `full` for customers who require it.
  - Baseline admission accepts the `meta:` identity for these files only.
- **Reuse:** unchanged (path + size + mtime + file id when available) → reuse the stored hash. mtime alone is never treated as cryptographic; the hash stays what the reveal path checks.
- **Coverage states:** `FULL_CONTENT` / `PARTIAL_CONTENT` (cap hit) / `METADATA_ONLY` (policy) / `SKIPPED_POLICY` / `FAILED`. Fix the untruthful FULL cases (E5).
- **Default caps:** text 100 MiB → 16 MiB (`PARTIAL_CONTENT` beyond). Zip capture only when `inspect_archives`. PDF capped by size, with no whole-file load past the cap.

**Expected bytes read (EXTRAPOLATED; replace with the estate's own size histogram — the metadata pass can record it for free):**

| Scenario | Today | After W2.2 |
|---|---|---|
| First scan, 3 TB | ≈3 TB (≥7.6 h at 1 GbE) | ≈ Σ min(size, 16 MiB) over inspectable files. For a typical server where most bytes sit in large binaries: ≈0.3–1 TB (≈1–3 h) |
| 0% changed | ≈0 content bytes (already; MEASURED 0 content reads) | ≈0 |
| 1% changed | ≈30 GB if uniform | ≈3–10 GB |
| 10% changed | ≈300 GB | ≈30–100 GB |

- **Complexity:** MEDIUM.

### W2.3 SMB read and ACL efficiency, target protection

- **Read path.**
  - Open once per file and read sequentially. smbprotocol (already used for SMB3 encryption) allows multiple outstanding reads / credits; pysmb does one READ at a time.
  - Either move the plain path to smbprotocol, or batch reads inside one open.
- **ACL refresh policy** (fixes E14 without 3 round trips × N every night):
  - re-read ACLs of folders each scan (inheritance roots);
  - re-read file ACLs for files with explicit ACEs;
  - run a full file-ACL refresh on a slower cadence (weekly), as its own scan profile.
- **Target protection.**
  - Per-target session cap, coordinated through the database when multiple workers run.
  - Token-bucket bandwidth limit per target (`DSPM_SMB_MAX_MBPS`).
  - Adaptive backoff on latency or `STATUS_INSUFF_SERVER_RESOURCES`.
  - Open with `FILE_SHARE_DELETE`.
  - Skip offline/recall-on-access files (`FILE_ATTRIBUTE_OFFLINE` / `RECALL_ON_DATA_ACCESS`) as `SKIPPED_POLICY`.
- **Instrumentation.** Record per scan: bytes read, read latency p95, sessions, resets. The target's own CPU, RAM and disk queue are read with perfmon during the pilot gate.
- **Complexity:** MEDIUM.

### W2.4 Durable orchestration for every scan type (no new infrastructure)

- **Make `scan_jobs` the source of truth.**
  - API polls and cancels read and write the database: cancel becomes a durable flag that workers and engines check.
  - Store the compact result (or a pointer) durably. This fixes "completed shows failed" across workers.
- **`recover_interrupted_jobs` gets owner + heartbeat** (`owner_host`, `owner_pid`, `heartbeat_at`, written by the job). It only fails jobs whose owner is gone (the S10 finding).
- **Scheduler overlap guard:** skip if the previous run of the same schedule is still unfinished.
- **Endpoint fleet.**
  - Endpoint scans become ledger scans (W1.3), are schedulable and run on `main.py worker`.
  - A global endpoint concurrency cap N replaces "4 job threads, 10 per tenant".
- **Fairness and backoff:** per-tenant fairness in `LedgerQueue.take`; backoff on requeue.
- **Complexity:** MEDIUM.

### W2.5 Read side at 1–2M

- **Caching.**
  - Remediation summary + facets → `derived_cache` with single-flight (one rebuild per generation across backends).
  - Do not bump the estate generation per partition; bump once per scan or per N units.
  - Cache the dashboard's `data_retention_summary`.
  - Cache access principals per generation.
- **Keyset.** Row-value keyset for every sort (remediation and text sorts), selecting the sort expression (as done for category in `b05e5a6`).
- **Search under FORCE RLS.** GIN is unusable here. Decide between:
  1. the optional search engine for text search (exists);
  2. tenant-local prefix/btree search;
  3. dropping the GINs.

  Do not keep paying for indexes the application role cannot use.
- **Complexity:** MEDIUM.

### W2.6 Scan profiles (map existing knobs; do not invent new engines)

- **INVENTORY**: metadata + folder ACLs; no content, no hash beyond identity. `read_content=False`.
- **STANDARD DSPM** (default): metadata + bounded content inspection (16 MiB text, Office/PDF caps) + tiered hash.
- **FULL / COMPLIANCE**: archives, OCR, larger caps, full hash optional.
- **INCREMENTAL**: not a depth. It is the reuse behaviour of every profile. "Full rescan" remains available (version signature bump or `incremental_enabled=False`).

Pattern from mature DSPM products, without marketing claims:
- inventory and permissions on a fast cadence; content classification on new/changed objects;
- sampled or bounded inspection of very large objects;
- event-driven change capture for file servers where an agent or journal is available.

100% inventory does not require rereading 100% of bytes each cycle.

---

## 7. WAVE 3 — scale validation, then horizontal expansion

> *Superseded by §24 (revised Wave 3) and §25 (Wave 4). The original text is kept below. In short: certification stays; the partition cap and the planner move forward into Wave 3; the PostgreSQL structure items move into Wave 4; multi-node, the change journal and the search engine are deferred to the triggers of §26.4.*

1. **Certification on a scale host:** the 200K → 1M → 2M gates (§16) on PostgreSQL with the real schema and RLS.
2. **Multi-node scanning (only when §19's formula says so).**
   - Shared artifact store (or partition records in PostgreSQL / object storage).
   - The same vault/artifact keys on every node.
   - A worker registry with heartbeat.
   - Per-target caps coordinated in the database.
   - NTP for lease clocks.
3. **50M structural items.**
   - Lift `MAX_SCAN_PARTITIONS` (BIGINT `seq`, or `(unit, local_seq)`).
   - Dynamic frontier for all sources (W1.3's model).
   - PostgreSQL: detail_json diet (store less per asset; the report body already has the full record), history tables partitioned by scan/time with retention, incremental aggregate tables instead of O(estate) GROUP BYs.
   - A dedicated search index.
4. **Change-journal incremental (§11)** if enumeration time exceeds the SLA.

---

## 8. PostgreSQL strategy

**Authoritative database**
- PostgreSQL is authoritative; production refuses SQLite (VERIFIED).
- Close the script gap: `backend/store.py` should call `db.enforce_database_authority` (or refuse) at import when `DSPM_ENV=production` and no `DSPM_DB_URL` is set. Today only `main.py` and `backend/app.py` enforce it.
- SQLite stays dev/test only. Do not optimise it.

**Split state that remains by design (acceptable)**
- The L1 `meta_index.sqlite` per host is a cache: reconstructible from `scan_object_baselines`.
- Artifact bodies and partition records live on the filesystem; multi-node needs shared storage (Wave 3).

**Ingestion**
- **Batches.** Keep `executemany` (pipelined). Size batches by **bytes**, not only rows: on PostgreSQL `assets.detail_json` averages ≈43 KB logical (MEASURED, `ENTERPRISE_DATABASE_ROADMAP_2026-08.md`), so 1,000 rows ≈ 43 MB of parameters. Start at 250–500 rows per batch and tune with `pg_write_bench`.
- **Transactions.** One transaction per unit (≈500–2,000 files), never per file, never per scan.
- **COPY** is blocked by FORCE RLS. Do not add a BYPASSRLS loader role unless measured ingestion forces it.

**Indexes**
- Remove redundant prefixes on `assets` (23 indexes) and the GINs unusable under RLS (W2.5).
- Add `(tenant_id, scan_label, current_scan_id)` on `assets` (W1.4).
- Every new index must justify its write cost in `pg_write_bench`.

**RLS** stays (FORCE).
- The cost of the policy is a per-row filter: measure it once, RLS on vs a BYPASSRLS session, on the 200k gate.
- The real RLS cost found so far is index *usability* for non-leakproof operators, not per-row CPU.

**Pool**
- 10 connections per process is enough once `store._lock` stops serialising writes in-process.
- Unit workers each hold ≤ 1 connection during a persist.
- Budget: API 10 + W workers × 2 ≤ 50.

**Server tuning (ship as guidance; none ships today)**
- `shared_buffers` ≈ 25% RAM, `max_wal_size` ≥ 8 GB for bulk loads, `checkpoint_timeout` 15 min.
- Autovacuum scale factors lowered on `findings`, `assets` and `finding_index`.
- `track_io_timing` on.
- `pg_stat_statements` for the gates.

**Size model at 1M files / 5M findings (EXTRAPOLATED, current schema)**

> *Database only. For all Sentro-owned storage (artifacts, caches, backups, WAL) and the model after Wave 4, see §26.*

- ≈55–60 GB after the first scan; ≈100–110 GB after 5 scans (history + `finding_index`); ≈4 GB/scan after that.
- W2.1 retention plus delta writes brings steady state to ≈45–50 GB plus changed-object history.
- 50M on the current schema ≈ 2.5 TB of current-state tables: the detail_json diet and history partitioning are mandatory before 50M.

---

## 9. SMB strategy

| Aspect | Today (verified) | Target |
|---|---|---|
| Partition unit | Share group; a share never split | `smb_range` units inside shares, bounded by files and bytes (W1.2) |
| Memory lifecycle | Whole share: plans + slot results + records with content until the share finishes | Per unit; content dropped after detectors |
| Retry | Chunk of ≈⌈fresh/workers⌉ files, then the whole share dropped as "done, incomplete" | Unit fails → ledger retry with backoff; breaker pauses the scan |
| Checkpoint | Per share-group partition (when the flag is on) | Per unit; enumeration progress also durable (streaming planner) |
| Hashing | Full file, every fresh file, 1 MiB opens | Tiered policy (W2.2); one open per file |
| Metadata | Depth-first `listPath`, one thread per share, ≈7 round trips per fresh file incl. ACL; reused file 0 | Parallel by unit; ACL refresh policy (W2.3) |
| Incremental | Full namespace walk + per-file reuse probe | Same Level 1; per-unit batched probes; Level 2 only via §11 |
| Network | No throttle; up to 64 sessions per scan per process | Per-target caps + token bucket; adaptive backoff |
| Coverage truth | `$` shares skipped even when named; depth default 4 silent; Office over 100 MiB empty-but-FULL | Fixed by W1.5/W2.2 |

---

## 10. WinRM strategy

| Aspect | Today (verified) | Target |
|---|---|---|
| Record limit | `$maxRecords = 5000`, silent beyond (marked incomplete) | No cap; folder-frontier pages (W1.3) |
| Enumeration | Whole listing built remotely, one reply, 512 MB cap | Pages of ≤ P records streamed; frontier durable in the ledger |
| PowerShell memory | All runspace instances started up front; `ConvertTo-Json` of everything; PDF `ReadAllBytes`; 5 MB buffer per text file; Office XML up to 200 MB read for 120 KB | Bounded per page; streaming JSON lines; capped PDF; right-sized buffers |
| Sessions | One pywinrm session per job; new shell + `powershell.exe` per command (≈1.55 s) | One shell per scan, many commands |
| Content batching | B4: 32 MB / 256 files, analysed per batch — good | Keep. Skip non-text files' content fetch (hash-only per policy) |
| Durability | None: one save at the end; crash = failed | Pages are units; crash resumes from the frontier |
| Fleet | 4 job threads shared; ≤ 10 per tenant; not schedulable; never on workers | Ledger + workers + global endpoint cap; schedules |
| Endpoint impact | Fixed 8 runspaces, no priority; full `Get-FileHash` of every fetched file | Runspaces = f(endpoint cores); below-normal priority; tiered hash; per-command wall clock that stops the remote process |
| Millions of files on one endpoint | Impossible (cap) | Same bounded memory at any size; duration ∝ files |

---

## 11. Incremental scanning strategy

- **Level 1 (metadata-diff). Exists; keep and fix.**
  - Full enumeration + reuse by `(path, size, mtime, version signature)`.
  - MEASURED: no-change rescan 16× faster, 0 content reads.
  - Fixes:
    - write amplification (E9);
    - batched per-unit baseline probes, not one connection per file under the lock;
    - ACL refresh policy (E14);
    - file id in the key where available.
  - Cost at 1M files is dominated by enumeration round trips: ≈50k folder listings + probes. EXTRAPOLATED: ≈10–30 min on a LAN file server.
- **Level 2 (USN change journal).**
  - Technically practical **only with code running on the file server**. `FSCTL_QUERY_USN_JOURNAL` / `FSCTL_READ_USN_JOURNAL` need a local volume handle (admin). They are not reachable over SMB.
  - Agentless option: WinRM to the file server (the product already speaks WinRM): run a reader script per volume, return changed file references, resolve paths (`FSCTL_GET_NTFS_FILE_NAME` / `OpenFileById`), and feed the **same work units**.
  - Continuity rules:
    - checkpoint = `(UsnJournalID, NextUsn)` per volume;
    - if `UsnJournalID` changed, or the checkpoint is < `FirstUsn` (wrapped/truncated) → fall back to Level 1;
    - handle rename (old/new name records), delete, and security change (`USN_REASON_SECURITY_CHANGE` — this also fixes ACL drift);
    - never trust the journal when continuity cannot be proven.
  - **Sequence:** Level 1 bounded and fixed first (Waves 1–2). Level 2 only when the enumeration time measured at the 2M pilot exceeds the scan SLA, or for 10M+.

---

## 12. Memory model

> *Superseded by §26.1. Measured since: a unit's peak RSS follows the bytes it holds (110 MiB + 1.0 MiB per MiB of text), and three terms still grow with size (§23.4, §23.5 N1 and N7).*

**Why memory is bounded after Wave 1:**
- Units bound files and bytes.
- Content is dropped after classification.
- Futures and results are consumed per unit.
- The planner streams.
- Finalize streams.
- No estate-sized list survives a unit.

**Starting limits** (set by the gates, not by guesswork):

| Knob | Start value | Evidence |
|---|---|---|
| Unit size | ≤ 2,000 files AND ≤ 2 GiB estimated read bytes | existing `DSPM_PARTITION_MAX_FILES` = 2000 |
| In-flight analysis | `pipeline_buffer` = max(8 × analysis workers, 2 × io workers, 64) | 72 here; works (MEASURED) |
| Per-file text cap | 16 MiB | was 100 MiB |
| Readers per target | ≤ 16 | was up to 64 |
| Detector pool | min(8, CPU−1) workers | MEASURED 64–80 MiB each |
| DB batch | 250–500 rows (byte-bounded) | |
| Unit workers per node | 2–4 | |

**Expected peak (EXTRAPOLATED):**

| Component | Peak |
|---|---|
| Engine/API base | ≈0.3–0.5 GB |
| Detector pool | ≈0.4–0.6 GB |
| Readers (16 × ≤ 2 × 16 MiB) | ≈0.5 GB |
| Units in flight (W ≤ 4 × ≈100 MB) | ≈0.4 GB |
| **Scanner total** | **≈2–3 GB, flat in N** |
| PostgreSQL `shared_buffers` | 4–8 GB |

The partitioned heap is already MEASURED flat (16.1 → 16.9 MiB traced, 1k → 4k files). The RSS residual is +3.7 KiB/file (allocator); its plateau is UNVERIFIED and must be checked at the 200K gate.

---

## 13. Concurrency model

Each layer is bounded, and each bound is a knob:

1. **Scans per node:** a global scan-slot cap, durable in `scan_jobs`; not per-process threads.
2. **Unit workers per node:** W (2–4), each owning one unit lease.
3. **Per-target sessions:** a cap S_target, shared through the database when there are several workers or nodes.
4. **Readers:** R ≤ S_target, each holding ≤ 1 file buffer.
5. **Analysis:** detector pool P = min(8, CPU−1), with the existing pipeline semaphore for backpressure into readers.
6. **DB writers:** ≤ 1 per unit worker; pool 10 per process.
7. **WinRM:** ≤ 1 command per endpoint at a time; global endpoint concurrency E; remote runspaces = f(endpoint cores).

If persistence falls behind, unit workers block on the persist; readers block on the semaphore; enumeration blocks on the ledger-write batch. **RAM is never the overflow buffer.**

---

## 14. Failure and recovery model

> *This table was the target. As a description of today it is wrong in several rows: see §23.9 for what the code does now and what Wave 3 must guarantee.*

| Event | Behaviour after Waves 1–2 |
|---|---|
| Unit worker crash | Lease expires (300 s) → unit requeued with attempt + 1 and backoff; committed units untouched (single-transaction persist + attempt CAS) |
| Backend crash | `scan_jobs` owner heartbeat stops → only that owner's jobs are failed or resumed; ledger scans resume under the same job id |
| DB outage | Unit workers pause and retry with backoff (today an inline scan fails or burns attempts) |
| Endpoint outage | The page unit fails → retried with backoff; after N failures the endpoint scan pauses as resumable |
| SMB interruption | The unit fails (not the share); circuit breaker pauses the target |
| Partial partition | Rolled back as a whole; re-run idempotently |
| Retry | Idempotent; tested by running the same unit twice → identical estate |
| Cancellation | Durable flag; engines and readers check it per file and per chunk; an in-flight unit's persist refuses a cancelled scan |

---

## 15. Benchmark plan (only what proves the roadmap)

| # | Test | Purpose |
|---|---|---|
| T1 | **Metadata scale test** (synthetic SMB / WinRM / local trees through fake transports: 20k → 200k entries, one flat folder of 100k) | Peak RSS vs N (must be flat); units, retries, resume |
| T2 | **Database scale test** (`pg_write_bench` promoted to `scripts/`; a real-schema synthetic loader with RLS at 200k / 1M / 5M findings) | Files/s first save and rescan; WAL bytes; table/index sizes; the click cost; console query p95 under concurrent writes |
| T3 | **Content throughput test** (representative 2–5 GB mix: Office, PDF, text, zip, media) | MB/s and files/s per core; bytes read per policy; extrapolate to 3 TB |
| T4 | **Real endpoint/file-server impact test** (pilot) | Target CPU/RAM/disk queue/handles (perfmon), SMB sessions, network Mbps, at the chosen caps |

**Measured today (baselines):**
- **Content scan:** 3,083 small files with 6 frameworks in 78 s (39.5 files/s). py-spy: detectors 36%, engine 26%, save 22%.
- **Engine, tiny files:** ≈250 files/s run-only, ≈205 with save, ≈160 with compliance, ≈112 partitioned (budget 250).
- **PostgreSQL write, synthetic 2 findings/file:**
  - first save: 187 files/s at 2k; 491 files/s at 20k (stats refreshed);
  - unchanged rescan: 92 files/s at 2k; 312 files/s at 20k;
  - first save at 20k with stale statistics: stall > 634 s.
- **Hashing:** SHA-256 388 MB/s per core.
- **API under load:** Locust, 40 users, 12,471 requests, 0 failures, p50 26 ms, p95 79 ms (3k-file estate; not scale evidence).

---

## 16. Scale certification gates

> *Superseded by §27, which keeps G0–G5, adds a fault gate and an amplification gate, and judges every gate on ten lines.*

| Gate | Where | PASS means |
|---|---|---|
| **G0 10K** | this host, PostgreSQL | All Wave 1 regression tests green on PG; kill/resume parity on PG; scale_gate envelopes on PG |
| **G1 200K architecture** | scale host (**UNVERIFIED – REQUIRES SCALE HOST**: C14 sized ≈150 GiB) | Peak RSS at 200k within 15% of 50k (same unit size). No transaction > 60 s. Unit retry idempotent. API p95 < 300 ms during the scan. PG first save ≥ 200 files/s and rescan ≥ 5× first-save speed (delta writes) |
| **G2 1M representative** | scale host + synthetic DB | T1 at 1M flat RSS; T2 1M/5M findings: click ≤ 50 ms, dashboard ≤ 500 ms, remediation page ≤ 300 ms p95; WAL per no-change rescan ≤ 10% of first scan |
| **G3 2M near-term production** | the pilot file server (real) | Full scan completes with no wall-clock failure; incremental (≤ 1% change) ≤ SLA (e.g. ≤ 2 h); peak scanner RSS ≤ 4 GB; target impact within the agreed caps; a mid-scan backend restart resumes |
| **G4 10M** | synthetic metadata + DB | Model holds (flat RSS, linear time); partition cap lifted. Else **UNVERIFIED** |
| **G5 50M** | modelling + multi-node rehearsal | Only after Wave 3 items; **never claimed without a run** |

---

## 17. Near-term production target (1 Windows File Server, 3 TB, 1–2M files)

**Must be true before deployment:**
1. W1.1 + W1.2 merged: partitioned is the path; SMB shares split into units; per-unit time budget; no `store._lock` around PostgreSQL writes.
2. W1.4 merged: no plan pathology; no O(scan) click; bounded transactions with timeouts.
3. W1.5 merged: correctness fixes (truncation/completeness, failed-analysis replay, UTF-16, connection-error classification, coverage truth).
4. W2.2 tiered hashing and caps: otherwise the first scan is network-bound at ≥ 7.6 h for 3 TB, and memory per reader can reach hundreds of MB.
5. W2.4 durable job state (owner heartbeat), so a restart during a multi-hour scan resumes.
6. G0 + G1 passed on PostgreSQL; G3 run as the pilot acceptance.
7. PostgreSQL tuning applied (shared_buffers, WAL, autovacuum) and `pg_stat_statements` enabled.

**Can wait:** W1.3 (WinRM paging; not on the file-server path), W2.1 (delta writes), W2.5 (read side), W2.6 (profiles).
- W2.1 is strongly recommended before daily incrementals.
- W2.5 matters once findings exceed about 1M.

---

## 18. 50M architecture target (beyond near-term)

- **Structure:** lift the partition cap; dynamic frontier enumeration for every source.
- **Nodes:** multi-node workers with shared artifact storage, a worker registry, and per-target throttles coordinated through PostgreSQL.
- **PostgreSQL:**
  - detail_json diet (≈43 KB logical per asset today);
  - history partitioned by scan/time with retention;
  - incremental aggregates instead of GROUP BY over the estate;
  - a dedicated search index (GIN unusable under RLS);
  - realistic hardware (≈2.5 TB current state on today's schema shrinks to ≈0.5–1 TB after the diet; EXTRAPOLATED).
- **Change capture:** USN Level 2 for the large file servers.
- **Certification:** G4/G5 on a scale host.

---

## 19. Estimated capacity model (8 vCPU / 32 GB, PostgreSQL local NVMe, 1 GbE)

> *Superseded by §26. Two rows here did not survive measurement: the incremental scan is not enumeration-bound (an unchanged rescan runs at 117–160 files/s), and the content rate has a bytes term (1.6 MiB/s of text on one core).*

All values EXTRAPOLATED unless marked.

| Quantity | Estimate | Basis |
|---|---|---|
| Content analysis rate | ≈40–60 inspectable files/s (small/medium docs, compliance on) | MEASURED 39.5 files/s on 6 vCPU, small files |
| Metadata enumeration | ≈1–3k files/s per share-unit stream; ≈10–30 min for 1M files | Round-trip model: ≈50k folder listings, parallel units |
| Bytes read, first scan | 3 TB today; ≈0.3–1 TB after W2.2 | File-size mix decides; measure the histogram |
| Network time, first scan | ≥ 7.6 h today; ≈1–3 h after W2.2 | 110 MB/s effective |
| Initial scan duration, 1M files | ≈4–8 h after Waves 1–2 (CPU ≈ network); 2M ≈ 8–16 h | 40–60 inspectable files/s, ≈40–60% inspectable |
| Incremental (1% change), 1M | ≈20–45 min (enumeration-dominated) | 10k changed files ≈ 4 min analysis |
| Peak scanner RAM | ≈2–3 GB, flat | §12 |
| PostgreSQL storage, 1M / 5M findings | ≈45–60 GB current state; +4 GB/scan before W2.1 retention | Agent model from measured row sizes |
| WAL per no-change rescan | today ≈ size of all rewritten rows (tens of GB at 1M); after W2.1 ≈ changed rows only | MEASURED rescan rewrites everything |
| Unit workers | 2–4 | |
| DB connections | ≈20–40 total | |

**Is 8 vCPU / 16–32 GB realistic for 1–2M files?** Yes, after Waves 1–2:
- **RAM** stops scaling with N (32 GB comfortable, 16 GB workable with PostgreSQL at 4 GB `shared_buffers`).
- **CPU** sets the first full scan at hours, which is acceptable once.
- **Incrementals** are enumeration-bound.

**Not realistic today:** the default path needs ≈29–58 GiB of scanner RAM for 1–2M small files and still fails at 30 minutes.

**Horizontal trigger:**

```
nodes = max( ceil(N_inspect / (R_node · SLA_s)),  ceil(B_read / (BW_node · SLA_s)) )
```

where `N_inspect` = new/changed inspectable files in the window, `R_node` ≈ 50 files/s, `B_read` = bytes to read, `BW_node` ≈ 110 MB/s.

| Case | Result |
|---|---|
| 2M initial, 48 h SLA, 1M inspectable | 1M / (50 × 172,800) = 0.12 → **1 node** |
| 50M initial, 72 h SLA, 20M inspectable | 20M / (50 × 259,200) = 1.5 → 2 nodes by CPU |
| 50M initial, ≈30 TB to read after tiering | 30e12 / (1.1e8 × 259,200) = 1.05 → 2 nodes by network |
| Daily 1% incremental at 50M | 500k inspectable / (50 × 86,400) = 0.12 → 1 node |

Horizontal scanning is justified for 50M *initial* scans and for many independent sources, not for 1–2M.

---

## 20. Execution order (practical)

> *Steps 1–7 and 9–11 are delivered (§5, §6). Steps 8, 12 and 13 are replaced by §29.*

1. **W1.5:** review and merge the pending worker branches (correctness prerequisites). Re-run on PostgreSQL.
2. **W1.4:** prune plan fix + index, O(1) lifecycle edits, transaction timeouts, `rows_json` removal.
3. **W1.1:** per-unit time budget + stall watchdog; `store._lock` only for SQLite; concurrent unit workers; partitioned tests on PostgreSQL.
4. **W1.2:** SMB `smb_range` units + streaming planner + unit retry/backoff + ACL batch fix.
5. **G0** on PostgreSQL. Flip `DSPM_PARTITIONED_SCANS` on by default.
6. **W2.2:** tiered hashing, caps, coverage states, single read for Office/PDF/OCR.
7. **W2.4:** durable job state (owner heartbeat, durable cancel/result), scheduler overlap guard.
8. **G1 200K** on a scale host (T1 + T2 + T3).
9. **W2.1:** delta writes + retention + index diet + fillfactor.
10. **W1.3:** WinRM folder-frontier paging, endpoint scans in the ledger, shell reuse, fleet cap.
11. **W2.3 + W2.5:** SMB read path, ACL refresh policy, target throttles; read-side caches/keyset/search decision.
12. **G2 1M** synthetic + **G3 2M pilot**.
13. **Wave 3 (only as the formula and metrics require):** partition cap, multi-node, USN, PostgreSQL 50M structure.

---

## 21. What NOT to do

- Do not raise `$maxRecords` (or any cap) to millions. Page instead.
- Do not raise RAM to fit `report["files"]`. Stream units.
- Do not disable the time budget entirely (`DSPM_SCAN_MAX_SECONDS=0`). Make it per unit and resumable.
- Do not add Redis, Celery, Kafka or Kubernetes. The PostgreSQL ledger already does durable claiming; the bottlenecks are elsewhere.
- Do not optimise SQLite as the enterprise database.
- Do not use one transaction per scan, nor one per file.
- Do not create one task per file in the ledger. Units are hundreds to thousands of files.
- Do not use unbounded queues. Every stage has a semaphore or lease.
- Do not keep full rescans forever. Metadata reuse exists; make it cheap (delta writes).
- Do not add more PostgreSQL indexes to fix reads. Remove the redundant and unusable ones first; justify each by write cost.
- Do not use COPY by bypassing RLS for speed.
- Do not treat mtime alone as cryptographic identity. Keep SHA-256 where evidence depends on it.
- Do not claim 2M, 10M or 50M, or 3–5 TB, without a gate run on a host that can hold it.
- Do not split every fix into its own phase. The waves above are the unit of planning.

---

## 22. Final priority table

> *Rows 1–10 and 12 are delivered. The current priority table is in §29.*

| Priority | Workstream | Why | Impact | Complexity | Dependency | Required for 1–2M? | Required for 50M? | Can be deferred? |
|---|---|---|---|---|---|---|---|---|
| 1 | W1.2 SMB intra-share units | A share is one memory/retry/txn unit | Removes the main memory and retry blocker on the target topology | HIGH | W1.1 | **Yes** | Yes | No |
| 2 | W1.1 Partitioned = the path; per-unit budget; no global lock on PG | Default path is O(N) RAM and fails at 30 min | Bounded RAM, no wall-clock failure | MEDIUM | W1.4 (PG) | **Yes** | Yes | No |
| 3 | W1.4 PG correctness (prune plan, O(1) click, bounded txns) | Quadratic first save; O(scan) clicks | Makes PG viable at 1M | MEDIUM | — | **Yes** | Yes | No |
| 4 | W1.5 Merge correctness fixes | Truncation/replay/UTF-16/coverage | Trustworthy incremental | LOW–MED | — | **Yes** | Yes | No |
| 5 | W2.2 Tiered hashing + caps + coverage | 3 TB full read; 100 MiB buffers | 3–10× fewer bytes; bounded readers | MEDIUM | W1.2 | **Yes** | Yes | No |
| 6 | W2.4 Durable job state | Restarts lose/kill scans | Multi-hour scans survive | MEDIUM | W1.1 | **Yes** | Yes | No |
| 7 | W2.1 Delta writes + retention | Rescans rewrite everything | Rescan DB work ∝ changes | MED–HIGH | W1.4 | Strongly | **Yes** | Briefly |
| 8 | W1.3 WinRM paging + ledger | 5,000-file cap | Endpoints of any size | HIGH | W1.1 | No (file-server target) | **Yes** (50+ endpoints) | Yes, after 1–6 |
| 9 | W2.5 Read side | O(estate) console aggregates | Console at 5M findings | MEDIUM | W2.1 | At ≥ 1M findings | Yes | Partly |
| 10 | W2.3 SMB read/ACL/throttle | Round trips, ACL drift, target safety | Speed + safety | MEDIUM | W1.2 | Recommended | Yes | Partly |
| 11 | Gates G0–G3 | Evidence | Certifies each step | MEDIUM | each wave | **Yes** | Yes | No |
| 12 | W2.6 Scan profiles | Clarity of depth vs cost | Operator control | LOW | W2.2 | No | Helpful | Yes |
| 13 | Wave 3 (partition cap, multi-node, USN, PG 50M structure) | Beyond one node / 4M files | Horizontal scale | HIGH | Waves 1–2 + G2 | No | **Yes** | Yes, until metrics |

---

## Final decision

> *The decision of 2026-10-02, kept as written. Its five changes are delivered. The current answers are in §30.*

1. **Top 5 changes by scalability gain.**
   1. SMB intra-share work units with streaming planning and per-unit retry (W1.2).
   2. The partitioned ledger as the only scan path, with a per-unit time budget and no process-global lock around PostgreSQL writes (W1.1).
   3. PostgreSQL correctness at scale: the stats-proof prune, O(1) lifecycle edits, bounded transactions (W1.4).
   4. Tiered hashing and byte-capped readers with truthful coverage (W2.2).
   5. Delta persistence so unchanged files cost no row writes (W2.1).

   WinRM paging (W1.3) is the top item for the 50-endpoint target, not for the file server.

2. **The single most important blocker for 1–2M files / 3 TB.** The SMB share is the indivisible unit. One 1–2M-file share is enumerated, downloaded and held in memory whole, retried as ≈31k-file chunks, and finally dropped as "done, incomplete". W1.2 fixes this, on top of W1.1's ledger path.

3. **Is 8 vCPU / 16–32 GB realistic after those changes?** Yes.
   - RAM becomes a constant ≈2–3 GB for the scanner (§12), instead of ≈30–60 GiB at 1–2M today.
   - CPU sets a one-time first scan of ≈4–8 h per 1M files; the network share of that falls 3–10× with tiered hashing.
   - Incrementals are enumeration-bound (≈20–45 min).
   - PostgreSQL fits in ≈50–60 GB on NVMe.

   This is EXTRAPOLATED from measured rates, and G1/G3 must confirm it. The bottlenecks that make it unrealistic *today* are software (B1–B4, B9–B11), not hardware.

4. **What still separates that system from 50M files.**
   - The 2,147-partition cap and static planning (needs a dynamic frontier and BIGINT `seq`).
   - Single-node artifact storage and per-process target throttles (needs shared storage, a worker registry and database-coordinated caps).
   - PostgreSQL volume and aggregates (≈2.5 TB current state on today's schema; needs a detail_json diet, history partitioning, incremental aggregates, real search).
   - No change journal.
   - No certification above ≈20k files on PostgreSQL.

5. **What the NEXT implementation prompt should focus on first.** W1.5 → W1.4 → W1.1 → W1.2, in that order:
   1. Merge the pending correctness fixes.
   2. Make PostgreSQL saves safe (the stats-proof prune, O(1) clicks, transaction timeouts).
   3. Make the partitioned ledger the scan path, with per-unit budgets and no global lock on PostgreSQL.
   4. Implement SMB `smb_range` units with a streaming planner and per-unit retry.

   Prove each step on PostgreSQL with `pg_write_bench` and the G0 gate before moving on.

---

# Part II — Reassessment, revised Wave 3, and Wave 4

*2026-10-05 · code read at `6ddfe31`. Landed afterwards and checked against the findings: three job-state fixes (`07f10be`, `f72463f`, `3096ea7`), which change none of them; and the advanced scan scope (`8954cf4`, `82ebfe4`, `7580006`), whose per-scan scope block W3.6 reuses. This part is analysis and plan: no product code was changed for it.*

**Status: AUTHORITATIVE.** Approved 2026-10-05, with the decisions in §23.0. Wave 3 (§24) is the next implementation; Wave 4 (§25) is approved as direction and is **not** to be implemented before Wave 3 exits.

**Where the two parts differ, Part II is the plan.** Part I (§0–§22) stays as the record of what was measured and decided for Waves 1 and 2. Part II supersedes §7 (Wave 3), §12 (memory model), §14 (failure model, as a description of today), §16 (gates), §19 (capacity model), §20 (execution order), §22 (priority table) and the Final decision.

**Evidence base.**
- Six read-only code audits at `6ddfe31`: enumeration and planning; content and classification; persistence and storage; database roles and locking; failure and recovery; the read side. Line numbers drift; function names are the anchors.
- Measurements taken on this host today (6 vCPU, 16 GB): `scripts/amplification_probe.py` in both modes, and two `py-spy` profiles. They ran on a throwaway SQLite install, because the PostgreSQL test database was in use by another session and C: had 3.4 GB free. Row counts and row operations are the same code path as PostgreSQL's.
- PostgreSQL figures are the ones recorded in §6 and in `docs/database/POSTGRESQL_WAL_ARCHIVE_AND_TUNING_2026-10.md`. **No PostgreSQL run above 20,000 files exists.**

**Labels.**
- **MEASURED**: run, at the size stated.
- **TESTED**: pinned by a regression test.
- **CODE-VERIFIED**: the code path was read end to end; nothing was run.
- **EXTRAPOLATED**: modelled from measurements.
- **ARCHITECTURALLY SUPPORTED**: the design allows it; nothing ran.
- **UNVERIFIED**: not checked.

---

## 23. Reassessment

### 23.0 Decisions recorded 2026-10-05

The four questions this reassessment raised were answered by the product owner. They bind Wave 3 and Wave 4.

| # | Question | Decision | Where it lands |
|---|---|---|---|
| D1 | May the console show the previous aggregate while it is rebuilt? | **Yes, marked.** The previous aggregate may be shown only as stale: with the exact time it was computed and the rebuild status (rebuilding, or rebuild failed). It is never presented as current data, in the console or in the API. | W3.4; §27 API line |
| D2 | How much scan history is kept? | **The latest 3 completed scans per label by default, configurable.** No unlimited full historical copies. Beyond the window only what audit and change tracking genuinely need is kept: the scan's summary and coverage, its audit events, and finding lifecycle (first seen, changed, resolved). A tenant under legal hold keeps everything. | W3.5; W4.1 |
| D3 | Is a verbatim report body stored for every scan? | **No, not by default.** A scan stores a summary, a manifest of its unit records, and the audit and evidence records it needs. No second full copy of the estate per scan. A full report that an operator explicitly exports or generates stays as an artifact under the retention policy. | W3.5 (the body becomes summary + manifest); W4.1 (content-addressed dedupe of unchanged units) |
| D4 | Is the default depth limit of 4 kept? | **No.** The default traverses the whole target. A depth limit exists only when configured, and is then part of the scan's visible scope and results; a depth-limited scan never claims full coverage. | W3.6 |

**Labels on scale figures.** Every figure for 10M or 50M files, and every claim that a 16 GB or 32 GB node suffices, is **EXTRAPOLATED** and stays **UNVERIFIED** until its gate passes: G2 (1–2M, 16 GB profile), G4 (10M, 32 GB) and G5 (50M). No such figure may be quoted without its label.

### 23.1 Where the product is after Waves 1 and 2

**What holds, and should not be redone:**
- Local, SMB and endpoint scans normally run as bounded units through the PostgreSQL ledger. Scanner RSS was flat from 4,000 to 20,000 small files: 320 → 295 MiB (MEASURED, PostgreSQL).
- A changed file costs only its own rows. 60 changed files in 6,000 produced 250 asset statements and 252 finding statements (MEASURED).
- An unchanged file is not read: 0 content reads on every rescan (MEASURED).
- Jobs have owners, heartbeats, and the states `paused` and `incomplete`.

**What still sets the limits:**

| Fact | Number | Label |
|---|---|---|
| A rescan's cost follows the estate, not the change | Unchanged rescan: 138–160 files/s (SQLite), 117 files/s (PostgreSQL). First scan: 46 and 41. So 1M unchanged files take about 1.7–2.4 h | Rates MEASURED; 1M EXTRAPOLATED |
| A default scan classifies on one core | 1.55–1.6 MiB/s of text and 46–49 small files/s on a 6 vCPU host. The process pool is built only when a compliance framework is selected (`detector_pool.build_pool`) | MEASURED; CODE-VERIFIED |
| A unit's memory follows the bytes it holds | Peak RSS ≈ 110 MiB + 1.0 MiB per MiB of text in the unit. Units of 30, 60 and 120 MiB peaked at 141, 173 and 233 MiB | MEASURED |
| Every scan stores the findings again, and the records twice | With nothing changed, a scan adds one `finding_index` row (1.2 KB) and one `finding_occurrences` row (0.17 KB) per finding, and 1.05 KB per file in the artifact store | MEASURED, 6,000 files / 9,600 findings |
| Proven scale | 20,000 files on PostgreSQL; 19,000 in the SQLite harness | MEASURED |

### 23.2 Measured amplification

| Quantity | Today | Basis |
|---|---|---|
| RAM per active unit | 110 MiB + 1.0 × text bytes held. With compliance on, add 64–250 MiB per detector worker. An SMB unit holds up to 512 MiB of weighted bytes, 2 GiB after two cap doublings (§23.5 N7). A local unit has no byte bound: 2,000 files × 16 MiB | Slope MEASURED (30–120 MiB units); workers MEASURED 2026-09; bounds CODE-VERIFIED |
| Database payload per file | 6.4 KB logical: asset 2.98 (of which `detail_json` 2.37), baseline 2.84 (of which `snapshot_json` 2.37: the same record again), access 0.36 (3 principals), version 0.20. PostgreSQL: 2.9 KiB per asset with its 21 indexes | MEASURED: SQLite, 6,000 small files; PostgreSQL bench, 4,000 |
| Database payload per finding | Row 0.68 KB (1.26 KiB on PostgreSQL with 16 indexes), plus 1.2 KB in `finding_index` and 0.17 KB in `finding_occurrences`. The last two are written again on every scan | MEASURED |
| Indexes on the seven hot tables | 46: assets 21, findings 16, `finding_index` 3, occurrences 2, access 2, baselines 1, versions 1 | CODE-VERIFIED |
| Other stores per file | Reuse cache: 5.9 KB in `meta_index.sqlite`, plus one 0.77 KB `.enc` file per scanned file, all in one directory. Artifacts: 1.05 KB per file per scan | MEASURED |
| Growth per scan with nothing changed | 1.36 KB per finding and 1.05 KB per file. The database file grew 16.7 MiB per scan for a 3.6 MiB corpus | MEASURED |
| WAL per new file | 12.4 KiB for the save alone (2 findings). End to end with 8 findings: 51 KiB at 20,000 files, 105 KiB at 4,000 | MEASURED, PostgreSQL |
| WAL per unchanged file | 5.3 KiB for the save alone. End to end: 45 KiB at 4,000 files, which is 43% of a first scan against a target of 10% | MEASURED, PostgreSQL |
| Row writes per unchanged file | In PostgreSQL 2 + 3F row versions: the asset, its baseline, and per finding one update and two inserts. Beside them, a no-op version upsert and a reuse-cache rewrite. With 5 findings: 17 rows and 2 other writes | MEASURED (row counters, statement trace); baseline CODE-VERIFIED |
| Statements per new file | 3 + principals + 3 per finding, pipelined in batches of 1,000 rows | CODE-VERIFIED |
| Source bytes read | First scan: Σ min(size, cap) over inspected types, 0.127 of the corpus on the W2.2 mix. Unchanged: 0 | MEASURED, 2,071 files / 1.4 GB |
| Source operations per file | SMB, new file: its folder listing, 1 ACL read, 1 open and close per MiB read. SMB, unchanged: the listing only. WinRM: 4,400–31,000 commands per 1M files, each a new `powershell.exe`; a new file is read twice (text, then hash) | CODE-VERIFIED |
| Repeated listings | A folder is listed once per planning pass, and once more by every range unit that covers part of it. A folder of 1M entries is listed about 500 times | CODE-VERIFIED |
| Copies of one analysed record | 5 live: `detail_json`, `snapshot_json`, the reuse cache, the unit artifact, the report body. One more body per scan, kept for ever. All of it again in each of 7 backup sets | CODE-VERIFIED; sizes MEASURED |
| Copies of content in memory | Parent: 2 T + R per in-flight file. Detector worker: 10–15 T. (T is the decoded text, R the raw bytes.) The worker sends the content back with its result | CODE-VERIFIED |
| CPU of an unchanged rescan | About a third is JSON, gzip and encryption of records that did not change. By stage: persist 33%, walk and probe 25%, finalize 14% | MEASURED (py-spy, 4,000 files, 427 samples: coarse) |
| Temporary bytes | Scanning: none beyond SMB OCR images (25 MiB each at most). Backup: a plaintext dump and a tar of the whole artifact store in %TEMP% | CODE-VERIFIED |

### 23.3 What the roadmap got right

- One bounded path through a durable ledger, with SMB shares cut into range units.
- PostgreSQL as the queue: no Redis, Celery or Kafka. Nothing found since argues for one.
- Bytes read follow bytes inspected; coverage states that never overclaim.
- Row-level security kept; SQLite not optimised as an enterprise database.
- Delta persistence as a direction. The estate tables are now O(changed) (MEASURED).
- "Never claim a scale without a run."

### 23.4 What it got wrong, and what is out of date

| Part I item | Class | Why |
|---|---|---|
| §0, §1 (the switched-off bounded path) | OUTDATED | Describes the product before Wave 1 |
| B1, B2, B3, B5, B6, B8, B9, B10, B12 | ALREADY SOLVED | Waves 1–2, with the tests named in §5 and §6 |
| B4 whole-scan wall clock | PARTIAL | Gone from the bounded path. It returns through the unpartitioned fallback (N2) |
| B7 SMB retry granularity | PARTIAL | A unit is retried. Infrastructure and data failures share one attempt counter, and a unit out of attempts fails the scan (N3, N4) |
| B11 "every rescan rewrites everything" | PARTIAL | Estate rows are no longer rewritten. Presence stamps, per-scan history and both artifact copies still are |
| E1, E3, E4, E5, E6, E12 | ALREADY SOLVED | W2.2, W2.3 |
| E2 one SMB open per MiB; E11 content returned over IPC; E13 silent depth limit; E14 ACL drift | CORRECT, still open | Re-confirmed in code |
| E7 single-threaded local collection | UNDERENGINEERED | The larger fact is that classification itself runs on one core for a default scan (N9) |
| E8 per-partition fixed costs | PARTIAL | The detector pool is shared. The whole reuse-cache directory is still listed once per unit, and planning still re-walks (N7, N11) |
| E9 unchanged-rescan write amplification | CORRECT, still open | 6,000 cache rewrites per 6,000-file rescan (MEASURED) |
| E10 read side | PARTIAL | Cached and single-flight inside one process. Nothing is served while a rebuild runs (N12) |
| §5 Wave 1 status, "Done" | CORRECT, with three caveats | "No wall clock on the scan" holds only on the bounded path (N2). The streaming planner left out of W1.2 is now a blocker at 3 TB (N7). "No record cap" on endpoints stops at 2,147 pages |
| §6 Wave 2 status: W2.2, W2.3, W2.6 | CORRECT | Re-measured or re-read; nothing to add |
| §6 Wave 2 status: W2.1 "Done" | PARTIAL | True for the estate rows. An unchanged rescan still writes 2 + 3F row versions per file and stores the estate again (§23.2) |
| §6 Wave 2 status: W2.4 "Done" | PARTIAL | Jobs are durable. A scan is still failed for good by an infrastructure error (N3), and six job-state defects were found by review and fixed in `f72463f` |
| §6 Wave 2 status: W2.5 "Done" | PARTIAL | N12 |
| §6 "G1 200K: held for scale host" | CORRECT | Still so. C: has 3.4 GB free |
| §2.3 "the 2,147-partition cap does not block 2M" | WRONG ASSUMPTION | W1.2 added a 512 MiB byte budget per unit. The cap now binds at about 1.1 TB of weighted bytes, inside the 3 TB target (N7) |
| §2.3 "SQLite is not relevant" | PARTIAL | The authority gates hold. A local SQLite file and a flat-file cache sit on the hot path of every PostgreSQL deployment, and operator tools can run on a stray SQLite file (§23.7) |
| §3 "metadata-first reuse: KEEP, TUNE" | UNDERENGINEERED | Per-file reuse is itself O(estate): every unchanged file is probed, rebuilt, digested, serialised and stamped |
| §4 target architecture, "set-based touch of unchanged" | UNDERENGINEERED | A touch per row is still O(files + findings) row versions, and per-scan history is absent from the design |
| W2.1 fillfactor 60 on assets and findings | SUPERSEDED by W4.2 | It trades 40% of each heap page for HOT presence updates. Without per-row presence the tables return to about 90 |
| §7 item 1, certification gates | CORRECT; REQUIRES NEW EVIDENCE | No scale host yet. Criteria extended in §27 |
| §7 item 2, multi-node scanning | WRONG PRIORITY | One node classifies on one core and pays O(estate) per scan. More nodes would multiply the same writes into one PostgreSQL |
| §7 item 3, "50M structural": partition cap, dynamic frontier | WRONG PRIORITY | Needed at 1–2M / 3 TB, not at 50M (N7). Moved into Wave 3 |
| §7 item 3: `detail_json` diet, incremental aggregates | WRONG PRIORITY | They decide the minimum resources at 1–2M. Moved into Wave 4 |
| §7 item 3: history tables partitioned by scan or time | OVERENGINEERED | Partitioning a table that should mostly not be written. Stop writing it (W4.1, W4.2) |
| §7 item 3: a dedicated search index | OVERENGINEERED for now | Normalised filter tables and the existing optional projection come first (W4.4) |
| §7 item 4, change journal | CORRECT as deferred | Trigger restated in §26.4 |
| §8 size model, "≈55–60 GB, +4 GB per scan" | PARTIAL | Database only. It leaves out two estate copies per scan in the artifact store (never collected by default), the local caches, 7 full backup sets and the WAL archive |
| §12 "no term contains N(files)" | WRONG ASSUMPTION | Three terms do: a unit holds all its content; the cap doubling grows the unit with the estate; the API parses whole reports (N1, N7) |
| §14 failure table | WRONG as a description of today | "Database outage: workers pause and retry" is not implemented. A blip fails the scan for good (N3) |
| §19 "content analysis ≈40–60 files/s" | PARTIAL | True for small files. It is one core, and it has no bytes-per-second term: 1.6 MiB/s decides the first scan of large text |
| §19 "incremental ≈20–45 min, enumeration-dominated" | WRONG ASSUMPTION | An unchanged rescan runs at 117–160 files/s: about 2 h per 1M files, pipeline-dominated |
| §19 horizontal trigger, `R_node ≈ 50 files/s` | REQUIRES NEW EVIDENCE | Re-derive after W4.3 |
| §17, §19 "8 vCPU / 16–32 GB is realistic after Waves 1–2" | PARTIAL | True for the scan process on small files (295–320 MiB, MEASURED). Not yet safe at 16 GB: one folder of large text files, or one click on Findings, can exceed it (N1, N7). No document in the repository asks for 64 or 128 GB, and nothing found here justifies it |
| §18 "50M ≈ 2.5 TB of current state, 0.5–1 TB after the diet" | REQUIRES NEW EVIDENCE | Re-modelled at 325–750 GB after W4.1 (§26.2, EXTRAPOLATED), from measured row sizes. No run above 20,000 files |
| §16, §20, §22, Final decision | SUPERSEDED | §27, §29, §30 |

### 23.5 Bottlenecks the roadmap did not have

All CODE-VERIFIED at `6ddfe31` unless marked. Sizes at scale are EXTRAPOLATED.

| # | Finding | Evidence | What it costs at 1–2M files |
|---|---|---|---|
| N1 | **Interactive paths parse whole scan reports.** `/api/history/hash-changes` parses the two newest reports; the console calls it when Findings is first opened and after every scan. The PDF report is built on the event loop, one row per file. The finding drawer falls back to a whole report for any finding outside the 5 newest scans. `/api/history/{id}/report` returns the files by default | `app.scan_hash_changes`, `store._report_body`, `reporting/router.create_report`, `store._find_finding_row` | 5.4–6.5 KiB of RSS per file per parsed report (the code's own figure): 11–13 GiB for two 1M-file reports. With inline execution the scan runs inside this process, so the API's out-of-memory kill is the scan's too |
| N2 | **The bounded path has exits.** A connection reset during SMB planning, a group of overlapping shares, or a file named `_manifest.json` makes the planner return nothing, and the scan then runs unpartitioned: the whole estate in memory under the 1,800 s wall clock | `partition.plan_share_partitions`, `app._run_partitioned_scan_payload` ("Not worth partitioning") | The two failure modes Wave 1 removed, reachable by a network blip |
| N3 | **Infrastructure errors fail a scan for good.** Any exception in the control loop or in finalize marks the scan `failed`, and a failed scan is never resumed. A database error during a persist discards the unit and spends one of its 3 attempts. With the file server offline, every queued unit burns an attempt at connect-timeout speed | `partitioned_scan.continue_partitioned_scan`, `_run_unit`, `settle_if_finished` | A 2-second database blip is worse than a 10-minute outage: the blip lets the "failed" mark land |
| N4 | **One unit out of attempts fails the whole scan.** No quarantine, no retry API. An SMB unit over its time budget raises "Scan cancelled", which counts as a failure | `partitioned_scan._run_partitions` | Hours of completed units end as `failed` because of one folder |
| N5 | **A hung file hangs its scan as RUNNING for ever.** Extraction and detection have no enforced timeout; deadlines are checked between files; the lease thread keeps renewing. A detector timeout disables the shared pool and reruns the same payload in the parent | `detector_stage`, `detector_pool`, `partitioned_scan._run_unit` | Cancel cannot unblock it; the third restart fails it |
| N6 | **Finalize is O(estate), twice, in one transaction.** It reads every unit artifact, then streams the whole body again inside a transaction that holds the tenant's advisory lock and idles meanwhile (limit 1,800 s). A crash waits 3,600 s and redoes everything; an error is a permanent `failed` | `store.finalize_partitioned_scan`, `partitioned_scan._finalize_when_claimed` | MEASURED about 0.7 ms per file for small records (py-spy, 4,000 files). EXTRAPOLATED: about 25 min at 2M files, part of it inside the idle transaction; larger records reach the 30-minute limit sooner, with every unit already done |
| N7 | **Unit size is bounded by count, and grows with the estate.** Content stays in the unit's records until the unit ends. Local units have no byte budget. Above 2,147 units the planner doubles both budgets and walks the whole target again; 2,147 × 512 MiB is 1.1 TB of weighted bytes | `partition.plan_bounded_partitions`, `plan_share_partitions`, `smb_scanner.plan_share_ranges` (weight = min(size, read cap) for every file, read or not) | 3 TB over SMB: likely 1–2 doublings, units of 4,000–8,000 files and 1–2 GiB, 2–3 serial planning walks before the first unit starts. Endpoint scans fail outright above 2,147 pages |
| N8 | **An unchanged file still goes through the whole pipeline** after the read: probe, rebuild, digest, unit artifact, report body, stamps, index and occurrence rows | §23.2 (MEASURED) | About 7 ms and 2 + 3F row writes per unchanged file, every scan |
| N9 | **A default scan classifies on one core** (threads in the engine process). The pool exists only with compliance on. Two detector paths are quadratic: PCI rebuilds a context blob per card and per CSV row; GDPR tests membership in uncapped lists | `detector_pool.build_pool`; `pci_classifier`, `gdpr_classifier` | MEASURED 1.6 MiB/s. 50 GB of inspected text takes 8.3 h on any core count |
| N10 | **Storage that nothing reads or collects.** `finding_occurrences` and `asset_versions` have no reader. Only the newest `finding_index` row per finding is read. Unit artifacts are released at finalize but collection is off by default. No code deletes a scan, its report, or its history rows. Each of 7 backup sets tars the whole artifact store | `store` (no `SELECT` from either table), `housekeeping`, `backup` | Heavy case, a month of nightly scans at 1M files: on the order of 1 TB of Sentro-owned storage (§26.3) |
| N11 | **The reuse cache does not scale as a directory.** One file per scanned file in one folder, never evicted. Each unit's engine lists the whole folder into a set | `discovery_engine._finding_digest_exists`, `scan_cache.write_entry` | A rescan of 2M files lists about 2 × 10⁹ directory entries and holds 0.3 GiB per unit. At 50M it cannot run |
| N12 | **The console stops being served from cache once a rebuild outlasts its validity.** TTL 30 s; the generation moves every 15 s per process during a scan; nothing is served while a rebuild runs; followers wait up to 120 s and then build themselves. One pool of 10 connections is shared with the scan. Statement and lock timeouts are 900 s. `store._lock` is still taken at about 130 call sites on PostgreSQL | `live_cache`, `store._build_remediation_summary`, `db` pool settings | 6–9 ms per 1,000 findings (MEASURED): the break-even is 1.7–2.5M findings. Beyond it every page waits 30–45 s, the pool empties, and login and job polls fail |
| N13 | **Prune and "complete" can be wrong.** Two scans with one label: the later finalizer deletes what the newer scan stamped. Completeness is all-or-nothing, so one unreadable folder disables every prune. A unit can be complete but empty (session wait past the deadline; a WinRM page with no output) | `store._prune_unseen_assets`, `discovery_engine` completeness | Deleted assets that exist, or stale assets that never leave |
| N14 | **Operator tools can run on a stray SQLite file.** Only `main.py` resolves the configuration file. `python -m backend.migrations upgrade`, the scripts and a bare `uvicorn` see no database URL, create `data\dspm.sqlite`, and succeed on it. Every import also runs a demo-asset purge scan | `config.bootstrap`, `store` import | A retention or migration command that reports success and touched nothing |
| N15 | **Coverage is lost silently.** `max_depth` defaults to 4 for SMB and local scans. Paths containing `\windows\`, `\program files\`, `\programdata\` and similar are skipped with no counter | `app.ScanRequest`, `smb_scanner._skip_path` | A scan reported complete that never entered most of a deep share |

**Checked and found sound** (CODE-VERIFIED): job polling (one request every 1.2 s, no overlap, one primary-key read); progress writes (one update per second per job, not per file); the console's DOM and client arrays (50 to 5,000 rows, bounded, no growing logs); inventory export (streamed by keyset); double persistence of a unit (prevented by the attempt check at both ends of the transaction); a partial artifact is never referenced by a row.

### 23.6 Rankings

**Resource bottlenecks on one node, largest first:**
1. Work per scan that follows the estate instead of the change: CPU, database writes, WAL and storage (N8, N10).
2. First-scan classification on one core (N9).
3. Copies and per-scan history: storage, WAL, backups (N10).
4. A unit's working set, bounded by count (N7).
5. Console aggregates recomputed from the estate (N12).
6. PostgreSQL write overheads: 46 indexes, text hash keys, a process lock and a tenant-wide advisory lock.
7. Protocol overheads: one SMB open per MiB, one PowerShell per WinRM command.

**Crash, freeze and stuck risks at very large scale, worst first:**
1. Whole-report parses in the API process (N1): out of memory, and the scan dies with it.
2. The unpartitioned fallback (N2).
3. Finalize at the idle-in-transaction limit, with a full redo (N6).
4. A database blip or one bad unit ending the scan as `failed` (N3, N4).
5. A hung file leaving the scan RUNNING for ever (N5).
6. Aggregate rebuilds and the shared pool freezing the console (N12).
7. Unit growth through the partition cap (N7).
8. Disk: artifacts never collected, plaintext backup staging, the unpruned WAL archive (N10).

**What limits one node today** (rates MEASURED, limits EXTRAPOLATED): a first scan covers about 4M small files or 135 GiB of text per day; a rescan covers 10–14M files per day whatever changed; finalize reaches its 30-minute limit near 2M files; the partition cap binds near 1.1 TB of weighted bytes; storage grows by every scan and is never trimmed.

### 23.7 PostgreSQL and SQLite: the actual roles

- **Authoritative database.** PostgreSQL holds the estate, the ledger and queue, jobs, sessions, audit and the derived cache. Production refuses SQLite at three gates (`config.production_problems`, the `store` import, application start). There is **no fallback from PostgreSQL to SQLite**, at boot or at run time (CODE-VERIFIED).
- **SQLite and local files on the hot path of a PostgreSQL deployment:**

| Store | Holds | Divergence risk | Growth |
|---|---|---|---|
| `meta_index.sqlite`, one per tenant | The reuse snapshot of every file: owner, ACL, preview, findings | Low for findings (the key carries the policy signature, and estate writes compare PostgreSQL digests). Owner and ACL are replayed stale (E14). If lost: one PostgreSQL query per file, under the process lock | One row per file version, never evicted, rewritten every scan |
| `<digest>.enc` findings cache | Findings per file | A missing entry fails closed: the file is re-read | One file per scanned file, never evicted |
| Artifact store (a local directory) | Unit records and report bodies, referenced from PostgreSQL rows | High. References dangle if the directory is lost or the unit ran on another node. Tenant erasure deletes files inside an uncommitted transaction | Two estate copies per scan until collected |

- **Unintended SQLite.** N14.
- **Duplication.** The analysed record is in PostgreSQL twice and on local disk three times (§23.2).
- **Efficiency.** The bulk path is sound: pipelined `executemany`, 1,000 rows per batch. The costs are in §23.6 item 6, plus 5 round trips per one-statement transaction and one query per file when the local cache misses.
- **Direction.** Wave 4 spends nothing on SQLite as a primary database. It takes SQLite and flat files off the PostgreSQL hot path (W4.1, W4.2).

### 23.8 What each kind of scan pays

| Scan | Content read | Pipeline | Database | History and artifacts | Rate today (MEASURED) |
|---|---|---|---|---|---|
| Initial | Σ min(size, cap) of inspected types | Full, on one core | 3 + principals + 3F statements per file | One of each | 41–49 files/s; 1.6 MiB/s |
| Unchanged | 0 | Everything after the read, per file | 2 + 3F row writes per file | A full copy again | 117–160 files/s |
| About 1% changed | The changed files | As unchanged, plus 1% of an initial scan | As unchanged, plus the changed rows | A full copy again | 139–143 files/s |
| About 10% changed | The changed files | As unchanged, plus 10% | As unchanged, plus the changed rows | A full copy again | 109–110 files/s |
| Large change (new detection rules) | Everything again: the reuse key carries the policy signature | Full | Rows whose result changed | A full copy again | As initial |

Repeated work with no information in it: the per-file probe, rebuild and digest of unchanged files; every presence stamp; every `finding_index` and `finding_occurrences` row after the first; both artifact copies; the reuse-cache rewrite; the aggregate rebuilds a scan forces.

A suppression-rule change does not re-read content: the findings cache keeps findings from before suppression. A detection-rule change must re-read; W4.3 makes that cheaper, nothing makes it free.

### 23.9 What happens on failure today, and what Wave 3 must guarantee

| Event | Today (CODE-VERIFIED) | Guarantee after Wave 3 |
|---|---|---|
| Backend restart | Mid-unit: the unit is redone after its 300 s lease plus up to 60 s, and the restart spends an attempt. Mid-finalize: a 3,600 s wait, then a full redo. Mid-planning: nothing was recorded, the job fails | One unit redone, no attempt spent. Finalize resumes at its step. Planning resumes from the units already written |
| Worker crash | The lease expires within 300 s and the unit is requeued. One unit and one attempt are lost | Same, without the attempt |
| PostgreSQL unavailable | A persist error discards the unit and spends an attempt. A control-loop or finalize error marks the scan `failed` for good if the mark lands | Bounded retry, then `paused`. Never `failed`, never an attempt |
| SMB disconnect, server offline | A reset retries the chunk, then the unit. With the server offline every queued unit burns its attempts in turn and the scan fails in minutes | The target's breaker pauses the scan. Units keep their attempts |
| WinRM hang, endpoint offline | A command times out after 900 s; three timeouts fail the scan. Offline: failed within minutes | A hung command costs one page. An unreachable endpoint pauses the scan |
| Disk low or full | Checked between units, inline only: not in queue workers, not before finalize, not for PostgreSQL's volume unless configured. Out of space in finalize is a permanent `failed` | Checked in every executor and before finalize; a scan projected not to fit is refused. Out of space pauses |
| WAL grows unexpectedly | Reported when the archive directory is configured; nothing acts on it | The same floor pauses the scan; the pre-flight projects WAL from measured per-file figures |
| User cancels | The job is cancelled at once and the engine stops at the next file (up to 900 s inside a WinRM command). The cancel is not on the scan record, so a restart can resume a cancelled scan | Cancel is durable on the scan. Units already persisted stay; nothing is pruned |
| One unit fails repeatedly | The whole scan is `failed` | The unit is quarantined and named; the scan finishes `incomplete`; nothing it missed is treated as deleted |
| A file hangs its parser | The scan is RUNNING for ever | The file is killed at its deadline and marked FAILED; the unit completes |

---

## 24. Revised Wave 3 — contain, bound, certify

Wave 3 was "scale validation, then horizontal expansion". It becomes: **no failure costs more than one unit, no path leaves the bounded pipeline, no request reads a whole scan — then certify.** Only the changes are listed.

| Change | What | Why (evidence) |
|---|---|---|
| KEEP | Certification on a scale host: G1 200K, G2 1M, G3 pilot | Still the only proof. It now comes after the containment items, with the wider criteria of §27 |
| ADD W3.1 | **No exit from the bounded path.** Planning failure retries, then pauses; it never runs the estate unpartitioned. Overlapping-share groups are cut into ranges. The 2,147 cap goes: 64-bit ordering, no budget doubling. Units are written to the ledger while the walk runs, so planning is resumable and the first unit starts in seconds. A folder is listed once and feeds successive units. Local units get the byte budget. A unit's weight counts only bytes that will be read | N2, N7. Two items Part I filed under "50M" bind at 3 TB |
| ADD W3.2 | **Failures are contained.** Infrastructure errors (database, pool timeout, unreachable target, disk) pause and resume: no attempt spent, no `failed`. A unit out of data attempts is quarantined and the scan ends `incomplete`. A per-file deadline in a killable worker; the lease stops renewing past the unit's budget. Finalize runs in recorded steps, with the body streamed outside the transaction. Cancel is durable on the scan record. Prune checks that no newer scan of the label exists; completeness is per unit; an empty unit is not complete | N3, N4, N5, N6, N13 |
| ADD W3.3 | **No interactive path reads a whole scan.** Hash changes are computed from rows, or once at finalize. Reports are built from rows, off the event loop, with a row ceiling. The drawer and triage never fall back to a body. Report endpoints refuse or stream above a size | N1: the largest memory term left in the product |
| ADD W3.4 | **The console survives a scan.** While one rebuild runs across processes, the previous aggregate is served marked stale: the exact time it was computed and the rebuild status travel with it, and the console shows them; it is never presented as current (D1). Separate connection budgets for the scan, the API and heavy reads. Interactive lock and statement timeouts in seconds. `store._lock` taken on SQLite only | N12. Relaxes B3.1's "never serve the estate as it was", as approved in D1 |
| ADD W3.5 | **Storage stops growing by default.** Retention keeps the latest 3 completed scans per label, configurable; older scans keep only their summary, coverage, audit events and finding lifecycle (D2). A scan's stored record is its summary plus a manifest of the unit record artifacts it already wrote: finalize no longer streams a second full copy of the estate (D3; also removes most of N6). An explicitly exported or generated report is an artifact under the same retention. Artifact collection on after finalize, with the `.part` sweep. The two unread tables are no longer written. Backups copy artifacts incrementally and stage nothing in plaintext. A node profile for 16 and 32 GB ships with the PostgreSQL settings (§26.1). Configuration is resolved inside `backend.db` | N10, N14 |
| ADD W3.6 | **Coverage is said.** No default depth limit for local, SMB or endpoint scans (D4). A configured limit is part of the scan's scope, recorded in the scope block the advanced scan scope (`8954cf4`) already reports, and in the results: the folders not entered are counted, and the scan's coverage says it was depth-limited, never full. Skipped system paths are counted the same way. The ACL refresh policy left over from W2.3 (E14) | N15 |
| MOVE to Wave 4 | The `detail_json` diet, the history model, incremental aggregates | They decide minimum resources at 1–2M, not only at 50M |
| MOVE from Wave 4 to W3.5 | The per-scan body becomes summary + manifest (part of W4.1 step 3, without the cross-scan dedupe) | D3 forbids the per-scan copy by default, and it is the cheapest way to make finalize short (N6) |
| DEFER past Wave 4 | Multi-node scanning, a shared artifact store, a worker registry, the change journal, a dedicated search engine | §26.4 gives the trigger. Until one node uses its cores and pays only for change, more nodes multiply waste into one PostgreSQL |

**Wave 3 exit.**
1. The fault gate (§27) passes on PostgreSQL: every event of §23.9 ends in its guaranteed state, with estate parity against an uninterrupted run.
2. No code path can run an unpartitioned scan above one unit's worth of files (TESTED).
3. A unit of 2,000 files × 16 MiB runs inside the byte budget (TESTED).
4. No interactive route can reach the report-body reader (TESTED by a guard that fails the request).
5. Storage after 10 unchanged scans equals storage after 3 (the default window). No per-scan full copy of the estate is written.
6. A scan run with no depth setting enters every folder; a depth-limited scan reports its limit and the folders it did not enter, and is never shown as full coverage (TESTED).
7. G1 passes on a scale host. Then the pilot (G3) may be attempted: it will complete, and it will be heavy (§28).

---

## 25. Wave 4 — Maximum Optimization / Minimum Resource

**Purpose: make every cost of a scan follow what changed and what is inspected, and keep one copy of each fact, so that the same 16–32 GB node holds ten times the files.** (A target: EXTRAPOLATED, UNVERIFIED until G4.)

Six workstreams, in priority order (impact × resource reduction × reliability × 50M value, over complexity and regression risk). The designs are directions verified against the current code; each is confirmed or corrected when implemented.

### W4.1 One copy of each fact, and nothing unread

- **Objective.** Sentro-owned bytes are the estate once, plus what changed.
- **Verified root cause.** Five live copies of every analysed record, one more per scan kept for ever, two tables nothing reads, 46 indexes on seven tables (§23.2, N10). MEASURED: +2.8 KB per file and +1.05 KB of artifacts for a scan in which nothing changed.
- **Change.**
  1. `finding_index` keeps one body per finding version (finding id and digest), not one per scan. `finding_occurrences` is no longer written (W3.5), or is folded into that body.
  2. The baseline keeps the fingerprint and digest; the snapshot is read from `assets`. `detail_json` stops repeating what the `findings` rows hold.
  3. The manifest W3.5 introduces points at content-addressed unit records, with the keys a reuse rewrites stripped, so an unchanged unit points at the object it already has and no scan stores it again.
  4. The reuse cache is not written on a hit; the one-file-per-file layout goes; entries are evicted by generation.
  5. Index diet: candidates are the six two-column prefixes on `assets`, the duplicate `modified_at` index, `findings (tenant_id, asset_id)` and `finding_index (tenant_id, index_version)` (redundant by their column lists; each confirmed by `EXPLAIN` before it goes). Every survivor is justified by a read. `wal_compression = lz4` in the node profile.
- **Expected impact** (EXTRAPOLATED). Growth per unchanged scan: 3.9 KB per file → about 0.2 KB (presence stamps only, until W4.2). First-scan database bytes −35–45%. First-scan WAL −30–50%. Backups shrink with the artifact store.
- **Affected subsystems.** `store` (history, baseline, finalize, indexes, a migration), `artifacts`, `partitioned_scan` finalize, `discovery_engine` cache, `housekeeping`, `backup`.
- **RAM.** Finalize no longer parses each unit's records twice. No estate-sized body is left for anything to parse.
- **Storage.** The largest reduction in the plan (§26.3).
- **CPU, network, database.** Less JSON, gzip and encryption on every scan; fewer index inserts per row; fewer full-page images.
- **Reliability.** Finalize becomes short. Fewer objects that can dangle.
- **Risks.** History views must give the same answers from one body plus scan intervals. Per D3 there is no verbatim per-scan body by default: the summary and the manifest's hash are the audit anchor, and an explicitly exported report is the verbatim copy. A data migration of existing history.
- **Validation.** `amplification_probe.py rates` before and after; history and drawer parity tests on SQLite and PostgreSQL; `pg_write_bench` and `pg_scan_rehearsal` WAL; restore drill with incremental artifacts.
- **Exit criteria.** At most 2 stored copies of a record (PostgreSQL, and its backup). Bytes per file per unchanged scan ≤ 0.3 KB. First-scan WAL per file ≤ 70% of today's on `pg_scan_rehearsal` at 20,000 files. History parity.

### W4.2 Unchanged costs nothing

- **Objective.** A rescan's time, row writes and WAL follow the changed folders. An unchanged folder costs its listing and one small row.
- **Verified root cause.** Reuse is decided per file, after which the file still goes through probe, rebuild, digest, serialisation and three presence stamps (N8). MEASURED: 7 ms and 2 + 3F row writes per unchanged file; a third of the CPU is serialisation of unchanged records.
- **Change.**
  1. A folder manifest: per scope and folder, a digest of the listing (names, sizes, modified times, change times and file ids where the source gives them), the policy signature, the file count, and the scans that last saw and last changed it.
  2. A folder whose digest and signature match is skipped whole: no per-file probe, no records, no artifact, no stamps. Its manifest row is stamped, set-based per unit.
  3. Presence and prune move from row stamps to the manifest. Files missing from a changed folder's listing are retired in that unit's transaction. Folders a complete scan did not see are retired by folder key. `assets` gets an indexed folder key. Fillfactor returns to about 90.
  4. A unit's identity becomes its folder, which is stable. Today's ids are positional: one added file shifts every later boundary.
  5. Changed folders keep the per-file path, with one batched baseline query per listing instead of the local cache.
  6. Finding history records only what opened, changed or resolved; a scan's view is the interval a finding was current.
- **Expected impact** (EXTRAPOLATED). Unchanged rescan: from 117–160 files/s to listing speed. Row writes per unchanged file: from 2 + 3F to about one per folder. WAL per unchanged rescan: −95% or more.
- **Affected subsystems.** `partition` and the planners, `partitioned_scan`, `store` (presence, prune, baselines, history), all three collectors' listing code.
- **RAM.** Records of unchanged folders are never built.
- **Storage.** No per-scan growth for unchanged data; manifests cost about 0.2 KB per folder.
- **CPU, network, database.** CPU and database work ∝ change. Network: the listing only, as today.
- **Reliability.** Shorter scans meet fewer faults. Presence no longer depends on every row being stamped.
- **Risks.** The highest regression risk in the plan: prune semantics change. A content change that keeps size and modified time is missed, as it is today; the full-rescan control stays. ACL drift: the change time moves when the security descriptor does, and SMB listings carry it, which would close E14 without a round trip per file — UNVERIFIED on a real server, including for inherited changes.
- **Validation.** Estate parity between the skipping scan and a full scan, on SQLite and PostgreSQL, across 0%, 1%, 10% and 100% change; deleted, renamed and moved folders; an ACL-only change; overlapping scans of one label; mutation checks on every skip condition.
- **Exit criteria.** Unchanged rescan ≥ 20× the first-scan rate on the probe (local). Row writes per unchanged file ≤ 0.1. WAL of an unchanged rescan ≤ 2% of the first scan's. Parity on every case above.

### W4.3 Classification on every core, at a bounded cost per byte

- **Objective.** First scans and changed files use the node's cores, and no file can hold a worker.
- **Verified root cause.** N9: threads in one process unless compliance is on (MEASURED 1.6 MiB/s, 46–49 files/s on 6 vCPU). The worker returns the content. The parent encodes each record several times and seals the cache entry twice. One cache file is created and renamed per file (11% of the parent's samples). Two quadratic detector paths. One SMB open per MiB. One PowerShell per WinRM command, and each file read twice.
- **Change.** The process pool serves every scan level, sized by the node profile. IPC carries text in and findings out, several small files per task. Each record is serialised once. The quadratic paths get local windows, one lowercase pass, sets and caps. The per-file deadline of W3.2 becomes the pool's contract. SMB opens a file once. WinRM keeps one runspace and hashes while reading. `DSPM_PARTITION_WORKERS` rises to 2–4 once W4.6 bounds a unit by bytes.
- **Expected impact** (EXTRAPOLATED). At least 150 small files/s and 8 MiB/s of text on 8 vCPU: seven workers at the measured single-core rate, before the algorithmic gains.
- **Affected subsystems.** `detector_pool`, `detector_stage`, `discovery_engine`, `classification`, `smb_scanner` read path, `winrm_endpoint_scanner`.
- **RAM.** Plus workers × (baseline + bounded text): 7 × 0.4 GiB at most, inside the profile.
- **Storage.** None.
- **CPU, network, database.** CPU per file and per MiB down 3× or more; SMB round trips per MiB from about 4 to about 1.
- **Reliability.** A hung or crashing file costs itself, not the pool or the unit.
- **Risks.** Detection parity: the same findings from the pool as from the threads. Worker start-up cost on tiny scans (keep the start threshold).
- **Validation.** `detector_benchmark.py` and the compliance corpora for parity; throughput at 1, 2, 4 and 7 workers; a file that hangs and a file that crashes the worker; one real file server and one real endpoint for the protocol changes (UNVERIFIED until then).
- **Exit criteria.** Files/s and MiB/s scale at ≥ 0.7 per added worker up to 7. Identical findings on the benchmark corpora. A 16 MiB CSV without a card finishes in seconds.

### W4.4 Aggregates maintained, reads bounded

- **Objective.** Console latency does not depend on estate size, during scans included.
- **Verified root cause.** N12. Twelve passes over `findings` per rebuild; filters as `LIKE` on JSON text; eight text sorts without matching indexes; totals by uncapped `COUNT(*)`; access views by `GROUP BY` over every access row.
- **Change.** Counters per tenant and dimension, updated in the unit's transaction from the rows that changed (cheap once W4.2 makes writes follow change). Child tables for finding type and framework with plain indexes. Row-value keyset and expression indexes for the sorts the console offers. Capped or estimated totals. A per-principal access rollup. Text search through the existing optional projection.
- **Expected impact** (EXTRAPOLATED). Summary and facets from 30–45 s at 5M findings to an indexed read.
- **Affected subsystems.** `store` read functions, `live_cache`, a migration, `search`. No change to how the console looks.
- **RAM.** Removes large sorts and hash aggregates from PostgreSQL's working memory.
- **Storage.** Small: the counter and child tables.
- **CPU, network, database.** Database CPU per page view becomes constant.
- **Reliability.** The pool cannot be emptied by readers.
- **Risks.** Counter drift: reconcile against a full count on a schedule, and expose the difference.
- **Validation.** A synthetic 1M-file / 5M-finding tenant on PostgreSQL under FORCE RLS with a writer running; `EXPLAIN` asserted for each list and sort.
- **Exit criteria.** Summary and facets ≤ 300 ms p95 at 5M findings during a write load. No console read over 2 s. No response sized by the estate.

### W4.5 PostgreSQL write path and concurrency

- **Objective.** Scan writes never stall the API, and more than one worker can write.
- **Verified root cause.** A process-wide lock at about 130 call sites; a tenant-wide advisory lock held for a whole persist or finalize; 5 round trips per one-statement transaction; one query per file when the local cache misses; no storage parameters on small hot tables (`scan_jobs` is written every second).
- **Change.** The process lock on SQLite only (W3.4 starts this). The advisory lock narrowed to the scope and folder range a unit writes. Small transactions pipelined. Batched probes. Storage parameters for the small hot tables. Measure the share of full-page images with `pg_stat_wal` before deciding anything about key order.
- **Expected impact** (EXTRAPOLATED). Two unit workers give ≥ 1.6× the persist throughput; no interactive request waits on a scan's lock.
- **Affected subsystems.** `store`, `db`.
- **RAM, storage.** None.
- **CPU, network, database.** Fewer round trips; shorter lock holds.
- **Reliability.** Removes the lock convoy when PostgreSQL is slow.
- **Risks.** Read-merge-writes that rely on the process lock today (the SIEM status is one) need their own row locks. Lock-order mistakes between tenants.
- **Validation.** Two workers on one tenant with parity; `pg_locks` sampling during `pg_scan_rehearsal`; API latency during a two-worker scan.
- **Exit criteria.** API p95 < 300 ms during a two-worker scan on PostgreSQL. No interactive request waits more than 5 s on a lock.

### W4.6 One node budget

- **Objective.** RAM, disk, WAL and connections are budgets the software enforces, shipped as a 16 GB and a 32 GB profile.
- **Verified root cause.** Bounds are by count: files per unit, buffer slots, threads (about 60 per scan; an OCR thread per image). A unit's content lives until the unit ends (MEASURED slope 1.0). The capture budget charges 1× the bytes while 3–5× are held; documents are bounded by compressed size. No cross-process cap on concurrent scans. The disk floor is checked in one executor.
- **Change.** The collector keeps metadata and hands content to the analysis task, which releases it, so a unit's memory stops following its bytes. One in-flight-bytes budget, charged at working size. A node profile that sets pool sizes, workers and the PostgreSQL memory settings together. Scan admission in the ledger. A pre-flight that projects a scan's disk and WAL from the measured per-file figures and refuses what will not fit.
- **Expected impact** (EXTRAPOLATED). Scanner peak ≤ 2 GiB on the 16 GB profile for any mix of file sizes.
- **Affected subsystems.** `discovery_engine`, the collectors, `parallelism`, `disk_guard`, `config`.
- **RAM.** The remaining size-dependent term goes.
- **Storage.** Refusal instead of a full disk.
- **CPU, network, database.** Neutral.
- **Reliability.** No out-of-memory from a folder of large text files; no scan started into a disk it cannot fit.
- **Risks.** Throughput if the byte budget is set too low: tune on the content benchmark.
- **Validation.** `amplification_probe.py unit-bytes` from 30 MiB to 2 GiB units; a soak of 10 consecutive scans in one process.
- **Exit criteria.** Peak RSS within 1.3× across unit sizes from 30 to 480 MiB of text. RSS after 10 scans within 5% of RSS after 2. A scan projected not to fit is refused with the numbers.

---

## 26. Resource and capacity model

Everything in this section is **EXTRAPOLATED** from the measurements in §23.2 unless marked, and **UNVERIFIED** until the gate named for it passes (§27): 1–2M figures and the 16 GB profile by G2 and G3, 10M figures and the 32 GB profile by G4, 50M figures by G5. Nothing above 20,000 files has been run on PostgreSQL.

**Reference estate.** One Windows file server over 1 GbE. A heavy case of 5 findings per file (the sizing case since §8) and a light case of 1. Five principals per file. 50 GB of inspected text per 1M files: an assumption, to be replaced by the estate's own size histogram, which the metadata pass can record.

### 26.1 Memory budget on one node (EXTRAPOLATED; UNVERIFIED until G2 on each profile)

| Component | 16 GB profile | 32 GB profile |
|---|---|---|
| PostgreSQL `shared_buffers` | 4 GB | 8 GB |
| PostgreSQL sessions, `work_mem`, maintenance | 1 GB | 2 GB |
| File cache left to PostgreSQL | 4 GB | 10 GB |
| Scan process (W4.6 budget) | 2 GB | 3 GB |
| Detector workers (7 × up to 0.4 GiB) | 3 GB | 5 GB |
| API and console reads | 1 GB | 1.5 GB |
| Operating system and headroom | 1 GB | 2.5 GB |

More than 32 GB is not needed by anything in the design. The term that would ask for it is PostgreSQL's cache during a 50M first scan, because row ids are text hashes and index inserts land at random; the answer there is storage that serves 10,000 random reads a second, not more memory (UNVERIFIED).

### 26.2 After revised Wave 3 and Wave 4 (all EXTRAPOLATED)

| | 1M files (UNVERIFIED until G2/G3) | 2M files (UNVERIFIED until G3) | 10M files (UNVERIFIED until G4) | 50M files (UNVERIFIED until G5) |
|---|---|---|---|---|
| RAM | 16 GB | 16 GB | 32 GB | 32 GB |
| CPU | 8 vCPU | 8 vCPU | 8 vCPU | 16 vCPU |
| PostgreSQL, current state (light–heavy) | 6.5–15 GB | 13–30 GB | 65–150 GB | 325–750 GB |
| Record objects and manifests | 1–2.5 GB | 2–5 GB | 10–25 GB | 50–125 GB |
| Backups: 2 sets, compressed, objects incremental | 5–13 GB | 10–25 GB | 50–115 GB | 250–575 GB |
| WAL written by the first scan | 25–35 GB | 50–70 GB | 250–350 GB | 1.2–1.7 TB |
| WAL written by a 1% rescan | 0.3–0.5 GB | 0.6–1 GB | 3–5 GB | 15–25 GB |
| WAL held on disk | `max_wal_size` 8 GB, plus the archive between base backups | same | same | same |
| Temporary disk | under 1 GB | under 1 GB | under 1 GB | under 1 GB |
| Disk to provision | 100 GB | 150 GB | 500 GB | 2 TB (NVMe) |
| Network, first scan | Σ min(size, cap) of inspected types; 1 TB takes 2.5 h at 110 MB/s, below the CPU term | same | same | same |
| Network, rescan | the listing: about 0.2 GB per 1M entries | | | |
| Initial scan | about 3.5 h | about 7 h | about 1.5 days | 7–8 days on one node |
| 1% incremental | 10–30 min | 20–60 min | 1.5–5 h | 7–24 h on one listing stream; 1–3 h on eight, or with a change journal |

Per-file figures behind the table: 6.5 KiB (light) to 15 KiB (heavy) in PostgreSQL after W4.1; first scan at 150 files/s plus text at 8 MiB/s after W4.3; listing at 1,000–3,000 entries per second per stream (§11's round-trip model, UNVERIFIED on a real server).

**The same sizes today** (rates MEASURED, totals EXTRAPOLATED): initial scan 14 h, 29 h, 6 days and 30 days; an unchanged rescan 2.4 h, 4.7 h, 1 day and 5 days.

### 26.3 Sentro-owned storage for a 3–5 TB estate (EXTRAPOLATED)

Storage follows files and findings, not terabytes.

| | 1M files, heavy case |
|---|---|
| Today, after the first scan | Database about 22 GB; artifacts 1–2.5 GB; reuse cache about 10 GB |
| Today, after 30 nightly scans | Database about 115 GB (+9 GB per scan for five scans, then +2.3 GB per scan for ever); artifacts 30–75 GB; 7 backup sets of dump plus artifact tar: 600–900 GB. **On the order of 1 TB**, and still growing |
| After Wave 3 (3 kept scans, summary + manifest, collection, incremental backups) | Bounded: about 40 GB of database, 2–5 GB of artifacts, backups by policy. 70–150 GB |
| After Wave 4 | 15 GB of database, 1–2.5 GB of objects, two backup sets: **30–55 GB**. Light case 15–25 GB |

**Target: about 1–2% of the source** for a 3–5 TB estate of 1–2M files, all stores and backups included: 50–100 GB (EXTRAPOLATED; UNVERIFIED until G3).

### 26.4 When one node stops being enough

One node after Waves 3 and 4 (EXTRAPOLATED, UNVERIFIED until G4): about 13M small files or 0.7 TB of inspected text per day on a first scan, and listing speed on every scan after it.

Horizontal scanning becomes necessary when one of these holds, and not before:
1. **First-scan window.** `files / 150 per second` or `inspected text / 8 MiB per second` exceeds the agreed window. For 50M files that is 7–8 days on one node (EXTRAPOLATED).
2. **Listing window.** A full listing of the estate exceeds the incremental window even with parallel streams. That is the trigger for the change journal (§11), which is cheaper than nodes.
3. **Network locality.** Sources sit at sites whose links cannot carry the listing and the changed bytes.
4. **Availability.** A requirement that scanning continues through the loss of a node.

PostgreSQL stays one instance through 50M files (325–750 GB; EXTRAPOLATED, UNVERIFIED until G5). Scanner nodes do not relieve it; W4.1 and W4.2 do.

---

## 27. Acceptance gates

| Gate | Size and place | Proves | When |
|---|---|---|---|
| **Fault** | This host, PostgreSQL, a few units, fake transports | Every event of §23.9 ends in its guaranteed state | Wave 3 exit; re-run after W4.1, W4.2 |
| **Amplification** | This host: `amplification_probe.py` (SQLite) and `pg_scan_rehearsal.py` at 20,000 files | The per-file figures of §28 | Before and after every Wave 4 workstream |
| **G1** | 200K files, scale host, PostgreSQL | The architecture at 10× what has been run | As soon as a host exists; Wave 3 exit |
| **G2** | 1M files / 5M findings synthetic, scale host | The near-term size in the database and console | After Wave 3; again after Wave 4 |
| **G3** | The pilot file server: 1–2M files, about 3 TB | The near-term workload, real | After G1; "comfortable" only after Wave 4 |
| **G4** | 10M files, synthetic metadata and database, one 32 GB node | A substantially larger single node | After Wave 4 |
| **G5** | 50M: G4's model, then a staged real estate | Progress toward 50M. Never claimed without a run | After G4 |

Every gate from G1 up is judged on all ten lines. Where the two waves differ, both thresholds are given.

| Line | After Wave 3 | After Wave 4 |
|---|---|---|
| RAM | Scan process ≤ 3 GiB. Peak at the gate's size within 15% of peak at a quarter of it. Node total within its profile | Scan process ≤ 2 GiB on the 16 GB profile, for any mix of file sizes |
| CPU and throughput | First scan ≥ 40 small files/s. Unchanged rescan ≥ 2.5× that: no worse than today | First scan ≥ 150 files/s and ≥ 8 MiB/s on 8 vCPU. Unchanged rescan ≥ 20× the first-scan rate |
| Disk | Sentro-owned storage after 10 unchanged scans equals storage after 3 (the default window). No full per-scan copy of the estate | Growth of an unchanged scan ≤ 1% of the first scan's. Total within §26.2 |
| WAL | `pg_wal` never above `max_wal_size` + 1 GB. Unchanged rescan no worse than today's 43% of a first scan | Unchanged rescan ≤ 2% of the first scan's WAL. First scan ≤ 35 KiB per file |
| Database responsiveness | No transaction over 60 s. No interactive request waits over 5 s on a lock. Dead tuples under 20% of any hot table at the end | Same, with two unit workers |
| API responsiveness | p95 per request < 300 ms and no request over 2 s while the scan runs. An aggregate served from the previous value carries its computed-at time and rebuild status, and the console shows it as stale (D1) | The same without serving a previous value: summary and facets ≤ 300 ms at the gate's finding count |
| Frontend | Every page usable within 2 s during the scan. No list response over 1 MB. Browser memory flat over an hour with the scan view open | Same |
| Correctness | Estate equals a reference full scan (parity digest). No duplicate asset or finding. Coverage states add up to the file count. An incomplete scan prunes nothing. A depth- or scope-limited scan says so and never reports full coverage (D4) | The same for a scan that skipped unchanged folders, at 0%, 1% and 10% change |
| Recovery | One backend restart and one PostgreSQL restart mid-scan: resumed within 7 minutes, at most one unit redone each, no manual step | Same; finalize interrupted and resumed |
| Error rate | No unit failed for an infrastructure reason. Files marked FAILED ≤ 0.1%, each listed with its reason. No scan `failed` | Same |

G3 adds what only a real server shows: the file server's CPU, disk queue and session count under the per-target caps (perfmon), and the ACL change-time behaviour W4.2 relies on. Until it runs: **UNVERIFIED — REQUIRES PILOT.**

---

## 28. Before and after

| Metric | Current | After revised Wave 3 | Target after Wave 4 | Evidence |
|---|---|---|---|---|
| Peak scanner RAM | 0.3 GiB on small files; 110 MiB + 1.0 × the unit's text. Worst case 3.5–6.5 GiB for an SMB unit; unbounded for a local unit | ≤ 3 GiB: every unit under the byte budget, no cap doubling | ≤ 2 GiB, independent of what a unit holds | Slope MEASURED; worst case CODE-VERIFIED; targets EXTRAPOLATED |
| RAM growth with file count | None in the scan for small files. Growth through unit doubling above about 1.1 TB weighted, through whole-report parses (5.4–6.5 KiB per file each), and through the cache listing (170 B per entry per unit) | None | None | CODE-VERIFIED |
| Sentro storage per file, first scan | 21 KB: database 14.3, reuse cache 5.9, artifacts 1.1 (1.6 findings per file) | About 20 KB | 7–9 KB | MEASURED (SQLite); targets EXTRAPOLATED |
| Database storage per file (PostgreSQL) | About 9 KiB at 1 finding per file, 22 KiB at 5 | About 8 and 21 KiB | 6.5 and 15 KiB | EXTRAPOLATED from MEASURED row sizes |
| Storage per finding | 2.0 KB on the first scan, and 1.36 KB more on every scan | 1.2 KB per kept scan (3 by default), deleted with the scan | 2.2 KiB once | MEASURED; targets EXTRAPOLATED |
| Growth per unchanged scan | 2.8 KB per file in the database and 1.05 KB in artifacts, never deleted | About 2.8 KB per file and 0.5 KB of artifacts (no body copy), deleted after 3 scans | ≤ 0.05 KB per file | MEASURED; targets EXTRAPOLATED |
| WAL, first scan | 51–105 KiB per file (8 findings) | About the same | 25–35 KiB per file | MEASURED (PostgreSQL, 4,000 and 20,000 files); target EXTRAPOLATED |
| WAL, unchanged rescan | 45 KiB per file at 4,000 files: 43% of the first scan | Somewhat lower (no occurrence rows) | ≤ 1 KiB per file: ≤ 2% | MEASURED; targets EXTRAPOLATED |
| Bytes read | First scan: Σ min(size, cap) of inspected types (0.127 of the W2.2 corpus). Unchanged: 0 | Same | Same; a WinRM file is read once | MEASURED |
| Unchanged rescan cost | 7 ms and 17 row versions per file (5 findings). 1M files: about 2 h | Same | One listing, about one row per folder. 1M files: 10–30 min over SMB | MEASURED; target EXTRAPOLATED |
| Database writes | 3 + principals + 3F statements per new file; 2 + 3F row writes per unchanged file | 3 + principals + 2F; 2 + 2F | Changed files only | CODE-VERIFIED, MEASURED |
| Files per second, first scan | 41–49 small files/s; 1.6 MiB/s of text; one core | Same | ≥ 150 files/s; ≥ 8 MiB/s on 8 vCPU | MEASURED; target EXTRAPOLATED |
| API impact of a scan | Beyond 1.7–2.5M findings every aggregate is rebuilt per request (30–45 s at 5M). The pool of 10 is shared with the scan. Opening Findings parses two whole reports | The previous value is served during one rebuild; separate pools; no whole-report read | Summary and facets ≤ 300 ms at 5M findings | Rebuild rate MEASURED at 32,000 findings; the rest CODE-VERIFIED and EXTRAPOLATED |
| Restart cost | Mid-unit: one unit, after up to 6 minutes, and an attempt. Mid-finalize: 60 minutes, then all of finalize. Mid-planning: the scan | One unit after up to 6 minutes. Finalize resumes at its step. Planning resumes | Same, and finalize no longer follows the estate | CODE-VERIFIED |
| Failure blast radius | The whole scan, for one unit out of attempts, any control-loop or finalize error, or a short database blip | One unit, quarantined. Infrastructure faults pause | Same | CODE-VERIFIED |

---

## 29. Final execution order and priority table

1. **W3.2 + W3.1: contain failures and close the exits from the bounded path.** On this host, on PostgreSQL, proved by the fault gate.
2. **W3.3 + W3.4: take whole-scan reads off interactive paths; serve the previous aggregate during a rebuild.**
3. **W3.5 + W3.6: keep 3 scans per label, store summary + manifest instead of a body, turn collection on, stop writing the two unread tables, ship the node profile, remove the default depth limit and say what was not covered.** Storage stops growing.
4. **G1 at 200K as soon as a scale host exists.** After steps 1–3 the pilot (G3) can run. It will complete, and it will be heavy.
5. **W4.1: one copy of each fact.** The largest storage and WAL cut for the least risk.
6. **W4.2: unchanged costs nothing.** The largest recurring cut, and the highest risk: it changes presence and prune.
7. **W4.3: classification on every core.**
8. **W4.4 + W4.5: maintained aggregates; the PostgreSQL write path.**
9. **W4.6: the node budget. Then G2 and G4,** and the horizontal decision by §26.4.

Steps 1–3 need no hardware. **Wave 4 (steps 5–9) does not start before Wave 3's exit criteria (§24) are met.** Its steps are measured on this host with the amplification gate, and re-certified at scale when a host exists.

| Priority | Workstream | Why | Impact | Complexity | Regression risk | Needed for the pilot? | Needed for a comfortable 1–2M? | Needed for 50M? |
|---|---|---|---|---|---|---|---|---|
| 1 | W3.2 Failures contained | A blip or one unit fails hours of work | No scan lost to infrastructure | MEDIUM | MEDIUM | **Yes** | Yes | Yes |
| 2 | W3.1 No exit from the bounded path | Fallback to the whole estate in memory; the cap binds at 1.1 TB | The Wave 1 guarantees actually hold at 3 TB | MEDIUM | MEDIUM | **Yes** | Yes | Yes |
| 3 | W3.3 No whole-scan reads | 11–13 GiB on opening Findings at 1M files | Removes the product's largest memory term | LOW–MEDIUM | LOW | **Yes** | Yes | Yes |
| 4 | W3.4 Console survives a scan | Rebuild loop and shared pool | Usable console during scans | MEDIUM | LOW | **Yes** | Yes | Yes |
| 5 | W3.5 Storage stops growing | Nothing is ever deleted or collected | Bounded storage | LOW–MEDIUM | LOW | **Yes** | Yes | Yes |
| 6 | Gates: fault, G1, G3 | No proof above 20,000 files | Certifies Wave 3 | MEDIUM | — | **Yes** | Yes | Yes |
| 7 | W4.1 One copy of each fact | 5 copies, per-scan history, 46 indexes | Storage to 30–55 GB at 1M; first-scan WAL −30–50% | MEDIUM | MEDIUM | No | **Yes** | **Yes** |
| 8 | W4.2 Unchanged costs nothing | 7 ms and 2 + 3F writes per unchanged file | Rescans at listing speed; WAL −95% | HIGH | HIGH | No | **Yes** | **Yes** |
| 9 | W4.3 Classification on every core | One core: 1.6 MiB/s | First scan 3–5× faster | MEDIUM | MEDIUM | No | **Yes** | **Yes** |
| 10 | W3.6 Coverage said; ACL refresh | Depth 4 by default (removed by D4); ACL drift | Trustworthy "complete" | LOW | LOW | **Yes** (D4) | Yes | Yes |
| 11 | W4.4 Aggregates maintained | O(estate) reads | Constant console cost | MEDIUM | MEDIUM | No | At ≥ 2M findings | **Yes** |
| 12 | W4.5 PostgreSQL write path | Process lock, tenant-wide lock | Parallel writers; no API stalls | MEDIUM | MEDIUM | No | Helpful | **Yes** |
| 13 | W4.6 Node budget | Bounds by count | 2 GiB scan process on any mix | MEDIUM | LOW | No | For 16 GB | Yes |
| 14 | Horizontal scanning, change journal, search engine | Only past §26.4's triggers | Beyond one node | HIGH | HIGH | No | No | By trigger |

---

## 30. The fourteen questions

1. **The #1 remaining barrier to maximum files with minimum RAM.** Memory still follows size in three places, and the first is the barrier: a unit holds all of its content until it ends, its size is bounded by file count, and above 2,147 units the planner doubles it (MEASURED slope 1.0 MiB per MiB; cap CODE-VERIFIED). The other two are the whole-report parses in the API and the unpartitioned fallback. W3.1 and W3.3 bound all three; W4.6 removes the slope.
2. **What causes the most unnecessary Sentro-owned storage.** History kept as full copies per scan and never deleted: a `finding_index` body and an occurrence row per finding per scan, two copies of every record per scan in the artifact store with collection off, and all of it tarred into each of 7 backup sets. On the order of 1 TB after a month of nightly scans at 1M files (EXTRAPOLATED, heavy case).
3. **The biggest crash or freeze risk at very large scale.** An interactive request that parses a whole scan report. Opening Findings parses two (11–13 GiB at 1M files, EXTRAPOLATED), inside the process that also runs the scan.
4. **The major optimization the old roadmap missed.** Change detection above the file, with history kept as changes. W2.1 stopped rewriting unchanged rows but left every unchanged file going through the pipeline (7 ms, 2 + 3F row writes) and every scan storing the estate again.
5. **What was wrongly prioritised or overengineered.** Multi-node scanning, the dedicated search index and partitioned history tables were planned ahead of using more than one core and before paying only for change. In the other direction, the partition cap, the planner and the `detail_json` diet were filed under "50M" although they bind at 3 TB.
6. **How Wave 3 should change.** From "validate, then go horizontal" to "contain, bound, certify": failures cost one unit, no path leaves the bounded pipeline, no request reads a whole scan, storage stops growing; then G1 and the pilot. Multi-node, the change journal and the search engine leave the wave (§24).
7. **Wave 4's purpose in one sentence.** Make every cost of a scan follow what changed and what is inspected, and keep one copy of each fact, so that the same 16–32 GB node holds ten times the files (a target, UNVERIFIED until G4).
8. **Can 32 GB stay the maximum normal single-node requirement after Wave 4?** Yes, through 10M files with margin (EXTRAPOLATED; UNVERIFIED until G4). At 50M it holds for steady state; the first scan then needs fast storage for random index reads, not more memory (UNVERIFIED).
9. **Can 16 GB support the optimized 1–2M-file class?** Yes (EXTRAPOLATED; UNVERIFIED until G2 and G3 run on the 16 GB profile): PostgreSQL 4 GB of buffers over a 13–30 GB database, a 2 GiB scan process, 3 GiB of detector workers (§26.1). Today it is not safe: one folder of large text files or one click on Findings can exceed it.
10. **Sentro-owned storage for a 3–5 TB estate.** About 1–2% of the source: 50–100 GB for 1–2M files, all stores and two backup sets included (EXTRAPOLATED). It follows files and findings (6.5–15 KiB per file in PostgreSQL), not terabytes.
11. **The realistic maximum of one optimized node.** 10M files comfortably (EXTRAPOLATED; UNVERIFIED until G4): a first scan in about 1.5 days, daily incrementals in 1.5–5 h. 50M is inside the architecture for steady state, with a first scan of about a week and a listing that needs parallel streams or the change journal. All EXTRAPOLATED; proven scale is 20,000 files.
12. **When horizontal scaling becomes necessary.** When the first-scan window, the listing window, network locality or availability demands it (§26.4): in practice a 50M first scan that must finish in under a week, or sources spread over sites. Not for 1–10M on one file server.
13. **How close the revised Wave 3 and Wave 4 bring Sentro to 50M.** The per-scan cost stops following the estate and the memory stops following size, which is the architecture 50M needs. What then remains: the first-scan window, the listing time, one PostgreSQL instance at 325–750 GB with random-key indexes, and every measurement above 20,000 files. ARCHITECTURALLY SUPPORTED after Wave 4, EXTRAPOLATED and UNVERIFIED until G5; proven at 0.04% of that size today.
14. **The next implementation prompt.** §31: revised Wave 3 in full, with the decisions of §23.0.

---

## 31. The next implementation prompt

The prompt for the revised Wave 3, the work that must be done before Wave 4. It includes the decisions of §23.0.

```text
Continue the Sentro DSPM project from its current repository state. This is an
implementation task: inspect, implement, test, measure, fix regressions. Do not push.

AUTHORITY
docs/SCALING_ROADMAP_2026-10.md Part II (sections 23-31) is the authoritative plan;
Part I is history. Read sections 23.0, 23.5, 23.9, 24, 27 and 28 before changing code.
Scope is the revised Wave 3 only: W3.1-W3.6 and the fault gate. Do NOT implement Wave 4
(section 25); where a Wave 3 item touches Wave 4 ground, do only what section 24 says.
Do not redo Waves 1-2. Do not add infrastructure (no Redis, Celery, Kafka, Docker).

BEFORE YOU START
- git status and git log: another Claude session may be live on this tree. If files you
  did not change are modified, find out who is editing them (memory:
  sibling-session-shared-tree) and do not touch them; commit path-limited, never -a.
- Free disk on C: (3-4 GB at last check). Every PostgreSQL run writes WAL plus an
  archive copy. Never delete or move C:\SentroPostgres\wal_archive or change archive_mode.
- Run scripts/amplification_probe.py rates --files 6000 and unit-bytes (30 and 120 MiB
  units) on the unchanged tree and keep the output: it is the "before".

ORDER: W3.2, W3.1, W3.3, W3.4, W3.5, W3.6. Commit each workstream separately, with its
tests. If the run cannot finish all six, stop at a workstream boundary and report.

W3.2 Failures are contained
- Classify errors as infrastructure (database errors, pool timeout, unreachable target,
  disk below the floor) or data. Infrastructure errors never spend a unit attempt and
  never mark a scan failed: bounded retry with backoff, then the scan is paused and the
  resume sweep continues it. A failed mark that lands during a blip must not be possible.
- With a target unreachable, the target's breaker pauses the scan; queued units keep
  their attempts.
- A unit out of data attempts is quarantined and named; the scan finishes incomplete;
  nothing it missed is pruned or treated as deleted.
- A per-file deadline that stops the work (killable worker or equivalent). The file is
  marked FAILED with its reason, is not rerun in the parent, and does not disable the
  shared detector pool. The lease stops renewing once a unit is past its budget, so a
  hung unit cannot keep a scan RUNNING for ever. An SMB unit over budget is truncated and
  says so; it is not reported as "Scan cancelled".
- Finalize runs in recorded steps and resumes at the step it reached; no transaction
  idles while a large body is written; no hour-long wait for a dead finalizer.
- Cancel is durable on the scan record: a restart never resumes a cancelled scan.
- Prune refuses when a newer scan of the same label exists. Completeness is per unit;
  an empty or skipped unit is not complete.
- Disk floor checked in every executor (inline and queue workers) and before finalize.

W3.1 No exit from the bounded path
- Planning failure retries, then pauses. No code path may run a scan unpartitioned above
  one unit's worth of files: not after an SMB reset during planning, not for an
  overlapping-share group (cut it into ranges), not because a file is named
  _manifest.json.
- Remove the 2,147-unit ceiling (64-bit ordering) and the budget doubling; endpoint scans
  lose the same ceiling. Units are written to the ledger while the walk runs, so planning
  is resumable and the first unit starts before planning ends.
- A folder is listed once for all the range units cut from it.
- Local units get the byte budget. A unit's weight counts only bytes that will be read
  (non-content types weigh nothing; documents weigh up to the document cap).

W3.3 No interactive path reads a whole scan
- /api/history/hash-changes answers from rows (or from a result computed once at
  finalize), never from report bodies.
- PDF/report generation reads rows, runs off the event loop, and has a row ceiling.
- The finding drawer, occurrences and triage never fall back to a report body.
- Report endpoints that could return a whole scan refuse above a size or stream.
- Add a guard that fails any interactive request reaching the whole-body reader, and a
  test that exercises every console route with it on.

W3.4 The console survives a scan (decision D1)
- derived_cache: while one rebuild runs across processes (single-flight across backends,
  e.g. an advisory lock), readers get the previous value marked STALE, with the exact
  time it was computed and the rebuild status (rebuilding / rebuild failed). The API
  carries both fields; the console shows them. A stale value must never be presented as
  current. No reader waits on a rebuild. No rebuild pile-up when a rebuild outlasts the
  generation interval.
- Separate connection budgets for scan work, API requests and heavy reads; interactive
  lock and statement timeouts in seconds, not 900 s.
- store._lock taken on SQLite only; read-merge-writes that relied on it (the SIEM status
  is one) get row locks.

W3.5 Storage stops growing (decisions D2, D3)
- Retention keeps the latest 3 completed scans per label by default
  (DSPM_SCAN_RETENTION_PER_LABEL or similar, configurable, catalogued in
  backend/config.py and .env.example). Older scans keep only their summary, coverage,
  audit events and finding lifecycle; their per-file rows, bodies, finding_index rows
  and artifacts are deleted in bounded batches. A tenant under legal hold keeps
  everything. Align DSPM_FINDING_INDEX_KEEP_SCANS with the per-label window.
- No verbatim per-scan body by default: a scan's stored record is its summary plus a
  manifest of the unit record artifacts it already wrote. Finalize no longer streams a
  second full copy of the estate. Every remaining reader (history report endpoints,
  exports, get_inventory_asset with a scan id) streams through the manifest. A full
  report an operator explicitly exports or generates is an artifact under the same
  retention. Content-addressed dedupe of unchanged units is Wave 4 (W4.1): not now.
- Artifact collection on by default after finalize, including the .part sweep.
- Stop writing finding_occurrences (no reader) and the no-op asset_versions upsert;
  keep the tables until a later migration.
- Backups copy artifacts incrementally and never stage plaintext in %TEMP%.
- Resolve configuration (DSPM_CONFIG_FILE, DSPM_DB_URL_FILE) inside backend.db, so tools
  and a bare uvicorn cannot run on a stray data\dspm.sqlite.
- Ship a 16 GB and a 32 GB node profile (pool sizes, workers, PostgreSQL settings) as
  guidance, consistent with section 26.1; label every figure EXTRAPOLATED.

W3.6 Coverage is said (decision D4)
- Remove the silent default depth limit for local, SMB and endpoint scans: with no depth
  setting a scan enters every folder. Keep an explicit, optional depth limit.
- A configured limit is part of the scan's scope: recorded in the scope block the
  advanced scan scope already reports (collectors/scan_scope.py, 8954cf4), counted
  (folders not entered), shown in results and history, and the scan's coverage says it
  was depth-limited. A depth- or scope-limited scan never claims full coverage.
- Skipped system paths are counted and reported the same way.
- The ACL refresh policy (E14): folders' ACLs each scan, files with explicit ACEs, a
  slower full refresh; measure its cost on the fake SMB server.
- Existing saved profiles and schedules that carry max_depth=4 because it was the old
  default: decide visibly (migrate to "no limit" or keep and show the limit); do not
  change a deliberate limit silently.

PROOF
- Fault gate on PostgreSQL (sentro_test only, disposable): every row of section 23.9
  ends in its guaranteed state - backend restart mid-unit/mid-finalize/mid-planning,
  worker crash, PostgreSQL unavailable (short blip and long outage), SMB disconnect and
  server offline, WinRM hang and endpoint offline, disk below the floor, cancel, one
  unit failing repeatedly, a file hanging its parser - each with estate parity against
  an uninterrupted run. Fake transports are fine; say so.
- Mutation checks on every new guard (each mutation must fail a test).
- scripts/amplification_probe.py before and after; pg_scan_rehearsal.py at 4,000 and,
  if disk allows, 20,000 files.
- Targeted suites on SQLite and PostgreSQL, then both full suites (run the SQLite suite
  from a worktree outside AppData). Static gates: ruff, mypy, bandit, eslint.
- Do not modify tests merely to make wrong behaviour pass.

REPORT
A. Status per workstream (DONE / PARTIAL / NOT DONE) and per Wave 3 exit criterion
   (section 24), each PASS / FAIL / UNVERIFIED.
B. What changed: problem, root cause, fix, files, migrations, new settings.
C. Measured numbers against section 28's "After revised Wave 3" column, labelled
   MEASURED / TESTED / CODE-VERIFIED / EXTRAPOLATED.
D. What remains before G1 and before the pilot.
E. Manual actions that need a human.
Update docs/SCALING_ROADMAP_2026-10.md with a Wave 3 delivery status under section 24,
keeping Part I and the rest of Part II intact.

STANDING RULES
PostgreSQL is authoritative; RLS stays FORCE; no BYPASSRLS role; no wildcard tenant
access. Never delete WAL or archive files. Never raise a cap, a timeout or RAM as a fix.
No whole-estate structure in memory; no transaction per scan or per file; no ledger task
per file; no unbounded queue. Never label partial inspection FULL. G1, G2, G3, 10M and
50M stay UNVERIFIED without the hardware; every 16 GB / 32 GB / 10M / 50M figure is
EXTRAPOLATED. Ask before downloads. Do not touch sentro_dev, sentro_bench or the live
:8000 database. Never reintroduce MFA. Commit trailer as the session instructs.
```
