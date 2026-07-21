# SENTRO DSPM — Scan Progress & Cache Root Fix Report

Date: 2026-07-15

## Outcome

The scan pipeline no longer freezes at 14% and the cache now genuinely reduces
scan time for unchanged files. Collection emits real progress; a repeat scan
over unchanged files reuses a metadata-first snapshot and skips the per-file
owner (ACL) subprocess, content read, full-file SHA-256, and reclassification.
Results (findings, risk, preview) are byte-for-byte equivalent on reuse, a
changed file is correctly re-read, tenant isolation and evidence safety are
preserved, and no external dependency was added.

Measured on a 120-file local dataset: cold scan **178.5 s** → warm (unchanged)
scan **4.2 s** (~**42× faster**), findings identical (360), risk identical.

## Files changed

- `collectors/file_scanner.py` — `scan_directory` gains `reuse_probe` and
  `progress_callback`; `add_file` performs metadata-first reuse (skipping owner
  + read + hash) and emits discovered/matched/reused progress; `FileRecord` /
  `normalize_records` carry `cache_reused` + `reused_preview`.
- `discovery/discovery_engine.py` — version signature; `_reuse_probe`,
  `_meta_digest`/`_meta_path`, `_write_meta_sidecar`, `_read_full_content`
  (re-read safety fallback), `_collection_progress`; `_collect_records` wires the
  probe + progress + reuse diagnostics; `_analyze_record` handles reused records
  (preview restore, cache-miss re-read); `_store_cached_findings` writes the
  reuse sidecar.
- `backend/jobs.py` — `_update_scan_job_progress` adds a real `collecting` stage
  (8→40 band with discovered/reused counts) and rebalances `collected`→42 /
  `analyzing` 45→95, so progress moves past 14.
- `tests/test_scan_cache_reuse.py` (new), `tests/test_scan_jobs.py` (extended),
  `tests/test_scan_and_dashboard_ui_contract.py` (extended).
- `docs/scan_progress_cache_root_fix_analysis.md`,
  `docs/scan_progress_cache_root_fix_report.md` (new).

## Progress behavior result

Collection now emits a `collecting` stage carrying `(files discovered, files
reused)`. `jobs._update_scan_job_progress` maps it into an 8→40 band with the
message `Discovering files… N found[, M reused from cache]`, then `collected`→42
(`Collected N files. Analyzing`) and `analyzing` 45→95 (`Analyzing files
i/total`). The bar moves through real stages instead of sitting at the 14
heartbeat ceiling. In the probe, collection emitted 9 stages and mapped progress
peaked at 95 across the run. The heartbeat + wall-clock deadline remain as a
floor/safety net.

## Cache behavior result

A first classification of a file writes a `.meta.json` reuse sidecar (owner,
hashes, content_status, preview, version signature) keyed by a digest of
`(version_signature, path, size, mtime)`. On the next scan, `reuse_probe` finds
it and the collector emits the record from the snapshot with no file I/O. The
finding cache then supplies the stored findings. Guarantees:

- **Unchanged file** → reused (skips owner subprocess, content read, full hash,
  reclassification). Probe: 120/120 reused on scan 2, 119/120 on scan 3.
- **Changed file** (size/mtime differs) → sidecar digest changes → miss → full
  re-read + reclassify. Probe: the edited file was not reused and its findings
  updated (360 → 357).
- **Version upgrade** (detector/parser/rule/framework) → version signature
  changes → all sidecars miss → full re-read (correctness over speed).
- **Missing findings cache** (sidecar present, finding file gone) → safe
  `_read_full_content` fallback re-reads the file, so reuse can never yield empty
  findings.
- **Tenant isolation** → `tenant_id` is part of the version signature, so
  sidecars never cross tenants.

## Scan speed result

Warm scan of unchanged files was ~42× faster than the cold scan (178.5 s →
4.2 s for 120 files) because the per-file `powershell Get-Acl` owner subprocess,
full content read, and full-file SHA-256 are skipped for reused files. The
remaining warm-scan time is cheap sidecar/finding-cache JSON reads plus
in-memory risk/canonical recomputation.

## Timeout / failure behavior

Unchanged from the prior pass and still correct: the collection heartbeat
enforces `DSPM_SCAN_MAX_SECONDS` (default 1800 s) and flips a hung/too-slow scan
to `status="failed"` with a clear message; the frontend surfaces the failure
instead of a stuck bar. Real collection progress now also makes a genuinely slow
(but progressing) scan visibly advance rather than look hung.

## Frontend polling / result

No frontend code change was required. `pollScan` already renders the backend's
authoritative `job.progress` and `job.message`, pins 100 on completion, and
throws on `failed`/`cancelled` (surfacing the error and clearing the bar); the
prior pass added transient-error tolerance. With the backend now emitting real
`collecting`/`collected`/`analyzing` progress and messages, the UI shows
meaningful stages that advance past 14. A source-contract test locks this in.

## Tests added / updated

- `tests/test_scan_cache_reuse.py` (7): second scan reuses unchanged files;
  reuse avoids content reads and owner/ACL calls (asserts the reader and owner
  are never called on a fully-cached scan); reuse preserves findings, risk, and
  preview; a changed file is not reused; a missing findings cache triggers a safe
  re-read; collection emits progress + reused counters; progress moves past 14.
- `tests/test_scan_jobs.py` (+4): `collecting` stage moves progress past 14;
  `collecting` reports the reused count; stage sequence is monotonic through
  analysis; the status dict reports progress/message/status.
- `tests/test_scan_and_dashboard_ui_contract.py` (+1): the async poll loop is
  driven by backend `job.progress`/`job.message`, pins 100 on completion, and
  surfaces failure.

## Commands run and full results

- `python -m compileall backend collectors discovery` → exit 0
  (`COMPILEALL OK`).
- `python -m unittest tests.test_scan_cache_reuse` → `Ran 7 tests` … `OK`.
- `python -m unittest tests.test_scan_jobs` → `OK` (9 tests).
- `python -m unittest discover tests` → `Ran 274 tests in 56.138s` …
  `OK (skipped=1)`.
- `node --check frontend/app.js` / `frontend/copilot.js` → **not run: Node is
  not installed in this environment** (`node` is not on PATH and no `node.exe`
  exists on disk). No frontend JS was changed in this pass; the async poll path
  was verified by source-contract test and manual review.

## Remaining risks

- **Cold (first-ever) scan is still slow** because a new/changed file still pays
  the per-file `Get-Acl` owner subprocess + full read + full hash. Reuse removes
  this on every subsequent scan of unchanged files (the reported problem). A
  native ACL API (pywin32), batched owner resolution, or an owner-optional mode
  is a documented follow-up (would add a dependency or change output, so it was
  intentionally left out of this no-dependency MVP).
- **size+mtime+path reuse heuristic.** A file rewritten with identical size and
  an unchanged mtime would be reused. This is the sanctioned enterprise-assessment
  MVP heuristic; the version signature still forces full re-reads on any detector/
  rule change. Full content-integrity reuse (rolling hash / version id) is future
  work.
- **Warm scan reads 2 small JSON files per reused file** (sidecar + finding
  cache). Vastly cheaper than the owner subprocess + full read, but for very
  large trees a consolidated index would reduce open() calls further (follow-up).
- **SMB / WinRM** keep the collect-all cost during collection; they are protected
  by the deadline and use the existing finding cache, but do not yet have
  metadata-first collection reuse or per-file collection progress (follow-up;
  untestable here without `pysmb`/`pywinrm`).
- **Reused-file preview** is restored from the stored snapshot; it reflects the
  content at first classification (correct for unchanged files by definition).
- **Node syntax check pending** — run `node --check frontend/app.js` /
  `frontend/copilot.js` in a Node-enabled environment before release.

## Manual verification steps

1. Run a local scan of a real folder (async). Confirm the progress bar advances
   through "Discovering files… N found", "Collected N files. Analyzing",
   "Analyzing files i/total", reaches 100, and the dashboard refreshes.
2. Run the **same** scan again unchanged. Confirm it is dramatically faster and
   the message shows "… M reused from cache"; confirm the dashboard/report
   findings and risk are identical to the first run.
3. Modify one file, rescan. Confirm only that file is re-read/reclassified
   (reused count drops by one) and its findings update correctly.
4. Point a scan at an unreachable/oversized target. Confirm it ends as **failed**
   within `DSPM_SCAN_MAX_SECONDS`, not stuck.
5. Delete `data/scan_cache` and rescan. Confirm a correct (cold) scan rebuilds
   the cache and sidecars, and the next scan reuses them.
6. Run `node --check frontend/app.js` and `frontend/copilot.js` in a Node
   environment.
