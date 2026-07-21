# SENTRO DSPM — SMB/WinRM Scan Progress & Cache + Top-N PDF Scope Fix Report

Date: 2026-07-16

## Outcome

- **SMB** scans now emit real collection progress (discovered/reused counters)
  and reuse the metadata-first cache: an unchanged file skips the remote
  content read, the full-file hash transfer, and the per-path ACL PowerShell
  subprocess, while findings/risk/owner/preview stay identical. Reuse is
  fail-closed against a missing findings-cache entry.
- **WinRM** endpoint scans are protected by the shared heartbeat + wall-clock
  deadline (a hung remote script becomes a *failed* job, not eternal
  "running/8") and report real per-record progress during backend analysis.
  Collection-time reuse for WinRM is documented as not feasible without a
  remote protocol change; reclassification is still avoided by the existing
  content-hash finding cache.
- **Top-N PDF reports** preserve the explicit limit, severity, extension, and
  selected-finding scope end-to-end — "top 5 critical files as PDF" produces a
  report scoped to exactly the 5 highest-risk critical files, titled
  "Top 5 CRITICAL". `.pdf` extension *file listings* remain listings.
- Local scan cache behavior, tenant isolation, signed artifacts, evidence
  safety, and secret masking are unchanged; no dependency was added.

## Files changed

- `backend/jobs.py` — reusable `collection_heartbeat` context manager
  (heartbeat band + `SCAN_MAX_SECONDS` deadline), used by `_run_scan_job`.
- `collectors/smb_scanner.py` — `SMBConfig.reuse_probe` / `progress_callback`;
  `_walk_share` metadata-first reuse before preview/hash/ACL; visited/matched/
  reused counters + throttled progress; `reuse_key` on records; reuse counters
  in diagnostics.
- `collectors/file_scanner.py` — `normalize_records` carries `reuse_key`.
- `discovery/discovery_engine.py` — SMB branch wired to the shared reuse probe
  and collection progress; sidecars store `finding_cache_digest`
  (fail-closed probe); `_write_meta_sidecar` supports local + SMB identities;
  non-local reused records that miss the finding cache fail honestly.
- `backend/app.py` — WinRM remote phase wrapped in `collection_heartbeat`
  (ceiling 60, honest single-batch message); shared
  `_analyze_endpoint_records` with per-record 70→90 progress + cancellation for
  remote and local endpoint paths.
- `backend/copilot/report_model.py` — scope normalizer preserves `limit`
  (1–100), adds `extension` scope kind (optional severity filter), builds
  "Top N …" labels; the cap is applied after risk sorting and drives every
  scoped section.
- `backend/copilot/conversation_repair.py` — `requested_report_scope` parses
  "top N" and extensions (dotted, or known bare extension + file noun);
  `_inherited_reportable_scope` returns extension scopes with limits;
  `scopes_equal` compares limit/extension; `_scope_display_label` handles the
  new kinds; explicit top-N counts as an explicit scope.
- `backend/copilot/file_queries.py` — non-negated report/format requests
  (including bare-"pdf"-as-format) always defer to the report route;
  `.pdf files` listings and corrections unchanged.
- `backend/copilot/service.py` — evidence file-list results publish
  `last_reportable_scope` (severity/extension/limit) for later
  "that as a report" / bare "pdf".
- `backend/copilot/artifacts.py` — extension scope description; filename tags
  like `top5_critical` / `top5_pdf_files`.
- Tests: `tests/test_smb_scan_cache_progress.py` (new),
  `tests/test_topn_report_scope.py` (new), `tests/test_scan_jobs.py` (+4).
- Docs: this report + `docs/smb_winrm_cache_progress_and_topn_pdf_analysis.md`.

## SMB progress/cache result

`_walk_share` now checks the metadata-first sidecar (identity
`smb://server/share/path` + size + mtime + version signature) **before** any
remote I/O. On a hit it emits the stored snapshot (owner, ACL, hashes,
content status, completeness, preview) with `cache_reused: true`; the existing
finding cache then supplies the findings without reclassification. Counters
stream through the same `collecting` stage as local scans
("Discovering files… N found, M reused from cache"), and
`scan_diagnostics` reports `files_discovered` / `cache_reused_files`.

Stub-connection measurements (60 files): warm scan makes **zero**
`retrieveFileFromOffset` calls and **zero** ACL subprocess calls; findings,
risk levels, owner, and preview identical to the cold scan; one changed file
(different mtime) is re-read and reclassified while the other 59 reuse.

Fail-closed safety: sidecars record their paired findings-cache digest; if
that entry is missing, the probe misses and the file is fully re-read while
the SMB connection is still open. A residual eviction race fails the record
honestly (`record_failed`) rather than emitting empty findings. Version
signature (tenant + parser + detector + rule catalog + frameworks) still
invalidates all reuse on any classifier change; tenant isolation is part of
the identity digest.

## WinRM progress/cache result

- The remote scan phase runs inside `collection_heartbeat(job, ceiling=60)`:
  the job advances within a bounded band with the honest message "Running
  remote endpoint inventory (WinRM returns results in one batch)", and a hung
  or too-slow remote script is flipped to `failed` by the `SCAN_MAX_SECONDS`
  deadline instead of staying "running" forever.
- Backend analysis now reports real per-record progress
  ("Analyzing endpoint files i/N", 70→90) and honors cancellation, for both
  remote-WinRM and local endpoint scans.
- **Documented limitation:** per-file *collection* progress and metadata-first
  reuse are not possible for WinRM without changing the remote protocol — the
  endpoint script enumerates, reads, and hashes everything before returning a
  single batch, so no metadata exists backend-side before the heavy work.
  Unchanged files still skip reclassification via the content-hash finding
  cache during analysis.

## Top-N report result

`report_model` is the single scope authority. Verified end-to-end (provider
forced down, artifact creation intercepted, register recomputed from the real
model):

| Request | Scope | Register |
| --- | --- | --- |
| top 5 critical files as PDF report | severity CRITICAL, limit 5, "Top 5 CRITICAL" | exactly 5 |
| top 5 critical files → "give me that as a pdf report" | inherited CRITICAL + limit 5 | exactly 5 |
| top 10 high files as PDF | HIGH, limit 10 | exactly 10 |
| give me pdf about only medium alerts | MEDIUM, uncapped | all 8 MEDIUM |
| critical + high PDF report | CRITICAL + HIGH, uncapped | all 23 |
| selected single finding | finding scope | exactly 1 |
| give me top 5 pdf files | **file listing**, no artifact | — |
| top 5 pdf files → "that as a pdf report" | extension .pdf, limit 5, "Top 5 .pdf files" | exactly 5 |
| top 5 .pdf files as report (direct) | extension .pdf, limit 5 | exactly 5 |
| bare "pdf" after top 5 critical | inherited CRITICAL + limit 5 | exactly 5 |
| "dont give pdf report i need .pdf extension files top 5" | **file listing** | — |

The scoped summary, distribution, detection signals, remediation plan,
priority queue, and evidence register all reflect the capped set; posture and
the full-scan summary remain whole-scan metrics. Uncapped severity, finding,
and full-scan reports are unchanged from the previous behavior.

## PDF Composer / artifact result

No fork was introduced: Copilot artifacts and the dashboard's PDF Composer
endpoint both flow through `create_report_artifact` → `build_report_model` →
the shared visual renderer, so the new scope kinds/labels appear identically
in the stored PDF, the HTML companion ("Scoped to file type: Top 5 .pdf
files."), the report title, and the filename tag (`dspm_report_top5_critical_…`).
The dashboard Composer's full-scan report passes no limit and is unchanged.
Signed download tokens, tenant/subject storage, and authorization were not
touched.

## Tests added / updated

- `tests/test_smb_scan_cache_progress.py` (4): SMB collection emits progress
  with discovered/reused counters mapping past 14; unchanged second scan
  reuses (zero remote reads, zero ACL calls, identical findings/risk/owner/
  preview); changed file re-read/reclassified; missing findings cache
  fails closed and re-reads.
- `tests/test_scan_jobs.py` (+4): `collection_heartbeat` advances within its
  ceiling; deadline fails a hung remote scan; `_analyze_endpoint_records`
  reaches 90 with per-record messages; cancellation raises.
- `tests/test_topn_report_scope.py` (15): report-model caps for severity+limit,
  uncapped severity, combined severities, extension+limit, single finding,
  full-scan no implicit cap; flow tests for all eight required report cases
  plus the `.pdf`-listing regressions.
- All previous suites (local cache reuse, scan jobs, stabilization, visual
  PDF, template unification, file queries) pass unchanged.

## Commands run and full results

- `python -m compileall backend collectors discovery` → exit 0
  (`COMPILEALL OK`).
- `python -m unittest tests.test_smb_scan_cache_progress` → `Ran 4 tests` …
  `OK`.
- `python -m unittest tests.test_topn_report_scope tests.test_scan_jobs` →
  `Ran 28 tests` … `OK`.
- `python -m unittest discover tests` → `Ran 297 tests in 65.106s` …
  `OK (skipped=1)`.
- `node --check frontend/app.js` / `frontend/copilot.js` → **not run: Node is
  not installed in this environment** (`node` absent from PATH). No frontend
  JavaScript was changed in this pass; the poll loop already renders backend
  progress/message and failure states (locked by existing contract tests).

## Remaining risks

- **WinRM collection remains single-batch.** Per-file collection progress and
  metadata-first reuse need a two-phase remote protocol (metadata manifest +
  skip-list) — roadmap work. Until then WinRM cost on unchanged files is paid
  on the endpoint; only reclassification is cached.
- **SMB reuse heuristic is size+mtime+path** under the version signature —
  the same sanctioned MVP heuristic as local. A rewrite preserving both size
  and mtime would be reused.
- **SMB tests use a stubbed connection** (no `pysmb`/live server in this
  environment). The stub exercises the real `_walk_share` code path; a live
  SMB lab pass is still recommended before release.
- **Cold scans are unchanged** — first-ever files still pay full remote reads,
  hash, and ACL; reuse only accelerates subsequent scans.
- **`scopes_equal` now includes limit/extension**, so a differently-limited
  follow-up regenerates a fresh artifact instead of reusing the cached link —
  intended, but it mints more artifacts for users who vary N repeatedly.
- **Node syntax check pending** in a Node-enabled environment (no JS changed).

## Manual verification steps

1. Run an SMB scan against a real share; confirm the progress bar advances
   with "Discovering files… N found" and the scan completes at 100.
2. Re-run the same SMB scan unchanged; confirm it is much faster, the message
   shows "… M reused from cache", diagnostics report `cache_reused_files`, and
   findings/risk match the first run.
3. Modify one remote file; rescan; confirm only that file is re-read.
4. Run a WinRM endpoint scan; confirm the message notes the single-batch
   remote inventory, progress advances during analysis ("Analyzing endpoint
   files i/N"), and an unreachable/hung endpoint ends as **failed** within
   `DSPM_SCAN_MAX_SECONDS`.
5. In Copilot: "top 5 critical files as PDF report" → open the PDF; title/scope
   say "Top 5 CRITICAL" and the evidence register has exactly 5 rows.
6. "give me top 5 pdf files" → a file listing (no artifact); then "give me that
   as a pdf report" → a "Top 5 .pdf files" report with 5 rows.
7. "give me pdf about only medium alerts" → an uncapped MEDIUM report.
8. Dashboard → Open PDF Composer → full report unchanged (no cap).
9. `node --check frontend/app.js` / `frontend/copilot.js` in a Node
   environment.
