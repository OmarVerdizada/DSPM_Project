# SENTRO DSPM — SMB/WinRM Scan Progress & Cache + Top-N PDF Scope Analysis

Date: 2026-07-16

## Scope and method

Focused stabilization pass covering the two documented follow-ups from the
previous passes: (A) SMB/WinRM collection progress and metadata-first cache
reuse, and (B) top-N limit preservation in PDF report scope. Not the enterprise
roadmap. All conclusions verified from source and by runtime probes: the SMB
walk driven against a fake in-memory connection, and a full `handle_chat`
replay of the required report cases with the provider forced down.

## Reports / PDF read

- `docs/scan_progress_cache_root_fix_analysis.md` / `_report.md` (local
  metadata-first reuse + real collection progress; SMB/WinRM flagged follow-up).
- `docs/dspm_system_stabilization_analysis.md` / `_fix_report.md` (heartbeat,
  deadline, report-scope inheritance, `.pdf` vs PDF-report intent).
- `docs/pdf_report_template_unification_report.md` (single server-side PDF
  renderer driven by `report_model`; dashboard Composer uses the same artifact).
- `docs/Sentro_DSPM_Enterprise_Full_Technical_Assessment_2026.pdf` (context
  only: collect-all pipeline, per-file ACL cost, full hash cost, WinRM
  full-work-on-endpoint, timeout-not-interruption).
- The listed `copilot_report_intent_context_fix_*` docs do not exist in this
  workspace; that work is recorded in the `dspm_system_stabilization_*` docs.

## Source areas inspected

`collectors/smb_scanner.py` (`scan`, `_walk_share`, `_read_file_preview`,
`_hash_file`, `_acl_for_path`), `collectors/winrm_endpoint_scanner.py`
(`scan`, remote script contract), `collectors/file_scanner.py`
(`normalize_records`, local reuse), `discovery/discovery_engine.py`
(`_collect_records`, `_reuse_probe`, `_write_meta_sidecar`, `_analyze_record`),
`backend/jobs.py` (heartbeat/deadline, progress mapping), `backend/app.py`
(`endpoint_scan`, `_run_endpoint_scan_payload`, `_run_local_endpoint_scan_payload`),
`backend/copilot/{report_model,conversation_repair,file_queries,service,
artifacts,report_pdf}.py`, `frontend/app.js` (poll loop — unchanged), and the
scan/cache/report test suites.

## Analysis questions

1. **How does SMB collect records?** `SMBScanner.scan()` iterates shares and
   `_walk_share` recursively lists each folder via `listPath`. For every
   matching file it *always* performed a remote content read
   (`_read_file_preview`), a **full-file chunked SHA-256** (`_hash_file` re-reads
   the entire file over the network), and a per-path ACL lookup
   (`_acl_for_path`, a PowerShell subprocess per path). Collect-all, no
   progress, no reuse.
2. **How does WinRM collect records?** One remote PowerShell script enumerates,
   filters, reads content, and hashes **on the endpoint**, returning all
   records in a single JSON response (`WinRMEndpointScanner.scan`). The backend
   sees nothing until the whole batch returns.
3. **Where can SMB safely emit progress?** Inside `_walk_share`'s per-entry
   loop — the same place the local walker emits. Implemented: visited/matched/
   reused counters emitted (throttled) through a `progress_callback`.
4. **Where can WinRM emit progress?** Nowhere per-file without changing the
   remote protocol (single-response contract). The safe points are phase
   boundaries: before the remote call, after it returns, and per-record during
   backend analysis. Implemented: heartbeat band + deadline around the remote
   call, real per-record progress (70→90) during analysis.
5. **What metadata is available before heavy reads?** SMB: `listPath` returns
   filename, `file_size`, `last_write_time`, `create_time`, hidden/system flags
   — everything the metadata-first probe needs, before any content I/O. WinRM:
   metadata only arrives *with* the already-read content, so nothing is
   available "before" the heavy work.
6. **Can unchanged SMB/WinRM files be safely reused via path/source/size/mtime?**
   SMB: yes — same sidecar model as local, keyed by a source-qualified identity
   `smb://server/share/path` + size + mtime + version signature (tenant,
   parser, detector, rule catalog, frameworks). WinRM: no — the heavy work
   happens remotely before metadata is visible; reuse would require a remote
   manifest/checkpoint protocol (documented as out of scope).
7. **Which heavy operations can be skipped safely?** For an unchanged SMB file:
   the remote content read, the full-file hash transfer, the per-path ACL
   PowerShell subprocess, and reclassification (via the existing finding
   cache). All skipped on sidecar hit.
8. **Which cannot be skipped yet and why?** WinRM per-file work (remote script
   does it before the backend can intervene); SMB share/folder enumeration
   (needed to detect changes at all); zip/protected files (their protection
   state requires opening them); first-ever (cold) scans.
9. **How does report scope store severity/limit/extension/selected item?**
   Scope dicts `{"kind": full|severity|finding, severities?, finding_ref?,
   label}` flow from `conversation_repair.resolve_report_scope` →
   `create_report_artifact` → `report_model.build_report_model`. Session memory
   holds `last_reportable_scope` / `last_file_query` (which has `extension` and
   `limit`) / `last_artifact_scope`.
10. **Where is the top-N limit lost?** Three places: (a)
    `requested_report_scope` never parsed "top N" or extensions from the
    message; (b) `_inherited_reportable_scope` carried `limit` from
    `last_file_query`, but (c) `report_model._normalize_scope` **stripped every
    key except kind/severities/finding_ref/label**, so even an inherited limit
    never reached `_select_scoped_files`, and there was no extension scope kind
    at all. Additionally the file-query route never wrote
    `last_reportable_scope`, so inheritance relied on the raw
    `last_file_query` fallback.
11. **How should report_model apply top-N without breaking full reports?**
    Normalize `limit` (1–100) as an optional scope field; after severity/
    extension/finding filtering and risk-descending sort, cap `scoped_sorted`
    to the limit and compute *all scoped sections* (summary, distribution,
    signals, remediation, queue, register) from the capped set. Posture and
    `full_summary` stay whole-scan. No limit ⇒ unchanged behavior, so full and
    uncapped severity reports are byte-identical to before.
12. **How do PDF Composer/backend artifacts stay consistent?** They already
    share one renderer: `create_report_artifact` → `build_report_model` →
    `report_pdf`, and the PDF/HTML take title/label from the normalized scope.
    Fixing the normalizer fixes every consumer; the dashboard Composer's
    full-scan endpoint passes no limit and is unaffected. `_scope_filename_tag`
    and `_SCOPE_DESCRIPTION` were extended for extension/top-N labels.

## SMB progress/cache root cause

`_walk_share` paid the full remote cost (preview read + full hash + ACL
subprocess) for **every** file on **every** scan, before the finding cache
could run, and emitted zero progress — identical in shape to the local bug
fixed in the previous pass, but left as a follow-up. Progress relied entirely
on the jobs-level heartbeat band.

## WinRM progress/cache root cause

`_run_endpoint_scan_payload` pinned `job.progress = 8`, then blocked on the
single-response remote script with **no heartbeat and no wall-clock deadline**
(the deadline added previously lives in `_run_scan_job`, which the endpoint
path does not use). A hung remote script left the job "running/8" forever.
The analyze loop (`[_analyze_record(r) for r in records]`) then jumped 70→92
with no per-record signal. Collection-time reuse is architecturally impossible
without a remote protocol change: the endpoint reads/hashes before the backend
sees any metadata. (Reclassification is still avoided by the existing
content-hash finding cache during backend analysis.)

## Safe reuse feasibility

- **SMB — feasible and implemented.** `listPath` metadata precedes all heavy
  I/O. The existing sidecar/version-signature model extends cleanly with a
  source-qualified identity; no separate cache was created.
- **Fail-closed requirement:** unlike local, SMB has no post-collection re-read
  fallback (the connection is closed by analysis time). The sidecar therefore
  now records its paired findings-cache digest and the probe misses when that
  entry is gone, forcing a full re-read *while the connection is open*. As a
  final backstop, a reused non-local record that still misses the finding cache
  fails that record honestly instead of classifying empty content.
- **WinRM — not feasible this pass.** Reuse would need the remote script to
  return a metadata manifest first and accept a skip-list (a two-round-trip
  protocol change). Documented as the remaining limitation; progress/deadline/
  failure behavior improved instead.

## Top-N report root cause

`_normalize_scope` was a whitelist that silently dropped `limit` (and had no
extension kind), so any top-N intent — parsed or inherited — died there. The
message parser also never extracted "top N"/extensions, and the file-query
route didn't publish its scope. Fixed at all three layers with `report_model`
as the single authority for normalization and capping.

## Chosen fix plan

1. **SMB:** add `reuse_probe` + `progress_callback` to `SMBConfig`; in
   `_walk_share`, after filters and before any remote I/O, probe with
   `smb://server/share/path` + size + mtime; on hit emit the stored snapshot
   (owner/ACL/hashes/status/preview) with `cache_reused`; tag full-read records
   with `reuse_key` so `_write_meta_sidecar` stores the same identity; counters
   in diagnostics and progress.
2. **Engine:** wire the SMB scanner to the existing `_reuse_probe` /
   `_collection_progress`; sidecars now store `finding_cache_digest`
   (fail-closed probe); `_write_meta_sidecar` accepts local + SMB.
3. **WinRM:** extract the heartbeat/deadline into a reusable
   `jobs.collection_heartbeat` context manager; wrap the remote scan phase
   (ceiling 60, honest message); shared `_analyze_endpoint_records` gives real
   per-record 70→90 progress and cancellation for both remote and local
   endpoint paths.
4. **Top-N:** `report_model` normalizes/applies `limit` and an `extension`
   scope kind (optionally severity-filtered) and labels them ("Top 5 CRITICAL",
   "Top 5 .pdf files"); `requested_report_scope` parses top-N and extensions;
   `_inherited_reportable_scope` returns extension scopes; the file-query list
   route publishes `last_reportable_scope`; `scopes_equal` compares
   limit/extension so a different-scoped follow-up regenerates;
   `file_queries` defers all non-negated report/format requests to the report
   route (".pdf files" listings and corrections unchanged).

## Rejected alternatives

- **Fake/animated SMB progress only.** Rejected — the walk has real counters
  available; progress must represent real state.
- **A separate SMB cache.** Rejected — reuses the existing sidecar + version
  signature + finding cache; one invalidation model, no drift.
- **WinRM metadata-first reuse via remote manifest.** Rejected for this pass —
  a two-phase remote protocol change (manifest + skip-list) is roadmap-scale;
  risk of silent coverage loss without a lab to validate against.
- **Reusing local re-read fallback for SMB misses.** Rejected — the SMB
  connection is closed by analysis time; a local `Path` read of a remote path
  returns empty and would silently classify "no findings". Fail-closed probe +
  honest per-record failure instead.
- **Capping only the evidence register (not scoped stats).** Rejected — a
  "Top 5 CRITICAL" report whose distribution/signals still counted all
  criticals would contradict its own title.
- **Parsing top-N in the artifact layer.** Rejected — scope normalization
  belongs in `report_model` (single authority already shared by Copilot and
  the dashboard Composer endpoint).
- **Baking display counts into severity-list scopes.** Rejected — "medium
  alerts PDF" must stay uncapped MEDIUM; only explicit/requested limits (from
  the message or the previous file query) are preserved.
