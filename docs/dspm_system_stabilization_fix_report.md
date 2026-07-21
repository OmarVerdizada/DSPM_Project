# SENTRO DSPM — System Stabilization Fix Report

Date: 2026-07-15

## Outcome

The current-system regressions across scan progress, dashboard delta
explanation, Copilot intent/report routing, cross-message report scope, and
English/Azerbaijani language consistency are fixed. All changes are
deterministic, local-only, add no dependencies, and preserve tenant isolation,
auth, signed-artifact download, safe path handling, secret masking,
evidence-backed factual answers, and provider-final blocking for DSPM facts.

The required regression transcript now behaves correctly end-to-end (verified
by a direct `handle_chat` replay with the model provider forced down).

## Files changed

Backend / frontend:

- `backend/jobs.py` — scan-collection progress heartbeat + wall-clock deadline.
- `frontend/app.js` — `pollScan` transient-error tolerance; dashboard delta
  tooltip/label.
- `backend/copilot/file_queries.py` — `pdf` format vs `.pdf` extension;
  superlative listing cues.
- `backend/copilot/conversation_repair.py` — bare/anaphoric report-scope
  inheritance; English-default artifact renderers; emphatic-negation correction
  cue.
- `backend/copilot/product_help.py` — navigation why/evidence guard; new
  risk-summary delta-explanation route + renderer.
- `backend/copilot/correction_detection.py` — "not what i asked" wrong-route
  terms.
- `backend/copilot/language.py` — universal/format tokens are language-neutral.
- `backend/copilot/service.py` — `last_reportable_scope` writes; English-default
  language fallbacks; English branches for P0/P1 scoped-finding renderers; wire
  the delta-explanation route.

Tests / docs:

- `tests/test_scan_jobs.py` (new)
- `tests/test_copilot_stabilization.py` (new)
- `tests/test_scan_and_dashboard_ui_contract.py` (new)
- `docs/dspm_system_stabilization_analysis.md` (new)
- `docs/dspm_system_stabilization_fix_report.md` (new)

## Scan progress fix

`backend/jobs.py` `_run_scan_job` now starts a lightweight daemon **heartbeat**
around `DSPMDiscoveryEngine.run()`:

- while collection runs (before the first `"collected"` callback lifts progress
  to ≥15), it nudges `job.progress` up to a ceiling of 14 every
  `COLLECT_HEARTBEAT_SECONDS` (default 2s), so the bar visibly moves instead of
  freezing at 7;
- it enforces a wall-clock deadline `SCAN_MAX_SECONDS` (default 1800s,
  env-overridable) — a genuinely hung collection (unreachable target, oversized
  tree) is flipped to `status="failed"` with a clear error, so the frontend
  shows a failure instead of an eternal running/7.

`frontend/app.js` `pollScan` now wraps the `GET /api/scans/{id}` call in
try/catch with bounded retry (`MAX_POLL_ERRORS = 5`): a single transient poll
error (5xx, brief 401, network blip) keeps polling instead of abandoning a scan
that is still running/completing on the backend; only sustained errors surface a
failure. Backend `job.progress` remains authoritative; completion still reaches
100 and refreshes history, and genuine failures still surface via the existing
toast path.

No scanner/collector internals or the durable-job architecture were changed
(that is roadmap work: SCAN-002 / ARCH-003).

## Dashboard delta explanation fix

- `product_help.detect_product_help` now returns a deterministic
  `risk_summary_delta_explanation` for "why does the risk summary show minus /
  Critical: -1" questions, and its **navigation** branch now bails when the
  message contains a why/explanation cue or matches `_EVIDENCE_GUARD_RE`
  (severity words / minus data). `service._handle_product_help` renders the new
  kind via `product_help.render_risk_summary_delta`.
- The explanation is accurate to the code: the values are per-severity deltas
  between the latest and previous saved scan (`delta = latest − previous`); a
  minus means fewer files at that severity than last scan (posture improved), a
  `+` means more, `0` means no change, and it needs ≥2 saved scans. It offers to
  compare the two scans. It never tells the user how to navigate.
- The "Dashboaard" typo was a provider hallucination triggered when "answer me"
  escaped to the provider; with the dashboard question now answered
  deterministically and "answer me" no longer repeating navigation, it does not
  occur.
- `frontend/app.js buildScanComparison` now renders a one-line hint ("Change vs
  previous scan (latest − previous). A minus value means fewer than last scan.")
  and a per-row `title`/`aria-label` on each delta ("Critical: 1 fewer than
  previous scan (latest N − previous M)"), so the negatives are self-explanatory
  in the UI.

## Copilot critical-file behavior fix

`file_queries.parse_file_query` `has_query_cue` now also matches `most`,
`what are`, `which are`, `riskiest`, `highest`. "What are the most critical
files?" is answered from the latest scan (severity-filtered, risk-sorted
evidence) instead of generic advice, matching "give me top 5 critical files".

## Previous-result-to-report behavior fix

- `conversation_repair.resolve_report_scope` now inherits scope for
  bare/anaphoric report requests ("give me that as a pdf report", "give as a
  pdf", bare "pdf", "make it a report", "export this") via a new
  `_inherited_reportable_scope` helper that reads, in order,
  `last_reportable_scope`, the `last_file_query` severity (with limit), and any
  stored `last_count_scope_severities`.
- `service.py` now writes an authoritative `last_reportable_scope` after every
  scoped evidence/report turn: in `_store_contract_list_context` for
  severity-scoped findings lists, and in the artifact-create repair path for the
  resolved report scope. This gives correct **recency** — a bare "pdf" after
  "medium alerts" inherits MEDIUM, not a stale earlier CRITICAL.
- The artifact-create path now passes the resolved `report_scope` into
  `render_artifact_answer` / `artifact_session_fields`, so the scope label and
  stored artifact scope are correct.

## PDF report vs .pdf extension behavior fix

`file_queries` now treats a format-ambiguous token ("pdf") as a `.pdf` extension
filter **only** when it is dotted (".pdf") or immediately followed by a file
noun ("pdf files", "pdf extension", "pdf types"). A bare "pdf" adjacent to a
report/format context is an output format, so `_extract_extension` returns
`None` and the report-deferral guard fires, handing the message to the report
route.

Result:

- "give me top 5 **pdf files**" and ".pdf extension files" → `file_query_list`
  (no artifact) — unchanged.
- "top 5 critical files **as a pdf report**" → CRITICAL PDF report (no `.pdf`
  file listing).
- "give me **pdf about only medium alerts**" → MEDIUM PDF report (no `.pdf` file
  listing).
- "give me a PDF report" → report generation — unchanged.

## Medium/high/critical report behavior fix

Scoped report requests resolve to the correct severity scope, whether the
severity is named in the message ("give me pdf about only medium alerts" →
MEDIUM; "you must give top 5 critical files as a pdf report" → CRITICAL) or
inherited from the previous reportable result (bare "pdf" / "give as a pdf").
The scope is passed to `create_report_artifact`, which builds the scoped report
via the existing `report_model` (severity/finding/full), unchanged. No
accidental `.pdf`-extension filtering; no generic full-scan report when a
specific scope exists.

## Language consistency fix

- `language.detect_language_metadata` now treats a message composed solely of
  universal format/technical tokens (`pdf`, `csv`, `json`, `url`, …) as
  language-neutral (`unknown`, low confidence), so a bare "pdf" no longer
  misdetects as Azerbaijani and instead inherits the established session
  language (English-first).
- `conversation_repair.render_artifact_answer` / `render_artifact_error` /
  `render_missing_artifact_link` now make Azerbaijani an explicit
  `language == "az"` branch and default the fallback to **English**, so an
  English conversation can never emit "PDF hazırdır" / "Skan" / "Filtr".
- The `else: "az"` service-layer language defaults in
  `_handle_conversation_repair`, `_rerender_previous_answer`, and
  `_handle_p0_situation_guardrail` are now `"en"`, matching
  `language_runtime.DEFAULT_LANGUAGE`.
- `service._p0_scoped_findings_text` / `_p1_scoped_detail_text` now branch on
  language with a full English rendering (previously always Azerbaijani), via a
  shared `_finding_scope_footer` helper.

Azerbaijani remains fully supported: a genuine AZ conversation (detected or
locked AZ, or an explicit request) still renders Azerbaijani; only ambiguous /
unknown input defaults to English.

## Corrections fix

- `correction_detection._WRONG_ROUTE_TERMS` now includes "not what i asked" /
  "that is not what i asked" / "not what i wanted".
- `conversation_repair.detect_severity_subset_correction` now recognizes
  emphatic negation ("Noooooo", "xeyr") as a correction cue.

## Tests added / updated

- `tests/test_scan_jobs.py` (5 tests): completed job reaches 100; failed job
  reports failure (not stale running); scan completes through `_run_scan_job`;
  progress advances past 7 during a slow collection; wall-clock deadline marks a
  hung job failed.
- `tests/test_copilot_stabilization.py` (11 tests): "most critical files"
  evidence-backed; "that as a pdf report" preserves CRITICAL; "top 5 critical
  files as a pdf report" is not a `.pdf` listing; "pdf about only medium alerts"
  → MEDIUM report; bare "pdf" after medium inherits MEDIUM + stays English;
  "top 5 pdf files" still lists `.pdf`; correction still lists `.pdf` files;
  dashboard minus → delta explanation; "answer me" not navigation; no
  "Dashboaard"; English report has no "Skan"/"PDF hazırdır"; provider-down
  keeps report + evidence deterministic.
- `tests/test_scan_and_dashboard_ui_contract.py` (2 tests): `pollScan`
  transient-error tolerance; dashboard delta tooltip/hint present.

## Commands run and full results

- `python -m compileall backend` → exit 0 (`COMPILEALL OK`).
- `python -m unittest tests.test_scan_jobs` → `Ran 5 tests` … `OK`.
- `python -m unittest tests.test_copilot_stabilization` → `Ran 11 tests` …
  `OK`.
- `python -m unittest tests.test_scan_and_dashboard_ui_contract` →
  `Ran 2 tests` … `OK`.
- `python -m unittest discover tests` → `Ran 262 tests in 54.104s` …
  `OK (skipped=1)`.
- `node --check frontend/app.js` / `frontend/copilot.js` → **not run**: Node is
  not installed in this environment (`node` is not on PATH and no `node.exe`
  exists on disk). The `app.js` changes are small, self-contained additions (a
  try/catch retry block in `pollScan` and a `title`/`aria-label` in
  `buildScanComparison`); they were reviewed for balanced braces and valid
  syntax. Re-run `node --check frontend/app.js` in an environment with Node
  before release.

## Remaining risks

- **Scan hang is surfaced, not interrupted.** The deadline flips the *job* to
  failed so the UI is correct, but the underlying worker thread can linger until
  its next cooperative cancel check (same limitation as the existing cancel
  path). True mid-parse cancellation is roadmap work (SCAN-002). The default
  deadline (1800s) is generous; tune `DSPM_SCAN_MAX_SECONDS` for very large
  legitimate scans.
- **Node syntax check pending.** See above — run `node --check` on the two
  frontend files in a Node-enabled environment.
- **Language-neutral token list is bounded.** Bare single-token messages that
  are common file/format words inherit the session language; an unusual bare
  token could still be detected by the normal path. This is intentionally
  conservative and English-first.
- **`report_model` has no top-N limit.** A "top 5 critical" report scopes to
  CRITICAL correctly; the numeric limit is preserved in the inherited scope
  (`limit`) but the current renderer includes all matching CRITICAL rows
  (priority queue caps at 10). Honoring an explicit top-N cap in the register is
  a small future enhancement, not a correctness regression.
- **Full browser verification.** This environment has no browser test runner or
  PDF rasterizer; frontend behavior is covered by source-contract tests plus the
  manual steps below.

## Manual verification steps

1. **Scan progress:** start an async file-server/local scan against a slow or
   large target; confirm the bar moves past 7% during collection, reaches 100%
   on completion, and refreshes the dashboard. Point a scan at an unreachable
   target; confirm it ends as *failed* (not stuck at 7) within the configured
   deadline. Briefly interrupt connectivity mid-scan; confirm the UI keeps
   monitoring and does not abandon the scan.
2. **Copilot report flow (English session):** ask "What are the most critical
   files?" (expect real files), then "give me that as a pdf report" (expect a
   CRITICAL report), "you must give top 5 critical files as a pdf report" (report,
   not `.pdf` file list), "give me top 5 pdf files" (`.pdf` file list, no
   report), "give me pdf about only medium alerts" (MEDIUM report), then bare
   "pdf" (still MEDIUM, English "Your PDF is ready", no "PDF hazırdır"/"Skan").
3. **Dashboard delta:** with ≥2 saved scans, hover a risk-summary delta and
   confirm the tooltip explains it; ask the Copilot "why does the risk summary
   show minus, Critical: -1" and confirm a delta explanation (not navigation,
   no "Dashboaard"); then "answer me" and confirm it does not repeat navigation.
4. **Azerbaijani session:** confirm Azerbaijani report/finding replies are still
   Azerbaijani when the conversation language is AZ or explicitly requested.
5. Run `node --check frontend/app.js` and `node --check frontend/copilot.js` in
   a Node-enabled environment.
