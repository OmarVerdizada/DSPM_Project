# SENTRO DSPM — System Stabilization Analysis

Date: 2026-07-15

## Scope and method

This is a stabilization pass (bug-fix / integration-fix / quality) across the
current DSPM backend, frontend, scan flow, reports, and AI Copilot. It is **not**
the enterprise roadmap in
`Sentro_DSPM_Enterprise_Full_Technical_Assessment_2026.pdf`; that PDF was read
only as context for current system risk.

Every conclusion below was verified against source and against the real runtime
(a direct replay of the failing transcript through `handle_chat` with the local
model provider forced down via `LLMError`, and direct unit exercise of the scan
job lifecycle). No provider output was used as evidence for any DSPM fact.

## Reports / PDF read (modified-time order)

Enterprise assessment PDF (40 pages, context only):
`docs/Sentro_DSPM_Enterprise_Full_Technical_Assessment_2026.pdf`.

Docs (newest first):
`docs/pdf_report_template_unification_report.md`,
`docs/copilot_final_polish_pdf_ui_fix_report.md`,
`docs/copilot_final_polish_pdf_ui_analysis.md`,
`docs/copilot_file_query_intent_ui_fix_report.md`,
`docs/copilot_file_query_intent_ui_fix_analysis.md`,
`docs/copilot_chat_layout_regression_fix_report.md`,
`docs/compliance_remediation_priorities.md`,
plus the root changelogs/notes (`REPORT_EXPORT_*`, `SECURITY_AND_UI_FIXES_v101`,
`PROJECT_UPDATE_NOTES_v80/81`, `PRODUCT_FEATURES`, `README`).

These establish the intended architecture: evidence-first deterministic report
data, a native browser PDF Composer plus a unified dependency-free server PDF
renderer, scoped report models (`report_model.py`), tenant/subject-isolated
signed artifacts, English-first language resolution, provider-final exclusion
for DSPM facts, and a deterministic file-query route (`file_queries.py`) added
in the prior pass. The regressions in this pass are the *next layer* on top of
those fixes (the `.pdf`-format vs `.pdf`-extension boundary and cross-message
report-scope memory), not a regression of them.

Relevant enterprise-assessment risk context (not implemented here): SCAN-002
("timeout is measured, not enforced — a stuck worker is never cancelled") and
ARCH-003 ("in-memory job dictionary"). Both directly explain the scan-progress
symptom and bound what a stabilization fix can safely do without the roadmap.

## Source areas inspected

Backend: `backend/jobs.py`, `discovery/discovery_engine.py`, `backend/app.py`
(scan routes `POST /api/scan`, `GET /api/scans/{id}`), `backend/store.py`,
`backend/copilot/{service,file_queries,report_model,conversation_repair,`
`route_dispatcher,product_help,correction_detection,language,language_runtime,`
`language_service}.py`.

Frontend: `frontend/app.js` (`runQueuedScan`, `pollScan`, `setScanProgress`,
`smoothProgress`, `buildScanComparison`, `buildReportComparisonRows`).

Tests: `tests/test_copilot_file_queries.py`,
`tests/test_copilot_visual_pdf_report.py`,
`tests/test_copilot_chat_ui_contract.py`, `tests/test_platform_regression.py`,
`tests/test_endpoint_scopes.py`.

## Scan progress root cause (stuck at 7%)

The async file-server/local scan path is the only one that shows 7:

`runQueuedScan()` → `POST /api/scan {async_scan:true}` → `create_scan_job` →
`create_job` submits to a `ThreadPoolExecutor` and returns immediately
(`jobs.py`), the worker runs `_run_custom_job` → `_run_scan_job` →
`DSPMDiscoveryEngine.run()`; the frontend `pollScan` polls `GET /api/scans/{id}`
every 1200 ms and reads `progress/status/message` (field names match the
backend `to_dict`).

1. **7 is a hardcoded backend value** at `jobs.py:_run_scan_job` (`job.progress
   = 7`, "Collecting files"). It is not a frontend stage weight (there is no
   `0.07`/stage table in `app.js`).
2. **Primary cause — no progress during collection.**
   `discovery_engine.run()` calls `_collect_records()` to completion and only
   *then* emits the first `"collected"` callback (→15). During the entire
   collection phase there are zero progress updates, so a slow or hanging
   collection (unreachable SMB, huge tree, network stall) pins the job at
   exactly 7. This is the "sometimes": it is target/data dependent.
3. **Secondary cause — no real timeout.** `_timed_detector` only *measures*
   elapsed time (`degraded_mode`), it never interrupts; collection has no
   wall-clock cap. A hang therefore never raises, so `_run_custom_job`'s
   `except` never fires, status never becomes `failed`, and `pollScan` never
   reaches its failure branch. The bar "never advances even when it fails"
   because the job never actually *fails* — it silently hangs at running/7.
4. **Contributing — fragile polling.** `pollScan`'s `while(true)` had **no
   try/catch** around the `api()` GET, so a single transient poll error (5xx,
   brief 401 → redirect, network blip) aborted monitoring for a scan that was
   still running/completing on the backend.

On genuine completion the flow is correct (100 + `loadHistory()` refresh); on a
genuine backend failure the toast + `setScanProgress(false)` path already fires.
Only the silent-hang and transient-poll-error cases produce the stuck bar.

## Dashboard delta / minus root cause

The negative severity values ("Critical: -1") are **frontend-computed deltas
between the two most recent saved scans**, not counts. `app.js
buildScanComparison` uses `previous = trend[len-2]`, `latest = trend[len-1]`,
then `delta = Number(current) - Number(prior)`; `buildReportComparisonRows`
does the same. So `Critical: -1` = "the latest scan has 1 fewer critical file
than the previous scan" (posture improved); `+` means more (worsened); it needs
≥2 saved scans. The backend `report_model._comparison` computes the identical
`delta = current_i - prior_i`, and `professional_workflows.render_scan_delta`
consumes the same latest-vs-previous `severity_delta`, so the Copilot can
describe them consistently. **This is correct behavior, only under-explained.**

The bug was purely routing: the question was answered as **navigation**. In
`product_help.detect_product_help` the navigation branch fired on `show` +
`page` + a resolvable tab token ("dashboard") and — unlike the features/overview
branches — applied **no `_EVIDENCE_GUARD_RE` and no why/explanation guard**,
even though the message literally contained "Critical: -1, High: -2". Navigation
has `RoutePriority.UI_NAVIGATION_HELP = 89` in `route_dispatcher`, so it
outranked almost everything and `render_navigation_help` emitted "open the
Dashboard page from the sidebar".

**"Dashboaard" typo:** the misspelled string exists nowhere in source
(`render_navigation_help` uses the verified `UI_TABS` label "Dashboard"). It is
a *provider hallucination* on re-answer: "answer me" matched no deterministic
route and fell to the legacy provider fallback, which paraphrased/corrupted the
prior navigation answer. Its appearance is itself evidence that "answer me" was
escaping the deterministic layer.

## Copilot intent / report root causes

- **A. "What are the most critical files?" → generic.** `file_queries`'
  `has_query_cue` regex required an explicit listing cue (`top|give|show|list|
  find|highest|riskiest|...`). A superlative question with file context but no
  cue ("what are the **most** critical files") failed the gate and fell to the
  legacy provider route, while "give me top 5 critical files" (has `top`/`give`)
  worked.
- **B. `pdf` *report* mis-classified as `.pdf` *extension* (core bug).** `"pdf"`
  is a member of `_KNOWN_EXTENSIONS` but not of `_REPORT_RE`. When file context
  (or "only"-style inheritance) was present, `_extract_extension` returned
  `.pdf` for the bare token "pdf", which defeated the report-deferral guard
  (`... and extension is None`). So "top 5 critical files **as a pdf report**"
  and "**pdf** about only medium alerts" were parsed as `.pdf` extension file
  listings. `parse_file_query` runs *before* the report route in `handle_chat`,
  so this mis-claim always won.
- **C. Report scope lost between messages.** No "last reportable result" frame
  was consulted. `resolve_report_scope` parsed scope only from the current
  message and inherited a cached scope **only** for explicit corrections; a
  bare/anaphoric request ("give me that as a pdf report", "give as a pdf",
  bare "pdf") produced `{"kind":"full"}` → a generic full-scan report, dropping
  the prior severity/limit.
- **E. Corrections/follow-ups.** `"not what i asked"` was absent from
  `_WRONG_ROUTE_TERMS`; emphatic negation ("Noooooo") was not a correction cue;
  "answer me" matched no deterministic re-answer route and hit the provider.

## Language leak root cause

Two layers:

1. **Detector misclassification.** `detect_language_metadata("pdf")` returned
   `("az", 0.99)` — `understand_message` classifies the bare universal token
   "pdf" as high-confidence Azerbaijani. `language_runtime.decide_language`
   treats a clear current-turn detection (≥0.6) as authoritative and overrides
   the established English session, so a bare "pdf" turn resolved the response
   language to `az`.
2. **Azerbaijani-as-fallback renderers.** `conversation_repair.
   render_artifact_answer` (and `render_artifact_error` /
   `render_missing_artifact_link`) put Azerbaijani in a bare `else`, so any
   language that was not exactly `en`/`ru` produced "PDF hazırdır" / "Skan" /
   "Filtr". The service layer compounded it: `_handle_conversation_repair`,
   `_rerender_previous_answer`, and `_handle_p0_situation_guardrail` defaulted
   an unrecognized language to `"az"`, contradicting
   `language_runtime.DEFAULT_LANGUAGE = "en"`. Separately,
   `service._p0_scoped_findings_text` / `_p1_scoped_detail_text` accepted a
   `language` argument but never branched on it — their bodies were always
   Azerbaijani.

## State / memory / context root cause

Report-scope memory existed only as `last_artifact_scope` (written after a PDF
was made) and `last_file_query` (severity/limit of the last file query). Neither
was a general "most-recent reportable scope", and `resolve_report_scope` read
neither for bare/anaphoric report requests. Evidence turns that established a
severity scope (severity findings list, scoped report) did not record a single
authoritative reportable-scope frame, so a later bare "pdf" either fell to full
scope or inherited a *stale* earlier `last_file_query` severity instead of the
most recent one.

## Frontend / backend integration root causes

- Backend `job.progress` is authoritative for the stage number, but `pollScan`
  re-derives a smoothed value (`smoothProgress` applied twice per poll) and had
  no error tolerance, so the UI could decouple from live backend state on a
  single transient error.
- The dashboard delta is computed entirely client-side from `trend[-2]` /
  `trend[-1]`; it had no user-facing explanation, which is why the negative
  values looked like a bug to users and generated the Copilot question.

## Rejected hypotheses

- *7% is a frontend stage weight.* Rejected — no stage table exists; 7 is
  hardcoded in `jobs.py`.
- *Real scan failures stick at 7%.* Rejected — genuine failures surface via the
  toast/`setScanProgress(false)` path; only silent hangs and swallowed poll
  errors stick.
- *The PDF Composer / report model is broken.* Rejected — explicit report
  requests use the intended scoped Composer/artifact flow; the defect was intent
  precedence for the `pdf` token and missing cross-message scope memory.
- *The negative dashboard values are a computation bug.* Rejected — they are
  correct latest-vs-previous deltas; the only defect was routing the question to
  navigation and not explaining the values in the UI.
- *"Dashboaard" is a hardcoded typo.* Rejected — it exists nowhere in source; it
  is a provider hallucination produced because "answer me" escaped the
  deterministic layer.
- *Default language should be Azerbaijani.* Rejected — `language_runtime`
  already documents English-first (`DEFAULT_LANGUAGE = "en"`); the `else:"az"`
  service defaults contradicted it and caused the leak.

## Chosen fix plan

1. **Scan progress (`jobs.py`, `frontend/app.js`).** Add a collection heartbeat
   that nudges progress 7→14 during collection and enforces a configurable
   wall-clock deadline that flips a hung job to `failed`. Harden `pollScan` with
   bounded retry so a transient poll error does not abandon a live scan.
2. **`pdf` format vs `.pdf` extension (`file_queries.py`).** Treat a
   format-ambiguous token ("pdf") as an extension only when written dotted
   (".pdf") or immediately followed by a file noun ("pdf files"); otherwise it
   is an output format and the file route defers to the report route. Add
   superlative listing cues (`most`, `what are`) so evidence critical-file
   questions are answered from scan data.
3. **Cross-message report scope (`conversation_repair.py`, `service.py`).**
   Add a `last_reportable_scope` frame written after every scoped evidence /
   report turn, and make `resolve_report_scope` inherit it for bare/anaphoric
   report requests.
4. **Dashboard delta (`product_help.py`, `service.py`, `frontend/app.js`).**
   Guard the navigation branch against why/evidence questions; add a
   deterministic `risk_summary_delta_explanation` route + renderer; add a
   user-facing tooltip to the dashboard delta values.
5. **Language (`language.py`, `conversation_repair.py`, `service.py`).** Make
   universal tokens language-neutral so a bare "pdf" inherits the session
   language; make Azerbaijani explicit and English the default in the artifact
   renderers; change the `else:"az"` service defaults to `"en"`; give the P0/P1
   scoped-finding renderers a real English branch.
6. **Corrections (`correction_detection.py`, `conversation_repair.py`).** Add
   "not what i asked" to the wrong-route terms and emphatic negation to the
   severity-subset correction cues.

All changes are deterministic, local-only, add no dependencies, and preserve
tenant isolation, auth, signed-artifact download, secret masking, and
provider-final blocking for DSPM facts.
