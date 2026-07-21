# SENTRO DSPM PDF Report Template Unification

## Root cause

The two report flows did not share a renderer. The dashboard's **Open PDF Composer** action generated a large HTML document inside `frontend/app.js` and relied on browser printing, while Copilot artifacts used `backend/copilot/report_model.py`, an HTML companion in `backend/copilot/artifacts.py`, and a separate dependency-free PDF renderer in `backend/copilot/report_pdf.py`. The dashboard and stored PDF therefore had independent layout and color rules. Both also retained older teal styling that did not match SENTRO's navy/blue/indigo product theme.

## Template sources found

- Dashboard PDF action: `exportPdf()` and the former PDF mode of the executive HTML builder in `frontend/app.js`.
- Dashboard Word export: the executive HTML builder in `frontend/app.js`; it is now explicitly Word-only and is not a PDF source.
- Copilot report model and scope normalization: `backend/copilot/report_model.py`.
- Copilot artifact creation, tenant-scoped storage, signed URLs, and HTML companion: `backend/copilot/artifacts.py`.
- Copilot stored visual PDF: `backend/copilot/report_pdf.py`.
- Signed artifact serving: `backend/copilot/router.py` and `backend/security.py`.
- Existing focused coverage: `tests/test_copilot_visual_pdf_report.py`.

## Chosen shared template approach

The server-side visual renderer is now the single PDF source of truth, identified by the stable marker `sentro-dspm-unified-v1`.

Copilot continues to create reports through `create_report_artifact()`. The dashboard now calls the authenticated `POST /api/v1/copilot/reports` endpoint, which calls the same artifact creator with full-scan scope. It then opens the returned signed `preview_url`. The preview uses the same stored PDF as the download URL; `inline=1` changes only the response disposition so the browser PDF viewer can expose Print / Save PDF. The original signed attachment URL and authorization checks remain unchanged.

The HTML artifact remains an accessible companion representation, not a second PDF renderer. It carries the same template marker and SENTRO colors, but neither dashboard nor Copilot PDF output is built from it.

## Files changed

- `backend/copilot/report_pdf.py`
- `backend/copilot/artifacts.py`
- `backend/copilot/schemas.py`
- `backend/copilot/router.py`
- `frontend/app.js`
- `tests/test_copilot_visual_pdf_report.py`
- `tests/test_pdf_report_template_unification.py`
- `docs/pdf_report_template_unification_report.md`

## Dashboard PDF Composer result

- The existing **Open PDF Composer** action remains the single dashboard PDF action.
- It opens a popup synchronously, shows a branded preparation state, requests the shared report with the current scan ID, validates the shared template marker, and navigates to the signed inline PDF.
- Printing and saving use the browser PDF viewer against the exact same binary generated for Copilot.
- The former dashboard executive builder is Word-only; its old PDF path and PDF toolbar were removed so it cannot diverge into a second PDF template.
- No report action was duplicated.

## Copilot PDF result

- Copilot retains the existing artifact creation path, scoped report model, tenant/subject storage boundary, signed download token, filename behavior, and download URL.
- The stored PDF remains a structured multi-page visual report rather than plain text.
- Its sections include executive summary, risk posture, risk distribution, detection signals, remediation plan, scan comparison, priority file queue, and full evidence register.
- Artifact metadata now includes `template_id` and a signed inline `preview_url` in addition to the unchanged signed attachment URL.

## Theme and color result

The shared renderer now uses SENTRO-aligned tokens:

- Navy `#0B1739` for primary headers.
- Deep blue `#102A56` for structural accents.
- Blue `#2563EB`, indigo `#4F46E5`, and purple `#7C3AED` for cards, signals, and emphasis.
- White and very light blue/gray report surfaces for print readability.
- Harmonized severity colors remain distinct: strong red for CRITICAL, orange/red for HIGH, amber for MEDIUM, and green for LOW.

Renderer-operation previews of all four representative full-report pages showed consistent headers/footers, clean cards, readable bars, aligned remediation and comparison panels, and evidence rows contained within the landscape page.

## Scoped report result

The shared report model and renderer were not forked or duplicated. Existing scope normalization remains in place for:

- full scan;
- individual MEDIUM, HIGH, and CRITICAL severity scopes;
- combined CRITICAL + HIGH scope;
- a single selected finding.

Focused tests confirm full, MEDIUM-only, CRITICAL + HIGH, HIGH signed download, and single-finding behavior. Because all severity scopes use the same normalizer, CRITICAL-only and HIGH-only use the same covered severity path.

## Tests and checks run

- `python -m compileall backend` — passed.
- `python -m unittest discover tests` — passed: 244 tests, 1 skipped.
- `node --check frontend/copilot.js` — passed.
- `node --check frontend/app.js` — passed.
- Focused unification suite — passed: 9 tests before the final theme-command assertion update.
- Generated `tmp/pdfs/sentro-unified-full.pdf` — 4 pages, 16/16 evidence rows, not truncated.
- Generated `tmp/pdfs/sentro-unified-critical-high.pdf` — 3 pages, 2/2 scoped evidence rows, not truncated.
- Existing PDF geometry contract checked every rectangle and text origin against landscape page bounds.
- Theme contract checks the marker and confirms navy, blue, and indigo drawing commands are present in the PDF payload.
- Renderer-level page previews were inspected for all four pages with no observed clipping, overlap, broken table, or unreadable section.

The available headless browser could fetch the generated PDF but did not expose its PDF canvas to screenshots, and no native PDF rasterizer was installed. No dependency was added. Final browser PDF-viewer rendering therefore remains part of the manual verification below.

## Manual verification steps

1. Open dashboard Reports / PDF Composer.
2. Generate/print a full report.
3. Ask Copilot for a full PDF report.
4. Compare both: they must use the same layout and theme.
5. Ask Copilot for a MEDIUM-only report.
6. Ask Copilot for a CRITICAL + HIGH report.
7. Ask Copilot for a single-finding report.
8. Confirm colors match the SENTRO site style.
9. Confirm the report is visually structured and not plain text.
10. Confirm the signed download works and the dashboard preview can print/save.

Also confirm that the dashboard still presents only one PDF Composer action and that Word export remains available.

## Remaining risks

- A real browser PDF-viewer pass is still required because this environment had no independent PDF rasterizer and its headless PDF canvas was not screenshot-accessible. Renderer previews and strict geometry tests reduce, but do not completely eliminate, viewer-specific rendering risk.
- The dashboard endpoint intentionally creates full-scan reports only. Scoped report creation remains a Copilot flow, using the same renderer and model.
- The dependency-free PDF renderer uses built-in Helvetica fonts and transliterates unsupported characters, matching existing behavior; richer Unicode typography would require a font/embed change outside this task and would add packaging risk.
