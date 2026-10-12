# Report Export Upgrade v102

This update replaces the legacy Reporting Center export experience with an enterprise-style evidence pack.

## Changed files

- `frontend/index.html`
  - Updated report export button labels and description.
- `frontend/app.js`
  - Added an enterprise Reporting Center preview.
  - Rebuilt Word export as a board-ready executive brief.
  - Rebuilt PDF export as a print-safe report view with popup fallback.
  - Rebuilt Excel export as a multi-sheet Excel XML workbook.
  - Added export-safe helpers for filenames, status logic, XML escaping, evidence summaries, recommendation rows, and workbook rows.
- `frontend/styles.css`
  - Added Reporting Center enterprise preview styles, KPI cards, export pack cards, status cover variants, and responsive layout.

## Export outputs

- Word: `dspm-<tenant>-enterprise-report-<timestamp>-executive-brief.doc`
- Excel: `dspm-<tenant>-enterprise-report-<timestamp>-workbook.xls`
- PDF: opens a print-ready report page; if the browser blocks popups, downloads a PDF-ready HTML file instead.

## Excel workbook sheets

- Executive Summary
- Risk Register
- Departments
- Folders
- Signals
- Comparison

## Report sections

- Confidential DSPM cover
- Executive summary
- Risk posture score
- KPI matrix
- Executive insight cards
- Severity distribution
- Detection signals
- Remediation plan
- Department/folder concentration
- Scan comparison
- Priority file risk register

## Verification

- `node --check frontend/app.js` passes.
