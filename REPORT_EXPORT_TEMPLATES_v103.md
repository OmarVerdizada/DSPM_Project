# Report Export Templates v103

This upgrade replaces the old green/flat export output with product-level report templates aligned with the DSPM UI.

## What changed

### Reporting Center UI
- Button labels now match the real output:
  - `Export Excel Workbook`
  - `Export Word Pack`
  - `Open PDF Composer`
- The on-page report preview now has an expandable **Show full evidence register** drawer.
- The preview no longer uses hidden “additional files” messaging. All rows are available when the drawer is opened.

### PDF Composer
- PDF export now opens a composer instead of immediately forcing `window.print()`.
- Default PDF view is executive-only so the first pages stay clean and board-ready.
- User can click **Show full data register** before printing to include every file row in Appendix A.
- This is the best browser-compatible solution because final PDF files are static; the click action happens before printing/saving.

### Word Pack
- Word export includes:
  - cover
  - executive summary
  - KPI cards
  - risk distribution visuals
  - detection signals
  - department/folder risk
  - remediation plan
  - scan comparison
  - full evidence register appendix
- Word files are static, so the full appendix is included directly instead of relying on a button that Word may not preserve.

### Excel Workbook
- Excel export is structured as an audit-ready workbook-style `.xls` file with:
  - executive summary
  - full risk register
  - remediation plan
  - departments
  - folders
  - detection signals
  - scan comparison
- All rows are exported. No data is cut off.

## Changed files

- `frontend/index.html`
- `frontend/app.js`
- `frontend/styles.css`

## Implementation notes

The project currently exports from the frontend using HTML-based templates. This upgrade keeps that architecture to avoid backend dependencies, but improves layout, typography, colors, data density, and PDF/Word behavior.

If you later want true `.docx` and `.xlsx` generation, the next best step is adding backend endpoints using `python-docx`, `openpyxl`, and a PDF renderer such as Playwright/Chromium or WeasyPrint.
