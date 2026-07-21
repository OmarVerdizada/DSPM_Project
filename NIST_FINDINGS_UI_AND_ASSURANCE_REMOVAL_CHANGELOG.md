# NIST Findings UI And Assurance Removal Changelog

## Root Cause

- The finding type dropdown used the keyword-library group label as its primary text. For the NIST built-in catalog, that label came from generated catalog fields such as `Education Records Type 3` instead of a rule display contract.
- The backend display helper previously collapsed NIST rules to category-level labels or cleaned generated type names after the fact. That still left weak labels and duplicate names in the rule selector.
- Framework badges only read a narrow set of framework fields, so PCI primary findings with NIST mappings could lose the NIST badge in the card/popup.
- Assurance was added as an active backend/frontend metric in an earlier pass, creating API fields, dashboard widgets, filters, detail rows, and tests that the product no longer needs.

## Real Rule-Name Fix

- `get_finding_display_name()` now treats NIST as a first-class framework and refuses generated `Type N` labels as primary display names.
- Display priority remains metadata-first: Azerbaijani label, label, data type, service, official name, human-readable type, rule id, fallback.
- When the catalog only provides generated `Type N` labels, a category taxonomy derives a real enterprise data name from the rule ordinal, without creating an index label in the UI.
- `/api/nist/catalog` rule rows now expose `display_name`, `display_name_az`, `technical_type`, `rule_id`, category, severity, handling tier, and description for the dropdown.
- The frontend finding type selector reads `display_name` through `findingDisplayName()` and uses rule id/technical type only as metadata.
- The keyword-library selector was rebuilt to defend against stale or weak labels. If NIST group labels collapse to category names such as `Legal and Law Enforcement`, the frontend derives distinct names such as `Legal Matter Records`, `Contract Records`, `Law Enforcement Records`, and `Litigation Hold Records`.
- Category options are rebuilt from the actual option set, sorted by display label, and include rule counts so category and finding selectors stay aligned.

## Assurance Removal

- Removed active backend helper functions, aggregation, report summary fields, API enrichment, classifier output fields, canonical model output, frontend state, filters, widgets, detail rows, CSS, and old tests related to assurance.
- `protection_state`, `claimed_protection_state`, and `verified_protection_state` remain because they are concrete finding evidence fields, not an assurance score/status.
- Legacy stored rows that still contain the removed field are ignored by new API/detail/frontend paths. No destructive DB migration is required for the current JSON/report storage model.

## NIST Visual Identity

- Added stable NIST framework normalization for `nist`, `NIST`, `nist_sp800_60`, `nist_sp800_60_enterprise`, and `NIST SP 800-60 Enterprise`.
- Added NIST visual tokens and `framework-nist` styling for framework badges and chips.
- Multi-framework badge rendering now reads `frameworks`, `mapped_frameworks`, `framework_mappings`, and `requirement_mappings`, so PCI + NIST mappings show both badges.
- Framework badges are now scoped to the selected compliance frameworks. If only NIST is selected, stale GDPR mappings are not shown as active scan chips.
- Inventory rows no longer render separate compliance score chips; framework chips show only `GDPR`, `PCI DSS`, `NIST`, or `Standard scan`.
- Framework strip badges no longer include finding severity or score because risk is already shown in the row risk column.

## NIST Popup Detail Contract

NIST findings use the same generic renderer as standard scan, GDPR, and PCI DSS findings.
Inventory rows suppress NIST-only finding-name chips and keep the `NIST` framework pill, while the `+N` detail action opens the full finding evidence.
The popup does not add a synthetic NIST compliance mapping row or a NIST-only detail layout.

## Backend Metadata Pipeline

- NIST classifier output preserves rule id, framework, catalog metadata, source metadata, category, real display names, technical type, handling tier, risk scores, CIA impacts, detection evidence, mappings, governance, remediation, exact source location, counts, and structured `framework_metadata.nist`.
- Canonical finding enrichment keeps NIST framework id canonical as `nist_sp800_60_enterprise` and adds display names without dropping rule metadata.

## Regression Verification

- Focus tests: `8 passed`
- Full suite: `194 passed, 1 skipped`
- JavaScript syntax check: `node --check frontend/app.js` passed.
- Backend startup/import check: `python -c "import backend.app"` passed.
