# GDPR and PCI DSS Remediation Priorities

This project should prioritize correctness and evidence safety before adding more keyword coverage or UI cards. The keyword library is already broad; trustworthy findings depend on validated entities, secure evidence, correlation, workflow, and framework-specific reporting.

## Phase 1 - Security and Correctness Blockers

Status in this branch:

- Full PAN protection-state validation: implemented and regression-tested.
- Bare PAN detection: implemented and regression-tested.
- Confidence vs severity separation: implemented in finding and risk metadata.
- CVV and service-code length validation: implemented and regression-tested.
- PAN-SAD correlation scoped to record/proximity evidence: implemented and regression-tested.
- Tenant HMAC evidence fingerprints: implemented for PCI, GDPR, and canonical entities.
- Raw SAD secure serialization/redaction: implemented for findings and previews.
- Generic scan remains active when compliance is selected: implemented in discovery flow.
- GDPR occurrence and unique-value counts: implemented and regression-tested.
- Full-file chunked local text scan: implemented with a 100 MB default budget and partial metadata beyond that budget.

## Phase 2 - Data Model and Workflow

Status in this branch:

- Canonical finding, occurrence, and entity model: implemented.
- Finding lifecycle APIs and persistence through scan reports/history: implemented.
- Status, owner, SLA, assignment, comments, suppression, false-positive, risk acceptance, resolve, reopen, validate: implemented.
- Risk acceptance requires justification, approver, expiration, compensating controls, affected assets, accepted volume, and review date.
- Parent/child display state is available to UI and tested for PCI hierarchy behavior.

Remaining enterprise hardening:

- Dedicated normalized findings database tables rather than report-derived persistence.
- Structured parsers for CSV, JSON, XML, XLSX, PDFs, and databases with first-class location rows.

## Phase 3 - Compliance Correctness

Status in this branch:

- Corporate confidential data is no longer automatically treated as GDPR personal data.
- GDPR metadata includes personal-data type, special category, Article 10, legal mappings, retention, transfer, DPIA, and review fields.
- PCI DSS requirement mappings are versioned through a catalog model.
- Authorization lifecycle and SAD exception states are explicit review states rather than inferred from labels alone.
- PCI protection assurance distinguishes claimed protection from verified state.

Remaining enterprise hardening:

- Retention and exposure control findings should become separate generated findings with their own lifecycle.
- More official source-backed PCI and GDPR catalog entries should be added as rule catalogs mature.

## Phase 4 - UI and Reporting

Status in this branch:

- PCI scope summary and GDPR privacy posture reporting are exposed in report data and UI panels.
- Findings UI uses backend taxonomy fields rather than frontend regex classification.
- Detail drawer surfaces PCI/GDPR metadata, hierarchy, evidence sections, confidence, protection, and workflow fields.

Remaining enterprise hardening:

- Trend and SLA reporting.
- Framework-specific export formats.
- Dedicated occurrence viewer optimized for very large occurrence sets.

## Phase 5 - Enterprise Scale

Status in this branch:

- Incremental scan/cache keys include tenant, file hash, detector version, and rule catalog version.
- Detector metrics and timeout metadata are exposed for GDPR scans.
- Keyword catalog corruption handling and import limits are implemented.

Remaining enterprise hardening:

- Aho-Corasick or trie keyword matcher for all large keyword catalogs.
- Distributed database-backed rule catalog with rollback and multi-node concurrency guarantees.
- Performance budgets and observability dashboards.
