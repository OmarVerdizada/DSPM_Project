# SENTRO metric definitions

SENTRO global metrics are database aggregations. A browser page, preview window, or API result length is never a global count.

## Inventory metrics

- `total_files`: unique current rows in the normalized `assets` estate. A file mapped to several frameworks is still one file.
- `sensitive_files`: unique current files with at least one finding.
- `frameworks[].file_count`: unique current files mapped to that framework. Framework counts are not additive because one file may map to several frameworks.
- `frameworks[].severity_file_counts`: those same unique framework files grouped by the file's effective severity.
- `finding_types[].file_count`: unique current files carrying that data/finding type; Dashboard Data Classes uses this value rather than occurrence volume from a report preview.
- `risk_counts`: unique current files grouped by effective file severity.

Dashboard Compliance Frameworks and Data Inventory framework filters both consume `GET /api/inventory/facets`. A compact report's `latestFiles` array may contain only the top-risk 200-file preview and is never used for global framework totals.

## Finding metrics

- A finding is one detector/data-risk record associated with a file. One file can have many findings.
- An occurrence is one or more appearances represented by a finding's `occurrence_count`. Multiple occurrences do not create extra files or findings.
- `total_findings`: exact finding-row count for the requested scope.
- `total_occurrences`: sum of `occurrence_count` for those findings.
- `findings_by_framework`: finding and occurrence counts per framework. A multi-framework finding contributes once to each mapped framework but remains one finding overall.

## Finding scope

- `current` (default): findings present on each asset's latest authoritative observation. A complete newer named scan retires unseen assets and their findings from current scope. A finding absent from a newly observed file is also retired.
- `historical`: findings no longer present in current scope.
- `all`: current and historical finding rows.

Historical rows remain available for investigation but are read-only in the Remediation Center. Workflow actions operate on current findings.

## Remediation lifecycle groups

The backend helper `REMEDIATION_STATUS_GROUPS` is authoritative:

- Open: `NEW`, `OPEN`, `UNDER_REVIEW`, `CONFIRMED`, `REOPENED`
- In progress: `ASSIGNED`, `IN_PROGRESS`
- Validation: `PENDING_VALIDATION`
- Resolved: `RESOLVED`
- Exceptions: `RISK_ACCEPTED`, `SUPPRESSED`, `FALSE_POSITIVE`

`active_findings` is Open + In progress + Validation. `affected_files` is the number of distinct files among active findings. `overdue` is the number of active findings whose non-empty SLA due timestamp is in the past.

The Remediation summary is unfiltered within the selected current/historical/all scope. The queue's `total` is the exact number matching its server-side search, filter, and status query. `items.length` is only the current bounded page and must never be displayed as either total.

## Report metrics

Saved report counts are scan-scoped snapshots. They may legitimately differ from current estate metrics when the report is older, explicitly scoped, or compact/windowed. Current Dashboard and Data Inventory cards use inventory facets; current Remediation cards use remediation summary metrics.
