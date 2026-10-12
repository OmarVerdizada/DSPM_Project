# DSPM Product Feature Status

## Implemented in this build

- JWT authentication with roles: `admin`, `analyst`, `viewer`.
- SQLite-backed tenant and user management with invitation-code registration, admin user creation, role updates, password reset, and login activity.
- Separate login and registration pages with tenant ID, registration code, and password confirmation.
- API key generation helper and API-key authentication through `X-API-Key`.
- Tenant-aware SQLite storage at `data/dspm.sqlite`, created automatically on first run.
- Hidden local and SMB files are included in discovery results and counted in scan summaries.
- AES-backed local credential vault using `cryptography.Fernet`.
- SMB credentials can be saved once and reused through `credential_ref`.
- Protected scan, connection-test, risk-rule, history, audit, and dashboard APIs.
- Async scan job API with queued/running/completed/failed/cancelled status.
- Scan history, trend data, executive risk posture score, and audit log.
- Enhanced scan analytics for risk trend, critical/high files, department risk, scan comparison, and top risky folders.
- Polished Excel, Word, and print/PDF exports with report-safe sizing, SVG charts, heatmap, trend visuals, and priority queues.
- Threshold alert generation with optional webhook via `DSPM_ALERT_WEBHOOK_URL`.
- Binary content extraction for DOCX, XLSX, PPTX, and lightweight PDF text streams.
- Optional spaCy NER adapter, off unless `DSPM_ML_NER_ENABLED=1` and the extra is installed; its
  output is LOW severity, LOW confidence, and excluded from posture. PHI, payroll, customer and
  repository context detection is done by the regex catalog and the GDPR/NIST context rules.
- Frontend sign-in, credential reference flow, async scan polling, and scan history view.
- Generic DLP policy JSON export endpoint.
- Scale features (Phase B), with no infrastructure beyond the database:
  - Partitioned, resumable scans (every local, SMB and endpoint scan since W4.6): a scan holds and writes one partition at a time and continues where it stopped after a restart. Scans running at once are admitted up to `DSPM_MAX_RUNNING_SCANS`, and a scan projected not to fit the disk is paused before it writes, with the numbers.
  - Multi-worker scanning: with `DSPM_SCAN_EXECUTION=queue`, `python main.py worker` processes take partitions straight from the database ledger; leases take back a dead worker's partition, and a queue that cannot be reached runs the scan in the backend instead.
  - Scheduled scans that run unattended, and retention that runs daily, each claimed once across backends.
  - Suppression rules: a finding dismissed as a false positive becomes a rule the next scan applies, and comes back when the rule is withdrawn.
  - Paged endpoint scans: 5 MB per file and 32 MB per command, analysed batch by batch.
  - One finding per value: a card found by several detectors is one finding carrying every framework tag.
  - Dashboard aggregates shared between backends and workers through the database (`derived_cache`), invalidated by every estate write; live scan progress on the job record.
  - `scripts/scale_gate.py`: the scale envelopes measured on every CI run and nightly.

## Production adapters still needed

- Replace local vault with HashiCorp Vault or AWS Secrets Manager.
- Add WebSocket/SSE progress streaming instead of polling.
- Add PostgreSQL + SQLAlchemy if tenant state must survive horizontal scaling.
- Add first-class SharePoint, OneDrive, S3, Azure Blob, and Google Drive collectors.
- Add real Jira/ServiceNow/PagerDuty/Teams/Slack integrations for remediation workflows.
- Add Kubernetes manifests, Helm chart, Prometheus metrics, and Grafana dashboards.
- Add downloadable SDKs and versioned public API docs.
