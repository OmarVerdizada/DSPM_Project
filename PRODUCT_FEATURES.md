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
- ML detection adapter: spaCy NER if installed, heuristic PHI/finance context otherwise.
- Frontend sign-in, credential reference flow, async scan polling, and scan history view.
- Generic DLP policy JSON export endpoint.

## Production adapters still needed

- Replace local vault with HashiCorp Vault or AWS Secrets Manager.
- Replace in-process scan queue with Celery + Redis for multi-worker deployments.
- Add WebSocket/SSE progress streaming instead of polling.
- Add PostgreSQL + SQLAlchemy if tenant state must survive horizontal scaling.
- Add first-class SharePoint, OneDrive, S3, Azure Blob, and Google Drive collectors.
- Add real Jira/ServiceNow/PagerDuty/Teams/Slack integrations for remediation workflows.
- Add Kubernetes manifests, Helm chart, Prometheus metrics, and Grafana dashboards.
- Add downloadable SDKs and versioned public API docs.
