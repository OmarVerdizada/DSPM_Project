# DSPM DLP Discovery Console

Enterprise-focused Data Security Posture Management prototype for discovering sensitive data on file servers, scoring exposure, and preparing DLP-ready remediation actions.

The product is designed around an MSSP workflow: scan a customer environment, classify sensitive files, explain why each item is risky, generate DLP recommendations, track tenant posture, and export executive evidence.

## Highlights

- AD/SMB file-server discovery with local enterprise demo data fallback.
- Regex and heuristic classification for secrets, PCI, PII, finance, HR, legal, customer data, PHI context, source-code assets, passports, national IDs, IBAN, SWIFT/BIC, GitHub, Slack, Google, Azure, JWT, API keys, and private keys.
- 0-100 file risk scoring with LOW, MEDIUM, HIGH, and CRITICAL severity bands.
- Risk posture score that updates from the current scan and manual analyst overrides.
- Remediation workflow with ticket id, owner, SLA, status, and action list per risky file.
- MSSP multi-tenant mode with isolated history, audit, credentials, reports, and customer portfolio posture.
- Customer asset rules for tenant-specific crown-jewel paths, folders, extensions, and filenames.
- Executive dashboard with posture ring, risk distribution, folder heatmap, signal mix, posture trend, topology, MSSP portfolio, and remediation queue.
- Right-side detail drawers for long risk reasons and DLP recommendations.
- Report center with Excel, Word, and print/PDF exports.
- Security operations view with API keys, audit trail, DLP policy export, and credential vault support.

## Screens

- `Overview`: scan results, findings, manual risk override, reasons, DLP actions.
- `Executive`: CISO/MSSP posture, customer portfolio, trend, remediation queue, heatmap, topology.
- `Customer Assets`: tenant-specific business context and forced-risk rules.
- `Reports`: customer-ready evidence exports.
- `History`: tenant scan history and posture score.
- `Security`: API keys, audit, DLP policy export.
- `Integrations`: connector and response workflow roadmap.
- `Risk Logic`: severity ranges, scoring formula, detection signals, customer asset context.

## Quick Start

Install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Run the web app:

```powershell
python main.py serve --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000
```

Default local login:

```text
admin / admin123
```

For production-like use, set `DSPM_ADMIN_PASSWORD` before starting the app.

## Demo Data

If no SMB server is provided, the scanner uses `enterprise_test_data` by default. The folder is generated locally and ignored by git so realistic secret-like test data is not published to GitHub.

Generate a fresh enterprise-style sample file tree:

```powershell
python scripts/generate_enterprise_test_data.py --output enterprise_test_data --files-per-share 10
```

The generated dataset includes realistic departments, exports, contracts, HR data, finance data, source-code context, logs, archives, secrets, and regulated identifiers so the UI can be tested like an enterprise assessment.

The generated files intentionally contain secret-like patterns for classifier testing. Keep `enterprise_test_data/` local and regenerate it when needed.

## CLI Scan

```powershell
python main.py scan --local-path enterprise_test_data --output report.json
```

The CLI writes a full JSON report with summary, file findings, permissions, risk reasons, DLP recommendations, and remediation actions.

## API Overview

Core endpoints:

- `POST /api/auth/login`
- `POST /api/test-connection`
- `POST /api/scan`
- `GET /api/scans/{job_id}`
- `GET /api/history`
- `GET /api/executive-dashboard`
- `GET /api/tenants`
- `GET /api/risk-rules`
- `GET /api/audit`
- `POST /api/dlp-policy`
- `POST /api/api-keys`
- `POST /api/credentials`

Tenant isolation is controlled with the authenticated token and `X-Tenant-ID` header for admin/API-key workflows.

## Risk Model

Risk is calculated from multiple signals:

- Content findings: secrets, PII, PCI, PHI, financial identifiers, HR, legal, customer, and source-code context.
- Filename and path keywords: password, finance, payroll, customer, backup, database, contract, salary, legal, HR, VPN, and similar.
- File extensions: `.env`, `.pem`, `.key`, `.pfx`, `.bak`, `.sql`, `.db`, `.zip`, `.pst`, `.csv`, `.xlsx`, `.docx`, `.json`, and other leakage-prone formats.
- Permission posture: broad groups, writable access, and high blast-radius ACLs.
- Source exposure: SMB share exposure adds context.
- Customer asset overrides: MSSP analysts can force LOW, MEDIUM, HIGH, or CRITICAL based on customer-specific crown-jewel assets.

Severity bands:

- `0-39`: LOW
- `40-69`: MEDIUM
- `70-89`: HIGH
- `90-100`: CRITICAL

## Remediation Workflow

Each risky file receives remediation metadata:

- `ticket`: deterministic DSPM ticket id.
- `owner`: security owner, data owner, business owner, or IT operations.
- `SLA`: 24 hours, 3 business days, 14 days, or 30 days based on severity.
- `status`: urgent, open, needs review, or monitor.
- `actions`: quarantine, rotate secrets, restrict sharing, apply labels, review ACLs, create DLP rules, or validate ownership.

## MSSP Mode

The app supports a managed-service workflow:

- Tenant-specific scan history and audit logs.
- Tenant-specific reports and latest assessment.
- Tenant-specific asset rules and manual risk overrides in the browser.
- Admin tenant switcher in the top bar.
- Executive MSSP customer portfolio cards for customer posture comparison.
- API-key support for tenant-scoped automation.

## Configuration

Useful environment variables:

- `DSPM_ADMIN_PASSWORD`: overrides the default local admin password.
- `DSPM_ENV`: shown in retention metadata.
- `DSPM_API_KEYS`: API-key hash mapping in `tenant_id:hash` format.
- `DSPM_WEBHOOK_URL`: optional alert webhook destination.

Local runtime data is written under `data/tenants/` and is ignored by git.

## Project Structure

```text
backend/          FastAPI app, auth, tenant store, jobs, alerts, vault
classification/   Regex and heuristic classifiers
collectors/        Local file scanner, SMB scanner, binary text extraction
discovery/         Scan orchestration and report building
frontend/          HTML, CSS, browser app
permissions/       ACL analysis
risk/              Risk scoring, risk rules, remediation model
scripts/           Report writer, logger, demo data generator
enterprise_test_data/  Local synthetic sample data generated on demand
```

## Roadmap

- Microsoft Purview DLP export.
- Jira, ServiceNow, Slack, and Teams remediation integrations.
- SharePoint, OneDrive, Google Drive, S3, Azure Blob, SQL Server, and PostgreSQL connectors.
- Persisted remediation state with assignment and closure workflow.
- Fine-grained RBAC for MSSP analysts and customer viewers.
- Scheduled scans and posture drift alerts.
- Docker packaging and production deployment profile.

## Status

This is a prototype/MVP intended for enterprise DSPM and DLP readiness testing. It is suitable for demos, local pilots, and product development, but should be hardened before production deployment.
