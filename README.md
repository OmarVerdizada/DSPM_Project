# DSPM DLP Discovery Console

Enterprise-focused Data Security Posture Management prototype for discovering sensitive data on file servers, scoring exposure, and preparing DLP-ready remediation actions.

The product is designed around an MSSP workflow: scan a customer environment, classify sensitive files, explain why each item is risky, generate DLP recommendations, track tenant posture, and export executive evidence.

## Highlights

- AD/SMB file-server discovery with local enterprise demo data fallback.
- Hidden local and SMB file entries are included in scan scope and marked in scan metadata.
- Regex and heuristic classification for secrets, PCI, PII, finance, HR, legal, customer data, PHI context, source-code assets, passports, national IDs, IBAN, SWIFT/BIC, GitHub, Slack, Google, Azure, JWT, API keys, and private keys.
- 0-100 file risk scoring with LOW, MEDIUM, HIGH, and CRITICAL severity bands.
- Risk posture score that updates from the current scan and manual analyst overrides.
- Remediation workflow with ticket id, owner, SLA, status, and action list per risky file.
- MSSP multi-tenant mode with isolated history, audit, credentials, reports, and customer portfolio posture.
- Customer asset rules for tenant-specific crown-jewel paths, folders, extensions, and filenames.
- Executive dashboard with posture ring, risk distribution, folder heatmap, signal mix, posture trend, topology, MSSP portfolio, and remediation queue.
- Scan result analytics include risk trend, critical/high file queue, department risk, scan comparison, and top risky folders.
- Right-side detail drawers for long risk reasons and DLP recommendations.
- Dashboard tables keep long file paths visible instead of truncating them, and priority queues stay read-only so analysts can search or filter inventory deliberately.
- History and security audit views include working date-range filters for all scans, last 24 hours, last 5 days, last 7 days, last 30 days, and custom ranges.
- Report center with polished Excel, Word, and print/PDF exports, including KPI cards, SVG charts, department risk, folder heatmap, trend context, and priority file queues.
- Security operations view with API keys, audit trail, DLP policy export, and credential vault support.
- SQLite-backed tenant and user management with invitation-code registration, admin role management, password resets, and activity logging.
- Windows endpoint profile scanning over WinRM, including DSPM host preparation, target WinRM verification, credential vault handoff, and scoped profile scans.

## Screens

- `Overview`: scan results, findings, manual risk override, reasons, DLP actions.
- `Executive`: CISO/MSSP posture, customer portfolio, trend, remediation queue, heatmap, topology.
- `Customer Assets`: tenant-specific business context and forced-risk rules.
- `Reports`: customer-ready evidence exports.
- `History`: tenant scan history and posture score.
- `Tenants`: admin tenant creation, registration-code rotation/copy, full tenant offboarding, and tenant portfolio status.
- `Security`: user management, role management, password reset, API keys, audit, DLP policy export.
- `Integrations`: connector and response workflow roadmap.
- `Risk Logic`: severity ranges, scoring formula, detection signals, customer asset context.
- `Endpoint Scan`: prepares the management host when needed, verifies target workstation WinRM with the entered local-admin credential, and scans profile paths, one drive, or all fixed drives.

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

You can also create the same sample tree from the dashboard sidebar with the `Demo dataset` Generate button. It rebuilds the project-local folder and then keeps `Local sample path` pointed at the generated dataset for the next scan.

The generated dataset includes realistic departments, exports, contracts, HR data, finance data, source-code context, logs, archives, secrets, and regulated identifiers so the UI can be tested like an enterprise assessment.

The generated files intentionally contain secret-like patterns for classifier testing. Keep `enterprise_test_data/` local and regenerate it when needed.

## CLI Scan

```powershell
python main.py scan --local-path enterprise_test_data --output report.json
```

The CLI writes a full JSON report with summary, file findings, permissions, risk reasons, DLP recommendations, and remediation actions.

## File Server Scans

File-server scans use the credential entered in the sidebar only against the `File server / IP` target. For a domain account, enter the domain and username normally. For a server-local admin account, you can leave `Domain` as `WORKGROUP` or set it to the file server name; the scanner also tries the `SERVER\username` form automatically.

By default, hidden administrative shares are skipped. Enable `Scan admin disk shares like C$` only when you intentionally want to scan drive shares such as `C$` or `D$` with a local administrator credential on that file server. `ADMIN$`, `IPC$`, and `print$` are still skipped.

For VM testing:

```text
File server / IP: LAB-FILE01 or 192.0.2.20
Domain: WORKGROUP or LAB-FILE01
Username: svc_dspm_scan
Password: <file-server-local-admin-password>
Scan admin disk shares like C$: checked when testing C$ or D$
```

## Windows Endpoint Scans

Endpoint scans use WinRM to inspect selected paths on a target workstation. The credential entered in the target or endpoint form is used only against that target host, and it should be a local administrator on that workstation.

1. In `Management server WinRM`, prepare only the DSPM management host if it is not already ready.
2. In `Target machine WinRM`, enter the target IP, optional Windows profile user to scan, and a local-admin credential that is valid on the target workstation. The app first verifies existing WinRM; if it is already reachable, it skips WMI bootstrap.
3. In `Endpoint scan`, choose a focused path scope first, such as `Desktop only`, `Documents only`, or `OneDrive only`. Use `All profile`, `C drive`, or `All fixed drives` only after the connection is proven because these scopes can traverse large trees.

Example target preparation values:

```text
Target host / IP: LAB-WKS01 or 192.0.2.150
Target Windows user: test.user
Domain: EXAMPLE
Admin username: svc_dspm_scan
Admin password: <target-local-admin-password>
```

If WinRM is already enabled by Group Policy, `Prepare & Test target WinRM` should report that the existing connection is verified. If it reports WMI access denied, the target rejected remote WMI/DCOM changes for that credential; make sure the account or group is in the target workstation's local `Administrators` group, or fix this with GPO or a one-time local bootstrap on the target.

Scan notes:

- File-server extension, hidden, and system filters are narrowing filters. For example, `.pdf` plus `Hidden files` returns hidden PDFs, not every PDF plus every hidden file.
- File-server SMB scans can include admin disk shares (`C$`, `D$`) when `Include SMB admin shares` is selected and the credential has access.
- File-server scans enrich owner, principals, and permissions on a best-effort basis. If the backend host or credential cannot read ACLs, the scan continues with metadata and records ACL diagnostics.
- Async file-server scans save the full report, then reload it by `scan_id` so large results are not limited to the in-memory job preview.
- Local sample paths are project-local only. Use Endpoint custom paths for workstation folders outside the project.
- Cancelling a file-server async scan stops traversal cooperatively at the next share/folder/file step. Remote WinRM endpoint scans use a synchronous remote PowerShell command, so cancellation stops the DSPM job state immediately but cannot always interrupt an already-running remote command until the remote command returns.

### Group Policy For WinRM Targets

For domain workstations, prefer GPO over one-by-one WMI bootstrap:

- Enable `Computer Configuration > Policies > Administrative Templates > Windows Components > Windows Remote Management (WinRM) > WinRM Service > Allow remote server management through WinRM`.
- Set both IPv4 and IPv6 filters to `*` unless your environment requires a narrower range.
- Add inbound firewall rules for TCP `5985` on the Domain profile.
- Enable predefined inbound rules for `Windows Remote Management` and `Windows Management Instrumentation (WMI)`.
- Set the `Windows Remote Management (WS-Management)` service to Automatic, or create a GPO Preferences service item that starts `WinRM`.

After applying GPO, run this on the target or wait for policy refresh:

```powershell
gpupdate /force
```

Validate from the DSPM server:

```powershell
Test-NetConnection 192.0.2.150 -Port 5985
```

`TcpTestSucceeded : True` means the network path and WinRM listener are reachable.

## AD / Windows Environment Checklist

This project does not perform full AD inventory collection. It uses AD/Windows access to scan SMB file servers and WinRM-enabled Windows endpoints. Prepare the environment with least privilege:

- Domain service account: create a dedicated account such as `DOMAIN\svc_dspm_scan`. Do not make it a Domain Admin. For file-share scans, grant only the required share and NTFS permissions: `Read`, `List folder contents`, `Read attributes`, and `Read permissions`.
- File server local/admin account: local administrator rights are needed only when scanning hidden administrative disk shares such as `C$` or `D$`. Normal shared folders do not require local admin rights if the service account has read access.
- Endpoint local admin account/group: workstation scans require an account that is a local administrator on the target endpoint. A practical model is to create `GG_DSPM_Endpoint_Local_Admins`, add the scan account or a separate `svc_dspm_endpoint` account, and use GPO to place that group in local `Administrators` on scoped workstations.
- Credential separation: keep file-server read access and endpoint local-admin access separate when possible. Do not provide Domain Admin, Enterprise Admin, or domain-controller admin credentials to the tool.
- SMB/file-server connectivity: allow TCP `445` from the DSPM server to target file servers. DNS names or IP addresses must resolve from the `File server / IP` field.
- WinRM connectivity: allow TCP `5985` for HTTP WinRM endpoint scans. If SSL WinRM is used, allow TCP `5986`.
- WinRM GPO: enable `Allow remote server management through WinRM`, set appropriate IPv4/IPv6 filters (`*` is acceptable for lab use), and keep the `WinRM` service Automatic/Running.
- Firewall GPO: enable inbound rules for `Windows Remote Management`, `Windows Management Instrumentation (WMI)`, and TCP `5985` on the Domain profile. WMI/DCOM must also be reachable if one-time remote bootstrap is used.
- Remote UAC/local admin: if local administrator credentials are used remotely, `LocalAccountTokenFilterPolicy=1` may be required. Prefer setting this through a scoped GPO.
- ACL risk analysis: the project reads principals such as `Everyone`, `Domain Users`, `Authenticated Users`, `Users`, `Guest`, `Administrators`, `Domain Admins`, and `Enterprise Admins` to score broad, writable, and privileged access. The scan account must be able to run `Get-Acl` against scanned paths.
- GPO targeting: link these policies only to test, workstation, or file-server OUs that are in scan scope instead of the entire domain.
- Validation order: first run `Test-NetConnection <host> -Port 445` for file servers and `Test-NetConnection <host> -Port 5985` for endpoints, then use `Test connection` and `Prepare & Test target WinRM` in the UI.

## API Overview

Core endpoints:

- `POST /api/auth/login`
- `POST /api/auth/register`
- `POST /api/auth/change-password`
- `GET /api/users`
- `POST /api/users`
- `PUT /api/users/{username}/role`
- `POST /api/users/{username}/reset-password`
- `GET /api/users/activity`
- `POST /api/tenants`
- `DELETE /api/tenants/{tenant_id}`
- `POST /api/test-connection`
- `POST /api/demo-data/generate`
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
- `POST /api/endpoint/activate-local-winrm`
- `POST /api/endpoint/repair-winrm`
- `POST /api/endpoint/test-connection`
- `POST /api/endpoint/scan`

Tenant isolation is controlled with the authenticated token and `X-Tenant-ID` header for admin/API-key workflows.

Self-registration does not expose a public tenant directory. Tenant registration codes are generated by the backend and shown only to admins in the `Tenants` screen. Users need both their tenant ID and that tenant's registration code to create a viewer account.

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

- `DSPM_ADMIN_PASSWORD`: required in production and overrides the local development admin password. Set `DSPM_SECRET_KEY` and `DSPM_VAULT_KEY` in production as well.
- `DSPM_DB_PATH`: optional custom SQLite database path. Defaults to `data/dspm.sqlite`.
- `DSPM_ENV`: shown in retention metadata.
- `DSPM_API_KEYS`: API-key hash mapping in `tenant_id:hash` format.
- `DSPM_WEBHOOK_URL`: optional alert webhook destination.

Local runtime data is stored in SQLite at `data/dspm.sqlite` and is ignored by git. The database and schema are created automatically on first run after `git clone` or `git pull`, so no machine-specific path changes are required.

## Dependencies

Install Python dependencies from `requirements.txt`. SQLite does not need a separate package because the app uses Python's built-in `sqlite3` module. The frontend is static HTML/CSS/JavaScript served by FastAPI, so no Node.js or npm install is required.

WinRM endpoint scanning requires the existing `pywinrm` dependency from `requirements.txt`. No extra package is needed for the GPO-based target preparation flow.

Optional tooling:

- Git is required only for committing and pushing changes to GitHub.
- Browser print/PDF exports look best when print background graphics are enabled.

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
