# DSPM DLP Discovery Console

Enterprise-focused Data Security Posture Management prototype for discovering sensitive data on file servers, scoring exposure, and preparing DLP-ready remediation actions.

The product is designed around an MSSP workflow: scan a customer environment, classify sensitive files, explain why each item is risky, generate DLP recommendations, track tenant posture, and export executive evidence.

## Highlights

- AD/SMB file-server discovery with local enterprise demo data fallback.
- Tenant-scoped incremental scanning across local, SMB, and WinRM sources: unchanged objects
  reuse durable findings without content reads, while an explicit full-scan control remains
  available for periodic verification.
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
- Dashboard tables keep long file paths visible instead of truncating them, and priority queues stay read-only so analysts can search or filter inventory deliberately. The Data Inventory table consumes the cursor-paginated `/api/inventory` endpoint in a bounded 100-row page window, caches at most three pages, and refetches evicted pages by cursor instead of growing the DOM indefinitely. Saved-scan restore and scan-completion responses are metadata-only in the console; filter facets come from `/api/inventory/facets`, and full evidence for one row is fetched from `/api/inventory/{asset_id}` only when its detail drawer is opened. Filtered CSV and NDJSON actions stream the normalized inventory directly to disk without constructing a browser Blob.
- History and security audit views include working date-range filters for all scans, last 24 hours, last 5 days, last 7 days, last 30 days, and custom ranges.
- Report center with Word (.docx), Excel (.xlsx) and PDF reports built on the server, including KPI cards, department risk, folder heatmap, trend context, and priority file queues. Every export passes one masking step (a card number or IBAN that arrives as a file name is masked too). Workbook cells never run as formulas. The PDF embeds a Unicode font, so Azerbaijani, Russian and Greek file names print as themselves.
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
- `Risk Logic`: severity ranges, scoring formula, detection signals, customer asset context.
- `Endpoint Scan`: prepares the management host when needed, verifies target workstation WinRM with the entered local-admin credential, and scans profile paths, one drive, or all fixed drives.

## Roles and permissions

Every API route names the permission it needs (`backend/permissions.py`; the full route matrix is `tests/test_route_permissions.py`), and a role is a set of permissions:

| Role | May |
|---|---|
| `viewer` | read dashboards, the inventory and findings |
| `auditor` | what a viewer may, plus read the audit trail and file reports |
| `scan_operator` | read, plus configure, schedule and run scans (and vault the credentials a scan uses) |
| `analyst` | read evidence, triage findings, manage rules, scan, export and file reports |
| `admin` | everything in its tenant, including users, roles, invites and API keys |

Operating the installation itself (tenants, legal holds, the shared NIST catalogue, install-wide settings such as OCR, and database diagnostics) belongs to the built-in `admin` account of the `default` tenant, and no role grants it.

A tenant administrator can also define **custom roles** (Security ops, or `POST/PUT/DELETE /api/roles`): a name and any set of the permissions above except the installation's. A custom role belongs to its tenant, and one still held by a user, an API key or an open invite cannot be deleted. Invites and API keys may carry any role that does not administer the tenant. `GET /api/roles` lists the roles and what each allows; sign-in, session renewal and `GET /api/profile` return the caller's `permissions`, which the console uses to decide what to show.

**Who can read the sensitive files** (`inventory.view`): every scan keeps each file's access-control entries - allow and deny, with SIDs - and the effective access of every principal: its allow entries less its denies of the same right. `GET /api/access/principals` lists the principals with how many files each can read and write and how many of those hold findings (`kind=broad|privileged|service` narrows it); `GET /api/access/files?key=<principal key>` lists the files a principal can read (or `writable_only=true`), riskiest first, and `?kind=broad` the files every-user groups can read. Broad groups (Everyone, Authenticated Users, Domain Users, Users, Guests…) are recognised by well-known SID or exact name; service and indexer accounts (NT SERVICE, IIS, NETWORK/LOCAL SERVICE, and any account in `DSPM_INDEXER_PRINCIPALS`) are flagged. "Writable" exposure means a broad group can write. Local scans read each file's ACL in-process (`DSPM_LOCAL_ACL=0` turns it off); group nesting is not resolved.

**Revealing a value** (`evidence.reveal`, held by tenant administrators and granted to anyone else only through a custom role; it needs a session verified with two-step sign-in, so no API key can hold it): a scan keeps only a masked sample and a keyed fingerprint of each value. **Reveal** beside a sample on a finding asks for a reason, then the server reads the file again from where the scan found it - the server's own disk, or the SMB share with the saved credential the scan used - checks it is the same file (whole-file SHA-256 and size), runs detection again, and returns only the value whose fingerprint was chosen. A changed or missing file reveals nothing; a scan run with a password typed at scan time kept no credential, so its files cannot be revealed (scan with a saved credential); endpoint scans are not revealable yet. Every attempt, revealed or refused, is in the audit trail with who, what file, the reason and the result - never the value - and an account may reveal `DSPM_REVEAL_MAX_PER_HOUR` (20) values an hour. The console shows the value in its dialog only, for a minute.

**Evidence** - file previews and the matched values behind a finding - is returned only to a role with `evidence.view`. Everyone else sees the same findings, counts, locations and risk, with the evidence left out and the response marked `evidence_hidden`.

## Sign-in: workspaces, two-step sign-in and the directory

**Workspaces.** A sign-in name is unique within its workspace (tenant), so two workspaces can each have an `alice`. The sign-in page has an optional **Workspace** field; with it, the name is looked up in that workspace only. Without it, the name is read as the account key, so every account created before this change signs in exactly as before. Where a name is taken elsewhere, the new account's key becomes `name@workspace`; the person still types `name`. Registering a name another workspace uses neither fails nor says the other exists.

**Two-step sign-in (TOTP).** Administrators (`tenant.admin`, and the installation's administrator) set up an authenticator app at their first sign-in and give a code at every sign-in after; no session exists until they do. Anyone who stores scan credentials (`credential.manage`, or vaulting a password for a scan) is asked for a code once per session, and sets up an authenticator the first time from **Settings → Security → Two-step sign-in**. Codes are RFC 6238 (30 seconds, 6 digits, one step of clock skew), each accepted once. Ten single-use recovery codes are shown once at setup; only their hashes are kept, and the authenticator key is stored encrypted with the vault key. Wrong codes are limited per account (`DSPM_MFA_MAX_FAILURES`, 5 in 15 minutes). An API key cannot answer a code, so it cannot hold a permission that needs one. There is no SMS, e-mail or cloud service involved.

A person who lost their phone uses a recovery code, or a workspace administrator uses **Reset 2-step** on the user list (their sessions end; they set up again at the next sign-in). The installation's built-in administrator is reset only from the host:

```powershell
python main.py mfa reset admin
```

**Directory sign-in (Active Directory / LDAP).** A workspace administrator configures it in **Settings → Security → Directory sign-in**: the directory host over LDAPS or StartTLS (plain LDAP is refused), the system trust store or an uploaded CA certificate (always verified), the user search base, a read-only service account, and an ordered list of *group → role* mappings - a person gets the role of the first listed group they belong to, and someone in none of them cannot sign in. The service account's password is kept in the vault and never shown again: leave the field empty to keep it, type a new one to replace it, or use **Remove password**. **Test connection** signs the service account in and, given a name, says which role that person would get.

People sign in with their directory name and their workspace (with no workspace named, the `default` workspace's directory is asked). The first directory sign-in creates the account (it has no local password, so it can never be signed into with one). Groups are read again at session renewal once `DSPM_DIRECTORY_REVALIDATE_SECONDS` (900) have passed: a changed group changes the role, and a removed group, a disabled directory account or a vanished one ends every session of that account. If the directory cannot be reached, sign-in answers that it is unavailable and renewal is refused - it fails closed. Local accounts are never affected, so the local administrator can always sign in during an outage. Every directory sign-in, failure (with its reason), role change and settings change is in the audit trail; no password is.

## The credential vault's keys

Saved scan credentials, the directory's service account password and every MFA seed are sealed with the vault key; each sealed value names the key that sealed it. With `DSPM_VAULT_KEYRING` set (the Windows package sets it), the keys form a versioned ring:

```powershell
python main.py vault status                    # the active key, every key held, how many values each seals
python main.py vault rotate                    # a new key becomes active; everything is re-sealed with it
python main.py vault rotate --resume           # finish a rotation that was interrupted
python main.py vault rollback                  # the previous key becomes active again
python main.py vault escrow export --out D:\escrow\sentro-keys.json
python main.py vault escrow verify D:\escrow\sentro-keys.json
python main.py vault escrow recover D:\escrow\sentro-keys.json --out <DSPM_VAULT_KEYRING>
```

A rotation makes the new key active first, then re-seals every value in one database transaction; the ring keeps the old key, so a rotation that stops part-way never leaves a value unreadable, and `--resume` finishes it. The escrow is the whole ring encrypted with a key derived (scrypt) from a passphrase of at least 16 characters, asked for or read from `--passphrase-file` - never taken from the command line; keep it off the host, apart from the backups. `escrow verify` checks the escrow opens and holds every key a sealed value names - run it after every rotation. Every key operation is in the audit trail (key ids only, never a key).

**Settings -> Security -> Saved scan credentials** (credential managers) lists each saved credential's account, when it was saved, last used and last had its password changed, which key seals it, and a privilege check: members of Domain Admins and the other protected groups, accounts Active Directory marks `adminCount=1` (when directory sign-in is configured), and names like Administrator are flagged when the credential is saved and on request. Replace a password there (the reference stays, so scan profiles and schedules keep working) or delete the credential. A password older than `DSPM_CREDENTIAL_ROTATION_DAYS` (90) is marked due - a recommendation, not an enforcement.

## Quick Start

Install dependencies:

Requires Python 3.12 or newer (tested to 3.14).

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# For development and running the test suite:
pip install -r requirements.txt -r requirements-dev.txt
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

The built-in user is `admin`. There is no hardcoded default password. On first
start, set `DSPM_DEV_ADMIN_PASSWORD` to choose the local password, or leave it
unset and the app generates a strong one-time password and prints it to the
console:

```text
[dspm] No DSPM_ADMIN_PASSWORD or DSPM_DEV_ADMIN_PASSWORD is set. Generated a
one-time local admin password for 'admin': <shown once at startup>
```

For production, set `DSPM_ADMIN_PASSWORD` before starting the app (the server
refuses to start without it when `DSPM_ENV=production`).

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

## Audit trail

Every administrative and security-relevant action is written to a per-tenant audit trail, including sign-in attempts (recorded in the tenant the attempted name belongs to), report creation and download, full-report fetches, the DLP policy, and Word and Excel exports (recorded with their size and masked-value count, never their content). Blocked sign-in attempts are aggregated, one row per order of magnitude, so a brute force cannot flood the table.

Each tenant's rows form a hash chain. Check it at any time:

```powershell
python main.py audit verify            # every tenant; exits 1 and names the rows if a chain is broken
python main.py audit verify --tenant acme --json
```

A changed, deleted, inserted or reordered row, or cut-off newest rows, is reported. Rows written before the chain existed are sealed at upgrade, and verify says how far the seal reaches.

Anyone who can read a workspace's trail (`audit.view`) can run the same check for that workspace from the console - **Verify integrity** on the audit trail - or through `GET /api/audit/verify`. The check is recorded in the trail, and limited to `DSPM_AUDIT_VERIFY_MAX_PER_HOUR` (20) per workspace, since it reads the whole trail.

To forward the trail to a SIEM, the installation's administrator turns on **Settings → Features → SIEM Integration** and gives the receiver: host, port, TLS (recommended), TCP or UDP, CEF or JSON, and for TLS the system trust store or an uploaded private CA certificate - the certificate and its name are always verified. **Test connection** sends one test line without saving; the card shows whether the receiver is connected, when events were last delivered, how many wait, and the last error, and **Retry now** sends what is queued. Turning it off keeps the configuration; **Remove configuration** deletes it. Every change is in the audit trail, and turning forwarding off is sent to the SIEM before it stops. An install configured with `DSPM_SIEM_URL` before this is imported once. Events leave as CEF (or JSON) in RFC 5424 syslog, queued in the database with the audit row and retried with back-off while the SIEM is down; each carries its chain position, so the SIEM holds an independent copy of every chain. `GET /api/health` reports the backlog, and `python main.py audit forward` drains it on demand. Behind a reverse proxy, set `DSPM_TRUSTED_PROXIES` so audit rows and throttles record the client rather than the proxy.

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

**How sure a finding is.** Every finding states a confidence from 0 to 99 and its tier: CONFIRMED (an exact match, below), HIGH (85 and up), MEDIUM (60 and up) or LOW, with `confidence_basis` saying why. A GDPR finding's confidence comes from what its detector established: a secret assignment or a value with a checkable shape (an e-mail address, an IP, a FIN, a passport or national ID, a card or bank number) starts higher than a name, an address or a phone number, and those higher than a finding made only of context words; the rule's keywords in the file, three or more distinct values, and a country validator that passed raise it; a failed validator, a secret whose value is a reference rather than a literal (`password = os.environ[...]`), and a special category or HR record in a file that names no person lower it. A finding that states no confidence reads as 70 (MEDIUM) everywhere - the risk engine, the compliance views and the canonical model read it one way. What the tiers are worth is measured on a labelled corpus (`tests/gdpr_corpus.py`, `python scripts/gdpr_confidence_eval.py`) and recorded in `docs/evidence/d2-gdpr-confidence-2026-09-29.json`: looking at MEDIUM and above removes 14 of 31 false positives and loses one true positive; HIGH and above is 80% precise.

**Exact-data matching** (`rules.manage`; uploading needs a session verified with two-step sign-in): a workspace can upload an approved reference set - its customers' e-mail addresses, its employees' national IDs - with `POST /api/exact-match/sets` (`name`, `entity_type` of `EMAIL_ADDRESS`, `PHONE_NUMBER`, `GOVERNMENT_ID`, `PASSPORT_NUMBER` or `PERSON_NAME`, and up to 50,000 `values`). From the next scan, a GDPR finding whose value is in a set is CONFIRMED and names the sets it matched. The values are normalised (an e-mail's case, a phone's or an ID's punctuation and spacing), fingerprinted with an HMAC keyed by the installation's evidence key and the workspace, and dropped: no value, and no unkeyed hash of one, is stored, returned, logged or audited, and the fingerprints a scan matches with never reach a report or the estate. `GET /api/exact-match/sets` lists names, types and sizes (a set built with a different evidence key matches nothing and is shown as not `current`); `DELETE /api/exact-match/sets/{id}` removes one. A workspace holds at most `DSPM_EDM_MAX_ROWS` (250,000) reference values.

Until this release the detectors keyed every value fingerprint with the `default` workspace whatever workspace scanned, because the scan's workspace was never passed to them. They are keyed with the scanning workspace now. In a workspace other than `default`, a suppression rule written for one value (`fingerprint`) before the upgrade was keyed the old way and no longer matches: write it again from the finding.

## Database column sampling

`POST /api/database/scan` (`scan.run`) reads a database's text columns and reports the ones holding sensitive data, each column a record (`postgresql://db01:5432/crm/public.customers/email`). It reads a **bounded sample**: at most `sample_rows` rows a table (default 1,000, at most 10,000), `max_tables` tables, 200 text columns a table and 256 characters a value, under a statement timeout; the table's row count is exact (or the planner's estimate when counting ran out of time, and it says so), and every column carries `database.table_rows`, `table_rows_exact`, `sampled_rows` and `sample_limit`. `schemas` and `include_tables` (`schema.table` patterns) narrow what is read. The session is read-only, connects to the address the workspace's scan targets allow (pinned), and in production must verify TLS (`sslmode` `verify-full` or `verify-ca`). The password is typed for the scan or taken from a saved credential (`credential_ref`); findings carry masked samples only, a column has no preview, and nothing sampled is logged or exported. PostgreSQL is supported; MySQL and SQL Server need their drivers (PyMySQL, pyodbc), which are not installed with the product.

## Alerts, webhooks, e-mail and tickets

A scan that finds critical exposure raises an **alert**. Alerts are listed under **Evidence → Alerts** (`GET /api/alerts`, `inventory.view`) with where each was delivered, and acknowledged there (`POST /api/alerts/{id}/acknowledge`, `findings.triage`). An alert is written to the audit trail when it is raised, so a configured SIEM receives it too (syslog, CEF or JSON - see *Audit trail*).

Each workspace's administrator (`tenant.admin`; changes need a session verified with two-step sign-in) sets where alerts go in **Account → Settings → Features → Alerts & tickets** (`GET/PUT/DELETE /api/integrations/{webhook|email|jira|servicenow}`, `.../enabled`, `.../test`, `.../retry`):

- **Webhook** - an HTTPS POST of the alert as JSON, signed: `X-Sentro-Signature: t=<unix time>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>`, with `X-Sentro-Event` and `X-Sentro-Delivery`. Sentro makes the signing secret and shows it once, when it is made or rotated; a receiver recomputes the HMAC and refuses a timestamp more than five minutes old (`backend.alert_delivery.verify_signature` is that check).
- **E-mail** - a plain-text message through the workspace's relay, over STARTTLS or TLS (verified); a relay without TLS may be used only without a password.
- **Jira** (REST API v2: Cloud with an account e-mail and API token, Data Center with a personal access token) and **ServiceNow** (the incident table) - **Send to Jira/ServiceNow** on a finding (`POST /api/findings/{id}/ticket`, `findings.triage`) creates a ticket; Sentro asks every `DSPM_TICKET_SYNC_SECONDS` (300) whether it is done, and when it is closed there the finding is resolved here, recorded as the ticket's doing (`POST /api/tickets/sync` asks now).

Delivery is a queue: an alert is queued for each channel in the transaction that records it, and a deliverer sends what is due every `DSPM_ALERT_DELIVERY_INTERVAL_SECONDS` (5). A receiver that is down or refuses leaves the alert queued, retried with a back-off that grows to five minutes, and it is marked delivered only when the receiver accepted it (a 2xx answer; a relay that took the message). A ticket is created the same way, and creating it twice is prevented by Sentro's reference on it (a Jira label, a ServiceNow correlation id), looked up before a ticket is made. Turning a channel off or removing it cancels what was waiting for it. Every delivery, a delivery's first failure, every ticket created or closed, and every change, test and removal of a channel is in the audit trail - never a secret.

Every outbound call is checked: only `https://` is called; a name is resolved once and refused if it resolves to a loopback, link-local, multicast or cloud-metadata address, and the connection is made to the address that was checked; the certificate chain and name are always verified, against the system's trust store or a private CA uploaded with the channel; no redirect is followed. The secrets - the signing secret, the relay password, the Jira token, the ServiceNow password - are sealed in the vault and never returned: the settings say only that one is set. A secret left out of a save is kept, a new one replaces it, **Remove saved ...** deletes it, and a mask is refused as a value. `DSPM_ALERT_WEBHOOK_URL`, the old unsigned webhook, is imported once into the `default` workspace as a signed webhook (an `https://` address only); make a new signing secret in the console to give it to the receiver.

## Licence and signed updates

Both are signed by the publisher with an Ed25519 key kept offline (`scripts/sentro_sign.py`), and an install trusts only the publisher keys in its trust file (`DSPM_TRUST_FILE`; the Windows installer pins the key at the first install from `-PublisherKeyFile`, or from the package with `-TrustPackagePublisher` after comparing fingerprints). A key the package itself carries is never trusted for being there. Verification is plain Python (`backend/signing.py`, RFC 8032, checked against `cryptography`), so the installer can run it before anything is installed.

- **Update packages**: `SIGNATURE.json` signs what the package is (label, commit, build time, schema revision) and the digest of `SHA256SUMS`. An upgrade is checked by the **installed** release's verifier against the pinned key before anything is placed: a changed or added file, rewritten checksums, an edited manifest, another publisher's signature or an unsigned package (without `-AllowUnsigned`) is refused, and so is an **older** build unless `-AllowDowngrade` (or `-RestoreBackup`) says so. `python main.py package verify --package <folder>` runs the same check from an installed release.
- **Licence**: a signed file with the customer, validity dates and features, installed by the installation's administrator in Settings -> Features -> Licence (`PUT /api/licence`, `platform.admin` with two-step sign-in) or on the host with `python main.py licence install <file>` - the offline recovery path. An altered, untrusted, not-yet-valid or expired licence is refused and the installed one stays. With `DSPM_LICENCE_REQUIRED=1`, a missing or run-out licence stops **new scans only** (402, with how to recover), after `DSPM_LICENCE_GRACE_DAYS` (14) for an expired one; everything already found stays readable. See docs/DEPLOYMENT_WINDOWS.md.

## Monitoring

`GET /metrics` answers in the Prometheus text format - the backend's readiness, requests by method and status, scan jobs and partitions by state and the age of the oldest queued, the SIEM outbox, waiting alert deliveries and tickets, backup age and the last backup attempt, the licence, and whether each collector answered. A scraper sends `Authorization: Bearer <DSPM_METRICS_TOKEN>` (use `DSPM_METRICS_TOKEN_FILE`); without a token only the installation's administrator can read it. The metrics count the installation as a whole: no workspace, path, value or secret is in them. `deploy/monitoring/` holds a scrape configuration, alert rules (backend down or not ready, queue stuck or backed up, backup failed or stale, SIEM or alert channel failing, licence, a failing collector) and a Fluent Bit example for shipping logs written as JSON lines (`DSPM_LOG_FORMAT=json`, redacted like the text format).

The installation also alerts on itself: every `DSPM_OPS_ALERT_INTERVAL_SECONDS` (300) it checks for a scan queued longer than `DSPM_QUEUE_STUCK_MINUTES` (30), a failed last backup (`main.py backup create` records each attempt - the time and the error's type only), no backup newer than `DSPM_BACKUP_MAX_AGE_HOURS` (26) in production, and a SIEM refusing events for 15 minutes. Each condition raises one alert of the `default` workspace when it starts - delivered to its channels like any other - and is recorded as recovered when it clears. High availability (a second backend node, PostgreSQL failover and failback) is not covered yet.

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
- `DSPM_DB_URL`: optional PostgreSQL DSN. When set (e.g. `postgresql://sentro_app:…@host:5432/sentro_dev?sslmode=require`) the store runs on PostgreSQL instead of SQLite — see [PostgreSQL backend](#postgresql-backend-optional) below. Empty by default (SQLite).
- `DSPM_INVENTORY_FROM_NORMALIZED`: indexed normalized inventory is enabled by default. A completeness/readiness gate automatically retains report-blob compatibility for migrated databases until `python scripts/backfill_normalized.py` succeeds; set this variable to `0` only as an explicit rollback. `DSPM_INVENTORY_COUNT_CACHE_SECONDS` (default `5`, `0` disables) reuses the same capped filtered total across cursor pages and is invalidated on scan saves/backfills. Once normalized reads are selected, operational query failures return retryable `503` responses instead of materializing report blobs.
- `DSPM_EXPORT_BATCH_SIZE`: normalized inventory rows per streaming CSV/NDJSON database batch, clamped to `10`-`5000` and defaulting to `1000`. Export is always keyset-paginated and intentionally returns `409` instead of using the unbounded report-blob fallback when the normalized mirror is incomplete. See [Streaming inventory exports](docs/inventory/STREAMING_EXPORTS.md).
- `DSPM_SEARCH_ENGINE`: `database` (default) or `meilisearch` for the optional S-F fuzzy/typo-tolerant inventory-search projection. `DSPM_SEARCH_READ_ENABLED=0` keeps reads on PostgreSQL/SQLite during backfill/shadow indexing; set it to `1` only after verifying the dedicated index. Search failures automatically fall back to the existing database path.
- `DSPM_ENV`: `local` (default) or `production`. Production enables fail-closed startup checks, disables the OpenAPI docs routes, blocks `--reload`, and scans nothing on the network until a workspace lists its scan targets (Security operations → Scan targets: networks and host names; anything else is refused before the scan connects and recorded in the audit trail — `DSPM_ALLOW_PRIVATE_TARGETS` is no longer read). It also serves only on loopback behind an HTTPS reverse proxy on the same host, and refuses to start with an unsafe network boundary: an empty or wildcard `DSPM_TRUSTED_HOSTS`, a wildcard, local or `http://` entry in `DSPM_CORS_ORIGINS`, a `0.0.0.0/0` `DSPM_TRUSTED_PROXIES`, or no trusted proxy for the loopback listener. See [deploy/reverse-proxy](deploy/reverse-proxy/README.md) for the Caddy and nginx configurations.
- `DSPM_API_KEYS`: API-key hash mapping in `tenant_id:hash` format.
- `DSPM_ALERT_WEBHOOK_URL`: optional alert webhook destination, POSTed on CRITICAL findings.

See [`.env.example`](.env.example) for the complete, code-verified list of all supported environment variables with defaults and production guidance. Note that the application does not auto-load `.env` files; export the values into the process environment.

The complete normalized-inventory deployment, cutover, rollback, index verification, 5M-row benchmark, optional-search, and export procedure is in [Track S operations](docs/inventory/TRACK_S_OPERATIONS.md).

Local runtime data is stored in SQLite at `data/dspm.sqlite` and is ignored by git. The database and schema are created automatically on first run after `git clone` or `git pull`, so no machine-specific path changes are required.

### PostgreSQL backend (optional)

The store (users and password hashes, API-key hashes, the encrypted credential vault, scan history, audit log, login-throttle and token-revocation state) defaults to SQLite. For a hardened, off-host, least-privilege deployment you can run it on **PostgreSQL** without any code change — set `DSPM_DB_URL` to a libpq DSN. The dialect seam lives in [`backend/db.py`](backend/db.py); SQLite remains byte-for-byte the default when `DSPM_DB_URL` is empty. PostgreSQL provisioning also installs `pg_trgm`; Track S-D uses its GIN index to accelerate literal substring searches across normalized inventory paths, names, owners, and finding metadata.

**One-command install (Windows).** `scripts/setup_postgres.ps1 install` stands up a persistent, auto-starting `SentroPostgres` Windows service (initialized with scram auth, bound to 127.0.0.1), provisions a least-privilege app role + database, initializes the schema, and writes the `DSPM_DB_URL` to an admin-only credentials file (`C:\SentroPostgres\credentials.env`). It is idempotent, and `uninstall` (with `-RemoveData`) reverses it.

```powershell
pip install -r requirements-postgres.txt            # psycopg (only needed for Postgres)
./scripts/setup_postgres.ps1 install                # persistent service + provisioned role/db + schema

# Migrate existing SQLite data (users, tenants, vault, scans, audit, ...) into Postgres:
$env:DSPM_DB_URL = (./scripts/setup_postgres.ps1 url)
python -m scripts.migrate_sqlite_to_postgres

./scripts/run_app.ps1 --host 127.0.0.1 --port 8000  # runs the app on Postgres
```

`run_app.ps1` loads `DSPM_DB_URL` from the credentials file for the app process only, so the DB password never enters the global machine environment. (If you prefer, `setx DSPM_DB_URL "<url>" /M` makes any launch use Postgres, at the cost of exposing the password in the machine environment.)

The provisioned role is not a superuser and has only `CONNECT` + `USAGE, CREATE ON SCHEMA public` — it owns its own tables and nothing else. Bind Postgres to localhost/socket, require TLS for non-local clients, and encrypt the data volume and backups for production (see the roadmap's Phase 2 runbook).

**Provisioning against an existing Postgres** (idempotent; no service install):

```bash
python -m scripts.provision_postgres --admin-url postgresql://postgres@dbhost:5432/postgres
# -> prints the DSPM_DB_URL to export
```

**Running the test suite on Postgres.** The suite TRUNCATES its target database per test for isolation, so it refuses to run against Postgres unless you opt in with `DSPM_PG_TEST_RESET=1` — **always point it at a dedicated test database, never production**:

```bash
export DSPM_DB_URL='postgresql://sentro_app:<pw>@127.0.0.1:5432/sentro_test'
export DSPM_PG_TEST_RESET=1
python -m pytest tests/ -q
```

For a disposable **local dev** cluster on Windows (trust auth, spare port, no service install), `scripts/pg_dev_cluster.ps1 up` will `initdb` + start one; `down`/`destroy` tear it down.

### Optional dedicated inventory search (S-F)

PostgreSQL remains the source of truth and the default search provider. At very large scale, an operator can enable a metadata-only Meilisearch projection for typo-tolerant inventory text queries. Tenant ID is mandatory in every engine filter; raw evidence and `detail_json` are never indexed. Non-text inventory browsing continues to use S-C keyset pagination, and any dedicated-engine timeout/error falls back to the database.

Use a staged cutover:

```powershell
$env:DSPM_SEARCH_ENGINE = "meilisearch"
$env:DSPM_MEILISEARCH_URL = "http://127.0.0.1:7700"
$env:DSPM_MEILISEARCH_API_KEY = "<admin-key>"  # environment/secret store only
$env:DSPM_SEARCH_READ_ENABLED = "0"

python -m scripts.reindex_search --rebuild       # bounded DB keyset batches; task-aware writes
python -m scripts.reindex_search                 # verifies service, index, and current settings

$env:DSPM_SEARCH_READ_ENABLED = "1"              # enable q=... reads after verification
```

New/updated scans dual-write metadata when `DSPM_SEARCH_DUAL_WRITE=1`. `/api/health` exposes provider availability and read-cutover state without exposing the URL or API key. Rebuild is intentionally explicit because it deletes and recreates only the configured Meilisearch index. See the official [Meilisearch document API](https://www.meilisearch.com/docs/reference/api/documents/add-or-replace-documents) and [filter/sort/facet guide](https://www.meilisearch.com/docs/capabilities/filtering_sorting_faceting/overview) for service-side operations.

S-F.2 adds bounded drift reconciliation and automated repair. Configure
`DSPM_SEARCH_RECONCILE_SECONDS` (default `300`, `0` disables) and
`DSPM_SEARCH_RECONCILE_REPAIR` (default `1`). Use
`python -m scripts.reindex_search --check-drift` for a read-only audit or
`--repair-drift` to upsert missing/stale documents and remove search-only
orphans. The last durable reconciliation result is exposed under
`/api/health.search.reconciliation`. Deployment, backup, upgrade, failure, and
certification procedures are in
[`docs/search/MEILISEARCH_OPERATIONS.md`](docs/search/MEILISEARCH_OPERATIONS.md).

## Dependencies

**Python 3.12 or newer is required** (tested to 3.14). `main.py` refuses an older interpreter with the command that installs a supported tree, rather than letting it fail as an import error inside a dependency. The floor is where `requirements.lock` is generated and where the lowest CI leg installs from it: an older interpreter resolves a different dependency tree, so an install that appeared to work would not be the tree anything was tested against.

Requirements are split by purpose:

| File | Purpose |
| --- | --- |
| `requirements.txt` | Runtime dependencies only. Use this alone for production installs. |
| `requirements-dev.txt` | Adds the test runner. Use `pip install -r requirements.txt -r requirements-dev.txt` for development. |
| `requirements-ml.txt` | Optional spaCy-based ML/NER classification. See the caveat below. |
| `requirements-postgres.txt` | Optional PostgreSQL backend (psycopg). Only needed when `DSPM_DB_URL` is set. |

SQLite does not need a separate package because the app uses Python's built-in `sqlite3` module. WinRM endpoint scanning uses the existing `pywinrm` dependency; no extra package is needed for the GPO-based target preparation flow.

### Optional ML classification

`classification/ml_classifier.py` imports `spacy` and loads the `en_core_web_sm` model. Neither is installed by `requirements.txt`, and both failures are swallowed silently — so on a standard install the ML/NER detection path is **disabled without any warning** and classification falls back to heuristics. To enable it:

```powershell
pip install -r requirements-ml.txt
python -m spacy download en_core_web_sm
```

Enabling it changes detection output. Decide deliberately whether ML classification should be on before deploying.

### Building the landing page

The operator console in `frontend/` is static HTML/CSS/JavaScript served directly by FastAPI and needs no build step. The separate marketing site in `frontend-landing/` **is** a Vite/React/Three.js application and does require Node.js (Node 20+):

```powershell
cd frontend-landing
npm ci
npm run build
```

`backend/app.py` serves the resulting `frontend-landing/dist/` at `/` and `/login` when it exists, so that directory is currently a committed deployment artifact. Rebuild and commit it whenever `frontend-landing/src/` changes, or the deployed landing page will silently diverge from source.

### Static analysis gates

CI's `Static analysis` job runs `scripts/static_gate.py`, and it runs the same way locally. The job fails on:

- a name the console uses and nothing defines (ESLint `no-undef`, the pinned copy in `frontend/node_modules`);
- an undefined Python name (Ruff `F82`);
- a type error in the security modules (mypy);
- a medium-or-higher Bandit finding missing from the reviewed baseline, `security/bandit-baseline.json`;
- a match for the offline Semgrep rules in `security/semgrep.yml`.

A reviewed exception is marked on its own line (`# nosemgrep: <rule>` with a reason), never file-wide.

```powershell
pip install -r requirements-static.txt
python -m venv .semgrep-venv; .semgrep-venv\Scripts\pip install -r requirements-semgrep.txt
cd frontend; npm ci; cd ..
$env:SEMGREP_BIN = ".semgrep-venv\Scripts\semgrep.exe"
python scripts/static_gate.py            # or one gate: ruff | mypy | bandit | semgrep | eslint
```

`.github/workflows/dast-nightly.yml` runs an OWASP ZAP baseline scan every night against a disposable instance on a throwaway database. It never fails on findings: the report is uploaded as an artifact for a person to review.

To review an install's security configuration without touching it:

```powershell
python scripts/review_install_copy.py --report docs/evidence/install-review.json
```

The script copies the database read-only (the install can keep running), then checks the copy:

- verifies every tenant's audit hash chain;
- serves the copy with this tree on its own port and temporary keys;
- checks the CSP, security headers, content-versioned asset URLs, refusals without a session and API caching;
- names what a production start would refuse.

It deletes the copy afterwards and exits 1 if any check fails.

Optional tooling:

- Git is required only for committing and pushing changes to GitHub.
- Browser print/PDF exports look best when print background graphics are enabled.

## Project Structure

```text
backend/          FastAPI app, auth, tenant store, jobs, alerts, vault
classification/   Regex and heuristic classifiers
collectors/        Local file scanner, SMB scanner, binary text extraction
discovery/         Scan orchestration and report building
frontend/          HTML, CSS, browser app (static, no build step)
frontend-landing/  Vite/React marketing site (requires `npm ci && npm run build`)
permissions/       ACL analysis
risk/              Risk scoring, risk rules, remediation model
scripts/           Report writer, logger, demo data generator
tests/             Test suite (stdlib unittest, run with pytest)
docs/              Engineering analyses and fix reports
enterprise_test_data/  Local synthetic sample data generated on demand
```

`enterprise_test_data/` is gitignored but is also the default `--local-path` for CLI scans and the demo flow. A fresh clone must generate it before the default scan will work:

```powershell
python scripts/generate_enterprise_test_data.py --output enterprise_test_data --files-per-share 10
```

## Roadmap

- Microsoft Purview DLP export.
- Jira, ServiceNow, Slack, and Teams remediation integrations.
- SharePoint, OneDrive, Google Drive, S3, Azure Blob, SQL Server, and PostgreSQL connectors.
- Persisted remediation state with assignment and closure workflow.
- Directory (AD/LDAP) group mapping onto roles and permissions.
- Scheduled scans and posture drift alerts.
- Docker packaging and production deployment profile.

## Status

This is a prototype/MVP intended for enterprise DSPM and DLP readiness testing. It is suitable for demos, local pilots, and product development, but should be hardened before production deployment.
