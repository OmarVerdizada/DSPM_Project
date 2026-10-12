# Installing Sentro on Windows Server

Two ways to install, from the same source:

| | Source install (this folder) | Offline package (Windows services) |
|---|---|---|
| For | evaluation, pilots, development; production on one host if services are not required | production |
| Python | a `.venv` in this folder, built from python.org Python 3.12+ | the embeddable Python 3.14.6 inside the package |
| Packages | `pip install --require-hashes` from the lock files (PyPI, or a local wheel folder) | wheels inside the package, no network |
| Runs as | the signed-in administrator, started by `scripts\start.ps1` | `SentroBackend` / `SentroWorker` services under virtual accounts |
| Data root | `data\` in this folder (`-DataRoot` to move it) | `C:\ProgramData\Sentro` |
| Guide | this document | this document's prerequisites, then [DEPLOYMENT_WINDOWS.md](DEPLOYMENT_WINDOWS.md) |

Either way the database starts empty at the current schema revision. Nothing from another
installation is carried over.

## 1. Prerequisites

### Operating system and software

| Item | Requirement | Notes |
|---|---|---|
| Windows | Windows Server 2019 (build 17763) or 2022, x64 | Tested for this handover: Server 2019 Standard 17763. `preflight.ps1` FAILs below Server 2016 |
| PowerShell | Windows PowerShell 5.1 (built in) | scripts run with `-ExecutionPolicy Bypass` for the process only |
| Python (source install) | 3.12, 3.13 or 3.14, x64, from python.org | tested: 3.14.6. Not needed for the offline package |
| PostgreSQL (production) | PostgreSQL 18 server, on this host or another | tested: 18 (development and CI). The `pg_trgm` and `btree_gin` contrib extensions must be available (they ship with the EDB Windows installer). `pg_dump`/`pg_restore` 18 on this host for backups |
| Visual C++ runtime | none beyond Windows | every binary dependency is a wheel |
| Node.js | not needed to run Sentro | only for the ESLint gate in development |
| Internet | not needed at run time | a source install downloads its pinned packages from PyPI once, or installs them from `-WheelDirectory` |

Windows features: nothing has to be added to the Sentro host. The WinRM *client* used for
endpoint scans is part of Windows. Sentro does not need IIS, .NET SDKs, Docker, Redis or any
message broker.

### Hardware

These figures are labelled by how they are known. Nothing below 6 vCPU / 16 GB has been
measured.

| Profile | CPU | RAM | Free disk for the data root | Basis |
|---|---|---|---|---|
| Minimum (evaluation, SQLite, small estates) | 4 vCPU | 8 GB | 20 GB plus 2 GB floor | UNVERIFIED: `preflight.ps1` warns below this and fails below 4 vCPU / 8 GB |
| Tested | 6 vCPU | 16 GB | - | MEASURED: the development host every number in docs/SCALING_ROADMAP_2026-10.md was taken on |
| Recommended (production, one node with PostgreSQL) | 8 vCPU | 16 GB | 100 GB per million files scanned | EXTRAPOLATED: [deploy/node-profiles](../deploy/node-profiles/README.md) `node-16gb` |
| Large estates (2M files and more) | 8-16 vCPU | 32 GB | 150 GB for 2M files | EXTRAPOLATED: `node-32gb`; more than 32 GB is not needed by the design |

Scans pause, instead of filling the disk, when free space drops below `DSPM_MIN_FREE_DISK_MB`
(2048 MB by default). If PostgreSQL archives WAL (`archive_mode = on`), the archive grows
until it is pruned after a base backup. Size the disk for that and schedule the pruning.

### Network

| Direction | Port | Purpose | Needed for |
|---|---|---|---|
| inbound | 443/TCP | the HTTPS reverse proxy (Caddy or nginx, [deploy/reverse-proxy](../deploy/reverse-proxy/README.md)) | production access from other machines |
| local only | 8000/TCP on 127.0.0.1 | the backend; never exposed directly | always |
| outbound / local | 5432/TCP (or the port you choose) | PostgreSQL | production |
| outbound | 445/TCP | SMB file-server scans | file-server scans |
| outbound | 5986/TCP (HTTPS) or 5985/TCP (HTTP) | WinRM endpoint scans; production requires HTTPS with a verified certificate unless `DSPM_REQUIRE_WINRM_SSL=0` | endpoint scans |
| outbound | 636/TCP (LDAPS) or 389/TCP (StartTLS) | directory sign-in (Active Directory / LDAP) | optional |
| outbound | 22/TCP | Linux/macOS over SFTP | optional |
| outbound | 443/TCP | Microsoft Graph (SharePoint/OneDrive), webhooks, Jira, ServiceNow | optional |
| outbound | 587 or 465/TCP | e-mail alerts through the customer's relay | optional |
| outbound | the SIEM's syslog port | audit forwarding (TLS recommended) | optional |

Windows Firewall on the Sentro host: allow inbound 443 for the reverse proxy only. Do not
open 8000. Outbound rules are only needed if the host restricts outbound traffic.
`setup.ps1` does not change firewall rules. Make these changes through your change process.

In production a workspace scans nothing until its scan targets (networks, host names) are
listed under **Security operations → Scan targets**. Anything else is refused before a
connection is made.

### Accounts

| Account | Rights | Notes |
|---|---|---|
| Installer | local Administrator on the Sentro host | runs `setup.ps1` / `install.ps1`; owns the data root |
| Sentro runtime | source install: the signed-in administrator; package: `NT SERVICE\SentroBackend` and `NT SERVICE\SentroWorker` (virtual accounts, no password) | change rights on the data root; read-only on config and secrets |
| File-server scan account | a domain account (for example `svc_dspm_scan`): Read, List folder contents, Read attributes, Read permissions on the shares in scope | never a Domain Admin; local admin only to scan admin shares such as `C$` |
| Endpoint scan account | local Administrators on the scoped workstations (a group pushed by GPO) or the least-privilege model of [ENDPOINT_LEAST_PRIVILEGE.md](ENDPOINT_LEAST_PRIVILEGE.md) | separate from the file-server account |
| Directory service account (optional) | read-only bind for directory sign-in | its password is sealed in Sentro's vault |
| PostgreSQL application role | not superuser, no CREATEDB / CREATEROLE / BYPASSRLS; owns its schema | created by `scripts/provision_postgres.py` or `scripts/setup_postgres.ps1` |

Scan credentials are entered in the console and sealed in the vault. They are never put in
configuration files.

### Preparing scan targets

* **File servers:** TCP 445 reachable from the Sentro host, and the scan account granted read
  on the shares. For servers that require SMB encryption, use the **SMB 3 encryption** scan
  option. It needs `smbprotocol`, which `setup.ps1` installs.
* **Windows endpoints:** WinRM enabled by GPO (*Allow remote server management through
  WinRM*, the WinRM service set to Automatic, and inbound firewall rules for WinRM on the
  Domain profile). Use an HTTPS listener (5986) with a certificate the Sentro host trusts for
  production. Validate with `Test-NetConnection <host> -Port 5986` (or 5985). The
  [product reference](PRODUCT_REFERENCE.md#group-policy-for-winrm-targets) has the GPO
  details. Sentro reconfigures endpoints ("WinRM activation") only when
  `DSPM_ALLOW_WINRM_ACTIVATION=1` in production.
* Link GPOs only to the OUs in scope.

### Folder permissions

The data root holds the database (SQLite) or nothing but artifacts (PostgreSQL), the
encrypted artifact store and scan cache, backups, reports and logs. Its `config` and
`secrets` subfolders are limited to Administrators, SYSTEM and the installing account
(source install) or the service accounts (package). Keep the data root on an NTFS volume
that only administrators can browse. Never place it in a share.

## 2. Check the machine

Copy this folder to the new host, for example to `D:\Sentro`. Any path works; nothing
depends on the old location. Then run the read-only checks:

```powershell
cd D:\Sentro
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\preflight.ps1
```

Before setup, some items FAIL or WARN as expected: there is no `.venv` and no configuration
yet. Fix any FAIL about Windows, CPU, memory or disk first.

## 3. Source install: evaluation (SQLite)

```powershell
.\scripts\setup.ps1
.\scripts\start.ps1
```

`setup.ps1` does the following, and nothing outside this folder:

1. creates `.venv` from Python 3.12+ and installs `requirements.lock`,
   `requirements-postgres.lock` and `requirements-connectors.lock` with
   `--require-hashes`;
2. creates `data\{config,secrets,db,artifacts,backups,cache,reports,logs,trust}`;
3. generates the keys and the administrator password, one file each in `data\secrets`. They
   are never printed, never overwritten, and readable only by Administrators, SYSTEM and you;
4. writes `data\config\sentro.toml`, which holds no secrets;
5. runs `main.py config check`, then `main.py migrate upgrade` (revision 0 to current), then
   `main.py admin ensure`;
6. runs `preflight.ps1`.

`start.ps1` refuses to start if the configuration is refused, the schema does not match
this build, or the port is taken. It starts the backend, waits for `/api/ready`, then starts
the worker.

Sign in at `http://127.0.0.1:8000/` as `admin`, with the password from
`data\secrets\admin_password`. Then change it:

```powershell
.\.venv\Scripts\python.exe main.py --config data\config\sentro.toml admin set-password
```

**Offline host:** pass `-WheelDirectory <folder>` to `setup.ps1`, pointing at a folder of
wheels for every package in the three lock files. A built offline package's `wheelhouse\`
works, if it was built from the same commit. Because `pysmb` is published as a source
archive only, the folder must also hold a `pysmb` wheel (the package builder makes one) or
`setuptools` and `wheel` to build it.

## 4. Source install: production (PostgreSQL behind HTTPS)

1. **PostgreSQL.** Install PostgreSQL 18 (EDB installer, with its command-line tools), then
   either:
   * create a dedicated cluster for Sentro on this host:
     `.\scripts\setup_postgres.ps1 install`. This creates the `SentroPostgres` service on
     port 5442, the `sentro_app` role and the `sentro` database with its extensions, and
     writes the application URL to `C:\SentroPostgres\db_url`, which only administrators
     can read. It needs `.venv`, so run `setup.ps1` first in local mode, or
   * provision a database on an existing server with `scripts\provision_postgres.py`. See
     [DATABASE_SETUP.md](DATABASE_SETUP.md).
2. **Configure Sentro for production:**
   ```powershell
   .\scripts\setup.ps1 -Mode production -DatabaseUrlFile C:\SentroPostgres\db_url -PublicHostName sentro.corp.example
   ```
   If `data\config\sentro.toml` already exists from an evaluation run, `setup.ps1` keeps it.
   Use a new `-DataRoot`, or edit the file to set `DSPM_ENV = "production"`,
   `DSPM_DB_URL_FILE`, `DSPM_TRUSTED_HOSTS` and `DSPM_TRUSTED_PROXIES`, and remove
   `DSPM_DB_PATH`. Also rename `DSPM_DEV_ADMIN_PASSWORD_FILE` to `DSPM_ADMIN_PASSWORD_FILE`.
3. **HTTPS:** install the reverse proxy from [deploy/reverse-proxy](../deploy/reverse-proxy/README.md)
   with the customer's certificate for the public host name, forwarding to `127.0.0.1:8000`.
4. `.\scripts\start.ps1`, then browse to `https://sentro.corp.example/`.

Production refuses to start on weak settings: missing keys, SQLite, a wildcard host or CORS
origin, a remote PostgreSQL without a verified certificate, and plaintext report copies.
`main.py config check` lists what it would refuse. A source install runs under the
signed-in account and stops at sign-out. For an unattended server, use the offline package
and its services.

## 5. Offline package (Windows services)

Build the package on a machine with the source and Internet access (or a wheel cache):

```powershell
.\.venv\Scripts\python.exe packaging\windows\build_package.py --help
```

Copy the resulting `sentro-<label>-win64.zip` to the server, check its SHA-256, extract it,
and run `install.ps1`. The full procedure covers the install, upgrade, uninstall and
signing; see [DEPLOYMENT_WINDOWS.md](DEPLOYMENT_WINDOWS.md). Run the prerequisite checks
above first. `scripts\preflight.ps1 -ConfigFile C:\ProgramData\Sentro\config\sentro.toml`
from a source copy checks a package install's configuration and folders.

## 6. After installing

* `Invoke-RestMethod http://127.0.0.1:8000/api/ready` must answer `ready: True`.
* `main.py version` shows the build and the schema: the supported revision and the applied
  one.
* The only account is `admin`; the only workspace is `default`. There are no scans,
  findings or reports.
* Take the first backup: `main.py backup create --verify`. Copy the keys in the secrets
  folder to escrow, away from the host and apart from the backups. A backup cannot be
  restored without them.
* Continue with [OPERATIONS.md](OPERATIONS.md) and [SECURITY_DEPLOYMENT.md](SECURITY_DEPLOYMENT.md).
