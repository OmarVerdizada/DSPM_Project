# Sentro DSPM

Sentro is a Data Security Posture Management (DSPM) and DLP-readiness product for Windows
estates. It runs on premises, one installation per customer. It finds sensitive data on
file servers, Windows endpoints and other sources, classifies it (PII, PCI, secrets,
GDPR/NIST categories, financial and HR data), scores the risk of each file from its content
and its access rights, and tracks remediation. It produces the evidence and reports a
security team or an MSSP hands to a customer.

It is an offline product. Nothing is fetched from the Internet at run time, there is no
cloud dependency and no second sign-in factor, and every workspace (tenant) is isolated in
the database by row-level security.

> **Handover package.** If you received this folder as a handover, read
> [docs/HANDOVER.md](docs/HANDOVER.md) first. The **New VM quick start** is below.

## Architecture

```text
 browser ──HTTPS──> reverse proxy (Caddy / nginx, same host; production)
                         │
                         ▼ 127.0.0.1:8000
              ┌────────────────────────┐        ┌──────────────────────────┐
              │ backend  (main.py serve)│ queue  │ worker  (main.py worker) │
              │ FastAPI API + console   │──────> │ runs scans, partitioned, │
              │ (frontend/ static files)│        │ resumable                │
              └───────────┬────────────┘        └────────────┬─────────────┘
                          │                                  │  SMB 445 / WinRM 5985-5986 /
                          ▼                                  ▼  SFTP 22 / HTTPS (Graph) / PostgreSQL
              ┌──────────────────────────┐     scanned sources (file servers, endpoints, ...)
              │ database                  │
              │  PostgreSQL 18 (production, FORCE row-level security)
              │  SQLite (evaluation / development)
              └──────────────────────────┘
   data root: encrypted artifact store, encrypted scan cache, backups, reports, logs
```

| Part | Where |
|---|---|
| API, authentication, permissions, jobs | `backend/` (`backend/app.py` is the FastAPI app, `backend/store.py` the data layer, `backend/migrations.py` the schema revisions) |
| Operator console | `frontend/` (static HTML/CSS/JavaScript served by the backend; no build step) |
| Collectors: local folders, SMB, WinRM endpoints, SFTP, databases, SharePoint/OneDrive | `collectors/`, `discovery/` |
| Classification, compliance frameworks, risk and remediation | `classification/`, `risk/`, `permissions/` |
| Command line: serve, worker, migrate, backup, vault, audit, admin, version | `main.py` (`python main.py --help`) |
| Install and operations scripts | `scripts/` (see [scripts/README.md](scripts/README.md)) |
| Offline Windows package (services) | `packaging/windows/` |
| Reverse proxy, monitoring, sizing profiles | `deploy/` |

**Scan types:** Windows file servers over SMB (SMB 2/3, optional SMB 3.1.1 encryption);
Windows endpoints over WinRM (profiles, drives, custom paths); local folders on the Sentro
host; Linux and macOS over SFTP; PostgreSQL column sampling; SharePoint Online and OneDrive
through Microsoft Graph. Scans are incremental (unchanged files reuse their findings),
partitioned and resumable, and can be scheduled.

## Requirements

Python 3.12 or newer is required (tested to 3.14; the offline package carries 3.14.6).

| | Tested | Notes |
|---|---|---|
| Operating system | Windows Server 2019 (build 17763) | Windows Server 2022 is the other supported target (docs/DEPLOYMENT_WINDOWS.md); it was not part of this handover's tests |
| PowerShell | Windows PowerShell 5.1 | the scripts in `scripts/` |
| Python | 3.14.6 x64 | 3.12 and 3.13 run in CI |
| Database | PostgreSQL 18 (production), SQLite (evaluation) | extensions `pg_trgm`, `btree_gin` |
| Hardware | 6 vCPU, 16 GB RAM (the development host) | sizing guidance: [docs/INSTALLATION_WINDOWS.md](docs/INSTALLATION_WINDOWS.md#hardware) |

Full prerequisites: firewall ports, service accounts, WinRM and SMB preparation, folder
permissions. See [docs/INSTALLATION_WINDOWS.md](docs/INSTALLATION_WINDOWS.md).

## New VM quick start (evaluation install, SQLite)

In an elevated Windows PowerShell, in this folder, after installing Python 3.12+ x64
(python.org, "Add python.exe to PATH"):

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\preflight.ps1                   # read-only checks: PASS / WARN / FAIL
.\scripts\setup.ps1                       # .venv, pinned packages, secrets, config, schema, admin
.\scripts\start.ps1                       # backend + worker, waits for /api/ready
```

Then open `http://127.0.0.1:8000/` and sign in as `admin`. The password is in
`data\secrets\admin_password`, which only Administrators can read. Change it with:

```powershell
.\.venv\Scripts\python.exe main.py --config data\config\sentro.toml admin set-password
```

Stop with `.\scripts\stop.ps1`. A fresh install has no workspaces other than `default`, no
scans and no findings. Create a workspace under **Tenants**, list its scan targets under
**Security operations → Scan targets**, and start a scan.

**Production** (PostgreSQL, HTTPS reverse proxy, Windows services): follow
[docs/INSTALLATION_WINDOWS.md](docs/INSTALLATION_WINDOWS.md). It covers the source install
in production mode, and the offline package with Windows services
([docs/DEPLOYMENT_WINDOWS.md](docs/DEPLOYMENT_WINDOWS.md)).

## Everyday commands

All commands run from this folder. `--config` names the configuration file; `setup.ps1`
writes it to `data\config\sentro.toml`, and `DSPM_CONFIG_FILE` can name it instead.

```powershell
$py = '.\.venv\Scripts\python.exe'; $cfg = 'data\config\sentro.toml'
& $py main.py --config $cfg version              # version, commit/build, schema supported vs applied
& $py main.py --config $cfg config check         # validate the configuration (secrets shown as "set")
& $py main.py --config $cfg migrate status       # schema revision (read-only)
& $py main.py --config $cfg migrate upgrade      # apply new revisions (Sentro stopped, backup first)
& $py main.py --config $cfg backup create --verify
& $py main.py --config $cfg audit verify         # every workspace's audit hash chain
Invoke-RestMethod http://127.0.0.1:8000/api/health   # alive, version, database identity
Invoke-RestMethod http://127.0.0.1:8000/api/ready    # database, schema, runtime folders, backups
```

Logs are written to `data\logs` (`backend.log`, `worker.log`, and the console output of
processes `start.ps1` started). Operations, upgrades and troubleshooting:
[docs/OPERATIONS.md](docs/OPERATIONS.md).

## Configuration

One TOML file (`[settings]`) plus the process environment, which overrides it. Secrets are
never written in the file: each is a file named by `<NAME>_FILE`, in `data\secrets`.
`main.py config check` validates the configuration, and production refuses weak settings.
The operator's view is [docs/CONFIGURATION.md](docs/CONFIGURATION.md); every setting with
its default is in [.env.example](.env.example).

## Database

`scripts/setup.ps1` creates a fresh database at the current schema revision through the
migrations. Nothing is copied from another installation. PostgreSQL setup covers the
server, the extensions, the least-privilege role, row-level security, a separate test
database, and moving from SQLite. See [docs/DATABASE_SETUP.md](docs/DATABASE_SETUP.md).

## Tests and static gates

```powershell
& $py -m pip install --require-hashes -r requirements.lock -r requirements-connectors.lock -r requirements-postgres.lock
& $py -m pip install -r requirements-dev.txt -r requirements-static.txt
& $py -m pytest tests -q                         # SQLite; each test gets its own temporary database
& $py scripts\static_gate.py ruff                # also: mypy | bandit | eslint (needs `npm ci` in frontend\)
```

The suite on PostgreSQL truncates its database: point `DSPM_DB_URL` at a dedicated
`*_test` database and set `DSPM_PG_TEST_RESET=1` ([docs/DATABASE_SETUP.md](docs/DATABASE_SETUP.md#test-database)).

## Documentation

| Document | For |
|---|---|
| [docs/HANDOVER.md](docs/HANDOVER.md) | what this package is, its state, known limitations, first steps |
| [docs/INSTALLATION_WINDOWS.md](docs/INSTALLATION_WINDOWS.md) | prerequisites and installation (source install and offline package) |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | configuration file, secrets, settings |
| [docs/DATABASE_SETUP.md](docs/DATABASE_SETUP.md) | SQLite and PostgreSQL, roles, RLS, migrations, test database |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | start/stop, health, logs, backups, upgrades, troubleshooting |
| [docs/SECURITY_DEPLOYMENT.md](docs/SECURITY_DEPLOYMENT.md) | hardening a production deployment |
| [docs/DEPLOYMENT_WINDOWS.md](docs/DEPLOYMENT_WINDOWS.md) | the offline package: services, upgrades, signing, data at rest |
| [docs/PRODUCT_REFERENCE.md](docs/PRODUCT_REFERENCE.md) | features in depth: roles, scans, vault, audit, alerts, API, risk model |
| [docs/ENDPOINT_LEAST_PRIVILEGE.md](docs/ENDPOINT_LEAST_PRIVILEGE.md) | WinRM endpoint accounts with least privilege |
| [docs/SCALING_ROADMAP_2026-10.md](docs/SCALING_ROADMAP_2026-10.md) | the engineering log and measured performance |
| [docs/history/](docs/history/) | older change notes |

## Licence

Proprietary. See [LICENSE](LICENSE).
