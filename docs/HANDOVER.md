# Sentro handover

This folder is the Sentro product as handed over to a new engineering and operations team:
the complete source, its dependency locks, the install and start scripts, and the
documentation needed to bring it up on a new Windows Server with no knowledge of the machine
it was developed on.

## What you received

| | |
|---|---|
| Product | Sentro DSPM, application version 1.0.0 |
| Source | branch `sentro-ironhack`; the exact commit and export date are in `BUILD.json` at the root, and `main.py version` prints them |
| Schema | the revision the build supports is printed by `main.py version` (`schema_supported`); a new database is created at that revision |
| Python | 3.12+ (tested 3.14.6); dependencies hash-locked in `requirements*.lock` |
| Database | PostgreSQL 18 (production) or SQLite (evaluation), created empty by the migrations |

```text
backend/  frontend/  classification/  collectors/  discovery/  permissions/  risk/   the product
main.py                                     the command line (serve, worker, migrate, backup, admin, version, ...)
scripts/                                    install/start/stop/preflight, operations tools, gates, benchmarks (scripts/README.md)
packaging/windows/                          the offline package builder and its Windows-service installer
deploy/                                     reverse proxy, monitoring, sizing profiles
tests/  test_data/                          the test suite (unittest, run with pytest) and its small fixtures
docs/                                       this document, the operator guides, the engineering log, evidence
requirements*.txt / *.lock, pyproject.toml  dependencies and tool settings
.env.example                                the catalogue of every setting
.github/workflows/                          CI definitions (unit suites on both engines, static gates, nightly perf/DAST)
BUILD.json                                  what this export is (commit, date) - written when the export was made
```

## What was deliberately left out

The package is a clean source tree. It behaves like a new installation and carries nothing
from the development machine:

| Left out | Why |
|---|---|
| databases (`data\dspm.sqlite`, PostgreSQL clusters and dumps), backups, reports, artifacts, scan caches, logs | runtime and customer data: users, workspaces, credentials, scan history, findings, audit events |
| keys, passwords, credential files, `.env` files | secrets. A new install generates its own (`scripts\setup.ps1`) |
| `.venv`, `.build-venv`, `node_modules`, `__pycache__`, tool caches, coverage data | regenerable, and machine-specific |
| `dist\` (built offline packages) | stale against this source; rebuild with `packaging\windows\build_package.py` |
| synthetic datasets (`enterprise_test_data\`, benchmark corpora, `tmp\`) | regenerable: `scripts\generate_enterprise_test_data.py` and the benchmark scripts |
| `.git` | the export has no history (see *Source control* below) |
| editor and AI-assistant settings (`.claude\`, `.agents\`, `.obsidian\`, `skills-lock.json`) | developer tooling |
| internal assessments marked confidential (security assessments, gap analyses, product and remediation roadmaps, a quality audit's raw output, a technical assessment PDF, a NIST catalogue in Azerbaijani) | held internally by the previous owner and excluded from the repository by design. Ask for them separately if your organisation is entitled to them |

References to the development lab in the engineering documents were generalised. This
includes host addresses, workspace ids and absolute paths on the development machine. The
signed evidence packages under `docs/database/evidence/packages/` are kept unmodified: they
name the development database and its cluster identifier, which are not secrets.

## Bringing it up

Follow the README's *New VM quick start* (evaluation, SQLite) or
[INSTALLATION_WINDOWS.md](INSTALLATION_WINDOWS.md) (production). In short:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\preflight.ps1      # read-only: what the machine is missing
.\scripts\setup.ps1          # .venv, packages, secrets, configuration, schema, administrator
.\scripts\start.ps1          # backend + worker; http://127.0.0.1:8000/
```

The first sign-in is `admin`. The password is generated into `data\secrets\admin_password`.
A fresh install has the `default` workspace, the built-in `admin` and nothing else.

## Verified in this handover

The handover was checked by building a fresh copy of this export, with no git metadata,
into a new folder. It got a new virtual environment installed only from the lock files, a
generated configuration, and a new SQLite database migrated from revision 0. It was
started, checked through `/api/health` and `/api/ready`, signed into as `admin`, and found
empty. A new workspace was created and a scan run. The results, and the test and static
gate runs, are recorded in the handover report that accompanied this package. Not verified
in the handover: a PostgreSQL production install on the new hardware, the offline package
build, and real file servers or endpoints.

## Known limitations and open items

From the engineering log ([SCALING_ROADMAP_2026-10.md](SCALING_ROADMAP_2026-10.md), §24-§25):

* **Scale is proven to 20,000 files.** Every figure for 1M files and above, and the 16 GB /
  32 GB node profiles, is EXTRAPOLATED. The scale gates G1-G5 need a scale host and were
  never run.
* **Real-network behaviour is partly unverified.** WinRM endpoint figures were measured
  against an emulated endpoint. The SMB and WinRM listing digests behind "unchanged costs
  nothing" are unverified on real servers. The WinRM envelope size and a persistent remote
  PowerShell session (needs `pypsrp`) are not done.
* **Code signing is held** for a code-signing certificate. Packages are built unsigned, and
  `install.ps1` needs `-AllowUnsigned` (DEPLOYMENT_WINDOWS.md). The publisher's Ed25519
  signature works.
* **High availability is not covered:** one backend node, one PostgreSQL. No failover.
* **No second sign-in factor**, by product decision (offline product).
* **SMB 3 encryption** uses `smbprotocol`. Owners and ACLs on such scans are read through
  Windows' own SMB client (product reference, *File Server Scans*).
* **Split PostgreSQL roles** (`scripts/db_roles.py`) are optional, and upgrades with them are
  manual (DATABASE_SETUP.md).
* **Optional engines not installed:** Meilisearch for typo-tolerant search, spaCy for ML
  classification (its model needs a download), and RapidOCR for images
  (`requirements-ocr.txt`, `DSPM_OCR_ENABLED=1`).
* Production needs the `admin_password` file at every start, even after the password has
  been changed with `main.py admin set-password`.

## Source control

The export carries no `.git`. The full history lives in the original repository: branch
`sentro-ironhack`, at the commit in `BUILD.json`. Two tools need a git checkout:

* `packaging\windows\build_package.py` packages a git ref;
* `scripts\check_frontend_tokens.py` diffs against git.

Use the original repository for both. To start a new history from this export instead:

```powershell
git init; git add -A; git commit -m "Sentro baseline from handover <commit in BUILD.json>"
```

`.gitignore` already excludes every runtime folder `setup.ps1` creates (`.venv`, `data\`).

## First week for the receiving team

1. Run `preflight.ps1` and `setup.ps1` on the new VM, start Sentro, sign in, and change the
   administrator password.
2. Escrow `data\secrets` off the host. Take and verify a backup.
3. Run the test suite (OPERATIONS.md, *Tests*) and the static gates on the new VM.
4. Decide on the production layout: PostgreSQL location, reverse proxy and certificate,
   services (offline package) or source install. Then follow INSTALLATION_WINDOWS.md.
5. Prepare one file server and one endpoint per INSTALLATION_WINDOWS.md and scan them. This
   is also the first real-network measurement the open items above ask for.
6. Read [SECURITY_DEPLOYMENT.md](SECURITY_DEPLOYMENT.md) before exposing the console.

## Where things are documented

| Need | Document |
|---|---|
| install, prerequisites, hardware, ports, accounts | [INSTALLATION_WINDOWS.md](INSTALLATION_WINDOWS.md) |
| settings and secrets | [CONFIGURATION.md](CONFIGURATION.md), `.env.example` |
| PostgreSQL, roles, RLS, migrations, test database | [DATABASE_SETUP.md](DATABASE_SETUP.md) |
| running, health, logs, backups, upgrades, troubleshooting | [OPERATIONS.md](OPERATIONS.md) |
| hardening | [SECURITY_DEPLOYMENT.md](SECURITY_DEPLOYMENT.md) |
| the offline package and Windows services | [DEPLOYMENT_WINDOWS.md](DEPLOYMENT_WINDOWS.md) |
| features, API, risk model | [PRODUCT_REFERENCE.md](PRODUCT_REFERENCE.md) |
| endpoint least privilege | [ENDPOINT_LEAST_PRIVILEGE.md](ENDPOINT_LEAST_PRIVILEGE.md) |
| engineering log, measurements, open work | [SCALING_ROADMAP_2026-10.md](SCALING_ROADMAP_2026-10.md), [PERFORMANCE_AUDIT_AND_ROADMAP_2026-09.md](PERFORMANCE_AUDIT_AND_ROADMAP_2026-09.md), `docs/database/`, `docs/perf/`, `docs/frontend/` |
| retained measurement evidence | `docs/evidence/`, `docs/database/evidence/` (README there) |
| older change notes | `docs/history/` |
