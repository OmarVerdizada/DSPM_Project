# Database setup

Sentro keeps everything in one database: users and password hashes, workspaces, the sealed
credential vault, scans, inventory, findings, remediation, audit trail and job state. Large
report bodies and artifacts are stored encrypted in the artifact folder.

| Engine | Use | Selected by |
|---|---|---|
| **PostgreSQL 18** | production (required by `DSPM_ENV=production`) | `DSPM_DB_URL` / `DSPM_DB_URL_FILE` |
| **SQLite** | evaluation, development, the default test suite | `DSPM_DB_PATH` (when no PostgreSQL URL is set) |

A new installation **never copies a database**: the schema is created from nothing by the
migrations, so a fresh install has only the `default` workspace and the built-in `admin`
account.

## Schema revisions and migrations

The schema is a numbered series of revisions in `backend/migrations.py`. Each is
recorded in the database with its checksum when applied. This build's revision:

```powershell
.\.venv\Scripts\python.exe main.py --config <config> version              # "this build supports revision N; the database is at M"
.\.venv\Scripts\python.exe main.py --config <config> migrate status --json
.\.venv\Scripts\python.exe main.py --config <config> migrate upgrade      # 0 -> N on a new database; only what is missing on an old one
```

* `migrate status` and `version` only read. They never upgrade.
* `migrate upgrade` takes a database advisory lock, so two starters apply each revision once.
  On an empty database it builds every revision from 1.
* **Production never upgrades on its own**: a backend whose database is behind or ahead of
  the build refuses to serve, and says so. Upgrade with Sentro stopped and a verified backup
  taken (`main.py backup create --verify`). A **local** install upgrades its own database at
  start.
* A database at a newer revision than the build is refused: run the newer build, or
  restore the backup taken before the upgrade.

Freshly migrated and upgraded databases converge. `tests/test_schema_migrations.py` covers
this (legacy then upgrade converges, idempotent upgrade, behind/ahead refused), and so do
`tests/test_migration_deployment.py` (each revision a serving state, an older release
upgraded applies only what is missing, racing starters) and `tests/test_two_backends.py`.
The suites run on both engines.

## SQLite (evaluation)

`scripts\setup.ps1` (local mode) sets `DSPM_DB_PATH` to `data\db\dspm.sqlite` and creates the
schema. Nothing else is needed. SQLite runs in WAL mode; back it up with
`main.py backup create --verify` (an online, encrypted backup), never by copying the file
while Sentro runs. Production refuses SQLite.

## PostgreSQL (production)

### 1. Install the server

Install PostgreSQL 18 for Windows (the EDB installer, with *Command Line Tools*), on the
Sentro host or on a database server. Sentro needs:

* the contrib extensions **`pg_trgm`** and **`btree_gin`**, installed in Sentro's database
  by an administrator (the application role cannot install extensions);
* `pg_dump` and `pg_restore` of the same major version **on the Sentro host**, for backups:
  `C:\Program Files\PostgreSQL\18\bin` by default, or `DSPM_PG_BIN`.

For sizing (`shared_buffers`, connections), see `deploy/node-profiles/postgresql-16gb.conf`
and `postgresql-32gb.conf` (EXTRAPOLATED), and `scripts/pg_tuning_advisor.py`. Every Sentro
process opens up to `DSPM_DB_POOL_MAX + DSPM_DB_POOL_MAX_API + DSPM_DB_POOL_MAX_HEAVY`
connections. Keep `max_connections` above the sum over the backend and every worker, plus 10.

### 2. Create the database, role and extensions

**Option A: a dedicated cluster on the Sentro host** (simplest):

```powershell
.\scripts\setup_postgres.ps1 install
```

This runs `initdb` into `C:\SentroPostgres\data` with scram-sha-256 auth, registers the
auto-starting service `SentroPostgres` on 127.0.0.1:5442, creates the role `sentro_app`
and the database `sentro` with both extensions, and creates the schema. The passwords are
generated with a cryptographic RNG. The superuser's password goes to
`C:\SentroPostgres\credentials.env` and the application URL to `C:\SentroPostgres\db_url`;
both are readable by Administrators and SYSTEM only. Nothing is printed and no password
goes on a command line. Use `-Port`, `-DataDir`, `-Database` and `-Role` to change the
defaults. Then `setup_postgres.ps1 status` checks the service and `url` shows the URL with
its password hidden.

**Option B: an existing PostgreSQL server.** Run as a role with CREATEDB and CREATEROLE. The
admin URL comes from the environment and the result goes to a protected file:

```powershell
$env:DSPM_PG_ADMIN_URL = 'postgresql://postgres:<password>@db01.corp.example:5432/postgres?sslmode=verify-full&sslrootcert=C:/certs/db-ca.pem'
.\.venv\Scripts\python.exe -m scripts.provision_postgres --host db01.corp.example --port 5432 `
    --db sentro --role sentro_app --sslmode verify-full --url-file D:\Sentro\data\secrets\db_url
Remove-Item Env:\DSPM_PG_ADMIN_URL
```

Then add `&sslrootcert=<path to the CA on the Sentro host>` to the URL in the file. The
script is idempotent. It creates the database (`REVOKE ALL ... FROM PUBLIC`,
`GRANT CONNECT` to the role) and a `LOGIN` role that is not a superuser and cannot create
databases or roles. It installs `pg_trgm` and `btree_gin`, grants `USAGE, CREATE` on schema
`public`, and verifies the role is unprivileged. A password chosen by you comes from
`DSPM_PG_APP_PASSWORD`; otherwise one is generated into the file only.

### 3. Point Sentro at it, and create the schema

```powershell
.\scripts\setup.ps1 -Mode production -DatabaseUrlFile <the db_url file> -PublicHostName sentro.corp.example
```

`setup.ps1` copies the URL into `data\secrets\db_url` and sets `DSPM_DB_URL_FILE`; delete
your copy afterwards. It then runs `migrate upgrade`. The offline package's `install.ps1
-DatabaseUrlFile` does the same.

TLS: a server on another host must be reached with `sslmode=verify-full` (or `verify-ca`)
and `sslrootcert`. Production refuses no `sslmode` (libpq falls back to plaintext) and
`require` (which accepts any certificate). Loopback connections need no TLS.

### Roles, row-level security and grants

* **One application role** (`sentro_app`) is the supported model. It owns the tables its
  migrations create and is the role the backend, the worker and `migrate upgrade` connect as.
  It is not a superuser and has no BYPASSRLS. **Never point Sentro at a superuser**:
  superusers bypass row-level security.
* **Row-level security** is ENABLEd and **FORCEd** on every table with a `tenant_id`, and
  every revision that adds such a table applies it (`backend/store.py`, the
  `tenant_isolation` policies). FORCE applies the policies to the owner too. Each
  transaction states its scope: a workspace (`app.tenant_id`), or one named platform
  purpose (`app.platform`, such as migration or backup). A table admits only the purposes
  `backend/store.py` lists for it. `tests/test_tenant_rls.py` and `tests/test_platform_scope.py`
  pin this, and `/api/ready` warns if a tenant table lacks its foreign key or RLS.
* Backups (`main.py backup create`) run `pg_dump` under the backup purpose with row security
  on. The rows travel as `INSERT`s, because PostgreSQL does not load `COPY` data into a table
  with row-level security. `DSPM_BACKUP_DB_URL` can name a separate role for this.
* **Split roles (optional, advanced).** `scripts/db_roles.py` converges a four-role model:
  `sentro_owner` (owns the tables, runs migrations), `sentro_app` (DML only),
  `sentro_backup` (read-only, for pg_dump) and `sentro_readonly`. It writes evidence of the
  privilege matrix. With split roles, the application role can no longer run DDL. Every
  `migrate upgrade` (including the offline installer's) must then be run with the owner's
  URL, for example `$env:DSPM_DB_URL_FILE = '<owner url file>'` for that one command, while
  the services keep the application role's URL. It is not automated by `setup.ps1` or the
  installer.

### Write-ahead log and disk

Every scan writes WAL. With `archive_mode = on`, the archive grows until a base backup lets
you prune it. Sentro does not prune it, so schedule this. A full disk stops PostgreSQL;
Sentro pauses scans below `DSPM_MIN_FREE_DISK_MB` on its own volume. See
[database/POSTGRESQL_WAL_ARCHIVE_AND_TUNING_2026-10.md](database/POSTGRESQL_WAL_ARCHIVE_AND_TUNING_2026-10.md).

## Moving an existing SQLite store to PostgreSQL

Only for an installation whose data you are keeping. A handover or a new install starts
empty and does not need this.

```powershell
# Sentro stopped. The URL travels in this shell's environment only (the script reads
# DSPM_MIGRATE_DEST_URL or DSPM_DB_URL, never a flag).
$env:DSPM_MIGRATE_DEST_URL = (Get-Content '<db_url file>' -Raw).Trim()
.\.venv\Scripts\python.exe -m scripts.migrate_sqlite_to_postgres --source <path to dspm.sqlite> --evidence-dir <folder>
Remove-Item Env:\DSPM_MIGRATE_DEST_URL
```

It builds or verifies the destination schema with the migrations. It **empties each
destination table first** (`--no-truncate` keeps what is there), copies every application
table in foreign-key order in batches, and refuses a source whose rows name a workspace
that no longer exists. It reconciles row counts per table and per workspace, and writes a
JSON reconciliation report (no credentials, no data). The artifact folder and keys must
come with the database: the same `artifact_key`, `vault_key` and `evidence_hmac_key`.

## Test database

The test suite truncates its database before every test. On PostgreSQL it therefore
refuses to run unless `DSPM_PG_TEST_RESET=1`. Give it a database of its own, **never** the
application's:

```powershell
$env:DSPM_PG_ADMIN_URL = 'postgresql://postgres:<password>@127.0.0.1:5442/postgres'
.\.venv\Scripts\python.exe -m scripts.provision_postgres --port 5442 --db sentro_test --role sentro_test_app --url-file D:\SentroSecrets\test_db_url
Remove-Item Env:\DSPM_PG_ADMIN_URL

$env:DSPM_DB_URL = (Get-Content 'D:\SentroSecrets\test_db_url' -Raw).Trim()   # this shell only
$env:DSPM_PG_TEST_RESET = '1'
.\.venv\Scripts\python.exe -m pytest tests -q
```

Benchmarks and tests that write to PostgreSQL directly (`scripts/pg_write_bench.py`,
`scripts/pg_index_census.py`, the live database-sampling test) refuse any database that is
not a `*_test` database on the local host (`backend.db.is_disposable_test_url`). Every
PostgreSQL run writes WAL. Check free disk first.
