# Operations

Commands below are for a **source install**, run from the Sentro folder:

```powershell
$py = '.\.venv\Scripts\python.exe'; $cfg = 'data\config\sentro.toml'
```

For the **offline package**, use
`& 'C:\Program Files\Sentro\current\python\python.exe' 'C:\Program Files\Sentro\current\app\main.py' --config C:\ProgramData\Sentro\config\sentro.toml ...`
and the services, as in [DEPLOYMENT_WINDOWS.md](DEPLOYMENT_WINDOWS.md).

## Start and stop

| | Source install | Offline package |
|---|---|---|
| start | `.\scripts\start.ps1` (backend, wait for ready, then the worker) | `Start-Service SentroBackend, SentroWorker` |
| stop | `.\scripts\stop.ps1` (worker, then backend; only this install's processes) | `Stop-Service SentroWorker, SentroBackend` |
| foreground, for debugging | `& $py main.py --config $cfg serve --host 127.0.0.1 --port 8000` | - |

`start.ps1` refuses to start, and says why, when the configuration is refused, the
database schema does not match the build, or the port is in use. A scan that was running
when Sentro stopped resumes from its last finished partition, under the same job id, when
Sentro starts again.

## Health

| Endpoint | Authentication | Answers |
|---|---|---|
| `GET /api/health` | none | the process is alive; version, build, schema and database identity (non-secret) |
| `GET /api/ready` | none | `200` and `ready: true` when the database answers a read, the schema matches the build, the runtime folders are writable, and (in production) the backups are current. Otherwise `503` with `failures`. Warnings never fail it |
| `GET /metrics` | `Authorization: Bearer <DSPM_METRICS_TOKEN>` (or the installation admin) | Prometheus text: readiness, requests, queue, backups, licence, collectors |

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/ready | ConvertTo-Json -Depth 4
& $py main.py --config $cfg version
```

`/api/ready` reports each runtime folder (`artifacts`, `reports`, `scan cache`, `backups`,
`logs`) by name only; `config check` shows their paths. Alert rules for Prometheus and a
Fluent Bit example are in `deploy/monitoring/`.

## Logs

With `DSPM_LOG_DIR` set (`setup.ps1` sets `data\logs`), each process writes
`<DSPM_LOG_DIR>\backend.log` and `worker.log`, rolled at `DSPM_LOG_MAX_MB`. A source install
also keeps each process's console output (standard output and errors), where a start-up
error appears before logging is configured, in `backend.console.log` and
`worker.console.log`. Every record passes a redacting filter
(`backend/logging_setup.py`). It masks JWTs, bearer tokens, PostgreSQL URL passwords,
`password=`/`secret=`/`token=`/`api_key=`/`authorization=` values, and the configured
secret values themselves. `DSPM_LOG_FORMAT=json` writes JSON lines for a log shipper. File
contents, matched values and findings belong in the database and the encrypted artifact
store, and are not meant to appear in a log. Treat a log line that shows one as a defect.

## Built-in administrator

```powershell
& $py main.py --config $cfg admin set-password                       # asks twice
& $py main.py --config $cfg admin set-password --password-file <file>  # then delete the file
```

The policy applies (12 characters by default, `DSPM_PASSWORD_MIN_LENGTH`). Every session of
the account ends, and the change is audited. The console cannot change the built-in
account. `admin ensure` creates the account if it is missing and changes nothing
otherwise. Other users are managed in the console (**Security**).

## Backups and restore

```powershell
& $py main.py --config $cfg backup create --verify     # encrypted set: database (SQLite online backup or pg_dump) + artifact store
& $py main.py --config $cfg backup list
& $py main.py --config $cfg backup verify <manifest>
& $py main.py --config $cfg backup restore <manifest> --yes   # Sentro stopped; the replaced database is kept aside
```

The backend also takes a verified set every `DSPM_BACKUP_SCHEDULE_HOURS` (24) and keeps the
newest `DSPM_RETAIN_BACKUP_SETS` (7) verified sets. `DSPM_BACKUP_COPY_DIR` copies each
verified set off the host. **A backup is useless without `backup_key`**: escrow the
secrets folder separately. The [product reference](PRODUCT_REFERENCE.md#backups) has the
details, and [DEPLOYMENT_WINDOWS.md](DEPLOYMENT_WINDOWS.md) has key recovery.

## Upgrading

**Source install** (a newer handover or source tree):

1. `.\scripts\stop.ps1`
2. `& $py main.py --config $cfg backup create --verify`
3. Replace the code, keeping the data root (`data\`, or your `-DataRoot`) and `.venv`. For
   example, extract the new tree into a new folder and move `data\` across.
4. `.\scripts\setup.ps1`: installs the new locks, keeps the existing configuration and
   secrets, and upgrades the schema.
5. `.\scripts\start.ps1`

**Offline package:** `upgrade.ps1` stops the services, backs up, migrates, switches the
release, starts and waits for ready, and rolls back on failure (DEPLOYMENT_WINDOWS.md).

A build older than the database refuses to serve. Go back by restoring the backup taken
before the upgrade.

## Routine checks

| What | How | How often |
|---|---|---|
| readiness | `/api/ready`, or the `sentro_ready` metric | continuously |
| backups verified and copied off-host | `backup list`; `/metrics` `sentro_backup_verified_age_seconds` | daily |
| audit chains intact | `& $py main.py --config $cfg audit verify` | weekly, and before handing evidence over |
| free disk on the data and PostgreSQL volumes | `preflight.ps1`; scans pause below `DSPM_MIN_FREE_DISK_MB` | weekly |
| vault key escrow current | `vault escrow verify <file>` after every `vault rotate` | after each rotation |
| PostgreSQL WAL archive pruned (if archiving) | your DBA's base-backup schedule | per schedule |

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `start.ps1`: "the configuration is refused" | run `main.py --config <file> config check`; each `REFUSED:` line names the setting |
| `start.ps1`: "schema revision M and this build needs N" | take a backup, then `.\scripts\setup.ps1` (or `main.py migrate upgrade`); a database newer than the build needs the newer build |
| `/api/ready` 503 "database probe failed" | PostgreSQL down or unreachable (`setup_postgres.ps1 status`, `preflight.ps1`), or the URL file is wrong |
| `/api/ready` 503 "the artifacts folder is not writable" (or reports, scan cache) | the runtime account lost rights on the data root, or the volume is full or read-only |
| `/api/ready` 503 about backups (production) | the last scheduled backup failed or is too old: `backup create --verify` shows the stage that fails |
| port 8000 in use | another Sentro (`stop.ps1`) or another program; `start.ps1 -Port <n>` |
| "Python 3.12 or newer is required" | the interpreter that ran `main.py` is older; use `.venv\Scripts\python.exe` |
| `ModuleNotFoundError` | packages missing from `.venv`: run `setup.ps1` again; preflight lists what is missing |
| production start: "DSPM_ADMIN_PASSWORD must be set" | the `admin_password` file (`DSPM_ADMIN_PASSWORD_FILE`) is missing; production needs it at every start |
| a page says "Unable to load ..." | check `backend.log` for the request: a 200 there means the page failed to render, not the API |
| file-server scan: connection reset (WinError 10054) | the server requires SMB encryption: use the scan's **SMB 3 encryption** option |
| endpoint scan refused for HTTP | production requires WinRM over HTTPS (5986) with a trusted certificate; `DSPM_REQUIRE_WINRM_SSL=0` allows HTTP only on a trusted network |
| endpoint scan: access denied | the account is not a local administrator on the target, or `LocalAccountTokenFilterPolicy` blocks remote local admins (see the product reference, AD checklist) |
| scans pause | free disk below `DSPM_MIN_FREE_DISK_MB`; free space, and scans continue |
| forgotten admin password | `admin set-password` on the host (above) |

## Tests

```powershell
& $py -m pip install -r requirements-dev.txt          # pytest + the connector packages the tests import
& $py -m pytest tests -q                               # SQLite: each test its own temporary database and folders
```

The suite never touches the install's database: it uses temporary files, and on PostgreSQL
it refuses to run without `DSPM_PG_TEST_RESET=1` and a dedicated `*_test` database
([DATABASE_SETUP.md](DATABASE_SETUP.md#test-database)). Static gates:
`& $py -m pip install -r requirements-static.txt; & $py scripts\static_gate.py ruff` (also
`mypy`, `bandit`; `eslint` after `npm ci` in `frontend\`; `semgrep` in its own venv,
`requirements-semgrep.txt`). Some checks need a git checkout of the source
(`scripts/check_frontend_tokens.py` diffs against git).
