# Configuration

## Where settings come from

Every setting is a `DSPM_*` name (`backend/config.py`, the catalogue). Sentro resolves each
one, in this order of precedence:

1. the **process environment**;
2. the **configuration file**: TOML, `[settings]` table, named by `--config <file>` on any
   `main.py` command or by `DSPM_CONFIG_FILE`;
3. a **node profile** (`DSPM_NODE_PROFILE = "16gb"` or `"32gb"`), which fills in pools,
   workers and admission limits that neither of the above set;
4. the **default** in the code.

A name the catalogue does not know is refused, not ignored, so a typo stops the start.
`.env.example` documents every setting with its default and why it exists. A `.env` file is
**not** loaded.

```powershell
.\.venv\Scripts\python.exe main.py --config data\config\sentro.toml config check        # what is set, and from where
.\.venv\Scripts\python.exe main.py --config data\config\sentro.toml config check --all  # every setting, defaults included
```

`config check` shows secrets only as `(set)`. It exits 1 and names each problem when the
configuration would be refused.

## The configuration file

`scripts\setup.ps1` writes `data\config\sentro.toml` for a source install. The offline
package's installer writes `C:\ProgramData\Sentro\config\sentro.toml`. Neither is
overwritten later. A local (evaluation) file looks like this, with your paths:

```toml
[settings]
DSPM_ENV = "local"
DSPM_LOG_DIR = 'D:\Sentro\data\logs'
DSPM_ARTIFACT_DIR = 'D:\Sentro\data\artifacts'
DSPM_BACKUP_DIR = 'D:\Sentro\data\backups'
DSPM_REPORT_DIR = 'D:\Sentro\data\reports'
DSPM_SCAN_CACHE_DIR = 'D:\Sentro\data\cache'
DSPM_SCAN_EXECUTION = "queue"
DSPM_SECRET_KEY_FILE = 'D:\Sentro\data\secrets\secret_key'
DSPM_VAULT_KEY_FILE = 'D:\Sentro\data\secrets\vault_key'
DSPM_ARTIFACT_KEY_FILE = 'D:\Sentro\data\secrets\artifact_key'
DSPM_BACKUP_KEY_FILE = 'D:\Sentro\data\secrets\backup_key'
DSPM_EVIDENCE_HMAC_KEY_FILE = 'D:\Sentro\data\secrets\evidence_hmac_key'
DSPM_DEV_ADMIN_PASSWORD_FILE = 'D:\Sentro\data\secrets\admin_password'
DSPM_VAULT_KEYRING = 'D:\Sentro\data\secrets\vault_keyring.json'
DSPM_TRUST_FILE = 'D:\Sentro\data\trust\publishers.json'
DSPM_DB_PATH = 'D:\Sentro\data\db\dspm.sqlite'
```

Use single-quoted (literal) TOML strings for Windows paths, so the backslashes stay as they
are. Production replaces the last line with:

```toml
DSPM_ENV = "production"
DSPM_ADMIN_PASSWORD_FILE = 'D:\Sentro\data\secrets\admin_password'   # instead of DSPM_DEV_ADMIN_PASSWORD_FILE
DSPM_DB_URL_FILE = 'D:\Sentro\data\secrets\db_url'
DSPM_TRUSTED_HOSTS = "sentro.corp.example"      # the name users type, served by the reverse proxy
DSPM_TRUSTED_PROXIES = "127.0.0.1"              # the reverse proxy on this host
```

After changing the file, run `config check`, then restart Sentro (`scripts\stop.ps1` and
`scripts\start.ps1`, or `Restart-Service SentroBackend, SentroWorker`).

## Secrets

A secret is never written in the configuration file, on a command line or in a log. Each
secret setting `NAME` has a `NAME_FILE` form naming a file that holds only the value. The
file's folder must be readable by Administrators and the Sentro runtime account only.
`setup.ps1` and the installer generate the following, once, and never overwrite them:

| File (`data\secrets\`) | Setting | What it protects | If it is lost |
|---|---|---|---|
| `secret_key` | `DSPM_SECRET_KEY` | session token signatures | everyone signs in again |
| `vault_key` (and `vault_keyring.json` once rotated) | `DSPM_VAULT_KEY`, `DSPM_VAULT_KEYRING` | saved scan credentials, the directory service password, integration secrets | every saved credential must be entered again |
| `artifact_key` | `DSPM_ARTIFACT_KEY` | the encrypted report and artifact store, the scan cache | stored reports and artifacts cannot be read |
| `backup_key` | `DSPM_BACKUP_KEY` | backup sets | **backups cannot be restored** |
| `evidence_hmac_key` | `DSPM_EVIDENCE_HMAC_KEY` | value fingerprints, exact-data matching, evidence signatures | fingerprints, suppression rules and exact-match sets stop matching |
| `admin_password` | `DSPM_ADMIN_PASSWORD` (production) / `DSPM_DEV_ADMIN_PASSWORD` (local) | creates the built-in `admin` account at first start | nothing, once the account exists; production still requires the file at every start |
| `db_url` | `DSPM_DB_URL` | the PostgreSQL application role's URL, password included | provision a new password (DATABASE_SETUP.md) |

Escrow the keys (the whole `secrets` folder) off the host, apart from the backups.
`main.py vault escrow export` writes the vault key ring encrypted with a passphrase.

Without any key settings, a **local** install generates keys under the profile of the
account that runs it (`%USERPROFILE%\.dspm\`, or the `DSPM_LOCAL_*_PATH` settings) and prints
a generated administrator password once. `setup.ps1` avoids both by writing every key into
the data root. **Production** refuses to start unless every key, the administrator password
and the database URL are configured.

## Settings an operator usually sets

| Area | Settings | Notes |
|---|---|---|
| Mode | `DSPM_ENV` | `local` (default) or `production` (fail-closed checks, no OpenAPI docs, loopback only behind a proxy) |
| Database | `DSPM_DB_PATH` (SQLite), `DSPM_DB_URL_FILE` (PostgreSQL), `DSPM_DB_CONNECT_TIMEOUT`, `DSPM_DB_POOL_*`, `DSPM_DB_EXPECTED_IDENTITY` | production requires PostgreSQL; `DSPM_DB_EXPECTED_IDENTITY` pins the install to one database (value from `/api/health`) |
| Network boundary | `DSPM_TRUSTED_HOSTS`, `DSPM_TRUSTED_PROXIES`, `DSPM_CORS_ORIGINS` | production refuses empty or wildcard hosts, wildcard or `http://` origins, and a `0.0.0.0/0` proxy |
| Folders | `DSPM_ARTIFACT_DIR`, `DSPM_REPORT_DIR`, `DSPM_SCAN_CACHE_DIR`, `DSPM_BACKUP_DIR`, `DSPM_LOG_DIR`, `DSPM_DATA_DIR` | defaults are under the install's `data\` folder; `/api/ready` creates missing ones and fails if one cannot be written |
| Disk | `DSPM_MIN_FREE_DISK_MB` (2048) | scans pause below it |
| Logs | `DSPM_LOG_DIR`, `DSPM_LOG_LEVEL` (`info`), `DSPM_LOG_FORMAT` (`text` or `json`), `DSPM_LOG_MAX_MB`, `DSPM_LOG_BACKUPS` | without `DSPM_LOG_DIR`, logs go to the console only |
| Scans | `DSPM_SCAN_EXECUTION` (`inline` or `queue`), `DSPM_NODE_PROFILE`, `DSPM_PARTITION_WORKERS`, `DSPM_ANALYSIS_WORKERS` | `queue` hands scans to `main.py worker` processes, and the backend runs a scan itself if no worker takes it |
| SMB | `DSPM_SMB_REQUIRE_ENCRYPTION`, `DSPM_SMB_MAX_SESSIONS_PER_TARGET`, `DSPM_SMB_ACL_PROCESS_PATHS` | |
| WinRM | `DSPM_REQUIRE_WINRM_SSL`, `DSPM_WINRM_KERBEROS`, `DSPM_WINRM_COMMAND_TIMEOUT_SECONDS`, `DSPM_ALLOW_WINRM_ACTIVATION` | unset `DSPM_REQUIRE_WINRM_SSL` means HTTPS is required in production and HTTP is tolerated locally; Kerberos needs `pywinrm[kerberos]` |
| Sessions and passwords | `DSPM_TOKEN_TTL_SECONDS` (1800), `DSPM_REFRESH_TOKEN_TTL_SECONDS` (28800), `DSPM_SESSION_IDLE_SECONDS` (3600), `DSPM_PASSWORD_MIN_LENGTH` (12), `DSPM_MAX_SESSIONS_PER_USER` | |
| Backups | `DSPM_BACKUP_SCHEDULE_HOURS` (24), `DSPM_RETAIN_BACKUP_SETS` (7), `DSPM_BACKUP_COPY_DIR`, `DSPM_BACKUP_MAX_AGE_HOURS`, `DSPM_BACKUP_READY_MAX_AGE_HOURS`, `DSPM_PG_BIN` | `DSPM_PG_BIN` is where `pg_dump`/`pg_restore` are (default `C:\Program Files\PostgreSQL\18\bin`, else PATH) |
| Monitoring | `DSPM_METRICS_TOKEN_FILE` | the bearer token a Prometheus scraper sends to `/metrics` |
| Optional features | `DSPM_OCR_ENABLED` (needs `requirements-ocr.txt`), `DSPM_LICENCE_REQUIRED`, `DSPM_TRUST_FILE`, `DSPM_SEARCH_ENGINE` (Meilisearch) | |

## Settings production refuses

`DSPM_ALLOW_LEGACY_SHA256_PASSWORDS=1`, `DSPM_SYNC_BUILTIN_ADMIN=1`,
`DSPM_WINRM_SSL_SKIP_CA_CHECK=1`, `DSPM_PLAINTEXT_REPORT_EXPORT=1`,
`DSPM_ALLOW_DL_TOKEN_QUERY=1`, `DSPM_SCAN_CACHE_ENCRYPT=0`, a default-on switch set to
nothing, `DSPM_DEV_ADMIN_PASSWORD`, any test-suite switch, a missing key, `DSPM_CORS_ORIGINS=*`,
a non-PostgreSQL `DSPM_DB_URL`, and a remote PostgreSQL without `sslmode=verify-full` (or
`verify-ca`). The backend also refuses to start while the backup folder holds an
unencrypted database dump.

## Every setting

Generated from `backend/config.py` (the catalogue `main.py config check` enforces) and the
value `.env.example` shows. Secrets have no value here: give them as `<NAME>_FILE`.
`.env.example` explains each one.

| Setting | Type | Allowed | In .env.example |
|---|---|---|---|
| `DSPM_ACCESS_FINDINGS` | bool |  | `1` |
| `DSPM_ACCESS_MAX_PRINCIPALS` | int | 2 .. 10000 | `25` |
| `DSPM_ACL_CHANGE_RETENTION_DAYS` | int | 1 ..  | `365` |
| `DSPM_ACL_FULL_REFRESH_DAYS` | float | 0 .. 365 | `7` |
| `DSPM_ACL_REMOTE_SID_LOOKUP` | bool |  | `1` |
| `DSPM_ADMIN_PASSWORD` | secret |  | (file: DSPM_ADMIN_PASSWORD_FILE) |
| `DSPM_ALERT_DELIVERY_INTERVAL_SECONDS` | int | 1 ..  | `5` |
| `DSPM_ALERT_WEBHOOK_URL` | secret |  | (file: DSPM_ALERT_WEBHOOK_URL_FILE) |
| `DSPM_ALLOW_DL_TOKEN_QUERY` | bool |  | `0` |
| `DSPM_ALLOW_EXTERNAL_BIND` | bool |  |  |
| `DSPM_ALLOW_LEGACY_SHA256_PASSWORDS` | bool |  | `0` |
| `DSPM_ALLOW_PRIVATE_TARGETS` | bool |  |  |
| `DSPM_ALLOW_WINRM_ACTIVATION` | bool |  | `0` |
| `DSPM_ANALYSIS_WORKERS` | int | 1 ..  | `0` |
| `DSPM_API_KEYS` | secret |  | (file: DSPM_API_KEYS_FILE) |
| `DSPM_ARCHIVE_TIMEOUT_SECONDS` | float | 0 ..  | `30` |
| `DSPM_ARTIFACT_DIR` | path |  | `data/artifacts` |
| `DSPM_ARTIFACT_DL_TOKEN_TTL_SECONDS` | int | 10 ..  | `300` |
| `DSPM_ARTIFACT_KEY` | secret |  | (file: DSPM_ARTIFACT_KEY_FILE) |
| `DSPM_AUDIT_VERIFY_MAX_PER_HOUR` | int | 1 ..  | `20` |
| `DSPM_BACKUP_COPY_DIR` | path |  |  |
| `DSPM_BACKUP_DB_URL` | secret |  | (file: DSPM_BACKUP_DB_URL_FILE) |
| `DSPM_BACKUP_DIR` | path |  | `data/backups` |
| `DSPM_BACKUP_KEY` | secret |  | (file: DSPM_BACKUP_KEY_FILE) |
| `DSPM_BACKUP_MAX_AGE_HOURS` | float | 0 ..  | `26` |
| `DSPM_BACKUP_READY_MAX_AGE_HOURS` | float | 0 ..  | `48` |
| `DSPM_BACKUP_SCHEDULE_HOURS` | float | 0 .. 744 | `24` |
| `DSPM_BREACHED_PASSWORDS_FILE` | path |  |  |
| `DSPM_CONFIG_FILE` | path |  |  |
| `DSPM_CORS_ORIGINS` | str |  |  |
| `DSPM_COUNTS_RECONCILE_SECONDS` | int | 0 ..  | `86400` |
| `DSPM_CREDENTIAL_ROTATION_DAYS` | int | 1 .. 3650 | `90` |
| `DSPM_DATA_DIR` | path |  | `data` |
| `DSPM_DB_ACTIVITY_MONITORING` | bool |  | `0` |
| `DSPM_DB_ACTIVITY_MONITORING_REQUIRED` | bool |  | `0` |
| `DSPM_DB_CONNECT_TIMEOUT` | int | 1 .. 600 | `10` |
| `DSPM_DB_EVIDENCE_SIGNING_KEY` | secret |  | (file: DSPM_DB_EVIDENCE_SIGNING_KEY_FILE) |
| `DSPM_DB_EXPECTED_IDENTITY` | str |  |  |
| `DSPM_DB_PATH` | path |  | `data/dspm.sqlite` |
| `DSPM_DB_POOL_CHECK` | bool |  | `1` |
| `DSPM_DB_POOL_MAX` | int | 1 ..  | `10` |
| `DSPM_DB_POOL_MAX_API` | int | 1 .. 200 | `8` |
| `DSPM_DB_POOL_MAX_HEAVY` | int | 1 .. 200 | `2` |
| `DSPM_DB_POOL_MAX_IDLE` | int | 0 ..  | `300` |
| `DSPM_DB_POOL_MIN` | int | 0 ..  | `1` |
| `DSPM_DB_URL` | secret |  | (file: DSPM_DB_URL_FILE) |
| `DSPM_DEMO_ASSETS_IN_INVENTORY` | bool |  | `0` |
| `DSPM_DETECTOR_POOL_IDLE_SECONDS` | float | 0 ..  | `60` |
| `DSPM_DETECTOR_POOL_MIN_KIB` | int | 0 ..  | `64` |
| `DSPM_DETECTOR_POOL_SHARED` | bool |  | `1` |
| `DSPM_DETECTOR_POOL_START_AFTER` | int | 0 ..  | `96` |
| `DSPM_DETECTOR_PREFILTER` | bool |  | `1` |
| `DSPM_DETECTOR_PROCESSES` | int | 0 ..  |  |
| `DSPM_DEV_ADMIN_PASSWORD` | secret |  | (file: DSPM_DEV_ADMIN_PASSWORD_FILE) |
| `DSPM_DIRECTORY_REVALIDATE_SECONDS` | int | 60 .. 3600 | `900` |
| `DSPM_DOCUMENT_SCAN_MAX_BYTES` | int | 1 ..  |  |
| `DSPM_EDM_MAX_ROWS` | int | 1 ..  | `250000` |
| `DSPM_ENDPOINT_FETCH_BATCH_BYTES` | int | 1024 ..  | `16777216` |
| `DSPM_ENDPOINT_MAX_FILE_TEXT_BYTES` | int | 1024 ..  | `5242880` |
| `DSPM_ENDPOINT_PAGE_FOLDERS` | int | 1 .. 10000 | `500` |
| `DSPM_ENV` | enum | local / development / dev / test / production / prod | `production` |
| `DSPM_EVIDENCE_HMAC_KEY` | secret |  | (file: DSPM_EVIDENCE_HMAC_KEY_FILE) |
| `DSPM_EXPORT_BATCH_SIZE` | int | 1 ..  | `1000` |
| `DSPM_FILE_DEADLINE_SECONDS` | int | 0 .. 3600 | `120` |
| `DSPM_FINDING_INDEX_KEEP_SCANS` | int | 0 .. 1000 |  |
| `DSPM_GDPR_DETECTOR_TIMEOUT_SECONDS` | float | 0 ..  |  |
| `DSPM_GRAPH_AUTHORITY` | str |  | `https://login.microsoftonline.com` |
| `DSPM_GRAPH_CA_FILE` | path |  |  |
| `DSPM_GRAPH_DOWNLOAD_HOSTS` | str |  |  |
| `DSPM_GRAPH_ENDPOINT` | str |  | `https://graph.microsoft.com` |
| `DSPM_HASH_POLICY` | enum | meta / sampled / full | `meta` |
| `DSPM_HOST_IO_BUDGET` | int | 1 ..  | `0` |
| `DSPM_INDEXER_PRINCIPALS` | str |  |  |
| `DSPM_INFRA_RETRIES` | int | 1 .. 20 | `4` |
| `DSPM_INFRA_RETRY_SECONDS` | float | 0 .. 30 | `2` |
| `DSPM_INVENTORY_BENCHMARK_ALLOW_WRITE` | bool |  |  |
| `DSPM_INVENTORY_COUNT_CACHE_SECONDS` | int | 0 ..  | `5` |
| `DSPM_INVENTORY_FACETS_CACHE_SECONDS` | int | 0 ..  | `30` |
| `DSPM_IN_FLIGHT_MB` | int | 16 .. 65536 | `512` |
| `DSPM_IO_WORKERS` | int | 1 ..  | `0` |
| `DSPM_JOB_HEARTBEAT_SECONDS` | float | 1 ..  | `15` |
| `DSPM_JOB_RETENTION_SECONDS` | int | 0 ..  |  |
| `DSPM_JOB_STALE_SECONDS` | int | 30 ..  | `120` |
| `DSPM_JOB_WORKERS` | int | 1 ..  |  |
| `DSPM_JSON_COMPRESS_MIN` | int | 0 ..  | `2048` |
| `DSPM_LICENCE_GRACE_DAYS` | int | 0 ..  | `14` |
| `DSPM_LICENCE_REQUIRED` | bool |  | `0` |
| `DSPM_LIVE_CACHE` | bool |  | `1` |
| `DSPM_LIVE_CACHE_PARTITION_SECONDS` | float | 0 ..  | `15` |
| `DSPM_LIVE_CACHE_SECONDS` | int | 0 ..  | `30` |
| `DSPM_LOCAL_ACL` | bool |  | `1` |
| `DSPM_LOCAL_ARTIFACT_KEY_PATH` | path |  | `~/.dspm/artifact_key` |
| `DSPM_LOCAL_BACKUP_KEY_PATH` | path |  |  |
| `DSPM_LOCAL_EVIDENCE_KEY_PATH` | path |  |  |
| `DSPM_LOCAL_JWT_SECRET_PATH` | path |  |  |
| `DSPM_LOCAL_VAULT_KEY_PATH` | path |  |  |
| `DSPM_LOGIN_IP_MAX_ATTEMPTS` | int | 1 ..  | `30` |
| `DSPM_LOGIN_MAX_ATTEMPTS` | int | 1 ..  | `5` |
| `DSPM_LOGIN_WINDOW_SECONDS` | int | 1 ..  | `300` |
| `DSPM_LOG_BACKUPS` | int | 1 .. 100 |  |
| `DSPM_LOG_DIR` | path |  |  |
| `DSPM_LOG_FORMAT` | enum | text / json | `text` |
| `DSPM_LOG_LEVEL` | enum | debug / info / warning / error | `INFO` |
| `DSPM_LOG_MAX_MB` | int | 1 .. 1024 |  |
| `DSPM_MAINTAINED_COUNTS` | bool |  | `1` |
| `DSPM_MAX_BODY_BYTES` | int | 1024 ..  | `26214400` |
| `DSPM_MAX_JOBS_PER_TENANT` | int | 1 ..  |  |
| `DSPM_MAX_JOBS_TOTAL` | int | 1 ..  |  |
| `DSPM_MAX_JOB_RESULT_FILES` | int | 1 ..  |  |
| `DSPM_MAX_RUNNING_SCANS` | int | 1 .. 64 | `2` |
| `DSPM_MAX_SESSIONS_PER_USER` | int | 1 ..  | `16` |
| `DSPM_MEILISEARCH_API_KEY` | secret |  | (file: DSPM_MEILISEARCH_API_KEY_FILE) |
| `DSPM_MEILISEARCH_INDEX` | str |  | `sentro_assets_v1` |
| `DSPM_MEILISEARCH_URL` | str |  |  |
| `DSPM_METRICS_TOKEN` | secret |  | (file: DSPM_METRICS_TOKEN_FILE) |
| `DSPM_MIGRATE_DEST_URL` | secret |  | (file: DSPM_MIGRATE_DEST_URL_FILE) |
| `DSPM_MIN_FREE_DISK_MB` | int | 0 ..  | `2048` |
| `DSPM_ML_NER_ENABLED` | bool |  | `0` |
| `DSPM_NIST_DETECTOR_TIMEOUT_SECONDS` | float | 0 ..  |  |
| `DSPM_NODE_PROFILE` | enum |  / 16gb / 32gb |  |
| `DSPM_NORMALIZED_WRITE_BEST_EFFORT` | bool |  | `0` |
| `DSPM_OCR_CACHE_MAX` | int | 0 ..  | `1024` |
| `DSPM_OCR_ENABLED` | bool |  | `0` |
| `DSPM_OCR_INTRA_OP_THREADS` | int | 1 ..  | `0` |
| `DSPM_OCR_MAX_CHARS` | int | 1 ..  | `120000` |
| `DSPM_OCR_MAX_DIMENSION` | int | 1 ..  | `2600` |
| `DSPM_OCR_MAX_FILE_BYTES` | int | 1 ..  | `26214400` |
| `DSPM_OCR_MAX_PIXELS` | int | 1 ..  | `40000000` |
| `DSPM_OCR_MIN_CONFIDENCE` | float | 0 .. 1 | `0.3` |
| `DSPM_OCR_TIMEOUT_SECONDS` | float | 0 ..  | `20` |
| `DSPM_OPS_ALERT_INTERVAL_SECONDS` | int | 30 ..  | `300` |
| `DSPM_PARTITIONED_SCANS` | bool |  |  |
| `DSPM_PARTITION_LEASE_SECONDS` | int | 5 ..  | `300` |
| `DSPM_PARTITION_MAX_ATTEMPTS` | int | 1 ..  | `3` |
| `DSPM_PARTITION_MAX_BYTES` | int | 1 ..  | `536870912` |
| `DSPM_PARTITION_MAX_FILES` | int | 1 ..  | `2000` |
| `DSPM_PARTITION_MAX_SECONDS` | int | 0 .. 86400 |  |
| `DSPM_PARTITION_RETRY_SECONDS` | int | 0 .. 900 | `30` |
| `DSPM_PARTITION_WORKERS` | int | 1 .. 8 | `1` |
| `DSPM_PASSWORD_CHANGE_MAX_FAILURES` | int | 1 ..  | `5` |
| `DSPM_PASSWORD_MIN_LENGTH` | int | 8 .. 128 | `12` |
| `DSPM_PBKDF2_ROUNDS` | int | 210000 .. 1200000 |  |
| `DSPM_PG_ADMIN_URL` | secret |  | (file: DSPM_PG_ADMIN_URL_FILE) |
| `DSPM_PG_API_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS` | int | 0 .. 86400 | `60` |
| `DSPM_PG_API_LOCK_TIMEOUT_SECONDS` | int | 0 .. 86400 | `5` |
| `DSPM_PG_API_STATEMENT_TIMEOUT_SECONDS` | int | 0 .. 86400 | `30` |
| `DSPM_PG_APP_PASSWORD` | secret |  | (file: DSPM_PG_APP_PASSWORD_FILE) |
| `DSPM_PG_APP_ROLE` | str |  | `sentro_app` |
| `DSPM_PG_BIN` | path |  |  |
| `DSPM_PG_DATA_DIR` | path |  |  |
| `DSPM_PG_DB` | str |  | `sentro` |
| `DSPM_PG_HEAVY_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS` | int | 0 .. 86400 | `300` |
| `DSPM_PG_HEAVY_LOCK_TIMEOUT_SECONDS` | int | 0 .. 86400 | `10` |
| `DSPM_PG_HEAVY_STATEMENT_TIMEOUT_SECONDS` | int | 0 .. 86400 | `300` |
| `DSPM_PG_HOST` | str |  | `127.0.0.1` |
| `DSPM_PG_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS` | int | 0 .. 86400 | `1800` |
| `DSPM_PG_LOCK_TIMEOUT_SECONDS` | int | 0 .. 86400 | `900` |
| `DSPM_PG_PORT` | int | 1 .. 65535 | `5432` |
| `DSPM_PG_SSLMODE` | enum | disable / allow / prefer / require / verify-ca / verify-full |  |
| `DSPM_PG_STATEMENT_TIMEOUT_SECONDS` | int | 0 .. 86400 | `900` |
| `DSPM_PG_SUPERUSER_PASSWORD` | secret |  | (file: DSPM_PG_SUPERUSER_PASSWORD_FILE) |
| `DSPM_PIPELINE_BUFFER` | int | 1 ..  | `0` |
| `DSPM_PIPELINE_ENABLED` | bool |  | `1` |
| `DSPM_PLAINTEXT_REPORT_EXPORT` | bool |  | `0` |
| `DSPM_PREFLIGHT_DB_KIB_PER_FILE` | int | 0 ..  | `32` |
| `DSPM_PREFLIGHT_LOCAL_KIB_PER_FILE` | int | 0 ..  | `8` |
| `DSPM_PREFLIGHT_WAL_KIB_PER_FILE` | int | 0 ..  | `32` |
| `DSPM_QUEUE_STUCK_MINUTES` | int | 0 ..  | `30` |
| `DSPM_RAW_EVIDENCE_PREVIEW` | bool |  |  |
| `DSPM_READINESS_CACHE_SECONDS` | int | 0 ..  | `60` |
| `DSPM_READ_FROM_NORMALIZED` | bool |  |  |
| `DSPM_REFRESH_MAX_FAILURES` | int | 1 ..  | `30` |
| `DSPM_REFRESH_TOKEN_TTL_SECONDS` | int | 60 ..  | `28800` |
| `DSPM_REGISTER_MAX_FAILURES` | int | 1 ..  | `10` |
| `DSPM_REPORT_ARTIFACTS` | bool |  | `1` |
| `DSPM_REPORT_BODY_MAX_BYTES` | int | 1 ..  | `16777216` |
| `DSPM_REPORT_DIR` | path |  | `data/reports` |
| `DSPM_REPORT_MAX_ROWS` | int | 1 .. 50000 | `2000` |
| `DSPM_REQUIRE_WINRM_SSL` | bool |  | `1` |
| `DSPM_RETAIN_ALERT_DAYS` | int | 0 ..  |  |
| `DSPM_RETAIN_AUDIT_DAYS` | int | 0 ..  |  |
| `DSPM_RETAIN_BACKUP_DAYS` | int | 0 ..  | `0` |
| `DSPM_RETAIN_BACKUP_SETS` | int | 1 .. 1000 | `7` |
| `DSPM_RETAIN_REPORT_FILE_DAYS` | int | 0 ..  | `90` |
| `DSPM_RETENTION_INTERVAL_SECONDS` | int | 0 ..  | `86400` |
| `DSPM_RETENTION_PRUNE_ARTIFACTS` | bool |  | `1` |
| `DSPM_REVEAL_MAX_PER_HOUR` | int | 1 .. 1000 | `20` |
| `DSPM_SCAN_BREAKER_SECONDS` | int | 0 .. 86400 | `300` |
| `DSPM_SCAN_CACHE_DIR` | path |  |  |
| `DSPM_SCAN_CACHE_ENCRYPT` | bool |  | `1` |
| `DSPM_SCAN_EXECUTION` | enum | inline / queue | `inline` |
| `DSPM_SCAN_HEARTBEAT_SECONDS` | int | 1 ..  | `2` |
| `DSPM_SCAN_MAX_SECONDS` | int | 0 ..  | `1800` |
| `DSPM_SCAN_QUEUE_MAX_SECONDS` | int | 0 ..  | `86400` |
| `DSPM_SCAN_REPORT_ROWS_CACHE` | int | 0 ..  | `4` |
| `DSPM_SCAN_RESUME_INTERVAL_SECONDS` | int | 0 ..  | `60` |
| `DSPM_SCAN_RETENTION_PER_LABEL` | int | 1 .. 1000 | `3` |
| `DSPM_SCAN_RUN_VIEW_MAX_FILES` | int | 1 .. 10000000 | `20000` |
| `DSPM_SCAN_SCHEDULER_INTERVAL_SECONDS` | int | 0 ..  | `30` |
| `DSPM_SCAN_SLA_SECONDS` | int | 0 ..  | `0` |
| `DSPM_SCAN_STALL_SECONDS` | int | 0 ..  |  |
| `DSPM_SCHEMA_CHECK_SECONDS` | int | 5 .. 3600 | `30` |
| `DSPM_SEARCH_BATCH_SIZE` | int | 1 ..  | `500` |
| `DSPM_SEARCH_BENCHMARK_ALLOW_WRITE` | bool |  |  |
| `DSPM_SEARCH_DUAL_WRITE` | bool |  | `1` |
| `DSPM_SEARCH_ENGINE` | enum |  / database / meilisearch | `database` |
| `DSPM_SEARCH_READ_ENABLED` | bool |  | `0` |
| `DSPM_SEARCH_RECONCILE_REPAIR` | bool |  | `1` |
| `DSPM_SEARCH_RECONCILE_SECONDS` | int | 0 ..  | `300` |
| `DSPM_SEARCH_TIMEOUT_SECONDS` | float | 0 ..  | `2` |
| `DSPM_SECRET_KEY` | secret |  | (file: DSPM_SECRET_KEY_FILE) |
| `DSPM_SESSION_IDLE_SECONDS` | int | 0 ..  | `3600` |
| `DSPM_SESSION_TOUCH_SECONDS` | int | 1 ..  | `60` |
| `DSPM_SIEM_CA_FILE` | path |  |  |
| `DSPM_SIEM_FORMAT` | enum | cef / json | `cef` |
| `DSPM_SIEM_INTERVAL_SECONDS` | int | 1 ..  | `2` |
| `DSPM_SIEM_URL` | str |  |  |
| `DSPM_SLOW_QUERY_MEAN_MS` | float | 0 ..  | `250` |
| `DSPM_SMB_ACL_BATCH` | bool |  | `1` |
| `DSPM_SMB_ACL_BATCH_SIZE` | int | 1 ..  | `32` |
| `DSPM_SMB_ACL_BATCH_TIMEOUT_SECONDS` | float | 1 ..  |  |
| `DSPM_SMB_ACL_PROCESS_PATHS` | int | 1 .. 5000 | `500` |
| `DSPM_SMB_ALLOW_SERVICE_IDENTITY` | bool |  | `1 (no password is handled; the service account must be` |
| `DSPM_SMB_CAPTURE_BUDGET_MB` | int | 16 ..  | `256` |
| `DSPM_SMB_FILE_PARALLEL` | int | 1 ..  | `1` |
| `DSPM_SMB_MAX_MBPS` | float | 0 ..  | `0` |
| `DSPM_SMB_MAX_SESSIONS_PER_TARGET` | int | 1 ..  | `8` |
| `DSPM_SMB_PARALLEL` | int | 1 ..  | `1` |
| `DSPM_SMB_READ_OFFLINE` | bool |  | `0` |
| `DSPM_SMB_REQUIRE_ENCRYPTION` | bool |  | `0` |
| `DSPM_SMB_SHARE_DELETE` | bool |  | `1` |
| `DSPM_SMB_SINGLE_PASS` | bool |  | `0 for the independent readers while diagnosing an unusual` |
| `DSPM_SQLITE_CACHE_KB` | int |  |  |
| `DSPM_SQLITE_HOLD_OPEN` | bool |  | `1` |
| `DSPM_SQLITE_JOURNAL_MODE` | enum | wal / delete / truncate | `wal` |
| `DSPM_SQLITE_MMAP_MB` | int | 0 ..  |  |
| `DSPM_SQLITE_WAL_LIMIT_MB` | int | 0 ..  | `64` |
| `DSPM_STORE_REPORT_BODY` | bool |  | `0` |
| `DSPM_SYNC_BUILTIN_ADMIN` | bool |  | `0` |
| `DSPM_TENANT_EXISTS_CACHE_SECONDS` | int | 0 ..  | `30` |
| `DSPM_TEXT_SCAN_MAX_BYTES` | int | 1 ..  |  |
| `DSPM_TICKET_SYNC_SECONDS` | int | 30 ..  | `300` |
| `DSPM_TOKEN_REVOCATION_CACHE_SECONDS` | int | 0 ..  | `30` |
| `DSPM_TOKEN_TTL_SECONDS` | int | 60 ..  | `1800` |
| `DSPM_TRIAGE_BINARY_SKIP` | bool |  | `1` |
| `DSPM_TRIAGE_ENABLED` | bool |  | `0 turns triage off; DSPM_TRIAGE_BINARY_SKIP=0 keeps the` |
| `DSPM_TRIAGE_ORDER` | str |  | `1` |
| `DSPM_TRIAGE_SAMPLE_BYTES` | int | 0 ..  | `0` |
| `DSPM_TRUSTED_HOSTS` | str |  | `dspm.example.com` |
| `DSPM_TRUSTED_PROXIES` | str |  | `127.0.0.1` |
| `DSPM_TRUST_FILE` | path |  |  |
| `DSPM_UNCHANGED_UNIT_SKIP` | bool |  | `1` |
| `DSPM_VAULT_KEY` | secret |  | (file: DSPM_VAULT_KEY_FILE) |
| `DSPM_VAULT_KEYRING` | path |  |  |
| `DSPM_WAL_ARCHIVE_DIR` | path |  |  |
| `DSPM_WAL_ARCHIVE_WARN_GB` | int | 1 ..  | `20` |
| `DSPM_WHOLE_SCAN_GUARD` | bool |  | `1` |
| `DSPM_WINRM_ACTIVATION_HTTPS` | bool |  | `0` |
| `DSPM_WINRM_COMMAND_TIMEOUT_SECONDS` | int | 0 .. 86400 | `900` |
| `DSPM_WINRM_KERBEROS` | bool |  | `0` |
| `DSPM_WINRM_PARALLEL` | int | 1 ..  | `1` |
| `DSPM_WINRM_RESPONSE_MAX_BYTES` | int | 1024 ..  | `536870912` |
| `DSPM_WINRM_SSL_SKIP_CA_CHECK` | bool |  | `0` |
| `DSPM_WINRM_WORKERS` | int | 1 ..  |  |
| `DSPM_WORK_QUEUE` | str |  | `ledger` |
