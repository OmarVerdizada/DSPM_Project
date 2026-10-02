# Installing Sentro on Windows Server (offline package)

This is the supported way to run Sentro on a customer's Windows Server: one offline
package, two Windows services, one configuration file, and nothing fetched from the
Internet. There is no Redis, Memurai, Docker or container of any kind.

| | |
|---|---|
| Host | Windows Server 2019 or 2022, x64, an administrator account for install and upgrade |
| Runtime | Python 3.14.6 (the embeddable build from python.org, carried in the package and private to the install) |
| Database | **production:** PostgreSQL (the customer's, or one on this host); **evaluation:** SQLite in the data root |
| Services | `SentroBackend` (API and console, `127.0.0.1:8000`) and `SentroWorker` (scans), automatic start, restart on failure |
| Front door | an HTTPS reverse proxy on the same host ([deploy/reverse-proxy](../deploy/reverse-proxy/README.md)) |

## What is in the package

```
sentro-<label>-win64\
  install.ps1  upgrade.ps1  uninstall.ps1      the three things an operator runs
  manifest.json      commit, schema revision, runtime, every wheel with its digest, signing status
  SHA256SUMS         the digest of every file; lib\PackageDigest.ps1 holds the digest of SHA256SUMS
  runtime\           python-3.14.6-embed-amd64.zip (digest pinned; python.exe signed by the PSF)
  wheelhouse\        every dependency as a wheel, installed with pip --no-index --require-hashes
  app\               the product source at the packaged commit (tracked files only), BUILD.json
  bin\WinSW-x64.exe  the service wrapper (WinSW 2.12.0, MIT, third_party\WinSW-LICENSE.txt)
  installer\         sentro_installer.py (run by the package's own Python at a first install),
                     upgrade-installed.ps1 (kept in every release as current\installer\upgrade.ps1)
  docs\              this file
```

The label is `r<schema revision>-<commit time>-<commit>`. Each release is placed beside
the others under the install root; `current` is a junction to the one running.

## Signing

The package is built to be Authenticode-signed: with a code-signing certificate available
to the build (`SENTRO_SIGNING_CERT_THUMBPRINT`), every script is signed, and
`lib\PackageDigest.ps1` - which names the digest of `SHA256SUMS`, which names the digest
of every file - is signed last, so one signature vouches for the whole package. The
installer then refuses any script whose signature is not valid for that certificate, and
the operator can run it under `-ExecutionPolicy AllSigned`.

**Status: HELD FOR CODE-SIGNING CERTIFICATE.** No certificate has been provided, so
packages are built unsigned and say so in `manifest.json`. The installer refuses an
unsigned package unless it is run with `-AllowUnsigned`; before doing that, compare the
package's SHA-256 (`sentro-<label>-win64.zip.sha256`) with the value published with the
release. `SHA256SUMS` detects a damaged file; only a signature proves who built it.
WinSW is not signed by its authors; its digest is pinned in the package manifest.

### The publisher's signature (D10)

Independently of Authenticode, a release is signed by its publisher with an Ed25519 key
kept offline (`scripts/sentro_sign.py`; `build_package.py --sign-key`). `SIGNATURE.json`
signs what the package is - its label, commit, build time and schema revision - and the
digest of `SHA256SUMS`, so a changed file, a rewritten `SHA256SUMS` or a manifest edited to
pass an old build off as new are all refused. `publisher.json` is the key the package says
signed it; it is **never trusted because the package carries it**.

An install trusts the publisher keys in `<DataRoot>\trust\publishers.json` (named by
`DSPM_TRUST_FILE` in the configuration) and nothing else. The key is pinned once, at the
first install, by the operator:

```powershell
# the publisher's .pub file, obtained with the release through a channel you trust
powershell -ExecutionPolicy Bypass -File .\install.ps1 ... -PublisherKeyFile D:\sentro-publisher.pub
# or, after comparing the fingerprint the installer prints with the published one
powershell -ExecutionPolicy Bypass -File .\install.ps1 ... -TrustPackagePublisher
```

An upgrade is verified with the **installed** release's verifier and the pinned key before
anything from the new package is placed; a package signed by any other key is refused,
whatever key it carries. To check a package before starting an upgrade at all - with code
that is already installed, not code from the package - run on the server:

```powershell
& "C:\Program Files\Sentro\current\python\python.exe" "C:\Program Files\Sentro\current\app\main.py" package verify --package D:\sentro-r34-...-win64
```

A package that is not publisher-signed is refused unless `-AllowUnsigned` is given (check
its SHA-256 against the published value first). **Production publisher key: HELD for the
publisher's key ceremony** - the key pair is made offline by the product owner with
`scripts/sentro_sign.py keygen`, and only its `.pub` ever leaves that machine.

## Install

From an elevated PowerShell, in the unpacked package folder:

```powershell
# production: PostgreSQL, served as https://sentro.corp.example through the reverse proxy
powershell -ExecutionPolicy Bypass -File .\install.ps1 `
    -PublicHostName sentro.corp.example `
    -DatabaseUrlFile C:\secure\sentro-db-url.txt `
    -AllowUnsigned

# evaluation: SQLite in the data root, no reverse proxy needed
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Mode evaluation -AllowUnsigned
```

Options: `-InstallRoot` (default `C:\Program Files\Sentro`), `-DataRoot` (default
`C:\ProgramData\Sentro`), `-ServicePrefix` (default `Sentro`: the services are
`<Prefix>Backend` and `<Prefix>Worker`), `-Port` (default 8000). A second, isolated
install on the same host needs only a different prefix, port and pair of roots.

What it does, in order: checks the package; locks the data root to Administrators and
SYSTEM; generates the keys and the first administrator password (one file each in
`<DataRoot>\secrets`, never overwriting an existing one); writes
`<DataRoot>\config\sentro.toml`; unpacks the runtime, installs the wheels and the
application as a new release; checks the configuration; migrates the database; registers
both services, each under its own virtual account (`NT SERVICE\<name>`, no password); gives
those accounts change rights on the data root and read-only rights on the configuration,
the secrets and the program files; starts both; and waits until `/api/ready` answers.

The database URL file is copied into the secrets folder; delete your copy afterwards. The
URL never appears on a command line, in the configuration file or in a service definition.

First sign-in: the administrator password is in `<DataRoot>\secrets\admin_password`
(readable by Administrators and the services only). Sign in as `admin`, set up two-step
sign-in (required for administrators), and change the password; the file then no longer
opens anything.

## Configuration

`<DataRoot>\config\sentro.toml` is the one configuration source:

```toml
[settings]
DSPM_ENV = "production"
DSPM_DB_URL_FILE = 'C:\ProgramData\Sentro\secrets\db_url'
DSPM_TRUSTED_HOSTS = "sentro.corp.example"
DSPM_TRUSTED_PROXIES = "127.0.0.1"
DSPM_LOG_DIR = 'C:\ProgramData\Sentro\logs'
```

Every name is a `DSPM_*` setting documented in `.env.example` (in `current\app`). The
process environment overrides the file; the file overrides the defaults. A name Sentro
does not know is refused, not ignored. Secrets are never written in the file: each secret
setting has a `<NAME>_FILE` form naming a file that holds it. In production, settings that
weaken the install are refused before anything starts - legacy password hashes,
administrator password resync, endpoint scans without certificate checks, plaintext report
copies, download tokens in URLs, `*` CORS, test switches, and a remote PostgreSQL reached
without TLS - as are missing keys.

Check it after any change (secrets are shown only as "set"):

```powershell
& 'C:\Program Files\Sentro\current\python\python.exe' 'C:\Program Files\Sentro\current\app\main.py' `
    --config C:\ProgramData\Sentro\config\sentro.toml config check
Restart-Service SentroBackend, SentroWorker
```

## PostgreSQL

Production requires PostgreSQL. Provision the database and roles with
`scripts/provision_postgres.py` and `scripts/db_roles.py` (a migration role that owns the
schema, an application role without superuser or BYPASSRLS). The URL in
`-DatabaseUrlFile` is the application role's; for a server on another host it must
verify the server's certificate (`sslmode=verify-full`, or `verify-ca`, with
`sslrootcert` naming the server's CA) - production refuses anything less, including no
`sslmode` at all (libpq then falls back to plaintext) and `require` (which accepts any
certificate). The same rule holds for `DSPM_BACKUP_DB_URL` and `DSPM_MIGRATE_DEST_URL`.
The installer runs the schema migrations; the services never change the schema.

Row-level security is FORCEd on every tenant table. Backups and restores name their
purpose (`app.platform=backup`, admitted on every table since schema revision 30) and run
with row security on; the rows travel as `INSERT`s, because PostgreSQL does not load
`COPY` data into a table with row-level security. A PostgreSQL backup taken before
revision 30 could not be taken at all; take a new one after upgrading.

## TLS

The backend has no TLS and listens on `127.0.0.1` only. Terminate HTTPS on the same host
with the reverse proxy in [deploy/reverse-proxy](../deploy/reverse-proxy/README.md) (Caddy,
nginx or IIS/ARR), using the certificate your PKI issues for `-PublicHostName`. Production
refuses to start without `DSPM_TRUSTED_HOSTS` and a trusted proxy covering the backend's
address.

## Keys, artifacts and backups

| File in `<DataRoot>\secrets` | Protects | Losing it means |
|---|---|---|
| `vault_key` | saved scan credentials | every saved credential must be entered again |
| `artifact_key` | stored report bodies (`<DataRoot>\artifacts`) | stored reports cannot be read |
| `backup_key` | backup sets (`<DataRoot>\backups`) | backups cannot be restored |
| `secret_key` | session signing | everyone signs in again |
| `evidence_hmac_key` | evidence fingerprints | fingerprints from before cannot be matched |
| `admin_password`, `db_url` | first sign-in, database access | reset from the host / re-issue the URL |

The vault key is versioned (`DSPM_VAULT_KEYRING` = `<DataRoot>\secrets\vault_keyring.json`,
created by the first rotation). Rotate it, and keep its escrow current, as an administrator:

```powershell
$app = 'C:\Program Files\Sentro\current'; $cfg = 'C:\ProgramData\Sentro\config\sentro.toml'
& "$app\python\python.exe" "$app\app\main.py" --config $cfg vault rotate
& "$app\python\python.exe" "$app\app\main.py" --config $cfg vault escrow export --out E:\escrow\sentro-keys.json
& "$app\python\python.exe" "$app\app\main.py" --config $cfg vault escrow verify E:\escrow\sentro-keys.json
```

The services keep running: the new key is active before anything is re-sealed, the ring
keeps the old one, and the re-seal is one transaction. The escrow is encrypted with a
passphrase you type (or give in `--passphrase-file`); keep the escrow and the passphrase
apart, and both apart from the backups. After losing the secrets folder, `vault escrow
recover <escrow> --out <DSPM_VAULT_KEYRING>` writes the ring back - and refuses an escrow
that cannot open what is sealed now (one exported before the last rotation; `--accept-missing`
recovers it anyway). Recovering over an existing ring needs `--force` and keeps the replaced
ring beside it. With the ring file present, `DSPM_VAULT_KEY` is no longer required: the ring
holds the keys. Key operations take a lock, so a second one started meanwhile is refused;
a value no key in the ring opens stops a rotation before anything changes (`--skip-unreadable`
leaves such values as they are and names them).

Keep an off-host copy of the secrets folder, held separately from the backups (a backup
and the key that opens it must not travel together), under the customer's key custody.
Report bodies and backups are encrypted; the database backup covers the artifact store.

```powershell
$app = 'C:\Program Files\Sentro\current'
& "$app\python\python.exe" "$app\app\main.py" --config C:\ProgramData\Sentro\config\sentro.toml backup create --verify
& "$app\python\python.exe" "$app\app\main.py" --config C:\ProgramData\Sentro\config\sentro.toml backup list
```

`backup create --verify` writes the encrypted database (SQLite online backup, or
`pg_dump` for PostgreSQL) and the artifact archive, then decrypts both into a temporary
folder and checks every digest, the integrity check and the row counts before it reports
success, and marks the set verified in its manifest. The database password is passed to
`pg_dump` through its environment, never its command line.

### Scheduled backups

The backend takes a verified set on its own every `DSPM_BACKUP_SCHEDULE_HOURS` (24), so no
Task Scheduler job is needed. The run is claimed through the database: with several
backends one of them takes it. A verified set the upgrade or an operator took counts, and a
failed run is retried after an hour. Each run is audited in the `default` workspace's trail
(`backup.created` / `backup.failed`, with the stage and the error's type - never its text, a
key or a path) and recorded as the last backup attempt, which `/metrics`
(`sentro_backup_last_attempt_success`) and the installation's own alerts read. Set
`DSPM_BACKUP_SCHEDULE_HOURS = 0` only if backups are taken some other way.

Retention follows each scheduled set: every set at least as new as the
`DSPM_RETAIN_BACKUP_SETS`-th (7) newest verified set is kept, and so is every set younger
than `DSPM_RETAIN_BACKUP_DAYS` (0, off). Until that many sets have verified, nothing is
removed - a run of failed backups never costs a set that restores.

In production `/api/ready` - which the installer, the upgrade and a load balancer wait on -
**fails** when the last backup attempt failed, or the newest verified set is older than
`DSPM_BACKUP_READY_MAX_AGE_HOURS` (48, never less than `DSPM_BACKUP_MAX_AGE_HOURS`), or no
set has verified and the database is older than that. A new install is ready before its
first backup. `DSPM_BACKUP_MAX_AGE_HOURS` (26) stays the warning and alert threshold. Fix
the backup (`backup create --verify` shows what fails) and readiness recovers by itself.

### Off-host copies and key recovery

Set `DSPM_BACKUP_COPY_DIR` to the approved off-host location, for example a share on the
backup server:

```toml
DSPM_BACKUP_COPY_DIR = '\\backup01\sentro$\prod'
```

The backend service runs as a virtual account (`NT SERVICE\SentroBackend`, or the
`-ServicePrefix` you chose), and a virtual account reaches a network share as the host's
computer account: grant `<DOMAIN>\<host>$` Modify on that share and folder, and nothing on
it to anyone the backups need not reach. After each set verifies,
its encrypted files and then its manifest are copied there. Each file is written under a
temporary name, checked against the digest its manifest records, and renamed into place,
so the location never holds a partial set. Retention applies there too. A copy that fails
is a failed backup (`backup.failed`, stage `copy`), and the local set is kept.

**No key is ever copied.** A backup set and the key that opens it must not travel together.
Recovery on a new host needs, besides a backup set:

| Key | Where it lives | How it is recovered |
|---|---|---|
| backup key (`<DataRoot>\secrets\backup_key`) | the customer's key custody (password vault, HSM, sealed envelope) | written back to `secrets\backup_key` by an administrator |
| artifact key (`secrets\artifact_key`) | the same custody | as above: the artifact objects in the set stay encrypted with it |
| vault key ring (`secrets\vault_keyring.json`) | `vault escrow export` (above), kept apart from the backups and from its passphrase | `vault escrow recover <escrow> --out <DSPM_VAULT_KEYRING>` |

Escrow the backup and artifact keys once at install (they do not rotate), and the vault
escrow after every rotation. The restore drill: on a disposable host or database, put the
escrowed keys in place, copy a set from the off-host location, and run `backup verify
<manifest>` and `backup restore <manifest> --yes`; reconcile the row counts the restore
reports and check that a stored report opens.

## Sensitive data at rest

What a scan learns - paths, owners, ACLs, previews, findings - is kept in these places.
Found values are stored masked everywhere but the moment-long temporary extraction files;
paths and owners are not masked anywhere.

| Surface | Where | At rest | How long |
|---|---|---|---|
| Database | `<DataRoot>\db` (SQLite) or PostgreSQL | not encrypted by Sentro: use BitLocker or the database server's own encryption | until erased (workspace erasure, retention for event rows) |
| Report bodies | `<DataRoot>\artifacts\<workspace>` | gzip + Fernet, `artifact_key` | removed with the workspace; unreferenced ones with `DSPM_RETENTION_PRUNE_ARTIFACTS=1` |
| Backups | `<DataRoot>\backups` | Fernet, `backup_key` | `backup create --keep N`; **production will not start beside an unencrypted dump here** |
| Scan cache | `<DataRoot>\cache\tenants\<workspace>` | sealed with `artifact_key` (`DSPM_SCAN_CACHE_ENCRYPT`, on) | removed with the workspace; rebuilt by the next scan if deleted |
| Plaintext report files | `<DataRoot>\reports\*.json` | **plaintext** - not written unless `DSPM_PLAINTEXT_REPORT_EXPORT=1` (refused in production) | deleted after `DSPM_RETAIN_REPORT_FILE_DAYS` (90; a held workspace's are kept) |
| `main.py scan --output` | wherever it is pointed | **plaintext** - refused unless `DSPM_PLAINTEXT_REPORT_EXPORT=1`, always in production | the operator's |
| Rendered reports (PDF, HTML) | `<InstallRoot>\current\app\data\reports_artifacts\<workspace>` | **plaintext**; values masked, paths reduced to file names | **kept** - not aged out, not removed by workspace erasure (see below) |
| Temporary extraction | the service account's `%TEMP%` | **plaintext** for the moment a document or image from SMB, SharePoint or SFTP is converted to text; zero-filled, then deleted (a process killed mid-file can leave one). Archive members are read in memory | seconds |
| Logs | `<DataRoot>\logs` | plaintext; secrets, tokens and passwords redacted; paths and host names can appear | `DSPM_LOG_MAX_MB` x `DSPM_LOG_BACKUPS` |

**The scan cache (C0.2).** Each entry - a findings entry per file (`<digest>.enc`) and a row
per file in `meta_index.sqlite` - is zlib-compressed and sealed with Fernet under the
artifact key, behind a format marker (`SSC1`); reads are bounded before anything is
decrypted, writes go to a private name and are renamed into place, and an entry that does
not open (another key, altered, the other format) is a miss and is replaced. Each
workspace has its own directory, so erasing a workspace removes its cache. The plaintext
cache an older release left in the cache root is deleted, by exact name, on the first
scan after the upgrade; that scan reads files again or replays them from the database
baseline, and later scans reuse as before. Changing the artifact key, or
`DSPM_SCAN_CACHE_ENCRYPT`, empties the cache the same way. Measured on 3,000 small files
(`python scripts/scan_cache_cost.py`): a cold scan, which analyses and
writes every entry, took 32.9 s sealed against 30.1 s in clear (+9.5%); an unchanged rescan,
which opens every entry and seals it again, 11.6 s against 9.3 s (+24%, on a host where two
runs of the same build differed by 21%), of which the sealing itself is about 1.3 s - 0.45 ms
per file. Sealing and opening an 11.4 KB entry costs 159 and 171 us against 60 and 30 us for
compression alone. On disk sealing adds 1.9% (26.1 MB against 25.6 MB), and the sealed cache
is 14% smaller than the plaintext one it replaces (30.5 MB), because findings entries are
compressed now too.

### Removing plaintext copies (retention procedure)

Plaintext copies made before C0.2 - a `pg_dump` left unencrypted in the backup directory,
report files in `<DataRoot>\reports`, rendered reports - are somebody's data, so Sentro does
not delete them itself, with one exception (report files older than the retention window).
An operator removes them, in this order, once a good encrypted backup exists:

1. **See what there is.** `main.py config check` names every unencrypted dump in the backup
   directory (`REFUSED: the backend will not start: ...`); `Get-ChildItem <DataRoot>\reports`
   and `<InstallRoot>\current\app\data\reports_artifacts` show the rest.
2. **Take an encrypted backup and prove it.** `main.py backup create --verify` - it is not
   refused beside the dump, because it comes first.
3. **Restore drill.** Restore that backup where it cannot harm the install: a scratch install
   with a copy of the secrets folder and its own `DSPM_DB_PATH` (SQLite), or a disposable
   PostgreSQL database. `main.py backup verify <manifest>`, then `main.py backup restore
   <manifest> --yes`, and check the workspaces and scans are there.
4. **Delete the plaintext copies.** The dumps `config check` named, the report files no
   external reader still needs, and rendered reports older than your policy. Deleting does
   not overwrite: on a disk without BitLocker the blocks stay readable until reused.
5. **Check again and start.** `main.py config check` reports the configuration valid; start
   the services. Record the deletion (what, when, who, which backup was drilled) in the
   change log.

`tests/test_c02_data_lifecycle.py::TheCleanupProcedureTest` runs steps 1-5 against a
throwaway install, including a restore after the cleanup.

Rendered reports (the PDF and HTML a user downloads) are the remaining plaintext surface
with no lifecycle: they are written under the release's own `data` folder, which cannot be
moved by configuration, so neither retention nor workspace erasure reaches them yet.
Remove them by hand in step 4 (a new release starts with none; an old release's go when it
is removed from `releases\`).

## Upgrade

Start an upgrade from the **install**, naming the new package's folder:

```powershell
& "$env:ProgramFiles\Sentro\current\installer\upgrade.ps1" -Package D:\sentro-<label>-win64
```

Everything that runs before the package is verified is code this install already verified:
that script, the installer and package checks beside it, and the running release's Python.
The package is copied to a folder only administrators can write (`<InstallRoot>\.staging`),
every file is checked against `SHA256SUMS`, and the publisher's signature against this
install's pinned key, with the running release's verifier - before any of the package's
code runs. Running the package's own `upgrade.ps1` would run the package's installer first,
and someone who can write to the folder it waits in could take the check out of it; that
script therefore refuses to run on an install that has the launcher.

An install made before the launcher existed has none, so its first upgrade runs the
package's `upgrade.ps1` - check the package's SHA-256 against the value published with the
release first. An install from before D10 has no pinned publisher key either; pin it on that
upgrade from the key file published with the release (`-PublisherKeyFile publisher.pub`).
Every later upgrade starts from the launcher that upgrade placed.

1. The new release is placed beside the running one and its configuration checked -
   nothing is stopped yet, so a bad package costs no downtime.
2. The worker, then the backend, is stopped (quiesce).
3. An encrypted backup is taken and verified. If it fails, the old release is restarted.
4. The database is migrated. Revisions apply in one transaction: if one fails, the
   database is unchanged and the old release is restarted.
5. `current` is switched to the new release; both services start; the upgrade waits for
   `/api/ready`.
6. If the new release does not become ready, the upgrade rolls back: services stop,
   `current` points at the old release again, the backup from step 3 is restored, and the
   old release is started. On PostgreSQL the restore is one transaction (`pg_restore
   --clean --single-transaction`); the database's contents it replaces are backed up first.
   Extensions (`pg_trgm`, `btree_gin`) belong to the database administrator and are left
   as they are.

A backend that is still running an older release when the database is migrated - a second
node, or a service that was not stopped - notices within `DSPM_SCHEMA_CHECK_SECONDS` (30):
its data routes answer 503 with `reason: schema_mismatch` and both revisions; readiness
answers too, and only reads. Every background writer stands down at the top of its next
pass: the scan worker, scan scheduler, scan resumer, SIEM forwarder, alert deliverer, the
installation's own alerts, the search reconciler, housekeeping and the backup schedule.
Queued work waits for the matching release, and each logs once that it paused. A pass
already under way finishes its current item. The console shows one notice: the database
was upgraded to revision N, this service runs revision M, restart the Sentro service.

The previous release stays under `releases\` for rollback; older ones are removed.
`<DataRoot>\install.json` records every install, upgrade and uninstall, with the backup
each upgrade took.

## Downgrade

A package that expects an **older schema** than the database holds is refused: the older
code cannot run on the newer schema, and running it would lose what the newer schema
holds. To go back, restore the backup that the upgrade took (at the older schema):

```powershell
& "$env:ProgramFiles\Sentro\current\installer\upgrade.ps1" -Package D:\sentro-<older label>-win64 -RestoreBackup C:\ProgramData\Sentro\backups\sentro_sqlite_<stamp>.manifest.json
```

A package at the **same** schema but an **older build** is refused too (D10): an old signed
package is still an old package, and replaying one is how a fixed vulnerability comes back.
Going back is a decision the operator states:

```powershell
& "$env:ProgramFiles\Sentro\current\installer\upgrade.ps1" -Package D:\sentro-<older label>-win64 -AllowDowngrade
```

Going back with `-RestoreBackup` is already such a statement and needs no second flag.

## Licence (D10)

A licence is a file the publisher signs with its licence key; nothing is fetched and
nothing reports back. It holds the customer, its validity dates and what it covers, and is
refused if it was altered, is signed by a key the install does not trust for licences
(`<DataRoot>\trust\publishers.json`), is not yet valid or has expired. A refused licence
never replaces the one installed.

Install it in the console (Settings -> Features -> Licence, as the installation's
administrator with two-step sign-in), or on the server. **The server path is the offline
recovery path** - it needs neither the console nor a network, only the file:

```powershell
cd "C:\Program Files\Sentro\current\app"
..\python\python.exe main.py licence install D:\contoso-2027.licence
..\python\python.exe main.py licence status
```

Whether scans need a licence is the operator's setting, `DSPM_LICENCE_REQUIRED` (off by
default). When it is on and the licence is missing or has run out, **new scans are
refused, and nothing else is**: findings, reports, exports, the audit trail and the
console stay available, and nothing is deleted. An expired licence keeps scans running for
`DSPM_LICENCE_GRACE_DAYS` (14) so a renewal can arrive; a scheduled scan that cannot start
records why on its schedule. Recovery is always the same step: install the renewal with
`main.py licence install`, and the next scan runs.

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -AllowUnsigned
```

Removes both services and the program files, and **keeps the data root** - the database,
the keys, the configuration, the backups and the logs. Installing again with the same data
root continues from them. Deleting the data needs both switches, and there is no undo:

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -RemoveData -ConfirmRemoveData Sentro -AllowUnsigned
```

## Logs

| File | What |
|---|---|
| `<DataRoot>\logs\backend.log`, `worker.log` | the services' application logs, rolled at 10 MB, 10 kept (`DSPM_LOG_MAX_MB`, `DSPM_LOG_BACKUPS`) |
| `<DataRoot>\logs\service\*` | the wrapper's own capture of each service's console output, rolled at 10 MB, 8 kept |
| `<DataRoot>\logs\installer-*.log` | each install, upgrade and uninstall |

Logs are appended across restarts. Configured secret values, bearer and signed tokens,
`password=`-style pairs and database-URL passwords are replaced with `[redacted]` before
anything is written.

## Not covered here

High availability, failover and a quarter of operating history are a separate enterprise
production gate. A clean install on a second, separate Windows Server host has not been
run from this repository (see the roadmap's C11 status); the evidence so far is from an
isolated install beside other software on the build host.
