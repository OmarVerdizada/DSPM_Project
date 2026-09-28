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
  installer\         sentro_installer.py (run by the package's own Python)
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
require TLS (`sslmode=verify-full` with the server's CA) - production refuses one that
does not. The installer runs the schema migrations; the services never change the schema.

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
recover` writes the ring back.

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
success. The database password is passed to `pg_dump` through its environment, never its
command line.

## Upgrade

In the new package's folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\upgrade.ps1 -AllowUnsigned
```

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
   old release is started. (Automatic restore covers SQLite; on PostgreSQL the services
   are left stopped with the backup named, and the restore is the documented `pg_restore`
   procedure, since it replaces the customer's database.)

The previous release stays under `releases\` for rollback; older ones are removed.
`<DataRoot>\install.json` records every install, upgrade and uninstall, with the backup
each upgrade took.

## Downgrade

A package that expects an **older schema** than the database holds is refused: the older
code cannot run on the newer schema, and running it would lose what the newer schema
holds. To go back, restore the backup that the upgrade took (at the older schema):

```powershell
powershell -ExecutionPolicy Bypass -File .\upgrade.ps1 -RestoreBackup C:\ProgramData\Sentro\backups\sentro_sqlite_<stamp>.manifest.json -AllowUnsigned
```

A package at the **same** schema installs over a newer one without a restore.

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
