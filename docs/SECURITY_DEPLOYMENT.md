# Deploying Sentro securely

Sentro holds the most sensitive facts about a customer: where their secrets, personal data
and card numbers are, who can read them, and the credentials to look. Use this checklist for
a production deployment. Production mode (`DSPM_ENV=production`) enforces much of it by
refusing to start. The rest is the operator's.

## What production mode enforces

The backend refuses to start, and `main.py config check` names each problem, when:

* a key is missing: `DSPM_SECRET_KEY`, `DSPM_VAULT_KEY` (or its key ring),
  `DSPM_ARTIFACT_KEY`, `DSPM_BACKUP_KEY`, `DSPM_EVIDENCE_HMAC_KEY`, `DSPM_ADMIN_PASSWORD`,
  or `DSPM_DB_URL`;
* the database is SQLite, or a remote PostgreSQL is reached without a verified certificate
  (`sslmode=verify-full`/`verify-ca` with `sslrootcert`);
* the network boundary is open: an empty or wildcard `DSPM_TRUSTED_HOSTS`, a wildcard,
  local or `http://` CORS origin, a `0.0.0.0/0` trusted proxy, or no trusted proxy for the
  loopback listener. Production serves on 127.0.0.1 behind an HTTPS reverse proxy on the
  same host;
* a weakening switch is on: legacy SHA-256 passwords, administrator password resync,
  WinRM without certificate checks, plaintext report copies, download tokens in URLs, an
  unencrypted scan cache, `DSPM_DEV_ADMIN_PASSWORD`, test-suite switches;
* the backup folder holds an unencrypted database dump.

It also disables the OpenAPI pages, refuses `--reload`, and scans nothing until a workspace
lists its scan targets. Without explicit opt-in it never reconfigures an endpoint (WinRM
activation), and it requires WinRM over HTTPS.

## Secrets

* Every secret is a file named by `<NAME>_FILE`: never in the configuration file, never on
  a command line, never in a service definition, never in the machine environment (`setx`).
  `scripts/check_no_cmdline_secrets.py` guards the code against passing one on a command
  line.
* The `secrets` and `config` folders allow Administrators, SYSTEM and the runtime account
  only. `setup.ps1` and the offline installer set this. Do not widen it.
* Escrow the `secrets` folder off the host and apart from the backups. Without
  `backup_key`, backups cannot be restored. Without the vault key, saved credentials
  cannot be read.
* Rotate the vault key with `main.py vault rotate`, then `vault escrow export` and
  `vault escrow verify`. Rotating `DSPM_SECRET_KEY` signs everyone out.
* Change the generated administrator password after the first sign-in
  (`main.py admin set-password`). Create named accounts for people, or use directory
  sign-in; keep `admin` for administering the installation.
* Sentro has no second sign-in factor. It is an offline product, and this is a product
  decision. Restrict who can reach the console: the reverse proxy, firewall scope, and
  directory groups mapped to roles.

## Network

* Expose only the reverse proxy (443) with the customer's certificate
  ([deploy/reverse-proxy](../deploy/reverse-proxy/README.md)). Never expose 8000. Set
  `DSPM_TRUSTED_HOSTS` to the public name and `DSPM_TRUSTED_PROXIES` to the proxy.
* PostgreSQL: listen on 127.0.0.1 when it is on the same host (`setup_postgres.ps1` does). A
  remote server must use verified TLS and `pg_hba` limited to the Sentro host.
* List each workspace's scan targets (networks and host names) under **Security operations
  → Scan targets**. In production nothing else is scanned. A refused target is audited.
* Endpoints: WinRM over HTTPS (5986) with certificates the Sentro host trusts. Plain HTTP
  WinRM sends NTLM-protected traffic. Allow it only on a trusted network, explicitly
  (`DSPM_REQUIRE_WINRM_SSL=0`).
* File servers that require SMB encryption are scanned with the **SMB 3 encryption** option.
  `DSPM_SMB_REQUIRE_ENCRYPTION=1` requires it for every SMB scan. Without encryption,
  owners and ACLs are read through Windows' own SMB client (see the product reference).

## Least privilege

* Scan accounts: read-only on the shares in scope, never Domain Admin, and separate
  accounts for file servers and endpoints. The endpoint account follows
  [ENDPOINT_LEAST_PRIVILEGE.md](ENDPOINT_LEAST_PRIVILEGE.md). The console flags saved
  credentials that belong to privileged groups.
* Database scans get their own account with a strong password. Passwords are only offered
  over SCRAM-SHA-256.
* The PostgreSQL role is not a superuser and has no BYPASSRLS, CREATEDB or CREATEROLE.
  Row-level security is FORCEd on every workspace table
  ([DATABASE_SETUP.md](DATABASE_SETUP.md#roles-row-level-security-and-grants)).
* The offline package runs its services as virtual accounts (`NT SERVICE\...`), with change
  rights on the data root only. A source install runs as the signed-in administrator: use
  the package for an unattended production server.
* Console roles: give people the least role that does their job (viewer, auditor,
  scan_operator, analyst, admin). Evidence (previews, matched values) needs
  `evidence.view`, and revealing a value needs `evidence.reveal`. Every reveal is audited
  and rate-limited.

## Data at rest

* Reports and artifacts are encrypted (`artifact_key`), and so is the incremental scan
  cache. Backups are encrypted (`backup_key`) and verified by decrypting them.
* Plaintext report files are written only with `DSPM_PLAINTEXT_REPORT_EXPORT=1`, which
  production refuses. Old ones age out after `DSPM_RETAIN_REPORT_FILE_DAYS`.
* A backup, verify or restore stages the database in plaintext briefly, in the service
  account's temporary folder. Keep `%TEMP%` on an encrypted volume.
  [DEPLOYMENT_WINDOWS.md](DEPLOYMENT_WINDOWS.md#sensitive-data-at-rest) lists every place
  data rests.
* Encrypt the data and PostgreSQL volumes (BitLocker), and keep them off shares.

## Audit and monitoring

* Every security-relevant action is in a per-workspace audit trail with a hash chain.
  Check it with `main.py audit verify`, and forward it to a SIEM over TLS (product
  reference, *Audit trail*).
* Scrape `/metrics` with a token (`DSPM_METRICS_TOKEN_FILE`) and alert on the rules in
  `deploy/monitoring/`.
* Logs are redacted (see [OPERATIONS.md](OPERATIONS.md#logs)). Ship them, and restrict who
  can read the log folder.

## Updates and integrity

* Install only packages whose SHA-256 matches the published value. With a publisher key
  pinned (`DSPM_TRUST_FILE`), the installer verifies the publisher's Ed25519 signature
  before placing anything. Authenticode signing of the package scripts is ready but **held
  for a code-signing certificate** ([DEPLOYMENT_WINDOWS.md](DEPLOYMENT_WINDOWS.md#signing)).
* Python dependencies install from hash-pinned lock files (`--require-hashes`).

## Do not

* Do not add antivirus exclusions for Sentro or turn off Defender to make a scan or a test
  pass.
* Do not turn off row-level security, grant BYPASSRLS, or connect Sentro as a superuser.
* Do not skip TLS verification (`DSPM_WINRM_SSL_SKIP_CA_CHECK`, `sslmode=require` to a
  remote host).
* Do not copy a production database, its backups or its secrets to a test machine. The
  test suite needs its own `*_test` database.
