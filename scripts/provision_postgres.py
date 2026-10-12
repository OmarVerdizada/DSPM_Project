"""Idempotent PostgreSQL provisioning for the Sentro DSPM store (roadmap Phase 2, M2).

Creates the least-privilege footprint the app needs and nothing more:
  * a dedicated application database (default ``sentro``),
  * a **non-superuser** login role (default ``sentro_app``) - no CREATEDB/CREATEROLE,
  * the trusted ``pg_trgm`` extension used by Track S-D inventory search,
  * ``REVOKE ALL ... FROM PUBLIC`` on the database + ``GRANT CONNECT`` to the role,
  * ``GRANT USAGE, CREATE ON SCHEMA public`` so the app owns and manages its tables.

It then writes the ``DSPM_DB_URL`` to --url-file (the output shows it with the password
hidden). Safe to re-run: every step checks
for existence first, so provisioning is convergent, not destructive.

This is the deployment-side automation for the Phase 2 acceptance criteria
("the app connects as a least-privilege role"). It talks to Postgres as an
*admin* (superuser, or any role with CREATEDB + CREATEROLE) - supply that via
--admin-url / DSPM_PG_ADMIN_URL. It never needs, sees, or stores the admin
password beyond the single connection.

Secrets never go on the command line: the admin URL comes from DSPM_PG_ADMIN_URL and an
operator-chosen app password from DSPM_PG_APP_PASSWORD (both process environment), and the
resulting URL is written to --url-file, never printed. See docs/DATABASE_SETUP.md.

Examples (PowerShell)
---------------------
PostgreSQL on this host (scripts/setup_postgres.ps1 runs exactly this):
    $env:DSPM_PG_ADMIN_URL = 'postgresql://postgres:<pw>@127.0.0.1:5432/postgres'
    python -m scripts.provision_postgres --port 5432 --url-file C:\\SentroSecrets\\db_url

A remote server (TLS with a verified certificate, as production requires):
    $env:DSPM_PG_ADMIN_URL = 'postgresql://postgres:<pw>@db01.corp.example:5432/postgres?sslmode=verify-full&sslrootcert=C:/certs/ca.pem'
    python -m scripts.provision_postgres --host db01.corp.example --sslmode verify-full --url-file C:\\SentroSecrets\\db_url
    (then add &sslrootcert=... to the URL in the file, naming the CA on the Sentro host)
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path
from urllib.parse import quote

try:
    import psycopg
except Exception:  # pragma: no cover - clear operator guidance
    print(
        "psycopg is required. Install the Postgres extra:\n"
        "    pip install -r requirements-postgres.txt",
        file=sys.stderr,
    )
    raise SystemExit(2)


def _identifier(name: str) -> str:
    """Validate a SQL identifier (we interpolate role/db names, which cannot be
    parameterized). Restrict to a conservative charset so this can never inject."""
    if not name or not all(c.isalnum() or c == "_" for c in name) or name[0].isdigit():
        raise SystemExit(f"Invalid identifier {name!r}: use [A-Za-z_][A-Za-z0-9_]*")
    return name


def _quote_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def provision(admin_url: str, db: str, role: str, password: str) -> None:
    db = _identifier(db)
    role = _identifier(role)

    # CREATE DATABASE cannot run inside a transaction block -> autocommit.
    with psycopg.connect(admin_url, autocommit=True) as conn:
        exists = conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (db,)).fetchone()
        if exists:
            print(f"= database {db} already exists")
        else:
            conn.execute(f"CREATE DATABASE {db}")
            print(f"+ created database {db}")

        role_exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
        if role_exists:
            print(f"= role {role} already exists (password left unchanged)")
        else:
            conn.execute(f"CREATE ROLE {role} LOGIN PASSWORD {_quote_literal(password)}")
            print(f"+ created least-privilege role {role} (NOSUPERUSER NOCREATEDB NOCREATEROLE)")

        # Least privilege at the database level.
        conn.execute(f"REVOKE ALL ON DATABASE {db} FROM PUBLIC")
        conn.execute(f"GRANT CONNECT ON DATABASE {db} TO {role}")
        print(f"= revoked PUBLIC, granted CONNECT on {db} to {role}")

    # Schema-level grant must be issued while connected to the target database.
    db_admin_url = _swap_dbname(admin_url, db)
    with psycopg.connect(db_admin_url, autocommit=True) as conn:
        # Track S-D: pg_trgm preserves the inventory API's literal substring
        # semantics (including path fragments) while allowing a GIN index to
        # serve ``LIKE '%query%'``.  Install it as the provisioning/admin role;
        # the runtime app role intentionally has no extension-management power.
        conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
        print("= pg_trgm extension ready (Track S-D inventory search)")
        # Phase 7 combines equality filters and trigrams in one access path.
        conn.execute("CREATE EXTENSION IF NOT EXISTS btree_gin")
        print("= btree_gin extension ready (Phase 7 filtered search)")

        conn.execute(f"GRANT USAGE, CREATE ON SCHEMA public TO {role}")
        print(f"= granted USAGE, CREATE ON SCHEMA public to {role}")

        # Verify the role really is unprivileged (defence in depth against a typo).
        row = conn.execute(
            "SELECT rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = %s",
            (role,),
        ).fetchone()
        if row and any(row):
            raise SystemExit(f"! role {role} is not least-privilege: {row!r}")
    print(f"= verified {role} is NOT superuser / createdb / createrole")


def _swap_dbname(url: str, db: str) -> str:
    """Return ``url`` with its database (path) replaced by ``db``, preserving query."""
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "/" + db, parts.query, parts.fragment))


def build_app_url(host: str, port: int, db: str, role: str, password: str, sslmode: str | None) -> str:
    auth = role if not password else f"{role}:{quote(password)}"
    url = f"postgresql://{auth}@{host}:{port}/{db}"
    if sslmode:
        url += f"?sslmode={sslmode}"
    return url


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Provision the Sentro DSPM PostgreSQL store (idempotent).")
    ap.add_argument("--admin-url", default=os.getenv("DSPM_PG_ADMIN_URL"),
                    help="libpq URL for an admin (superuser or CREATEDB+CREATEROLE). Env: DSPM_PG_ADMIN_URL")
    ap.add_argument("--db", default=os.getenv("DSPM_PG_DB", "sentro"), help="application database name")
    ap.add_argument("--role", default=os.getenv("DSPM_PG_APP_ROLE", "sentro_app"), help="application login role")
    ap.add_argument("--password", default=os.getenv("DSPM_PG_APP_PASSWORD"),
                    help="password for the app role (generated if omitted on first create). Env: DSPM_PG_APP_PASSWORD")
    ap.add_argument("--host", default=os.getenv("DSPM_PG_HOST", "127.0.0.1"), help="host for the emitted DSPM_DB_URL")
    ap.add_argument("--port", type=int, default=int(os.getenv("DSPM_PG_PORT", "5432")), help="port for the emitted DSPM_DB_URL")
    ap.add_argument("--sslmode", default=os.getenv("DSPM_PG_SSLMODE"),
                    help="sslmode for the emitted URL (verify-full for a remote server)")
    ap.add_argument("--url-file", default="",
                    help="write the application's DSPM_DB_URL (password included) to this file, for "
                         "DSPM_DB_URL_FILE; the output only ever shows it with the password hidden")
    args = ap.parse_args(argv)

    if not args.admin_url:
        ap.error("--admin-url (or DSPM_PG_ADMIN_URL) is required")

    password = args.password
    generated = False
    if not password:
        if not args.url_file:
            ap.error("give --url-file (or the app role's password in DSPM_PG_APP_PASSWORD): a generated "
                     "password must be written somewhere other than the screen")
        password = "Sp" + secrets.token_urlsafe(18)  # letters+digits, satisfies typical policies
        generated = True

    provision(args.admin_url, args.db, args.role, password)

    app_url = build_app_url(args.host, args.port, args.db, args.role, password, args.sslmode)
    shown = build_app_url(args.host, args.port, args.db, args.role, "***" if password else "", args.sslmode)
    print(f"\nProvisioning complete. DSPM_DB_URL: {shown}")
    if args.url_file:
        target = Path(args.url_file)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(app_url + "\n", encoding="utf-8")
        _restrict_file(target)
        print(f"The full URL is in {target} (Administrators and SYSTEM only): point DSPM_DB_URL_FILE at it,")
        print("or give it to scripts\\setup.ps1 -DatabaseUrlFile / packaging\\windows\\install.ps1 -DatabaseUrlFile.")
    if generated:
        print("A password was generated for the app role; it is only in that file.")
    return 0


def _restrict_file(path: Path) -> None:
    """Administrators and SYSTEM only (Windows); the owner only elsewhere."""
    if os.name != "nt":
        path.chmod(0o600)
        return
    import subprocess

    subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", "*S-1-5-32-544:F", "/grant:r", "*S-1-5-18:F"],
                   capture_output=True, text=True, check=True)


if __name__ == "__main__":
    raise SystemExit(main())
