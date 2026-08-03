"""Idempotent PostgreSQL provisioning for the Sentro DSPM store (roadmap Phase 2, M2).

Creates the least-privilege footprint the app needs and nothing more:
  * a dedicated application database (default ``sentro_dev``),
  * a **non-superuser** login role (default ``sentro_app``) - no CREATEDB/CREATEROLE,
  * ``REVOKE ALL ... FROM PUBLIC`` on the database + ``GRANT CONNECT`` to the role,
  * ``GRANT USAGE, CREATE ON SCHEMA public`` so the app owns and manages its tables.

It then prints the ``DSPM_DB_URL`` to export. Safe to re-run: every step checks
for existence first, so provisioning is convergent, not destructive.

This is the deployment-side automation for the Phase 2 acceptance criteria
("the app connects as a least-privilege role"). It talks to Postgres as an
*admin* (superuser, or any role with CREATEDB + CREATEROLE) - supply that via
--admin-url / DSPM_PG_ADMIN_URL. It never needs, sees, or stores the admin
password beyond the single connection.

Examples
--------
Local trust-auth dev cluster on port 5441 (as created by scripts/pg_dev_cluster.ps1):
    python -m scripts.provision_postgres --admin-url postgresql://postgres@127.0.0.1:5441/postgres

Production (admin over TLS), app password from the environment:
    export DSPM_PG_ADMIN_URL='postgresql://postgres@db.internal:5432/postgres?sslmode=require'
    export DSPM_PG_APP_PASSWORD='<strong-secret>'
    python -m scripts.provision_postgres --host db.internal --sslmode require
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
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
    ap.add_argument("--db", default=os.getenv("DSPM_PG_DB", "sentro_dev"), help="application database name")
    ap.add_argument("--role", default=os.getenv("DSPM_PG_APP_ROLE", "sentro_app"), help="application login role")
    ap.add_argument("--password", default=os.getenv("DSPM_PG_APP_PASSWORD"),
                    help="password for the app role (generated if omitted on first create). Env: DSPM_PG_APP_PASSWORD")
    ap.add_argument("--host", default=os.getenv("DSPM_PG_HOST", "127.0.0.1"), help="host for the emitted DSPM_DB_URL")
    ap.add_argument("--port", type=int, default=int(os.getenv("DSPM_PG_PORT", "5432")), help="port for the emitted DSPM_DB_URL")
    ap.add_argument("--sslmode", default=os.getenv("DSPM_PG_SSLMODE"), help="sslmode for the emitted URL (e.g. require)")
    args = ap.parse_args(argv)

    if not args.admin_url:
        ap.error("--admin-url (or DSPM_PG_ADMIN_URL) is required")

    password = args.password
    generated = False
    if not password:
        password = "Sp" + secrets.token_urlsafe(18)  # letters+digits, satisfies typical policies
        generated = True

    provision(args.admin_url, args.db, args.role, password)

    app_url = build_app_url(args.host, args.port, args.db, args.role, password, args.sslmode)
    print("\nProvisioning complete. Point the app at Postgres with:\n")
    print(f"    export DSPM_DB_URL='{app_url}'\n")
    if generated:
        print("NOTE: a password was generated for the app role and is embedded in the URL above.")
        print("      Store it in your secret manager; it will not be shown again.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
