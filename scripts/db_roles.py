"""PostgreSQL role separation for the Sentro store (roadmap Phase 4b, DB-04).

One privileged role doing everything is how the Phase 1 grant gap happened
(sentro_app could not read scan_object_baselines, discovered live during the
first backup). This script establishes and verifies the standing model:

- ``sentro_owner``    owns every application table and runs migrations (DDL).
- ``sentro_app``      the runtime: DML on tables, USAGE on sequences, no DDL.
- ``sentro_backup``   read-only, for pg_dump - never the runtime credential.
- ``sentro_readonly`` read-only, for operators/support tooling.

Idempotent: roles are created only if absent (new passwords are generated and
appended to the credentials file, never printed), ownership and grants
converge on every run, and ALTER DEFAULT PRIVILEGES makes future tables
created by the owner (i.e. by migrations) inherit the same grants so the
backup gap cannot silently reopen. A verification pass proves the matrix with
has_table_privilege() and writes a sanitized evidence artifact.

The defaults are those of scripts/setup_postgres.ps1's dedicated cluster; give --host,
--port, --dbname and --credentials for any other server.

Usage (admin credentials via env file, never flags):
    python scripts/db_roles.py --credentials C:\\SentroPostgres\\credentials.env \
        --dbname sentro [--evidence-dir docs/database/evidence]
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

ROLES = ("sentro_owner", "sentro_app", "sentro_backup", "sentro_readonly")
DML = ("SELECT", "INSERT", "UPDATE", "DELETE")
READ = ("SELECT",)


def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def ensure_roles(admin_conn, creds: dict[str, str], creds_path: Path) -> list[str]:
    """Create missing roles; persist any generated password to the credentials
    file (append). Returns the list of roles created this run."""
    from psycopg import sql

    created: list[str] = []
    for role in ROLES:
        exists = admin_conn.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)
        ).fetchone()
        if exists:
            continue
        password = secrets.token_urlsafe(24)
        admin_conn.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE").format(
                sql.Identifier(role), sql.Literal(password)
            )
        )
        key = f"DSPM_PG_{role.removeprefix('sentro_').upper()}_PASSWORD"
        with open(creds_path, "a", encoding="utf-8") as handle:
            handle.write(f"{key}={password}\n")
        creds[key] = password
        created.append(role)
    return created


def converge(db_conn) -> dict:
    """Ownership, grants, and default privileges on the target database."""
    from psycopg import sql

    tables = [
        str(r[0]) for r in db_conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = current_schema() ORDER BY 1"
        ).fetchall()
    ]
    sequences = [
        str(r[0]) for r in db_conn.execute(
            "SELECT sequencename FROM pg_sequences WHERE schemaname = current_schema() ORDER BY 1"
        ).fetchall()
    ]

    for table in tables:
        db_conn.execute(sql.SQL("ALTER TABLE {} OWNER TO sentro_owner").format(sql.Identifier(table)))
        db_conn.execute(sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON {} TO sentro_app").format(
            sql.Identifier(table)))
        db_conn.execute(sql.SQL("GRANT SELECT ON {} TO sentro_backup, sentro_readonly").format(
            sql.Identifier(table)))
    for sequence in sequences:
        db_conn.execute(sql.SQL("ALTER SEQUENCE {} OWNER TO sentro_owner").format(sql.Identifier(sequence)))
        db_conn.execute(sql.SQL("GRANT USAGE, SELECT ON SEQUENCE {} TO sentro_app").format(
            sql.Identifier(sequence)))
        db_conn.execute(sql.SQL("GRANT SELECT ON SEQUENCE {} TO sentro_backup, sentro_readonly").format(
            sql.Identifier(sequence)))

    # The schema: owner may create (migrations); the others only resolve names.
    # The original single-role setup had granted CREATE to the runtime role -
    # revoke it so no compromised runtime credential can add objects.
    db_conn.execute("GRANT USAGE, CREATE ON SCHEMA public TO sentro_owner")
    db_conn.execute("GRANT USAGE ON SCHEMA public TO sentro_app, sentro_backup, sentro_readonly")
    db_conn.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    db_conn.execute("REVOKE CREATE ON SCHEMA public FROM sentro_app, sentro_backup, sentro_readonly")
    db_conn.execute("GRANT CONNECT ON DATABASE {} TO sentro_owner, sentro_app, sentro_backup, sentro_readonly".format(
        db_conn.execute("SELECT quote_ident(current_database())").fetchone()[0]))

    # Backups must never be silently partial: pg_dump refuses to run when a
    # row-level-security policy could filter its COPY, so the read-only
    # backup role bypasses RLS outright (it already can only SELECT).
    db_conn.execute("ALTER ROLE sentro_backup BYPASSRLS")

    # RLS default scope (revision 0004): sessions start unscoped ('*') so
    # cross-tenant paths (login, backups, platform admin) keep working; the
    # connection seam narrows to one tenant per transaction via SET LOCAL.
    for role in ROLES:
        db_conn.execute(
            "ALTER ROLE {} IN DATABASE {} SET app.tenant_id = '*'".format(
                role,
                db_conn.execute("SELECT quote_ident(current_database())").fetchone()[0],
            )
        )

    # Future tables/sequences created by the owner (migrations) inherit the
    # matrix automatically - this is what keeps the backup gap closed.
    db_conn.execute(
        "ALTER DEFAULT PRIVILEGES FOR ROLE sentro_owner IN SCHEMA public "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentro_app"
    )
    db_conn.execute(
        "ALTER DEFAULT PRIVILEGES FOR ROLE sentro_owner IN SCHEMA public "
        "GRANT SELECT ON TABLES TO sentro_backup, sentro_readonly"
    )
    db_conn.execute(
        "ALTER DEFAULT PRIVILEGES FOR ROLE sentro_owner IN SCHEMA public "
        "GRANT USAGE, SELECT ON SEQUENCES TO sentro_app"
    )
    db_conn.execute(
        "ALTER DEFAULT PRIVILEGES FOR ROLE sentro_owner IN SCHEMA public "
        "GRANT SELECT ON SEQUENCES TO sentro_backup, sentro_readonly"
    )
    return {"tables": tables, "sequences": sequences}


def verify(db_conn, tables: list[str]) -> dict:
    """Prove the privilege matrix from the catalog; fail on any deviation."""
    failures: list[str] = []
    matrix: dict[str, dict[str, bool]] = {}
    checks = {
        "sentro_app": {priv: True for priv in DML},
        "sentro_backup": {"SELECT": True, "INSERT": False, "UPDATE": False, "DELETE": False},
        "sentro_readonly": {"SELECT": True, "INSERT": False, "UPDATE": False, "DELETE": False},
    }
    for role, expected in checks.items():
        summary: dict[str, bool] = {}
        for priv, want in expected.items():
            bad = [
                table for table in tables
                if bool(db_conn.execute(
                    "SELECT has_table_privilege(%s, quote_ident(%s), %s)",
                    (role, table, priv),
                ).fetchone()[0]) != want
            ]
            summary[priv] = not bad
            if bad:
                failures.append(f"{role} {priv} wrong on: {', '.join(bad[:5])}")
        matrix[role] = summary

    # No runtime DDL: sentro_app must not be able to create in the schema.
    for role in ("sentro_app", "sentro_backup", "sentro_readonly"):
        can_create = bool(db_conn.execute(
            "SELECT has_schema_privilege(%s, 'public', 'CREATE')", (role,)
        ).fetchone()[0])
        matrix.setdefault(role, {})["schema CREATE denied"] = not can_create
        if can_create:
            failures.append(f"{role} can CREATE in schema public")

    owned_elsewhere = [
        str(r[0]) for r in db_conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = current_schema() "
            "AND tableowner <> 'sentro_owner'"
        ).fetchall()
    ]
    if owned_elsewhere:
        failures.append(f"tables not owned by sentro_owner: {', '.join(owned_elsewhere[:5])}")

    return {"matrix": matrix, "tables_not_owned": owned_elsewhere, "failures": failures}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", default=r"C:\SentroPostgres\credentials.env")
    parser.add_argument("--dbname", default="sentro")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5442)
    parser.add_argument("--evidence-dir", default="")
    args = parser.parse_args()

    creds_path = Path(args.credentials)
    creds = read_env_file(creds_path)
    superuser_password = creds.get("DSPM_PG_SUPERUSER_PASSWORD", "")
    if not superuser_password:
        print("DSPM_PG_SUPERUSER_PASSWORD missing from the credentials file.", file=sys.stderr)
        return 2

    import psycopg
    from psycopg.conninfo import make_conninfo

    admin_cluster = make_conninfo(host=args.host, port=args.port, user="postgres",
                                  password=superuser_password, dbname="postgres")
    admin_db = make_conninfo(host=args.host, port=args.port, user="postgres",
                             password=superuser_password, dbname=args.dbname)

    with psycopg.connect(admin_cluster, autocommit=True, connect_timeout=15) as conn:
        created = ensure_roles(conn, creds, creds_path)

    with psycopg.connect(admin_db, connect_timeout=15) as conn:
        scope = converge(conn)
        conn.commit()
        result = verify(conn, scope["tables"])

    print(f"roles created this run: {created or 'none (all existed)'}")
    print(f"converged {len(scope['tables'])} tables, {len(scope['sequences'])} sequences")
    for role, summary in result["matrix"].items():
        state = ", ".join(f"{name}={'ok' if ok else 'FAIL'}" for name, ok in summary.items())
        print(f"  {role:<16} {state}")
    for failure in result["failures"]:
        print(f"  FAILURE: {failure}")

    if args.evidence_dir:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        evidence = {
            "applied_at": datetime.now(timezone.utc).isoformat(),
            "database": args.dbname,
            "roles_created": created,
            "tables": len(scope["tables"]),
            "sequences": len(scope["sequences"]),
            "verification": result["matrix"],
            "failures": result["failures"],
            "result": "PASS" if not result["failures"] else "FAIL",
        }
        out_dir = Path(args.evidence_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / f"db_roles_{stamp}.json"
        out.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        print(f"evidence: {out}")

    return 0 if not result["failures"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
