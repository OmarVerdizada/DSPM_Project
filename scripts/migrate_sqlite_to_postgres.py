"""One-time data migration: copy the Sentro DSPM store from SQLite to PostgreSQL
(roadmap Phase 2, M2). Carries the existing users, tenants, API keys, encrypted
vault, scan history, audit/alert logs, throttle/revocation state, and the
normalized mirror over to Postgres so nothing is lost when the app switches
backends.

Idempotent: with --truncate (default) the destination tables are emptied and
rebuilt from the source, so re-running converges to "Postgres == SQLite". The
destination schema is created if absent (via store.init_db against the dest).

Usage:
    export DSPM_DB_URL='postgresql://sentro_app:<pw>@127.0.0.1:5442/sentro_dev'
    python -m scripts.migrate_sqlite_to_postgres            # source = data/dspm.sqlite
    python -m scripts.migrate_sqlite_to_postgres --source other.sqlite --dest <dsn>
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Copy order is not constrained by FKs (there are none), but keep parents first
# for readability. Tables absent in the source are skipped.
TABLES = [
    "tenants", "users", "api_keys", "registration_invites", "secrets",
    "scan_reports", "audit_events", "alert_events", "login_failures", "revoked_tokens",
    "scan_runs", "assets", "asset_versions", "findings", "finding_occurrences",
    "finding_index", "scan_jobs",
]

# GENERATED ... AS IDENTITY columns: explicit ids copy fine (BY DEFAULT), but the
# identity sequence must then be advanced past the max copied id.
IDENTITY_COLUMNS = {"audit_events": "id", "alert_events": "id"}


def _sqlite_columns(src: sqlite3.Connection, table: str) -> list[str]:
    return [row[1] for row in src.execute(f"PRAGMA table_info({table})").fetchall()]


def migrate(source: Path, dest_dsn: str, truncate: bool) -> int:
    # Ensure the destination schema exists (init_db runs against the dest URL).
    os.environ["DSPM_DB_URL"] = dest_dsn
    from backend import store  # noqa: E402 - after env is set so it targets Postgres
    store.init_db()

    import psycopg  # noqa: E402

    src = sqlite3.connect(source)
    src.row_factory = sqlite3.Row

    totals: dict[str, tuple[int, int]] = {}
    with psycopg.connect(dest_dsn) as dst:
        for table in TABLES:
            cols = _sqlite_columns(src, table)
            if not cols:
                continue  # table not present in this source DB
            rows = src.execute(f"SELECT {', '.join(cols)} FROM {table}").fetchall()

            with dst.cursor() as cur:
                if truncate:
                    cur.execute(f"TRUNCATE TABLE {table} RESTART IDENTITY CASCADE")
                if rows:
                    collist = ", ".join(cols)
                    placeholders = ", ".join(["%s"] * len(cols))
                    cur.executemany(
                        f"INSERT INTO {table} ({collist}) VALUES ({placeholders}) ON CONFLICT DO NOTHING",
                        [tuple(r) for r in rows],
                    )
                dest_n = cur.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            totals[table] = (len(rows), dest_n)

        # Advance identity sequences past the copied ids so future inserts don't collide.
        with dst.cursor() as cur:
            for table, col in IDENTITY_COLUMNS.items():
                if table in totals:
                    cur.execute(
                        f"SELECT setval(pg_get_serial_sequence('{table}', '{col}'), "
                        f"COALESCE((SELECT MAX({col}) FROM {table}), 1))"
                    )
        dst.commit()

    src.close()

    mismatches = 0
    print(f"{'table':<22} {'source':>8} {'dest':>8}")
    for table, (s, d) in totals.items():
        flag = "" if s == d else "  <-- MISMATCH"
        if s != d:
            mismatches += 1
        print(f"{table:<22} {s:>8} {d:>8}{flag}")
    print(f"\nMigrated {len(totals)} tables; {sum(s for s, _ in totals.values())} source rows.")
    if mismatches:
        print(f"WARNING: {mismatches} table(s) differ (duplicate PKs skipped, or a non-truncate re-run).")
    return 1 if mismatches else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Migrate the Sentro DSPM store from SQLite to PostgreSQL.")
    ap.add_argument("--source", default=os.getenv("DSPM_DB_PATH", str(BASE_DIR / "data" / "dspm.sqlite")),
                    help="source SQLite file (default: data/dspm.sqlite)")
    ap.add_argument("--dest", default=os.getenv("DSPM_DB_URL"),
                    help="destination PostgreSQL DSN (default: DSPM_DB_URL)")
    ap.add_argument("--no-truncate", action="store_true",
                    help="append instead of replacing dest tables (default is truncate + copy)")
    args = ap.parse_args(argv)

    source = Path(args.source)
    if not source.exists():
        print(f"source SQLite file not found: {source}", file=sys.stderr)
        return 2
    if not args.dest or not args.dest.lower().startswith(("postgres://", "postgresql://")):
        print("destination must be a PostgreSQL DSN (--dest or DSPM_DB_URL)", file=sys.stderr)
        return 2

    return migrate(source, args.dest, truncate=not args.no_truncate)


if __name__ == "__main__":
    raise SystemExit(main())
