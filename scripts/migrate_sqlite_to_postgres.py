"""SQLite -> PostgreSQL store migration, v2 (roadmap Phase 3, DB-06/M2).

What changed from v1 and why:

- **Schema discovery, not a name list.** v1 hardcoded 17 tables and silently
  dropped anything newer (app_settings, scan_object_baselines,
  search_reconciliation_state, scan_profiles). v2 enumerates the source's
  real tables from ``sqlite_master`` and copies every application table, so a
  new table can never be lost by forgetting to edit a list.
- **The destination schema is built by the migration runner**, so a migrated
  database carries recorded schema revisions and passes the production
  startup gate - not by the legacy convergent ``init_db`` path.
- **Invariant reconciliation.** Beyond per-table row counts, tenant-scoped
  tables are reconciled per tenant, and identity sequences are checked to be
  ahead of the copied ids. The full reconciliation is written as a JSON
  evidence artifact (no credentials, no data).
- **Bounded memory.** Rows stream in batches instead of fetchall() on the
  largest tables.

Copy order is a topological sort over the destination's foreign keys
(parents before children), computed from the catalog - revision 0003's tenant
FKs made load order matter, and discovery keeps it correct automatically.

Usage (DSNs via env, never on the command line - they carry credentials):
    set DSPM_DB_URL=postgresql://...          # destination
    python -m scripts.migrate_sqlite_to_postgres            # source = data/dspm.sqlite
    python -m scripts.migrate_sqlite_to_postgres --source other.sqlite
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

BATCH_ROWS = 5000

# Never copied: the destination builds its own recorded revision history via
# the migration runner, and SQLite internals/FTS shadow tables are engine-local.
EXCLUDED_TABLES = {"schema_migrations"}
EXCLUDED_PREFIXES = ("sqlite_",)


def discover_tables(src: sqlite3.Connection) -> list[str]:
    """Every application table actually present in the source database.

    FTS5 virtual tables and their shadow tables (<name>_data, _idx, _content,
    _docsize, _config) are excluded structurally - by finding the virtual
    tables in sqlite_master - so a renamed search index can never leak
    engine-local rows into the copy."""
    rows = src.execute(
        "SELECT name, COALESCE(sql, '') FROM sqlite_master WHERE type = 'table' ORDER BY name"
    ).fetchall()
    fts_bases = [
        str(name) for name, sql in rows
        if "using fts5" in str(sql).lower().replace('"', "")
    ]

    def _is_fts(name: str) -> bool:
        return any(name == base or name.startswith(base + "_") for base in fts_bases)

    return [
        str(name) for name, _sql in rows
        if str(name) not in EXCLUDED_TABLES
        and not str(name).startswith(EXCLUDED_PREFIXES)
        and not _is_fts(str(name))
    ]


def _copy_order(dst, tables: list[str]) -> list[str]:
    """Order tables parents-first using the destination's FK graph (Kahn's
    algorithm, alphabetical tiebreak). Revision 0003's tenant foreign keys
    made alphabetical order fail: alert_events loaded before tenants."""
    with dst.cursor() as cur:
        cur.execute(
            "SELECT c.conrelid::regclass::text, c.confrelid::regclass::text "
            "FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace "
            "WHERE c.contype = 'f' AND n.nspname = current_schema()",
        )
        edges = [(str(child), str(parent)) for child, parent in cur.fetchall()]
    in_scope = set(tables)
    depends_on: dict[str, set[str]] = {t: set() for t in tables}
    for child, parent in edges:
        if child in in_scope and parent in in_scope and child != parent:
            depends_on[child].add(parent)
    ordered: list[str] = []
    ready = sorted(t for t, deps in depends_on.items() if not deps)
    while ready:
        table = ready.pop(0)
        ordered.append(table)
        for other, deps in depends_on.items():
            if table in deps:
                deps.discard(table)
                if not deps and other not in ordered and other not in ready:
                    ready.append(other)
        ready.sort()
    # A cycle (impossible today) falls back to appending the remainder so the
    # copy still runs; the FK violation would then name the real problem.
    ordered.extend(sorted(t for t in tables if t not in ordered))
    return ordered


def _sqlite_columns(src: sqlite3.Connection, table: str) -> list[str]:
    return [row[1] for row in src.execute(f"PRAGMA table_info({table})").fetchall()]


def _dest_identity_columns(dst, tables: list[str]) -> dict[str, str]:
    """GENERATED AS IDENTITY columns discovered from the catalog, not a list."""
    with dst.cursor() as cur:
        cur.execute(
            "SELECT c.relname, a.attname FROM pg_attribute a "
            "JOIN pg_class c ON c.oid = a.attrelid "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE a.attidentity <> '' AND n.nspname = current_schema() "
            "AND c.relname = ANY(%s)",
            (tables,),
        )
        return {str(r[0]): str(r[1]) for r in cur.fetchall()}


def _tenant_counts_sqlite(src: sqlite3.Connection, table: str) -> dict[str, int]:
    return {
        str(r[0]): int(r[1])
        for r in src.execute(
            f"SELECT tenant_id, COUNT(*) FROM {table} GROUP BY tenant_id"
        ).fetchall()
    }


def _tenant_counts_pg(dst, table: str) -> dict[str, int]:
    with dst.cursor() as cur:
        cur.execute(f"SELECT tenant_id, COUNT(*) FROM {table} GROUP BY tenant_id")
        return {str(r[0]): int(r[1]) for r in cur.fetchall()}


def _as_url_dsn(dsn: str) -> str:
    """Normalize any psycopg conninfo (keyword or URL) to URL form - the
    backend seam selects PostgreSQL by the postgresql:// prefix."""
    if dsn.lower().startswith(("postgres://", "postgresql://")):
        return dsn
    from urllib.parse import quote

    from psycopg.conninfo import conninfo_to_dict

    parts = conninfo_to_dict(dsn)
    auth = quote(str(parts.get("user") or ""), safe="")
    password = parts.get("password")
    if password:
        auth += f":{quote(str(password), safe='')}"
    host = str(parts.get("host") or "127.0.0.1")
    port = str(parts.get("port") or "5432")
    dbname = quote(str(parts.get("dbname") or ""), safe="")
    return f"postgresql://{auth}@{host}:{port}/{dbname}"


def migrate(source: Path, dest_dsn: str, truncate: bool, evidence_dir: Path | None) -> int:
    dest_dsn = _as_url_dsn(dest_dsn)
    # Build/verify the destination schema through the versioned runner so the
    # migrated database has recorded revisions (production verifies them).
    os.environ["DSPM_DB_URL"] = dest_dsn
    os.environ["DSPM_MIGRATIONS_CLI"] = "1"  # keep the store import inert
    from backend import migrations  # noqa: E402 - after env targets the dest

    final_revision = migrations.upgrade()

    import psycopg  # noqa: E402

    src = sqlite3.connect(source)
    src.row_factory = sqlite3.Row

    tables = discover_tables(src)
    report: dict[str, dict] = {}
    skipped: list[str] = []
    tenant_mismatches: dict[str, dict] = {}

    with psycopg.connect(dest_dsn) as dst:
        present: list[str] = []
        for table in tables:
            with dst.cursor() as cur:
                cur.execute("SELECT to_regclass(%s)", (table,))
                (present if cur.fetchone()[0] is not None else skipped).append(table)

        for table in _copy_order(dst, present):

            cols = _sqlite_columns(src, table)
            collist = ", ".join(cols)
            placeholders = ", ".join(["%s"] * len(cols))
            source_count = int(src.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

            with dst.cursor() as cur:
                if truncate:
                    cur.execute(f"TRUNCATE TABLE {table} RESTART IDENTITY CASCADE")
                reader = src.execute(f"SELECT {collist} FROM {table}")
                while True:
                    batch = reader.fetchmany(BATCH_ROWS)
                    if not batch:
                        break
                    cur.executemany(
                        f"INSERT INTO {table} ({collist}) VALUES ({placeholders}) "
                        "ON CONFLICT DO NOTHING",
                        [tuple(r) for r in batch],
                    )
                cur.execute(f"SELECT COUNT(*) FROM {table}")
                dest_count = int(cur.fetchone()[0])
            report[table] = {"source": source_count, "dest": dest_count}

            if "tenant_id" in cols:
                src_by_tenant = _tenant_counts_sqlite(src, table)
                dst_by_tenant = _tenant_counts_pg(dst, table)
                if src_by_tenant != dst_by_tenant:
                    tenant_mismatches[table] = {
                        tenant: {
                            "source": src_by_tenant.get(tenant, 0),
                            "dest": dst_by_tenant.get(tenant, 0),
                        }
                        for tenant in set(src_by_tenant) | set(dst_by_tenant)
                        if src_by_tenant.get(tenant, 0) != dst_by_tenant.get(tenant, 0)
                    }

        # Advance identity sequences past the copied ids (discovered, not listed).
        sequences: dict[str, int] = {}
        identity_cols = _dest_identity_columns(dst, [t for t in report])
        with dst.cursor() as cur:
            for table, col in identity_cols.items():
                cur.execute(
                    f"SELECT setval(pg_get_serial_sequence('{table}', '{col}'), "
                    f"GREATEST(COALESCE((SELECT MAX({col}) FROM {table}), 1), 1))"
                )
                sequences[f"{table}.{col}"] = int(cur.fetchone()[0])
        dst.commit()

    src.close()

    mismatched = [t for t, c in report.items() if c["source"] != c["dest"]]
    result = "PASS" if not mismatched and not tenant_mismatches else "FAIL"

    print(f"{'table':<30} {'source':>9} {'dest':>9}")
    for table, counts in report.items():
        flag = "" if counts["source"] == counts["dest"] else "  <-- MISMATCH"
        print(f"{table:<30} {counts['source']:>9} {counts['dest']:>9}{flag}")
    for table in skipped:
        print(f"{table:<30} {'skipped: no destination table':>30}")
    total_rows = sum(c["source"] for c in report.values())
    print(f"\nschema revision: {final_revision}")
    print(f"migrated {len(report)} tables, {total_rows} source rows -> {result}")
    if tenant_mismatches:
        print(f"per-tenant mismatches in: {', '.join(sorted(tenant_mismatches))}")

    if evidence_dir is not None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        evidence = {
            "migrated_at": datetime.now(timezone.utc).isoformat(),
            "source_file": source.name,
            "schema_revision": final_revision,
            "tables": report,
            "tables_skipped_missing_on_dest": skipped,
            "rows_total": total_rows,
            "per_tenant_mismatches": tenant_mismatches,
            "identity_sequences": sequences,
            "result": result,
        }
        evidence_dir.mkdir(parents=True, exist_ok=True)
        out = evidence_dir / f"migration_{stamp}.json"
        out.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        print(f"evidence: {out}")

    return 0 if result == "PASS" else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Migrate the Sentro DSPM store from SQLite to PostgreSQL.")
    ap.add_argument("--source", default=os.getenv("DSPM_DB_PATH", str(BASE_DIR / "data" / "dspm.sqlite")),
                    help="source SQLite file (default: data/dspm.sqlite)")
    ap.add_argument("--no-truncate", action="store_true",
                    help="append instead of replacing dest tables (default is truncate + copy)")
    ap.add_argument("--evidence-dir", default="",
                    help="write a JSON reconciliation artifact into this directory")
    args = ap.parse_args(argv)

    source = Path(args.source)
    if not source.exists():
        print(f"source SQLite file not found: {source}", file=sys.stderr)
        return 2
    dest = (os.getenv("DSPM_MIGRATE_DEST_URL") or os.getenv("DSPM_DB_URL") or "").strip()
    # URL and keyword conninfo are both fine; whatever psycopg parses is
    # PostgreSQL. The guard exists to catch an empty env or a SQLite path.
    try:
        from psycopg.conninfo import conninfo_to_dict

        if not dest or not conninfo_to_dict(dest).get("dbname"):
            raise ValueError("no dbname")
    except Exception:
        print("destination must be a PostgreSQL DSN with a dbname in "
              "DSPM_MIGRATE_DEST_URL or DSPM_DB_URL "
              "(env, not a flag - DSNs carry credentials)", file=sys.stderr)
        return 2

    return migrate(source, dest, truncate=not args.no_truncate,
                   evidence_dir=Path(args.evidence_dir) if args.evidence_dir else None)


if __name__ == "__main__":
    raise SystemExit(main())
