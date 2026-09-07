"""Compress the three write-only JSON columns and apply the history window.

`assets.detail_json`, `scan_object_baselines.snapshot_json` and
`finding_index.response_json` hold JSON the interface never reads in bulk. New
rows are written compressed; this rewrites the ones an earlier build left as
plain text, drops finding responses outside the retention window, and reclaims
the freed pages.

    python -m scripts.compact_json_columns --dry-run
    python -m scripts.compact_json_columns
    python -m scripts.compact_json_columns --no-vacuum     # skip the rewrite

SQLite only - on PostgreSQL these columns are TOAST-compressed by the server
and this script reports that and exits. Safe to re-run: a row already stored as
a compressed blob is left alone.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend import db, store  # noqa: E402

TARGETS = (
    ("assets", "detail_json", ("tenant_id", "id")),
    ("scan_object_baselines", "snapshot_json", ("tenant_id", "scope_key", "object_key")),
    ("finding_index", "response_json", ("tenant_id", "scan_id", "seq")),
)


def _column_bytes(conn, table: str, column: str) -> int:
    row = conn.execute(f"SELECT COALESCE(SUM(LENGTH({column})), 0) AS n FROM {table}").fetchone()
    return int(row["n"] or 0)


def compact(dry_run: bool = False, batch_size: int = 400) -> dict:
    report: dict = {"tables": {}, "trimmed": 0}
    for table, column, keys in TARGETS:
        key_list = ", ".join(keys)
        where = " AND ".join(f"{key} = ?" for key in keys)
        rewritten = 0
        with store._connect() as conn:
            before = _column_bytes(conn, table, column)
        cursor: tuple = tuple("" for _ in keys)
        while True:
            with store._connect() as conn:
                rows = conn.execute(
                    f"SELECT {key_list}, {column} AS payload FROM {table} "
                    f"WHERE ({key_list}) > ({', '.join('?' for _ in keys)}) "
                    f"ORDER BY {key_list} LIMIT ?",
                    (*cursor, batch_size),
                ).fetchall()
                if not rows:
                    break
                pending = []
                for row in rows:
                    payload = row["payload"]
                    # Already a blob: written by this build, leave it.
                    if isinstance(payload, (bytes, bytearray, memoryview)):
                        continue
                    packed = store.pack_json_text(payload or "")
                    if isinstance(packed, str):
                        continue  # below the floor; text is the cheaper form
                    pending.append((packed, *[row[key] for key in keys]))
                if pending and not dry_run:
                    conn.executemany(
                        f"UPDATE {table} SET {column} = ? WHERE {where}", pending
                    )
                rewritten += len(pending)
                cursor = tuple(rows[-1][key] for key in keys)
        with store._connect() as conn:
            after = _column_bytes(conn, table, column)
        report["tables"][f"{table}.{column}"] = {
            "rewritten": rewritten, "before_mb": before / 1e6, "after_mb": after / 1e6,
        }

    # The retention window, applied to every tenant that has history.
    with store._connect() as conn:
        tenants = [str(row[0]) for row in conn.execute("SELECT DISTINCT tenant_id FROM finding_index")]
        for tenant in tenants:
            if dry_run:
                continue
            report["trimmed"] += store._trim_finding_index(conn, tenant)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-vacuum", action="store_true", help="leave the freed pages in the file")
    parser.add_argument("--batch-size", type=int, default=400)
    args = parser.parse_args()

    if db.is_postgres():
        print("PostgreSQL compresses these columns itself (TOAST); nothing to do.")
        return 0

    store.init_db()
    size_before = store.DB_PATH.stat().st_size
    result = compact(args.dry_run, max(50, min(args.batch_size, 5000)))
    for name, stats in result["tables"].items():
        verb = "would rewrite" if args.dry_run else "rewrote"
        print(f"  {name:40} {verb} {stats['rewritten']:6} rows   "
              f"{stats['before_mb']:7.1f} -> {stats['after_mb']:7.1f} MB")
    print(f"  finding responses dropped by the retention window: {result['trimmed']}")

    if not args.dry_run and not args.no_vacuum:
        # VACUUM rewrites the file, which is what actually returns the pages the
        # updates above freed. It needs room for a second copy while it runs.
        with store._connect() as conn:
            conn.execute("VACUUM")
        store.refresh_read_model_state()
    size_after = store.DB_PATH.stat().st_size
    print(f"  database {size_before/1e6:.1f} MB -> {size_after/1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
