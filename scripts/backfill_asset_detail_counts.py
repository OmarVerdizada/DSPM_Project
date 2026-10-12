"""Fill assets.reason_count / assets.dlp_count for rows written before they existed.

The two numbers the inventory table shows per row are lengths of two lists
inside ``assets.detail_json``. They are written with the row now; rows saved by
an earlier build carry the column default of 0, and the API falls back to
reading the blob for those. This walks the estate once, in bounded batches, and
fills them in.

    python -m scripts.backfill_asset_detail_counts            # every tenant
    python -m scripts.backfill_asset_detail_counts --tenant <tenant id>
    python -m scripts.backfill_asset_detail_counts --dry-run

Safe to re-run: it only touches rows whose stored counts differ from the blob.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend import store  # noqa: E402  (path set above)


def backfill(tenant: str = "", batch_size: int = 500, dry_run: bool = False) -> dict:
    scanned = updated = 0
    cursor_tenant, cursor_id = "", ""
    where = "(tenant_id > ? OR (tenant_id = ? AND id > ?))"
    params_head: tuple = ()
    if tenant:
        where += " AND tenant_id = ?"
        params_head = (tenant,)

    while True:
        with store._connect() as conn:
            rows = conn.execute(
                "SELECT tenant_id, id, detail_json, reason_count, dlp_count FROM assets "
                f"WHERE {where} ORDER BY tenant_id ASC, id ASC LIMIT ?",
                (cursor_tenant, cursor_tenant, cursor_id, *params_head, batch_size),
            ).fetchall()
            if not rows:
                break
            pending = []
            for row in rows:
                scanned += 1
                reasons, actions = store._detail_counts(row["detail_json"])
                if reasons != int(row["reason_count"] or 0) or actions != int(row["dlp_count"] or 0):
                    pending.append((reasons, actions, row["tenant_id"], row["id"]))
            if pending and not dry_run:
                conn.executemany(
                    "UPDATE assets SET reason_count = ?, dlp_count = ? WHERE tenant_id = ? AND id = ?",
                    pending,
                )
            updated += len(pending)
            cursor_tenant = str(rows[-1]["tenant_id"] or "")
            cursor_id = str(rows[-1]["id"] or "")

    if updated and not dry_run:
        store._invalidate_inventory_query_cache(tenant or None)
    return {"scanned": scanned, "updated": updated, "dry_run": dry_run}


def main() -> int:
    # C10: an operator data migration spans tenants, and says so - on PostgreSQL a
    # transaction that names no tenant and no purpose sees no tenant rows.
    from backend import db

    with db.platform_scope("migration"):
        return _main()


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tenant", default="", help="one tenant id (default: all)")
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--dry-run", action="store_true", help="report what would change, write nothing")
    args = parser.parse_args()

    store.init_db()
    result = backfill(args.tenant, max(50, min(args.batch_size, 5000)), args.dry_run)
    verb = "would update" if result["dry_run"] else "updated"
    print(f"scanned {result['scanned']} assets, {verb} {result['updated']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
