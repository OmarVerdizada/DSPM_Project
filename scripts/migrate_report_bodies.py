"""Move stored report bodies into the artifact tier (Phase 5, DB-07).

The schema change (revision 0005) only adds the reference columns. This is the
data migration that follows it: for every ``scan_reports`` row whose body is
still inline, write the body to the artifact store, record its content id and
size, and clear the inline column.

Deliberately separate from the schema revision. A migration that both alters a
table and rewrites hundreds of megabytes across an object store is one nobody
can reason about when it fails halfway; this one is idempotent, resumable, and
verifies every object it writes before clearing the source.

Safety properties:

- **Verify before clear.** Each body is written, read back, hash-checked and
  compared to the original text before the inline column is cleared. A row is
  only ever emptied once its body is provably retrievable.
- **Idempotent.** Rows already carrying a reference are skipped, so a re-run
  after an interruption resumes.
- **Reversible while both columns exist.** ``--dry-run`` reports the work;
  nothing is destructive until the contract release drops ``report_json``.

Usage:
    python scripts/migrate_report_bodies.py --dry-run
    python scripts/migrate_report_bodies.py --apply [--evidence-dir docs/database/evidence]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> int:
    # C10: an operator data migration spans tenants, and says so - on PostgreSQL a
    # transaction that names no tenant and no purpose sees no tenant rows.
    from backend import db

    with db.platform_scope("migration"):
        return _main()


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="perform the move (default is a report)")
    parser.add_argument("--dry-run", action="store_true", help="explicit no-op form of the default")
    parser.add_argument("--evidence-dir", default="")
    args = parser.parse_args()
    apply_changes = args.apply and not args.dry_run

    from backend import artifacts, store

    with store._connect() as conn:
        rows = conn.execute(
            "SELECT tenant_id, scan_id, LENGTH(report_json) AS n FROM scan_reports "
            "WHERE COALESCE(report_ref, '') = '' AND COALESCE(report_json, '') <> '' "
            "ORDER BY tenant_id, scan_id"
        ).fetchall()
        pending = [(str(r["tenant_id"]), str(r["scan_id"]), int(r["n"] or 0)) for r in rows]

    total_bytes = sum(n for _t, _s, n in pending)
    print(f"rows with inline bodies: {len(pending)}  ({total_bytes / 1024 / 1024:.1f} MB)")
    if not apply_changes:
        for tenant, scan_id, size in pending[:20]:
            print(f"  would move {tenant}/{scan_id}  {size / 1024 / 1024:.2f} MB")
        if len(pending) > 20:
            print(f"  ... and {len(pending) - 20} more")
        print("\ndry run - re-run with --apply to move the bodies.")
        return 0

    moved = 0
    moved_bytes = 0
    failures: list[dict] = []
    for tenant, scan_id, _size in pending:
        try:
            with store._connect() as conn:
                row = conn.execute(
                    "SELECT report_json FROM scan_reports WHERE tenant_id = ? AND scan_id = ?",
                    (tenant, scan_id),
                ).fetchone()
            body = str(row["report_json"] or "") if row else ""
            if not body:
                continue

            ref = artifacts.put_text(tenant, body)
            # Verify before clearing: read the object back through the same
            # path the application will use, and require an exact match.
            if artifacts.get_text(tenant, ref.content_id) != body:
                raise RuntimeError("read-back mismatch")

            with store._lock:
                with store._connect() as conn:
                    conn.execute(
                        "UPDATE scan_reports SET report_ref = ?, report_bytes = ?, report_json = '' "
                        "WHERE tenant_id = ? AND scan_id = ?",
                        (ref.content_id, ref.size_bytes, tenant, scan_id),
                    )
            moved += 1
            moved_bytes += ref.size_bytes
            print(f"  moved {tenant}/{scan_id} -> {ref.content_id[:12]}...  "
                  f"{ref.size_bytes / 1024 / 1024:.2f} MB")
        except Exception as exc:
            failures.append({"tenant_id": tenant, "scan_id": scan_id, "error": type(exc).__name__})
            print(f"  FAILED {tenant}/{scan_id}: {type(exc).__name__}: {exc}", file=sys.stderr)

    stats = artifacts.store_stats()
    print(f"\nmoved {moved} bodies ({moved_bytes / 1024 / 1024:.1f} MB); "
          f"store now holds {stats['objects']} objects "
          f"({stats['ciphertext_bytes'] / 1024 / 1024:.1f} MB ciphertext)")
    if failures:
        print(f"{len(failures)} row(s) failed and kept their inline body.", file=sys.stderr)

    if args.evidence_dir:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_dir = Path(args.evidence_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        evidence = {
            "migrated_at": datetime.now(timezone.utc).isoformat(),
            "rows_considered": len(pending),
            "bodies_moved": moved,
            "bytes_moved": moved_bytes,
            "failures": failures,
            "artifact_store": stats,
            "result": "PASS" if not failures else "PARTIAL",
        }
        out = out_dir / f"report_bodies_{stamp}.json"
        out.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        print(f"evidence: {out}")

    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
