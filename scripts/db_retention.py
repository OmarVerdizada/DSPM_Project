"""Per-data-class retention (roadmap Phase 6, DB-13).

Operational history grows without bound today. This tool prunes the two
append-only event tables by age, per tenant-agnostic policy, and reports
exactly what it would (or did) remove. Scan reports, findings, assets, and
the audit trail of the CURRENT retention window are never touched by
default - shortening `--audit-days` below the compliance window is an
explicit operator decision.

Dry-run by default; `--apply` deletes. Ages come from env or flags:

    DSPM_RETAIN_ALERT_DAYS  (default 365)
    DSPM_RETAIN_AUDIT_DAYS  (default 730)

Usage:
    python scripts/db_retention.py               # report only
    python scripts/db_retention.py --apply       # prune per policy
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

POLICIES = (
    # (table, timestamp column, env var, default days)
    ("alert_events", "created_at", "DSPM_RETAIN_ALERT_DAYS", 365),
    ("audit_events", "timestamp", "DSPM_RETAIN_AUDIT_DAYS", 730),
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="actually delete (default is a dry-run report)")
    parser.add_argument("--alert-days", type=int, default=None)
    parser.add_argument("--audit-days", type=int, default=None)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=None,
        help="write a sanitized Phase 7 retention-run artifact",
    )
    args = parser.parse_args()

    overrides = {"alert_events": args.alert_days, "audit_events": args.audit_days}

    # This operational CLI consumes the installed schema; it never owns schema
    # upgrades.  Without the inert-import flag a local-mode PostgreSQL shell
    # would try DDL as sentro_app before the retention run even starts.
    os.environ["DSPM_MIGRATIONS_CLI"] = "1"
    from backend import store

    # A legal hold suspends scheduled deletion for that tenant. Tables pruned
    # here are tenant-scoped, so held tenants are excluded from the delete
    # rather than the whole run being refused.
    held = store.tenants_under_legal_hold()
    if held:
        print(f"legal hold active for {len(held)} tenant(s); their rows are preserved")

    now = datetime.now(timezone.utc)
    total_removed = 0
    results: list[dict] = []
    for table, column, env_var, default_days in POLICIES:
        days = overrides.get(table) or int(os.getenv(env_var, str(default_days)))
        cutoff = (now - timedelta(days=days)).isoformat()
        exclude = ""
        params: tuple = (cutoff,)
        if held:
            placeholders = ", ".join("?" for _ in held)
            exclude = f" AND tenant_id NOT IN ({placeholders})"
            params = (cutoff, *sorted(held))
        with store._connect() as conn:
            row = conn.execute(
                f"SELECT COUNT(*) AS n FROM {table} WHERE {column} < ?{exclude}", params
            ).fetchone()
            stale = int(row["n"])
            if args.apply and stale:
                conn.execute(f"DELETE FROM {table} WHERE {column} < ?{exclude}", params)
        action = "removed" if args.apply else "would remove"
        print(f"{table:<14} older than {days:>4}d: {action} {stale}")
        results.append({
            "data_class": table,
            "retention_days": days,
            "eligible_rows": stale,
            "removed_rows": stale if args.apply else 0,
        })
        total_removed += stale if args.apply else 0

    # Unreferenced artifact objects: garbage collection, not retention.
    # Nothing reachable from a row is ever removed here.
    try:
        from backend import artifacts

        # Report bodies and unfinalized partition records alike: see
        # store.referenced_artifact_ids.
        referenced = store.referenced_artifact_ids()
        stats = artifacts.store_stats()
        if args.apply:
            collected = artifacts.prune(referenced)
            print(f"{'artifacts':<14} unreferenced objects: removed {collected} of {stats['objects']}")
            artifact_result = {
                "objects": int(stats["objects"]),
                "eligible_objects": collected,
                "removed_objects": collected,
            }
        else:
            unreferenced = sum(
                1 for tenant, cid, _path in artifacts.iter_objects()
                if (tenant, cid) not in referenced
            )
            print(f"{'artifacts':<14} unreferenced objects: would remove {unreferenced} "
                  f"of {stats['objects']}")
            artifact_result = {
                "objects": int(stats["objects"]),
                "eligible_objects": unreferenced,
                "removed_objects": 0,
            }
    except Exception as exc:  # pragma: no cover - artifact tier may be disabled
        print(f"{'artifacts':<14} skipped ({type(exc).__name__})")
        artifact_result = {"result": "SKIPPED", "reason": type(exc).__name__}

    if not args.apply:
        print("\ndry run - re-run with --apply to prune.")
    else:
        print(f"\npruned {total_removed} rows.")

    if args.evidence_dir:
        from backend import db_certification

        payload = {
            "evidence_kind": "retention_run",
            "generated_at": now.isoformat(),
            "run_at": now.isoformat(),
            "mode": "apply" if args.apply else "dry_run",
            "legal_hold_tenants_preserved": len(held),
            "data_classes": results,
            "artifacts": artifact_result,
            "result": "PASS",
        }
        output = db_certification.write_evidence(args.evidence_dir, "retention", payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        print(f"evidence: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
