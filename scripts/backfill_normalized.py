"""One-off migration: backfill the normalized DATA-001 tables from existing
report_json rows (Phase 1).

Idempotent and safe to re-run. The readiness gate keeps report_json compatibility
until the requested scope is fully mirrored; after completion, the default indexed
inventory path can take over. Run during a maintenance window for large datasets.

Usage:
    python scripts/backfill_normalized.py [tenant_id]
"""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend import store


def main() -> None:
    tenant_id = sys.argv[1] if len(sys.argv) > 1 else None
    result = store.backfill_normalized_scans(tenant_id)
    scope = f"tenant '{tenant_id}'" if tenant_id else "all tenants"
    print(
        f"Backfill complete for {scope}: "
        f"{result['mirrored']} mirrored, {result['failed']} failed, {result['scanned']} scanned."
    )


if __name__ == "__main__":
    main()
