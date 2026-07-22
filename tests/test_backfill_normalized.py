"""Phase 1 DATA-001 backfill: historical report_json rows populate the mirror."""

from __future__ import annotations

import unittest
from uuid import uuid4

from backend import store


def _report(scan_id: str) -> dict:
    return {
        "scan_id": scan_id,
        "source": "local",
        "timestamp": "2026-07-22T00:00:00Z",
        "summary": {"total_files": 1},
        "files": [
            {
                "name": "legacy.txt",
                "path": "/data/legacy.txt",
                "size": 100,
                "content_hash": "leg-1",
                "findings": [{"type": "password", "risk": "HIGH", "occurrence_count": 7}],
            }
        ],
    }


class BackfillTests(unittest.TestCase):
    def test_backfill_repopulates_missing_normalized_rows(self) -> None:
        tenant = f"bf-{uuid4().hex[:8]}"
        scan_id = f"{tenant}-s1"
        store.create_tenant(tenant, "Backfill Tenant")
        store.save_scan_history(tenant, _report(scan_id))

        # simulate a pre-dual-write historical scan: blob exists, mirror does not
        with store._connect() as conn:
            for table in ("scan_runs", "assets", "asset_versions", "findings", "finding_occurrences"):
                conn.execute(f"DELETE FROM {table} WHERE tenant_id = ?", (tenant,))
        with store._connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_runs WHERE tenant_id=?", (tenant,)).fetchone()[0], 0)

        result = store.backfill_normalized_scans(tenant)
        self.assertEqual(result["mirrored"], 1)
        self.assertEqual(result["failed"], 0)

        with store._connect() as conn:
            runs = conn.execute("SELECT COUNT(*) FROM scan_runs WHERE tenant_id=?", (tenant,)).fetchone()[0]
            occ = conn.execute(
                "SELECT occurrence_count FROM finding_occurrences WHERE tenant_id=? AND scan_id=?",
                (tenant, scan_id),
            ).fetchone()
        self.assertEqual(runs, 1)
        self.assertEqual(occ["occurrence_count"], 7)

    def test_backfill_is_idempotent(self) -> None:
        tenant = f"bf2-{uuid4().hex[:8]}"
        store.create_tenant(tenant, "Backfill Tenant 2")
        store.save_scan_history(tenant, _report(f"{tenant}-s1"))

        store.backfill_normalized_scans(tenant)
        store.backfill_normalized_scans(tenant)  # re-run

        with store._connect() as conn:
            occ = conn.execute(
                "SELECT COUNT(*) FROM finding_occurrences WHERE tenant_id=?", (tenant,)
            ).fetchone()[0]
        self.assertEqual(occ, 1)  # not duplicated across runs


if __name__ == "__main__":
    unittest.main()
