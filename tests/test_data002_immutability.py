"""DATA-002: scan-run creation timestamp and the normalized scan run are immutable
across re-saves (finding-lifecycle updates re-save the same scan_id)."""

from __future__ import annotations

import unittest
from uuid import uuid4

from backend import store


def _report(scan_id: str, total_files: int) -> dict:
    return {
        "scan_id": scan_id,
        "source": "local",
        "timestamp": "2026-07-22T00:00:00Z",
        "summary": {"total_files": total_files},
        "files": [
            {"name": "a.txt", "path": "/a.txt", "size": 10, "content_hash": "h",
             "findings": [{"type": "password", "risk": "HIGH", "occurrence_count": 2}]}
        ],
    }


class Data002ImmutabilityTests(unittest.TestCase):
    def test_created_at_and_scan_run_are_stable_across_resave(self) -> None:
        tenant = f"d2-{uuid4().hex[:8]}"
        scan_id = f"{tenant}-s1"
        store.create_tenant(tenant, "DATA-002")

        store.save_scan_history(tenant, _report(scan_id, total_files=1))
        with store._connect() as conn:
            ca1 = conn.execute("SELECT created_at FROM scan_reports WHERE tenant_id=? AND scan_id=?", (tenant, scan_id)).fetchone()["created_at"]
            run1 = conn.execute("SELECT total_files FROM scan_runs WHERE tenant_id=? AND id=?", (tenant, scan_id)).fetchone()["total_files"]

        # lifecycle-style re-save of the SAME scan_id, even with a changed summary
        store.save_scan_history(tenant, _report(scan_id, total_files=999))
        with store._connect() as conn:
            ca2 = conn.execute("SELECT created_at FROM scan_reports WHERE tenant_id=? AND scan_id=?", (tenant, scan_id)).fetchone()["created_at"]
            run2 = conn.execute("SELECT total_files FROM scan_runs WHERE tenant_id=? AND id=?", (tenant, scan_id)).fetchone()["total_files"]
            runs = conn.execute("SELECT COUNT(*) FROM scan_runs WHERE tenant_id=? AND id=?", (tenant, scan_id)).fetchone()[0]

        self.assertEqual(ca1, ca2, "blob created_at must not change on re-save")
        self.assertEqual(run1, 1)
        self.assertEqual(run2, 1, "immutable scan run must keep its original values, not the re-saved ones")
        self.assertEqual(runs, 1, "no duplicate scan-run rows")


if __name__ == "__main__":
    unittest.main()
