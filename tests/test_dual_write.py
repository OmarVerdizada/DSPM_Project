"""Phase 1 DATA-001 dual-write: save_scan_history mirrors into normalized tables."""

from __future__ import annotations

import unittest
from uuid import uuid4

from backend import store


def _report(scan_id: str) -> dict:
    return {
        "scan_id": scan_id,
        "source": "smb",
        "timestamp": "2026-07-22T00:00:00Z",
        "summary": {"total_files": 1, "critical": 1},
        "files": [
            {
                "name": "prod_passwords.txt",
                "path": r"\\fs\share\prod_passwords.txt",
                "size": 2048,
                "content_hash": "hash-1",
                "scan_completeness": "FULL",
                "findings": [
                    {"type": "password", "risk": "CRITICAL", "occurrence_count": 5,
                     "secure_value_fingerprints": ["fp-1"]},
                ],
            }
        ],
    }


class DualWriteTests(unittest.TestCase):
    def test_save_mirrors_into_normalized_tables_and_blob_read_unchanged(self) -> None:
        tenant = f"dw-{uuid4().hex[:8]}"
        scan_id = f"{tenant}-s1"
        store.create_tenant(tenant, "Dual Write")
        store.save_scan_history(tenant, _report(scan_id))

        # blob read path is unchanged
        blob = store.read_scan_report(tenant, scan_id)
        self.assertIsNotNone(blob)
        self.assertEqual(blob.get("scan_id"), scan_id)

        with store._connect() as conn:
            runs = conn.execute("SELECT COUNT(*) FROM scan_runs WHERE tenant_id=?", (tenant,)).fetchone()[0]
            assets = conn.execute("SELECT COUNT(*) FROM assets WHERE tenant_id=?", (tenant,)).fetchone()[0]
            finds = conn.execute("SELECT COUNT(*) FROM findings WHERE tenant_id=?", (tenant,)).fetchone()[0]
            occ = conn.execute(
                "SELECT occurrence_count, fingerprint FROM finding_occurrences WHERE tenant_id=? AND scan_id=?",
                (tenant, scan_id),
            ).fetchone()
        self.assertEqual(runs, 1)
        self.assertEqual(assets, 1)
        self.assertEqual(finds, 1)
        self.assertEqual(occ["occurrence_count"], 5)  # true count, not the sample cap
        self.assertEqual(occ["fingerprint"], "fp-1")

    def test_resave_is_idempotent_for_occurrences(self) -> None:
        tenant = f"dw2-{uuid4().hex[:8]}"
        scan_id = f"{tenant}-s1"
        store.create_tenant(tenant, "Dual Write 2")
        store.save_scan_history(tenant, _report(scan_id))
        store.save_scan_history(tenant, _report(scan_id))  # lifecycle-style re-save

        with store._connect() as conn:
            occ = conn.execute(
                "SELECT COUNT(*) FROM finding_occurrences WHERE tenant_id=? AND scan_id=?",
                (tenant, scan_id),
            ).fetchone()[0]
        self.assertEqual(occ, 1)  # refreshed, not duplicated


if __name__ == "__main__":
    unittest.main()
