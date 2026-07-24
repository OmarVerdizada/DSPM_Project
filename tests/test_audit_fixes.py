"""Regression tests for the Phase 0/1 audit fixes."""

from __future__ import annotations

import unittest
from uuid import uuid4

from backend import store
from backend.domain import normalize_scan_report
from discovery.discovery_engine import _safe_preview


class SanitizerLargeKeyTests(unittest.TestCase):
    def test_large_private_key_is_masked_in_preview(self) -> None:
        # FINDING 1: a 4096-ish RSA body (>2000 chars) must not leak past the
        # length-capped detection rule into the preview.
        body = "MIIE" + "Zz09" * 900  # ~3600 char base64-ish body
        key = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
        blob = "\n".join(_safe_preview(key)["lines"])
        self.assertNotIn(body[:40], blob)
        self.assertIn("[redacted:private_key]", blob)


class NormalizeStatusTests(unittest.TestCase):
    def test_lifecycle_status_is_carried_not_forced_open(self) -> None:
        # F1: a RESOLVED finding must not be normalized as OPEN.
        report = {
            "scan_id": "s1", "source": "local", "timestamp": "2026-07-23T00:00:00Z",
            "summary": {"total_files": 1},
            "files": [{"name": "f.txt", "path": "/f.txt", "size": 1, "findings": [
                {"type": "password", "risk": "HIGH", "status": "RESOLVED"},
                {"type": "email", "risk": "LOW", "review_status": "suppressed"},
            ]}],
        }
        scan = normalize_scan_report("t", report)
        by_rule = {f.rule: f.status for f in scan.findings}
        self.assertEqual(by_rule["password"], "RESOLVED")
        self.assertEqual(by_rule["email"], "SUPPRESSED")


class TenantErasureTests(unittest.TestCase):
    def test_delete_tenant_clears_normalized_and_job_tables(self) -> None:
        # F7: erasure must remove the normalized tables (finding_index holds the
        # full finding evidence) and durable job records.
        tenant = f"erase-{uuid4().hex[:8]}"
        store.create_tenant(tenant, "Erase")
        store.save_scan_history(tenant, {
            "scan_id": f"{tenant}-s1", "source": "local", "timestamp": "2026-07-23T00:00:00Z",
            "summary": {"total_files": 1},
            "files": [{"name": "f.txt", "path": "/f.txt", "size": 1, "findings": [
                {"finding_id": "f1", "type": "password", "risk": "HIGH"}]}],
        })
        store.record_job({"id": f"{tenant}-j", "tenant_id": tenant, "status": "completed",
                          "created_at": "2026-07-23T00:00:00Z"})

        store.delete_tenant_with_data(tenant)
        with store._connect() as conn:
            for table in ("scan_runs", "assets", "asset_versions", "findings", "finding_occurrences", "finding_index", "scan_jobs"):
                count = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE tenant_id = ?", (tenant,)).fetchone()[0]
                self.assertEqual(count, 0, f"{table} not erased")


class JobPruneTests(unittest.TestCase):
    def test_prune_removes_old_terminal_keeps_running(self) -> None:
        # F8: bound scan_jobs growth.
        tenant = f"prune-{uuid4().hex[:8]}"
        old_id, run_id = f"{tenant}-old", f"{tenant}-run"
        with store._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scan_jobs (id, tenant_id, status, progress, message, created_at, finished_at, error, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (old_id, tenant, "completed", 100, "Completed", "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z", None, "2020-01-01T00:00:00Z"),
            )
        store.record_job({"id": run_id, "tenant_id": tenant, "status": "running", "created_at": "2020-01-01T00:00:00Z"})

        store.prune_job_records(86400)  # 1 day
        self.assertIsNone(store.read_job(tenant, old_id))       # old terminal -> pruned
        self.assertIsNotNone(store.read_job(tenant, run_id))    # running -> kept


if __name__ == "__main__":
    unittest.main()
