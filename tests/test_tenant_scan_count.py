"""DATA-003 regression: tenant scan_count is the real total, not 0/1."""

from __future__ import annotations

import unittest
import inspect
from uuid import uuid4

from backend import store


class TenantScanCountTests(unittest.TestCase):
    def test_scan_count_reflects_all_scans(self) -> None:
        tenant_id = f"count-test-{uuid4().hex[:8]}"
        store.create_tenant(tenant_id, "Count Test Tenant")

        self.assertEqual(store.count_scan_history(tenant_id), 0)

        for i in range(3):
            store.save_scan_history(
                tenant_id,
                {"scan_id": f"{tenant_id}-scan-{i}", "summary": {"total_files": i}, "source": "local"},
            )

        self.assertEqual(store.count_scan_history(tenant_id), 3)

        tenant = next(t for t in store.list_tenants() if t["tenant_id"] == tenant_id)
        self.assertEqual(tenant["scan_count"], 3)

    def test_tenant_portfolio_is_set_based_and_can_scope_before_querying(self) -> None:
        first = f"portfolio-a-{uuid4().hex[:8]}"
        second = f"portfolio-b-{uuid4().hex[:8]}"
        store.create_tenant(first, "First")
        store.create_tenant(second, "Second")
        store.save_scan_history(first, {"scan_id": f"{first}-scan", "summary": {"critical": 2}, "source": "local"})

        rows = store.list_tenants(first)
        self.assertEqual([row["tenant_id"] for row in rows], [first])
        self.assertEqual(rows[0]["scan_count"], 1)
        self.assertEqual(rows[0]["latest"]["summary"]["critical"], 2)
        self.assertEqual(rows[0]["retention"]["report_count"], 1)

        source = inspect.getsource(store.list_tenants)
        self.assertIn("ROW_NUMBER() OVER", source)
        self.assertNotIn("read_scan_history(", source)
        self.assertNotIn("count_scan_history(", source)


if __name__ == "__main__":
    unittest.main()
