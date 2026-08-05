"""DATA-003 regression: tenant scan_count is the real total, not 0/1."""

from __future__ import annotations

import unittest
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


if __name__ == "__main__":
    unittest.main()
