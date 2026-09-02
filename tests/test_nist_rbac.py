import unittest

from fastapi.testclient import TestClient

from backend.app import app
from backend.security import create_token, hash_password
from backend.store import create_user
from classification.compliance.nist_catalog import load_nist_catalog


class NISTRBACTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        try:
            create_user("nist_viewer", hash_password("Viewer123"), "viewer", "default", "NIST Viewer")
        except Exception:
            pass
        try:
            create_user("nist_analyst", hash_password("Analyst123"), "analyst", "default", "NIST Analyst")
        except Exception:
            pass
        self.viewer_headers = {"Authorization": f"Bearer {create_token('nist_viewer', 'viewer', 'default')}"}
        self.analyst_headers = {"Authorization": f"Bearer {create_token('nist_analyst', 'analyst', 'default')}"}

    def test_viewer_can_read_status_but_not_validate(self):
        self.assertEqual(self.client.get("/api/nist/catalog/status", headers=self.viewer_headers).status_code, 200)
        self.assertEqual(self.client.post("/api/nist/catalog/validate", headers=self.viewer_headers, json={"catalog": load_nist_catalog()}).status_code, 403)

    def test_analyst_can_validate_but_not_import(self):
        self.assertEqual(self.client.post("/api/nist/catalog/validate", headers=self.analyst_headers, json={"catalog": load_nist_catalog()}).status_code, 200)
        self.assertEqual(self.client.post("/api/nist/catalog/import", headers=self.analyst_headers, json={"catalog": load_nist_catalog(), "dry_run": True}).status_code, 403)

    def test_non_platform_admin_cannot_mutate_global_catalog(self):
        # H3 invariant: the catalog is a platform-global vendor baseline, so a
        # tenant-scoped admin (admin role, but NOT the built-in admin/default
        # platform admin) must not import/activate/rollback it.
        try:
            create_user("nist_tenant_admin", hash_password("Admin123"), "admin", "default", "Tenant Admin")
        except Exception:
            pass
        headers = {"Authorization": f"Bearer {create_token('nist_tenant_admin', 'admin', 'default')}"}
        self.assertEqual(
            self.client.post("/api/nist/catalog/import", headers=headers, json={"catalog": load_nist_catalog(), "dry_run": True}).status_code, 403
        )
        self.assertEqual(
            self.client.post("/api/nist/catalog/activate", headers=headers, json={"catalog_hash": "a" * 64}).status_code, 403
        )
        self.assertEqual(self.client.post("/api/nist/catalog/rollback", headers=headers).status_code, 403)

    def test_platform_admin_passes_the_catalog_gate(self):
        # The built-in platform admin (admin/default) is NOT blocked by the gate.
        headers = {"Authorization": f"Bearer {create_token('admin', 'admin', 'default')}"}
        resp = self.client.post("/api/nist/catalog/import", headers=headers, json={"catalog": load_nist_catalog(), "dry_run": True})
        self.assertNotEqual(resp.status_code, 403, "platform admin must pass the platform-admin gate")


if __name__ == "__main__":
    unittest.main()
