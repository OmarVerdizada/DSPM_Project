import unittest

from fastapi.testclient import TestClient

from backend.app import app
from backend.security import create_token, hash_password
from backend.store import create_user
from classification.compliance.nist_catalog import load_nist_catalog


class NISTAPITests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.admin_headers = {"Authorization": f"Bearer {create_token('admin', 'admin', 'default')}"}

    def test_status_and_catalog_endpoints(self):
        status = self.client.get("/api/nist/catalog/status", headers=self.admin_headers)
        catalog = self.client.get("/api/nist/catalog?limit=5", headers=self.admin_headers)

        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["rule_count"], 154)
        self.assertEqual(catalog.status_code, 200)
        self.assertEqual(len(catalog.json()["rules"]), 5)

    def test_validate_endpoint_accepts_catalog(self):
        response = self.client.post("/api/nist/catalog/validate", headers=self.admin_headers, json={"catalog": load_nist_catalog()})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["valid"])


if __name__ == "__main__":
    unittest.main()

