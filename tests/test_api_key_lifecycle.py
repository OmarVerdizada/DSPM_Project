"""M18 (roadmap 1.10): DB-backed API keys with a full lifecycle - a key is
revocable and expirable WITHOUT a redeploy; expired keys reject."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend import store
from backend.app import app
from backend.security import create_token, generate_api_key, require_principal


def _future() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()


def _past() -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()


class ApiKeyStoreTests(unittest.TestCase):
    TENANT = "t_apikey_store"

    def setUp(self) -> None:
        if not store.tenant_exists(self.TENANT):
            store.create_tenant(self.TENANT, self.TENANT)

    def tearDown(self) -> None:
        with store._connect() as conn:
            conn.execute("DELETE FROM api_keys WHERE tenant_id = ?", (self.TENANT,))

    def test_create_lookup_revoke(self) -> None:
        _, key_hash = generate_api_key()
        key_id = store.create_api_key_record(self.TENANT, key_hash, "ci", "analyst", "admin", _future())
        self.assertEqual(store.get_active_api_key(key_hash)["id"], key_id)
        self.assertTrue(store.revoke_api_key(self.TENANT, key_id))
        self.assertIsNone(store.get_active_api_key(key_hash))  # revoked -> gone

    def test_expired_key_is_inactive(self) -> None:
        _, key_hash = generate_api_key()
        store.create_api_key_record(self.TENANT, key_hash, "old", "viewer", "admin", _past())
        self.assertIsNone(store.get_active_api_key(key_hash))


class ApiKeyAuthTests(unittest.TestCase):
    TENANT = "t_apikey_auth"

    def setUp(self) -> None:
        if not store.tenant_exists(self.TENANT):
            store.create_tenant(self.TENANT, self.TENANT)

    def tearDown(self) -> None:
        with store._connect() as conn:
            conn.execute("DELETE FROM api_keys WHERE tenant_id = ?", (self.TENANT,))

    def test_valid_key_authenticates_then_revoke_rejects(self) -> None:
        raw, key_hash = generate_api_key()
        key_id = store.create_api_key_record(self.TENANT, key_hash, "svc", "analyst", "admin", _future())

        principal = require_principal(None, raw, None)
        self.assertEqual((principal.role, principal.tenant_id, principal.auth_type), ("analyst", self.TENANT, "api_key"))

        # Revoke at runtime - the very next call is rejected, no redeploy.
        store.revoke_api_key(self.TENANT, key_id)
        with self.assertRaises(HTTPException) as ctx:
            require_principal(None, raw, None)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_expired_key_is_rejected(self) -> None:
        raw, key_hash = generate_api_key()
        store.create_api_key_record(self.TENANT, key_hash, "old", "viewer", "admin", _past())
        with self.assertRaises(HTTPException) as ctx:
            require_principal(None, raw, None)
        self.assertEqual(ctx.exception.status_code, 401)


class ApiKeyManagementRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.admin = {"Authorization": f"Bearer {create_token('admin', 'admin', 'default')}"}
        self._key_ids: list[str] = []

    def tearDown(self) -> None:
        with store._connect() as conn:
            for key_id in self._key_ids:
                conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))

    def test_create_use_and_revoke_via_api(self) -> None:
        created = self.client.post("/api/api-keys", headers=self.admin, json={"label": "ci", "role": "viewer", "ttl_days": 30})
        self.assertEqual(created.status_code, 200, created.text)
        data = created.json()
        self._key_ids.append(data["key_id"])
        raw = data["api_key"]

        # The key works on a viewer endpoint.
        used = self.client.get("/api/risk-rules", headers={"X-API-Key": raw})
        self.assertEqual(used.status_code, 200, used.text)

        # It appears in the management listing.
        listing = self.client.get("/api/api-keys", headers=self.admin)
        self.assertIn(data["key_id"], [k["id"] for k in listing.json()["api_keys"]])

        # Revoke it -> immediately rejected (no redeploy).
        revoked = self.client.post(f"/api/api-keys/{data['key_id']}/revoke", headers=self.admin)
        self.assertEqual(revoked.status_code, 200)
        after = self.client.get("/api/risk-rules", headers={"X-API-Key": raw})
        self.assertEqual(after.status_code, 401)

    def test_admin_role_key_is_rejected(self) -> None:
        response = self.client.post("/api/api-keys", headers=self.admin, json={"role": "admin"})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
