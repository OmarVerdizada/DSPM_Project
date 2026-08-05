"""M5 (roadmap 1.7): registration-code lifecycle - time-boxed, limited-use invite
tokens with per-redemption audit and optional admin approval.

Acceptance: a code expires and caps redemptions; each redemption is audited."""

from __future__ import annotations

import hashlib
import secrets
import unittest
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from backend import store
from backend.app import app
from backend.security import create_token
from backend.store import (
    create_registration_invite,
    delete_user,
    get_user,
    list_registration_invites,
    redeem_registration_invite,
    revoke_registration_invite,
)


def _hash(token: str) -> str:
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


def _expires(hours: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


class InviteStoreLifecycleTests(unittest.TestCase):
    TENANT = "t_invite_store_test"

    def tearDown(self) -> None:
        with store._connect() as conn:
            conn.execute("DELETE FROM registration_invites WHERE tenant_id = ?", (self.TENANT,))

    def _create(self, *, max_uses=1, hours=1.0, requires_approval=False, role="viewer"):
        token = "tok_" + secrets.token_urlsafe(8)
        invite_id = create_registration_invite(
            self.TENANT, _hash(token), role, max_uses, _expires(hours), requires_approval, "admin"
        )
        return token, _hash(token), invite_id

    def test_redeem_increments_and_caps(self) -> None:
        _, token_hash, _ = self._create(max_uses=2)
        first = redeem_registration_invite(self.TENANT, token_hash)
        self.assertEqual((first["role"], first["used_count"]), ("viewer", 1))
        second = redeem_registration_invite(self.TENANT, token_hash)
        self.assertEqual(second["used_count"], 2)
        self.assertIsNone(redeem_registration_invite(self.TENANT, token_hash))  # cap reached

    def test_expired_invite_is_refused(self) -> None:
        _, token_hash, _ = self._create(hours=-1.0)  # already in the past
        self.assertIsNone(redeem_registration_invite(self.TENANT, token_hash))

    def test_revoked_invite_is_refused(self) -> None:
        _, token_hash, invite_id = self._create(max_uses=5)
        self.assertTrue(revoke_registration_invite(self.TENANT, invite_id))
        self.assertIsNone(redeem_registration_invite(self.TENANT, token_hash))

    def test_wrong_tenant_cannot_redeem(self) -> None:
        _, token_hash, _ = self._create()
        self.assertIsNone(redeem_registration_invite("some_other_tenant", token_hash))

    def test_list_reports_invite(self) -> None:
        _, _, invite_id = self._create()
        self.assertIn(invite_id, [i["id"] for i in list_registration_invites(self.TENANT)])


class InviteEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.admin = {"Authorization": f"Bearer {create_token('admin', 'admin', 'default')}"}
        self._users: list[str] = []
        self._invites: list[str] = []

    def tearDown(self) -> None:
        for username in self._users:
            delete_user(username)
        if self._invites:
            with store._connect() as conn:
                conn.executemany(
                    "DELETE FROM registration_invites WHERE id = ?", [(i,) for i in self._invites]
                )

    def _make_invite(self, **body) -> dict:
        response = self.client.post("/api/tenants/default/invites", headers=self.admin, json=body)
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self._invites.append(data["invite_id"])
        return data

    def _register(self, username: str, token: str) -> "object":
        self._users.append(username)
        return self.client.post(
            "/api/auth/register",
            json={"username": username, "password": "Str0ng-Pass_123", "tenant_id": "default", "registration_code": token},
        )

    def test_register_with_invite_then_single_use_cap(self) -> None:
        invite = self._make_invite(role="viewer", max_uses=1, ttl_hours=1)
        ok = self._register("inv_user_a", invite["token"])
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertFalse(ok.json()["pending_approval"])
        # single-use invite: a second registration is refused (cap).
        capped = self._register("inv_user_b", invite["token"])
        self.assertEqual(capped.status_code, 403)

    def test_requires_approval_creates_inactive_user_with_invite_role(self) -> None:
        invite = self._make_invite(role="analyst", max_uses=1, requires_approval=True)
        response = self._register("inv_pending", invite["token"])
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["pending_approval"])
        user = get_user("inv_pending")
        self.assertEqual(user["role"], "analyst")     # role comes from the invite
        self.assertFalse(user["is_active"])            # inactive until an admin activates

    def test_invite_role_admin_is_rejected(self) -> None:
        response = self.client.post("/api/tenants/default/invites", headers=self.admin, json={"role": "admin"})
        self.assertEqual(response.status_code, 400)

    def test_revoked_invite_blocks_registration(self) -> None:
        invite = self._make_invite(max_uses=5)
        revoke = self.client.post(
            f"/api/tenants/default/invites/{invite['invite_id']}/revoke", headers=self.admin
        )
        self.assertEqual(revoke.status_code, 200)
        blocked = self._register("inv_revoked", invite["token"])
        self.assertEqual(blocked.status_code, 403)

    def test_bad_token_is_refused(self) -> None:
        blocked = self._register("inv_badtoken", "inv_not_a_real_token")
        self.assertEqual(blocked.status_code, 403)


if __name__ == "__main__":
    unittest.main()
