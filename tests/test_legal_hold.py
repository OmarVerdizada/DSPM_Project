"""Legal hold (roadmap Phase 6, DB-11).

Retention deletes data on a schedule and erasure deletes it on request. A
legal hold is the instruction that outranks both, for as long as an
investigation or dispute requires. It lives in the database rather than in a
runbook because the code paths that delete data are the ones that must honour
it - trusting an operator to remember is how preserved data gets destroyed.
"""

from __future__ import annotations

import unittest
from uuid import uuid4

from backend import store


class LegalHoldState(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant = f"hold-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "Hold tenant")

        def _cleanup() -> None:
            try:
                store.set_legal_hold(self.tenant, False)
            except Exception:
                pass
            try:
                store.delete_tenant_with_data(self.tenant)
            except Exception:
                pass

        self.addCleanup(_cleanup)

    def test_a_new_tenant_is_not_held(self) -> None:
        hold = store.get_legal_hold(self.tenant)
        self.assertFalse(hold["active"])
        self.assertEqual(hold["reason"], "")

    def test_placing_a_hold_requires_a_reason(self) -> None:
        with self.assertRaises(ValueError):
            store.set_legal_hold(self.tenant, True, "   ")

    def test_hold_records_reason_and_time(self) -> None:
        hold = store.set_legal_hold(self.tenant, True, "Matter 2026-114")
        self.assertTrue(hold["active"])
        self.assertEqual(hold["reason"], "Matter 2026-114")
        self.assertTrue(hold["set_at"])
        self.assertIn(self.tenant, store.tenants_under_legal_hold())

    def test_lifting_a_hold_clears_it(self) -> None:
        store.set_legal_hold(self.tenant, True, "Matter 2026-114")
        lifted = store.set_legal_hold(self.tenant, False)
        self.assertFalse(lifted["active"])
        self.assertEqual(lifted["reason"], "")
        self.assertNotIn(self.tenant, store.tenants_under_legal_hold())

    def test_setting_a_hold_on_an_unknown_tenant_is_an_error(self) -> None:
        with self.assertRaises(ValueError):
            store.set_legal_hold(f"absent-{uuid4().hex[:8]}", True, "reason")


class HoldBlocksDestruction(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant = f"hold-erase-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "Hold erase")
        store.save_scan_history(self.tenant, {
            "scan_id": "held-scan",
            "source": "smb",
            "summary": {"total_files": 1},
            "files": [{
                "path": "/held/doc.txt", "name": "doc.txt",
                "risk": {"level": "HIGH", "score": 80},
                "findings": [{"type": "email", "risk": "HIGH"}],
            }],
        })

    def tearDown(self) -> None:
        try:
            store.set_legal_hold(self.tenant, False)
            store.delete_tenant_with_data(self.tenant)
        except Exception:
            pass

    def test_erasure_is_refused_while_held(self) -> None:
        store.set_legal_hold(self.tenant, True, "Preservation notice")
        with self.assertRaises(store.LegalHoldActive) as caught:
            store.delete_tenant_with_data(self.tenant)
        self.assertIn("legal hold", str(caught.exception))
        # And the data is genuinely still there.
        self.assertTrue(store.tenant_exists(self.tenant))
        self.assertEqual(len(store.read_scan_history(self.tenant)), 1)

    def test_erasure_proceeds_once_the_hold_is_lifted(self) -> None:
        store.set_legal_hold(self.tenant, True, "Preservation notice")
        with self.assertRaises(store.LegalHoldActive):
            store.delete_tenant_with_data(self.tenant)
        store.set_legal_hold(self.tenant, False)
        store.delete_tenant_with_data(self.tenant)
        self.assertFalse(store.tenant_exists(self.tenant))


class HoldRoutes(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient
        from backend.app import app
        from backend.security import create_token

        self.client = TestClient(app)
        self.admin = {"Authorization": f"Bearer {create_token('admin', 'admin', 'default')}"}
        self.tenant = f"hold-api-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "Hold API")

        def _cleanup() -> None:
            try:
                store.set_legal_hold(self.tenant, False)
                store.delete_tenant_with_data(self.tenant)
            except Exception:
                pass

        self.addCleanup(_cleanup)

    def test_hold_requires_platform_admin(self) -> None:
        response = self.client.get(f"/api/tenants/{self.tenant}/legal-hold")
        self.assertIn(response.status_code, (401, 403))

    def test_place_read_and_lift_through_the_api(self) -> None:
        placed = self.client.put(
            f"/api/tenants/{self.tenant}/legal-hold",
            headers=self.admin, json={"active": True, "reason": "Matter 7"},
        )
        self.assertEqual(placed.status_code, 200, placed.text)
        self.assertTrue(placed.json()["active"])

        read = self.client.get(f"/api/tenants/{self.tenant}/legal-hold", headers=self.admin)
        self.assertEqual(read.json()["reason"], "Matter 7")

        # Deleting the tenant now conflicts with its state, not its request.
        blocked = self.client.delete(f"/api/tenants/{self.tenant}", headers=self.admin)
        self.assertEqual(blocked.status_code, 409, blocked.text)

        lifted = self.client.put(
            f"/api/tenants/{self.tenant}/legal-hold",
            headers=self.admin, json={"active": False},
        )
        self.assertEqual(lifted.status_code, 200)
        self.assertFalse(lifted.json()["active"])

    def test_a_hold_without_a_reason_is_rejected(self) -> None:
        response = self.client.put(
            f"/api/tenants/{self.tenant}/legal-hold",
            headers=self.admin, json={"active": True, "reason": ""},
        )
        self.assertEqual(response.status_code, 400, response.text)


if __name__ == "__main__":
    unittest.main()
