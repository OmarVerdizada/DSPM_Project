"""SC-15 regression: only the platform admin may pivot tenants via X-Tenant-ID."""

from __future__ import annotations

import unittest
from uuid import uuid4

from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient

from backend import store
from backend.app import app
from backend.security import create_token, hash_password, is_platform_admin, require_principal


def _creds(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


class TenantPivotTests(unittest.TestCase):
    def test_is_platform_admin_definition(self) -> None:
        from backend.security import Principal

        self.assertTrue(is_platform_admin(Principal("admin", "admin", "default")))
        self.assertFalse(is_platform_admin(Principal("admin", "admin", "tenant-x")))
        self.assertFalse(is_platform_admin(Principal("alice", "admin", "default")))
        self.assertFalse(is_platform_admin(Principal("admin", "analyst", "default")))

    def test_platform_admin_may_pivot(self) -> None:
        target = f"pivot-target-{uuid4().hex[:8]}"
        store.create_tenant(target, "Pivot Target")
        # the built-in admin/default is the platform admin
        principal = require_principal(_creds(create_token("admin", "admin", "default")), None, target)
        self.assertEqual(principal.tenant_id, target)
        self.assertEqual(principal.home_tenant_id, "default")
        self.assertTrue(is_platform_admin(principal), "a tenant pivot must not discard platform authority")

    def test_local_administrator_keeps_platform_controls_while_pivoted(self) -> None:
        target = f"pivot-ui-{uuid4().hex[:8]}"
        created = f"created-from-pivot-{uuid4().hex[:8]}"
        store.create_tenant(target, "Pivot UI")
        token = create_token("admin", "admin", "default")
        client = TestClient(app)
        pivot_headers = {
            "Authorization": f"Bearer {token}",
            "X-Tenant-ID": target,
        }

        portfolio = client.get("/api/tenants", headers=pivot_headers)
        self.assertEqual(portfolio.status_code, 200, portfolio.text)
        tenant_ids = {item["tenant_id"] for item in portfolio.json()["tenants"]}
        self.assertIn("default", tenant_ids)
        self.assertIn(target, tenant_ids)

        create_response = client.post(
            "/api/tenants",
            headers=pivot_headers,
            json={"tenant_id": created, "display_name": "Created while pivoted"},
        )
        self.assertEqual(create_response.status_code, 200, create_response.text)

        # Switching back is just another effective scope on the same token.
        default_headers = {
            "Authorization": f"Bearer {token}",
            "X-Tenant-ID": "default",
        }
        back_to_default = client.get("/api/tenants", headers=default_headers)
        self.assertEqual(back_to_default.status_code, 200, back_to_default.text)
        self.assertIn(created, {item["tenant_id"] for item in back_to_default.json()["tenants"]})

    def test_dashboard_history_and_inventory_are_isolated_per_pivot(self) -> None:
        """A fresh tenant must not inherit any informational dashboard state.

        The platform admin deliberately reuses one token while changing the
        effective tenant header, which is the same path exercised by the UI
        switcher and the Posture trend regression.
        """
        populated = f"dashboard-a-{uuid4().hex[:8]}"
        fresh = f"dashboard-b-{uuid4().hex[:8]}"
        store.create_tenant(populated, "Populated dashboard")
        store.create_tenant(fresh, "Fresh dashboard")
        self.addCleanup(store.delete_tenant_with_data, populated)
        self.addCleanup(store.delete_tenant_with_data, fresh)
        store.save_scan_history(populated, {
            "scan_id": f"{populated}-scan",
            "timestamp": "2026-09-01T12:00:00+00:00",
            "source": "smb",
            "scan_label": "Finance source",
            "summary": {"total_files": 1, "critical": 1, "high": 0, "medium": 0, "low": 0},
            "files": [{
                "path": "/finance/exposure.txt",
                "name": "exposure.txt",
                "risk": {"level": "CRITICAL", "score": 95},
                "findings": [{"type": "secret", "risk": "CRITICAL"}],
            }],
        })

        token = create_token("admin", "admin", "default")
        client = TestClient(app)

        def get(path: str, tenant_id: str):
            return client.get(path, headers={
                "Authorization": f"Bearer {token}",
                "X-Tenant-ID": tenant_id,
            })

        populated_dashboard = get("/api/executive-dashboard", populated).json()
        fresh_dashboard = get("/api/executive-dashboard", fresh).json()
        self.assertEqual(populated_dashboard["tenant_id"], populated)
        self.assertEqual([item["scan_id"] for item in populated_dashboard["trend"]], [f"{populated}-scan"])
        self.assertEqual(fresh_dashboard["tenant_id"], fresh)
        self.assertEqual(fresh_dashboard["trend"], [])
        self.assertEqual(fresh_dashboard["risk_posture_score"], 100)

        for path in ("/api/history", "/api/history/hash-changes", "/api/inventory/facets", "/api/inventory"):
            response = get(path, fresh)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["tenant_id"], fresh, path)
        self.assertEqual(get("/api/history", fresh).json()["history"], [])
        self.assertEqual(get("/api/inventory/facets", fresh).json()["total"], 0)
        self.assertEqual(get("/api/inventory", fresh).json()["items"], [])

    def test_tenant_admin_may_not_pivot(self) -> None:
        home = f"tenant-a-{uuid4().hex[:8]}"
        victim = f"victim-{uuid4().hex[:8]}"
        store.create_tenant(home, "Tenant A")
        store.create_tenant(victim, "Victim Tenant")
        uname = f"tadmin{uuid4().hex[:6]}"
        store.create_user(uname, hash_password("Password123"), "admin", home, "Tenant A Admin")

        # a tenant-scoped admin sets X-Tenant-ID to another tenant -> ignored
        principal = require_principal(_creds(create_token(uname, "admin", home)), None, victim)
        self.assertEqual(principal.tenant_id, home)


if __name__ == "__main__":
    unittest.main()
