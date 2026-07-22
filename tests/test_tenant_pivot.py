"""SC-15 regression: only the platform admin may pivot tenants via X-Tenant-ID."""

from __future__ import annotations

import unittest
from uuid import uuid4

from fastapi.security import HTTPAuthorizationCredentials

from backend import store
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
