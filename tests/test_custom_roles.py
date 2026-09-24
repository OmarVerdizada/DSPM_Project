"""M2/C3: a tenant defines its own roles.

The built-in roles are fixed sets of permissions. A custom role is the same thing under a
name the tenant chooses - "privacy_reviewer" reads evidence and the audit trail and
changes nothing - stored per tenant (revision 0021) and resolved within it: two tenants
may use one name for different sets, and a name one tenant defined means nothing in
another. The installation's own permission is never assignable, and a role still held
by an account, an API key or an open invite is not deleted from under it.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend import migrations, permissions, security, store
from backend.app import app

TENANT = "tenant-roles"
OTHER = "tenant-roles-other"
PASSWORD = "a-custom-roles-pass-8"
REVIEWER = ["inventory.view", "evidence.view", "audit.view"]


class _RolesCase(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "roles.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        for tenant in (TENANT, OTHER):
            store.create_tenant(tenant, tenant)
        self.password_hash = security.hash_password(PASSWORD)
        store.create_user("roles-boss", self.password_hash, "admin", TENANT)
        store.create_user("roles-other-boss", self.password_hash, "admin", OTHER)
        store.create_user("roles-member", self.password_hash, "viewer", TENANT)
        store._forget_revocation()
        security._session_last_seen.clear()
        self.addCleanup(store._forget_revocation)
        self.addCleanup(security._session_last_seen.clear)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def _as(self, user: str, role: str, tenant: str = TENANT) -> dict:
        return {"Authorization": f"Bearer {security.create_token(user, role, tenant)}"}

    @property
    def boss(self) -> dict:
        return self._as("roles-boss", "admin")

    def _create(self, name: str = "privacy_reviewer", granted: list[str] | None = None, headers: dict | None = None):
        return self.client.post("/api/roles", headers=headers or self.boss, json={
            "name": name, "label": "Privacy reviewer", "permissions": granted if granted is not None else REVIEWER,
        })


class DefiningARoleTest(_RolesCase):

    def test_a_role_is_created_listed_and_audited(self) -> None:
        response = self._create()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["role"]["permissions"], sorted(REVIEWER))
        names = [role["name"] for role in self.client.get("/api/roles", headers=self.boss).json()["roles"]]
        self.assertEqual(names, list(permissions.BUILTIN_ROLES) + ["privacy_reviewer"])
        actions = [event["action"] for event in store.read_audit_log(TENANT, 20)]
        self.assertIn("role.created", actions)

    def test_what_a_role_may_not_be(self) -> None:
        for name, granted, why in (
            ("analyst", REVIEWER, "built-in"),
            ("Privacy Reviewer", REVIEWER, "lowercase"),
            ("pr", REVIEWER, "lowercase"),
            ("ops_superuser", ["inventory.view", "platform.admin"], "platform.admin"),
            ("ops_wizard", ["inventory.view", "scans.run"], "Unknown permission"),
            ("ops_nothing", [], "at least one"),
        ):
            with self.subTest(name=name):
                response = self._create(name, granted)
                self.assertEqual(response.status_code, 400, response.text)
                self.assertIn(why, response.json()["detail"])

    def test_a_name_is_taken_once_per_tenant(self) -> None:
        self._create()
        self.assertEqual(self._create().status_code, 409)

    def test_only_an_administrator_defines_roles(self) -> None:
        response = self._create(headers=self._as("roles-member", "viewer"))
        self.assertEqual(response.status_code, 403)


class HoldingARoleTest(_RolesCase):

    def setUp(self) -> None:
        super().setUp()
        self.assertEqual(self._create().status_code, 200)
        moved = self.client.put("/api/users/roles-member/role", headers=self.boss, json={"role": "privacy_reviewer"})
        self.assertEqual(moved.status_code, 200, moved.text)
        self.member = self._as("roles-member", "privacy_reviewer")

    def test_the_account_can_do_exactly_what_the_role_says(self) -> None:
        self.assertEqual(self.client.get("/api/audit", headers=self.member).status_code, 200)
        self.assertEqual(self.client.get("/api/inventory", headers=self.member).status_code, 200)
        self.assertEqual(self.client.get("/api/nist/catalog/export", headers=self.member).status_code, 403)
        self.assertEqual(self.client.post("/api/findings/f-1/comment", headers=self.member,
                                          json={"comment": "x"}).status_code, 403)
        profile = self.client.get("/api/profile", headers=self.member).json()
        self.assertEqual(profile["permissions"], sorted(REVIEWER))

    def test_signing_in_with_it_works_and_says_so(self) -> None:
        login = self.client.post("/api/auth/login", json={"username": "roles-member", "password": PASSWORD})
        self.assertEqual(login.status_code, 200, login.text)
        self.assertEqual(login.json()["role"], "privacy_reviewer")
        self.assertEqual(login.json()["permissions"], sorted(REVIEWER))

    def test_a_change_to_the_role_applies_at_once(self) -> None:
        changed = self.client.put("/api/roles/privacy_reviewer", headers=self.boss,
                                  json={"permissions": REVIEWER + ["export"]})
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertEqual(self.client.get("/api/nist/catalog/export", headers=self.member).status_code, 200)
        actions = [event["action"] for event in store.read_audit_log(TENANT, 20)]
        self.assertIn("role.updated", actions)

    def test_a_held_role_is_not_deleted(self) -> None:
        refused = self.client.delete("/api/roles/privacy_reviewer", headers=self.boss)
        self.assertEqual(refused.status_code, 409, refused.text)
        self.assertIn("1 user", refused.json()["detail"])
        self.client.put("/api/users/roles-member/role", headers=self.boss, json={"role": "viewer"})
        deleted = self.client.delete("/api/roles/privacy_reviewer", headers=self.boss)
        self.assertEqual(deleted.status_code, 200, deleted.text)
        self.assertIsNone(store.get_custom_role(TENANT, "privacy_reviewer"))

    def test_a_built_in_role_is_neither_changed_nor_deleted(self) -> None:
        self.assertEqual(self.client.put("/api/roles/viewer", headers=self.boss,
                                         json={"permissions": ["export"]}).status_code, 400)
        self.assertEqual(self.client.delete("/api/roles/viewer", headers=self.boss).status_code, 400)

    def test_invites_and_keys_may_carry_it_but_not_one_that_administers(self) -> None:
        invite = self.client.post(f"/api/tenants/{TENANT}/invites", headers=self.boss, json={"role": "privacy_reviewer"})
        self.assertEqual(invite.status_code, 200, invite.text)
        key = self.client.post("/api/api-keys", headers=self.boss, json={"label": "reviewer", "role": "privacy_reviewer"})
        self.assertEqual(key.status_code, 200, key.text)
        by_key = self.client.get("/api/audit", headers={"X-API-Key": key.json()["api_key"]})
        self.assertEqual(by_key.status_code, 200, "an API key resolves its custom role in its tenant")
        self._create("deputy_admin", ["inventory.view", "tenant.admin"])
        self.assertEqual(self.client.post(f"/api/tenants/{TENANT}/invites", headers=self.boss,
                                          json={"role": "deputy_admin"}).status_code, 400)
        self.assertEqual(self.client.post("/api/api-keys", headers=self.boss,
                                          json={"label": "x", "role": "deputy_admin"}).status_code, 400)

    def test_the_last_administrator_is_not_removed_by_editing_a_role(self) -> None:
        self._create("owner_role", ["inventory.view", "tenant.admin"])
        self.client.put("/api/users/roles-boss/role", headers=self.boss, json={"role": "owner_role"})
        owner = self._as("roles-boss", "owner_role")
        refused = self.client.put("/api/roles/owner_role", headers=owner, json={"permissions": ["inventory.view"]})
        self.assertEqual(refused.status_code, 400, refused.text)
        self.assertIn("tenant.admin", store.get_custom_role(TENANT, "owner_role")["permissions"])


class ARoleBelongsToItsTenantTest(_RolesCase):

    def setUp(self) -> None:
        super().setUp()
        self._create()
        self.other = self._as("roles-other-boss", "admin", OTHER)

    def test_another_tenant_does_not_see_it(self) -> None:
        names = [role["name"] for role in self.client.get("/api/roles", headers=self.other).json()["roles"]]
        self.assertNotIn("privacy_reviewer", names)

    def test_nor_change_or_delete_it(self) -> None:
        self.assertEqual(self.client.put("/api/roles/privacy_reviewer", headers=self.other,
                                         json={"permissions": ["export"]}).status_code, 404)
        self.assertEqual(self.client.delete("/api/roles/privacy_reviewer", headers=self.other).status_code, 404)
        self.assertEqual(store.get_custom_role(TENANT, "privacy_reviewer")["permissions"], sorted(REVIEWER))

    def test_nor_give_it_to_its_own_users(self) -> None:
        response = self.client.post("/api/users", headers=self.other, json={
            "username": "other-reviewer", "password": "an-other-reviewer-4", "role": "privacy_reviewer", "tenant_id": OTHER})
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIsNone(store.get_user("other-reviewer"))

    def test_the_same_name_can_mean_something_else_there(self) -> None:
        response = self._create(granted=["inventory.view", "export"], headers=self.other)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(security.role_permissions_in("privacy_reviewer", OTHER), {"inventory.view", "export"})
        self.assertEqual(security.role_permissions_in("privacy_reviewer", TENANT), set(REVIEWER))

    def test_an_account_holding_a_name_its_tenant_lacks_is_refused(self) -> None:
        # A row written behind the application's back: the store refuses it, and so does
        # the session check, rather than granting what another tenant defined.
        with self.assertRaises(ValueError):
            store.create_user("other-reviewer", self.password_hash, "privacy_reviewer", OTHER)
        with store._connect() as conn:
            conn.execute("UPDATE users SET role = 'privacy_reviewer' WHERE username = 'roles-other-boss'")
        response = self.client.get("/api/profile", headers=self.other)
        self.assertEqual(response.status_code, 401)

    def test_erasing_the_tenant_erases_its_roles(self) -> None:
        store.delete_tenant_with_data(TENANT)
        self.assertEqual(store.list_custom_roles(TENANT), [])


class RevisionTwentyOneTest(unittest.TestCase):

    def test_an_install_at_revision_twenty_gains_the_table(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            original = store.DB_PATH
            store.DB_PATH = Path(tmp) / "r20.sqlite"
            try:
                migrations.upgrade()
                with store._connect() as conn:
                    conn.execute("DROP TABLE custom_roles")
                    conn.execute("DELETE FROM schema_migrations WHERE revision >= 21")
                migrations.upgrade()
                raw = sqlite3.connect(store.DB_PATH)
                columns = [row[1] for row in raw.execute("PRAGMA table_info(custom_roles)")]
                recorded = {row[0] for row in raw.execute("SELECT revision FROM schema_migrations")}
                raw.close()
            finally:
                store.DB_PATH = original
        self.assertEqual(columns, ["tenant_id", "name", "label", "description", "permissions",
                                   "created_by", "created_at", "updated_at"])
        self.assertIn(21, recorded)

    def test_the_table_is_erased_with_its_tenant(self) -> None:
        self.assertIn("custom_roles", store._TENANT_ERASURE_TABLES)


if __name__ == "__main__":
    unittest.main()
