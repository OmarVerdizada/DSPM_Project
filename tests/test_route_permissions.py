"""M2/C3: every route names the permission it needs, and roles are sets of permissions.

Authorization was three ranks, viewer < analyst < admin, and each route stated the lowest
rank it accepted. A rank cannot say "may run scans but not read what they found", and it
put every read behind the same door - a viewer could export the inventory, file reports,
fetch keyword libraries and catalogues, and read scan configuration, because all of those
were reads (the Phase C/D roadmap's S13).

The gate for C3 begins here: a route-permission matrix over every registered route. It is
written out below rather than derived, so that adding a route, or moving one to a
different permission, is a visible change to this file - the same discipline
tests/test_every_route_is_guarded.py applies to public routes.
"""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from backend import app as app_module
from backend import db, migrations, permissions, security, store
from backend.app import app

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
SMOKE = ROOT / "tests" / "js" / "refresh_retry_smoke.js"

PUBLIC = "PUBLIC"
AUTH = permissions.AUTHENTICATED

# Every API route, by method and path, and the permission(s) it accepts. A tuple means any one.
MATRIX: dict[tuple[str, str], str | tuple[str, ...]] = {
    ("POST", "/api/auth/login"): PUBLIC,
    ("POST", "/api/auth/refresh"): PUBLIC,
    ("POST", "/api/auth/register"): PUBLIC,
    # C2: the second step of sign-in. The five-minute challenge token from the password
    # step is the credential; without one, each answers 401.
    ("GET", "/api/health"): PUBLIC,
    ("GET", "/api/ready"): PUBLIC,
    # self-service: an account's own profile, password and sign-out
    ("POST", "/api/auth/change-password"): AUTH,
    ("POST", "/api/auth/logout"): AUTH,
    ("POST", "/api/logout"): AUTH,
    ("GET", "/api/profile"): AUTH,
    ("PUT", "/api/profile"): AUTH,
    ("PUT", "/api/profile/avatar"): AUTH,
    ("GET", "/api/settings/features"): AUTH,
    # reading the estate
    ("GET", "/api/compliance-keywords"): "inventory.view",
    ("GET", "/api/compliance-keywords/template"): "inventory.view",
    ("GET", "/api/executive-dashboard"): "inventory.view",
    ("GET", "/api/findings"): "inventory.view",
    ("POST", "/api/findings/detail"): "inventory.view",
    ("GET", "/api/findings/{finding_id}"): "inventory.view",
    ("GET", "/api/findings/{finding_id}/history"): "inventory.view",
    ("GET", "/api/findings/{finding_id}/occurrences"): "inventory.view",
    ("GET", "/api/history"): "inventory.view",
    ("GET", "/api/history/hash-changes"): "inventory.view",
    ("GET", "/api/history/latest/report"): "inventory.view",
    ("GET", "/api/history/{scan_id}/report"): "inventory.view",
    ("GET", "/api/inventory"): "inventory.view",
    ("GET", "/api/inventory-detail-counts"): "inventory.view",
    ("GET", "/api/inventory/facets"): "inventory.view",
    ("GET", "/api/inventory/{asset_id}"): "inventory.view",
    ("GET", "/api/nist/catalog"): "inventory.view",
    ("GET", "/api/nist/catalog/rules/{rule_id}"): "inventory.view",
    ("GET", "/api/nist/catalog/status"): "inventory.view",
    ("GET", "/api/risk-rules"): "inventory.view",
    ("GET", "/api/scans/{job_id}"): "inventory.view",
    ("GET", "/api/suppression-rules"): "inventory.view",
    # scanning, and the configuration that describes targets
    ("POST", "/api/demo-data/generate"): "scan.run",
    ("POST", "/api/endpoint/activate-local-winrm"): "scan.run",
    ("POST", "/api/endpoint/activate-winrm"): "scan.run",
    ("POST", "/api/endpoint/check-access"): "scan.run",
    ("POST", "/api/endpoint/repair-winrm"): "scan.run",
    ("POST", "/api/endpoint/scan"): "scan.run",
    ("POST", "/api/endpoint/test-connection"): "scan.run",
    ("POST", "/api/scan"): "scan.run",
    ("GET", "/api/scan-profiles"): "scan.run",
    ("POST", "/api/scan-profiles"): "scan.run",
    ("DELETE", "/api/scan-profiles/{profile_id}"): "scan.run",
    ("GET", "/api/scan-schedules"): "scan.run",
    ("POST", "/api/scan-schedules"): "scan.run",
    ("DELETE", "/api/scan-schedules/{schedule_id}"): "scan.run",
    ("PATCH", "/api/scan-schedules/{schedule_id}"): "scan.run",
    ("POST", "/api/scan-schedules/{schedule_id}/run"): "scan.run",
    ("POST", "/api/scans/{job_id}/cancel"): "scan.run",
    ("POST", "/api/test-connection"): "scan.run",
    # the console vaults a typed password before every scan
    ("POST", "/api/credentials"): ("scan.run", "credential.manage"),
    # working the findings
    ("POST", "/api/findings/{finding_id}/assign"): "findings.triage",
    ("POST", "/api/findings/{finding_id}/comment"): "findings.triage",
    ("POST", "/api/findings/{finding_id}/false-positive"): "findings.triage",
    ("POST", "/api/findings/{finding_id}/reopen"): "findings.triage",
    ("POST", "/api/findings/{finding_id}/resolve"): "findings.triage",
    ("POST", "/api/findings/{finding_id}/risk-acceptance"): "findings.triage",
    ("PATCH", "/api/findings/{finding_id}/status"): "findings.triage",
    ("POST", "/api/findings/{finding_id}/suppress"): "findings.triage",
    ("POST", "/api/findings/{finding_id}/validate"): "findings.triage",
    ("PATCH", "/api/history/{scan_id}/findings/workflow"): "findings.triage",
    ("POST", "/api/compliance-keywords/import"): "rules.manage",
    ("POST", "/api/compliance-keywords/validate"): "rules.manage",
    ("POST", "/api/nist/catalog/validate"): "rules.manage",
    ("POST", "/api/suppression-rules"): "rules.manage",
    ("DELETE", "/api/suppression-rules/{rule_id}"): "rules.manage",
    ("PATCH", "/api/suppression-rules/{rule_id}"): "rules.manage",
    # what leaves the product
    ("GET", "/api/compliance-keywords/export"): "export",
    ("POST", "/api/dlp-policy"): "export",
    ("GET", "/api/inventory/export"): "export",
    ("GET", "/api/nist/catalog/export"): "export",
    ("POST", "/api/v1/reports"): "report.create",
    ("POST", "/api/v1/reports/office"): "report.create",
    ("GET", "/api/v1/reports/artifacts/{artifact_id}"): "report.create",
    ("GET", "/api/audit"): "audit.view",
    ("GET", "/api/audit/verify"): "audit.view",
    ("GET", "/api/users/activity"): "audit.view",
    # the tenant's own administration
    ("GET", "/api/api-keys"): "tenant.admin",
    ("POST", "/api/api-keys"): "tenant.admin",
    ("POST", "/api/api-keys/{key_id}/revoke"): "tenant.admin",
    ("GET", "/api/roles"): "tenant.admin",
    ("POST", "/api/roles"): "tenant.admin",
    ("PUT", "/api/roles/{name}"): "tenant.admin",
    ("DELETE", "/api/roles/{name}"): "tenant.admin",
    ("GET", "/api/scan-targets"): ("scan.run", "tenant.admin"),
    ("POST", "/api/scan-targets"): "tenant.admin",
    ("DELETE", "/api/scan-targets/{entry_id}"): "tenant.admin",
    ("POST", "/api/scan-targets/check"): ("scan.run", "tenant.admin"),
    ("GET", "/api/tenants"): "tenant.admin",
    ("GET", "/api/tenants/{tenant_id}/invites"): "tenant.admin",
    ("POST", "/api/tenants/{tenant_id}/invites"): "tenant.admin",
    ("POST", "/api/tenants/{tenant_id}/invites/{invite_id}/revoke"): "tenant.admin",
    ("POST", "/api/tenants/{tenant_id}/regenerate-registration-code"): "tenant.admin",
    ("POST", "/api/tenants/{tenant_id}/registration-code"): "tenant.admin",
    ("GET", "/api/users"): "tenant.admin",
    ("POST", "/api/users"): "tenant.admin",
    ("DELETE", "/api/users/{username}"): "tenant.admin",
    ("PUT", "/api/users/{username}/active"): "tenant.admin",
    ("POST", "/api/users/{username}/delete"): "tenant.admin",
    ("POST", "/api/users/{username}/reset-password"): "tenant.admin",
    ("PUT", "/api/users/{username}/role"): "tenant.admin",
    # C12: saved credentials - listed, replaced, checked and deleted by a credential manager
    ("GET", "/api/credentials"): "credential.manage",
    # C13: one raw value, read again from its source
    ("POST", "/api/findings/{finding_id}/reveal"): "evidence.reveal",
    # D7: who can read the estate's files
    ("GET", "/api/access/principals"): "inventory.view",
    ("GET", "/api/access/files"): "inventory.view",
    # Revision 0055: one file's owner and permissions, the headline numbers, the changes.
    ("GET", "/api/access/assets/{asset_id}"): "inventory.view",
    ("GET", "/api/access/summary"): "inventory.view",
    ("GET", "/api/access/changes"): "inventory.view",
    # D2: exact-data-match reference sets
    ("POST", "/api/exact-match/sets"): "rules.manage",
    ("GET", "/api/exact-match/sets"): "rules.manage",
    ("DELETE", "/api/exact-match/sets/{set_id}"): "rules.manage",
    ("GET", "/api/alerts"): "inventory.view",
    ("POST", "/api/alerts/{alert_id}/acknowledge"): "findings.triage",
    ("GET", "/api/integrations"): "tenant.admin",
    ("PUT", "/api/integrations/{channel}"): "tenant.admin",
    ("PUT", "/api/integrations/{channel}/enabled"): "tenant.admin",
    ("POST", "/api/integrations/{channel}/test"): "tenant.admin",
    ("POST", "/api/integrations/{channel}/retry"): "tenant.admin",
    ("DELETE", "/api/integrations/{channel}"): "tenant.admin",
    ("POST", "/api/findings/{finding_id}/ticket"): "findings.triage",
    ("GET", "/api/tickets/systems"): "findings.triage",
    ("GET", "/api/tickets"): "inventory.view",
    ("POST", "/api/tickets/sync"): "findings.triage",
    ("GET", "/api/licence"): "platform.admin",
    ("POST", "/api/database/scan"): "scan.run",
    ("POST", "/api/sharepoint/scan"): "scan.run",
    ("POST", "/api/sftp/scan"): "scan.run",
    ("PUT", "/api/licence"): "platform.admin",
    ("PUT", "/api/credentials/{secret_ref}"): "credential.manage",
    ("DELETE", "/api/credentials/{secret_ref}"): "credential.manage",
    ("POST", "/api/credentials/{secret_ref}/preflight"): "credential.manage",
    # C2: the workspace's directory sign-in
    ("GET", "/api/settings/directory"): "tenant.admin",
    ("PUT", "/api/settings/directory"): "tenant.admin",
    ("DELETE", "/api/settings/directory"): "tenant.admin",
    ("POST", "/api/settings/directory/test"): "tenant.admin",
    # the installation: every tenant at once
    ("GET", "/api/admin/db-activity"): "platform.admin",
    ("GET", "/api/admin/db-metrics"): "platform.admin",
    ("GET", "/api/admin/runtime"): "platform.admin",
    ("GET", "/api/admin/db-slow-queries"): "platform.admin",
    ("POST", "/api/nist/catalog/activate"): "platform.admin",
    ("POST", "/api/nist/catalog/import"): "platform.admin",
    ("POST", "/api/nist/catalog/rollback"): "platform.admin",
    ("PUT", "/api/settings/features"): "platform.admin",
    ("GET", "/api/settings/siem"): "platform.admin",
    ("PUT", "/api/settings/siem"): "platform.admin",
    ("DELETE", "/api/settings/siem"): "platform.admin",
    ("PUT", "/api/settings/siem/enabled"): "platform.admin",
    ("POST", "/api/settings/siem/test"): "platform.admin",
    ("POST", "/api/settings/siem/retry"): "platform.admin",
    ("POST", "/api/tenants"): "platform.admin",
    ("DELETE", "/api/tenants/{tenant_id}"): "platform.admin",
    ("GET", "/api/tenants/{tenant_id}/legal-hold"): "platform.admin",
    ("PUT", "/api/tenants/{tenant_id}/legal-hold"): "platform.admin",
}


def _declared(route: APIRoute) -> str | tuple[str, ...]:
    """The permission a route's dependency tree declares, or PUBLIC."""
    stack = list(route.dependant.dependencies)
    found: list[tuple[str, ...]] = []
    while stack:
        dependency = stack.pop()
        declared = getattr(dependency.call, "required_permissions", None)
        if declared:
            found.append(tuple(declared))
        stack.extend(dependency.dependencies)
    if not found:
        return PUBLIC
    if len(set(found)) != 1:
        return ("CONFLICT",) + tuple(sorted({name for group in found for name in group}))
    group = found[0]
    return group[0] if len(group) == 1 else tuple(group)


def _api_routes() -> dict[tuple[str, str], APIRoute]:
    routes = {}
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path.startswith("/api/"):
            for method in route.methods - {"HEAD", "OPTIONS"}:
                routes[(method, route.path)] = route
    return routes


class TheMatrixCoversEveryRouteTest(unittest.TestCase):

    def test_every_registered_route_is_in_the_matrix(self) -> None:
        missing = sorted(set(_api_routes()) - set(MATRIX))
        self.assertEqual(missing, [], "a route with no decided permission")

    def test_the_matrix_names_no_route_that_is_gone(self) -> None:
        self.assertEqual(sorted(set(MATRIX) - set(_api_routes())), [])

    def test_every_route_declares_what_the_matrix_says(self) -> None:
        wrong = {key: (_declared(route), MATRIX[key]) for key, route in _api_routes().items()
                 if key in MATRIX and _declared(route) != MATRIX[key]}
        self.assertEqual(wrong, {}, "declared vs matrix")

    def test_the_rank_model_is_gone(self) -> None:
        self.assertFalse(hasattr(security, "require_role"), "a route could still ask for a rank")
        self.assertFalse(hasattr(security, "ROLES"))

    def test_every_matrix_permission_exists(self) -> None:
        for value in MATRIX.values():
            for name in (value if isinstance(value, tuple) else (value,)):
                if name not in (PUBLIC, AUTH):
                    self.assertIn(name, permissions.PERMISSIONS)

    def test_every_permission_guards_something(self) -> None:
        used = {name for value in MATRIX.values() for name in (value if isinstance(value, tuple) else (value,))}
        # evidence.view is enforced on fields rather than routes: backend/evidence.py,
        # pinned by tests/test_evidence_scope.py.
        unused = set(permissions.PERMISSIONS) - used - {"evidence.view"}
        self.assertEqual(unused, set())

    def test_a_misspelt_permission_fails_at_definition(self) -> None:
        with self.assertRaises(ValueError):
            security.require_permission("scans.run")
        with self.assertRaises(ValueError):
            security.require_permission()


class TheRoleCatalogueTest(unittest.TestCase):

    def test_no_role_holds_the_platform_permission(self) -> None:
        for name, role in permissions.BUILTIN_ROLES.items():
            with self.subTest(role=name):
                self.assertFalse(role["permissions"] & permissions.PLATFORM_ONLY)
                self.assertTrue(role["permissions"] <= set(permissions.PERMISSIONS))

    def test_a_viewer_only_reads(self) -> None:
        self.assertEqual(permissions.role_permissions("viewer"), {"inventory.view"})

    def test_an_analyst_keeps_what_it_could_do(self) -> None:
        self.assertEqual(permissions.role_permissions("analyst"), {
            "inventory.view", "evidence.view", "findings.triage", "scan.run", "credential.manage",
            "rules.manage", "export", "report.create",
        })

    def test_a_scan_operator_does_not_read_evidence(self) -> None:
        self.assertNotIn("evidence.view", permissions.role_permissions("scan_operator"))
        self.assertIn("scan.run", permissions.role_permissions("scan_operator"))

    def test_a_tenant_admin_has_everything_but_the_installation(self) -> None:
        self.assertEqual(permissions.role_permissions("admin"),
                         set(permissions.PERMISSIONS) - permissions.PLATFORM_ONLY)

    def test_invites_and_keys_never_carry_administration(self) -> None:
        self.assertNotIn("admin", permissions.DELEGABLE_ROLES)
        for name in permissions.DELEGABLE_ROLES:
            self.assertNotIn("tenant.admin", permissions.role_permissions(name))

    def test_an_unknown_role_may_do_nothing(self) -> None:
        self.assertEqual(permissions.role_permissions("wizard"), frozenset())
        self.assertFalse(permissions.is_known_role("wizard"))

    def test_the_platform_identity_is_the_only_holder(self) -> None:
        platform = security.Principal("admin", "admin", "default")
        tenant_admin = security.Principal("boss", "admin", "tenant-c3")
        self.assertIn("platform.admin", security.principal_permissions(platform))
        self.assertNotIn("platform.admin", security.principal_permissions(tenant_admin))


TENANT = "tenant-c3"
PASSWORD = "a-c3-harbour-pass-9"


class _RolesCase(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "c3.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        for tenant in ("default", TENANT):
            try:
                store.create_tenant(tenant, tenant)
            except Exception:
                pass
        password_hash = security.hash_password(PASSWORD)
        self.users = {"viewer": "c3-viewer", "auditor": "c3-auditor", "scan_operator": "c3-operator",
                      "analyst": "c3-analyst", "admin": "c3-boss"}
        for role, name in self.users.items():
            store.create_user(name, password_hash, role, TENANT)
        if store.get_user("admin") is None:
            store.create_user("admin", password_hash, "admin", "default")
        store._forget_revocation()
        security._session_last_seen.clear()
        self.addCleanup(store._forget_revocation)
        self.addCleanup(security._session_last_seen.clear)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def _as(self, role: str) -> dict:
        if role == "platform":
            return {"Authorization": f"Bearer {security.create_token('admin', 'admin', 'default')}"}
        return {"Authorization": f"Bearer {security.create_token(self.users[role], role, TENANT)}"}

    def _status(self, role: str, method: str, path: str, **kwargs) -> int:
        return self.client.request(method, path, headers=self._as(role), **kwargs).status_code


class AViewerTest(_RolesCase):
    """The S13 finding: a read-only account could take everything out."""

    def test_reads(self) -> None:
        self.assertEqual(self._status("viewer", "GET", "/api/inventory"), 200)
        self.assertEqual(self._status("viewer", "GET", "/api/findings"), 200)

    def test_exports_nothing(self) -> None:
        for method, path in (("GET", "/api/inventory/export?format=csv"), ("GET", "/api/nist/catalog/export"),
                             ("GET", "/api/compliance-keywords/export"), ("POST", "/api/dlp-policy")):
            with self.subTest(path=path):
                response = self.client.request(method, path, headers=self._as("viewer"), json={})
                self.assertEqual(response.status_code, 403, response.text)
                self.assertIn("needs export", response.json()["detail"])

    def test_files_no_report_and_downloads_none(self) -> None:
        self.assertEqual(self._status("viewer", "POST", "/api/v1/reports", json={}), 403)
        self.assertEqual(self._status("viewer", "GET", "/api/v1/reports/artifacts/" + "a" * 32), 403)

    def test_does_not_read_scan_configuration(self) -> None:
        self.assertEqual(self._status("viewer", "GET", "/api/scan-profiles"), 403)
        self.assertEqual(self._status("viewer", "GET", "/api/scan-schedules"), 403)

    def test_changes_nothing(self) -> None:
        self.assertEqual(self._status("viewer", "POST", "/api/findings/f-1/comment", json={"comment": "x"}), 403)
        self.assertEqual(self._status("viewer", "POST", "/api/suppression-rules",
                                      json={"finding_type": "email", "reason": "x"}), 403)


class AnAuditorTest(_RolesCase):

    def test_reads_the_trail_and_files_reports(self) -> None:
        self.assertEqual(self._status("auditor", "GET", "/api/audit"), 200)
        # No scan in this tenant: the report route answers, rather than refusing the role.
        self.assertEqual(self._status("auditor", "POST", "/api/v1/reports", json={}), 404)

    def test_changes_and_exports_nothing(self) -> None:
        self.assertEqual(self._status("auditor", "POST", "/api/findings/f-1/comment", json={"comment": "x"}), 403)
        self.assertEqual(self._status("auditor", "GET", "/api/nist/catalog/export"), 403)
        self.assertEqual(self._status("auditor", "GET", "/api/scan-profiles"), 403)


class AScanOperatorTest(_RolesCase):

    def test_runs_scans_and_vaults_their_credentials(self) -> None:
        self.assertEqual(self._status("scan_operator", "GET", "/api/scan-profiles"), 200)
        with mock.patch.object(app_module.vault, "store", return_value="ref-c3"):
            response = self.client.post("/api/credentials", headers=self._as("scan_operator"),
                                        json={"username": "svc", "password": "p", "domain": "LAB"})
        self.assertEqual(response.status_code, 200, response.text)

    def test_does_not_triage_export_or_audit(self) -> None:
        self.assertEqual(self._status("scan_operator", "POST", "/api/findings/f-1/comment", json={"comment": "x"}), 403)
        self.assertEqual(self._status("scan_operator", "GET", "/api/nist/catalog/export"), 403)
        self.assertEqual(self._status("scan_operator", "GET", "/api/audit"), 403)


class AnAnalystTest(_RolesCase):

    def test_exports_triages_and_files(self) -> None:
        self.assertEqual(self._status("analyst", "GET", "/api/nist/catalog/export"), 200)
        # An unknown finding is a 404: the permission admitted the request.
        self.assertEqual(self._status("analyst", "POST", "/api/findings/f-1/comment", json={"comment": "x"}), 404)
        self.assertEqual(self._status("analyst", "POST", "/api/v1/reports", json={}), 404)

    def test_does_not_administer(self) -> None:
        self.assertEqual(self._status("analyst", "GET", "/api/audit"), 403)
        self.assertEqual(self._status("analyst", "GET", "/api/users"), 403)


class ATenantAdministratorTest(_RolesCase):

    def test_administers_the_tenant(self) -> None:
        self.assertEqual(self._status("admin", "GET", "/api/users"), 200)
        roles = self.client.get("/api/roles", headers=self._as("admin")).json()
        self.assertEqual([role["name"] for role in roles["roles"]], list(permissions.BUILTIN_ROLES))
        self.assertNotIn("admin", roles["delegable"])

    def test_does_not_operate_the_installation(self) -> None:
        # Install-wide: OCR for every tenant, database diagnostics, other tenants.
        self.assertEqual(self._status("admin", "PUT", "/api/settings/features", json={"ocr_enabled": False}), 403)
        self.assertEqual(self._status("admin", "GET", "/api/admin/db-metrics"), 403)
        self.assertEqual(self._status("admin", "POST", "/api/tenants", json={"tenant_id": "c3-other"}), 403)
        features = self.client.get("/api/settings/features", headers=self._as("admin")).json()
        self.assertFalse(features["features"]["ocr"]["editable"])

    def test_the_platform_administrator_does(self) -> None:
        self.assertEqual(self._status("platform", "GET", "/api/admin/db-metrics"), 200)
        self.assertEqual(self._status("platform", "POST", "/api/tenants", json={"tenant_id": "c3-other"}), 200)

    def test_gives_the_new_roles(self) -> None:
        created = self.client.post("/api/users", headers=self._as("admin"), json={
            "username": "c3-new-auditor", "password": "a-new-auditor-pass-4", "role": "auditor", "tenant_id": TENANT})
        self.assertEqual(created.status_code, 200, created.text)
        self.assertEqual(store.get_user("c3-new-auditor")["role"], "auditor")
        moved = self.client.put(f"/api/users/{self.users['viewer']}/role", headers=self._as("admin"),
                                json={"role": "scan_operator"})
        self.assertEqual(moved.status_code, 200, moved.text)

    def test_an_unknown_role_is_refused(self) -> None:
        response = self.client.post("/api/users", headers=self._as("admin"), json={
            "username": "c3-wizard", "password": "a-wizard-pass-4411", "role": "wizard", "tenant_id": TENANT})
        self.assertEqual(response.status_code, 400)
        self.assertIsNone(store.get_user("c3-wizard"))

    def test_invites_and_keys_carry_delegable_roles_only(self) -> None:
        invite = self.client.post(f"/api/tenants/{TENANT}/invites", headers=self._as("admin"), json={"role": "auditor"})
        self.assertEqual(invite.status_code, 200, invite.text)
        refused = self.client.post(f"/api/tenants/{TENANT}/invites", headers=self._as("admin"), json={"role": "admin"})
        self.assertEqual(refused.status_code, 400)
        key = self.client.post("/api/api-keys", headers=self._as("admin"), json={"label": "ops", "role": "scan_operator"})
        self.assertEqual(key.status_code, 200, key.text)
        self.assertEqual(self.client.post("/api/api-keys", headers=self._as("admin"),
                                          json={"label": "x", "role": "admin"}).status_code, 400)

    def test_the_last_administrator_cannot_step_down_to_a_role_without_administration(self) -> None:
        response = self.client.put(f"/api/users/{self.users['admin']}/role", headers=self._as("admin"),
                                   json={"role": "auditor"})
        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(store.get_user(self.users["admin"])["role"], "admin")


class TheConsoleIsToldTest(_RolesCase):

    def test_sign_in_profile_and_renewal_carry_the_permissions(self) -> None:
        login = self.client.post("/api/auth/login", json={"username": self.users["auditor"], "password": PASSWORD})
        self.assertEqual(login.status_code, 200, login.text)
        expected = sorted(permissions.role_permissions("auditor"))
        self.assertEqual(login.json()["permissions"], expected)
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        self.assertEqual(self.client.get("/api/profile", headers=headers).json()["permissions"], expected)
        renewed = self.client.post("/api/auth/refresh")
        self.assertEqual(renewed.json()["permissions"], expected)

    def test_a_role_changed_mid_session_shows_on_the_next_read(self) -> None:
        headers = self._as("viewer")
        store.update_user_role(self.users["viewer"], "analyst")
        self.assertIn("export", self.client.get("/api/profile", headers=headers).json()["permissions"])


@unittest.skipIf(db.is_postgres(), "builds an older SQLite file; the PostgreSQL upgrade path is scripted in C0.5")
class RevisionTwentyTest(unittest.TestCase):
    """users.role had CHECK (role IN ('admin', 'analyst', 'viewer')) since the baseline."""

    OLD_USERS = ("CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, "
                 "role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')), "
                 "tenant_id TEXT NOT NULL DEFAULT 'default', full_name TEXT NOT NULL DEFAULT '', "
                 "is_active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
                 "last_login_at TEXT)")

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        self.path = Path(self.temp_dir.name) / "old.sqlite"
        original = store.DB_PATH
        store.DB_PATH = self.path
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))

    def _old_install(self) -> None:
        raw = sqlite3.connect(self.path)
        raw.execute(self.OLD_USERS)
        raw.execute("ALTER TABLE users ADD COLUMN avatar TEXT NOT NULL DEFAULT ''")
        raw.execute("CREATE INDEX idx_users_tenant ON users (tenant_id, role)")
        raw.executemany(
            "INSERT INTO users (username, password_hash, role, tenant_id, created_at, updated_at, avatar) "
            "VALUES (?, ?, ?, 'default', 'then', 'then', ?)",
            [("old-admin", "hash-a", "admin", "data:a"), ("old-viewer", "hash-v", "viewer", "")],
        )
        with self.assertRaises(sqlite3.IntegrityError):
            raw.execute("INSERT INTO users (username, password_hash, role, created_at, updated_at) "
                        "VALUES ('x', 'h', 'auditor', 'n', 'n')")
        raw.commit()
        raw.close()

    def _users_sql(self) -> str:
        raw = sqlite3.connect(self.path)
        try:
            return raw.execute("SELECT sql FROM sqlite_master WHERE name = 'users'").fetchone()[0]
        finally:
            raw.close()

    def test_an_old_install_opens_and_keeps_every_row_column_and_index(self) -> None:
        self._old_install()
        migrations.upgrade()
        self.assertNotIn("CHECK", self._users_sql().upper())
        self.assertEqual(store.get_user("old-admin")["password_hash"], "hash-a")
        self.assertEqual(store.get_user("old-admin").get("avatar"), "data:a")
        raw = sqlite3.connect(self.path)
        indexes = {row[0] for row in raw.execute("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'users'")}
        raw.close()
        self.assertIn("idx_users_tenant", indexes)
        store.create_user("new-auditor", "hash-n", "auditor", "default")
        self.assertEqual(store.get_user("new-auditor")["role"], "auditor")

    def test_it_runs_once(self) -> None:
        self._old_install()
        migrations.upgrade()
        before = self._users_sql()
        with store._connect() as conn:
            store.open_role_catalogue(conn)
        self.assertEqual(self._users_sql(), before)

    def test_a_fresh_install_never_had_it(self) -> None:
        store.init_db()
        self.assertNotIn("CHECK", self._users_sql().upper())

    def test_the_store_checks_the_name_instead(self) -> None:
        store.init_db()
        with self.assertRaises(ValueError):
            store.create_user("wizard", "h", "wizard", "default")
        store.create_user("fine", "h", "viewer", "default")
        with self.assertRaises(ValueError):
            store.update_user_role("fine", "wizard")


class TheConsoleGatesTest(unittest.TestCase):
    """The real app.js, in Node: it gates on the permissions the server stated."""

    def _evaluate(self, permission_list: list[str], expressions: dict[str, str]) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "scenario.json"
            fixture.write_text(json.dumps({"drive": "evaluate", "permissions": permission_list,
                                           "evaluate": expressions}), encoding="utf-8")
            result = subprocess.run([NODE, str(SMOKE), str(fixture)], cwd=ROOT, capture_output=True,
                                    text=True, timeout=180, check=False)
        report = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertIsNone(report.get("error"), report.get("error"))
        return report["values"]

    PROBES = {
        "scan": "permittedTabName('file-servers')",
        "endpoint": "permittedTabName('endpoint')",
        "security": "permittedTabName('security')",
        "triage": "remediationCanManage({scope: 'current'})",
        "admin": "isAdminRole()",
    }

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_a_viewer_is_sent_away_from_scans_and_administration(self) -> None:
        values = self._evaluate(["inventory.view"], self.PROBES)
        self.assertEqual(values, {"scan": "overview", "endpoint": "overview", "security": "settings",
                                  "triage": False, "admin": False})

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_a_scan_operator_reaches_the_scan_pages_only(self) -> None:
        values = self._evaluate(sorted(permissions.role_permissions("scan_operator")), self.PROBES)
        self.assertEqual(values, {"scan": "file-servers", "endpoint": "endpoint", "security": "settings",
                                  "triage": False, "admin": False})

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_a_tenant_administrator_reaches_everything(self) -> None:
        values = self._evaluate(sorted(permissions.role_permissions("admin")), self.PROBES)
        self.assertEqual(values, {"scan": "file-servers", "endpoint": "endpoint", "security": "security",
                                  "triage": True, "admin": True})

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_a_server_that_states_no_permissions_does_not_hide_an_admins_console(self) -> None:
        # 2026-09-24: the live server was still the pre-C3 process while the console on
        # disk was new. That server never sends `permissions`, and the console read the
        # absence as "none": the tenant switcher, the scan pages, exports, reports,
        # triage and the audit trail all disappeared for the administrator. With nothing
        # stated, the console falls back to the role's built-in permissions (the harness
        # signs in as the installation's own `admin`).
        values = self._evaluate([], {**self.PROBES, "platform": "can('platform.admin')"})
        self.assertEqual(values, {"scan": "file-servers", "endpoint": "endpoint", "security": "security",
                                  "triage": True, "admin": True, "platform": True})

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_the_fallback_follows_the_role_and_a_stated_list_still_wins(self) -> None:
        held = "[...currentPermissions].sort().join(',')"
        values = self._evaluate([], {
            "viewer": f"(currentRole = 'viewer', currentUser = 'v', setPermissions([]), {held})",
            "tenant_admin": f"(currentRole = 'admin', currentUser = 'boss', setPermissions([]), {held})",
            "custom": f"(currentRole = 'reviewer', currentUser = 'r', setPermissions([]), {held})",
            "stated": f"(currentRole = 'admin', currentUser = 'admin', setPermissions(['inventory.view']), {held})",
        })
        self.assertEqual(values["viewer"], "inventory.view")
        self.assertEqual(values["tenant_admin"], ",".join(sorted(permissions.role_permissions("admin"))),
                         "a tenant's administrator is not the installation's")
        self.assertEqual(values["custom"], "", "a custom role's permissions only the server can state")
        self.assertEqual(values["stated"], "inventory.view")

    def test_the_consoles_fallback_is_the_role_catalogue(self) -> None:
        script = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
        block = script[script.index("const BUILTIN_ROLE_PERMISSIONS = {"):]
        block = block[:block.index("};")]
        fallback = {role: set(re.findall(r'"([a-z_.]+)"', body))
                    for role, body in re.findall(r"^\s*([a-z_]+): \[(.*?)\],?$", block, re.MULTILINE | re.DOTALL)}
        self.assertEqual(fallback, {name: set(role["permissions"]) for name, role in permissions.BUILTIN_ROLES.items()})

    @unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
    def test_the_role_picker_offers_the_catalogue(self) -> None:
        values = self._evaluate(["tenant.admin"], {"options": "roleOptionsHtml('auditor')"})
        for name in permissions.BUILTIN_ROLES:
            self.assertIn(f'value="{name}"', values["options"])
        self.assertIn('value="auditor" title="" selected', values["options"])

    def test_every_gate_in_the_markup_and_script_names_a_real_permission(self) -> None:
        markup = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        script = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
        names = set()
        for value in re.findall(r'data-requires="([^"]+)"', markup + script):
            names.update(value.split())
        names.update(re.findall(r'\bcan\("([^"]+)"\)', script))
        names.update(re.findall(r'"([a-z]+\.[a-z]+)"', script[script.index("const TAB_PERMISSIONS"):][:200]))
        self.assertTrue(names)
        self.assertEqual(names - set(permissions.PERMISSIONS), set(), "a gate that can never open")

    def test_the_scan_pages_and_exports_are_gated_in_the_markup(self) -> None:
        markup = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        for fragment, permission in (('id="tab-file-servers"', "scan.run"), ('id="tab-endpoint"', "scan.run"),
                                     ('id="fx-newscan-btn"', "scan.run"), ('id="inventory-export-csv"', "export"),
                                     ('id="inventory-export-ndjson"', "export"), ('id="report-generate"', "report.create"),
                                     ('id="export-dlp-policy-btn"', "export")):
            with self.subTest(element=fragment):
                tag = markup[markup.rindex("<", 0, markup.index(fragment)):markup.index(">", markup.index(fragment))]
                self.assertIn(f'data-requires="{permission}"', tag)


if __name__ == "__main__":
    unittest.main()
