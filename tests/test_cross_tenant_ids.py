"""M2/C3: another tenant's identifier gets a refusal, not the record.

The last line of C3's gate is "cross-tenant IDs fail". Permissions decide WHAT a caller
may do; tenant scoping decides to WHICH records. A tenant administrator holds every
permission its tenant has - so the question here is whether holding them lets it reach
another tenant's asset, finding, scan, job, profile, schedule, rule, invite, key, user,
report or role by using that tenant's real identifier.

Every route that takes an identifier is tried, with a real one from the other tenant,
by that tenant's own administrator. Each must refuse (403 or 404), say nothing about the
record, and change nothing - the other tenant's records are compared before and after.
The list of routes is checked against the route matrix, so a new route that takes an
identifier cannot be added without deciding how it is scoped.
"""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from backend import app as app_module
from backend import jobs, security, store
from backend.app import app
from backend.reporting import artifacts
from tests.test_evidence_scope import FRAMEWORKS, _scan_report
from tests.test_route_permissions import MATRIX

A, B = "xt-alpha", "xt-bravo"
PASSWORD = "a-cross-tenant-pass-6"

# (method, path, body). The path's placeholders are filled with tenant A's identifiers.
ATTEMPTS = [
    ("GET", "/api/findings/{finding_id}", None),
    ("GET", "/api/findings/{finding_id}/history", None),
    ("GET", "/api/findings/{finding_id}/occurrences", None),
    ("POST", "/api/findings/{finding_id}/assign", {"owner": "b-boss"}),
    ("POST", "/api/findings/{finding_id}/comment", {"comment": "from another tenant"}),
    ("POST", "/api/findings/{finding_id}/false-positive", {"reason": "from another tenant"}),
    ("POST", "/api/findings/{finding_id}/reopen", {"comment": "from another tenant"}),
    ("POST", "/api/findings/{finding_id}/resolve", {"comment": "from another tenant"}),
    ("POST", "/api/findings/{finding_id}/risk-acceptance", {"reason": "from another tenant"}),
    ("PATCH", "/api/findings/{finding_id}/status", {"status": "resolved"}),
    ("POST", "/api/findings/{finding_id}/suppress", {"reason": "from another tenant"}),
    ("POST", "/api/findings/{finding_id}/validate", {}),
    ("GET", "/api/history/{scan_id}/report", None),
    ("PATCH", "/api/history/{scan_id}/findings/workflow", {"path": "{asset_path}", "type": "email", "status": "resolved"}),
    ("GET", "/api/inventory/{asset_id}", None),
    ("GET", "/api/scans/{job_id}", None),
    ("POST", "/api/scans/{job_id}/cancel", None),
    ("DELETE", "/api/scan-profiles/{profile_id}", None),
    ("PATCH", "/api/scan-schedules/{schedule_id}", {"name": "hijacked"}),
    ("DELETE", "/api/scan-schedules/{schedule_id}", None),
    ("POST", "/api/scan-schedules/{schedule_id}/run", None),
    ("PATCH", "/api/suppression-rules/{rule_id}", {"reason": "hijacked"}),
    ("DELETE", "/api/suppression-rules/{rule_id}", None),
    ("GET", "/api/tenants/{tenant_id}/invites", None),
    ("POST", "/api/tenants/{tenant_id}/invites", {"role": "viewer"}),
    ("POST", "/api/tenants/{tenant_id}/invites/{invite_id}/revoke", None),
    ("POST", "/api/tenants/{tenant_id}/regenerate-registration-code", None),
    ("POST", "/api/tenants/{tenant_id}/registration-code", None),
    ("GET", "/api/tenants/{tenant_id}/legal-hold", None),
    ("PUT", "/api/tenants/{tenant_id}/legal-hold", {"active": True, "reason": "hijacked"}),
    ("DELETE", "/api/tenants/{tenant_id}", None),
    ("POST", "/api/api-keys/{key_id}/revoke", None),
    ("DELETE", "/api/users/{username}", None),
    ("PUT", "/api/users/{username}/active", {"is_active": False}),
    ("POST", "/api/users/{username}/delete", None),
    ("POST", "/api/users/{username}/reset-password", {"password": "a-foreign-reset-pass-9"}),
    ("PUT", "/api/users/{username}/role", {"role": "analyst"}),
    ("GET", "/api/v1/reports/artifacts/{artifact_id}", None),
    ("PUT", "/api/roles/{name}", {"permissions": ["export"]}),
    ("DELETE", "/api/roles/{name}", None),
]

# Routes that take an identifier but not a tenant's: said here, with the reason.
EXCUSED = {
    ("GET", "/api/nist/catalog/rules/{rule_id}"):
        "the NIST catalogue is one shared, vendor-maintained baseline, not any tenant's data",
}


class EveryIdentifierRouteIsTriedTest(unittest.TestCase):

    def test_the_list_covers_the_matrix(self) -> None:
        with_identifiers = {key for key in MATRIX if "{" in key[1]}
        tried = {(method, path) for method, path, _ in ATTEMPTS}
        self.assertEqual(with_identifiers - tried - set(EXCUSED), set(), "an identifier route nobody tried")
        self.assertEqual(tried - with_identifiers, set(), "a tried route that is not in the matrix")


class AnotherTenantsIdentifiersFailTest(unittest.TestCase):
    report: dict

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = _scan_report()

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "cross.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        # ARTIFACT_ROOT is resolved at import from DATA_DIR; without this, the report
        # this test files lands in the repository's data/ directory.
        artifact_root = mock.patch.object(artifacts, "ARTIFACT_ROOT", Path(self.temp_dir.name) / "artifacts")
        artifact_root.start()
        self.addCleanup(artifact_root.stop)
        for tenant in (A, B):
            store.create_tenant(tenant, tenant)
        password_hash = security.hash_password(PASSWORD)
        for name, role, tenant in (("a-boss", "admin", A), ("a-analyst", "analyst", A), ("a-member", "viewer", A),
                                   ("b-boss", "admin", B)):
            store.create_user(name, password_hash, role, tenant)
        store._forget_revocation()
        security._session_last_seen.clear()
        self.addCleanup(store._forget_revocation)
        self.addCleanup(security._session_last_seen.clear)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.ids = self._seed_tenant_a()

    def _as(self, user: str, role: str, tenant: str) -> dict:
        return {"Authorization": f"Bearer {security.create_token(user, role, tenant)}"}

    def _ok(self, response) -> dict:
        self.assertEqual(response.status_code, 200, response.text[:300])
        return response.json()

    def _seed_tenant_a(self) -> dict:
        boss, analyst = self._as("a-boss", "admin", A), self._as("a-analyst", "analyst", A)
        payload = app_module.ScanRequest(save_report=True, compliance_enabled=True, compliance_frameworks=FRAMEWORKS)
        data = json.loads(json.dumps(self.report))
        app_module._persist_compliance_scan(data, payload, security.Principal("a-analyst", "analyst", A))
        asset = self._ok(self.client.get("/api/inventory", headers=analyst))["items"][0]
        finding = self._ok(self.client.get("/api/findings?limit=50", headers=analyst))["items"][0]
        profile = self._ok(self.client.post("/api/scan-profiles", headers=boss,
                                            json={"kind": "file-server", "name": "Finance", "config": {}}))
        schedule = self._ok(self.client.post("/api/scan-schedules", headers=boss, json={
            "name": "nightly", "interval_seconds": 86400, "first_run_at": "2099-01-01T00:00:00+00:00",
            "scan": {"local_path": "enterprise_test_data", "scan_label": "nightly"}}))
        rule = self._ok(self.client.post("/api/suppression-rules", headers=boss,
                                         json={"finding_type": "email", "reason": "known test data"}))
        invite = self._ok(self.client.post(f"/api/tenants/{A}/invites", headers=boss, json={"role": "viewer"}))
        key = self._ok(self.client.post("/api/api-keys", headers=boss, json={"label": "ops", "role": "viewer"}))
        self._ok(self.client.post("/api/roles", headers=boss, json={"name": "xt_reviewer", "permissions": ["inventory.view"]}))
        artifact = self._ok(self.client.post("/api/v1/reports", headers=analyst, json={}))
        job = jobs.create_job(A, lambda _job: {"ok": True})
        for _ in range(100):
            if jobs.get_job(job.id).status in {"completed", "failed"}:
                break
            time.sleep(0.02)
        return {
            "asset_id": asset["id"], "asset_path": asset["path"], "finding_id": finding["finding_id"],
            "scan_id": data["scan_id"], "job_id": job.id,
            "profile_id": (profile.get("profile") or profile)["profile_id"],
            "schedule_id": (schedule.get("schedule") or schedule)["schedule_id"],
            "rule_id": (rule.get("rule") or rule)["rule_id"],
            "invite_id": invite["invite_id"], "key_id": key["key_id"], "artifact_id": artifact["artifact_id"],
            "username": "a-member", "name": "xt_reviewer", "tenant_id": A,
        }

    def _state_of_a(self) -> str:
        """Everything tenant A has, read by tenant A, as one comparable document."""
        boss, analyst = self._as("a-boss", "admin", A), self._as("a-analyst", "analyst", A)
        ids = self.ids
        state = {
            "finding": self._ok(self.client.get(f"/api/findings/{ids['finding_id']}", headers=analyst))["finding"],
            "history": self._ok(self.client.get(f"/api/findings/{ids['finding_id']}/history", headers=analyst)),
            "profiles": self._ok(self.client.get("/api/scan-profiles", headers=boss))["profiles"],
            "schedules": self._ok(self.client.get("/api/scan-schedules", headers=boss)),
            "rules": self._ok(self.client.get("/api/suppression-rules", headers=boss)),
            "invites": self._ok(self.client.get(f"/api/tenants/{A}/invites", headers=boss)),
            "keys": self._ok(self.client.get("/api/api-keys", headers=boss)),
            "users": self._ok(self.client.get("/api/users", headers=boss)),
            "roles": [role for role in self._ok(self.client.get("/api/roles", headers=boss))["roles"] if not role.get("builtin")],
            "tenant": store.get_tenant(A),
            "legal_hold": store.get_legal_hold(A),
            "password": store.get_user("a-member")["password_hash"],
        }
        return json.dumps(state, sort_keys=True, default=str)

    def _fill(self, value):
        if isinstance(value, str):
            return value.format(**self.ids)
        if isinstance(value, dict):
            return {key: self._fill(item) for key, item in value.items()}
        return value

    def test_every_attempt_is_refused_says_nothing_and_changes_nothing(self) -> None:
        before = self._state_of_a()
        intruder = self._as("b-boss", "admin", B)
        leaks = [self.ids["asset_path"], "payroll.txt", "xt_reviewer", "known test data", "a-member"]
        wrong = []
        for method, path, body in ATTEMPTS:
            response = self.client.request(method, self._fill(path), headers=intruder,
                                           json=self._fill(body) if body is not None else None)
            if response.status_code not in (403, 404):
                wrong.append(f"{method} {path}: {response.status_code} {response.text[:120]}")
            wrong.extend(f"{method} {path}: names {marker!r}" for marker in leaks if marker in response.text)
        self.assertEqual(wrong, [], "answered with something other than a refusal")
        self.assertEqual(self._state_of_a(), before, "tenant A changed")


if __name__ == "__main__":
    unittest.main()
