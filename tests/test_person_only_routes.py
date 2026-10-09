"""Sign-in without a second factor, and the routes only a person may use.

Two-step sign-in was removed (the product owner's decision, 2026-10-02: Sentro runs
fully offline). It had also kept API keys away from saved credentials, reveals,
licences, integrations and exact-match uploads - routes that asked for a verified
session a key can never have. That protection stays without it: a key's role may not
hold a person-only permission, and a route admitted only by one - or marked
person_only - refuses a key.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from backend import db, migrations, store
from backend.app import app
from backend.permissions import PERSON_ONLY_PERMISSIONS
from backend.security import create_token, generate_api_key, hash_password


class SignInIsOneStepTest(unittest.TestCase):

    def test_a_password_opens_an_administrators_session(self) -> None:
        user = f"po-admin-{uuid4().hex[:6]}"
        store.create_user(user, hash_password("Po-admin-pass-1x"), "admin", "default")
        self.addCleanup(store.delete_user, user)
        response = TestClient(app).post("/api/auth/login", json={"username": user, "password": "Po-admin-pass-1x"})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body["access_token"])
        self.assertNotIn("mfa_token", body)
        self.assertNotIn("mfa_verified", body)

    def test_the_two_step_routes_are_gone(self) -> None:
        paths = {route.path for route in app.routes}
        self.assertFalse([path for path in paths if "/mfa" in path], "a two-step sign-in route is still served")

    def test_the_schema_holds_no_second_factor(self) -> None:
        names = [name for _, name, _ in migrations._revisions()]
        self.assertIn("remove_two_step_sign_in", names)
        with db.platform_scope("migration"), store._connect() as conn:
            self.assertEqual(db.table_columns(conn, "user_mfa"), set(), "the authenticator table is still there")
            for table in ("user_sessions", "refresh_tokens"):
                self.assertNotIn("mfa_verified", db.table_columns(conn, table), table)


class APersonOnlyRouteRefusesAnApiKeyTest(unittest.TestCase):

    def setUp(self) -> None:
        # Per test, not per class: on PostgreSQL the suite empties the tables before each test.
        cls = self
        cls.client = TestClient(app)
        cls.tenant = f"po-{uuid4().hex[:8]}"
        store.create_tenant(cls.tenant, "Person only")
        # A role edited to hold a person-only permission after its key was made: the key
        # route refuses such a role, so the store is written directly here.
        cls.role = f"keyed_{uuid4().hex[:6]}"
        store.save_custom_role(cls.tenant, cls.role, "Keyed", "",
                               ["inventory.view", "credential.manage", "rules.manage"], "test")
        raw, key_hash = generate_api_key()
        expires = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        store.create_api_key_record(cls.tenant, key_hash, "keyed", cls.role, "test", expires)
        cls.key = {"X-API-Key": raw}
        cls.person = f"po-person-{uuid4().hex[:6]}"
        store.create_user(cls.person, hash_password("Po-person-pass-1x"), cls.role, cls.tenant)
        cls.session = {"Authorization": f"Bearer {create_token(cls.person, cls.role, cls.tenant)}"}

    def tearDown(self) -> None:
        store.delete_user(self.person)

    def test_saved_credentials_are_for_a_person(self) -> None:
        refused = self.client.get("/api/credentials", headers=self.key)
        self.assertEqual(refused.status_code, 403, refused.text)
        self.assertEqual(refused.json()["detail"]["code"], "person_only")
        self.assertEqual(self.client.get("/api/credentials", headers=self.session).status_code, 200)

    def test_a_route_marked_person_only_refuses_a_key_whatever_admits_it(self) -> None:
        body = {"name": "customers", "entity_type": "EMAIL_ADDRESS", "values": ["a@example.com"]}
        refused = self.client.post("/api/exact-match/sets", headers=self.key, json=body)
        self.assertEqual(refused.status_code, 403, refused.text)
        self.assertEqual(refused.json()["detail"]["code"], "person_only")

    def test_a_key_is_not_made_for_a_person_only_role(self) -> None:
        admin = {"Authorization": f"Bearer {create_token('admin', 'admin', 'default')}"}
        store.save_custom_role("default", "po_creds", "Creds", "", ["inventory.view", "credential.manage"], "test")
        self.addCleanup(store.delete_custom_role, "default", "po_creds")
        refused = self.client.post("/api/api-keys", headers=admin, json={"label": "x", "role": "po_creds", "ttl_days": 1})
        self.assertEqual(refused.status_code, 400, refused.text)

    def test_the_marked_routes_are_the_ones_that_needed_a_verified_session(self) -> None:
        marked = sorted(f"{sorted(route.methods)[0]} {route.path}" for route in app.routes
                        if any(getattr(dependency.call, "person_only", False)
                               for dependency in getattr(getattr(route, "dependant", None), "dependencies", [])))
        for expected in ("POST /api/exact-match/sets", "PUT /api/licence", "GET /api/credentials"):
            self.assertIn(expected, marked)
        self.assertTrue(PERSON_ONLY_PERMISSIONS >= {"credential.manage", "evidence.reveal"})


if __name__ == "__main__":
    unittest.main()
