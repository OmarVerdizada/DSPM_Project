"""Saved scan profiles: the deck behind the File Server / Endpoint scan pages.

A profile is a named, editable scan configuration persisted per tenant. It
must never persist a credential - the client vaults passwords into refs, and
the store strips secret-shaped keys defensively - and one tenant's profiles
must be invisible to another.
"""

from __future__ import annotations

import unittest
from uuid import uuid4

from fastapi.testclient import TestClient

from backend.app import app
from backend.security import create_token, hash_password
from backend.store import create_tenant, create_user, delete_user, list_scan_profiles


def _headers(tenant: str = "default") -> dict:
    return {"Authorization": f"Bearer {create_token('admin', 'admin', tenant)}"}


class ScanProfileApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def _save(self, tenant: str = "default", **overrides) -> dict:
        payload = {
            "kind": "file-server",
            "name": "HR file server",
            "config": {
                "server": "10.10.33.149",
                "domain": "shamsi.local",
                "username": "svc_scan",
                "credential_ref": "ref-abc",
                "max_depth": 4,
                "inspect_archives": False,
            },
        }
        payload.update(overrides)
        response = self.client.post("/api/scan-profiles", json=payload, headers=_headers(tenant))
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_profile_round_trips_and_updates_in_place(self) -> None:
        profile = self._save()
        listed = self.client.get("/api/scan-profiles", headers=_headers()).json()["profiles"]
        match = next(p for p in listed if p["profile_id"] == profile["profile_id"])
        self.assertEqual(match["name"], "HR file server")
        self.assertEqual(match["config"]["server"], "10.10.33.149")

        renamed = self._save(profile_id=profile["profile_id"], name="HR share (renamed)")
        self.assertEqual(renamed["profile_id"], profile["profile_id"])
        self.assertEqual(renamed["created_at"], profile["created_at"], "update keeps creation time")

        listed_after = self.client.get("/api/scan-profiles", headers=_headers()).json()["profiles"]
        same_id = [p for p in listed_after if p["profile_id"] == profile["profile_id"]]
        self.assertEqual(len(same_id), 1, "update must not duplicate the profile")
        self.assertEqual(same_id[0]["name"], "HR share (renamed)")

        self.client.delete(f"/api/scan-profiles/{profile['profile_id']}", headers=_headers())
        remaining = self.client.get("/api/scan-profiles", headers=_headers()).json()["profiles"]
        self.assertNotIn(profile["profile_id"], [p["profile_id"] for p in remaining])

    def test_passwords_never_persist_even_when_sent_raw(self) -> None:
        profile = self._save(config={
            "server": "srv", "username": "u",
            "password": "SuperSecret1!", "admin_password": "AlsoSecret", "token": "t",
            "credential_ref": "ref-ok",
        })
        self.assertNotIn("password", profile["config"])
        self.assertNotIn("admin_password", profile["config"])
        self.assertNotIn("token", profile["config"])
        self.assertEqual(profile["config"]["credential_ref"], "ref-ok")

        stored = next(
            p for p in list_scan_profiles("default") if p["profile_id"] == profile["profile_id"]
        )
        self.assertNotIn("password", stored["config"], "raw secret reached the database")
        self.client.delete(f"/api/scan-profiles/{profile['profile_id']}", headers=_headers())

    def test_profiles_are_tenant_isolated(self) -> None:
        tenant = f"pt-{uuid4().hex[:8]}"
        create_tenant(tenant, "Profile tenant")
        # The principal's tenant comes from the USER RECORD, not the token
        # claim, so isolation needs a real admin in the other tenant.
        other_admin = f"padmin-{uuid4().hex[:6]}"
        create_user(other_admin, hash_password("x9!Profile"), "admin", tenant)
        self.addCleanup(delete_user, other_admin)
        tenant_headers = {"Authorization": f"Bearer {create_token(other_admin, 'admin', tenant)}"}
        response = self.client.post(
            "/api/scan-profiles",
            json={"kind": "endpoint", "name": "Laptop fleet", "config": {"host": "10.10.33.52"}},
            headers=tenant_headers,
        )
        self.assertEqual(response.status_code, 200, response.text)
        mine = response.json()

        other = self.client.get("/api/scan-profiles", headers=_headers("default")).json()["profiles"]
        self.assertNotIn(mine["profile_id"], [p["profile_id"] for p in other])

        cross_delete = self.client.delete(
            f"/api/scan-profiles/{mine['profile_id']}", headers=_headers("default")
        ).json()
        self.assertFalse(cross_delete["deleted"], "another tenant must not delete the profile")
        still_there = self.client.get("/api/scan-profiles", headers=tenant_headers).json()["profiles"]
        self.assertIn(mine["profile_id"], [p["profile_id"] for p in still_there])

    def test_validation_rejects_bad_kind_and_blank_name(self) -> None:
        bad_kind = self.client.post(
            "/api/scan-profiles",
            json={"kind": "cloud", "name": "x", "config": {}},
            headers=_headers(),
        )
        self.assertIn(bad_kind.status_code, (400, 422))
        blank = self.client.post(
            "/api/scan-profiles",
            json={"kind": "endpoint", "name": "   ", "config": {}},
            headers=_headers(),
        )
        self.assertIn(blank.status_code, (400, 422))


if __name__ == "__main__":
    unittest.main()
