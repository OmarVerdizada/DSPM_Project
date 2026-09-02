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

    def test_unknown_urls_redirect_and_api_stays_strict(self) -> None:
        """Professional URL behavior: an unknown page path redirects to the
        dashboard instead of leaking a raw JSON 404; unknown API and asset
        paths keep failing loudly so clients notice."""
        page = self.client.get("/definitely-not-a-page", follow_redirects=False)
        self.assertEqual(page.status_code, 302)
        self.assertEqual(page.headers.get("location"), "/dashboard")
        api = self.client.get("/api/definitely-not-a-route", follow_redirects=False)
        self.assertEqual(api.status_code, 404)
        asset = self.client.get("/missing-file.js", follow_redirects=False)
        self.assertEqual(asset.status_code, 404)
        real = self.client.get("/scan", follow_redirects=False)
        self.assertEqual(real.status_code, 200)

    def test_scan_name_labels_assets_and_drives_the_inventory_filter(self) -> None:
        """Data Inventory filters by the scan a customer configured ("HR file
        share"), not the collector protocol ("smb"). The name travels on the
        report, lands on every asset it produced, and is exposed as a facet."""
        from backend.store import list_inventory, inventory_facets, save_scan_history

        tenant = f"lbl-{uuid4().hex[:8]}"
        create_tenant(tenant, "Label tenant")

        def report(scan_id, label, prefix, count):
            return {
                "scan_id": scan_id, "source": "smb", "scan_label": label, "summary": {},
                "files": [{"path": f"/{prefix}/f{i}.txt", "name": f"f{i}.txt",
                           "risk": {"level": "HIGH", "score": 70}} for i in range(count)],
            }

        save_scan_history(tenant, report("s-hr", "HR file share", "hr", 4))
        save_scan_history(tenant, report("s-fin", "Finance archive", "fin", 2))

        facets = inventory_facets(tenant)
        self.assertEqual(
            {item["value"]: item["count"] for item in facets["scans"]},
            {"HR file share": 4, "Finance archive": 2},
        )

        # The one Source parameter accepts a scan name OR a protocol.
        self.assertEqual(len(list_inventory(tenant, source="HR file share")["items"]), 4)
        self.assertEqual(len(list_inventory(tenant, source="Finance archive")["items"]), 2)
        self.assertEqual(len(list_inventory(tenant, source="smb")["items"]), 6)

    def test_inventory_api_accepts_a_full_length_scan_name_filter(self) -> None:
        response = self.client.get(
            "/api/inventory",
            params={"source": "S" * 80},
            headers=_headers(),
        )
        self.assertEqual(response.status_code, 200, response.text)

    def test_named_scan_reads_its_saved_run_after_current_assets_are_overwritten(self) -> None:
        """A scan source is a saved run, not the mutable label on an asset.

        A later scan of the same path used to overwrite ``assets.scan_label``;
        selecting the first scan then returned no rows even though its report
        still held the complete result.
        """
        from backend.store import get_inventory_asset, inventory_facets, list_inventory, save_scan_history

        tenant = f"historical-label-{uuid4().hex[:8]}"
        create_tenant(tenant, "Historical label")
        path = "/shared/customer-record.txt"
        save_scan_history(tenant, {
            "scan_id": "named-run",
            "source": "smb",
            "scan_label": "Customer records",
            "summary": {"total_files": 1, "high": 1},
            "files": [{
                "path": path,
                "name": "customer-record.txt",
                "findings": [{"type": "email", "risk": "HIGH", "count": 2}],
                "risk": {
                    "level": "HIGH",
                    "score": 80,
                    "reasons": ["Personal data"],
                    "dlp_recommendations": ["Restrict sharing"],
                },
            }],
        })
        # Same stable asset, newer unlabeled run: this is the regression trigger.
        save_scan_history(tenant, {
            "scan_id": "newer-run",
            "source": "smb",
            "summary": {"total_files": 1, "low": 1},
            "files": [{
                "path": path,
                "name": "customer-record.txt",
                "findings": [],
                "risk": {"level": "LOW", "score": 10, "reasons": [], "dlp_recommendations": []},
            }],
        })

        selected = list_inventory(tenant, source="Customer records")
        self.assertEqual(selected["source"], "scan-report")
        self.assertEqual(selected["scan_id"], "named-run")
        self.assertEqual(selected["total"], 1)
        item = selected["items"][0]
        self.assertEqual(item["risk_level"], "HIGH")
        self.assertEqual(item["finding_count"], 1)
        self.assertEqual((item["reason_count"], item["dlp_count"]), (1, 1))

        facets = inventory_facets(tenant, source="Customer records")
        self.assertEqual(facets["total"], 1)
        self.assertEqual(facets["risk_counts"], {"HIGH": 1})

        detail = get_inventory_asset(tenant, item["id"], scan_id=selected["scan_id"])
        self.assertEqual(detail["risk"]["level"], "HIGH")
        self.assertEqual(detail["scan_id"], "named-run")

    def test_sorting_orders_the_whole_inventory_not_one_page(self) -> None:
        """A column header sorts every asset in the tenant. The API orders the
        full table and returns one keyset page, so a 3-row page must match the
        first 3 of the globally sorted set - not a re-sort of loaded rows."""
        from backend.store import list_inventory, save_scan_history

        tenant = f"srt-{uuid4().hex[:8]}"
        create_tenant(tenant, "Sort tenant")
        save_scan_history(tenant, {
            "scan_id": "s-sort", "source": "smb", "scan_label": "Sort scan", "summary": {},
            # Names deliberately out of insertion order.
            "files": [{"path": f"/x/{name}", "name": name, "risk": {"level": "HIGH", "score": score}}
                      for name, score in (("zulu.txt", 10), ("alpha.txt", 90), ("mike.txt", 50),
                                          ("bravo.txt", 20), ("yankee.txt", 80))],
        })

        everything = [item["name"] for item in list_inventory(tenant, sort="name", limit=100)["items"]]
        self.assertEqual(everything, sorted(everything), "sort must be applied by the database")

        page = [item["name"] for item in list_inventory(tenant, sort="name", limit=3)["items"]]
        self.assertEqual(page, everything[:3], "a page must be the head of the GLOBAL order")
        self.assertEqual(page[0], "alpha.txt")

        by_risk = [item["risk_score"] for item in list_inventory(tenant, sort="risk_score", limit=2)["items"]]
        self.assertEqual(by_risk, [90, 80], "risk sort returns the globally highest first")

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
