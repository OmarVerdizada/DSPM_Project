"""Track S-C - cursor-paginated inventory API + read-switch parity.

The inventory is served from the normalized `assets` table (fast, keyset) when
DSPM_INVENTORY_FROM_NORMALIZED=1 and the mirror is complete, else from the report
blobs. These tests pin the two paths byte-for-byte equal (parity) and check that
keyset pagination covers every row exactly once with no gaps or duplicates - on
whichever backend DSPM_DB_URL selects (temp SQLite here; conftest isolates on PG).
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from uuid import uuid4

from backend import store

_RISK = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
_FRAMEWORKS = ["GDPR", "PCI-DSS", "HIPAA"]


def _files(source: str, n: int) -> list[dict]:
    out = []
    for i in range(n):
        out.append({
            "path": f"/{source}/file_{i:03d}",
            "name": f"file_{i:03d}",
            "extension": ".txt" if i % 2 == 0 else ".csv",
            "size": (i * 13) % 500,
            "owner": f"user{i % 3}",
            "modified_at": f"2026-06-{(i % 28) + 1:02d}T00:00:00+00:00",
            "risk": {"level": _RISK[i % 4], "score": (i * 7) % 100},
            "findings": [{"type": "t", "framework": _FRAMEWORKS[j % 3]} for j in range(i % 4)],
        })
    return out


def _report(scan_id: str, source: str, files: list[dict]) -> dict:
    return {"scan_id": scan_id, "source": source, "summary": {}, "files": files}


class _SeededStore(unittest.TestCase):
    """15 local + 10 smb assets across two scans (same names, different source ->
    distinct ids, so the id tiebreaker is exercised)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = store.DB_PATH
        store.DB_PATH = Path(self._tmp.name) / "inv.sqlite"
        store.init_db()
        self.tid = f"t-{uuid4().hex[:8]}"
        store.create_tenant(self.tid, "INV")
        store.save_scan_history(self.tid, _report("s1", "local", _files("local", 15)))
        store.save_scan_history(self.tid, _report("s2", "smb", _files("smb", 10)))

    def tearDown(self) -> None:
        store.DB_PATH = self._orig
        self._tmp.cleanup()

    def _both(self, **kw):
        filt = store._inventory_filters(
            kw.get("risk", ""), kw.get("source", ""), kw.get("framework", ""),
            kw.get("q", ""), kw.get("extension", ""), kw.get("protected"),
            kw.get("finding_type", ""))
        args = (self.tid, filt, kw.get("sort", "risk_score"), kw.get("cursor", ""), kw.get("limit", 100))
        return store._list_inventory_normalized(*args), store._list_inventory_blob(*args)


class InventoryParityTests(_SeededStore):
    def test_normalized_equals_blob_across_filters_and_sorts(self) -> None:
        combos = [
            {}, {"risk": "CRITICAL"}, {"risk": "low"}, {"source": "local"}, {"source": "smb"},
            {"extension": ".txt"}, {"extension": ".csv"}, {"framework": "GDPR"},
            {"framework": "pci-dss"}, {"q": "file_00"}, {"q": "smb/file_012"},
            {"sort": "size"}, {"sort": "finding_count"}, {"sort": "modified_at"}, {"sort": "name"},
            {"risk": "HIGH", "sort": "size"}, {"source": "smb", "sort": "name"}, {"limit": 5},
        ]
        for kw in combos:
            n, b = self._both(**kw)
            self.assertEqual(n, b, f"normalized != blob for {kw}")

    def test_parity_holds_page_by_page(self) -> None:
        for sort in ("risk_score", "size", "modified_at", "name"):
            cursor = ""
            for _ in range(50):
                n, b = self._both(sort=sort, cursor=cursor, limit=4)
                self.assertEqual(n, b, f"page parity mismatch sort={sort} cursor={cursor!r}")
                if not n["has_more"]:
                    break
                cursor = n["next_cursor"]


class InventoryKeysetTests(_SeededStore):
    def _walk(self, path_fn, sort="risk_score", limit=4):
        seen, cursor = [], ""
        for _ in range(100):
            filt = store._inventory_filters("", "", "", "", "")
            page = path_fn(self.tid, filt, sort, cursor, limit)
            seen.extend(item["id"] for item in page["items"])
            self.assertLessEqual(len(page["items"]), limit)
            if not page["has_more"]:
                break
            cursor = page["next_cursor"]
        return seen

    def test_keyset_covers_all_exactly_once_normalized(self) -> None:
        ids = self._walk(store._list_inventory_normalized)
        self.assertEqual(len(ids), 25)
        self.assertEqual(len(set(ids)), 25)  # no gaps, no duplicates

    def test_keyset_covers_all_exactly_once_blob(self) -> None:
        ids = self._walk(store._list_inventory_blob)
        self.assertEqual(len(ids), 25)
        self.assertEqual(len(set(ids)), 25)

    def test_page_sequence_identical_across_paths(self) -> None:
        self.assertEqual(self._walk(store._list_inventory_normalized),
                         self._walk(store._list_inventory_blob))

    def test_cursor_is_versioned_sort_bound_and_rejects_search_cursor(self) -> None:
        filt = store._inventory_filters("", "", "", "", "")
        first = store._list_inventory_normalized(self.tid, filt, "risk_score", "", 4)
        decoded = json.loads(base64.urlsafe_b64decode(first["next_cursor"]).decode("utf-8"))
        self.assertEqual(decoded[:3], ["sc-v3", "risk_score", "DESC"])

        wrong_sort = store._list_inventory_normalized(self.tid, filt, "size", first["next_cursor"], 4)
        size_first = store._list_inventory_normalized(self.tid, filt, "size", "", 4)
        self.assertEqual(wrong_sort, size_first)

        search_cursor = base64.urlsafe_b64encode(b'["sf-v3",999999999]').decode("ascii")
        forged = store._list_inventory_normalized(self.tid, filt, "risk_score", search_cursor, 4)
        self.assertEqual(forged, store._list_inventory_normalized(self.tid, filt, "risk_score", "", 4))


class InventoryFilterTests(_SeededStore):
    def test_source_filter_and_total(self) -> None:
        n, _ = self._both(source="local")
        self.assertTrue(all(i["source"] == "local" for i in n["items"]))
        self.assertEqual(n["total"], 15)

    def test_common_file_server_source_group_matches_local_and_smb_only(self) -> None:
        normalized, blob = self._both(source="scan-kind:file-server")
        self.assertEqual(normalized, blob)
        self.assertEqual(normalized["total"], 25)
        self.assertTrue(all(item["source"] in {"local", "smb"} for item in normalized["items"]))

        store.save_scan_history(self.tid, _report("endpoint-1", "endpoint-local", _files("endpoint", 3)))
        normalized, blob = self._both(source="scan-kind:endpoint")
        self.assertEqual(normalized, blob)
        self.assertEqual(normalized["total"], 3)
        self.assertTrue(all(item["source"] == "endpoint-local" for item in normalized["items"]))

    def test_risk_filter_case_insensitive(self) -> None:
        n, _ = self._both(risk="critical")
        self.assertTrue(n["items"])
        self.assertTrue(all(i["risk_level"] == "CRITICAL" for i in n["items"]))

    def test_search_and_framework_and_extension(self) -> None:
        n, _ = self._both(q="file_005")
        self.assertTrue(all("file_005" in i["path"].lower() for i in n["items"]))
        n, _ = self._both(framework="gdpr")
        self.assertTrue(all("gdpr" in (i["top_frameworks"] or "").lower() for i in n["items"]))
        n, _ = self._both(extension=".txt")
        self.assertTrue(all(i["extension"] == ".txt" for i in n["items"]))

        files = [{
            "path": "/opaque.bin", "name": "opaque.bin", "risk": {"level": "HIGH", "score": 80},
            "findings": [{"type": "api_token", "display_name": "Access token", "framework": "GDPR"}],
        }]
        store.save_scan_history(self.tid, _report("s-search-metadata", "local", files))
        normalized, blob = self._both(q="access token")
        self.assertEqual(normalized, blob)
        self.assertEqual([item["name"] for item in normalized["items"]], ["opaque.bin"])

    def test_protected_finding_type_and_multi_framework_or(self) -> None:
        files = [
            {
                "path": "/special/locked.txt", "name": "locked.txt", "protected": True,
                "findings": [{"type": "api_key", "display_name": "API key", "framework": "GDPR"}],
            },
            {
                "path": "/special/card.txt", "name": "card.txt",
                "findings": [{"type": "pan", "display_name": "Payment card", "framework": "PCI-DSS"}],
            },
        ]
        store.save_scan_history(self.tid, _report("s-filter", "local", files))

        normalized, blob = self._both(protected=True)
        self.assertEqual(normalized, blob)
        self.assertEqual([item["name"] for item in normalized["items"]], ["locked.txt"])

        normalized, blob = self._both(finding_type="API key")
        self.assertEqual(normalized, blob)
        self.assertEqual([item["name"] for item in normalized["items"]], ["locked.txt"])

        normalized, blob = self._both(framework="gdpr,pci_dss")
        self.assertEqual(normalized, blob)
        self.assertIn("locked.txt", {item["name"] for item in normalized["items"]})
        self.assertIn("card.txt", {item["name"] for item in normalized["items"]})

    def test_normalized_facets_and_asset_detail(self) -> None:
        files = [{
            "path": "/detail/secret.txt", "name": "secret.txt", "protected": True,
            "risk": {"level": "HIGH", "score": 88},
            "findings": [{"type": "token", "display_name": "Access token", "framework": "GDPR", "samples": ["masked"]}],
        }]
        store.save_scan_history(self.tid, _report("s-detail", "local", files))
        with mock.patch.dict(os.environ, {"DSPM_INVENTORY_FROM_NORMALIZED": "1"}):
            facets = store.inventory_facets(self.tid)
            page = store.list_inventory(self.tid, q="detail/secret")
            detail = store.get_inventory_asset(self.tid, page["items"][0]["id"])
        self.assertEqual(facets["source"], "normalized")
        self.assertGreaterEqual(facets["protected"], 1)
        self.assertIn("Access token", {item["value"] for item in facets["finding_types"]})
        self.assertEqual(detail["path"], "/detail/secret.txt")
        self.assertEqual(detail["findings"][0]["samples"], ["masked"])

    def test_facets_aggregate_the_whole_estate_across_sources(self) -> None:
        """Dashboard regression: after a file-server scan (many files) followed by
        an endpoint scan (few files), the dashboard hydrated itself from the
        latest scan alone and reported 1 file while Data Inventory showed all of
        them. The facets estate block is what the dashboard now renders, so it
        must cover EVERY source and carry the estate aggregates on both the
        normalized and blob read paths."""
        with mock.patch.dict(os.environ, {"DSPM_INVENTORY_FROM_NORMALIZED": "1"}):
            normalized = store.inventory_facets(self.tid)
        with mock.patch.dict(os.environ, {"DSPM_INVENTORY_FROM_NORMALIZED": "0"}):
            blob = store.inventory_facets(self.tid)

        for label, facets in (("normalized", normalized), ("blob", blob)):
            self.assertEqual(facets["total"], 25, f"{label}: both sources must be counted")
            self.assertEqual(
                {item["value"] for item in facets["sources"]}, {"local", "smb"},
                f"{label}: the estate spans every scan source",
            )
            # Seeded files with i % 4 != 0 carry findings: 11 of 15 local + 7 of 10 smb.
            self.assertEqual(facets["sensitive"], 18, f"{label}: sensitive estate count")
            self.assertEqual(facets["hidden"], 0, f"{label}: hidden estate count")
            self.assertGreater(facets["avg_risk_score"], 0, f"{label}: estate risk average")
        self.assertAlmostEqual(
            normalized["avg_risk_score"], blob["avg_risk_score"], places=6,
            msg="both read paths must agree on the estate average",
        )

    def test_demo_sample_scans_never_enter_the_estate(self) -> None:
        """Dashboard regression: demo-dataset scans (enterprise_test_data) were
        persisted into `assets` like real scans, so the dashboard and Data
        Inventory counted synthetic files alongside the customer's real estate
        (490 "high" where the real file server had 207). Demo scans stay
        viewable as reports but must never enter the durable estate."""
        demo_files = [{
            "path": f"C:\repo\enterprise_test_data\HR\f{i}.txt", "name": f"f{i}.txt",
            "risk": {"level": "HIGH", "score": 80},
            "findings": [{"type": "t", "framework": "GDPR"}],
        } for i in range(10)]
        before = store.inventory_facets(self.tid)["total"]
        store.save_scan_history(self.tid, _report("s-demo", "local", demo_files))

        self.assertEqual(
            store.inventory_facets(self.tid)["total"], before,
            "a demo-dataset scan must not add assets to the estate",
        )
        history_ids = {item["scan_id"] for item in store.read_scan_history(self.tid, limit=50)}
        self.assertIn("s-demo", history_ids, "the demo scan report itself stays in history")

    def test_purge_removes_legacy_demo_assets_only(self) -> None:
        """Estates written before the demo exclusion carry synthetic rows; the
        startup purge removes exactly those and nothing real."""
        demo_files = [{
            "path": f"/mnt/enterprise_test_data/Sales/g{i}.csv", "name": f"g{i}.csv",
            "risk": {"level": "MEDIUM", "score": 50}, "findings": [],
        } for i in range(4)]
        with mock.patch.dict(os.environ, {"DSPM_DEMO_ASSETS_IN_INVENTORY": "1"}):
            store.save_scan_history(self.tid, _report("s-legacy", "local", demo_files))
        self.assertEqual(store.inventory_facets(self.tid)["total"], 29, "legacy path wrote demo rows")

        removed = store.purge_demo_sample_assets(self.tid)

        self.assertEqual(removed, 4)
        facets = store.inventory_facets(self.tid)
        self.assertEqual(facets["total"], 25, "every real asset must survive the purge")
        self.assertEqual({item["value"] for item in facets["sources"]}, {"local", "smb"})

    def test_search_is_case_insensitive_and_like_wildcards_are_literal(self) -> None:
        files = [
            {"path": "/Finance/Q4_100%.xlsx", "name": "Q4_100%.xlsx", "owner": "ACME\\Alice"},
            {"path": "/Finance/Q4X100-final.xlsx", "name": "Q4X100-final.xlsx", "owner": "ACME\\Bob"},
        ]
        store.save_scan_history(self.tid, _report("s3", "local", files))

        normalized, blob = self._both(q="FINANCE/Q4_100%")
        self.assertEqual(normalized, blob)
        self.assertEqual([item["name"] for item in normalized["items"]], ["Q4_100%.xlsx"])

        normalized, blob = self._both(q="ACME\\ALICE")
        self.assertEqual(normalized, blob)
        self.assertEqual([item["name"] for item in normalized["items"]], ["Q4_100%.xlsx"])

    def test_sort_risk_score_descending(self) -> None:
        n, _ = self._both(sort="risk_score", limit=100)
        scores = [i["risk_score"] for i in n["items"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_sort_risk_score_ascending_is_server_wide_and_cursor_bound(self) -> None:
        normalized = store.list_inventory(self.tid, sort="risk_score", direction="asc", limit=4)
        blob = None
        with mock.patch.dict(os.environ, {"DSPM_INVENTORY_FROM_NORMALIZED": "0"}):
            blob = store.list_inventory(self.tid, sort="risk_score", direction="asc", limit=4)
        self.assertEqual(normalized["items"], blob["items"])
        scores = [item["risk_score"] for item in normalized["items"]]
        self.assertEqual(scores, sorted(scores))
        # A cursor generated for Most Critical cannot be reused for Low first.
        descending = store.list_inventory(self.tid, sort="risk_score", direction="desc", limit=4)
        reversed_with_old_cursor = store.list_inventory(
            self.tid, sort="risk_score", direction="asc", cursor=descending["next_cursor"], limit=4,
        )
        self.assertEqual(reversed_with_old_cursor["items"], normalized["items"])


class InventoryReadSwitchTests(_SeededStore):
    def test_explicit_flag_off_serves_blob(self) -> None:
        env = dict(os.environ)
        env["DSPM_INVENTORY_FROM_NORMALIZED"] = "0"
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(store.list_inventory(self.tid)["source"], "blob")

    def test_complete_mirror_uses_normalized_path_by_default(self) -> None:
        env = dict(os.environ)
        env.pop("DSPM_INVENTORY_FROM_NORMALIZED", None)
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(store.list_inventory(self.tid)["source"], "normalized")

    def test_flag_on_and_ready_serves_normalized(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_INVENTORY_FROM_NORMALIZED": "1"}):
            self.assertEqual(store.list_inventory(self.tid)["source"], "normalized")

    def test_malformed_cursor_serves_first_page(self) -> None:
        r = store.list_inventory(self.tid, cursor="!!!not-base64!!!")
        self.assertTrue(r["items"])

    def test_selected_normalized_path_fails_closed_instead_of_materializing_blobs(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_INVENTORY_FROM_NORMALIZED": "1"}), mock.patch(
            "backend.store._list_inventory_normalized", side_effect=RuntimeError("database interrupted")
        ), mock.patch("backend.store._list_inventory_blob") as blob:
            with self.assertRaises(store.InventoryReadUnavailable):
                store.list_inventory(self.tid)
        blob.assert_not_called()

    def test_missing_normalized_detail_does_not_scan_report_blobs(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_INVENTORY_FROM_NORMALIZED": "1"}), mock.patch(
            "backend.store._inventory_blob_rows"
        ) as blob:
            self.assertIsNone(store.get_inventory_asset(self.tid, "0" * 24))
        blob.assert_not_called()

    def test_capped_total_is_reused_across_cursor_pages_and_invalidated_on_save(self) -> None:
        store._invalidate_inventory_query_cache(self.tid)
        conn = mock.Mock()
        conn.execute.return_value.fetchone.return_value = (25,)
        where, params = ["tenant_id = ?"], [self.tid]
        with mock.patch.dict(os.environ, {"DSPM_INVENTORY_COUNT_CACHE_SECONDS": "30"}):
            self.assertEqual(store._capped_inventory_total(conn, self.tid, where, params), 25)
            self.assertEqual(store._capped_inventory_total(conn, self.tid, where, params), 25)
            self.assertEqual(conn.execute.call_count, 1)
            cache_entries = [key for key in store._inventory_count_cache if key[1] == self.tid]
            self.assertEqual(len(cache_entries), 1)
            store.save_scan_history(self.tid, _report("cache-invalidation", "local", []))
            self.assertFalse([key for key in store._inventory_count_cache if key[1] == self.tid])


class InventorySEEndpointTests(_SeededStore):
    def setUp(self) -> None:
        super().setUp()
        from fastapi.testclient import TestClient
        from backend.app import app
        from backend.security import create_token

        store.create_user("se-viewer", "unused-test-hash", "viewer", self.tid)
        self.client = TestClient(app)
        self.headers = {"Authorization": f"Bearer {create_token('se-viewer', 'viewer', self.tid)}"}

    def test_facets_detail_and_compact_history_routes(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_INVENTORY_FROM_NORMALIZED": "1"}):
            facets = self.client.get("/api/inventory/facets", headers=self.headers)
            page = self.client.get("/api/inventory?limit=1", headers=self.headers)
            asset_id = page.json()["items"][0]["id"]
            detail = self.client.get(f"/api/inventory/{asset_id}", headers=self.headers)
        compact = self.client.get("/api/history/s2/report?include_files=false", headers=self.headers)
        full = self.client.get("/api/history/s2/report", headers=self.headers)

        self.assertEqual(facets.status_code, 200, facets.text)
        self.assertEqual(facets.json()["source"], "normalized")
        self.assertEqual(detail.status_code, 200, detail.text)
        self.assertIn("path", detail.json()["asset"])
        self.assertEqual(compact.status_code, 200, compact.text)
        self.assertEqual(compact.json()["report"]["files"], [])
        self.assertTrue(compact.json()["report"]["files_omitted"])
        self.assertEqual(len(full.json()["report"]["files"]), 10)

    def test_inventory_route_accepts_all_server_facets(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_INVENTORY_FROM_NORMALIZED": "1"}):
            response = self.client.get(
                "/api/inventory?protected=false&finding_type=t&framework=gdpr,pci_dss&limit=5",
                headers=self.headers,
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertLessEqual(len(response.json()["items"]), 5)


class InventoryEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient
        from backend.app import app
        from backend.security import create_token

        self.client = TestClient(app)
        self.headers = {"Authorization": f"Bearer {create_token('admin', 'admin', 'default')}"}

    def test_shape(self) -> None:
        r = self.client.get("/api/inventory?limit=5&sort=risk_score", headers=self.headers)
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        for key in ("items", "next_cursor", "has_more", "total", "total_is_estimate", "source"):
            self.assertIn(key, body)
        self.assertIsInstance(body["items"], list)

    def test_requires_auth(self) -> None:
        self.assertIn(self.client.get("/api/inventory").status_code, (401, 403))

    def test_normalized_operational_failure_is_retryable_503(self) -> None:
        with mock.patch("backend.app.list_inventory", side_effect=store.InventoryReadUnavailable("hidden")):
            response = self.client.get("/api/inventory", headers=self.headers)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers["retry-after"], "5")
        self.assertNotIn("hidden", response.text)


if __name__ == "__main__":
    unittest.main()
