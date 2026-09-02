"""Track S-F optional Meilisearch valve contracts (no live service required)."""

from __future__ import annotations

import json
import os
import unittest
from unittest import mock

import httpx

from backend import search, store


class SearchConfigurationTests(unittest.TestCase):
    def test_database_search_is_the_safe_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            for name in ("DSPM_SEARCH_ENGINE", "DSPM_MEILISEARCH_URL", "DSPM_SEARCH_READ_ENABLED"):
                os.environ.pop(name, None)
            config = search.config_from_env()
        self.assertEqual(config.engine, "database")
        self.assertFalse(config.enabled)
        self.assertFalse(config.read_enabled)
        self.assertEqual(config.reconcile_interval_seconds, 300)
        self.assertTrue(config.reconcile_repair)

    def test_read_cutover_is_separate_from_indexing_configuration(self) -> None:
        with mock.patch.dict(os.environ, {
            "DSPM_SEARCH_ENGINE": "meilisearch",
            "DSPM_MEILISEARCH_URL": "http://127.0.0.1:7700/",
            "DSPM_SEARCH_READ_ENABLED": "0",
        }):
            config = search.config_from_env()
            self.assertTrue(config.enabled)
            self.assertFalse(search.external_search_requested())


class SearchProjectionTests(unittest.TestCase):
    def test_projection_is_metadata_only_and_tenant_scoped(self) -> None:
        document = search.asset_document({
            "tenant_id": "tenant-a", "id": "asset-1", "path": "/secret.txt",
            "finding_types": '["Access token"]', "framework_keys": '["gdpr"]',
            "detail_json": '{"samples":["must-not-leave-db"]}',
        })
        self.assertEqual(document["tenant_id"], "tenant-a")
        self.assertEqual(document["finding_types"], ["Access token"])
        self.assertEqual(document["finding_types_normalized"], ["access token"])
        self.assertEqual(len(document["projection_hash"]), 64)
        self.assertNotIn("detail_json", document)

    def test_filter_always_includes_escaped_tenant_and_all_facets(self) -> None:
        expression = search.build_filter('tenant "quoted"', {
            "risk": "HIGH", "source": "smb", "extension": ".txt",
            "protected": True, "finding_type": "Access token",
            "frameworks": ["gdpr", "pci_dss"],
        })
        self.assertIn('tenant_id = "tenant \\"quoted\\""', expression)
        self.assertIn('index_version = "sf-v3"', expression)
        self.assertIn('risk_level = "HIGH"', expression)
        self.assertIn("is_protected = true", expression)
        self.assertIn('finding_types_normalized = "access token"', expression)
        self.assertIn(
            '(framework_keys_normalized = "gdpr" OR framework_keys_normalized = "pci_dss")',
            expression,
        )

    def test_search_cursor_offset_is_bounded_to_engine_cap(self) -> None:
        encoded = search._encode_cursor(99_999_999)
        self.assertEqual(search._decode_cursor(encoded), search._COUNT_CAP)

        def unexpected_request(_: httpx.Request) -> httpx.Response:
            self.fail("a cursor at the hit ceiling must not query beyond maxTotalHits")

        client = search.MeilisearchClient(
            search.SearchConfig(engine="meilisearch", url="http://search", read_enabled=True),
            transport=httpx.MockTransport(unexpected_request),
        )
        try:
            page = client.search("tenant-a", {"q": "x"}, "risk_score", "DESC", encoded, 100)
        finally:
            client.close()
        self.assertEqual(page["items"], [])
        self.assertFalse(page["has_more"])


class MeilisearchClientTests(unittest.TestCase):
    def test_index_creation_settings_and_writes_wait_for_async_tasks(self) -> None:
        calls: list[tuple[str, str]] = []
        next_task = iter((1, 2, 3))

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append((request.method, request.url.path))
            if request.method == "GET" and request.url.path.startswith("/tasks/"):
                return httpx.Response(200, json={"status": "succeeded"})
            return httpx.Response(202, json={"taskUid": next(next_task)})

        config = search.SearchConfig(engine="meilisearch", url="http://search")
        client = search.MeilisearchClient(config, transport=httpx.MockTransport(handler))
        try:
            client.add_documents([search.asset_document({"tenant_id": "t", "id": "a"})], wait=True)
        finally:
            client.close()

        self.assertEqual(calls[0], ("POST", "/indexes"))
        self.assertEqual(calls[1], ("GET", "/tasks/1"))
        self.assertEqual(calls[2], ("PATCH", "/indexes/sentro_assets_v1/settings"))
        self.assertIn(("GET", "/tasks/2"), calls)
        self.assertIn(("POST", "/indexes/sentro_assets_v1/documents"), calls)
        self.assertEqual(calls[-1], ("GET", "/tasks/3"))

    def test_existing_index_error_code_still_applies_and_waits_for_settings(self) -> None:
        calls: list[tuple[str, str]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append((request.method, request.url.path))
            if request.method == "POST" and request.url.path == "/indexes":
                return httpx.Response(400, json={"code": "index_already_exists", "type": "invalid_request"})
            if request.method == "PATCH":
                return httpx.Response(202, json={"taskUid": 9})
            return httpx.Response(200, json={"status": "succeeded"})

        config = search.SearchConfig(engine="meilisearch", url="http://search")
        client = search.MeilisearchClient(config, transport=httpx.MockTransport(handler))
        try:
            tasks = client.ensure_index(wait=True)
        finally:
            client.close()

        self.assertEqual(tasks, [9])
        self.assertEqual(calls[-1], ("GET", "/tasks/9"))

    def test_search_maps_page_cursor_facets_and_shape(self) -> None:
        requests: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(json.loads(request.content.decode()))
            return httpx.Response(200, json={
                "hits": [
                    {"id": "a1", "path": "/a", "name": "a", "risk_score": 90,
                     "finding_types": ["Token"], "framework_keys": ["gdpr"], "is_protected": True},
                    {"id": "a2", "path": "/b", "name": "b", "risk_score": 80},
                ],
                "estimatedTotalHits": 3,
                "facetDistribution": {
                    "risk_level": {"HIGH": 2}, "source": {"smb": 2},
                    "is_protected": {"true": 1}, "finding_types": {"Token": 1},
                    "framework_keys": {"gdpr": 1},
                },
            })

        config = search.SearchConfig(engine="meilisearch", url="http://search", read_enabled=True)
        client = search.MeilisearchClient(config, transport=httpx.MockTransport(handler))
        try:
            page = client.search("tenant-a", {"q": "tok", "frameworks": []}, "risk_score", "DESC", "", 1)
        finally:
            client.close()

        self.assertEqual(page["source"], "meilisearch")
        self.assertEqual(len(page["items"]), 1)
        self.assertTrue(page["has_more"])
        self.assertTrue(page["next_cursor"])
        self.assertEqual(page["items"][0]["finding_types"], '["Token"]')
        self.assertEqual(page["facets"]["protected"], 1)
        self.assertEqual(requests[0]["filter"], 'tenant_id = "tenant-a" AND index_version = "sf-v3"')
        self.assertEqual(requests[0]["sort"], ["risk_score:desc", "id:desc"])
        self.assertEqual(requests[0]["limit"], 2)

    def test_http_failure_is_a_fallback_signal_without_secret_leak(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(503, json={"message": "down"})

        config = search.SearchConfig(engine="meilisearch", url="http://search", api_key="super-secret")
        client = search.MeilisearchClient(config, transport=httpx.MockTransport(handler))
        try:
            with self.assertRaises(search.SearchUnavailable) as raised:
                client.health()
        finally:
            client.close()
        self.assertNotIn("super-secret", str(raised.exception))

    def test_health_requires_current_index_settings(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/health":
                return httpx.Response(200, json={"status": "available"})
            if request.url.path.endswith("/settings"):
                return httpx.Response(200, json={
                    "filterableAttributes": search.FILTERABLE_ATTRIBUTES,
                    "displayedAttributes": search.INDEX_DISPLAYED_ATTRIBUTES,
                })
            if request.url.path.endswith("/stats"):
                return httpx.Response(200, json={"numberOfDocuments": 12, "isIndexing": False})
            return httpx.Response(200, json={"uid": "sentro_assets_v1", "primaryKey": "id"})

        config = search.SearchConfig(engine="meilisearch", url="http://search")
        client = search.MeilisearchClient(config, transport=httpx.MockTransport(handler))
        try:
            status = client.health()
        finally:
            client.close()

        self.assertTrue(status["index_ready"])
        self.assertEqual(status["index_version"], "sf-v3")
        self.assertEqual(status["documents"], 12)


class SearchReconciliationTests(unittest.TestCase):
    def test_repair_upserts_missing_and_stale_documents_and_deletes_orphans(self) -> None:
        assets = [
            {"tenant_id": "tenant-a", "id": "a", "path": "/secret-a.txt", "name": "a"},
            {"tenant_id": "tenant-a", "id": "b", "path": "/secret-b.txt", "name": "b"},
        ]

        class FakeClient:
            def __init__(self) -> None:
                stale_b = search.asset_document(assets[1])
                stale_b["projection_hash"] = "stale"
                self.documents = {
                    "b": stale_b,
                    "orphan": search.asset_document({
                        "tenant_id": "tenant-z", "id": "orphan", "path": "/gone", "name": "gone"
                    }),
                }

            def ensure_index(self, *, wait: bool = False) -> list[int]:
                return []

            def stats(self) -> dict:
                return {"numberOfDocuments": len(self.documents), "isIndexing": False}

            def fetch_documents(self, ids: list[str]) -> dict[str, dict]:
                return {asset_id: self.documents[asset_id] for asset_id in ids if asset_id in self.documents}

            def add_documents(self, documents: list[dict], *, wait: bool = False) -> None:
                self.documents.update({document["id"]: document for document in documents})

            def iter_documents(self, batch_size: int = 500):
                yield [self.documents[key] for key in sorted(self.documents)]

            def delete_documents(self, ids: list[str], *, wait: bool = False) -> None:
                for asset_id in ids:
                    self.documents.pop(asset_id, None)

        fake = FakeClient()
        source = {asset["id"]: asset for asset in assets}
        env = {"DSPM_SEARCH_ENGINE": "meilisearch", "DSPM_MEILISEARCH_URL": "http://search"}
        with mock.patch.dict(os.environ, env), mock.patch("backend.search._client", return_value=fake):
            result = search.reconcile_index(
                [assets],
                lambda documents: [
                    source[str(document["id"])] for document in documents if str(document["id"]) in source
                ],
                repair=True,
            )

        self.assertEqual(result["missing_documents"], 1)
        self.assertEqual(result["stale_documents"], 1)
        self.assertEqual(result["orphan_documents"], 1)
        self.assertEqual(result["repaired_upserts"], 2)
        self.assertEqual(result["repaired_deletes"], 1)
        self.assertTrue(result["in_sync"])
        self.assertEqual(set(fake.documents), {"a", "b"})

    def test_reconciliation_metrics_round_trip_in_authoritative_store(self) -> None:
        metrics = {
            "checked_at": "2026-08-05T00:00:00+00:00",
            "status": "in_sync",
            "in_sync": True,
            "lag_documents": 0,
        }
        store.save_search_reconciliation("test-index", metrics)
        self.assertEqual(store.get_search_reconciliation("test-index"), metrics)

    def test_authoritative_lookup_requires_matching_tenant_and_id(self) -> None:
        store.save_scan_history("tenant-lookup", {
            "scan_id": "sf2-lookup",
            "timestamp": "2026-08-05T00:00:00Z",
            "source": "local",
            "summary": {"total_files": 1},
            "files": [{"path": "/lookup-secret.txt", "name": "lookup-secret.txt", "size": 12}],
        })
        asset = next(
            asset
            for batch in store.iter_search_asset_batches(10)
            for asset in batch
            if asset["tenant_id"] == "tenant-lookup"
        )
        rows = store.get_search_assets_by_refs([
            {"tenant_id": "wrong-tenant", "id": asset["id"]},
            {"tenant_id": "tenant-lookup", "id": asset["id"]},
        ])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["tenant_id"], "tenant-lookup")


class SearchReadSwitchTests(unittest.TestCase):
    def test_text_query_uses_external_valve_when_read_enabled(self) -> None:
        expected = {"items": [], "source": "meilisearch", "next_cursor": None, "has_more": False, "total": 0}
        with mock.patch("backend.search.external_search_requested", return_value=True), mock.patch(
            "backend.search.search_inventory", return_value=expected
        ) as engine:
            result = store.list_inventory("tenant-a", q="typoed-name")
        self.assertIs(result, expected)
        self.assertEqual(engine.call_args.args[0], "tenant-a")

    def test_engine_failure_falls_back_to_existing_inventory_path(self) -> None:
        fallback = {"items": [], "next_cursor": None, "has_more": False, "total": 0, "total_is_estimate": False}
        with mock.patch("backend.search.external_search_requested", return_value=True), mock.patch(
            "backend.search.search_inventory", side_effect=search.SearchUnavailable("offline")
        ), mock.patch("backend.store._inventory_ready", return_value=True), mock.patch(
            "backend.store._list_inventory_normalized", return_value=fallback
        ) as database:
            result = store.list_inventory("tenant-a", q="anything")
        self.assertEqual(result["source"], "normalized")
        database.assert_called_once()

    def test_rebuild_stream_uses_keyset_not_offset_pagination(self) -> None:
        import inspect

        source = inspect.getsource(store.iter_search_asset_batches).upper()
        self.assertIn("ID > ?", source)
        self.assertNotIn("OFFSET", source)


if __name__ == "__main__":
    unittest.main()
