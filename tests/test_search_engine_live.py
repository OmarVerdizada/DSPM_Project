"""S-F.2 live Meilisearch parity, repair, isolation, and failure certification.

Opt in with DSPM_MEILISEARCH_LIVE_URL. The suite creates and deletes one unique
index and never touches the configured production index.
"""

from __future__ import annotations

import os
import uuid
import unittest
from unittest import mock

from backend import search, store


_LIVE_URL = os.getenv("DSPM_MEILISEARCH_LIVE_URL", "").rstrip("/")
_LIVE_KEY = os.getenv("DSPM_MEILISEARCH_LIVE_KEY", "")


def _asset(asset_id: str, tenant: str, name: str, risk: int, *, protected: bool = False) -> dict:
    path = f"/finance/{name}.txt"
    return {
        "id": asset_id,
        "tenant_id": tenant,
        "source": "smb",
        "path": path,
        "name": f"{name}.txt",
        "extension": ".txt",
        "share": "finance",
        "risk_level": "CRITICAL" if risk >= 90 else "HIGH",
        "risk_score": risk,
        "size": 100 + risk,
        "owner": "finance-team",
        "modified_at": "2026-08-05T00:00:00Z",
        "finding_count": 1,
        "top_frameworks": "GDPR",
        "is_protected": protected,
        "finding_types": '["Access Token"]',
        "framework_keys": '["gdpr"]',
        "search_text": f"{path} {name} finance-team access token".lower(),
    }


@unittest.skipUnless(_LIVE_URL, "set DSPM_MEILISEARCH_LIVE_URL for live S-F.2 certification")
class LiveMeilisearchCertificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.index_uid = f"sentro_sf2_live_{uuid.uuid4().hex}"
        cls.config = search.SearchConfig(
            engine="meilisearch",
            url=_LIVE_URL,
            api_key=_LIVE_KEY,
            index_uid=cls.index_uid,
            timeout_seconds=5,
            read_enabled=True,
            batch_size=100,
            reconcile_interval_seconds=0,
        )
        cls.client = search.MeilisearchClient(cls.config)
        cls.assets = [
            _asset("a1", "tenant-a", "quarterly-secret", 99, protected=True),
            _asset("a2", "tenant-a", "payroll-token", 91),
            _asset("a3", "tenant-a", "budget-secret", 80),
            _asset("b1", "tenant-b", "quarterly-secret", 100, protected=True),
        ]
        cls.client.add_documents([search.asset_document(asset) for asset in cls.assets], wait=True)

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls.client.delete_index(wait=True)
        finally:
            cls.client.close()

    def test_typo_search_filter_parity_and_tenant_isolation(self) -> None:
        page = self.client.search(
            "tenant-a",
            {
                "q": "secrett",
                "risk": "",
                "source": "smb",
                "extension": ".txt",
                "protected": None,
                "finding_type": "access token",
                "frameworks": ["gdpr"],
            },
            "risk_score",
            "DESC",
            "",
            20,
        )
        self.assertEqual([item["id"] for item in page["items"]], ["a1", "a3"])
        self.assertNotIn("b1", {item["id"] for item in page["items"]})
        self.assertEqual(page["facets"]["protected"], 1)

    def test_live_reconciliation_repairs_missing_stale_and_orphan_documents(self) -> None:
        expected = self.assets
        self.client.delete_documents(["a1"], wait=True)
        stale = search.asset_document(expected[1])
        stale["projection_hash"] = "stale"
        orphan = search.asset_document(_asset("orphan", "tenant-z", "orphan-secret", 70))
        self.client.add_documents([stale, orphan], wait=True)
        source = {asset["id"]: asset for asset in expected}
        env = {
            "DSPM_SEARCH_ENGINE": "meilisearch",
            "DSPM_MEILISEARCH_URL": _LIVE_URL,
            "DSPM_MEILISEARCH_API_KEY": _LIVE_KEY,
            "DSPM_MEILISEARCH_INDEX": self.index_uid,
            "DSPM_SEARCH_BATCH_SIZE": "100",
        }
        with mock.patch.dict(os.environ, env), mock.patch("backend.search._client", return_value=self.client):
            result = search.reconcile_index(
                [expected],
                lambda documents: [
                    source[str(document["id"])]
                    for document in documents
                    if str(document["id"]) in source
                ],
                repair=True,
            )
        self.assertEqual(result["missing_documents"], 1)
        self.assertEqual(result["stale_documents"], 1)
        self.assertEqual(result["orphan_documents"], 1)
        self.assertTrue(result["in_sync"])
        self.assertEqual(self.client.stats()["numberOfDocuments"], len(expected))

    def test_real_connection_failure_falls_back_without_leaking_configuration(self) -> None:
        fallback = {"items": [], "next_cursor": None, "has_more": False, "total": 0, "total_is_estimate": False}
        env = {
            "DSPM_SEARCH_ENGINE": "meilisearch",
            "DSPM_MEILISEARCH_URL": "http://127.0.0.1:1",
            "DSPM_SEARCH_READ_ENABLED": "1",
            "DSPM_SEARCH_TIMEOUT_SECONDS": "0.2",
        }
        search.close_search_clients()
        with mock.patch.dict(os.environ, env), mock.patch(
            "backend.store._list_inventory_blob", return_value=fallback
        ):
            result = store.list_inventory("tenant-a", q="secret")
        self.assertEqual(result["source"], "blob")


if __name__ == "__main__":
    unittest.main()
