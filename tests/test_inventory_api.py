"""Track S-C - cursor-paginated inventory API + read-switch parity.

The inventory is served from the normalized `assets` table (fast, keyset) when
DSPM_INVENTORY_FROM_NORMALIZED=1 and the mirror is complete, else from the report
blobs. These tests pin the two paths byte-for-byte equal (parity) and check that
keyset pagination covers every row exactly once with no gaps or duplicates - on
whichever backend DSPM_DB_URL selects (temp SQLite here; conftest isolates on PG).
"""

from __future__ import annotations

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
            kw.get("q", ""), kw.get("extension", ""))
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


class InventoryFilterTests(_SeededStore):
    def test_source_filter_and_total(self) -> None:
        n, _ = self._both(source="local")
        self.assertTrue(all(i["source"] == "local" for i in n["items"]))
        self.assertEqual(n["total"], 15)

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

    def test_sort_risk_score_descending(self) -> None:
        n, _ = self._both(sort="risk_score", limit=100)
        scores = [i["risk_score"] for i in n["items"]]
        self.assertEqual(scores, sorted(scores, reverse=True))


class InventoryReadSwitchTests(_SeededStore):
    def test_flag_off_serves_blob(self) -> None:
        env = dict(os.environ)
        env.pop("DSPM_INVENTORY_FROM_NORMALIZED", None)
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(store.list_inventory(self.tid)["source"], "blob")

    def test_flag_on_and_ready_serves_normalized(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_INVENTORY_FROM_NORMALIZED": "1"}):
            self.assertEqual(store.list_inventory(self.tid)["source"], "normalized")

    def test_malformed_cursor_serves_first_page(self) -> None:
        r = store.list_inventory(self.tid, cursor="!!!not-base64!!!")
        self.assertTrue(r["items"])


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


if __name__ == "__main__":
    unittest.main()
