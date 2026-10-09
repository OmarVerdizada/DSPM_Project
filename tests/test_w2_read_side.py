"""W2.5: the console's aggregates are built once and shared, and its lists page by keyset.

The remediation summary and facets were per-process 15-second caches, the retention summary
and the access principals were not cached at all, every partition of a running scan made
every cached answer unservable, concurrent readers of a missing answer each ran the same
aggregate, and the access files list paged by OFFSET.
"""
from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from backend import live_cache, security, store
from tests.test_w2_delta_persistence import _file, _report


class _Database(unittest.TestCase):
    FILES = 30

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._previous_path = store.DB_PATH
        store.DB_PATH = Path(self._dir.name) / "read-side.sqlite"
        self._env = mock.patch.dict(os.environ, {
            "DSPM_ARTIFACT_DIR": str(Path(self._dir.name) / "artifacts"), "DSPM_LIVE_CACHE": "1"})
        self._env.start()
        store.init_db()
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "read side")
        files = [_file(i, risk="HIGH" if i % 3 else "LOW",
                       principals=("CORP\\finance", "Everyone") if i % 2 else ("CORP\\finance",))
                 for i in range(self.FILES)]
        store.save_scan_history(self.tenant, _report("scan-a", files, "2026-10-01T00:00:00+00:00"))
        live_cache.reset_for_tests()

    def tearDown(self) -> None:
        self._env.stop()
        store.DB_PATH = self._previous_path
        live_cache.reset_for_tests()
        self._dir.cleanup()


class OneReaderBuildsAnAnswerTest(_Database):

    def test_concurrent_readers_of_a_missing_answer_share_one_build(self) -> None:
        calls, start = [], threading.Event()

        def build():
            calls.append(1)
            time.sleep(0.2)
            return {"n": 42}

        results: list = []

        def reader() -> None:
            start.wait()
            results.append(live_cache.cached_json(self.tenant, "slow_aggregate", None, build))

        threads = [threading.Thread(target=reader) for _ in range(6)]
        for thread in threads:
            thread.start()
        start.set()
        for thread in threads:
            thread.join(10)
        self.assertEqual(len(calls), 1, "the aggregate ran once per reader")
        self.assertEqual(results, [{"n": 42}] * 6)
        self.assertEqual(live_cache.diagnostics()["coalesced"], 5)


class TheQueueCountsAreSharedTest(_Database):

    def test_a_second_ask_is_answered_without_the_aggregates_until_a_finding_changes(self) -> None:
        first = store.remediation_summary(self.tenant)
        with mock.patch.object(store, "_build_remediation_summary", side_effect=AssertionError("rebuilt")):
            self.assertEqual(store.remediation_summary(self.tenant), first)
        finding_id = store.get_remediation_findings(self.tenant)["items"][0]["finding_id"] \
            if hasattr(store, "get_remediation_findings") else None
        if finding_id is None:
            with store._connect() as conn:
                finding_id = str(conn.execute("SELECT id FROM findings WHERE tenant_id = ? LIMIT 1",
                                              (self.tenant,)).fetchone()["id"])
        store.update_finding_lifecycle(self.tenant, finding_id, "status", {"status": "IN_PROGRESS"}, "analyst")
        after = store.remediation_summary(self.tenant)
        self.assertEqual(after["in_progress"], first["in_progress"] + 1, "a click left the counts stale")

    def test_the_facets_retention_and_principals_are_shared_too(self) -> None:
        facets = store._remediation_facets(self.tenant, "current")
        retention = store.data_retention_summary(self.tenant)
        principals = store.list_access_principals(self.tenant)
        with mock.patch.object(store, "_build_remediation_facets", side_effect=AssertionError("rebuilt")), \
                mock.patch.object(store, "_build_retention_summary", side_effect=AssertionError("rebuilt")), \
                mock.patch.object(store, "_build_access_principals", side_effect=AssertionError("rebuilt")):
            self.assertEqual(store._remediation_facets(self.tenant, "current"), facets)
            self.assertEqual(store.data_retention_summary(self.tenant), retention)
            self.assertEqual(store.list_access_principals(self.tenant), principals)
        self.assertEqual({item["principal"] for item in principals}, {"CORP\\finance", "Everyone"})


class APartitionDoesNotEmptyTheCacheTest(_Database):

    def test_partition_writes_move_the_generation_once_a_window_and_a_save_always(self) -> None:
        def generation() -> int:
            return store.derived_lookup(self.tenant, "nothing")[1]

        store._partition_generation_moved.pop(self.tenant, None)
        before = generation()
        with mock.patch.dict(os.environ, {"DSPM_LIVE_CACHE_PARTITION_SECONDS": "3600"}):
            store._invalidate_after_partition(self.tenant)
            store._invalidate_after_partition(self.tenant)
            store._invalidate_after_partition(self.tenant)
        self.assertEqual(generation(), before + 1)
        store.save_scan_history(self.tenant, _report("scan-b", [_file(1)], "2026-10-02T00:00:00+00:00"))
        self.assertGreater(generation(), before + 1, "a saved scan always moves it")


class TheAccessListPagesByKeysetTest(_Database):

    def test_keyset_pages_are_the_offset_pages(self) -> None:
        principal = store.list_access_principals(self.tenant)[0]["key"]
        whole = store.list_access_assets(self.tenant, principal_key=principal, limit=500)
        pages, after = [], None
        while True:
            page = store.list_access_assets(self.tenant, principal_key=principal, limit=7, after=after)
            pages.extend(page)
            if len(page) < 7:
                break
            last = page[-1]
            after = (last["risk_score"], last["path"], last["asset_id"])
        self.assertEqual([item["asset_id"] for item in pages], [item["asset_id"] for item in whole])
        self.assertEqual(len(whole), self.FILES)

    def test_the_api_hands_out_a_cursor_and_refuses_a_forged_one(self) -> None:
        from backend.app import app

        store.create_user("rs-admin", security.hash_password("Kestrel-lantern-4471"), "admin", self.tenant)
        client = TestClient(app)
        headers = {"Authorization": f"Bearer {security.create_token('rs-admin', 'admin', self.tenant)}"}
        principal = store.list_access_principals(self.tenant)[0]["key"]
        seen, cursor = [], ""
        for _ in range(10):
            params = {"key": principal, "sensitive_only": "false", "limit": 8}
            if cursor:
                params["cursor"] = cursor
            body = client.get("/api/access/files", params=params, headers=headers).json()
            seen.extend(item["asset_id"] for item in body["files"])
            cursor = body["next_cursor"]
            if not cursor:
                break
        self.assertEqual(len(seen), self.FILES)
        self.assertEqual(len(set(seen)), self.FILES)
        forged = client.get("/api/access/files", params={"key": principal, "cursor": "not-a-cursor"}, headers=headers)
        self.assertEqual(forged.status_code, 400)


if __name__ == "__main__":
    unittest.main()
