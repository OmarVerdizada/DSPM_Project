"""W3.4 (scaling roadmap, section 24, decision D1): the console survives a scan.

While a scan writes, every write moved the estate's generation and every reader of a cached
aggregate rebuilt it - inline, in its request, in every backend at once. Now one rebuild runs
for all of them, on a pool of its own, and readers get the previous answer marked STALE with
the exact time it was computed and the rebuild's state; the API carries both and the console
shows them. Requests run on their own connection budget with their statements and lock waits
bounded in seconds; the process lock is taken on SQLite only, and the read-merge-writes that
relied on it take row or advisory locks.
"""
from __future__ import annotations

import json
import os
import threading
import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from backend import db, live_cache, security, siem_settings, store
from backend.app import app
from tests.test_live_cache import _DatabaseTest

PASSWORD = "a-w34-harbour-pass-9"


class AStaleAnswerIsServedAsStaleTest(_DatabaseTest):

    def setUp(self) -> None:
        super().setUp()
        self.addCleanup(live_cache.wait_for_rebuilds, 30)

    def _answer(self, builder):
        with live_cache.collecting() as fresh:
            value = live_cache.cached_json(self.tenant, "posture_inputs", None, builder)
        return value, fresh.summary()

    def test_a_reader_gets_the_previous_answer_marked_stale_and_never_waits(self) -> None:
        first, fresh = self._answer(lambda: {"assets": 1})
        self.assertEqual((first, fresh["stale"]), ({"assets": 1}, False))
        computed = fresh["computed_at"]
        store.bump_estate_generation(self.tenant)

        release = threading.Event()
        calls = []

        def slow_rebuild():
            calls.append(1)
            release.wait(30)
            return {"assets": 2}

        started = time.monotonic()
        value, fresh = self._answer(slow_rebuild)
        self.assertLess(time.monotonic() - started, 5, "a reader waited on the rebuild")
        self.assertEqual(value, {"assets": 1})
        self.assertEqual(fresh, {"stale": True, "computed_at": computed, "rebuild": "rebuilding"})
        # Every other reader meanwhile - here or in another backend - gets the same, and no
        # second rebuild starts.
        for _ in range(5):
            value, fresh = self._answer(slow_rebuild)
            self.assertEqual((value, fresh["stale"], fresh["rebuild"]), ({"assets": 1}, True, "rebuilding"))
        release.set()
        self.assertTrue(live_cache.wait_for_rebuilds(30))
        self.assertEqual(len(calls), 1, "a rebuild piled up behind the one running")
        value, fresh = self._answer(lambda: {"assets": 99})
        self.assertEqual((value, fresh["stale"]), ({"assets": 2}, False))

    def test_a_rebuild_that_outlasts_the_writes_behind_it_is_not_joined(self) -> None:
        self._answer(lambda: {"assets": 1})
        release = threading.Event()
        calls = []

        def slow_rebuild():
            calls.append(1)
            release.wait(30)
            return {"assets": 2}

        for _ in range(4):
            store.bump_estate_generation(self.tenant)  # a scan writing all the while
            self._answer(slow_rebuild)
        release.set()
        live_cache.wait_for_rebuilds(30)
        self.assertEqual(len(calls), 1)

    def test_a_failed_rebuild_keeps_the_previous_answer_and_says_so(self) -> None:
        self._answer(lambda: {"assets": 1})
        store.bump_estate_generation(self.tenant)

        def failing():
            raise RuntimeError("the aggregate failed")

        self._answer(failing)
        live_cache.wait_for_rebuilds(30)
        value, fresh = self._answer(failing)
        self.assertEqual((value, fresh["stale"], fresh["rebuild"]), ({"assets": 1}, True, "rebuild failed"))

    def test_a_rebuild_whose_owner_died_is_taken_over(self) -> None:
        self._answer(lambda: {"assets": 1})
        store.bump_estate_generation(self.tenant)
        key = live_cache.cache_key("posture_inputs", None)
        self.assertTrue(store.derived_claim_rebuild(self.tenant, key, "dead-owner", stale_after_seconds=600,
                                                    retry_after_seconds=30))
        _, fresh = self._answer(lambda: {"assets": 2})
        self.assertEqual(fresh["rebuild"], "rebuilding", "a live rebuild elsewhere is reported")
        self.assertFalse(live_cache._rebuilding, "a second rebuild started beside a live one")
        with store._connect() as conn:
            conn.execute("UPDATE derived_cache SET rebuild_started_at = '2000-01-01T00:00:00+00:00' "
                         "WHERE tenant_id = ?", (self.tenant,))
        self._answer(lambda: {"assets": 2})
        live_cache.wait_for_rebuilds(30)
        value, fresh = self._answer(lambda: {"assets": 99})
        self.assertEqual((value, fresh["stale"]), ({"assets": 2}, False))


class TheApiAndTheConsoleSayItTest(_DatabaseTest):

    def test_the_dashboard_carries_the_freshness_of_its_figures(self) -> None:
        self.addCleanup(live_cache.wait_for_rebuilds, 30)
        store.create_user("w34-boss", security.hash_password(PASSWORD), "admin", self.tenant)
        client = TestClient(app)
        self.addCleanup(client.close)
        headers = {"Authorization": f"Bearer {security.create_token('w34-boss', 'admin', self.tenant)}"}
        first = client.get("/api/executive-dashboard", headers=headers).json()
        self.assertFalse(first["freshness"]["stale"])
        store.bump_estate_generation(self.tenant)  # a scan wrote
        second = client.get("/api/executive-dashboard", headers=headers).json()
        self.assertEqual(second["freshness"], {"stale": True, "computed_at": first["freshness"]["computed_at"],
                                               "rebuild": "rebuilding"})
        live_cache.wait_for_rebuilds(30)
        third = client.get("/api/executive-dashboard", headers=headers).json()
        self.assertFalse(third["freshness"]["stale"], "the rebuilt figures were not served as current")
        for path in ("/api/inventory/facets", "/api/access/principals", "/api/findings"):
            self.assertIn("freshness", client.get(path, headers=headers).json(), path)

    def test_the_console_shows_a_stale_figure_as_stale(self) -> None:
        source = open(os.path.join(os.path.dirname(__file__), "..", "frontend", "app.js"), encoding="utf-8").read()
        for needle in ("function freshnessNote", "Figures as of", "Refreshing them failed",
                       "followDashboardFreshness(renderFreshness(dashboardFreshness"):
            self.assertIn(needle, source)
        page = open(os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html"), encoding="utf-8").read()
        for element in ("dashboard-freshness", "remediation-freshness", "access-freshness"):
            self.assertIn(f'id="{element}"', page)


class RequestsHaveTheirOwnBudgetTest(unittest.TestCase):

    def test_each_workload_has_its_own_bounds(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            for name in ("DSPM_PG_API_STATEMENT_TIMEOUT_SECONDS", "DSPM_PG_API_LOCK_TIMEOUT_SECONDS",
                         "DSPM_PG_STATEMENT_TIMEOUT_SECONDS", "DSPM_PG_LOCK_TIMEOUT_SECONDS"):
                os.environ.pop(name, None)
            self.assertIn("-c statement_timeout=30000", db.session_options("api"))
            self.assertIn("-c lock_timeout=5000", db.session_options("api"))
            self.assertIn("-c statement_timeout=900000", db.session_options("scan"))
            self.assertIn("-c lock_timeout=10000", db.session_options("heavy"))
            self.assertEqual(db.session_options(), db.session_options("scan"), "outside a request: scan work")

    def test_a_request_runs_on_the_api_budget_and_its_estate_write_on_the_scans(self) -> None:
        seen = {}

        def probe() -> dict:
            seen["request"] = db.current_workload()
            with store._estate_write("t-none") as _conn:
                seen["estate_write"] = db.current_workload()
            return {}

        app.add_api_route("/__w34_probe", probe, methods=["GET"])
        # Ahead of the console's catch-all route, which would answer it otherwise.
        app.router.routes.insert(0, app.router.routes.pop())
        try:
            client = TestClient(app)
            self.addCleanup(client.close)
            with mock.patch.object(store, "_connect", side_effect=lambda: _NullConn()):
                client.get("/__w34_probe")
        finally:
            app.router.routes[:] = [route for route in app.router.routes if getattr(route, "path", "") != "/__w34_probe"]
        self.assertEqual(seen, {"request": "api", "estate_write": "scan"})

    def test_the_process_lock_is_taken_on_sqlite_only(self) -> None:
        with mock.patch.object(db, "is_postgres", return_value=True):
            self.assertIsNot(store._sqlite_write_lock(), store._lock)
        with mock.patch.object(db, "is_postgres", return_value=False):
            self.assertIs(store._sqlite_write_lock(), store._lock)
        source = open(store.__file__, encoding="utf-8").read()
        self.assertNotIn("with _lock:", source, "a write section takes the process lock on PostgreSQL")


class _NullConn:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, *_args, **_kwargs):
        return self


class ReadMergeWritesHoldTheirRowsTest(_DatabaseTest):

    def test_a_refresh_token_is_spent_once(self) -> None:
        store.issue_refresh_token("hash-1", "family-1", "user-1", "jti-1", int(time.time()), int(time.time()) + 600)
        self.assertEqual(store.consume_refresh_token("hash-1")["status"], "ok")
        self.assertEqual(store.consume_refresh_token("hash-1")["status"], "replayed")

    def test_a_refresh_token_spent_meanwhile_is_a_replay(self) -> None:
        # The read saw it unspent; another request spent it before this one's write.
        store.issue_refresh_token("hash-2", "family-2", "user-2", "jti-2", int(time.time()), int(time.time()) + 600)
        real_connect = store._connect

        class SpendAfterRead:
            def __init__(self, conn):
                self.conn = conn

            def execute(self, sql, params=()):
                if sql.startswith("UPDATE refresh_tokens SET used_at"):
                    with real_connect() as other:
                        other.execute("UPDATE refresh_tokens SET used_at = 1 WHERE token_hash = 'hash-2'")
                return self.conn.execute(sql, params)

        class Wrapped:
            def __enter__(self_inner):
                self_inner.cm = real_connect()
                return SpendAfterRead(self_inner.cm.__enter__())

            def __exit__(self_inner, *exc):
                return self_inner.cm.__exit__(*exc)

        with mock.patch.object(store, "_connect", side_effect=lambda: Wrapped()), \
                mock.patch.object(store, "_sqlite_write_lock", side_effect=lambda: _NoLock()):
            self.assertEqual(store.consume_refresh_token("hash-2")["status"], "replayed")

    def test_the_siem_status_merges_every_change(self) -> None:
        siem_settings.record(delivered=1)
        siem_settings.record(last_error="none")
        with store._connect() as conn:
            row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (siem_settings.STATUS_KEY,)).fetchone()
        self.assertEqual(json.loads(row["value"]), {"delivered": 1, "last_error": "none"})

    def test_an_alert_channel_saved_twice_is_one_row(self) -> None:
        for _ in range(2):
            store.save_alert_channel(self.tenant, "email", enabled=True, config={"to": "a@b.c"}, secret_ref="",
                                     actor="admin")
        store.record_alert_channel_status(self.tenant, "email", tested=True)
        store.save_alert_channel(self.tenant, "email", enabled=True, config={"to": "x@y.z"}, secret_ref="ref",
                                 actor="admin")
        with store._connect() as conn:
            rows = conn.execute("SELECT config_json, status_json FROM alert_channels WHERE tenant_id = ?",
                                (self.tenant,)).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]["status_json"]), {"tested": True}, "a save overwrote the status")
        self.assertEqual(store.delete_alert_channel(self.tenant, "email"), "ref")
        self.assertIsNone(store.delete_alert_channel(self.tenant, "email"))

    def test_the_audit_head_never_moves_back(self) -> None:
        store.audit(self.tenant, "admin", "w34.one", {})
        store.audit(self.tenant, "admin", "w34.two", {})
        with store._connect() as conn:
            conn.execute("UPDATE audit_chain_heads SET pruned_through_seq = 99 WHERE tenant_id = ?", (self.tenant,))
            conn.execute("UPDATE audit_events SET timestamp = '2000-01-01T00:00:00+00:00' WHERE tenant_id = ?",
                         (self.tenant,))
        store._prune_audit_chains("2001-01-01T00:00:00+00:00", [], apply=True)
        with store._connect() as conn:
            head = conn.execute("SELECT pruned_through_seq FROM audit_chain_heads WHERE tenant_id = ?",
                                (self.tenant,)).fetchone()
        self.assertEqual(int(head["pruned_through_seq"]), 99)


class _NoLock:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@unittest.skipUnless(db.is_postgres(), "concurrency between connections, on the authoritative database")
class OnPostgresTest(_DatabaseTest):

    def test_a_request_session_is_bounded_in_seconds(self) -> None:
        with db.workload("api"), store._connect() as conn:
            statement = str(conn.execute("SHOW statement_timeout").fetchone()[0])
            lock = str(conn.execute("SHOW lock_timeout").fetchone()[0])
        self.assertEqual((statement, lock), ("30s", "5s"))
        with db.workload("scan"), store._connect() as conn:
            self.assertEqual(str(conn.execute("SHOW statement_timeout").fetchone()[0]), "15min")
        self.assertIn("api", db.pools())

    def test_two_requests_presenting_one_refresh_token_get_one_session(self) -> None:
        store.issue_refresh_token("hash-pg", "family-pg", "user-pg", "jti-pg", int(time.time()), int(time.time()) + 600)
        barrier = threading.Barrier(2)
        results = []

        def present():
            barrier.wait(5)
            results.append(store.consume_refresh_token("hash-pg")["status"])

        threads = [threading.Thread(target=present) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        self.assertEqual(sorted(results), ["ok", "replayed"])

    def test_concurrent_status_records_lose_nothing(self) -> None:
        barrier = threading.Barrier(8)

        def record(index: int):
            barrier.wait(5)
            siem_settings.record(**{f"k{index}": index})

        threads = [threading.Thread(target=record, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        with store._connect() as conn:
            row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (siem_settings.STATUS_KEY,)).fetchone()
        self.assertEqual(set(json.loads(row["value"])), {f"k{index}" for index in range(8)})


if __name__ == "__main__":
    unittest.main()
