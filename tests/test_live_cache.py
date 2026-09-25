"""B3.1: the dashboard's aggregates are shared between backends, through the database.

The case for sharing them was measured, not assumed: the estate aggregates the console
asks for on every refresh were paid for by each backend and each worker separately,
because the only cache was per-process. On this host's PostgreSQL: 7.31 ms at 1,369
assets, 5.34 s extrapolated to a million, and a 3.9-hour scan spending about 6.95 hours
of database time answering the console.

Memurai held that cache until the product owner removed it on 2026-09-18. It now lives
in ``derived_cache`` (revision 0017), and these pin what the move must not have lost:

- a second process answers **without running the aggregates** - one row, not the estate;
- every authoritative write makes the cached answer unservable at once, so the console
  never shows the estate as it was before a scan - including a write that lands while
  an answer is being computed;
- the cache holds the answer and nothing else, and every answer expires;
- turned off, or broken, every call is exactly the database read it always was;
- and a scan's progress reaches the job record, where a console on any backend reads it,
  without ever putting a finished job back to "running".
"""

from __future__ import annotations

import inspect
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from backend import db, jobs, live_cache, partitioned_scan, store
from tests.test_estate_write_is_batched import _report
from tests.test_partitioned_local_scan import TENANT, _LocalTest


class _DatabaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self._previous_path = store.DB_PATH
        store.DB_PATH = Path(self._dir.name) / "live-cache.sqlite"
        self._env = mock.patch.dict(os.environ, {
            "DSPM_ARTIFACT_DIR": str(Path(self._dir.name) / "artifacts"),
            "DSPM_LIVE_CACHE": "1",
        })
        self._env.start()
        store.init_db()
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "live cache")
        live_cache.reset_for_tests()

    def tearDown(self) -> None:
        self._env.stop()
        store.DB_PATH = self._previous_path
        live_cache.reset_for_tests()
        self._dir.cleanup()

    def _forget_this_process(self) -> None:
        """What a second backend has: the database, and none of this process's memory."""
        with store._inventory_query_cache_lock:
            store._inventory_count_cache.clear()
            store._inventory_facets_cache.clear()

    def _statements(self):
        """Every SQL statement the store issues while the context is open."""
        seen: list[str] = []
        original = db._apply_sqlite_pragmas

        def traced(conn) -> None:
            original(conn)
            conn.set_trace_callback(seen.append)

        return seen, mock.patch.object(db, "_apply_sqlite_pragmas", traced)


class WhatTheCacheSavesTest(_DatabaseTest):

    def test_a_second_reader_does_not_pay_for_the_aggregate(self) -> None:
        built = []

        def builder() -> dict:
            built.append(1)
            return {"assets": 1_000_000}

        first = live_cache.cached_json(self.tenant, "posture_inputs", None, builder)
        second = live_cache.cached_json(self.tenant, "posture_inputs", None, builder)

        self.assertEqual(first, second)
        self.assertEqual(len(built), 1, "the second reader went back to the database")

    def test_a_second_backend_reads_one_row_and_never_the_estate(self) -> None:
        store.save_scan_history(self.tenant, _report("s1", 40))
        expected = store.posture_inputs(self.tenant)
        store.inventory_facets(self.tenant)

        self._forget_this_process()
        seen, tracing = self._statements()
        with tracing:
            posture = store.posture_inputs(self.tenant)
            store.inventory_facets(self.tenant)

        self.assertEqual(posture, expected)
        estate = [sql for sql in seen if any(table in sql for table in (" assets", " findings", "finding_index"))]
        self.assertEqual(estate, [], "a second backend ran the aggregates again")
        lookups = [sql for sql in seen if "derived_cache" in sql]
        self.assertEqual(len(lookups), 2, f"expected one lookup per answer, saw: {seen}")

    def test_one_tenants_answer_is_never_another_tenants(self) -> None:
        other = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(other, "other")
        live_cache.cached_json(self.tenant, "posture_inputs", None, lambda: {"assets": 1})
        answer = live_cache.cached_json(other, "posture_inputs", None, lambda: {"assets": 2})
        self.assertEqual(answer, {"assets": 2})

    def test_different_parameters_are_different_answers(self) -> None:
        live_cache.cached_json(self.tenant, "inventory_facets", {"source": "smb"}, lambda: {"n": 1})
        answer = live_cache.cached_json(self.tenant, "inventory_facets", {"source": "local"}, lambda: {"n": 2})
        self.assertEqual(answer, {"n": 2})


class InvalidationTest(_DatabaseTest):

    def test_a_saved_scan_makes_the_cached_answer_unservable_at_once(self) -> None:
        store.save_scan_history(self.tenant, _report("s1", 10, prefix="a"))
        before = store.posture_inputs(self.tenant)
        store.save_scan_history(self.tenant, _report("s2", 30, prefix="b", scan_label="other"))
        after = store.posture_inputs(self.tenant)
        self.assertNotEqual(after, before, "the console would have shown the estate as it was before the scan")
        self.assertEqual(after, store._posture_inputs(self.tenant))

    def test_a_write_that_lands_while_an_answer_is_computed_is_not_hidden_by_it(self) -> None:
        def builder_overtaken_by_a_write() -> dict:
            # The read happened; a scan commits before the answer is stored.
            store.bump_estate_generation(self.tenant)
            return {"assets": "as it was"}

        live_cache.cached_json(self.tenant, "posture_inputs", None, builder_overtaken_by_a_write)
        answer = live_cache.cached_json(self.tenant, "posture_inputs", None, lambda: {"assets": "as it is"})
        self.assertEqual(answer, {"assets": "as it is"}, "an answer older than the last write was served")

    def test_an_older_answer_never_replaces_a_newer_one(self) -> None:
        _, generation = store.derived_lookup(self.tenant, "k")
        store.bump_estate_generation(self.tenant)
        store.derived_store(self.tenant, "k", generation + 1, json.dumps({"v": "new"}), 30)
        store.derived_store(self.tenant, "k", generation, json.dumps({"v": "old"}), 30)
        stored, _ = store.derived_lookup(self.tenant, "k")
        self.assertEqual(json.loads(stored), {"v": "new"}, "a slow backend overwrote a newer answer")

    def test_every_estate_writer_moves_the_generation(self) -> None:
        # One hook, called by every authoritative estate write; the generation moves there.
        _, before = store.derived_lookup(self.tenant, "k")
        store._invalidate_inventory_query_cache(self.tenant)
        _, after = store.derived_lookup(self.tenant, "k")
        self.assertEqual(after, before + 1)
        for writer in (store.save_scan_history, store.persist_partition, store.finalize_partitioned_scan,
                       store.backfill_normalized_scans, store.purge_demo_sample_assets,
                       store.delete_tenant_with_data, store.reset_default_tenant_data):
            with self.subTest(writer=writer.__name__):
                self.assertIn("invalidate", inspect.getsource(writer),
                              "an estate write that leaves cached answers standing")

    def test_a_partitioned_scan_is_visible_once_it_is_finalized(self) -> None:
        # The Memuraant, "posture_inputs", None, lambda: {"assets": 1})
        with store._connect() as conn:
            conn.execute("UPDATE derived_cache SET expires_at = ? WHERE tenant_id = ?",
                         ("2000-01-01T00:00:00.000000+00:00", self.tenant))
        answer = live_cache.cached_json(self.tenant, "posture_inputs", None, lambda: {"assets": 2})
        self.assertEqual(answer, {"assets": 2})

    def test_erasing_a_tenant_erases_its_answers(self) -> None:
        self.assertIn("derived_cache", store._TENANT_ERASURE_TABLES)
        live_cache.cached_json(self.tenant, "posture_inputs", None, lambda: {"assets": 1})
        store.delete_tenant_with_data(self.tenant)
        with store._connect() as conn:
            left = conn.execute("SELECT COUNT(*) AS n FROM derived_cache WHERE tenant_id = ?",
                                (self.tenant,)).fetchone()["n"]
        self.assertEqual(left, 0)


class APartitionedScanTest(_LocalTest):

    def test_its_result_is_on_the_console_once_it_finishes(self) -> None:
        # The Memurai version moved its generation only in save_scan_history, so a
        # partitioned scan's result waited out the TTL. Every writer calls the hook now.
        os.environ["DSPM_LIVE_CACHE"] = "1"
        self._use_database("live")
        before = store.posture_inputs(TENANT)
        partitioned_scan.run_partitioned_scan(TENANT, self._config("live"), request={"local_path": "estate"},
                                              scan_label="estate", max_files=3)
        after = store.posture_inputs(TENANT)
        self.assertNotEqual(after, before, "the console kept showing the estate from before the scan")
        self.assertEqual(after, store._posture_inputs(TENANT))


class WhatTheCacheMayNeverDoTest(_DatabaseTest):

    def test_it_never_changes_the_answer(self) -> None:
        answer = {"assets": 3, "sensitive": 1, "levels": {"HIGH": 2}}
        first = live_cache.cached_json(self.tenant, "x", None, lambda: answer)
        second = live_cache.cached_json(self.tenant, "x", None, lambda: {"assets": 99})
        self.assertEqual(first, answer)
        self.assertEqual(second, answer, "a cached answer is the one that was built, not a new one")

    def test_what_it_stores_is_the_answer_and_nothing_else(self) -> None:
        live_cache.cached_json(self.tenant, "posture_inputs", None, lambda: {"assets": 5, "sensitive_assets": 2})
        with store._connect() as conn:
            rows = conn.execute("SELECT value_json FROM derived_cache WHERE tenant_id = ?", (self.tenant,)).fetchall()
        self.assertEqual([json.loads(row["value_json"]) for row in rows], [{"assets": 5, "sensitive_assets": 2}],
                         "only counts belong here - never content, previews or samples")

    def test_names_nobody_asks_for_again_do_not_pile_up(self) -> None:
        # A viewer can ask for the facets of any scan name; each one is a key.
        for index in range(40):
            store.inventory_facets(self.tenant, source=f"no-such-scan-{index}")
        with store._connect() as conn:
            conn.execute("UPDATE derived_cache SET expires_at = ? WHERE tenant_id = ?",
                         ("2000-01-01T00:00:00.000000+00:00", self.tenant))
        store.posture_inputs(self.tenant)
        with store._connect() as conn:
            left = conn.execute("SELECT cache_key FROM derived_cache WHERE tenant_id = ?", (self.tenant,)).fetchall()
        self.assertEqual([row["cache_key"].split(":")[0] for row in left], ["posture_inputs"],
                         "every name ever asked for kept its row")

    def test_turned_off_it_is_exactly_the_database_read(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_LIVE_CACHE": "0"}):
            calls = []
            for _ in range(2):
                live_cache.cached_json(self.tenant, "x", None, lambda: calls.append(1) or {"assets": 2})
            self.assertEqual(len(calls), 2)
            self.assertFalse(live_cache.enabled())
        with store._connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) AS n FROM derived_cache").fetchone()["n"], 0)

    @unittest.skipIf(db.is_postgres(), "drops the table; on PostgreSQL that is the shared test database")
    def test_a_database_without_the_table_is_not_an_outage(self) -> None:
        with store._connect() as conn:
            conn.execute("DROP TABLE derived_cache")
        self.assertEqual(live_cache.cached_json(self.tenant, "x", None, lambda: {"assets": 7}), {"assets": 7})
        self.assertGreaterEqual(live_cache.diagnostics()["errors"], 1)

    def test_it_reports_what_it_did(self) -> None:
        live_cache.cached_json(self.tenant, "x", None, lambda: {"a": 1})
        live_cache.cached_json(self.tenant, "x", None, lambda: {"a": 1})
        diagnostics = live_cache.diagnostics()
        self.assertEqual((diagnostics["enabled"], diagnostics["backend"]), (True, "database"))
        self.assertEqual((diagnostics["misses"], diagnostics["hits"]), (1, 1))


class LiveProgressTest(_DatabaseTest):

    def _job(self, **overrides) -> jobs.ScanJob:
        job = jobs.ScanJob(id=f"job-{uuid.uuid4().hex[:8]}", tenant_id=self.tenant, **overrides)
        store.record_job(job.to_dict())
        jobs._published_at.pop(job.id, None)
        return job

    def test_a_scan_running_elsewhere_can_still_be_watched(self) -> None:
        job = self._job(status="running")
        job.progress, job.message = 42, "Scanning partition 3 of 7"
        jobs.publish_progress(job)
        record = store.read_job(self.tenant, job.id)
        self.assertEqual((record["progress"], record["message"]), (42, "Scanning partition 3 of 7"))

    def test_progress_is_written_at_most_once_a_second(self) -> None:
        job = self._job(status="running")
        with mock.patch.object(store, "record_job_progress") as write:
            for step in range(50):
                job.progress = step
                jobs.publish_progress(job)
        self.assertEqual(write.call_count, 1, "a scan reporting every record wrote the database every record")

    def test_a_late_progress_write_never_reopens_a_finished_job(self) -> None:
        job = self._job(status="running")
        store.record_job({**job.to_dict(), "status": "completed", "progress": 100, "message": "Completed"})
        store.record_job_progress(self.tenant, job.id, 60, "Analyzing files 10/20")
        record = store.read_job(self.tenant, job.id)
        self.assertEqual((record["status"], record["progress"], record["message"]), ("completed", 100, "Completed"))

    def test_progress_only_touches_its_own_tenants_job(self) -> None:
        job = self._job(status="running")
        store.record_job_progress("someone-else", job.id, 99, "not yours")
        self.assertEqual(store.read_job(self.tenant, job.id)["progress"], 0)


if __name__ == "__main__":
    unittest.main()
