"""B3/B9: the queue gates, against a real Memurai rather than a fake.

`tests/test_work_queue.py` proves the Redis Streams adapter against a fake that implements
the commands it uses. That is the right test for CI, and it cannot answer the questions
the plan's acceptance gates actually ask - whether Memurai on Windows behaves the way the
adapter assumes, and whether anything sensitive ends up in it.

These run only when `DSPM_MEMURAI_LIVE=1` and a reachable server is configured
(`scripts/memurai_setup.py health` proves both), so CI and a developer without Memurai
skip them:

- a scan's partitions are delivered through a real consumer group and run by a real
  worker, and the scan finishes with the findings an inline scan produces;
- **worker kill**: an entry read but never acknowledged - the crash the contract is built
  around - is reclaimed by another worker, which finds the partition already done and
  writes nothing twice;
- **no sensitive value in Redis**: after scanning a fixture holding a known card number
  and a known secret, every key and every stream entry in the server is dumped, and
  neither value appears anywhere in it;
- the stream carries **partition-scale** work: one entry per partition, three identifier
  fields, and nothing else.
"""

from __future__ import annotations

import os
import shutil
import unittest
import uuid
from pathlib import Path
from unittest import mock

from backend import partitioned_scan, store, work_queue
from backend.work_queue import RedisStreamQueue
from discovery.discovery_engine import ScanConfig

ROOT = Path(__file__).resolve().parent.parent
LIVE = os.getenv("DSPM_MEMURAI_LIVE") == "1"
CARD = "4111 1111 1111 1111"
SECRET_VALUE = "AKIAIOSFODNN7EXAMPLE"
TENANT = "memurai-live"


def _redis_url() -> str:
    """The product's own connection string, built the way an install builds it."""
    configured = os.getenv("DSPM_REDIS_URL", "").strip()
    if configured:
        return configured
    from scripts.memurai_setup import ACL_USER, DEFAULT_PORT, read_secret

    secret = read_secret()
    return f"redis://{ACL_USER}:{secret}@127.0.0.1:{DEFAULT_PORT}/0" if secret else ""


@unittest.skipUnless(LIVE, "set DSPM_MEMURAI_LIVE=1 with Memurai running to exercise these")
class TheQueueAgainstARealMemuraiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.url = _redis_url()
        if not cls.url:
            raise unittest.SkipTest("no DSPM_REDIS_URL and no password file")
        cls.stream = f"dspm:test:{uuid.uuid4().hex[:8]}"
        cls.group = "dspm-test-workers"

    def setUp(self) -> None:
        self.base = ROOT / "tmp" / f"memurai-live-{uuid.uuid4().hex[:8]}"
        self.estate = self.base / "estate"
        for index in range(12):
            folder = self.estate / f"dept{index % 3}"
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f"file{index}.txt").write_text(
                f"customer {index}\ncard number: {CARD}\naws_secret_access_key = {SECRET_VALUE}\n",
                encoding="utf-8",
            )
        self._previous_db = store.DB_PATH
        self._env = mock.patch.dict(os.environ, {
            "DSPM_ARTIFACT_DIR": str(self.base / "artifacts"),
            "DSPM_SCAN_CACHE_DIR": str(self.base / "cache"),
            "DSPM_WORK_QUEUE": "redis",
            "DSPM_REDIS_URL": self.url,
            "DSPM_REDIS_STREAM": self.stream,
            "DSPM_REDIS_GROUP": self.group,
        })
        self._env.start()
        store.DB_PATH = self.base / "live.sqlite"
        store.init_db()
        try:
            store.create_tenant(TENANT, "memurai live")
        except Exception:
            pass
        self.queue = work_queue.work_queue_from_env()

    def tearDown(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            try:
                self.queue.client.delete(self.stream)
            except Exception:
                pass
        self._env.stop()
        store.DB_PATH = self._previous_db
        shutil.rmtree(self.base, ignore_errors=True)

    def _config(self) -> ScanConfig:
        return ScanConfig(
            tenant_id=TENANT,
            local_path=str(self.estate),
            use_sample_when_empty=True,
            persistent_cache_enabled=False,
            cache_dir=str(self.base / "cache"),
            incremental_enabled=False,
            max_workers=1,
        )

    def _rebuild(self, _record: dict) -> ScanConfig:
        return self._config()

    def _written(self, scan_id: str) -> tuple:
        """What this scan has written: the estate rows, and the partition's own records.

        A partition's records live on its ledger row (`records_json`/`records_bytes`),
        not in a table of their own, so "wrote nothing twice" is this pair being equal
        before and after the redelivery.
        """
        import hashlib

        digest = hashlib.sha256()
        with store._connect() as conn:
            for table in ("assets", "findings", "finding_occurrences", "finding_index"):
                rows = conn.execute(f"SELECT * FROM {table} WHERE tenant_id = ?", (TENANT,)).fetchall()
                for row in sorted(str(tuple(item)) for item in rows):
                    digest.update(row.encode("utf-8"))
            sizes = conn.execute(
                "SELECT partition_id, records_bytes, length(COALESCE(records_json, '')) AS inline "
                "FROM scan_partitions WHERE tenant_id = ? AND scan_id = ? ORDER BY partition_id",
                (TENANT, scan_id),
            ).fetchall()
        return digest.hexdigest(), [tuple(row) for row in sizes]

    def _planned(self):
        record = partitioned_scan.start_partitioned_scan(
            TENANT, self._config(), request={"local_path": str(self.estate)},
            scan_label="memurai-live", max_files=4,
        )
        self.assertIsNotNone(record, "the estate did not split into partitions")
        return record

    def test_it_is_a_real_redis_stream_queue(self) -> None:
        self.assertIsInstance(self.queue, RedisStreamQueue)
        self.assertTrue(self.queue.client.ping())

    def test_a_scan_is_delivered_through_memurai_and_run_by_a_worker(self) -> None:
        from backend import partition_worker

        record = self._planned()
        units = store.list_scan_partitions(TENANT, record["scan_id"])
        self.assertEqual(self.queue.publish(TENANT, record["scan_id"], [u["partition_id"] for u in units]), len(units))

        partition_worker.run_worker(self.queue, self._rebuild, worker_id="worker-live", stop_when_idle=True)

        statuses = {unit["status"] for unit in store.list_scan_partitions(TENANT, record["scan_id"])}
        self.assertEqual(statuses, {"done"}, "a partition came back from Memurai unfinished")
        # The worker settles the scan itself once its last partition is written, so by
        # here it is already finalized - which is the behaviour B3 review asked for.
        self.assertEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "done")
        report = store.read_scan_report(TENANT, record["scan_id"])
        self.assertEqual(len(report["files"]), 12, "a file was lost between Memurai and the report")
        self.assertEqual(report["scan_diagnostics"]["partitioned"]["partitions"], len(units))

    def test_an_entry_never_acknowledged_is_reclaimed_and_runs_nothing_twice(self) -> None:
        record = self._planned()
        units = store.list_scan_partitions(TENANT, record["scan_id"])
        self.queue.publish(TENANT, record["scan_id"], [units[0]["partition_id"]])

        # A worker takes the entry, commits the partition, and dies before acknowledging.
        delivery = self.queue.take("worker-dies")
        self.assertIsNotNone(delivery)
        self.assertEqual(
            partitioned_scan.run_queued_partition(record, self._config(), delivery.partition_id,
                                                  worker_id="worker-dies"),
            "written",
        )
        written_after_commit = self._written(record["scan_id"])

        # Another worker reclaims it once it has been idle, and finds it done.
        reclaimed = self.queue.reclaim("worker-b", idle_seconds=0)
        self.assertTrue(reclaimed, "an unacknowledged entry was never handed to anybody else")
        self.assertEqual(
            partitioned_scan.run_queued_partition(record, self._config(), reclaimed[0].partition_id,
                                                  worker_id="worker-b"),
            "finished",
        )
        self.assertEqual(self._written(record["scan_id"]), written_after_commit,
                         "the redelivery wrote the partition a second time")

    def test_the_stream_carries_identifiers_and_nothing_else(self) -> None:
        record = self._planned()
        units = store.list_scan_partitions(TENANT, record["scan_id"])
        self.queue.publish(TENANT, record["scan_id"], [u["partition_id"] for u in units])

        entries = self.queue.client.xrange(self.stream)
        self.assertEqual(len(entries), len(units), "one entry per partition, not one per file")
        for _entry_id, fields in entries:
            self.assertEqual(set(fields), {"tenant_id", "scan_id", "partition_id"})

    def test_no_scanned_value_ever_reaches_memurai(self) -> None:
        from backend import partition_worker
        from scripts.memurai_setup import connect, read_secret

        record = self._planned()
        units = store.list_scan_partitions(TENANT, record["scan_id"])
        self.queue.publish(TENANT, record["scan_id"], [u["partition_id"] for u in units])
        partition_worker.run_worker(self.queue, self._rebuild, worker_id="worker-live", stop_when_idle=True)
        partitioned_scan.settle_if_finished(record, self._config())

        # Dumped as the operator, because the product's own user may not run KEYS - which
        # is the point of the ACL, and why this check has to ask with the other account.
        operator = connect(read_secret())
        blob: list[str] = []
        for key in operator.scan_iter("*", count=500):
            blob.append(str(key))
            kind = operator.type(key)
            if kind == "stream":
                for _entry_id, fields in operator.xrange(key):
                    blob.extend(f"{name}={value}" for name, value in fields.items())
            elif kind == "string":
                blob.append(str(operator.get(key)))
            elif kind == "hash":
                blob.extend(f"{name}={value}" for name, value in (operator.hgetall(key) or {}).items())
            elif kind in {"list", "set", "zset"}:
                blob.extend(str(item) for item in (operator.lrange(key, 0, -1) if kind == "list"
                                                   else operator.smembers(key) if kind == "set"
                                                   else operator.zrange(key, 0, -1)))
        dumped = "\n".join(blob)
        for value in (CARD, CARD.replace(" ", ""), SECRET_VALUE):
            with self.subTest(value=value[:6]):
                self.assertNotIn(value, dumped, "a scanned value reached the operational plane")

    def test_a_second_backend_answers_the_dashboard_without_touching_the_database(self) -> None:
        """B3.1's gate: zero repeated O(estate) aggregation.

        The first backend pays for the aggregates and shares the answer. The second one -
        here, this process with every in-process cache cleared, which is what a second
        backend is from the database's point of view - answers from Memurai and issues no
        statement at all.
        """
        from backend import live_cache
        from scripts.scale_gate import _counting_statements, _synthetic_report

        store.save_scan_history(TENANT, _synthetic_report("dash-1", 200))
        live_cache.reset_for_tests()

        def dashboard_reads() -> tuple:
            return store.posture_inputs(TENANT), store.inventory_facets(TENANT)

        def forget_in_process_caches() -> None:
            store._inventory_facets_cache.clear()
            live_cache.reset_for_tests()

        forget_in_process_caches()
        with _counting_statements(store) as first:
            warm = dashboard_reads()
        self.assertGreater(first["execute"], 0, "the first backend did not read the estate at all")

        forget_in_process_caches()
        with _counting_statements(store) as second:
            again = dashboard_reads()

        self.assertEqual(again, warm, "the shared answer is not the one the database gave")
        self.assertEqual(second["execute"], 0,
                         f"a second backend re-ran the aggregates: {second['execute']} statements")

    def test_a_saved_scan_is_visible_at_once_rather_than_at_the_end_of_a_ttl(self) -> None:
        from backend import live_cache
        from scripts.scale_gate import _synthetic_report

        store.save_scan_history(TENANT, _synthetic_report("dash-2", 50))
        before = store.posture_inputs(TENANT)
        store._inventory_facets_cache.clear()
        store.save_scan_history(TENANT, _synthetic_report("dash-3", 150))
        store._inventory_facets_cache.clear()
        after = store.posture_inputs(TENANT)
        self.assertNotEqual(before, after, "the console would have shown the estate as it was before the scan")
        self.assertTrue(live_cache.configured())

    def test_memurai_stays_under_its_cap(self) -> None:
        from scripts.memurai_setup import connect, read_secret

        info = connect(read_secret()).info("memory")
        used, limit = int(info.get("used_memory", 0)), int(info.get("maxmemory", 0))
        self.assertGreater(limit, 0, "maxmemory is unlimited")
        self.assertLess(used, limit, f"{used // 1024} KB used of {limit // 1024} KB")


if __name__ == "__main__":
    unittest.main()
