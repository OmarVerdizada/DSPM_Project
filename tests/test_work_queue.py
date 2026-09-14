"""B3 fundamentals: workers run partitions from a queue, and the ledger stays the truth.

Holds the work queue and the worker to plan §2 and §8 without a Redis server: a fake
implements the Redis Streams commands the queue uses, and the real ``redis`` package is
never imported. The gates in their fundamental form:

- **Worker kill:** a worker commits a partition and dies before ``XACK``; the entry is
  reclaimed once idle, the partition is not run again, and the finished scan's estate is
  exactly an uninterrupted scan's.
- **No sensitive value in Redis:** a scan of files holding a known card number and a
  known password leaves neither anywhere in the stream - only identifiers ever enter it.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import unittest
from unittest import mock

from backend import partition_worker, partitioned_scan, store
from backend.work_queue import (
    LedgerQueue,
    PayloadRefused,
    RedisStreamQueue,
    partition_payload,
    read_payload,
    work_queue_from_env,
)
from discovery.discovery_engine import ScanConfig
from tests.test_partitioned_local_scan import TENANT, _LocalTest

REQUEST = {"local_path": "estate", "max_depth": 4}


class FakeRedis:
    """The Redis Streams commands the queue uses, in memory, with a clock the test moves."""

    def __init__(self) -> None:
        self.now_ms = 1_000_000
        self.streams: dict[str, list[tuple[str, dict]]] = {}
        self.groups: dict[tuple[str, str], dict] = {}
        self._sequence = 0

    def xgroup_create(self, name, groupname, id="$", mkstream=False):
        if name not in self.streams:
            if not mkstream:
                raise Exception("ERR The XGROUP subcommand requires the key to exist")
            self.streams[name] = []
        if (name, groupname) in self.groups:
            raise Exception("BUSYGROUP Consumer Group name already exists")
        self.groups[(name, groupname)] = {"next": len(self.streams[name]) if id == "$" else 0, "pending": {}}
        return True

    def xadd(self, name, fields):
        self._sequence += 1
        entry_id = f"{self.now_ms}-{self._sequence}"
        self.streams.setdefault(name, []).append((entry_id, dict(fields)))
        return entry_id

    def xreadgroup(self, groupname, consumername, streams, count=None, block=None):
        out = []
        for name, cursor in streams.items():
            assert cursor == ">"
            group = self.groups[(name, groupname)]
            entries = self.streams[name][group["next"]:group["next"] + (count or len(self.streams[name]))]
            group["next"] += len(entries)
            for entry_id, _fields in entries:
                group["pending"][entry_id] = {"consumer": consumername, "delivered_ms": self.now_ms}
            if entries:
                out.append((name, [(entry_id, dict(fields)) for entry_id, fields in entries]))
        return out

    def xack(self, name, groupname, *ids):
        pending = self.groups[(name, groupname)]["pending"]
        return sum(1 for entry_id in ids if pending.pop(entry_id, None) is not None)

    def xautoclaim(self, name, groupname, consumername, min_idle_time, start_id="0-0", count=None):
        pending = self.groups[(name, groupname)]["pending"]
        fields = dict(self.streams[name])
        claimed = []
        for entry_id, state in pending.items():
            if self.now_ms - state["delivered_ms"] >= min_idle_time:
                state.update(consumer=consumername, delivered_ms=self.now_ms)
                claimed.append((entry_id, dict(fields[entry_id])))
                if count and len(claimed) >= count:
                    break
        return ["0-0", claimed, []]

    def pending(self, name="dspm:partitions", groupname="dspm-workers") -> dict:
        return self.groups[(name, groupname)]["pending"]

    def dump(self) -> str:
        return json.dumps(self.streams, sort_keys=True)


class ThePayloadIsOnlyIdentifiersTest(unittest.TestCase):

    def test_a_partition_message_is_exactly_three_identifiers(self) -> None:
        self.assertEqual(partition_payload("tenant-a", "20260914031500123456", "p00003"),
                         {"tenant_id": "tenant-a", "scan_id": "20260914031500123456", "partition_id": "p00003"})
        self.assertEqual(read_payload({b"tenant_id": b"t1", b"scan_id": b"s1", b"partition_id": b"p1"}),
                         {"tenant_id": "t1", "scan_id": "s1", "partition_id": "p1"})

    def test_anything_else_is_refused_without_repeating_it(self) -> None:
        card = "4111 1111 1111 1111"
        refused = [
            {"tenant_id": "t", "scan_id": "s", "partition_id": "p", "preview": card},
            {"tenant_id": "t", "scan_id": "s"},
            {"tenant_id": "t", "scan_id": "s", "partition_id": card},
            {"tenant_id": "t", "scan_id": "s", "partition_id": "C:/Finance/payroll.xlsx"},
            {"tenant_id": "t", "scan_id": "s", "partition_id": "p\npassword=Secret"},
            {"tenant_id": "t", "scan_id": "s", "partition_id": "p" * 201},
            {"tenant_id": "t", "scan_id": "s", "partition_id": 7},
            {"tenant_id": "t", "scan_id": "s", "partition_id": b"\xff\xfe"},
            ["tenant_id", "scan_id", "partition_id"],
        ]
        for fields in refused:
            with self.subTest(fields=str(fields)[:60]):
                with self.assertRaises(PayloadRefused) as caught:
                    read_payload(fields)
                self.assertNotIn(card, str(caught.exception))
                self.assertNotIn("Secret", str(caught.exception))


class TheRedisStreamQueueTest(unittest.TestCase):
    def setUp(self) -> None:
        self.redis = FakeRedis()
        self.queue = RedisStreamQueue(self.redis)

    def test_a_published_partition_is_delivered_once_and_acknowledged(self) -> None:
        self.assertEqual(self.queue.publish("t1", "s1", ["p00000", "p00001"]), 2)
        first = self.queue.take("worker-a")
        second = self.queue.take("worker-b")
        self.assertEqual((first.partition_id, second.partition_id), ("p00000", "p00001"))
        self.assertIsNone(self.queue.take("worker-c"))
        self.queue.ack(first)
        self.assertEqual(list(self.redis.pending()), [second.receipt])
        self.queue.publish("t1", "s2", ["p00000"])  # the group already exists

    def test_an_entry_never_acknowledged_is_reclaimed_only_once_idle(self) -> None:
        self.queue.publish("t1", "s1", ["p00000"])
        taken = self.queue.take("worker-a")
        self.redis.now_ms += 30_000
        self.assertEqual(self.queue.reclaim("worker-b", idle_seconds=60), [])
        self.redis.now_ms += 30_000
        (again,) = self.queue.reclaim("worker-b", idle_seconds=60)
        self.assertEqual((again.partition_id, again.receipt), (taken.partition_id, taken.receipt))
        self.assertEqual(self.redis.pending()[taken.receipt]["consumer"], "worker-b")

    def test_an_entry_that_is_not_a_partition_message_is_dropped_not_delivered(self) -> None:
        self.queue.publish("t1", "s1", [])
        self.redis.xadd("dspm:partitions", {"tenant_id": "t1", "scan_id": "s1", "partition_id": "p0", "content": "x"})
        self.assertIsNone(self.queue.take("worker-a"))
        self.assertEqual(self.redis.pending(), {}, "the refused entry was left to circulate")

    def test_publishing_refuses_a_value_that_is_not_an_identifier(self) -> None:
        with self.assertRaises(PayloadRefused):
            self.queue.publish("t1", "s1", ["../../etc/passwd"])
        self.assertEqual(self.redis.streams["dspm:partitions"], [])


class ChoosingTheQueueTest(unittest.TestCase):

    def test_the_ledger_is_the_default_and_redis_needs_a_url_and_its_package(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            for name in ("DSPM_WORK_QUEUE", "DSPM_REDIS_URL"):
                os.environ.pop(name, None)
            self.assertIsInstance(work_queue_from_env(), LedgerQueue)
            os.environ["DSPM_WORK_QUEUE"] = "redis"
            with self.assertRaisesRegex(RuntimeError, "DSPM_REDIS_URL"):
                work_queue_from_env()
            os.environ["DSPM_REDIS_URL"] = "redis://127.0.0.1:6379/0"
            with mock.patch.dict(sys.modules, {"redis": None}):
                with self.assertRaisesRegex(RuntimeError, "redis Python package"):
                    work_queue_from_env()
            os.environ["DSPM_WORK_QUEUE"] = "kafka"
            with self.assertRaisesRegex(RuntimeError, "ledger or redis"):
                work_queue_from_env()


class WorkersRunAScanTest(_LocalTest):

    def _settings(self, name: str) -> dict:
        return dict(
            tenant_id=TENANT, local_path=str(self.estate), max_depth=4, use_sample_when_empty=True,
            persistent_cache_enabled=False, incremental_enabled=False, max_workers=2,
            cache_dir=str(self.base / f"{name}-cache"),
        )

    def _start(self, name: str) -> dict:
        self._use_database(name)
        record = partitioned_scan.start_partitioned_scan(
            TENANT, ScanConfig(**self._settings(name)), request=REQUEST, scan_label="estate", max_files=3,
        )
        self.assertIsNotNone(record)
        return record

    def _rebuild(self, name: str):
        return lambda record: ScanConfig(**self._settings(name))

    def test_a_worker_killed_after_its_commit_and_before_xack_writes_nothing_twice(self) -> None:
        self._use_database("uninterrupted")
        whole = partitioned_scan.run_partitioned_scan(
            TENANT, ScanConfig(**self._settings("uninterrupted")), request=REQUEST, scan_label="estate", max_files=3,
        )
        whole_rows = self._rows()
        whole_paths = [f["path"] for f in store.read_scan_report(TENANT, whole["scan_id"])["files"]]

        record = self._start("redis")
        redis = FakeRedis()
        queue = RedisStreamQueue(redis)
        units = store.list_scan_partitions(TENANT, record["scan_id"])
        queue.publish(TENANT, record["scan_id"], [unit["partition_id"] for unit in units])

        first = queue.take("worker-a")
        self.assertEqual(partitioned_scan.run_queued_partition(
            record, ScanConfig(**self._settings("redis")), first.partition_id, worker_id="worker-a"), "written")
        # worker-a dies here: committed to the ledger, never acknowledged.
        self.assertIn(first.receipt, redis.pending())
        redis.now_ms += 400_000
        (again,) = [d for d in queue.reclaim("worker-b", idle_seconds=300) if d.receipt == first.receipt]
        self.assertEqual(partition_worker.handle_delivery(queue, again, self._rebuild("redis"), worker_id="worker-b"),
                         "finished")
        self.assertNotIn(first.receipt, redis.pending())

        handled = partition_worker.run_worker(queue, self._rebuild("redis"), worker_id="worker-b", stop_when_idle=True)
        self.assertEqual(handled, len(units) - 1)
        self.assertEqual(redis.pending(), {})
        self.assertEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "done")
        self.assertEqual({unit["attempt"] for unit in store.list_scan_partitions(TENANT, record["scan_id"])}, {1},
                         "a partition ran twice")
        self.assertEqual([f["path"] for f in store.read_scan_report(TENANT, record["scan_id"])["files"]], whole_paths)
        self.assertEqual(self._rows(), whole_rows, "the estate differs from an uninterrupted scan")

        stream = redis.dump()
        self.assertNotIn("4111", stream, "a card number reached the queue")
        self.assertNotIn("Secret", stream, "a password reached the queue")
        for _entry_id, fields in redis.streams["dspm:partitions"]:
            self.assertEqual(set(fields), {"tenant_id", "scan_id", "partition_id"})

    def test_two_ledger_workers_share_a_scan_and_run_each_partition_once(self) -> None:
        record = self._start("ledger")
        results: list[int] = []

        def work(worker_id: str) -> None:
            results.append(partition_worker.run_worker(
                LedgerQueue(), self._rebuild("ledger"), worker_id=worker_id, stop_when_idle=True))

        threads = [threading.Thread(target=work, args=(f"worker-{n}",)) for n in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=300)
        # A worker that found nothing queued while the other held the last partition
        # stops; whatever is left is finished by one more pass.
        partition_worker.run_worker(LedgerQueue(), self._rebuild("ledger"), worker_id="worker-late", stop_when_idle=True)
        units = store.list_scan_partitions(TENANT, record["scan_id"])
        self.assertEqual({unit["status"] for unit in units}, {"done"})
        self.assertEqual({unit["attempt"] for unit in units}, {1}, "a partition ran twice")
        self.assertEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "done")
        walked, _ = self._single_walk(ScanConfig(**self._settings("ledger")))
        self.assertEqual([f["path"] for f in store.read_scan_report(TENANT, record["scan_id"])["files"]], walked)

    def test_a_message_for_a_finished_or_unrebuildable_scan_is_dropped(self) -> None:
        record = self._start("dropped")
        redis = FakeRedis()
        queue = RedisStreamQueue(redis)
        unit = store.list_scan_partitions(TENANT, record["scan_id"])[0]
        queue.publish(TENANT, record["scan_id"], [unit["partition_id"]])
        delivery = queue.take("worker-a")

        def cannot_rebuild(_record):
            raise ValueError("the credential is gone from the vault")

        self.assertEqual(partition_worker.handle_delivery(queue, delivery, cannot_rebuild, worker_id="worker-a"), "dropped")
        self.assertEqual(redis.pending(), {})
        stored = store.read_partitioned_scan(TENANT, record["scan_id"])
        self.assertEqual(stored["status"], "failed")
        self.assertIn("ValueError", stored["error"])
        queue.publish(TENANT, record["scan_id"], [unit["partition_id"]])
        late = queue.take("worker-b")
        self.assertEqual(partition_worker.handle_delivery(queue, late, self._rebuild("dropped"), worker_id="worker-b"),
                         "dropped")

    def test_a_failed_partition_is_queued_again_until_its_attempts_run_out(self) -> None:
        record = self._start("retry")
        redis = FakeRedis()
        queue = RedisStreamQueue(redis)
        unit = store.list_scan_partitions(TENANT, record["scan_id"])[0]
        queue.publish(TENANT, record["scan_id"], [unit["partition_id"]])
        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_ATTEMPTS": "2"}), \
                mock.patch.object(partitioned_scan.DSPMDiscoveryEngine, "run", side_effect=OSError("locked")):
            first = queue.take("worker-a")
            self.assertEqual(partition_worker.handle_delivery(queue, first, self._rebuild("retry"), worker_id="worker-a"),
                             "retry")
            again = queue.take("worker-a")
            self.assertEqual(again.partition_id, unit["partition_id"])
            self.assertEqual(partition_worker.handle_delivery(queue, again, self._rebuild("retry"), worker_id="worker-a"),
                             "stopped")
        self.assertEqual(redis.pending(), {})
        stored = store.read_partitioned_scan(TENANT, record["scan_id"])
        self.assertEqual(stored["status"], "failed")
        self.assertIn("failed 2 times", stored["error"])


class TheWorkerCommandTest(unittest.TestCase):

    def test_python_main_worker_runs_the_queue_from_the_environment(self) -> None:
        import main

        args = main.build_parser().parse_args(["worker", "--worker-id", "node-1"])
        self.assertIs(args.func, main.work)
        with mock.patch("backend.partition_worker.run_worker", return_value=0) as run_worker, \
                mock.patch.dict(os.environ, {"DSPM_WORK_QUEUE": "ledger"}):
            args.func(args)
        queue, rebuild = run_worker.call_args[0]
        self.assertIsInstance(queue, LedgerQueue)
        from backend.app import rebuild_scan_config

        self.assertIs(rebuild, rebuild_scan_config)
        self.assertEqual(run_worker.call_args[1]["worker_id"], "node-1")


if __name__ == "__main__":
    unittest.main()
