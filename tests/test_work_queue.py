"""B3 fundamentals: workers run partitions from a queue, and the ledger stays the truth.

Holds the work queue and the worker to plan §2 and §8. The queue is the ledger itself
(Memurai, and the Redis Streams queue beside it, were removed on 2026-09-18), so these
run against the database and nothing else. The gates in their fundamental form:

- **Worker kill:** a worker commits a partition and dies; the same partition handed out
  again is not run again, and the finished scan's estate is exactly an uninterrupted
  scan's.
- **Only identifiers travel:** what a queue hands a worker is a partition's three
  identifiers, and anything else is refused before it is sent.

And what a review of the first version found: a worker that could not see a local scan's
folders would have written them as empty and let finalize prune the estate; a dead
worker's partition was never taken back; one misconfigured worker failed scans for
everyone; a busy database ended the worker; a scan whose last worker died before
finalizing stayed unfinished.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
import unittest
from unittest import mock

from backend import db, partition_worker, partitioned_scan, store
from backend.work_queue import (
    Delivery,
    LedgerQueue,
    PayloadRefused,
    partition_payload,
    read_payload,
    work_queue_from_env,
)
from discovery.discovery_engine import ScanConfig
from tests.test_partitioned_local_scan import TENANT, _LocalTest

REQUEST = {"local_path": "estate", "max_depth": 4}


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


class ChoosingTheQueueTest(unittest.TestCase):

    def test_the_ledger_is_the_queue_and_a_stale_redis_setting_still_gets_it(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_WORK_QUEUE", None)
            self.assertIsInstance(work_queue_from_env(), LedgerQueue)
            os.environ["DSPM_WORK_QUEUE"] = "redis"
            with self.assertLogs("backend.work_queue", level=logging.WARNING) as logged:
                self.assertIsInstance(work_queue_from_env(), LedgerQueue,
                                      "an install upgraded with its old environment would have no workers")
            self.assertIn("Memurai was removed", "\n".join(logged.output))
            os.environ["DSPM_WORK_QUEUE"] = "kafka"
            with self.assertRaisesRegex(RuntimeError, "must be ledger"):
                work_queue_from_env()


class WorkersRunAScanTest(_LocalTest):

    def _settings(self, name: str) -> dict:
        return dict(
            tenant_id=TENANT, local_path=str(self.estate), max_depth=4, walk_local_path=True,
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

    @unittest.skipIf(db.is_postgres(), "compares two databases; on PostgreSQL the suite has one")
    def test_a_partition_handed_out_again_after_its_commit_writes_nothing_twice(self) -> None:
        self._use_database("uninterrupted")
        whole = partitioned_scan.run_partitioned_scan(
            TENANT, ScanConfig(**self._settings("uninterrupted")), request=REQUEST, scan_label="estate", max_files=3,
        )
        whole_rows = self._rows()
        whole_paths = [f["path"] for f in store.read_scan_report(TENANT, whole["scan_id"])["files"]]

        record = self._start("killed")
        queue = LedgerQueue()
        units = store.list_scan_partitions(TENANT, record["scan_id"])
        self.assertEqual(partitioned_scan.enqueue_partitioned_scan(record, queue), len(units),
                         "the console would report and audit a scan as queued with no partitions")

        first = queue.take("worker-a")
        self.assertEqual(partition_payload(first.tenant_id, first.scan_id, first.partition_id),
                         {"tenant_id": TENANT, "scan_id": record["scan_id"], "partition_id": first.partition_id},
                         "the ledger handed out something other than a partition's identifiers")
        self.assertEqual(partitioned_scan.run_queued_partition(
            record, ScanConfig(**self._settings("killed")), first.partition_id, worker_id="worker-a"), "written")
        # worker-a dies here, its partition committed. Two workers can be handed the same
        # partition by the ledger queue; the second must find it done and do nothing.
        again = Delivery(tenant_id=first.tenant_id, scan_id=first.scan_id, partition_id=first.partition_id)
        self.assertEqual(partition_worker.handle_delivery(queue, again, self._rebuild("killed"), worker_id="worker-b"),
                         "finished")

        handled = partition_worker.run_worker(queue, self._rebuild("killed"), worker_id="worker-b", stop_when_idle=True)
        self.assertEqual(handled, len(units) - 1)
        self.assertEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "done")
        self.assertEqual({unit["attempt"] for unit in store.list_scan_partitions(TENANT, record["scan_id"])}, {1},
                         "a partition ran twice")
        self.assertEqual([f["path"] for f in store.read_scan_report(TENANT, record["scan_id"])["files"]], whole_paths)
        self.assertEqual(self._rows(), whole_rows, "the estate differs from an uninterrupted scan")

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

    def test_a_scan_this_worker_cannot_rebuild_is_left_alone_and_a_finished_one_is_dropped(self) -> None:
        record = self._start("unbuildable")
        queue = LedgerQueue()

        def cannot_rebuild(_record):
            raise ValueError("the credential is not in this worker's vault")

        handled = partition_worker.run_worker(queue, cannot_rebuild, worker_id="worker-a", stop_when_idle=True)
        self.assertEqual(handled, 1, "the worker kept asking for a scan it had just found it cannot run")
        self.assertEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "running",
                         "one worker's configuration failed a scan other workers could run")
        self.assertEqual({unit["status"] for unit in store.list_scan_partitions(TENANT, record["scan_id"])},
                         {"queued"})
        self.assertIsNotNone(LedgerQueue().take("worker-b"), "another worker was kept from a scan it can run")

        store.mark_partitioned_scan(TENANT, record["scan_id"], "failed", error="cancelled")
        delivery = Delivery(tenant_id=TENANT, scan_id=record["scan_id"],
                            partition_id=store.list_scan_partitions(TENANT, record["scan_id"])[0]["partition_id"])
        self.assertEqual(partition_worker.handle_delivery(queue, delivery, self._rebuild("unbuildable"),
                                                          worker_id="worker-b"), "dropped")
        self.assertIsNone(LedgerQueue().take("worker-c"), "a failed scan was still handed out")

    def test_a_local_scan_planned_on_another_host_is_left_to_that_host(self) -> None:
        record = self._start("elsewhere")
        with store._connect() as conn:
            conn.execute(
                "UPDATE partitioned_scans SET header_json = ? WHERE tenant_id = ? AND scan_id = ?",
                (json.dumps(dict(record["header"], host="another-host")), TENANT, record["scan_id"]),
            )
        self.assertIsNone(LedgerQueue().take("worker-a"), "the ledger queue handed out another host's folders")
        # However a delivery arrives, the worker checks the host itself.
        units = store.list_scan_partitions(TENANT, record["scan_id"])
        delivery = Delivery(tenant_id=TENANT, scan_id=record["scan_id"], partition_id=units[0]["partition_id"])
        self.assertEqual(partition_worker.handle_delivery(LedgerQueue(), delivery, self._rebuild("elsewhere"),
                                                          worker_id="worker-a"), "elsewhere")
        self.assertEqual({unit["status"] for unit in store.list_scan_partitions(TENANT, record["scan_id"])}, {"queued"},
                         "a partition naming another host's folders was run here")

    def test_a_dead_workers_partition_is_taken_back_and_finished(self) -> None:
        record = self._start("dead-worker")
        first = LedgerQueue().take("worker-a")
        # worker-a claims its partition and dies before writing it: the row stays running.
        self.assertIsNotNone(store.claim_partition(TENANT, record["scan_id"], first.partition_id,
                                                   worker_id="worker-a", lease_seconds=1))
        time.sleep(1.2)
        partition_worker.run_worker(LedgerQueue(), self._rebuild("dead-worker"), worker_id="worker-b",
                                    stop_when_idle=True)
        self.assertEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "done",
                         "the dead worker's partition was never taken back, so the scan could not finish")
        self.assertEqual(store.read_scan_partition(TENANT, record["scan_id"], first.partition_id)["attempt"], 2)

    def test_a_partition_whose_holder_died_on_its_last_attempt_fails_the_scan(self) -> None:
        record = self._start("poison")
        unit = store.list_scan_partitions(TENANT, record["scan_id"])[0]
        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_ATTEMPTS": "1"}):
            self.assertIsNotNone(store.claim_partition(TENANT, record["scan_id"], unit["partition_id"],
                                                       worker_id="worker-a", lease_seconds=1))
            time.sleep(1.2)
            handled = partition_worker.run_worker(LedgerQueue(), self._rebuild("poison"), worker_id="worker-b",
                                                  stop_when_idle=True)
        stored = store.read_partitioned_scan(TENANT, record["scan_id"])
        self.assertEqual(stored["status"], "failed")
        self.assertIn("lease expired on its last attempt", stored["error"])
        self.assertEqual(handled, 0, "the rest of a scan that could never finish was run anyway")

    def test_a_scan_whose_last_worker_died_before_finalizing_is_finished_by_another(self) -> None:
        record = self._start("stranded")
        for unit in store.list_scan_partitions(TENANT, record["scan_id"]):
            self.assertEqual(partitioned_scan.run_queued_partition(
                record, ScanConfig(**self._settings("stranded")), unit["partition_id"], worker_id="worker-a"), "written")
        # worker-a died before it could finalize.
        self.assertEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "running")
        partition_worker.run_worker(LedgerQueue(), self._rebuild("stranded"), worker_id="worker-b", stop_when_idle=True)
        self.assertEqual(store.read_partitioned_scan(TENANT, record["scan_id"])["status"], "done")
        walked, _ = self._single_walk(ScanConfig(**self._settings("stranded")))
        self.assertEqual([f["path"] for f in store.read_scan_report(TENANT, record["scan_id"])["files"]], walked)

    def test_the_worker_waits_out_a_busy_database(self) -> None:
        self._use_database("busy")
        calls = {"n": 0}

        class BusyOnce(LedgerQueue):
            def take(self, worker_id, *, block_seconds=0.0):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise sqlite3.OperationalError("database is locked")
                return None

        handled = partition_worker.run_worker(BusyOnce(), self._rebuild("busy"), worker_id="worker-a",
                                              idle_seconds=0.01, stop_when_idle=True)
        self.assertEqual((handled, calls["n"]), (0, 2))

    def test_a_failed_partition_is_queued_again_until_its_attempts_run_out(self) -> None:
        record = self._start("retry")
        queue = LedgerQueue()
        # Retry counting, not timing: the back-off has its own tests (test_backend_audit_pipeline).
        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_ATTEMPTS": "2", "DSPM_PARTITION_RETRY_SECONDS": "0"}), \
                mock.patch.object(partitioned_scan.DSPMDiscoveryEngine, "run", side_effect=OSError("locked")):
            first = queue.take("worker-a")
            self.assertEqual(partition_worker.handle_delivery(queue, first, self._rebuild("retry"), worker_id="worker-a"),
                             "retry")
            again = queue.take("worker-a")
            self.assertEqual(again.partition_id, first.partition_id, "the failed partition was not queued again")
            self.assertEqual(partition_worker.handle_delivery(queue, again, self._rebuild("retry"), worker_id="worker-a"),
                             "stopped")
        stored = store.read_partitioned_scan(TENANT, record["scan_id"])
        self.assertEqual(stored["status"], "failed")
        self.assertIn("failed 2 times", stored["error"])
        self.assertIsNone(queue.take("worker-a"), "a failed scan was still handed out")


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
