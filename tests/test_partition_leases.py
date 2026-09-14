"""B2.4: a partitioned scan can be continued, and its units are leased.

Requeuing every running unit is correct only at the startup of the one process that
runs scans; a second worker sharing the ledger would have its live units taken away.
A lease makes taking a unit back depend on its holder going quiet. And a partitioned
scan's header lived only in the process running it, so a restart could not continue
it - revision 0014 keeps it, without secrets, beside a status that lets exactly one
finalize run.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from backend import db, store

SCAN = "scan-leased"


class _LeaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self._previous_path = store.DB_PATH
        store.DB_PATH = Path(self._dir.name) / "leases.sqlite"
        self._env = mock.patch.dict(os.environ, {"DSPM_ARTIFACT_DIR": str(Path(self._dir.name) / "artifacts")})
        self._env.start()
        store.init_db()
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "leases")

    def tearDown(self) -> None:
        self._env.stop()
        store.DB_PATH = self._previous_path
        self._dir.cleanup()

    def _plan(self, count: int = 2, scan_id: str = SCAN) -> None:
        store.create_scan_partitions(self.tenant, scan_id, "job-l", [{"part": i} for i in range(count)])


class TheRevisionTest(_LeaseTest):

    def test_a_fresh_database_has_the_scan_record_and_the_lease(self) -> None:
        with store._connect() as conn:
            partitions = db.table_columns(conn, "scan_partitions")
            scans = db.table_columns(conn, "partitioned_scans")
        self.assertTrue({"lease_owner", "lease_expires_at"} <= partitions)
        self.assertTrue({"tenant_id", "scan_id", "job_id", "status", "request_json", "header_json", "resumable"} <= scans)

    def test_it_upgrades_a_0013_ledger_and_is_idempotent(self) -> None:
        path = os.path.join(self._dir.name, "ledger-0013.sqlite")
        raw = sqlite3.connect(path)
        raw.execute(
            "CREATE TABLE scan_partitions (tenant_id TEXT NOT NULL, scan_id TEXT NOT NULL, partition_id TEXT NOT NULL, "
            "status TEXT NOT NULL DEFAULT 'queued', updated_at TEXT NOT NULL, PRIMARY KEY (tenant_id, scan_id, partition_id))"
        )
        raw.execute("CREATE TABLE tenants (tenant_id TEXT PRIMARY KEY)")
        raw.commit()
        raw.close()
        with mock.patch.object(store, "add_tenant_integrity"), mock.patch.object(store, "add_tenant_rls"):
            for _ in range(2):
                with db.connect(path) as conn:
                    store.add_partitioned_scan_ledger(conn)
        with db.connect(path) as conn:
            self.assertIn("lease_owner", db.table_columns(conn, "scan_partitions"))
            self.assertIn("header_json", db.table_columns(conn, "partitioned_scans"))


class LeasesTest(_LeaseTest):

    def test_a_claim_takes_a_lease_for_its_worker(self) -> None:
        self._plan()
        unit = store.claim_next_partition(self.tenant, SCAN, worker_id="worker-a", lease_seconds=60)
        self.assertEqual(unit["lease_owner"], "worker-a")
        stored = store.list_scan_partitions(self.tenant, SCAN)[0]
        self.assertEqual((stored["lease_owner"], stored["lease_expires_at"]), ("worker-a", unit["lease_expires_at"]))
        expires = datetime.strptime(stored["lease_expires_at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        self.assertAlmostEqual((expires - datetime.now(timezone.utc)).total_seconds(), 60, delta=5)

    def test_only_the_holder_of_this_attempt_can_renew(self) -> None:
        self._plan()
        unit = store.claim_next_partition(self.tenant, SCAN, worker_id="worker-a", lease_seconds=5)
        self.assertTrue(store.renew_partition_lease(self.tenant, SCAN, unit["partition_id"], attempt=unit["attempt"],
                                                    worker_id="worker-a", lease_seconds=600))
        self.assertFalse(store.renew_partition_lease(self.tenant, SCAN, unit["partition_id"], attempt=unit["attempt"],
                                                     worker_id="worker-b"))
        self.assertFalse(store.renew_partition_lease(self.tenant, SCAN, unit["partition_id"], attempt=unit["attempt"] + 1,
                                                     worker_id="worker-a"))

    def test_only_an_expired_lease_is_taken_back(self) -> None:
        self._plan(2)
        live = store.claim_next_partition(self.tenant, SCAN, worker_id="alive", lease_seconds=600)
        quiet = store.claim_next_partition(self.tenant, SCAN, worker_id="gone", lease_seconds=1)
        later = datetime.now(timezone.utc) + timedelta(seconds=30)
        self.assertEqual(store.requeue_expired_partitions(now=later), 1)
        states = {u["partition_id"]: (u["status"], u["lease_owner"]) for u in store.list_scan_partitions(self.tenant, SCAN)}
        self.assertEqual(states[live["partition_id"]], ("running", "alive"))
        self.assertEqual(states[quiet["partition_id"]], ("queued", ""))
        again = store.claim_next_partition(self.tenant, SCAN, worker_id="new")
        self.assertEqual((again["partition_id"], again["attempt"]), (quiet["partition_id"], 2))
        with self.assertRaises(store.PartitionNotClaimed):
            store.persist_partition(self.tenant, SCAN, quiet["partition_id"], quiet["attempt"], {}, [], write_estate=True)

    def test_a_lease_string_compares_correctly_at_a_whole_second(self) -> None:
        exact = datetime(2026, 9, 14, 3, 0, 5, 0, tzinfo=timezone.utc)
        later = datetime(2026, 9, 14, 3, 0, 5, 1, tzinfo=timezone.utc)
        self.assertLess(store._lease_time(exact), store._lease_time(later))
        self.assertEqual(len(store._lease_time(exact)), len(store._lease_time(later)))

    def test_finishing_and_requeuing_clear_the_lease(self) -> None:
        self._plan(2)
        first = store.claim_next_partition(self.tenant, SCAN, worker_id="w")
        store.fail_scan_partition(self.tenant, SCAN, first["partition_id"], "boom", attempt=first["attempt"])
        second = store.claim_next_partition(self.tenant, SCAN, worker_id="w")
        store.requeue_interrupted_partitions(self.tenant)
        leases = {u["partition_id"]: u["lease_owner"] for u in store.list_scan_partitions(self.tenant, SCAN)}
        self.assertEqual(leases, {first["partition_id"]: "", second["partition_id"]: ""})

    def test_failed_units_are_retried_up_to_the_limit(self) -> None:
        self._plan(1)
        for attempt in range(1, 4):
            unit = store.claim_next_partition(self.tenant, SCAN)
            self.assertEqual(unit["attempt"], attempt)
            store.fail_scan_partition(self.tenant, SCAN, unit["partition_id"], "transient", attempt=unit["attempt"])
            retried = store.requeue_failed_partitions(self.tenant, SCAN, max_attempts=3)
            self.assertEqual(retried, 1 if attempt < 3 else 0)
        self.assertEqual(store.list_scan_partitions(self.tenant, SCAN)[0]["status"], "failed")


class TheScanRecordTest(_LeaseTest):

    def test_registering_strips_a_typed_password_and_keeps_the_header(self) -> None:
        row = store.register_partitioned_scan(
            self.tenant, SCAN, job_id="job-1",
            request={"local_path": "C:/data", "password": "typed-secret-never-stored", "username": "svc"},
            header={"timestamp": "2026-09-14T00:00:00Z", "scan_label": "nightly", "max_files": 2000},
        )
        self.assertFalse(row["resumable"])
        self.assertNotIn("password", row["request"])
        self.assertEqual(row["header"]["scan_label"], "nightly")
        self.assertEqual(row["status"], "running")
        with store._connect() as conn:
            raw = conn.execute("SELECT request_json FROM partitioned_scans WHERE tenant_id = ?", (self.tenant,)).fetchone()[0]
        self.assertNotIn("typed-secret-never-stored", raw)

    def test_registering_again_changes_nothing(self) -> None:
        store.register_partitioned_scan(self.tenant, SCAN, job_id="job-1", request={"local_path": "C:/a"},
                                        header={"timestamp": "first"})
        row = store.register_partitioned_scan(self.tenant, SCAN, job_id="job-2", request={"local_path": "C:/b"},
                                              header={"timestamp": "second"})
        self.assertEqual((row["job_id"], row["header"]["timestamp"], row["request"]["local_path"]), ("job-1", "first", "C:/a"))
        self.assertTrue(store.bind_partitioned_scan_job(self.tenant, SCAN, "job-2"))
        self.assertEqual(store.read_partitioned_scan(self.tenant, SCAN)["job_id"], "job-2")

    def test_exactly_one_finalize_claim_wins_and_a_stale_one_can_be_taken_back(self) -> None:
        store.register_partitioned_scan(self.tenant, SCAN, job_id="j", request={}, header={})
        self.assertTrue(store.claim_scan_finalize(self.tenant, SCAN))
        self.assertFalse(store.claim_scan_finalize(self.tenant, SCAN))
        self.assertFalse(store.claim_scan_finalize(self.tenant, SCAN, stale_after_seconds=3600))
        self.assertTrue(store.claim_scan_finalize(self.tenant, SCAN, stale_after_seconds=0))
        store.mark_partitioned_scan(self.tenant, SCAN, "done")
        self.assertFalse(store.claim_scan_finalize(self.tenant, SCAN, stale_after_seconds=0))
        with self.assertRaises(ValueError):
            store.mark_partitioned_scan(self.tenant, SCAN, "exploded")

    def test_unfinished_scans_are_listed_across_tenants(self) -> None:
        other = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(other, "other")
        store.register_partitioned_scan(self.tenant, "scan-1", job_id="a", request={"local_path": "x"}, header={})
        store.register_partitioned_scan(other, "scan-2", job_id="b", request={"password": "typed"}, header={})
        store.register_partitioned_scan(self.tenant, "scan-3", job_id="c", request={}, header={})
        store.mark_partitioned_scan(self.tenant, "scan-3", "done")
        listed = {(row["tenant_id"], row["scan_id"]) for row in store.list_unfinished_partitioned_scans()}
        self.assertTrue({(self.tenant, "scan-1"), (other, "scan-2")} <= listed)
        self.assertNotIn((self.tenant, "scan-3"), listed)
        resumable = {(row["tenant_id"], row["scan_id"]) for row in store.list_unfinished_partitioned_scans(resumable_only=True)}
        self.assertIn((self.tenant, "scan-1"), resumable)
        self.assertNotIn((other, "scan-2"), resumable)

    def test_erasing_a_tenant_erases_its_scan_records(self) -> None:
        store.register_partitioned_scan(self.tenant, SCAN, job_id="j", request={}, header={})
        store.delete_tenant_with_data(self.tenant)
        with store._connect() as conn:
            left = conn.execute("SELECT COUNT(*) FROM partitioned_scans WHERE tenant_id = ?", (self.tenant,)).fetchone()[0]
        self.assertEqual(left, 0)


if __name__ == "__main__":
    unittest.main()
