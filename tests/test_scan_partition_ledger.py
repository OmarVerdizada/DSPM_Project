"""B2.1: the ledger a resumable scan needs.

A restart used to lose every running scan. The job row held a status and nothing
about what the job had been asked to do, so on startup it could only be marked
failed. Revision 0011 gives a job its scan and its request, and gives a scan a
row per unit of work. Nothing in the scan path uses it yet; these tests pin the
ledger itself, and the two ways it could quietly go wrong - a progress write
erasing a job's binding, and a typed password reaching the database.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
import uuid
from datetime import datetime, timezone

from backend import db, migrations, store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class _LedgerTest(unittest.TestCase):
    def setUp(self) -> None:
        self._previous = os.environ.get("DSPM_DB_PATH")
        self._dir = tempfile.TemporaryDirectory()
        os.environ["DSPM_DB_PATH"] = os.path.join(self._dir.name, "ledger.sqlite")
        store.init_db()
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "ledger")

    def tearDown(self) -> None:
        if self._previous is None:
            os.environ.pop("DSPM_DB_PATH", None)
        else:
            os.environ["DSPM_DB_PATH"] = self._previous
        self._dir.cleanup()

    def _job(self, job_id: str, progress: int = 5) -> None:
        store.record_job({
            "id": job_id, "tenant_id": self.tenant, "status": "running",
            "progress": progress, "message": "Running", "created_at": _now(),
        })


class TheRevisionTest(_LedgerTest):

    def test_the_revision_is_registered_after_the_ones_before_it(self) -> None:
        revisions = migrations._revisions()
        names = {name: number for number, name, _func in revisions}
        self.assertIn("scan_partition_ledger", names)
        self.assertGreater(names["scan_partition_ledger"], names["remediation_filter_indexes"])

    def test_a_fresh_database_is_built_with_the_ledger(self) -> None:
        with store._connect() as conn:
            columns = db.table_columns(conn, "scan_jobs")
            partitions = db.table_columns(conn, "scan_partitions")
        for column in ("scan_id", "request_json", "resumable"):
            self.assertIn(column, columns)
        for column in ("tenant_id", "scan_id", "partition_id", "status", "attempt", "spec_json"):
            self.assertIn(column, partitions)

    def test_it_upgrades_a_database_built_before_it_and_is_idempotent(self) -> None:
        path = os.path.join(self._dir.name, "legacy.sqlite")
        raw = sqlite3.connect(path)
        raw.execute(
            "CREATE TABLE scan_jobs (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, status TEXT NOT NULL, "
            "progress INTEGER NOT NULL DEFAULT 0, message TEXT, created_at TEXT NOT NULL, "
            "finished_at TEXT, error TEXT, updated_at TEXT NOT NULL)"
        )
        raw.execute(
            "INSERT INTO scan_jobs VALUES ('old-job', 't', 'completed', 100, 'Completed', 'x', 'y', NULL, 'z')"
        )
        raw.commit()
        raw.close()

        for _ in range(2):
            with db.connect(path) as conn:
                store.add_scan_partition_ledger(conn)

        with db.connect(path) as conn:
            columns = db.table_columns(conn, "scan_jobs")
            existing = conn.execute("SELECT status, scan_id, resumable FROM scan_jobs WHERE id = 'old-job'").fetchone()
            tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        self.assertIn("scan_id", columns)
        self.assertIn("scan_partitions", tables)
        self.assertEqual(existing["status"], "completed", "the upgrade changed an existing job")
        self.assertEqual(existing["scan_id"], "")
        self.assertEqual(existing["resumable"], 0)


class JobBindingTest(_LedgerTest):

    def test_a_progress_write_does_not_erase_the_binding(self) -> None:
        """INSERT OR REPLACE on SQLite would have reset every column it does not name."""
        self._job("job-1", progress=5)
        store.bind_job_to_scan(self.tenant, "job-1", "scan-1", {"local_path": "/data"})
        self._job("job-1", progress=60)
        binding = store.read_job_binding(self.tenant, "job-1")
        self.assertEqual(binding["scan_id"], "scan-1")
        self.assertTrue(binding["resumable"])
        self.assertEqual(binding["request"], {"local_path": "/data"})

    def test_a_typed_password_is_never_stored(self) -> None:
        self._job("job-2")
        result = store.bind_job_to_scan(self.tenant, "job-2", "scan-2", {
            "server": "fs01", "username": "svc-scan", "password": "hunter2-not-for-disk", "domain": "CORP",
        })
        self.assertFalse(result["resumable"])
        binding = store.read_job_binding(self.tenant, "job-2")
        self.assertNotIn("password", binding["request"])
        self.assertEqual(binding["request"].get("username"), "svc-scan")
        self.assertFalse(binding["resumable"])
        with store._connect() as conn:
            stored = conn.execute("SELECT request_json FROM scan_jobs WHERE id = 'job-2'").fetchone()["request_json"]
        self.assertNotIn("hunter2-not-for-disk", stored)

    def test_the_resumability_rule(self) -> None:
        cases = [
            ({"local_path": "/data"}, True),
            ({"server": "fs01"}, True),
            ({"server": "fs01", "credential_ref": "cred-1"}, True),
            ({"server": "fs01", "username": "svc", "password": "typed"}, False),
            ({"server": "fs01", "password": "typed", "credential_ref": "cred-1"}, True),
            ({"host": "pc01", "credential_ref": "cred-2"}, True),
            ({"host": "pc01", "password": "typed"}, False),
            (None, True),
        ]
        for request, expected in cases:
            with self.subTest(request=request):
                self.assertEqual(store.scan_request_is_resumable(request), expected)

    def test_another_tenant_cannot_read_the_binding(self) -> None:
        self._job("job-3")
        store.bind_job_to_scan(self.tenant, "job-3", "scan-3", {"local_path": "/data"})
        self.assertIsNone(store.read_job_binding("some-other-tenant", "job-3"))


class PartitionLifecycleTest(_LedgerTest):

    def _plan(self, scan_id: str, count: int) -> list[str]:
        return store.create_scan_partitions(
            self.tenant, scan_id, "job-x", [{"root": f"dept{index}"} for index in range(count)],
        )

    def test_units_are_claimed_in_plan_order_and_finish_once(self) -> None:
        ids = self._plan("scan-a", 3)
        self.assertEqual(ids, ["p00000", "p00001", "p00002"])

        first = store.claim_next_partition(self.tenant, "scan-a")
        self.assertEqual((first["partition_id"], first["status"], first["attempt"]), ("p00000", "running", 1))
        self.assertEqual(first["spec"], {"root": "dept0"})
        self.assertTrue(store.complete_scan_partition(self.tenant, "scan-a", "p00000", 10))
        self.assertFalse(store.complete_scan_partition(self.tenant, "scan-a", "p00000", 99),
                         "a unit that is not running must not finish again")

        second = store.claim_next_partition(self.tenant, "scan-a")
        self.assertEqual(second["partition_id"], "p00001")
        self.assertTrue(store.fail_scan_partition(self.tenant, "scan-a", "p00001", "share went away"))

        third = store.claim_next_partition(self.tenant, "scan-a")
        self.assertEqual(third["partition_id"], "p00002")
        self.assertIsNone(store.claim_next_partition(self.tenant, "scan-a"))

        summary = store.scan_partition_summary(self.tenant, "scan-a")
        self.assertEqual(
            {key: summary[key] for key in ("partitions", "queued", "running", "done", "failed", "files")},
            {"partitions": 3, "queued": 0, "running": 1, "done": 1, "failed": 1, "files": 10},
        )
        self.assertFalse(summary["complete"])
        failed = next(p for p in store.list_scan_partitions(self.tenant, "scan-a") if p["partition_id"] == "p00001")
        self.assertEqual(failed["error"], "share went away")

    def test_a_scan_is_complete_only_when_every_unit_is_done(self) -> None:
        self._plan("scan-b", 2)
        for _ in range(2):
            unit = store.claim_next_partition(self.tenant, "scan-b")
            store.complete_scan_partition(self.tenant, "scan-b", unit["partition_id"], 1)
        self.assertTrue(store.scan_partition_summary(self.tenant, "scan-b")["complete"])
        self.assertFalse(store.scan_partition_summary(self.tenant, "no-such-scan")["complete"],
                         "a scan with no units is not complete")

    def test_planning_again_never_resets_a_unit_that_ran(self) -> None:
        self._plan("scan-c", 3)
        unit = store.claim_next_partition(self.tenant, "scan-c")
        store.complete_scan_partition(self.tenant, "scan-c", unit["partition_id"], 7)
        self._plan("scan-c", 3)
        units = store.list_scan_partitions(self.tenant, "scan-c")
        self.assertEqual(len(units), 3)
        self.assertEqual((units[0]["status"], units[0]["files"]), ("done", 7))

    def test_an_interrupted_unit_goes_back_in_the_queue_and_counts_its_attempts(self) -> None:
        self._plan("scan-d", 1)
        self.assertEqual(store.claim_next_partition(self.tenant, "scan-d")["attempt"], 1)
        self.assertIsNone(store.claim_next_partition(self.tenant, "scan-d"))
        self.assertEqual(store.requeue_interrupted_partitions(self.tenant), 1)
        self.assertEqual(store.claim_next_partition(self.tenant, "scan-d")["attempt"], 2)

    def test_a_stale_worker_cannot_finish_a_unit_that_was_claimed_again(self) -> None:
        self._plan("scan-e", 1)
        stale = store.claim_next_partition(self.tenant, "scan-e")
        store.requeue_interrupted_partitions(self.tenant)
        fresh = store.claim_next_partition(self.tenant, "scan-e")
        self.assertFalse(store.complete_scan_partition(
            self.tenant, "scan-e", stale["partition_id"], 1, attempt=stale["attempt"]))
        self.assertTrue(store.complete_scan_partition(
            self.tenant, "scan-e", fresh["partition_id"], 1, attempt=fresh["attempt"]))

    def test_a_spec_can_name_its_own_unit(self) -> None:
        ids = store.create_scan_partitions(self.tenant, "scan-f", "job-x", [{"partition_id": "share:HR"}, {}])
        self.assertEqual(ids, ["share:HR", "p00001"])

    def test_tenants_do_not_see_each_others_units(self) -> None:
        self._plan("scan-g", 2)
        other = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(other, "other")
        self.assertIsNone(store.claim_next_partition(other, "scan-g"))
        self.assertEqual(store.scan_partition_summary(other, "scan-g")["partitions"], 0)
        self.assertEqual(store.list_scan_partitions(other, "scan-g"), [])


class ErasureTest(_LedgerTest):

    def test_deleting_a_tenant_deletes_its_units(self) -> None:
        store.create_scan_partitions(self.tenant, "scan-z", "job-z", [{"root": "a"}, {"root": "b"}])
        store.delete_tenant_with_data(self.tenant)
        with store._connect() as conn:
            left = conn.execute(
                "SELECT COUNT(*) AS n FROM scan_partitions WHERE tenant_id = ?", (self.tenant,),
            ).fetchone()["n"]
        self.assertEqual(left, 0)


if __name__ == "__main__":
    unittest.main()
