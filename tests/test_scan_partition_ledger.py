"""B2.1: the ledger a resumable scan needs.

A restart used to lose every running scan. The job row held a status and nothing
about what the job had been asked to do, so on startup it could only be marked
failed. Revision 0011 gives a job its scan and its request, and gives a scan a
row per unit of work. Nothing in the scan path uses it yet; these tests pin the
ledger itself, and the two ways it could quietly go wrong - a progress write
erasing a job's binding, and a typed password reaching the database.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from unittest import mock

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

    @unittest.skipIf(db.is_postgres(), "builds an older SQLite file; the PostgreSQL upgrade path is scripted in C0.5")
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
            # A local scan needs no credential; a password left in the form is not one.
            ({"local_path": "/data", "password": "left-over-from-the-form"}, True),
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

    def test_binding_says_whether_there_was_a_job_to_bind(self) -> None:
        """A binding written to no row is a resume that silently cannot happen."""
        self.assertFalse(store.bind_job_to_scan(self.tenant, "no-such-job", "scan-4", {})["bound"])
        self._job("job-4")
        self.assertTrue(store.bind_job_to_scan(self.tenant, "job-4", "scan-4", {})["bound"])


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
        self.assertTrue(store.complete_scan_partition(self.tenant, "scan-a", "p00000", 10, attempt=first["attempt"]))
        self.assertFalse(store.complete_scan_partition(self.tenant, "scan-a", "p00000", 99, attempt=first["attempt"]),
                         "a unit that is not running must not finish again")

        second = store.claim_next_partition(self.tenant, "scan-a")
        self.assertEqual(second["partition_id"], "p00001")
        self.assertTrue(store.fail_scan_partition(
            self.tenant, "scan-a", "p00001", "share went away", attempt=second["attempt"]))

        third = store.claim_next_partition(self.tenant, "scan-a")
        self.assertEqual(third["partition_id"], "p00002")
        self.assertIsNone(store.claim_next_partition(self.tenant, "scan-a"))

        summary = store.scan_partition_summary(self.tenant, "scan-a")
        self.assertEqual(
            {key: summary[key] for key in ("partitions", "queued", "running", "done", "failed", "files")},
            {"partitions": 3, "queued": 0, "running": 1, "done": 1, "failed": 1, "files": 10},
        )
        self.assertFalse(summary["complete"])
        self.assertFalse(summary["finished"], "a unit is still running")
        failed = next(p for p in store.list_scan_partitions(self.tenant, "scan-a") if p["partition_id"] == "p00001")
        self.assertEqual(failed["error"], "share went away")

        store.fail_scan_partition(self.tenant, "scan-a", "p00002", "gone too", attempt=third["attempt"])
        summary = store.scan_partition_summary(self.tenant, "scan-a")
        self.assertTrue(summary["finished"], "nothing is left to run")
        self.assertFalse(summary["complete"], "but a scan with a failed unit is not complete")

    def test_a_scan_is_complete_only_when_every_unit_is_done(self) -> None:
        self._plan("scan-b", 2)
        for _ in range(2):
            unit = store.claim_next_partition(self.tenant, "scan-b")
            store.complete_scan_partition(self.tenant, "scan-b", unit["partition_id"], 1, attempt=unit["attempt"])
        summary = store.scan_partition_summary(self.tenant, "scan-b")
        self.assertTrue(summary["complete"])
        self.assertTrue(summary["finished"])
        empty = store.scan_partition_summary(self.tenant, "no-such-scan")
        self.assertFalse(empty["complete"], "a scan with no units is not complete")
        self.assertFalse(empty["finished"], "nor finished")

    def test_planning_again_never_resets_a_unit_that_ran(self) -> None:
        self._plan("scan-c", 3)
        unit = store.claim_next_partition(self.tenant, "scan-c")
        store.complete_scan_partition(self.tenant, "scan-c", unit["partition_id"], 7, attempt=unit["attempt"])
        self.assertEqual(self._plan("scan-c", 3), ["p00000", "p00001", "p00002"])
        units = store.list_scan_partitions(self.tenant, "scan-c")
        self.assertEqual(len(units), 3)
        self.assertEqual((units[0]["status"], units[0]["files"]), ("done", 7))

    def test_a_different_plan_for_a_planned_scan_is_refused(self) -> None:
        """Units are numbered by position, so a re-enumeration that inserts a folder
        would shift every id after it - one unit would never run and another would
        run twice. A resumed scan continues the plan it has; it does not make a new one.
        """
        self._plan("scan-i", 3)
        unit = store.claim_next_partition(self.tenant, "scan-i")
        store.complete_scan_partition(self.tenant, "scan-i", unit["partition_id"], 4, attempt=unit["attempt"])
        shifted = [{"root": "deptX"}] + [{"root": f"dept{index}"} for index in range(3)]
        for plan in (shifted, [{"root": "dept0"}, {"root": "dept1"}], [{"root": "dept0"}, {"root": "other"}, {"root": "dept2"}]):
            with self.subTest(plan=plan):
                with self.assertRaises(ValueError):
                    store.create_scan_partitions(self.tenant, "scan-i", "job-x", plan)
        units = store.list_scan_partitions(self.tenant, "scan-i")
        self.assertEqual([u["spec"]["root"] for u in units], ["dept0", "dept1", "dept2"])
        self.assertEqual(units[0]["status"], "done")

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
        self.assertFalse(store.fail_scan_partition(
            self.tenant, "scan-e", stale["partition_id"], "stale", attempt=stale["attempt"]))
        self.assertTrue(store.complete_scan_partition(
            self.tenant, "scan-e", fresh["partition_id"], 1, attempt=fresh["attempt"]))

    def test_finishing_a_unit_requires_the_attempt_that_claimed_it(self) -> None:
        """Without it, a stale worker finishes the newer attempt's unit."""
        self._plan("scan-h", 1)
        unit = store.claim_next_partition(self.tenant, "scan-h")
        with self.assertRaises(TypeError):
            store.complete_scan_partition(self.tenant, "scan-h", unit["partition_id"], 1)  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            store.fail_scan_partition(self.tenant, "scan-h", unit["partition_id"], "x")  # type: ignore[call-arg]

    def test_a_claim_reports_the_attempt_it_actually_took(self) -> None:
        """Another claimer can take and requeue the unit between the read and the update.

        The claim must then report the attempt the row really holds - a worker told
        the wrong attempt can never complete its own unit.
        """
        self._plan("scan-j", 1)
        tenant = self.tenant
        real_connect = store._connect
        raced = {"done": False}

        class _Racing:
            def __init__(self, conn):
                self._conn = conn

            def __getattr__(self, name):
                return getattr(self._conn, name)

            def execute(self, sql, params=()):
                if not raced["done"] and str(sql).startswith("UPDATE scan_partitions SET status = 'running'"):
                    raced["done"] = True
                    # What a second process's claim-then-requeue leaves behind.
                    self._conn.execute(
                        "UPDATE scan_partitions SET attempt = attempt + 1 WHERE tenant_id = ? AND scan_id = ?",
                        (tenant, "scan-j"),
                    )
                return self._conn.execute(sql, params)

        @contextlib.contextmanager
        def racing_connect(*args, **kwargs):
            with real_connect(*args, **kwargs) as conn:
                yield _Racing(conn)

        with mock.patch.object(store, "_connect", racing_connect):
            claimed = store.claim_next_partition(self.tenant, "scan-j")
        self.assertTrue(raced["done"], "the race was never injected")
        stored = store.list_scan_partitions(self.tenant, "scan-j")[0]
        self.assertEqual(claimed["attempt"], stored["attempt"])
        self.assertTrue(store.complete_scan_partition(
            self.tenant, "scan-j", claimed["partition_id"], 1, attempt=claimed["attempt"]))

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
