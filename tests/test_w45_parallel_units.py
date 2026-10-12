"""W4.5: the units of a scan write the estate side by side; a save or a finalize still alone.

Every unit's write held the workspace's estate lock exclusively, and its first statement
updated the scan's own row - so a second unit worker waited for the first's whole
transaction, twice over, and two workers persisted no faster than one. A unit now holds the
lock shared and touches the scan's row last; it locks the rows of the files it writes, in id
order, first. Here one unit's transaction is held open at a gate while another writes:

- another unit of the same scan finishes meanwhile;
- a save - which reads and prunes across the label - waits for it, as before;
- a unit of another scan that writes some of the same files waits for it, row by row, and
  one that writes none of them does not;
- two units appending to the scan's plan never take the same ordinal.

PostgreSQL only: SQLite has one writer at a time, as it always had.
"""
from __future__ import annotations

import threading
import time
import unittest
import uuid
from unittest import mock

from backend import db, store
from tests.test_persist_partition import _copy, _files, _header


@unittest.skipUnless(db.is_postgres(), "concurrent writers are PostgreSQL's")
class UnitsWriteSideBySideTest(unittest.TestCase):

    def setUp(self) -> None:
        self.tenant = f"w45-{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "W4.5 units")
        self.gate = threading.Event()
        self.inside = threading.Event()
        self.errors: list[BaseException] = []

    def tearDown(self) -> None:
        self.gate.set()
        try:
            store.delete_tenant_with_data(self.tenant)
        except Exception:  # noqa: BLE001 - a test's tenant, best effort
            pass

    def _units(self, scan_id: str, count: int) -> list[dict]:
        # A recorded, running scan: its row is the one every unit touches.
        store.register_partitioned_scan(self.tenant, scan_id, job_id=f"job-{scan_id}", request={}, header=_header())
        store.create_scan_partitions(self.tenant, scan_id, f"job-{scan_id}", [{"part": index} for index in range(count)])
        return [store.claim_next_partition(self.tenant, scan_id) for _ in range(count)]

    def _persist(self, scan_id: str, unit: dict, files: list[dict], **kwargs) -> dict:
        return store.persist_partition(self.tenant, scan_id, unit["partition_id"], unit["attempt"], _copy(_header()),
                                       _copy(files), write_estate=True, **kwargs)

    def _in_thread(self, target) -> threading.Thread:
        def run() -> None:
            try:
                target()
            except BaseException as exc:  # noqa: BLE001 - reported by the test
                self.errors.append(exc)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread

    def _held(self, name: str, *, before: bool = False):
        """Patch ``store.<name>`` so the first call waits at the gate - inside its transaction,
        after the call or (``before``) before it."""
        real = getattr(store, name)
        first = threading.Lock()

        def wait() -> None:
            if first.acquire(blocking=False):
                self.inside.set()
                self.assertTrue(self.gate.wait(30), "the gate was never opened")

        def gated(*args, **kwargs):
            if before:
                wait()
            result = real(*args, **kwargs)
            if not before:
                wait()
            return result
        return mock.patch.object(store, name, side_effect=gated)

    def test_two_units_of_a_scan_write_at_once(self) -> None:
        first, second = self._units("w45-a", 2)
        with self._held("_write_incremental_baseline"):
            holder = self._in_thread(lambda: self._persist("w45-a", first, _files(20)))
            self.assertTrue(self.inside.wait(30))
            started = time.perf_counter()
            other = self._in_thread(lambda: self._persist("w45-a", second, _files(20, start=100)))
            other.join(15)
            self.assertFalse(other.is_alive(), "the second unit waited for the first's whole transaction")
            self.assertLess(time.perf_counter() - started, 15)
            self.gate.set()
            holder.join(30)
        self.assertEqual(self.errors, [])
        with db.tenant_scope(self.tenant), store._connect() as conn:
            self.assertEqual(int(conn.execute("SELECT COUNT(*) AS n FROM assets WHERE tenant_id = ?",
                                              (self.tenant,)).fetchone()["n"]), 40)

    def test_a_save_still_waits_for_a_unit(self) -> None:
        (unit,) = self._units("w45-b", 1)
        with self._held("_write_incremental_baseline"):
            holder = self._in_thread(lambda: self._persist("w45-b", unit, _files(10)))
            self.assertTrue(self.inside.wait(30))
            saver = self._in_thread(lambda: store.save_scan_history(
                self.tenant, {**_header(), "scan_id": "w45-save", "files": _files(5, start=500)}))
            saver.join(2)
            self.assertTrue(saver.is_alive(), "a save ran beside a unit")
            self.gate.set()
            holder.join(30)
            saver.join(30)
        self.assertFalse(saver.is_alive())
        self.assertEqual(self.errors, [])

    def test_overlapping_units_of_two_scans_wait_row_by_row(self) -> None:
        # The files exist (their rows can be locked): a first scan wrote them.
        store.save_scan_history(self.tenant, {**_header(), "scan_id": "w45-seed", "files": _files(30)})
        (unit_one,) = self._units("w45-c1", 1)
        overlapping, apart = self._units("w45-c2", 2)
        # Held after it locked its files' rows and before it wrote any: what keeps the other
        # unit out is the lock it takes first, not the rows it happened to write already.
        with self._held("_write_normalized_rows", before=True):
            holder = self._in_thread(lambda: self._persist("w45-c1", unit_one, _files(10)))
            self.assertTrue(self.inside.wait(30))
            other = self._in_thread(lambda: self._persist("w45-c2", apart, _files(10, start=20)))
            other.join(15)
            self.assertFalse(other.is_alive(), "a unit writing none of the same files waited")
            waiting = self._in_thread(lambda: self._persist("w45-c2", overlapping, _files(10, start=5)))
            waiting.join(2)
            self.assertTrue(waiting.is_alive(), "two units wrote the same files at once")
            self.gate.set()
            holder.join(30)
            waiting.join(30)
        self.assertFalse(waiting.is_alive())
        self.assertEqual(self.errors, [])

    def test_appends_to_the_plan_never_share_an_ordinal(self) -> None:
        first, second = self._units("w45-d", 2)
        found = [{"part": f"found-{index}"} for index in range(3)]
        # Held after its append, inside the transaction: the other appends meanwhile.
        with self._held("_touch_scan_record"):
            holder = self._in_thread(lambda: self._persist("w45-d", first, _files(5), new_units=found))
            self.assertTrue(self.inside.wait(30))
            other = self._in_thread(lambda: self._persist("w45-d", second, _files(5, start=50), new_units=found))
            other.join(2)
            self.gate.set()
            holder.join(30)
            other.join(30)
        self.assertEqual(self.errors, [])
        with db.tenant_scope(self.tenant), store._connect() as conn:
            ordinals = [int(row["ordinal"]) for row in conn.execute(
                "SELECT ordinal FROM scan_partitions WHERE tenant_id = ? AND scan_id = ?",
                (self.tenant, "w45-d")).fetchall()]
        self.assertEqual(len(ordinals), 8)
        self.assertEqual(len(set(ordinals)), 8, f"two appends took the same ordinals: {sorted(ordinals)}")


@unittest.skipUnless(db.is_postgres(), "statement-level triggers are PostgreSQL's")
class ABatchIsOneStatementTest(unittest.TestCase):
    """A batch of rows goes as one INSERT, so the counting triggers fire once per batch.

    psycopg's executemany sends a statement per row: each fired the statement-level
    triggers and appended its own delta rows - 58 a file, measured - where one batch's rows
    aggregate to one delta row per count they touch. A batch whose upsert would touch one
    key twice still goes row by row, and must still land."""

    def setUp(self) -> None:
        self.tenant = f"w45-{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "W4.5 batches")
        self.addCleanup(store.delete_tenant_with_data, self.tenant)

    def test_a_save_appends_one_delta_per_count_per_statement(self) -> None:
        from tests.test_w44_maintained_counts import _report

        with mock.patch.object(store, "_fold_estate_counts", lambda _tenant: None):
            store.save_scan_history(self.tenant, _report("w45-s1", "alpha", range(0, 40), "2026-10-01T00:00:00+00:00"))
        with db.tenant_scope(self.tenant), store._connect() as conn:
            findings = int(conn.execute("SELECT COUNT(*) AS n FROM findings WHERE tenant_id = ?",
                                        (self.tenant,)).fetchone()["n"])
            busiest = int(conn.execute(
                "SELECT MAX(n) AS n FROM (SELECT COUNT(*) AS n FROM estate_count_deltas WHERE tenant_id = ? "
                "GROUP BY dim, k1, k2, k3) AS per_count", (self.tenant,)).fetchone()["n"] or 0)
        self.assertGreater(findings, 40)
        # f.total moves with every finding: once per statement that wrote findings, not per row.
        self.assertLessEqual(busiest, 3, f"one count got {busiest} delta rows for {findings} findings")

    def test_an_upsert_batch_that_repeats_a_key_still_lands(self) -> None:
        # The key is the first column alone: two rows that differ only after it repeat it.
        sql = ("INSERT INTO estate_count_state (tenant_id, drift_json) VALUES (?, ?) "
               "ON CONFLICT (tenant_id) DO UPDATE SET drift_json = excluded.drift_json")
        rows = [(self.tenant, '{"n": 1}'), (self.tenant, '{"n": 2}')]
        with db.tenant_scope(self.tenant), store._connect() as conn:
            self.assertEqual(store._executemany(conn, sql, rows), 2)
            self.assertEqual(conn.execute("SELECT drift_json FROM estate_count_state WHERE tenant_id = ?",
                                          (self.tenant,)).fetchone()["drift_json"], '{"n": 2}')


if __name__ == "__main__":
    unittest.main()
