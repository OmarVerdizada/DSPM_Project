"""W4.4: every page of every list the console sorts is read from an index, in order.

A remediation page ordered by ``COALESCE(column, '') COLLATE "C"`` had no index on that
expression (the indexes were on the plain columns), so each page sorted every finding of
the tenant; the keyset was an OR that an index could only filter. Revision 0053 indexes
each sort's expression and the keyset is a row value. This captures the page queries the
product runs - every sort, both directions, a first page and the next - and EXPLAINs them
with sequential scans and sorts made expensive: a sort no index can answer still shows a
Sort node over the table, and the test names it. PostgreSQL only (the SQLite planner is
not what production runs).
"""
from __future__ import annotations

import contextlib
import json
import unittest
from unittest import mock
from uuid import uuid4

from backend import db, store
from tests.test_w44_maintained_counts import _report


@unittest.skipUnless(db.is_postgres(), "the production planner")
class EveryPageIsAnIndexRangeTest(unittest.TestCase):

    def setUp(self) -> None:
        # Per test: the suite truncates PostgreSQL before every test.
        self.tenant = f"w44p-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "W4.4 plans")
        store.save_scan_history(self.tenant, _report("w44p-1", "plans", range(0, 400), "2026-10-01T00:00:00+00:00"))
        with db.tenant_scope(self.tenant), store._connect() as conn:
            conn.execute("ANALYZE findings")
            conn.execute("ANALYZE assets")

    def tearDown(self) -> None:
        with contextlib.suppress(Exception):
            store.delete_tenant_with_data(self.tenant)

    def _captured(self, call) -> list[tuple[str, tuple]]:
        """The SELECTs on findings or assets that ``call`` runs, with their parameters."""
        seen: list[tuple[str, tuple]] = []
        real = store._connect

        @contextlib.contextmanager
        def tracing():
            with real() as conn:
                class _Conn:
                    def __getattr__(self, name):
                        return getattr(conn, name)

                    def execute(self, sql, params=()):
                        text = str(sql)
                        if text.lstrip().upper().startswith("SELECT") and ("FROM findings" in text or "FROM assets" in text):
                            seen.append((text, tuple(params or ())))
                        return conn.execute(sql, params)
                yield _Conn()

        store._connect, original = tracing, store._connect
        try:
            call()
        finally:
            store._connect = original
        return seen

    def _plan(self, sql: str, params: tuple) -> dict:
        with db.tenant_scope(self.tenant), store._connect() as conn:
            conn.execute("SET LOCAL enable_seqscan = off")
            conn.execute("SET LOCAL enable_sort = off")
            row = conn.execute(f"EXPLAIN (FORMAT JSON) {sql}", params).fetchone()
        plan = row[0]
        return (json.loads(plan) if isinstance(plan, str) else plan)[0]["Plan"]

    @staticmethod
    def _nodes(plan: dict):
        yield plan
        for child in plan.get("Plans") or []:
            yield from EveryPageIsAnIndexRangeTest._nodes(child)

    def _assert_index_ordered(self, label: str, sql: str, params: tuple, *, keyset: bool = False) -> None:
        nodes = list(self._nodes(self._plan(sql, params)))
        sorts = [node for node in nodes if node["Node Type"] in ("Sort", "Incremental Sort")]
        self.assertEqual(sorts, [], f"{label}: sorted, not read in index order")
        scans = [node for node in nodes if node.get("Relation Name") in ("findings", "assets")]
        self.assertTrue(scans and all(node["Node Type"] in ("Index Scan", "Index Only Scan") for node in scans),
                        f"{label}: {[node['Node Type'] for node in scans]}")
        if keyset:
            # The next page starts where the last ended as a range of the index - a row
            # value in its Index Cond - not by reading from the start and filtering.
            self.assertTrue(any("ROW(" in str(node.get("Index Cond") or "") for node in scans),
                            f"{label}: the keyset is not an index range: {[node.get('Index Cond') for node in scans]}")

    def test_every_remediation_sort_both_ways_and_its_next_page(self) -> None:
        for sort in store.REMEDIATION_SORTS:
            for direction in ("ASC", "DESC"):
                first: dict = {}
                queries = self._captured(lambda: first.update(store.list_remediation_findings(
                    self.tenant, sort=sort, direction=direction, limit=20)))
                pages = [(sql, params) for sql, params in queries if sql.lstrip().startswith("SELECT *")]
                self.assertEqual(len(pages), 1, f"{sort} {direction}: {queries}")
                self._assert_index_ordered(f"remediation {sort} {direction}", *pages[0])
                cursor = first.get("next_cursor")
                self.assertTrue(cursor, f"{sort} {direction}: no second page to read")
                queries = self._captured(lambda: store.list_remediation_findings(
                    self.tenant, sort=sort, direction=direction, after=cursor, limit=20))
                pages = [(sql, params) for sql, params in queries if sql.lstrip().startswith("SELECT *")]
                self._assert_index_ordered(f"remediation {sort} {direction} page 2", *pages[0], keyset=True)

    def test_every_inventory_sort_both_ways(self) -> None:
        for sort in store.INVENTORY_SORTS:
            for direction in ("ASC", "DESC"):
                queries = self._captured(lambda: store.list_inventory(self.tenant, sort=sort, direction=direction,
                                                                      limit=20))
                pages = [(sql, params) for sql, params in queries if "ORDER BY" in sql]
                self.assertTrue(pages, f"inventory {sort} {direction}: {queries}")
                self._assert_index_ordered(f"inventory {sort} {direction}", *pages[0])
                cursor = store.list_inventory(self.tenant, sort=sort, direction=direction, limit=20).get("next_cursor")
                self.assertTrue(cursor, f"inventory {sort} {direction}: no second page to read")
                queries = self._captured(lambda: store.list_inventory(self.tenant, sort=sort, direction=direction,
                                                                      cursor=cursor, limit=20))
                pages = [(sql, params) for sql, params in queries if "ORDER BY" in sql]
                self._assert_index_ordered(f"inventory {sort} {direction} page 2", *pages[0], keyset=True)

    def test_the_remediation_total_stops_at_the_cap(self) -> None:
        with mock.patch.object(store, "REMEDIATION_COUNT_CAP", 50):
            store._invalidate_remediation_query_cache(self.tenant)
            page = store.list_remediation_findings(self.tenant, status="all", limit=10)
        self.assertEqual(page["total"], 50)
        self.assertTrue(page["total_is_estimate"])


if __name__ == "__main__":
    unittest.main()
