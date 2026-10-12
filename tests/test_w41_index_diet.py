"""W4.1 step 5 (revision 0050): an index no read needs is not kept.

Every index on a table is written on every insert and on every update that is not HOT. The
census (scripts/pg_index_census.py, 10,000 files on PostgreSQL) EXPLAINed what the console
reads and what a rescan writes, then the same with these indexes dropped: each statement one
of them answered was answered by the longer index it is a prefix of - six on ``assets``, and
``findings (tenant_id, asset_id)`` by ``(tenant_id, is_current, asset_id)`` through a skip scan
- and two were read by nothing. SQLite keeps the two whose covering read it cannot make: it
has no ``(tenant_id, is_protected, risk_score, id)``, and no skip scan without statistics.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from backend import db, migrations, store
from tests.test_w2_migration_safety import _index_names, _report

_ROWS = ("assets", "findings", "scan_reports", "scan_object_baselines")


class TheConvergedSchemaHasNoRedundantIndexTest(unittest.TestCase):

    def test_none_is_left_and_each_one_it_leaned_on_is_there(self) -> None:
        store.init_db()
        with store._connect() as conn, db.platform_scope("migration"):
            names = _index_names(conn)
        self.assertEqual(set(store.redundant_indexes()) & names, set())
        covers = {store.REDUNDANT_INDEXES[name] for name in store.redundant_indexes()} - {""}
        self.assertLessEqual(covers, names, "an index the dropped ones leaned on is missing")
        if not db.is_postgres():
            self.assertLessEqual({"idx_assets_tenant_protected", "idx_findings_tenant_asset"}, names,
                                 "SQLite dropped an index it has no covering read for")


class AnInstallAtRevision49DropsThemTest(unittest.TestCase):
    """An install as revision 49 left it - with the redundant indexes - upgrades to 50 keeping
    every row, and loses only those indexes."""

    def setUp(self) -> None:
        revisions = migrations._revisions()
        if db.is_postgres():
            self.addCleanup(migrations.upgrade)
            with store._connect() as conn, db.platform_scope("migration"):
                conn.execute("DELETE FROM schema_migrations WHERE revision > 49")
        else:
            temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
            self.addCleanup(temp.cleanup)
            original = store.DB_PATH
            store.DB_PATH = Path(temp.name) / "at49.sqlite"
            self.addCleanup(setattr, store, "DB_PATH", original)
            with patch.object(migrations, "_revisions", lambda: revisions[:49]):
                migrations.upgrade()
        with store._connect() as conn, db.platform_scope("migration"):
            for name in store.redundant_indexes():
                conn.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {store.REDUNDANT_INDEX_DEFINITIONS[name]}")
            self.assertEqual(migrations.current_revision(conn), 49)
        self.tenant = f"at49-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "At 49")
        store.save_scan_history(self.tenant, _report("s1", 5))
        store.save_scan_history(self.tenant, _report("s2", 3))

    def _counts(self) -> dict:
        with store._connect() as conn, db.platform_scope("migration"):
            return {table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])  # noqa: S608
                    for table in _ROWS}

    def test_the_upgrade_keeps_every_row_and_drops_only_the_redundant_indexes(self) -> None:
        rows = self._counts()
        with store._connect() as conn, db.platform_scope("migration"):
            before = _index_names(conn)
        self.assertLessEqual(set(store.redundant_indexes()), before)
        self.assertEqual(migrations.upgrade(), migrations.expected_revision())
        with store._connect() as conn, db.platform_scope("migration"):
            after = _index_names(conn)
        # ... and revision 0054 (W5) the plain-column indexes revision 0053's sort indexes replaced;
        # revision 0055 the access principal index its rank index leads with.
        self.assertEqual(before - after, set(store.redundant_indexes()) | (set(store.SORTED_TWICE_INDEXES) & before)
                         | (set(store.REPLACED_ACCESS_INDEXES) & before))
        # Revision 0051 (W4.2) builds its own, 0053 and 0055 theirs; nothing else is built.
        from backend import estate_counts

        self.assertEqual(after - before, (set(store.UNIT_MANIFEST_INDEXES) | set(store.REMEDIATION_SORT_INDEXES)
                                          | set(store.INVENTORY_SORT_INDEXES) | set(estate_counts.INDEXES)
                                          | set(store.ACCESS_MODEL_INDEXES)) - before)
        self.assertEqual(self._counts(), rows)
        # Re-runnable.
        with store._connect() as conn, db.platform_scope("migration"):
            store.drop_redundant_indexes(conn)
            self.assertEqual(_index_names(conn), after)


if __name__ == "__main__":
    unittest.main()
