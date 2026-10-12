"""W4.6: revision 0052 adds when a scan was admitted, keeping every scan an install has.

An install as revision 51 left it - no ``partitioned_scans.admitted_at`` - upgrades to 52 with
every scan row kept and none admitted (the column is empty until a runner is). Running the
revision again changes nothing. SQLite on a private file; PostgreSQL on sentro_test, taken
back to 51's shape and converged again by the cleanup.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from backend import db, migrations, store


class AnInstallAtRevision51UpgradesTest(unittest.TestCase):

    def setUp(self) -> None:
        revisions = migrations._revisions()
        if db.is_postgres():
            self.addCleanup(migrations.upgrade)
            with store._connect() as conn, db.platform_scope("migration"):
                if "admitted_at" in db.table_columns(conn, "partitioned_scans"):
                    conn.execute("ALTER TABLE partitioned_scans DROP COLUMN admitted_at")
                conn.execute("DELETE FROM schema_migrations WHERE revision > 51")
        else:
            temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
            self.addCleanup(temp.cleanup)
            original = store.DB_PATH
            store.DB_PATH = Path(temp.name) / "at51.sqlite"
            self.addCleanup(setattr, store, "DB_PATH", original)
            with patch.object(migrations, "_revisions", lambda: revisions[:51]):
                migrations.upgrade()
            # Revision 0001 converges to this build's schema; 51 had no such column.
            with store._connect() as conn:
                conn.execute("ALTER TABLE partitioned_scans DROP COLUMN admitted_at")
        self.tenant = f"at51-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "At 51")
        with store._connect() as conn, db.platform_scope("migration"):
            self.assertEqual(migrations.current_revision(conn), 51)
            self.assertNotIn("admitted_at", db.table_columns(conn, "partitioned_scans"))
            for scan_id, status in (("s-running", "running"), ("s-done", "done")):
                conn.execute("INSERT INTO partitioned_scans (tenant_id, scan_id, status, created_at, updated_at) "
                             "VALUES (?, ?, ?, '2026-10-01T00:00:00+00:00', '2026-10-01T00:00:00+00:00')",
                             (self.tenant, scan_id, status))

    def _scans(self) -> list[tuple]:
        with store._connect() as conn, db.platform_scope("migration"):
            columns = db.table_columns(conn, "partitioned_scans")
            admitted = "admitted_at" if "admitted_at" in columns else "'-'"
            return [tuple(row) for row in conn.execute(
                f"SELECT scan_id, status, {admitted} FROM partitioned_scans WHERE tenant_id = ? ORDER BY scan_id",
                (self.tenant,)).fetchall()]

    def test_the_upgrade_adds_the_column_and_keeps_every_scan(self) -> None:
        self.assertEqual(migrations.upgrade(), migrations.expected_revision())
        self.assertEqual(self._scans(), [("s-done", "done", ""), ("s-running", "running", "")])
        with store._connect() as conn, db.platform_scope("migration"):
            store.add_scan_admission(conn)  # again: a no-op
            self.assertEqual(migrations.current_revision(conn), migrations.expected_revision())
        self.assertEqual(self._scans(), [("s-done", "done", ""), ("s-running", "running", "")])
        # An upgraded install admits: the running scan takes the one slot.
        self.assertEqual(store.admit_partitioned_scan(self.tenant, "s-running", limit=1, alive_seconds=10 ** 9),
                         (True, 0))


if __name__ == "__main__":
    unittest.main()
