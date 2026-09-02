"""Migration v2 schema discovery (roadmap Phase 3, DB-06).

The v1 migration hardcoded 17 table names and silently lost every table added
after the list was written. v2 discovers tables from the source database;
these tests pin the discovery contract: every application table is found, and
engine-local internals (SQLite bookkeeping, FTS shadow tables) plus the
destination-owned revision history are excluded.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.migrate_sqlite_to_postgres import discover_tables


class MigrationDiscoveryTests(unittest.TestCase):
    def _connect(self) -> sqlite3.Connection:
        # Cleanup order matters on Windows: connections must close before the
        # temp dir can be removed, and addCleanup runs LIFO.
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._tmp.cleanup)
        conn = sqlite3.connect(Path(self._tmp.name) / "source.sqlite")
        self.addCleanup(conn.close)
        return conn

    def test_discovers_every_application_table(self) -> None:
        src = self._connect()
        for name in ("tenants", "scan_profiles", "app_settings",
                     "scan_object_baselines", "search_reconciliation_state"):
            src.execute(f"CREATE TABLE {name} (id TEXT PRIMARY KEY)")
        found = discover_tables(src)
        # The v1 regression: these four postdated the hardcoded list and were
        # silently dropped by the old migration.
        for name in ("app_settings", "scan_object_baselines",
                     "search_reconciliation_state", "scan_profiles"):
            self.assertIn(name, found)
        self.assertIn("tenants", found)

    def test_excludes_engine_internals_and_revision_history(self) -> None:
        src = self._connect()
        src.execute("CREATE TABLE assets (id TEXT PRIMARY KEY)")
        src.execute("CREATE TABLE schema_migrations (revision INTEGER PRIMARY KEY)")
        # AUTOINCREMENT materializes sqlite_sequence, a real internal table.
        src.execute("CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT)")
        src.execute("INSERT INTO audit_events DEFAULT VALUES")
        src.execute("CREATE VIRTUAL TABLE inventory_fts USING fts5(search_text)")

        found = discover_tables(src)
        self.assertEqual(
            [name for name in found if name in {"assets", "audit_events"}],
            ["assets", "audit_events"],
        )
        self.assertNotIn("schema_migrations", found)
        self.assertNotIn("sqlite_sequence", found)
        self.assertFalse(
            [name for name in found if name.startswith("inventory_fts")],
            f"FTS shadow tables leaked into discovery: {found}",
        )

    def test_against_the_real_baseline_schema(self) -> None:
        """Discovery over a database built by revision 0001 finds at least the
        v1 list plus the four tables v1 lost - proving the regression cannot
        recur for tables that exist today."""
        from backend import store

        src = self._connect()
        # The baseline DDL runs against a plain sqlite3 connection: it only
        # needs executescript/execute, which sqlite3 provides. The db-seam
        # helpers used in the ALTER paths read PRAGMA table_info - available
        # here too because the seam special-cases SQLite connections... so run
        # through the seam instead for full fidelity.
        src.close()
        import backend.db as db

        path = Path(self._tmp.name) / "baseline.sqlite"
        with db.connect(path) as conn:
            store.apply_baseline_schema(conn)
        raw = sqlite3.connect(path)
        self.addCleanup(raw.close)
        found = set(discover_tables(raw))
        v1_list = {
            "tenants", "users", "api_keys", "registration_invites", "secrets",
            "scan_reports", "audit_events", "alert_events", "login_failures",
            "revoked_tokens", "scan_runs", "assets", "asset_versions",
            "findings", "finding_occurrences", "finding_index", "scan_jobs",
        }
        lost_by_v1 = {"app_settings", "scan_object_baselines",
                      "search_reconciliation_state", "scan_profiles"}
        self.assertTrue(v1_list <= found, f"missing: {v1_list - found}")
        self.assertTrue(lost_by_v1 <= found, f"missing: {lost_by_v1 - found}")


if __name__ == "__main__":
    unittest.main()
