"""Versioned schema control (roadmap Phase 2, DB-05).

Pins the contract of backend/migrations.py: a fresh database is built by
recorded revisions, re-running is a no-op, production refuses to serve a
database that is behind or ahead of the build, existing databases can be
adopted via stamp, and the legacy convergent init_db path still works.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from backend import db, migrations, store


class _TempStore(unittest.TestCase):
    """Fresh empty SQLite file per test (Postgres runs use conftest's reset)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_db_path = store.DB_PATH
        store.DB_PATH = Path(self._tmp.name) / "state.sqlite"

    def tearDown(self) -> None:
        store.DB_PATH = self._orig_db_path
        self._tmp.cleanup()

    def _recorded(self) -> list[dict]:
        with store._connect() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT revision, name, checksum FROM schema_migrations ORDER BY revision"
            ).fetchall()]


@unittest.skipIf(db.is_postgres(), "temp-file isolation is SQLite-specific")
class FreshDatabaseUpgrade(_TempStore):
    def test_upgrade_builds_schema_and_records_history(self) -> None:
        final = migrations.upgrade()
        self.assertEqual(final, migrations.expected_revision())
        rows = self._recorded()
        self.assertEqual([r["revision"] for r in rows], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22])
        self.assertEqual(rows[0]["name"], "baseline_convergent_schema")
        self.assertEqual(rows[1]["name"], "saved_scan_labels")
        self.assertEqual(rows[2]["name"], "tenant_referential_integrity")
        self.assertEqual(rows[3]["name"], "tenant_row_level_security")
        self.assertEqual(rows[4]["name"], "report_artifact_references")
        self.assertEqual(rows[5]["name"], "tenant_rls_unscoped_guard")
        self.assertEqual(rows[6]["name"], "tenant_legal_hold")
        self.assertEqual(rows[7]["name"], "inventory_filtered_search_scale_index")
        self.assertEqual(rows[8]["name"], "remediation_operational_index")
        self.assertEqual(rows[9]["name"], "remediation_filter_indexes")
        self.assertEqual(rows[10]["name"], "scan_partition_ledger")
        self.assertEqual(rows[11]["name"], "scan_partition_records")
        self.assertEqual(rows[12]["name"], "partition_write_indexes")
        self.assertEqual(rows[13]["name"], "partitioned_scan_ledger")
        # Checksum is the SHA-256 of the revision's source - 64 hex chars.
        for row in rows:
            self.assertRegex(row["checksum"], r"^[0-9a-f]{64}$")
        # The baseline actually ran: a core table exists and accepts reads.
        with store._connect() as conn:
            conn.execute("SELECT COUNT(*) AS c FROM tenants").fetchone()
            self.assertIn("scan_label", db.table_columns(conn, "scan_reports"))

    def test_upgrade_is_idempotent(self) -> None:
        migrations.upgrade()
        again = migrations.upgrade()
        self.assertEqual(again, migrations.expected_revision())
        self.assertEqual(len(self._recorded()), 22)

    def test_status_reports_pending_then_clean(self) -> None:
        before = migrations.status()
        self.assertEqual(before["applied_revision"], 0)
        self.assertEqual([p["revision"] for p in before["pending"]], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22])
        migrations.upgrade()
        after = migrations.status()
        self.assertEqual(after["applied_revision"], after["expected_revision"])
        self.assertEqual(after["pending"], [])


@unittest.skipIf(db.is_postgres(), "temp-file isolation is SQLite-specific")
class ProductionVerifyGate(_TempStore):
    def test_behind_refuses(self) -> None:
        # No history at all - the strongest "behind" case.
        with self.assertRaisesRegex(RuntimeError, "Refusing to serve.*upgrade"):
            migrations.verify_or_raise()

    def test_current_revision_is_a_pure_read(self) -> None:
        # The verify path must not create tables (the runtime role has no DDL
        # rights once Phase 4 splits roles): after a failed verify the file
        # still has no schema_migrations table.
        with self.assertRaises(RuntimeError):
            migrations.verify_or_raise()
        with store._connect() as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
            ).fetchone()
        self.assertIsNone(row)

    def test_ahead_refuses(self) -> None:
        migrations.upgrade()
        with store._connect() as conn:
            conn.execute(
                "INSERT INTO schema_migrations (revision, name, checksum, applied_at) "
                "VALUES (99, 'from-the-future', 'x', '2099-01-01T00:00:00+00:00')"
            )
        with self.assertRaisesRegex(RuntimeError, "NEWER"):
            migrations.verify_or_raise()

    def test_at_expected_passes(self) -> None:
        migrations.upgrade()
        migrations.verify_or_raise()  # must not raise


@unittest.skipIf(db.is_postgres(), "temp-file isolation is SQLite-specific")
class AdoptExistingDatabase(_TempStore):
    def test_stamp_records_without_running(self) -> None:
        # Legacy path built the schema; stamp adopts it into version control.
        store.init_db()
        self.assertEqual(migrations.status()["applied_revision"], 0)
        migrations.stamp(migrations.expected_revision())
        rows = self._recorded()
        self.assertEqual([r["revision"] for r in rows], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22])
        self.assertIn("(stamped)", rows[0]["name"])
        migrations.verify_or_raise()  # adopted DB now passes the gate

    def test_legacy_init_db_then_upgrade_converges(self) -> None:
        # A DB built by the legacy path upgrades cleanly (baseline DDL is
        # convergent), ending with recorded history.
        store.init_db()
        final = migrations.upgrade()
        self.assertEqual(final, migrations.expected_revision())


@unittest.skipIf(db.is_postgres(), "temp-file isolation is SQLite-specific")
class StartupPolicy(_TempStore):
    def test_migrations_cli_flag_keeps_import_inert(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_MIGRATIONS_CLI": "1"}):
            store.ensure_schema_ready()
        self.assertEqual(migrations.status()["applied_revision"], 0)

    def test_production_startup_refuses_unmigrated(self) -> None:
        env = {"DSPM_ENV": "production"}
        with mock.patch.dict(os.environ, env):
            os.environ.pop("DSPM_MIGRATIONS_CLI", None)
            with self.assertRaisesRegex(RuntimeError, "Refusing to serve"):
                store.ensure_schema_ready()

    def test_dev_startup_auto_upgrades(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_ENV": "local"}):
            os.environ.pop("DSPM_MIGRATIONS_CLI", None)
            store.ensure_schema_ready()
        self.assertEqual(
            migrations.status()["applied_revision"], migrations.expected_revision()
        )


if __name__ == "__main__":
    unittest.main()
