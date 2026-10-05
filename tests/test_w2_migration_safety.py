"""Upgrading a real install across revisions 36-40 keeps its data, and fails as a whole.

A database built by this build already has revisions 39 and 40's objects: the convergent
baseline creates them. An install made before revision 38 does not, and still holds the
two-step sign-in tables revision 38 removes. These tests build that install - at revision
37, with the old objects put back and the new ones taken away - fill it, and upgrade it.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from backend import db, migrations, store

_OLD_USER_MFA_DDL = """CREATE TABLE IF NOT EXISTS user_mfa (
    username TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    secret_ciphertext TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 0,
    confirmed_at TEXT,
    last_step INTEGER NOT NULL DEFAULT 0,
    recovery_hashes TEXT NOT NULL DEFAULT '[]',
    pending_ciphertext TEXT NOT NULL DEFAULT '',
    pending_expires_at INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
)"""
_COUNTED = ("tenants", "users", "user_sessions", "scan_reports", "assets", "findings", "finding_index")


def _report(scan_id: str, count: int) -> dict:
    files = []
    for index in range(count):
        name = f"f{index}.txt"
        files.append({"path": f"//fs01/finance/{name}", "name": name, "extension": ".txt", "size": 10,
                      "modified_at": "2026-09-01T00:00:00+00:00", "risk": {"level": "HIGH", "score": 80},
                      "findings": [{"finding_id": f"f-{scan_id}-{name}", "type": "email", "risk": "HIGH",
                                    "framework": "gdpr", "count": 1, "status": "OPEN"}]})
    return {"scan_id": scan_id, "source": "smb", "summary": {}, "scan_label": "finance",
            "timestamp": "2026-09-01T00:00:00+00:00", "files": files}


_REVISION_41_COLUMNS = (
    ("scan_jobs", "owner_host"), ("scan_jobs", "owner_pid"), ("scan_jobs", "owner_instance"),
    ("scan_jobs", "heartbeat_at"), ("scan_jobs", "cancel_requested"), ("scan_jobs", "resumes"),
    ("scan_schedules", "last_job_id"),
    # Revision 42 (W2.1): the row digests.
    ("assets", "row_digest"), ("findings", "row_digest"), ("scan_object_baselines", "snapshot_digest"),
)


def _index_names(conn) -> set[str]:
    if db.is_postgres():
        rows = conn.execute("SELECT indexname AS name FROM pg_indexes WHERE schemaname = current_schema()").fetchall()
    else:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'").fetchall()
    return {str(row["name"]) for row in rows}


class _Upgrade:
    """What every upgrade test does: an install as revision 37 left it, filled, upgraded."""

    tenant: str

    def _make_old_install(self) -> None:
        with store._connect() as conn, db.platform_scope("migration"):
            conn.execute("DROP INDEX IF EXISTS idx_findings_tenant_lifecycle")
            conn.execute("DROP INDEX IF EXISTS idx_assets_tenant_scan_label_current_id")
            if "lifecycle_json" in db.table_columns(conn, "findings"):
                conn.execute("ALTER TABLE findings DROP COLUMN lifecycle_json")
            conn.execute(_OLD_USER_MFA_DDL)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_user_mfa_tenant ON user_mfa (tenant_id)")
            for table in ("user_sessions", "refresh_tokens"):
                if "mfa_verified" not in db.table_columns(conn, table):
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN mfa_verified INTEGER NOT NULL DEFAULT 0")
            # Revision 41 (W2.4): job ownership and the schedule's last job.
            conn.execute("DROP INDEX IF EXISTS idx_scan_jobs_status")
            for table, column in _REVISION_41_COLUMNS:
                if column in db.table_columns(conn, table):
                    conn.execute(f"ALTER TABLE {table} DROP COLUMN {column}")
            # Revision 42 dropped the generation index the baseline schema had at 37.
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_object_baselines_generation "
                         "ON scan_object_baselines (tenant_id, scope_key, last_scan_id)")
            conn.execute("DELETE FROM schema_migrations WHERE revision > 37")

    def _fill_scans(self) -> None:
        # Written by this build's code while the schema is still whole: the old install is
        # shaped afterwards, and the rows written here are what the upgrade must keep.
        self.tenant = f"upgrade-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "Upgrade")
        store.save_scan_history(self.tenant, _report("s1", 5))
        store.save_scan_history(self.tenant, _report("s2", 3))

    def _fill(self) -> None:
        with store._connect() as conn, db.platform_scope("migration"):
            conn.execute("INSERT INTO users (username, tenant_id, password_hash, role, created_at, updated_at) "
                         "VALUES (?, ?, 'x', 'analyst', '2026-09-01', '2026-09-01')", (f"ana-{self.tenant}", self.tenant))
            conn.execute("INSERT INTO user_mfa (username, tenant_id, secret_ciphertext, enabled, updated_at) "
                         "VALUES (?, ?, 'sealed', 1, '2026-09-01')", (f"ana-{self.tenant}", self.tenant))
            conn.execute("INSERT INTO user_sessions (jti, username, issued_at, expires_at, last_seen_at, mfa_verified) "
                         "VALUES (?, ?, 1, 2000000000, 1, 1)", (f"jti-{self.tenant}", f"ana-{self.tenant}"))

    def _counts(self) -> dict:
        with store._connect() as conn, db.platform_scope("migration"):
            return {table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                    for table in _COUNTED}

    def _assert_upgraded(self, before: dict) -> None:
        self.assertEqual(migrations.upgrade(), migrations.expected_revision())
        with store._connect() as conn, db.platform_scope("migration"):
            self.assertEqual(migrations.current_revision(conn), migrations.expected_revision())
            self.assertNotIn("mfa_verified", db.table_columns(conn, "user_sessions"))
            self.assertNotIn("mfa_verified", db.table_columns(conn, "refresh_tokens"))
            self.assertEqual(db.table_columns(conn, "user_mfa"), set(), "revision 38 left the MFA secrets")
            self.assertIn("lifecycle_json", db.table_columns(conn, "findings"))
            for table, column in _REVISION_41_COLUMNS:
                self.assertIn(column, db.table_columns(conn, table))
            indexes = _index_names(conn)
            self.assertNotIn("idx_scan_object_baselines_generation", indexes)
            self.assertNotIn("idx_assets_tenant_scan_label_current_id", indexes)
            self.assertEqual(int(conn.execute("SELECT COUNT(*) FROM findings WHERE lifecycle_json <> ''")
                                 .fetchone()[0]), 0)
        self.assertEqual(self._counts(), before, "the upgrade lost or added rows")
        migrations.verify_or_raise()
        with store._connect() as conn:
            # The revisions this upgrade applied record this build's source.
            self.assertEqual([item["revision"] for item in migrations.checksum_drift(conn)
                              if item["revision"] > 37], [])
        # The upgraded install serves: a finding reads and takes an analyst action.
        with store._connect() as conn:
            finding_id = str(conn.execute("SELECT id FROM findings WHERE tenant_id = ? AND is_current = 1",
                                          (self.tenant,)).fetchone()["id"])
        store.update_finding_lifecycle(self.tenant, finding_id, "comment", {"comment": "after upgrade"}, "ana")
        self.assertEqual(store.get_finding(self.tenant, finding_id)["comments"][0]["comment"], "after upgrade")

    def _assert_failed_upgrade_changes_nothing(self) -> None:
        def boom(_conn) -> None:
            raise RuntimeError("a revision failed")

        revisions = migrations._revisions()
        failing = [*revisions, (revisions[-1][0] + 1, "fails_on_purpose", boom)]
        with patch.object(migrations, "_revisions", lambda: failing),                 self.assertRaisesRegex(RuntimeError, "a revision failed"):
            migrations.upgrade()
        with store._connect() as conn, db.platform_scope("migration"):
            self.assertEqual(migrations.current_revision(conn), 37, "part of a failed upgrade was recorded")
            self.assertIn("mfa_verified", db.table_columns(conn, "user_sessions"),
                          "revision 38 ran outside the upgrade's transaction")
            self.assertEqual(int(conn.execute("SELECT COUNT(*) FROM user_mfa").fetchone()[0]), 1)
            self.assertNotIn("lifecycle_json", db.table_columns(conn, "findings"))


@unittest.skipIf(db.is_postgres(), "a private database file")
class AnSqliteInstallUpgradesWholeTest(_Upgrade, unittest.TestCase):

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(temp.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(temp.name) / "upgrade.sqlite"
        self.addCleanup(setattr, store, "DB_PATH", original)
        revisions = migrations._revisions()
        with patch.object(migrations, "_revisions", lambda: revisions[:37]):
            migrations.upgrade()
        self._fill_scans()
        self._make_old_install()
        self._fill()

    def test_the_upgrade_keeps_every_row_and_removes_only_the_mfa_data(self) -> None:
        self._assert_upgraded(self._counts())

    def test_a_failed_upgrade_changes_nothing_and_a_retry_completes(self) -> None:
        before = self._counts()
        self._assert_failed_upgrade_changes_nothing()
        self._assert_upgraded(before)


@unittest.skipUnless(db.is_postgres(), "the disposable PostgreSQL database")
class APostgresInstallUpgradesWholeTest(_Upgrade, unittest.TestCase):
    """On sentro_test: its schema is taken back to revision 37's shape, then upgraded again -
    whatever the test's outcome, the cleanup converges it to this build's revision."""

    def setUp(self) -> None:
        self.addCleanup(migrations.upgrade)
        self._fill_scans()
        self._make_old_install()
        self._fill()
        with store._connect() as conn:
            self.policies = int(conn.execute("SELECT COUNT(*) FROM pg_policies WHERE schemaname = current_schema()")
                                .fetchone()[0])

    def _assert_rls_unchanged(self) -> None:
        with store._connect() as conn:
            self.assertEqual(int(conn.execute("SELECT COUNT(*) FROM pg_policies WHERE schemaname = current_schema()")
                                 .fetchone()[0]), self.policies)
            forced = {row[0] for row in conn.execute(
                "SELECT relname FROM pg_class WHERE relname IN ('assets', 'findings', 'finding_index') "
                "AND relrowsecurity AND relforcerowsecurity").fetchall()}
        self.assertEqual(forced, {"assets", "findings", "finding_index"})

    def test_the_upgrade_keeps_every_row_and_removes_only_the_mfa_data(self) -> None:
        self._assert_upgraded(self._counts())
        self._assert_rls_unchanged()

    def test_a_failed_upgrade_changes_nothing_and_a_retry_completes(self) -> None:
        before = self._counts()
        self._assert_failed_upgrade_changes_nothing()
        self._assert_upgraded(before)
        self._assert_rls_unchanged()
