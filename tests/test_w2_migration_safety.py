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
    # Revision 52 (W4.6): when a scan was admitted.
    ("partitioned_scans", "admitted_at"),
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
            # Revision 53 (W4.4): the console's counts - their triggers, tables and sort indexes.
            from backend import estate_counts

            estate_counts.drop_triggers(conn)
            for table in ("estate_count_deltas", "estate_counts", "estate_count_state"):
                conn.execute(f"DROP TABLE IF EXISTS {table}")
            for index in (*store.REMEDIATION_SORT_INDEXES, *store.INVENTORY_SORT_INDEXES):
                conn.execute(f"DROP INDEX IF EXISTS {index}")
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
            self.assertEqual(indexes & set(store.UNUSABLE_SEARCH_INDEXES), set(), "revision 43 left a GIN index")
            self.assertEqual(indexes & set(store.PRESENCE_INDEXES), set(), "revision 49 left a presence index")
            self.assertLessEqual(set(store.REMEDIATION_SORT_INDEXES) | set(store.INVENTORY_SORT_INDEXES), indexes,
                                 "revision 53 left a sort unindexed")
        # Revision 53 counted what the old install held, and the triggers count from then on.
        drift = store.reconcile_estate_counts(self.tenant, repair=False)["drift"]
        self.assertEqual(drift["keys"], 0, f"the upgrade's counts are not the rows': {drift}")
        with db.tenant_scope(self.tenant), store._connect() as conn:
            self.assertGreater(int(conn.execute("SELECT COUNT(*) AS n FROM estate_counts WHERE tenant_id = ?",
                                                (self.tenant,)).fetchone()["n"] or 0), 0)
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


class ARevisionRunAgainLocksNothingTest(unittest.TestCase):
    """Revision 36 on a schema that has it, and revision 39 anywhere, write nothing and hold no
    lock that blocks a reader or a writer: re-running them is how every upgrade starts on an
    install that applied them (the runner re-checks the convergent schema), and revision 36's
    first form altered every byte column again - an exclusive lock on assets for each run."""

    _BLOCKING = ("ShareUpdateExclusiveLock", "ShareLock", "ShareRowExclusiveLock", "ExclusiveLock",
                 "AccessExclusiveLock")

    class _Recording:
        """The connection, with every statement run through it written down."""

        def __init__(self, conn, statements: list[str]) -> None:
            self._conn, self._statements = conn, statements

        def execute(self, sql, *args):
            self._statements.append(" ".join(str(sql).split()))
            return self._conn.execute(sql, *args)

        def __getattr__(self, name):
            return getattr(self._conn, name)

    def _run(self, revision) -> tuple[list[str], list[tuple[str, str]]]:
        statements: list[str] = []
        with store._connect() as conn, db.platform_scope("migration"):
            revision(self._Recording(conn, statements))
            held: list[tuple[str, str]] = []
            if db.is_postgres():
                held = [(str(row[0]), str(row[1])) for row in conn.execute(
                    "SELECT c.relname, l.mode FROM pg_locks l JOIN pg_class c ON c.oid = l.relation "
                    "WHERE l.pid = pg_backend_pid() AND l.mode = ANY(?)", (list(self._BLOCKING),)).fetchall()]
        return statements, held

    def setUp(self) -> None:
        if not db.is_postgres():
            temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
            self.addCleanup(temp.cleanup)
            original = store.DB_PATH
            store.DB_PATH = Path(temp.name) / "rerun.sqlite"
            self.addCleanup(setattr, store, "DB_PATH", original)
        migrations.upgrade()

    def test_revision_36_reads_and_alters_nothing_already_64_bit(self) -> None:
        statements, held = self._run(store.widen_byte_counts)
        self.assertEqual([sql for sql in statements if not sql.upper().startswith("SELECT")], [])
        self.assertEqual(held, [], "a re-run of revision 36 held a lock that blocks the estate tables")
        if db.is_postgres():
            self.assertEqual(len(statements), len(store._BYTE_COUNT_COLUMNS), "one type check per column")

    def test_revision_39_is_a_no_op(self) -> None:
        statements, held = self._run(store.add_asset_prune_index)
        self.assertEqual((statements, held), ([], []), "revision 39 builds an index revision 42 drops")
        with store._connect() as conn:
            self.assertNotIn("idx_assets_tenant_scan_label_current_id", _index_names(conn))


class AnInstallAtRevision48UpgradesTest(unittest.TestCase):
    """An install as revision 48 left it - with revision 0046's two indexes on the presence
    marker - upgrades to 49 keeping every row, and loses only those two indexes."""

    def setUp(self) -> None:
        revisions = migrations._revisions()
        if db.is_postgres():
            # sentro_test is taken back to 48's record and indexes; the cleanup converges it.
            self.addCleanup(migrations.upgrade)
            with store._connect() as conn, db.platform_scope("migration"):
                conn.execute("DELETE FROM schema_migrations WHERE revision > 48")
        else:
            temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
            self.addCleanup(temp.cleanup)
            original = store.DB_PATH
            store.DB_PATH = Path(temp.name) / "at48.sqlite"
            self.addCleanup(setattr, store, "DB_PATH", original)
            with patch.object(migrations, "_revisions", lambda: revisions[:48]):
                migrations.upgrade()
        with store._connect() as conn, db.platform_scope("migration"):
            conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_scan_content_hash "
                         "ON assets (tenant_id, current_scan_id, content_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_scan_risk ON assets (tenant_id, current_scan_id, risk_score)")
            self.assertEqual(migrations.current_revision(conn), 48)
        self.tenant = f"at48-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "At 48")
        store.save_scan_history(self.tenant, _report("s1", 5))
        store.save_scan_history(self.tenant, _report("s2", 3))

    def _counts(self) -> dict:
        with store._connect() as conn, db.platform_scope("migration"):
            return {table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in _COUNTED}

    def test_the_upgrade_keeps_every_row_and_drops_only_the_presence_indexes(self) -> None:
        before_rows = self._counts()
        with store._connect() as conn, db.platform_scope("migration"):
            before = _index_names(conn)
        self.assertLessEqual(set(store.PRESENCE_INDEXES), before)
        # The newest revision (0050, W4.1) also drops the redundant indexes an install has.
        self.assertEqual(migrations.upgrade(), migrations.expected_revision())
        with store._connect() as conn, db.platform_scope("migration"):
            after = _index_names(conn)
            self.assertEqual(migrations.current_revision(conn), migrations.expected_revision())
        # ... and revision 0054 (W5) the plain-column indexes the sort indexes replaced; revision
        # 0055 the access principal index its rank index leads with.
        self.assertEqual(before - after, set(store.PRESENCE_INDEXES) | (set(store.redundant_indexes()) & before)
                         | (set(store.SORTED_TWICE_INDEXES) & before) | (set(store.REPLACED_ACCESS_INDEXES) & before))
        # ... and revision 53's (W4.4): the sorts' indexes and the counts' own; and 0055's.
        from backend import estate_counts

        self.assertEqual(after - before, (set(store.UNIT_MANIFEST_INDEXES) | set(store.REMEDIATION_SORT_INDEXES)
                                          | set(store.INVENTORY_SORT_INDEXES) | set(estate_counts.INDEXES)
                                          | set(store.ACCESS_MODEL_INDEXES)) - before)
        self.assertEqual(self._counts(), before_rows)


class TheConvergedSchemaIsTheMigratedOneTest(unittest.TestCase):
    """A fresh install is built by the converged baseline (revision 0001) and then every later
    revision; an old install by the revisions alone. They must end with the same indexes - in
    particular none that revisions 0042, 0043, 0049 or 0050 dropped."""

    _DROPPED = {"idx_assets_tenant_scan_label_current_id", "idx_scan_object_baselines_generation",
                *store.UNUSABLE_SEARCH_INDEXES, *store.PRESENCE_INDEXES, *store.redundant_indexes(),
                *store.SORTED_TWICE_INDEXES}  # revision 0054 (W5)

    def _install(self, name: str, upto: int | None) -> set[str]:
        temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(temp.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(temp.name) / f"{name}.sqlite"
        try:
            revisions = migrations._revisions()
            if upto is not None:
                with patch.object(migrations, "_revisions", lambda: revisions[:upto]):
                    migrations.upgrade()
            migrations.upgrade()
            with store._connect() as conn:
                self.assertEqual(migrations.current_revision(conn), migrations.expected_revision())
                return {name for name in _index_names(conn) if not name.startswith("sqlite_autoindex")}
        finally:
            store.DB_PATH = original

    @unittest.skipIf(db.is_postgres(), "two private database files")
    def test_a_fresh_install_and_an_upgraded_one_have_the_same_indexes(self) -> None:
        fresh = self._install("fresh", None)
        from_37 = self._install("from37", 37)
        self.assertEqual(fresh & self._DROPPED, set())
        self.assertEqual(fresh, from_37)

    @unittest.skipUnless(db.is_postgres(), "the disposable PostgreSQL database")
    def test_converging_a_migrated_database_changes_no_index(self) -> None:
        with store._connect() as conn, db.platform_scope("migration"):
            before = _index_names(conn)
            store.apply_baseline_schema(conn)
            after = _index_names(conn)
        self.assertEqual(before & self._DROPPED, set())
        self.assertEqual(after, before)


@unittest.skipUnless(db.is_postgres(), "the disposable PostgreSQL database")
class APostgresInstallUpgradesWholeTest(_Upgrade, unittest.TestCase):
    """On sentro_test: its schema is taken back to revision 37's shape, then upgraded again -
    whatever the test's outcome, the cleanup converges it to this build's revision."""

    def setUp(self) -> None:
        self.addCleanup(migrations.upgrade)
        self._fill_scans()
        # This build's policies, counted before the install is taken back to 37's shape (which
        # drops revision 53's tables and so their policies): the upgrade must restore them all.
        with store._connect() as conn:
            self.policies = int(conn.execute("SELECT COUNT(*) FROM pg_policies WHERE schemaname = current_schema()")
                                .fetchone()[0])
        self._make_old_install()
        self._fill()

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
