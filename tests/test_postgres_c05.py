"""M1/C0.5: the migrations, isolation and roles, on a real PostgreSQL test database.

Runs only when the suite targets PostgreSQL (DSPM_DB_URL + DSPM_PG_TEST_RESET=1, a
dedicated disposable database - sentro_test). It holds the evidence C0.5 asks for that
the rest of the suite does not already give:

* the migration runner: a failing revision reports ITS OWN error and leaves no lock
  behind (a session advisory lock released in a `finally` used to hide the error and
  outlive the failure); every revision re-executes cleanly on the migrated schema;
* tenant isolation on every tenant-scoped table that holds rows - not only the assets
  and audit rows tests/test_tenant_rls.py covers - read, update and delete;
* the application role: not a superuser, no BYPASSRLS, bound by FORCEd RLS on the
  tables it owns;
* background writers - the schedule claim, the SIEM outbox drain - run unscoped and
  see every tenant, which is the fail-open C10 is to close.
"""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
from uuid import uuid4

from backend import db, migrations, store

# A floor: the test also requires every table with a tenant_id column, so a new tenant
# table the seed does not reach fails it rather than going unchecked.
REQUIRED_ISOLATED = {
    "assets", "findings", "scan_reports", "scan_runs", "audit_events", "audit_chain_heads",
    "audit_outbox", "suppression_rules", "scan_schedules", "partitioned_scans", "secrets", "custom_roles",
    "api_keys", "registration_invites", "derived_cache", "alert_events", "finding_index", "scan_jobs",
    "scan_object_baselines", "scan_partitions", "scan_profiles", "users", "scan_targets",
    # C2: a workspace's directory sign-in settings.
    "directory_settings",
    # C13: how each scan reached its files.
    "scan_sources",
    # D7: who can read each file; revision 0055: what changed in its permissions.
    "asset_access", "asset_acl_changes",
    # D2: exact-data-match reference sets.
    "edm_sets", "edm_fingerprints",
    # D3: where alerts go, what is waiting for them, and findings' tickets.
    "alert_channels", "alert_deliveries", "finding_tickets",
    # D5: delta checkpoints.
    "source_checkpoints",
    # W4.2: what an unchanged unit is skipped by, and the files it covers.
    "scan_unit_manifest", "scan_unit_coverage",
    # W4.4: the console's counts, their pending deltas and their reconcile state.
    "estate_counts", "estate_count_deltas", "estate_count_state",
}


@unittest.skipUnless(db.is_postgres(), "C0.5 is about PostgreSQL")
class TheMigrationRunnerTest(unittest.TestCase):

    def test_the_schema_is_at_the_expected_revision_with_every_control(self) -> None:
        info = migrations.status()
        self.assertEqual(info["applied_revision"], migrations.expected_revision())
        self.assertEqual(info["pending"], [])
        coverage = store.tenant_isolation_coverage()
        self.assertEqual((coverage["missing_foreign_key"], coverage["missing_rls"]), ([], []))
        self.assertGreaterEqual(coverage["scoped_tables"], 24)

    def test_a_failing_revision_reports_its_own_error_and_holds_no_lock(self) -> None:
        before = migrations.status()["applied_revision"]
        real = migrations._revisions

        def failing(conn) -> None:
            raise RuntimeError("revision 99 refused on purpose")

        with mock.patch.object(migrations, "_revisions", lambda: [*real(), (before + 1, "failing_on_purpose", failing)]):
            with self.assertRaises(RuntimeError) as raised:
                migrations.upgrade()
        self.assertIn("refused on purpose", str(raised.exception), "the revision's error, not 'transaction aborted'")
        self.assertEqual(migrations.status()["applied_revision"], before, "nothing recorded")
        with store._connect() as conn:
            held = conn.execute("SELECT COUNT(*) AS n FROM pg_locks WHERE locktype = 'advisory'").fetchone()["n"]
        self.assertEqual(int(held), 0, "the migration lock ended with the transaction")
        # And the next upgrade is not blocked by a lock the failure left behind.
        self.assertEqual(migrations.upgrade(), before)

    def test_every_revision_reexecutes_on_the_migrated_schema(self) -> None:
        failures = []
        context = store._connect()
        conn = context.__enter__()
        try:
            for number, name, func in migrations._revisions():
                conn.execute(f"SAVEPOINT rev_{number}")
                try:
                    func(conn)
                    conn.execute(f"RELEASE SAVEPOINT rev_{number}")
                except Exception as exc:  # noqa: BLE001 - collected
                    conn.execute(f"ROLLBACK TO SAVEPOINT rev_{number}")
                    failures.append(f"{number:04d} {name}: {type(exc).__name__}: {str(exc).splitlines()[0][:120]}")
        finally:
            conn._raw.rollback()
            context.__exit__(None, None, None)
        self.assertEqual(failures, [])


@unittest.skipUnless(db.is_postgres(), "C0.5 is about PostgreSQL")
class EveryTenantTableIsIsolatedTest(unittest.TestCase):
    """Rows for two tenants in every table the store writes, then tenant A's scope asked
    about tenant B's rows three ways. RLS is FORCEd, so the application role is bound
    even on the tables it owns."""

    def setUp(self) -> None:
        self.a, self.b = f"iso-a-{uuid4().hex[:6]}", f"iso-b-{uuid4().hex[:6]}"
        for tenant in (self.a, self.b):
            store.create_tenant(tenant, tenant)
            self._seed(tenant)

    def _seed(self, tenant: str) -> None:
        # An incremental scan, so the object baseline is written.
        store.save_scan_history(tenant, {
            "scan_id": f"{tenant}-scan", "source": "local", "timestamp": "2026-08-06T00:00:00Z",
            "mode": "incremental", "summary": {"total_files": 1},
            "scan_diagnostics": {"incremental": {"enabled": True, "baseline_update": True, "scope_key": "scope-a",
                                                 "version_signature": "policy-v1", "complete": True}},
            "files": [{"path": f"/{tenant}/doc.txt", "reuse_key": f"local:///{tenant}/doc.txt", "name": "doc.txt",
                       "size": 7, "modified_at": "2026-08-06T00:00:00Z", "content_hash": "hash-a",
                       "risk": {"level": "HIGH", "score": 80},
                       "acl": {"owner": "O", "principals": ["Everyone"], "permissions": ["Read"]},
                       "findings": [{"type": "email", "risk": "HIGH", "count": 1, "finding_id": f"{tenant}-f1"}]}],
        })
        store.record_job({"id": f"{tenant}-job", "tenant_id": tenant, "status": "running",
                          "created_at": "2026-08-06T00:00:00Z"})
        store.save_scan_profile(tenant, profile_id=None, kind="file-server", name="seed", config={"local_path": "C:/x"})
        store.create_user(f"{tenant}-user", "not-a-hash", "viewer", tenant)
        with mock.patch.dict(os.environ, {"DSPM_SIEM_URL": "tcp://127.0.0.1:9"}):
            store.audit(tenant, "tester", "iso.seeded", {})
        store.create_suppression_rule(tenant, finding_type="email", reason="seed", created_by="tester")
        store.create_scan_schedule(tenant, name="nightly", request={"local_path": "C:/x"}, created_by="tester")
        store.register_partitioned_scan(tenant, f"{tenant}-pscan", job_id=f"{tenant}-job", request={}, header={})
        store.create_scan_partitions(tenant, f"{tenant}-pscan", f"{tenant}-job", [{"part": 0}])
        store.save_secret(tenant, f"{tenant}-secret", "ciphertext-not-a-secret")
        store.save_custom_role(tenant, "isolation_role", "Isolation", "", ["inventory.view"], actor="tester")
        store.create_api_key_record(tenant, uuid4().hex, "seed", "viewer", "tester", None)
        store.create_registration_invite(tenant, uuid4().hex, "viewer", 1,
                                         (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(), False, "tester")
        store.derived_store(tenant, "iso-key", 1, "{}", 60)
        store.save_alert_channel(tenant, "webhook", enabled=True, config={"url": "https://hooks.example.test/x",
                                 "min_severity": "LOW"}, secret_ref="", actor="tester")
        store.save_alerts(tenant, f"{tenant}-scan", [{"kind": "seed"}])
        store.create_finding_ticket(tenant, f"{tenant}-ticket", f"{tenant}-finding", "jira", {"summary": "seed"}, "tester")
        store.save_source_checkpoint(tenant, f"sharepoint:{tenant}", {"drives": {}})
        store.add_scan_target(tenant, "network", "10.20.0.0/16", "seed", "tester")
        store.save_directory_settings(tenant, False, {"host": "dc.example.test"}, "", "tester")
        store.record_scan_source(tenant, f"{tenant}-scan", "smb", "fs1", "typed")
        store.create_edm_set(tenant, f"{tenant}-edm", "seed", "EMAIL_ADDRESS", ["f" * 64], "kd", "tester",
                             max_rows=10)
        # W3.5: a scan no longer writes these two; the tables stay until a later revision
        # drops them, and the rows an earlier scan left in them are still a tenant's. W4.1:
        # nor the finding index for an estate scan (only the demo dataset's scans write it).
        with db.tenant_scope(tenant), store._connect() as conn:
            conn.execute("INSERT INTO asset_versions (tenant_id, asset_id, version) VALUES (?, ?, ?)",
                         (tenant, f"{tenant}-asset", "v1"))
            conn.execute("INSERT INTO finding_occurrences (tenant_id, finding_id, scan_id) VALUES (?, ?, ?)",
                         (tenant, f"{tenant}-f1", f"{tenant}-scan"))
            conn.execute("INSERT INTO finding_index (tenant_id, scan_id, seq, finding_id, status, response_json, "
                         "index_version) VALUES (?, ?, 0, ?, 'OPEN', '{}', '')",
                         (tenant, f"{tenant}-scan", f"{tenant}-f1"))
            # W4.2: what an unchanged unit is skipped by, and the files it covers.
            conn.execute("INSERT INTO scan_unit_manifest (tenant_id, scope_key, unit_key, updated_at) "
                         "VALUES (?, 'scope-a', 'unit-1', '2026-10-08T00:00:00Z')", (tenant,))
            conn.execute("INSERT INTO scan_unit_coverage (tenant_id, scope_key, unit_key, folder_key) "
                         "VALUES (?, 'scope-a', 'unit-1', 'c:\\data')", (tenant,))
            # W4.4: the console's counts, their pending deltas and their reconcile state.
            conn.execute("INSERT INTO estate_counts (tenant_id, dim, k1, n) VALUES (?, 'f.status', 'OPEN', 1)",
                         (tenant,))
            conn.execute("INSERT INTO estate_count_deltas (tenant_id, dim, k1, n) VALUES (?, 'f.status', 'OPEN', 1)",
                         (tenant,))
            conn.execute("INSERT INTO estate_count_state (tenant_id, reconciled_at) VALUES (?, '2026-10-09T00:00:00Z')",
                         (tenant,))
            # Revision 0055: a permission change between two scans.
            conn.execute("INSERT INTO asset_acl_changes (tenant_id, id, asset_id, detected_at, summary) "
                         "VALUES (?, ?, ?, '2026-10-10T00:00:00Z', 'Everyone: gained read')",
                         (tenant, f"{tenant}-change", f"{tenant}-asset"))

    def _tenant_tables(self) -> list[str]:
        with db.platform_scope("migration"), store._connect() as conn:
            return [row["table_name"] for row in conn.execute(
                "SELECT DISTINCT table_name FROM information_schema.columns WHERE column_name = 'tenant_id' "
                "AND table_schema = current_schema() AND table_name <> 'tenants' ORDER BY table_name").fetchall()]

    def _tables_with_rows_for(self, tenant: str) -> list[str]:
        scoped = self._tenant_tables()
        # Counted as an operator would (C10: a transaction that names no one sees nothing).
        with db.platform_scope("migration"), store._connect() as conn:
            return [table for table in scoped
                    if conn.execute(f'SELECT COUNT(*) AS n FROM "{table}" WHERE tenant_id = ?', (tenant,)).fetchone()["n"]]

    def test_tenant_a_can_neither_read_nor_change_tenant_b(self) -> None:
        tables = self._tables_with_rows_for(self.b)
        self.assertEqual(sorted(REQUIRED_ISOLATED - set(tables)), [], "the seed must reach every required table")
        self.assertEqual(sorted(set(self._tenant_tables()) - set(tables)), [],
                         "a tenant table the seed does not reach is a table this test does not check")
        leaks = []
        for table in tables:
            with db.tenant_scope(self.a):
                context = store._connect()
                conn = context.__enter__()
                try:
                    seen = conn.execute(f'SELECT COUNT(*) AS n FROM "{table}" WHERE tenant_id = ?', (self.b,)).fetchone()["n"]
                    updated = conn.execute(f'UPDATE "{table}" SET tenant_id = tenant_id WHERE tenant_id = ?', (self.b,)).rowcount
                    deleted = conn.execute(f'DELETE FROM "{table}" WHERE tenant_id = ?', (self.b,)).rowcount
                finally:
                    conn._raw.rollback()   # nothing here is kept, whatever it did
                    context.__exit__(None, None, None)
            if seen or updated or deleted:
                leaks.append((table, seen, updated, deleted))
        self.assertEqual(leaks, [], "(table, rows seen, updated, deleted) of the other tenant")
        self.assertGreaterEqual(len(tables), len(REQUIRED_ISOLATED))

    def test_a_write_into_another_tenant_is_refused_by_the_policy(self) -> None:
        with db.tenant_scope(self.a):
            with self.assertRaises(Exception) as refused:
                with store._connect() as conn:
                    conn.execute("INSERT INTO suppression_rules (tenant_id, rule_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
                                 (self.b, uuid4().hex, datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()))
        self.assertIn("row-level security", str(refused.exception))


@unittest.skipUnless(db.is_postgres(), "C0.5 is about PostgreSQL")
class TheApplicationRoleTest(unittest.TestCase):

    def test_it_holds_no_privilege_that_would_bypass_isolation(self) -> None:
        with store._connect() as conn:
            role = conn.execute(
                "SELECT rolsuper, rolbypassrls, rolcreaterole FROM pg_roles WHERE rolname = current_user").fetchone()
            owner_bound = conn.execute(
                "SELECT COUNT(*) AS n FROM pg_class WHERE relnamespace = current_schema()::regnamespace "
                "AND relrowsecurity AND NOT relforcerowsecurity").fetchone()["n"]
        self.assertEqual((role["rolsuper"], role["rolbypassrls"], role["rolcreaterole"]), (False, False, False))
        self.assertEqual(int(owner_bound), 0, "every RLS table FORCEs it, so owning a table grants no way round")


@unittest.skipUnless(db.is_postgres(), "C0.5 is about PostgreSQL")
class BackgroundWritersTest(unittest.TestCase):
    """The writers no request starts run without a tenant scope. Today that sees every
    tenant (fail-open by design until C10); what matters here is that they work at all
    under the application role on PostgreSQL."""

    def test_the_schedule_claim_takes_due_work_from_every_tenant(self) -> None:
        tenants = [f"bg-{uuid4().hex[:6]}" for _ in range(2)]
        for tenant in tenants:
            store.create_tenant(tenant, tenant)
            store.create_scan_schedule(tenant, name="due", request={"local_path": "C:/x"}, created_by="tester",
                                       first_run_at=datetime.now(timezone.utc) - timedelta(minutes=1))
        claimed = store.claim_due_schedules(limit=10)
        self.assertEqual(sorted({row["tenant_id"] for row in claimed} & set(tenants)), sorted(tenants))
        self.assertEqual(store.claim_due_schedules(limit=10), [], "claimed once")

    def test_the_siem_drain_reads_the_outbox_of_every_tenant(self) -> None:
        tenants = [f"bg-{uuid4().hex[:6]}" for _ in range(2)]
        with mock.patch.dict(os.environ, {"DSPM_SIEM_URL": "tcp://127.0.0.1:9"}):
            for tenant in tenants:
                store.create_tenant(tenant, tenant)
                store.audit(tenant, "tester", "bg.queued", {})
            claimed = store.claim_audit_outbox(limit=50, now=9e12, lease_seconds=60, owner="c05")
        self.assertEqual(sorted({row["tenant_id"] for row in claimed} & set(tenants)), sorted(tenants))


@unittest.skipUnless(db.is_postgres(), "C0.5 is about PostgreSQL")
class APartitionWorkerKeepsToItsOwnDatabaseTest(unittest.TestCase):
    """discovery.partition's worker processes scan into a throwaway SQLite file. With
    DSPM_DB_URL inherited they converged the SHARED schema instead, all at once and outside
    the migration lock - three of them deadlocked on its backfill - and created their
    tenant here. Deterministic where the deadlock was not: the tenant must not appear."""

    def test_the_workers_scan_and_leave_the_shared_database_alone(self) -> None:
        import shutil
        import tempfile
        from pathlib import Path

        from discovery.discovery_engine import ScanConfig
        from discovery.partition import run_partitioned

        tenant = f"pw-{uuid4().hex[:8]}"
        # Under the repository: the collector does not scan a user's Temp folder.
        scratch = Path(__file__).resolve().parent.parent / "tmp"
        scratch.mkdir(exist_ok=True)
        root = Path(tempfile.mkdtemp(prefix="c05-partition-", dir=scratch))
        try:
            for name in ("a", "b"):
                (root / name).mkdir()
                (root / name / "note.txt").write_text("contact jane.doe@example.com\n", encoding="utf-8")
            config = ScanConfig(tenant_id=tenant, local_path=str(root), max_depth=3, walk_local_path=True,
                                persistent_cache_enabled=False, incremental_enabled=False)
            report = run_partitioned(config, workers=2)
        finally:
            shutil.rmtree(root, ignore_errors=True)
        self.assertEqual(report["scan_diagnostics"]["partitioned"]["worker_processes"], 2)
        self.assertEqual(report["summary"]["total_files"], 2, "the workers scanned")
        self.assertFalse(store.tenant_exists(tenant), "a worker wrote into the shared database")


if __name__ == "__main__":
    unittest.main()
