"""Row-level security isolation (roadmap Phase 4c, DB-03). PostgreSQL only.

Runs when the suite targets PostgreSQL (DSPM_DB_URL + DSPM_PG_TEST_RESET=1);
on SQLite these are skipped - RLS is a PostgreSQL engine control and SQLite
is a development backend behind the Phase 0 production gate.

The contract under test: inside db.tenant_scope(A), a query with NO tenant
predicate (or a hostile one) can neither read nor write tenant B; outside a
scope, behavior is unchanged ('*' default). The live rehearsal evidence in
docs/database/evidence/rls_rehearsal_*.json proves the same properties as
the unprivileged runtime role against real data.
"""

from __future__ import annotations

import unittest
from uuid import uuid4

from backend import db, store


@unittest.skipUnless(db.is_postgres(), "RLS is a PostgreSQL engine control")
class TenantRlsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant_a = f"rls-a-{uuid4().hex[:8]}"
        self.tenant_b = f"rls-b-{uuid4().hex[:8]}"
        for tenant in (self.tenant_a, self.tenant_b):
            store.create_tenant(tenant, tenant)
            self.addCleanup(store.delete_tenant_with_data, tenant)
            store.save_scan_history(tenant, {
                "scan_id": f"{tenant}-scan",
                "source": "smb",
                "summary": {"total_files": 1},
                "files": [{
                    "path": f"/{tenant}/doc.txt", "name": "doc.txt",
                    "risk": {"level": "HIGH", "score": 80},
                    "findings": [{"type": "email", "risk": "HIGH"}],
                }],
            })

    def test_scoped_transaction_cannot_read_other_tenants(self) -> None:
        with db.tenant_scope(self.tenant_a):
            with store._connect() as conn:
                # Predicate-free: policy confines the whole table view.
                tenants = {
                    str(row["tenant_id"]) for row in conn.execute(
                        "SELECT DISTINCT tenant_id FROM assets"
                    ).fetchall()
                }
                # Hostile predicate: asking for B explicitly yields nothing.
                leaked = conn.execute(
                    "SELECT COUNT(*) AS n FROM assets WHERE tenant_id = ?",
                    (self.tenant_b,),
                ).fetchone()
        self.assertEqual(tenants, {self.tenant_a})
        self.assertEqual(int(leaked["n"]), 0)

    def test_scoped_transaction_cannot_write_other_tenants(self) -> None:
        with db.tenant_scope(self.tenant_a):
            with self.assertRaises(Exception) as caught:
                with store._connect() as conn:
                    conn.execute(
                        "INSERT INTO audit_events (tenant_id, timestamp, actor, action, detail_json) "
                        "VALUES (?, '2026-09-02T00:00:00+00:00', 'attacker', 'x', '{}')",
                        (self.tenant_b,),
                    )
        self.assertIn("row-level security", str(caught.exception))

    def test_unscoped_behavior_is_unchanged(self) -> None:
        with store._connect() as conn:
            tenants = {
                str(row["tenant_id"]) for row in conn.execute(
                    "SELECT DISTINCT tenant_id FROM assets WHERE tenant_id IN (?, ?)",
                    (self.tenant_a, self.tenant_b),
                ).fetchall()
            }
        self.assertEqual(tenants, {self.tenant_a, self.tenant_b})

    def test_an_ended_scope_leaves_the_connection_unscoped(self) -> None:
        """Regression: after a SET LOCAL scope ends, PostgreSQL reverts the GUC
        to its session value, which for a never-set custom GUC is the EMPTY
        STRING - not NULL. A policy that only treated NULL as "no scope" left
        pooled connections denying every later unscoped statement, and the bug
        hid on any database where a role default of '*' had been set."""
        with db.tenant_scope(self.tenant_a):
            with store._connect() as conn:
                conn.execute("SELECT 1 AS one").fetchone()

        # The next transaction on that pooled connection must span tenants again.
        with store._connect() as conn:
            setting = conn.execute(
                "SELECT current_setting('app.tenant_id', true) AS s"
            ).fetchone()["s"]
            tenants = {
                str(row["tenant_id"]) for row in conn.execute(
                    "SELECT DISTINCT tenant_id FROM assets WHERE tenant_id IN (?, ?)",
                    (self.tenant_a, self.tenant_b),
                ).fetchall()
            }
            # And an unrelated write must still be permitted.
            conn.execute(
                "INSERT INTO audit_events (tenant_id, timestamp, actor, action, detail_json) "
                "VALUES (?, '2026-09-02T00:00:00+00:00', 'test', 'unscoped-write', '{}')",
                (self.tenant_b,),
            )
        self.assertIn(setting, (None, "", "*"), "scope must not persist past the transaction")
        self.assertEqual(tenants, {self.tenant_a, self.tenant_b})

    def test_store_reads_are_scoped_by_decorator(self) -> None:
        # list_inventory(A) runs inside tenant_scope(A); its result can only
        # ever contain A. This asserts the wiring, not just the policy.
        page = store.list_inventory(self.tenant_a, limit=10)
        paths = {str(item.get("path") or "") for item in page["items"]}
        self.assertTrue(all(f"/{self.tenant_a}/" in path for path in paths if path))
        facets = store.inventory_facets(self.tenant_b)
        self.assertEqual(facets["total"], 1)


if __name__ == "__main__":
    unittest.main()
