"""C10: no transaction reaches a tenant's rows without saying whose they are.

The gate: "Unscoped SQL is denied; scheduled/worker flows still run; erased tenant
cannot be found in Meilisearch or the authoritative store." Before C10 the policies
read an unset tenant scope as "every tenant", and the background writers depended on
it. Now a transaction names a tenant or a platform purpose, and each tenant table
admits only the purposes that need it (store.PLATFORM_ACCESS).

The classification tests run on both databases; the policy tests need PostgreSQL.
"""

from __future__ import annotations

import inspect
import json
import os
import re
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
from uuid import uuid4

import httpx

from backend import db, migrations, search, store


class EveryStoreFunctionHasAScopeTest(unittest.TestCase):
    """A function added later cannot forget: it is tenant-first, or it says its purpose,
    or it says it touches no tenant table."""

    def test_every_database_function_is_classified(self) -> None:
        unclassified = []
        for name, func in inspect.getmembers(store, inspect.isfunction):
            if func.__module__ != "backend.store":
                continue
            raw = inspect.unwrap(func)
            params = list(inspect.signature(raw).parameters)
            if params and params[0] == "conn":
                continue   # revisions and helpers run inside a caller's transaction
            if "_connect()" not in inspect.getsource(raw):
                continue
            classified = (
                (params and params[0] == "tenant_id")
                or name in store.PLATFORM_FUNCTIONS
                or name in store.NO_TENANT_TABLES
                or name in store.SCOPED_INSIDE
            )
            if not classified:
                unclassified.append(name)
        self.assertEqual(unclassified, [], "a store function that reaches the database with no scope")

    def test_the_scopes_are_applied(self) -> None:
        for name, purpose in store.PLATFORM_FUNCTIONS.items():
            with self.subTest(name=name):
                self.assertEqual(getattr(getattr(store, name), "_platform_purpose", None), purpose)
        self.assertTrue(getattr(store.list_inventory, "_tenant_scoped", False))
        self.assertTrue(getattr(store.save_scan_history, "_tenant_scoped", False))
        for name in store.ALL_TENANTS_PURPOSE:
            self.assertTrue(getattr(getattr(store, name), "_tenant_scoped", False), name)

    def test_a_tenant_first_function_runs_in_its_tenants_scope(self) -> None:
        # What each function's transaction would be told, read where it opens one.
        observed = []
        with mock.patch.object(store, "_connect", side_effect=lambda: observed.append(
                (db.current_tenant_scope(), db.current_platform_scope())) or (_ for _ in ()).throw(RuntimeError("stop"))):
            for call in (lambda: store.list_suppression_rules("tenant-x"), lambda: store.claim_due_schedules(),
                         lambda: store.list_users(None), lambda: store.list_users("tenant-y"),
                         lambda: migrations.upgrade()):
                with self.assertRaises(RuntimeError):
                    call()
        self.assertEqual(observed, [("tenant-x", None), (None, "scheduler"), (None, "platform-admin"), ("tenant-y", None),
                                    (None, "migration")])

    def test_the_policy_map_is_what_was_decided(self) -> None:
        self.assertEqual({table: sorted(purposes) for table, purposes in store.PLATFORM_ACCESS.items()}, {
            "users": ["auth", "platform-admin"],
            "api_keys": ["auth"],
            "user_mfa": ["auth", "vault"],
            "secrets": ["vault"],
            "registration_invites": ["auth"],
            "scan_schedules": ["scheduler"],
            "audit_outbox": ["siem"],
            "audit_events": ["housekeeping", "platform-admin"],
            "audit_chain_heads": ["housekeeping"],
            "alert_events": ["housekeeping", "platform-admin"],
            "derived_cache": ["housekeeping"],
            "scan_reports": ["housekeeping", "platform-admin"],
            "scan_jobs": ["housekeeping", "resume"],
            "partitioned_scans": ["resume"],
            "scan_partitions": ["housekeeping", "resume"],
            "assets": ["housekeeping", "search-indexer"],
            # D7: the demo-sample purge removes an asset's access rows with it
            "asset_access": ["housekeeping"],
            # D3: the deliverer spans workspaces; retention prunes old deliveries
            "alert_deliveries": ["delivery", "housekeeping"],
            "finding_tickets": ["delivery"],
        })
        every = {purpose for purposes in store.PLATFORM_ACCESS.values() for purpose in purposes}
        self.assertLessEqual(every | {"migration", "backup"}, set(db.PLATFORM_PURPOSES))

    def test_an_unknown_purpose_is_refused_and_a_tenant_inside_one_wins(self) -> None:
        with self.assertRaises(ValueError):
            with db.platform_scope("everything"):
                pass
        with db.platform_scope("scheduler"):
            with db.tenant_scope("t1"):
                self.assertEqual(db.current_tenant_scope(), "t1")
            self.assertIsNone(db.current_tenant_scope())
        predicate = store.tenant_policy_predicate("assets")
        self.assertNotIn("'*'", predicate, "'*' no longer means every tenant")
        self.assertIn("'search-indexer'", predicate)
        self.assertIn("'migration'", store.tenant_policy_predicate("secrets"))
        self.assertNotIn("'auth'", store.tenant_policy_predicate("secrets"))


def _seed(tenant: str) -> None:
    store.create_tenant(tenant, tenant)
    store.save_scan_history(tenant, {
        "scan_id": f"{tenant}-scan", "source": "smb", "summary": {"total_files": 1},
        "files": [{"path": f"/{tenant}/ledger.xlsx", "name": f"{tenant}-ledger.xlsx",
                   "risk": {"level": "HIGH", "score": 80},
                   "findings": [{"type": "email", "risk": "HIGH", "count": 1}]}],
    })


@unittest.skipUnless(db.is_postgres(), "row-level security is PostgreSQL's")
class UnscopedSqlIsDeniedTest(unittest.TestCase):

    def setUp(self) -> None:
        self.a, self.b = f"ps-a-{uuid4().hex[:6]}", f"ps-b-{uuid4().hex[:6]}"
        for tenant in (self.a, self.b):
            _seed(tenant)

    def _count(self, table: str) -> int:
        with store._connect() as conn:
            return int(conn.execute(f'SELECT COUNT(*) AS n FROM "{table}" WHERE tenant_id IN (?, ?)',
                                    (self.a, self.b)).fetchone()["n"])

    def test_a_transaction_that_names_no_one_sees_nothing_and_writes_nothing(self) -> None:
        self.assertEqual(self._count("assets"), 0)
        self.assertEqual(self._count("scan_reports"), 0)
        with self.assertRaises(Exception) as refused:
            with store._connect() as conn:
                conn.execute("INSERT INTO suppression_rules (tenant_id, rule_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
                             (self.a, uuid4().hex, "2026-01-01", "2026-01-01"))
        self.assertIn("row-level security", str(refused.exception))
        # '*' was the old "every tenant"; set by hand - or as a role default - it is no one.
        with store._connect() as conn:
            conn.execute("SELECT set_config('app.tenant_id', '*', true)")
            self.assertEqual(int(conn.execute("SELECT COUNT(*) AS n FROM assets WHERE tenant_id IN (?, ?)",
                                              (self.a, self.b)).fetchone()["n"]), 0)

    def test_a_tenant_sees_its_own_rows(self) -> None:
        with db.tenant_scope(self.a):
            self.assertEqual(self._count("assets"), 1)

    def test_each_purpose_reaches_only_its_tables(self) -> None:
        expectations = {
            "search-indexer": {"assets": 2, "users": 0, "audit_outbox": 0, "secrets": 0},
            "scheduler": {"assets": 0, "scan_reports": 0},
            "siem": {"assets": 0, "users": 0},
            "auth": {"assets": 0, "scan_reports": 0, "secrets": 0},
            "housekeeping": {"scan_reports": 2, "secrets": 0, "users": 0},
        }
        for purpose, tables in expectations.items():
            with db.platform_scope(purpose):
                for table, expected in tables.items():
                    with self.subTest(purpose=purpose, table=table):
                        self.assertEqual(self._count(table), expected)

    def test_every_policy_on_the_database_is_the_one_the_code_writes(self) -> None:
        with store._connect() as conn:
            rows = conn.execute("SELECT tablename, qual FROM pg_policies WHERE schemaname = current_schema() "
                                "AND policyname = 'tenant_isolation'").fetchall()
        self.assertGreaterEqual(len(rows), 25)
        for row in rows:
            with self.subTest(table=row["tablename"]):
                self.assertIn("app.platform", row["qual"])
                self.assertNotIn("'*'", row["qual"])
                # The live policy admits exactly the purposes the code says - a map changed
                # without a revision to rebuild the policies shows here.
                admitted = set(re.findall(r"'([a-z-]+)'::text", row["qual"]))
                # every table admits a migration and a whole-database backup (revision 0030)
                expected = set(store.PLATFORM_ACCESS.get(row["tablename"], frozenset())) | {"migration", "backup"}
                self.assertEqual(admitted & set(db.PLATFORM_PURPOSES), expected)


@unittest.skipUnless(db.is_postgres(), "row-level security is PostgreSQL's")
class TheBackgroundWorkStillRunsTest(unittest.TestCase):
    """Scheduled and worker flows, each under its own purpose, across two tenants."""

    def setUp(self) -> None:
        self.tenants = [f"bg-{uuid4().hex[:6]}" for _ in range(2)]
        for tenant in self.tenants:
            _seed(tenant)

    def test_the_scheduler_claims_due_work_in_every_tenant(self) -> None:
        for tenant in self.tenants:
            store.create_scan_schedule(tenant, name="due", request={"local_path": "C:/x"}, created_by="t",
                                       first_run_at=datetime.now(timezone.utc) - timedelta(minutes=1))
        claimed = {row["tenant_id"] for row in store.claim_due_schedules(limit=10)}
        self.assertLessEqual(set(self.tenants), claimed)

    def test_the_siem_drain_reads_every_tenants_outbox(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_SIEM_URL": "tcp://127.0.0.1:9"}):
            for tenant in self.tenants:
                store.audit(tenant, "tester", "bg.queued", {})
        claimed = store.claim_audit_outbox(limit=100, now=9e12, lease_seconds=60, owner="c10")
        self.assertLessEqual(set(self.tenants), {row["tenant_id"] for row in claimed})

    def test_the_search_indexer_reads_every_tenants_assets(self) -> None:
        seen = {asset["tenant_id"] for batch in store.iter_search_asset_batches(200) for asset in batch}
        self.assertLessEqual(set(self.tenants), seen)

    def test_housekeeping_and_resume_run(self) -> None:
        with db.tenant_scope(self.tenants[0]), store._connect() as conn:
            conn.execute("INSERT INTO scan_jobs (id, tenant_id, status, progress, message, created_at, finished_at, "
                         "error, updated_at) VALUES (?, ?, 'completed', 100, 'Completed', ?, ?, NULL, ?)",
                         (f"{self.tenants[0]}-old", self.tenants[0], "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z",
                          "2020-01-01T00:00:00Z"))
        store.record_job({"id": f"{self.tenants[1]}-run", "tenant_id": self.tenants[1], "status": "running",
                          "created_at": "2020-01-01T00:00:00Z"})
        store.prune_job_records(86400)
        self.assertIsNone(store.read_job(self.tenants[0], f"{self.tenants[0]}-old"))
        store.recover_interrupted_jobs()
        self.assertEqual(store.read_job(self.tenants[1], f"{self.tenants[1]}-run")["status"], "failed")
        self.assertIsInstance(store.list_unfinished_partitioned_scans(), list)
        self.assertTrue(all(result["ok"] for result in store.verify_audit_chain()))


class _FakeMeilisearch:
    """Just enough of Meilisearch: an index of documents, delete by tenant filter, search
    filtered by tenant, and tasks that succeed. Down when `down` is set."""

    def __init__(self) -> None:
        self.documents: dict[str, dict] = {}
        self.down = False
        self._task = 0

    def _accepted(self) -> httpx.Response:
        self._task += 1
        return httpx.Response(202, json={"taskUid": self._task})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("down", request=request)
        path, body = request.url.path, json.loads(request.content or b"{}")
        if path.startswith("/tasks/"):
            return httpx.Response(200, json={"status": "succeeded"})
        if path == "/indexes" or path.endswith("/settings"):
            return self._accepted()
        if path.endswith("/documents/delete"):
            tenant = re.search(r'tenant_id = "([^"]*)"', body["filter"]).group(1)
            self.documents = {key: doc for key, doc in self.documents.items() if doc["tenant_id"] != tenant}
            return self._accepted()
        if path.endswith("/documents"):
            for doc in body:
                self.documents[doc["id"]] = doc
            return self._accepted()
        if path.endswith("/search"):
            tenant = re.search(r'tenant_id = "([^"]*)"', body["filter"]).group(1)
            hits = [doc for doc in self.documents.values() if doc["tenant_id"] == tenant]
            return httpx.Response(200, json={"hits": hits, "estimatedTotalHits": len(hits)})
        return httpx.Response(404, json={"code": "not_found"})


class AnErasedTenantIsFoundNowhereTest(unittest.TestCase):
    """The optional index is part of erasure, and when it is down the database answers."""

    ENV = {"DSPM_SEARCH_ENGINE": "meilisearch", "DSPM_MEILISEARCH_URL": "http://meili.test",
           "DSPM_SEARCH_READ_ENABLED": "1"}

    def setUp(self) -> None:
        self.fake = _FakeMeilisearch()
        env = mock.patch.dict(os.environ, self.ENV)
        env.start()
        self.addCleanup(env.stop)
        client = search.MeilisearchClient(search.config_from_env(), transport=httpx.MockTransport(self.fake))
        patcher = mock.patch.object(search, "_client", return_value=client)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.a, self.b = f"er-a-{uuid4().hex[:6]}", f"er-b-{uuid4().hex[:6]}"
        for tenant in (self.a, self.b):
            _seed(tenant)
        search.index_assets((asset for batch in store.iter_search_asset_batches(500) for asset in batch
                             if asset["tenant_id"] in (self.a, self.b)), wait=True)

    def _indexed(self, tenant: str) -> int:
        return sum(1 for doc in self.fake.documents.values() if doc["tenant_id"] == tenant)

    def _in_database(self, tenant: str) -> int:
        with db.tenant_scope(tenant), store._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) AS n FROM assets WHERE tenant_id = ?", (tenant,)).fetchone()["n"])

    def test_erasure_reaches_the_index_and_the_database(self) -> None:
        self.assertEqual((self._indexed(self.a), self._indexed(self.b)), (1, 1))
        usage = store.delete_tenant_with_data(self.a)
        self.assertEqual(usage["search_documents"], "removed")
        self.assertEqual((self._indexed(self.a), self._indexed(self.b)), (0, 1))
        self.assertEqual(self._in_database(self.a), 0)
        self.assertEqual(search.search_inventory(self.a, {"q": "ledger"}, "risk_score", "desc", "", 50)["items"], [])
        self.assertEqual(len(search.search_inventory(self.b, {"q": "ledger"}, "risk_score", "desc", "", 50)["items"]), 1)

    def test_with_the_index_down_the_database_answers_and_erasure_says_what_is_pending(self) -> None:
        store.delete_tenant_with_data(self.a)
        self.fake.down = True
        with mock.patch.object(store, "_inventory_ready", return_value=True):
            b = store.list_inventory(self.b, q="ledger")
            a = store.list_inventory(self.a, q="ledger")
        self.assertNotEqual(b.get("source"), "meilisearch")
        self.assertEqual([item["name"] for item in b["items"]], [f"{self.b}-ledger.xlsx"])
        self.assertEqual(a["items"], [])
        usage = store.delete_tenant_with_data(self.b)
        self.assertTrue(usage["search_documents"].startswith("pending"))
        self.assertEqual(self._in_database(self.b), 0, "the erasure itself stands")


if __name__ == "__main__":
    unittest.main()
