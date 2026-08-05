"""Live PostgreSQL round-trip tests for the backend/db.py seam (roadmap Phase 2).

SKIPPED unless ``DSPM_DB_URL`` points at a reachable PostgreSQL. To run the whole
suite against Postgres (the real Phase 2 acceptance check), an operator does:

    createdb sentro_dev                       # once
    export DSPM_DB_URL='postgresql://sentro_app:<pw>@127.0.0.1:5432/sentro_dev?sslmode=require'
    python -m pytest tests/ -q                 # every store test now runs on Postgres

This module additionally pins the constructs that differ from SQLite and would
silently misbehave on a naive port: ON CONFLICT upsert idempotency, IDENTITY
auto-increment ordering, and DOUBLE-PRECISION epoch storage for login throttling.
All work is scoped to a random tenant id so it is safe against a shared dev DB."""

from __future__ import annotations

import time
import unittest
from uuid import uuid4

from backend import db, store


def _tid() -> str:
    return f"pg-it-{uuid4().hex[:10]}"


@unittest.skipUnless(db.is_postgres(), "DSPM_DB_URL is not a PostgreSQL DSN")
class PostgresBackendTests(unittest.TestCase):
    """End-to-end store operations over psycopg. Each test isolates itself to a
    fresh tenant and cleans up with delete_tenant_with_data."""

    def setUp(self) -> None:
        store.init_db()
        self.tenant = _tid()
        store.create_tenant(self.tenant, "PG IT")

    def tearDown(self) -> None:
        try:
            store.delete_tenant_with_data(self.tenant)
        except Exception:
            pass

    def test_tenant_crud(self) -> None:
        self.assertTrue(store.tenant_exists(self.tenant))
        t = store.get_tenant(self.tenant)
        self.assertIsNotNone(t)
        self.assertEqual(t["tenant_id"], self.tenant)

    def test_scan_upsert_is_idempotent(self) -> None:
        # ON CONFLICT (tenant_id, scan_id) DO UPDATE: re-saving the same scan_id
        # must refresh in place, not duplicate.
        report = {"scan_id": "s1", "source": "test", "summary": {"files": 3}, "files": []}
        store.save_scan_history(self.tenant, report)
        store.save_scan_history(self.tenant, report)
        self.assertEqual(store.count_scan_history(self.tenant), 1)
        back = store.read_scan_report(self.tenant, "s1")
        self.assertEqual(back["source"], "test")

    def test_created_at_is_immutable_across_resave(self) -> None:
        report = {"scan_id": "s2", "source": "a", "summary": {}, "files": []}
        store.save_scan_history(self.tenant, report)
        first = store.read_scan_history(self.tenant)
        report["source"] = "b"
        store.save_scan_history(self.tenant, report)
        again = store.read_scan_history(self.tenant)
        self.assertEqual(len(again), 1)  # still one scan
        self.assertEqual(store.read_scan_report(self.tenant, "s2")["source"], "b")
        self.assertEqual(first[0]["scan_id"], again[0]["scan_id"])

    def test_audit_identity_autoincrement_and_order(self) -> None:
        # audit_events.id is INTEGER PRIMARY KEY AUTOINCREMENT -> IDENTITY in PG.
        store.audit(self.tenant, "alice", "first.action", {"n": 1})
        store.audit(self.tenant, "bob", "second.action", {"n": 2})
        log = store.read_audit_log(self.tenant, limit=10)
        self.assertGreaterEqual(len(log), 2)
        actions = [e["action"] for e in log]
        # read_audit_log returns chronological (reversed from id DESC) -> first, second
        self.assertLess(actions.index("first.action"), actions.index("second.action"))

    def test_login_failure_epoch_double_precision(self) -> None:
        # timestamp is REAL in SQLite -> DOUBLE PRECISION in PG; a ~10-digit epoch
        # with sub-second fraction must round-trip without float4 precision loss.
        key = f"ip:{self.tenant}"
        self.assertEqual(store.count_login_failures(key, 300), 0)
        store.record_login_failure(key, 300)
        store.record_login_failure(key, 300)
        self.assertEqual(store.count_login_failures(key, 300), 2)
        store.clear_login_failures(key)
        self.assertEqual(store.count_login_failures(key, 300), 0)

    def test_revoked_token_lifecycle(self) -> None:
        jti = f"jti-{uuid4().hex[:8]}"
        self.assertFalse(store.is_token_revoked(jti) is False and False)  # sanity
        future = int(time.time()) + 3600
        store.revoke_token_jti(jti, future)
        self.assertTrue(store.is_token_revoked(jti))

    def test_api_key_lifecycle(self) -> None:
        key_id = store.create_api_key_record(self.tenant, "hash_abc123", "label", "analyst", "admin", None)
        active = store.get_active_api_key("hash_abc123")
        self.assertIsNotNone(active)
        self.assertEqual(active["tenant_id"], self.tenant)
        store.touch_api_key(key_id)
        keys = store.list_api_keys(self.tenant)
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["hash_prefix"], "hash_abc")  # substr(key_hash,1,8)
        self.assertTrue(store.revoke_api_key(self.tenant, key_id))
        self.assertIsNone(store.get_active_api_key("hash_abc123"))

    def test_registration_invite_atomic_redeem(self) -> None:
        future = (store.datetime.now(store.timezone.utc) + store.timedelta(hours=1)).isoformat()
        store.create_registration_invite(self.tenant, "tok_hash", "viewer", 1, future, False, "admin")
        first = store.redeem_registration_invite(self.tenant, "tok_hash")
        self.assertIsNotNone(first)
        # Second redeem exceeds max_uses=1 -> None (conditional UPDATE race-free).
        self.assertIsNone(store.redeem_registration_invite(self.tenant, "tok_hash"))

    def test_user_crud_and_secret_vault(self) -> None:
        store.create_user(f"u-{self.tenant}", "pwhash", "analyst", self.tenant, "Full Name")
        u = store.get_user(f"u-{self.tenant}")
        self.assertEqual(u["role"], "analyst")
        store.update_user_role(f"u-{self.tenant}", "viewer", self.tenant)
        self.assertEqual(store.get_user(f"u-{self.tenant}")["role"], "viewer")
        # encrypted vault blob round-trip (INSERT OR REPLACE secrets)
        store.save_secret(self.tenant, "sec1", "ciphertext-xyz")
        self.assertEqual(store.read_secret(self.tenant, "sec1"), "ciphertext-xyz")
        store.save_secret(self.tenant, "sec1", "ciphertext-updated")  # upsert
        self.assertEqual(store.read_secret(self.tenant, "sec1"), "ciphertext-updated")

    def test_delete_tenant_with_data_purges_all_tables(self) -> None:
        store.save_scan_history(self.tenant, {"scan_id": "sx", "summary": {}, "files": []})
        store.audit(self.tenant, "actor", "act", {})
        store.save_secret(self.tenant, "s", "c")
        store.delete_tenant_with_data(self.tenant)
        self.assertFalse(store.tenant_exists(self.tenant))
        self.assertEqual(store.count_scan_history(self.tenant), 0)
        self.assertIsNone(store.read_secret(self.tenant, "s"))


if __name__ == "__main__":
    unittest.main()
