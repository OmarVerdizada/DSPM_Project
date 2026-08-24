from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend import db, store


@unittest.skipIf(db.is_postgres(), "SQLite-focused reset coverage")
class TenantErasureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "tenant-erasure.sqlite"
        store.init_db()

    def tearDown(self) -> None:
        store.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    @staticmethod
    def _future() -> str:
        return (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    def test_delete_tenant_purges_credentials_and_invalidates_search_state(self) -> None:
        tenant_id = "erase-me"
        store.create_tenant(tenant_id, "Erase Me")
        store.create_registration_invite(
            tenant_id, "invite-hash", "viewer", 1, self._future(), False, "admin"
        )
        store.create_api_key_record(
            tenant_id, "api-key-hash", "automation", "analyst", "admin", None
        )
        store.save_search_reconciliation("sentro_assets_v1", {"orphaned": 1})

        store.delete_tenant_with_data(tenant_id)

        self.assertFalse(store.tenant_exists(tenant_id))
        self.assertEqual(store.list_registration_invites(tenant_id), [])
        self.assertEqual(store.list_api_keys(tenant_id), [])
        self.assertIsNone(store.get_active_api_key("api-key-hash"))
        self.assertIsNone(store.get_search_reconciliation("sentro_assets_v1"))

    def test_reset_default_keeps_only_clean_built_in_admin(self) -> None:
        store.create_user("admin", "preserved-password-hash", "viewer", "default", "Old Name")
        store.create_user("analyst", "remove-me", "analyst", "default", "Analyst")
        store.save_scan_history(
            "default",
            {"scan_id": "default-scan", "summary": {"total_files": 0}, "files": []},
        )
        store.save_secret("default", "secret", "ciphertext")
        store.create_registration_invite(
            "default", "default-invite", "viewer", 1, self._future(), False, "admin"
        )
        store.create_api_key_record(
            "default", "default-api-key", "automation", "analyst", "admin", None
        )
        before_code = store.get_tenant("default")["registration_code"]

        store.reset_default_tenant_data()

        tenant = store.get_tenant("default")
        self.assertEqual(tenant["display_name"], "Default")
        self.assertNotEqual(tenant["registration_code"], before_code)
        self.assertEqual(store.count_scan_history("default"), 0)
        self.assertIsNone(store.read_secret("default", "secret"))
        self.assertEqual(store.list_registration_invites("default"), [])
        self.assertEqual(store.list_api_keys("default"), [])
        self.assertEqual([user["username"] for user in store.list_users("default")], ["admin"])
        admin = store.get_user("admin")
        self.assertEqual(admin["password_hash"], "preserved-password-hash")
        self.assertEqual(admin["role"], "admin")
        self.assertEqual(admin["full_name"], "Local Administrator")
        self.assertTrue(admin["is_active"])
        self.assertIsNone(admin["last_login_at"])


if __name__ == "__main__":
    unittest.main()
