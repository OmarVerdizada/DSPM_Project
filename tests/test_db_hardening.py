"""M2 interim (roadmap 2.1): the SQLite data dir + DB file are restricted so a
non-admin OS user cannot read credential hashes / encrypted vault blobs. Best-effort
POSIX chmod (no-op on Windows, where NTFS ACLs govern; full controls come with the
PostgreSQL migration)."""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from backend import db, store


@unittest.skipIf(db.is_postgres(), "SQLite-specific at-rest file hardening; Postgres at-rest is a server concern")
class DbHardeningTests(unittest.TestCase):
    def tearDown(self) -> None:
        store._perms_hardened = False  # don't leak the flag into other tests

    def test_hardening_requests_restrictive_modes(self) -> None:
        # Cross-platform: assert chmod is invoked with 0700 (dir) and 0600 (db),
        # regardless of whether the OS honours it.
        with TemporaryDirectory() as d:
            dbp = Path(d) / "dspm.sqlite"
            dbp.write_bytes(b"")  # so DB_PATH.exists()
            calls: list[tuple[Path, int]] = []
            with mock.patch.object(store, "DB_PATH", dbp), \
                 mock.patch("backend.store.os.chmod", side_effect=lambda p, m: calls.append((Path(p), m))):
                store._perms_hardened = False
                store._harden_db_permissions()
            modes = {p.name: m for p, m in calls}
            self.assertEqual(modes.get(dbp.parent.name), 0o700)  # data dir owner-only
            self.assertEqual(modes.get("dspm.sqlite"), 0o600)     # db owner rw only

    def test_connect_hardens_and_is_idempotent(self) -> None:
        with TemporaryDirectory() as d:
            dbp = Path(d) / "sub" / "dspm.sqlite"
            with mock.patch.object(store, "DB_PATH", dbp):
                store._perms_hardened = False
                with store._connect() as conn:
                    conn.execute("CREATE TABLE IF NOT EXISTS t (x)")
                self.assertTrue(dbp.exists())
                self.assertTrue(store._perms_hardened)  # ran once
                # second connect must not error (flag short-circuits the chmod)
                with store._connect() as conn:
                    conn.execute("SELECT 1")
                if os.name == "posix":
                    self.assertEqual(dbp.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(dbp.parent.stat().st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
