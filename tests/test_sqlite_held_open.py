"""P4: a server holds its SQLite database open, so no request's close is the last one.

Every store call opens and closes its own connection. On a WAL database the LAST
connection to close checkpoints the WAL and deletes it, and the next open rebuilds the
WAL index - which made that close 10 of the 17 ms an audit write cost on this host, and
half of what verify_token cost. One idle connection held for the life of the server
means no request is ever the last. The mechanism is observable without a clock: while
the file is held, a closing connection leaves the WAL in place; with nothing held, it
deletes it.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from backend import db, store


class _WalCase(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        self.path = Path(self.temp_dir.name) / "held.sqlite"
        with db.connect(self.path) as conn:
            conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        # Release first on the way out, so the temporary directory can be removed.
        self.addCleanup(db.release_sqlite_anchor)

    @property
    def wal(self) -> Path:
        return Path(str(self.path) + "-wal")

    def _write(self) -> None:
        with db.connect(self.path) as conn:
            conn.execute("INSERT INTO t (v) VALUES ('x')")


@unittest.skipIf(db.is_postgres(), "SQLite's WAL is what this is about")
class HoldingTheFileOpenTest(_WalCase):

    def test_without_it_every_close_checkpoints_and_deletes_the_wal(self) -> None:
        # The cost being removed - pinned, so the test below means something.
        self._write()
        self.assertFalse(self.wal.exists(), "the last close checkpoints and deletes the WAL")

    def test_with_it_a_close_is_not_the_last_one(self) -> None:
        self.assertTrue(db.hold_sqlite_open(self.path))
        self._write()
        self.assertTrue(self.wal.exists(), "a request's close must not be the last connection")
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM t").fetchone()[0], 1)

    def test_releasing_it_lets_the_last_close_clean_up_again(self) -> None:
        db.hold_sqlite_open(self.path)
        self._write()
        db.release_sqlite_anchor()
        self._write()
        self.assertFalse(self.wal.exists())
        self.assertIsNone(db.held_sqlite_path())

    def test_it_blocks_no_writer_and_no_checkpoint(self) -> None:
        # The held connection runs no transaction: a full checkpoint still completes.
        db.hold_sqlite_open(self.path)
        for _ in range(20):
            self._write()
        with db.connect(self.path) as conn:
            busy, _, _ = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        self.assertEqual(busy, 0, "the checkpoint was not blocked")

    def test_one_path_at_a_time(self) -> None:
        other = Path(self.temp_dir.name) / "other.sqlite"
        with db.connect(other) as conn:
            conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        db.hold_sqlite_open(self.path)
        db.hold_sqlite_open(other)
        self.assertEqual(db.held_sqlite_path(), str(other))
        self._write()
        self.assertFalse(self.wal.exists(), "the first path was released")

    def test_it_can_be_turned_off(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_SQLITE_HOLD_OPEN": "0"}):
            self.assertFalse(db.hold_sqlite_open(self.path))
        self.assertIsNone(db.held_sqlite_path())

    def test_a_rollback_journal_has_nothing_to_save(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_SQLITE_JOURNAL_MODE": "delete"}):
            self.assertFalse(db.hold_sqlite_open(self.path))

    def test_the_wal_that_now_persists_is_bounded(self) -> None:
        with db.connect(self.path) as conn:
            limit = conn.execute("PRAGMA journal_size_limit").fetchone()[0]
        self.assertEqual(limit, 64 * 1024 * 1024)


@unittest.skipIf(db.is_postgres(), "SQLite's WAL is what this is about")
class TheServerHoldsItForItsLifeTest(unittest.TestCase):

    def test_startup_holds_the_database_and_shutdown_lets_go(self) -> None:
        from backend.app import app

        self.addCleanup(db.release_sqlite_anchor)
        with TestClient(app) as client:
            self.assertEqual(client.get("/api/health").status_code, 200)
            self.assertEqual(db.held_sqlite_path(), str(store.DB_PATH))
        self.assertIsNone(db.held_sqlite_path(), "released at shutdown, so the file can be moved")

    def test_importing_the_store_holds_nothing(self) -> None:
        # Tools and tests import the store; only a server's lifespan holds the file.
        db.release_sqlite_anchor()
        with db.connect(store.DB_PATH) as conn:
            conn.execute("SELECT 1").fetchone()
        self.assertIsNone(db.held_sqlite_path())


if __name__ == "__main__":
    unittest.main()
