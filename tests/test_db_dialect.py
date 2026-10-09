"""Offline unit tests for the SQLite->PostgreSQL dialect seam (backend/db.py).

These need no database server: they pin the *pure* translation functions
(placeholders, ON CONFLICT upserts, DDL type/identity rewrites, statement
splitting) and the dual-index row object. The live psycopg round-trip is covered
separately by tests/test_postgres_backend.py (skipped unless DSPM_DB_URL is set)."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from backend import db


class BackendSelectionTests(unittest.TestCase):
    def test_defaults_to_sqlite(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("DSPM_DB_URL", None)
            self.assertTrue(db.is_sqlite())
            self.assertFalse(db.is_postgres())
            self.assertEqual(db.backend_name(), "sqlite")

    def test_postgres_url_selects_postgres(self) -> None:
        for url in (
            "postgresql://u:p@localhost:5432/d",
            "postgres://u@127.0.0.1/d",
            "POSTGRESQL://u@h/d",  # scheme is case-insensitive
        ):
            with mock.patch.dict("os.environ", {"DSPM_DB_URL": url}):
                self.assertTrue(db.is_postgres(), url)
                self.assertEqual(db.backend_name(), "postgres")

    def test_non_pg_url_stays_sqlite(self) -> None:
        with mock.patch.dict("os.environ", {"DSPM_DB_URL": "sqlite:///x.db"}):
            self.assertTrue(db.is_sqlite())


class PlaceholderTranslationTests(unittest.TestCase):
    def test_question_marks_become_percent_s(self) -> None:
        self.assertEqual(
            db.translate_sql("SELECT * FROM t WHERE a = ? AND b = ?"),
            "SELECT * FROM t WHERE a = %s AND b = %s",
        )

    def test_question_mark_inside_string_literal_is_preserved(self) -> None:
        # The literal '?' must survive; only the real placeholder is rewritten.
        self.assertEqual(
            db.translate_sql("SELECT * FROM t WHERE label = '?' AND b = ?"),
            "SELECT * FROM t WHERE label = '?' AND b = %s",
        )

    def test_literal_percent_is_doubled(self) -> None:
        # psycopg client-side binding treats % specially; a literal % must double.
        self.assertEqual(
            db.translate_sql("SELECT * FROM t WHERE x LIKE 'a%' AND y = ?"),
            "SELECT * FROM t WHERE x LIKE 'a%%' AND y = %s",
        )


class UpsertRewriteTests(unittest.TestCase):
    def test_insert_or_replace_becomes_on_conflict_do_update(self) -> None:
        out = db.translate_sql(
            "INSERT OR REPLACE INTO secrets (tenant_id, secret_id, ciphertext, created_at) "
            "VALUES (?, ?, ?, ?)"
        )
        self.assertIn("INSERT INTO secrets (tenant_id, secret_id, ciphertext, created_at)", out)
        self.assertIn("VALUES (%s, %s, %s, %s)", out)
        self.assertIn("ON CONFLICT (tenant_id, secret_id) DO UPDATE SET", out)
        # PK columns must NOT be in the SET list; non-PK columns must be.
        self.assertIn("ciphertext = EXCLUDED.ciphertext", out)
        self.assertIn("created_at = EXCLUDED.created_at", out)
        self.assertNotIn("tenant_id = EXCLUDED", out)
        self.assertNotIn("secret_id = EXCLUDED", out)

    def test_single_column_pk_upsert(self) -> None:
        out = db.translate_sql(
            "INSERT OR REPLACE INTO revoked_tokens (jti, expires_at, revoked_at) VALUES (?, ?, ?)"
        )
        self.assertIn("ON CONFLICT (jti) DO UPDATE SET", out)
        self.assertIn("expires_at = EXCLUDED.expires_at", out)
        self.assertIn("revoked_at = EXCLUDED.revoked_at", out)
        self.assertNotIn("jti = EXCLUDED", out)

    def test_insert_or_replace_preserves_trailing_subquery(self) -> None:
        # The findings upsert computes first_seen via a COALESCE subquery in VALUES;
        # the ON CONFLICT clause must be appended AFTER the whole statement.
        sql = (
            "INSERT OR REPLACE INTO findings "
            "(tenant_id, id, asset_id, first_seen, last_seen) "
            "VALUES (?, ?, ?, "
            "COALESCE((SELECT first_seen FROM findings WHERE tenant_id = ? AND id = ?), ?), ?)"
        )
        out = db.translate_sql(sql)
        self.assertTrue(out.startswith("INSERT INTO findings"))
        self.assertIn("COALESCE((SELECT first_seen FROM findings", out)
        self.assertIn("ON CONFLICT (tenant_id, id) DO UPDATE SET", out)
        # ON CONFLICT is the tail, not spliced mid-statement.
        self.assertLess(out.index("COALESCE"), out.index("ON CONFLICT"))

    def test_insert_or_ignore_becomes_do_nothing(self) -> None:
        out = db.translate_sql(
            "INSERT OR IGNORE INTO tenants (tenant_id, display_name, created_at) VALUES (?, ?, ?)"
        )
        self.assertTrue(out.startswith("INSERT INTO tenants"))
        self.assertIn("ON CONFLICT DO NOTHING", out)
        self.assertNotIn("OR IGNORE", out)

    def test_insert_or_ignore_with_select_source(self) -> None:
        # The tenant back-fill seed uses INSERT ... SELECT ... UNION; DO NOTHING
        # must land at the very end (valid Postgres).
        out = db.translate_sql(
            "INSERT OR IGNORE INTO tenants (tenant_id, display_name, created_at, updated_at) "
            "SELECT tenant_id, tenant_id, ?, ? FROM users"
        )
        self.assertTrue(out.rstrip().endswith("ON CONFLICT DO NOTHING"))
        self.assertIn("SELECT tenant_id, tenant_id, %s, %s FROM users", out)

    def test_all_pk_columns_upsert_is_do_nothing(self) -> None:
        with mock.patch.dict(db._PK, {"synth": ("a", "b")}, clear=False):
            out = db.translate_sql("INSERT OR REPLACE INTO synth (a, b) VALUES (?, ?)")
        self.assertIn("ON CONFLICT (a, b) DO NOTHING", out)

    def test_unknown_table_upsert_raises(self) -> None:
        with self.assertRaises(ValueError):
            db.translate_sql("INSERT OR REPLACE INTO not_a_real_table (x) VALUES (?)")

    def test_every_table_written_with_insert_or_replace_has_its_real_key(self) -> None:
        """C0.5 (2026-09-25): user_sessions and refresh_tokens were written with INSERT OR
        REPLACE and had no entry, so on PostgreSQL every sign-in and every session renewal
        raised. The map is now checked in both directions against the schema itself: the
        tables the backend writes this way, and each one's actual primary key."""
        import re
        import sqlite3
        import tempfile
        from pathlib import Path

        from backend import migrations, store

        source = "".join(path.read_text(encoding="utf-8") for path in Path("backend").rglob("*.py"))
        written = set(re.findall(r"INSERT OR REPLACE INTO (\w+)", source))
        self.assertIn("user_sessions", written, "the scan must find the statements it is about")
        self.assertEqual(sorted(written - set(db._PK)), [], "written with INSERT OR REPLACE but not mapped")
        if db.is_postgres():
            # The suite's own database: its keys are the ones ON CONFLICT has to name.
            with store._connect() as conn:
                for table, key in db._PK.items():
                    rows = conn.execute(
                        "SELECT a.attname AS name FROM pg_index i "
                        "JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "
                        "WHERE i.indrelid = to_regclass(?) AND i.indisprimary "
                        "ORDER BY array_position(i.indkey::int2[], a.attnum)",
                        (table,),
                    ).fetchall()
                    with self.subTest(table=table):
                        self.assertEqual(tuple(row["name"] for row in rows), key)
            return
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schema.sqlite"
            original = store.DB_PATH
            store.DB_PATH = path
            try:
                migrations.upgrade()
            finally:
                store.DB_PATH = original
            conn = sqlite3.connect(path)
            try:
                for table, key in db._PK.items():
                    columns = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
                    real = tuple(name for _cid, name, *_rest, pk in sorted(columns, key=lambda c: c[-1]) if pk)
                    with self.subTest(table=table):
                        self.assertEqual(real, key)
            finally:
                conn.close()

    def test_plain_insert_is_untouched_except_placeholders(self) -> None:
        out = db.translate_sql(
            "INSERT INTO audit_events (tenant_id, timestamp) VALUES (?, ?)"
        )
        self.assertEqual(out, "INSERT INTO audit_events (tenant_id, timestamp) VALUES (%s, %s)")
        self.assertNotIn("ON CONFLICT", out)


class SchemaTranslationTests(unittest.TestCase):
    def test_autoincrement_becomes_identity(self) -> None:
        out = db.translate_schema(
            "CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, x TEXT)"
        )
        self.assertNotIn("AUTOINCREMENT", out.upper())
        self.assertIn("GENERATED BY DEFAULT AS IDENTITY", out)
        self.assertIn("PRIMARY KEY", out)

    def test_real_becomes_double_precision(self) -> None:
        out = db.translate_schema("CREATE TABLE login_failures (rate_key TEXT, timestamp REAL NOT NULL)")
        self.assertIn("DOUBLE PRECISION", out)
        self.assertNotIn(" REAL", out)

    def test_portable_ddl_is_unchanged(self) -> None:
        ddl = "CREATE TABLE users (username TEXT PRIMARY KEY, role TEXT CHECK (role IN ('admin')))"
        self.assertEqual(db.translate_schema(ddl), ddl)


class SplitStatementsTests(unittest.TestCase):
    def test_splits_and_strips_comments(self) -> None:
        script = """
        -- a leading comment
        CREATE TABLE a (x TEXT);
        -- another comment
        CREATE INDEX idx ON a (x);
        """
        stmts = db.split_statements(script)
        self.assertEqual(len(stmts), 2)
        self.assertTrue(stmts[0].startswith("CREATE TABLE a"))
        self.assertTrue(stmts[1].startswith("CREATE INDEX idx"))
        self.assertNotIn("--", "\n".join(stmts))

    def test_semicolon_inside_string_literal_does_not_split(self) -> None:
        stmts = db.split_statements("INSERT INTO t VALUES ('a;b'); SELECT 1;")
        self.assertEqual(len(stmts), 2)
        self.assertEqual(stmts[0], "INSERT INTO t VALUES ('a;b')")
        self.assertEqual(stmts[1], "SELECT 1")

    def test_trailing_statement_without_semicolon(self) -> None:
        self.assertEqual(db.split_statements("SELECT 1"), ["SELECT 1"])
        self.assertEqual(db.split_statements("   \n  "), [])


class PgRowTests(unittest.TestCase):
    def _row(self) -> "db._PgRow":
        return db._PgRow({"a": 0, "b": 1, "c": 2}, (10, "twenty", None))

    def test_int_and_str_indexing(self) -> None:
        r = self._row()
        self.assertEqual(r["a"], 10)
        self.assertEqual(r[0], 10)
        self.assertEqual(r["b"], "twenty")
        self.assertEqual(r[1], "twenty")
        self.assertIsNone(r["c"])
        self.assertIsNone(r[2])

    def test_len_iter_keys_get(self) -> None:
        r = self._row()
        self.assertEqual(len(r), 3)
        self.assertEqual(list(r), [10, "twenty", None])
        self.assertEqual(r.keys(), ["a", "b", "c"])
        self.assertEqual(r.get("missing", "default"), "default")
        self.assertEqual(r.get("a"), 10)

    def test_dict_conversion(self) -> None:
        self.assertEqual(dict(self._row()), {"a": 10, "b": "twenty", "c": None})

    def test_truthiness_matches_sqlite_row(self) -> None:
        # A 1-column existence probe ("SELECT 1") must be truthy; only None is falsy.
        probe = db._PgRow({"?column?": 0}, (1,))
        self.assertTrue(bool(probe))


class _FakeCursor:
    def __init__(self, rows=None):
        self._rows = rows or []
        self.description = None

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _FakeRaw:
    """Minimal stand-in for a psycopg connection - records executed SQL so the
    _PgConn wrapper's translate-and-forward plumbing can be checked offline."""

    def __init__(self, rows_for=None):
        self.executed: list[tuple] = []
        self.committed = False
        self.closed = False
        self._rows_for = rows_for or {}

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        for needle, rows in self._rows_for.items():
            if needle in sql:
                return _FakeCursor(rows)
        return _FakeCursor()

    def cursor(self):
        raw = self

        class _Cur(_FakeCursor):
            def executemany(self, sql, seq):
                raw.executed.append((sql, seq))

        return _Cur()

    def commit(self):
        self.committed = True

    def rollback(self):
        pass

    def close(self):
        self.closed = True


class WrapperPlumbingTests(unittest.TestCase):
    def test_execute_translates_and_forwards_params(self) -> None:
        raw = _FakeRaw()
        conn = db._PgConn(raw)
        conn.execute("SELECT * FROM t WHERE a = ?", (7,))
        self.assertEqual(raw.executed[-1], ("SELECT * FROM t WHERE a = %s", (7,)))

    def test_execute_forwards_upsert_translation(self) -> None:
        raw = _FakeRaw()
        db._PgConn(raw).execute(
            "INSERT OR REPLACE INTO secrets (tenant_id, secret_id, ciphertext, created_at) VALUES (?, ?, ?, ?)",
            ("t", "s", "c", "now"),
        )
        sql, params = raw.executed[-1]
        self.assertIn("ON CONFLICT (tenant_id, secret_id) DO UPDATE SET", sql)
        self.assertEqual(params, ("t", "s", "c", "now"))

    def test_execute_always_passes_a_tuple_never_none(self) -> None:
        # psycopg must run client-side binding (to un-double %%), which requires a
        # non-None params sequence even for parameterless statements.
        raw = _FakeRaw()
        db._PgConn(raw).execute("SAVEPOINT sp")
        self.assertEqual(raw.executed[-1], ("SAVEPOINT sp", ()))

    def test_executescript_splits_and_translates_ddl(self) -> None:
        raw = _FakeRaw()
        db._PgConn(raw).executescript(
            "CREATE TABLE a (id INTEGER PRIMARY KEY AUTOINCREMENT);\n"
            "-- comment\n"
            "CREATE INDEX idx ON a (id);"
        )
        self.assertEqual(len(raw.executed), 2)
        self.assertIn("GENERATED BY DEFAULT AS IDENTITY", raw.executed[0][0])
        self.assertNotIn("AUTOINCREMENT", raw.executed[0][0].upper())
        self.assertTrue(raw.executed[1][0].startswith("CREATE INDEX idx"))

    def test_get_pool_none_without_psycopg_pool(self) -> None:
        # When psycopg_pool is absent, the pool getter returns None so connect()
        # falls back to connect-per-op (the live pooled path is covered by the
        # Postgres suite, which runs with pooling enabled).
        with mock.patch.object(db, "ConnectionPool", None):
            self.assertIsNone(db._get_pool())

    def test_numeric_pool_settings_are_bounded_and_typo_safe(self) -> None:
        with mock.patch.dict(os.environ, {"POOL_TEST": "not-a-number"}):
            self.assertEqual(db._env_number("POOL_TEST", 10, 1, 20, int), 10)
        with mock.patch.dict(os.environ, {"POOL_TEST": "999"}):
            self.assertEqual(db._env_number("POOL_TEST", 10, 1, 20, int), 20)

    def test_executemany_translates_and_forwards(self) -> None:
        raw = _FakeRaw()
        conn = db._PgConn(raw)
        conn.executemany("DELETE FROM registration_invites WHERE id = ?", [("a",), ("b",)])
        sql, params = raw.executed[-1]
        self.assertEqual(sql, "DELETE FROM registration_invites WHERE id = %s")
        self.assertEqual(params, [("a",), ("b",)])

    def test_table_columns_postgres_branch(self) -> None:
        raw = _FakeRaw(rows_for={"information_schema.columns": [("username",), ("role",)]})
        conn = db._PgConn(raw)
        with mock.patch.dict("os.environ", {"DSPM_DB_URL": "postgresql://x@h/d"}):
            cols = db.table_columns(conn, "users")
        self.assertEqual(cols, {"username", "role"})
        # The PRAGMA path must NOT be used on Postgres.
        self.assertNotIn("PRAGMA", raw.executed[-1][0].upper())

    def test_postgres_extension_available_uses_catalog(self) -> None:
        raw = _FakeRaw(rows_for={"pg_extension": [(1,)]})
        conn = db._PgConn(raw)
        with mock.patch.dict("os.environ", {"DSPM_DB_URL": "postgresql://x@h/d"}):
            self.assertTrue(db.postgres_extension_available(conn, "pg_trgm"))
        sql, params = raw.executed[-1]
        self.assertIn("pg_extension", sql)
        self.assertEqual(params, ("pg_trgm",))

    def test_postgres_extension_available_is_false_on_sqlite(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertFalse(db.postgres_extension_available(object(), "pg_trgm"))


if __name__ == "__main__":
    unittest.main()
