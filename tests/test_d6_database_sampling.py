"""D6: which database columns hold sensitive data - sampled within stated limits, counted
exactly, and reported with masked evidence only.

Gate line: "Seeded PAN/email columns found with accurate table/row counts and no raw
sample in logs or exports."

PostgreSQL is tested live, against tables seeded for the test in the disposable
sentro_test database and dropped after it (skipped when that database is not the one
configured). MySQL and SQL Server need drivers the product does not install: their SQL is
checked here, and a scan of either says the driver is missing - HELD.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from backend import db, security, store
from backend.app import app
from collectors import database_scanner
from discovery.database_engine import DatabaseDiscoveryEngine
from discovery.discovery_engine import ScanConfig

PASSWORD = "Kestrel-lantern-4471"
CARDS = ["4111111111111111", "5555555555554444", "4012888888881881", "378282246310005"]


def _pg_dsn() -> str:
    url = os.getenv("DSPM_DB_URL", "")
    return url if db.is_postgres() and url.endswith("@127.0.0.1:5442/sentro_test") else ""


class FakeCursor:
    """A DB-API cursor over fixed tables: {(schema, table): (columns, types, rows)}. It runs
    the sample SQL as PostgreSQL would - `left(col::text, n)` cuts a value, a bare column
    does not - and keeps the longest value it sent and how each result was fetched."""

    def __init__(self, tables: dict, statements: list, wire: dict) -> None:
        self.tables, self.statements, self.wire, self._rows = tables, statements, wire, []
        self._sample = False

    def execute(self, sql: str, params=()) -> None:
        self.statements.append(sql)
        self._sample = False
        if "information_schema.tables" in sql:
            self._rows = sorted(self.tables)
        elif "information_schema.columns" in sql:
            columns, types, _ = self.tables[tuple(params)]
            self._rows = list(zip(columns, types))
        elif sql.startswith("SELECT COUNT"):
            name = sql.split("FROM ", 1)[1]
            self._rows = [(len(self._table(name)[2]),)]
        else:
            name = sql.split("FROM ", 1)[1].split(" LIMIT")[0]
            limit = int(sql.rsplit("LIMIT ", 1)[1])
            columns, types, rows = self._table(name)
            selected = sql.split("SELECT ", 1)[1].split(" FROM")[0]
            wanted = [quoted.replace('""', '"') for quoted in re.findall(r'"((?:[^"]|"")*)"', selected)]
            cut = re.match(r'left\(".*?"::text, (\d+)\)', selected)
            width = int(cut.group(1)) if cut else None

            def sent(value):
                if value is None:
                    return None
                value = str(value)[:width] if width else value
                self.wire["longest"] = max(self.wire.get("longest", 0), len(str(value)))
                return value

            self._rows = [tuple(sent(row[columns.index(column)]) for column in wanted) for row in rows[:limit]]
            self._sample = True

    def _table(self, quoted: str):
        schema, table = (part.strip('"') for part in quoted.split("."))
        return self.tables[(schema, table)]

    def fetchall(self):
        if self._sample:
            self.wire.setdefault("fetches", []).append("fetchall")
        rows, self._rows = list(self._rows), []
        return rows

    def fetchmany(self, size=1):
        if self._sample:
            self.wire.setdefault("fetches", []).append(size)
        rows, self._rows = self._rows[:size], self._rows[size:]
        return rows

    def fetchone(self):
        return self._rows[0] if self._rows else None


class FakeConnection:
    def __init__(self, tables: dict) -> None:
        self.tables, self.statements, self.wire = tables, [], {}

    def cursor(self) -> FakeCursor:
        return FakeCursor(self.tables, self.statements, self.wire)

    def close(self) -> None:
        pass


def seeded_tables(rows: int = 2500) -> dict:
    customers = []
    for index in range(rows):
        card = CARDS[index % len(CARDS)] if index % 25 == 0 else None
        customers.append((f"customer{index}@example.com", card, f"note {index}", index))
    return {
        ("public", "customers"): (["email", "card", "note", "id"], ["text", "character varying", "text", "integer"],
                                  customers),
        ("public", "empty_things"): (["label"], ["text"], []),
        ("public", "orders"): (["ref"], ["text"], [("ORD-1",), ("ORD-2",)]),
        ("audit", "numbers_only"): (["amount"], ["numeric"], [(1,), (2,)]),
    }


def source(**extra) -> database_scanner.DatabaseSource:
    settings = {"engine": "postgresql", "host": "db.corp.test", "port": 5432, "database": "crm",
                "username": "reader", "sample_rows": 1000, **extra}
    return database_scanner.DatabaseSource(**settings)


class TheSamplerTest(unittest.TestCase):

    def test_each_text_column_is_a_record_with_exact_counts_and_its_sample_size(self) -> None:
        records, diagnostics = database_scanner.scan(source(), connection=FakeConnection(seeded_tables()))
        by_name = {record["name"]: record for record in records}
        self.assertEqual(sorted(by_name), ["public.customers.card", "public.customers.email", "public.customers.note",
                                           "public.orders.ref"],
                         "text columns only; the integer and the numeric are not read, the empty table not at all")
        facts = by_name["public.customers.card"]["database"]
        self.assertEqual((facts["table_rows"], facts["table_rows_exact"], facts["sampled_rows"], facts["sample_limit"]),
                         (2500, True, 1000, 1000))
        self.assertEqual(facts["non_null_sampled"], 40, "every 25th row of the first 1,000 holds a card")
        self.assertEqual(by_name["public.customers.card"]["scan_completeness"], "PARTIAL")
        self.assertEqual(by_name["public.customers.card"]["path"], "postgresql://db.corp.test:5432/crm/public.customers/card")
        self.assertEqual((diagnostics["tables"], diagnostics["columns"]), (4, 4), "four tables read, four columns")

    def test_the_limits_are_explicit_and_bounded(self) -> None:
        bounded = source(sample_rows=10**9, max_tables=10**9, max_value_chars=1).bounded()
        self.assertEqual((bounded.sample_rows, bounded.max_tables, bounded.max_value_chars), (10_000, 5000, 16))
        connection = FakeConnection(seeded_tables())
        database_scanner.scan(source(sample_rows=7), connection=connection)
        self.assertTrue(any(sql.endswith("LIMIT 7") for sql in connection.statements))

    def test_include_tables_and_schemas_narrow_what_is_read(self) -> None:
        connection = FakeConnection(seeded_tables())
        records, _ = database_scanner.scan(source(include_tables=["public.cust*"]), connection=connection)
        self.assertEqual({record["database"]["table"] for record in records}, {"customers"})
        sql, params = database_scanner.PostgresDialect().tables_sql(["public"])
        self.assertIn("table_schema IN (%s)", sql)
        self.assertEqual(params, ["public"])

    def test_identifiers_are_quoted_for_each_engine(self) -> None:
        evil = 'x"; DROP TABLE t; --'
        self.assertEqual(database_scanner.PostgresDialect().quote(evil), '"x""; DROP TABLE t; --"')
        self.assertEqual(database_scanner.MySQLDialect().quote("a`b"), "`a``b`")
        self.assertEqual(database_scanner.SQLServerDialect().quote("a]b"), "[a]]b]")
        self.assertIn("TOP (5)", database_scanner.SQLServerDialect().sample_sql("dbo", "t", ["c"], 5, 256))

    def test_each_engine_cuts_a_value_in_the_sql(self) -> None:
        # M4 exit review: the cut was made in Python, after the whole cell had crossed the wire.
        postgres = database_scanner.PostgresDialect().sample_sql("s", 't"x', ['a"b', "c"], 7, 64)
        self.assertEqual(postgres, 'SELECT left("a""b"::text, 64), left("c"::text, 64) FROM "s"."t""x" LIMIT 7')
        self.assertEqual(database_scanner.MySQLDialect().sample_sql("s", "t", ["a`b"], 7, 64),
                         "SELECT LEFT(CAST(`a``b` AS CHAR), 64) FROM `s`.`t` LIMIT 7")
        self.assertEqual(database_scanner.SQLServerDialect().sample_sql("s", "t", ["a]b"], 7, 64),
                         "SELECT TOP (7) LEFT(CAST([a]]b] AS NVARCHAR(MAX)), 64) FROM [s].[t]")

    def test_a_large_value_never_crosses_the_wire_whole(self) -> None:
        # A 5,000-character jsonb cell in 450 rows, sampled at 32 characters a value.
        tables = {("public", "events"): (["payload"], ["jsonb"], [("{" + "x" * 5000 + "}",) for _ in range(450)])}
        connection = FakeConnection(tables)
        records, _ = database_scanner.scan(source(max_value_chars=32), connection=connection)
        self.assertEqual(records[0]["database"]["sampled_rows"], 450)
        self.assertLessEqual(connection.wire["longest"], 32, "the database sent the cut value, not the cell")
        self.assertTrue(all(len(line) <= 32 for line in records[0]["content"].split("\n")))
        fetches = connection.wire["fetches"]
        self.assertNotIn("fetchall", fetches, "the sample is fetched in batches")
        self.assertTrue(all(size <= database_scanner.FETCH_ROWS for size in fetches))
        self.assertGreater(len(fetches), 1)

    def test_each_tables_columns_are_handed_on_as_the_table_is_read(self) -> None:
        connection = FakeConnection(seeded_tables())
        handed = []
        records, _ = database_scanner.scan(source(), connection=connection,
                                           record_callback=lambda record: handed.append((record["name"],
                                                                                         len(connection.statements))))
        self.assertEqual([name for name, _ in handed], [record["name"] for record in records])
        orders_sampled = next(index for index, sql in enumerate(connection.statements)
                              if '"orders" LIMIT' in sql)
        customers_handed = max(at for name, at in handed if name.startswith("public.customers."))
        self.assertLessEqual(customers_handed, orders_sampled, "customers analysed before orders is read")
        # The engine passes its callback down, rather than replaying the list at the end.
        engine_handed = []
        engine_connection = FakeConnection(seeded_tables())
        engine = DatabaseDiscoveryEngine(ScanConfig(tenant_id="default"), source(), connection=engine_connection)
        engine._collect_records(record_callback=lambda record: engine_handed.append(len(engine_connection.statements)))
        self.assertLess(engine_handed[0], len(engine_connection.statements))

    def test_mysql_and_sql_server_say_their_driver_is_missing(self) -> None:
        for engine in ("mysql", "sqlserver"):
            with self.subTest(engine=engine), self.assertRaisesRegex(database_scanner.DriverMissing, "HELD"):
                database_scanner.connect(database_scanner.DatabaseSource(engine=engine, host="h", port=1, database="d",
                                                                         username="u"))

    def test_a_failing_table_is_named_and_its_error_is_only_a_type(self) -> None:
        tables = seeded_tables()

        class Broken(FakeConnection):
            def cursor(self):
                cursor = super().cursor()
                original = cursor.execute

                def execute(sql, params=()):
                    if "empty_things" in str(params) or "empty_things" in sql:
                        raise RuntimeError("relation contains 4111111111111111")
                    original(sql, params)
                cursor.execute = execute
                return cursor

        records, diagnostics = database_scanner.scan(source(), connection=Broken(tables))
        self.assertEqual(diagnostics["errors"], [{"table": "public.empty_things", "error": "RuntimeError"}])
        self.assertNotIn("4111", json.dumps(diagnostics))
        self.assertEqual(diagnostics.get("scan_errors"), 1, "a table not read leaves the scan incomplete")

    def test_what_was_not_read_leaves_the_scan_incomplete(self) -> None:
        complete = database_scanner.scan(source(), connection=FakeConnection(seeded_tables()))[1]
        self.assertFalse(any(complete.get(key) for key in ("scan_errors", "record_limit_reached", "scan_aborted_reason")))
        tables = database_scanner.scan(source(max_tables=1), connection=FakeConnection(seeded_tables()))[1]
        self.assertEqual((tables["tables_skipped"], tables.get("record_limit_reached")), (3, True))
        columns = database_scanner.scan(source(max_columns=1), connection=FakeConnection(seeded_tables()))[1]
        self.assertEqual((columns["columns_skipped"], columns.get("record_limit_reached")), (2, True))
        stopped = database_scanner.scan(source(), connection=FakeConnection(seeded_tables()), cancel_check=lambda: True)[1]
        self.assertEqual(stopped.get("scan_aborted_reason"), "cancelled")


class FakePostgres:
    """Speaks just enough of the PostgreSQL wire protocol to do what a hostile host would:
    refuse TLS, then ask for the password in the clear (3) or as MD5 (5). It keeps every
    byte the client sends. Not a database - nothing here connects to one."""

    def __init__(self, auth_code: int) -> None:
        self.auth_code, self.received = auth_code, bytearray()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _exactly(self, conn, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = conn.recv(size - len(data))
            if not chunk:
                raise ConnectionError("closed")
            self.received += chunk
            data += chunk
        return data

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(5)
                try:
                    while True:
                        length = struct.unpack("!i", self._exactly(conn, 4))[0]
                        code = struct.unpack("!i", self._exactly(conn, length - 4)[:4])[0]
                        if code not in (80877103, 80877104):  # SSLRequest, GSSENCRequest: answered "no"
                            break
                        conn.sendall(b"N")
                    salt = b"salt" if self.auth_code == 5 else b""
                    conn.sendall(b"R" + struct.pack("!ii", 8 + len(salt), self.auth_code) + salt)
                    chunk = conn.recv(4096)  # the password message - or nothing, as it should be
                    self.received += chunk
                except (OSError, ConnectionError, struct.error):
                    pass

    def close(self) -> None:
        self.listener.close()


class TheConnectionTest(unittest.TestCase):
    """The password is offered only through SCRAM-SHA-256 (M4 exit review)."""

    def target(self, **extra) -> database_scanner.DatabaseSource:
        return source(host="db.corp.test", address="127.0.0.1", password="Svc-Fileserver-Secret-77",
                      sslmode="prefer", **extra).bounded()

    def test_a_host_that_asks_for_the_password_in_the_clear_never_gets_it(self) -> None:
        for name, code in (("cleartext", 3), ("md5", 5)):
            with self.subTest(auth=name):
                server = FakePostgres(code)
                self.addCleanup(server.close)
                with self.assertRaisesRegex(database_scanner.DatabaseScanError, "SCRAM-SHA-256") as refused:
                    database_scanner.connect(self.target(port=server.port))
                self.assertIn("password was not sent", str(refused.exception))
                self.assertNotIn(b"Svc-Fileserver-Secret-77", bytes(server.received))
                self.assertNotIn(b"md5", bytes(server.received), "no MD5 answer either")
                self.assertTrue(server.received, "the client did reach the fake host")

    def test_scram_is_required_and_bound_to_tls_when_tls_is(self) -> None:
        import psycopg

        for sslmode, binding in (("verify-full", "require"), ("verify-ca", "require"), ("require", "require"),
                                 ("prefer", None), ("disable", None)):
            with self.subTest(sslmode=sslmode), mock.patch.object(psycopg, "connect") as dialled:
                database_scanner.connect(source(sslmode=sslmode, address="10.1.2.3").bounded())
                kwargs = dialled.call_args.kwargs
                self.assertEqual(kwargs["require_auth"], "scram-sha-256")
                self.assertEqual(kwargs.get("channel_binding"), binding)
                self.assertEqual((kwargs["hostaddr"], kwargs["sslmode"]), ("10.1.2.3", sslmode))

    def test_a_libpq_that_cannot_refuse_is_not_used(self) -> None:
        import psycopg

        with (mock.patch.object(psycopg.pq, "version", return_value=150007),
              mock.patch.object(psycopg, "connect") as dialled,
              self.assertRaisesRegex(database_scanner.DatabaseScanError, "older than 16")):
            database_scanner.connect(self.target(port=5432))
        dialled.assert_not_called()


class TheEngineTest(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        original = store.DB_PATH
        store.DB_PATH = self.tmp / "d6.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()

    def test_cards_and_emails_are_found_masked_with_no_raw_value_or_preview(self) -> None:
        config = ScanConfig(tenant_id="default", compliance_enabled=True, compliance_frameworks=["gdpr", "pci_dss"])
        with self.assertLogs(level=logging.DEBUG) as logs:
            logging.getLogger("d6.marker").debug("start")
            report = DatabaseDiscoveryEngine(config, source(), connection=FakeConnection(seeded_tables())).run().to_dict()
        columns = {entry["name"]: entry for entry in report["files"]}
        card_types = {finding["type"] for finding in columns["public.customers.card"]["findings"]}
        self.assertTrue(card_types & {"credit_card", "pci_pan", "payment_card"} or
                        any("card" in kind or "pan" in kind for kind in card_types), card_types)
        self.assertTrue(any("email" in finding["type"] for finding in columns["public.customers.email"]["findings"]))
        self.assertEqual(columns["public.customers.note"]["findings"], [], "a column of notes holds nothing")
        self.assertEqual(columns["public.customers.card"]["preview"]["available"], False)
        self.assertEqual((columns["public.customers.card"]["database"]["table_rows"],
                          columns["public.customers.card"]["database"]["sampled_rows"]), (2500, 1000),
                         "the report says how much of the table the finding rests on")
        text = json.dumps(report) + "\n".join(logs.output)
        for card in CARDS:
            self.assertNotIn(card, text, "no raw card number in the report or the logs")
        self.assertNotIn("customer0@example.com", text, "no raw address either")
        self.assertTrue(report["scan_diagnostics"]["incremental"]["complete"])

    def test_a_scan_that_missed_a_table_is_not_complete_so_nothing_is_pruned(self) -> None:
        config = ScanConfig(tenant_id="default", compliance_enabled=False)
        report = DatabaseDiscoveryEngine(config, source(max_tables=2),
                                         connection=FakeConnection(seeded_tables())).run().to_dict()
        # The store prunes a named scan's unseen assets only when this is true.
        self.assertFalse(report["scan_diagnostics"]["incremental"]["complete"])


class TheRouteTest(unittest.TestCase):
    """What the route refuses before it dials anything."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        original = store.DB_PATH
        store.DB_PATH = self.tmp / "d6r.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        if store.get_user("d6r-admin") is None:
            store.create_user("d6r-admin", security.hash_password(PASSWORD), "admin", "default")
        self.client = TestClient(app)
        self.headers = {"Authorization": f"Bearer {security.create_token('d6r-admin', 'admin', 'default', mfa_verified=True)}"}
        self.body = {"host": "db.corp.test", "database": "crm", "username": "reader", "password": "x", "sslmode": "prefer"}

    def post(self):
        from fastapi import HTTPException

        dialled = HTTPException(status_code=418, detail="dialled")
        with mock.patch("collectors.database_scanner.connect", side_effect=dialled):
            return self.client.post("/api/database/scan", headers=self.headers, json=self.body)

    def test_the_target_must_be_in_scope(self) -> None:
        from fastapi import HTTPException

        with mock.patch("backend.app._validate_scan_target", side_effect=HTTPException(status_code=403, detail="out of scope")):
            self.assertEqual(self.post().status_code, 403)

    def test_production_reads_over_verified_tls_only(self) -> None:
        with (mock.patch("backend.app.IS_PRODUCTION", True), mock.patch("backend.app._validate_scan_target")):
            refused = self.post()
        self.assertEqual(refused.status_code, 400)
        self.assertIn("verify-full", refused.json()["detail"])

    def test_a_required_licence_is_required_here_too(self) -> None:
        with (mock.patch.dict(os.environ, {"DSPM_LICENCE_REQUIRED": "1"}), mock.patch("backend.app._validate_scan_target")):
            self.assertEqual(self.post().status_code, 402)


@unittest.skipUnless(_pg_dsn(), "the live PostgreSQL scan runs against the disposable sentro_test database")
class ThePostgreSQLScanTest(unittest.TestCase):
    """A real PostgreSQL, real tables: 2,500 customers, a card in every 25th row."""

    def setUp(self) -> None:
        import psycopg

        self.prefix = f"d6_seed_{os.getpid()}"
        self.conn = psycopg.connect(_pg_dsn(), autocommit=True)
        self.addCleanup(self.conn.close)
        self.conn.execute(f"CREATE TABLE {self.prefix}_customers (id integer, email text, card varchar(19), note text)")
        self.addCleanup(self.conn.execute, f"DROP TABLE IF EXISTS {self.prefix}_customers")
        with self.conn.cursor() as cursor:
            cursor.executemany(
                f"INSERT INTO {self.prefix}_customers (id, email, card, note) VALUES (%s, %s, %s, %s)",
                [(index, f"customer{index}@example.com", CARDS[index % 4] if index % 25 == 0 else None, f"note {index}")
                 for index in range(2500)])
        store.create_user("d6-admin", security.hash_password(PASSWORD), "admin", "default") \
            if store.get_user("d6-admin") is None else None
        self.client = TestClient(app)
        self.headers = {"Authorization": f"Bearer {security.create_token('d6-admin', 'admin', 'default', mfa_verified=True)}"}
        from urllib.parse import urlsplit

        parts = urlsplit(_pg_dsn())
        self.target = {"host": "127.0.0.1", "port": parts.port, "database": parts.path.lstrip("/"),
                       "username": parts.username, "password": parts.password or os.getenv("PGPASSWORD", ""),
                       "sslmode": "prefer"}
        if not self.target["password"]:
            import psycopg.conninfo

            self.target["password"] = psycopg.conninfo.conninfo_to_dict(self.conn.info.dsn).get("password", "") or \
                self._pgpass()

    def _pgpass(self) -> str:
        path = Path(os.getenv("APPDATA", "")) / "postgresql" / "pgpass.conf"
        for line in path.read_text(encoding="utf-8").splitlines() if path.is_file() else []:
            host, port, database, user, password = line.split(":", 4)
            if port in ("*", str(self.target["port"])) and user in ("*", self.target["username"]):
                return password
        return ""

    def scan(self) -> dict:
        # The database is on this host, and loopback is never a scan target: allowed here only.
        with (mock.patch("backend.app._validate_scan_target"),
              mock.patch("collectors.net_guard.resolve_and_pin", return_value="127.0.0.1")):
            response = self.client.post("/api/database/scan", headers=self.headers, json={
                **self.target, "schemas": ["public"], "include_tables": [f"public.{self.prefix}_*"],
                "sample_rows": 1000, "compact_result": False, "scan_label": "d6 seed"})
        self.assertEqual(response.status_code, 200, response.text[:400])
        return response.json()

    def test_the_scanning_session_cannot_write(self) -> None:
        import psycopg

        source = database_scanner.DatabaseSource(engine="postgresql", host="127.0.0.1", port=self.target["port"],
                                                 database=self.target["database"], username=self.target["username"],
                                                 password=self.target["password"], sslmode="prefer", address="127.0.0.1")
        connection = database_scanner.connect(source)
        self.addCleanup(connection.close)
        self.addCleanup(self.conn.execute, f"DROP TABLE IF EXISTS {self.prefix}_written")
        with self.assertRaises(psycopg.errors.ReadOnlySqlTransaction):
            connection.execute(f"CREATE TABLE {self.prefix}_written (x int)")

    def test_seeded_columns_are_found_with_exact_counts_and_nothing_raw_leaves(self) -> None:
        report = self.scan()
        columns = {entry["name"].split(".", 1)[1]: entry for entry in report["files"]}
        card, email = columns[f"{self.prefix}_customers.card"], columns[f"{self.prefix}_customers.email"]
        self.assertEqual((card["database"]["table_rows"], card["database"]["table_rows_exact"],
                          card["database"]["sampled_rows"]), (2500, True, 1000))
        self.assertEqual(card["database"]["non_null_sampled"], 40)
        self.assertTrue(card["findings"] and email["findings"])
        self.assertEqual(columns[f"{self.prefix}_customers.note"]["findings"], [])
        exported = self.client.get("/api/inventory/export?format=ndjson", headers=self.headers)
        findings = self.client.get("/api/findings?limit=200", headers=self.headers)
        for text in (json.dumps(report), exported.text, findings.text):
            for value in CARDS:
                self.assertNotIn(value, text)
            self.assertNotIn("customer25@example.com", text)


if __name__ == "__main__":
    unittest.main()
