"""Database column sampling (D6): which columns of a database hold sensitive data.

A database is scanned table by table, reading a bounded sample of each text column - never
the whole table - and each column becomes one record the detectors read like a file:

    postgresql://db01:5432/crm/public.customers/email

The bounds are explicit and reported with every result: at most `sample_rows` rows a table
(default 1,000, at most 10,000), `max_tables` tables, `max_columns` text columns a table,
`max_value_chars` characters a value, and a statement timeout on every query. The table's
row count is exact (COUNT(*), within the timeout) and says so, or the planner's estimate
when the count ran out of time, and says that instead - so "4 of 1,000 sampled rows hold a
card number in a table of 2,500,000 rows" is what a finding says, not a guess passed off as
a count.

Nothing read leaves the scan: the sampled values are the detectors' input only. Findings
carry masked samples and keyed fingerprints like every other finding; no value is logged,
and an error is reported by its type, never its text (a driver's message can quote a row).

The session is read-only (`default_transaction_read_only`), connects to the address the
workspace's scan targets allowed (resolved once and pinned, collectors.net_guard) and
verifies TLS as the connection's sslmode says. PostgreSQL is supported; MySQL and SQL
Server have their SQL here and need their driver (PyMySQL, pyodbc) - neither is installed
with the product: HELD until a pilot needs one.

The password is only ever offered through SCRAM-SHA-256 (M4 exit review). The host is
whatever the caller names within the workspace's scan targets, and the credential any
saved scan credential - the vault has no separate database kind - so a host that asked
libpq for the password in the clear (`password` authentication) would have been handed,
say, the file-server service account's password. libpq's `require_auth` refuses every
other method before the password goes anywhere, and under TLS `channel_binding=require`
ties the exchange to the server's certificate, so it cannot be relayed either. Saved
credentials stay one kind (README): give database scans an account of their own.

Bounded on the wire as well as in the record: a value is cut to `max_value_chars` in the
SQL, so a 5 MB jsonb cell sends its first 256 characters, not 5 MB; rows are fetched in
batches; and each table's columns are handed to the engine (`record_callback`) as soon as
the table is read, so analysis starts while the next table is sampled.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger(__name__)

ENGINES = ("postgresql", "mysql", "sqlserver")
DEFAULT_PORTS = {"postgresql": 5432, "mysql": 3306, "sqlserver": 1433}
MAX_SAMPLE_ROWS = 10_000
FETCH_ROWS = 200  # rows a fetch: the sample is read in batches, never all at once
# libpq 16 added require_auth; an older one cannot refuse a cleartext-password request.
LIBPQ_REQUIRE_AUTH = 160000
TLS_SSLMODES = ("require", "verify-ca", "verify-full")
TEXT_TYPES = {
    "postgresql": {"text", "character varying", "character", "json", "jsonb", "citext", "uuid", "xml", "name"},
    "mysql": {"char", "varchar", "tinytext", "text", "mediumtext", "longtext", "json", "enum", "set"},
    "sqlserver": {"char", "varchar", "nchar", "nvarchar", "text", "ntext", "xml", "uniqueidentifier"},
}
SYSTEM_SCHEMAS = {
    "postgresql": {"pg_catalog", "information_schema", "pg_toast"},
    "mysql": {"mysql", "information_schema", "performance_schema", "sys"},
    "sqlserver": {"sys", "INFORMATION_SCHEMA"},
}


class DatabaseScanError(RuntimeError):
    """The database could not be scanned. `str()` is safe to show."""

    client_safe = True  # backend.errors: every message here is written for the person


class DriverMissing(DatabaseScanError):
    """The engine's driver is not installed with this product."""


@dataclass
class DatabaseSource:
    engine: str
    host: str
    port: int
    database: str
    username: str
    password: str = field(default="", repr=False)
    sslmode: str = "verify-full"
    schemas: list[str] = field(default_factory=list)
    include_tables: list[str] = field(default_factory=list)  # "schema.table" patterns (fnmatch)
    sample_rows: int = 1000
    max_tables: int = 500
    max_columns: int = 200
    max_value_chars: int = 256
    statement_timeout_ms: int = 15_000
    address: str = ""  # the pinned address to dial; the host name is kept for TLS

    def bounded(self) -> "DatabaseSource":
        if self.engine not in ENGINES:
            raise DatabaseScanError("Choose postgresql, mysql or sqlserver.")
        self.sample_rows = max(1, min(MAX_SAMPLE_ROWS, int(self.sample_rows or 1000)))
        self.max_tables = max(1, min(5000, int(self.max_tables or 500)))
        self.max_columns = max(1, min(1000, int(self.max_columns or 200)))
        self.max_value_chars = max(16, min(4096, int(self.max_value_chars or 256)))
        self.statement_timeout_ms = max(1000, min(300_000, int(self.statement_timeout_ms or 15_000)))
        return self

    def location(self, *parts: str) -> str:
        return f"{self.engine}://{self.host}:{self.port}/{self.database}/" + "/".join(parts)


# ── dialects: the SQL, and nothing else ────────────────────────────────────────────
class Dialect:
    engine = ""

    def quote(self, name: str) -> str:
        raise NotImplementedError

    def tables_sql(self, schemas: list[str]) -> tuple[str, list]:
        system = sorted(SYSTEM_SCHEMAS[self.engine])
        clauses = ["table_type = 'BASE TABLE'"]
        params: list = []
        if schemas:
            clauses.append("table_schema IN (" + ", ".join(self.marker for _ in schemas) + ")")
            params += schemas
        else:
            clauses.append("table_schema NOT IN (" + ", ".join(self.marker for _ in system) + ")")
            params += system
        return (f"SELECT table_schema, table_name FROM information_schema.tables WHERE {' AND '.join(clauses)} "
                "ORDER BY table_schema, table_name", params)

    def columns_sql(self) -> str:
        return ("SELECT column_name, data_type FROM information_schema.columns "
                f"WHERE table_schema = {self.marker} AND table_name = {self.marker} ORDER BY ordinal_position")

    def count_sql(self, schema: str, table: str) -> str:
        return f"SELECT COUNT(*) FROM {self.quote(schema)}.{self.quote(table)}"

    def sample_sql(self, schema: str, table: str, columns: list[str], limit: int, max_chars: int) -> str:
        """At most `limit` rows of `columns`, each value cut to `max_chars` characters by
        the database - what crosses the wire is the bounded sample, not the cell."""
        raise NotImplementedError

    marker = "%s"


class PostgresDialect(Dialect):
    engine = "postgresql"

    def quote(self, name: str) -> str:
        return '"' + str(name).replace('"', '""') + '"'

    def sample_sql(self, schema: str, table: str, columns: list[str], limit: int, max_chars: int) -> str:
        selected = ", ".join(f"left({self.quote(column)}::text, {int(max_chars)})" for column in columns)
        return f"SELECT {selected} FROM {self.quote(schema)}.{self.quote(table)} LIMIT {int(limit)}"

    def estimate_sql(self) -> str:
        return ("SELECT GREATEST(c.reltuples, 0)::bigint FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = %s AND c.relname = %s")


class MySQLDialect(Dialect):
    engine = "mysql"

    def quote(self, name: str) -> str:
        return "`" + str(name).replace("`", "``") + "`"

    def sample_sql(self, schema: str, table: str, columns: list[str], limit: int, max_chars: int) -> str:
        selected = ", ".join(f"LEFT(CAST({self.quote(column)} AS CHAR), {int(max_chars)})" for column in columns)
        return f"SELECT {selected} FROM {self.quote(schema)}.{self.quote(table)} LIMIT {int(limit)}"


class SQLServerDialect(Dialect):
    engine = "sqlserver"
    marker = "?"

    def quote(self, name: str) -> str:
        return "[" + str(name).replace("]", "]]") + "]"

    def count_sql(self, schema: str, table: str) -> str:
        return f"SELECT COUNT_BIG(*) FROM {self.quote(schema)}.{self.quote(table)}"

    def sample_sql(self, schema: str, table: str, columns: list[str], limit: int, max_chars: int) -> str:
        selected = ", ".join(f"LEFT(CAST({self.quote(column)} AS NVARCHAR(MAX)), {int(max_chars)})" for column in columns)
        return f"SELECT TOP ({int(limit)}) {selected} FROM {self.quote(schema)}.{self.quote(table)}"


DIALECTS = {"postgresql": PostgresDialect(), "mysql": MySQLDialect(), "sqlserver": SQLServerDialect()}


# ── connecting ─────────────────────────────────────────────────────────────────────
def connect(source: DatabaseSource):
    """A read-only session to `source`, dialled at its pinned address."""
    if source.engine == "postgresql":
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - psycopg is in the PostgreSQL extra
            raise DriverMissing("The PostgreSQL driver (psycopg) is not installed.") from exc
        if psycopg.pq.version() < LIBPQ_REQUIRE_AUTH:
            raise DatabaseScanError("This install's PostgreSQL client library (libpq) is older than 16 and cannot "
                                    "refuse a server that asks for the password in the clear, so no database is "
                                    "scanned with it. Install psycopg[binary] from requirements-postgres.txt.")
        # Only SCRAM-SHA-256 is offered the password; under TLS the exchange is bound to
        # the server's certificate. Unknown to psycopg, both go to libpq as they are.
        auth = {"require_auth": "scram-sha-256"}
        if source.sslmode in TLS_SSLMODES:
            auth["channel_binding"] = "require"
        try:
            return psycopg.connect(host=source.host, hostaddr=source.address or None, port=source.port,
                                   dbname=source.database, user=source.username, password=source.password,
                                   sslmode=source.sslmode, connect_timeout=10, autocommit=True,
                                   options=f"-c default_transaction_read_only=on "
                                           f"-c statement_timeout={source.statement_timeout_ms}", **auth)
        except psycopg.Error as exc:
            # libpq's own wording, read here and never repeated: the message is said in ours.
            text = str(exc)
            if "authentication method requirement" in text or "channel binding" in text:
                bound = " with channel binding" if "channel_binding" in auth else ""
                raise DatabaseScanError(
                    f"{source.host}:{source.port} did not authenticate with SCRAM-SHA-256{bound}, the only way "
                    "this scan offers a password; the password was not sent. Set the account to scram-sha-256 in "
                    "the server's pg_hba.conf (and password_encryption).") from exc
            raise DatabaseScanError(f"Could not connect to {source.host}:{source.port} ({type(exc).__name__}).") from exc
    driver = {"mysql": "PyMySQL", "sqlserver": "pyodbc"}[source.engine]
    raise DriverMissing(f"Scanning {source.engine} needs its driver ({driver}), which is not installed with this "
                        "product. HELD until a pilot needs it.")


# ── scanning ───────────────────────────────────────────────────────────────────────
def _row_count(cursor, dialect: Dialect, schema: str, table: str) -> tuple[int, bool]:
    """(rows, exact). The planner's estimate when the exact count ran out of time."""
    try:
        cursor.execute(dialect.count_sql(schema, table))
        return int(cursor.fetchone()[0]), True
    except Exception as exc:
        logger.info("Row count of a table timed out or failed (%s); using the estimate", type(exc).__name__)
        if isinstance(dialect, PostgresDialect):
            cursor.execute(dialect.estimate_sql(), (schema, table))
            row = cursor.fetchone()
            return int(row[0] if row else 0), False
        return 0, False


def scan(source: DatabaseSource, *, connection=None, cancel_check=None,
         record_callback: Callable[[dict], None] | None = None) -> tuple[list[dict], dict]:
    """(records, diagnostics): one record a sampled text column. `record_callback` gets
    each table's records as soon as the table is read, so the engine analyses one table
    while the next is sampled instead of after the last."""
    source.bounded()
    dialect = DIALECTS[source.engine]
    conn = connection or connect(source)
    records: list[dict] = []
    diagnostics = {"mode": "database", "engine": source.engine, "database": source.database,
                   "sample_rows_limit": source.sample_rows, "max_tables": source.max_tables,
                   "max_columns": source.max_columns, "max_value_chars": source.max_value_chars,
                   "statement_timeout_ms": source.statement_timeout_ms, "tables": 0, "columns": 0,
                   "tables_skipped": 0, "columns_skipped": 0, "errors": []}
    try:
        cursor = conn.cursor()
        sql, params = dialect.tables_sql(source.schemas)
        cursor.execute(sql, params)
        tables = [(str(row[0]), str(row[1])) for row in cursor.fetchall()]
        if source.include_tables:
            tables = [(schema, table) for schema, table in tables
                      if any(fnmatch.fnmatchcase(f"{schema}.{table}", pattern) for pattern in source.include_tables)]
        if len(tables) > source.max_tables:
            diagnostics["tables_skipped"] = len(tables) - source.max_tables
            tables = tables[:source.max_tables]
        for schema, table in tables:
            if cancel_check and cancel_check():
                diagnostics["cancelled"] = True
                break
            try:
                table_records = _scan_table(cursor, dialect, source, schema, table, diagnostics)
            except Exception as exc:
                # The table is named in the report; the error only by its type.
                diagnostics["errors"].append({"table": f"{schema}.{table}", "error": type(exc).__name__})
                continue
            diagnostics["tables"] += 1
            records.extend(table_records)
            # Outside the try: the engine refusing a record is not this table failing.
            if record_callback is not None:
                for record in table_records:
                    record_callback(record)
        diagnostics["columns"] = len(records)
        # What was in scope and not read - a table that failed, tables or columns past the
        # limits, a cancelled scan - makes the scan incomplete, in the engine's own markers:
        # a named, complete scan prunes what it did not see, and these were not looked at.
        if diagnostics["errors"]:
            diagnostics["scan_errors"] = len(diagnostics["errors"])
        if diagnostics["tables_skipped"] or diagnostics["columns_skipped"]:
            diagnostics["record_limit_reached"] = True
        if diagnostics.get("cancelled"):
            diagnostics["scan_aborted_reason"] = "cancelled"
    finally:
        if connection is None:
            try:
                conn.close()
            except Exception:
                pass
    diagnostics["records"] = len(records)
    return records, diagnostics


def _scan_table(cursor, dialect: Dialect, source: DatabaseSource, schema: str, table: str,
                diagnostics: dict | None = None) -> list[dict]:
    cursor.execute(dialect.columns_sql(), (schema, table))
    text_types = TEXT_TYPES[source.engine]
    columns = [(str(name), str(kind)) for name, kind in cursor.fetchall() if str(kind).lower() in text_types]
    if len(columns) > source.max_columns and diagnostics is not None:
        diagnostics["columns_skipped"] += len(columns) - source.max_columns
    columns = columns[:source.max_columns]
    if not columns:
        return []
    rows, exact = _row_count(cursor, dialect, schema, table)
    if exact and rows == 0:
        return []  # nothing to sample: counted in the diagnostics, not inventoried
    cursor.execute(dialect.sample_sql(schema, table, [name for name, _ in columns], source.sample_rows,
                                      source.max_value_chars))
    # In batches: only the cut values are kept, one list a column, never the rows as well.
    sampled = 0
    column_values: list[list[str]] = [[] for _ in columns]
    while sampled < source.sample_rows:
        batch = cursor.fetchmany(FETCH_ROWS)
        if not batch:
            break
        sampled += len(batch)
        for row in batch:
            for index, values in enumerate(column_values):
                if row[index] is not None:
                    # Cut in the SQL already; cut again in case a driver counts differently.
                    values.append(str(row[index])[:source.max_value_chars])
    records = []
    for (column, kind), values in zip(columns, column_values):
        content = "\n".join(values)
        complete = exact and sampled >= rows
        records.append({
            "source": "database", "path": source.location(f"{schema}.{table}", column),
            "name": f"{schema}.{table}.{column}", "extension": ".column", "size": len(content.encode("utf-8")),
            "is_dir": False, "content": content, "content_status": "sampled", "content_scannable": True,
            "scan_completeness": "COMPLETE" if complete else "PARTIAL", "truncated": not complete,
            "bytes_scanned": len(content.encode("utf-8")), "total_bytes": len(content.encode("utf-8")),
            "database": {"engine": source.engine, "database": source.database, "schema": schema, "table": table,
                         "column": column, "data_type": kind, "table_rows": rows, "table_rows_exact": exact,
                         "sampled_rows": sampled, "non_null_sampled": len(values),
                         "sample_limit": source.sample_rows},
        })
    return records
