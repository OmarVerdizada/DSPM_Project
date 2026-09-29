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
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

ENGINES = ("postgresql", "mysql", "sqlserver")
DEFAULT_PORTS = {"postgresql": 5432, "mysql": 3306, "sqlserver": 1433}
MAX_SAMPLE_ROWS = 10_000
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

    def sample_sql(self, schema: str, table: str, columns: list[str], limit: int) -> str:
        raise NotImplementedError

    marker = "%s"


class PostgresDialect(Dialect):
    engine = "postgresql"

    def quote(self, name: str) -> str:
        return '"' + str(name).replace('"', '""') + '"'

    def sample_sql(self, schema: str, table: str, columns: list[str], limit: int) -> str:
        selected = ", ".join(f"{self.quote(column)}::text" for column in columns)
        return f"SELECT {selected} FROM {self.quote(schema)}.{self.quote(table)} LIMIT {int(limit)}"

    def estimate_sql(self) -> str:
        return ("SELECT GREATEST(c.reltuples, 0)::bigint FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = %s AND c.relname = %s")


class MySQLDialect(Dialect):
    engine = "mysql"

    def quote(self, name: str) -> str:
        return "`" + str(name).replace("`", "``") + "`"

    def sample_sql(self, schema: str, table: str, columns: list[str], limit: int) -> str:
        selected = ", ".join(f"CAST({self.quote(column)} AS CHAR)" for column in columns)
        return f"SELECT {selected} FROM {self.quote(schema)}.{self.quote(table)} LIMIT {int(limit)}"


class SQLServerDialect(Dialect):
    engine = "sqlserver"
    marker = "?"

    def quote(self, name: str) -> str:
        return "[" + str(name).replace("]", "]]") + "]"

    def count_sql(self, schema: str, table: str) -> str:
        return f"SELECT COUNT_BIG(*) FROM {self.quote(schema)}.{self.quote(table)}"

    def sample_sql(self, schema: str, table: str, columns: list[str], limit: int) -> str:
        selected = ", ".join(f"CAST({self.quote(column)} AS NVARCHAR(MAX))" for column in columns)
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
        try:
            return psycopg.connect(host=source.host, hostaddr=source.address or None, port=source.port,
                                   dbname=source.database, user=source.username, password=source.password,
                                   sslmode=source.sslmode, connect_timeout=10, autocommit=True,
                                   options=f"-c default_transaction_read_only=on "
                                           f"-c statement_timeout={source.statement_timeout_ms}")
        except psycopg.Error as exc:
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


def scan(source: DatabaseSource, *, connection=None, cancel_check=None) -> tuple[list[dict], dict]:
    """(records, diagnostics): one record a sampled text column."""
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
                records.extend(_scan_table(cursor, dialect, source, schema, table, diagnostics))
                diagnostics["tables"] += 1
            except Exception as exc:
                # The table is named in the report; the error only by its type.
                diagnostics["errors"].append({"table": f"{schema}.{table}", "error": type(exc).__name__})
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
    cursor.execute(dialect.sample_sql(schema, table, [name for name, _ in columns], source.sample_rows))
    sampled = cursor.fetchall()
    records = []
    for index, (column, kind) in enumerate(columns):
        values = [str(row[index])[:source.max_value_chars] for row in sampled if row[index] is not None]
        content = "\n".join(values)
        complete = exact and len(sampled) >= rows
        records.append({
            "source": "database", "path": source.location(f"{schema}.{table}", column),
            "name": f"{schema}.{table}.{column}", "extension": ".column", "size": len(content.encode("utf-8")),
            "is_dir": False, "content": content, "content_status": "sampled", "content_scannable": True,
            "scan_completeness": "COMPLETE" if complete else "PARTIAL", "truncated": not complete,
            "bytes_scanned": len(content.encode("utf-8")), "total_bytes": len(content.encode("utf-8")),
            "database": {"engine": source.engine, "database": source.database, "schema": schema, "table": table,
                         "column": column, "data_type": kind, "table_rows": rows, "table_rows_exact": exact,
                         "sampled_rows": len(sampled), "non_null_sampled": len(values),
                         "sample_limit": source.sample_rows},
        })
    return records
