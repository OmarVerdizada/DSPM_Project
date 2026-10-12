"""W4.4: the console's counts, maintained as the rows they count change.

The remediation summary and facets and the inventory facets were aggregates over every
finding and every asset of a tenant - a dozen passes, JSON arrays unnested, two COUNT
(DISTINCT) - rebuilt whenever a write moved the estate generation: 30 to 45 s at 5 million
findings (scaling roadmap, section 23), during a scan for every unit it wrote. They are
now read from counts the database keeps as the rows change:

- ``estate_counts`` holds one row per tenant, dimension and key - ``f.status`` /
  ``CONFIRMED`` / current - with how many rows have it (``n``) and what they add up to
  (``occ``: occurrences, or risk scores);
- triggers on ``findings`` and ``assets`` maintain them, for every write path there is or
  will be - no hook to miss. On PostgreSQL a statement-level trigger appends the
  statement's net change, aggregated, to ``estate_count_deltas``: append-only, so two
  units written at once never wait on the same hot count row (W4.5). Only rows whose
  counted columns changed are counted, so a presence stamp or an unchanged rescan costs
  nothing. On SQLite (development and tests) row triggers update the counts directly;
- the deltas are folded into the counts under a per-tenant lock - after a unit is written
  and before a read - in one statement, which also keeps ``f.active_files`` (files with
  an active finding) from the per-file counts crossing zero;
- what a count cannot know - "now" - stays in the read: overdue findings and the age of
  sensitive files are kept by day, and the day that holds "now" is counted from its rows;
- ``reconcile`` recomputes every count from the rows, records the difference and repairs
  it: the drift is visible, never silent. The direct aggregates remain the oracle
  (``DSPM_MAINTAINED_COUNTS=0``).

Nothing here is evidence: dimensions hold statuses, severities, frameworks, data types,
owners, shares, folders and the affected asset's name - what the facets already show.

Revision 0055 counts ``asset_access`` too - per principal, how many files it can read,
write or fully control (and how many of them hold sensitive data), how many it owns or is
denied on - so "who can read the sensitive files" is read from counts, not aggregated
over every access row of the estate; and per file, the sensitive files a broad group can
read or write and the files an unresolved SID appears on. ``k2`` of the per-principal
dimensions is the principal's class (broad, privileged, service, unresolved), fixed by its
SID, so a class is listed from the counts alone. A table's triggers are written only
once it has every column they read: revision 0053 runs before 0055 adds them.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone

from backend import db

COUNTS_TABLE = "estate_counts"
# The tables counted, and the columns that identify one of their rows.
TABLES = ("findings", "assets", "asset_access")
KEY_COLUMNS = {"findings": ("id",), "assets": ("id",), "asset_access": ("asset_id", "principal_key")}
# A principal's class, from flags its SID fixes: k2 of the per-principal dimensions.
PRINCIPAL_CLASS = ("CASE WHEN r.broad = 1 THEN 'broad' WHEN r.privileged = 1 THEN 'privileged' "
                   "WHEN r.service = 1 THEN 'service' WHEN r.unresolved = 1 THEN 'unresolved' ELSE '' END")
PRINCIPAL_CLASSES = ("broad", "privileged", "service", "unresolved")
DELTAS_TABLE = "estate_count_deltas"
STATE_TABLE = "estate_count_state"
INDEXES = ("idx_estate_count_deltas_tenant", "idx_estate_counts_top")
# The PostgreSQL advisory lock a tenant's fold and reconcile hold (namespace: "ECNT").
_LOCK_NAMESPACE = 0x45434E54


def enabled() -> bool:
    """``DSPM_MAINTAINED_COUNTS`` (on): read the console's counts from ``estate_counts``.
    Off, the direct aggregates answer, as they did before W4.4."""
    return str(os.getenv("DSPM_MAINTAINED_COUNTS", "1")).strip().lower() not in {"0", "false", "no", "off"}


@dataclass(frozen=True)
class Dim:
    """One counted dimension: ``keys`` are SQL over a row ``r`` (``item`` is the element of
    ``json_column`` when it is set); ``k3`` is the findings' scope unless given."""
    name: str
    table: str
    keys: tuple[str, ...] = ()
    json_column: str = ""
    where: str = ""
    occ: str = "0"
    k3: str = ""


# The statuses that count as active - backend.store.REMEDIATION_ACTIVE_STATUSES, which a test
# holds this equal to. Its own copy: the store migrates at import, above where it defines its.
ACTIVE_STATUSES = ("NEW", "OPEN", "UNDER_REVIEW", "CONFIRMED", "REOPENED", "ASSIGNED", "IN_PROGRESS",
                   "PENDING_VALIDATION")


def _active(statuses: tuple[str, ...]) -> str:
    return "r.status IN (" + ", ".join(f"'{status}'" for status in statuses) + ")"


def dims(active_statuses: tuple[str, ...] = ACTIVE_STATUSES) -> tuple[Dim, ...]:
    active = _active(active_statuses)
    return (
        # findings - k3 is is_current ('0'/'1'), so current, historical and all are sums
        Dim("f.total", "findings", occ="COALESCE(r.occurrence_count, 0)"),
        Dim("f.status", "findings", ("COALESCE(r.status, '')",)),
        Dim("f.severity", "findings", ("COALESCE(r.severity, '')",)),
        Dim("f.owner", "findings", ("COALESCE(r.owner, '')",)),
        Dim("f.category", "findings", ("COALESCE(r.category, '')",)),
        Dim("f.data_type", "findings", ("COALESCE(r.data_type, '')",)),
        Dim("f.asset", "findings", ("COALESCE(r.affected_asset, '')",)),
        Dim("f.asset_all", "findings", ("COALESCE(r.affected_asset, '')",), k3="'*'"),
        Dim("f.framework", "findings", ("COALESCE(item.value, '')",), json_column="frameworks_json",
            occ="COALESCE(r.occurrence_count, 0)"),
        Dim("f.active_sla_day", "findings", ("substr(r.sla_due, 1, 10)",),
            where=f"{active} AND COALESCE(r.sla_due, '') <> ''"),
        # per file, read only through f.active_files - kept by the fold (PostgreSQL)
        Dim("f.active_asset", "findings", ("COALESCE(r.asset_id, '')",), where=active),
        Dim("f.active_asset_all", "findings", ("COALESCE(r.asset_id, '')",), where=active, k3="'*'"),
        # per file with a broadly exposed finding - read only through f.exposed_files
        Dim("f.exposed_asset", "findings", ("COALESCE(r.asset_id, '')",),
            where="r.exposure IN ('PUBLIC', 'BROAD_INTERNAL', 'WRITABLE_INTERNAL')"),
        # assets
        Dim("a.total", "assets", occ="COALESCE(r.risk_score, 0)"),
        Dim("a.risk", "assets", ("COALESCE(r.risk_level, '')",)),
        Dim("a.source_unlabeled", "assets", ("COALESCE(r.source, '')",), where="COALESCE(r.scan_label, '') = ''"),
        Dim("a.label", "assets", ("r.scan_label",), where="COALESCE(r.scan_label, '') <> ''"),
        Dim("a.protected", "assets", where="r.is_protected = 1"),
        Dim("a.hidden", "assets", where="r.is_hidden = 1"),
        Dim("a.sensitive", "assets", where="r.finding_count > 0"),
        Dim("a.type_sev", "assets", ("COALESCE(item.value, '')", "COALESCE(r.risk_level, '')"),
            json_column="finding_types"),
        Dim("a.framework_sev", "assets", ("COALESCE(item.value, '')", "COALESCE(r.risk_level, '')"),
            json_column="framework_keys"),
        Dim("a.share_sev", "assets", ("r.share", "COALESCE(r.risk_level, '')"), where="COALESCE(r.share, '') <> ''"),
        Dim("a.share_folder_sev", "assets", ("r.share", "{first_segment}", "COALESCE(r.risk_level, '')"),
            where="COALESCE(r.share, '') <> ''"),
        Dim("a.sensitive_day", "assets", ("substr(COALESCE(r.modified_at, ''), 1, 10)",), where="r.finding_count > 0"),
        # revision 0055: whether each file's ACL was read
        Dim("a.acl_state", "assets", ("COALESCE(r.acl_state, '')",)),
        # asset_access - per principal (k1), its class (k2)
        Dim("x.read", "asset_access", ("r.principal_key", PRINCIPAL_CLASS), where="r.can_read = 1"),
        Dim("x.read_sensitive", "asset_access", ("r.principal_key", PRINCIPAL_CLASS),
            where="r.can_read = 1 AND r.sensitive = 1"),
        Dim("x.write", "asset_access", ("r.principal_key", PRINCIPAL_CLASS), where="r.can_write = 1"),
        Dim("x.write_sensitive", "asset_access", ("r.principal_key", PRINCIPAL_CLASS),
            where="r.can_write = 1 AND r.sensitive = 1"),
        Dim("x.full", "asset_access", ("r.principal_key", PRINCIPAL_CLASS), where="r.full_control = 1"),
        Dim("x.full_sensitive", "asset_access", ("r.principal_key", PRINCIPAL_CLASS),
            where="r.full_control = 1 AND r.sensitive = 1"),
        Dim("x.deny", "asset_access", ("r.principal_key", PRINCIPAL_CLASS), where="r.has_deny = 1"),
        Dim("x.owner", "asset_access", ("r.principal_key", PRINCIPAL_CLASS), where="r.is_owner = 1"),
        Dim("x.explicit", "asset_access", ("r.principal_key", PRINCIPAL_CLASS), where="r.has_explicit = 1"),
        # per file, read only through their counts of files (x.*_files)
        Dim("x.broad_read_asset", "asset_access", ("r.asset_id",),
            where="r.broad = 1 AND r.can_read = 1 AND r.sensitive = 1"),
        Dim("x.broad_write_asset", "asset_access", ("r.asset_id",),
            where="r.broad = 1 AND r.can_write = 1 AND r.sensitive = 1"),
        Dim("x.unresolved_asset", "asset_access", ("r.asset_id",), where="r.unresolved = 1"),
    )


# The columns a count reads, by table: an update that changes none of them changes no count.
COUNTED_COLUMNS = {
    "findings": ("tenant_id", "id", "status", "severity", "owner", "category", "data_type", "affected_asset",
                 "frameworks_json", "occurrence_count", "sla_due", "is_current", "asset_id", "exposure"),
    "assets": ("tenant_id", "id", "risk_level", "risk_score", "source", "scan_label", "is_protected", "is_hidden",
               "finding_count", "finding_types", "framework_keys", "share", "path", "modified_at", "acl_state"),
    "asset_access": ("tenant_id", "asset_id", "principal_key", "can_read", "can_write", "full_control", "has_deny",
                     "is_owner", "has_explicit", "sensitive", "broad", "privileged", "service", "unresolved"),
}
# Per-file dimensions, and the count of files they keep: files whose count is positive.
DISTINCT = {"f.active_asset": "f.active_files", "f.active_asset_all": "f.active_files",
            "f.exposed_asset": "f.exposed_files", "x.broad_read_asset": "x.broad_read_files",
            "x.broad_write_asset": "x.broad_write_files", "x.unresolved_asset": "x.unresolved_files"}


def table_ready(conn, table: str) -> bool:
    """Whether ``table`` has every column its counts read - not yet, for asset_access and
    assets, while revisions 0053 and 0054 run on a database revision 0055 has not reached."""
    present = {str(column).lower() for column in db.table_columns(conn, table)}
    return bool(present) and all(column in present for column in COUNTED_COLUMNS[table])


def _first_segment() -> str:
    if db.is_postgres():
        return "split_part(ltrim(replace(r.path, '\\', '/'), '/'), '/', 1)"
    return ("substr(ltrim(replace(r.path, '\\', '/'), '/'), 1, "
            "instr(ltrim(replace(r.path, '\\', '/'), '/') || '/', '/') - 1)")


def _json_items(column: str) -> str:
    """A row's JSON array, as rows ``item(value)``; anything that is not an array is none."""
    # Nested CASE, not AND: neither engine promises to test the validity first, and a cast
    # that raised would fail the scan's write that fired the trigger.
    if db.is_postgres():
        return (f"CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN pg_input_is_valid(COALESCE(r.{column}, ''), "
                f"'jsonb') THEN CASE WHEN jsonb_typeof(r.{column}::jsonb) = 'array' THEN r.{column}::jsonb "
                f"ELSE '[]'::jsonb END ELSE '[]'::jsonb END) AS item(value)")
    return (f", json_each(CASE WHEN json_valid(COALESCE(r.{column}, '')) THEN CASE WHEN json_type(r.{column}) = "
            f"'array' THEN r.{column} ELSE '[]' END ELSE '[]' END) AS item")


def _select(dim: Dim, source: str, sign: int) -> str:
    """One dimension's rows over ``source`` (a table or transition table, aliased ``r``)."""
    keys = [key.replace("{first_segment}", _first_segment()) for key in dim.keys] + ["''"] * (3 - len(dim.keys))
    if dim.table == "findings" and len(dim.keys) < 3:
        k3 = dim.k3 or ("CAST(r.is_current AS TEXT)")
        keys = keys[:2] + [k3]
    elif dim.k3:
        keys = keys[:2] + [dim.k3]
    joined = _json_items(dim.json_column) if dim.json_column else ""
    where = f" WHERE {dim.where}" if dim.where else ""
    return (f"SELECT r.tenant_id AS tenant_id, '{dim.name}' AS dim, {keys[0]} AS k1, {keys[1]} AS k2, "
            f"{keys[2]} AS k3, {sign} AS n, ({dim.occ}) * {sign} AS occ FROM {source} AS r {joined}{where}")


def _union(all_dims: tuple[Dim, ...], table: str, source: str, sign: int) -> str:
    return " UNION ALL ".join(_select(dim, source, sign) for dim in all_dims if dim.table == table)


# --- schema ---------------------------------------------------------------------------------

def create_tables(conn) -> None:
    conn.execute(f"""CREATE TABLE IF NOT EXISTS {COUNTS_TABLE} (
            tenant_id TEXT NOT NULL,
            dim TEXT NOT NULL,
            k1 TEXT NOT NULL DEFAULT '',
            k2 TEXT NOT NULL DEFAULT '',
            k3 TEXT NOT NULL DEFAULT '',
            n BIGINT NOT NULL DEFAULT 0,
            occ BIGINT NOT NULL DEFAULT 0,
            PRIMARY KEY (tenant_id, dim, k1, k2, k3)
        );""")
    serial = "BIGSERIAL" if db.is_postgres() else "INTEGER"
    conn.execute(f"""CREATE TABLE IF NOT EXISTS {DELTAS_TABLE} (
            id {serial} PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            dim TEXT NOT NULL,
            k1 TEXT NOT NULL DEFAULT '',
            k2 TEXT NOT NULL DEFAULT '',
            k3 TEXT NOT NULL DEFAULT '',
            n BIGINT NOT NULL DEFAULT 0,
            occ BIGINT NOT NULL DEFAULT 0
        );""")
    conn.execute(f"""CREATE TABLE IF NOT EXISTS {STATE_TABLE} (
            tenant_id TEXT NOT NULL PRIMARY KEY,
            reconciled_at TEXT NOT NULL DEFAULT '',
            drift_json TEXT NOT NULL DEFAULT '{{}}',
            repaired INTEGER NOT NULL DEFAULT 0
        );""")
    # The pending deltas of a tenant, in order; the top of a large dimension by count.
    conn.execute(f"CREATE INDEX IF NOT EXISTS {INDEXES[0]} ON {DELTAS_TABLE} (tenant_id, id)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS {INDEXES[1]} ON {COUNTS_TABLE} (tenant_id, dim, k3, n DESC, k1)")


def ensure_triggers(conn, active_statuses: tuple[str, ...] = ACTIVE_STATUSES, *, force: bool = False) -> bool:
    """Write the counting triggers unless the ones in place are these: one function and three
    statement triggers per table on PostgreSQL (the function carries a digest of what it was
    written from), a row trigger per event on SQLite (their stored text is compared).
    Returns whether anything was written. The schema converges at every start, and a
    CREATE TRIGGER takes a lock on the table it is on - so nothing is written twice."""
    all_dims = dims(active_statuses)
    written = False
    for table in TABLES:
        if not table_ready(conn, table):
            continue
        if db.is_postgres():
            function = f"estate_counts_{table}"
            function_sql, triggers = _pg_statements(table, all_dims)
            definition = "\n".join([function_sql, *(create for _name, create in triggers)])
            digest = hashlib.sha256(definition.encode("utf-8")).hexdigest()[:32]
            if force or not _pg_current(conn, table, function, digest):
                conn.execute(function_sql)
                for name, create in triggers:
                    conn.execute(f"DROP TRIGGER IF EXISTS {name} ON {table}")
                    conn.execute(create)
                conn.execute(f"COMMENT ON FUNCTION {function}() IS 'estate-counts {digest}'")
                written = True
        else:
            for name, create in _sqlite_statements(table, all_dims):
                row = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
                                   (name,)).fetchone()
                if force or row is None or str(row["sql"]) != create:
                    conn.execute(f"DROP TRIGGER IF EXISTS {name}")
                    conn.execute(create)
                    written = True
    return written


def _pg_current(conn, table: str, function: str, digest: str) -> bool:
    row = conn.execute(
        "SELECT obj_description(p.oid, 'pg_proc') AS note FROM pg_proc AS p JOIN pg_namespace AS s "
        "ON s.oid = p.pronamespace WHERE p.proname = ? AND s.nspname = current_schema()", (function,)).fetchone()
    if row is None or str(row["note"] or "") != f"estate-counts {digest}":
        return False
    found = conn.execute(
        "SELECT COUNT(*) AS n FROM pg_trigger AS t JOIN pg_class AS c ON c.oid = t.tgrelid "
        "WHERE c.relname = ? AND NOT t.tgisinternal AND t.tgname IN (?, ?, ?)",
        (table, *(f"trg_{function}_{event}" for event in ("insert", "delete", "update")))).fetchone()
    return int(found["n"] or 0) == 3


def _pg_statements(table: str, all_dims: tuple[Dim, ...]) -> tuple[str, list[tuple[str, str]]]:
    columns = COUNTED_COLUMNS[table]
    keys = KEY_COLUMNS[table]
    compared = ", ".join(f"o.{column}" for column in columns if column != "tenant_id" and column not in keys)
    compared_new = ", ".join(f"n.{column}" for column in columns if column != "tenant_id" and column not in keys)
    first = keys[0]
    joined = " AND ".join(f"n.{key} = o.{key}" for key in keys)
    picked = ", ".join(f"COALESCE(o.{key}, n.{key}) AS k_{key}" for key in keys)
    listed = ", ".join(f"k_{key}" for key in keys)
    insert = f"INSERT INTO {DELTAS_TABLE} (tenant_id, dim, k1, k2, k3, n, occ) "              "SELECT tenant_id, dim, k1, k2, k3, SUM(n), SUM(occ) FROM ({rows}) AS d "              "GROUP BY tenant_id, dim, k1, k2, k3 HAVING SUM(n) <> 0 OR SUM(occ) <> 0"
    function = f"estate_counts_{table}"
    # Only the rows an update changed are counted: the old and new transition rows are
    # paired on the key, and a pair whose counted columns are all the same cancels out.
    changed = (f"(SELECT COALESCE(o.tenant_id, n.tenant_id) AS t, {picked} "
               f"FROM old_rows AS o FULL JOIN new_rows AS n ON n.tenant_id = o.tenant_id AND {joined} "
               f"WHERE o.{first} IS NULL OR n.{first} IS NULL OR ROW({compared}) IS DISTINCT FROM ROW({compared_new}))")
    old_keys = ", ".join(f"o.{key}" for key in keys)
    new_keys = ", ".join(f"n.{key}" for key in keys)
    changed_old = f"(SELECT o.* FROM old_rows AS o WHERE (o.tenant_id, {old_keys}) IN (SELECT t, {listed} FROM changed_keys))"
    changed_new = f"(SELECT n.* FROM new_rows AS n WHERE (n.tenant_id, {new_keys}) IN (SELECT t, {listed} FROM changed_keys))"
    body = f"""
BEGIN
  IF TG_OP = 'INSERT' THEN
    {insert.format(rows=_union(all_dims, table, 'new_rows', 1))};
  ELSIF TG_OP = 'DELETE' THEN
    {insert.format(rows=_union(all_dims, table, 'old_rows', -1))};
  ELSE
    WITH changed_keys AS {changed}
    {insert.format(rows=_union(all_dims, table, changed_old, -1) + ' UNION ALL '
                   + _union(all_dims, table, changed_new, 1))};
  END IF;
  RETURN NULL;
END"""
    function_sql = f"CREATE OR REPLACE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $fn${body}$fn$"
    triggers = []
    for event, referencing in (("INSERT", "NEW TABLE AS new_rows"), ("DELETE", "OLD TABLE AS old_rows"),
                               ("UPDATE", "OLD TABLE AS old_rows NEW TABLE AS new_rows")):
        name = f"trg_{function}_{event.lower()}"
        triggers.append((name, f"CREATE TRIGGER {name} AFTER {event} ON {table} REFERENCING {referencing} "
                               f"FOR EACH STATEMENT EXECUTE FUNCTION {function}()"))
    return function_sql, triggers


def _sqlite_statements(table: str, all_dims: tuple[Dim, ...]) -> list[tuple[str, str]]:
    columns = COUNTED_COLUMNS[table]

    def apply(which: str, sign: int) -> str:
        row = ", ".join(f"{which}.{column} AS {column}" for column in columns)
        rows = _union(all_dims, table, f"(SELECT {row})", sign)
        return (f"INSERT INTO {COUNTS_TABLE} (tenant_id, dim, k1, k2, k3, n, occ) "
                f"SELECT tenant_id, dim, k1, k2, k3, SUM(n), SUM(occ) FROM ({rows}) WHERE 1 "
                "GROUP BY tenant_id, dim, k1, k2, k3 "
                "ON CONFLICT (tenant_id, dim, k1, k2, k3) DO UPDATE SET n = n + excluded.n, occ = occ + excluded.occ;")

    watched = ", ".join(column for column in columns if column != "tenant_id" and column not in KEY_COLUMNS[table])
    statements = []
    for event, body in (("INSERT", apply("NEW", 1)), ("DELETE", apply("OLD", -1)),
                        (f"UPDATE OF {watched}", apply("OLD", -1) + " " + apply("NEW", 1))):
        name = f"trg_estate_counts_{table}_{event.split()[0].lower()}"
        statements.append((name, f"CREATE TRIGGER {name} AFTER {event} ON {table} BEGIN {body} END"))
    return statements


def drop_triggers(conn) -> None:
    for table in TABLES:
        for event in ("insert", "delete", "update"):
            if db.is_postgres():
                conn.execute(f"DROP TRIGGER IF EXISTS trg_estate_counts_{table}_{event} ON {table}")
            else:
                conn.execute(f"DROP TRIGGER IF EXISTS trg_estate_counts_{table}_{event}")


# --- counting from the rows (backfill, reconcile, the oracle) --------------------------------

def recount(conn, tenant_id: str | None, active_statuses: tuple[str, ...] = ACTIVE_STATUSES) -> list[tuple]:
    """Every count, from the rows: ``(tenant_id, dim, k1, k2, k3, n, occ)``."""
    all_dims = dims(active_statuses)
    rows: list[tuple] = []
    for table in TABLES:
        if not table_ready(conn, table):
            continue
        source = f"(SELECT * FROM {table} WHERE tenant_id = ?)" if tenant_id is not None else table
        for dim in all_dims:
            if dim.table != table:
                continue
            sql = (f"SELECT tenant_id, dim, k1, k2, k3, SUM(n) AS n, SUM(occ) AS occ FROM ({_select(dim, source, 1)}) AS d "
                   "GROUP BY tenant_id, dim, k1, k2, k3")
            params = (tenant_id,) if tenant_id is not None else ()
            rows.extend((str(row["tenant_id"]), str(row["dim"]), str(row["k1"] or ""), str(row["k2"] or ""),
                         str(row["k3"] or ""), int(row["n"] or 0), int(row["occ"] or 0))
                        for row in conn.execute(sql, params).fetchall())
    distinct: dict[tuple[str, str, str], int] = {}
    for tenant, dim, _k1, _k2, k3, n, _occ in rows:
        if dim in DISTINCT and n > 0:
            distinct[(tenant, DISTINCT[dim], k3)] = distinct.get((tenant, DISTINCT[dim], k3), 0) + 1
    if db.is_postgres():
        # The fold keeps these on PostgreSQL; SQLite counts the per-file rows when asked.
        rows.extend((tenant, target, "", "", k3, n, 0) for (tenant, target, k3), n in distinct.items())
    return [row for row in rows if row[5] or row[6]]


def _store_counts(conn, tenant_id: str | None, rows: list[tuple]) -> None:
    if tenant_id is None:
        conn.execute(f"DELETE FROM {COUNTS_TABLE}")
        conn.execute(f"DELETE FROM {DELTAS_TABLE}")
    else:
        conn.execute(f"DELETE FROM {COUNTS_TABLE} WHERE tenant_id = ?", (tenant_id,))
        conn.execute(f"DELETE FROM {DELTAS_TABLE} WHERE tenant_id = ?", (tenant_id,))
    if rows:
        conn.executemany(f"INSERT INTO {COUNTS_TABLE} (tenant_id, dim, k1, k2, k3, n, occ) "
                         "VALUES (?, ?, ?, ?, ?, ?, ?)", rows)


def backfill(conn, active_statuses: tuple[str, ...] = ACTIVE_STATUSES) -> int:
    """Count every tenant's rows into ``estate_counts`` (the revision; migration scope)."""
    rows = recount(conn, None, active_statuses)
    _store_counts(conn, None, rows)
    # Counted from the rows just now: as good as a reconcile, so no first read recounts them.
    now = datetime.now(timezone.utc).isoformat()
    # Only the tenants whose rows it counted: one with no rows (or none this transaction may
    # see) is counted on its first read instead.
    conn.execute(f"DELETE FROM {STATE_TABLE}")
    note = json.dumps({"keys": 0, "by_dim": {}, "backfill": True})
    conn.executemany(f"INSERT INTO {STATE_TABLE} (tenant_id, reconciled_at, drift_json, repaired) VALUES (?, ?, ?, 0)",
                     [(tenant, now, note) for tenant in sorted({row[0] for row in rows})])
    return len(rows)


# --- folding the deltas (PostgreSQL) ------------------------------------------------------

_DISTINCT_CASES = " ".join(f"WHEN '{dim}' THEN '{target}'" for dim, target in DISTINCT.items())
_DISTINCT_DIMS = ", ".join(f"'{dim}'" for dim in DISTINCT)
_FOLD_SQL = f"""
WITH moved AS (
    DELETE FROM {DELTAS_TABLE} WHERE tenant_id = ? RETURNING dim, k1, k2, k3, n, occ
), net AS (
    SELECT dim, k1, k2, k3, SUM(n) AS n, SUM(occ) AS occ FROM moved GROUP BY dim, k1, k2, k3
    HAVING SUM(n) <> 0 OR SUM(occ) <> 0
), folded AS (
    INSERT INTO {COUNTS_TABLE} AS c (tenant_id, dim, k1, k2, k3, n, occ)
    SELECT ?, dim, k1, k2, k3, n, occ FROM net
    ON CONFLICT (tenant_id, dim, k1, k2, k3) DO UPDATE SET n = c.n + EXCLUDED.n, occ = c.occ + EXCLUDED.occ
    RETURNING c.dim, c.k1, c.k2, c.k3, c.n
), crossed AS (
    SELECT CASE f.dim {_DISTINCT_CASES} END AS target, f.k3,
           SUM(CASE WHEN f.n > 0 AND f.n - d.n <= 0 THEN 1
                    WHEN f.n <= 0 AND f.n - d.n > 0 THEN -1 ELSE 0 END) AS n
    FROM folded AS f JOIN net AS d ON d.dim = f.dim AND d.k1 = f.k1 AND d.k2 = f.k2 AND d.k3 = f.k3
    WHERE f.dim IN ({_DISTINCT_DIMS}) GROUP BY 1, f.k3
)
INSERT INTO {COUNTS_TABLE} AS c (tenant_id, dim, k1, k2, k3, n, occ)
SELECT ?, target, '', '', k3, n, 0 FROM crossed WHERE n <> 0
ON CONFLICT (tenant_id, dim, k1, k2, k3) DO UPDATE SET n = c.n + EXCLUDED.n
"""


def _lock(conn, tenant_id: str) -> None:
    conn.execute("SELECT pg_advisory_xact_lock(?, hashtext(?))", (_LOCK_NAMESPACE, tenant_id))


def fold(conn, tenant_id: str) -> None:
    """Fold a tenant's pending deltas into its counts (PostgreSQL; a no-op on SQLite)."""
    if not db.is_postgres():
        return
    if conn.execute(f"SELECT 1 FROM {DELTAS_TABLE} WHERE tenant_id = ? LIMIT 1", (tenant_id,)).fetchone() is None:
        return
    _lock(conn, tenant_id)
    conn.execute(_FOLD_SQL, (tenant_id, tenant_id, tenant_id))
    conn.execute(f"DELETE FROM {COUNTS_TABLE} WHERE tenant_id = ? AND n = 0 AND occ = 0", (tenant_id,))


# --- reading -----------------------------------------------------------------------------
# A read never folds and never waits for a fold (W4.5): it reads the counts and the deltas
# not yet folded into them together - every count here is a sum, so the two add up to what
# the rows say - and a count of files adds the zero-crossings the pending per-file deltas
# make against the per-file counts. Exact, and no lock: the writers fold after they commit.

def _scopes(k3s: tuple[str, ...]) -> str:
    return ", ".join("?" for _ in k3s)


def rows(conn, tenant_id: str, names: tuple[str, ...]) -> list[tuple[str, str, str, str, int, int]]:
    """``(dim, k1, k2, k3, n, occ)`` of the dimensions named, counts and pending deltas added,
    in one statement."""
    marks = ", ".join("?" for _ in names)
    found = conn.execute(
        f"SELECT dim, k1, k2, k3, SUM(n) AS n, SUM(occ) AS occ FROM ("
        f"SELECT dim, k1, k2, k3, n, occ FROM {COUNTS_TABLE} WHERE tenant_id = ? AND dim IN ({marks}) "
        f"UNION ALL SELECT dim, k1, k2, k3, n, occ FROM {DELTAS_TABLE} WHERE tenant_id = ? AND dim IN ({marks})"
        ") AS c GROUP BY dim, k1, k2, k3 HAVING SUM(n) <> 0 OR SUM(occ) <> 0",
        (tenant_id, *names, tenant_id, *names)).fetchall()
    return [(str(row["dim"]), str(row["k1"] or ""), str(row["k2"] or ""), str(row["k3"] or ""), int(row["n"] or 0),
             int(row["occ"] or 0)) for row in found]


def ranked(conn, tenant_id: str, wanted: dict[str, tuple[int, bool]], k3s: tuple[str, ...]) -> dict[str, list]:
    """For each dimension ``name: (limit, include_empty)``: its keys by count, then key - in
    the database's own collation - as ``[(k1, n), ...]``, in one statement. For dimensions
    whose keys are few (every one here but the per-file ones)."""
    names = tuple(wanted)
    marks, scopes = ", ".join("?" for _ in names), _scopes(k3s)
    found = conn.execute(
        f"SELECT dim, k1, n FROM (SELECT dim, k1, SUM(n) AS n, ROW_NUMBER() OVER (PARTITION BY dim "
        f"ORDER BY SUM(n) DESC, k1 ASC) AS position FROM ("
        f"SELECT dim, k1, n FROM {COUNTS_TABLE} WHERE tenant_id = ? AND dim IN ({marks}) AND k3 IN ({scopes}) "
        f"UNION ALL SELECT dim, k1, n FROM {DELTAS_TABLE} WHERE tenant_id = ? AND dim IN ({marks}) AND k3 IN ({scopes})"
        ") AS c GROUP BY dim, k1 HAVING SUM(n) > 0) AS r ORDER BY dim, position",
        (tenant_id, *names, *k3s, tenant_id, *names, *k3s)).fetchall()
    out: dict[str, list] = {name: [] for name in names}
    for row in found:
        name, key = str(row["dim"]), str(row["k1"] or "")
        limit, include_empty = wanted[name]
        if (key or include_empty) and len(out[name]) < limit:
            out[name].append((key, int(row["n"] or 0)))
    return out


def top(conn, tenant_id: str, name: str, k3: str, limit: int) -> list[tuple[str, int]]:
    """The ``limit`` largest non-empty keys of a per-file dimension in one scope, from the
    index: the counts' top ``limit`` plus as many as there are pending keys, and the pending
    keys themselves, added up - no key outside those can be in the top."""
    found = conn.execute(
        f"WITH pending AS (SELECT k1, SUM(n) AS n FROM {DELTAS_TABLE} WHERE tenant_id = ? AND dim = ? AND k3 = ? "
        "GROUP BY k1), "
        f"head_keys AS (SELECT k1, n FROM {COUNTS_TABLE} WHERE tenant_id = ? AND dim = ? AND k3 = ? AND n > 0 "
        "ORDER BY n DESC, k1 ASC LIMIT ? + (SELECT COUNT(*) FROM pending)), "
        f"held AS (SELECT c.k1, c.n FROM {COUNTS_TABLE} AS c JOIN pending AS p ON p.k1 = c.k1 "
        "WHERE c.tenant_id = ? AND c.dim = ? AND c.k3 = ? AND c.k1 NOT IN (SELECT k1 FROM head_keys)) "
        "SELECT k1, SUM(n) AS n FROM (SELECT k1, n FROM head_keys UNION ALL SELECT k1, n FROM held "
        "UNION ALL SELECT k1, n FROM pending) AS c WHERE k1 <> '' GROUP BY k1 HAVING SUM(n) > 0 "
        "ORDER BY SUM(n) DESC, k1 ASC LIMIT ?",
        (tenant_id, name, k3, tenant_id, name, k3, limit, tenant_id, name, k3, limit)).fetchall()
    return [(str(row["k1"]), int(row["n"] or 0)) for row in found]


def keyed(conn, tenant_id: str, names: tuple[str, ...], keys: list[str]) -> dict[str, dict[str, int]]:
    """``{k1: {dim: n}}`` for the keys named, in the dimensions named - counts and pending
    deltas added, in one statement read through the primary key."""
    if not keys or not names:
        return {}
    marks, key_marks = ", ".join("?" for _ in names), ", ".join("?" for _ in keys)
    found = conn.execute(
        f"SELECT dim, k1, SUM(n) AS n FROM ("
        f"SELECT dim, k1, n FROM {COUNTS_TABLE} WHERE tenant_id = ? AND dim IN ({marks}) AND k1 IN ({key_marks}) "
        f"UNION ALL SELECT dim, k1, n FROM {DELTAS_TABLE} WHERE tenant_id = ? AND dim IN ({marks}) "
        f"AND k1 IN ({key_marks})) AS c GROUP BY dim, k1 HAVING SUM(n) <> 0",
        (tenant_id, *names, *keys, tenant_id, *names, *keys)).fetchall()
    out: dict[str, dict[str, int]] = {}
    for row in found:
        out.setdefault(str(row["k1"]), {})[str(row["dim"])] = int(row["n"] or 0)
    return out


def top_keys(conn, tenant_id: str, name: str, limit: int, *, k2: str | None = None) -> list[tuple[str, int]]:
    """The ``limit`` largest keys of a per-principal dimension, optionally of one class
    (``k2``). Like ``top``: the counts' head plus as many as there are pending keys, and the
    pending keys themselves, added up - no key outside those can be in the top."""
    k2_sql = " AND k2 = ?" if k2 is not None else ""
    k2_args: tuple = (k2,) if k2 is not None else ()
    found = conn.execute(
        f"WITH pending AS (SELECT k1, SUM(n) AS n FROM {DELTAS_TABLE} WHERE tenant_id = ? AND dim = ?{k2_sql} "
        "GROUP BY k1), "
        # One row a key (k2 follows from k1, k3 is ''): read in index order, no aggregate.
        f"head_keys AS (SELECT k1, n FROM {COUNTS_TABLE} WHERE tenant_id = ? AND dim = ? AND k3 = ''{k2_sql} "
        "AND n > 0 ORDER BY n DESC, k1 ASC LIMIT ? + (SELECT COUNT(*) FROM pending)), "
        f"held AS (SELECT c.k1, c.n FROM {COUNTS_TABLE} AS c JOIN pending AS p ON p.k1 = c.k1 "
        f"WHERE c.tenant_id = ? AND c.dim = ? AND c.k3 = ''{k2_sql.replace('k2', 'c.k2')} "
        "AND c.k1 NOT IN (SELECT k1 FROM head_keys)) "
        "SELECT k1, SUM(n) AS n FROM (SELECT k1, n FROM head_keys UNION ALL SELECT k1, n FROM held "
        "UNION ALL SELECT k1, n FROM pending) AS c WHERE k1 <> '' GROUP BY k1 HAVING SUM(n) > 0 "
        "ORDER BY SUM(n) DESC, k1 ASC LIMIT ?",
        (tenant_id, name, *k2_args, tenant_id, name, *k2_args, limit, tenant_id, name, *k2_args, limit)).fetchall()
    return [(str(row["k1"]), int(row["n"] or 0)) for row in found]


# Every principal with a row has one in at least one of these: it can read, write or is
# denied something, or it owns the file.
_CLASS_DIMS = "('x.read', 'x.write', 'x.deny', 'x.owner')"


def class_keys(conn, tenant_id: str, k2: str) -> list[str]:
    """Every principal of one class that has a row in any per-principal dimension."""
    found = conn.execute(
        f"SELECT DISTINCT k1 FROM (SELECT k1 FROM {COUNTS_TABLE} WHERE tenant_id = ? AND dim IN {_CLASS_DIMS} "
        f"AND k2 = ? AND n > 0 UNION SELECT k1 FROM {DELTAS_TABLE} WHERE tenant_id = ? AND dim IN {_CLASS_DIMS} "
        "AND k2 = ?) AS c", (tenant_id, k2, tenant_id, k2)).fetchall()
    return sorted(str(row["k1"]) for row in found if row["k1"])


def files(conn, tenant_id: str, per_file: str, k3: str) -> int:
    """How many files have a positive count in a per-file dimension (``DISTINCT``), in a
    scope ('1' current, '0' historical, '*' all). PostgreSQL keeps it as a count, folded,
    and adds the crossings the pending deltas make; SQLite counts the per-file rows."""
    if db.is_postgres():
        row = conn.execute(
            f"WITH pending AS (SELECT k1, SUM(n) AS d FROM {DELTAS_TABLE} WHERE tenant_id = ? AND dim = ? AND k3 = ? "
            "GROUP BY k1 HAVING SUM(n) <> 0), "
            "crossed AS (SELECT SUM(CASE WHEN COALESCE(c.n, 0) <= 0 AND COALESCE(c.n, 0) + p.d > 0 THEN 1 "
            "WHEN COALESCE(c.n, 0) > 0 AND COALESCE(c.n, 0) + p.d <= 0 THEN -1 ELSE 0 END) AS n "
            f"FROM pending AS p LEFT JOIN {COUNTS_TABLE} AS c ON c.tenant_id = ? AND c.dim = ? AND c.k3 = ? "
            "AND c.k2 = '' AND c.k1 = p.k1) "
            f"SELECT COALESCE((SELECT n FROM {COUNTS_TABLE} WHERE tenant_id = ? AND dim = ? AND k1 = '' AND k2 = '' "
            "AND k3 = ?), 0) + COALESCE((SELECT n FROM crossed), 0) AS n",
            (tenant_id, per_file, k3, tenant_id, per_file, k3, tenant_id, DISTINCT[per_file], k3)).fetchone()
        return int(row["n"] or 0) if row else 0
    row = conn.execute(f"SELECT COUNT(*) AS n FROM {COUNTS_TABLE} WHERE tenant_id = ? AND dim = ? AND k3 = ? "
                       "AND n > 0", (tenant_id, per_file, k3)).fetchone()
    return int(row["n"] or 0) if row else 0


# --- drift ---------------------------------------------------------------------------------

def reconcile(conn, tenant_id: str, active_statuses: tuple[str, ...] = ACTIVE_STATUSES, *,
              repair: bool = True) -> dict:
    """Recount a tenant from its rows, compare with what is kept, record the difference and
    (by default) repair it. Holds the tenant's fold lock, so no fold runs meanwhile."""
    if db.is_postgres():
        _lock(conn, tenant_id)
    fold(conn, tenant_id)
    truth = {row[1:5]: (row[5], row[6]) for row in recount(conn, tenant_id, active_statuses)}
    kept = {}
    for row in conn.execute(f"SELECT dim, k1, k2, k3, n, occ FROM {COUNTS_TABLE} WHERE tenant_id = ?",
                            (tenant_id,)).fetchall():
        value = (int(row["n"] or 0), int(row["occ"] or 0))
        if value != (0, 0):
            kept[(str(row["dim"]), str(row["k1"]), str(row["k2"]), str(row["k3"]))] = value
    differ = sorted(key for key in set(truth) | set(kept) if truth.get(key, (0, 0)) != kept.get(key, (0, 0)))
    drift = {"keys": len(differ), "by_dim": {}}
    for key in differ:
        drift["by_dim"][key[0]] = drift["by_dim"].get(key[0], 0) + 1
    if differ and repair:
        _store_counts(conn, tenant_id, [(tenant_id, *key, *value) for key, value in truth.items()])
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(f"INSERT INTO {STATE_TABLE} (tenant_id, reconciled_at, drift_json, repaired) VALUES (?, ?, ?, ?) "
                 "ON CONFLICT (tenant_id) DO UPDATE SET reconciled_at = excluded.reconciled_at, "
                 "drift_json = excluded.drift_json, repaired = excluded.repaired",
                 (tenant_id, now, json.dumps(drift, sort_keys=True), int(bool(differ and repair))))
    return {"tenant_id": tenant_id, "reconciled_at": now, "drift": drift, "repaired": bool(differ and repair)}


def state(conn, tenant_id: str) -> dict:
    row = conn.execute(f"SELECT reconciled_at, drift_json, repaired FROM {STATE_TABLE} WHERE tenant_id = ?",
                       (tenant_id,)).fetchone()
    if row is None:
        return {"reconciled_at": "", "drift": {"keys": 0, "by_dim": {}}, "repaired": False}
    try:
        drift = json.loads(row["drift_json"] or "{}")
    except ValueError:
        drift = {}
    return {"reconciled_at": str(row["reconciled_at"] or ""), "drift": drift, "repaired": bool(row["repaired"])}
