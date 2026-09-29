from __future__ import annotations

import base64
import contextlib
import functools
import inspect
import contextvars
import hashlib
import json
import math
import os
import re
import secrets
import threading
import time
import zlib
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend import db
from backend.permissions import is_known_role
from discovery.suppression import MAX_SUPPRESSION_RULES
from risk.risk_engine import finding_recommendation, finding_reason
from scripts.logger import get_logger

logger = get_logger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.getenv("DSPM_DB_PATH", DATA_DIR / "dspm.sqlite"))
_lock = threading.Lock()
_sqlite_inventory_fts_enabled = False


def db_path() -> Path:
    return DB_PATH


_perms_hardened = False


def _harden_db_permissions() -> None:
    """M2 interim (roadmap 2.1): restrict the SQLite data dir + DB file so a non-admin
    OS user cannot read credential hashes (users.password_hash, api_keys.key_hash) or
    the encrypted credential-vault blobs (secrets). Best-effort POSIX chmod - 0700 on
    the data dir (which also covers the WAL/SHM sidecar files), 0600 on the DB. On
    Windows this is a no-op and host NTFS ACLs govern; the full least-privilege /
    off-host / encrypted-at-rest controls come with the PostgreSQL migration."""
    global _perms_hardened
    if _perms_hardened:
        return
    try:
        os.chmod(DB_PATH.parent, 0o700)
    except OSError:
        pass
    try:
        if DB_PATH.exists():
            os.chmod(DB_PATH, 0o600)
    except OSError:
        pass
    _perms_hardened = True


@contextmanager
def _connect():
    # Delegate connection/commit/close to the backend seam (backend/db.py):
    # SQLite (default) yields the same raw sqlite3 connection as before; Postgres
    # (DSPM_DB_URL) yields an equivalent wrapper. The at-rest file hardening is
    # SQLite-only - Postgres at-rest protection is an operator/server concern.
    with db.connect(DB_PATH) as conn:
        if db.is_sqlite():
            _harden_db_permissions()
        yield conn


def generate_registration_code() -> str:
    return f"reg_{secrets.token_urlsafe(18)}"


def ensure_registration_code(tenant_id: str, current_code: str | None = None) -> str:
    if current_code:
        return current_code
    now = datetime.now(timezone.utc).isoformat()
    registration_code = generate_registration_code()
    with _lock:
        with _connect() as conn:
            conn.execute(
                """
                UPDATE tenants
                SET registration_code = ?, updated_at = ?
                WHERE tenant_id = ? AND (registration_code IS NULL OR registration_code = '')
                """,
                (registration_code, now, tenant_id),
            )
            row = conn.execute(
                "SELECT registration_code FROM tenants WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
    return row["registration_code"] if row and row["registration_code"] else registration_code


def rotate_registration_code(tenant_id: str) -> str | None:
    now = datetime.now(timezone.utc).isoformat()
    registration_code = generate_registration_code()
    with _lock:
        with _connect() as conn:
            result = conn.execute(
                """
                UPDATE tenants
                SET registration_code = ?, updated_at = ?
                WHERE tenant_id = ?
                """,
                (registration_code, now, tenant_id),
            )
            if result.rowcount == 0:
                return None
    return registration_code


def create_registration_invite(
    tenant_id: str,
    token_hash: str,
    role: str,
    max_uses: int,
    expires_at: str,
    requires_approval: bool,
    created_by: str,
) -> str:
    invite_id = f"inv_{secrets.token_urlsafe(9)}"
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO registration_invites
                    (id, tenant_id, token_hash, role, max_uses, used_count, expires_at,
                     requires_approval, revoked, created_by, created_at, last_redeemed_at)
                VALUES (?, ?, ?, ?, ?, 0, ?, ?, 0, ?, ?, NULL)
                """,
                (invite_id, tenant_id, token_hash, role, int(max_uses), expires_at,
                 1 if requires_approval else 0, created_by, now),
            )
    return invite_id


def redeem_registration_invite(tenant_id: str, token_hash: str) -> dict | None:
    """Atomically consume one use of a matching, non-revoked, non-expired invite
    with uses remaining. Returns the invite (role, requires_approval, remaining) or
    None. The conditional UPDATE + SQLite write lock make the use-cap race-free."""
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            result = conn.execute(
                """
                UPDATE registration_invites
                SET used_count = used_count + 1, last_redeemed_at = ?
                WHERE tenant_id = ? AND token_hash = ? AND revoked = 0
                  AND expires_at > ? AND used_count < max_uses
                """,
                (now, tenant_id, token_hash, now),
            )
            if result.rowcount != 1:
                return None
            row = conn.execute(
                "SELECT id, role, requires_approval, max_uses, used_count "
                "FROM registration_invites WHERE tenant_id = ? AND token_hash = ?",
                (tenant_id, token_hash),
            ).fetchone()
    if row is None:
        return None
    return {
        "id": row["id"],
        "role": row["role"],
        "requires_approval": bool(row["requires_approval"]),
        "max_uses": row["max_uses"],
        "used_count": row["used_count"],
        "remaining_uses": max(0, row["max_uses"] - row["used_count"]),
    }


def list_registration_invites(tenant_id: str) -> list[dict]:
    with _lock:
        with _connect() as conn:
            rows = conn.execute(
                """
                SELECT id, tenant_id, role, max_uses, used_count, expires_at,
                       requires_approval, revoked, created_by, created_at, last_redeemed_at
                FROM registration_invites WHERE tenant_id = ? ORDER BY created_at DESC
                """,
                (tenant_id,),
            ).fetchall()
    return [
        {
            "id": r["id"],
            "tenant_id": r["tenant_id"],
            "role": r["role"],
            "max_uses": r["max_uses"],
            "used_count": r["used_count"],
            "remaining_uses": max(0, r["max_uses"] - r["used_count"]),
            "expires_at": r["expires_at"],
            "requires_approval": bool(r["requires_approval"]),
            "revoked": bool(r["revoked"]),
            "created_by": r["created_by"],
            "created_at": r["created_at"],
            "last_redeemed_at": r["last_redeemed_at"],
        }
        for r in rows
    ]


def revoke_registration_invite(tenant_id: str, invite_id: str) -> bool:
    with _lock:
        with _connect() as conn:
            result = conn.execute(
                "UPDATE registration_invites SET revoked = 1 "
                "WHERE tenant_id = ? AND id = ? AND revoked = 0",
                (tenant_id, invite_id),
            )
    return result.rowcount == 1


def create_api_key_record(
    tenant_id: str,
    key_hash: str,
    label: str,
    role: str,
    created_by: str,
    expires_at: str | None,
) -> str:
    key_id = f"key_{secrets.token_urlsafe(9)}"
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO api_keys
                    (id, tenant_id, key_hash, label, role, created_by, created_at, last_used_at, expires_at, revoked)
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, 0)
                """,
                (key_id, tenant_id, key_hash, label, role, created_by, now, expires_at),
            )
    return key_id


def get_active_api_key(key_hash: str) -> dict | None:
    """Return {id, tenant_id, role} for a key that exists AND is not revoked AND is
    not expired, else None. Does NOT touch last_used (see touch_api_key)."""
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            row = conn.execute(
                "SELECT id, tenant_id, role FROM api_keys "
                "WHERE key_hash = ? AND revoked = 0 AND (expires_at IS NULL OR expires_at > ?)",
                (key_hash, now),
            ).fetchone()
    if row is None:
        return None
    return {"id": row["id"], "tenant_id": row["tenant_id"], "role": row["role"]}


def touch_api_key(key_id: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now, key_id))


def list_api_keys(tenant_id: str) -> list[dict]:
    with _lock:
        with _connect() as conn:
            rows = conn.execute(
                """
                SELECT id, tenant_id, label, role, created_by, created_at, last_used_at,
                       expires_at, revoked, substr(key_hash, 1, 8) AS hash_prefix
                FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC
                """,
                (tenant_id,),
            ).fetchall()
    return [
        {
            "id": r["id"],
            "tenant_id": r["tenant_id"],
            "label": r["label"],
            "role": r["role"],
            "created_by": r["created_by"],
            "created_at": r["created_at"],
            "last_used_at": r["last_used_at"],
            "expires_at": r["expires_at"],
            "revoked": bool(r["revoked"]),
            "hash_prefix": r["hash_prefix"],
        }
        for r in rows
    ]


def revoke_api_key(tenant_id: str, key_id: str) -> bool:
    with _lock:
        with _connect() as conn:
            result = conn.execute(
                "UPDATE api_keys SET revoked = 1 WHERE tenant_id = ? AND id = ? AND revoked = 0",
                (tenant_id, key_id),
            )
    return result.rowcount == 1


def init_db() -> None:
    """Converge the schema (legacy path). Production routes through
    backend.migrations instead - see ensure_schema_ready()."""
    global _sqlite_inventory_fts_enabled
    with _lock:
        with _connect() as conn:
            apply_baseline_schema(conn)


def add_scan_report_labels(conn) -> None:
    """Revision 0002: index the operator-facing scan name on saved runs.

    ``assets.scan_label`` is only the label of the newest observation of an
    asset, so it cannot identify an older named scan after another run touches
    the same path.  The immutable report row needs its own label in order to
    resolve the latest result for a selected scan without searching/parsing all
    report blobs on every inventory request.
    """
    columns = db.table_columns(conn, "scan_reports")
    if "scan_label" not in columns:
        conn.execute("ALTER TABLE scan_reports ADD COLUMN scan_label TEXT NOT NULL DEFAULT ''")

    # Existing reports already carry scan_label inside their authoritative JSON
    # blob.  Backfill once during the schema migration; new writes populate the
    # indexed column directly.  Both supported databases provide native JSON
    # extraction, and every report_json value is produced by json.dumps().
    if db.is_postgres():
        conn.execute(
            "UPDATE scan_reports SET scan_label = LEFT(COALESCE(report_json::jsonb ->> 'scan_label', ''), 80) "
            "WHERE scan_label = '' AND report_json LIKE '%\"scan_label\"%'"
        )
    else:
        conn.execute(
            "UPDATE scan_reports SET scan_label = SUBSTR(COALESCE(json_extract(report_json, '$.scan_label'), ''), 1, 80) "
            "WHERE scan_label = '' AND json_valid(report_json) AND report_json LIKE '%\"scan_label\"%'"
        )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_reports_tenant_label_created "
        "ON scan_reports (tenant_id, scan_label, created_at, scan_id)"
    )


def add_tenant_integrity(conn) -> None:
    """Revision 0003: referential integrity for tenant scoping (Phase 4, DB-03).

    PostgreSQL only - production is PostgreSQL by the Phase 0 authority gate,
    and SQLite (development) cannot add constraints to existing tables without
    a rebuild. Every tenant-scoped table (discovered from the catalog, so a
    new table is covered automatically) gains a validated foreign key to
    tenants. ON DELETE RESTRICT: erasure must stay the deliberate, audited
    delete_tenant_with_data() path - the database refuses a tenant row delete
    that would silently strand or drop scoped data.

    Orphaned rows make VALIDATE fail; the migration surfaces them per table
    and refuses, so repair is an explicit operator decision, never silent
    data loss inside a schema upgrade.
    """
    if not db.is_postgres():
        return  # recorded no-op: SQLite is a development backend

    tables = [
        str(r["table_name"]) for r in conn.execute(
            "SELECT DISTINCT table_name FROM information_schema.columns "
            "WHERE column_name = 'tenant_id' AND table_schema = current_schema() "
            "AND table_name <> 'tenants' ORDER BY table_name"
        ).fetchall()
    ]

    orphans: dict[str, int] = {}
    for table in tables:
        row = conn.execute(
            f"SELECT COUNT(*) AS n FROM {table} t "
            "WHERE NOT EXISTS (SELECT 1 FROM tenants x WHERE x.tenant_id = t.tenant_id)"
        ).fetchone()
        if int(row["n"]):
            orphans[table] = int(row["n"])
    if orphans:
        detail = ", ".join(f"{table}: {count}" for table, count in sorted(orphans.items()))
        raise RuntimeError(
            "Refusing to add tenant foreign keys: orphaned rows reference "
            f"missing tenants ({detail}). Repair or re-home these rows first - "
            "a schema migration never deletes data."
        )

    for table in tables:
        constraint = f"fk_{table}_tenant"
        exists = conn.execute(
            "SELECT 1 FROM pg_constraint WHERE conname = ? "
            "AND conrelid = to_regclass(?)::oid",
            (constraint, table),
        ).fetchone()
        if exists:
            continue
        # NOT VALID keeps the lock window minimal on a live table; the
        # separate VALIDATE takes only a SHARE UPDATE EXCLUSIVE lock.
        conn.execute(
            f"ALTER TABLE {table} ADD CONSTRAINT {constraint} "
            "FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id) "
            "ON DELETE RESTRICT NOT VALID"
        )
        conn.execute(f"ALTER TABLE {table} VALIDATE CONSTRAINT {constraint}")


def add_tenant_rls(conn) -> None:
    """Revision 0004: row-level security on tenant-scoped tables (Phase 4c).

    Policies confine a transaction to ``current_setting('app.tenant_id')``
    when the connection seam has set one (db.tenant_scope). An unset or '*'
    scope behaves exactly as before - login, platform administration,
    migrations, and backups all span tenants legitimately - so this ships as
    pure defense-in-depth on the request paths that carry user input: even a
    query with a missing or hostile predicate cannot read or write another
    tenant inside a scoped transaction. FORCE applies the policy to the table
    owner as well; only superusers bypass. Tightening the unset case to
    fail-closed is the documented follow-up once every code path is scoped.
    """
    if not db.is_postgres():
        return  # recorded no-op: SQLite is a development backend

    tables = [
        str(r["table_name"]) for r in conn.execute(
            "SELECT DISTINCT table_name FROM information_schema.columns "
            "WHERE column_name = 'tenant_id' AND table_schema = current_schema() "
            "AND table_name <> 'tenants' ORDER BY table_name"
        ).fetchall()
    ]
    for table in tables:
        predicate = tenant_policy_predicate(table)
        conn.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        conn.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        conn.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        conn.execute(
            f"CREATE POLICY tenant_isolation ON {table} FOR ALL "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )


# C10: the cross-tenant work each tenant table admits, by purpose (db.PLATFORM_PURPOSES).
# A table not listed admits only its own tenant's scope - and "migration" and "backup",
# which every table admits: schema revisions, operator data migrations and a
# whole-database backup or restore span tenants by definition.
# Widening an entry is a security decision; tests/test_platform_scope.py pins this map.
# The policies are written from it when a revision runs add_tenant_rls, so a change here
# ships with a revision that re-runs it (the same test compares a live database's policies).
PLATFORM_ACCESS: dict[str, frozenset] = {
    "users": frozenset({"auth", "platform-admin"}),
    "api_keys": frozenset({"auth"}),
    # C2: an account's MFA state is read while it signs in, before its tenant is known.
    # Directory settings are read by tenant (the workspace named at sign-in), so they
    # need no platform purpose at all.
    "user_mfa": frozenset({"auth", "vault"}),
    # C12: a vault key rotation re-seals every tenant's credentials in one transaction.
    "secrets": frozenset({"vault"}),
    "registration_invites": frozenset({"auth"}),
    "scan_schedules": frozenset({"scheduler"}),
    "audit_outbox": frozenset({"siem"}),
    # The installation's tenant portfolio counts scans, audit rows and alerts per tenant.
    "audit_events": frozenset({"housekeeping", "platform-admin"}),
    "audit_chain_heads": frozenset({"housekeeping"}),
    "alert_events": frozenset({"housekeeping", "platform-admin"}),
    "derived_cache": frozenset({"housekeeping"}),
    "scan_reports": frozenset({"housekeeping", "platform-admin"}),
    "scan_jobs": frozenset({"housekeeping", "resume"}),
    "partitioned_scans": frozenset({"resume"}),
    # Artifact collection must see a partition's records, or it would take them for garbage.
    "scan_partitions": frozenset({"resume", "housekeeping"}),
    "assets": frozenset({"search-indexer", "housekeeping"}),
    # D7: the demo-sample purge removes an asset's access rows with the asset.
    "asset_access": frozenset({"housekeeping"}),
}


def tenant_policy_predicate(table: str) -> str:
    """Rows of `table` a transaction may see and write: its tenant's, or every tenant's
    when it names a purpose this table admits. Nothing when it names neither - an unset
    scope used to mean everything (C10). NULLIF because a SET LOCAL that ends reverts a
    never-set custom setting to '', not NULL; '*' matches no tenant, so a role default of
    '*' - which db_roles.py once set - grants nothing now."""
    # A whole-database backup and its restore read and write every table, as a migration does.
    purposes = sorted(PLATFORM_ACCESS.get(table, frozenset()) | {"migration", "backup"})
    listed = ", ".join(f"'{purpose}'" for purpose in purposes)
    return (f"tenant_id = NULLIF(current_setting('app.tenant_id', true), '') "
            f"OR NULLIF(current_setting('app.platform', true), '') IN ({listed})")


def tenant_isolation_coverage() -> dict:
    """Which tenant-scoped tables lack a tenant foreign key or RLS.

    Revisions 0003 and 0004 enumerate the tables that exist *when they run*, so
    a table added by a later revision inherits neither control unless its
    revision asks for them. Nothing in the schema forces that, so this reports
    the gap instead: a test fails the build on it, and the readiness payload
    surfaces it at runtime. PostgreSQL-only - SQLite has no RLS, and production
    is PostgreSQL by the Phase 0 authority gate.
    """
    if not db.is_postgres():
        return {"applicable": False, "scoped_tables": 0,
                "missing_foreign_key": [], "missing_rls": []}
    with _connect() as conn:
        scoped = [
            str(row["table_name"]) for row in conn.execute(
                "SELECT DISTINCT table_name FROM information_schema.columns "
                "WHERE column_name = 'tenant_id' AND table_schema = current_schema() "
                "AND table_name <> 'tenants' ORDER BY table_name"
            ).fetchall()
        ]
        with_fk = {
            str(row["t"]) for row in conn.execute(
                "SELECT conrelid::regclass::text AS t FROM pg_constraint "
                "WHERE contype = 'f' AND conname LIKE 'fk\\_%\\_tenant'"
            ).fetchall()
        }
        with_rls = {
            str(row["relname"]) for row in conn.execute(
                "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = current_schema() AND c.relrowsecurity AND c.relforcerowsecurity"
            ).fetchall()
        }
    return {
        "applicable": True,
        "scoped_tables": len(scoped),
        "missing_foreign_key": sorted(set(scoped) - with_fk),
        "missing_rls": sorted(set(scoped) - with_rls),
    }


def repair_tenant_rls_predicate(conn) -> None:
    """Revision 0006: rebuild the RLS policies with the empty-string guard.

    Revision 0004's predicate treated only NULL as "no scope". After any
    scoped transaction the session value of a custom GUC is the empty string,
    so a pooled connection that had once carried a tenant scope refused every
    subsequent unscoped statement. ``add_tenant_rls`` drops and recreates each
    policy, so re-running it is the whole repair.
    """
    add_tenant_rls(conn)


def add_scan_partition_ledger(conn) -> None:
    """Revision 0011: the partition ledger resumable scans need (Phase B, B2.1).

    A restart used to lose every running scan: the job row held a status and
    nothing about what the job had been asked to do, so
    ``recover_interrupted_jobs`` could only mark it failed. This adds what
    resuming needs and nothing that uses it yet - ``scan_jobs`` learns its scan,
    its sanitized request and whether it can resume, and ``scan_partitions``
    records each unit of a scan with its status and attempt count.

    Revisions 0003 and 0004 enumerate tenant tables when they run, so a table
    added later inherits neither the tenant foreign key nor row-level security.
    Both are idempotent, and re-running them here is how the new table gets them;
    ``tenant_isolation_coverage`` fails the build otherwise.
    """
    columns = db.table_columns(conn, "scan_jobs")
    if "scan_id" not in columns:
        conn.execute("ALTER TABLE scan_jobs ADD COLUMN scan_id TEXT NOT NULL DEFAULT ''")
    if "request_json" not in columns:
        conn.execute("ALTER TABLE scan_jobs ADD COLUMN request_json TEXT NOT NULL DEFAULT '{}'")
    if "resumable" not in columns:
        conn.execute("ALTER TABLE scan_jobs ADD COLUMN resumable INTEGER NOT NULL DEFAULT 0")
    conn.execute("""CREATE TABLE IF NOT EXISTS scan_partitions (
            tenant_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            partition_id TEXT NOT NULL,
            job_id TEXT NOT NULL DEFAULT '',
            ordinal INTEGER NOT NULL DEFAULT 0,
            spec_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'queued',
            attempt INTEGER NOT NULL DEFAULT 0,
            files INTEGER NOT NULL DEFAULT 0,
            error TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL DEFAULT '',
            finished_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, scan_id, partition_id)
        );""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_partitions_next "
        "ON scan_partitions (tenant_id, scan_id, status, ordinal)"
    )
    add_tenant_integrity(conn)
    add_tenant_rls(conn)


def add_scan_partition_records(conn) -> None:
    """Revision 0012: what a finished partition keeps for finalize (B2.2b).

    Finalizing a partitioned scan reads each partition's records back in plan
    order, one partition at a time, to build the report sections and body
    without holding the estate. Those must be the records the partition actually
    wrote: the ``assets`` table is current state, which a later scan can
    overwrite first, and a demo scan does not write it at all.

    ``records_ref`` points at an artifact, and ``records_json`` holds the records
    inline when the artifact tier is off. ``summary_json`` is the partition's
    summary as the engine counted it, before compliance enrichment strips
    framework-only findings, so the scan summary is the exact sum.
    ``diagnostics_json`` is the partition's own scan diagnostics, for finalize to
    merge.
    """
    columns = db.table_columns(conn, "scan_partitions")
    if "records_ref" not in columns:
        conn.execute("ALTER TABLE scan_partitions ADD COLUMN records_ref TEXT NOT NULL DEFAULT ''")
    if "records_bytes" not in columns:
        conn.execute("ALTER TABLE scan_partitions ADD COLUMN records_bytes INTEGER NOT NULL DEFAULT 0")
    if "records_json" not in columns:
        conn.execute("ALTER TABLE scan_partitions ADD COLUMN records_json TEXT")
    if "summary_json" not in columns:
        conn.execute("ALTER TABLE scan_partitions ADD COLUMN summary_json TEXT NOT NULL DEFAULT '{}'")
    if "diagnostics_json" not in columns:
        conn.execute("ALTER TABLE scan_partitions ADD COLUMN diagnostics_json TEXT NOT NULL DEFAULT '{}'")


def add_partition_write_indexes(conn) -> None:
    """Revision 0013: a partition's deletes seek to its own rows (B2.2b).

    A partition refreshes its own finding occurrences and its own range of the
    finding index before writing them. Both deletes had only a (tenant_id, scan_id)
    index to work with, so each walked every row the scan had already written and
    filtered it down: measured, a partitioned scan's write peak grew about 1.25 MB
    per partition as those pages filled the connection's page cache, and the scan was
    quadratic in time. With the partition's own column in the index both deletes
    seek. Each new index extends the one it replaces, so every query the old one
    served still has it, and writes pay for no extra index.
    """
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_occurrences_scan_finding "
        "ON finding_occurrences (tenant_id, scan_id, finding_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_finding_index_tenant_scan_seq "
        "ON finding_index (tenant_id, scan_id, seq)"
    )
    conn.execute("DROP INDEX IF EXISTS idx_occurrences_scan")
    conn.execute("DROP INDEX IF EXISTS idx_finding_index_tenant_scan")


def add_partitioned_scan_ledger(conn) -> None:
    """Revision 0014: continuing a partitioned scan, and leases (B2.4, the base of B3).

    A partitioned scan's header - the timestamp every partition stamps, its label,
    compliance settings and file budget - and its request lived only in the process
    running it, so a restart could not continue it. ``partitioned_scans`` keeps them,
    with the request stored without secrets, and a status whose compare-and-set lets
    exactly one finalize run.

    ``scan_partitions`` gains a lease. Requeuing every running unit is correct only at
    the startup of the one process that owns the scans; with a lease, a unit is taken
    back only once its holder has stopped renewing it, which is what lets more than
    one worker share a ledger (B2 review).

    Revisions 0003 and 0004 enumerate tenant tables when they run, so both are re-run
    here to give the new table its tenant foreign key and row-level security.
    """
    columns = db.table_columns(conn, "scan_partitions")
    if "lease_owner" not in columns:
        conn.execute("ALTER TABLE scan_partitions ADD COLUMN lease_owner TEXT NOT NULL DEFAULT ''")
    if "lease_expires_at" not in columns:
        conn.execute("ALTER TABLE scan_partitions ADD COLUMN lease_expires_at TEXT NOT NULL DEFAULT ''")
    conn.execute("""CREATE TABLE IF NOT EXISTS partitioned_scans (
            tenant_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            job_id TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'running',
            request_json TEXT NOT NULL DEFAULT '{}',
            header_json TEXT NOT NULL DEFAULT '{}',
            resumable INTEGER NOT NULL DEFAULT 0,
            error TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, scan_id)
        );""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_partitioned_scans_status "
        "ON partitioned_scans (status, updated_at)"
    )
    add_tenant_integrity(conn)
    add_tenant_rls(conn)


def add_scan_schedules(conn) -> None:
    """Revision 0015: the scans a backend runs unattended (B3).

    A pilot's value is the scan nobody has to start: ``scan_schedules`` holds the scan
    request - through the same secret filter scan profiles use, so a typed password
    never reaches the database - how often it runs, and when it is next due. The
    scheduler claims a due schedule by compare-and-set on that due time, so several
    backends sharing one database start it exactly once.

    Revisions 0003 and 0004 enumerate tenant tables when they run, so both are re-run
    here to give the new table its tenant foreign key and row-level security.
    """
    conn.execute("""CREATE TABLE IF NOT EXISTS scan_schedules (
            tenant_id TEXT NOT NULL,
            schedule_id TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            request_json TEXT NOT NULL DEFAULT '{}',
            interval_seconds INTEGER NOT NULL DEFAULT 86400,
            enabled INTEGER NOT NULL DEFAULT 1,
            next_run_at TEXT NOT NULL,
            last_run_at TEXT NOT NULL DEFAULT '',
            last_scan_id TEXT NOT NULL DEFAULT '',
            last_status TEXT NOT NULL DEFAULT '',
            last_error TEXT NOT NULL DEFAULT '',
            runs INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, schedule_id)
        );""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_schedules_due "
        "ON scan_schedules (enabled, next_run_at)"
    )
    add_tenant_integrity(conn)
    add_tenant_rls(conn)


def add_suppression_rules(conn) -> None:
    """Revision 0016: the findings an analyst has told the scan not to report (B6).

    A false positive was a decision the estate remembered and every scan re-made:
    the row kept its status, and the next scan created the finding again for the
    analyst to dismiss again. ``suppression_rules`` is the decision itself - a
    finding type, a path or prefix, a source, or one salted value fingerprint - and
    the scan applies it when it emits, so the finding is never created.

    The rule stores a fingerprint, never a value: the same thing a finding stores,
    for the same reason.

    Revisions 0003 and 0004 enumerate tenant tables when they run, so both are re-run
    here to give the new table its tenant foreign key and row-level security.
    """
    conn.execute("""CREATE TABLE IF NOT EXISTS suppression_rules (
            tenant_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            finding_type TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            path_pattern TEXT NOT NULL DEFAULT '',
            fingerprint TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            expires_at TEXT NOT NULL DEFAULT '',
            source_finding_id TEXT NOT NULL DEFAULT '',
            source_scan_id TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, rule_id)
        );""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_suppression_rules_active "
        "ON suppression_rules (tenant_id, active)"
    )
    add_tenant_integrity(conn)
    add_tenant_rls(conn)


def add_derived_cache(conn) -> None:
    """Revision 0017: the console's derived state, shared between backends through the database.

    Memurai was removed on 2026-09-18 at the product owner's decision, and with it the
    shared cache B3.1 kept there. What that cache was FOR still stands: the estate
    aggregates the console asks for on every refresh used to be paid for by every
    backend and every worker separately, because the only cache was per-process.

    ``derived_cache`` holds those answers - derived numbers only, never content - keyed
    per tenant, and ``tenants.estate_generation`` says which estate they describe. Every
    authoritative write moves the generation, and a cached answer is served only while
    its generation is the tenant's current one. A second backend then answers a refresh
    with one primary-key lookup instead of the aggregates, with nothing to install.

    Revisions 0003 and 0004 enumerate tenant tables when they run, so both are re-run
    here to give the new table its tenant foreign key and row-level security.
    """
    if "estate_generation" not in db.table_columns(conn, "tenants"):
        conn.execute("ALTER TABLE tenants ADD COLUMN estate_generation INTEGER NOT NULL DEFAULT 0")
    conn.execute("""CREATE TABLE IF NOT EXISTS derived_cache (
            tenant_id TEXT NOT NULL,
            cache_key TEXT NOT NULL,
            generation INTEGER NOT NULL DEFAULT 0,
            value_json TEXT NOT NULL DEFAULT '{}',
            expires_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, cache_key)
        );""")
    add_tenant_integrity(conn)
    add_tenant_rls(conn)


def add_user_sessions(conn) -> None:
    """Revision 0018: a session is a row, not a fact one process happens to remember (C1).

    The idle timeout lived in a per-process dictionary. That was a deliberate trade -
    a per-request database write is exactly what the performance work removed from the
    authenticated path - but it has two consequences a security review will not accept:
    a restart admits every session once more, because the process that had been watching
    them forgot, and with several workers each one only knows what it has seen itself.

    The row is the durable half. Writes are still throttled (see security._touch_session),
    so the authenticated path does not pay for one per request; what the row buys is that
    the FIRST sight of a session in any process reads when it was really last used, and
    that a password change can end every session a user has rather than only the ones
    this process knows about.

    Deliberately NOT tenant-scoped: it is authentication infrastructure, keyed by the
    account. Revisions 0003 and 0004 enumerate tables by their `tenant_id` column, so a
    tenant column here would put session lookups behind row-level security - on a path
    that runs before any tenant scope exists, and which C10 will tighten to deny.
    """

    conn.execute("""CREATE TABLE IF NOT EXISTS user_sessions (
            jti TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL
        );""")
    conn.execute("CREATE INDEX IF NOT EXISTS user_sessions_owner ON user_sessions (username, last_seen_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS user_sessions_expiry ON user_sessions (expires_at)")


def open_role_catalogue(conn) -> None:
    """Revision 0020: users.role accepts the role catalogue, not three fixed names (C3).

    The baseline pinned the column with CHECK (role IN ('admin', 'analyst', 'viewer')),
    which made three ranks a property of the schema. C3 names permissions and gives
    roles sets of them - an auditor, a scan operator - so which names are valid is the
    application's to say (`backend.permissions`), and the store checks it on every write.

    PostgreSQL drops the constraint in place. SQLite cannot alter a constraint, so the
    table is rebuilt from its own recorded definition minus the CHECK: every column the
    install has, every row, and the indexes as they were. An install that is already
    open is left alone.
    """

    if db.is_postgres():
        rows = conn.execute(
            "SELECT conname, pg_get_constraintdef(oid) AS definition FROM pg_constraint "
            "WHERE conrelid = to_regclass('users')::oid AND contype = 'c'"
        ).fetchall()
        for row in rows:
            if "role" in str(row["definition"]).lower():
                conn.execute(f'ALTER TABLE users DROP CONSTRAINT IF EXISTS "{row["conname"]}"')
        return

    found = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'").fetchone()
    ddl = str(found["sql"] or "") if found else ""
    constraint = re.compile(r"\s*CHECK\s*\(\s*role\s+IN\s*\([^)]*\)\s*\)", re.IGNORECASE)
    if not ddl or not constraint.search(ddl):
        return
    open_ddl = constraint.sub("", ddl)
    open_ddl, renamed = re.subn(r'^CREATE TABLE\s+(IF NOT EXISTS\s+)?"?users"?', "CREATE TABLE users_c3_open",
                                open_ddl, count=1, flags=re.IGNORECASE)
    if not renamed:
        raise RuntimeError("Revision 0020 could not read the users table definition")
    indexes = [str(row["sql"]) for row in conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'users' AND sql IS NOT NULL"
    ).fetchall()]
    columns = ", ".join(str(row["name"]) for row in conn.execute("PRAGMA table_info(users)").fetchall())
    conn.execute("DROP TABLE IF EXISTS users_c3_open")
    conn.execute(open_ddl)
    conn.execute(f"INSERT INTO users_c3_open ({columns}) SELECT {columns} FROM users")
    conn.execute("DROP TABLE users")
    conn.execute("ALTER TABLE users_c3_open RENAME TO users")
    for statement in indexes:
        conn.execute(statement)


def add_custom_roles(conn) -> None:
    """Revision 0021: a tenant's own roles (C3).

    The built-in roles are sets of named permissions; a custom role is the same thing
    under a name the tenant chooses - "privacy_reviewer" reads evidence and the audit
    trail and changes nothing. users.role, invites and API keys store its name, which is
    resolved within the tenant, so two tenants may use one name for different sets.

    Revisions 0003 and 0004 enumerate tenant tables when they run, so both are re-run
    here to give the new table its tenant foreign key and row-level security.
    """
    conn.execute("""CREATE TABLE IF NOT EXISTS custom_roles (
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            permissions TEXT NOT NULL DEFAULT '[]',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, name)
        );""")
    add_tenant_integrity(conn)
    add_tenant_rls(conn)


_AUDIT_OUTBOX_DDL = """CREATE TABLE IF NOT EXISTS audit_outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            seq INTEGER NOT NULL DEFAULT 0,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at REAL NOT NULL DEFAULT 0,
            lease_until REAL NOT NULL DEFAULT 0,
            lease_owner TEXT NOT NULL DEFAULT '',
            last_error TEXT NOT NULL DEFAULT ''
        );"""


_AUDIT_CHAIN_HEADS_DDL = """CREATE TABLE IF NOT EXISTS audit_chain_heads (
            tenant_id TEXT PRIMARY KEY,
            last_seq INTEGER NOT NULL DEFAULT 0,
            last_hash TEXT NOT NULL DEFAULT '',
            pruned_through_seq INTEGER NOT NULL DEFAULT 0,
            pruned_through_hash TEXT NOT NULL DEFAULT '',
            sealed_through_seq INTEGER NOT NULL DEFAULT 0,
            sealed_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT ''
        );"""


def add_audit_chain(conn) -> None:
    """Revision 0022: each tenant's audit rows become a hash chain (C4).

    Adds `seq`, `prev_hash` and `row_hash` to `audit_events` and a head per tenant.
    Existing rows are SEALED: chained in the order they were written, with the head
    recording how far the seal reaches and when. Nothing can prove those rows were not
    edited before today - the seal only makes any edit from now on visible - and
    `audit verify` says so rather than implying more (backend.audit_chain).

    `audit_chain_heads` has a tenant column, so revisions 0003 and 0004 are re-run to
    give it its tenant foreign key and row-level security.
    """
    from backend import audit_chain

    columns = db.table_columns(conn, "audit_events")
    if "seq" not in columns:
        conn.execute("ALTER TABLE audit_events ADD COLUMN seq INTEGER")
    if "prev_hash" not in columns:
        conn.execute("ALTER TABLE audit_events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''")
    if "row_hash" not in columns:
        conn.execute("ALTER TABLE audit_events ADD COLUMN row_hash TEXT NOT NULL DEFAULT ''")
    conn.executescript(_AUDIT_CHAIN_HEADS_DDL)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_events_chain ON audit_events (tenant_id, seq)")

    sealed_at = datetime.now(timezone.utc).isoformat()
    tenants = [str(row["tenant_id"]) for row in conn.execute(
        "SELECT DISTINCT tenant_id FROM audit_events WHERE seq IS NULL").fetchall()]
    for tenant_id in tenants:
        head = conn.execute("SELECT last_seq, last_hash FROM audit_chain_heads WHERE tenant_id = ?",
                            (tenant_id,)).fetchone()
        seq = int(head["last_seq"]) if head else 0
        prev = str(head["last_hash"]) if head else ""
        rows = conn.execute(
            "SELECT id, timestamp, actor, action, detail_json FROM audit_events "
            "WHERE tenant_id = ? AND seq IS NULL ORDER BY id", (tenant_id,)).fetchall()
        for row in rows:
            seq += 1
            digest = audit_chain.row_hash(prev, tenant_id, seq, row["timestamp"], row["actor"], row["action"],
                                          row["detail_json"] or "")
            conn.execute("UPDATE audit_events SET seq = ?, prev_hash = ?, row_hash = ? WHERE id = ?",
                         (seq, prev, digest, row["id"]))
            prev = digest
        conn.execute(
            "INSERT INTO audit_chain_heads (tenant_id, last_seq, last_hash, sealed_through_seq, sealed_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (tenant_id) DO UPDATE SET last_seq = excluded.last_seq, "
            "last_hash = excluded.last_hash, sealed_through_seq = excluded.sealed_through_seq, "
            "sealed_at = excluded.sealed_at, updated_at = excluded.updated_at",
            (tenant_id, seq, prev, seq, sealed_at, sealed_at),
        )
    add_tenant_integrity(conn)
    add_tenant_rls(conn)


def add_audit_outbox(conn) -> None:
    """Revision 0023: the queue between the audit trail and the SIEM (C4, backend.siem).

    A row is written here in the same transaction as the audit row it carries, so an event
    cannot be recorded without being queued. The forwarder deletes what was delivered and
    leaves what was not, with the next attempt's time, so an outage costs a delay, not
    events. It has a tenant column (erasure removes a tenant's undelivered events with the
    rest of its data), so revisions 0003 and 0004 are re-run for it.
    """
    # executescript, not execute: it is what translates the dialect (AUTOINCREMENT
    # becomes an identity column on PostgreSQL) - the C0.5 run found this failing.
    conn.executescript(_AUDIT_OUTBOX_DDL)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_outbox_due ON audit_outbox (next_attempt_at, id)")
    add_tenant_integrity(conn)
    add_tenant_rls(conn)


_SCAN_TARGETS_DDL = """CREATE TABLE IF NOT EXISTS scan_targets (
            tenant_id TEXT NOT NULL,
            entry_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, entry_id)
        );"""


def add_scan_targets(conn) -> None:
    """Revision 0024: the networks and host names a workspace may scan (C5).

    Replaces the install-wide DSPM_ALLOW_PRIVATE_TARGETS switch with a list per tenant
    (backend/target_scope). A tenant table, so revisions 0003 and 0004 are re-run for
    its foreign key and row-level security; erased with its tenant.
    """
    conn.execute(_SCAN_TARGETS_DDL)
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_targets_value ON scan_targets (tenant_id, value)")
    add_tenant_integrity(conn)
    add_tenant_rls(conn)


def deny_unscoped_tenant_access(conn) -> None:
    """Revision 0025: an unscoped transaction sees no tenant's rows (C10).

    Until now the policies treated an unset tenant scope as "every tenant", so any code
    path that forgot its scope read and wrote across tenants, and the background
    writers depended on exactly that. They now name their purpose (db.platform_scope)
    and each table admits only the purposes that need it (PLATFORM_ACCESS). Re-running
    revision 0004 rebuilds every tenant table's policy with that predicate.
    """
    add_tenant_rls(conn)


_DIRECTORY_SETTINGS_DDL = """CREATE TABLE IF NOT EXISTS directory_settings (
            tenant_id TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 0,
            config_json TEXT NOT NULL DEFAULT '{}',
            bind_secret_ref TEXT NOT NULL DEFAULT '',
            updated_by TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        );"""

_USER_MFA_DDL = """CREATE TABLE IF NOT EXISTS user_mfa (
            username TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            secret_ciphertext TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 0,
            confirmed_at TEXT,
            last_step INTEGER NOT NULL DEFAULT 0,
            recovery_hashes TEXT NOT NULL DEFAULT '[]',
            pending_ciphertext TEXT NOT NULL DEFAULT '',
            pending_expires_at INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        );"""


def _identity_ddl(conn) -> None:
    """Idempotent DDL for revision 0026, also run by the convergent baseline."""
    columns = db.table_columns(conn, "users")
    for column, ddl in (("login_name", "TEXT NOT NULL DEFAULT ''"), ("auth_source", "TEXT NOT NULL DEFAULT 'local'"),
                        ("external_id", "TEXT NOT NULL DEFAULT ''"), ("directory_synced_at", "INTEGER NOT NULL DEFAULT 0")):
        if column not in columns:
            conn.execute(f"ALTER TABLE users ADD COLUMN {column} {ddl}")
    conn.execute("UPDATE users SET login_name = username WHERE login_name = ''")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_login ON users (tenant_id, login_name)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external ON users (tenant_id, auth_source, external_id) "
                 "WHERE external_id <> ''")
    conn.execute(_DIRECTORY_SETTINGS_DDL)
    conn.execute(_USER_MFA_DDL)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user_mfa_tenant ON user_mfa (tenant_id)")
    for table in ("user_sessions", "refresh_tokens"):
        if "mfa_verified" not in db.table_columns(conn, table):
            conn.execute(f"ALTER TABLE {table} ADD COLUMN mfa_verified INTEGER NOT NULL DEFAULT 0")


_SECRET_COLUMNS = (
    ("kind", "TEXT NOT NULL DEFAULT 'scan'"),
    ("label", "TEXT NOT NULL DEFAULT ''"),
    ("last_used_at", "TEXT"),
    ("rotated_at", "TEXT"),
    ("rekeyed_at", "TEXT"),
    ("privilege_json", "TEXT NOT NULL DEFAULT '{}'"),
    ("updated_at", "TEXT"),
)


def _vault_ddl(conn) -> None:
    """Idempotent DDL for revision 0027, also run by the convergent baseline."""
    columns = db.table_columns(conn, "secrets")
    for column, ddl in _SECRET_COLUMNS:
        if column not in columns:
            conn.execute(f"ALTER TABLE secrets ADD COLUMN {column} {ddl}")


# D7: who can read or write each file in the current estate - one row per principal
# with effective access, written with the asset and replaced when it is scanned again.
_ASSET_ACCESS_DDL = """CREATE TABLE IF NOT EXISTS asset_access (
            tenant_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            principal_key TEXT NOT NULL,
            principal TEXT NOT NULL,
            sid TEXT NOT NULL DEFAULT '',
            can_read INTEGER NOT NULL DEFAULT 0,
            can_write INTEGER NOT NULL DEFAULT 0,
            broad INTEGER NOT NULL DEFAULT 0,
            privileged INTEGER NOT NULL DEFAULT 0,
            service INTEGER NOT NULL DEFAULT 0,
            scan_id TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (tenant_id, asset_id, principal_key)
        );"""
_ASSET_ACCESS_INDEX = "CREATE INDEX IF NOT EXISTS idx_asset_access_principal ON asset_access (tenant_id, principal_key)"


# D2: approved reference sets for exact-data matching - the set, and a keyed fingerprint
# of each of its values. Never a value, never an unkeyed hash of one.
_EDM_DDL = (
    """CREATE TABLE IF NOT EXISTS edm_sets (
            tenant_id TEXT NOT NULL,
            set_id TEXT NOT NULL,
            name TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            row_count INTEGER NOT NULL DEFAULT 0,
            key_digest TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, set_id)
        );""",
    """CREATE TABLE IF NOT EXISTS edm_fingerprints (
            tenant_id TEXT NOT NULL,
            set_id TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            PRIMARY KEY (tenant_id, set_id, fingerprint)
        );""",
    "CREATE INDEX IF NOT EXISTS idx_edm_fingerprint ON edm_fingerprints (tenant_id, fingerprint)",
)


def add_exact_data_match(conn) -> None:
    """Revision 0032: approved reference sets for exact-data matching (D2).

    A workspace uploads a list of the values it knows are personal data - its customers'
    e-mail addresses, its employees' national IDs - and a GDPR finding whose value is on
    it is confirmed. `edm_sets` names each set; `edm_fingerprints` holds a keyed,
    per-tenant fingerprint of each value (classification.exact_match) - never the value.
    Tenant tables: revisions 0003 and 0004 are re-run for their keys and row-level
    security. Rollback: restore the pre-upgrade backup (older code ignores them).
    """
    for statement in _EDM_DDL:
        conn.execute(statement)
    add_tenant_integrity(conn)
    add_tenant_rls(conn)


def add_asset_access(conn) -> None:
    """Revision 0031: who can read each file (D7).

    A scan has always read each file's ACL and kept it inside the asset's detail, where
    no query could reach it: "who can read the files with card numbers" had no answer.
    `asset_access` holds each principal's effective access (allow entries less the
    denies of the same right), with whether the principal is a broad group, a
    privileged one or a service or indexer account. A tenant table: revisions 0003
    and 0004 are re-run for its key and row-level security. It is filled as assets are
    scanned again; rollback: restore the pre-upgrade backup (older code ignores it).
    """
    conn.execute(_ASSET_ACCESS_DDL)
    conn.execute(_ASSET_ACCESS_INDEX)
    add_tenant_integrity(conn)
    add_tenant_rls(conn)


_SCAN_SOURCES_DDL = """CREATE TABLE IF NOT EXISTS scan_sources (
            tenant_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            source_kind TEXT NOT NULL DEFAULT '',
            server TEXT NOT NULL DEFAULT '',
            credential_kind TEXT NOT NULL DEFAULT 'none',
            credential_ref TEXT NOT NULL DEFAULT '',
            recorded_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, scan_id)
        );"""


def admit_whole_database_backup(conn) -> None:
    """Revision 0030: the policies admit the "backup" purpose on every tenant table.

    Since C10 FORCEd row-level security, the table owner pg_dump connects as was subject
    to the policies with no scope - so pg_dump failed on the first table, and a PostgreSQL
    install could take no backup at all (M3 exit review). The dump and the restore now run
    with row security on under this purpose, as a migration runs under "migration".
    Rollback: restore the pre-upgrade backup."""
    add_tenant_rls(conn)


def classify_directory_secrets(conn) -> None:
    """Revision 0029: the directory service account's password is a directory secret.

    Revision 0027 gave `secrets` a kind with 'scan' as its default, and a bind password
    saved between revisions 0026 and 0027 kept that default - so a scan could be pointed
    at a target with it, and a credential manager could replace or delete it (M3 exit
    review). Every secret a workspace's directory settings name is marked 'directory'.
    Data only, idempotent; rollback: restore the pre-upgrade backup (older code ignores
    the kind)."""
    conn.execute(
        "UPDATE secrets SET kind = 'directory' WHERE kind <> 'directory' AND EXISTS ("
        "SELECT 1 FROM directory_settings d WHERE d.tenant_id = secrets.tenant_id "
        "AND d.bind_secret_ref = secrets.secret_id AND d.bind_secret_ref <> '')")


def add_scan_sources(conn) -> None:
    """Revision 0028: how each scan reached its files (C13).

    A value behind a finding is revealed by reading the file again, so the product must
    know how the scan read it: the source kind, the server, and whether the credential
    was a saved one (its vault reference - never a password) or a password typed at scan
    time, which is kept nowhere and makes the scan's files unrevealable. A tenant table:
    revisions 0003 and 0004 are re-run for its key and row-level security. Rollback:
    restore the pre-upgrade backup; older code ignores the table.
    """
    conn.execute(_SCAN_SOURCES_DDL)
    add_tenant_integrity(conn)
    add_tenant_rls(conn)


def add_vault_key_lifecycle(conn) -> None:
    """Revision 0027: what a saved credential is, and its dates (C12).

    `secrets` gains the credential's kind (a scan credential, or a directory service
    account's password), its label (DOMAIN\\username - the account's name, never its
    password), when it was last used, when its password was last replaced, when it was
    last re-sealed under a new vault key, and the result of the last privilege check.
    Re-runs revision 0004, because PLATFORM_ACCESS now admits the "vault" purpose to
    `secrets` and `user_mfa` (a key rotation re-seals every tenant's values). Rollback:
    restore the pre-upgrade backup; the columns are additive and older code ignores them.
    """
    _vault_ddl(conn)
    add_tenant_rls(conn)


def add_tenant_scoped_identities(conn) -> None:
    """Revision 0026: an account is found by its workspace and its sign-in name (C2).

    `users.username` was the only name an account had, unique across the installation,
    so two tenants could not each have an "alice" and registering one told the caller
    the other existed. It stays the internal account key - the session subject, the
    audit actor, the key every other table uses - and gains:

    * `login_name`, what the person types, unique per tenant (backfilled from the key,
      so every existing account signs in exactly as before);
    * `auth_source` ('local' or 'ldap') and `external_id` (the directory's own stable
      identifier), so a directory account is recognised after a rename and can never
      be signed into with a local password;
    * `directory_synced_at`, when its groups were last read - the bound on how long a
      removed group can keep its privilege.

    It also adds each tenant's directory settings, each account's MFA state, and the
    MFA-verified flag on sessions and refresh chains. Both new tables are tenant
    tables: revisions 0003 and 0004 are re-run for their keys and row-level security.
    Rollback: restore the pre-upgrade backup (the upgrade command takes one); the new
    columns are additive, so older code ignores them but would not enforce MFA.
    """
    _identity_ddl(conn)
    add_tenant_integrity(conn)
    add_tenant_rls(conn)


def add_refresh_tokens(conn) -> None:
    """Revision 0019: the rotating half of a bounded session (C1).

    An access token that lives eight hours is a bearer credential with an eight-hour
    blast radius: whoever copies it out of a browser, a proxy log or a crash dump holds
    the account until it expires, and nothing short of revoking it can shorten that. The
    answer is a SHORT access token and a refresh token that is exchanged for the next
    one - which only helps if the refresh token is single use, because a long-lived
    refresh token is the same problem wearing a different name.

    So each exchange retires the token presented and issues a new one in the same
    FAMILY. Presenting a retired token means two parties hold the chain: the legitimate
    one that rotated it and someone replaying a copy. Which is which cannot be known, so
    the whole family is revoked and both are sent back to the sign-in page. That is the
    detection a rotating token buys, and it is the reason to rotate at all.

    Like `user_sessions`, no tenant column: this is authentication infrastructure that
    is read before a tenant scope exists (see add_user_sessions).
    """

    conn.execute("""CREATE TABLE IF NOT EXISTS refresh_tokens (
            token_hash TEXT PRIMARY KEY,
            family_id TEXT NOT NULL,
            username TEXT NOT NULL,
            session_jti TEXT NOT NULL DEFAULT '',
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            used_at INTEGER NOT NULL DEFAULT 0
        );""")
    conn.execute("CREATE INDEX IF NOT EXISTS refresh_tokens_family ON refresh_tokens (family_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS refresh_tokens_owner ON refresh_tokens (username)")
    conn.execute("CREATE INDEX IF NOT EXISTS refresh_tokens_expiry ON refresh_tokens (expires_at)")


def _tenant_scoped(func, all_tenants_purpose: str | None = None):
    """Run a store function inside db.tenant_scope(<its tenant_id>).

    On PostgreSQL every transaction the function opens is then confined by the RLS
    policies to that tenant; on SQLite this is a no-op. Called with no tenant (a
    function where None means "every tenant"), it runs in `all_tenants_purpose`'s
    platform scope when one is named, and otherwise in whatever scope its caller has.
    Since C10 every store function whose first parameter is tenant_id is wrapped (see
    the end of this module); the decorator marks the ones written before that.
    """
    if getattr(func, "_tenant_scoped", False):
        return func
    default = inspect.signature(func).parameters["tenant_id"].default

    def scope_for(args, kwargs):
        tenant = args[0] if args else kwargs.get("tenant_id", default)
        if tenant not in (None, "", inspect.Parameter.empty):
            return db.tenant_scope(str(tenant))
        if all_tenants_purpose:
            return db.platform_scope(all_tenants_purpose)
        return contextlib.nullcontext()

    if inspect.isgeneratorfunction(func):
        @functools.wraps(func)
        def generator(*args, **kwargs):
            with scope_for(args, kwargs):
                yield from func(*args, **kwargs)
        generator._tenant_scoped = True
        return generator

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        with scope_for(args, kwargs):
            return func(*args, **kwargs)
    wrapper._tenant_scoped = True
    return wrapper


def _platform_scoped(purpose: str):
    """Run a store function in db.platform_scope(purpose): work that is for no one
    tenant, which the policies admit only on the tables that purpose needs (C10)."""
    if purpose not in db.PLATFORM_PURPOSES:
        raise ValueError(f"Unknown platform purpose {purpose!r}")

    def decorate(func):
        if inspect.isgeneratorfunction(func):
            # Around the iteration, not the call: a generator's queries run as it is read.
            @functools.wraps(func)
            def generator(*args, **kwargs):
                with db.platform_scope(purpose):
                    yield from func(*args, **kwargs)
            generator._platform_purpose = purpose
            return generator

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with db.platform_scope(purpose):
                return func(*args, **kwargs)
        wrapper._platform_purpose = purpose
        return wrapper
    return decorate


def add_report_artifact_refs(conn) -> None:
    """Revision 0005: reference report bodies instead of storing them (Phase 5).

    Expand step only - it adds the reference columns and touches no data. The
    bodies themselves are moved by ``scripts/migrate_report_bodies.py``, which
    is a data migration with its own evidence, deliberately separate from the
    schema change: a migration that both alters a table and rewrites 250 MB
    across an object store is one that cannot be reasoned about when it fails
    halfway. Dropping ``report_json`` is the contract step, in a later release,
    once every install has been backfilled.
    """
    columns = db.table_columns(conn, "scan_reports")
    if "report_ref" not in columns:
        conn.execute("ALTER TABLE scan_reports ADD COLUMN report_ref TEXT NOT NULL DEFAULT ''")
    if "report_bytes" not in columns:
        conn.execute("ALTER TABLE scan_reports ADD COLUMN report_bytes INTEGER NOT NULL DEFAULT 0")


def add_legal_hold(conn) -> None:
    """Revision 0007: legal hold on a tenant (Phase 6, DB-11).

    Retention deletes data on a schedule; a legal hold is the instruction that
    overrides it for one tenant, for as long as an investigation or dispute
    requires. It has to live in the database rather than in a runbook, because
    the code paths that delete data are the ones that must honour it -
    ``delete_tenant_with_data`` and the retention tool both refuse a held
    tenant rather than trusting an operator to remember.
    """
    columns = db.table_columns(conn, "tenants")
    if "legal_hold" not in columns:
        conn.execute("ALTER TABLE tenants ADD COLUMN legal_hold INTEGER NOT NULL DEFAULT 0")
    if "legal_hold_reason" not in columns:
        conn.execute("ALTER TABLE tenants ADD COLUMN legal_hold_reason TEXT NOT NULL DEFAULT ''")
    if "legal_hold_set_at" not in columns:
        conn.execute("ALTER TABLE tenants ADD COLUMN legal_hold_set_at TEXT NOT NULL DEFAULT ''")


def add_inventory_filtered_search_index(conn) -> None:
    """Revision 0008: keep filtered substring search indexed at Phase 7 scale.

    A standalone trigram GIN and standalone tenant/filter B-tree combine on
    small estates, but PostgreSQL stopped intersecting them at five million
    rows. One multicolumn GIN makes tenant, risk, source and trigram terms a
    single access path. ``btree_gin`` supplies equality operator classes for
    the first three columns; installing extensions remains an admin action.
    """
    if not db.is_postgres():
        return
    missing = [
        name
        for name in ("pg_trgm", "btree_gin")
        if not db.postgres_extension_available(conn, name)
    ]
    if missing:
        raise RuntimeError(
            "Phase 7 filtered-search index requires PostgreSQL extension(s): "
            + ", ".join(missing)
            + ". Rerun scripts/provision_postgres.py as the database admin."
        )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_assets_tenant_filter_search_trgm "
        "ON assets USING GIN (tenant_id, risk_level, source, "
        "(lower(COALESCE(search_text, ''))) gin_trgm_ops)"
    )


def add_remediation_operational_index(conn) -> None:
    """Revision 0009: queryable current-state finding projection.

    ``finding_index`` remains the immutable per-scan detail/history projection.
    The ``findings`` aggregate becomes the lightweight operational read model:
    one stable finding row, an explicit current/historical bit, and only the
    columns needed for filtering, sorting, pagination and global metrics.
    """
    asset_columns = db.table_columns(conn, "assets")
    for column, definition in (
        ("current_scan_id", "TEXT NOT NULL DEFAULT ''"),
        ("observed_at", "TEXT NOT NULL DEFAULT ''"),
    ):
        if column not in asset_columns:
            conn.execute(f"ALTER TABLE assets ADD COLUMN {column} {definition}")

    finding_columns = db.table_columns(conn, "findings")
    for column, definition in (
        ("scan_id", "TEXT NOT NULL DEFAULT ''"),
        ("seq", "INTEGER NOT NULL DEFAULT 0"),
        ("is_current", "INTEGER NOT NULL DEFAULT 0"),
        ("risk_score", "INTEGER NOT NULL DEFAULT 0"),
        ("owner", "TEXT NOT NULL DEFAULT ''"),
        ("sla_due", "TEXT NOT NULL DEFAULT ''"),
        ("display_name", "TEXT NOT NULL DEFAULT ''"),
        ("data_type", "TEXT NOT NULL DEFAULT ''"),
        ("exposure", "TEXT NOT NULL DEFAULT ''"),
        ("affected_asset", "TEXT NOT NULL DEFAULT ''"),
        ("file_name", "TEXT NOT NULL DEFAULT ''"),
        ("file_path", "TEXT NOT NULL DEFAULT ''"),
        ("source", "TEXT NOT NULL DEFAULT ''"),
        ("occurrence_count", "INTEGER NOT NULL DEFAULT 0"),
        ("confidence", "INTEGER NOT NULL DEFAULT 0"),
        ("frameworks_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("search_text", "TEXT NOT NULL DEFAULT ''"),
    ):
        if column not in finding_columns:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {column} {definition}")

    for index in (
        "idx_findings_tenant_current_risk_id ON findings (tenant_id, is_current, risk_score, id)",
        "idx_findings_tenant_current_status_risk_id ON findings (tenant_id, is_current, status, risk_score, id)",
        "idx_findings_tenant_current_severity_risk_id ON findings (tenant_id, is_current, severity, risk_score, id)",
        "idx_findings_tenant_current_framework ON findings (tenant_id, is_current, framework)",
        "idx_findings_tenant_current_asset ON findings (tenant_id, is_current, asset_id)",
        "idx_findings_tenant_current_last_seen_id ON findings (tenant_id, is_current, last_seen, id)",
        "idx_findings_tenant_current_sla_id ON findings (tenant_id, is_current, sla_due, id)",
        "idx_finding_index_tenant_finding_scan ON finding_index (tenant_id, finding_id, scan_id)",
    ):
        conn.execute(f"CREATE INDEX IF NOT EXISTS {index}")

    if db.is_postgres():
        missing = [name for name in ("pg_trgm",) if not db.postgres_extension_available(conn, name)]
        if missing:
            raise RuntimeError("Remediation search requires PostgreSQL extension: pg_trgm")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_tenant_search_trgm "
            "ON findings USING GIN ((lower(COALESCE(search_text, ''))) gin_trgm_ops)"
        )

    # Existing installs already have the latest per-asset snapshot in
    # assets.detail_json. Rebuild only the current marker from that canonical
    # inventory instead of declaring every historical aggregate current.
    conn.execute("UPDATE findings SET is_current = 0")
    assets = conn.execute(
        "SELECT tenant_id, id, source, path, name, owner, modified_at, detail_json "
        "FROM assets WHERE detail_json <> '{}'"
    ).fetchall()
    for asset in assets:
        try:
            file_obj = json.loads(unpack_json_text(asset["detail_json"]) or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        tenant_id = str(asset["tenant_id"] or "")
        asset_id = str(asset["id"] or "")
        path = str(file_obj.get("path") or asset["path"] or "")
        source = str(file_obj.get("source") or asset["source"] or "")
        for seq, finding in enumerate(file_obj.get("findings") or []):
            rule = str(finding.get("type") or finding.get("rule_id") or "sensitive_data")
            finding_id = str(finding.get("finding_id") or hashlib.sha256(
                "|".join((tenant_id, asset_id, rule, path)).encode("utf-8", errors="replace")
            ).hexdigest()[:24])
            raw_frameworks = [finding.get("framework")]
            additional_frameworks = finding.get("frameworks") or []
            if isinstance(additional_frameworks, (list, tuple, set)):
                raw_frameworks.extend(additional_frameworks)
            else:
                raw_frameworks.append(additional_frameworks)
            frameworks = []
            for value in raw_frameworks:
                key = re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")
                key = {"pci": "pci_dss", "pcidss": "pci_dss", "nist": "nist_sp800_60_enterprise"}.get(key, key)
                if key and key not in frameworks:
                    frameworks.append(key)
            if not frameworks:
                frameworks = ["standard_scan"]
            risk = finding.get("risk")
            severity = str(risk.get("level") if isinstance(risk, dict) else risk or finding.get("severity") or "LOW").upper()
            risk_score = int(finding.get("risk_score") or (risk.get("score") if isinstance(risk, dict) else 0) or 0)
            display_name = str(finding.get("display_name") or finding.get("label") or rule).replace("_", " ").strip()
            data_type = str(finding.get("data_type") or finding.get("finding_category") or finding.get("data_category") or finding.get("category") or "Unclassified")
            affected_asset = str(finding.get("asset_name") or finding.get("resource_name") or file_obj.get("host_id") or file_obj.get("server") or file_obj.get("share") or source or asset_id)
            owner = str(finding.get("owner") or finding.get("assignee") or finding.get("data_owner") or file_obj.get("owner") or asset["owner"] or "")
            occurrence_count = int(finding.get("occurrence_count") or finding.get("count") or len(finding.get("occurrences") or []) or 1)
            status = str(finding.get("status") or finding.get("review_status") or "OPEN").upper()
            last_seen = str(finding.get("last_seen") or asset["modified_at"] or "")
            search_text = " ".join((finding_id, display_name, rule, path, affected_asset, owner, data_type, " ".join(frameworks))).lower()
            conn.execute(
                "INSERT INTO findings (tenant_id, id, asset_id, rule, severity, category, framework, status, "
                "first_seen, last_seen, scan_id, seq, is_current, risk_score, owner, sla_due, display_name, "
                "data_type, exposure, affected_asset, file_name, file_path, source, occurrence_count, confidence, "
                "frameworks_json, search_text, severity_rank) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (tenant_id, id) DO UPDATE SET asset_id = excluded.asset_id, rule = excluded.rule, "
                "severity = excluded.severity, category = excluded.category, framework = excluded.framework, "
                "status = excluded.status, last_seen = excluded.last_seen, seq = excluded.seq, is_current = 1, "
                "risk_score = excluded.risk_score, owner = excluded.owner, sla_due = excluded.sla_due, "
                "display_name = excluded.display_name, data_type = excluded.data_type, exposure = excluded.exposure, "
                "affected_asset = excluded.affected_asset, file_name = excluded.file_name, file_path = excluded.file_path, "
                "source = excluded.source, occurrence_count = excluded.occurrence_count, confidence = excluded.confidence, "
                "frameworks_json = excluded.frameworks_json, search_text = excluded.search_text, "
                "severity_rank = excluded.severity_rank",
                (
                    tenant_id, finding_id, asset_id, rule, severity, data_type, frameworks[0], status,
                    str(finding.get("first_seen") or last_seen), last_seen, seq, risk_score, owner,
                    str(finding.get("sla_due") or ""), display_name, data_type,
                    str(finding.get("exposure") or finding.get("exposure_state") or ""), affected_asset,
                    str(file_obj.get("name") or asset["name"] or path.replace("\\", "/").rsplit("/", 1)[-1]), path, source,
                    occurrence_count, int(finding.get("confidence") or 0),
                    json.dumps(frameworks, ensure_ascii=False, separators=(",", ":")), search_text,
                    severity_rank(severity),
                ),
            )


def add_remediation_filter_indexes(conn) -> None:
    """Revision 0010: indexes matching the shipped queue filters and sorts."""
    for index in (
        "idx_findings_tenant_current_owner_id ON findings (tenant_id, is_current, owner, id)",
        "idx_findings_tenant_current_data_type_id ON findings (tenant_id, is_current, data_type, id)",
        "idx_findings_tenant_current_affected_asset_id ON findings (tenant_id, is_current, affected_asset, id)",
        "idx_findings_tenant_current_status_sla_id ON findings (tenant_id, is_current, status, sla_due, id)",
        "idx_findings_tenant_current_name_id ON findings (tenant_id, is_current, display_name, id)",
    ):
        conn.execute(f"CREATE INDEX IF NOT EXISTS {index}")
    if db.is_postgres():
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_frameworks_gin "
            "ON findings USING GIN ((COALESCE(frameworks_json, '[]')::jsonb))"
        )


def apply_baseline_schema(conn) -> None:
    """Revision 0001: the convergent baseline DDL, factored out so the
    versioned migration runner (roadmap Phase 2, DB-05) applies it as the
    first recorded revision instead of anonymous startup DDL."""
    global _sqlite_inventory_fts_enabled
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS scan_reports (
            tenant_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            timestamp TEXT,
            source TEXT,
            scan_label TEXT NOT NULL DEFAULT '',
            summary_json TEXT NOT NULL DEFAULT '{}',
            report_json TEXT NOT NULL,
            report_ref TEXT NOT NULL DEFAULT '',
            report_bytes INTEGER NOT NULL DEFAULT 0,
            -- The inventory projection of this run: the same rows the Source
            -- filter pages through. Selecting a named scan used to decrypt the
            -- 8.3MB report artifact and re-normalise every asset in Python -
            -- 2.3 seconds a page cold, and O(report) rather than O(page), so a
            -- ten-times estate would not have answered at all. Written once,
            -- with the run.
            rows_json TEXT,
            -- The metadata-only form of the report: everything but the file
            -- array. The console restores it at every boot, and deriving it
            -- meant decrypting and parsing the whole artifact to throw the
            -- files away - 1.0s, measured, on the boot critical path.
            compact_json TEXT,
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, scan_id)
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            detail_json TEXT NOT NULL DEFAULT '{}',
            seq INTEGER,
            prev_hash TEXT NOT NULL DEFAULT '',
            row_hash TEXT NOT NULL DEFAULT ''
        );

        -- C4 (revision 0023): audit events waiting for the SIEM.
        CREATE TABLE IF NOT EXISTS audit_outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            seq INTEGER NOT NULL DEFAULT 0,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at REAL NOT NULL DEFAULT 0,
            lease_until REAL NOT NULL DEFAULT 0,
            lease_owner TEXT NOT NULL DEFAULT '',
            last_error TEXT NOT NULL DEFAULT ''
        );

        -- C4 (revision 0022): the head of each tenant's audit chain.
        CREATE TABLE IF NOT EXISTS audit_chain_heads (
            tenant_id TEXT PRIMARY KEY,
            last_seq INTEGER NOT NULL DEFAULT 0,
            last_hash TEXT NOT NULL DEFAULT '',
            pruned_through_seq INTEGER NOT NULL DEFAULT 0,
            pruned_through_hash TEXT NOT NULL DEFAULT '',
            sealed_through_seq INTEGER NOT NULL DEFAULT 0,
            sealed_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS secrets (
            tenant_id TEXT NOT NULL,
            secret_id TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, secret_id)
        );

        CREATE TABLE IF NOT EXISTS scan_profiles (
            tenant_id TEXT NOT NULL,
            profile_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            name TEXT NOT NULL,
            config_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, profile_id)
        );

        CREATE TABLE IF NOT EXISTS alert_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            scan_id TEXT,
            alerts_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS login_failures (
            rate_key TEXT NOT NULL,
            timestamp REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS revoked_tokens (
            jti TEXT PRIMARY KEY,
            expires_at INTEGER NOT NULL,
            revoked_at TEXT NOT NULL
        );

        -- C1 (revision 0018). Deliberately without a tenant_id: revisions 0003/0004
        -- enumerate tenant tables by that column, and session lookups run before any
        -- tenant scope exists. See add_user_sessions.
        CREATE TABLE IF NOT EXISTS user_sessions (
            jti TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            tenant_id TEXT NOT NULL DEFAULT 'default',
            full_name TEXT NOT NULL DEFAULT '',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_login_at TEXT
        );

        CREATE TABLE IF NOT EXISTS tenants (
            tenant_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            registration_code TEXT NOT NULL DEFAULT '',
            legal_hold INTEGER NOT NULL DEFAULT 0,
            legal_hold_reason TEXT NOT NULL DEFAULT '',
            legal_hold_set_at TEXT NOT NULL DEFAULT '',
            estate_generation INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        -- M5: time-boxed, limited-use registration invites. The plaintext
        -- token is never stored - only its sha256. Redemption is an atomic
        -- conditional UPDATE (not expired, not revoked, used_count<max_uses).
        CREATE TABLE IF NOT EXISTS registration_invites (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            max_uses INTEGER NOT NULL DEFAULT 1,
            used_count INTEGER NOT NULL DEFAULT 0,
            expires_at TEXT NOT NULL,
            requires_approval INTEGER NOT NULL DEFAULT 0,
            revoked INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            last_redeemed_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_registration_invites_lookup
            ON registration_invites (tenant_id, token_hash);

        -- M18: DB-backed API keys with a full lifecycle (created / last-used
        -- / revoked / expiry), so a key is revocable and expirable WITHOUT
        -- a redeploy. Only the key's sha256 is stored.
        CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT 'analyst',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            expires_at TEXT,
            revoked INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash);

        -- C5 (revision 0024): the networks and host names a tenant may scan.
        CREATE TABLE IF NOT EXISTS scan_targets (
            tenant_id TEXT NOT NULL,
            entry_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, entry_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_targets_value ON scan_targets (tenant_id, value);

        -- C3 (revision 0021): a tenant's own roles, by name.
        CREATE TABLE IF NOT EXISTS custom_roles (
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            permissions TEXT NOT NULL DEFAULT '[]',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, name)
        );

        -- C1 (revision 0019). No tenant_id, for the same reason as user_sessions.
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token_hash TEXT PRIMARY KEY,
            family_id TEXT NOT NULL,
            username TEXT NOT NULL,
            session_jti TEXT NOT NULL DEFAULT '',
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            used_at INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS user_sessions_owner ON user_sessions (username, last_seen_at);
        CREATE INDEX IF NOT EXISTS user_sessions_expiry ON user_sessions (expires_at);
        CREATE INDEX IF NOT EXISTS refresh_tokens_family ON refresh_tokens (family_id);
        CREATE INDEX IF NOT EXISTS refresh_tokens_owner ON refresh_tokens (username);
        CREATE INDEX IF NOT EXISTS refresh_tokens_expiry ON refresh_tokens (expires_at);

        CREATE INDEX IF NOT EXISTS idx_scan_reports_tenant_created
            ON scan_reports (tenant_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_scan_reports_tenant_created_scan
            ON scan_reports (tenant_id, created_at, scan_id);
        CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_timestamp
            ON audit_events (tenant_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_alert_events_tenant_created
            ON alert_events (tenant_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_login_failures_key_timestamp
            ON login_failures (rate_key, timestamp);
        CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires
            ON revoked_tokens (expires_at);
        CREATE INDEX IF NOT EXISTS idx_users_tenant
            ON users (tenant_id, role);

        -- Phase 1 (DATA-001) normalized model. Written alongside the
        -- report_json blob (dual-write); reads still use the blob.
        CREATE TABLE IF NOT EXISTS scan_runs (
            tenant_id TEXT NOT NULL,
            id TEXT NOT NULL,
            source TEXT,
            mode TEXT,
            policy_version TEXT,
            started_at TEXT,
            ended_at TEXT,
            status TEXT,
            total_files INTEGER NOT NULL DEFAULT 0,
            summary_json TEXT NOT NULL DEFAULT '{}',
            PRIMARY KEY (tenant_id, id)
        );

        CREATE TABLE IF NOT EXISTS assets (
            tenant_id TEXT NOT NULL,
            id TEXT NOT NULL,
            source TEXT,
            stable_object_id TEXT,
            path TEXT,
            name TEXT,
            -- S-B queryable-inventory columns (denormalized from the scan
            -- so the inventory list filters/sorts/searches in the DB).
            extension TEXT,
            share TEXT,
            risk_level TEXT,
            risk_score INTEGER NOT NULL DEFAULT 0,
            size INTEGER NOT NULL DEFAULT 0,
            owner TEXT,
            modified_at TEXT,
            finding_count INTEGER NOT NULL DEFAULT 0,
            top_frameworks TEXT,
            is_hidden INTEGER NOT NULL DEFAULT 0,
            is_system INTEGER NOT NULL DEFAULT 0,
            is_protected INTEGER NOT NULL DEFAULT 0,
            search_text TEXT,
            finding_types TEXT NOT NULL DEFAULT '[]',
            framework_keys TEXT NOT NULL DEFAULT '[]',
            detail_json TEXT NOT NULL DEFAULT '{}',
            scan_label TEXT NOT NULL DEFAULT '',
            current_scan_id TEXT NOT NULL DEFAULT '',
            observed_at TEXT NOT NULL DEFAULT '',
            -- The collapsed table shows how many reasons and DLP actions a file
            -- carries. Those are two lengths inside detail_json, and reading
            -- them per page meant fetching and parsing the whole blob for every
            -- row: 11.3MB and 127ms for a page of 100, measured. They are
            -- written here once, when the blob that defines them is written.
            reason_count INTEGER NOT NULL DEFAULT 0,
            dlp_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (tenant_id, id)
        );

        CREATE TABLE IF NOT EXISTS asset_versions (
            tenant_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            version TEXT NOT NULL,
            size INTEGER NOT NULL DEFAULT 0,
            mtime TEXT,
            content_hash TEXT,
            coverage TEXT,
            PRIMARY KEY (tenant_id, asset_id, version)
        );

        -- Track P-A: authoritative per-object delta baseline. The
        -- analyzed snapshot remains normalized in assets.detail_json;
        -- this table owns only identity/fingerprint/generation state.
        CREATE TABLE IF NOT EXISTS scan_object_baselines (
            tenant_id TEXT NOT NULL,
            scope_key TEXT NOT NULL,
            object_key TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            size BIGINT NOT NULL DEFAULT 0,
            mtime TEXT NOT NULL DEFAULT '',
            content_hash TEXT NOT NULL DEFAULT '',
            version_signature TEXT NOT NULL,
            last_scan_id TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            snapshot_json TEXT NOT NULL DEFAULT '{}',
            PRIMARY KEY (tenant_id, scope_key, object_key)
        );

        CREATE TABLE IF NOT EXISTS findings (
            tenant_id TEXT NOT NULL,
            id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            rule TEXT,
            severity TEXT,
            category TEXT,
            framework TEXT,
            status TEXT,
            first_seen TEXT,
            last_seen TEXT,
            scan_id TEXT NOT NULL DEFAULT '',
            seq INTEGER NOT NULL DEFAULT 0,
            is_current INTEGER NOT NULL DEFAULT 0,
            risk_score INTEGER NOT NULL DEFAULT 0,
            owner TEXT NOT NULL DEFAULT '',
            sla_due TEXT NOT NULL DEFAULT '',
            display_name TEXT NOT NULL DEFAULT '',
            data_type TEXT NOT NULL DEFAULT '',
            exposure TEXT NOT NULL DEFAULT '',
            affected_asset TEXT NOT NULL DEFAULT '',
            file_name TEXT NOT NULL DEFAULT '',
            file_path TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            occurrence_count INTEGER NOT NULL DEFAULT 0,
            confidence INTEGER NOT NULL DEFAULT 0,
            frameworks_json TEXT NOT NULL DEFAULT '[]',
            search_text TEXT NOT NULL DEFAULT '',
            -- Severity as an orderable number. The display value stays in
            -- `severity`; this exists so "worst first" is an index range scan
            -- rather than a CASE expression sorted in temp space.
            severity_rank INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (tenant_id, id)
        );

        CREATE TABLE IF NOT EXISTS finding_occurrences (
            tenant_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            locator TEXT,
            fingerprint TEXT,
            occurrence_count INTEGER NOT NULL DEFAULT 1
        );

        -- Materialized per-finding read index (DATA-001 read-switch).
        -- Stores the exact list_findings response per finding so the
        -- read path can serve findings without loading full report
        -- blobs. Behind DSPM_READ_FROM_NORMALIZED (default off).
        CREATE TABLE IF NOT EXISTS finding_index (
            tenant_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            finding_id TEXT NOT NULL,
            status TEXT,
            response_json TEXT NOT NULL,
            -- F2: stamps the logic version that produced response_json. A
            -- read only trusts rows whose stamp == FINDING_INDEX_VERSION,
            -- so a change to _finding_response/_finding_status invalidates
            -- stale rows (they fall back to the blob until re-backfilled).
            index_version TEXT NOT NULL DEFAULT ''
        );

        -- S-F.2 durable reconciliation metrics for the optional search
        -- projection. The DB remains authoritative; this stores only
        -- counts/status, never document metadata or evidence.
        CREATE TABLE IF NOT EXISTS search_reconciliation_state (
            provider TEXT NOT NULL,
            index_uid TEXT NOT NULL,
            checked_at TEXT NOT NULL,
            metrics_json TEXT NOT NULL,
            PRIMARY KEY (provider, index_uid)
        );

        CREATE INDEX IF NOT EXISTS idx_scan_runs_tenant
            ON scan_runs (tenant_id, started_at);
        CREATE INDEX IF NOT EXISTS idx_findings_tenant_asset
            ON findings (tenant_id, asset_id);
        CREATE INDEX IF NOT EXISTS idx_occurrences_scan_finding
            ON finding_occurrences (tenant_id, scan_id, finding_id);
        CREATE INDEX IF NOT EXISTS idx_occurrences_finding
            ON finding_occurrences (finding_id);
        CREATE INDEX IF NOT EXISTS idx_finding_index_tenant_scan_seq
            ON finding_index (tenant_id, scan_id, seq);
        CREATE INDEX IF NOT EXISTS idx_finding_index_tenant_finding_scan
            ON finding_index (tenant_id, finding_id, scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_tenant_current_risk_id
            ON findings (tenant_id, is_current, risk_score, id);
        CREATE INDEX IF NOT EXISTS idx_findings_tenant_current_status_risk_id
            ON findings (tenant_id, is_current, status, risk_score, id);
        CREATE INDEX IF NOT EXISTS idx_findings_tenant_current_severity_risk_id
            ON findings (tenant_id, is_current, severity, risk_score, id);
        CREATE INDEX IF NOT EXISTS idx_findings_tenant_current_framework
            ON findings (tenant_id, is_current, framework);
        CREATE INDEX IF NOT EXISTS idx_findings_tenant_current_asset
            ON findings (tenant_id, is_current, asset_id);
        CREATE INDEX IF NOT EXISTS idx_findings_tenant_current_last_seen_id
            ON findings (tenant_id, is_current, last_seen, id);
        CREATE INDEX IF NOT EXISTS idx_findings_tenant_current_sla_id
            ON findings (tenant_id, is_current, sla_due, id);
        CREATE INDEX IF NOT EXISTS idx_findings_tenant_current_owner_id
            ON findings (tenant_id, is_current, owner, id);
        CREATE INDEX IF NOT EXISTS idx_findings_tenant_current_data_type_id
            ON findings (tenant_id, is_current, data_type, id);
        CREATE INDEX IF NOT EXISTS idx_findings_tenant_current_affected_asset_id
            ON findings (tenant_id, is_current, affected_asset, id);
        CREATE INDEX IF NOT EXISTS idx_findings_tenant_current_status_sla_id
            ON findings (tenant_id, is_current, status, sla_due, id);
        CREATE INDEX IF NOT EXISTS idx_findings_tenant_current_name_id
            ON findings (tenant_id, is_current, display_name, id);
        CREATE INDEX IF NOT EXISTS idx_scan_object_baselines_generation
            ON scan_object_baselines (tenant_id, scope_key, last_scan_id);

        -- Durable job state (ARCH-003). The executor is still in-memory,
        -- but the job RECORD survives a restart so status/history are not
        -- lost and an orphaned "running" job can be recovered to failed.
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            status TEXT NOT NULL,
            progress INTEGER NOT NULL DEFAULT 0,
            message TEXT,
            created_at TEXT NOT NULL,
            finished_at TEXT,
            error TEXT,
            updated_at TEXT NOT NULL,
            -- B2, revision 0011: which scan the job runs and what it was asked
            -- to do, so a restart can resume it. The request is stored without
            -- secrets, and a job whose only credential was a typed password is
            -- not resumable.
            scan_id TEXT NOT NULL DEFAULT '',
            request_json TEXT NOT NULL DEFAULT '{}',
            resumable INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_scan_jobs_tenant
            ON scan_jobs (tenant_id, created_at);

        -- B2, revision 0011: the partition ledger. One row per unit of a scan,
        -- and a restart resumes from the first unit that is not done.
        CREATE TABLE IF NOT EXISTS scan_partitions (
            tenant_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            partition_id TEXT NOT NULL,
            job_id TEXT NOT NULL DEFAULT '',
            ordinal INTEGER NOT NULL DEFAULT 0,
            spec_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'queued',
            attempt INTEGER NOT NULL DEFAULT 0,
            files INTEGER NOT NULL DEFAULT 0,
            error TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL DEFAULT '',
            finished_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL,
            records_ref TEXT NOT NULL DEFAULT '',
            records_bytes INTEGER NOT NULL DEFAULT 0,
            records_json TEXT,
            summary_json TEXT NOT NULL DEFAULT '{}',
            diagnostics_json TEXT NOT NULL DEFAULT '{}',
            lease_owner TEXT NOT NULL DEFAULT '',
            lease_expires_at TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (tenant_id, scan_id, partition_id)
        );
        CREATE INDEX IF NOT EXISTS idx_scan_partitions_next
            ON scan_partitions (tenant_id, scan_id, status, ordinal);

        -- B2.4, revision 0014: one row per partitioned scan - what continuing it after
        -- a restart, or from another worker, needs.
        CREATE TABLE IF NOT EXISTS partitioned_scans (
            tenant_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            job_id TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'running',
            request_json TEXT NOT NULL DEFAULT '{}',
            header_json TEXT NOT NULL DEFAULT '{}',
            resumable INTEGER NOT NULL DEFAULT 0,
            error TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, scan_id)
        );
        CREATE INDEX IF NOT EXISTS idx_partitioned_scans_status
            ON partitioned_scans (status, updated_at);

        CREATE TABLE IF NOT EXISTS scan_schedules (
            tenant_id TEXT NOT NULL,
            schedule_id TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            request_json TEXT NOT NULL DEFAULT '{}',
            interval_seconds INTEGER NOT NULL DEFAULT 86400,
            enabled INTEGER NOT NULL DEFAULT 1,
            next_run_at TEXT NOT NULL,
            last_run_at TEXT NOT NULL DEFAULT '',
            last_scan_id TEXT NOT NULL DEFAULT '',
            last_status TEXT NOT NULL DEFAULT '',
            last_error TEXT NOT NULL DEFAULT '',
            runs INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, schedule_id)
        );
        CREATE INDEX IF NOT EXISTS idx_scan_schedules_due
            ON scan_schedules (enabled, next_run_at);

        CREATE TABLE IF NOT EXISTS suppression_rules (
            tenant_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            finding_type TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            path_pattern TEXT NOT NULL DEFAULT '',
            fingerprint TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            expires_at TEXT NOT NULL DEFAULT '',
            source_finding_id TEXT NOT NULL DEFAULT '',
            source_scan_id TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, rule_id)
        );
        CREATE INDEX IF NOT EXISTS idx_suppression_rules_active
            ON suppression_rules (tenant_id, active);

        CREATE TABLE IF NOT EXISTS derived_cache (
            tenant_id TEXT NOT NULL,
            cache_key TEXT NOT NULL,
            generation INTEGER NOT NULL DEFAULT 0,
            value_json TEXT NOT NULL DEFAULT '{}',
            expires_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, cache_key)
        );

        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    # Kept outside the CREATE script so a legacy scan_reports table can gain the
    # column before its label index is created.
    add_scan_report_labels(conn)
    add_report_artifact_refs(conn)
    add_legal_hold(conn)
    now = datetime.now(timezone.utc).isoformat()
    columns = db.table_columns(conn, "tenants")
    if "registration_code" not in columns:
        conn.execute("ALTER TABLE tenants ADD COLUMN registration_code TEXT NOT NULL DEFAULT ''")
    user_columns = db.table_columns(conn, "users")
    if "avatar" not in user_columns:
        # Profile photo as a bounded data URL (~300 KB cap enforced at the
        # API); kept off _public_user so /api/users listings stay small.
        conn.execute("ALTER TABLE users ADD COLUMN avatar TEXT NOT NULL DEFAULT ''")
    # F2: bring pre-version-stamp finding_index rows up to the current
    # schema. They land with index_version='' (i.e. "unknown logic"), so
    report_columns = db.table_columns(conn, "scan_reports")
    if "rows_json" not in report_columns:
        conn.execute("ALTER TABLE scan_reports ADD COLUMN rows_json TEXT")
    if "compact_json" not in report_columns:
        conn.execute("ALTER TABLE scan_reports ADD COLUMN compact_json TEXT")

    # the read-switch treats them as stale and serves the blob until a
    # backfill re-stamps them - the safe default for a migration mirror.
    finding_columns = db.table_columns(conn, "findings")
    if "severity_rank" not in finding_columns:
        conn.execute("ALTER TABLE findings ADD COLUMN severity_rank INTEGER NOT NULL DEFAULT 0")
        conn.execute(
            "UPDATE findings SET severity_rank = CASE severity "
            "WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END"
        )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_findings_tenant_current_rank_id "
        "ON findings (tenant_id, is_current, severity_rank, id)"
    )

    asset_count_columns = db.table_columns(conn, "assets")
    for column in ("reason_count", "dlp_count"):
        if column not in asset_count_columns:
            conn.execute(f"ALTER TABLE assets ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0")
    fi_columns = db.table_columns(conn, "finding_index")
    if "index_version" not in fi_columns:
        conn.execute("ALTER TABLE finding_index ADD COLUMN index_version TEXT NOT NULL DEFAULT ''")
    # Created here (not in the schema script above) because the column it
    # covers may have just been added by the ALTER on a pre-existing DB.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_finding_index_version ON finding_index (tenant_id, index_version)")

    baseline_columns = db.table_columns(conn, "scan_object_baselines")
    if "snapshot_json" not in baseline_columns:
        conn.execute("ALTER TABLE scan_object_baselines ADD COLUMN snapshot_json TEXT NOT NULL DEFAULT '{}'")

    # S-B: bring pre-existing `assets` tables up to the queryable-inventory
    # schema. New columns default to 0/NULL; a re-scan (dual-write) or
    # backfill_normalized_scans() populates them for historical assets.
    asset_columns = db.table_columns(conn, "assets")
    for col, coltype in (
        ("extension", "TEXT"),
        ("share", "TEXT"),
        ("risk_level", "TEXT"),
        ("risk_score", "INTEGER NOT NULL DEFAULT 0"),
        ("size", "INTEGER NOT NULL DEFAULT 0"),
        ("owner", "TEXT"),
        ("modified_at", "TEXT"),
        ("finding_count", "INTEGER NOT NULL DEFAULT 0"),
        ("top_frameworks", "TEXT"),
        ("is_hidden", "INTEGER NOT NULL DEFAULT 0"),
        ("is_system", "INTEGER NOT NULL DEFAULT 0"),
        ("is_protected", "INTEGER NOT NULL DEFAULT 0"),
        ("search_text", "TEXT"),
        ("finding_types", "TEXT NOT NULL DEFAULT '[]'"),
        ("framework_keys", "TEXT NOT NULL DEFAULT '[]'"),
        ("detail_json", "TEXT NOT NULL DEFAULT '{}'"),
        # The operator-facing scan name ("HR file share"), so Data
        # Inventory can filter by the scan a customer configured
        # instead of the collector protocol (smb / endpoint-winrm).
        ("scan_label", "TEXT NOT NULL DEFAULT ''"),
    ):
        if col not in asset_columns:
            conn.execute(f"ALTER TABLE assets ADD COLUMN {col} {coltype}")
    # Index every filter/sort column (created after the ALTERs so the
    # columns exist on a migrated DB).
    for _idx in (
        "idx_assets_tenant_risk_score ON assets (tenant_id, risk_score)",
        "idx_assets_tenant_risk_level ON assets (tenant_id, risk_level)",
        "idx_assets_tenant_extension ON assets (tenant_id, extension)",
        "idx_assets_tenant_size ON assets (tenant_id, size)",
        "idx_assets_tenant_modified ON assets (tenant_id, modified_at)",
        "idx_assets_tenant_finding_count ON assets (tenant_id, finding_count)",
        "idx_assets_tenant_source ON assets (tenant_id, source)",
        "idx_assets_tenant_protected ON assets (tenant_id, is_protected)",
    ):
        conn.execute(f"CREATE INDEX IF NOT EXISTS {_idx}")

    # S-C.1: match every keyset ORDER BY with its id tiebreaker. A
    # two-column sort index still makes the database sort equal-valued
    # rows at scale; these composites serve first and deep pages alike.
    for _idx in (
        "idx_assets_tenant_risk_score_id ON assets (tenant_id, risk_score, id)",
        "idx_assets_tenant_size_id ON assets (tenant_id, size, id)",
        "idx_assets_tenant_finding_count_id ON assets (tenant_id, finding_count, id)",
        # New sortable columns need the same id-tiebreaker composite, or
        # keyset pagination falls back to a temp B-tree at scale.
        "idx_assets_tenant_risk_level_id ON assets (tenant_id, risk_level, id)",
        "idx_assets_tenant_source_id ON assets (tenant_id, source, id)",
        "idx_assets_tenant_scan_label_id ON assets (tenant_id, scan_label, id)",
    ):
        conn.execute(f"CREATE INDEX IF NOT EXISTS {_idx}")
    if db.is_postgres():
        # Track S 5M PostgreSQL acceptance composites. These match the
        # production inventory filter predicates while preserving
        # risk_score/id ordering for LIMIT/keyset reads.
        for _idx in (
            "idx_assets_tenant_risk_level_source_extension_risk_score_id "
            "ON assets (tenant_id, risk_level, source, extension, risk_score, id)",
            "idx_assets_tenant_protected_risk_score_id "
            "ON assets (tenant_id, is_protected, risk_score, id)",
            "idx_assets_tenant_risk_level_source_risk_score_id "
            "ON assets (tenant_id, risk_level, source, risk_score, id)",
        ):
            conn.execute(f"CREATE INDEX IF NOT EXISTS {_idx}")

        # Text keysets explicitly use C collation for SQLite/Python
        # parity, so the index expression must use that same collation.
        conn.execute(
            'CREATE INDEX IF NOT EXISTS idx_assets_tenant_modified_c_id '
            'ON assets (tenant_id, (COALESCE(modified_at, \'\') COLLATE "C"), id)'
        )
        conn.execute(
            'CREATE INDEX IF NOT EXISTS idx_assets_tenant_name_c_id '
            'ON assets (tenant_id, (COALESCE(name, \'\') COLLATE "C"), id)'
        )
    else:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_assets_tenant_modified_c_id "
            "ON assets (tenant_id, COALESCE(modified_at, ''), id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_assets_tenant_name_c_id "
            "ON assets (tenant_id, COALESCE(name, ''), id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_assets_tenant_scan_label_c_id "
            "ON assets (tenant_id, COALESCE(scan_label, ''), id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_assets_tenant_source_c_id "
            "ON assets (tenant_id, COALESCE(source, ''), id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_assets_tenant_risk_level_c_id "
            "ON assets (tenant_id, COALESCE(risk_level, ''), id)"
        )
        # SQLite cannot reliably select the OR-predicate partial index
        # below. detail_json is NOT NULL on SQLite, so an exact empty-JSON
        # index makes the readiness probe constant time without indexing
        # the large JSON text itself.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_assets_tenant_empty_detail "
            "ON assets (tenant_id) WHERE detail_json = '{}'"
        )
        # SQLite development/on-prem compatibility path: FTS5's trigram
        # tokenizer preserves the product's literal substring semantics
        # (partial names, paths and identifiers) without scanning every
        # potentially large search_text value. External-content triggers
        # keep the index transactional with the authoritative assets row.
        try:
            required_triggers = {
                "assets_search_fts_ai", "assets_search_fts_ad", "assets_search_fts_au",
            }
            existing_objects = {
                str(row["name"])
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE name = 'assets_search_fts' "
                    "OR name IN ('assets_search_fts_ai', 'assets_search_fts_ad', 'assets_search_fts_au')"
                ).fetchall()
            }
            needs_rebuild = "assets_search_fts" not in existing_objects or not required_triggers <= existing_objects
            conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS assets_search_fts USING fts5("
                "tenant_id UNINDEXED, search_text, content='assets', content_rowid='rowid', tokenize='trigram')"
            )
            conn.executescript(
                """
                CREATE TRIGGER IF NOT EXISTS assets_search_fts_ai AFTER INSERT ON assets BEGIN
                    INSERT INTO assets_search_fts(rowid, tenant_id, search_text)
                    VALUES (new.rowid, new.tenant_id, COALESCE(new.search_text, ''));
                END;
                CREATE TRIGGER IF NOT EXISTS assets_search_fts_ad AFTER DELETE ON assets BEGIN
                    INSERT INTO assets_search_fts(assets_search_fts, rowid, tenant_id, search_text)
                    VALUES ('delete', old.rowid, old.tenant_id, COALESCE(old.search_text, ''));
                END;
                CREATE TRIGGER IF NOT EXISTS assets_search_fts_au
                AFTER UPDATE OF tenant_id, search_text ON assets BEGIN
                    INSERT INTO assets_search_fts(assets_search_fts, rowid, tenant_id, search_text)
                    VALUES ('delete', old.rowid, old.tenant_id, COALESCE(old.search_text, ''));
                    INSERT INTO assets_search_fts(rowid, tenant_id, search_text)
                    VALUES (new.rowid, new.tenant_id, COALESCE(new.search_text, ''));
                END;
                """
            )
            if needs_rebuild:
                conn.execute("INSERT INTO assets_search_fts(assets_search_fts) VALUES ('rebuild')")
            _sqlite_inventory_fts_enabled = True
        except Exception as exc:  # pragma: no cover - depends on SQLite build options
            _sqlite_inventory_fts_enabled = False
            logger.warning(
                "SQLite trigram inventory index unavailable; using compatible LIKE search: %s",
                type(exc).__name__,
            )
    # Readiness checks run on every normalized request. This partial
    # index is empty for a healthy mirror, avoiding a 5M-row scan merely
    # to prove that no pre-S-E detail rows remain.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_assets_tenant_missing_detail "
        "ON assets (tenant_id) WHERE detail_json IS NULL OR detail_json = '{}'"
    )

    # Track S-D: PostgreSQL substring search over paths/names/owners is
    # backed by pg_trgm without changing the S-C API's literal-substring
    # semantics. The expression is intentionally identical to the WHERE
    # predicate below. SQLite keeps its compatible LIKE fallback.
    #
    # CREATE EXTENSION belongs to scripts/provision_postgres.py because
    # the runtime role is least-privilege. Existing deployments that have
    # not rerun provisioning remain correct (sequential LIKE), but warn.
    if db.is_postgres():
        if db.postgres_extension_available(conn, "pg_trgm"):
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_assets_search_trgm "
                "ON assets USING GIN ((lower(COALESCE(search_text, ''))) gin_trgm_ops)"
            )
        else:
            logger.warning(
                "Track S-D search index unavailable: pg_trgm is not installed; "
                "rerun scripts/provision_postgres.py as the PostgreSQL admin"
            )

    _identity_ddl(conn)  # C2 (revision 0026)
    _vault_ddl(conn)  # C12 (revision 0027)
    conn.execute(_SCAN_SOURCES_DDL)  # C13 (revision 0028)
    conn.execute(_ASSET_ACCESS_DDL)  # D7 (revision 0031)
    conn.execute(_ASSET_ACCESS_INDEX)
    for statement in _EDM_DDL:  # D2 (revision 0032)
        conn.execute(statement)
    conn.execute(
        """
        INSERT OR IGNORE INTO tenants (tenant_id, display_name, registration_code, created_at, updated_at)
        VALUES ('default', 'Default', ?, ?, ?)
        """,
        (generate_registration_code(), now, now),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO tenants (tenant_id, display_name, registration_code, created_at, updated_at)
        SELECT tenant_id, tenant_id, '', ?, ? FROM users
        UNION
        SELECT tenant_id, tenant_id, '', ?, ? FROM scan_reports
        UNION
        SELECT tenant_id, tenant_id, '', ?, ? FROM audit_events
        UNION
        SELECT tenant_id, tenant_id, '', ?, ? FROM secrets
        UNION
        SELECT tenant_id, tenant_id, '', ?, ? FROM alert_events
        """,
        (now, now, now, now, now, now, now, now, now, now),
    )
    rows = conn.execute("SELECT tenant_id FROM tenants WHERE registration_code = ''").fetchall()
    for row in rows:
        conn.execute(
            "UPDATE tenants SET registration_code = ?, updated_at = ? WHERE tenant_id = ?",
            (generate_registration_code(), now, row["tenant_id"]),
        )



def ensure_schema_ready() -> None:
    """Startup schema policy (Phase 2, DB-05).

    Development/SQLite: auto-apply pending revisions (same convergent behavior
    as before, now recorded). Production: NEVER apply DDL at startup - verify
    the recorded revision matches this build and refuse to serve otherwise, so
    schema changes only happen through an operator-run migration step.
    """
    if os.getenv("DSPM_MIGRATIONS_CLI") == "1":
        return  # the migrations CLI is driving; keep the import inert

    from backend import migrations  # local import; migrations imports store

    if os.getenv("DSPM_ENV", "local").strip().lower() in {"prod", "production"}:
        migrations.verify_or_raise()
    else:
        migrations.upgrade()


ensure_schema_ready()


SCAN_PROFILE_KINDS = {"file-server", "endpoint"}
_SCAN_PROFILE_SECRET_KEYS = {"password", "admin_password", "secret", "token"}


def _sanitize_scan_profile_config(config: dict) -> dict:
    """Profiles persist configuration, never credentials.

    The client vaults passwords into credential refs before saving, but the
    store strips secret-shaped keys anyway so a raw password can never land in
    the database even through a hand-crafted API call.
    """
    cleaned = {}
    for key, value in (config or {}).items():
        if str(key).lower() in _SCAN_PROFILE_SECRET_KEYS:
            continue
        cleaned[key] = value
    return cleaned


def list_scan_profiles(tenant_id: str) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT profile_id, kind, name, config_json, created_at, updated_at "
            "FROM scan_profiles WHERE tenant_id = ? ORDER BY created_at",
            (tenant_id,),
        ).fetchall()
    profiles = []
    for row in rows:
        try:
            config = json.loads(row["config_json"] or "{}")
        except json.JSONDecodeError:
            config = {}
        profiles.append({
            "profile_id": row["profile_id"],
            "kind": row["kind"],
            "name": row["name"],
            "config": config,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })
    return profiles


def save_scan_profile(
    tenant_id: str,
    *,
    profile_id: str | None,
    kind: str,
    name: str,
    config: dict,
) -> dict:
    if kind not in SCAN_PROFILE_KINDS:
        raise ValueError("Unknown scan profile kind")
    clean_name = str(name or "").strip()[:80]
    if not clean_name:
        raise ValueError("Scan profile name is required")
    cleaned = _sanitize_scan_profile_config(config if isinstance(config, dict) else {})
    encoded = json.dumps(cleaned, ensure_ascii=False, separators=(",", ":"))
    if len(encoded) > 32 * 1024:
        raise ValueError("Scan profile configuration is too large")
    now = datetime.now(timezone.utc).isoformat()
    new_id = str(profile_id or "").strip() or secrets.token_urlsafe(9)
    with _lock:
        with _connect() as conn:
            existing = conn.execute(
                "SELECT created_at FROM scan_profiles WHERE tenant_id = ? AND profile_id = ?",
                (tenant_id, new_id),
            ).fetchone()
            created_at = existing["created_at"] if existing else now
            conn.execute(
                "INSERT INTO scan_profiles (tenant_id, profile_id, kind, name, config_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (tenant_id, profile_id) DO UPDATE SET "
                "kind = excluded.kind, name = excluded.name, config_json = excluded.config_json, "
                "updated_at = excluded.updated_at",
                (tenant_id, new_id, kind, clean_name, encoded, created_at, now),
            )
    return {
        "profile_id": new_id,
        "kind": kind,
        "name": clean_name,
        "config": cleaned,
        "created_at": created_at,
        "updated_at": now,
    }


def delete_scan_profile(tenant_id: str, profile_id: str) -> bool:
    with _lock:
        with _connect() as conn:
            result = conn.execute(
                "DELETE FROM scan_profiles WHERE tenant_id = ? AND profile_id = ?",
                (tenant_id, profile_id),
            )
    return bool(result.rowcount)


# The request an audit row belongs to. Set once per request by the API layer;
# `audit()` is called from thirty places and threading a Request through all of
# them would be a worse change than a context variable.
_request_origin: contextvars.ContextVar[dict] = contextvars.ContextVar("dspm_request_origin", default={})


def set_request_origin(client_ip: str = "", user_agent: str = "") -> None:
    _request_origin.set({
        "client_ip": str(client_ip or "")[:64],
        "user_agent": str(user_agent or "")[:200],
    })


def audit(tenant_id: str, actor: str, action: str, detail: dict | None = None) -> None:
    """Record one action.

    The row carries the ORIGIN of the request as well as the actor. A trail that
    says "admin deleted a tenant" without saying from where cannot answer the
    first question anyone asks of it. Note the address is the peer's: behind a
    reverse proxy every row reads as the proxy unless the proxy is configured to
    preserve it, and X-Forwarded-For is deliberately not trusted here.
    """

    timestamp = datetime.now(timezone.utc).isoformat()
    detail = {**(detail or {}), **{k: v for k, v in _request_origin.get().items() if v}}
    with _lock:
        with _connect() as conn:
            _append_audit(conn, tenant_id, timestamp, actor, action, json.dumps(detail, ensure_ascii=False))


def _append_audit(conn, tenant_id: str, timestamp: str, actor: str, action: str, detail_json: str) -> tuple[int, str]:
    """Append one row to its tenant's chain (C4, backend.audit_chain).

    The first statement WRITES the tenant's head row, so on SQLite this transaction holds
    the database's write lock before it reads the head - two processes cannot both read
    the same last hash and fork the chain. PostgreSQL gets the same from FOR UPDATE.
    """
    from backend import audit_chain

    conn.execute(
        "INSERT INTO audit_chain_heads (tenant_id, updated_at) VALUES (?, ?) ON CONFLICT (tenant_id) DO NOTHING",
        (tenant_id, timestamp),
    )
    lock = " FOR UPDATE" if db.is_postgres() else ""
    head = conn.execute(
        f"SELECT last_seq, last_hash FROM audit_chain_heads WHERE tenant_id = ?{lock}", (tenant_id,)
    ).fetchone()
    seq = int(head["last_seq"] or 0) + 1
    prev = str(head["last_hash"] or "")
    digest = audit_chain.row_hash(prev, tenant_id, seq, timestamp, actor, action, detail_json)
    conn.execute(
        "INSERT INTO audit_events (tenant_id, timestamp, actor, action, detail_json, seq, prev_hash, row_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (tenant_id, timestamp, actor, action, detail_json, seq, prev, digest),
    )
    conn.execute(
        "UPDATE audit_chain_heads SET last_seq = ?, last_hash = ?, updated_at = ? WHERE tenant_id = ?",
        (seq, digest, timestamp, tenant_id),
    )
    from backend.siem import forwarding_enabled

    # Asked through this transaction's own connection: an event is queued exactly when
    # forwarding was on at the moment it was recorded, on whichever backend recorded it.
    if forwarding_enabled(conn):
        # Same transaction as the row: an event is never recorded without being queued
        # for the SIEM, nor queued without being recorded (backend.siem).
        payload = json.dumps({
            "tenant_id": tenant_id, "seq": seq, "row_hash": digest, "timestamp": timestamp,
            "actor": actor, "action": action, "detail": json.loads(detail_json or "{}"),
        }, ensure_ascii=False)
        conn.execute(
            "INSERT INTO audit_outbox (tenant_id, seq, payload, created_at) VALUES (?, ?, ?, ?)",
            (tenant_id, seq, payload, timestamp),
        )
    return seq, digest




def claim_audit_outbox(*, limit: int, now: float, lease_seconds: float, owner: str) -> list[dict]:
    """Take up to `limit` due events, oldest first, leased to `owner` so another backend
    draining the same outbox does not send them too."""
    claimed: list[dict] = []
    with _lock:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT id, tenant_id, seq, payload, attempts FROM audit_outbox "
                "WHERE next_attempt_at <= ? AND lease_until <= ? ORDER BY id LIMIT ?",
                (now, now, int(limit)),
            ).fetchall()
            for row in rows:
                taken = conn.execute(
                    "UPDATE audit_outbox SET lease_until = ?, lease_owner = ? WHERE id = ? AND lease_until <= ?",
                    (now + lease_seconds, owner, row["id"], now),
                ).rowcount
                if taken:
                    claimed.append(dict(row))
    return claimed


def delete_audit_outbox(ids: list[int]) -> None:
    if not ids:
        return
    with _lock:
        with _connect() as conn:
            conn.executemany("DELETE FROM audit_outbox WHERE id = ?", [(int(item),) for item in ids])


def retry_audit_outbox(outbox_id: int, attempts: int, next_attempt_at: float, error: str) -> None:
    with _lock:
        with _connect() as conn:
            conn.execute(
                "UPDATE audit_outbox SET attempts = ?, next_attempt_at = ?, lease_until = 0, lease_owner = '', "
                "last_error = ? WHERE id = ?",
                (int(attempts), float(next_attempt_at), str(error)[:200], int(outbox_id)),
            )


def audit_outbox_status() -> dict:
    """What is waiting for the SIEM: a count and the age of the oldest - never content."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS pending, MIN(created_at) AS oldest, MAX(attempts) AS attempts, "
            "SUM(CASE WHEN attempts > 0 THEN 1 ELSE 0 END) AS failing FROM audit_outbox"
        ).fetchone()
    oldest = str(row["oldest"] or "")
    age = 0.0
    if oldest:
        try:
            age = max(0.0, (datetime.now(timezone.utc) - datetime.fromisoformat(oldest)).total_seconds())
        except ValueError:
            age = 0.0
    return {"pending": int(row["pending"] or 0), "oldest_seconds": round(age, 1), "max_attempts": int(row["attempts"] or 0),
            "failing": int(row["failing"] or 0)}


def reset_audit_outbox_backoff() -> int:
    """Make every waiting event due now - the console's Retry. Only the wait changes:
    attempts and the last error stay, and delivery still needs a receiver that answers."""
    with _lock:
        with _connect() as conn:
            return int(conn.execute(
                "UPDATE audit_outbox SET next_attempt_at = 0 WHERE next_attempt_at > 0 AND lease_until <= ?",
                (time.time(),),
            ).rowcount or 0)


def verify_audit_chain(tenant_id: str | None = None) -> list[dict]:
    """Check every tenant's audit chain (or one tenant's); see backend.audit_chain.verify_chain."""
    from backend import audit_chain

    with _connect() as conn:
        if tenant_id is None:
            tenants = sorted({str(row["tenant_id"]) for row in conn.execute(
                "SELECT tenant_id FROM audit_chain_heads UNION SELECT DISTINCT tenant_id FROM audit_events"
            ).fetchall()})
        else:
            tenants = [tenant_id]
        results = []
        for tenant in tenants:
            head_row = conn.execute(
                "SELECT last_seq, last_hash, pruned_through_seq, pruned_through_hash, sealed_through_seq, sealed_at "
                "FROM audit_chain_heads WHERE tenant_id = ?", (tenant,)).fetchone()
            # Streamed from the cursor: verification holds one row at a time, not the trail.
            rows = (dict(row) for row in conn.execute(
                "SELECT id, seq, timestamp, actor, action, detail_json, prev_hash, row_hash FROM audit_events "
                "WHERE tenant_id = ? ORDER BY seq, id", (tenant,)))
            head = dict(head_row) if head_row is not None else None
            result = audit_chain.verify_chain(tenant, rows, head)
            if head is None and result["rows"]:
                # A head can be deleted to hide a truncated chain: its absence is itself a finding.
                result["problems"].insert(0, {"seq": None, "problem": "the tenant has audit rows but no chain head"})
                del result["problems"][audit_chain.PROBLEM_LIMIT:]
                result["problem_count"] += 1
                result["ok"] = False
            results.append(result)
    return results


def report_artifacts_enabled() -> bool:
    """Store report bodies in the artifact tier (Phase 5, DB-07).

    On by default. ``DSPM_REPORT_ARTIFACTS=0`` keeps bodies inline in the
    database - the pre-Phase-5 behaviour - for an install that has not yet
    added the artifact directory to its backup set.
    """
    return os.getenv("DSPM_REPORT_ARTIFACTS", "1") != "0"


class StreamedFiles:
    """A report's ``files`` that are produced while the body is written, not held.

    ``iter_report_json`` walks it exactly as it walks a list, so the body is byte-for-
    byte what the list would have produced. ``json.dumps`` refuses it, which is the
    point: nothing can quietly turn it back into one string. Each iteration calls
    ``factory`` again, so a body can be streamed more than once.
    """

    __slots__ = ("factory",)

    def __init__(self, factory) -> None:
        self.factory = factory

    def __iter__(self):
        return iter(self.factory())


def _json_key(key) -> str:
    """A dict key encoded exactly as ``json.dumps`` encodes it inside an object.

    JSON keys are strings, so ``json.dumps`` writes the key ``1`` as ``"1"`` and
    ``None`` as ``"null"``, and refuses a tuple - none of which it does to a value.
    """
    if isinstance(key, str):
        return json.dumps(key, ensure_ascii=False)
    return json.dumps({key: 0}, ensure_ascii=False)[1:-4]


def iter_report_json(report: dict):
    """The report as JSON, a piece at a time, never as one string.

    ``json.dumps(report)`` on a million-file scan is a gigabyte of text held
    beside the report it was built from - measured at 4.63 KB per file, and the
    tallest thing in the save once the projection stopped being built whole.

    The output is byte-for-byte what ``json.dumps(report, ensure_ascii=False)``
    produces, which is not a nicety: an artifact's name is the SHA-256 of its
    plaintext, so a different-but-equivalent encoding would give every existing
    report a new content id and re-store it on the next lifecycle update. A
    nested value serialises the same whether it is dumped alone or as part of
    its parent, so only the punctuation between values has to be reproduced
    here - `json.dumps` default separators, in insertion order.

    ``files`` is emitted record by record and may be any iterable, which is what
    lets the scanner eventually hand this a stream rather than a list.
    """

    yield "{"
    for index, (key, value) in enumerate(report.items()):
        if index:
            yield ", "
        yield _json_key(key)
        yield ": "
        if key == "files" and isinstance(value, (list, tuple, StreamedFiles)):
            yield "["
            for position, record in enumerate(value):
                if position:
                    yield ", "
                yield json.dumps(record, ensure_ascii=False)
            yield "]"
        else:
            yield json.dumps(value, ensure_ascii=False)
    yield "}"


def _store_report_body(tenant_id: str, report: dict) -> tuple[str, int, str]:
    """Persist a report body; returns (report_ref, report_bytes, inline_body).

    The object is durable before the row that references it. The reverse order
    would risk a reference to a body that does not exist; this order risks only
    an unreferenced object, which ``artifacts.prune()`` collects.

    With the artifact tier on - the default - the body is streamed and never
    exists as a single string. With it off the body is a column value, so it has
    to be assembled; that is the pre-Phase-5 behaviour and it keeps the
    pre-Phase-5 memory cost with it.
    """
    if not report_artifacts_enabled():
        body = "".join(iter_report_json(report))
        return "", len(body.encode("utf-8")), body
    from backend import artifacts

    ref = artifacts.put_stream(tenant_id, iter_report_json(report))
    return ref.content_id, ref.size_bytes, ""


def _report_body(tenant_id: str, row) -> dict:
    """Resolve a scan_reports row to its report, from wherever the body lives.

    Reads the artifact tier when the row carries a reference and falls back to
    the inline blob otherwise, so an install mid-backfill serves both.
    """
    if row is None:
        return {}
    try:
        content_id = str(row["report_ref"] or "")
    except (KeyError, IndexError, TypeError):
        content_id = ""
    if content_id:
        from backend import artifacts

        return json.loads(artifacts.get_text(tenant_id, content_id) or "{}")
    try:
        inline = row["report_json"]
    except (KeyError, IndexError, TypeError):
        inline = ""
    return json.loads(inline or "{}")


@_tenant_scoped
def save_scan_history(tenant_id: str, report: dict) -> str:
    scan_id = report.get("scan_id") or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    report["scan_id"] = scan_id
    created_at = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            # DATA-002: a scan run's creation timestamp is immutable. Finding-
            # lifecycle updates re-save the same scan_id to refresh the body, but
            # must NOT reset created_at (that broke history/audit ordering). The
            # immutable scan-run record itself lives in the normalized scan_runs
            # table, written authoritatively below (Phase 5): if that write
            # fails, this whole save fails and nothing is persisted.
            existing = conn.execute(
                "SELECT created_at FROM scan_reports WHERE tenant_id = ? AND scan_id = ?",
                (tenant_id, scan_id),
            ).fetchone()
            if existing and existing["created_at"]:
                created_at = existing["created_at"]
            inventory_rows: list[dict] = []
            normalized_written = _dual_write_normalized(conn, tenant_id, report, is_new_scan=existing is None,
                                                        inventory_rows=inventory_rows)
            if normalized_written:
                _write_incremental_baseline(conn, tenant_id, report, is_new_scan=existing is None)
            else:
                incremental = (report.get("scan_diagnostics") or {}).get("incremental")
                if isinstance(incremental, dict) and incremental.get("enabled"):
                    incremental["baseline_committed"] = False
                    incremental["baseline_commit_reason"] = "normalized_asset_write_unavailable"
            report_ref, report_bytes, inline_body = _store_report_body(tenant_id, report)
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_reports
                    (tenant_id, scan_id, timestamp, source, scan_label, summary_json,
                     report_json, report_ref, report_bytes, rows_json, compact_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    scan_id,
                    report.get("timestamp"),
                    report.get("source"),
                    str(report.get("scan_label") or "").strip()[:80],
                    json.dumps(report.get("summary", {}), ensure_ascii=False),
                    inline_body,
                    report_ref,
                    report_bytes,
                    _packed_report_rows(tenant_id, report, inventory_rows if normalized_written else None),
                    _packed_compact_report(report),
                    created_at,
                ),
            )
    _invalidate_inventory_query_cache(tenant_id)
    _invalidate_remediation_query_cache(tenant_id)
    # A scan is the only thing that changes the shape of this data, so it is
    # also the only moment the planner's statistics need refreshing. SQLite
    # ships with none until ANALYZE has run.
    with suppress(Exception):
        db.optimize_sqlite(DB_PATH)
    # S-F dual-write is an optional, best-effort projection and deliberately
    # runs after the authoritative DB transaction/lock has completed. Search
    # outages must never roll back or delay ownership of the saved scan.
    try:
        from backend.search import SearchUnavailable, index_scan_report

        index_scan_report(tenant_id, report)
    except SearchUnavailable as exc:
        logger.warning("Dedicated search indexing deferred for scan %s: %s", scan_id, exc)
    except Exception as exc:  # pragma: no cover - optional projection guard
        logger.warning("Dedicated search indexing skipped for scan %s: %s", scan_id, type(exc).__name__)
    return scan_id


# F2: logic version of the materialized finding_index. Bump this whenever
# _finding_response or _finding_status changes shape, so already-stored rows are
# recognized as stale and the read-switch falls back to the blob until a
# re-backfill (scripts/backfill_normalized.py) re-stamps them.
FINDING_INDEX_VERSION = "fi-v1"


class NormalizedWriteFailed(RuntimeError):
    """A scan could not be written to the normalized surfaces."""


def _normalized_write_is_best_effort() -> bool:
    """Legacy mirror semantics: swallow normalized failures and keep the blob.

    Phase 5 made normalized writes authoritative. This escape hatch exists for
    emergency operation only (an operator accepting a degraded estate to keep
    scanning); it is off by default and read live so it can be flipped without
    a restart.
    """
    return os.getenv("DSPM_NORMALIZED_WRITE_BEST_EFFORT", "0") == "1"


# Three columns hold JSON the interface never reads in bulk: the per-scan
# finding history (188MB), the incremental-scan baselines (110MB) and the
# per-asset detail blob (62MB). 360MB of a 523MB database.
#
# SQLite stores what it is given, so these are zlib'd into BLOBs. PostgreSQL is
# deliberately excluded: TOAST already compresses a large TEXT value, and
# storing our own bytes there would trade its transparent handling for a
# format only this module understands.
#
# Measured on this data: 5.6x for the baselines, 5.7x for the detail blobs,
# 2.3x for the finding history - the last is small rows, where zlib has less
# to work with. Base64 would have kept the columns TEXT and cost a third of
# every gain, which is why these are BLOBs.
_JSON_ZLIB_MAGIC = b"DSPMz1"


def _compression_floor() -> int:
    """Below this, the header costs more than the saving - and `'{}'` must stay
    text, because two partial indexes and the read-model gate compare against
    it literally."""
    try:
        return max(256, min(int(os.getenv("DSPM_JSON_COMPRESS_MIN", "2048")), 1_000_000))
    except ValueError:
        return 2048


def pack_json_text(value: str):
    if db.is_postgres():
        return value
    text = value if isinstance(value, str) else str(value or "")
    if len(text) < _compression_floor():
        return text
    return _JSON_ZLIB_MAGIC + zlib.compress(text.encode("utf-8"), 6)


def unpack_json_text(value) -> str:
    """Accepts what any generation of this schema stored: text, a compressed
    blob, or a blob that predates compression."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if raw.startswith(_JSON_ZLIB_MAGIC):
            return zlib.decompress(raw[len(_JSON_ZLIB_MAGIC):]).decode("utf-8")
        return raw.decode("utf-8", "replace")
    return value if isinstance(value, str) else ("" if value is None else str(value))


def _detail_counts(detail_json) -> tuple[int, int]:
    """(reasons, dlp actions) from an asset's detail blob, at write time."""
    try:
        detail = json.loads(unpack_json_text(detail_json) or "{}")
    except (json.JSONDecodeError, TypeError):
        return (0, 0)
    risk = detail.get("risk") if isinstance(detail, dict) else {}
    risk = risk if isinstance(risk, dict) else {}
    return (len(risk.get("reasons") or []), len(risk.get("dlp_recommendations") or []))


def _dual_write_normalized(conn, tenant_id: str, report: dict, *, is_new_scan: bool = True,
                           inventory_rows: list | None = None) -> bool:
    """Write the scan's normalized surfaces (roadmap Phase 5, DB-07).

    **Authoritative:** assets, findings, occurrences and the finding index are
    written inside the same transaction as the report row, so a failure fails
    the whole save. Before Phase 5 this was a best-effort mirror whose failure
    was logged and swallowed - which could persist a report whose normalized
    projection silently did not exist, and the inventory read path would then
    serve an estate missing that scan. A scan that cannot be projected is not
    a scan that happened.

    The savepoint is retained so the best-effort escape hatch can still roll
    back only the mirror rows.
    """
    try:
        conn.execute("SAVEPOINT dspm_norm")
        _write_normalized_rows(conn, tenant_id, report, refresh_current=is_new_scan, inventory_rows=inventory_rows)
        conn.execute("RELEASE SAVEPOINT dspm_norm")
        return True
    except Exception as exc:
        try:
            conn.execute("ROLLBACK TO SAVEPOINT dspm_norm")
            conn.execute("RELEASE SAVEPOINT dspm_norm")
        except Exception:
            pass
        if not _normalized_write_is_best_effort():
            raise NormalizedWriteFailed(
                f"Refusing to save scan {report.get('scan_id')!r}: the normalized "
                f"surfaces could not be written ({type(exc).__name__}: {exc}). The "
                "save was rolled back; no partial estate was persisted."
            ) from exc
        logger.warning("Normalized dual-write skipped for scan %s: %s", report.get("scan_id"), exc)
        return False


def _write_incremental_baseline(conn, tenant_id: str, report: dict, *, is_new_scan: bool = True,
                                prune: bool = True) -> None:
    """Advance a scope generation inside the authoritative scan transaction.

    A partial/truncated scan may refresh objects it did see but never prunes the
    prior generation. A complete scan deletes unseen rows only after every
    current row and its normalized asset snapshot have been written.
    """

    diagnostics = report.get("scan_diagnostics") if isinstance(report.get("scan_diagnostics"), dict) else {}
    incremental = diagnostics.get("incremental") if isinstance(diagnostics, dict) else None
    if not isinstance(incremental, dict) or not incremental.get("baseline_update", incremental.get("enabled")):
        return
    if not is_new_scan:
        # Finding workflow/lifecycle operations re-save historical report blobs.
        # They may refresh assets.detail_json, but must never roll the active
        # object generation back to that report's older size/mtime set.
        refreshed = 0
        scan_id = str(report.get("scan_id") or "")
        scope_key = str(incremental.get("scope_key") or "")
        for record in report.get("files") or []:
            object_key = str(record.get("reuse_key") or record.get("path") or "")
            if not object_key:
                continue
            result = conn.execute(
                "UPDATE scan_object_baselines SET snapshot_json = ?, updated_at = ? "
                "WHERE tenant_id = ? AND scope_key = ? AND object_key = ? AND last_scan_id = ?",
                (
                    pack_json_text(json.dumps(record, ensure_ascii=False, separators=(",", ":"))),
                    datetime.now(timezone.utc).isoformat(),
                    tenant_id,
                    scope_key,
                    object_key,
                    scan_id,
                ),
            )
            refreshed += max(0, int(result.rowcount or 0))
        incremental["baseline_snapshot_rows_refreshed"] = refreshed
        incremental["baseline_commit_reason"] = "existing_scan_resave_preserved_generation"
        return
    scope_key = str(incremental.get("scope_key") or "")
    version_signature = str(incremental.get("version_signature") or "")
    scan_id = str(report.get("scan_id") or "")
    if not scope_key or not version_signature or not scan_id:
        incremental["baseline_committed"] = False
        incremental["baseline_commit_reason"] = "missing_scope_version_or_scan_id"
        return

    from backend.domain import asset_identity

    source = str(report.get("source") or "local")
    now = datetime.now(timezone.utc).isoformat()
    rows: list[tuple] = []
    rows_written = 0
    skipped = 0
    archive_mtimes = {
        str(record.get("path") or ""): str(record.get("modified_at") or record.get("mtime") or "")
        for record in report.get("files") or []
        if str(record.get("extension") or "").lower() == ".zip" and "::" not in str(record.get("path") or "")
    }

    def flush_rows() -> None:
        nonlocal rows_written
        if not rows:
            return
        conn.executemany(
            """
            INSERT OR REPLACE INTO scan_object_baselines
                (tenant_id, scope_key, object_key, asset_id, size, mtime,
                 content_hash, version_signature, last_scan_id, last_seen_at,
                 updated_at, snapshot_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        rows_written += len(rows)
        rows.clear()

    for record in report.get("files") or []:
        path = str(record.get("path") or record.get("name") or "")
        object_key = str(record.get("reuse_key") or path)
        mtime = str(record.get("modified_at") or record.get("mtime") or record.get("last_write_time") or "")
        if not mtime and "::" in path:
            mtime = archive_mtimes.get(path.split("::", 1)[0], "")
        content_hash = str(record.get("content_hash") or record.get("file_hash") or record.get("sha256") or "")
        if (
            not object_key
            or not mtime
            or (
                int(record.get("size") or record.get("total_bytes") or 0) > 0
                and not content_hash
                and "::" not in object_key
            )
        ):
            skipped += 1
            continue
        stable_object_id = str(record.get("stable_object_id") or record.get("asset_id") or "")
        asset_id = asset_identity(tenant_id, source, stable_object_id, path)
        rows.append(
            (
                tenant_id,
                scope_key,
                object_key,
                asset_id,
                int(record.get("size") or record.get("total_bytes") or 0),
                mtime,
                content_hash,
                version_signature,
                scan_id,
                now,
                now,
                pack_json_text(json.dumps(record, ensure_ascii=False, separators=(",", ":"))),
            )
        )
        if len(rows) >= 500:
            flush_rows()
    flush_rows()

    if not prune:
        # A partition writes its objects and leaves the prune to finalize. It has
        # not seen the rest of the scan, so everything it did not write would look
        # deleted.
        incremental["baseline_committed"] = True
        incremental["baseline_rows_written"] = rows_written
        incremental["baseline_rows_skipped"] = skipped
        incremental["deleted_objects"] = 0
        incremental["prune_skipped"] = True
        return

    incremental["baseline_committed"] = True
    incremental["baseline_rows_written"] = rows_written
    incremental["baseline_rows_skipped"] = skipped
    _prune_incremental_baseline(conn, tenant_id, incremental, scope_key, scan_id)


def _prune_incremental_baseline(conn, tenant_id: str, incremental: dict, scope_key: str, scan_id: str) -> None:
    """Delete a scope's objects this scan did not write - only if the scan was complete.

    Shared by the single save and by finalize, which is the only point a
    partitioned scan knows it saw everything.
    """
    stale = conn.execute(
        "SELECT COUNT(*) AS count FROM scan_object_baselines "
        "WHERE tenant_id = ? AND scope_key = ? AND last_scan_id <> ?",
        (tenant_id, scope_key, scan_id),
    ).fetchone()
    deleted = int(stale["count"] if stale else 0)
    complete = bool(incremental.get("complete"))
    if complete:
        conn.execute(
            "DELETE FROM scan_object_baselines "
            "WHERE tenant_id = ? AND scope_key = ? AND last_scan_id <> ?",
            (tenant_id, scope_key, scan_id),
        )
    incremental["deleted_objects"] = deleted if complete else 0
    incremental["prune_skipped"] = not complete


def incremental_baseline_exists(tenant_id: str, scope_key: str) -> bool:
    """Cheap first-scan guard that avoids one guaranteed-miss query per file."""

    if not tenant_id or not scope_key:
        return False
    with _lock:
        with _connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM scan_object_baselines WHERE tenant_id = ? AND scope_key = ? LIMIT 1",
                (tenant_id, scope_key),
            ).fetchone()
    return row is not None


def probe_incremental_object(
    tenant_id: str,
    scope_key: str,
    object_key: str,
    size: int,
    mtime: str,
    version_signature: str,
) -> dict:
    """Classify one object and return a durable analyzed snapshot on a match."""

    if not tenant_id or not scope_key or not object_key:
        return {"state": "new"}
    with _lock:
        with _connect() as conn:
            row = conn.execute(
                """
                SELECT b.size, b.mtime, b.content_hash, b.version_signature,
                       b.snapshot_json
                FROM scan_object_baselines b
                WHERE b.tenant_id = ? AND b.scope_key = ? AND b.object_key = ?
                """,
                (tenant_id, scope_key, object_key),
            ).fetchone()
    if row is None:
        return {"state": "new"}
    exact = (
        int(row["size"] or 0) == int(size or 0)
        and str(row["mtime"] or "") == str(mtime or "")
        and str(row["version_signature"] or "") == str(version_signature or "")
        and (bool(str(row["content_hash"] or "")) or int(size or 0) == 0)
    )
    if not exact or not row["snapshot_json"]:
        return {"state": "changed"}
    try:
        detail = json.loads(unpack_json_text(row["snapshot_json"]))
    except (TypeError, json.JSONDecodeError):
        return {"state": "changed"}
    if not isinstance(detail, dict):
        return {"state": "changed"}
    from discovery.incremental import reuse_snapshot_from_result

    snapshot = reuse_snapshot_from_result(detail)
    if str(detail.get("extension") or "").lower() == ".zip":
        prefix = f"{object_key}::"
        with _lock:
            with _connect() as conn:
                child_rows = conn.execute(
                    "SELECT object_key, snapshot_json FROM scan_object_baselines "
                    "WHERE tenant_id = ? AND scope_key = ? "
                    "AND substr(object_key, 1, ?) = ? ORDER BY object_key",
                    (tenant_id, scope_key, len(prefix), prefix),
                ).fetchall()
        archive_records: list[dict] = []
        for child in child_rows:
            try:
                child_detail = json.loads(unpack_json_text(child["snapshot_json"]) or "{}")
            except (TypeError, json.JSONDecodeError):
                child_detail = {}
            if isinstance(child_detail, dict) and child_detail:
                child_detail.setdefault("reuse_key", str(child["object_key"] or ""))
                archive_records.append(child_detail)
        snapshot["archive_records"] = archive_records
        snapshot["archive_bundle_complete"] = True
    return {"state": "unchanged", "snapshot": snapshot}


# Matches the bundled synthetic demo dataset. Kept in sync with the client-side
# isSampleDataPath() and the compact-response detection in backend/app.py.
_DEMO_SAMPLE_PATH_RE = re.compile(
    r"(^|[\\/])enterprise_test_data([\\/]|$)|(^|[\\/])README_enterprise_dataset\.md$|(^|[\\/])_manifest\.json$",
    re.IGNORECASE,
)


def _demo_assets_allowed_in_inventory() -> bool:
    return os.getenv("DSPM_DEMO_ASSETS_IN_INVENTORY", "0") == "1"


def is_demo_sample_report(report: dict) -> bool:
    """True when a scan is of the bundled synthetic demo dataset.

    Mirrors the client's isDemoSampleReport(): an explicit flag wins; otherwise
    a majority of file paths under enterprise_test_data marks the scan as demo.
    """
    if not isinstance(report, dict):
        return False
    if report.get("is_demo_sample") is not None:
        return bool(report.get("is_demo_sample"))
    files = report.get("files")
    if not isinstance(files, list) or not files:
        return False
    sample_count = sum(
        1 for file_obj in files
        if isinstance(file_obj, dict) and _DEMO_SAMPLE_PATH_RE.search(
            str(file_obj.get("path") or file_obj.get("full_path") or file_obj.get("name") or "")
        )
    )
    return sample_count / len(files) >= 0.5


def purge_demo_sample_assets(tenant_id: str | None = None) -> int:
    """Remove synthetic demo-dataset assets from the durable estate.

    Legacy hygiene: demo scans used to be persisted into `assets` like real
    scans, so the dashboard and Data Inventory counted synthetic files alongside
    the customer's real estate. New demo scans skip the estate entirely; this
    removes rows written before that rule existed. Scan reports/history are
    untouched - only the estate tables (assets, asset_versions, findings).
    """
    if _demo_assets_allowed_in_inventory():
        return 0
    scope_sql = " AND tenant_id = ?" if tenant_id else ""
    like_args = ("%enterprise_test_data%",) + ((tenant_id,) if tenant_id else ())
    with _lock:
        with _connect() as conn:
            rows = conn.execute(
                f"SELECT id, path FROM assets WHERE path LIKE ?{scope_sql}", like_args
            ).fetchall()
            demo_ids = [str(row["id"]) for row in rows if _DEMO_SAMPLE_PATH_RE.search(str(row["path"] or ""))]
            for asset_id in demo_ids:
                args = (asset_id,) + ((tenant_id,) if tenant_id else ())
                conn.execute(f"DELETE FROM asset_versions WHERE asset_id = ?{scope_sql}", args)
                conn.execute(f"DELETE FROM asset_access WHERE asset_id = ?{scope_sql}", args)
                conn.execute(f"DELETE FROM findings WHERE asset_id = ?{scope_sql}", args)
                conn.execute(f"DELETE FROM assets WHERE id = ?{scope_sql}", args)
    if demo_ids:
        logger.info("Purged %d demo-sample assets from the estate%s", len(demo_ids), f" (tenant {tenant_id})" if tenant_id else "")
        invalidate_inventory = globals().get("_invalidate_inventory_query_cache")
        invalidate_remediation = globals().get("_invalidate_remediation_query_cache")
        if callable(invalidate_inventory):
            invalidate_inventory(tenant_id)
        if callable(invalidate_remediation):
            invalidate_remediation(tenant_id)
    return len(demo_ids)


# One-time hygiene migration at startup: estates written before the demo-scan
# exclusion existed may still carry synthetic sample assets. Idempotent and a
# no-op once clean (or when DSPM_DEMO_ASSETS_IN_INVENTORY=1 opts back in).
try:
    purge_demo_sample_assets()
except Exception as exc:  # pragma: no cover - never block startup on hygiene
    logger.warning("Demo-sample estate purge skipped: %s", type(exc).__name__)


def _operational_frameworks(finding: dict) -> list[str]:
    values = [finding.get("framework")]
    additional = finding.get("frameworks")
    if isinstance(additional, (list, tuple, set)):
        values.extend(additional)
    elif additional:
        values.append(additional)
    aliases = {
        "pci": "pci_dss", "pcidss": "pci_dss", "pci_dss_4_0": "pci_dss",
        "nist": "nist_sp800_60_enterprise", "nist_sp_800_60": "nist_sp800_60_enterprise",
        "nist_sp800_60": "nist_sp800_60_enterprise",
    }
    result: list[str] = []
    for value in values:
        key = re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")
        key = aliases.get(key, key)
        if key and key not in result:
            result.append(key)
    return result or ["standard_scan"]


# How many rows one `executemany` carries. The point of the cap is MEMORY, not
# the database: a million-row parameter list is held in full while the scan is
# still producing more. Round trips are already amortised inside psycopg's
# pipelined executemany, so a larger batch buys nothing - measured on this
# host's PostgreSQL, executemany runs at 27.6us/row against 98.2us/row for a
# loop of execute(), and a hand-built multi-row VALUES form was no faster again
# (the cost has moved from round trips to binding and parsing).
#
# 1,000 is sized from the widest row we write. `assets.detail_json` measured
# over 1,371 real rows as stored: 4.6 KB median, 11.7 KB p99, 20 KB worst. So a
# batch holds ~4.4 MB of parameters at the median and ~11 MB at p99 - a cap that
# still means something. At 5,000 the same p99 is 56 MB, which is not a cap.
_WRITE_BATCH = 1000

# How many ids fit in one `IN (...)`. Deliberately far below both real limits -
# 32,766 measured on this SQLite build, 65,535 documented for PostgreSQL -
# because older SQLite builds ship SQLITE_MAX_VARIABLE_NUMBER at 999 and this
# product is installed on machines we do not choose. 900 still turns a
# million-row retirement loop into ~1,100 statements.
_ID_CHUNK = 900


def _executemany(conn, sql: str, rows) -> int:
    """One statement, many rows, in bounded batches. Returns the row count."""

    written = 0
    batch: list = []
    for row in rows:
        batch.append(row)
        if len(batch) >= _WRITE_BATCH:
            conn.executemany(sql, batch)
            written += len(batch)
            batch = []
    if batch:
        conn.executemany(sql, batch)
        written += len(batch)
    return written


def _id_chunks(ids):
    """`ids` in slices that fit one statement's bind-parameter budget."""

    ordered = list(dict.fromkeys(str(value) for value in ids if value))
    for start in range(0, len(ordered), _ID_CHUNK):
        yield ordered[start:start + _ID_CHUNK]


def _existing_finding_lifecycle(conn, tenant_id: str, finding_ids) -> dict:
    """The status/owner/SLA an analyst has already set, for these findings.

    This used to be one SELECT per finding, inside the write loop - two million
    round trips on a million-file scan, purely to avoid clobbering triage state.
    The same answer costs one statement per 900 findings when it is asked once.

    Asking once per batch also fixes the meaning of the answer inside a batch:
    every finding in it sees the prior state, taken before the batch wrote
    anything. The per-finding SELECT read back rows the same scan had just
    written, so when one finding id appeared twice in a report the second
    occurrence inherited whatever the first resolved to.

    Across batches that inheritance is back, and it is stated rather than hidden
    (B1 review, 2026-09-14). Since B1.1 the estate is written 1,000 files at a
    time, so a finding id repeated in a *later* batch reads the row an earlier
    batch wrote. That changes a result only when the two copies disagree about
    owner, severity or due date - which two readings of the same file in one scan
    do not, and a test pins a path listed twice across a batch boundary. Undoing
    it exactly would mean holding every finding's prior state for the whole scan,
    which is the memory B1.1 exists to give back.
    """

    existing: dict[str, dict] = {}
    for chunk in _id_chunks(finding_ids):
        placeholders = ",".join("?" for _ in chunk)
        rows = conn.execute(
            f"SELECT id, status, owner, sla_due, severity_rank FROM findings "
            f"WHERE tenant_id = ? AND id IN ({placeholders})",
            (tenant_id, *chunk),
        ).fetchall()
        for row in rows:
            existing[str(row["id"])] = {
                "status": row["status"], "owner": row["owner"], "sla_due": row["sla_due"],
                "severity_rank": row["severity_rank"],
            }
    return existing


def _operational_finding_id(tenant_id: str, asset_id: str, file_obj: dict, finding: dict) -> str:
    """A finding's stable identity, computed without touching the database.

    The caller needs this BEFORE the write, so it can fetch every finding's
    existing lifecycle state in one query instead of one row at a time.
    """

    from backend.domain import finding_identity

    path = str(file_obj.get("path") or file_obj.get("name") or "")
    rule = str(finding.get("type") or finding.get("rule_id") or "sensitive_data")
    return str(finding.get("finding_id") or finding_identity(tenant_id, asset_id, rule, path))


_FINDING_UPSERT_SQL = (
    "INSERT INTO findings (tenant_id, id, asset_id, rule, severity, category, framework, status, "
    "first_seen, last_seen, scan_id, seq, is_current, risk_score, owner, sla_due, display_name, "
    "data_type, exposure, affected_asset, file_name, file_path, source, occurrence_count, confidence, "
    "frameworks_json, search_text, severity_rank) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
    "ON CONFLICT (tenant_id, id) DO UPDATE SET asset_id = excluded.asset_id, rule = excluded.rule, "
    "severity = excluded.severity, category = excluded.category, framework = excluded.framework, status = excluded.status, "
    "first_seen = COALESCE(NULLIF(findings.first_seen, ''), excluded.first_seen), last_seen = excluded.last_seen, "
    "scan_id = CASE WHEN excluded.is_current = 1 THEN excluded.scan_id ELSE findings.scan_id END, "
    "seq = CASE WHEN excluded.is_current = 1 THEN excluded.seq ELSE findings.seq END, "
    "is_current = CASE WHEN excluded.is_current = 1 THEN 1 ELSE findings.is_current END, "
    "risk_score = excluded.risk_score, owner = excluded.owner, sla_due = excluded.sla_due, "
    "display_name = excluded.display_name, data_type = excluded.data_type, exposure = excluded.exposure, "
    "affected_asset = excluded.affected_asset, file_name = excluded.file_name, file_path = excluded.file_path, "
    "source = excluded.source, occurrence_count = excluded.occurrence_count, confidence = excluded.confidence, "
    "frameworks_json = excluded.frameworks_json, search_text = excluded.search_text, "
    "severity_rank = excluded.severity_rank"
)


def _operational_finding_params(
    tenant_id: str, scan_id: str, seq: int, asset_id: str, file_obj: dict, finding: dict,
    finding_id: str, existing: dict | None, *, is_current: bool,
) -> tuple:
    """The row for one lightweight finding, without evidence/history payloads.

    Pure with respect to the database - it issues no SQL. `existing` is whatever
    a previous scan left behind for this finding, looked up once for the whole
    scan by `_existing_finding_lifecycle`.

    It DOES still mutate `finding` with the resolved status/owner/SLA, because
    `_write_finding_index` indexes the enriched dict and the list and the drawer
    have to agree about lifecycle after a re-scan.
    """

    from backend.finding_contracts import get_finding_display_name

    path = str(file_obj.get("path") or file_obj.get("name") or "")
    rule = str(finding.get("type") or finding.get("rule_id") or "sensitive_data")
    risk = finding.get("risk")
    severity = str(
        (risk.get("level") if isinstance(risk, dict) else risk)
        or finding.get("severity") or finding.get("impact_severity") or "LOW"
    ).upper()
    risk_score = int(
        finding.get("risk_score") or finding.get("operational_priority_score")
        or (risk.get("score") if isinstance(risk, dict) else 0) or 0
    )
    frameworks = _operational_frameworks(finding)
    display_name = str(finding.get("display_name") or get_finding_display_name(finding) or rule)
    data_type = str(
        finding.get("data_type") or finding.get("data_element") or finding.get("personal_data_type")
        or finding.get("finding_category") or finding.get("data_category") or finding.get("category")
        or finding.get("entity_type") or "Unclassified"
    )
    source = str(file_obj.get("source") or "")
    affected_asset = str(
        finding.get("asset_name") or finding.get("resource_name") or file_obj.get("host_id")
        or file_obj.get("server") or file_obj.get("share") or source or asset_id
    )
    owner = str(
        finding.get("owner") or finding.get("assignee") or finding.get("data_owner")
        or file_obj.get("owner") or ""
    )
    occurrence_count = int(
        finding.get("occurrence_count") or finding.get("count")
        or len(finding.get("occurrences") or []) or 1
    )
    status = _finding_status(finding)
    sla_due = str(finding.get("sla_due") or finding.get("due_date") or "")
    if is_current and existing is not None:
        # A scan observes content, not triage. Everything a human decided about
        # this finding - its state, who owns it, when it is due - stays on the
        # row and is re-asserted here unchanged.
        #
        # This used to test whether the incoming finding carried a value of its
        # own, which sounds right and never fired: every finding reaching a scan
        # write has been through `apply_canonical_finding_model`, which stamps
        # "OPEN", the file's owner, and a due date computed from THIS scan's
        # clock onto every one of them. So the test always saw a value, always
        # took it, and every scheduled scan silently reset the whole estate -
        # a confirmed finding back to open, an assignee back to whoever owns the
        # file, and a due date pushed far enough forward that nothing could ever
        # be overdue.
        #
        # A lifecycle change does not come through here. `update_finding_lifecycle`
        # re-saves the same scan_id, which makes `refresh_current` False, which
        # makes `is_current` False - and the analyst's values below win. That is
        # what this branch being conditional has always been for.
        status = str(existing["status"] or status)
        owner = str(existing["owner"] or owner)
        # The one thing a scan may still say about a deadline: a finding that got
        # worse restarts on the shorter clock its new severity carries. Every
        # other scan leaves the date alone, so the clock actually runs out.
        escalated = severity_rank(severity) > int(existing["severity_rank"] or 0)
        if not escalated:
            sla_due = str(existing["sla_due"] or sla_due)
    # The same enriched object is indexed into the lazy detail surface below;
    # keep list and drawer lifecycle values identical after a re-scan.
    finding["status"] = status
    if owner:
        finding["owner"] = owner
    if sla_due:
        finding["sla_due"] = sla_due
    first_seen = str(finding.get("first_seen") or "")
    last_seen = str(finding.get("last_seen") or "")
    file_name = str(file_obj.get("name") or path.replace("\\", "/").rsplit("/", 1)[-1])
    exposure = str(finding.get("exposure") or finding.get("exposure_state") or "")
    search_text = " ".join(
        (finding_id, display_name, rule, path, file_name, affected_asset, owner, data_type, exposure, " ".join(frameworks))
    ).lower()
    return (
        tenant_id, finding_id, asset_id, rule, severity,
        str(finding.get("category") or finding.get("finding_category") or ""), frameworks[0], status,
        first_seen, last_seen, scan_id, seq, 1 if is_current else 0, risk_score, owner,
        sla_due, display_name, data_type,
        exposure, affected_asset, file_name, path, source, occurrence_count,
        int(finding.get("confidence") or 0), json.dumps(frameworks, ensure_ascii=False, separators=(",", ":")),
        search_text, severity_rank(severity),
    )


def _upsert_operational_finding(
    conn, tenant_id: str, scan_id: str, seq: int, asset_id: str,
    file_obj: dict, finding: dict, *, is_current: bool,
) -> None:
    """Write one finding row. Kept for single-row callers; the scan path batches."""

    finding_id = _operational_finding_id(tenant_id, asset_id, file_obj, finding)
    existing = _existing_finding_lifecycle(conn, tenant_id, [finding_id]).get(finding_id) if is_current else None
    conn.execute(
        _FINDING_UPSERT_SQL,
        _operational_finding_params(
            tenant_id, scan_id, seq, asset_id, file_obj, finding, finding_id, existing,
            is_current=is_current,
        ),
    )

def _write_normalized_rows(conn, tenant_id: str, report: dict, *, refresh_current: bool = True,
                          partition: dict | None = None, inventory_rows: list | None = None) -> None:
    from backend.domain import asset_identity, iter_normalized_chunks, scan_run_from_report

    run = scan_run_from_report(tenant_id, report)
    scan_id = run.id
    if not scan_id:
        return
    # Demo-dataset scans stay per-scan records (report blob, scan_runs,
    # occurrences, finding index) but never enter the durable estate: the
    # dashboard and Data Inventory describe the customer's real data, and
    # synthetic sample files inflating those numbers is a defect, not a demo.
    if partition is not None and "write_estate" in partition:
        # A partition cannot see the rest of the scan, and a majority inside one
        # partition can disagree with the majority across all of them - so whether
        # this is a demo scan is decided once, for the whole scan, and passed in.
        write_estate = bool(partition["write_estate"])
    else:
        write_estate = _demo_assets_allowed_in_inventory() or not is_demo_sample_report(report)
    # Refresh this scan's occurrences so a re-save (e.g. a lifecycle update) is
    # idempotent rather than duplicating rows. A partition refreshes only its own
    # occurrences, further down: deleting every occurrence of the scan here would
    # erase the partitions that finished before it.
    if partition is None:
        conn.execute("DELETE FROM finding_occurrences WHERE tenant_id = ? AND scan_id = ?", (tenant_id, scan_id))

    # DATA-002: a scan run is immutable and append-only. The first write creates
    # it; later re-saves (finding-lifecycle updates that refresh the blob) must
    # NOT overwrite it. INSERT OR IGNORE keeps the original run record; mutable
    # finding lifecycle lives in the `findings` aggregate below, not here.
    # A partition does not know the scan's summary yet, and this row can never be
    # corrected once written - so a partitioned scan writes it once, at finalize.
    if partition is None:
        conn.execute(
            """
            INSERT OR IGNORE INTO scan_runs
                (tenant_id, id, source, mode, policy_version, started_at, ended_at, status, total_files, summary_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (tenant_id, run.id, run.source, run.mode, run.policy_version, run.started_at, run.ended_at, run.status, run.total_files, json.dumps(run.summary, ensure_ascii=False)),
        )
    observed_at = str(report.get("completed_at") or report.get("timestamp") or run.ended_at or "")
    scan_label = str(report.get("scan_label") or "").strip()[:80]
    diagnostics = report.get("scan_diagnostics") if isinstance(report.get("scan_diagnostics"), dict) else {}
    incremental = diagnostics.get("incremental") if isinstance(diagnostics, dict) else None
    complete_scope = not isinstance(incremental, dict) or bool(incremental.get("complete"))
    # A named, complete scan prunes the assets it did not see - after its own rows
    # are written, below. A partition never prunes: it has not seen the rest of
    # the scan, so every asset it did not write would look like one that
    # disappeared. Finalize runs the same prune once every partition is done.
    # One walk of the report, in batches. `seq` and the path->id map that the
    # finding rows need are the only things that cross a batch boundary, and
    # both are bounded by what has actually been seen rather than by the estate.
    seq_offset = int(partition.get("seq_offset") or 0) if partition is not None else 0
    seq_span = int(partition.get("seq_span") or PARTITION_SEQ_SPAN) if partition is not None else 0
    seq = seq_offset
    source = str(report.get("source") or "local")
    cleared_occurrences: set[str] = set()
    for records, piece in iter_normalized_chunks(tenant_id, report):
        estate_rows = bool(write_estate and refresh_current)
        if inventory_rows is not None and estate_rows:
            # P2: the rows scan_reports.rows_json holds are these assets. Collected
            # here, the save no longer normalises the whole report a second time to
            # build them (15% of a save, and a second dump of every record).
            inventory_rows.extend(_inventory_row(asset, scan_id) for asset in piece.assets)
        _executemany(
            conn,
            "INSERT INTO assets "
            "(tenant_id, id, source, stable_object_id, path, name, extension, share, "
            "risk_level, risk_score, size, owner, modified_at, finding_count, "
            "top_frameworks, is_hidden, is_system, is_protected, search_text, "
            "finding_types, framework_keys, detail_json, scan_label, current_scan_id, observed_at, "
            "reason_count, dlp_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (tenant_id, id) DO UPDATE SET "
            "source = excluded.source, stable_object_id = excluded.stable_object_id, "
            "path = excluded.path, name = excluded.name, extension = excluded.extension, "
            "share = excluded.share, risk_level = excluded.risk_level, risk_score = excluded.risk_score, "
            "size = excluded.size, owner = excluded.owner, modified_at = excluded.modified_at, "
            "finding_count = excluded.finding_count, top_frameworks = excluded.top_frameworks, "
            "is_hidden = excluded.is_hidden, is_system = excluded.is_system, "
            "is_protected = excluded.is_protected, search_text = excluded.search_text, "
            "finding_types = excluded.finding_types, framework_keys = excluded.framework_keys, "
            "detail_json = excluded.detail_json, scan_label = excluded.scan_label, "
            "current_scan_id = excluded.current_scan_id, observed_at = excluded.observed_at, "
        "reason_count = excluded.reason_count, dlp_count = excluded.dlp_count",
            (
                (tenant_id, asset.id, asset.source, asset.stable_object_id, asset.path, asset.name,
                 asset.extension, asset.share, asset.risk_level, asset.risk_score, asset.size,
                 asset.owner, asset.modified_at, asset.finding_count, asset.top_frameworks,
                 asset.is_hidden, asset.is_system, asset.is_protected, asset.search_text,
                 asset.finding_types, asset.framework_keys, pack_json_text(asset.detail_json), asset.scan_label,
                 scan_id, observed_at, asset.reason_count, asset.dlp_count)
                for asset in (piece.assets if estate_rows else [])
            ),
        )
        _executemany(
            conn,
            "INSERT OR REPLACE INTO asset_versions (tenant_id, asset_id, version, size, mtime, content_hash, coverage) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                (tenant_id, version.asset_id, version.version, version.size, version.mtime, version.content_hash, version.coverage)
                for version in (piece.asset_versions if estate_rows else [])
            ),
        )
        # Only this batch's paths. A report that lists the same path twice, with
        # the copies in different batches, still resolves: the projection emits
        # one asset for it, and the identity is recomputed from the record.
        asset_ids_by_path = {asset.path: asset.id for asset in piece.assets}
        if estate_rows:
            _write_asset_access(conn, tenant_id, scan_id, records, asset_ids_by_path)
        if estate_rows:
            # Every finding on the assets this batch touched becomes historical,
            # and the current ones are re-asserted by the upsert below. This was
            # one UPDATE per asset - a million statements on a million-file scan
            # - to express a set operation the database can do in one.
            for id_chunk in _id_chunks(asset_ids_by_path.values()):
                placeholders = ",".join("?" for _ in id_chunk)
                conn.execute(
                    f"UPDATE findings SET is_current = 0 WHERE tenant_id = ? AND asset_id IN ({placeholders})",
                    (tenant_id, *id_chunk),
                )
        if write_estate:
            # Two passes, because the lifecycle state an analyst set on a
            # previous scan has to be read BEFORE the rows are built - and
            # reading it one finding at a time was two million round trips.
            pending: list[tuple] = []
            for file_obj in records:
                path = str(file_obj.get("path") or file_obj.get("name") or "")
                asset_id = asset_ids_by_path.get(path) or asset_identity(
                    tenant_id, source,
                    str(file_obj.get("stable_object_id") or file_obj.get("asset_id") or ""),
                    path,
                )
                for finding in file_obj.get("findings") or []:
                    finding.setdefault("first_seen", str(report.get("timestamp") or ""))
                    finding.setdefault("last_seen", str(report.get("timestamp") or ""))
                    pending.append((
                        seq, asset_id, file_obj, finding,
                        _operational_finding_id(tenant_id, asset_id, file_obj, finding),
                    ))
                    seq += 1
            if partition is not None and seq - seq_offset > seq_span:
                # Past this point the rows would take the next partition's range and
                # scramble the finding order across the scan.
                raise ValueError(f"partition has more than {seq_span} findings")
            existing = (
                _existing_finding_lifecycle(conn, tenant_id, [item[4] for item in pending])
                if refresh_current and pending else {}
            )
            _executemany(
                conn,
                _FINDING_UPSERT_SQL,
                (
                    _operational_finding_params(
                        tenant_id, scan_id, item_seq, item_asset_id, item_file, item_finding,
                        item_id, existing.get(item_id), is_current=refresh_current,
                    )
                    for item_seq, item_asset_id, item_file, item_finding, item_id in pending
                ),
            )
        if partition is not None:
            # Only this partition's occurrences, so running it again replaces them.
            # Each id is cleared once per call: a report can list a file twice, and
            # clearing it again in a later batch would delete what the earlier batch
            # just wrote.
            fresh = [
                finding_id for finding_id in dict.fromkeys(o.finding_id for o in piece.occurrences)
                if finding_id not in cleared_occurrences
            ]
            cleared_occurrences.update(fresh)
            for id_chunk in _id_chunks(fresh):
                placeholders = ",".join("?" for _ in id_chunk)
                conn.execute(
                    f"DELETE FROM finding_occurrences WHERE tenant_id = ? AND scan_id = ? AND finding_id IN ({placeholders})",
                    (tenant_id, scan_id, *id_chunk),
                )
        _executemany(
            conn,
            "INSERT INTO finding_occurrences (tenant_id, finding_id, scan_id, locator, fingerprint, occurrence_count) VALUES (?, ?, ?, ?, ?, ?)",
            (
                (tenant_id, occurrence.finding_id, occurrence.scan_id, occurrence.locator, occurrence.fingerprint, occurrence.occurrence_count)
                for occurrence in piece.occurrences
            ),
        )

    if partition is None:
        if write_estate and refresh_current and scan_label and complete_scope:
            _prune_unseen_assets(conn, tenant_id, scan_label, scan_id)
        _write_finding_index(conn, tenant_id, report)
        _trim_finding_index(conn, tenant_id)
    else:
        # A partition writes its own range of the index and leaves retention to
        # finalize, the only step that knows the scan is finished.
        _write_finding_index(conn, tenant_id, report, seq_offset=seq_offset, seq_span=seq_span)


def _write_asset_access(conn, tenant_id: str, scan_id: str, records: list, asset_ids_by_path: dict) -> None:
    """D7: this batch's assets' access rows, replaced - one row per principal with read
    or write, from the ACL the collector read (allow entries less the same principal's
    denies)."""
    from permissions.acl_analyzer import effective_access

    rows: dict[tuple, tuple] = {}
    for file_obj in records:
        asset_id = asset_ids_by_path.get(str(file_obj.get("path") or file_obj.get("name") or ""))
        if not asset_id:
            continue
        for access in effective_access(file_obj.get("acl") or {}):
            rows[(asset_id, access.key)] = (
                tenant_id, asset_id, access.key, access.principal[:256], access.sid[:184], int(access.read),
                int(access.write), int(access.broad), int(access.privileged), int(access.service), scan_id)
    for id_chunk in _id_chunks(asset_ids_by_path.values()):
        placeholders = ",".join("?" for _ in id_chunk)
        conn.execute(f"DELETE FROM asset_access WHERE tenant_id = ? AND asset_id IN ({placeholders})",
                     (tenant_id, *id_chunk))
    _executemany(
        conn,
        "INSERT INTO asset_access (tenant_id, asset_id, principal_key, principal, sid, can_read, can_write, "
        "broad, privileged, service, scan_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows.values(),
    )


def _prune_unseen_assets(conn, tenant_id: str, scan_label: str, scan_id: str) -> None:
    """Take the assets a named, complete scan did not see out of the current estate.

    A named scan is an authoritative inventory scope; an unnamed one is not pruned,
    because source alone is not a reliable scope identity. The unseen assets'
    findings become historical, and the assets and their versions leave.

    **This runs after the scan's own rows are written** (B2.2b, 2026-09-14). It used
    to run before them, and ``current_scan_id <> scan_id`` then also matched every
    asset the scan was about to see again - so a complete re-scan deleted and
    re-inserted those rows and threw away their version history. That was never
    the intent, and a partitioned scan, which can only prune once every partition
    is done, could not reproduce it. Run afterwards, the same condition matches
    exactly the assets this scan did not see, for a single scan and a partitioned
    one alike.
    """
    stale_sql = "SELECT id FROM assets WHERE tenant_id = ? AND scan_label = ? AND current_scan_id <> ?"
    stale_params = (tenant_id, scan_label, scan_id)
    conn.execute(
        f"UPDATE findings SET is_current = 0 WHERE tenant_id = ? AND asset_id IN ({stale_sql})",
        (tenant_id, *stale_params),
    )
    conn.execute(
        f"DELETE FROM asset_versions WHERE tenant_id = ? AND asset_id IN ({stale_sql})",
        (tenant_id, *stale_params),
    )
    conn.execute(
        f"DELETE FROM asset_access WHERE tenant_id = ? AND asset_id IN ({stale_sql})",
        (tenant_id, *stale_params),
    )
    conn.execute(
        "DELETE FROM assets WHERE tenant_id = ? AND scan_label = ? AND current_scan_id <> ?",
        stale_params,
    )


SEVERITY_RANKS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def severity_rank(severity) -> int:
    return SEVERITY_RANKS.get(str(severity or "").upper(), 0)


def _finding_index_retention() -> int:
    """How many scans keep their full per-finding response.

    `finding_index` is an immutable history projection: the interface reads one
    row of it at a time, through the finding-detail endpoint, and never in
    bulk. Every scan writes one row per finding, so on this estate it reached
    188MB - a third of the database - for 25 scans. Older scans keep their
    status row, which is what the history views actually read; only the
    response body is dropped.

    0 disables the window and keeps everything.
    """
    try:
        return max(0, min(int(os.getenv("DSPM_FINDING_INDEX_KEEP_SCANS", "5")), 1000))
    except ValueError:
        return 5


def _trim_finding_index(conn, tenant_id: str) -> int:
    """Blank the response body of scans outside the retention window."""
    keep = _finding_index_retention()
    if not keep:
        return 0
    recent = [
        str(row["scan_id"])
        for row in conn.execute(
            "SELECT DISTINCT scan_id FROM finding_index WHERE tenant_id = ? "
            "ORDER BY scan_id DESC LIMIT ?",
            (tenant_id, keep),
        ).fetchall()
    ]
    if not recent:
        return 0
    placeholders = ",".join("?" for _ in recent)
    result = conn.execute(
        f"UPDATE finding_index SET response_json = '' "
        f"WHERE tenant_id = ? AND response_json <> '' AND scan_id NOT IN ({placeholders})",
        (tenant_id, *recent),
    )
    return int(result.rowcount or 0)


def _write_finding_index(conn, tenant_id: str, report: dict, *,
                         seq_offset: int | None = None, seq_span: int | None = None) -> None:
    """Materialize the exact per-finding list_findings response (read-switch).

    Stores what list_findings would produce for each finding of this scan, so
    the read path can serve findings without loading full report blobs. Refreshed
    per scan so a re-save is idempotent.
    """
    scan_id = str(report.get("scan_id") or "")
    if not scan_id:
        return
    span = int(seq_span or PARTITION_SEQ_SPAN)
    if seq_offset is None:
        conn.execute("DELETE FROM finding_index WHERE tenant_id = ? AND scan_id = ?", (tenant_id, scan_id))
    else:
        conn.execute(
            "DELETE FROM finding_index WHERE tenant_id = ? AND scan_id = ? AND seq >= ? AND seq < ?",
            (tenant_id, scan_id, int(seq_offset), int(seq_offset) + span),
        )

    def _index_rows():
        # `seq` counts only the findings actually indexed, exactly as the loop
        # this replaced did - it is incremented after a row is emitted, not for
        # every finding in the report.
        seq = int(seq_offset or 0)
        for row in _iter_report_findings(report):
            finding = row["finding"]
            finding_id = str(finding.get("finding_id") or "")
            if not finding_id:
                continue
            if seq_offset is not None and seq - int(seq_offset) >= span:
                raise ValueError(f"partition has more than {span} indexed findings")
            yield (tenant_id, scan_id, seq, finding_id, _finding_status(finding),
                   pack_json_text(json.dumps(_finding_response(row), ensure_ascii=False)), FINDING_INDEX_VERSION)
            seq += 1

    _executemany(
        conn,
        "INSERT INTO finding_index (tenant_id, scan_id, seq, finding_id, status, response_json, index_version) VALUES (?, ?, ?, ?, ?, ?, ?)",
        _index_rows(),
    )


def backfill_normalized_scans(tenant_id: str | None = None) -> dict:
    """Populate the normalized tables from existing report_json rows (DATA-001).

    Idempotent and safe to re-run: reads still use the blob, so this only fills
    the mirror for historical scans. Each scan is savepoint-isolated, so a single
    bad/legacy report is skipped rather than aborting the whole backfill. Pass a
    tenant_id to bound the work; omit it for a full (maintenance-window) backfill.

    Returns ``{"scanned": int, "mirrored": int, "failed": int}``.
    """
    scanned = mirrored = failed = 0
    with _lock:
        with _connect() as conn:
            # Assets are an upserted latest-state projection. Replay oldest to
            # newest so a historical backfill cannot leave an older copy of the
            # same source-qualified asset as the visible inventory row.
            query = "SELECT tenant_id, scan_id FROM scan_reports"
            params: tuple = ()
            if tenant_id:
                query += " WHERE tenant_id = ?"
                params = (tenant_id,)
            query += " ORDER BY created_at ASC, scan_id ASC"
            keys = conn.execute(query, params).fetchall()
            for key in keys:
                scanned += 1
                blob = conn.execute(
                    "SELECT report_json, report_ref FROM scan_reports WHERE tenant_id = ? AND scan_id = ?",
                    (key["tenant_id"], key["scan_id"]),
                ).fetchone()
                if blob is None:
                    failed += 1
                    continue
                try:
                    # The body may be inline or in the artifact tier; either way
                    # the backfill reads it through the same resolver.
                    report = _report_body(key["tenant_id"], blob)
                except Exception:
                    failed += 1
                    continue
                if not report:
                    failed += 1
                    continue
                if isinstance(report, dict):
                    report.setdefault("scan_id", key["scan_id"])
                try:
                    conn.execute("SAVEPOINT dspm_backfill")
                    _write_normalized_rows(conn, key["tenant_id"], report)
                    conn.execute("RELEASE SAVEPOINT dspm_backfill")
                    mirrored += 1
                except Exception as exc:  # pragma: no cover - defensive per-row guard
                    try:
                        conn.execute("ROLLBACK TO SAVEPOINT dspm_backfill")
                        conn.execute("RELEASE SAVEPOINT dspm_backfill")
                    except Exception:
                        pass
                    failed += 1
                    logger.warning("Backfill skipped scan %s: %s", key["scan_id"], exc)
    _invalidate_inventory_query_cache(tenant_id)
    return {"scanned": scanned, "mirrored": mirrored, "failed": failed}


def record_job(job: dict) -> None:
    """Best-effort persistence of a scan job's lifecycle state (ARCH-003).

    The large/transient result payload is deliberately NOT stored - the scan
    report is persisted separately via save_scan_history. A DB error here must
    never break the running job, so callers wrap this defensively.
    """
    now = datetime.now(timezone.utc).isoformat()
    params = (
        str(job.get("id")),
        str(job.get("tenant_id")),
        str(job.get("status") or "queued"),
        int(job.get("progress") or 0),
        job.get("message"),
        str(job.get("created_at")),
        job.get("finished_at"),
        job.get("error"),
        now,
    )
    # F6: the terminal state write is a job's last chance to record its outcome;
    # if it is lost the row is stuck "running" until a restart-recovery sweep.
    # SQLite's busy-timeout already absorbs brief contention, but add a small
    # bounded retry so a lock that outlives it still lands the row instead of
    # silently dropping the transition. Non-lock errors propagate immediately.
    for attempt in range(3):
        try:
            # C10: the job's own tenant - unscoped, the policies would refuse the write.
            with _lock, db.tenant_scope(str(job.get("tenant_id"))):
                with _connect() as conn:
                    # An explicit upsert rather than INSERT OR REPLACE. On
                    # SQLite a REPLACE deletes the row and inserts a new one, so
                    # every column this statement does not name - the scan
                    # binding a resumable job carries - would reset to its
                    # default on each progress write. PostgreSQL translates the
                    # same statement into an update and keeps them, so the loss
                    # would have been SQLite-only and invisible in production.
                    conn.execute(
                        """
                        INSERT INTO scan_jobs
                            (id, tenant_id, status, progress, message, created_at, finished_at, error, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT (id) DO UPDATE SET
                            tenant_id = excluded.tenant_id, status = excluded.status,
                            progress = excluded.progress, message = excluded.message,
                            created_at = excluded.created_at, finished_at = excluded.finished_at,
                            error = excluded.error, updated_at = excluded.updated_at
                        """,
                        params,
                    )
            return
        except db.OperationalError as exc:
            # SQLite's "database is locked" is the transient this retry targets;
            # on Postgres, contention surfaces as different errors that fall
            # through to `raise` (server-side locking/queueing handles it there).
            if "locked" not in str(exc).lower() or attempt == 2:
                raise
            time.sleep(0.05 * (attempt + 1))


# How long a progress write may wait for SQLite's write lock. Progress is written from
# the thread running the scan, and the next write a second later carries it anyway.
_PROGRESS_BUSY_TIMEOUT_MS = 250


def record_job_progress(tenant_id: str, job_id: str, progress: int, message: str | None) -> None:
    """Move a running job's progress and message, and nothing else (B3.1).

    Status is `record_job`'s alone: a progress write snapshotted before the job finished
    and landing after it must not put a completed job back to "running", so this never
    names the status, and it touches no job that has already reached a terminal state.
    """
    with _connect() as conn:
        if db.is_sqlite():
            conn.execute(f"PRAGMA busy_timeout = {_PROGRESS_BUSY_TIMEOUT_MS}")
        conn.execute(
            "UPDATE scan_jobs SET progress = ?, message = ?, updated_at = ? "
            "WHERE id = ? AND tenant_id = ? AND status NOT IN ('completed', 'failed', 'cancelled')",
            (int(progress or 0), message, datetime.now(timezone.utc).isoformat(), str(job_id), str(tenant_id)),
        )


def read_job(tenant_id: str, job_id: str) -> dict | None:
    """Persisted job record, shaped like ScanJob.to_dict() (no result payload)."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, tenant_id, status, progress, message, created_at, finished_at, error FROM scan_jobs WHERE id = ? AND tenant_id = ?",
            (job_id, tenant_id),
        ).fetchone()
    if not row:
        return None

    def _ts(value: str | None) -> float:
        if not value:
            return 0.0
        try:
            return datetime.fromisoformat(value).timestamp()
        except ValueError:
            return 0.0

    created, finished = row["created_at"], row["finished_at"]
    end = _ts(finished) if finished else datetime.now(timezone.utc).timestamp()
    return {
        "id": row["id"],
        "tenant_id": row["tenant_id"],
        "status": row["status"],
        "progress": row["progress"],
        "message": row["message"],
        "created_at": created,
        "finished_at": finished,
        "elapsed_seconds": round(max(0.0, end - _ts(created)), 3),
        "result": None,
        "error": row["error"],
    }


INTERRUPTED_JOB_ERROR = "Scan was interrupted by a backend restart. Re-run the scan."
RESUMING_JOB_ERROR = (
    "Scan was interrupted by a backend restart. It continues automatically from its last finished partition."
)


def recover_interrupted_jobs(*, resuming: bool = True) -> int:
    """Mark jobs left queued/running by a prior process as failed (ARCH-003).

    Called at startup: the in-memory executor cannot survive a restart, so any
    still-open job is orphaned. Returns the number recovered. The job of a
    partitioned scan that can be resumed says so instead of asking for a re-run:
    the resume sweep continues that scan under the same job id (B2.4). With resuming
    turned off, every job asks for a re-run, since nothing will continue it.
    """
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            cursor = conn.execute(
                """
                UPDATE scan_jobs
                SET status = 'failed',
                    message = 'Interrupted',
                    error = CASE WHEN EXISTS (
                        SELECT 1 FROM partitioned_scans p
                        WHERE p.tenant_id = scan_jobs.tenant_id AND p.job_id = scan_jobs.id
                          AND p.status IN ('running', 'finalizing') AND p.resumable = 1
                    ) THEN ? ELSE ? END,
                    finished_at = COALESCE(finished_at, ?),
                    updated_at = ?
                WHERE status IN ('queued', 'running')
                """,
                (RESUMING_JOB_ERROR if resuming else INTERRUPTED_JOB_ERROR, INTERRUPTED_JOB_ERROR, now, now),
            )
            return cursor.rowcount


# --- B5: retention, and the housekeeping that runs it -------------------------

# What grows on its own and is not evidence anybody keeps: the two append-only
# event tables. Scan reports, findings, assets and the current audit window are
# never touched here - shortening the audit window is an operator decision, made
# with DSPM_RETAIN_AUDIT_DAYS and never by default.
RETENTION_POLICIES = (
    # (table, timestamp column, environment variable, default days)
    ("alert_events", "created_at", "DSPM_RETAIN_ALERT_DAYS", 365),
    ("audit_events", "timestamp", "DSPM_RETAIN_AUDIT_DAYS", 730),
)


def _prune_audit_chains(cutoff: str, held: list[str], *, apply: bool) -> int:
    """Retention for the audit trail without breaking its chains (C4).

    Only a PREFIX of a tenant's chain is removed - everything up to the newest row older
    than the cutoff - and the head keeps that row's seq and hash, so what remains still
    starts from a known point and verifies. Deleting by timestamp alone could take a
    row out of the middle if clocks ever stepped back, which would read as tampering.
    """
    removed = 0
    with _lock:
        with _connect() as conn:
            # Rows in no chain (written around audit(), which nothing should do) have no
            # chain to keep whole; they age out by timestamp as every row used to.
            held_clause = f" AND tenant_id NOT IN ({', '.join('?' for _ in held)})" if held else ""
            unchained = int(conn.execute(
                f"SELECT COUNT(*) AS n FROM audit_events WHERE seq IS NULL AND timestamp < ?{held_clause}",
                (cutoff, *held)).fetchone()["n"] or 0)
            removed += unchained
            if apply and unchained:
                conn.execute(f"DELETE FROM audit_events WHERE seq IS NULL AND timestamp < ?{held_clause}", (cutoff, *held))
            rows = conn.execute(
                "SELECT tenant_id, MAX(seq) AS through FROM audit_events WHERE timestamp < ? AND seq IS NOT NULL "
                "GROUP BY tenant_id", (cutoff,)).fetchall()
            for row in rows:
                tenant_id, through = str(row["tenant_id"]), int(row["through"] or 0)
                if tenant_id in held or not through:
                    continue
                count = int(conn.execute("SELECT COUNT(*) AS n FROM audit_events WHERE tenant_id = ? AND seq <= ?",
                                         (tenant_id, through)).fetchone()["n"] or 0)
                removed += count
                if not apply:
                    continue
                last = conn.execute("SELECT row_hash FROM audit_events WHERE tenant_id = ? AND seq = ?",
                                    (tenant_id, through)).fetchone()
                conn.execute("DELETE FROM audit_events WHERE tenant_id = ? AND seq <= ?", (tenant_id, through))
                conn.execute(
                    "UPDATE audit_chain_heads SET pruned_through_seq = ?, pruned_through_hash = ? WHERE tenant_id = ?",
                    (through, str(last["row_hash"]) if last else "", tenant_id),
                )
    return removed


def prune_event_tables(*, now: datetime | None = None, apply: bool = False,
                       overrides: dict | None = None) -> list[dict]:
    """Count - and with ``apply``, delete - event rows past their retention window.

    One definition, used by ``scripts/db_retention.py`` and by the housekeeping sweep
    that runs unattended (B5), so the two can never drift apart. A tenant under legal
    hold keeps every row: the hold suspends scheduled deletion for that tenant, and the
    rest of the run goes ahead rather than being refused.
    """
    moment = now or datetime.now(timezone.utc)
    held = sorted(tenants_under_legal_hold())
    results: list[dict] = []
    for table, column, env_var, default_days in RETENTION_POLICIES:
        wanted = (overrides or {}).get(table)
        try:
            days = int(wanted if wanted else os.getenv(env_var, str(default_days)))
        except (TypeError, ValueError):
            days = default_days
        days = max(1, days)
        cutoff = (moment - timedelta(days=days)).isoformat()
        if table == "audit_events":
            stale = _prune_audit_chains(cutoff, held, apply=apply)
            results.append({"data_class": table, "retention_days": days, "eligible_rows": stale,
                            "removed_rows": stale if apply else 0, "held_tenants": len(held)})
            continue
        clause = f"{column} < ?"
        params: tuple = (cutoff,)
        if held:
            clause += f" AND tenant_id NOT IN ({', '.join('?' for _ in held)})"
            params = (cutoff, *held)
        with _lock:
            with _connect() as conn:
                stale = int(conn.execute(
                    f"SELECT COUNT(*) AS n FROM {table} WHERE {clause}", params,
                ).fetchone()["n"] or 0)
                if apply and stale:
                    conn.execute(f"DELETE FROM {table} WHERE {clause}", params)
        results.append({
            "data_class": table,
            "retention_days": days,
            "eligible_rows": stale,
            "removed_rows": stale if apply else 0,
            "held_tenants": len(held),
        })
    return results


def claim_housekeeping_run(name: str, *, interval_seconds: int, now: datetime | None = None) -> bool:
    """Take the next run of an unattended job; returns whether this caller took it.

    A compare-and-set on when it last ran, kept in ``app_settings``, so several backends
    sharing one database run it once between them - and a backend that restarts every
    hour does not run a daily job every hour.
    """
    key = f"housekeeping.{name}.last_run"
    moment = now or datetime.now(timezone.utc)
    stamp = moment.isoformat()
    cutoff = (moment - timedelta(seconds=max(1, int(interval_seconds)))).isoformat()
    with _lock:
        with _connect() as conn:
            taken = int(conn.execute(
                "UPDATE app_settings SET value = ?, updated_at = ? WHERE key = ? AND value < ?",
                (stamp, stamp, key, cutoff),
            ).rowcount or 0)
            if taken == 1:
                return True
            started = int(conn.execute(
                "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO NOTHING",
                (key, stamp, stamp),
            ).rowcount or 0)
    return started == 1


# --- B3: scans that run unattended -------------------------------------------

# A schedule is a scan, not a cron tick: anything under five minutes is a mistake
# nobody meant to make, and the floor says so rather than letting scans pile up.
SCHEDULE_MIN_INTERVAL_SECONDS = 300
SCHEDULE_MAX_INTERVAL_SECONDS = 366 * 24 * 3600


# B3.1: the console's derived state, shared between backends (revision 0017). The policy -
# what is cached, for how long, and when it is on - lives in backend/live_cache.py; these
# are its three statements.
@_tenant_scoped
def derived_lookup(tenant_id: str, cache_key: str) -> tuple[str | None, int]:
    """A cached answer, if one is current, and the tenant's generation either way.

    One indexed read: the tenant row for its generation, and the cache row for the
    answer. The answer is returned only if it was computed at that generation and has
    not expired - a write since then, or its TTL, makes it absent. The generation comes
    back regardless, because whoever computes a fresh answer must store it under the
    generation it read BEFORE computing: a write that lands meanwhile then leaves that
    answer stale by generation, and it is never served.
    """
    now = _lease_time(datetime.now(timezone.utc))
    with _connect() as conn:
        row = conn.execute(
            "SELECT t.estate_generation AS generation, c.generation AS cached_generation, "
            "c.value_json AS value_json, c.expires_at AS expires_at "
            "FROM tenants AS t LEFT JOIN derived_cache AS c "
            "ON c.tenant_id = t.tenant_id AND c.cache_key = ? "
            "WHERE t.tenant_id = ?",
            (cache_key, tenant_id),
        ).fetchone()
    if row is None:
        return None, -1
    generation = int(row["generation"] or 0)
    if (
        row["value_json"] is not None
        and int(row["cached_generation"] or 0) == generation
        and str(row["expires_at"] or "") > now
    ):
        return str(row["value_json"]), generation
    return None, generation


@_tenant_scoped
def derived_store(tenant_id: str, cache_key: str, generation: int, value_json: str, ttl_seconds: int) -> None:
    """Keep an answer for the generation it was computed at.

    An answer computed at an older generation never replaces one computed at a newer
    one - two backends that raced across a write leave the newer answer standing.

    It takes no store lock: readers call this, and a reader may be running under a caller
    that already holds it.

    The tenant's expired answers go in the same transaction. Keys are not a closed set -
    the inventory's facets are asked for by scan name, and any viewer can ask for any
    name - so without it the table would keep one row for every name ever asked for.
    With it, a tenant holds at most what was asked for within one TTL.
    """
    if generation < 0:
        return
    now = datetime.now(timezone.utc)
    expires = _lease_time(now + timedelta(seconds=max(1, int(ttl_seconds))))
    with _connect() as conn:
        conn.execute(
            "INSERT INTO derived_cache (tenant_id, cache_key, generation, value_json, expires_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (tenant_id, cache_key) DO UPDATE SET "
            "generation = excluded.generation, value_json = excluded.value_json, "
            "expires_at = excluded.expires_at, updated_at = excluded.updated_at "
            "WHERE excluded.generation >= derived_cache.generation",
            (tenant_id, cache_key, int(generation), value_json, expires, now.isoformat()),
        )
        conn.execute(
            "DELETE FROM derived_cache WHERE tenant_id = ? AND expires_at <= ?",
            (tenant_id, _lease_time(now)),
        )


def bump_estate_generation(tenant_id: str | None = None) -> None:
    """The estate changed: every cached answer about it stops being served.

    Its own short transaction, after the write that changed the estate has committed.
    Inside the write it would hold the tenant row for the length of it, and parallel
    partition writers would queue behind one another on that row. The cost of running
    after the commit is a moment in which a reader sees the new estate and caches it
    under the old generation - an answer that is then never served, not a wrong one.
    """
    with _connect() as conn:
        if tenant_id is None:
            conn.execute("UPDATE tenants SET estate_generation = estate_generation + 1")
        else:
            conn.execute(
                "UPDATE tenants SET estate_generation = estate_generation + 1 WHERE tenant_id = ?",
                (tenant_id,),
            )


_SUPPRESSION_COLUMNS = (
    "tenant_id, rule_id, finding_type, source, path_pattern, fingerprint, reason, active, "
    "expires_at, source_finding_id, source_scan_id, created_by, created_at, updated_at"
)


def _suppression_row(row) -> dict:
    return {
        "tenant_id": str(row["tenant_id"]),
        "rule_id": str(row["rule_id"]),
        "finding_type": str(row["finding_type"] or ""),
        "source": str(row["source"] or ""),
        "path_pattern": str(row["path_pattern"] or ""),
        "fingerprint": str(row["fingerprint"] or ""),
        "reason": str(row["reason"] or ""),
        "active": bool(row["active"]),
        "expires_at": str(row["expires_at"] or ""),
        "source_finding_id": str(row["source_finding_id"] or ""),
        "source_scan_id": str(row["source_scan_id"] or ""),
        "created_by": str(row["created_by"] or ""),
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
    }


def _suppression_expiry(value) -> str:
    """An expiry as a UTC timestamp, or empty for a rule that does not expire."""
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Suppression expiry must be an ISO timestamp") from exc
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat()


@_tenant_scoped
def create_suppression_rule(
    tenant_id: str,
    *,
    finding_type: str = "",
    source: str = "",
    path_pattern: str = "",
    fingerprint: str = "",
    reason: str = "",
    created_by: str = "",
    expires_at: str = "",
    source_finding_id: str = "",
    source_scan_id: str = "",
) -> dict:
    """Store what the next scan must not report again (B6).

    Refused outright: a rule that names nothing, which would suppress the estate. A
    rule identical to one already active is not stored twice - the analyst who
    dismisses the same finding from two places gets the same rule back.
    """
    finding_type = str(finding_type or "").strip().lower()[:80]
    source = str(source or "").strip().lower()[:40]
    path_pattern = str(path_pattern or "").strip()[:1024]
    fingerprint = str(fingerprint or "").strip()[:128]
    reason = str(reason or "").strip()[:500]
    if not (finding_type or path_pattern or fingerprint):
        raise ValueError("A suppression rule must name a finding type, a path or a fingerprint")
    if not reason:
        raise ValueError("A suppression rule needs a reason")
    expiry = _suppression_expiry(expires_at)
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            existing = conn.execute(
                f"SELECT {_SUPPRESSION_COLUMNS} FROM suppression_rules "
                "WHERE tenant_id = ? AND active = 1 AND finding_type = ? AND source = ? "
                "AND path_pattern = ? AND fingerprint = ?",
                (tenant_id, finding_type, source, path_pattern, fingerprint),
            ).fetchone()
            if existing is not None:
                return _suppression_row(existing)
            total = conn.execute(
                "SELECT COUNT(*) AS n FROM suppression_rules WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
            if int((total["n"] if total else 0) or 0) >= MAX_SUPPRESSION_RULES:
                raise ValueError(f"A tenant may hold at most {MAX_SUPPRESSION_RULES} suppression rules")
            rule_id = f"sup_{secrets.token_urlsafe(9)}"
            conn.execute(
                "INSERT INTO suppression_rules (tenant_id, rule_id, finding_type, source, path_pattern, "
                "fingerprint, reason, active, expires_at, source_finding_id, source_scan_id, created_by, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)",
                (
                    tenant_id, rule_id, finding_type, source, path_pattern, fingerprint, reason,
                    expiry, str(source_finding_id or "")[:120], str(source_scan_id or "")[:120],
                    str(created_by or "")[:160], now, now,
                ),
            )
            row = conn.execute(
                f"SELECT {_SUPPRESSION_COLUMNS} FROM suppression_rules WHERE tenant_id = ? AND rule_id = ?",
                (tenant_id, rule_id),
            ).fetchone()
    return _suppression_row(row)


@_tenant_scoped
def list_suppression_rules(tenant_id: str, *, active_only: bool = False) -> list[dict]:
    clause = " AND active = 1" if active_only else ""
    with _connect() as conn:
        rows = conn.execute(
            f"SELECT {_SUPPRESSION_COLUMNS} FROM suppression_rules WHERE tenant_id = ?{clause} "
            "ORDER BY created_at DESC, rule_id",
            (tenant_id,),
        ).fetchall()
    return [_suppression_row(row) for row in rows]


@_tenant_scoped
def get_suppression_rule(tenant_id: str, rule_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            f"SELECT {_SUPPRESSION_COLUMNS} FROM suppression_rules WHERE tenant_id = ? AND rule_id = ?",
            (tenant_id, rule_id),
        ).fetchone()
    return _suppression_row(row) if row is not None else None


@_tenant_scoped
def update_suppression_rule(tenant_id: str, rule_id: str, update: dict) -> dict | None:
    """Change what a rule says about itself - never what it matches.

    A rule that matched something else would be a different decision wearing the same
    id, and the scans that ran under the old one would be unexplainable. Turn this one
    off and write the other.
    """
    sets: list[str] = []
    values: list = []
    if "active" in update:
        sets.append("active = ?")
        values.append(1 if bool(update.get("active")) else 0)
    if "reason" in update:
        reason = str(update.get("reason") or "").strip()[:500]
        if not reason:
            raise ValueError("A suppression rule needs a reason")
        sets.append("reason = ?")
        values.append(reason)
    if "expires_at" in update:
        sets.append("expires_at = ?")
        values.append(_suppression_expiry(update.get("expires_at")))
    if not sets:
        return get_suppression_rule(tenant_id, rule_id)
    sets.append("updated_at = ?")
    values.append(datetime.now(timezone.utc).isoformat())
    with _lock:
        with _connect() as conn:
            cursor = conn.execute(
                f"UPDATE suppression_rules SET {', '.join(sets)} WHERE tenant_id = ? AND rule_id = ?",
                (*values, tenant_id, rule_id),
            )
            if not cursor.rowcount:
                return None
            row = conn.execute(
                f"SELECT {_SUPPRESSION_COLUMNS} FROM suppression_rules WHERE tenant_id = ? AND rule_id = ?",
                (tenant_id, rule_id),
            ).fetchone()
    return _suppression_row(row) if row is not None else None


@_tenant_scoped
def delete_suppression_rule(tenant_id: str, rule_id: str) -> bool:
    with _lock:
        with _connect() as conn:
            cursor = conn.execute(
                "DELETE FROM suppression_rules WHERE tenant_id = ? AND rule_id = ?",
                (tenant_id, rule_id),
            )
            return bool(cursor.rowcount)


def suppression_rules_for_scan(tenant_id: str) -> list[dict]:
    """The active rules a scan carries, as plain dicts the engine can compile.

    Read when the scan's configuration is built, never per file. A partitioned scan
    builds one per unit, so a rule written mid-scan reaches the units that start after
    it - never the records already reported.
    """
    try:
        return list_suppression_rules(tenant_id, active_only=True)
    except Exception as exc:
        # A scan is not the place to discover that the rules table is unreadable; it
        # reports everything it finds, which is the safe direction - but silently
        # reporting more than the tenant asked for is worth a line in the log.
        logger.warning("Suppression rules unreadable for tenant %s; scanning without them: %s", tenant_id, exc)
        return []


_SCHEDULE_COLUMNS = (
    "tenant_id, schedule_id, name, request_json, interval_seconds, enabled, next_run_at, "
    "last_run_at, last_scan_id, last_status, last_error, runs, created_by, created_at, updated_at"
)


def _schedule_interval(seconds) -> int:
    try:
        wanted = int(seconds)
    except (TypeError, ValueError):
        wanted = 86_400
    return max(SCHEDULE_MIN_INTERVAL_SECONDS, min(wanted, SCHEDULE_MAX_INTERVAL_SECONDS))


def _schedule_row(row) -> dict:
    try:
        request = json.loads(row["request_json"] or "{}")
    except (TypeError, ValueError):
        request = {}
    return {
        "tenant_id": str(row["tenant_id"]),
        "schedule_id": str(row["schedule_id"]),
        "name": str(row["name"] or ""),
        "request": request if isinstance(request, dict) else {},
        "interval_seconds": int(row["interval_seconds"] or 0),
        "enabled": bool(row["enabled"]),
        "next_run_at": str(row["next_run_at"] or ""),
        "last_run_at": str(row["last_run_at"] or ""),
        "last_scan_id": str(row["last_scan_id"] or ""),
        "last_status": str(row["last_status"] or ""),
        "last_error": str(row["last_error"] or ""),
        "runs": int(row["runs"] or 0),
        "created_by": str(row["created_by"] or ""),
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
    }


@_tenant_scoped
def create_scan_schedule(
    tenant_id: str,
    *,
    name: str,
    request: dict,
    interval_seconds: int = 86_400,
    first_run_at: datetime | None = None,
    enabled: bool = True,
    created_by: str = "",
) -> dict:
    """Record a scan to run unattended; returns the stored schedule (B3).

    The request goes through the same secret filter scan profiles and partitioned scans
    use, so a typed password is never stored - and a schedule that needs one could not
    run unattended anyway. The first run is due immediately unless a time is given.
    """
    interval = _schedule_interval(interval_seconds)
    now = datetime.now(timezone.utc)
    due = (first_run_at or now).astimezone(timezone.utc).isoformat()
    cleaned = _sanitize_scan_profile_config(request if isinstance(request, dict) else {})
    schedule_id = f"sch_{secrets.token_urlsafe(9)}"
    stamp = now.isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO scan_schedules (tenant_id, schedule_id, name, request_json, interval_seconds, "
                "enabled, next_run_at, created_by, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    tenant_id, schedule_id, str(name or "")[:120],
                    json.dumps(cleaned, ensure_ascii=False, separators=(",", ":"), default=str),
                    interval, 1 if enabled else 0, due, str(created_by or "")[:160], stamp, stamp,
                ),
            )
            row = conn.execute(
                f"SELECT {_SCHEDULE_COLUMNS} FROM scan_schedules WHERE tenant_id = ? AND schedule_id = ?",
                (tenant_id, schedule_id),
            ).fetchone()
    return _schedule_row(row)


@_tenant_scoped
def list_scan_schedules(tenant_id: str) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            f"SELECT {_SCHEDULE_COLUMNS} FROM scan_schedules WHERE tenant_id = ? ORDER BY created_at, schedule_id",
            (tenant_id,),
        ).fetchall()
    return [_schedule_row(row) for row in rows]


@_tenant_scoped
def read_scan_schedule(tenant_id: str, schedule_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            f"SELECT {_SCHEDULE_COLUMNS} FROM scan_schedules WHERE tenant_id = ? AND schedule_id = ?",
            (tenant_id, str(schedule_id)),
        ).fetchone()
    return _schedule_row(row) if row is not None else None


@_tenant_scoped
def update_scan_schedule(
    tenant_id: str,
    schedule_id: str,
    *,
    name: str | None = None,
    request: dict | None = None,
    interval_seconds: int | None = None,
    enabled: bool | None = None,
    next_run_at: datetime | None = None,
) -> dict | None:
    """Change a schedule; returns it as stored, or ``None`` if there is no such schedule."""
    sets = ["updated_at = ?"]
    params: list = [datetime.now(timezone.utc).isoformat()]
    if name is not None:
        sets.append("name = ?")
        params.append(str(name)[:120])
    if request is not None:
        sets.append("request_json = ?")
        params.append(json.dumps(
            _sanitize_scan_profile_config(request if isinstance(request, dict) else {}),
            ensure_ascii=False, separators=(",", ":"), default=str,
        ))
    if interval_seconds is not None:
        sets.append("interval_seconds = ?")
        params.append(_schedule_interval(interval_seconds))
    if enabled is not None:
        sets.append("enabled = ?")
        params.append(1 if enabled else 0)
    if next_run_at is not None:
        sets.append("next_run_at = ?")
        params.append(next_run_at.astimezone(timezone.utc).isoformat())
    with _lock:
        with _connect() as conn:
            conn.execute(
                f"UPDATE scan_schedules SET {', '.join(sets)} WHERE tenant_id = ? AND schedule_id = ?",
                (*params, tenant_id, str(schedule_id)),
            )
            row = conn.execute(
                f"SELECT {_SCHEDULE_COLUMNS} FROM scan_schedules WHERE tenant_id = ? AND schedule_id = ?",
                (tenant_id, str(schedule_id)),
            ).fetchone()
    return _schedule_row(row) if row is not None else None


@_tenant_scoped
def delete_scan_schedule(tenant_id: str, schedule_id: str) -> bool:
    with _lock:
        with _connect() as conn:
            return int(conn.execute(
                "DELETE FROM scan_schedules WHERE tenant_id = ? AND schedule_id = ?",
                (tenant_id, str(schedule_id)),
            ).rowcount or 0) == 1


def claim_due_schedules(*, now: datetime | None = None, limit: int = 10) -> list[dict]:
    """Take the schedules that are due, across tenants; returns the ones this caller claimed.

    The claim is a compare-and-set on the due time the row was read with, so two
    backends sharing a database start a schedule exactly once. The next run is counted
    from now, not from the due time that passed: a backend that was off for a week owes
    one scan, not a week of them.
    """
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    stamp = moment.isoformat()
    claimed: list[dict] = []
    with _lock:
        with _connect() as conn:
            rows = conn.execute(
                f"SELECT {_SCHEDULE_COLUMNS} FROM scan_schedules "
                "WHERE enabled = 1 AND next_run_at <= ? ORDER BY next_run_at LIMIT ?",
                (stamp, max(1, int(limit))),
            ).fetchall()
            for row in rows:
                schedule = _schedule_row(row)
                due = (moment + timedelta(seconds=schedule["interval_seconds"])).isoformat()
                taken = conn.execute(
                    "UPDATE scan_schedules SET next_run_at = ?, last_run_at = ?, last_status = 'started', "
                    "last_error = '', runs = runs + 1, updated_at = ? "
                    "WHERE tenant_id = ? AND schedule_id = ? AND enabled = 1 AND next_run_at = ?",
                    (due, stamp, stamp, schedule["tenant_id"], schedule["schedule_id"], schedule["next_run_at"]),
                )
                if int(taken.rowcount or 0) == 1:
                    schedule.update(next_run_at=due, last_run_at=stamp, last_status="started",
                                    last_error="", runs=schedule["runs"] + 1)
                    claimed.append(schedule)
    return claimed


@_tenant_scoped
def record_schedule_run(tenant_id: str, schedule_id: str, *, scan_id: str = "", status: str = "",
                        error: str = "") -> bool:
    """What became of a scheduled run - the scan it started, and how it ended."""
    with _lock:
        with _connect() as conn:
            return int(conn.execute(
                "UPDATE scan_schedules SET last_scan_id = ?, last_status = ?, last_error = ?, updated_at = ? "
                "WHERE tenant_id = ? AND schedule_id = ?",
                (str(scan_id or ""), str(status or "")[:40], str(error or "")[:500],
                 datetime.now(timezone.utc).isoformat(), tenant_id, str(schedule_id)),
            ).rowcount or 0) == 1


# --- B2: resumable scans ------------------------------------------------------

SCAN_PARTITION_STATES = ("queued", "running", "done", "failed")
_PARTITION_COLUMNS = (
    "scan_id, partition_id, job_id, ordinal, spec_json, status, attempt, files, "
    "error, started_at, finished_at, records_ref, records_bytes, summary_json, diagnostics_json, "
    "lease_owner, lease_expires_at, "
    "CASE WHEN records_json IS NOT NULL OR records_ref <> '' THEN 1 ELSE 0 END AS has_records"
)
PARTITIONED_SCAN_STATES = ("running", "finalizing", "done", "failed")
DEFAULT_PARTITION_LEASE_SECONDS = 300


def _lease_time(moment: datetime) -> str:
    """A UTC instant as fixed-width text, so leases compare correctly as strings on both backends.

    ``isoformat()`` drops the microseconds when they are zero, and a shorter string then
    sorts before a longer one from the same second.
    """
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
# Plan order is encoded in the seq columns as ordinal * span + position. Both are
# INTEGER - four bytes on PostgreSQL - so one scan can order at most 2,147
# partitions of up to a million findings each. A plan longer than that is refused
# when it is created, not discovered when partition 2,148 tries to write.
PARTITION_SEQ_SPAN = 1_000_000
_POSTGRES_INTEGER_MAX = 2_147_483_647
MAX_SCAN_PARTITIONS = (_POSTGRES_INTEGER_MAX + 1) // PARTITION_SEQ_SPAN


def scan_request_is_resumable(request: dict) -> bool:
    """Whether a scan could be resumed after a restart.

    Resuming a remote scan means connecting again, and the product never stores
    a typed password. A request whose credential is a vault reference, or that
    needs no credential at all, can resume. A request whose only credential is a
    typed password cannot: after a restart it fails, as every scan used to, and
    says why.
    """
    request = request if isinstance(request, dict) else {}
    # A local scan needs no credential, so a password field it happens to carry is
    # not something it would need back (B2.4 review). A file server or an endpoint does.
    remote = any(str(request.get(key) or "").strip() for key in ("server", "host"))
    typed_password = remote and bool(str(request.get("password") or ""))
    vaulted = bool(str(request.get("credential_ref") or "").strip())
    return vaulted or not typed_password


@_tenant_scoped
def bind_job_to_scan(tenant_id: str, job_id: str, scan_id: str, request: dict) -> dict:
    """Record the scan a job runs and the request it was given, without secrets.

    ``bound`` says whether there was a job row to write to. A binding that lands
    nowhere is a scan that can never be resumed, which must not look like success.
    """
    resumable = scan_request_is_resumable(request)
    cleaned = _sanitize_scan_profile_config(request if isinstance(request, dict) else {})
    encoded = json.dumps(cleaned, ensure_ascii=False, separators=(",", ":"), default=str)
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            bound = int(conn.execute(
                "UPDATE scan_jobs SET scan_id = ?, request_json = ?, resumable = ?, updated_at = ? "
                "WHERE id = ? AND tenant_id = ?",
                (str(scan_id), encoded, 1 if resumable else 0, now, str(job_id), tenant_id),
            ).rowcount or 0) == 1
    return {"job_id": str(job_id), "scan_id": str(scan_id), "resumable": resumable, "bound": bound}


@_tenant_scoped
def read_job_binding(tenant_id: str, job_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT scan_id, request_json, resumable FROM scan_jobs WHERE id = ? AND tenant_id = ?",
            (str(job_id), tenant_id),
        ).fetchone()
    if row is None:
        return None
    try:
        request = json.loads(row["request_json"] or "{}")
    except (TypeError, ValueError):
        request = {}
    return {
        "scan_id": str(row["scan_id"] or ""),
        "request": request if isinstance(request, dict) else {},
        "resumable": bool(row["resumable"]),
    }


def _partition_row(row) -> dict:
    try:
        spec = json.loads(row["spec_json"] or "{}")
    except (TypeError, ValueError):
        spec = {}
    kept = {}
    for column in ("summary_json", "diagnostics_json"):
        try:
            value = json.loads(row[column] or "{}")
        except (TypeError, ValueError):
            value = {}
        kept[column] = value if isinstance(value, dict) else {}
    return {
        "scan_id": str(row["scan_id"]),
        "partition_id": str(row["partition_id"]),
        "job_id": str(row["job_id"] or ""),
        "ordinal": int(row["ordinal"] or 0),
        "spec": spec if isinstance(spec, dict) else {},
        "status": str(row["status"]),
        "attempt": int(row["attempt"] or 0),
        "files": int(row["files"] or 0),
        "error": str(row["error"] or ""),
        "started_at": str(row["started_at"] or ""),
        "finished_at": str(row["finished_at"] or ""),
        "records_ref": str(row["records_ref"] or ""),
        "records_bytes": int(row["records_bytes"] or 0),
        "has_records": bool(row["has_records"]),
        "summary": kept["summary_json"],
        "diagnostics": kept["diagnostics_json"],
        "lease_owner": str(row["lease_owner"] or ""),
        "lease_expires_at": str(row["lease_expires_at"] or ""),
    }


@_tenant_scoped
def create_scan_partitions(tenant_id: str, scan_id: str, job_id: str, specs: list[dict]) -> list[str]:
    """Plan a scan's units, in order.

    Idempotent for the same plan: planning it again never resets a unit that has
    already run. A *different* plan for a scan that is already planned is refused.
    Units without their own ``partition_id`` are numbered by position, so a
    re-enumeration that gained a folder would shift every id after it - one unit
    would never run and another would run twice (B2 review). A resumed scan
    continues the plan in its ledger; it does not make a new one.
    """
    now = datetime.now(timezone.utc).isoformat()
    specs = list(specs or [])
    if len(specs) > MAX_SCAN_PARTITIONS:
        raise ValueError(
            f"a scan can be ordered across at most {MAX_SCAN_PARTITIONS} partitions; this plan has {len(specs)}"
        )
    ids: list[str] = []
    rows: list[tuple] = []
    for ordinal, spec in enumerate(specs):
        spec = spec if isinstance(spec, dict) else {}
        partition_id = str(spec.get("partition_id") or f"p{ordinal:05d}")
        ids.append(partition_id)
        rows.append((
            tenant_id, str(scan_id), partition_id, str(job_id or ""), ordinal,
            json.dumps(spec, ensure_ascii=False, separators=(",", ":"), default=str), now,
        ))
    if not rows:
        return ids
    with _lock:
        with _connect() as conn:
            existing = [
                (str(row["partition_id"]), int(row["ordinal"] or 0), str(row["spec_json"] or ""))
                for row in conn.execute(
                    "SELECT partition_id, ordinal, spec_json FROM scan_partitions "
                    "WHERE tenant_id = ? AND scan_id = ? ORDER BY ordinal",
                    (tenant_id, str(scan_id)),
                ).fetchall()
            ]
            if existing:
                if existing != [(row[2], row[4], row[5]) for row in rows]:
                    raise ValueError(
                        f"scan {scan_id} is already planned with different units; "
                        "a resumed scan continues its ledger instead of planning again"
                    )
                return ids
            conn.executemany(
                "INSERT OR IGNORE INTO scan_partitions "
                "(tenant_id, scan_id, partition_id, job_id, ordinal, spec_json, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
    return ids


def _touch_scan_record(conn, tenant_id: str, scan_id: str, now: str) -> None:
    """Inside a partition's own transaction: its scan is alive (B2.4 review).

    The resume sweep takes over only a scan nobody has touched for a lease, and a worker
    running short partitions is never alive long enough for its renewal thread to touch it.
    """
    conn.execute(
        "UPDATE partitioned_scans SET updated_at = ? WHERE tenant_id = ? AND scan_id = ? "
        "AND status IN ('running', 'finalizing')",
        (now, tenant_id, str(scan_id)),
    )


@_tenant_scoped
def claim_next_partition(
    tenant_id: str, scan_id: str, *, worker_id: str = "", lease_seconds: int = DEFAULT_PARTITION_LEASE_SECONDS,
) -> dict | None:
    """Take the first queued unit of a scan, in plan order, and mark it running.

    The update is a compare-and-set on the status, so two claimers - threads now,
    worker processes in B3 - can never take the same unit. It also matches the
    attempt it read, so the attempt it reports is the one the row holds: a unit
    claimed and requeued by someone else in between would otherwise hand this
    worker a stale attempt it could never complete with (B2 review). A lost race
    means another claimer made progress, so it takes the next queued unit rather
    than reporting that none is left.

    The claim takes a lease for ``worker_id`` that expires after ``lease_seconds``
    unless renewed; only an expired lease is ever taken back from a running unit.
    """
    moment = datetime.now(timezone.utc)
    now = moment.isoformat()
    expires = _lease_time(moment + timedelta(seconds=max(1, int(lease_seconds))))
    with _lock:
        with _connect() as conn:
            while True:
                row = conn.execute(
                    f"SELECT {_PARTITION_COLUMNS} FROM scan_partitions "
                    "WHERE tenant_id = ? AND scan_id = ? AND status = 'queued' "
                    "ORDER BY ordinal LIMIT 1",
                    (tenant_id, str(scan_id)),
                ).fetchone()
                if row is None:
                    return None
                claimed = conn.execute(
                    "UPDATE scan_partitions SET status = 'running', attempt = attempt + 1, "
                    "started_at = ?, finished_at = '', error = '', updated_at = ?, "
                    "lease_owner = ?, lease_expires_at = ? "
                    "WHERE tenant_id = ? AND scan_id = ? AND partition_id = ? AND status = 'queued' "
                    "AND attempt = ?",
                    (now, now, str(worker_id or ""), expires, tenant_id, str(scan_id), str(row["partition_id"]),
                     int(row["attempt"] or 0)),
                )
                if int(claimed.rowcount or 0) == 1:
                    _touch_scan_record(conn, tenant_id, scan_id, now)
                    result = _partition_row(row)
                    result.update(
                        status="running", attempt=result["attempt"] + 1,
                        started_at=now, finished_at="", error="",
                        lease_owner=str(worker_id or ""), lease_expires_at=expires,
                    )
                    return result


@_tenant_scoped
def claim_partition(
    tenant_id: str, scan_id: str, partition_id: str, *, worker_id: str = "",
    lease_seconds: int = DEFAULT_PARTITION_LEASE_SECONDS,
) -> dict | None:
    """Claim one named partition if it is queued; returns it, or ``None`` when it is not queued.

    A queue worker is handed a partition, not the next one in plan order (B3). This is
    the same compare-and-set on status and attempt as :func:`claim_next_partition`, with
    the same lease, so queue workers and an in-process runner can share one scan.
    """
    moment = datetime.now(timezone.utc)
    now = moment.isoformat()
    expires = _lease_time(moment + timedelta(seconds=max(1, int(lease_seconds))))
    with _lock:
        with _connect() as conn:
            row = conn.execute(
                f"SELECT {_PARTITION_COLUMNS} FROM scan_partitions "
                "WHERE tenant_id = ? AND scan_id = ? AND partition_id = ? AND status = 'queued'",
                (tenant_id, str(scan_id), str(partition_id)),
            ).fetchone()
            if row is None:
                return None
            claimed = conn.execute(
                "UPDATE scan_partitions SET status = 'running', attempt = attempt + 1, "
                "started_at = ?, finished_at = '', error = '', updated_at = ?, "
                "lease_owner = ?, lease_expires_at = ? "
                "WHERE tenant_id = ? AND scan_id = ? AND partition_id = ? AND status = 'queued' AND attempt = ?",
                (now, now, str(worker_id or ""), expires, tenant_id, str(scan_id), str(partition_id),
                 int(row["attempt"] or 0)),
            )
            if int(claimed.rowcount or 0) != 1:
                return None
            _touch_scan_record(conn, tenant_id, scan_id, now)
    result = _partition_row(row)
    result.update(
        status="running", attempt=result["attempt"] + 1, started_at=now, finished_at="", error="",
        lease_owner=str(worker_id or ""), lease_expires_at=expires,
    )
    return result


@_tenant_scoped
def read_scan_partition(tenant_id: str, scan_id: str, partition_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            f"SELECT {_PARTITION_COLUMNS} FROM scan_partitions WHERE tenant_id = ? AND scan_id = ? AND partition_id = ?",
            (tenant_id, str(scan_id), str(partition_id)),
        ).fetchone()
    return _partition_row(row) if row is not None else None


def _finish_partition(tenant_id: str, scan_id: str, partition_id: str, status: str,
                      *, attempt: int, files: int = 0, error: str = "") -> bool:
    now = datetime.now(timezone.utc).isoformat()
    sql = (
        "UPDATE scan_partitions SET status = ?, files = ?, error = ?, finished_at = ?, updated_at = ?, "
        "lease_owner = '', lease_expires_at = '' "
        "WHERE tenant_id = ? AND scan_id = ? AND partition_id = ? AND status = 'running'"
    )
    params: list = [status, int(files or 0), str(error or "")[:500], now, now,
                    tenant_id, str(scan_id), str(partition_id)]
    if attempt is not None:
        sql += " AND attempt = ?"
        params.append(int(attempt))
    with _lock:
        with _connect() as conn:
            return int(conn.execute(sql, tuple(params)).rowcount or 0) == 1


@_tenant_scoped
def complete_scan_partition(tenant_id: str, scan_id: str, partition_id: str, files: int,
                            *, attempt: int) -> bool:
    """Mark a running unit done; returns whether this call did it.

    Only a running unit can finish, and only under the ``attempt`` that claimed it.
    That stops a stale worker - one whose unit was requeued and claimed again -
    from finishing the newer attempt. The attempt is required: an optional guard
    is one a caller forgets, and then the stale worker wins (B2 review). Delivery
    in B3 is at-least-once, so the case is real.
    """
    return _finish_partition(tenant_id, scan_id, partition_id, "done", files=files, attempt=attempt)


@_tenant_scoped
def fail_scan_partition(tenant_id: str, scan_id: str, partition_id: str, error: str,
                        *, attempt: int) -> bool:
    return _finish_partition(tenant_id, scan_id, partition_id, "failed", error=error, attempt=attempt)


@_tenant_scoped
def list_scan_partitions(tenant_id: str, scan_id: str) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            f"SELECT {_PARTITION_COLUMNS} FROM scan_partitions "
            "WHERE tenant_id = ? AND scan_id = ? ORDER BY ordinal",
            (tenant_id, str(scan_id)),
        ).fetchall()
    return [_partition_row(row) for row in rows]


@_tenant_scoped
def scan_partition_summary(tenant_id: str, scan_id: str) -> dict:
    counts = {state: 0 for state in SCAN_PARTITION_STATES}
    files = 0
    with _connect() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS n, COALESCE(SUM(files), 0) AS f FROM scan_partitions "
            "WHERE tenant_id = ? AND scan_id = ? GROUP BY status",
            (tenant_id, str(scan_id)),
        ).fetchall()
    for row in rows:
        counts[str(row["status"])] = int(row["n"] or 0)
        files += int(row["f"] or 0)
    total = sum(counts.values())
    return {
        "scan_id": str(scan_id),
        "partitions": total,
        **counts,
        "files": files,
        "complete": total > 0 and counts["done"] == total,
        # Nothing left to run. A scan can be finished without being complete: a
        # failed unit is terminal until something decides to retry it (B2.4).
        "finished": total > 0 and counts["queued"] == 0 and counts["running"] == 0,
    }


def requeue_interrupted_partitions(tenant_id: str | None = None) -> int:
    """Put units a stopped process left running back in the queue, whatever their lease.

    Correct only at the startup of the one process that runs scans in-process: every
    running unit then belongs to a process that no longer exists. Workers sharing a
    ledger use :func:`requeue_expired_partitions` instead. With no tenant it spans every
    tenant, as ``recover_interrupted_jobs`` does. The attempt count is left alone here
    and raised by the next claim, so it counts attempts that actually started.
    """
    now = datetime.now(timezone.utc).isoformat()
    sql = (
        "UPDATE scan_partitions SET status = 'queued', updated_at = ?, lease_owner = '', lease_expires_at = '' "
        "WHERE status = 'running'"
    )
    params: list = [now]
    if tenant_id:
        sql += " AND tenant_id = ?"
        params.append(tenant_id)
    with _lock:
        with _connect() as conn:
            return int(conn.execute(sql, tuple(params)).rowcount or 0)


@_tenant_scoped
def renew_partition_lease(
    tenant_id: str, scan_id: str, partition_id: str, *, attempt: int, worker_id: str,
    lease_seconds: int = DEFAULT_PARTITION_LEASE_SECONDS,
) -> bool:
    """Extend a running unit's lease; returns whether the caller still holds it.

    Only the worker that claimed this attempt can renew it. ``False`` means the unit was
    taken back - its lease expired and someone requeued it - and the caller should stop
    working on it: its write would be refused anyway.
    """
    expires = _lease_time(datetime.now(timezone.utc) + timedelta(seconds=max(1, int(lease_seconds))))
    with _lock:
        with _connect() as conn:
            return int(conn.execute(
                "UPDATE scan_partitions SET lease_expires_at = ?, updated_at = ? "
                "WHERE tenant_id = ? AND scan_id = ? AND partition_id = ? AND status = 'running' "
                "AND attempt = ? AND lease_owner = ?",
                (expires, datetime.now(timezone.utc).isoformat(), tenant_id, str(scan_id), str(partition_id),
                 int(attempt), str(worker_id or "")),
            ).rowcount or 0) == 1


def requeue_expired_partitions(
    *, tenant_id: str | None = None, now: datetime | None = None, max_attempts: int | None = None,
) -> int:
    """Take back running units whose lease has run out, whoever held them; returns how many.

    Safe with many workers: a unit whose holder is alive keeps renewing and is never
    touched. A unit without a lease - claimed before leases existed - is left to
    :func:`requeue_interrupted_partitions` at startup. With no tenant it spans every
    tenant; the attempt count is raised by the next claim.

    With ``max_attempts``, a unit whose holder went quiet on its last attempt is marked
    failed instead of queued. A partition that kills every process running it would
    otherwise be claimed again forever (B2.4 review).
    """
    cutoff = _lease_time(now or datetime.now(timezone.utc))
    stamp = datetime.now(timezone.utc).isoformat()
    expired = "status = 'running' AND lease_expires_at <> '' AND lease_expires_at < ?"
    scope = " AND tenant_id = ?" if tenant_id else ""
    scope_params: tuple = (tenant_id,) if tenant_id else ()
    changed = 0
    with _lock:
        with _connect() as conn:
            if max_attempts is not None:
                changed += int(conn.execute(
                    "UPDATE scan_partitions SET status = 'failed', error = 'lease expired on its last attempt', "
                    "finished_at = ?, lease_owner = '', lease_expires_at = '', updated_at = ? "
                    f"WHERE {expired} AND attempt >= ?{scope}",
                    (stamp, stamp, cutoff, int(max_attempts), *scope_params),
                ).rowcount or 0)
            changed += int(conn.execute(
                "UPDATE scan_partitions SET status = 'queued', lease_owner = '', lease_expires_at = '', updated_at = ? "
                f"WHERE {expired}{scope}",
                (stamp, cutoff, *scope_params),
            ).rowcount or 0)
    return changed


@_tenant_scoped
def requeue_failed_partitions(tenant_id: str, scan_id: str, *, max_attempts: int) -> int:
    """Give failed units of a scan another run, until they have had ``max_attempts``.

    A unit fails for reasons that may pass - a share that was briefly unreachable, a
    file locked for a moment. One that has failed ``max_attempts`` times stays failed,
    and the scan cannot be finalized until someone decides what to do with it.
    """
    with _lock:
        with _connect() as conn:
            return int(conn.execute(
                "UPDATE scan_partitions SET status = 'queued', lease_owner = '', lease_expires_at = '', updated_at = ? "
                "WHERE tenant_id = ? AND scan_id = ? AND status = 'failed' AND attempt < ?",
                (datetime.now(timezone.utc).isoformat(), tenant_id, str(scan_id), int(max_attempts)),
            ).rowcount or 0)


def _partitioned_scan_row(row) -> dict:
    parsed = {}
    for column in ("request_json", "header_json"):
        try:
            value = json.loads(row[column] or "{}")
        except (TypeError, ValueError):
            value = {}
        parsed[column] = value if isinstance(value, dict) else {}
    return {
        "tenant_id": str(row["tenant_id"]),
        "scan_id": str(row["scan_id"]),
        "job_id": str(row["job_id"] or ""),
        "status": str(row["status"]),
        "request": parsed["request_json"],
        "header": parsed["header_json"],
        "resumable": bool(row["resumable"]),
        "error": str(row["error"] or ""),
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
    }


_PARTITIONED_SCAN_COLUMNS = (
    "tenant_id, scan_id, job_id, status, request_json, header_json, resumable, error, created_at, updated_at"
)


@_tenant_scoped
def register_partitioned_scan(
    tenant_id: str, scan_id: str, *, job_id: str, request: dict, header: dict, resumable: bool | None = None,
) -> dict:
    """Record a partitioned scan before its first partition runs; returns the stored row.

    The request goes through the same secret filter scan profiles use, so a typed
    password never reaches the database - and a scan whose only credential was a typed
    password is recorded as not resumable. ``resumable=False`` records a scan that
    cannot be resumed for another reason, such as having no request to rebuild it from.
    Registering a scan that is already recorded changes nothing and returns what is
    there: a resumed scan continues with the header it started with.
    """
    resumable = scan_request_is_resumable(request) and resumable is not False
    cleaned = _sanitize_scan_profile_config(request if isinstance(request, dict) else {})
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO partitioned_scans "
                "(tenant_id, scan_id, job_id, status, request_json, header_json, resumable, error, created_at, updated_at) "
                "VALUES (?, ?, ?, 'running', ?, ?, ?, '', ?, ?)",
                (
                    tenant_id, str(scan_id), str(job_id or ""),
                    json.dumps(cleaned, ensure_ascii=False, separators=(",", ":"), default=str),
                    json.dumps(header if isinstance(header, dict) else {}, ensure_ascii=False, separators=(",", ":"), default=str),
                    1 if resumable else 0, now, now,
                ),
            )
            row = conn.execute(
                f"SELECT {_PARTITIONED_SCAN_COLUMNS} FROM partitioned_scans WHERE tenant_id = ? AND scan_id = ?",
                (tenant_id, str(scan_id)),
            ).fetchone()
    return _partitioned_scan_row(row)


@_tenant_scoped
def read_partitioned_scan(tenant_id: str, scan_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            f"SELECT {_PARTITIONED_SCAN_COLUMNS} FROM partitioned_scans WHERE tenant_id = ? AND scan_id = ?",
            (tenant_id, str(scan_id)),
        ).fetchone()
    return _partitioned_scan_row(row) if row is not None else None


def list_unfinished_partitioned_scans(*, resumable_only: bool = False) -> list[dict]:
    """Partitioned scans that are neither done nor failed, across every tenant, oldest first.

    Spans tenants the way job recovery does: it is read at startup, and by workers
    looking for work, before any tenant is known.
    """
    sql = (
        f"SELECT {_PARTITIONED_SCAN_COLUMNS} FROM partitioned_scans "
        "WHERE status IN ('running', 'finalizing')"
    )
    if resumable_only:
        sql += " AND resumable = 1"
    sql += " ORDER BY created_at, scan_id"
    with _connect() as conn:
        rows = conn.execute(sql).fetchall()
    return [_partitioned_scan_row(row) for row in rows]


@_tenant_scoped
def first_queued_partition(tenant_id: str, scan_id: str) -> str | None:
    """A scan's first queued partition in plan order - what the ledger queue hands a worker (B3).

    Naming a partition claims nothing: the worker's claim is the compare-and-set.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT partition_id FROM scan_partitions WHERE tenant_id = ? AND scan_id = ? AND status = 'queued' "
            "ORDER BY ordinal LIMIT 1",
            (tenant_id, str(scan_id)),
        ).fetchone()
    return str(row["partition_id"]) if row is not None else None


@_tenant_scoped
def bind_partitioned_scan_job(tenant_id: str, scan_id: str, job_id: str) -> bool:
    """Point a partitioned scan at the job now running it."""
    with _lock:
        with _connect() as conn:
            return int(conn.execute(
                "UPDATE partitioned_scans SET job_id = ?, updated_at = ? WHERE tenant_id = ? AND scan_id = ?",
                (str(job_id or ""), datetime.now(timezone.utc).isoformat(), tenant_id, str(scan_id)),
            ).rowcount or 0) == 1


@_tenant_scoped
def touch_partitioned_scan(tenant_id: str, scan_id: str) -> bool:
    """Record that an unfinished scan's runner is alive; returns whether the scan is still unfinished.

    The resume sweep takes over only a scan nobody has touched for a lease, so a runner
    touches its scan between partitions and, from its lease thread, while one runs.
    """
    with _lock:
        with _connect() as conn:
            return int(conn.execute(
                "UPDATE partitioned_scans SET updated_at = ? "
                "WHERE tenant_id = ? AND scan_id = ? AND status IN ('running', 'finalizing')",
                (datetime.now(timezone.utc).isoformat(), tenant_id, str(scan_id)),
            ).rowcount or 0) == 1


@_tenant_scoped
def claim_partitioned_scan_resume(
    tenant_id: str, scan_id: str, *, job_id: str, stale_after_seconds: int,
    finalizing_stale_after_seconds: int | None = None,
) -> bool:
    """Take over an unfinished scan nobody has touched for ``stale_after_seconds``; returns whether this caller did.

    A compare-and-set on the scan's last sign of life, so two sweeps never both continue
    one scan, and a runner that is alive - touching its scan every third of a lease -
    keeps it. The claim is itself a touch, and points the scan at ``job_id``. A scan
    left ``finalizing`` goes back to ``running``, so its new runner claims the finalize
    at once instead of waiting out a second lease.

    ``updated_at`` is ``isoformat()`` text with a ``+00:00`` offset, which compares
    correctly as a string even when its microseconds are dropped: ``+`` sorts before
    ``.``, unlike the ``Z`` a lease ends with.

    A scan left ``finalizing`` is judged by ``finalizing_stale_after_seconds``: finalize's
    write is one transaction that cannot touch the record while it runs, and on
    PostgreSQL it holds the record's row lock, which this update would wait on (B2.4
    review).
    """
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(seconds=max(0, int(stale_after_seconds)))).isoformat()
    finalizing = stale_after_seconds if finalizing_stale_after_seconds is None else finalizing_stale_after_seconds
    finalizing_cutoff = (now - timedelta(seconds=max(0, int(finalizing)))).isoformat()
    with _lock:
        with _connect() as conn:
            return int(conn.execute(
                "UPDATE partitioned_scans SET status = 'running', job_id = ?, updated_at = ? "
                "WHERE tenant_id = ? AND scan_id = ? AND ("
                "(status = 'running' AND updated_at < ?) OR (status = 'finalizing' AND updated_at < ?))",
                (str(job_id or ""), now.isoformat(), tenant_id, str(scan_id), cutoff, finalizing_cutoff),
            ).rowcount or 0) == 1


@_tenant_scoped
def claim_scan_finalize(tenant_id: str, scan_id: str, *, stale_after_seconds: int | None = None) -> bool:
    """Move a scan from running to finalizing; returns whether this caller may finalize it.

    A compare-and-set, so of several workers that each see the last partition finish,
    exactly one finalizes (B2.2b review: two finalizes at once made the second raise).
    A scan left ``finalizing`` by a process that died can be claimed again once it has
    been idle for ``stale_after_seconds`` - safe, because finalize is one transaction
    that either happened or did not.
    """
    now = datetime.now(timezone.utc)
    sql = "UPDATE partitioned_scans SET status = 'finalizing', updated_at = ? WHERE tenant_id = ? AND scan_id = ? AND ("
    sql += "status = 'running'"
    params: list = [now.isoformat(), tenant_id, str(scan_id)]
    if stale_after_seconds is not None:
        sql += " OR (status = 'finalizing' AND updated_at < ?)"
        params.append((now - timedelta(seconds=max(0, int(stale_after_seconds)))).isoformat())
    sql += ")"
    with _lock:
        with _connect() as conn:
            return int(conn.execute(sql, tuple(params)).rowcount or 0) == 1


@_tenant_scoped
def mark_partitioned_scan(tenant_id: str, scan_id: str, status: str, *, error: str = "") -> bool:
    """Set a partitioned scan's status; returns whether it changed.

    Only an unfinished scan is ever marked failed: a runner that lost a race to a
    finalize that succeeded must not turn that scan's success into a failure.
    """
    if status not in PARTITIONED_SCAN_STATES:
        raise ValueError(f"not a partitioned scan state: {status}")
    sql = "UPDATE partitioned_scans SET status = ?, error = ?, updated_at = ? WHERE tenant_id = ? AND scan_id = ?"
    if status == "failed":
        sql += " AND status IN ('running', 'finalizing')"
    with _lock:
        with _connect() as conn:
            return int(conn.execute(
                sql, (status, str(error or "")[:500], datetime.now(timezone.utc).isoformat(), tenant_id, str(scan_id)),
            ).rowcount or 0) == 1


class PartitionNotClaimed(RuntimeError):
    """A partition was persisted by a worker that does not hold it."""


def iter_json_array(items):
    """``json.dumps(list(items), ensure_ascii=False)``, a piece at a time."""
    yield "["
    for index, item in enumerate(items):
        if index:
            yield ", "
        yield json.dumps(item, ensure_ascii=False)
    yield "]"


@_tenant_scoped
def persist_partition(
    tenant_id: str,
    scan_id: str,
    partition_id: str,
    attempt: int,
    header: dict,
    records: list[dict],
    *,
    write_estate: bool,
) -> dict:
    """Write one finished partition of a scan: its rows, and its records for finalize.

    ``header`` is the partition's report without its files - timestamp, source,
    mode, label, and the partition's own ``summary`` and ``scan_diagnostics``.
    Everything happens in one transaction: the estate rows, the finding-index
    range, the baseline objects, the records finalize will read back, and marking
    the partition done.

    **The ledger decides, not the caller.** The partition's ordinal - which is
    where its findings sit in the scan's order - is read from its ledger row inside
    the transaction, together with the proof that this worker still holds it: the
    row must be running under ``attempt``. A worker that lost its partition is
    refused before anything is written, and one that loses it during the write is
    refused at the end, which rolls the rows back. A caller-supplied ordinal once let
    two partitions delete each other's index range (B2 review).

    **What a partition never does** is anything that needs the whole scan: the scan
    run row, the report row, pruning assets or baseline objects it did not see, and
    finding-index retention. Those belong to finalize.

    **Partitions must be disjoint by asset.** The same asset written by two
    partitions of one scan ends up differently from one save - the later
    partition's retirement demotes the earlier partition's findings. The planner
    guarantees disjointness; nothing here can check it without tagging every row.
    """
    header = dict(header or {})
    header.pop("files", None)
    raw_summary = header.get("summary")
    summary = dict(raw_summary) if isinstance(raw_summary, dict) else {}
    raw_diagnostics = header.get("scan_diagnostics")
    # A private copy: the baseline writer records its counts into these diagnostics,
    # and a dict shared between partitions would carry one partition's counts into
    # the next.
    diagnostics = json.loads(json.dumps(raw_diagnostics, default=str)) if isinstance(raw_diagnostics, dict) else {}
    report = {**header, "scan_id": str(scan_id), "scan_diagnostics": diagnostics, "files": records}
    now = datetime.now(timezone.utc).isoformat()

    def not_claimed() -> PartitionNotClaimed:
        return PartitionNotClaimed(
            f"partition {partition_id} of scan {scan_id} is not running under attempt {attempt}"
        )

    with _lock:
        with _connect() as conn:
            # The write starts by writing to its own ledger row. On PostgreSQL that locks
            # the row, so no other process can take the partition back until this commits:
            # its lease cannot be renewed meanwhile, because renewal waits for the store
            # lock this holds. It also shows the scan is alive (B2.4 review).
            held = conn.execute(
                "UPDATE scan_partitions SET updated_at = ? "
                "WHERE tenant_id = ? AND scan_id = ? AND partition_id = ? AND status = 'running' AND attempt = ?",
                (now, tenant_id, str(scan_id), str(partition_id), int(attempt)),
            )
            if int(held.rowcount or 0) != 1:
                raise not_claimed()
            _touch_scan_record(conn, tenant_id, scan_id, now)
            unit = conn.execute(
                "SELECT ordinal, status, attempt FROM scan_partitions "
                "WHERE tenant_id = ? AND scan_id = ? AND partition_id = ?",
                (tenant_id, str(scan_id), str(partition_id)),
            ).fetchone()
            if unit is None or str(unit["status"]) != "running" or int(unit["attempt"] or 0) != int(attempt):
                raise not_claimed()
            ordinal = int(unit["ordinal"] or 0)
            seq_offset = ordinal * PARTITION_SEQ_SPAN
            if not 0 <= ordinal < MAX_SCAN_PARTITIONS:
                raise ValueError(f"partition ordinal {ordinal} cannot be ordered in a four-byte seq column")
            _write_normalized_rows(
                conn, tenant_id, report, refresh_current=True,
                partition={"seq_offset": seq_offset, "seq_span": PARTITION_SEQ_SPAN, "write_estate": bool(write_estate)},
            )
            _write_incremental_baseline(conn, tenant_id, report, is_new_scan=True, prune=False)
            # The records are stored after the rows, because writing the rows fills
            # lifecycle fields into the findings, and finalize has to stream what a
            # single save would have stored. They are stored before the partition is
            # marked done, so a completed partition always has its records - and in
            # the same transaction as the rows, so a partition whose rows landed is
            # never run again with a different set of files.
            records_ref, records_bytes, inline = "", 0, None
            if report_artifacts_enabled():
                from backend import artifacts

                ref = artifacts.put_stream(tenant_id, iter_json_array(records))
                records_ref, records_bytes = ref.content_id, ref.size_bytes
            else:
                body = "".join(iter_json_array(records))
                inline, records_bytes = pack_json_text(body), len(body.encode("utf-8"))
            finished = conn.execute(
                "UPDATE scan_partitions SET status = 'done', files = ?, error = '', records_ref = ?, "
                "lease_owner = '', lease_expires_at = '', "
                "records_bytes = ?, records_json = ?, summary_json = ?, diagnostics_json = ?, "
                "finished_at = ?, updated_at = ? "
                "WHERE tenant_id = ? AND scan_id = ? AND partition_id = ? AND status = 'running' AND attempt = ?",
                (
                    len(records), records_ref, records_bytes, inline,
                    json.dumps(summary, ensure_ascii=False, separators=(",", ":"), default=str),
                    json.dumps(diagnostics, ensure_ascii=False, separators=(",", ":"), default=str),
                    now, now, tenant_id, str(scan_id), str(partition_id), int(attempt),
                ),
            )
            if int(finished.rowcount or 0) != 1:
                raise not_claimed()
    _invalidate_inventory_query_cache(tenant_id)
    _invalidate_remediation_query_cache(tenant_id)
    # The search projection is best effort and runs after the authoritative
    # transaction, exactly as it does for a single save.
    try:
        from backend.search import SearchUnavailable, index_scan_report

        index_scan_report(tenant_id, report)
    except SearchUnavailable as exc:
        logger.warning("Dedicated search indexing deferred for partition %s of %s: %s", partition_id, scan_id, exc)
    except Exception as exc:  # pragma: no cover - optional projection guard
        logger.warning("Dedicated search indexing skipped for partition %s of %s: %s", partition_id, scan_id, type(exc).__name__)
    return {
        "scan_id": str(scan_id),
        "partition_id": str(partition_id),
        "ordinal": ordinal,
        "files": len(records),
        "records_ref": records_ref,
        "records_bytes": records_bytes,
    }


def referenced_artifact_ids() -> set[tuple[str, str]]:
    """Every ``(tenant_id, content_id)`` a row still depends on.

    Report bodies, and the records of partitions whose scan has not been finalized
    yet. Retention collects whatever is not in this set, so anything that stores an
    artifact reference must be here: counting report bodies alone would let a
    partition's records be collected an hour after they were written, and the
    finalize or resume that needs them would fail (B2 review).
    """
    with _connect() as conn:
        rows = conn.execute(
            "SELECT tenant_id, report_ref AS ref FROM scan_reports WHERE COALESCE(report_ref, '') <> '' "
            "UNION ALL "
            "SELECT tenant_id, records_ref AS ref FROM scan_partitions WHERE COALESCE(records_ref, '') <> ''"
        ).fetchall()
    return {(str(row["tenant_id"]), str(row["ref"])) for row in rows}


class PartitionsNotFinished(RuntimeError):
    """A partitioned scan was finalized before every one of its partitions was done."""


class ScanAlreadyFinalized(RuntimeError):
    """Another finalize of this partitioned scan committed first; its report stands."""


# Diagnostics that describe how one engine was configured rather than what it
# found. Every partition's engine reports its own, and adding worker counts across
# partitions would describe nothing, so the last partition's report stands.
_CONFIGURATION_DIAGNOSTICS = frozenset({"parallelism", "worker_pool", "pipeline", "detector_pool", "io_workers"})
_MERGED_DIAGNOSTIC_LIST_LIMIT = 20
# An SMB scan's share coverage (B2.3) names every share however many there are: the
# ones it found, walked and skipped in the order the server listed them, and the ones
# it could not read or lost the connection to sorted, as the collector sorts them. So
# the partitions of one scan report exactly the single scan's lists.
_SHARE_ORDER_DIAGNOSTICS = frozenset({"shares_discovered", "shares_scanned", "shares_skipped"})
_SHARE_SORTED_DIAGNOSTICS = frozenset({"shares_access_denied", "shares_connection_reset"})


def merge_partition_diagnostics(diagnostics: list[dict]) -> dict:
    """One scan's diagnostics from its partitions', in plan order.

    Counts add up. A flag is set if any partition set it, except that the scan is
    ``complete`` - and its baseline ``baseline_committed`` - only if every partition
    was, because completeness is what licenses the prunes. ``delta_ratio`` is
    recomputed from the summed counts, and the number of suppression rules is the
    scan's, not the sum of its partitions'. Lists that differ are joined without
    duplicates and kept to 20 entries, the limit a single collector applies; text
    keeps the first partition's value. Keys keep the order they first appear in.
    """
    parts = [part for part in diagnostics if isinstance(part, dict)]
    if not parts:
        return {}
    return _merge_diagnostic_dicts(parts, top_level=True)


def _merge_diagnostic_dicts(parts: list[dict], *, top_level: bool = False) -> dict:
    merged: dict = {}
    for key in dict.fromkeys(key for part in parts for key in part):
        present = [part[key] for part in parts if key in part]
        if top_level and key in _CONFIGURATION_DIAGNOSTICS:
            merged[key] = present[-1]
        elif top_level and key in _SHARE_ORDER_DIAGNOSTICS and all(isinstance(value, list) for value in present):
            merged[key] = list(dict.fromkeys(str(item) for value in present for item in value))
        elif top_level and key in _SHARE_SORTED_DIAGNOSTICS and all(isinstance(value, list) for value in present):
            merged[key] = sorted({str(item) for value in present for item in value})
        elif top_level and key == "incremental" and all(isinstance(value, dict) for value in present):
            merged[key] = _merge_incremental_diagnostics(present)
        elif top_level and key == "suppression" and all(isinstance(value, dict) for value in present):
            merged[key] = _merge_suppression_diagnostics(present)
        elif key == "reuse_index" and all(isinstance(value, dict) for value in present):
            index = _merge_diagnostic_dicts(present)
            index["state"] = next(
                (str(value.get("state")) for value in present if value.get("state") not in (None, "ok")), "ok",
            )
            merged[key] = index
        else:
            merged[key] = _merge_diagnostic_values(present)
    return merged


def _merge_suppression_diagnostics(parts: list[dict]) -> dict:
    """What the rules did adds up; how many there were does not (B6).

    Every partition of one scan carries the same compiled rules, so summing ``rules``
    reported a tenant with one rule as a tenant with one per partition - six, for a scan
    cut into six. The counts beside it are real counts and still add up.
    """
    merged = _merge_diagnostic_dicts(parts)
    merged["rules"] = max((int(part.get("rules") or 0) for part in parts), default=0)
    return merged


def _merge_diagnostic_values(values: list):
    if all(isinstance(value, bool) for value in values):
        return any(values)
    if all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in values):
        return sum(values)
    if all(isinstance(value, dict) for value in values):
        return _merge_diagnostic_dicts(values)
    if all(isinstance(value, list) for value in values):
        if all(value == values[0] for value in values):
            return list(values[0])
        joined: list = []
        for value in values:
            for item in value:
                if item not in joined:
                    joined.append(item)
                    if len(joined) >= _MERGED_DIAGNOSTIC_LIST_LIMIT:
                        return joined
        return joined
    return values[0]


def _merge_incremental_diagnostics(parts: list[dict]) -> dict:
    merged = _merge_diagnostic_dicts(parts)
    if "complete" in merged:
        merged["complete"] = all(bool(part.get("complete")) for part in parts)
    if "baseline_committed" in merged:
        merged["baseline_committed"] = all(bool(part.get("baseline_committed")) for part in parts)
    if "delta_ratio" in merged:
        total = int(merged.get("total_objects") or 0)
        reads = int(merged.get("content_reads") or 0)
        merged["delta_ratio"] = round(reads / total, 6) if total else 0.0
    return merged


def iter_partition_records(tenant_id: str, scan_id: str):
    """Each finished partition's records, in plan order, one partition in memory at a time.

    Every database read is scoped to the tenant itself, rather than relying on the
    caller's scope: a generator runs whenever it is iterated, not when it was made.
    """
    with db.tenant_scope(str(tenant_id)):
        with _connect() as conn:
            units = [
                (str(row["partition_id"]), str(row["status"]))
                for row in conn.execute(
                    "SELECT partition_id, status FROM scan_partitions "
                    "WHERE tenant_id = ? AND scan_id = ? ORDER BY ordinal",
                    (tenant_id, str(scan_id)),
                ).fetchall()
            ]
    for partition_id, status in units:
        if status != "done":
            raise PartitionsNotFinished(f"partition {partition_id} of scan {scan_id} is {status}")
        with db.tenant_scope(str(tenant_id)):
            with _connect() as conn:
                row = conn.execute(
                    "SELECT records_ref, records_json FROM scan_partitions "
                    "WHERE tenant_id = ? AND scan_id = ? AND partition_id = ?",
                    (tenant_id, str(scan_id), partition_id),
                ).fetchone()
        content_id = str(row["records_ref"] or "") if row is not None else ""
        if content_id:
            from backend import artifacts

            with db.tenant_scope(str(tenant_id)):
                records = json.loads(artifacts.get_text(tenant_id, content_id) or "[]")
        elif row is not None and row["records_json"] is not None:
            records = json.loads(unpack_json_text(row["records_json"]) or "[]")
        else:
            raise PartitionsNotFinished(f"partition {partition_id} of scan {scan_id} kept no records")
        yield partition_id, records
        records = None


@_tenant_scoped
def finalize_partitioned_scan(
    tenant_id: str,
    scan_id: str,
    report: dict,
    *,
    write_estate: bool,
    file_count: int,
    sample_count: int,
) -> str:
    """Write everything about a partitioned scan that needs the whole scan.

    ``report`` is the finished report with its ``files`` as a :class:`StreamedFiles`
    over the partitions' records, and its summary, diagnostics and compliance
    sections already folded. In one transaction this writes what the partitions
    could not: the scan run, the unseen-asset prune for a named complete scan, the
    baseline prune, finding-index retention, the report body (streamed, never one
    string) and the report row - and then lets the partitions' records go, so
    retention can collect them.

    It is the second half of ``save_scan_history``, and a test holds it to that:
    the same records written as partitions and finalized leave the same rows and
    the same stored body as one save. The one deliberate difference is
    ``rows_json``, which stays empty rather than building a list of the whole
    estate; its reader projects the body instead.
    """
    from backend.domain import scan_run_from_report

    scan_id = str(scan_id)
    report["scan_id"] = scan_id
    created_at = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            # Two finalizes of one scan wait for each other here: the update takes the
            # scan record's row lock on PostgreSQL and makes this a write transaction on
            # SQLite, so the one that waited sees what the first committed (B2.4).
            conn.execute(
                "UPDATE partitioned_scans SET updated_at = ? WHERE tenant_id = ? AND scan_id = ?",
                (created_at, tenant_id, scan_id),
            )
            states = {
                str(row["status"]): int(row["n"] or 0)
                for row in conn.execute(
                    "SELECT status, COUNT(*) AS n FROM scan_partitions WHERE tenant_id = ? AND scan_id = ? GROUP BY status",
                    (tenant_id, scan_id),
                ).fetchall()
            }
            if not states or set(states) != {"done"}:
                raise PartitionsNotFinished(f"scan {scan_id} cannot be finalized: partitions {states or 'none'}")
            existing = conn.execute(
                "SELECT created_at FROM scan_reports WHERE tenant_id = ? AND scan_id = ?", (tenant_id, scan_id),
            ).fetchone()
            held = conn.execute(
                "SELECT COUNT(*) AS n FROM scan_partitions WHERE tenant_id = ? AND scan_id = ? "
                "AND (records_ref <> '' OR records_json IS NOT NULL)",
                (tenant_id, scan_id),
            ).fetchone()
            if existing is not None and not int(held["n"] or 0):
                # The first finalize released the records its body was built from; this
                # one would stream an empty body over that report.
                raise ScanAlreadyFinalized(f"scan {scan_id} is already finalized")
            if existing and existing["created_at"]:
                created_at = existing["created_at"]
            run = scan_run_from_report(tenant_id, report)
            conn.execute(
                """
                INSERT OR IGNORE INTO scan_runs
                    (tenant_id, id, source, mode, policy_version, started_at, ended_at, status, total_files, summary_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (tenant_id, run.id, run.source, run.mode, run.policy_version, run.started_at, run.ended_at,
                 run.status, run.total_files, json.dumps(run.summary, ensure_ascii=False)),
            )
            scan_label = str(report.get("scan_label") or "").strip()[:80]
            diagnostics = report.get("scan_diagnostics") if isinstance(report.get("scan_diagnostics"), dict) else {}
            incremental = diagnostics.get("incremental") if isinstance(diagnostics, dict) else None
            complete_scope = not isinstance(incremental, dict) or bool(incremental.get("complete"))
            if write_estate and scan_label and complete_scope:
                _prune_unseen_assets(conn, tenant_id, scan_label, scan_id)
            if (
                isinstance(incremental, dict)
                and incremental.get("baseline_update", incremental.get("enabled"))
                and incremental.get("baseline_committed")
                and str(incremental.get("scope_key") or "")
            ):
                _prune_incremental_baseline(conn, tenant_id, incremental, str(incremental.get("scope_key")), scan_id)
            _trim_finding_index(conn, tenant_id)
            report_ref, report_bytes, inline_body = _store_report_body(tenant_id, report)
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_reports
                    (tenant_id, scan_id, timestamp, source, scan_label, summary_json,
                     report_json, report_ref, report_bytes, rows_json, compact_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    scan_id,
                    report.get("timestamp"),
                    report.get("source"),
                    scan_label,
                    json.dumps(report.get("summary", {}), ensure_ascii=False),
                    inline_body,
                    report_ref,
                    report_bytes,
                    None,
                    pack_json_text(json.dumps(
                        compact_scan_report_from_counts(report, file_count, sample_count),
                        ensure_ascii=False, separators=(",", ":"),
                    )),
                    created_at,
                ),
            )
            # The body now holds every record, so the partitions' own copies are
            # unreferenced from here on and retention collects them.
            conn.execute(
                "UPDATE scan_partitions SET records_ref = '', records_bytes = 0, records_json = NULL, updated_at = ? "
                "WHERE tenant_id = ? AND scan_id = ?",
                (datetime.now(timezone.utc).isoformat(), tenant_id, scan_id),
            )
    _invalidate_inventory_query_cache(tenant_id)
    _invalidate_remediation_query_cache(tenant_id)
    _forget_scan_report_rows(tenant_id)
    with suppress(Exception):
        db.optimize_sqlite(DB_PATH)
    return scan_id


def prune_job_records(max_age_seconds: int) -> int:
    """Delete terminal (completed/failed/cancelled) job records older than
    max_age_seconds, so scan_jobs does not grow without bound (ARCH-003/F8)."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=max(0, int(max_age_seconds)))).isoformat()
    with _lock:
        with _connect() as conn:
            cursor = conn.execute(
                "DELETE FROM scan_jobs WHERE status IN ('completed', 'failed', 'cancelled') AND updated_at < ?",
                (cutoff,),
            )
            return cursor.rowcount


@_tenant_scoped
def count_scan_history(tenant_id: str) -> int:
    """Total number of persisted scans for a tenant (DATA-003).

    list_tenants previously derived scan_count from len(read_scan_history(...,
    limit=1)), which is always 0 or 1. MSSP portfolio dashboards need the real
    total, so count it in SQL.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM scan_reports WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
    return int(row[0]) if row else 0


@_tenant_scoped
def read_scan_history(tenant_id: str, limit: int | None = None) -> list[dict]:
    query = """
            SELECT scan_id, timestamp, source, scan_label, summary_json
            FROM scan_reports
            WHERE tenant_id = ?
            ORDER BY created_at DESC, scan_id DESC
            """
    params: tuple = (tenant_id,)
    if limit is not None:
        safe_limit = max(1, min(int(limit), 1000))
        query += " LIMIT ?"
        params = (tenant_id, safe_limit)
    with _connect() as conn:
        rows = conn.execute(query, params).fetchall()
    rows = list(reversed(rows))
    return [
        {
            "scan_id": row["scan_id"],
            "timestamp": row["timestamp"],
            "source": row["source"],
            "scan_label": row["scan_label"],
            "summary": json.loads(row["summary_json"] or "{}"),
        }
        for row in rows
    ]


@_tenant_scoped
def read_scan_report(tenant_id: str, scan_id: str | None = None) -> dict | None:
    if scan_id:
        query = """
                SELECT report_json, report_ref
                FROM scan_reports
                WHERE tenant_id = ? AND scan_id = ?
                """
        params: tuple = (tenant_id, scan_id)
    else:
        query = """
                SELECT report_json, report_ref
                FROM scan_reports
                WHERE tenant_id = ?
                ORDER BY created_at DESC, scan_id DESC
                LIMIT 1
                """
        params = (tenant_id,)
    with _connect() as conn:
        row = conn.execute(query, params).fetchone()
    return _report_body(tenant_id, row) if row else None


_scan_report_rows_cache: dict[tuple[str, str], list[dict]] = {}
_scan_report_rows_order: list[tuple[str, str]] = []
_scan_report_rows_lock = threading.Lock()


_SAMPLE_DATA_PATH = re.compile(
    r"(^|[\\/])enterprise_test_data([\\/]|$)|(^|[\\/])README_enterprise_dataset\.md$|(^|[\\/])_manifest\.json$",
    re.IGNORECASE,
)


def is_sample_data_path(file_obj: dict) -> bool:
    """Whether a file belongs to the bundled synthetic demo dataset."""
    return bool(_SAMPLE_DATA_PATH.search(
        str(file_obj.get("path") or file_obj.get("full_path") or file_obj.get("name") or "")
    ))


def compact_scan_report(report: dict) -> dict:
    """Metadata-only scan payload used by the windowed console.

    Full reports remain available to explicit API callers. The compact form
    preserves summaries and diagnostics but replaces the unbounded file array
    with an omission marker so browsers never deserialise it accidentally.
    """
    files = report.get("files") if isinstance(report, dict) else []
    files = files if isinstance(files, list) else []
    sample_count = sum(1 for file_obj in files if is_sample_data_path(file_obj))
    return compact_scan_report_from_counts(report, len(files), sample_count)


def compact_scan_report_from_counts(report: dict, file_count: int, sample_count: int) -> dict:
    """``compact_scan_report`` for a report whose files were counted, not held.

    A partitioned scan never has its files in one list; finalize counts them as it
    folds the report sections and builds the same compact form from the counts.
    """
    compact = dict(report or {})
    records = int(file_count or 0)
    file_count = records or int((compact.get("summary") or {}).get("total_files") or 0)
    compact["files"] = []
    compact["files_omitted"] = True
    compact["file_count"] = file_count
    compact["result_file_count"] = file_count
    compact["result_truncated"] = bool(file_count)
    compact["is_demo_sample"] = bool(compact.get("is_demo_sample") or (records and sample_count / records >= 0.5))
    return compact


def _packed_compact_report(report: dict):
    try:
        return pack_json_text(json.dumps(compact_scan_report(report), ensure_ascii=False, separators=(",", ":")))
    except Exception as exc:  # pragma: no cover - best effort, the reader falls back
        logger.warning("Compact scan report not stored: %s", type(exc).__name__)
        return None


@_tenant_scoped
def read_scan_report_compact(tenant_id: str, scan_id: str | None = None) -> dict | None:
    """The report without its files. Served from the stored form when the run
    has one; otherwise built from the full report once and stored, so the
    decrypt-and-parse happens once per run rather than once per boot."""
    with _connect() as conn:
        if scan_id:
            row = conn.execute(
                "SELECT scan_id, compact_json FROM scan_reports WHERE tenant_id = ? AND scan_id = ?",
                (tenant_id, scan_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT scan_id, compact_json FROM scan_reports WHERE tenant_id = ? "
                "ORDER BY created_at DESC, scan_id DESC LIMIT 1",
                (tenant_id,),
            ).fetchone()
    if row is None:
        return None
    if row["compact_json"] is not None:
        try:
            stored = json.loads(unpack_json_text(row["compact_json"]) or "")
            if isinstance(stored, dict) and stored:
                return stored
        except (json.JSONDecodeError, TypeError):
            pass
    report = read_scan_report(tenant_id, str(row["scan_id"]))
    if report is None:
        return None
    compact = compact_scan_report(report)
    with suppress(Exception):
        with _connect() as conn:
            conn.execute(
                "UPDATE scan_reports SET compact_json = ? WHERE tenant_id = ? AND scan_id = ?",
                (pack_json_text(json.dumps(compact, ensure_ascii=False, separators=(",", ":"))),
                 tenant_id, str(row["scan_id"])),
            )
    return compact


def _packed_report_rows(tenant_id: str, report: dict, rows: list[dict] | None = None):
    """The run's inventory projection, compressed, or None if it cannot be
    built. A failure here must never cost the operator the scan itself: the
    reader falls back to the report exactly as before. `rows`, when the save's
    normalized write already built them, are used as they are."""
    try:
        rows = rows or _scan_report_inventory_rows(tenant_id, report)
    except Exception as exc:  # pragma: no cover - projection is best effort
        logger.warning("Scan-report projection not stored: %s", type(exc).__name__)
        return None
    if not rows:
        return None
    return pack_json_text(json.dumps(rows, ensure_ascii=False, separators=(",", ":")))


def _stored_report_rows(tenant_id: str, scan_id: str) -> list[dict] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT rows_json FROM scan_reports WHERE tenant_id = ? AND scan_id = ?",
            (tenant_id, scan_id),
        ).fetchone()
    if not row or row["rows_json"] is None:
        return None
    try:
        rows = json.loads(unpack_json_text(row["rows_json"]) or "[]")
    except (json.JSONDecodeError, TypeError):
        return None
    return rows if isinstance(rows, list) and rows else None


def _store_report_rows(tenant_id: str, scan_id: str, rows: list[dict]) -> None:
    """Fill the projection for a run saved before this column existed, so the
    2.3-second read happens once per run rather than once per process."""
    if not rows:
        return
    with suppress(Exception):
        with _connect() as conn:
            conn.execute(
                "UPDATE scan_reports SET rows_json = ? WHERE tenant_id = ? AND scan_id = ?",
                (pack_json_text(json.dumps(rows, ensure_ascii=False, separators=(",", ":"))), tenant_id, scan_id),
            )


def _scan_report_rows_cache_max() -> int:
    try:
        return max(0, min(int(os.getenv("DSPM_SCAN_REPORT_ROWS_CACHE", "4")), 32))
    except ValueError:
        return 4


def _forget_scan_report_rows(tenant_id: str | None = None) -> None:
    with _scan_report_rows_lock:
        if tenant_id is None:
            _scan_report_rows_cache.clear()
            _scan_report_rows_order.clear()
            return
        for key in [item for item in _scan_report_rows_cache if item[0] == tenant_id]:
            _scan_report_rows_cache.pop(key, None)
            if key in _scan_report_rows_order:
                _scan_report_rows_order.remove(key)


def _cached_scan_report_rows(tenant_id: str, scan_id: str, build) -> list[dict]:
    """Memoise one run's inventory projection. A saved run never changes, and a
    re-save of the same scan id invalidates through `_forget_scan_report_rows`."""
    limit = _scan_report_rows_cache_max()
    key = (str(tenant_id), str(scan_id or ""))
    if not limit or not key[1]:
        return build()
    with _scan_report_rows_lock:
        cached = _scan_report_rows_cache.get(key)
        if cached is not None:
            _scan_report_rows_order.remove(key)
            _scan_report_rows_order.append(key)
            return cached
    rows = build()
    with _scan_report_rows_lock:
        _scan_report_rows_cache[key] = rows
        if key in _scan_report_rows_order:
            _scan_report_rows_order.remove(key)
        _scan_report_rows_order.append(key)
        while len(_scan_report_rows_order) > limit:
            _scan_report_rows_cache.pop(_scan_report_rows_order.pop(0), None)
    return rows


@_tenant_scoped
def latest_scan_id_by_label(tenant_id: str, scan_label: str) -> str:
    """The newest saved run for one configured scan name, as an id.

    Separated from reading the report so the caller can check its cache before
    paying for an 8MB decrypt and parse.
    """
    label = str(scan_label or "").strip()[:80]
    if not label:
        return ""
    with _connect() as conn:
        row = conn.execute(
            "SELECT scan_id FROM scan_reports WHERE tenant_id = ? AND scan_label = ? "
            "ORDER BY created_at DESC, scan_id DESC LIMIT 1",
            (tenant_id, label),
        ).fetchone()
        if row is None:
            row = conn.execute(
                "SELECT scan_id FROM scan_reports WHERE tenant_id = ? AND lower(scan_label) = ? "
                "ORDER BY created_at DESC, scan_id DESC LIMIT 1",
                (tenant_id, label.lower()),
            ).fetchone()
    return str(row["scan_id"]) if row else ""


@_tenant_scoped
def scan_report_inventory_rows_by_label(tenant_id: str, scan_label: str) -> tuple[str, list[dict]] | None:
    """(scan_id, projected rows) for a configured scan name, or None.

    On a cache hit this costs one indexed lookup; on a miss it falls back to the
    original path - read the report, project it - and remembers the result.
    """
    scan_id = latest_scan_id_by_label(tenant_id, scan_label)
    if not scan_id:
        return None

    def build() -> list[dict]:
        stored = _stored_report_rows(tenant_id, scan_id)
        if stored is not None:
            return stored
        report = read_scan_report(tenant_id, scan_id)
        rows = _scan_report_inventory_rows(tenant_id, report) if report else []
        _store_report_rows(tenant_id, scan_id, rows)
        return rows

    return scan_id, _cached_scan_report_rows(tenant_id, scan_id, build)


@_tenant_scoped
def read_latest_scan_report_by_label(tenant_id: str, scan_label: str) -> dict | None:
    """Return the newest persisted run for one configured scan name.

    A scan label is attached to a run, while the normalized ``assets`` table is
    a current-estate projection.  Looking up the report is therefore the only
    correct way to show a selected scan after a newer run has updated the same
    assets (or when demo assets are intentionally excluded from the estate).
    """
    label = str(scan_label or "").strip()[:80]
    if not label:
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT report_json, report_ref FROM scan_reports "
            "WHERE tenant_id = ? AND scan_label = ? "
            "ORDER BY created_at DESC, scan_id DESC LIMIT 1",
            (tenant_id, label),
        ).fetchone()
        if row is None:
            # Be forgiving of a case-only profile rename while keeping the
            # indexed, exact-name lookup as the normal fast path.
            row = conn.execute(
                "SELECT report_json, report_ref FROM scan_reports "
                "WHERE tenant_id = ? AND lower(scan_label) = ? "
                "ORDER BY created_at DESC, scan_id DESC LIMIT 1",
                (tenant_id, label.lower()),
            ).fetchone()
    return _report_body(tenant_id, row) if row else None


def update_finding_workflow(tenant_id: str, scan_id: str, selector: dict, update: dict, actor: str) -> dict | None:
    allowed_statuses = {
        "unreviewed",
        "confirmed",
        "false_positive",
        "suppressed",
        "risk_accepted",
        "resolved",
        "reopened",
    }
    report = read_scan_report(tenant_id, scan_id)
    if not report:
        return None

    file_path = str(selector.get("path") or "")
    finding_type = str(selector.get("type") or "")
    fingerprint = str(selector.get("fingerprint") or "")
    target_file = None
    target_finding = None
    for file_obj in report.get("files") or []:
        if file_path and str(file_obj.get("path") or "") != file_path:
            continue
        for finding in file_obj.get("findings") or []:
            if finding_type and str(finding.get("type") or "") != finding_type:
                continue
            fingerprints = [str(item) for item in finding.get("secure_fingerprints") or []]
            if fingerprint and fingerprint not in fingerprints:
                continue
            target_file = file_obj
            target_finding = finding
            break
        if target_finding:
            break
    if target_finding is None:
        return None

    now = datetime.now(timezone.utc).isoformat()
    status = str(update.get("review_status") or update.get("status") or "").strip().lower()
    if status:
        if status not in allowed_statuses:
            raise ValueError("Unsupported finding workflow status")
        target_finding["review_status"] = status
    if "exception_status" in update:
        target_finding["exception_status"] = str(update.get("exception_status") or "").strip() or target_finding.get("exception_status", "not_required")
    if "exception_reason" in update:
        target_finding["exception_reason"] = str(update.get("exception_reason") or "").strip()
    if "owner" in update:
        target_finding["owner"] = str(update.get("owner") or "").strip()
    if "due_date" in update:
        target_finding["due_date"] = str(update.get("due_date") or "").strip()
    if "sla" in update:
        target_finding["sla"] = str(update.get("sla") or "").strip()
    if status == "suppressed":
        target_finding["display_state"] = "suppressed"
    elif status == "reopened":
        target_finding["display_state"] = "primary"
    event = {
        "timestamp": now,
        "actor": actor,
        "action": str(update.get("action") or status or "update"),
        "status": target_finding.get("review_status", "unreviewed"),
        "comment": str(update.get("comment") or "").strip(),
    }
    target_finding.setdefault("status_history", []).append(event)
    target_finding["updated_at"] = now
    save_scan_history(tenant_id, report)
    audit(
        tenant_id,
        actor,
        "finding.workflow_updated",
        {
            "scan_id": scan_id,
            "path": target_file.get("path") if target_file else file_path,
            "type": target_finding.get("type"),
            "status": target_finding.get("review_status"),
        },
    )
    return target_finding


FINDING_LIFECYCLE_STATUSES = {
    "NEW",
    "OPEN",
    "UNDER_REVIEW",
    "CONFIRMED",
    "ASSIGNED",
    "IN_PROGRESS",
    "PENDING_VALIDATION",
    "RESOLVED",
    "REOPENED",
    "FALSE_POSITIVE",
    "SUPPRESSED",
    "RISK_ACCEPTED",
}

REMEDIATION_STATUS_GROUPS: dict[str, tuple[str, ...]] = {
    "open": ("NEW", "OPEN", "UNDER_REVIEW", "CONFIRMED", "REOPENED"),
    "in_progress": ("ASSIGNED", "IN_PROGRESS"),
    "validation": ("PENDING_VALIDATION",),
    "resolved": ("RESOLVED",),
    "exceptions": ("RISK_ACCEPTED", "SUPPRESSED", "FALSE_POSITIVE"),
}
REMEDIATION_ACTIVE_STATUSES = (
    *REMEDIATION_STATUS_GROUPS["open"],
    *REMEDIATION_STATUS_GROUPS["in_progress"],
    *REMEDIATION_STATUS_GROUPS["validation"],
)
REMEDIATION_SORTS: dict[str, tuple[str, bool, str]] = {
    "risk_score": ("risk_score", False, "DESC"),
    "severity": ("severity_rank", False, "DESC"),
    "last_seen": ("COALESCE(last_seen, '')", True, "DESC"),
    "sla_due": ("COALESCE(NULLIF(sla_due, ''), '9999-12-31T23:59:59+00:00')", True, "ASC"),
    "status": ("COALESCE(status, '')", True, "ASC"),
    "finding_name": ("COALESCE(display_name, '')", True, "ASC"),
    # Everything the table puts in a column can order it. `category` is the
    # canonical risk category the Risk-category filter already reads.
    # The same expression the row builder shows as `finding_category`, so the
    # order matches the column rather than a field behind it.
    "category": ("COALESCE(NULLIF(category, ''), data_type, '')", True, "ASC"),
    "data_type": ("COALESCE(data_type, '')", True, "ASC"),
    "asset": ("COALESCE(affected_asset, '')", True, "ASC"),
    "owner": ("COALESCE(owner, '')", True, "ASC"),
}
_REMEDIATION_CURSOR_VERSION = "rf-v1"
_remediation_cache: dict[tuple, tuple[float, dict]] = {}
_remediation_total_cache: dict[tuple, tuple[float, int]] = {}
_remediation_cache_lock = threading.Lock()


def _invalidate_remediation_query_cache(tenant_id: str | None = None) -> None:
    with _remediation_cache_lock:
        if tenant_id is None:
            _remediation_cache.clear()
            _remediation_total_cache.clear()
            return
        for key in [item for item in _remediation_cache if item[1] == tenant_id]:
            _remediation_cache.pop(key, None)
        for key in [item for item in _remediation_total_cache if item[1] == tenant_id]:
            _remediation_total_cache.pop(key, None)


def remediation_statuses(value: str = "") -> tuple[str, ...]:
    """One canonical lifecycle grouping used by queries, metrics and clients.

    Several groups can be asked for at once - "open" and "in progress" is a
    reasonable question - so this unions them. "all" anywhere means no filter
    at all, because a set that contains everything is not a filter.
    """
    # Split here rather than through filter_values: "all" is a real group
    # name in this facet, and the splitter drops it as the absence of a filter.
    raw = value if isinstance(value, (list, tuple, set)) else str(value or "").split(",")
    keys = [str(part).strip().lower().replace("-", "_") for part in raw][:20]
    keys = [key for key in keys if key]
    if not keys or "all" in keys:
        return ()
    statuses: list[str] = []
    for key in keys:
        if key == "active":
            group: tuple[str, ...] = REMEDIATION_ACTIVE_STATUSES
        elif key in REMEDIATION_STATUS_GROUPS:
            group = tuple(REMEDIATION_STATUS_GROUPS[key])
        else:
            exact = key.upper()
            group = (exact,) if exact in FINDING_LIFECYCLE_STATUSES else ()
        for status in group:
            if status not in statuses:
                statuses.append(status)
    return tuple(statuses)


def _remediation_scope(scope: str) -> str:
    value = str(scope or "current").strip().lower()
    return value if value in {"current", "historical", "all"} else "current"


def _remediation_scope_sql(scope: str) -> tuple[list[str], list]:
    clauses: list[str] = []
    params: list = []
    normalized = _remediation_scope(scope)
    if normalized == "current":
        clauses.append("is_current = 1")
    elif normalized == "historical":
        clauses.append("is_current = 0")
    return clauses, params


def _remediation_filter_sql(filters: dict) -> tuple[list[str], list]:
    clauses, params = _remediation_scope_sql(filters.get("scope", "current"))
    statuses = remediation_statuses(filters.get("status", ""))
    if statuses:
        clauses.append(f"status IN ({','.join('?' for _ in statuses)})")
        params.extend(statuses)
    severities = [value for value in filter_values(filters.get("severity"), upper=True)
                  if value in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}]
    if severities:
        clauses.append(f"severity IN ({','.join('?' for _ in severities)})")
        params.extend(severities)
    owners = filter_values(filters.get("owner"))
    if owners:
        owner_clauses = []
        for owner in owners:
            if owner == "__unassigned__":
                owner_clauses.append("owner = ''")
            else:
                owner_clauses.append("owner = ?")
                params.append(owner)
        clauses.append(f"({' OR '.join(owner_clauses)})")
    frameworks = filter_values(filters.get("framework"), lower=True)
    if frameworks:
        framework_clauses = []
        for framework in frameworks:
            if db.is_postgres():
                framework_clauses.append("jsonb_exists(COALESCE(frameworks_json, '[]')::jsonb, ?)")
                params.append(framework)
            else:
                framework_clauses.append("lower(frameworks_json) LIKE ? ESCAPE '\\'")
                params.append(f'%"{_like_escape(framework)}"%')
        clauses.append(f"({' OR '.join(framework_clauses)})")
    data_types = filter_values(filters.get("data_type"))
    if data_types:
        clauses.append(f"data_type IN ({','.join('?' for _ in data_types)})")
        params.extend(data_types)
    # Comma-separated, because one dashboard category can span several stored
    # ones: "regulated personal data" is pii, government_ids and biometric_data
    # together, and splitting it into three clicks would be three answers to
    # one question.
    categories = filter_values(filters.get("category"))
    if categories:
        clauses.append(f"category IN ({','.join('?' for _ in categories)})")
        params.extend(categories)
    assets = filter_values(filters.get("asset"))
    if assets:
        asset_clauses = []
        for asset in assets:
            asset_clauses.append("(asset_id = ? OR affected_asset = ?)")
            params.extend((asset, asset))
        clauses.append(f"({' OR '.join(asset_clauses)})")
    # SLA states are windows on one column, so several ticked states are a
    # union of windows rather than an intersection that could match nothing.
    now = datetime.now(timezone.utc)
    now_text = now.isoformat()
    soon_text = (now + timedelta(hours=24)).isoformat()
    sla_clauses = []
    for sla in filter_values(filters.get("sla"), upper=True):
        if sla == "OVERDUE":
            sla_clauses.append(
                f"(sla_due <> '' AND sla_due < ? AND status IN ({','.join('?' for _ in REMEDIATION_ACTIVE_STATUSES)}))")
            params.extend((now_text, *REMEDIATION_ACTIVE_STATUSES))
        elif sla == "DUE_SOON":
            sla_clauses.append("(sla_due >= ? AND sla_due <= ?)")
            params.extend((now_text, soon_text))
        elif sla == "ON_TRACK":
            sla_clauses.append("sla_due > ?")
            params.append(soon_text)
        elif sla == "NO_SLA":
            sla_clauses.append("sla_due = ''")
    if sla_clauses:
        clauses.append(f"({' OR '.join(sla_clauses)})")
    query = str(filters.get("q") or "").strip().lower()
    if query:
        clauses.append("lower(search_text) LIKE ? ESCAPE '\\'")
        params.append(f"%{_like_escape(query)}%")
    return clauses, params


def _encode_remediation_cursor(sort: str, direction: str, value, finding_id: str) -> str:
    raw = json.dumps([_REMEDIATION_CURSOR_VERSION, sort, direction, value, finding_id], ensure_ascii=False)
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def _decode_remediation_cursor(cursor: str, sort: str, direction: str, is_text: bool):
    if not cursor:
        return None
    try:
        version, cursor_sort, cursor_direction, value, finding_id = json.loads(
            base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
        )
        if version != _REMEDIATION_CURSOR_VERSION or cursor_sort != sort or cursor_direction != direction:
            return None
        if not isinstance(finding_id, str) or not finding_id:
            return None
        if is_text and not isinstance(value, str):
            return None
        if not is_text and (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)):
            return None
        return value, finding_id
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _remediation_row(row) -> dict:
    frameworks = _decode_string_list(row["frameworks_json"])
    severity = str(row["severity"] or "LOW")
    # A finding row carries its own risk story, so a report does not have to
    # open one detail blob per finding to print why it matters and what to do.
    signal = {
        "type": str(row["rule"] or ""),
        "label": str(row["display_name"] or row["rule"] or ""),
        "description": str(row["display_name"] or row["rule"] or ""),
        "category": str(row["category"] or ""),
        "framework": frameworks[0] if frameworks else str(row["framework"] or ""),
        "count": int(row["occurrence_count"] or 1),
    }
    return {
        "reason": finding_reason(signal),
        "recommendation": finding_recommendation(signal, severity),
        "finding_id": str(row["id"] or ""),
        "asset_id": str(row["asset_id"] or ""),
        "severity": str(row["severity"] or "LOW"),
        "risk": str(row["severity"] or "LOW"),
        "risk_score": int(row["risk_score"] or 0),
        "display_name": str(row["display_name"] or row["rule"] or "Finding"),
        "type": str(row["rule"] or ""),
        "technical_type": str(row["rule"] or ""),
        "data_type": str(row["data_type"] or "Unclassified"),
        "finding_category": str(row["category"] or row["data_type"] or ""),
        "framework": frameworks[0] if frameworks else str(row["framework"] or "standard_scan"),
        "frameworks": frameworks,
        "affected_asset": str(row["affected_asset"] or row["asset_id"] or ""),
        "exposure": str(row["exposure"] or ""),
        "owner": str(row["owner"] or ""),
        "status": str(row["status"] or "OPEN"),
        "sla_due": str(row["sla_due"] or ""),
        "last_seen": str(row["last_seen"] or ""),
        "occurrence_count": int(row["occurrence_count"] or 0),
        "confidence": int(row["confidence"] or 0),
        "scope": "current" if int(row["is_current"] or 0) else "historical",
        "file": {
            "name": str(row["file_name"] or ""),
            "path": str(row["file_path"] or ""),
            "source": str(row["source"] or ""),
        },
    }


def _remediation_framework_metric_rows(conn, tenant_id: str, scope_where: list[str], scope_params: list):
    where = " AND ".join(["f.tenant_id = ?", *[f"f.{clause}" for clause in scope_where]])
    params = (tenant_id, *scope_params)
    if db.is_postgres():
        return conn.execute(
            "SELECT item.value AS value, COUNT(*) AS n, COALESCE(SUM(f.occurrence_count), 0) AS occurrences "
            "FROM findings AS f CROSS JOIN LATERAL "
            "jsonb_array_elements_text(COALESCE(f.frameworks_json, '[]')::jsonb) AS item(value) "
            f"WHERE {where} GROUP BY item.value",
            params,
        ).fetchall()
    return conn.execute(
        "SELECT item.value AS value, COUNT(*) AS n, COALESCE(SUM(f.occurrence_count), 0) AS occurrences "
        "FROM findings AS f, json_each(COALESCE(f.frameworks_json, '[]')) AS item "
        f"WHERE {where} GROUP BY item.value",
        params,
    ).fetchall()


def posture_inputs(tenant_id: str) -> dict:
    """The posture measurements, shared between backends (B3.1).

    Three O(estate) aggregates that every console refresh asks for, on every backend,
    while a scan is writing. The answer is kept in `derived_cache` for the estate
    generation it describes, so a second backend reads one row instead of running them.
    `DSPM_LIVE_CACHE=0` makes it the plain database read it always was.
    """
    from backend import live_cache

    return live_cache.cached_json(tenant_id, "posture_inputs", None, lambda: _posture_inputs(tenant_id))


def _posture_inputs(tenant_id: str) -> dict:
    """The four measurements the posture score is made of, from the estate.

    Three aggregates, all index-served. They come from the normalized tables
    rather than from a scan report because posture is a statement about the
    ESTATE - a report covers one scan, and a console that scored the last scan
    could be improved by scanning a smaller folder.

    A severity-less asset (risk_level NONE - inventory, no signal) counts in
    `analysed_files` and nowhere else: it is what was looked at, and it is the
    denominator that makes the score comparable across estates of any size.
    """

    active = ", ".join("?" for _ in REMEDIATION_ACTIVE_STATUSES)
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        estate = conn.execute(
            "SELECT COUNT(*) AS analysed, "
            "SUM(CASE WHEN finding_count > 0 THEN 1 ELSE 0 END) AS sensitive, "
            "SUM(CASE WHEN is_protected = 1 THEN 1 ELSE 0 END) AS uninspected "
            "FROM assets WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        severity = conn.execute(
            "SELECT risk_level, COUNT(*) AS n FROM assets "
            "WHERE tenant_id = ? AND COALESCE(risk_level, '') NOT IN ('', ?) "
            "GROUP BY risk_level",
            (tenant_id, SEVERITYLESS_RISK_LEVEL),
        ).fetchall()
        # Exposure is a property of the FINDING (the canonical model records the
        # ACL breadth that applied when it was seen), counted over distinct
        # files so one file with six findings is one exposed file.
        work = conn.execute(
            "SELECT COUNT(DISTINCT CASE WHEN exposure IN ('PUBLIC', 'BROAD_INTERNAL', 'WRITABLE_INTERNAL') "
            "THEN asset_id END) AS exposed, "
            f"SUM(CASE WHEN status IN ({active}) THEN 1 ELSE 0 END) AS active_n, "
            f"SUM(CASE WHEN status IN ({active}) AND COALESCE(sla_due, '') <> '' "
            "AND sla_due < ? THEN 1 ELSE 0 END) AS overdue_n "
            "FROM findings WHERE tenant_id = ? AND is_current = 1",
            (*REMEDIATION_ACTIVE_STATUSES, *REMEDIATION_ACTIVE_STATUSES, now, tenant_id),
        ).fetchone()

    def _value(row, key) -> int:
        return int((row[key] if row else 0) or 0)

    return {
        "analysed_files": _value(estate, "analysed"),
        "findings_by_severity": {
            str(row["risk_level"]).lower(): int(row["n"] or 0) for row in severity if row["risk_level"]
        },
        "sensitive_files": _value(estate, "sensitive"),
        "exposed_sensitive_files": min(_value(work, "exposed"), _value(estate, "sensitive")),
        "active_findings": _value(work, "active_n"),
        "overdue_findings": _value(work, "overdue_n"),
        "uninspected_files": _value(estate, "uninspected"),
    }


def remediation_summary(tenant_id: str, scope: str = "current") -> dict:
    normalized_scope = _remediation_scope(scope)
    cache_key = (str(DB_PATH), tenant_id, normalized_scope, "summary")
    now_mono = time.monotonic()
    with _remediation_cache_lock:
        cached = _remediation_cache.get(cache_key)
        if cached and now_mono - cached[0] <= 15.0:
            return dict(cached[1])
    scope_where, scope_params = _remediation_scope_sql(normalized_scope)
    where = " AND ".join(["tenant_id = ?", *scope_where])
    open_values = ",".join(f"'{value}'" for value in REMEDIATION_STATUS_GROUPS["open"])
    progress_values = ",".join(f"'{value}'" for value in REMEDIATION_STATUS_GROUPS["in_progress"])
    validation_values = ",".join(f"'{value}'" for value in REMEDIATION_STATUS_GROUPS["validation"])
    active_values = ",".join(f"'{value}'" for value in REMEDIATION_ACTIVE_STATUSES)
    with _connect() as conn:
        affected_row = conn.execute(
            f"SELECT COUNT(DISTINCT asset_id) AS n FROM findings WHERE {where} AND status IN ({active_values})",
            (tenant_id, *scope_params),
        ).fetchone()
        row = conn.execute(
            "SELECT COUNT(*) AS total_findings, COALESCE(SUM(occurrence_count), 0) AS total_occurrences, "
            f"SUM(CASE WHEN status IN ({active_values}) THEN 1 ELSE 0 END) AS active_findings, "
    
            f"SUM(CASE WHEN status IN ({open_values}) THEN 1 ELSE 0 END) AS open_n, "
            f"SUM(CASE WHEN status IN ({progress_values}) THEN 1 ELSE 0 END) AS progress_n, "
            f"SUM(CASE WHEN status IN ({validation_values}) THEN 1 ELSE 0 END) AS validation_n, "
            f"SUM(CASE WHEN status IN ({active_values}) AND sla_due <> '' AND sla_due < ? THEN 1 ELSE 0 END) AS overdue_n, "
            "SUM(CASE WHEN status = 'RESOLVED' THEN 1 ELSE 0 END) AS resolved_n, "
            "SUM(CASE WHEN status = 'RISK_ACCEPTED' THEN 1 ELSE 0 END) AS risk_accepted_n, "
            "SUM(CASE WHEN status = 'SUPPRESSED' THEN 1 ELSE 0 END) AS suppressed_n, "
            "SUM(CASE WHEN status = 'FALSE_POSITIVE' THEN 1 ELSE 0 END) AS false_positive_n "
            f"FROM findings WHERE {where}",
            (datetime.now(timezone.utc).isoformat(), tenant_id, *scope_params),
        ).fetchone()
        status_rows = conn.execute(
            f"SELECT status, COUNT(*) AS n FROM findings WHERE {where} GROUP BY status",
            (tenant_id, *scope_params),
        ).fetchall()
        severity_rows = conn.execute(
            f"SELECT severity, COUNT(*) AS n FROM findings WHERE {where} GROUP BY severity",
            (tenant_id, *scope_params),
        ).fetchall()
        framework_rows = _remediation_framework_metric_rows(conn, tenant_id, scope_where, scope_params)
    summary = {
        "scope": normalized_scope,
        "total_findings": int((row["total_findings"] if row else 0) or 0),
        "total_occurrences": int((row["total_occurrences"] if row else 0) or 0),
        "active_findings": int((row["active_findings"] if row else 0) or 0),
        "affected_files": int((affected_row["n"] if affected_row else 0) or 0),
        "open": int((row["open_n"] if row else 0) or 0),
        "in_progress": int((row["progress_n"] if row else 0) or 0),
        "pending_validation": int((row["validation_n"] if row else 0) or 0),
        "overdue": int((row["overdue_n"] if row else 0) or 0),
        "resolved": int((row["resolved_n"] if row else 0) or 0),
        "risk_accepted": int((row["risk_accepted_n"] if row else 0) or 0),
        "suppressed": int((row["suppressed_n"] if row else 0) or 0),
        "false_positive": int((row["false_positive_n"] if row else 0) or 0),
        "findings_by_status": {str(item["status"] or "OPEN"): int(item["n"] or 0) for item in status_rows},
        "findings_by_severity": {str(item["severity"] or "LOW"): int(item["n"] or 0) for item in severity_rows},
        "findings_by_framework": {
            str(item["value"]): {"finding_count": int(item["n"] or 0), "occurrence_count": int(item["occurrences"] or 0)}
            for item in framework_rows if item["value"]
        },
        "status_groups": {key: list(values) for key, values in REMEDIATION_STATUS_GROUPS.items()},
    }
    with _remediation_cache_lock:
        _remediation_cache[cache_key] = (now_mono, dict(summary))
    return summary


def _remediation_facets(tenant_id: str, scope: str) -> dict:
    normalized_scope = _remediation_scope(scope)
    cache_key = (str(DB_PATH), tenant_id, normalized_scope, "facets")
    now_mono = time.monotonic()
    with _remediation_cache_lock:
        cached = _remediation_cache.get(cache_key)
        if cached and now_mono - cached[0] <= 15.0:
            return dict(cached[1])
    scope_where, scope_params = _remediation_scope_sql(normalized_scope)
    where = " AND ".join(["tenant_id = ?", *scope_where])
    with _connect() as conn:
        def values(column: str, limit: int = 250, include_empty: bool = False) -> list[dict]:
            nonempty = "" if include_empty else f"AND {column} <> ''"
            rows = conn.execute(
                f"SELECT {column} AS value, COUNT(*) AS n FROM findings WHERE {where} "
                f"{nonempty} GROUP BY {column} ORDER BY n DESC, {column} ASC LIMIT ?",
                (tenant_id, *scope_params, limit),
            ).fetchall()
            return [
                {"value": str(row["value"] or "") or "__unassigned__", "count": int(row["n"] or 0)}
                for row in rows
            ]
        framework_rows = _remediation_framework_metric_rows(conn, tenant_id, scope_where, scope_params)
        facets = {
            "severities": values("severity", 10),
            "statuses": values("status", 20),
            "owners": values("owner", include_empty=True),
            "categories": values("category"),
            "data_types": values("data_type"),
            "assets": values("affected_asset"),
            "frameworks": [{"value": str(row["value"]), "count": int(row["n"] or 0)} for row in framework_rows if row["value"]],
        }
    with _remediation_cache_lock:
        _remediation_cache[cache_key] = (now_mono, dict(facets))
    return facets


def _remediation_filtered_total(conn, tenant_id: str, where: str, params: list) -> int:
    cache_key = (str(DB_PATH), tenant_id, where, tuple(params))
    now_mono = time.monotonic()
    with _remediation_cache_lock:
        cached = _remediation_total_cache.get(cache_key)
        if cached and now_mono - cached[0] <= 15.0:
            return cached[1]
        if cached:
            _remediation_total_cache.pop(cache_key, None)
    total = int(conn.execute(f"SELECT COUNT(*) AS n FROM findings WHERE {where}", tuple(params)).fetchone()["n"] or 0)
    with _remediation_cache_lock:
        _remediation_total_cache[cache_key] = (now_mono, total)
        if len(_remediation_total_cache) > 512:
            oldest = min(_remediation_total_cache, key=lambda item: _remediation_total_cache[item][0])
            _remediation_total_cache.pop(oldest, None)
    return total


def list_remediation_findings(
    tenant_id: str, *, scope: str = "current", status: str = "active", severity: str = "",
    owner: str = "", framework: str = "", data_type: str = "", asset: str = "", sla: str = "",
    category: str = "", q: str = "", sort: str = "risk_score", direction: str = "",
    after: str = "", limit: int = 50,
) -> dict:
    """Server-filtered, keyset-paginated lightweight finding page plus metrics."""
    normalized_scope = _remediation_scope(scope)
    sort_key = sort if sort in REMEDIATION_SORTS else "risk_score"
    expression, is_text, default_direction = REMEDIATION_SORTS[sort_key]
    requested_direction = str(direction or "").strip().upper()
    sort_direction = requested_direction if requested_direction in {"ASC", "DESC"} else default_direction
    expression = db.collate_c(expression) if is_text else expression
    page_size = max(1, min(int(limit or 50), 200))
    filters = {
        "scope": normalized_scope, "status": status, "severity": severity, "owner": owner,
        "framework": framework, "data_type": data_type, "asset": asset, "sla": sla, "q": q,
        "category": category,
    }
    clauses, params = _remediation_filter_sql(filters)
    where = " AND ".join(["tenant_id = ?", *clauses])
    base_params: list = [tenant_id, *params]
    cursor = _decode_remediation_cursor(after, sort_key, sort_direction, is_text)
    page_clauses = list(clauses)
    page_params = list(base_params)
    if cursor:
        value, finding_id = cursor
        operator = ">" if sort_direction == "ASC" else "<"
        page_clauses.append(f"(({expression} {operator} ?) OR ({expression} = ? AND id {operator} ?))")
        page_params.extend((value, value, finding_id))
    page_where = " AND ".join(["tenant_id = ?", *page_clauses])
    with _connect() as conn:
        total = _remediation_filtered_total(conn, tenant_id, where, base_params)
        rows = conn.execute(
            f"SELECT * FROM findings WHERE {page_where} ORDER BY {expression} {sort_direction}, id {sort_direction} LIMIT ?",
            (*page_params, page_size + 1),
        ).fetchall()
    has_more = len(rows) > page_size
    page_rows = rows[:page_size]
    next_cursor = None
    if has_more and page_rows:
        last = page_rows[-1]
        if sort_key == "severity":
            sort_value = int(last["severity_rank"] or 0)
        elif sort_key == "sla_due":
            sort_value = str(last["sla_due"] or "9999-12-31T23:59:59+00:00")
        else:
            column = {"finding_name": "display_name", "asset": "affected_asset"}.get(sort_key, sort_key)
            sort_value = str(last[column] or "") if is_text else int(last[column] or 0)
        next_cursor = _encode_remediation_cursor(sort_key, sort_direction, sort_value, str(last["id"] or ""))
    items = [_remediation_row(row) for row in page_rows]
    return {
        "items": items,
        # Compatibility alias for older clients; it is the same bounded page,
        # never a total and never a bulk export.
        "findings": items,
        "total": total,
        "page_size": page_size,
        "has_more": has_more,
        "next_cursor": next_cursor,
        "scope": normalized_scope,
        "sort": sort_key,
        "direction": sort_direction.lower(),
        "summary": remediation_summary(tenant_id, normalized_scope),
        "facets": _remediation_facets(tenant_id, normalized_scope),
    }


def list_findings(tenant_id: str, status: str = "", limit: int = 200) -> list[dict]:
    """Compatibility wrapper returning one bounded page, never a total count."""
    return list_remediation_findings(
        tenant_id, scope="all", status=status or "all", limit=limit,
    )["items"]


def _list_findings_normalized(tenant_id: str, status: str, limit: int) -> list[dict]:
    return list_findings(tenant_id, status=status, limit=limit)


def _normalized_ready(tenant_id: str) -> bool:
    return _cached_readiness("normalized", tenant_id, lambda: _normalized_ready_uncached(tenant_id))


def _normalized_ready_uncached(tenant_id: str) -> bool:
    """True only when the normalized mirror can be trusted to answer for this
    tenant (F2). Guards the two ways the read-switch could silently return wrong
    data, so on either the caller serves the authoritative blob instead:

      * Completeness - a best-effort dual-write can roll back, leaving the blob
        (scan_reports) with a scan the mirror never received. scan_runs is
        written in the SAME savepoint as finding_index, so a scan_report with no
        matching scan_run proves the mirror is missing that scan's findings.
      * Currency - a change to the response/status logic makes already-stored
        finding_index rows stale; any row not stamped with the current
        FINDING_INDEX_VERSION is from older logic.

    Both are indexed existence probes that short-circuit on the first offender.
    """
    with _connect() as conn:
        incomplete = conn.execute(
            "SELECT 1 FROM scan_reports sr "
            "WHERE sr.tenant_id = ? AND NOT EXISTS ("
            "  SELECT 1 FROM scan_runs r WHERE r.tenant_id = sr.tenant_id AND r.id = sr.scan_id) "
            "LIMIT 1",
            (tenant_id,),
        ).fetchone()
        if incomplete:
            return False
        stale = conn.execute(
            "SELECT 1 FROM finding_index WHERE tenant_id = ? AND index_version <> ? LIMIT 1",
            (tenant_id, FINDING_INDEX_VERSION),
        ).fetchone()
    return stale is None


def _read_from_normalized(tenant_id: str) -> bool:
    return os.getenv("DSPM_READ_FROM_NORMALIZED", "0") == "1" and _normalized_ready(tenant_id)


# ---------------------------------------------------------------------------
# S-C/S-D: cursor-paginated inventory over the S-B `assets` columns, with
# PostgreSQL trigram-indexed substring search.
#
# Mirrors the findings read-switch: served from the normalized `assets` table
# when DSPM_INVENTORY_FROM_NORMALIZED=1 AND the mirror is complete, else from the
# authoritative report blobs (bounded to the 1000 newest scans, like the findings
# fallback). tests/test_inventory_api.py pins the two paths equal (parity).
#
# Keyset (not OFFSET) pagination: WHERE (sort, id) </> cursor ORDER BY sort, id -
# constant cost at any depth. Text ordering uses db.collate_c so Postgres, SQLite
# and the blob path's Python comparison agree byte-for-byte.
# ---------------------------------------------------------------------------

# name -> (column, is_text, default direction). Each supported key may be
# reversed by the caller; defaults keep the first click/operator expectation
# sensible (for example, risk starts most-critical first).
INVENTORY_SORTS: dict[str, tuple[str, bool, str]] = {
    "risk_score": ("risk_score", False, "DESC"),
    "size": ("size", False, "DESC"),
    "finding_count": ("finding_count", False, "DESC"),
    "modified_at": ("modified_at", True, "DESC"),
    "name": ("name", True, "ASC"),
    "source": ("source", True, "ASC"),
    "scan_label": ("scan_label", True, "ASC"),
    "risk_level": ("risk_level", True, "ASC"),
}
_DEFAULT_INVENTORY_SORT = "risk_score"
_INVENTORY_COLS = (
    "id", "source", "path", "name", "extension", "share", "risk_level",
    "risk_score", "size", "owner", "modified_at", "finding_count",
    "top_frameworks", "is_hidden", "is_system", "is_protected",
    "finding_types", "framework_keys", "scan_label",
)
# Persisted per row, so the collapsed table's two numbers cost nothing to read.
_INVENTORY_READ_COLS = (*_INVENTORY_COLS, "reason_count", "dlp_count")
_INVENTORY_COUNT_CAP = 10000
_INVENTORY_CURSOR_VERSION = "sc-v3"
_INVENTORY_COUNT_CACHE_MAX = 256
_inventory_count_cache: dict[tuple, tuple[float, int]] = {}
_inventory_facets_cache: dict[tuple, tuple[float, dict]] = {}
_inventory_query_cache_lock = threading.Lock()


class InventoryReadUnavailable(RuntimeError):
    """Normalized inventory was selected but could not safely serve the read."""


def _invalidate_inventory_query_cache(tenant_id: str | None = None) -> None:
    """Invalidate short-lived inventory aggregates after an authoritative write.

    Every authoritative estate write already calls this - a saved scan (and the finding
    lifecycle updates that re-save one), each partition and the finalize of a
    partitioned scan, a backfill, a tenant's deletion or reset - so the shared cache's
    generation moves here too, and it cannot drift from the per-process caches below.
    """
    with suppress(Exception):
        bump_estate_generation(tenant_id)
    _forget_readiness(tenant_id)
    _forget_scan_report_rows(tenant_id)
    with _inventory_query_cache_lock:
        if tenant_id is None:
            _inventory_count_cache.clear()
            _inventory_facets_cache.clear()
            return
        for key in [item for item in _inventory_count_cache if item[1] == tenant_id]:
            _inventory_count_cache.pop(key, None)
        for key in [item for item in _inventory_facets_cache if item[1] == tenant_id]:
            _inventory_facets_cache.pop(key, None)


def _inventory_count_cache_seconds() -> float:
    try:
        value = float(os.getenv("DSPM_INVENTORY_COUNT_CACHE_SECONDS", "5"))
    except ValueError:
        value = 5.0
    return max(0.0, min(value, 60.0))


def _capped_inventory_total(conn, tenant_id: str, where: list[str], params: list) -> int:
    """Return the capped total while avoiding the same count query on every page.

    The first page computes the bounded count. Cursor pages and rapid back/forward
    navigation reuse it briefly; saves/backfills invalidate it immediately.
    """
    cache_key = (str(DB_PATH), tenant_id, tuple(where), tuple(params))
    now = time.monotonic()
    ttl = _inventory_count_cache_seconds()
    if ttl:
        with _inventory_query_cache_lock:
            cached = _inventory_count_cache.get(cache_key)
            if cached and now - cached[0] <= ttl:
                return cached[1]
            if cached:
                _inventory_count_cache.pop(cache_key, None)

    cap_sql = f"SELECT COUNT(*) FROM (SELECT 1 FROM assets WHERE {' AND '.join(where)} LIMIT ?) t"
    total = int(conn.execute(cap_sql, tuple(params) + (_INVENTORY_COUNT_CAP + 1,)).fetchone()[0])
    if ttl:
        with _inventory_query_cache_lock:
            _inventory_count_cache[cache_key] = (now, total)
            if len(_inventory_count_cache) > _INVENTORY_COUNT_CACHE_MAX:
                oldest = min(_inventory_count_cache, key=lambda item: _inventory_count_cache[item][0])
                _inventory_count_cache.pop(oldest, None)
    return total


_readiness_cache: dict[tuple[str, str], tuple[float, bool]] = {}
_readiness_cache_lock = threading.Lock()


def _readiness_cache_seconds() -> float:
    try:
        value = float(os.getenv("DSPM_READINESS_CACHE_SECONDS", "60"))
    except ValueError:
        value = 60.0
    return max(0.0, min(value, 600.0))


def _cached_readiness(kind: str, tenant_id: str, probe) -> bool:
    ttl = _readiness_cache_seconds()
    if not ttl:
        return probe()
    key = (kind, tenant_id)
    now_mono = time.monotonic()
    with _readiness_cache_lock:
        cached = _readiness_cache.get(key)
        if cached and now_mono - cached[0] <= ttl:
            return cached[1]
    answer = probe()
    with _readiness_cache_lock:
        if len(_readiness_cache) > 256:
            _readiness_cache.clear()
        _readiness_cache[key] = (now_mono, answer)
    return answer


def refresh_read_model_state(tenant_id: str | None = None) -> None:
    """Forget which read model is ready.

    The gate answers "is the normalized mirror complete and current", and every
    in-process transition - a scan save, a backfill - already invalidates it.
    Call this after changing the underlying rows by any other route, including
    from a test or a maintenance script.
    """
    _forget_readiness(tenant_id)


def _forget_readiness(tenant_id: str | None = None) -> None:
    with _readiness_cache_lock:
        if tenant_id is None:
            _readiness_cache.clear()
            return
        for key in [item for item in _readiness_cache if item[1] == tenant_id]:
            _readiness_cache.pop(key, None)


def _inventory_ready(tenant_id: str) -> bool:
    return _cached_readiness("inventory", tenant_id, lambda: _inventory_ready_uncached(tenant_id))


def _inventory_ready_uncached(tenant_id: str) -> bool:
    """True when every persisted scan has been mirrored - a scan_report with no
    matching scan_run means the assets mirror is missing that scan (assets are
    written in the same savepoint as scan_runs)."""
    with _connect() as conn:
        incomplete = conn.execute(
            "SELECT 1 FROM scan_reports sr WHERE sr.tenant_id = ? AND NOT EXISTS ("
            "  SELECT 1 FROM scan_runs r WHERE r.tenant_id = sr.tenant_id AND r.id = sr.scan_id) LIMIT 1",
            (tenant_id,),
        ).fetchone()
        # SQLite's planner otherwise prefers a broad tenant/filter index and then
        # reads every large detail_json value merely to prove no stale row exists.
        # Pin the exact empty-on-healthy index; PostgreSQL uses the combined
        # partial index for the OR predicate (and permits legacy NULL rows).
        if db.is_sqlite():
            stale_detail = conn.execute(
                "SELECT 1 FROM assets INDEXED BY idx_assets_tenant_empty_detail "
                "WHERE tenant_id = ? AND detail_json = '{}' LIMIT 1",
                (tenant_id,),
            ).fetchone()
        else:
            stale_detail = conn.execute(
                "SELECT 1 FROM assets WHERE tenant_id = ? "
                "AND (detail_json IS NULL OR detail_json = '{}') LIMIT 1",
                (tenant_id,),
            ).fetchone()
    return incomplete is None and stale_detail is None


def _read_inventory_from_normalized(tenant_id: str) -> bool:
    # New/fresh installs dual-write complete detail rows, so the indexed path is
    # the safe and fast default. Operators can still force the legacy compatibility
    # path with 0; the readiness gate automatically falls back for old databases
    # until scripts/backfill_normalized.py has completed.
    return os.getenv("DSPM_INVENTORY_FROM_NORMALIZED", "1") != "0" and _inventory_ready(tenant_id)


def inventory_export_ready(tenant_id: str) -> bool:
    """Return whether S-G can export from the bounded normalized read model.

    Export intentionally does not consult ``DSPM_INVENTORY_FROM_NORMALIZED``:
    that flag controls interactive inventory reads and their compatibility blob
    fallback. A streaming export may use the normalized mirror whenever it is
    complete, but it must never fall back to materializing report blobs.
    """
    return _inventory_ready(tenant_id)


def _like_escape(value: str) -> str:
    """Escape LIKE wildcards so a search/framework term matches literally (and so
    the SQL LIKE and the blob path's Python substring test agree)."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _inventory_sort_spec(sort: str, direction: str = "") -> tuple[str, bool, str]:
    column, is_text, default_direction = INVENTORY_SORTS[sort]
    requested = str(direction or "").strip().upper()
    return column, is_text, requested if requested in {"ASC", "DESC"} else default_direction


def _encode_cursor(sort: str, direction: str, sort_value, asset_id: str) -> str:
    raw = json.dumps([_INVENTORY_CURSOR_VERSION, sort, direction, sort_value, asset_id], ensure_ascii=False)
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def _decode_cursor(cursor: str, sort: str, direction: str, is_text: bool):
    """Decode a cursor only when its version, sort, value type and asset id fit.

    Legacy v2 cursors remain valid only for a key's default direction. A cursor
    from the opposite order must restart at page one rather than skip or repeat
    rows after an operator reverses a sort.
    """
    if not cursor:
        return None
    try:
        decoded = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8"))
        if isinstance(decoded, list) and len(decoded) == 5:
            version, cursor_sort, cursor_direction, value, asset_id = decoded
            if version != _INVENTORY_CURSOR_VERSION or cursor_sort != sort:
                return None
            if cursor_direction != direction:
                return None
        elif isinstance(decoded, list) and len(decoded) == 4:
            version, cursor_sort, value, asset_id = decoded
            if version != "sc-v2" or cursor_sort != sort or direction != INVENTORY_SORTS[sort][2]:
                return None
        elif isinstance(decoded, list) and len(decoded) == 2:
            value, asset_id = decoded
            if direction != INVENTORY_SORTS[sort][2]:
                return None
        else:
            return None
        asset_id = str(asset_id)
        if not re.fullmatch(r"[0-9a-f]{24}", asset_id):
            return None
        if is_text:
            if not isinstance(value, str):
                return None
        elif isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            return None
        return value, asset_id
    except Exception:
        return None  # malformed cursor -> serve the first page rather than error


def filter_values(raw, *, lower: bool = False, upper: bool = False, limit: int = 40) -> list[str]:
    """A filter's selected values, from a comma-separated parameter.

    The console lets an operator tick several boxes in one facet, so every
    filter reads as a list and a single value is simply a list of one. Blank
    and "ALL" entries drop out - "ALL" is the absence of a filter, not a value
    to match - and duplicates collapse, so a repeated tick cannot multiply the
    clauses. The cap is there because the string arrives from a URL.
    """
    if isinstance(raw, (list, tuple, set)):
        parts = [str(item) for item in raw]
    else:
        parts = str(raw or "").split(",")
    seen: list[str] = []
    for part in parts:
        value = part.strip()
        if not value or value.upper() == "ALL":
            continue
        if lower:
            value = value.lower()
        if upper:
            value = value.upper()
        if value not in seen:
            seen.append(value)
        if len(seen) >= limit:
            break
    return seen


_INVENTORY_SOURCE_GROUPS = {
    "scan-kind:file-server": ("local", "smb"),
    "scan-kind:endpoint": ("endpoint", "endpoint-local", "endpoint-winrm"),
}


# Three entries in the Finding type facet are not data classes at all: they
# are the three states the dashboard's Assessment coverage card counts. Locked
# files were already listed this way; "Classified" and "Clear" are the other
# two columns of that card, which had nowhere to send a reader because no
# filter could express "carries at least one finding" or "read successfully
# and found nothing".
INVENTORY_PROTECTED_TYPE = "protected / locked"
INVENTORY_CLASSIFIED_TYPE = "classified"
INVENTORY_CLEAR_TYPE = "clear"


def _inventory_filters(risk: str, source: str, framework: str, q: str, extension: str,
                       protected: bool | None = None, finding_type: str = "") -> dict:
    frameworks = filter_values(framework, lower=True)
    sources = filter_values(source, lower=True)
    # A scan kind expands to the collector sources it covers; a named scan or a
    # raw protocol keeps its exact meaning. Both can be ticked at once.
    source_group: list[str] = []
    plain_sources: list[str] = []
    for value in sources:
        group = _INVENTORY_SOURCE_GROUPS.get(value, ())
        if group:
            source_group.extend(item for item in group if item not in source_group)
        elif value not in plain_sources:
            plain_sources.append(value)
    # Two facet entries are not stored values at all. The Severity list ends
    # with "Protected", and the Finding type list with "Protected / locked" -
    # both are the is_protected flag wearing a costume. A single-select could
    # translate either into `protected=true` and be done; a multi-select
    # cannot, because ticking "Critical" and "Protected" asks for files that
    # are EITHER, and an AND on the flag would answer with almost nothing.
    # So each pseudo-value joins the OR group of the facet it was ticked in,
    # and the standalone `protected` parameter keeps its own AND meaning for
    # the callers that pass it directly.
    risks = filter_values(risk, upper=True)
    protected_risk = "PROTECTED" in risks
    risks = [value for value in risks if value != "PROTECTED"]
    finding_types = filter_values(finding_type, lower=True)
    protected_type = INVENTORY_PROTECTED_TYPE in finding_types
    classified_type = INVENTORY_CLASSIFIED_TYPE in finding_types
    clear_type = INVENTORY_CLEAR_TYPE in finding_types
    finding_types = [value for value in finding_types
                     if value not in (INVENTORY_PROTECTED_TYPE, INVENTORY_CLASSIFIED_TYPE, INVENTORY_CLEAR_TYPE)]
    return {
        "risk": risks[0] if len(risks) == 1 else "",
        "risks": risks,
        "protected_risk": protected_risk,
        "protected_type": protected_type,
        "classified_type": classified_type,
        "clear_type": clear_type,
        "source": plain_sources[0] if len(plain_sources) == 1 else "",
        "sources": plain_sources,
        "source_group": tuple(source_group),
        "extension": "",
        "extensions": filter_values(extension, lower=True),
        "framework": frameworks[0] if len(frameworks) == 1 else "",
        "frameworks": frameworks,
        "finding_type": "",
        "finding_types": finding_types,
        "protected": protected,
        "q": str(q or "").strip().lower(),
    }


def _json_member_pattern(value: str) -> str:
    """LIKE pattern for one exact scalar in a compact JSON string array."""
    encoded = json.dumps(str(value or "").lower(), ensure_ascii=False)
    return f"%{_like_escape(encoded)}%"


def _inventory_normalized_where(tenant_id: str, filt: dict) -> tuple[list[str], list]:
    """Build the shared tenant/filter predicate for inventory reads and exports."""
    where = ["tenant_id = ?"]
    params: list = [tenant_id]
    risks = filt.get("risks") or ([filt["risk"]] if filt.get("risk") else [])
    risk_clauses: list[str] = []
    if risks:
        risk_clauses.append(f"risk_level IN ({', '.join('?' for _ in risks)})")
        params.extend(risks)
    if filt.get("protected_risk"):
        risk_clauses.append("is_protected = 1")
    if risk_clauses:
        where.append(f"({' OR '.join(risk_clauses)})")
    # Ticking a scan kind and a named scan means "either", so the two forms
    # join with OR rather than narrowing each other to nothing.
    source_clauses: list[str] = []
    if filt.get("source_group"):
        source_clauses.append(f"source IN ({', '.join('?' for _ in filt['source_group'])})")
        params.extend(filt["source_group"])
    for value in filt.get("sources") or ([filt["source"]] if filt.get("source") else []):
        # The Source filter accepts either a collector protocol ("smb") or the
        # operator-facing scan name ("HR file share"), so the inventory can be
        # narrowed to one configured scan without a second parameter.
        source_clauses.append("(source = ? OR lower(COALESCE(scan_label, '')) = ?)")
        params.extend([value, value])
    if source_clauses:
        where.append(f"({' OR '.join(source_clauses)})")
    extensions = filt.get("extensions") or ([filt["extension"]] if filt.get("extension") else [])
    if extensions:
        where.append(f"extension IN ({', '.join('?' for _ in extensions)})")
        params.extend(extensions)
    if filt["protected"] is not None:
        where.append("is_protected = ?"); params.append(1 if filt["protected"] else 0)
    # Each selected class stands for every stored spelling of itself, and
    # several selected classes mean "any of these".
    wanted_types: list[str] = []
    for value in filt.get("finding_types") or ([filt["finding_type"]] if filt.get("finding_type") else []):
        for name in finding_type_alias_group(value):
            if name.lower() not in {item.lower() for item in wanted_types}:
                wanted_types.append(name)
    type_clauses = ["lower(COALESCE(finding_types, '[]')) LIKE ? ESCAPE '\\'" for _ in wanted_types]
    params.extend(_json_member_pattern(name) for name in wanted_types)
    if filt.get("protected_type"):
        type_clauses.append("is_protected = 1")
    if filt.get("classified_type"):
        type_clauses.append("COALESCE(finding_count, 0) > 0")
    if filt.get("clear_type"):
        type_clauses.append("(COALESCE(finding_count, 0) = 0 AND is_protected = 0)")
    if type_clauses:
        where.append(f"({' OR '.join(type_clauses)})")
    if filt["frameworks"]:
        clauses = ["lower(COALESCE(framework_keys, '[]')) LIKE ? ESCAPE '\\'" for _ in filt["frameworks"]]
        where.append(f"({' OR '.join(clauses)})")
        params.extend(_json_member_pattern(framework) for framework in filt["frameworks"])
    if filt["q"]:
        if db.is_sqlite() and _sqlite_inventory_fts_enabled and len(filt["q"]) >= 3:
            # A quoted FTS5 trigram phrase is a literal substring query; quoting
            # prevents MATCH operators in user text from becoming query syntax.
            phrase = '"' + filt["q"].replace('"', '""') + '"'
            where.append(
                "rowid IN (SELECT rowid FROM assets_search_fts WHERE search_text MATCH ?)"
            )
            params.append(phrase)
        else:
            # PostgreSQL keeps this expression byte-for-byte aligned with
            # idx_assets_search_trgm. SQLite builds without FTS5 retain parity.
            where.append("lower(COALESCE(search_text, '')) LIKE ? ESCAPE '\\'")
            params.append(f"%{_like_escape(filt['q'])}%")
    return where, params


@_tenant_scoped
def list_inventory(tenant_id: str, *, risk: str = "", source: str = "", framework: str = "",
                   q: str = "", extension: str = "", protected: bool | None = None,
                   finding_type: str = "", sort: str = "risk_score", direction: str = "",
                   cursor: str = "", limit: int = 100) -> dict:
    """One keyset-paginated page of the file inventory. Filters: risk (level),
    source, framework(s, OR), protected state, exact finding type, q
    (search_text), extension. Returns
    {items, next_cursor, has_more, total, total_is_estimate, source}."""
    sort = sort if sort in INVENTORY_SORTS else _DEFAULT_INVENTORY_SORT
    _, _, direction = _inventory_sort_spec(sort, direction)
    limit = max(1, min(int(limit or 100), 500))
    filt = _inventory_filters(risk, source, framework, q, extension, protected, finding_type)
    # A selected operator-facing scan means "show that scan's latest saved
    # result", not "show current assets whose most recent observation still
    # happens to carry this label".  Resolve the immutable run before choosing
    # the current-estate normalized/search paths.
    selected = (scan_report_inventory_rows_by_label(tenant_id, source)
                if source and not filt.get("source_group") else None)
    if selected is not None:
        scan_id, report_rows = selected
        result = _inventory_page_from_rows(
            report_rows, filt, sort, cursor, limit, direction, source_already_matched=True,
        )
        result["source"] = "scan-report"
        result["scan_id"] = scan_id
        result["scan_label"] = str(source or "")
        return result
    # S-F valve: only text searches opt into the dedicated engine. Placeholder
    # inventory browsing keeps S-C keyset pagination. A separate read-enable
    # switch supports backfill/shadow operation before cutover.
    if filt["q"]:
        try:
            from backend.search import SearchUnavailable, external_search_requested, search_inventory

            if external_search_requested():
                col, _, _ = INVENTORY_SORTS[sort]
                return search_inventory(tenant_id, filt, col, direction, cursor, limit)
        except SearchUnavailable as exc:
            logger.warning("Dedicated inventory search unavailable, falling back to DB: %s", exc)
        except Exception as exc:  # pragma: no cover - optional projection guard
            logger.warning("Dedicated inventory search failed, falling back to DB: %s", type(exc).__name__)
    if _read_inventory_from_normalized(tenant_id):
        try:
            result = _list_inventory_normalized(tenant_id, filt, sort, cursor, limit, direction)
            result["source"] = "normalized"
            return result
        except Exception as exc:  # pragma: no cover - operational failure path
            logger.error("Normalized inventory read failed: %s", type(exc).__name__)
            raise InventoryReadUnavailable("Normalized inventory is temporarily unavailable") from exc
    result = _list_inventory_blob(tenant_id, filt, sort, cursor, limit, direction)
    result["source"] = "blob"
    return result


def _list_inventory_normalized(tenant_id: str, filt: dict, sort: str, cursor: str, limit: int, direction: str = "") -> dict:
    col, is_text, direction = _inventory_sort_spec(sort, direction)
    order_expr = db.collate_c(f"COALESCE({col}, '')") if is_text else col
    # Asset ids are fixed lowercase hex, so their order is identical under C and
    # locale collations. Keep the raw column so S-C.1 composite indexes match.
    id_expr = "id"
    op = "<" if direction == "DESC" else ">"

    where, params = _inventory_normalized_where(tenant_id, filt)

    count_where, count_params = list(where), list(params)

    decoded = _decode_cursor(cursor, sort, direction, is_text)
    if decoded is not None:
        cv, cid = decoded
        if db.is_postgres() and not is_text:
            where.append(f"({order_expr}, {id_expr}) {op} (?, ?)")
            params.extend([cv, cid])
        else:
            where.append(
                f"({order_expr} {op} ? OR "
                f"({order_expr} = ? AND {id_expr} {op} ?))"
            )
            params.extend([cv, cv, cid])

    sql = (
        f"SELECT {', '.join(_INVENTORY_READ_COLS)} FROM assets WHERE {' AND '.join(where)} "
        f"ORDER BY {order_expr} {direction}, {id_expr} {direction} LIMIT ?"
    )
    params.append(limit + 1)
    with _connect() as conn:
        rows = conn.execute(sql, tuple(params)).fetchall()
        total = _capped_inventory_total(conn, tenant_id, count_where, count_params)

    return _inventory_page(
        [{c: r[c] for c in _INVENTORY_READ_COLS} for r in rows], sort, col, is_text, limit, total, direction
    )


@_tenant_scoped
def inventory_reason_action_counts(tenant_id: str, ids: list) -> dict:
    """Reason/DLP-action counts for one inventory page, keyed by asset id.

    The windowed list projection deliberately excludes detail_json; the
    collapsed table still owes the operator real numbers, so this fetches just
    the page's blobs and counts in Python (backend-agnostic, page <= 500)."""
    wanted = [str(i) for i in ids if i]
    counts: dict = {}
    if not wanted:
        return counts
    with _connect() as conn:
        for start in range(0, len(wanted), 100):
            chunk = wanted[start:start + 100]
            placeholders = ",".join("?" * len(chunk))
            rows = conn.execute(
                f"SELECT id, detail_json FROM assets WHERE tenant_id = ? AND id IN ({placeholders})",
                (tenant_id, *chunk),
            ).fetchall()
            for row in rows:
                try:
                    risk = (json.loads(unpack_json_text(row["detail_json"]) or "{}") or {}).get("risk") or {}
                    counts[row["id"]] = (len(risk.get("reasons") or []), len(risk.get("dlp_recommendations") or []))
                except Exception:
                    counts[row["id"]] = (0, 0)
    return counts


@_tenant_scoped
def iter_inventory_export_rows(
    tenant_id: str, *, risk: str = "", source: str = "", framework: str = "",
    q: str = "", extension: str = "", protected: bool | None = None,
    finding_type: str = "", batch_size: int = 1_000,
):
    """Yield filtered inventory metadata in bounded, tenant-scoped keyset batches.

    Rows are ordered by ``id ASC`` rather than an interactive display sort so the
    composite assets primary key serves every page. The upper id is captured once,
    which prevents concurrent inserts from extending a long-running export. Each
    batch owns a short-lived connection; closing/cancelling the response therefore
    cannot strand a database cursor or a multi-hour read transaction.

    Callers must check :func:`inventory_export_ready` before starting an HTTP
    response. This function deliberately has no report-blob fallback.
    """
    batch_size = max(10, min(int(batch_size or 1_000), 5_000))
    filt = _inventory_filters(risk, source, framework, q, extension, protected, finding_type)
    base_where, base_params = _inventory_normalized_where(tenant_id, filt)
    # Raw id ordering lets the (tenant_id, id) primary key serve every batch;
    # ids are lowercase hexadecimal and therefore collation-agnostic.
    id_expr = "id"

    with _connect() as conn:
        upper_row = conn.execute(
            f"SELECT id FROM assets WHERE tenant_id = ? ORDER BY {id_expr} DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
    if upper_row is None:
        return
    upper_id = str(upper_row["id"] or "")
    cursor_id = ""

    while True:
        where = list(base_where)
        params = list(base_params)
        where.append(f"{id_expr} > ?")
        params.append(cursor_id)
        where.append(f"{id_expr} <= ?")
        params.append(upper_id)
        params.append(batch_size)
        with _connect() as conn:
            rows = conn.execute(
                f"SELECT {', '.join(_INVENTORY_COLS)} FROM assets "
                f"WHERE {' AND '.join(where)} ORDER BY {id_expr} ASC LIMIT ?",
                tuple(params),
            ).fetchall()
        if not rows:
            return
        for row in rows:
            yield {column: row[column] for column in _INVENTORY_COLS}
        cursor_id = str(rows[-1]["id"] or "")


def _scan_report_inventory_rows(tenant_id: str, report: dict) -> list[dict]:
    """Project one authoritative report into inventory rows with run context."""
    from backend.domain import iter_normalized_assets

    scan_id = str(report.get("scan_id") or "")
    return [_inventory_row(asset, scan_id) for asset in iter_normalized_assets(tenant_id, report)]


def _inventory_row(asset, scan_id: str) -> dict:
    row = {column: getattr(asset, column) for column in _INVENTORY_COLS}
    row["search_text"] = asset.search_text
    row["scan_id"] = scan_id
    row["reason_count"], row["dlp_count"] = asset.reason_count, asset.dlp_count
    return row


def _inventory_page_from_rows(
    rows: list[dict], filt: dict, sort: str, cursor: str, limit: int, direction: str = "", *, source_already_matched: bool = False,
) -> dict:
    """Apply the parity-safe inventory filters/sort/cursor to projected rows."""
    col, is_text, direction = _inventory_sort_spec(sort, direction)
    reverse = direction == "DESC"

    def _matches(row: dict) -> bool:
        risks = filt.get("risks") or ([filt["risk"]] if filt.get("risk") else [])
        if risks or filt.get("protected_risk"):
            if not (str(row.get("risk_level") or "") in risks
                    or (filt.get("protected_risk") and bool(row.get("is_protected")))):
                return False
        source_values = {str(row.get("source") or "").lower(), str(row.get("scan_label") or "").lower()}
        wanted_sources = set(filt.get("source_group") or ()) | set(filt.get("sources") or [])
        if wanted_sources and not source_already_matched and not (wanted_sources & source_values):
            return False
        extensions = filt.get("extensions") or ([filt["extension"]] if filt.get("extension") else [])
        if extensions and str(row.get("extension") or "") not in extensions:
            return False
        if filt["protected"] is not None and bool(row.get("is_protected")) is not filt["protected"]:
            return False
        finding_types = {str(value).lower() for value in _decode_string_list(row.get("finding_types"))}
        wanted = set()
        for value in filt.get("finding_types") or ([filt["finding_type"]] if filt.get("finding_type") else []):
            wanted |= {name.lower() for name in finding_type_alias_group(value)}
        if wanted or filt.get("protected_type") or filt.get("classified_type") or filt.get("clear_type"):
            found = int(row.get("finding_count") or 0)
            locked = bool(row.get("is_protected"))
            if not ((wanted & finding_types)
                    or (filt.get("protected_type") and locked)
                    or (filt.get("classified_type") and found > 0)
                    or (filt.get("clear_type") and found == 0 and not locked)):
                return False
        framework_keys = {str(value).lower() for value in _decode_string_list(row.get("framework_keys"))}
        if filt["frameworks"] and not any(value in framework_keys for value in filt["frameworks"]):
            return False
        if filt["q"] and filt["q"] not in str(row.get("search_text") or "").lower():
            return False
        return True

    def _key(row: dict):
        value = row.get(col)
        return ((value or "") if is_text else (value or 0), str(row.get("id") or ""))

    matched = sorted((row for row in rows if _matches(row)), key=_key, reverse=reverse)
    total = len(matched)
    decoded = _decode_cursor(cursor, sort, direction, is_text)
    if decoded is not None:
        cursor_value, cursor_id = decoded
        pivot = ((cursor_value or "") if is_text else (cursor_value or 0), str(cursor_id))
        matched = [row for row in matched if (_key(row) < pivot if reverse else _key(row) > pivot)]

    # search_text is an internal projection and is never returned to clients.
    for row in matched:
        row.pop("search_text", None)
    return _inventory_page(matched, sort, col, is_text, limit, total, direction)


def _list_inventory_scan_report(
    tenant_id: str, report: dict, filt: dict, sort: str, cursor: str, limit: int, direction: str = "",
) -> dict:
    return _inventory_page_from_rows(
        _scan_report_inventory_rows(tenant_id, report),
        filt,
        sort,
        cursor,
        limit,
        direction,
        source_already_matched=True,
    )


def _list_inventory_blob(tenant_id: str, filt: dict, sort: str, cursor: str, limit: int, direction: str = "") -> dict:
    from backend.domain import iter_normalized_assets

    latest: dict[str, dict] = {}
    for item in read_scan_history(tenant_id, limit=1000):  # oldest-first -> newest scan overwrites
        report = read_scan_report(tenant_id, item.get("scan_id"))
        if not report:
            continue
        for asset in iter_normalized_assets(tenant_id, report):
            latest[asset.id] = (
                {c: getattr(asset, c) for c in _INVENTORY_COLS}
                | {"search_text": asset.search_text, "reason_count": asset.reason_count, "dlp_count": asset.dlp_count}
            )
    return _inventory_page_from_rows(list(latest.values()), filt, sort, cursor, limit, direction)


def _decode_string_list(raw) -> list[str]:
    if isinstance(raw, list):
        return [str(value) for value in raw if str(value)]
    try:
        value = json.loads(str(raw or "[]"))
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(item) for item in value if str(item)] if isinstance(value, list) else []


def _inventory_blob_rows(tenant_id: str) -> list[dict]:
    """Latest materialized asset state reconstructed from report blobs."""
    from backend.domain import iter_normalized_assets

    latest: dict[str, dict] = {}
    for item in read_scan_history(tenant_id, limit=1000):
        report = read_scan_report(tenant_id, item.get("scan_id"))
        if not report:
            continue
        for asset in iter_normalized_assets(tenant_id, report):
            latest[asset.id] = asset.to_dict()
    return list(latest.values())


def _facet_items(counts: dict[str, int]) -> list[dict]:
    return [
        {"value": value, "count": count}
        for value, count in sorted(counts.items(), key=lambda item: (-item[1], item[0].lower()))
        if value
    ]


def _framework_facet_items(counts: dict[str, int], severity_counts: dict[str, dict[str, int]]) -> list[dict]:
    """Explicit unique-file metrics for every current inventory framework."""
    return [
        {
            "value": value,
            "count": count,  # compatibility for existing inventory filters
            "file_count": count,
            "severity_file_counts": severity_counts.get(value, {}),
        }
        for value, count in sorted(counts.items(), key=lambda item: (-item[1], item[0].lower()))
        if value
    ]


# Ordered youngest to oldest. ISO-8601 UTC timestamps sort chronologically as
# text, so the buckets are plain string comparisons against precomputed
# cutoffs - no date functions, and identical on SQLite and Postgres.
AGE_BUCKETS = (("fresh", 30), ("recent", 90), ("ageing", 365), ("stale", None))


def _age_cutoffs() -> list[tuple[str, str | None]]:
    now = datetime.now(timezone.utc)
    return [
        (name, (now - timedelta(days=days)).isoformat() if days else None)
        for name, days in AGE_BUCKETS
    ]


def _sensitive_age_counts_sql(conn, tenant_id: str) -> dict[str, int]:
    """How old the sensitive files are, counted once per file.

    Only files that carry a finding: the question is whether data worth
    protecting has been left untouched, and a file with nothing in it is not
    that question.
    """
    cutoffs = _age_cutoffs()
    fresh, recent, ageing = (value for _, value in cutoffs[:3])
    row = conn.execute(
        "SELECT "
        "SUM(CASE WHEN COALESCE(modified_at, '') = '' THEN 1 ELSE 0 END) AS unknown_n, "
        "SUM(CASE WHEN modified_at >= ? THEN 1 ELSE 0 END) AS fresh_n, "
        "SUM(CASE WHEN modified_at < ? AND modified_at >= ? THEN 1 ELSE 0 END) AS recent_n, "
        "SUM(CASE WHEN modified_at < ? AND modified_at >= ? THEN 1 ELSE 0 END) AS ageing_n, "
        "SUM(CASE WHEN modified_at <> '' AND modified_at < ? THEN 1 ELSE 0 END) AS stale_n "
        "FROM assets WHERE tenant_id = ? AND finding_count > 0",
        (fresh, fresh, recent, recent, ageing, ageing, tenant_id),
    ).fetchone()
    if row is None:
        return {}
    return {name: int(row[f"{name}_n"] or 0) for name in ("fresh", "recent", "ageing", "stale", "unknown")}


def _sensitive_age_counts_rows(rows: list[dict]) -> dict[str, int]:
    cutoffs = dict(_age_cutoffs())
    counts = {name: 0 for name in ("fresh", "recent", "ageing", "stale", "unknown")}
    for row in rows:
        if not (row.get("finding_count") or 0):
            continue
        modified = str(row.get("modified_at") or "")
        if not modified:
            counts["unknown"] += 1
        elif modified >= cutoffs["fresh"]:
            counts["fresh"] += 1
        elif modified >= cutoffs["recent"]:
            counts["recent"] += 1
        elif modified >= cutoffs["ageing"]:
            counts["ageing"] += 1
        else:
            counts["stale"] += 1
    return counts


def _first_path_segment_sql() -> str:
    """The first folder of an asset's path, as one SQL expression.

    A share on its own says "somewhere in Shares", which is not a place anyone
    can go and fix. One level down is, and two levels is where a tree stops
    being readable inside a dashboard card.
    """
    if db.is_postgres():
        return "split_part(ltrim(replace(a.path, '\\', '/'), '/'), '/', 1)"
    # SQLite: everything before the first '/' of the path with its leading
    # slash removed. The appended '/' makes a path with no folder work too.
    return (
        "substr(ltrim(replace(a.path, '\\', '/'), '/'), 1, "
        "instr(ltrim(replace(a.path, '\\', '/'), '/') || '/', '/') - 1)"
    )


def _location_tree(
    counts: dict[str, int],
    severity_counts: dict[str, dict[str, int]],
    child_counts: dict[tuple[str, str], int],
    child_severity: dict[tuple[str, str], dict[str, int]],
    *,
    shares: int = 7,
    children: int = 3,
) -> list[dict]:
    """Shares, each followed by its heaviest folders.

    Flat and ordered rather than nested: the client draws the indent from
    `depth`, which keeps this payload the same shape as every other facet.
    """
    def weight(by_severity: dict[str, int], total: int) -> tuple[int, int]:
        return (
            int(by_severity.get("CRITICAL", 0)) * 8
            + int(by_severity.get("HIGH", 0)) * 4
            + int(by_severity.get("MEDIUM", 0)),
            total,
        )

    def node(value: str, label: str, depth: int, parent: str, total: int, by_severity: dict) -> dict:
        return {
            "value": value,
            "label": label,
            "depth": depth,
            "parent": parent,
            "count": total,
            "file_count": total,
            "severity_file_counts": by_severity,
        }

    ordered = sorted(
        (name for name in counts if name),
        key=lambda name: (weight(severity_counts.get(name, {}), counts[name]), name.lower()),
        reverse=True,
    )[:shares]

    items: list[dict] = []
    for share in ordered:
        items.append(node(share, share, 0, "", counts[share], severity_counts.get(share, {})))
        folders = sorted(
            ((folder, total) for (owner, folder), total in child_counts.items() if owner == share and folder),
            key=lambda pair: (weight(child_severity.get((share, pair[0]), {}), pair[1]), pair[0].lower()),
            reverse=True,
        )[:children]
        for folder, total in folders:
            items.append(node(
                share + "/" + folder, folder, 1, share, total,
                child_severity.get((share, folder), {}),
            ))
    return items


def _location_facet_items(counts: dict[str, int], severity_counts: dict[str, dict[str, int]]) -> list[dict]:
    """Where the risk sits, by share.

    Ordered by weighted severity rather than raw volume: a share holding ten
    critical files is the place to go first even if another holds a hundred
    low ones. The weights are the ordering of the ramp, not a score anyone
    reads - the counts themselves are what the client shows.
    """
    def weight(value: str) -> tuple[int, int]:
        by_severity = severity_counts.get(value, {})
        return (
            int(by_severity.get("CRITICAL", 0)) * 8
            + int(by_severity.get("HIGH", 0)) * 4
            + int(by_severity.get("MEDIUM", 0)),
            counts.get(value, 0),
        )

    return [
        {
            "value": value,
            "count": counts[value],
            "file_count": counts[value],
            "severity_file_counts": severity_counts.get(value, {}),
        }
        for value in sorted(counts, key=lambda item: (weight(item), item.lower()), reverse=True)
        if value
    ]


# Two detectors can name the same thing twice. The generic content detector
# calls an address "Email"; the GDPR catalogue's `gdpr_email_address` calls it
# "Email address". Both resolve to the canonical entity EMAIL_ADDRESS, so the
# inventory listed one data class as two rows of 423 files each.
#
# This map is deliberately tiny, and the bar for adding to it is high: the two
# names must denote the SAME entity, not merely a related one. The generic
# `api_key` detector and `gdpr_api_token_oauth_secret` are NOT here - the
# second covers OAuth secrets and service tokens the first does not, and their
# canonical types differ (API_KEY against the coarse CREDENTIALS_SECRETS).
# `phone_number` and `gdpr_phone_number` need no entry: they already share a
# display name, which is what made email the odd one out.
FINDING_TYPE_ALIASES: dict[str, str] = {
    "email address": "Email",
}


def canonical_finding_type(value: str) -> str:
    """The one name a data class is listed under."""
    return FINDING_TYPE_ALIASES.get(str(value or "").strip().lower(), str(value or "").strip())


def finding_type_alias_group(value: str) -> list[str]:
    """Every stored name that means the given data class, so filtering on the
    canonical one still matches rows written under either."""
    canonical = canonical_finding_type(value)
    group = {canonical}
    for stored, target in FINDING_TYPE_ALIASES.items():
        if target.lower() == canonical.lower():
            group.add(stored)
    return sorted(group)


def _merge_finding_type_aliases(
    counts: dict[str, int], severity_counts: dict[str, dict[str, int]]
) -> tuple[dict[str, int], dict[str, dict[str, int]]]:
    """Fold aliased names into their canonical one.

    Counts are files, and a file carrying both names must not be counted twice
    - but the facet rows only carry totals, so the merged total is the LARGER
    of the two rather than their sum. On this estate that is exactly right:
    every file with "Email address" also has "Email"."""
    merged_counts: dict[str, int] = {}
    merged_severity: dict[str, dict[str, int]] = {}
    for value, count in counts.items():
        canonical = canonical_finding_type(value)
        merged_counts[canonical] = max(merged_counts.get(canonical, 0), count)
        target = merged_severity.setdefault(canonical, {})
        for level, level_count in (severity_counts.get(value) or {}).items():
            target[level] = max(target.get(level, 0), level_count)
    return merged_counts, merged_severity


def _finding_type_facet_items(counts: dict[str, int], severity_counts: dict[str, dict[str, int]]) -> list[dict]:
    counts, severity_counts = _merge_finding_type_aliases(counts, severity_counts)
    return [
        {
            "value": value,
            "count": count,
            "file_count": count,
            "severity_file_counts": severity_counts.get(value, {}),
        }
        for value, count in sorted(counts.items(), key=lambda item: (-item[1], item[0].lower()))
        if value
    ]


# risk_engine.LEVEL_NONE. Spelled out rather than imported so the store keeps
# no dependency on the scan-time package.
SEVERITYLESS_RISK_LEVEL = "NONE"


def _facets_from_rows(rows: list[dict], source: str) -> dict:
    risk_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    finding_counts: dict[str, int] = {}
    finding_severity_counts: dict[str, dict[str, int]] = {}
    framework_counts: dict[str, int] = {}
    framework_severity_counts: dict[str, dict[str, int]] = {}
    location_counts: dict[str, int] = {}
    location_severity_counts: dict[str, dict[str, int]] = {}
    child_counts: dict[tuple[str, str], int] = {}
    child_severity: dict[tuple[str, str], dict[str, int]] = {}
    protected_count = 0
    hidden_count = 0
    sensitive_count = 0
    score_total = 0.0
    scan_label_counts: dict[str, int] = {}
    for row in rows:
        risk = str(row.get("risk_level") or "").upper()
        asset_source = str(row.get("source") or "workspace")
        if risk and risk != SEVERITYLESS_RISK_LEVEL:
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        scan_label = str(row.get("scan_label") or "").strip()
        if scan_label:
            scan_label_counts[scan_label] = scan_label_counts.get(scan_label, 0) + 1
        else:
            # Protocol sources are the fallback for assets no named scan
            # covers; a labeled asset is reachable by its scan name, so its
            # protocol must not reappear as a duplicate filter option.
            source_counts[asset_source] = source_counts.get(asset_source, 0) + 1
        location = str(row.get("share") or "").strip()
        if location:
            location_counts[location] = location_counts.get(location, 0) + 1
            if risk:
                by_severity = location_severity_counts.setdefault(location, {})
                by_severity[risk] = by_severity.get(risk, 0) + 1
            segments = [
                part for part in str(row.get("path") or "").replace(chr(92), "/").split("/") if part
            ]
            folder = segments[0] if segments else ""
            if folder:
                key = (location, folder)
                child_counts[key] = child_counts.get(key, 0) + 1
                if risk:
                    by_child = child_severity.setdefault(key, {})
                    by_child[risk] = by_child.get(risk, 0) + 1
        protected_count += 1 if row.get("is_protected") else 0
        hidden_count += 1 if row.get("is_hidden") else 0
        score_total += float(row.get("risk_score") or 0)
        row_finding_types = set(_decode_string_list(row.get("finding_types")))
        if row_finding_types or row.get("finding_count"):
            sensitive_count += 1
        for finding_type in row_finding_types:
            finding_counts[finding_type] = finding_counts.get(finding_type, 0) + 1
            if risk:
                by_severity = finding_severity_counts.setdefault(finding_type, {})
                by_severity[risk] = by_severity.get(risk, 0) + 1
        for framework in set(_decode_string_list(row.get("framework_keys"))):
            framework_counts[framework] = framework_counts.get(framework, 0) + 1
            if risk:
                by_severity = framework_severity_counts.setdefault(framework, {})
                by_severity[risk] = by_severity.get(risk, 0) + 1
    if protected_count:
        finding_counts["Protected / locked"] = protected_count
    classified_count = sum(1 for row in rows if int(row.get("finding_count") or 0) > 0)
    if classified_count:
        finding_counts["Classified"] = classified_count
    clear_count = sum(
        1 for row in rows
        if int(row.get("finding_count") or 0) == 0 and not row.get("is_protected")
    )
    if clear_count:
        finding_counts["Clear"] = clear_count
    return {
        "total": len(rows), "risk_counts": risk_counts, "protected": protected_count,
        "sources": _facet_items(source_counts), "scans": _facet_items(scan_label_counts),
        "finding_types": _finding_type_facet_items(finding_counts, finding_severity_counts),
        "frameworks": _framework_facet_items(framework_counts, framework_severity_counts),
        "locations": _location_tree(location_counts, location_severity_counts, child_counts, child_severity),
        "sensitive_age": _sensitive_age_counts_rows(rows),
        "hidden": hidden_count, "sensitive": sensitive_count,
        "avg_risk_score": (score_total / len(rows)) if rows else 0.0,
        "source": source,
    }


def _normalized_json_facet_rows(conn, tenant_id: str, column: str):
    """Aggregate one JSON-array facet to one bounded row per distinct value."""
    if column not in {"finding_types", "framework_keys"}:
        raise ValueError("Unsupported inventory JSON facet")
    if db.is_postgres():
        return conn.execute(
            f"SELECT item.value AS value, COUNT(*) AS n FROM assets AS a "
            f"CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(a.{column}, '[]')::jsonb) "
            "AS item(value) WHERE a.tenant_id = ? GROUP BY item.value",
            (tenant_id,),
        ).fetchall()
    return conn.execute(
        f"SELECT item.value AS value, COUNT(*) AS n FROM assets AS a, "
        f"json_each(COALESCE(a.{column}, '[]')) AS item "
        "WHERE a.tenant_id = ? GROUP BY item.value",
        (tenant_id,),
    ).fetchall()


def _normalized_framework_facet_rows(conn, tenant_id: str):
    """One row per framework and risk bucket, counted as unique current files."""
    if db.is_postgres():
        return conn.execute(
            "SELECT item.value AS value, a.risk_level AS severity, COUNT(*) AS n FROM assets AS a "
            "CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(a.framework_keys, '[]')::jsonb) "
            "AS item(value) WHERE a.tenant_id = ? GROUP BY item.value, a.risk_level",
            (tenant_id,),
        ).fetchall()
    return conn.execute(
        "SELECT item.value AS value, a.risk_level AS severity, COUNT(*) AS n FROM assets AS a, "
        "json_each(COALESCE(a.framework_keys, '[]')) AS item "
        "WHERE a.tenant_id = ? GROUP BY item.value, a.risk_level",
        (tenant_id,),
    ).fetchall()


def _normalized_finding_type_facet_rows(conn, tenant_id: str):
    """One row per finding type and file-risk bucket for dashboard metrics."""
    if db.is_postgres():
        return conn.execute(
            "SELECT item.value AS value, a.risk_level AS severity, COUNT(*) AS n FROM assets AS a "
            "CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(a.finding_types, '[]')::jsonb) "
            "AS item(value) WHERE a.tenant_id = ? GROUP BY item.value, a.risk_level",
            (tenant_id,),
        ).fetchall()
    return conn.execute(
        "SELECT item.value AS value, a.risk_level AS severity, COUNT(*) AS n FROM assets AS a, "
        "json_each(COALESCE(a.finding_types, '[]')) AS item "
        "WHERE a.tenant_id = ? GROUP BY item.value, a.risk_level",
        (tenant_id,),
    ).fetchall()


def _inventory_facets_cache_seconds() -> float:
    try:
        value = float(os.getenv("DSPM_INVENTORY_FACETS_CACHE_SECONDS", "30"))
    except ValueError:
        value = 30.0
    return max(0.0, min(value, 300.0))


def _cache_inventory_facets(cache_key: tuple, facets: dict) -> dict:
    ttl = _inventory_facets_cache_seconds()
    if ttl:
        with _inventory_query_cache_lock:
            _inventory_facets_cache[cache_key] = (time.monotonic(), facets)
            if len(_inventory_facets_cache) > _INVENTORY_COUNT_CACHE_MAX:
                oldest = min(_inventory_facets_cache, key=lambda item: _inventory_facets_cache[item][0])
                _inventory_facets_cache.pop(oldest, None)
    return facets


@_tenant_scoped
def inventory_facets(tenant_id: str, source: str = "") -> dict:
    """Inventory facets, shared between backends (B3.1).

    The shared answer is asked first, although the per-process cache below is faster:
    only the estate generation sees a write another process made - a partition a
    `python main.py worker` wrote, or a scan saved on another backend - and a process
    that trusted its own cache first would show the estate from before it for the
    length of its TTL. The per-process cache serves when `DSPM_LIVE_CACHE=0`.
    """
    from backend import live_cache

    return live_cache.cached_json(
        tenant_id, "inventory_facets",
        {"source": str(source or ""), "normalized": os.getenv("DSPM_INVENTORY_FROM_NORMALIZED", "1")},
        lambda: _inventory_facets(tenant_id, source),
    )


def _inventory_facets(tenant_id: str, source: str = "") -> dict:
    """Aggregate inventory filters without transferring asset rows to the browser.

    With a configured scan name, facets describe that scan's newest persisted
    run.  Without one, they continue to describe the tenant's current estate.
    """
    cache_key = (
        str(DB_PATH), tenant_id, str(source or ""),
        os.getenv("DSPM_INVENTORY_FROM_NORMALIZED", "1"), "inventory-facets",
    )
    ttl = _inventory_facets_cache_seconds()
    if ttl:
        with _inventory_query_cache_lock:
            cached = _inventory_facets_cache.get(cache_key)
            if cached and time.monotonic() - cached[0] <= ttl:
                return cached[1]
            if cached:
                _inventory_facets_cache.pop(cache_key, None)
    selected = scan_report_inventory_rows_by_label(tenant_id, source) if source else None
    if selected is not None:
        return _cache_inventory_facets(cache_key, _facets_from_rows(selected[1], "scan-report"))
    if _read_inventory_from_normalized(tenant_id):
        try:
            with _connect() as conn:
                risk_rows = conn.execute(
                    "SELECT risk_level, COUNT(*) AS n FROM assets WHERE tenant_id = ? GROUP BY risk_level",
                    (tenant_id,),
                ).fetchall()
                # Protocol sources cover only assets without a named scan;
                # labeled assets are represented by the scans facet instead.
                source_rows = conn.execute(
                    "SELECT source, COUNT(*) AS n FROM assets "
                    "WHERE tenant_id = ? AND COALESCE(scan_label, '') = '' GROUP BY source",
                    (tenant_id,),
                ).fetchall()
                # Operator-facing scan names for the inventory Source filter.
                scan_label_rows = conn.execute(
                    "SELECT scan_label, COUNT(*) AS n FROM assets "
                    "WHERE tenant_id = ? AND scan_label <> '' GROUP BY scan_label",
                    (tenant_id,),
                ).fetchall()
                protected_row = conn.execute(
                    "SELECT COUNT(*) AS n FROM assets WHERE tenant_id = ? AND is_protected = 1", (tenant_id,)
                ).fetchone()
                total_row = conn.execute("SELECT COUNT(*) AS n FROM assets WHERE tenant_id = ?", (tenant_id,)).fetchone()
                # Estate aggregates for the dashboard: the tiles must describe the
                # whole indexed inventory (all sources), not the latest scan alone.
                estate_row = conn.execute(
                    "SELECT "
                    "SUM(CASE WHEN is_hidden = 1 THEN 1 ELSE 0 END) AS hidden_n, "
                    "SUM(CASE WHEN finding_count > 0 THEN 1 ELSE 0 END) AS sensitive_n, "
                    "AVG(COALESCE(risk_score, 0)) AS avg_score "
                    "FROM assets WHERE tenant_id = ?",
                    (tenant_id,),
                ).fetchone()
                finding_rows = _normalized_finding_type_facet_rows(conn, tenant_id)
                framework_rows = _normalized_framework_facet_rows(conn, tenant_id)
                # One row per share and risk bucket. A plain column, so this
                # is a GROUP BY rather than the JSON-array unnest the other
                # two facets need.
                sensitive_age = _sensitive_age_counts_sql(conn, tenant_id)
                location_rows = conn.execute(
                    "SELECT share AS value, risk_level AS severity, COUNT(*) AS n FROM assets "
                    "WHERE tenant_id = ? AND COALESCE(share, '') <> '' GROUP BY share, risk_level",
                    (tenant_id,),
                ).fetchall()
                child_rows = conn.execute(
                    "SELECT a.share AS owner, " + _first_path_segment_sql() + " AS folder, "
                    "a.risk_level AS severity, COUNT(*) AS n FROM assets AS a "
                    "WHERE a.tenant_id = ? AND COALESCE(a.share, '') <> '' "
                    "GROUP BY a.share, folder, a.risk_level",
                    (tenant_id,),
                ).fetchall()
            finding_counts: dict[str, int] = {}
            finding_severity_counts: dict[str, dict[str, int]] = {}
            for row in finding_rows:
                value = str(row["value"] or "")
                if not value:
                    continue
                count = int(row["n"] or 0)
                finding_counts[value] = finding_counts.get(value, 0) + count
                severity = str(row["severity"] or "").upper()
                if severity:
                    finding_severity_counts.setdefault(value, {})[severity] = count
            framework_counts: dict[str, int] = {}
            framework_severity_counts: dict[str, dict[str, int]] = {}
            for row in framework_rows:
                value = str(row["value"] or "")
                if not value:
                    continue
                count = int(row["n"] or 0)
                framework_counts[value] = framework_counts.get(value, 0) + count
                severity = str(row["severity"] or "").upper()
                if severity:
                    framework_severity_counts.setdefault(value, {})[severity] = count
            child_counts: dict[tuple[str, str], int] = {}
            child_severity: dict[tuple[str, str], dict[str, int]] = {}
            for row in child_rows:
                owner, folder = str(row["owner"] or ""), str(row["folder"] or "")
                if not owner or not folder:
                    continue
                count = int(row["n"] or 0)
                child_counts[(owner, folder)] = child_counts.get((owner, folder), 0) + count
                severity = str(row["severity"] or "").upper()
                if severity:
                    child_severity.setdefault((owner, folder), {})[severity] = count
            location_counts: dict[str, int] = {}
            location_severity_counts: dict[str, dict[str, int]] = {}
            for row in location_rows:
                value = str(row["value"] or "")
                if not value:
                    continue
                count = int(row["n"] or 0)
                location_counts[value] = location_counts.get(value, 0) + count
                severity = str(row["severity"] or "").upper()
                if severity:
                    location_severity_counts.setdefault(value, {})[severity] = count
            protected_count = int(protected_row["n"] if protected_row else 0)
            if protected_count:
                finding_counts["Protected / locked"] = protected_count
            # The same three coverage states the card counts, so the facet and
            # the card cannot disagree about what they mean.
            classified_count = int((estate_row["sensitive_n"] if estate_row else 0) or 0)
            if classified_count:
                finding_counts["Classified"] = classified_count
            clear_count = max(0, int(total_row["n"] if total_row else 0) - classified_count - protected_count)
            if clear_count:
                finding_counts["Clear"] = clear_count
            return _cache_inventory_facets(cache_key, {
                "total": int(total_row["n"] if total_row else 0),
                "risk_counts": {
                    str(row["risk_level"] or "").upper(): int(row["n"])
                    for row in risk_rows
                    if row["risk_level"] and str(row["risk_level"]).upper() != SEVERITYLESS_RISK_LEVEL
                },
                "protected": protected_count,
                "sources": _facet_items({str(row["source"] or "workspace"): int(row["n"]) for row in source_rows}),
                "scans": _facet_items({str(row["scan_label"]): int(row["n"]) for row in scan_label_rows}),
                "finding_types": _finding_type_facet_items(finding_counts, finding_severity_counts),
                "frameworks": _framework_facet_items(framework_counts, framework_severity_counts),
                "locations": _location_tree(location_counts, location_severity_counts, child_counts, child_severity),
                "sensitive_age": sensitive_age,
                "hidden": int((estate_row["hidden_n"] if estate_row else 0) or 0),
                "sensitive": int((estate_row["sensitive_n"] if estate_row else 0) or 0),
                "avg_risk_score": float((estate_row["avg_score"] if estate_row else 0) or 0.0),
                "source": "normalized",
            })
        except Exception as exc:  # pragma: no cover - operational failure path
            logger.error("Normalized inventory facets failed: %s", type(exc).__name__)
            raise InventoryReadUnavailable("Normalized inventory facets are temporarily unavailable") from exc
    return _cache_inventory_facets(cache_key, _facets_from_rows(_inventory_blob_rows(tenant_id), "blob"))


def iter_search_asset_batches(batch_size: int = 500):
    """Stream all normalized asset metadata in stable keyset batches for S-F.

    The rebuild script consumes this generator without loading the inventory or
    per-asset detail blobs into process memory.
    """
    batch_size = max(10, min(int(batch_size or 500), 5_000))
    columns = ("tenant_id", *_INVENTORY_COLS, "search_text")
    cursor_tenant = ""
    cursor_id = ""
    while True:
        with _connect() as conn:
            rows = conn.execute(
                f"SELECT {', '.join(columns)} FROM assets "
                "WHERE (tenant_id > ? OR (tenant_id = ? AND id > ?)) "
                "ORDER BY tenant_id ASC, id ASC LIMIT ?",
                (cursor_tenant, cursor_tenant, cursor_id, batch_size),
            ).fetchall()
        if not rows:
            return
        batch = [{column: row[column] for column in columns} for row in rows]
        yield batch
        cursor_tenant = str(rows[-1]["tenant_id"] or "")
        cursor_id = str(rows[-1]["id"] or "")


def get_search_assets_by_refs(documents: list[dict]) -> list[dict]:
    """Return projection rows by tenant+id so the composite PK serves the lookup."""
    refs = [
        (str(document.get("tenant_id") or ""), str(document.get("id") or ""))
        for document in documents
        if document.get("tenant_id") and document.get("id")
    ]
    if not refs:
        return []
    if len(refs) > 400:
        raise ValueError("search reconciliation lookup is limited to 400 tenant/id pairs")
    columns = ("tenant_id", *_INVENTORY_COLS, "search_text")
    predicates = " OR ".join("(tenant_id = ? AND id = ?)" for _ in refs)
    params = [value for ref in refs for value in ref]
    with _connect() as conn:
        rows = conn.execute(
            f"SELECT {', '.join(columns)} FROM assets WHERE {predicates}", params
        ).fetchall()
    return [{column: row[column] for column in columns} for row in rows]


def save_search_reconciliation(index_uid: str, metrics: dict) -> None:
    checked_at = str(metrics.get("checked_at") or datetime.now(timezone.utc).isoformat())
    payload = json.dumps(metrics, ensure_ascii=False, separators=(",", ":"))
    with _lock:
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO search_reconciliation_state
                    (provider, index_uid, checked_at, metrics_json)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (provider, index_uid) DO UPDATE SET
                    checked_at = excluded.checked_at,
                    metrics_json = excluded.metrics_json
                """,
                ("meilisearch", str(index_uid), checked_at, payload),
            )


def get_search_reconciliation(index_uid: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT metrics_json FROM search_reconciliation_state WHERE provider = ? AND index_uid = ?",
            ("meilisearch", str(index_uid)),
        ).fetchone()
    if not row:
        return None
    try:
        value = json.loads(row["metrics_json"] or "{}")
    except (json.JSONDecodeError, TypeError):
        return None
    return value if isinstance(value, dict) else None


@_tenant_scoped
def get_inventory_asset(tenant_id: str, asset_id: str, scan_id: str = "") -> dict | None:
    """Return one full asset, optionally from a specific saved scan run."""
    if scan_id:
        from backend.domain import iter_normalized_assets

        report = read_scan_report(tenant_id, scan_id)
        if report is None:
            return None
        for asset in iter_normalized_assets(tenant_id, report):
            if str(asset.id or "") != str(asset_id or ""):
                continue
            try:
                detail = json.loads(asset.detail_json or "{}")
            except (json.JSONDecodeError, TypeError):
                detail = {}
            risk_detail = detail.get("risk") if isinstance(detail, dict) else {}
            risk_detail = risk_detail if isinstance(risk_detail, dict) else {}
            return detail | {column: getattr(asset, column) for column in _INVENTORY_COLS} | {
                "scan_id": str(scan_id),
                "reason_count": len(risk_detail.get("reasons") or []),
                "dlp_count": len(risk_detail.get("dlp_recommendations") or []),
            }
        return None

    # The default current-estate path remains a single materialized-row read.
    if _read_inventory_from_normalized(tenant_id):
        try:
            with _connect() as conn:
                row = conn.execute(
                    f"SELECT {', '.join(_INVENTORY_COLS)}, detail_json FROM assets WHERE tenant_id = ? AND id = ?",
                    (tenant_id, asset_id),
                ).fetchone()
            if row:
                try:
                    detail = json.loads(unpack_json_text(row["detail_json"]) or "{}")
                except (json.JSONDecodeError, TypeError):
                    detail = {}
                return detail | {column: row[column] for column in _INVENTORY_COLS}
            return None
        except Exception as exc:  # pragma: no cover - operational failure path
            logger.error("Normalized inventory detail failed: %s", type(exc).__name__)
            raise InventoryReadUnavailable("Normalized inventory detail is temporarily unavailable") from exc
    for row in _inventory_blob_rows(tenant_id):
        if str(row.get("id") or "") == str(asset_id or ""):
            try:
                detail = json.loads(row.get("detail_json") or "{}")
            except (json.JSONDecodeError, TypeError):
                detail = {}
            return detail | {column: row.get(column) for column in _INVENTORY_COLS}
    return None


def _inventory_page(rows: list[dict], sort: str, col: str, is_text: bool, limit: int, total: int, direction: str = "") -> dict:
    """Shared page assembly for both inventory paths (identical output shape)."""
    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = None
    if has_more and page:
        last = page[-1]
        value = last.get(col)
        next_cursor = _encode_cursor(sort, direction, (value or "") if is_text else value, str(last.get("id") or ""))
    return {
        "items": page,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "total": min(total, _INVENTORY_COUNT_CAP),
        "total_is_estimate": total > _INVENTORY_COUNT_CAP,
    }


def _find_finding_response_normalized(tenant_id: str, finding_id: str) -> dict | None:
    """Newest stored list_findings response for a finding, from the index.

    Mirrors _find_finding_row's "newest scan containing this finding wins"
    (created_at DESC, scan_id DESC). Returns None when the finding is not in the
    index, so callers fall back to the authoritative blob path.
    """
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT fi.response_json AS response_json
            FROM finding_index AS fi
            JOIN scan_reports AS sr
              ON sr.tenant_id = fi.tenant_id AND sr.scan_id = fi.scan_id
            WHERE fi.tenant_id = ? AND fi.finding_id = ?
            ORDER BY sr.created_at DESC, sr.scan_id DESC, fi.seq ASC
            LIMIT 1
            """,
            (tenant_id, finding_id),
        ).fetchone()
    # An empty body means the scan fell outside the retention window, not that
    # the finding never existed.
    body = unpack_json_text(row["response_json"]) if row else ""
    return json.loads(body) if body else None


def get_finding(tenant_id: str, finding_id: str) -> dict | None:
    try:
        response = _find_finding_response_normalized(tenant_id, finding_id)
        if response is not None:
            return response
    except Exception as exc:  # pragma: no cover - defensive legacy fallback
        logger.warning("Indexed get_finding failed, falling back to blob: %s", exc)
    row = _find_finding_row(tenant_id, finding_id)
    return _finding_response(row) if row else None


def get_finding_history(tenant_id: str, finding_id: str) -> list[dict] | None:
    try:
        response = _find_finding_response_normalized(tenant_id, finding_id)
        if response is not None:
            return response.get("status_history") or response.get("history") or []
    except Exception as exc:  # pragma: no cover - defensive legacy fallback
        logger.warning("Indexed get_finding_history failed, falling back to blob: %s", exc)
    row = _find_finding_row(tenant_id, finding_id)
    if not row:
        return None
    finding = row["finding"]
    return finding.get("status_history") or finding.get("history") or []


def get_finding_occurrences(tenant_id: str, finding_id: str) -> list[dict] | None:
    try:
        response = _find_finding_response_normalized(tenant_id, finding_id)
        if response is not None:
            return response.get("occurrences") or []
    except Exception as exc:  # pragma: no cover - defensive legacy fallback
        logger.warning("Indexed get_finding_occurrences failed, falling back to blob: %s", exc)
    row = _find_finding_row(tenant_id, finding_id)
    if not row:
        return None
    return row["finding"].get("occurrences") or []


def update_finding_lifecycle(tenant_id: str, finding_id: str, action: str, payload: dict, actor: str) -> dict | None:
    with _connect() as conn:
        operational = conn.execute(
            "SELECT is_current FROM findings WHERE tenant_id = ? AND id = ?",
            (tenant_id, finding_id),
        ).fetchone()
    if operational is not None and not int(operational["is_current"] or 0):
        raise ValueError("Historical findings are read-only; remediate a current detection")
    row = _find_finding_row(tenant_id, finding_id)
    if not row:
        return None
    report = row["report"]
    finding = row["finding"]
    status = _status_for_action(action, payload)
    _validate_lifecycle_payload(status, payload)

    now = datetime.now(timezone.utc).isoformat()
    previous_status = _finding_status(finding)
    if status:
        finding["status"] = status
        finding["review_status"] = status.lower()
    if action == "assign":
        finding["owner"] = str(payload.get("owner") or "").strip()
        finding["assignee"] = finding["owner"]
    if action == "comment":
        comment = _comment_payload(payload, actor, now)
        finding.setdefault("comments", []).append(comment)
    if action == "risk-acceptance":
        finding["risk_acceptance"] = {
            "business_justification": str(payload.get("business_justification") or "").strip(),
            "approver": str(payload.get("approver") or "").strip(),
            "expiration_date": str(payload.get("expiration_date") or "").strip(),
            "compensating_controls": list(payload.get("compensating_controls") or []),
            "affected_assets": list(payload.get("affected_assets") or []),
            "accepted_volume": int(payload.get("accepted_volume") or 0),
            "review_date": str(payload.get("review_date") or "").strip(),
        }
    if action == "suppress":
        finding["suppression"] = {
            "reason": str(payload.get("reason") or payload.get("comment") or "").strip(),
            "expiration_date": str(payload.get("expiration_date") or "").strip(),
            "actor": actor,
            "created_at": now,
        }
        finding["display_state"] = "suppressed"
    if action == "reopen":
        finding["display_state"] = "primary"
        finding["resolution"] = ""
    if action == "resolve":
        finding["resolution"] = str(payload.get("resolution") or payload.get("comment") or "Resolved").strip()
        finding["resolved_at"] = now
    if action == "validate":
        finding["validated_at"] = now
        finding["validator"] = actor
    if payload.get("sla_due"):
        finding["sla_due"] = str(payload.get("sla_due")).strip()
    if payload.get("comment") and action != "comment":
        finding.setdefault("comments", []).append(_comment_payload(payload, actor, now))

    event = {
        "timestamp": now,
        "actor": actor,
        "action": action,
        "previous_status": previous_status,
        "status": _finding_status(finding),
        "comment": str(payload.get("comment") or "").strip(),
    }
    finding.setdefault("status_history", []).append(event)
    finding["updated_at"] = now
    save_scan_history(tenant_id, report)
    audit(tenant_id, actor, f"finding.{action}", {"finding_id": finding_id, "scan_id": row["scan_id"], "status": _finding_status(finding)})
    return _finding_response(row)


def _iter_report_findings(report: dict):
    scan_id = str(report.get("scan_id") or "")
    for file_obj in report.get("files") or []:
        for finding in file_obj.get("findings") or []:
            yield {"scan_id": scan_id, "report": report, "file": file_obj, "finding": finding}


def _find_finding_row(tenant_id: str, finding_id: str) -> dict | None:
    target = str(finding_id or "")
    # Operational projection owns the scan pointer, so the normal path opens
    # one report instead of walking up to 1,000 historical report blobs.
    try:
        with _connect() as conn:
            pointer = conn.execute(
                "SELECT scan_id FROM findings WHERE tenant_id = ? AND id = ? LIMIT 1",
                (tenant_id, target),
            ).fetchone()
        if pointer and pointer["scan_id"]:
            report = read_scan_report(tenant_id, pointer["scan_id"])
            if report:
                for row in _iter_report_findings(report):
                    if str(row["finding"].get("finding_id") or "") == target:
                        return row
    except Exception as exc:  # pragma: no cover - legacy compatibility path
        logger.warning("Operational finding lookup failed, using history fallback: %s", type(exc).__name__)
    for item in reversed(read_scan_history(tenant_id, limit=1000)):
        report = read_scan_report(tenant_id, item.get("scan_id"))
        if not report:
            continue
        for row in _iter_report_findings(report):
            if str(row["finding"].get("finding_id") or "") == target:
                return row
    return None


def _finding_response(row: dict) -> dict:
    finding = row["finding"]
    file_obj = row["file"]
    response = dict(finding)
    response["scan_id"] = row["scan_id"]
    response["file"] = {
        "name": file_obj.get("name") or file_obj.get("path") or "",
        "path": file_obj.get("path") or "",
        "source": file_obj.get("source") or "",
    }
    response["status"] = _finding_status(finding)
    return response


def _finding_status(finding: dict) -> str:
    status = str(finding.get("status") or finding.get("review_status") or "NEW").strip().upper()
    if status == "UNREVIEWED":
        return "NEW"
    return status if status in FINDING_LIFECYCLE_STATUSES else "OPEN"


def _status_for_action(action: str, payload: dict) -> str:
    action = str(action or "").strip().lower()
    if action == "status":
        return str(payload.get("status") or "").strip().upper()
    return {
        "assign": "ASSIGNED",
        "comment": "",
        "suppress": "SUPPRESSED",
        "false-positive": "FALSE_POSITIVE",
        "risk-acceptance": "RISK_ACCEPTED",
        "resolve": "RESOLVED",
        "reopen": "REOPENED",
        "validate": "CONFIRMED",
    }.get(action, "")


def _validate_lifecycle_payload(status: str, payload: dict) -> None:
    if status and status not in FINDING_LIFECYCLE_STATUSES:
        raise ValueError("Unsupported finding lifecycle status")
    if status == "ASSIGNED" and not str(payload.get("owner") or "").strip():
        raise ValueError("Assignment requires owner")
    if status == "RISK_ACCEPTED":
        required = ["business_justification", "approver", "expiration_date", "compensating_controls", "affected_assets", "accepted_volume", "review_date"]
        missing = [field for field in required if not payload.get(field)]
        if missing:
            raise ValueError(f"Risk acceptance missing required fields: {', '.join(missing)}")
        expiration = _parse_date(str(payload.get("expiration_date")))
        review = _parse_date(str(payload.get("review_date")))
        if expiration is None or expiration <= datetime.now(timezone.utc):
            raise ValueError("Risk acceptance expiration date must be in the future")
        if review is None or review > expiration:
            raise ValueError("Risk acceptance review date must be valid and on/before expiration")
        if int(payload.get("accepted_volume") or 0) <= 0:
            raise ValueError("Risk acceptance accepted volume must be positive")
    if status == "SUPPRESSED" and not str(payload.get("expiration_date") or "").strip():
        raise ValueError("Suppression requires expiration date; permanent ignore is not allowed")


def _parse_date(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.fromisoformat(f"{value}T00:00:00+00:00")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _comment_payload(payload: dict, actor: str, timestamp: str) -> dict:
    return {"timestamp": timestamp, "actor": actor, "comment": str(payload.get("comment") or "").strip()}


def list_tenants(tenant_id: str | None = None) -> list[dict]:
    """Return the tenant portfolio with one set-based database query.

    The former implementation performed seven queries per tenant (latest scan,
    scan count and four retention counts). That made an ordinary tenant-scoped
    admin pay for the entire platform portfolio and scaled linearly with network
    round trips on PostgreSQL. Window/grouped CTEs keep the response contract but
    bound the work to one query, optionally to one authorized tenant.
    """
    selected_where = "WHERE tenant_id = ?" if tenant_id else ""
    params: tuple = (tenant_id,) if tenant_id else ()
    with _connect() as conn:
        rows = conn.execute(
            f"""
            WITH selected_tenants AS (
                SELECT tenant_id, display_name, registration_code, created_at, updated_at
                FROM tenants {selected_where}
            ),
            latest_ranked AS (
                SELECT sr.tenant_id, sr.scan_id, sr.timestamp, sr.source, sr.summary_json,
                       ROW_NUMBER() OVER (
                           PARTITION BY sr.tenant_id
                           ORDER BY sr.created_at DESC, sr.scan_id DESC
                       ) AS row_number
                FROM scan_reports AS sr
                JOIN selected_tenants AS st ON st.tenant_id = sr.tenant_id
            ),
            scan_counts AS (
                SELECT sr.tenant_id, COUNT(*) AS n
                FROM scan_reports AS sr
                JOIN selected_tenants AS st ON st.tenant_id = sr.tenant_id
                GROUP BY sr.tenant_id
            ),
            audit_counts AS (
                SELECT ae.tenant_id, COUNT(*) AS n
                FROM audit_events AS ae
                JOIN selected_tenants AS st ON st.tenant_id = ae.tenant_id
                GROUP BY ae.tenant_id
            ),
            alert_counts AS (
                SELECT ae.tenant_id, COUNT(*) AS n
                FROM alert_events AS ae
                JOIN selected_tenants AS st ON st.tenant_id = ae.tenant_id
                GROUP BY ae.tenant_id
            ),
            baseline_counts AS (
                SELECT b.tenant_id, COUNT(*) AS n
                FROM scan_object_baselines AS b
                JOIN selected_tenants AS st ON st.tenant_id = b.tenant_id
                GROUP BY b.tenant_id
            )
            SELECT st.tenant_id, st.display_name, st.registration_code,
                   st.created_at, st.updated_at,
                   lr.scan_id AS latest_scan_id, lr.timestamp AS latest_timestamp,
                   lr.source AS latest_source, lr.summary_json AS latest_summary_json,
                   COALESCE(sc.n, 0) AS scan_count,
                   COALESCE(ac.n, 0) AS audit_count,
                   COALESCE(alc.n, 0) AS alert_count,
                   COALESCE(bc.n, 0) AS baseline_count
            FROM selected_tenants AS st
            LEFT JOIN latest_ranked AS lr
              ON lr.tenant_id = st.tenant_id AND lr.row_number = 1
            LEFT JOIN scan_counts AS sc ON sc.tenant_id = st.tenant_id
            LEFT JOIN audit_counts AS ac ON ac.tenant_id = st.tenant_id
            LEFT JOIN alert_counts AS alc ON alc.tenant_id = st.tenant_id
            LEFT JOIN baseline_counts AS bc ON bc.tenant_id = st.tenant_id
            ORDER BY st.tenant_id
            """,
            params,
        ).fetchall()
    tenants: list[dict] = []
    missing_codes: list[tuple[str, str, str]] = []
    for row in rows:
        row_tenant_id = row["tenant_id"]
        registration_code = str(row["registration_code"] or "")
        if not registration_code:
            registration_code = generate_registration_code()
            missing_codes.append((registration_code, datetime.now(timezone.utc).isoformat(), row_tenant_id))
        try:
            latest_summary = json.loads(row["latest_summary_json"] or "{}")
        except (json.JSONDecodeError, TypeError):
            latest_summary = {}
        latest = {"summary": latest_summary}
        if row["latest_scan_id"]:
            latest.update({
                "scan_id": row["latest_scan_id"],
                "timestamp": row["latest_timestamp"],
                "source": row["latest_source"],
            })
        tenants.append(
            {
                "tenant_id": row_tenant_id,
                "display_name": row["display_name"],
                "registration_code": registration_code,
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "scan_count": int(row["scan_count"] or 0),
                "latest": latest,
                "retention": {
                    "tenant_id": row_tenant_id,
                    "database": db.backend_name(),
                    "report_count": int(row["scan_count"] or 0),
                    "audit_events": int(row["audit_count"] or 0),
                    "alert_events": int(row["alert_count"] or 0),
                    "incremental_baseline_objects": int(row["baseline_count"] or 0),
                },
            }
        )
    if missing_codes:
        with _lock:
            with _connect() as conn:
                conn.executemany(
                    "UPDATE tenants SET registration_code = ?, updated_at = ? "
                    "WHERE tenant_id = ? AND (registration_code IS NULL OR registration_code = '')",
                    missing_codes,
                )
    if not tenants and tenant_id is None:
        tenants.append(
            {
                "tenant_id": "default",
                "display_name": "Default",
                "registration_code": generate_registration_code(),
                "scan_count": 0,
                "latest": {"summary": {}},
                "retention": data_retention_summary("default"),
            }
        )
    return tenants


_tenant_exists_cache: dict[str, tuple[float, bool]] = {}
_tenant_exists_lock = threading.Lock()


def _tenant_exists_cache_seconds() -> float:
    """Off-switchable, because a tenant deleted in one worker would otherwise
    keep resolving in the others for the length of this window."""
    try:
        value = float(os.getenv("DSPM_TENANT_EXISTS_CACHE_SECONDS", "30"))
    except ValueError:
        value = 30.0
    return max(0.0, min(value, 300.0))


def _forget_tenant_existence() -> None:
    with _tenant_exists_lock:
        _tenant_exists_cache.clear()


def tenant_exists(tenant_id: str) -> bool:
    """Cached: a tenant is created or deleted through this process, and both
    paths clear the entry, so the cache cannot answer for a tenant that has
    since gone."""
    key = str(tenant_id or "")
    ttl = _tenant_exists_cache_seconds()
    now_mono = time.monotonic()
    if ttl:
        with _tenant_exists_lock:
            cached = _tenant_exists_cache.get(key)
            if cached and now_mono - cached[0] <= ttl:
                return cached[1]
    with _connect() as conn:
        row = conn.execute("SELECT 1 FROM tenants WHERE tenant_id = ?", (tenant_id,)).fetchone()
    exists = row is not None
    if ttl:
        with _tenant_exists_lock:
            if len(_tenant_exists_cache) > 256:
                _tenant_exists_cache.clear()
            _tenant_exists_cache[key] = (now_mono, exists)
    return exists


def create_tenant(tenant_id: str, display_name: str = "") -> dict:
    now = datetime.now(timezone.utc).isoformat()
    name = display_name.strip() or tenant_id
    registration_code = generate_registration_code()
    with _lock:
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO tenants (tenant_id, display_name, registration_code, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (tenant_id, name, registration_code, now, now),
            )
    _forget_tenant_existence()
    tenant = get_tenant(tenant_id)
    if tenant is None:
        raise RuntimeError("Tenant was not created")
    return tenant


def get_tenant(tenant_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT tenant_id, display_name, registration_code,
                   legal_hold, legal_hold_reason, legal_hold_set_at,
                   created_at, updated_at
            FROM tenants
            WHERE tenant_id = ?
            """,
            (tenant_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "tenant_id": row["tenant_id"],
        "display_name": row["display_name"],
        "registration_code": ensure_registration_code(row["tenant_id"], row["registration_code"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def delete_tenant(tenant_id: str) -> bool:
    with _lock:
        with _connect() as conn:
            result = conn.execute("DELETE FROM tenants WHERE tenant_id = ?", (tenant_id,))
            deleted = result.rowcount > 0
    _forget_tenant_existence()
    return deleted


_TENANT_ERASURE_TABLES = (
    "registration_invites",
    "scan_targets",
    "audit_chain_heads",
    "audit_outbox",
    "custom_roles",
    "scan_schedules",
    "suppression_rules",
    "derived_cache",
    "api_keys",
    # Saved scan configurations reference vaulted credentials; leaving them
    # behind after erasure kept a dead tenant's connection settings alive
    # (found by the revision-0003 tenant foreign keys).
    "scan_profiles",
    "scan_reports",
    "audit_events",
    "alert_events",
    "secrets",
    "scan_object_baselines",
    "scan_runs",
    "assets",
    "asset_versions",
    # D7: who can read each file.
    "asset_access",
    # D2: exact-data-match reference sets.
    "edm_fingerprints",
    "edm_sets",
    "findings",
    "finding_occurrences",
    "finding_index",
    "scan_partitions",
    "partitioned_scans",
    "scan_jobs",
    # C2: the workspace's directory sign-in settings (their password is in `secrets`).
    "directory_settings",
    # C13: how each scan reached its files.
    "scan_sources",
)


def _delete_tenant_scoped_data(conn, tenant_id: str) -> None:
    """Delete every tenant-keyed record while leaving identity rows to the caller."""
    for table in _TENANT_ERASURE_TABLES:
        conn.execute(f"DELETE FROM {table} WHERE tenant_id = ?", (tenant_id,))


class LegalHoldActive(RuntimeError):
    """A destructive operation was refused because the tenant is under hold."""

    # C8: its message is written for the operator; backend.errors may show it.
    client_safe = True


def get_legal_hold(tenant_id: str) -> dict:
    with _connect() as conn:
        row = conn.execute(
            "SELECT legal_hold, legal_hold_reason, legal_hold_set_at "
            "FROM tenants WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
    if row is None:
        return {"tenant_id": tenant_id, "active": False, "reason": "", "set_at": ""}
    return {
        "tenant_id": tenant_id,
        "active": bool(row["legal_hold"]),
        "reason": str(row["legal_hold_reason"] or ""),
        "set_at": str(row["legal_hold_set_at"] or ""),
    }


def set_legal_hold(tenant_id: str, active: bool, reason: str = "") -> dict:
    """Place or lift a legal hold. Placing one requires a stated reason."""
    reason = str(reason or "").strip()[:500]
    if active and not reason:
        raise ValueError("A legal hold requires a reason.")
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            result = conn.execute(
                "UPDATE tenants SET legal_hold = ?, legal_hold_reason = ?, "
                "legal_hold_set_at = ?, updated_at = ? WHERE tenant_id = ?",
                (1 if active else 0, reason if active else "", now if active else "", now, tenant_id),
            )
            if not result.rowcount:
                raise ValueError(f"Unknown tenant: {tenant_id}")
    return get_legal_hold(tenant_id)


def assert_no_legal_hold(tenant_id: str, operation: str) -> None:
    """Refuse a destructive operation on a held tenant."""
    hold = get_legal_hold(tenant_id)
    if hold["active"]:
        raise LegalHoldActive(
            f"Refusing to {operation} tenant {tenant_id!r}: a legal hold is in force"
            f" (set {hold['set_at']}: {hold['reason']}). Lift the hold deliberately first."
        )


def tenants_under_legal_hold() -> set[str]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT tenant_id FROM tenants WHERE legal_hold = 1"
        ).fetchall()
    return {str(row["tenant_id"]) for row in rows}


def _erase_tenant_artifacts(tenant_id: str) -> int:
    """Remove a tenant's stored report bodies. Raises rather than swallowing.

    Every path that erases a tenant's scan data must call this. An erasure
    that half-succeeds - rows gone, contents still on disk - is worse than one
    that fails loudly, because it reports success while leaving the data it
    claimed to destroy.
    """
    try:
        from backend import artifacts

        return artifacts.delete_tenant(tenant_id)
    except Exception as exc:
        logger.error("Artifact erasure failed for tenant %s: %s", tenant_id, type(exc).__name__)
        raise


def delete_tenant_with_data(tenant_id: str) -> dict:
    # A legal hold outranks erasure: the whole point is that a scheduled or
    # requested deletion must not proceed while data is under preservation.
    assert_no_legal_hold(tenant_id, "erase")
    usage = tenant_usage(tenant_id)
    # Erasure is a platform operation on an arbitrary tenant: scope the
    # transaction to the target so RLS permits exactly these rows.
    with _lock, db.tenant_scope(tenant_id):
        with _connect() as conn:
            # C2: an account's second factor is part of the account.
            conn.execute("DELETE FROM user_mfa WHERE tenant_id = ?", (tenant_id,))
            conn.execute("DELETE FROM users WHERE tenant_id = ?", (tenant_id,))
            _delete_tenant_scoped_data(conn, tenant_id)
            conn.execute("DELETE FROM tenants WHERE tenant_id = ?", (tenant_id,))
            # Erasure is only whole if it reaches the bodies too: once reports
            # live in the artifact tier, deleting the rows alone would leave the
            # customer's report contents on disk (Phase 5, DB-07).
            usage["artifacts_removed"] = _erase_tenant_artifacts(tenant_id)
            # Reconciliation state covers the shared optional search projection,
            # not one tenant. Invalidate it after any erasure so the next pass
            # detects and removes documents that no longer exist in the DB.
            conn.execute("DELETE FROM search_reconciliation_state")
    usage["search_documents"] = _erase_tenant_search_documents(tenant_id)
    _invalidate_inventory_query_cache(tenant_id)
    _forget_tenant_existence()
    return usage


def _erase_tenant_search_documents(tenant_id: str) -> str:
    """C10: the optional search index is part of erasure, not left to the next
    reconciliation. If it cannot be reached the erasure still stands, says so, and the
    reconciliation (whose state was just cleared) removes the documents later."""
    from backend import search

    try:
        return search.erase_tenant(tenant_id)
    except search.SearchUnavailable as exc:
        logger.warning("Search index erasure for %s is pending: %s", tenant_id, exc)
        return "pending - the index could not be reached; the next reconciliation removes them"


def reset_default_tenant_data() -> dict:
    """Return the default tenant to a clean, accessible installation state.

    The built-in admin identity and its password hash are retained so an
    operator is not locked out. All other default-tenant identities, scans,
    findings, secrets, invitations, API keys, jobs, and operational history are
    erased. The registration code is rotated because it is tenant information.
    """
    tenant_id = "default"
    usage = tenant_usage(tenant_id)
    now = datetime.now(timezone.utc).isoformat()
    # C10: scoped to the tenant it resets - unscoped, the policies would show it nothing.
    with _lock, db.tenant_scope(tenant_id):
        with _connect() as conn:
            admin = conn.execute(
                "SELECT 1 FROM users WHERE username = ? AND tenant_id = ?",
                ("admin", tenant_id),
            ).fetchone()
            if admin is None:
                raise RuntimeError("Cannot reset the default tenant without its built-in admin user")
            _delete_tenant_scoped_data(conn, tenant_id)
            # A reset erases every scan this tenant owns, so its report bodies
            # must go with them. Deleting only the rows left the contents -
            # findings, paths, owners - readable on disk, which is the same
            # remanence bug the tenant-erasure path had before Phase 5b.
            usage["artifacts_removed"] = _erase_tenant_artifacts(tenant_id)
            # The built-in admin keeps its second factor, as it keeps its password.
            conn.execute("DELETE FROM user_mfa WHERE tenant_id = ? AND username <> ?", (tenant_id, "admin"))
            conn.execute(
                "DELETE FROM users WHERE tenant_id = ? AND username <> ?",
                (tenant_id, "admin"),
            )
            conn.execute(
                """
                UPDATE users
                SET role = 'admin', full_name = 'Local Administrator',
                    is_active = 1, updated_at = ?, last_login_at = NULL
                WHERE username = ? AND tenant_id = ?
                """,
                (now, "admin", tenant_id),
            )
            conn.execute(
                """
                UPDATE tenants
                SET display_name = 'Default', registration_code = ?, updated_at = ?
                WHERE tenant_id = ?
                """,
                (generate_registration_code(), now, tenant_id),
            )
            conn.execute("DELETE FROM login_failures")
            conn.execute("DELETE FROM search_reconciliation_state")
    usage["search_documents"] = _erase_tenant_search_documents(tenant_id)
    _invalidate_inventory_query_cache(tenant_id)
    return usage


def tenant_usage(tenant_id: str) -> dict:
    with _connect() as conn:
        users = conn.execute("SELECT COUNT(*) FROM users WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
        reports = conn.execute("SELECT COUNT(*) FROM scan_reports WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
        audits = conn.execute("SELECT COUNT(*) FROM audit_events WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
        alerts = conn.execute("SELECT COUNT(*) FROM alert_events WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
        secrets = conn.execute("SELECT COUNT(*) FROM secrets WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
        baseline_objects = conn.execute(
            "SELECT COUNT(*) FROM scan_object_baselines WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()[0]
    return {
        "users": users, "reports": reports, "audits": audits, "alerts": alerts,
        "secrets": secrets, "baseline_objects": baseline_objects,
    }


def read_audit_log(tenant_id: str, limit: int = 200) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT timestamp, tenant_id, actor, action, detail_json
            FROM audit_events
            WHERE tenant_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (tenant_id, limit),
        ).fetchall()
    events = [
        {
            "timestamp": row["timestamp"],
            "tenant_id": row["tenant_id"],
            "actor": row["actor"],
            "action": row["action"],
            "detail": json.loads(row["detail_json"] or "{}"),
        }
        for row in rows
    ]
    return list(reversed(events))


def data_retention_summary(tenant_id: str) -> dict:
    with _connect() as conn:
        report_count = conn.execute(
            "SELECT COUNT(*) FROM scan_reports WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()[0]
        audit_count = conn.execute(
            "SELECT COUNT(*) FROM audit_events WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()[0]
        alert_count = conn.execute(
            "SELECT COUNT(*) FROM alert_events WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()[0]
        baseline_count = conn.execute(
            "SELECT COUNT(*) FROM scan_object_baselines WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()[0]
    return {
        "tenant_id": tenant_id,
        "database": db.backend_name(),
        "report_count": report_count,
        "audit_events": audit_count,
        "alert_events": alert_count,
        "incremental_baseline_objects": baseline_count,
    }


def save_secret(tenant_id: str, secret_id: str, ciphertext: str, *, kind: str = "scan", label: str = "") -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO secrets (tenant_id, secret_id, ciphertext, created_at, kind, label, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (tenant_id, secret_id, ciphertext, now, kind, label, now),
            )


def replace_secret(tenant_id: str, secret_id: str, ciphertext: str, label: str) -> bool:
    """C12: the account's password changed; same reference, new sealed value, new date."""
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            return conn.execute(
                "UPDATE secrets SET ciphertext = ?, label = ?, rotated_at = ?, updated_at = ? "
                "WHERE tenant_id = ? AND secret_id = ?",
                (ciphertext, label, now, now, tenant_id, secret_id)).rowcount > 0


# A use is recorded at most once an hour: a scan resolves its credential on every
# partition, and "last used" answers "is this account still needed?", not "how often?".
_SECRET_USE_RESOLUTION = timedelta(hours=1)


def touch_secret_used(tenant_id: str, secret_id: str) -> None:
    now = datetime.now(timezone.utc)
    cutoff = (now - _SECRET_USE_RESOLUTION).isoformat()
    with _connect() as conn:
        conn.execute("UPDATE secrets SET last_used_at = ? WHERE tenant_id = ? AND secret_id = ? "
                     "AND (last_used_at IS NULL OR last_used_at < ?)", (now.isoformat(), tenant_id, secret_id, cutoff))


def set_secret_privilege(tenant_id: str, secret_id: str, privilege: dict) -> None:
    with _connect() as conn:
        conn.execute("UPDATE secrets SET privilege_json = ? WHERE tenant_id = ? AND secret_id = ?",
                     (json.dumps(privilege, separators=(",", ":")), tenant_id, secret_id))


def record_scan_source(tenant_id: str, scan_id: str, source_kind: str, server: str, credential_kind: str,
                       credential_ref: str = "") -> None:
    """C13: how a scan reached its files. A saved credential is recorded by reference; a
    typed password is recorded only as having been typed."""
    if credential_kind != "saved":
        credential_ref = ""
    with _lock:
        with _connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scan_sources (tenant_id, scan_id, source_kind, server, credential_kind, "
                "credential_ref, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, scan_id, source_kind, server, credential_kind, credential_ref,
                 datetime.now(timezone.utc).isoformat()))


def get_scan_source(tenant_id: str, scan_id: str) -> dict | None:
    if not scan_id:
        return None
    with _connect() as conn:
        row = conn.execute("SELECT source_kind, server, credential_kind, credential_ref FROM scan_sources "
                           "WHERE tenant_id = ? AND scan_id = ?", (tenant_id, scan_id)).fetchone()
    return dict(row) if row else None


def create_edm_set(tenant_id: str, set_id: str, name: str, entity_type: str, fingerprints, key_digest: str,
                   created_by: str) -> int:
    """D2: store a reference set - its name and its values' fingerprints - in one
    transaction. Returns how many distinct fingerprints it holds."""
    rows = sorted(set(fingerprints))
    with _lock:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO edm_sets (tenant_id, set_id, name, entity_type, row_count, key_digest, created_by, "
                "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, set_id, name, entity_type, len(rows), key_digest, created_by,
                 datetime.now(timezone.utc).isoformat()))
            _executemany(conn, "INSERT INTO edm_fingerprints (tenant_id, set_id, fingerprint) VALUES (?, ?, ?)",
                         ((tenant_id, set_id, fingerprint) for fingerprint in rows))
    return len(rows)


def list_edm_sets(tenant_id: str) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT set_id, name, entity_type, row_count, key_digest, created_by, created_at FROM edm_sets "
            "WHERE tenant_id = ? ORDER BY created_at, set_id", (tenant_id,)).fetchall()
    return [dict(row) for row in rows]


def delete_edm_set(tenant_id: str, set_id: str) -> bool:
    with _lock:
        with _connect() as conn:
            conn.execute("DELETE FROM edm_fingerprints WHERE tenant_id = ? AND set_id = ?", (tenant_id, set_id))
            return conn.execute("DELETE FROM edm_sets WHERE tenant_id = ? AND set_id = ?",
                                (tenant_id, set_id)).rowcount > 0


def count_edm_rows(tenant_id: str) -> int:
    with _connect() as conn:
        row = conn.execute("SELECT COALESCE(SUM(row_count), 0) AS n FROM edm_sets WHERE tenant_id = ?",
                           (tenant_id,)).fetchone()
    return int(row["n"] or 0)


def exact_match_index_for_scan(tenant_id: str, key_digest: str) -> dict:
    """D2: what a scan matches against - every fingerprint of the workspace's reference
    sets built with the current key, and the names of the sets holding it. Read once,
    when the scan's configuration is built, like the suppression rules. `digest` changes
    whenever a set is added or removed, and invalidates incremental reuse."""
    try:
        with _connect() as conn:
            sets = conn.execute(
                "SELECT set_id, name, row_count FROM edm_sets WHERE tenant_id = ? AND key_digest = ? "
                "ORDER BY set_id", (tenant_id, key_digest)).fetchall()
            names = {row["set_id"]: row["name"] for row in sets}
            index: dict[str, list[str]] = {}
            if names:
                for row in conn.execute("SELECT set_id, fingerprint FROM edm_fingerprints WHERE tenant_id = ?",
                                        (tenant_id,)).fetchall():
                    if row["set_id"] in names:
                        index.setdefault(row["fingerprint"], []).append(names[row["set_id"]])
    except Exception as exc:
        logger.warning("Exact-match reference sets could not be read for tenant %s (%s); the scan runs without "
                       "them.", tenant_id, type(exc).__name__)
        return {}
    if not index:
        return {}
    digest = hashlib.sha256(json.dumps([[row["set_id"], int(row["row_count"] or 0)] for row in sets]).encode()).hexdigest()
    return {"digest": digest[:16], "fingerprints": index}


def list_access_principals(tenant_id: str, *, kind: str = "", limit: int = 200) -> list[dict]:
    """D7: every principal with access to a file in the current estate, with how many
    files - and how many holding findings - it can read and write. `kind` narrows it to
    broad groups, privileged or service/indexer accounts."""
    kind_sql = {"broad": " AND aa.broad = 1", "privileged": " AND aa.privileged = 1",
                "service": " AND aa.service = 1"}.get(kind, "")
    with _connect() as conn:
        rows = conn.execute(
            "SELECT aa.principal_key AS principal_key, MAX(aa.principal) AS principal, MAX(aa.sid) AS sid, "
            "MAX(aa.broad) AS broad, MAX(aa.privileged) AS privileged, MAX(aa.service) AS service, "
            "SUM(aa.can_read) AS readable, SUM(aa.can_write) AS writable, "
            "SUM(CASE WHEN aa.can_read = 1 AND a.finding_count > 0 THEN 1 ELSE 0 END) AS readable_sensitive, "
            "MAX(CASE WHEN aa.can_read = 1 THEN a.risk_score ELSE 0 END) AS max_risk_score "
            "FROM asset_access aa JOIN assets a ON a.tenant_id = aa.tenant_id AND a.id = aa.asset_id "
            f"WHERE aa.tenant_id = ?{kind_sql} GROUP BY aa.principal_key "
            "ORDER BY readable_sensitive DESC, readable DESC, aa.principal_key LIMIT ?",  # noqa: S608 - fixed fragments
            (tenant_id, max(1, min(int(limit), 1000))),
        ).fetchall()
    return [{"key": row["principal_key"], "principal": row["principal"], "sid": row["sid"] or "",
             "broad": bool(row["broad"]), "privileged": bool(row["privileged"]), "service": bool(row["service"]),
             "readable_files": int(row["readable"] or 0), "readable_sensitive_files": int(row["readable_sensitive"] or 0),
             "writable_files": int(row["writable"] or 0), "max_risk_score": float(row["max_risk_score"] or 0)}
            for row in rows]


def list_access_assets(tenant_id: str, *, principal_key: str = "", kind: str = "", sensitive_only: bool = False,
                       writable_only: bool = False, limit: int = 100, offset: int = 0) -> list[dict]:
    """D7: the files a principal can read (or write), or - with `kind` - the files a broad
    group, privileged or service/indexer account can read; riskiest first."""
    clauses = ["aa.tenant_id = ?"]
    params: list = [tenant_id]
    if principal_key:
        clauses.append("aa.principal_key = ?")
        params.append(principal_key)
    kind_column = {"broad": "broad", "privileged": "privileged", "service": "service"}.get(kind)
    if kind_column:
        clauses.append(f"aa.{kind_column} = 1")
    clauses.append("aa.can_write = 1" if writable_only else "aa.can_read = 1")
    if sensitive_only:
        clauses.append("a.finding_count > 0")
    with _connect() as conn:
        rows = conn.execute(
            "SELECT a.id AS asset_id, a.path AS path, a.name AS name, a.share AS share, a.source AS source, "
            "a.risk_level AS risk_level, a.risk_score AS risk_score, a.finding_count AS finding_count, "
            "MAX(aa.can_read) AS can_read, MAX(aa.can_write) AS can_write, MAX(aa.principal) AS principal "
            "FROM asset_access aa JOIN assets a ON a.tenant_id = aa.tenant_id AND a.id = aa.asset_id "
            f"WHERE {' AND '.join(clauses)} "  # noqa: S608 - fixed fragments
            "GROUP BY a.id, a.path, a.name, a.share, a.source, a.risk_level, a.risk_score, a.finding_count "
            "ORDER BY a.risk_score DESC, a.path LIMIT ? OFFSET ?",
            (*params, max(1, min(int(limit), 500)), max(0, int(offset))),
        ).fetchall()
    return [{"asset_id": row["asset_id"], "path": row["path"], "name": row["name"], "share": row["share"] or "",
             "source": row["source"], "risk_level": row["risk_level"], "risk_score": float(row["risk_score"] or 0),
             "finding_count": int(row["finding_count"] or 0), "can_read": bool(row["can_read"]),
             "can_write": bool(row["can_write"]), "principal": row["principal"] if not principal_key else ""}
            for row in rows]


def finding_location(tenant_id: str, finding_id: str) -> dict | None:
    """C13: the asset a finding belongs to, and the newest scan that saw it."""
    with _connect() as conn:
        row = conn.execute("SELECT asset_id, scan_id FROM findings WHERE tenant_id = ? AND id = ?",
                           (tenant_id, finding_id)).fetchone()
    if row is None:
        return None
    location = {"asset_id": row["asset_id"], "scan_id": row["scan_id"]}
    latest = get_finding(tenant_id, finding_id)
    if latest and latest.get("scan_id"):
        location["scan_id"] = latest["scan_id"]
    return location


def list_secret_metadata(tenant_id: str) -> list[dict]:
    """A workspace's saved credentials without their sealed values."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT secret_id, ciphertext, created_at, kind, label, last_used_at, rotated_at, rekeyed_at, "
            "privilege_json FROM secrets WHERE tenant_id = ? ORDER BY created_at", (tenant_id,)).fetchall()
    items = []
    for row in rows:
        sealed = str(row["ciphertext"] or "")
        key = sealed[4:].split(".", 1)[0] if sealed.startswith("vk1.") else ""
        try:
            privilege = json.loads(row["privilege_json"] or "{}")
        except ValueError:
            privilege = {}
        items.append({"credential_ref": row["secret_id"], "kind": row["kind"] or "scan", "label": row["label"] or "",
                      "created_at": row["created_at"], "last_used_at": row["last_used_at"],
                      "rotated_at": row["rotated_at"], "rekeyed_at": row["rekeyed_at"],
                      "key_id": key, "privilege": privilege})
    return items


# C12: every value the vault seals, wherever it lives: (table, key columns, sealed column).
_SEALED_COLUMNS = (
    ("secrets", ("tenant_id", "secret_id"), "ciphertext"),
    ("user_mfa", ("username",), "secret_ciphertext"),
    ("user_mfa", ("username",), "pending_ciphertext"),
)


def vault_sealed_values() -> list[str]:
    """Every sealed value in every tenant (for the key ring's status and escrow check)."""
    return [value for _table, _keys, value in vault_sealed_rows()]


def vault_sealed_rows() -> list[tuple[str, dict, str]]:
    """Every sealed value with where it lives: (table, its key columns, the value). The key
    columns identify a row (tenant and reference, or account) - never a secret."""
    rows: list[tuple[str, dict, str]] = []
    with _connect() as conn:
        for table, keys, column in _SEALED_COLUMNS:
            for row in conn.execute(
                    f"SELECT {', '.join(keys)}, {column} AS v FROM {table} WHERE {column} <> ''").fetchall():  # noqa: S608 - fixed names
                rows.append((table, {key: row[key] for key in keys}, str(row["v"])))
    return rows


def reseal_vault_values(transform) -> int:
    """C12: pass every sealed value through `transform` (a new sealed value, or None to
    keep it) and write the results - in ONE transaction, so a failure part-way leaves
    every value as it was. Each write is conditional on the value it replaces."""
    now = datetime.now(timezone.utc).isoformat()
    changed = 0
    with _lock:
        with _connect() as conn:
            for table, keys, column in _SEALED_COLUMNS:
                rows = conn.execute(
                    f"SELECT {', '.join(keys)}, {column} AS v FROM {table} WHERE {column} <> ''").fetchall()  # noqa: S608
                for row in rows:
                    new = transform(str(row["v"]))
                    if new is None or new == row["v"]:
                        continue
                    stamp = ", rekeyed_at = ?" if table == "secrets" else ""
                    where = " AND ".join(f"{key} = ?" for key in keys)
                    params = [new, *([now] if stamp else []), *[row[key] for key in keys], row["v"]]
                    changed += conn.execute(
                        f"UPDATE {table} SET {column} = ?{stamp} WHERE {where} AND {column} = ?",  # noqa: S608
                        tuple(params)).rowcount
    return changed


def read_secret(tenant_id: str, secret_id: str) -> str | None:
    record = read_secret_record(tenant_id, secret_id)
    return record["ciphertext"] if record else None


def read_secret_record(tenant_id: str, secret_id: str) -> dict | None:
    """The sealed value and what it is for ("scan", or "directory" - the directory sign-in
    service account's password)."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT ciphertext, kind FROM secrets WHERE tenant_id = ? AND secret_id = ?",
            (tenant_id, secret_id),
        ).fetchone()
    return {"ciphertext": str(row["ciphertext"]), "kind": str(row["kind"] or "scan")} if row else None


def delete_secret(tenant_id: str, secret_id: str) -> None:
    with _lock:
        with _connect() as conn:
            conn.execute(
                "DELETE FROM secrets WHERE tenant_id = ? AND secret_id = ?",
                (tenant_id, secret_id),
            )


def save_alerts(tenant_id: str, scan_id: str | None, alerts: list[dict]) -> None:
    with _lock:
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO alert_events (tenant_id, scan_id, alerts_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    scan_id,
                    json.dumps(alerts, ensure_ascii=False),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )


def read_alerts(tenant_id: str, limit: int = 200) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT scan_id, alerts_json, created_at
            FROM alert_events
            WHERE tenant_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (tenant_id, limit),
        ).fetchall()
    events = [
        {
            "tenant_id": tenant_id,
            "scan_id": row["scan_id"],
            "alerts": json.loads(row["alerts_json"] or "[]"),
            "created_at": row["created_at"],
        }
        for row in rows
    ]
    return list(reversed(events))


def _require_known_role(role: str, tenant_id: str) -> None:
    # C3: revision 0020 took this check out of the schema; it lives here now, and a
    # custom role counts only in the tenant that defined it.
    if not role_exists(role, tenant_id):
        raise ValueError(f"Unknown role: {role!r}")


# C3: custom role permissions are read on every request that carries one, several times
# (the route's permission, evidence scope). A short cache keeps that to one read; a
# change made in this process clears it at once, one made by another backend within
# the TTL.
_CUSTOM_ROLE_TTL_SECONDS = 5.0
_custom_role_cache: dict[tuple[str, str, str], tuple[float, frozenset | None]] = {}


def _custom_role_key(tenant_id: str, name: str) -> tuple[str, str, str]:
    # The database is part of the key: a process that changes DB_PATH (the suite does)
    # must not see another database's roles.
    return (str(DB_PATH), str(tenant_id or ""), str(name or ""))


def _forget_custom_role(tenant_id: str, name: str) -> None:
    _custom_role_cache.pop(_custom_role_key(tenant_id, name), None)


def _custom_role_row(row) -> dict:
    try:
        granted = sorted(str(item) for item in json.loads(row["permissions"] or "[]"))
    except (TypeError, ValueError):
        granted = []
    return {
        "name": row["name"],
        "label": row["label"] or row["name"],
        "description": row["description"] or "",
        "permissions": granted,
        "builtin": False,
        "created_by": row["created_by"] or "",
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


@_tenant_scoped
def list_custom_roles(tenant_id: str) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT name, label, description, permissions, created_by, created_at, updated_at "
            "FROM custom_roles WHERE tenant_id = ? ORDER BY name",
            (tenant_id,),
        ).fetchall()
    return [_custom_role_row(row) for row in rows]


@_tenant_scoped
def get_custom_role(tenant_id: str, name: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT name, label, description, permissions, created_by, created_at, updated_at "
            "FROM custom_roles WHERE tenant_id = ? AND name = ?",
            (tenant_id, str(name or "")),
        ).fetchone()
    return _custom_role_row(row) if row is not None else None


def custom_role_permissions(tenant_id: str, name: str) -> frozenset | None:
    """The permissions a tenant's custom role grants, or None when it has no such role."""
    key = _custom_role_key(tenant_id, name)
    cached = _custom_role_cache.get(key)
    now = time.monotonic()
    if cached is not None and cached[0] > now:
        return cached[1]
    role = get_custom_role(key[1], key[2]) if key[1] and key[2] else None
    granted = frozenset(role["permissions"]) if role is not None else None
    _custom_role_cache[key] = (now + _CUSTOM_ROLE_TTL_SECONDS, granted)
    return granted


def role_exists(role: str, tenant_id: str) -> bool:
    """A built-in role, or a custom role of this tenant."""
    return is_known_role(role) or custom_role_permissions(tenant_id, role) is not None


@_tenant_scoped
def save_custom_role(tenant_id: str, name: str, label: str, description: str, permissions, actor: str) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    granted = json.dumps(sorted(permissions))
    with _lock:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO custom_roles (tenant_id, name, label, description, permissions, created_by, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (tenant_id, name) DO UPDATE SET label = excluded.label, "
                "description = excluded.description, permissions = excluded.permissions, updated_at = excluded.updated_at",
                (tenant_id, name, label, description, granted, actor, now, now),
            )
    _forget_custom_role(tenant_id, name)
    return get_custom_role(tenant_id, name)


@_tenant_scoped
def delete_custom_role(tenant_id: str, name: str) -> bool:
    with _lock:
        with _connect() as conn:
            deleted = conn.execute(
                "DELETE FROM custom_roles WHERE tenant_id = ? AND name = ?", (tenant_id, name)
            ).rowcount
    _forget_custom_role(tenant_id, name)
    return bool(deleted)


def _scan_target_row(row) -> dict:
    return {"entry_id": row["entry_id"], "kind": row["kind"], "value": row["value"], "note": row["note"],
            "created_by": row["created_by"], "created_at": row["created_at"]}


@_tenant_scoped
def list_scan_targets(tenant_id: str) -> list[dict]:
    """The networks and host names this tenant may scan (C5, backend/target_scope)."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT entry_id, kind, value, note, created_by, created_at FROM scan_targets "
            "WHERE tenant_id = ? ORDER BY kind DESC, value",
            (tenant_id,),
        ).fetchall()
    return [_scan_target_row(row) for row in rows]


@_tenant_scoped
def add_scan_target(tenant_id: str, kind: str, value: str, note: str, actor: str, *, limit: int = 500) -> dict:
    """Add one entry; a value the tenant already lists is refused, as is a list at its limit."""
    entry_id = secrets.token_hex(8)
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            existing = conn.execute("SELECT entry_id FROM scan_targets WHERE tenant_id = ? AND value = ?",
                                    (tenant_id, value)).fetchone()
            if existing is not None:
                raise ValueError(f"{value} is already in this workspace's scan targets.")
            count = conn.execute("SELECT COUNT(*) FROM scan_targets WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
            if int(count) >= limit:
                raise ValueError(f"A workspace can list at most {limit} scan targets; use a wider network.")
            conn.execute(
                "INSERT INTO scan_targets (tenant_id, entry_id, kind, value, note, created_by, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, entry_id, kind, value, note, actor, now),
            )
    return {"entry_id": entry_id, "kind": kind, "value": value, "note": note, "created_by": actor, "created_at": now}


@_tenant_scoped
def delete_scan_target(tenant_id: str, entry_id: str) -> dict | None:
    """Remove one entry of this tenant's; None when it has no such entry."""
    with _lock:
        with _connect() as conn:
            row = conn.execute(
                "SELECT entry_id, kind, value, note, created_by, created_at FROM scan_targets "
                "WHERE tenant_id = ? AND entry_id = ?", (tenant_id, str(entry_id or "")),
            ).fetchone()
            if row is None:
                return None
            conn.execute("DELETE FROM scan_targets WHERE tenant_id = ? AND entry_id = ?", (tenant_id, row["entry_id"]))
    return _scan_target_row(row)


@_tenant_scoped
def role_holders(tenant_id: str, name: str) -> dict:
    """Who still holds a role in this tenant: a role in use is not deleted from under them."""
    with _connect() as conn:
        users = conn.execute("SELECT COUNT(*) FROM users WHERE tenant_id = ? AND role = ?", (tenant_id, name)).fetchone()[0]
        keys = conn.execute(
            "SELECT COUNT(*) FROM api_keys WHERE tenant_id = ? AND role = ? AND revoked = 0", (tenant_id, name)
        ).fetchone()[0]
        invites = conn.execute(
            "SELECT COUNT(*) FROM registration_invites WHERE tenant_id = ? AND role = ? AND revoked = 0 "
            "AND used_count < max_uses",
            (tenant_id, name),
        ).fetchone()[0]
    return {"users": int(users), "api_keys": int(keys), "invites": int(invites)}


def create_user(username: str, password_hash: str, role: str, tenant_id: str = "default", full_name: str = "",
                *, login_name: str = "", auth_source: str = "local", external_id: str = "",
                directory_synced_at: int = 0) -> dict:
    """`username` is the installation-unique account key; `login_name` (default: the key)
    is what the person types, unique within the tenant (C2)."""
    _require_known_role(role, tenant_id)
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO users
                    (username, password_hash, role, tenant_id, full_name, is_active, created_at, updated_at,
                     login_name, auth_source, external_id, directory_synced_at)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
                """,
                (username, password_hash, role, tenant_id, full_name, now, now, login_name or username,
                 auth_source, external_id, int(directory_synced_at)),
            )
    user = get_user(username)
    if user is None:
        raise RuntimeError("User was not created")
    return user


def get_user(username: str) -> dict | None:
    with _connect() as conn:
        return _read_user(conn, username)


def token_state(jti: str, username: str) -> tuple[bool, dict | None]:
    """Whether a token is revoked, and the account it names - in ONE connection (C1).

    verify_token needs both on every request. A token revoked by another backend has to
    be refused at once, so the revocation cannot come from a per-process memory of "not
    revoked"; asking the database separately would cost a second connection per request
    (3.7 ms measured on SQLite, most of it opening the connection). Asked together with
    the user row verify_token was already reading, it costs one indexed lookup.
    """
    if not jti:
        return True, None
    ttl = _revocation_cache_seconds()
    if ttl:
        with _revocation_cache_lock:
            cached = _revocation_cache.get(jti)
            if cached and cached[1] and time.monotonic() - cached[0] <= ttl:
                return True, None
    with _connect() as conn:
        revoked = conn.execute(
            "SELECT 1 FROM revoked_tokens WHERE jti = ? AND expires_at >= ?", (jti, int(time.time()))
        ).fetchone() is not None
        user = None if revoked else _read_user(conn, username)
        if user is not None:
            # C2: whether THIS session proved a second factor - read in the same
            # connection, so the MFA gate costs no extra round trip.
            session = conn.execute("SELECT mfa_verified FROM user_sessions WHERE jti = ?", (jti,)).fetchone()
            user["session_mfa_verified"] = bool(session and session["mfa_verified"])
    if revoked and ttl:
        with _revocation_cache_lock:
            if len(_revocation_cache) >= _REVOCATION_CACHE_MAX:
                _revocation_cache.clear()
            _revocation_cache[jti] = (time.monotonic(), True)
    return revoked, user


def _read_user(conn, username: str) -> dict | None:
    row = conn.execute(
        """
        SELECT username, password_hash, role, tenant_id, full_name, is_active,
               created_at, updated_at, last_login_at, avatar,
               login_name, auth_source, external_id, directory_synced_at
        FROM users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()
    if row is None:
        return None
    return {
        "username": row["username"],
        "password_hash": row["password_hash"],
        "role": row["role"],
        "tenant_id": row["tenant_id"],
        "full_name": row["full_name"],
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "last_login_at": row["last_login_at"],
        "avatar": row["avatar"] or "",
        "login_name": row["login_name"] or row["username"],
        "auth_source": row["auth_source"] or "local",
        "external_id": row["external_id"] or "",
        "directory_synced_at": int(row["directory_synced_at"] or 0),
    }


def list_users(tenant_id: str | None = None) -> list[dict]:
    params: tuple = ()
    where = ""
    if tenant_id:
        where = "WHERE tenant_id = ?"
        params = (tenant_id,)
    with _connect() as conn:
        rows = conn.execute(
            f"""
            SELECT username, role, tenant_id, full_name, is_active, created_at, updated_at, last_login_at,
                   login_name, auth_source
            FROM users
            {where}
            ORDER BY tenant_id, username
            """,
            params,
        ).fetchall()
    return [
        {
            "username": row["username"],
            "role": row["role"],
            "tenant_id": row["tenant_id"],
            "full_name": row["full_name"],
            "is_active": bool(row["is_active"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "last_login_at": row["last_login_at"],
            "login_name": row["login_name"] or row["username"],
            "auth_source": row["auth_source"] or "local",
        }
        for row in rows
    ]


def update_user_role(username: str, role: str, tenant_id: str | None = None) -> dict | None:
    current = get_user(username)
    if current is None:
        return None
    _require_known_role(role, tenant_id or current["tenant_id"])
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            result = conn.execute(
                """
                UPDATE users
                SET role = ?, tenant_id = COALESCE(?, tenant_id), updated_at = ?
                WHERE username = ?
                """,
                (role, tenant_id, now, username),
            )
            if result.rowcount == 0:
                return None
    return get_user(username)


def update_user_password(username: str, password_hash: str) -> dict | None:
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            result = conn.execute(
                "UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?",
                (password_hash, now, username),
            )
            if result.rowcount == 0:
                return None
    return get_user(username)


def update_user_profile(username: str, full_name: str) -> dict | None:
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            result = conn.execute(
                "UPDATE users SET full_name = ?, updated_at = ? WHERE username = ?",
                (full_name, now, username),
            )
            if result.rowcount == 0:
                return None
    return get_user(username)


def update_user_avatar(username: str, avatar: str) -> dict | None:
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            result = conn.execute(
                "UPDATE users SET avatar = ?, updated_at = ? WHERE username = ?",
                (avatar, now, username),
            )
            if result.rowcount == 0:
                return None
    return get_user(username)


def get_app_setting(key: str) -> str | None:
    """Install-wide key/value settings (runtime feature flags and the like)."""
    with _connect() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    return None if row is None else row["value"]


def set_app_setting(key: str, value: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                (key, value, now),
            )


def delete_user(username: str) -> dict | None:
    user = get_user(username)
    if user is None:
        return None
    with _lock:
        with _connect() as conn:
            # C2: the second factor goes with the account. Left behind, it would be
            # waiting for the next account given the same key - someone else's
            # authenticator on a new person's sign-in.
            conn.execute("DELETE FROM user_mfa WHERE username = ?", (username,))
            conn.execute("DELETE FROM users WHERE username = ?", (username,))
    return user


def mark_user_login(username: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute("UPDATE users SET last_login_at = ? WHERE username = ?", (now, username))



# Rows older than this are gone whatever throttle wrote them - the longest window any
# throttle uses, with room to spare - so keys nobody asks about again do not accumulate.
_THROTTLE_HORIZON_SECONDS = 86_400


def _prune_throttle_rows(conn, rate_key: str, cutoff: float) -> None:
    """C8: prune THIS key by its own window, and everything else only by the horizon.

    Pruning every key by the caller's window was harmless while sign-in was the only
    throttle and all its keys shared one window. Once throttles with different windows
    share the table, a ten-minute check would erase the history a one-hour throttle is
    counting.
    """
    conn.execute("DELETE FROM login_failures WHERE rate_key = ? AND timestamp < ?", (rate_key, cutoff))
    conn.execute("DELETE FROM login_failures WHERE timestamp < ?",
                 (time.time() - _THROTTLE_HORIZON_SECONDS,))


def count_login_failures(rate_key: str, window_seconds: int) -> int:
    cutoff = time.time() - max(1, int(window_seconds))
    with _lock:
        with _connect() as conn:
            _prune_throttle_rows(conn, rate_key, cutoff)
            return int(
                conn.execute(
                    "SELECT COUNT(*) FROM login_failures WHERE rate_key = ? AND timestamp >= ?",
                    (rate_key, cutoff),
                ).fetchone()[0]
            )


def record_login_failure(rate_key: str, window_seconds: int) -> None:
    now = time.time()
    cutoff = now - max(1, int(window_seconds))
    with _lock:
        with _connect() as conn:
            _prune_throttle_rows(conn, rate_key, cutoff)
            conn.execute("INSERT INTO login_failures (rate_key, timestamp) VALUES (?, ?)", (rate_key, now))


def take_throttle_slot(rate_key: str, window_seconds: int, limit: int) -> bool:
    """Count an attempt and answer whether it is within `limit`, in one locked step (the
    check and the record, apart, let parallel requests through together)."""
    now = time.time()
    cutoff = now - max(1, int(window_seconds))
    with _lock:
        with _connect() as conn:
            _prune_throttle_rows(conn, rate_key, cutoff)
            used = int(conn.execute("SELECT COUNT(*) FROM login_failures WHERE rate_key = ? AND timestamp >= ?",
                                    (rate_key, cutoff)).fetchone()[0])
            if used >= limit:
                return False
            conn.execute("INSERT INTO login_failures (rate_key, timestamp) VALUES (?, ?)", (rate_key, now))
    return True


def clear_login_failures(rate_key: str) -> None:
    with _lock:
        with _connect() as conn:
            conn.execute("DELETE FROM login_failures WHERE rate_key = ?", (rate_key,))


def _max_sessions_per_user() -> int:
    """How many live sessions one account may hold. 0 disables the cap."""
    try:
        return max(0, int(os.getenv("DSPM_MAX_SESSIONS_PER_USER", "16")))
    except ValueError:
        return 16


def record_session(jti: str, username: str, issued_at: int, expires_at: int, mfa_verified: bool = False) -> None:
    """Remember a token that was just issued, and hold the account to its cap.

    The cap is what stops a stolen credential quietly accumulating sessions, and what
    bounds this table. The oldest sessions past it are revoked rather than deleted, so a
    token that is still in someone's hands stops working instead of being forgotten.
    """

    if not jti or not username:
        return
    now = int(time.time())
    cap = _max_sessions_per_user()
    with _lock:
        with _connect() as conn:
            conn.execute("DELETE FROM user_sessions WHERE expires_at < ?", (now,))
            conn.execute(
                "INSERT OR REPLACE INTO user_sessions (jti, username, issued_at, expires_at, last_seen_at, mfa_verified) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (jti, username, int(issued_at), int(expires_at), now, 1 if mfa_verified else 0),
            )
            surplus = []
            if cap:
                # Everything past the newest `cap`. `LIMIT -1 OFFSET ?` said that in SQLite
                # only; PostgreSQL refuses a negative LIMIT (found by the C0.5 run). An
                # account holds at most cap + 1 rows here, so the skip is done in Python.
                # Times are whole seconds, so sessions issued within one second tie: the
                # one being recorded always ranks first - it must never be the one revoked
                # - and the rest break ties by id, the same way on every backend.
                surplus = [
                    (str(row["jti"]), int(row["expires_at"]))
                    for row in conn.execute(
                        "SELECT jti, expires_at FROM user_sessions WHERE username = ? "
                        "ORDER BY CASE WHEN jti = ? THEN 0 ELSE 1 END, last_seen_at DESC, issued_at DESC, jti DESC",
                        (username, jti),
                    ).fetchall()[cap:]
                ]
            revoked_at = datetime.now(timezone.utc).isoformat()
            for old_jti, old_exp in surplus:
                conn.execute(
                    "INSERT OR REPLACE INTO revoked_tokens (jti, expires_at, revoked_at) VALUES (?, ?, ?)",
                    (old_jti, old_exp, revoked_at),
                )
                conn.execute("DELETE FROM user_sessions WHERE jti = ?", (old_jti,))
    if surplus:
        _forget_revocation()


def session_last_seen(jti: str) -> int | None:
    """When this session was last used, as the database knows it; None if unknown."""
    if not jti:
        return None
    with _connect() as conn:
        row = conn.execute("SELECT last_seen_at FROM user_sessions WHERE jti = ?", (jti,)).fetchone()
    return int(row["last_seen_at"]) if row else None


def touch_session(jti: str, seen_at: int | None = None) -> None:
    if not jti:
        return
    with _lock:
        with _connect() as conn:
            conn.execute(
                "UPDATE user_sessions SET last_seen_at = ? WHERE jti = ?",
                (int(seen_at if seen_at is not None else time.time()), jti),
            )


def forget_session(jti: str) -> None:
    """Drop a session row whose token has been revoked; the revocation itself stands."""
    if not jti:
        return
    with _lock:
        with _connect() as conn:
            conn.execute("DELETE FROM user_sessions WHERE jti = ?", (jti,))


def revoke_sessions_for_user(username: str, *, keep_jti: str = "") -> int:
    """End every session this account holds. Returns how many were ended.

    Called when the password changes: the point of changing a password after a
    compromise is that whoever had the old one is signed out, everywhere, including
    from the processes that never saw them sign in.
    """

    if not username:
        return 0
    revoked_at = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT jti, expires_at FROM user_sessions WHERE username = ?", (username,)
            ).fetchall()
            ended = 0
            for row in rows:
                jti = str(row["jti"])
                if keep_jti and jti == keep_jti:
                    continue
                conn.execute(
                    "INSERT OR REPLACE INTO revoked_tokens (jti, expires_at, revoked_at) VALUES (?, ?, ?)",
                    (jti, int(row["expires_at"]), revoked_at),
                )
                conn.execute("DELETE FROM user_sessions WHERE jti = ?", (jti,))
                ended += 1
    if ended:
        _forget_revocation()
    # A refresh token outliving the sessions it belongs to would mint new ones.
    revoke_refresh_tokens_for_user(username)
    return ended


def issue_refresh_token(token_hash: str, family_id: str, username: str,
                        session_jti: str, issued_at: int, expires_at: int, mfa_verified: bool = False) -> None:
    """Record a refresh token. Only its hash is stored - the secret itself lives in the
    caller's cookie, so a copy of this table is not a set of working credentials."""
    if not token_hash or not family_id or not username:
        return
    with _lock:
        with _connect() as conn:
            conn.execute("DELETE FROM refresh_tokens WHERE expires_at < ?", (int(time.time()),))
            conn.execute(
                "INSERT OR REPLACE INTO refresh_tokens "
                "(token_hash, family_id, username, session_jti, issued_at, expires_at, used_at, mfa_verified) "
                "VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
                (token_hash, family_id, username, session_jti, int(issued_at), int(expires_at),
                 1 if mfa_verified else 0),
            )


def consume_refresh_token(token_hash: str) -> dict:
    """Retire a refresh token and say what presenting it meant.

    Returns {"status": ...} where status is:
      * ``ok``       - it was current; the row is returned and is now spent,
      * ``replayed`` - it had already been spent. Two parties hold this chain and there
                       is no way to tell which one this is, so the caller revokes the
                       family: better both sign in again than one of them be an attacker
                       with a working session,
      * ``expired``  - past its absolute life,
      * ``unknown``  - never issued here, or already cleaned up.
    """

    if not token_hash:
        return {"status": "unknown"}
    now = int(time.time())
    with _lock:
        with _connect() as conn:
            row = conn.execute(
                "SELECT token_hash, family_id, username, session_jti, issued_at, expires_at, used_at, mfa_verified "
                "FROM refresh_tokens WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if row is None:
                return {"status": "unknown"}
            record = {key: row[key] for key in row.keys()}
            if int(record["used_at"]):
                return {"status": "replayed", **record}
            if int(record["expires_at"]) < now:
                conn.execute("DELETE FROM refresh_tokens WHERE token_hash = ?", (token_hash,))
                return {"status": "expired", **record}
            conn.execute("UPDATE refresh_tokens SET used_at = ? WHERE token_hash = ?", (now, token_hash))
    return {"status": "ok", **record}


def revoke_refresh_family(family_id: str) -> int:
    """End a refresh chain and every access session it issued. Returns sessions ended."""
    if not family_id:
        return 0
    revoked_at = datetime.now(timezone.utc).isoformat()
    ended = 0
    with _lock:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT session_jti FROM refresh_tokens WHERE family_id = ? AND session_jti <> ''",
                (family_id,),
            ).fetchall()
            for row in rows:
                jti = str(row["session_jti"])
                session = conn.execute(
                    "SELECT expires_at FROM user_sessions WHERE jti = ?", (jti,)
                ).fetchone()
                if session is not None:
                    conn.execute(
                        "INSERT OR REPLACE INTO revoked_tokens (jti, expires_at, revoked_at) VALUES (?, ?, ?)",
                        (jti, int(session["expires_at"]), revoked_at),
                    )
                    conn.execute("DELETE FROM user_sessions WHERE jti = ?", (jti,))
                    ended += 1
            conn.execute("DELETE FROM refresh_tokens WHERE family_id = ?", (family_id,))
    if ended:
        _forget_revocation()
    return ended


def revoke_refresh_tokens_for_user(username: str) -> int:
    """Every refresh chain this account holds. A password change has to reach these:
    ending the access sessions alone would leave a token that mints new ones."""
    if not username:
        return 0
    with _lock:
        with _connect() as conn:
            removed = conn.execute(
                "DELETE FROM refresh_tokens WHERE username = ?", (username,)
            ).rowcount
    return int(removed or 0)


def count_refresh_tokens_for_user(username: str) -> int:
    with _connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM refresh_tokens WHERE username = ?", (username,)
        ).fetchone()
    return int(row["n"] if row else 0)


def count_sessions_for_user(username: str) -> int:
    with _connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM user_sessions WHERE username = ?", (username,)
        ).fetchone()
    return int(row["n"] if row else 0)


def consume_one_time_token(token_id: str, expires_at: int) -> bool:
    """Spend a one-time credential. True only for the caller that spent it.

    C8: download tokens are single use. Checking "has it been used?" and then recording
    that it has would let two requests racing with one copied link both pass the check;
    the insert itself is the check here, so exactly one of them wins. The row lives in
    revoked_tokens because a spent token IS a revoked one, and that table already prunes
    itself by expiry.
    """

    if not token_id:
        return False
    now = int(time.time())
    revoked_at = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (now,))
            spent = conn.execute(
                "INSERT INTO revoked_tokens (jti, expires_at, revoked_at) VALUES (?, ?, ?) "
                "ON CONFLICT (jti) DO NOTHING",
                (f"dl:{token_id}", int(expires_at), revoked_at),
            ).rowcount
    return bool(spent)


def revoke_token_jti(jti: str, expires_at: int) -> None:
    if not jti:
        return
    now = datetime.now(timezone.utc).isoformat()
    cutoff = int(__import__("time").time())
    with _lock:
        with _connect() as conn:
            # Pruning belongs with the write: it used to run on every read.
            conn.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (cutoff,))
            conn.execute(
                "INSERT OR REPLACE INTO revoked_tokens (jti, expires_at, revoked_at) VALUES (?, ?, ?)",
                (jti, int(expires_at), now),
            )
    # This process just made the cached answer wrong.
    _forget_revocation()


_revocation_cache: dict[str, tuple[float, bool]] = {}
_revocation_cache_lock = threading.Lock()
_REVOCATION_CACHE_MAX = 4096


def _revocation_cache_seconds() -> float:
    try:
        value = float(os.getenv("DSPM_TOKEN_REVOCATION_CACHE_SECONDS", "30"))
    except ValueError:
        value = 30.0
    return max(0.0, min(value, 300.0))


def _forget_revocation(jti: str = "") -> None:
    with _revocation_cache_lock:
        if jti:
            _revocation_cache.pop(jti, None)
        else:
            _revocation_cache.clear()


def is_token_revoked(jti: str) -> bool:
    """Whether a token has been revoked - by this backend or any other.

    C1: only a REVOKED answer is remembered. A revocation never comes undone, so caching
    it is safe; "not revoked" is exactly the answer another backend can make wrong at any
    moment - a sign-out, a password change - and remembering it kept a revoked token
    working on every backend but the one that revoked it, for the length of the cache.
    That is one primary-key lookup per authenticated request, and correctness across
    backends does not come cheaper.
    """
    if not jti:
        return True
    ttl = _revocation_cache_seconds()
    now_mono = time.monotonic()
    if ttl:
        with _revocation_cache_lock:
            cached = _revocation_cache.get(jti)
            if cached and cached[1] and now_mono - cached[0] <= ttl:
                return True
    with _lock:
        with _connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM revoked_tokens WHERE jti = ? AND expires_at >= ?",
                (jti, int(time.time())),
            ).fetchone()
    revoked = row is not None
    if ttl and revoked:
        with _revocation_cache_lock:
            if len(_revocation_cache) >= _REVOCATION_CACHE_MAX:
                _revocation_cache.clear()
            _revocation_cache[jti] = (now_mono, True)
    return revoked



def update_user_active(username: str, is_active: bool) -> dict | None:
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            result = conn.execute(
                "UPDATE users SET is_active = ?, updated_at = ? WHERE username = ?",
                (1 if is_active else 0, now, username),
            )
            if result.rowcount == 0:
                return None
    return get_user(username)


# ── Scope for every store function (C10) ─────────────────────────────────────────
# PostgreSQL's policies deny a transaction that names neither a tenant nor a purpose,
# so every function that reaches a tenant table must name one. Two rules, applied
# here so a function added later cannot forget:
#
# * A function whose first parameter is tenant_id runs in that tenant's scope.
#   Where None means "every tenant", ALL_TENANTS_PURPOSE names the platform purpose.
# * A function that serves no single tenant runs in the purpose PLATFORM_FUNCTIONS
#   names. tests/test_platform_scope.py fails on a database-touching function that is
#   in neither group and not in NO_TENANT_TABLES (it touches only tables without
#   tenant rows: sessions, refresh tokens, revocations, settings, throttles).

# ---- C2: accounts found by workspace and sign-in name; directory settings; MFA ----

def find_user_by_login(tenant_id: str, login_name: str) -> dict | None:
    """The account this workspace knows by this sign-in name (revision 0026)."""
    with _connect() as conn:
        row = conn.execute("SELECT username FROM users WHERE tenant_id = ? AND login_name = ?",
                           (tenant_id, login_name)).fetchone()
        return _read_user(conn, row["username"]) if row else None


def find_directory_user(tenant_id: str, external_id: str) -> dict | None:
    """The account a directory entry was provisioned as, by the directory's own id."""
    if not external_id:
        return None
    with _connect() as conn:
        row = conn.execute("SELECT username FROM users WHERE tenant_id = ? AND auth_source = 'ldap' AND external_id = ?",
                           (tenant_id, external_id)).fetchone()
        return _read_user(conn, row["username"]) if row else None


def allocate_account_key(login_name: str, tenant_id: str) -> str | None:
    """An installation-unique account key for a new account: the sign-in name itself when
    no account anywhere holds it, else `name@workspace`. None when both are taken. The
    key is internal - a person signs in with their workspace and sign-in name - so a
    name used in another workspace no longer blocks, or reveals, anything."""
    candidates = [login_name, f"{login_name}@{tenant_id}"[:80]]
    with _connect() as conn:
        for candidate in candidates:
            if conn.execute("SELECT 1 FROM users WHERE username = ?", (candidate,)).fetchone() is None:
                return candidate
    return None


def update_directory_account(username: str, *, role: str, login_name: str, full_name: str,
                             synced_at: int, active: bool = True) -> dict | None:
    """Bring a directory account in line with what the directory said at `synced_at`."""
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute(
                "UPDATE users SET role = ?, login_name = ?, full_name = ?, directory_synced_at = ?, is_active = ?, "
                "updated_at = ? WHERE username = ? AND auth_source = 'ldap'",
                (role, login_name, full_name, int(synced_at), 1 if active else 0, now, username),
            )
            return _read_user(conn, username)


def get_directory_settings(tenant_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT tenant_id, enabled, config_json, bind_secret_ref, updated_by, updated_at "
            "FROM directory_settings WHERE tenant_id = ?", (tenant_id,)).fetchone()
    if row is None:
        return None
    try:
        config = json.loads(row["config_json"] or "{}")
    except (TypeError, ValueError):
        config = {}
    return {"tenant_id": row["tenant_id"], "enabled": bool(row["enabled"]), "config": config,
            "bind_secret_ref": row["bind_secret_ref"] or "", "updated_by": row["updated_by"],
            "updated_at": row["updated_at"]}


def save_directory_settings(tenant_id: str, enabled: bool, config: dict, bind_secret_ref: str, updated_by: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO directory_settings "
                "(tenant_id, enabled, config_json, bind_secret_ref, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (tenant_id, 1 if enabled else 0, json.dumps(config, sort_keys=True), bind_secret_ref or "",
                 updated_by, now),
            )


def delete_directory_settings(tenant_id: str) -> None:
    with _lock:
        with _connect() as conn:
            conn.execute("DELETE FROM directory_settings WHERE tenant_id = ?", (tenant_id,))


def get_user_mfa(username: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT username, tenant_id, secret_ciphertext, enabled, confirmed_at, last_step, recovery_hashes, "
            "pending_ciphertext, pending_expires_at, updated_at FROM user_mfa WHERE username = ?", (username,)
        ).fetchone()
    if row is None:
        return None
    record = {key: row[key] for key in row.keys()}
    record["enabled"] = bool(record["enabled"])
    try:
        record["recovery_hashes"] = list(json.loads(record["recovery_hashes"] or "[]"))
    except (TypeError, ValueError):
        record["recovery_hashes"] = []
    return record


def begin_mfa_enrollment(tenant_id: str, username: str, pending_ciphertext: str, pending_expires_at: int) -> None:
    """Hold a new secret until the person proves they captured it. An enabled factor
    stays in force until the new one is confirmed."""
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            existing = conn.execute("SELECT 1 FROM user_mfa WHERE username = ?", (username,)).fetchone()
            if existing:
                conn.execute("UPDATE user_mfa SET pending_ciphertext = ?, pending_expires_at = ?, updated_at = ? "
                             "WHERE username = ? AND tenant_id = ?",
                             (pending_ciphertext, int(pending_expires_at), now, username, tenant_id))
            else:
                conn.execute("INSERT INTO user_mfa (username, tenant_id, pending_ciphertext, pending_expires_at, "
                             "updated_at) VALUES (?, ?, ?, ?, ?)",
                             (username, tenant_id, pending_ciphertext, int(pending_expires_at), now))


def confirm_mfa_enrollment(tenant_id: str, username: str, secret_ciphertext: str, recovery_hashes: list[str],
                           step: int) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute(
                "UPDATE user_mfa SET secret_ciphertext = ?, enabled = 1, confirmed_at = ?, last_step = ?, "
                "recovery_hashes = ?, pending_ciphertext = '', pending_expires_at = 0, updated_at = ? "
                "WHERE username = ? AND tenant_id = ?",
                (secret_ciphertext, now, int(step), json.dumps(recovery_hashes), now, username, tenant_id),
            )


def replace_recovery_hashes(tenant_id: str, username: str, recovery_hashes: list[str]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute("UPDATE user_mfa SET recovery_hashes = ?, updated_at = ? WHERE username = ? AND tenant_id = ?",
                         (json.dumps(recovery_hashes), now, username, tenant_id))


def delete_user_mfa(tenant_id: str, username: str) -> bool:
    with _lock:
        with _connect() as conn:
            result = conn.execute("DELETE FROM user_mfa WHERE username = ? AND tenant_id = ?", (username, tenant_id))
    return bool(result.rowcount)


def consume_mfa_step(username: str, step: int) -> bool:
    """Accept a TOTP time step at most once, and never one older than the last accepted:
    a code seen over a shoulder or in a proxy log cannot be played again (RFC 6238 §5.2).
    One conditional UPDATE, so two sign-ins racing with the same code cannot both win."""
    with _lock:
        with _connect() as conn:
            result = conn.execute("UPDATE user_mfa SET last_step = ? WHERE username = ? AND enabled = 1 AND last_step < ?",
                                  (int(step), username, int(step)))
    return result.rowcount == 1


def consume_recovery_code(username: str, code_hash: str) -> int | None:
    """Spend one recovery code. Returns how many remain, or None when it was not one."""
    with _lock:
        with _connect() as conn:
            row = conn.execute("SELECT recovery_hashes FROM user_mfa WHERE username = ? AND enabled = 1",
                               (username,)).fetchone()
            if row is None:
                return None
            try:
                hashes = list(json.loads(row["recovery_hashes"] or "[]"))
            except (TypeError, ValueError):
                return None
            if code_hash not in hashes:
                return None
            hashes.remove(code_hash)
            result = conn.execute("UPDATE user_mfa SET recovery_hashes = ? WHERE username = ? AND recovery_hashes = ?",
                                  (json.dumps(hashes), username, row["recovery_hashes"]))
            if result.rowcount != 1:
                return None  # spent by a concurrent sign-in
    return len(hashes)


def mark_session_mfa(jti: str) -> None:
    """The session proved a second factor (a step-up after sign-in)."""
    if not jti:
        return
    with _lock:
        with _connect() as conn:
            conn.execute("UPDATE user_sessions SET mfa_verified = 1 WHERE jti = ?", (jti,))
            conn.execute("UPDATE refresh_tokens SET mfa_verified = 1 WHERE session_jti = ? AND used_at = 0", (jti,))


ALL_TENANTS_PURPOSE = {
    "list_users": "platform-admin",
    "list_tenants": "platform-admin",
    "requeue_expired_partitions": "resume",
    "requeue_interrupted_partitions": "resume",
    "purge_demo_sample_assets": "housekeeping",
    "backfill_normalized_scans": "migration",
    "verify_audit_chain": "housekeeping",
    "refresh_read_model_state": "housekeeping",
    "bump_estate_generation": "housekeeping",
}

PLATFORM_FUNCTIONS = {
    # Accounts are found by name, key or token before their tenant is known.
    "get_user": "auth", "create_user": "auth", "delete_user": "auth", "mark_user_login": "auth",
    "update_user_active": "auth", "update_user_avatar": "auth", "update_user_password": "auth",
    "update_user_profile": "auth", "update_user_role": "auth", "token_state": "auth",
    "get_active_api_key": "auth", "touch_api_key": "auth",
    "allocate_account_key": "auth", "update_directory_account": "auth", "get_user_mfa": "auth",
    "consume_mfa_step": "auth", "consume_recovery_code": "auth",
    "claim_due_schedules": "scheduler",
    "vault_sealed_values": "vault", "vault_sealed_rows": "vault", "reseal_vault_values": "vault",
    "claim_audit_outbox": "siem", "delete_audit_outbox": "siem", "retry_audit_outbox": "siem",
    "audit_outbox_status": "siem", "reset_audit_outbox_backoff": "siem",
    "_prune_audit_chains": "housekeeping", "prune_event_tables": "housekeeping",
    "prune_job_records": "housekeeping", "referenced_artifact_ids": "housekeeping",
    "recover_interrupted_jobs": "resume", "list_unfinished_partitioned_scans": "resume",
    "iter_search_asset_batches": "search-indexer", "get_search_assets_by_refs": "search-indexer",
    "init_db": "migration",
}

# Functions that name their scope themselves, from their arguments.
SCOPED_INSIDE = {"record_job", "reset_default_tenant_data", "delete_tenant_with_data"}

NO_TENANT_TABLES = {
    "_connect", "claim_housekeeping_run", "clear_login_failures", "count_login_failures",
    "record_login_failure", "take_throttle_slot", "consume_one_time_token", "is_token_revoked", "revoke_token_jti",
    "consume_refresh_token", "count_refresh_tokens_for_user", "issue_refresh_token",
    "revoke_refresh_family", "revoke_refresh_tokens_for_user", "count_sessions_for_user",
    "forget_session", "record_session", "session_last_seen", "touch_session",
    "revoke_sessions_for_user", "get_app_setting", "set_app_setting", "get_search_reconciliation",
    "mark_session_mfa",
    "save_search_reconciliation", "tenant_isolation_coverage", "tenants_under_legal_hold",
}


def _apply_scopes() -> None:
    namespace = globals()
    for name, func in list(namespace.items()):
        if not inspect.isfunction(func) or func.__module__ != __name__:
            continue
        if name in PLATFORM_FUNCTIONS:
            namespace[name] = _platform_scoped(PLATFORM_FUNCTIONS[name])(func)
            continue
        params = list(inspect.signature(func).parameters)
        if params and params[0] == "tenant_id" and not getattr(func, "_tenant_scoped", False):
            namespace[name] = _tenant_scoped(func, ALL_TENANTS_PURPOSE.get(name))
        elif name in ALL_TENANTS_PURPOSE and getattr(func, "_tenant_scoped", False):
            namespace[name] = _tenant_scoped(inspect.unwrap(func), ALL_TENANTS_PURPOSE[name])


_apply_scopes()
