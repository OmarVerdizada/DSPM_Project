from __future__ import annotations

import base64
import functools
import json
import math
import os
import re
import secrets
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend import db
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
    predicate = (
        "COALESCE(current_setting('app.tenant_id', true), '*') "
        "IN ('*', tenant_id)"
    )
    for table in tables:
        conn.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        conn.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        conn.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        conn.execute(
            f"CREATE POLICY tenant_isolation ON {table} FOR ALL "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )


def _tenant_scoped(func):
    """Run a store function inside db.tenant_scope(<first argument>).

    On PostgreSQL every transaction the function opens is then confined by
    the revision-0004 RLS policies to that tenant; on SQLite this is a no-op.
    Apply to functions whose first positional argument is tenant_id and whose
    queries serve user-shaped input.
    """
    @functools.wraps(func)
    def wrapper(tenant_id, *args, **kwargs):
        with db.tenant_scope(str(tenant_id)):
            return func(tenant_id, *args, **kwargs)
    return wrapper


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
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, scan_id)
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            detail_json TEXT NOT NULL DEFAULT '{}'
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

        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
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
        CREATE INDEX IF NOT EXISTS idx_occurrences_scan
            ON finding_occurrences (tenant_id, scan_id);
        CREATE INDEX IF NOT EXISTS idx_occurrences_finding
            ON finding_occurrences (finding_id);
        CREATE INDEX IF NOT EXISTS idx_finding_index_tenant_scan
            ON finding_index (tenant_id, scan_id);
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
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scan_jobs_tenant
            ON scan_jobs (tenant_id, created_at);

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
    # the read-switch treats them as stale and serves the blob until a
    # backfill re-stamps them - the safe default for a migration mirror.
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


def audit(tenant_id: str, actor: str, action: str, detail: dict | None = None) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (tenant_id, timestamp, actor, action, detail_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (tenant_id, timestamp, actor, action, json.dumps(detail or {}, ensure_ascii=False)),
            )


def report_artifacts_enabled() -> bool:
    """Store report bodies in the artifact tier (Phase 5, DB-07).

    On by default. ``DSPM_REPORT_ARTIFACTS=0`` keeps bodies inline in the
    database - the pre-Phase-5 behaviour - for an install that has not yet
    added the artifact directory to its backup set.
    """
    return os.getenv("DSPM_REPORT_ARTIFACTS", "1") != "0"


def _store_report_body(tenant_id: str, body: str) -> tuple[str, int, str]:
    """Persist a report body; returns (report_ref, report_bytes, inline_body).

    The object is durable before the row that references it. The reverse order
    would risk a reference to a body that does not exist; this order risks only
    an unreferenced object, which ``artifacts.prune()`` collects.
    """
    if not report_artifacts_enabled():
        return "", len(body.encode("utf-8")), body
    from backend import artifacts

    ref = artifacts.put_text(tenant_id, body)
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
            normalized_written = _dual_write_normalized(conn, tenant_id, report)
            if normalized_written:
                _write_incremental_baseline(conn, tenant_id, report, is_new_scan=existing is None)
            else:
                incremental = (report.get("scan_diagnostics") or {}).get("incremental")
                if isinstance(incremental, dict) and incremental.get("enabled"):
                    incremental["baseline_committed"] = False
                    incremental["baseline_commit_reason"] = "normalized_asset_write_unavailable"
            body = json.dumps(report, ensure_ascii=False)
            report_ref, report_bytes, inline_body = _store_report_body(tenant_id, body)
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_reports
                    (tenant_id, scan_id, timestamp, source, scan_label, summary_json,
                     report_json, report_ref, report_bytes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    created_at,
                ),
            )
    _invalidate_inventory_query_cache(tenant_id)
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


def _dual_write_normalized(conn, tenant_id: str, report: dict) -> bool:
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
        _write_normalized_rows(conn, tenant_id, report)
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


def _write_incremental_baseline(conn, tenant_id: str, report: dict, *, is_new_scan: bool = True) -> None:
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
                    json.dumps(record, ensure_ascii=False, separators=(",", ":")),
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
                json.dumps(record, ensure_ascii=False, separators=(",", ":")),
            )
        )
        if len(rows) >= 500:
            flush_rows()
    flush_rows()

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
    incremental["baseline_committed"] = True
    incremental["baseline_rows_written"] = rows_written
    incremental["baseline_rows_skipped"] = skipped
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
        detail = json.loads(row["snapshot_json"])
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
                child_detail = json.loads(child["snapshot_json"] or "{}")
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
                conn.execute(f"DELETE FROM findings WHERE asset_id = ?{scope_sql}", args)
                conn.execute(f"DELETE FROM assets WHERE id = ?{scope_sql}", args)
    if demo_ids:
        logger.info("Purged %d demo-sample assets from the estate%s", len(demo_ids), f" (tenant {tenant_id})" if tenant_id else "")
    return len(demo_ids)


# One-time hygiene migration at startup: estates written before the demo-scan
# exclusion existed may still carry synthetic sample assets. Idempotent and a
# no-op once clean (or when DSPM_DEMO_ASSETS_IN_INVENTORY=1 opts back in).
try:
    purge_demo_sample_assets()
except Exception as exc:  # pragma: no cover - never block startup on hygiene
    logger.warning("Demo-sample estate purge skipped: %s", type(exc).__name__)


def _write_normalized_rows(conn, tenant_id: str, report: dict) -> None:
    from backend.domain import normalize_scan_report

    scan = normalize_scan_report(tenant_id, report)
    scan_id = scan.scan_run.id
    if not scan_id:
        return
    # Demo-dataset scans stay per-scan records (report blob, scan_runs,
    # occurrences, finding index) but never enter the durable estate: the
    # dashboard and Data Inventory describe the customer's real data, and
    # synthetic sample files inflating those numbers is a defect, not a demo.
    write_estate = _demo_assets_allowed_in_inventory() or not is_demo_sample_report(report)
    # Refresh this scan's occurrences so a re-save (e.g. a lifecycle update) is
    # idempotent rather than duplicating rows.
    conn.execute("DELETE FROM finding_occurrences WHERE tenant_id = ? AND scan_id = ?", (tenant_id, scan_id))

    run = scan.scan_run
    # DATA-002: a scan run is immutable and append-only. The first write creates
    # it; later re-saves (finding-lifecycle updates that refresh the blob) must
    # NOT overwrite it. INSERT OR IGNORE keeps the original run record; mutable
    # finding lifecycle lives in the `findings` aggregate below, not here.
    conn.execute(
        """
        INSERT OR IGNORE INTO scan_runs
            (tenant_id, id, source, mode, policy_version, started_at, ended_at, status, total_files, summary_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (tenant_id, run.id, run.source, run.mode, run.policy_version, run.started_at, run.ended_at, run.status, run.total_files, json.dumps(run.summary, ensure_ascii=False)),
    )
    for asset in scan.assets if write_estate else []:
        conn.execute(
            "INSERT INTO assets "
            "(tenant_id, id, source, stable_object_id, path, name, extension, share, "
            "risk_level, risk_score, size, owner, modified_at, finding_count, "
            "top_frameworks, is_hidden, is_system, is_protected, search_text, "
            "finding_types, framework_keys, detail_json, scan_label) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (tenant_id, id) DO UPDATE SET "
            "source = excluded.source, stable_object_id = excluded.stable_object_id, "
            "path = excluded.path, name = excluded.name, extension = excluded.extension, "
            "share = excluded.share, risk_level = excluded.risk_level, risk_score = excluded.risk_score, "
            "size = excluded.size, owner = excluded.owner, modified_at = excluded.modified_at, "
            "finding_count = excluded.finding_count, top_frameworks = excluded.top_frameworks, "
            "is_hidden = excluded.is_hidden, is_system = excluded.is_system, "
            "is_protected = excluded.is_protected, search_text = excluded.search_text, "
            "finding_types = excluded.finding_types, framework_keys = excluded.framework_keys, "
            "detail_json = excluded.detail_json, scan_label = excluded.scan_label",
            (tenant_id, asset.id, asset.source, asset.stable_object_id, asset.path, asset.name,
             asset.extension, asset.share, asset.risk_level, asset.risk_score, asset.size,
             asset.owner, asset.modified_at, asset.finding_count, asset.top_frameworks,
             asset.is_hidden, asset.is_system, asset.is_protected, asset.search_text,
             asset.finding_types, asset.framework_keys, asset.detail_json, asset.scan_label),
        )
    for version in scan.asset_versions if write_estate else []:
        conn.execute(
            "INSERT OR REPLACE INTO asset_versions (tenant_id, asset_id, version, size, mtime, content_hash, coverage) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tenant_id, version.asset_id, version.version, version.size, version.mtime, version.content_hash, version.coverage),
        )
    for finding in scan.findings if write_estate else []:
        conn.execute(
            """
            INSERT OR REPLACE INTO findings
                (tenant_id, id, asset_id, rule, severity, category, framework, status, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?,
                    COALESCE((SELECT first_seen FROM findings WHERE tenant_id = ? AND id = ?), ?), ?)
            """,
            (tenant_id, finding.id, finding.asset_id, finding.rule, finding.severity, finding.category, finding.framework, finding.status,
             tenant_id, finding.id, finding.first_seen, finding.last_seen),
        )
    for occurrence in scan.occurrences:
        conn.execute(
            "INSERT INTO finding_occurrences (tenant_id, finding_id, scan_id, locator, fingerprint, occurrence_count) VALUES (?, ?, ?, ?, ?, ?)",
            (tenant_id, occurrence.finding_id, occurrence.scan_id, occurrence.locator, occurrence.fingerprint, occurrence.occurrence_count),
        )

    _write_finding_index(conn, tenant_id, report)


def _write_finding_index(conn, tenant_id: str, report: dict) -> None:
    """Materialize the exact per-finding list_findings response (read-switch).

    Stores what list_findings would produce for each finding of this scan, so
    the read path can serve findings without loading full report blobs. Refreshed
    per scan so a re-save is idempotent.
    """
    scan_id = str(report.get("scan_id") or "")
    if not scan_id:
        return
    conn.execute("DELETE FROM finding_index WHERE tenant_id = ? AND scan_id = ?", (tenant_id, scan_id))
    seq = 0
    for row in _iter_report_findings(report):
        finding = row["finding"]
        finding_id = str(finding.get("finding_id") or "")
        if not finding_id:
            continue
        conn.execute(
            "INSERT INTO finding_index (tenant_id, scan_id, seq, finding_id, status, response_json, index_version) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tenant_id, scan_id, seq, finding_id, _finding_status(finding), json.dumps(_finding_response(row), ensure_ascii=False), FINDING_INDEX_VERSION),
        )
        seq += 1


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
            with _lock:
                with _connect() as conn:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO scan_jobs
                            (id, tenant_id, status, progress, message, created_at, finished_at, error, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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


def recover_interrupted_jobs() -> int:
    """Mark jobs left queued/running by a prior process as failed (ARCH-003).

    Called at startup: the in-memory executor cannot survive a restart, so any
    still-open job is orphaned. Returns the number recovered.
    """
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            cursor = conn.execute(
                """
                UPDATE scan_jobs
                SET status = 'failed',
                    message = 'Interrupted',
                    error = 'Scan was interrupted by a backend restart. Re-run the scan.',
                    finished_at = COALESCE(finished_at, ?),
                    updated_at = ?
                WHERE status IN ('queued', 'running')
                """,
                (now, now),
            )
            return cursor.rowcount


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


def list_findings(tenant_id: str, status: str = "", limit: int = 200) -> list[dict]:
    # Read-switch (DATA-001): when enabled AND the mirror is provably complete
    # and current for this tenant (F2), serve findings from the materialized
    # finding_index instead of loading every report blob. Default off; a stale or
    # incomplete mirror - or any error - falls back to the authoritative blob.
    if _read_from_normalized(tenant_id):
        try:
            return _list_findings_normalized(tenant_id, status, limit)
        except Exception as exc:  # pragma: no cover - defensive fallback
            logger.warning("Normalized list_findings failed, falling back to blob: %s", exc)

    wanted_status = str(status or "").strip().upper()
    findings: dict[str, dict] = {}
    for item in reversed(read_scan_history(tenant_id, limit=1000)):
        report = read_scan_report(tenant_id, item.get("scan_id"))
        if not report:
            continue
        for row in _iter_report_findings(report):
            finding = row["finding"]
            finding_id = str(finding.get("finding_id") or "")
            if not finding_id or finding_id in findings:
                continue
            current_status = _finding_status(finding)
            if wanted_status and current_status != wanted_status:
                continue
            findings[finding_id] = _finding_response(row)
            if len(findings) >= max(1, min(int(limit or 200), 1000)):
                return list(findings.values())
    return list(findings.values())


def _list_findings_normalized(tenant_id: str, status: str, limit: int) -> list[dict]:
    """Read-switch implementation of list_findings over the finding_index.

    Mirrors the blob path exactly: newest scan first (created_at DESC, scan_id
    DESC), findings in report order (seq), dedup by finding_id on what has been
    kept, then the status filter, bounded to the 1000 newest scans and `limit`
    findings. Because the index stores the exact _finding_response output, the
    result is identical to the blob path.
    """
    wanted_status = str(status or "").strip().upper()
    cap = max(1, min(int(limit or 200), 1000))
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT fi.finding_id AS finding_id, fi.status AS status, fi.response_json AS response_json
            FROM finding_index AS fi
            JOIN scan_reports AS sr
              ON sr.tenant_id = fi.tenant_id AND sr.scan_id = fi.scan_id
            WHERE fi.tenant_id = ?
              AND fi.scan_id IN (
                  SELECT scan_id FROM scan_reports
                  WHERE tenant_id = ?
                  ORDER BY created_at DESC, scan_id DESC
                  LIMIT 1000
              )
            ORDER BY sr.created_at DESC, sr.scan_id DESC, fi.seq ASC
            """,
            (tenant_id, tenant_id),
        ).fetchall()

    findings: dict[str, dict] = {}
    for row in rows:
        finding_id = str(row["finding_id"] or "")
        if not finding_id or finding_id in findings:
            continue
        if wanted_status and str(row["status"] or "") != wanted_status:
            continue
        findings[finding_id] = json.loads(row["response_json"])
        if len(findings) >= cap:
            break
    return list(findings.values())


def _normalized_ready(tenant_id: str) -> bool:
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

# name -> (column, is_text, direction). All parity-safe: numeric compare, or text
# under COLLATE "C". risk_score is the default (highest risk first).
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
_INVENTORY_COUNT_CAP = 10000
_INVENTORY_CURSOR_VERSION = "sc-v2"
_INVENTORY_COUNT_CACHE_MAX = 256
_inventory_count_cache: dict[tuple, tuple[float, int]] = {}
_inventory_query_cache_lock = threading.Lock()


class InventoryReadUnavailable(RuntimeError):
    """Normalized inventory was selected but could not safely serve the read."""


def _invalidate_inventory_query_cache(tenant_id: str | None = None) -> None:
    """Invalidate short-lived inventory aggregates after an authoritative write."""
    with _inventory_query_cache_lock:
        if tenant_id is None:
            _inventory_count_cache.clear()
            return
        for key in [item for item in _inventory_count_cache if item[1] == tenant_id]:
            _inventory_count_cache.pop(key, None)


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


def _inventory_ready(tenant_id: str) -> bool:
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


def _encode_cursor(sort: str, sort_value, asset_id: str) -> str:
    raw = json.dumps([_INVENTORY_CURSOR_VERSION, sort, sort_value, asset_id], ensure_ascii=False)
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def _decode_cursor(cursor: str, sort: str, is_text: bool):
    """Decode a cursor only when its version, sort, value type and asset id fit.

    S-C's original two-item cursors remain accepted for in-flight clients. The
    strict asset-id/type checks also prevent a Meilisearch or cross-sort cursor
    from causing a database type error and triggering an expensive fallback.
    """
    if not cursor:
        return None
    try:
        decoded = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8"))
        if isinstance(decoded, list) and len(decoded) == 4:
            version, cursor_sort, value, asset_id = decoded
            if version != _INVENTORY_CURSOR_VERSION or cursor_sort != sort:
                return None
        elif isinstance(decoded, list) and len(decoded) == 2:
            value, asset_id = decoded
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


def _inventory_filters(risk: str, source: str, framework: str, q: str, extension: str,
                       protected: bool | None = None, finding_type: str = "") -> dict:
    frameworks = [part.strip().lower() for part in str(framework or "").split(",") if part.strip()]
    return {
        "risk": str(risk or "").strip().upper(),
        "source": str(source or "").strip().lower(),
        "extension": str(extension or "").strip().lower(),
        "framework": frameworks[0] if len(frameworks) == 1 else "",
        "frameworks": frameworks,
        "finding_type": str(finding_type or "").strip().lower(),
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
    if filt["risk"]:
        where.append("risk_level = ?"); params.append(filt["risk"])
    if filt["source"]:
        # The Source filter accepts either a collector protocol ("smb") or the
        # operator-facing scan name ("HR file share"), so the inventory can be
        # narrowed to one configured scan without a second parameter.
        where.append("(source = ? OR lower(COALESCE(scan_label, '')) = ?)")
        params.extend([filt["source"], filt["source"]])
    if filt["extension"]:
        where.append("extension = ?"); params.append(filt["extension"])
    if filt["protected"] is not None:
        where.append("is_protected = ?"); params.append(1 if filt["protected"] else 0)
    if filt["finding_type"]:
        where.append("lower(COALESCE(finding_types, '[]')) LIKE ? ESCAPE '\\'")
        params.append(_json_member_pattern(filt["finding_type"]))
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
                   finding_type: str = "", sort: str = "risk_score",
                   cursor: str = "", limit: int = 100) -> dict:
    """One keyset-paginated page of the file inventory. Filters: risk (level),
    source, framework(s, OR), protected state, exact finding type, q
    (search_text), extension. Returns
    {items, next_cursor, has_more, total, total_is_estimate, source}."""
    sort = sort if sort in INVENTORY_SORTS else _DEFAULT_INVENTORY_SORT
    limit = max(1, min(int(limit or 100), 500))
    filt = _inventory_filters(risk, source, framework, q, extension, protected, finding_type)
    # A selected operator-facing scan means "show that scan's latest saved
    # result", not "show current assets whose most recent observation still
    # happens to carry this label".  Resolve the immutable run before choosing
    # the current-estate normalized/search paths.
    selected_report = read_latest_scan_report_by_label(tenant_id, source) if source else None
    if selected_report is not None:
        result = _list_inventory_scan_report(tenant_id, selected_report, filt, sort, cursor, limit)
        result["source"] = "scan-report"
        result["scan_id"] = str(selected_report.get("scan_id") or "")
        result["scan_label"] = str(selected_report.get("scan_label") or "")
        return result
    # S-F valve: only text searches opt into the dedicated engine. Placeholder
    # inventory browsing keeps S-C keyset pagination. A separate read-enable
    # switch supports backfill/shadow operation before cutover.
    if filt["q"]:
        try:
            from backend.search import SearchUnavailable, external_search_requested, search_inventory

            if external_search_requested():
                col, _, direction = INVENTORY_SORTS[sort]
                return search_inventory(tenant_id, filt, col, direction, cursor, limit)
        except SearchUnavailable as exc:
            logger.warning("Dedicated inventory search unavailable, falling back to DB: %s", exc)
        except Exception as exc:  # pragma: no cover - optional projection guard
            logger.warning("Dedicated inventory search failed, falling back to DB: %s", type(exc).__name__)
    if _read_inventory_from_normalized(tenant_id):
        try:
            result = _list_inventory_normalized(tenant_id, filt, sort, cursor, limit)
            result["source"] = "normalized"
            return result
        except Exception as exc:  # pragma: no cover - operational failure path
            logger.error("Normalized inventory read failed: %s", type(exc).__name__)
            raise InventoryReadUnavailable("Normalized inventory is temporarily unavailable") from exc
    result = _list_inventory_blob(tenant_id, filt, sort, cursor, limit)
    result["source"] = "blob"
    return result


def _list_inventory_normalized(tenant_id: str, filt: dict, sort: str, cursor: str, limit: int) -> dict:
    col, is_text, direction = INVENTORY_SORTS[sort]
    order_expr = db.collate_c(f"COALESCE({col}, '')") if is_text else col
    # Asset ids are fixed lowercase hex, so their order is identical under C and
    # locale collations. Keep the raw column so S-C.1 composite indexes match.
    id_expr = "id"
    op = "<" if direction == "DESC" else ">"

    where, params = _inventory_normalized_where(tenant_id, filt)

    count_where, count_params = list(where), list(params)

    decoded = _decode_cursor(cursor, sort, is_text)
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
        f"SELECT {', '.join(_INVENTORY_COLS)} FROM assets WHERE {' AND '.join(where)} "
        f"ORDER BY {order_expr} {direction}, {id_expr} {direction} LIMIT ?"
    )
    params.append(limit + 1)
    with _connect() as conn:
        rows = conn.execute(sql, tuple(params)).fetchall()
        total = _capped_inventory_total(conn, tenant_id, count_where, count_params)

    return _inventory_page(
        [{c: r[c] for c in _INVENTORY_COLS} for r in rows], sort, col, is_text, limit, total
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
                    risk = (json.loads(row["detail_json"] or "{}") or {}).get("risk") or {}
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
    from backend.domain import normalize_scan_report

    scan_id = str(report.get("scan_id") or "")
    rows: list[dict] = []
    for asset in normalize_scan_report(tenant_id, report).assets:
        row = {column: getattr(asset, column) for column in _INVENTORY_COLS}
        row["search_text"] = asset.search_text
        row["scan_id"] = scan_id
        try:
            detail = json.loads(asset.detail_json or "{}")
        except (json.JSONDecodeError, TypeError):
            detail = {}
        risk_detail = detail.get("risk") if isinstance(detail, dict) else {}
        risk_detail = risk_detail if isinstance(risk_detail, dict) else {}
        row["reason_count"] = len(risk_detail.get("reasons") or [])
        row["dlp_count"] = len(risk_detail.get("dlp_recommendations") or [])
        rows.append(row)
    return rows


def _inventory_page_from_rows(
    rows: list[dict], filt: dict, sort: str, cursor: str, limit: int, *, source_already_matched: bool = False,
) -> dict:
    """Apply the parity-safe inventory filters/sort/cursor to projected rows."""
    col, is_text, direction = INVENTORY_SORTS[sort]
    reverse = direction == "DESC"

    def _matches(row: dict) -> bool:
        if filt["risk"] and str(row.get("risk_level") or "") != filt["risk"]:
            return False
        if filt["source"] and not source_already_matched and filt["source"] not in {
            str(row.get("source") or "").lower(), str(row.get("scan_label") or "").lower(),
        }:
            return False
        if filt["extension"] and str(row.get("extension") or "") != filt["extension"]:
            return False
        if filt["protected"] is not None and bool(row.get("is_protected")) is not filt["protected"]:
            return False
        finding_types = {str(value).lower() for value in _decode_string_list(row.get("finding_types"))}
        if filt["finding_type"] and filt["finding_type"] not in finding_types:
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
    decoded = _decode_cursor(cursor, sort, is_text)
    if decoded is not None:
        cursor_value, cursor_id = decoded
        pivot = ((cursor_value or "") if is_text else (cursor_value or 0), str(cursor_id))
        matched = [row for row in matched if (_key(row) < pivot if reverse else _key(row) > pivot)]

    # search_text is an internal projection and is never returned to clients.
    for row in matched:
        row.pop("search_text", None)
    return _inventory_page(matched, sort, col, is_text, limit, total)


def _list_inventory_scan_report(
    tenant_id: str, report: dict, filt: dict, sort: str, cursor: str, limit: int,
) -> dict:
    return _inventory_page_from_rows(
        _scan_report_inventory_rows(tenant_id, report),
        filt,
        sort,
        cursor,
        limit,
        source_already_matched=True,
    )


def _list_inventory_blob(tenant_id: str, filt: dict, sort: str, cursor: str, limit: int) -> dict:
    from backend.domain import normalize_scan_report

    latest: dict[str, dict] = {}
    for item in read_scan_history(tenant_id, limit=1000):  # oldest-first -> newest scan overwrites
        report = read_scan_report(tenant_id, item.get("scan_id"))
        if not report:
            continue
        for asset in normalize_scan_report(tenant_id, report).assets:
            latest[asset.id] = {c: getattr(asset, c) for c in _INVENTORY_COLS} | {"search_text": asset.search_text}
    return _inventory_page_from_rows(list(latest.values()), filt, sort, cursor, limit)


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
    from backend.domain import normalize_scan_report

    latest: dict[str, dict] = {}
    for item in read_scan_history(tenant_id, limit=1000):
        report = read_scan_report(tenant_id, item.get("scan_id"))
        if not report:
            continue
        for asset in normalize_scan_report(tenant_id, report).assets:
            latest[asset.id] = asset.to_dict()
    return list(latest.values())


def _facet_items(counts: dict[str, int]) -> list[dict]:
    return [
        {"value": value, "count": count}
        for value, count in sorted(counts.items(), key=lambda item: (-item[1], item[0].lower()))
        if value
    ]


def _facets_from_rows(rows: list[dict], source: str) -> dict:
    risk_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    finding_counts: dict[str, int] = {}
    framework_counts: dict[str, int] = {}
    protected_count = 0
    hidden_count = 0
    sensitive_count = 0
    score_total = 0.0
    scan_label_counts: dict[str, int] = {}
    for row in rows:
        risk = str(row.get("risk_level") or "").upper()
        asset_source = str(row.get("source") or "workspace")
        if risk:
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        scan_label = str(row.get("scan_label") or "").strip()
        if scan_label:
            scan_label_counts[scan_label] = scan_label_counts.get(scan_label, 0) + 1
        else:
            # Protocol sources are the fallback for assets no named scan
            # covers; a labeled asset is reachable by its scan name, so its
            # protocol must not reappear as a duplicate filter option.
            source_counts[asset_source] = source_counts.get(asset_source, 0) + 1
        protected_count += 1 if row.get("is_protected") else 0
        hidden_count += 1 if row.get("is_hidden") else 0
        score_total += float(row.get("risk_score") or 0)
        row_finding_types = set(_decode_string_list(row.get("finding_types")))
        if row_finding_types or row.get("finding_count"):
            sensitive_count += 1
        for finding_type in row_finding_types:
            finding_counts[finding_type] = finding_counts.get(finding_type, 0) + 1
        for framework in set(_decode_string_list(row.get("framework_keys"))):
            framework_counts[framework] = framework_counts.get(framework, 0) + 1
    if protected_count:
        finding_counts["Protected / locked"] = protected_count
    return {
        "total": len(rows), "risk_counts": risk_counts, "protected": protected_count,
        "sources": _facet_items(source_counts), "scans": _facet_items(scan_label_counts),
        "finding_types": _facet_items(finding_counts),
        "frameworks": _facet_items(framework_counts),
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


@_tenant_scoped
def inventory_facets(tenant_id: str, source: str = "") -> dict:
    """Aggregate inventory filters without transferring asset rows to the browser.

    With a configured scan name, facets describe that scan's newest persisted
    run.  Without one, they continue to describe the tenant's current estate.
    """
    selected_report = read_latest_scan_report_by_label(tenant_id, source) if source else None
    if selected_report is not None:
        return _facets_from_rows(_scan_report_inventory_rows(tenant_id, selected_report), "scan-report")
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
                finding_rows = _normalized_json_facet_rows(conn, tenant_id, "finding_types")
                framework_rows = _normalized_json_facet_rows(conn, tenant_id, "framework_keys")
            finding_counts = {str(row["value"]): int(row["n"]) for row in finding_rows if row["value"]}
            framework_counts = {str(row["value"]): int(row["n"]) for row in framework_rows if row["value"]}
            protected_count = int(protected_row["n"] if protected_row else 0)
            if protected_count:
                finding_counts["Protected / locked"] = protected_count
            return {
                "total": int(total_row["n"] if total_row else 0),
                "risk_counts": {str(row["risk_level"] or "").upper(): int(row["n"]) for row in risk_rows if row["risk_level"]},
                "protected": protected_count,
                "sources": _facet_items({str(row["source"] or "workspace"): int(row["n"]) for row in source_rows}),
                "scans": _facet_items({str(row["scan_label"]): int(row["n"]) for row in scan_label_rows}),
                "finding_types": _facet_items(finding_counts),
                "frameworks": _facet_items(framework_counts),
                "hidden": int((estate_row["hidden_n"] if estate_row else 0) or 0),
                "sensitive": int((estate_row["sensitive_n"] if estate_row else 0) or 0),
                "avg_risk_score": float((estate_row["avg_score"] if estate_row else 0) or 0.0),
                "source": "normalized",
            }
        except Exception as exc:  # pragma: no cover - operational failure path
            logger.error("Normalized inventory facets failed: %s", type(exc).__name__)
            raise InventoryReadUnavailable("Normalized inventory facets are temporarily unavailable") from exc
    return _facets_from_rows(_inventory_blob_rows(tenant_id), "blob")


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
        from backend.domain import normalize_scan_report

        report = read_scan_report(tenant_id, scan_id)
        if report is None:
            return None
        for asset in normalize_scan_report(tenant_id, report).assets:
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
                    detail = json.loads(row["detail_json"] or "{}")
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


def _inventory_page(rows: list[dict], sort: str, col: str, is_text: bool, limit: int, total: int) -> dict:
    """Shared page assembly for both inventory paths (identical output shape)."""
    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = None
    if has_more and page:
        last = page[-1]
        value = last.get(col)
        next_cursor = _encode_cursor(sort, (value or "") if is_text else value, str(last.get("id") or ""))
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
              AND fi.scan_id IN (
                  SELECT scan_id FROM scan_reports
                  WHERE tenant_id = ?
                  ORDER BY created_at DESC, scan_id DESC
                  LIMIT 1000
              )
            ORDER BY sr.created_at DESC, sr.scan_id DESC, fi.seq ASC
            LIMIT 1
            """,
            (tenant_id, finding_id, tenant_id),
        ).fetchone()
    return json.loads(row["response_json"]) if row and row["response_json"] else None


def get_finding(tenant_id: str, finding_id: str) -> dict | None:
    if _read_from_normalized(tenant_id):
        try:
            response = _find_finding_response_normalized(tenant_id, finding_id)
            if response is not None:
                return response
        except Exception as exc:  # pragma: no cover - defensive fallback
            logger.warning("Normalized get_finding failed, falling back to blob: %s", exc)
    row = _find_finding_row(tenant_id, finding_id)
    return _finding_response(row) if row else None


def get_finding_history(tenant_id: str, finding_id: str) -> list[dict] | None:
    if _read_from_normalized(tenant_id):
        try:
            response = _find_finding_response_normalized(tenant_id, finding_id)
            if response is not None:
                return response.get("status_history") or response.get("history") or []
        except Exception as exc:  # pragma: no cover - defensive fallback
            logger.warning("Normalized get_finding_history failed, falling back to blob: %s", exc)
    row = _find_finding_row(tenant_id, finding_id)
    if not row:
        return None
    finding = row["finding"]
    return finding.get("status_history") or finding.get("history") or []


def get_finding_occurrences(tenant_id: str, finding_id: str) -> list[dict] | None:
    if _read_from_normalized(tenant_id):
        try:
            response = _find_finding_response_normalized(tenant_id, finding_id)
            if response is not None:
                return response.get("occurrences") or []
        except Exception as exc:  # pragma: no cover - defensive fallback
            logger.warning("Normalized get_finding_occurrences failed, falling back to blob: %s", exc)
    row = _find_finding_row(tenant_id, finding_id)
    if not row:
        return None
    return row["finding"].get("occurrences") or []


def update_finding_lifecycle(tenant_id: str, finding_id: str, action: str, payload: dict, actor: str) -> dict | None:
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


def tenant_exists(tenant_id: str) -> bool:
    with _connect() as conn:
        row = conn.execute("SELECT 1 FROM tenants WHERE tenant_id = ?", (tenant_id,)).fetchone()
    return row is not None


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
    tenant = get_tenant(tenant_id)
    if tenant is None:
        raise RuntimeError("Tenant was not created")
    return tenant


def get_tenant(tenant_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT tenant_id, display_name, registration_code, created_at, updated_at
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
            return result.rowcount > 0


_TENANT_ERASURE_TABLES = (
    "registration_invites",
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
    "findings",
    "finding_occurrences",
    "finding_index",
    "scan_jobs",
)


def _delete_tenant_scoped_data(conn, tenant_id: str) -> None:
    """Delete every tenant-keyed record while leaving identity rows to the caller."""
    for table in _TENANT_ERASURE_TABLES:
        conn.execute(f"DELETE FROM {table} WHERE tenant_id = ?", (tenant_id,))


def delete_tenant_with_data(tenant_id: str) -> dict:
    usage = tenant_usage(tenant_id)
    # Erasure is a platform operation on an arbitrary tenant: scope the
    # transaction to the target so RLS permits exactly these rows.
    with _lock, db.tenant_scope(tenant_id):
        with _connect() as conn:
            conn.execute("DELETE FROM users WHERE tenant_id = ?", (tenant_id,))
            _delete_tenant_scoped_data(conn, tenant_id)
            conn.execute("DELETE FROM tenants WHERE tenant_id = ?", (tenant_id,))
            # Erasure is only whole if it reaches the bodies too: once reports
            # live in the artifact tier, deleting the rows alone would leave the
            # customer's report contents on disk (Phase 5, DB-07).
            try:
                from backend import artifacts

                usage["artifacts_removed"] = artifacts.delete_tenant(tenant_id)
            except Exception as exc:  # pragma: no cover - erasure must not half-fail silently
                logger.error("Artifact erasure failed for tenant %s: %s", tenant_id, type(exc).__name__)
                raise
            # Reconciliation state covers the shared optional search projection,
            # not one tenant. Invalidate it after any erasure so the next pass
            # detects and removes documents that no longer exist in the DB.
            conn.execute("DELETE FROM search_reconciliation_state")
    _invalidate_inventory_query_cache(tenant_id)
    return usage


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
    with _lock:
        with _connect() as conn:
            admin = conn.execute(
                "SELECT 1 FROM users WHERE username = ? AND tenant_id = ?",
                ("admin", tenant_id),
            ).fetchone()
            if admin is None:
                raise RuntimeError("Cannot reset the default tenant without its built-in admin user")
            _delete_tenant_scoped_data(conn, tenant_id)
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


def save_secret(tenant_id: str, secret_id: str, ciphertext: str) -> None:
    with _lock:
        with _connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO secrets (tenant_id, secret_id, ciphertext, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (tenant_id, secret_id, ciphertext, datetime.now(timezone.utc).isoformat()),
            )


def read_secret(tenant_id: str, secret_id: str) -> str | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT ciphertext FROM secrets WHERE tenant_id = ? AND secret_id = ?",
            (tenant_id, secret_id),
        ).fetchone()
    return str(row["ciphertext"]) if row else None


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


def create_user(username: str, password_hash: str, role: str, tenant_id: str = "default", full_name: str = "") -> dict:
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO users
                    (username, password_hash, role, tenant_id, full_name, is_active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (username, password_hash, role, tenant_id, full_name, now, now),
            )
    user = get_user(username)
    if user is None:
        raise RuntimeError("User was not created")
    return user


def get_user(username: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT username, password_hash, role, tenant_id, full_name, is_active,
                   created_at, updated_at, last_login_at, avatar
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
            SELECT username, role, tenant_id, full_name, is_active, created_at, updated_at, last_login_at
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
        }
        for row in rows
    ]


def update_user_role(username: str, role: str, tenant_id: str | None = None) -> dict | None:
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
            conn.execute("DELETE FROM users WHERE username = ?", (username,))
    return user


def mark_user_login(username: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute("UPDATE users SET last_login_at = ? WHERE username = ?", (now, username))



def count_login_failures(rate_key: str, window_seconds: int) -> int:
    cutoff = __import__("time").time() - max(1, int(window_seconds))
    with _lock:
        with _connect() as conn:
            conn.execute("DELETE FROM login_failures WHERE timestamp < ?", (cutoff,))
            return int(
                conn.execute(
                    "SELECT COUNT(*) FROM login_failures WHERE rate_key = ? AND timestamp >= ?",
                    (rate_key, cutoff),
                ).fetchone()[0]
            )


def record_login_failure(rate_key: str, window_seconds: int) -> None:
    now = __import__("time").time()
    cutoff = now - max(1, int(window_seconds))
    with _lock:
        with _connect() as conn:
            conn.execute("DELETE FROM login_failures WHERE timestamp < ?", (cutoff,))
            conn.execute("INSERT INTO login_failures (rate_key, timestamp) VALUES (?, ?)", (rate_key, now))


def clear_login_failures(rate_key: str) -> None:
    with _lock:
        with _connect() as conn:
            conn.execute("DELETE FROM login_failures WHERE rate_key = ?", (rate_key,))


def revoke_token_jti(jti: str, expires_at: int) -> None:
    if not jti:
        return
    now = datetime.now(timezone.utc).isoformat()
    cutoff = int(__import__("time").time())
    with _lock:
        with _connect() as conn:
            conn.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (cutoff,))
            conn.execute(
                "INSERT OR REPLACE INTO revoked_tokens (jti, expires_at, revoked_at) VALUES (?, ?, ?)",
                (jti, int(expires_at), now),
            )


def is_token_revoked(jti: str) -> bool:
    if not jti:
        return True
    cutoff = int(__import__("time").time())
    with _lock:
        with _connect() as conn:
            conn.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (cutoff,))
            row = conn.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)).fetchone()
    return row is not None



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
