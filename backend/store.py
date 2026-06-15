from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.getenv("DSPM_DB_PATH", DATA_DIR / "dspm.sqlite"))
_lock = threading.Lock()


def db_path() -> Path:
    return DB_PATH


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


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


def init_db() -> None:
    with _lock:
        with _connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scan_reports (
                    tenant_id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    timestamp TEXT,
                    source TEXT,
                    summary_json TEXT NOT NULL DEFAULT '{}',
                    report_json TEXT NOT NULL,
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

                CREATE INDEX IF NOT EXISTS idx_scan_reports_tenant_created
                    ON scan_reports (tenant_id, created_at);
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
                """
            )
            now = datetime.now(timezone.utc).isoformat()
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(tenants)").fetchall()}
            if "registration_code" not in columns:
                conn.execute("ALTER TABLE tenants ADD COLUMN registration_code TEXT NOT NULL DEFAULT ''")
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


init_db()


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


def save_scan_history(tenant_id: str, report: dict) -> str:
    scan_id = report.get("scan_id") or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    report["scan_id"] = scan_id
    created_at = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_reports
                    (tenant_id, scan_id, timestamp, source, summary_json, report_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    scan_id,
                    report.get("timestamp"),
                    report.get("source"),
                    json.dumps(report.get("summary", {}), ensure_ascii=False),
                    json.dumps(report, ensure_ascii=False),
                    created_at,
                ),
            )
    return scan_id


def read_scan_history(tenant_id: str, limit: int | None = None) -> list[dict]:
    query = """
            SELECT scan_id, timestamp, source, summary_json
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
            "summary": json.loads(row["summary_json"] or "{}"),
        }
        for row in rows
    ]


def list_tenants() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT tenant_id, display_name, registration_code, created_at, updated_at
            FROM tenants
            ORDER BY tenant_id
            """
        ).fetchall()
    tenants: list[dict] = []
    for row in rows:
        tenant_id = row["tenant_id"]
        registration_code = ensure_registration_code(tenant_id, row["registration_code"])
        history = read_scan_history(tenant_id, limit=1)
        latest = history[-1] if history else {"summary": {}}
        tenants.append(
            {
                "tenant_id": tenant_id,
                "display_name": row["display_name"],
                "registration_code": registration_code,
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "scan_count": len(history),
                "latest": latest,
                "retention": data_retention_summary(tenant_id),
            }
        )
    if not tenants:
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


def delete_tenant_with_data(tenant_id: str) -> dict:
    usage = tenant_usage(tenant_id)
    with _lock:
        with _connect() as conn:
            conn.execute("DELETE FROM users WHERE tenant_id = ?", (tenant_id,))
            conn.execute("DELETE FROM scan_reports WHERE tenant_id = ?", (tenant_id,))
            conn.execute("DELETE FROM audit_events WHERE tenant_id = ?", (tenant_id,))
            conn.execute("DELETE FROM alert_events WHERE tenant_id = ?", (tenant_id,))
            conn.execute("DELETE FROM secrets WHERE tenant_id = ?", (tenant_id,))
            conn.execute("DELETE FROM tenants WHERE tenant_id = ?", (tenant_id,))
    return usage


def tenant_usage(tenant_id: str) -> dict:
    with _connect() as conn:
        users = conn.execute("SELECT COUNT(*) FROM users WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
        reports = conn.execute("SELECT COUNT(*) FROM scan_reports WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
        audits = conn.execute("SELECT COUNT(*) FROM audit_events WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
        alerts = conn.execute("SELECT COUNT(*) FROM alert_events WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
        secrets = conn.execute("SELECT COUNT(*) FROM secrets WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
    return {"users": users, "reports": reports, "audits": audits, "alerts": alerts, "secrets": secrets}


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
    return {
        "tenant_id": tenant_id,
        "database": "sqlite",
        "report_count": report_count,
        "audit_events": audit_count,
        "alert_events": alert_count,
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
                   created_at, updated_at, last_login_at
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
