from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import threading
from pathlib import Path
from typing import Any

from backend.copilot.insights import InsightCard


_lock = threading.Lock()
DEFAULT_TENANT = "__global__"


def _db_path() -> str:
    configured = os.environ.get("DSPM_INSIGHT_DB", str(Path("data") / "insights.db"))
    if configured == ":memory:":
        return str(Path(tempfile.gettempdir()) / f"dspm_insights_{os.getpid()}.sqlite")
    return configured


def _connect() -> sqlite3.Connection:
    path = _db_path()
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    if path != ":memory:":
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS insights (
            tenant_id TEXT NOT NULL DEFAULT '__global__',
            insight_id TEXT NOT NULL,
            insight_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title_en TEXT NOT NULL,
            title_az TEXT NOT NULL,
            body_en TEXT NOT NULL,
            body_az TEXT NOT NULL,
            created_at TEXT NOT NULL,
            action_label_en TEXT,
            action_label_az TEXT,
            action_query TEXT,
            metadata TEXT DEFAULT '{}',
            dismissed INTEGER DEFAULT 0,
            PRIMARY KEY (tenant_id, insight_id)
        )
        """
    )
    conn.commit()
    return conn


def save_insights(insights: list[InsightCard], tenant_id: str | None = None) -> None:
    safe_tenant = tenant_id or DEFAULT_TENANT
    if not insights:
        return
    with _lock:
        conn = _connect()
        try:
            for item in insights:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO insights
                    (tenant_id, insight_id, insight_type, severity, title_en, title_az,
                     body_en, body_az, created_at, action_label_en, action_label_az,
                     action_query, metadata, dismissed)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        safe_tenant,
                        item.insight_id,
                        item.insight_type.value,
                        item.severity.value,
                        item.title_en,
                        item.title_az,
                        item.body_en,
                        item.body_az,
                        item.created_at,
                        item.action_label_en,
                        item.action_label_az,
                        item.action_query,
                        json.dumps(item.metadata, ensure_ascii=False),
                        int(item.dismissed),
                    ),
                )
            conn.commit()
        finally:
            conn.close()


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    metadata = row["metadata"] or "{}"
    try:
        parsed_metadata = json.loads(metadata)
    except json.JSONDecodeError:
        parsed_metadata = {}
    return {
        "insight_id": row["insight_id"],
        "insight_type": row["insight_type"],
        "severity": row["severity"],
        "title_en": row["title_en"],
        "title_az": row["title_az"],
        "body_en": row["body_en"],
        "body_az": row["body_az"],
        "created_at": row["created_at"],
        "action_label_en": row["action_label_en"],
        "action_label_az": row["action_label_az"],
        "action_query": row["action_query"],
        "metadata": parsed_metadata,
    }


def get_active_insights(limit: int = 20, tenant_id: str | None = None) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit or 20), 100))
    safe_tenant = tenant_id or DEFAULT_TENANT
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT insight_id, insight_type, severity, title_en, title_az, body_en, body_az,
                       created_at, action_label_en, action_label_az, action_query, metadata
                FROM insights
                WHERE dismissed = 0 AND tenant_id = ?
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 0
                        WHEN 'warning' THEN 1
                        WHEN 'info' THEN 2
                        WHEN 'success' THEN 3
                        ELSE 4
                    END,
                    created_at DESC
                LIMIT ?
                """,
                (safe_tenant, safe_limit),
            ).fetchall()
            return [_row_to_dict(row) for row in rows]
        finally:
            conn.close()


def dismiss_insight(insight_id: str, tenant_id: str | None = None) -> bool:
    safe_tenant = tenant_id or DEFAULT_TENANT
    with _lock:
        conn = _connect()
        try:
            cursor = conn.execute(
                "UPDATE insights SET dismissed = 1 WHERE tenant_id = ? AND insight_id = ?",
                (safe_tenant, insight_id),
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()


def get_insight(insight_id: str, tenant_id: str | None = None) -> dict[str, Any] | None:
    safe_tenant = tenant_id or DEFAULT_TENANT
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                """
                SELECT insight_id, insight_type, severity, title_en, title_az, body_en, body_az,
                       created_at, action_label_en, action_label_az, action_query, metadata
                FROM insights
                WHERE dismissed = 0 AND tenant_id = ? AND insight_id = ?
                """,
                (safe_tenant, insight_id),
            ).fetchone()
            return _row_to_dict(row) if row else None
        finally:
            conn.close()


def clear_insights_for_tests() -> None:
    with _lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM insights")
            conn.commit()
        finally:
            conn.close()
