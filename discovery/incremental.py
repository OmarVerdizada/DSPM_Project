"""First-class incremental-scan identities and reusable snapshots.

The collectors deliberately know nothing about the database.  They enumerate an
object's cheap fingerprint (identity, size and mtime) and ask the discovery
engine for a snapshot.  This module keeps the source/scope identity contract and
the snapshot shape shared across local, SMB and endpoint collectors.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def incremental_scope_key(source: str, target: str, options: dict[str, Any] | None = None) -> str:
    """Return a stable, non-secret key for one complete enumeration scope.

    Scope includes collection options that change which objects are visible. A
    narrower or differently-filtered scan therefore cannot prune the baseline
    created by a broader scan.
    """

    payload = {
        "schema": "sentro-incremental-scope-v1",
        "source": str(source or "").strip().lower(),
        "target": str(target or "").strip().lower(),
        "options": options or {},
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def qualified_object_key(source: str, target: str, path: str) -> str:
    """Source-qualify an object path so hosts/connectors can never collide."""

    source_value = str(source or "unknown").strip().lower()
    target_value = str(target or "local").strip().lower()
    path_value = str(path or "").replace("\\", "/")
    if not path_value.startswith("/"):
        path_value = f"/{path_value}"
    return f"{source_value}://{target_value}{path_value}"


def reuse_snapshot_from_result(result: dict[str, Any]) -> dict[str, Any]:
    """Convert a durable analyzed asset into the collector snapshot contract."""

    result = result if isinstance(result, dict) else {}
    preview = result.get("preview") if isinstance(result.get("preview"), dict) else None
    return {
        "owner": result.get("owner", ""),
        "acl": result.get("acl") or {},
        "content_status": result.get("content_status") or "reused_from_baseline",
        "content_scannable": bool(result.get("content_scannable", False)),
        "scan_error": result.get("scan_error", ""),
        "protected": bool(result.get("protected", False)),
        "protection_type": result.get("protection_type", ""),
        "sha256": result.get("sha256") or result.get("file_hash") or "",
        "content_hash": result.get("content_hash") or "",
        "scan_completeness": result.get("scan_completeness") or "UNKNOWN",
        "bytes_scanned": int(result.get("bytes_scanned") or 0),
        "total_bytes": int(result.get("total_bytes") or result.get("size") or 0),
        "truncated": bool(result.get("truncated", False)),
        "preview": preview,
        # Internal only. The discovery engine removes this before returning or
        # persisting the current file record.
        "baseline_result": result,
    }


def snapshot_is_failed_read(snapshot: dict[str, Any] | None) -> bool:
    """True when a cached result records a read that failed, not the file's content.

    A remote collector reuses an unchanged file by its size and modified time. Neither
    changes when the account is granted read access, nor when a download link that had
    expired is replaced, so a cached failure would be replayed for as long as the file
    stays unchanged. Such a result is read again instead.
    """

    return isinstance(snapshot, dict) and str(snapshot.get("content_status") or "") == "unreadable"


def apply_reuse_snapshot(record: dict[str, Any], snapshot: dict[str, Any], object_key: str) -> dict[str, Any]:
    """Overlay reusable state on freshly enumerated metadata without content I/O."""

    reused = dict(record or {})
    reused.update(
        {
            "content": "",
            "acl": snapshot.get("acl") or {},
            "content_status": str(snapshot.get("content_status") or "reused_from_baseline"),
            "content_scannable": bool(snapshot.get("content_scannable", False)),
            "scan_error": str(snapshot.get("scan_error") or ""),
            "protected": bool(snapshot.get("protected", False)),
            "protection_type": str(snapshot.get("protection_type") or ""),
            "owner": str(snapshot.get("owner") or ""),
            "sha256": str(snapshot.get("sha256") or ""),
            "file_hash": str(snapshot.get("sha256") or ""),
            "content_hash": str(snapshot.get("content_hash") or ""),
            "scan_completeness": str(snapshot.get("scan_completeness") or "UNKNOWN"),
            "bytes_scanned": int(snapshot.get("bytes_scanned") or 0),
            "total_bytes": int(snapshot.get("total_bytes") or reused.get("size") or 0),
            "truncated": bool(snapshot.get("truncated", False)),
            "cache_reused": True,
            "incremental_reused": True,
            "reused_preview": snapshot.get("preview") if isinstance(snapshot.get("preview"), dict) else None,
            "baseline_result": snapshot.get("baseline_result") if isinstance(snapshot.get("baseline_result"), dict) else None,
            "reuse_key": object_key,
        }
    )
    return reused
