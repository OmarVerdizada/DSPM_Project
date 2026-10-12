"""Track S-G: constant-memory inventory CSV and NDJSON serialization."""

from __future__ import annotations

import csv
import io
import json
import os
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone

from backend.store import iter_inventory_export_rows

_EXPORT_FIELDS = (
    "asset_id", "source", "path", "name", "extension", "share", "risk_level",
    "risk_score", "size_bytes", "owner", "modified_at", "finding_count",
    "frameworks", "finding_types", "hidden", "system", "protected",
)
_TEXT_FIELDS = {
    "asset_id", "source", "path", "name", "extension", "share", "risk_level",
    "owner", "modified_at", "frameworks", "finding_types",
}
_TARGET_CHUNK_BYTES = 64 * 1024


def _batch_size() -> int:
    try:
        configured = int(os.getenv("DSPM_EXPORT_BATCH_SIZE", "1000"))
    except (TypeError, ValueError):
        configured = 1_000
    return max(10, min(configured, 5_000))


def _decode_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    try:
        decoded = json.loads(str(value or "[]"))
    except (TypeError, ValueError, json.JSONDecodeError):
        decoded = []
    return [str(item) for item in decoded if str(item)] if isinstance(decoded, list) else []


def _export_record(row: dict) -> dict:
    frameworks = _decode_list(row.get("framework_keys"))
    if not frameworks:
        frameworks = [part.strip() for part in str(row.get("top_frameworks") or "").split(",") if part.strip()]
    return {
        "asset_id": str(row.get("id") or ""),
        "source": str(row.get("source") or ""),
        "path": str(row.get("path") or ""),
        "name": str(row.get("name") or ""),
        "extension": str(row.get("extension") or ""),
        "share": str(row.get("share") or ""),
        "risk_level": str(row.get("risk_level") or ""),
        "risk_score": int(row.get("risk_score") or 0),
        "size_bytes": int(row.get("size") or 0),
        "owner": str(row.get("owner") or ""),
        "modified_at": str(row.get("modified_at") or ""),
        "finding_count": int(row.get("finding_count") or 0),
        "frameworks": frameworks,
        "finding_types": _decode_list(row.get("finding_types")),
        "hidden": bool(row.get("is_hidden")),
        "system": bool(row.get("is_system")),
        "protected": bool(row.get("is_protected")),
    }


def _csv_safe(value) -> str | int:
    """Prevent spreadsheet formula execution without changing numeric columns."""
    if not isinstance(value, str):
        return value
    if value and (value[0] in {"=", "+", "-", "@", "\t", "\r"}):
        return "'" + value
    return value


def _csv_lines(rows: Iterable[dict]) -> Iterator[bytes]:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n")

    def encoded_line(values) -> bytes:
        buffer.seek(0)
        buffer.truncate(0)
        writer.writerow(values)
        return buffer.getvalue().encode("utf-8")

    yield encoded_line(_EXPORT_FIELDS)
    for row in rows:
        record = _export_record(row)
        values = []
        for field in _EXPORT_FIELDS:
            value = record[field]
            if isinstance(value, list):
                value = " | ".join(value)
            values.append(_csv_safe(value) if field in _TEXT_FIELDS else value)
        yield encoded_line(values)


def _ndjson_lines(rows: Iterable[dict]) -> Iterator[bytes]:
    for row in rows:
        record = _export_record(row)
        yield (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _bounded_chunks(lines: Iterable[bytes]) -> Iterator[bytes]:
    chunk = bytearray()
    for line in lines:
        if chunk and len(chunk) + len(line) > _TARGET_CHUNK_BYTES:
            yield bytes(chunk)
            chunk.clear()
        if len(line) > _TARGET_CHUNK_BYTES:
            yield line
        else:
            chunk.extend(line)
    if chunk:
        yield bytes(chunk)


def inventory_export_stream(tenant_id: str, export_format: str, **filters) -> Iterator[bytes]:
    """Return a lazy byte iterator; at most one DB batch plus ~64 KiB is held."""
    rows = iter_inventory_export_rows(tenant_id, batch_size=_batch_size(), **filters)
    lines = _csv_lines(rows) if export_format == "csv" else _ndjson_lines(rows)
    return _bounded_chunks(lines)


def inventory_export_response_metadata(tenant_id: str, export_format: str) -> tuple[str, str]:
    safe_tenant = "".join(ch for ch in tenant_id.strip() if ch.isalnum() or ch in {"-", "_"}) or "default"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = "csv" if export_format == "csv" else "ndjson"
    media_type = "text/csv" if export_format == "csv" else "application/x-ndjson"
    return f"sentro-inventory-{safe_tenant}-{timestamp}.{suffix}", media_type
