from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
_lock = threading.Lock()


def tenant_dir(tenant_id: str) -> Path:
    safe = "".join(ch for ch in tenant_id if ch.isalnum() or ch in {"-", "_"}) or "default"
    path = DATA_DIR / "tenants" / safe
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        with path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)


def append_jsonl(path: Path, item: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def audit(tenant_id: str, actor: str, action: str, detail: dict | None = None) -> None:
    append_jsonl(
        tenant_dir(tenant_id) / "audit.jsonl",
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": tenant_id,
            "actor": actor,
            "action": action,
            "detail": detail or {},
        },
    )


def save_scan_history(tenant_id: str, report: dict) -> str:
    scan_id = report.get("scan_id") or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    root = tenant_dir(tenant_id)
    report["scan_id"] = scan_id
    write_json(root / "reports" / f"{scan_id}.json", report)
    write_json(root / "latest_report.json", report)
    append_jsonl(
        root / "scan_history.jsonl",
        {
            "scan_id": scan_id,
            "timestamp": report.get("timestamp"),
            "source": report.get("source"),
            "summary": report.get("summary", {}),
        },
    )
    return scan_id


def read_scan_history(tenant_id: str) -> list[dict]:
    path = tenant_dir(tenant_id) / "scan_history.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_audit_log(tenant_id: str, limit: int = 200) -> list[dict]:
    path = tenant_dir(tenant_id) / "audit.jsonl"
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines[-limit:] if line.strip()]


def data_retention_summary(tenant_id: str) -> dict:
    root = tenant_dir(tenant_id)
    return {
        "tenant_id": tenant_id,
        "path": str(root),
        "report_count": len(list((root / "reports").glob("*.json"))) if (root / "reports").exists() else 0,
        "audit_events": len(read_audit_log(tenant_id, 100000)),
        "env": os.getenv("DSPM_ENV", "local"),
    }
