from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from backend.copilot.canonical_answer import canonical_answer_for_finding_list
from backend.copilot.conversation_state import ConversationState
from backend.copilot.schemas import SourceRef, ToolResult
from backend.security import Principal
from backend.store import DATA_DIR


MAX_ENTITY_ITEMS = 8
MAX_SUMMARY_CHARS = 500
MAX_LAST_SHOWN_ITEMS = 20
MAX_AVOIDED_ITEM_IDS = 50
MAX_UNSHOWN_POOL_IDS = 100
CONTEXT_VERSION = 1
SUPPORTED_SESSION_LANGUAGES = {"en", "az", "ru"}
SESSION_TTL_SECONDS = int(os.getenv("COPILOT_SESSION_TTL_SECONDS", "3600"))
SESSION_SWEEP_INTERVAL_SECONDS = int(os.getenv("COPILOT_SESSION_SWEEP_INTERVAL_SECONDS", "900"))
WINDOWS_PATH_RE = re.compile(r'\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n,.;)]*')
UNIX_PATH_RE = re.compile(r"(?<!\w)/(?:Users|home|mnt|var|tmp|etc|opt|root)/[^\s,.;)]*")
CREDENTIAL_RE = re.compile(r"\b(password|api_key|apikey|secret|token|private_key)=\S+", re.IGNORECASE)

_session_locks: dict[str, asyncio.Lock] = {}
_session_locks_guard = asyncio.Lock()


def _get_session_lock(tenant_id: str, subject: str, conversation_id: str) -> asyncio.Lock:
    key = f"{tenant_id}:{subject}:{conversation_id}"
    lock = _session_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _session_locks[key] = lock
    return lock


def _safe(value: str) -> str:
    return "".join(ch for ch in str(value or "") if ch.isalnum() or ch in {"-", "_"})[:80] or "default"


def _context_path(principal: Principal, conversation_id: str) -> Path:
    return (
        DATA_DIR
        / "copilot"
        / _safe(principal.tenant_id)
        / "session_context"
        / f"{_safe(principal.subject)}_{_safe(conversation_id)}.json"
    )


def _session_root() -> Path:
    return DATA_DIR / "copilot"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def is_session_expired(context: dict, now: datetime | None = None) -> bool:
    if SESSION_TTL_SECONDS <= 0:
        return False
    last_active = _parse_time(context.get("last_active") or context.get("updated_at"))
    if last_active is None:
        return True
    current = now or datetime.now(timezone.utc)
    return (current - last_active).total_seconds() > SESSION_TTL_SECONDS


def _display_name(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).replace("\\", "/").rstrip("/")
    name = PurePosixPath(text).name
    return (name or text)[:160]


def sanitize_text(value: Any, limit: int = MAX_SUMMARY_CHARS) -> str:
    text = str(value or "")
    text = WINDOWS_PATH_RE.sub(lambda match: _display_name(match.group(0)) or "[local file]", text)
    text = UNIX_PATH_RE.sub(lambda match: _display_name(match.group(0)) or "[local file]", text)
    text = CREDENTIAL_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _load_json_content(result: ToolResult) -> dict:
    try:
        data = json.loads(result.content)
    except json.JSONDecodeError:
        return {"summary": sanitize_text(result.content)}
    if not isinstance(data, dict):
        return {"value": data}
    summary = data.get("summary")
    if isinstance(summary, str) and summary.strip().startswith("{"):
        try:
            unwrapped = json.loads(summary)
        except json.JSONDecodeError:
            return data
        if isinstance(unwrapped, dict):
            if data.get("viewer_notice"):
                unwrapped["viewer_notice"] = data.get("viewer_notice")
            return unwrapped
    return data


def _first_scan_id(payloads: list[dict], sources: list[SourceRef]) -> str | None:
    for payload in payloads:
        scan_id = payload.get("scan_id")
        if scan_id:
            return str(scan_id)
        nested = payload.get("findings_context")
        if isinstance(nested, dict) and nested.get("scan_id"):
            return str(nested.get("scan_id"))
    for source in sources:
        if source.scan_id:
            return source.scan_id
    return None


def _append_unique(items: list[str], value: Any) -> None:
    text = _display_name(value)
    if text and text not in items and len(items) < MAX_ENTITY_ITEMS:
        items.append(text)


def _extract_entities(payloads: list[dict], sources: list[SourceRef]) -> dict[str, list[str]]:
    entities: dict[str, list[str]] = {"files": [], "assets": [], "findings": [], "alerts": []}
    for source in sources:
        if source.type == "alert":
            _append_unique(entities["alerts"], source.severity or source.scan_id)
        elif source.type == "finding":
            _append_unique(entities["files"], source.path)
            _append_unique(entities["findings"], source.severity)
    for payload in payloads:
        for key in ("results", "top_assets", "top_risks", "top_findings"):
            for item in payload.get(key) or []:
                if isinstance(item, dict):
                    _append_unique(entities["files"], item.get("name") or item.get("path"))
                    _append_unique(entities["assets"], item.get("name") or item.get("path"))
                    _append_unique(entities["findings"], item.get("severity"))
        for item in payload.get("alerts") or []:
            if isinstance(item, dict):
                _append_unique(entities["alerts"], item.get("title") or item.get("severity") or item.get("scan_id"))
        for item in payload.get("remediation_summary") or []:
            if isinstance(item, dict):
                _append_unique(entities["files"], item.get("path"))
                _append_unique(entities["findings"], item.get("severity"))
        nested = payload.get("findings_context")
        if isinstance(nested, dict):
            nested_entities = _extract_entities([nested], sources)
            for key, values in nested_entities.items():
                for value in values:
                    _append_unique(entities[key], value)
    return entities


def _extract_actions(payloads: list[dict]) -> list[str]:
    actions: list[str] = []
    for payload in payloads:
        for item in payload.get("remediation_summary") or []:
            if isinstance(item, dict):
                for action in item.get("actions") or []:
                    _append_unique(actions, sanitize_text(action, 160))
        for key in ("results", "top_assets", "top_risks", "top_findings"):
            for item in payload.get(key) or []:
                if isinstance(item, dict):
                    remediation = item.get("remediation") or {}
                    for action in remediation.get("actions") or []:
                        _append_unique(actions, sanitize_text(action, 160))
    return actions[:MAX_ENTITY_ITEMS]


def _risk_types(item: dict) -> list[str]:
    values: list[str] = []
    for finding in item.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        value = sanitize_text(finding.get("type"), 80)
        if value and value not in values:
            values.append(value)
    return values[:8]


def _shown_items(payloads: list[dict]) -> tuple[str | None, int | None, int | None, list[dict], dict | None]:
    for payload in payloads:
        result_type = str(payload.get("result_type") or "")
        if not result_type.endswith("_findings"):
            continue
        items = payload.get("results") or []
        shown: list[dict] = []
        for index, item in enumerate(items[:MAX_LAST_SHOWN_ITEMS], 1):
            if not isinstance(item, dict):
                continue
            name = _display_name(item.get("name") or item.get("path"))
            if not name:
                continue
            item_id = str(item.get("id") or item.get("finding_id") or name)
            shown.append(
                {
                    "index": index,
                    "id": item_id,
                    "name": name,
                    "severity": sanitize_text(item.get("severity"), 40),
                    "risk_score": item.get("risk_score"),
                    "risk_types": _risk_types(item),
                    "source_type": "finding",
                    "safe_identifier": name,
                    "detail_ref": name,
                    "full_detail_ref": name,
                }
            )
        list_label = f"{result_type}_list" if result_type.endswith("_findings") else "findings_list"
        return (
            list_label,
            int(payload.get("returned") or len(shown) or 0),
            int(payload.get("count") or len(shown) or 0),
            shown,
            shown[-1] if shown else None,
        )
    return None, None, None, [], None


def _first_findings_payload(payloads: list[dict]) -> dict | None:
    for payload in payloads:
        result_type = str(payload.get("result_type") or "")
        if result_type.endswith("_findings"):
            return payload
    return None


def _payload_item_ids(payload: dict | None, limit: int) -> list[str]:
    if not payload:
        return []
    values: list[str] = []
    for item in payload.get("results") or []:
        if not isinstance(item, dict):
            continue
        item_id = _display_name(item.get("id") or item.get("finding_id") or item.get("name") or item.get("path"))
        if item_id and item_id not in values:
            values.append(item_id)
        if len(values) >= limit:
            break
    return values


def _session_intent(intent: str, tool_names: list[str]) -> str:
    if "get_recent_alerts" in tool_names or intent == "alert_summary":
        return "critical_alerts"
    if "generate_remediation_summary" in tool_names or intent == "remediation_advice":
        return "remediation"
    if "get_high_risk_assets" in tool_names or intent == "asset_risk":
        return "high_risk_assets"
    if "get_scan_history" in tool_names or intent == "executive_summary":
        return "latest_scan"
    return intent or "unknown"


def build_context(
    principal: Principal,
    conversation_id: str,
    intent: str,
    language: str,
    tool_results: list[ToolResult],
    answer: str,
) -> dict:
    payloads = [_load_json_content(result) for result in tool_results]
    sources = [source for result in tool_results for source in result.sources]
    tool_names = [result.tool_name for result in tool_results]
    entities = _extract_entities(payloads, sources)
    result_type, requested_limit, total_count, shown_items, last_item = _shown_items(payloads)
    findings_payload = _first_findings_payload(payloads)
    source_count = sum(len(result.sources) for result in tool_results)
    summary_parts = [f"{len(tool_results)} tool result(s)", f"{source_count} source(s)"]
    scan_id = _first_scan_id(payloads, sources)
    if scan_id:
        summary_parts.append(f"scan_id={scan_id}")
    context = {
        "version": CONTEXT_VERSION,
        "conversation_id": conversation_id,
        "tenant_id": principal.tenant_id,
        "user_id": principal.subject,
        "last_intent": _session_intent(intent, tool_names),
        "last_language": language if language in SUPPORTED_SESSION_LANGUAGES else "en",
        "user_language": language if language in SUPPORTED_SESSION_LANGUAGES else "en",
        "answer_language": language if language in SUPPORTED_SESSION_LANGUAGES else "en",
        "selected_language": None,
        "response_language": language if language in SUPPORTED_SESSION_LANGUAGES else "en",
        "language_source": "session",
        "language_locked": False,
        "language_preference": language if language in SUPPORTED_SESSION_LANGUAGES else "en",
        "last_scan_id": scan_id,
        "last_time_range": None,
        "last_entities": entities,
        "last_tool_names": tool_names,
        "last_tool_result_summary": sanitize_text("; ".join(summary_parts)),
        "last_answer_summary": sanitize_text(answer),
        "last_answer_text": sanitize_text(answer, 1200),
        "last_answer_language": language if language in SUPPORTED_SESSION_LANGUAGES else "en",
        "last_recommended_actions": _extract_actions(payloads),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "last_active": _now_iso(),
    }
    if result_type:
        canonical_payload = None
        if findings_payload:
            canonical_payload = canonical_answer_for_finding_list(
                {
                    "scan_id": findings_payload.get("scan_id"),
                    "results": findings_payload.get("results") or [],
                    "count": findings_payload.get("count"),
                    "returned": findings_payload.get("returned"),
                    "severity": findings_payload.get("severity"),
                    "selection_mode": findings_payload.get("selection_mode"),
                },
                sanitize_text(answer),
                language,
            ).to_dict()
        shown_ids = _payload_item_ids(findings_payload, MAX_AVOIDED_ITEM_IDS)
        total_ids = _payload_item_ids(findings_payload, MAX_UNSHOWN_POOL_IDS)
        shown_id_set = set(shown_ids)
        unshown_ids = [item_id for item_id in total_ids if item_id not in shown_id_set][:MAX_UNSHOWN_POOL_IDS]
        severity = None
        selection_mode = None
        if findings_payload:
            severity = sanitize_text(findings_payload.get("severity"), 40).upper() or None
            selection_mode = sanitize_text(findings_payload.get("selection_mode") or "top", 40) or "top"
        context.update(
            {
                "last_result_type": result_type,
                "last_requested_limit": requested_limit,
                "last_total_count": total_count,
                "last_shown_items": shown_items,
                "last_item": last_item,
                "last_requested_severity": severity,
                "last_selection_mode": selection_mode,
                "last_task_type": intent,
                "avoided_item_ids": shown_ids[:MAX_AVOIDED_ITEM_IDS],
                "last_unshown_pool_ids": unshown_ids,
                "last_answer_structured_payload": canonical_payload or {
                    "scan_id": findings_payload.get("scan_id") if findings_payload else None,
                    "result_type": result_type,
                    "answer_type": result_type,
                    "severity": severity,
                    "selection_mode": selection_mode,
                    "returned": requested_limit,
                    "shown_items": shown_items,
                    "items": shown_items,
                },
            }
        )
        if len(shown_items) == 1 and last_item:
            selected = dict(last_item)
            selected["scan_id"] = scan_id
            selected["metric"] = "file_level_finding_count"
            selected["source"] = "shown_single_finding"
            context["current_item"] = selected
            context["last_item"] = selected
    return ConversationState.from_legacy_context(context).to_legacy_context(context)


async def save_session_context(principal: Principal, conversation_id: str, context: dict) -> None:
    path = _context_path(principal, conversation_id)

    def write() -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        next_context = ConversationState.from_legacy_context(context).to_legacy_context(context)
        next_context["last_active"] = _now_iso()
        if is_session_expired(next_context):
            path.unlink(missing_ok=True)
            return
        path.write_text(json.dumps(next_context, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    await asyncio.to_thread(write)


async def load_session_context(principal: Principal, conversation_id: str) -> dict | None:
    path = _context_path(principal, conversation_id)

    def read() -> dict | None:
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("tenant_id") != principal.tenant_id or data.get("user_id") != principal.subject:
            return None
        if is_session_expired(data):
            path.unlink(missing_ok=True)
            return None
        data = ConversationState.from_legacy_context(data).to_legacy_context(data)
        data["last_active"] = _now_iso()
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        return data

    try:
        return await asyncio.to_thread(read)
    except (OSError, json.JSONDecodeError):
        return None


async def clear_session_context(principal: Principal, conversation_id: str) -> None:
    """Discard derived state that is stale after conversation history editing."""
    path = _context_path(principal, conversation_id)

    def remove() -> None:
        path.unlink(missing_ok=True)

    await asyncio.to_thread(remove)


async def sweep_expired_session_contexts() -> int:
    root = _session_root()

    async def sweep() -> int:
        removed = 0
        if not root.exists():
            return removed
        for path in root.glob("*/session_context/*.json"):
            parts = path.parts
            if len(parts) < 3:
                continue
            tenant_id = parts[-3]
            filename = path.stem
            underscore_pos = filename.rfind("_")
            if underscore_pos < 0:
                continue
            subject = filename[:underscore_pos]
            conversation_id = filename[underscore_pos + 1:]
            lock = _get_session_lock(tenant_id, subject, conversation_id)
            async with lock:
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if is_session_expired(data):
                    try:
                        path.unlink()
                        removed += 1
                    except OSError:
                        continue
        return removed

    return await sweep()


async def session_context_sweeper() -> None:
    while True:
        await asyncio.sleep(max(1, SESSION_SWEEP_INTERVAL_SECONDS))
        try:
            await sweep_expired_session_contexts()
        except Exception:
            continue
