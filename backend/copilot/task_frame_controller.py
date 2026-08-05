"""Deterministic scoped task-frame controller for Copilot follow-ups.

The controller stores only compact, safe task metadata. It does not call
providers, tools, files, shell, or external services.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import Any, Mapping

from backend.copilot import language_service, situation_guardrails


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass(frozen=True)
class TaskFrameScope:
    kind: str
    values: list[str]
    object_alias: str | None = None
    metric_name: str | None = None
    scan_id: str | None = None


@dataclass(frozen=True)
class TaskFrameAction:
    name: str
    user_goal: str


@dataclass(frozen=True)
class TaskFrameSelectionPolicy:
    name: str


@dataclass
class TaskFrame:
    frame_id: str
    created_turn: int | None
    updated_turn: int | None
    source_route_id: str | None
    user_goal: str
    action: str
    scope_kind: str
    scope_values: list[str]
    object_alias: str | None
    metric_name: str | None
    scan_id: str | None
    selection_policy: str
    pending: bool = False
    pending_reason: str | None = None
    last_system_ask: str | None = None
    forbidden_context_sources: list[str] = field(default_factory=list)
    safe_summary: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any] | None) -> "TaskFrame | None":
        if not isinstance(payload, Mapping):
            return None
        values = [str(value).upper() for value in (payload.get("scope_values") or []) if str(value).upper() in SEVERITIES]
        if not values and payload.get("scope_kind") == "severity":
            return None
        return cls(
            frame_id=str(payload.get("frame_id") or _frame_id("frame", values, payload.get("scan_id"))),
            created_turn=_safe_int(payload.get("created_turn")),
            updated_turn=_safe_int(payload.get("updated_turn")),
            source_route_id=_safe_text(payload.get("source_route_id"), 100),
            user_goal=_safe_text(payload.get("user_goal"), 80) or "scoped_detail",
            action=_safe_text(payload.get("action"), 80) or "representative_detail",
            scope_kind=_safe_text(payload.get("scope_kind"), 80) or "severity",
            scope_values=values,
            object_alias=_safe_text(payload.get("object_alias"), 80),
            metric_name=_safe_text(payload.get("metric_name"), 120) or "file_level_finding_count",
            scan_id=_safe_text(payload.get("scan_id"), 160),
            selection_policy=_safe_text(payload.get("selection_policy"), 80) or "highest_risk",
            pending=bool(payload.get("pending")),
            pending_reason=_safe_text(payload.get("pending_reason"), 160),
            last_system_ask=_safe_text(payload.get("last_system_ask"), 120),
            forbidden_context_sources=[
                _safe_text(value, 80)
                for value in (payload.get("forbidden_context_sources") or [])
                if _safe_text(value, 80)
            ][:8],
            safe_summary=_safe_summary(payload.get("safe_summary")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "frame_id": self.frame_id,
            "created_turn": self.created_turn,
            "updated_turn": self.updated_turn,
            "source_route_id": self.source_route_id,
            "user_goal": self.user_goal,
            "action": self.action,
            "scope_kind": self.scope_kind,
            "scope_values": list(self.scope_values),
            "object_alias": self.object_alias,
            "metric_name": self.metric_name,
            "scan_id": self.scan_id,
            "selection_policy": self.selection_policy,
            "pending": self.pending,
            "pending_reason": self.pending_reason,
            "last_system_ask": self.last_system_ask,
            "forbidden_context_sources": list(self.forbidden_context_sources[:8]),
            "safe_summary": _safe_summary(self.safe_summary),
        }

    def audit_metadata(self, *, source: str, selected_suppressed: bool = False) -> dict[str, Any]:
        return {
            "task_frame_controller_used": True,
            "task_frame_used": True,
            "task_frame_id": self.frame_id,
            "task_frame_action": self.action,
            "task_frame_scope_kind": self.scope_kind,
            "task_frame_scope_values": ",".join(self.scope_values),
            "task_frame_selection_policy": self.selection_policy,
            "task_frame_pending": self.pending,
            "task_frame_source": source,
            "object_alias": self.object_alias,
            "selected_finding_suppressed": selected_suppressed,
        }


@dataclass(frozen=True)
class PendingUserIntent:
    kind: str
    action: str
    reason: str


@dataclass(frozen=True)
class TaskFrameResolution:
    should_answer: bool
    frame: TaskFrame | None
    source: str
    reason: str
    short_followup_resolved: bool = False
    answer_obligation_used: bool = False
    correction_recovery: bool = False
    another_one: bool = False
    selected_finding_suppressed: bool = False
    route_rejected: bool = False
    rejected_route_id: str | None = None
    rejection_reason: str | None = None
    pending_intent: PendingUserIntent | None = None

    def audit_metadata(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "short_followup_resolved": self.short_followup_resolved,
            "answer_obligation_used": self.answer_obligation_used,
            "route_rejected": self.route_rejected,
            "rejected_route_id": self.rejected_route_id,
            "rejection_reason": self.rejection_reason,
        }
        if self.frame:
            data.update(self.frame.audit_metadata(source=self.source, selected_suppressed=self.selected_finding_suppressed))
        return data


def safe_task_frame_payload(payload: Mapping[str, Any] | None) -> dict[str, Any] | None:
    frame = TaskFrame.from_dict(payload)
    return frame.to_dict() if frame else None


def create_count_frame(
    *,
    message: str,
    severity: str,
    scan_id: str | None,
    source_route_id: str,
    existing: Mapping[str, Any] | None = None,
) -> TaskFrame:
    existing_frame = active_frame(existing)
    turn = _next_turn(existing)
    object_alias = "alert_as_finding" if _mentions_alert(message) else None
    values = [severity.upper()]
    frame_id = existing_frame.frame_id if existing_frame and existing_frame.action == "count" and existing_frame.scope_values == values else _frame_id("count", values, scan_id)
    return TaskFrame(
        frame_id=frame_id,
        created_turn=existing_frame.created_turn if existing_frame and existing_frame.frame_id == frame_id else turn,
        updated_turn=turn,
        source_route_id=source_route_id,
        user_goal="scoped_count",
        action="count",
        scope_kind="severity",
        scope_values=values,
        object_alias=object_alias,
        metric_name="file_level_finding_count",
        scan_id=scan_id,
        selection_policy="none",
        pending=False,
        forbidden_context_sources=["selected_finding"],
        safe_summary={"object_alias_notice_seen": bool(object_alias)},
    )


def active_frame(context: Mapping[str, Any] | None) -> TaskFrame | None:
    context = context or {}
    payload = context.get("active_task_frame")
    if not isinstance(payload, Mapping):
        state = context.get("conversation_state_v2")
        payload = state.get("active_task_frame") if isinstance(state, Mapping) else None
    return TaskFrame.from_dict(payload)


def resolve_task_frame(message: str, context: Mapping[str, Any] | None) -> TaskFrameResolution:
    context = context or {}
    text = _fold(message)
    explicit = situation_guardrails.explicit_severities(message)
    frame = active_frame(context)
    last_count = [str(value).upper() for value in (context.get("last_count_scope_severities") or []) if str(value).upper() in SEVERITIES]
    selected_suppressed = _selected_outside_scope(context, explicit or (frame.scope_values if frame else last_count))

    if explicit and _is_correction(text):
        new_frame = _detail_frame(
            context=context,
            values=explicit,
            action="representative_detail",
            user_goal="wrong_scope_recovery",
            selection_policy="highest_risk",
            source_route_id="task_frame_correction",
            object_alias="alert_as_finding" if _mentions_alert(message) else (frame.object_alias if frame else None),
            scan_id=_scan_id(context, frame),
        )
        return TaskFrameResolution(
            True, new_frame, "current_explicit_correction", "explicit correction scope wins",
            short_followup_resolved=False, answer_obligation_used=True, correction_recovery=True,
            selected_finding_suppressed=selected_suppressed, route_rejected=selected_suppressed,
            rejected_route_id="selected_finding_detail" if selected_suppressed else None,
            rejection_reason="selected_finding_outside_active_scope" if selected_suppressed else None,
            pending_intent=PendingUserIntent("correction", "representative_detail", "explicit scoped correction"),
        )

    if _belongs_to_other_route(text):
        return TaskFrameResolution(False, None, "none", "message belongs to a higher-priority non-frame route")

    if explicit and _is_scoped_one_request(text):
        action = "random_detail" if _is_random(text) else "representative_detail"
        policy = "random_stable" if action == "random_detail" else "highest_risk"
        new_frame = _detail_frame(
            context=context,
            values=explicit,
            action=action,
            user_goal="scoped_detail",
            selection_policy=policy,
            source_route_id="task_frame_explicit_detail",
            object_alias="alert_as_finding" if _mentions_alert(message) else (frame.object_alias if frame else None),
            scan_id=_scan_id(context, frame),
        )
        return TaskFrameResolution(
            True, new_frame, "current_message", "current explicit scoped detail request",
            selected_finding_suppressed=selected_suppressed, route_rejected=selected_suppressed,
            rejected_route_id="selected_finding_detail" if selected_suppressed else None,
            rejection_reason="selected_finding_outside_active_scope" if selected_suppressed else None,
        )

    base_values = frame.scope_values if frame and frame.scope_kind == "severity" else last_count
    if base_values and (_is_detail_request(text) or _is_short_continuation(text) or _is_another(text)):
        action = "random_detail" if _is_random(text) else "representative_detail"
        policy = "random_stable" if action == "random_detail" else "highest_risk"
        if _is_another(text):
            action = "representative_detail"
            policy = "highest_risk"
        source = "active_task_frame" if frame else "last_count_scope"
        new_frame = _detail_frame(
            context=context,
            values=base_values,
            action=action,
            user_goal="scoped_detail",
            selection_policy=policy,
            source_route_id="task_frame_followup",
            object_alias=(frame.object_alias if frame else ("alert_as_finding" if _mentions_alert(message) else None)),
            scan_id=_scan_id(context, frame),
            previous_frame=frame,
        )
        return TaskFrameResolution(
            True, new_frame, source, "short scoped follow-up resolved against active task frame",
            short_followup_resolved=_is_short_continuation(text) or not explicit,
            answer_obligation_used=bool(frame and (frame.pending or frame.action in {"representative_detail", "random_detail"})),
            another_one=_is_another(text),
            selected_finding_suppressed=selected_suppressed,
            route_rejected=selected_suppressed,
            rejected_route_id="selected_finding_detail" if selected_suppressed else None,
            rejection_reason="selected_finding_outside_active_scope" if selected_suppressed else None,
            pending_intent=PendingUserIntent("followup", action, "scoped continuation"),
        )

    return TaskFrameResolution(False, None, "none", "no scoped task frame matched")


def scoped_items(frame: TaskFrame, findings: list[dict]) -> list[dict]:
    if frame.scope_kind != "severity":
        return []
    values = {value.upper() for value in frame.scope_values}
    return [item for item in findings if str(item.get("severity") or "").upper() in values]


def select_item(
    *,
    frame: TaskFrame,
    findings: list[dict],
    conversation_id: str,
    another_one: bool = False,
) -> tuple[dict | None, list[dict], str]:
    items = scoped_items(frame, findings)
    if not items:
        return None, [], "none_available"
    chosen_ids = [str(value) for value in (frame.safe_summary.get("selected_item_ids") or []) if value]
    if another_one:
        pool = [item for item in items if _item_id(item) not in set(chosen_ids)]
        if not pool:
            return None, items, "no_other_available"
        return _representative(pool), items, "highest_risk"
    if frame.selection_policy == "random_stable":
        seed = f"{conversation_id}|{frame.scan_id}|{','.join(frame.scope_values)}|{frame.frame_id}"
        index = int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8], 16) % len(items)
        return sorted(items, key=_stable_item_key)[index], items, "random_stable"
    return _representative(items), items, "highest_risk"


def mark_selected(frame: TaskFrame, item: dict | None, *, pending: bool = False) -> TaskFrame:
    selected_ids = [str(value) for value in (frame.safe_summary.get("selected_item_ids") or []) if value]
    if item:
        item_id = _item_id(item)
        if item_id and item_id not in selected_ids:
            selected_ids.append(item_id)
    summary = dict(frame.safe_summary)
    summary["selected_item_ids"] = selected_ids[:20]
    if item:
        summary["last_selected_item_id"] = _item_id(item)
        summary["last_selected_item_name"] = _safe_text(item.get("name"), 180)
    frame.safe_summary = summary
    frame.pending = pending
    frame.pending_reason = None if not pending else frame.pending_reason
    frame.last_system_ask = None if not pending else frame.last_system_ask
    return frame


def attach_frame(context: Mapping[str, Any] | None, frame: TaskFrame | None) -> dict[str, Any]:
    next_context = dict(context or {})
    if frame:
        payload = frame.to_dict()
        next_context["active_task_frame"] = payload
        state = dict(next_context.get("conversation_state_v2") or {})
        state["active_task_frame"] = payload
        next_context["conversation_state_v2"] = state
    return next_context


def _detail_frame(
    *,
    context: Mapping[str, Any],
    values: list[str],
    action: str,
    user_goal: str,
    selection_policy: str,
    source_route_id: str,
    object_alias: str | None,
    scan_id: str | None,
    previous_frame: TaskFrame | None = None,
) -> TaskFrame:
    turn = _next_turn(context)
    values = [value.upper() for value in values if value.upper() in SEVERITIES]
    frame_id = previous_frame.frame_id if previous_frame and previous_frame.scope_values == values else _frame_id(action, values, scan_id)
    return TaskFrame(
        frame_id=frame_id,
        created_turn=previous_frame.created_turn if previous_frame and previous_frame.frame_id == frame_id else turn,
        updated_turn=turn,
        source_route_id=source_route_id,
        user_goal=user_goal,
        action=action,
        scope_kind="severity",
        scope_values=values,
        object_alias=object_alias,
        metric_name="file_level_finding_count",
        scan_id=scan_id,
        selection_policy=selection_policy,
        pending=False,
        forbidden_context_sources=["selected_finding"],
        safe_summary=dict(previous_frame.safe_summary) if previous_frame else {},
    )


def _fold(message: str) -> str:
    return language_service.normalize_for_intent(message).lower()


def _is_detail_request(text: str) -> bool:
    return any(term in text for term in ("haqqinda", "melumat", "detail", "about", "aciqla", "izah", "bir ", "biri", "onlardan biri"))


def _is_scoped_one_request(text: str) -> bool:
    if _has_explicit_item_reference(text):
        return False
    one_terms = (
        "random",
        "tesadufi",
        "təsadufi",
        "bir ",
        "biri",
        "birini",
        "onlardan biri",
        "one ",
        "one of",
    )
    return _is_detail_request(text) and any(term in text for term in one_terms)


def _is_short_continuation(text: str) -> bool:
    compact = re.sub(r"\s+", " ", text).strip()
    return compact in {"ver de", "ver de bes", "he onu ver", "onu ac", "melumat ver", "haqqinda", "dedim axi", "biri haqqinda dedim", "dedim birini ver"} or any(
        term in compact for term in ("biri haqqinda dedim", "dedim", "ver de bes", "onu ver", "onu ac")
    )


def _is_correction(text: str) -> bool:
    return any(term in text for term in ("dedim", "anlamirsan", "anlamirs", "niye", "niyə", "vermeliydin", "sorusurdum", "sorushurdum", "critical verdin"))


def _is_random(text: str) -> bool:
    return "random" in text or "tesadufi" in text or "təsadüfi" in text


def _is_another(text: str) -> bool:
    return "basqa" in text or "başqa" in text or "another" in text or "different" in text


def _has_explicit_item_reference(text: str) -> bool:
    if re.search(r"\b[\w.-]+\.(?:ya?ml|json|docx?|xlsx?|pptx?|pdf|txt|csv|env|pem|key|sql|zip|7z|gz|tar)\b", text):
        return True
    if re.search(r"\b(?:number|item|#)\s*\d+\b", text):
        return True
    if re.search(r"\b\d+\s*(?:ci|inci|uncu|üncü|th|st|nd|rd)\b", text):
        return True
    if any(term in text for term in (" last ", " son ", " axirinci", "axırıncı", "release_secret_", "ma_secret_", "project_plan")):
        return True
    return False


def _belongs_to_other_route(text: str) -> bool:
    blocked = (
        "step by step",
        "remediation",
        "meslehet",
        "məsləhət",
        "pdf",
        "link",
        "yukle",
        "yükl",
        "download",
        "hesabat",
        "report",
        "ne elaqe",
        "nə əlaqə",
        "bayaq niye",
        "bayaq niyə",
    )
    return any(term in text for term in blocked)


def _mentions_alert(message: str) -> bool:
    return "alert" in _fold(message)


def _selected_outside_scope(context: Mapping[str, Any], values: list[str]) -> bool:
    if not values:
        return False
    scoped = {value.upper() for value in values}
    candidates: list[Mapping[str, Any]] = []
    for key in ("current_item", "last_item"):
        item = context.get(key)
        if isinstance(item, Mapping):
            candidates.append(item)
    for item in context.get("last_shown_items") or []:
        if isinstance(item, Mapping):
            candidates.append(item)
    for item in candidates:
        selected_severity = str(item.get("severity") or "").upper()
        if selected_severity and selected_severity not in scoped:
            return True
    return False


def _scan_id(context: Mapping[str, Any], frame: TaskFrame | None) -> str | None:
    return (frame.scan_id if frame else None) or _safe_text(context.get("last_count_scope_scan_id") or context.get("last_scan_id"), 160)


def _representative(items: list[dict]) -> dict:
    return sorted(items, key=lambda item: (-_risk_score(item), SEVERITY_RANK.get(str(item.get("severity") or "").upper(), 9), _stable_item_key(item)))[0]


def _stable_item_key(item: dict) -> str:
    return str(item.get("id") or item.get("name") or item.get("path") or "")


def _item_id(item: dict) -> str:
    return _stable_item_key(item)


def _risk_score(item: dict) -> float:
    try:
        return float(item.get("risk_score") or 0)
    except (TypeError, ValueError):
        return 0.0


def _frame_id(prefix: str, values: list[str], scan_id: Any) -> str:
    digest = hashlib.sha1(f"{prefix}|{','.join(values)}|{scan_id or ''}".encode("utf-8")).hexdigest()[:12]
    return f"tf_{digest}"


def _next_turn(context: Mapping[str, Any] | None) -> int | None:
    try:
        return int((context or {}).get("task_frame_turn") or 0) + 1
    except (TypeError, ValueError):
        return None


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_text(value: Any, limit: int = 200) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    return text[:limit]


def _safe_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    safe: dict[str, Any] = {}
    selected_ids = [_safe_text(item, 160) for item in (value.get("selected_item_ids") or [])]
    safe["selected_item_ids"] = [item for item in selected_ids if item][:20]
    for key in ("last_selected_item_id", "last_selected_item_name", "object_alias_notice_seen"):
        if key in value:
            safe[key] = value[key] if isinstance(value[key], bool) else _safe_text(value[key], 180)
    return safe
