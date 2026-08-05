"""Typed, safe conversation-state adapter for Copilot session context.

The runtime still stores a backwards-compatible session dict.  This module
adds a typed view over the sticky keys so handlers can reason about topic,
focus, scope, artifact, answer, and preference memory without storing raw
finding content.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from backend.copilot import task_frame_controller


MAX_ITEMS = 20
MAX_IDS = 50
MAX_TEXT = 800
MAX_PAYLOAD_ITEMS = 20


_SECRET_PATTERNS = (
    re.compile(r"sk_live_[A-Za-z0-9_=-]+", re.IGNORECASE),
    re.compile(r"sk-[A-Za-z0-9_=-]{10,}", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{12,}", re.IGNORECASE),
    re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^,\s;]+"),
)


def _safe_text(value: Any, limit: int = MAX_TEXT) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\x00", "").strip()
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    if len(text) > limit:
        text = text[:limit].rstrip() + "..."
    return text


def _safe_upper(value: Any) -> str | None:
    text = _safe_text(value, 80)
    return text.upper() if text else None


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_list(values: Any, limit: int = MAX_IDS) -> list[str]:
    if not isinstance(values, list):
        return []
    result: list[str] = []
    for value in values[:limit]:
        text = _safe_text(value, 120)
        if text:
            result.append(text)
    return result


def _safe_filter(value: Any) -> dict | str | None:
    if isinstance(value, Mapping):
        safe: dict[str, Any] = {}
        for key, item in value.items():
            text_key = _safe_text(key, 80)
            if text_key:
                safe[text_key] = _safe_text(item, 160) if not isinstance(item, (dict, list)) else str(type(item).__name__)
        return safe
    return _safe_text(value, 160)


@dataclass
class CanonicalFindingState:
    id: str | None = None
    name: str | None = None
    severity: str | None = None
    risk_score: float | None = None
    risk_types: list[str] = field(default_factory=list)
    scan_id: str | None = None
    source: str | None = None

    @classmethod
    def from_dict(cls, item: Mapping[str, Any] | None) -> "CanonicalFindingState | None":
        if not isinstance(item, Mapping):
            return None
        risk_types = item.get("risk_types")
        if not isinstance(risk_types, list):
            risk_types = item.get("findings") or item.get("reasons") or []
        if isinstance(risk_types, list):
            safe_types = []
            for entry in risk_types[:10]:
                if isinstance(entry, Mapping):
                    safe_types.append(_safe_text(entry.get("type"), 80))
                else:
                    safe_types.append(_safe_text(entry, 80))
            risk_types = [value for value in safe_types if value]
        else:
            risk_types = []
        state = cls(
            id=_safe_text(item.get("id") or item.get("path") or item.get("name"), 180),
            name=_safe_text(item.get("name") or item.get("path"), 180),
            severity=_safe_upper(item.get("severity") or item.get("risk_level") or item.get("level")),
            risk_score=_safe_float(item.get("risk_score") or item.get("score")),
            risk_types=list(risk_types),
            scan_id=_safe_text(item.get("scan_id"), 120),
            source=_safe_text(item.get("source"), 120),
        )
        return state if state.name or state.id else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "risk_types": list(self.risk_types[:10]),
            "scan_id": self.scan_id,
            "source": self.source,
        }


SelectedFindingState = CanonicalFindingState


@dataclass
class FocusEntity:
    entity_type: str | None = None
    item_id: str | None = None
    item_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"entity_type": self.entity_type, "item_id": self.item_id, "item_name": self.item_name}


@dataclass
class ShownItemsState:
    items: list[CanonicalFindingState] = field(default_factory=list)
    shown_count: int | None = None
    total_matching_count: int | None = None
    metric: str | None = None
    scan_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_dict() for item in self.items[:MAX_ITEMS]],
            "shown_count": self.shown_count,
            "total_matching_count": self.total_matching_count,
            "metric": self.metric,
            "scan_id": self.scan_id,
        }


@dataclass
class CountScopeState:
    severities: list[str] = field(default_factory=list)
    metric: str | None = None
    scan_id: str | None = None
    answer_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "severities": list(self.severities),
            "metric": self.metric,
            "scan_id": self.scan_id,
            "answer_type": self.answer_type,
        }


@dataclass
class ArtifactState:
    id: str | None = None
    name: str | None = None
    url: str | None = None
    type: str | None = None
    scan_id: str | None = None
    filter: dict | str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "type": self.type,
            "scan_id": self.scan_id,
            "filter": self.filter,
        }


@dataclass
class AnswerState:
    answer_type: str | None = None
    language: str | None = None
    text_summary: str | None = None
    structured_payload: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "answer_type": self.answer_type,
            "language": self.language,
            "text_summary": self.text_summary,
            "structured_payload": self.structured_payload,
        }


@dataclass
class UserPreferenceState:
    preferred_framing: str = "default"
    preferred_verbosity: str = "default"

    def to_dict(self) -> dict[str, Any]:
        return {
            "preferred_framing": self.preferred_framing,
            "preferred_verbosity": self.preferred_verbosity,
        }


@dataclass
class TopicState:
    current_topic: str | None = None
    topic_switch_detected: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"current_topic": self.current_topic, "topic_switch_detected": self.topic_switch_detected}


def _payload_metric_name(payload: Mapping[str, Any] | None) -> str | None:
    if not isinstance(payload, Mapping):
        return None
    metric = payload.get("metric")
    if isinstance(metric, Mapping):
        return _safe_text(metric.get("name"), 120)
    return _safe_text(metric, 120)


def _safe_structured_payload(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, Mapping):
        return None
    safe: dict[str, Any] = {}
    for key in ("answer_type", "scan_id", "language"):
        value = _safe_text(payload.get(key), 160)
        if value is not None:
            safe[key] = value
    metric = payload.get("metric")
    if isinstance(metric, Mapping):
        safe["metric"] = {
            key: _safe_text(metric.get(key), 180)
            for key in ("name", "object_type", "scope", "source", "definition")
            if metric.get(key) is not None
        }
    counts = payload.get("counts")
    if isinstance(counts, Mapping):
        safe["counts"] = {str(key): _safe_int(value) for key, value in counts.items() if _safe_int(value) is not None}
    evidence = payload.get("evidence")
    if isinstance(evidence, list):
        safe["evidence"] = []
        for ref in evidence[:MAX_PAYLOAD_ITEMS]:
            if isinstance(ref, Mapping):
                safe["evidence"].append({
                    key: _safe_text(ref.get(key), 160)
                    for key in ("source", "scan_id", "metric", "item_id", "item_name", "confidence")
                    if ref.get(key) is not None
                })
    items = payload.get("items") or payload.get("shown_items")
    if isinstance(items, list):
        safe_items = []
        for item in items[:MAX_PAYLOAD_ITEMS]:
            state = CanonicalFindingState.from_dict(item)
            if state:
                safe_items.append(state.to_dict())
        safe["items"] = safe_items
    return safe


@dataclass
class ConversationState:
    current_topic: TopicState = field(default_factory=TopicState)
    focus_entity: FocusEntity = field(default_factory=FocusEntity)
    selected_finding: CanonicalFindingState | None = None
    last_shown_items: ShownItemsState = field(default_factory=ShownItemsState)
    last_count_scope: CountScopeState | None = None
    last_artifact: ArtifactState | None = None
    last_answer: AnswerState = field(default_factory=AnswerState)
    last_requested_severity: str | None = None
    last_selection_mode: str | None = None
    avoided_item_ids: list[str] = field(default_factory=list)
    last_unshown_pool_ids: list[str] = field(default_factory=list)
    preferences: UserPreferenceState = field(default_factory=UserPreferenceState)
    last_failed_route: str | None = None
    last_user_correction: str | None = None
    language: str | None = None
    active_task_frame: dict[str, Any] | None = None

    @classmethod
    def from_legacy_context(cls, context: Mapping[str, Any] | None) -> "ConversationState":
        context = context or {}
        payload = context.get("last_answer_structured_payload")
        safe_payload = _safe_structured_payload(payload)
        items = []
        for item in (context.get("last_shown_items") or [])[:MAX_ITEMS]:
            state = CanonicalFindingState.from_dict(item)
            if state:
                items.append(state)
        selected = CanonicalFindingState.from_dict(context.get("current_item")) or CanonicalFindingState.from_dict(context.get("last_item"))
        severities = [s for s in (_safe_upper(value) for value in context.get("last_count_scope_severities") or []) if s]
        metric_name = _payload_metric_name(payload)
        if context.get("last_count_scope_metric"):
            metric_name = _safe_text(context.get("last_count_scope_metric"), 120)
        count_scope = None
        if severities or context.get("last_count_scope_scan_id") or str(context.get("last_answer_type") or "").startswith("severity_count"):
            count_scope = CountScopeState(
                severities=severities,
                metric=metric_name or "severity_distribution_file_level",
                scan_id=_safe_text(context.get("last_count_scope_scan_id") or context.get("last_scan_id"), 120),
                answer_type=_safe_text(context.get("last_answer_type") or context.get("last_task_type"), 120),
            )
        artifact = context.get("latest_artifact") if isinstance(context.get("latest_artifact"), Mapping) else {}
        artifact_id = context.get("last_artifact_id") or artifact.get("artifact_id")
        last_artifact = None
        if artifact_id or context.get("last_artifact_url") or artifact.get("download_url"):
            last_artifact = ArtifactState(
                id=_safe_text(artifact_id, 160),
                name=_safe_text(context.get("last_artifact_name") or artifact.get("filename") or artifact.get("name"), 180),
                url=_safe_text(context.get("last_artifact_url") or artifact.get("download_url"), 300),
                type=_safe_text(context.get("last_artifact_type") or artifact.get("type"), 80),
                scan_id=_safe_text(context.get("last_artifact_scan_id") or artifact.get("source_scan_id") or artifact.get("scan_id"), 120),
                filter=_safe_filter(context.get("last_artifact_filter")),
            )
        answer_type = _safe_text(context.get("last_answer_type") or context.get("last_task_type") or (safe_payload or {}).get("answer_type"), 120)
        answer = AnswerState(
            answer_type=answer_type,
            language=_safe_text(context.get("last_answer_language") or context.get("response_language"), 20),
            text_summary=_safe_text(context.get("last_answer_summary") or context.get("last_answer_text"), 500),
            structured_payload=safe_payload,
        )
        shown = ShownItemsState(
            items=items,
            shown_count=_safe_int((safe_payload or {}).get("counts", {}).get("shown_count") if isinstance((safe_payload or {}).get("counts"), Mapping) else context.get("last_requested_limit")),
            total_matching_count=_safe_int((safe_payload or {}).get("counts", {}).get("total_matching_count") if isinstance((safe_payload or {}).get("counts"), Mapping) else context.get("last_total_count")),
            metric=metric_name,
            scan_id=_safe_text((safe_payload or {}).get("scan_id") or context.get("last_scan_id"), 120),
        )
        framing = _safe_text(context.get("preferred_framing"), 40) or "default"
        if framing not in {"manager", "technical", "default"}:
            framing = "default"
        verbosity = _safe_text(context.get("preferred_verbosity"), 40) or "default"
        if verbosity not in {"short", "detailed", "default"}:
            verbosity = "default"
        topic = _safe_text(context.get("current_topic") or context.get("last_intent") or context.get("last_task_type"), 120)
        state_payload = context.get("conversation_state_v2") if isinstance(context.get("conversation_state_v2"), Mapping) else {}
        active_task_frame = task_frame_controller.safe_task_frame_payload(
            context.get("active_task_frame") if isinstance(context.get("active_task_frame"), Mapping)
            else state_payload.get("active_task_frame") if isinstance(state_payload, Mapping)
            else None
        )
        focus = FocusEntity()
        if selected:
            focus = FocusEntity("selected_finding", selected.id, selected.name)
        elif items:
            focus = FocusEntity("shown_list", None, None)
        elif count_scope:
            focus = FocusEntity("count_scope", None, None)
        elif last_artifact:
            focus = FocusEntity("artifact", last_artifact.id, last_artifact.name)
        return cls(
            current_topic=TopicState(topic, bool(context.get("topic_switch_detected"))),
            focus_entity=focus,
            selected_finding=selected,
            last_shown_items=shown,
            last_count_scope=count_scope,
            last_artifact=last_artifact,
            last_answer=answer,
            last_requested_severity=_safe_upper(context.get("last_requested_severity")),
            last_selection_mode=_safe_text(context.get("last_selection_mode"), 80),
            avoided_item_ids=_safe_list(context.get("avoided_item_ids")),
            last_unshown_pool_ids=_safe_list(context.get("last_unshown_pool_ids")),
            preferences=UserPreferenceState(framing, verbosity),
            last_failed_route=_safe_text(context.get("last_failed_route"), 120),
            last_user_correction=_safe_text(context.get("last_user_correction"), 300),
            language=_safe_text(context.get("response_language") or context.get("last_language") or context.get("language_preference"), 20),
            active_task_frame=active_task_frame,
        )

    def clear_active_focus(self, *, clear_artifact: bool = False, topic_switch: bool = True) -> "ConversationState":
        self.selected_finding = None
        self.last_shown_items = ShownItemsState()
        self.last_count_scope = None
        self.last_requested_severity = None
        self.last_selection_mode = None
        self.avoided_item_ids = []
        self.last_unshown_pool_ids = []
        if clear_artifact:
            self.last_artifact = None
        self.focus_entity = FocusEntity()
        self.current_topic.topic_switch_detected = topic_switch
        self.current_topic.current_topic = "topic_switch" if topic_switch else None
        return self

    def mark_failed_route(self, route: str, correction: str | None = None) -> None:
        self.last_failed_route = _safe_text(route, 120)
        self.last_user_correction = _safe_text(correction, 300)

    def to_safe_session_payload(self) -> dict[str, Any]:
        return {
            "version": 2,
            "current_topic": self.current_topic.to_dict(),
            "focus_entity": self.focus_entity.to_dict(),
            "selected_finding": self.selected_finding.to_dict() if self.selected_finding else None,
            "last_shown_items": self.last_shown_items.to_dict(),
            "last_count_scope": self.last_count_scope.to_dict() if self.last_count_scope else None,
            "last_artifact": self.last_artifact.to_dict() if self.last_artifact else None,
            "last_answer": self.last_answer.to_dict(),
            "last_requested_severity": self.last_requested_severity,
            "last_selection_mode": self.last_selection_mode,
            "avoided_item_ids": list(self.avoided_item_ids[:MAX_IDS]),
            "last_unshown_pool_ids": list(self.last_unshown_pool_ids[:MAX_IDS]),
            "preferences": self.preferences.to_dict(),
            "last_failed_route": self.last_failed_route,
            "last_user_correction": self.last_user_correction,
            "language": self.language,
            "active_task_frame": self.active_task_frame,
        }

    def to_legacy_context(self, base: Mapping[str, Any] | None = None) -> dict[str, Any]:
        context = dict(base or {})
        context["conversation_state_v2"] = self.to_safe_session_payload()
        if self.last_count_scope:
            context["last_count_scope_severities"] = list(self.last_count_scope.severities)
            context["last_count_scope_scan_id"] = self.last_count_scope.scan_id
            context["last_count_scope_metric"] = self.last_count_scope.metric
            context["last_answer_type"] = self.last_count_scope.answer_type or context.get("last_answer_type")
        if self.last_requested_severity:
            context["last_requested_severity"] = self.last_requested_severity
        if self.last_selection_mode:
            context["last_selection_mode"] = self.last_selection_mode
        context["preferred_framing"] = self.preferences.preferred_framing
        context["preferred_verbosity"] = self.preferences.preferred_verbosity
        if self.last_failed_route:
            context["last_failed_route"] = self.last_failed_route
        if self.last_user_correction:
            context["last_user_correction"] = self.last_user_correction
        if self.active_task_frame:
            context["active_task_frame"] = dict(self.active_task_frame)
        if self.last_artifact:
            context["last_artifact_id"] = self.last_artifact.id
            context["last_artifact_name"] = self.last_artifact.name
            context["last_artifact_url"] = self.last_artifact.url
            context["last_artifact_type"] = self.last_artifact.type
            context["last_artifact_scan_id"] = self.last_artifact.scan_id
            context["last_artifact_filter"] = self.last_artifact.filter
        return context

    def audit_metadata(self) -> dict[str, Any]:
        return {
            "conversation_topic": self.current_topic.current_topic,
            "focus_entity_type": self.focus_entity.entity_type,
            "topic_switch_detected": self.current_topic.topic_switch_detected,
            "preferred_framing": self.preferences.preferred_framing,
            "preferred_verbosity": self.preferences.preferred_verbosity,
        }
