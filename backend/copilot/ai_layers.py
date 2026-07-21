"""Local DSPM Copilot AI layer registry and policy metadata helpers.

This module is a developer/runtime map only. It does not expose new tools, add
providers, retrieve evidence, or decide visible wording.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping


class AILayer(str, Enum):
    INPUT_UNDERSTANDING = "INPUT_UNDERSTANDING"
    SITUATION_ROUTE = "SITUATION_ROUTE"
    CONVERSATION_STATE = "CONVERSATION_STATE"
    EVIDENCE_RAG = "EVIDENCE_RAG"
    TASK_WORKFLOW = "TASK_WORKFLOW"
    RESPONSE_BRAINMAP = "RESPONSE_BRAINMAP"
    CONTROLLED_VERBALIZER = "CONTROLLED_VERBALIZER"
    FALLBACK = "FALLBACK"
    SAFETY_POLICY = "SAFETY_POLICY"
    POLISH_VALIDATION = "POLISH_VALIDATION"
    MEMORY_PREFERENCE = "MEMORY_PREFERENCE"
    EVAL_GOLDEN_TEST = "EVAL_GOLDEN_TEST"


@dataclass(frozen=True)
class AILayerSpec:
    layer_id: AILayer
    purpose: str
    input: str
    output: str
    provider_allowed: bool
    evidence_required: bool
    state_read: tuple[str, ...] = field(default_factory=tuple)
    state_write: tuple[str, ...] = field(default_factory=tuple)
    fallback_behavior: str = "none"
    audit_metadata: tuple[str, ...] = field(default_factory=tuple)


LAYER_REGISTRY: dict[AILayer, AILayerSpec] = {
    AILayer.INPUT_UNDERSTANDING: AILayerSpec(
        AILayer.INPUT_UNDERSTANDING,
        "Normalize and interpret user input into safe route signals.",
        "message, selected language, lightweight context",
        "intent signals, normalized text, language metadata",
        provider_allowed=False,
        evidence_required=False,
        audit_metadata=("language_understanding_mode", "intent_confidence"),
    ),
    AILayer.SITUATION_ROUTE: AILayerSpec(
        AILayer.SITUATION_ROUTE,
        "Choose the deterministic situation or route owner.",
        "intent signals, session context, route candidates",
        "route decision, confidence, fallback policy",
        provider_allowed=False,
        evidence_required=False,
        state_read=("active_task_frame", "last_answer_type", "selected_finding"),
        fallback_behavior="clarify_or_deterministic_fallback",
        audit_metadata=("route_id", "route_confidence", "should_clarify"),
    ),
    AILayer.CONVERSATION_STATE: AILayerSpec(
        AILayer.CONVERSATION_STATE,
        "Read and persist safe contextual state.",
        "safe session payload",
        "selected item, last answer, preferences, task frame",
        provider_allowed=False,
        evidence_required=False,
        state_read=("last_answer_text", "selected_finding", "active_task_frame"),
        state_write=("last_answer_text", "selected_finding", "active_task_frame"),
        audit_metadata=("state_read", "state_write"),
    ),
    AILayer.EVIDENCE_RAG: AILayerSpec(
        AILayer.EVIDENCE_RAG,
        "Retrieve and render scan evidence from local DSPM data.",
        "validated DSPM query",
        "canonical evidence answer",
        provider_allowed=False,
        evidence_required=True,
        state_read=("scan_id", "selected_finding", "last_count_scope"),
        state_write=("shown_items", "selected_finding"),
        fallback_behavior="missing_data_clarification",
        audit_metadata=("metric_name", "scan_id", "evidence_count"),
    ),
    AILayer.TASK_WORKFLOW: AILayerSpec(
        AILayer.TASK_WORKFLOW,
        "Resolve scoped task frames and remediation workflows.",
        "task frame, selected finding, workflow request",
        "structured workflow/remediation answer",
        provider_allowed=False,
        evidence_required=True,
        state_read=("active_task_frame", "selected_finding"),
        state_write=("active_task_frame", "selected_finding"),
        fallback_behavior="ask_for_target_finding",
        audit_metadata=("task_frame_action", "structured_renderer_used"),
    ),
    AILayer.RESPONSE_BRAINMAP: AILayerSpec(
        AILayer.RESPONSE_BRAINMAP,
        "Build the safe semantic response plan before final text.",
        "route metadata and rendered draft",
        "ResponseBrainmap metadata",
        provider_allowed=False,
        evidence_required=False,
        fallback_behavior="deterministic_policy_answer",
        audit_metadata=("brainmap_situation_family", "brainmap_policy_source"),
    ),
    AILayer.CONTROLLED_VERBALIZER: AILayerSpec(
        AILayer.CONTROLLED_VERBALIZER,
        "Optionally reword safe non-evidence answers without deciding facts.",
        "ResponseBrainmap and safe draft",
        "validated final wording or fallback variant",
        provider_allowed=True,
        evidence_required=False,
        state_read=("recent_response_fingerprints",),
        state_write=("recent_response_fingerprints",),
        fallback_behavior="local_brainmap_variant",
        audit_metadata=("controlled_verbalizer_called", "verbalizer_denied_reason"),
    ),
    AILayer.FALLBACK: AILayerSpec(
        AILayer.FALLBACK,
        "Return safe local fallback/status answers when provider or context is unavailable.",
        "policy denial, timeout, missing context, provider health",
        "safe clarification or status answer",
        provider_allowed=False,
        evidence_required=False,
        state_read=("provider_health_snapshot", "last_answer_text"),
        fallback_behavior="safe_local_answer",
        audit_metadata=("fallback_reason", "provider_denied_reason"),
    ),
    AILayer.SAFETY_POLICY: AILayerSpec(
        AILayer.SAFETY_POLICY,
        "Enforce provider/tool/verbalizer boundaries and deny unsafe actions.",
        "route decision, brainmap, provider health",
        "allow/deny reason metadata",
        provider_allowed=False,
        evidence_required=False,
        fallback_behavior="deny_with_safe_reason",
        audit_metadata=("provider_denied_reason", "verbalizer_denied_reason", "policy_source_layer"),
    ),
    AILayer.POLISH_VALIDATION: AILayerSpec(
        AILayer.POLISH_VALIDATION,
        "Validate final visible answer invariants.",
        "candidate answer and metadata",
        "polished answer and validation metadata",
        provider_allowed=False,
        evidence_required=False,
        fallback_behavior="deterministic_repair_or_safe_fallback",
        audit_metadata=("polish_gate_used", "polish_failed_invariants"),
    ),
    AILayer.MEMORY_PREFERENCE: AILayerSpec(
        AILayer.MEMORY_PREFERENCE,
        "Persist safe user style preferences.",
        "assistant-behavior meta turn",
        "preference state update and acknowledgement",
        provider_allowed=False,
        evidence_required=False,
        state_read=("preferred_verbosity", "preferred_framing"),
        state_write=("preferred_verbosity", "preferred_framing"),
        fallback_behavior="short_local_acknowledgement",
        audit_metadata=("preferred_verbosity", "state_write"),
    ),
    AILayer.EVAL_GOLDEN_TEST: AILayerSpec(
        AILayer.EVAL_GOLDEN_TEST,
        "Protect architecture contracts through regression tests.",
        "golden conversation and metadata assertions",
        "pass/fail verification",
        provider_allowed=False,
        evidence_required=False,
        audit_metadata=("test_contract",),
    ),
}


def get_layer_spec(layer: AILayer | str) -> AILayerSpec:
    value = layer if isinstance(layer, AILayer) else AILayer(str(layer))
    return LAYER_REGISTRY[value]


def registry_metadata() -> dict[str, Any]:
    return {
        "ai_layer_registry_version": "p4ab.ai_layers.v1",
        "ai_layer_ids": [layer.value for layer in AILayer],
    }


def _layer_values(values: Iterable[AILayer | str] | None) -> list[str]:
    result: list[str] = []
    for value in values or []:
        text = value.value if isinstance(value, AILayer) else str(value)
        if text and text not in result:
            result.append(text)
    return result


def layer_transition_metadata(
    *,
    active_layer: AILayer,
    source_layers: Iterable[AILayer | str] | None = None,
    next_layer: AILayer | str | None = None,
    blocked_layers: Iterable[AILayer | str] | None = None,
    policy_reason: str | None = None,
    provider_denied_reason: str | None = None,
    verbalizer_denied_reason: str | None = None,
    fallback_reason: str | None = None,
    policy_source_layer: AILayer | str | None = AILayer.SAFETY_POLICY,
    route_confidence: float | None = None,
    importance: str | None = None,
    should_escalate_to_ai_arbiter: bool = False,
    should_clarify: bool = False,
    should_use_deterministic_renderer: bool = True,
    state_read: str | None = None,
    state_write: str | None = None,
    structured_only: bool = False,
) -> dict[str, Any]:
    active = active_layer.value
    next_value = next_layer.value if isinstance(next_layer, AILayer) else next_layer
    policy_layer_value = policy_source_layer.value if isinstance(policy_source_layer, AILayer) else policy_source_layer
    metadata: dict[str, Any] = {
        "active_layer": active,
        "ai_layer_active": active,
        "source_layers": _layer_values(source_layers),
        "ai_layer_source_layers": _layer_values(source_layers),
        "next_layer": next_value,
        "ai_layer_next": next_value,
        "blocked_layers": _layer_values(blocked_layers),
        "ai_layer_blocked": _layer_values(blocked_layers),
        "policy_reason": policy_reason,
        "ai_layer_policy_reason": policy_reason,
        "policy_source_layer": policy_layer_value,
        "provider_denied_reason": provider_denied_reason,
        "verbalizer_denied_reason": verbalizer_denied_reason,
        "fallback_reason": fallback_reason,
        "route_confidence": route_confidence,
        "importance": importance,
        "route_importance": importance,
        "should_escalate_to_ai_arbiter": bool(should_escalate_to_ai_arbiter),
        "should_clarify": bool(should_clarify),
        "should_use_deterministic_renderer": bool(should_use_deterministic_renderer),
        "structured_only": bool(structured_only),
    }
    if state_read:
        metadata["state_read"] = state_read
    if state_write:
        metadata["state_write"] = state_write
    return metadata


def contextual_importance(base_importance: str, *, has_context: bool, is_short: bool) -> str:
    if has_context and is_short:
        return "contextual_high"
    if base_importance in {"high", "critical"}:
        return base_importance
    return "normal"
