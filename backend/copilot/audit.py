from __future__ import annotations

import time
import contextvars
from datetime import datetime
from typing import Any

from backend.security import Principal
from backend.store import audit
from backend.copilot.masking import mask_sensitive_text
from backend.copilot.llm_client import OLLAMA_MODEL, OLLAMA_MODEL_PROFILE
from backend.copilot import situation_runtime

_LANGUAGE_CONTEXT: contextvars.ContextVar[dict[str, str | None]] = contextvars.ContextVar(
    "copilot_audit_language_context",
    default={},
)


def set_language_context(
    *,
    selected_language: str | None = None,
    response_language: str | None = None,
    language_source: str | None = None,
) -> contextvars.Token:
    return _LANGUAGE_CONTEXT.set(
        {
            "selected_language": selected_language,
            "response_language": response_language,
            "language_source": language_source,
        }
    )


def reset_language_context(token: contextvars.Token | None) -> None:
    if token is not None:
        _LANGUAGE_CONTEXT.reset(token)


def _safe_text(value: str | None, limit: int = 300) -> str:
    text = str(value or "")
    text = text.replace("\\", "/")
    text = text.split("/")[-1] if (":/" in text or text.startswith("/")) else text
    for marker in ("password=", "api_key=", "apikey=", "secret=", "token="):
        lowered = text.lower()
        index = lowered.find(marker)
        if index >= 0:
            end = text.find(" ", index)
            end = len(text) if end < 0 else end
            text = f"{text[:index]}{marker}[REDACTED]{text[end:]}"
    return text[:limit]


class AuditBuilder:
    """Build consistent sanitized audit metadata across route branches."""

    def __init__(self, message: str, user_id: str, conversation_id: str):
        self._data: dict[str, Any] = {
            "message_preview": _safe_text(mask_sensitive_text(message), 100),
            "user_id": _safe_text(user_id, 120),
            "conversation_id": _safe_text(conversation_id, 120),
            "timestamp": datetime.utcnow().isoformat(),
            "intent": None,
            "task_type": None,
            "language": None,
            "is_compound": False,
            "subtask_count": 0,
            "skill_names": [],
            "tool_names": [],
            "provider_planning_called": False,
            "provider_final_called": False,
            "provider_call_count": 0,
            "translator_called": False,
            "final_answer_mode": None,
            "teaching_mode": False,
            "language_understanding_mode": None,
            "fallback_used": False,
            "error_type": None,
            "success": True,
            "elapsed_ms_total": 0,
            "elapsed_ms_planner": 0,
            "elapsed_ms_tools": 0,
            "elapsed_ms_workflow": 0,
            "elapsed_ms_provider_total": 0,
            "elapsed_ms_translation": 0,
        }
        self._start_time = time.monotonic()

    def set(self, **kwargs: Any) -> "AuditBuilder":
        for key, value in kwargs.items():
            if key in self._data:
                self._data[key] = value
        return self

    def add_tool(self, tool_name: str) -> "AuditBuilder":
        if tool_name and tool_name not in self._data["tool_names"]:
            self._data["tool_names"].append(tool_name)
        return self

    def add_skill(self, skill_name: str) -> "AuditBuilder":
        if skill_name and skill_name not in self._data["skill_names"]:
            self._data["skill_names"].append(skill_name)
        return self

    def mark_provider_call(self, call_type: str) -> "AuditBuilder":
        self._data["provider_call_count"] += 1
        if call_type == "planning":
            self._data["provider_planning_called"] = True
        elif call_type == "final":
            self._data["provider_final_called"] = True
        return self

    def finalize(self) -> dict[str, Any]:
        self._data["elapsed_ms_total"] = int((time.monotonic() - self._start_time) * 1000)
        return dict(self._data)


async def log_interaction(
    principal: Principal,
    conversation_id: str,
    query_length: int,
    intent: str,
    tools_used: list[str],
    tool_result_counts: dict[str, int],
    response_length: int,
    response_time_ms: int,
    sources_count: int,
    error: str | None,
    language: str | None = None,
    *,
    task_type: str | None = None,
    provider_planning_called: bool = False,
    provider_final_called: bool = False,
    final_answer_mode: str | None = None,
    provider_call_count: int | None = None,
    translator_called: bool | None = None,
    is_compound: bool | None = None,
    workflow_step_count: int | None = None,
    skill_names: list[str] | None = None,
    fallback_used: bool | None = None,
    error_type: str | None = None,
    elapsed_ms_total: int | None = None,
    elapsed_ms_planner: int | None = None,
    elapsed_ms_tools: int | None = None,
    elapsed_ms_workflow: int | None = None,
    elapsed_ms_provider_planning: int | None = None,
    elapsed_ms_provider_final: int | None = None,
    elapsed_ms_translation: int | None = None,
    elapsed_ms_rendering: int | None = None,
    teaching_mode: bool | None = None,
    teaching_topic: str | None = None,
    tasks_dropped: list[str] | None = None,
    language_understanding: dict | None = None,
    selected_language: str | None = None,
    response_language: str | None = None,
    language_source: str | None = None,
    model_name: str | None = None,
    model_profile: str | None = None,
    language_validation_passed: bool | None = None,
    language_validation_fallback_used: bool | None = None,
    planner_used: bool | None = None,
    planner_source: str | None = None,
    planner_intent: str | None = None,
    planner_confidence: float | None = None,
    planner_rejected: bool | None = None,
    planner_rejection_reason: str | None = None,
    validated_intent: str | None = None,
    needs_dspm_evidence: bool | None = None,
    allowed_tools: list[str] | None = None,
    selection_mode: str | None = None,
    needs_step_by_step: bool | None = None,
    **extra: Any,
) -> None:
    language_context = _LANGUAGE_CONTEXT.get() or {}
    selected_language = selected_language if selected_language is not None else language_context.get("selected_language")
    response_language = response_language or language_context.get("response_language") or language
    language_source = language_source if language_source is not None else language_context.get("language_source")
    entry = {
        "conversation_id": conversation_id,
        "query_length": query_length,
        "intent": intent,
        "language": language,
        "tools_used": tools_used,
        "tool_result_counts": tool_result_counts,
        "response_length": response_length,
        "response_time_ms": response_time_ms,
        "sources_count": sources_count,
        "error": error,
        "success": error is None,
        "tool_names": tools_used,
        "skill_names": [],
        "is_compound": False,
        "workflow_step_count": 0,
        "provider_call_count": 0,
        "translator_called": False,
        "fallback_used": False,
        "elapsed_ms_total": response_time_ms,
        "elapsed_ms_planner": 0,
        "elapsed_ms_tools": 0,
        "elapsed_ms_workflow": 0,
        "elapsed_ms_provider_planning": 0,
        "elapsed_ms_provider_final": 0,
        "elapsed_ms_translation": 0,
        "elapsed_ms_rendering": 0,
        "teaching_mode": False,
        "selected_language": selected_language,
        "response_language": response_language or language,
        "language_source": language_source,
        "model_name": model_name or OLLAMA_MODEL,
        "model_profile": model_profile or OLLAMA_MODEL_PROFILE,
        "language_validation_passed": language_validation_passed if language_validation_passed is not None else True,
        "language_validation_fallback_used": language_validation_fallback_used if language_validation_fallback_used is not None else False,
        "planner_used": False,
        "planner_source": None,
        "planner_intent": None,
        "planner_confidence": None,
        "planner_rejected": False,
        "planner_rejection_reason": None,
        "validated_intent": None,
        "needs_dspm_evidence": False,
        "allowed_tools": [],
        "selection_mode": None,
        "needs_step_by_step": False,
    }
    if task_type is not None:
        entry["task_type"] = task_type
    entry["provider_planning_called"] = bool(provider_planning_called)
    entry["provider_final_called"] = bool(provider_final_called)
    if final_answer_mode is not None:
        entry["final_answer_mode"] = final_answer_mode
    if provider_call_count is not None:
        entry["provider_call_count"] = provider_call_count
    if translator_called is not None:
        entry["translator_called"] = translator_called
    extra_role_summary = extra.get("provider_role_budget_summary")
    if isinstance(extra_role_summary, dict):
        entry["provider_call_count"] = int(extra_role_summary.get("provider_call_count") or 0)
    role_metadata = situation_runtime.role_budget_metadata(
        verbalizer_call_count=int(extra.get("verbalizer_call_count") or 0),
        arbiter_call_count=int(extra.get("arbiter_call_count") or 0),
        planner_call_count=1 if bool(provider_planning_called) else 0,
        final_provider_call_count=1 if bool(provider_final_called) else 0,
        translator_call_count=1 if bool(entry.get("translator_called")) else 0,
        fast_verbalizer_used=bool(extra.get("fast_verbalizer_used")),
        fast_verbalizer_fallback_used=bool(extra.get("fast_verbalizer_fallback_used")),
    )
    if not isinstance(extra_role_summary, dict):
        entry.update(role_metadata)
    if is_compound is not None:
        entry["is_compound"] = is_compound
    if workflow_step_count is not None:
        entry["workflow_step_count"] = workflow_step_count
    if skill_names is not None:
        entry["skill_names"] = skill_names
    if fallback_used is not None:
        entry["fallback_used"] = fallback_used
    if error_type is not None:
        entry["error_type"] = error_type
    if elapsed_ms_total is not None:
        entry["elapsed_ms_total"] = elapsed_ms_total
    if elapsed_ms_planner is not None:
        entry["elapsed_ms_planner"] = elapsed_ms_planner
    if elapsed_ms_tools is not None:
        entry["elapsed_ms_tools"] = elapsed_ms_tools
    if elapsed_ms_workflow is not None:
        entry["elapsed_ms_workflow"] = elapsed_ms_workflow
    if elapsed_ms_provider_planning is not None:
        entry["elapsed_ms_provider_planning"] = elapsed_ms_provider_planning
    if elapsed_ms_provider_final is not None:
        entry["elapsed_ms_provider_final"] = elapsed_ms_provider_final
    if elapsed_ms_translation is not None:
        entry["elapsed_ms_translation"] = elapsed_ms_translation
    if elapsed_ms_rendering is not None:
        entry["elapsed_ms_rendering"] = elapsed_ms_rendering
    if teaching_mode is not None:
        entry["teaching_mode"] = teaching_mode
    if teaching_topic is not None:
        entry["teaching_topic"] = _safe_text(teaching_topic, 80)
    if tasks_dropped is not None:
        entry["tasks_dropped"] = [_safe_text(item, 120) for item in tasks_dropped[:10]]
    if planner_used is not None:
        entry["planner_used"] = bool(planner_used)
    if planner_source is not None:
        entry["planner_source"] = _safe_text(planner_source, 80)
    if planner_intent is not None:
        entry["planner_intent"] = _safe_text(planner_intent, 120)
    if planner_confidence is not None:
        entry["planner_confidence"] = max(0.0, min(float(planner_confidence), 1.0))
    if planner_rejected is not None:
        entry["planner_rejected"] = bool(planner_rejected)
    if planner_rejection_reason is not None:
        entry["planner_rejection_reason"] = _safe_text(planner_rejection_reason, 160)
    if validated_intent is not None:
        entry["validated_intent"] = _safe_text(validated_intent, 120)
    if needs_dspm_evidence is not None:
        entry["needs_dspm_evidence"] = bool(needs_dspm_evidence)
    if allowed_tools is not None:
        entry["allowed_tools"] = [_safe_text(tool, 120) for tool in allowed_tools[:20]]
    if selection_mode is not None:
        entry["selection_mode"] = _safe_text(selection_mode, 80)
    if needs_step_by_step is not None:
        entry["needs_step_by_step"] = bool(needs_step_by_step)
    if language_understanding is not None:
        allowed = {
            "language_understanding_mode",
            "detected_language",
            "language_candidates",
            "canonical_text",
            "canonical_candidates_count",
            "removed_fillers",
            "typo_corrections_count",
            "intent_candidates",
            "best_intent",
            "intent_confidence",
            "translation_mode",
            "az_quality_failed",
        }
        for key, value in language_understanding.items():
            if key not in allowed:
                continue
            if key == "canonical_text":
                entry[key] = _safe_text(str(value), 120)
            else:
                entry[key] = value
    # Prompt 7: allow-listed language-validator / previous-answer audit fields.
    _EXTRA_AUDIT_KEYS = {
        "language_validator_applied",
        "language_validator_passed",
        "language_validator_repaired",
        "language_validator_violations",
        "previous_answer_rerender_used",
        "previous_answer_source",
        "previous_answer_payload_type",
        "provider_translation_called",
        "answer_type",
        "evidence_count",
        "metric_name",
        "canonical_answer_used",
        "conversation_topic",
        "focus_entity_type",
        "topic_switch_detected",
        "selected_finding_used",
        "count_scope_used",
        "artifact_scope_used",
        "preferred_framing",
        "preferred_verbosity",
        "route_dispatcher_used",
        "route_id",
        "route_priority",
        "route_reason",
        "route_signals",
        "route_handler_name",
        "provider_allowed",
        "translator_allowed",
        "canonical_answer_expected",
        "situation_id",
        "situation_family",
        "situation_confidence",
        "situation_reason",
        "situation_signals",
        "situation_response_mode",
        "situation_provider_mode",
        "situation_zero_provider",
        "situation_candidates",
        "situation_conflict_detected",
        "situation_fallback_needed",
        "situation_classifier_used",
        "situation_classifier_latency_ms",
        "situation_speed_budget_ms",
        "situation_provider_timeout_ms",
        "situation_total_timeout_ms",
        "situation_max_answer_words",
        "situation_max_output_tokens",
        "situation_canonical_required",
        "situation_evidence_required",
        "situation_arbiter_used",
        "situation_arbiter_timed_out",
        "situation_arbiter_invalid_json",
        "situation_arbiter_provider_error",
        "situation_arbiter_situation_id",
        "situation_arbiter_confidence",
        "situation_arbiter_reason",
        "situation_arbiter_safety_flags",
        "situation_arbiter_latency_ms",
        "situation_final_source",
        "fast_verbalizer_enabled",
        "fast_verbalizer_eligible",
        "fast_verbalizer_used",
        "fast_verbalizer_timed_out",
        "fast_verbalizer_validation_failed",
        "fast_verbalizer_fallback_used",
        "fast_verbalizer_latency_ms",
        "fast_verbalizer_situation_id",
        "fast_verbalizer_provider_mode",
        "fast_verbalizer_reason",
        "verbalizer_call_count",
        "arbiter_call_count",
        "planner_call_count",
        "final_provider_call_count",
        "translator_call_count",
        "fast_verbalizer_provider_final_called",
        "fast_verbalizer_provider_planning_called",
        "fast_verbalizer_translator_called",
        "provider_role_budget_summary",
        "provider_budget_total",
        "provider_budget_roles",
        "arbiter_timeout_ms",
        "verbalizer_timeout_ms",
        "response_word_count",
        "response_length_class",
        "fallback_reason",
        "p0_guardrail_used",
        "scope_resolution_used",
        "scope_source",
        "scope_reason",
        "current_explicit_scope",
        "last_count_scope_used",
        "selected_finding_suppressed",
        "operation_intent",
        "operation_supported",
        "unsupported_action_answered",
        "recovery_controller_used",
        "recovery_type",
        "corrected_scope_used",
        "corrected_answer_returned",
        "fallback_family",
        "language_repair_applied",
        "turkish_leakage_blocked",
        "social_repetition_count",
        "response_variant_id",
        "task_frame_controller_used",
        "task_frame_used",
        "task_frame_id",
        "task_frame_action",
        "task_frame_scope_kind",
        "task_frame_scope_values",
        "task_frame_selection_policy",
        "task_frame_pending",
        "task_frame_source",
        "short_followup_resolved",
        "answer_obligation_used",
        "pending_frame_fulfilled",
        "pending_frame_clarification",
        "route_rejected",
        "rejected_route_id",
        "rejection_reason",
        "object_alias",
        "polish_gate_used",
        "polish_passed",
        "polish_failed_invariants",
        "polish_repair_action",
        "polish_scope_check",
        "polish_scope_violation",
        "polish_operation_boundary_checked",
        "polish_fallback_family_checked",
        "polish_language_repair_applied",
        "polish_internal_text_blocked",
        "polish_turkish_leakage_blocked",
        "polish_response_length_policy_applied",
        "polish_user_frustration_detected",
        "polish_corrected_answer_returned",
        "response_length_policy_applied",
        "response_length_budget",
        "response_trimmed",
        "polish_metric_added",
        "script_contamination_blocked",
        "script_contamination_ranges",
        "truncation_detected",
        "truncation_repair_applied",
        "provider_health_status",
        "provider_circuit_state",
        "provider_circuit_open",
        "provider_skip_reason",
        "provider_last_error_type",
        "provider_last_error_message_safe",
        "provider_failure_count",
        "provider_cooldown_remaining_ms",
        "brainmap_used",
        "brainmap_id",
        "brainmap_version",
        "brainmap_situation_family",
        "brainmap_situation_subtype",
        "brainmap_route_id",
        "brainmap_confidence",
        "brainmap_importance",
        "brainmap_provider_final_allowed",
        "brainmap_ai_verbalizer_allowed",
        "brainmap_deterministic_renderer_allowed",
        "brainmap_fallback_after_ms",
        "brainmap_variation_required",
        "brainmap_avoid_repeating_last_n",
        "brainmap_preferred_verbosity",
        "brainmap_response_length_budget",
        "brainmap_expected_answer_shape",
        "brainmap_evidence_required",
        "brainmap_evidence_available",
        "brainmap_metric_name",
        "brainmap_previous_answer_allowed",
        "brainmap_selected_finding_allowed",
        "brainmap_task_frame_allowed",
        "brainmap_ai_arbiter_required",
        "brainmap_policy_source",
        "controlled_verbalizer_allowed",
        "controlled_verbalizer_enabled",
        "controlled_verbalizer_default_enabled",
        "controlled_verbalizer_disabled_by_config",
        "controlled_verbalizer_force_block_reason",
        "controlled_verbalizer_called",
        "controlled_verbalizer_timeout_ms",
        "controlled_verbalizer_result",
        "controlled_verbalizer_fallback_used",
        "controlled_verbalizer_fallback_reason",
        "controlled_verbalizer_validation_failed",
        "controlled_verbalizer_validation_errors",
        "controlled_verbalizer_similarity_retry_used",
        "controlled_verbalizer_similarity_blocked",
        "controlled_verbalizer_latency_ms",
        "controlled_verbalizer_preferred_verbosity",
        "controlled_verbalizer_fallback_variant_id",
        "controlled_verbalizer_fallback_family",
        "controlled_verbalizer_response_fingerprint",
        "controlled_verbalizer_fingerprint_saved",
        "response_variant_seed",
        "anti_repetition_applied",
        "recent_fingerprint_count",
        "active_layer",
        "ai_layer_active",
        "source_layers",
        "ai_layer_source_layers",
        "next_layer",
        "ai_layer_next",
        "blocked_layers",
        "ai_layer_blocked",
        "policy_reason",
        "ai_layer_policy_reason",
        "policy_source_layer",
        "provider_denied_reason",
        "verbalizer_denied_reason",
        "route_confidence",
        "importance",
        "route_importance",
        "should_escalate_to_ai_arbiter",
        "should_clarify",
        "should_use_deterministic_renderer",
        "state_read",
        "state_write",
        "structured_only",
    }
    for key, value in extra.items():
        if key not in _EXTRA_AUDIT_KEYS:
            continue
        if isinstance(value, str):
            entry[key] = _safe_text(value, 160)
        elif isinstance(value, list):
            entry[key] = [_safe_text(str(item), 120) for item in value[:20]]
        else:
            entry[key] = value
    audit(
        principal.tenant_id,
        principal.subject,
        "copilot.chat",
        entry,
    )


async def log_plan_fixup(principal: Principal, payload: dict) -> None:
    audit(
        principal.tenant_id,
        principal.subject,
        "copilot.plan_fixup",
        {
            "event": "copilot_plan_fixup",
            "conversation_id": _safe_text(payload.get("conversation_id"), 120),
            "message_id": _safe_text(payload.get("message_id"), 120),
            "original_llm_task_type": _safe_text(payload.get("original_llm_task_type"), 80),
            "fixed_task_type": _safe_text(payload.get("fixed_task_type"), 80),
            "trigger": _safe_text(payload.get("trigger"), 160),
            "target_entity": _safe_text(payload.get("target_entity"), 160),
        },
    )
