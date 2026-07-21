from __future__ import annotations

import asyncio
import os
import time
import json
import logging
import re
import uuid
from collections.abc import AsyncIterator
from dataclasses import replace
from typing import Awaitable, Callable

from backend.store import read_scan_history, read_scan_report
from backend.copilot import audit, controlled_verbalizer, conversation_polish, correction_controller, correction_detection, evidence_sensitivity, fast_situation_arbiter, file_queries, memory, meta_renderers, product_help, provider_health, response_brainmap, route_dispatcher, routing_authority, situation_arbiter, situation_classifier, situation_guardrails, situation_policy, situation_runtime, state_writer, task_frame_controller, task_types, tools, verbalizer
from backend.copilot.artifacts import ArtifactError, create_report_artifact
from backend.copilot.answer_validator import safe_fallback_for_route, validate_contract_answer
from backend.copilot.az_canned import get_canned_response, is_unsupported_language_message
from backend.copilot.canonical_answer import (
    CanonicalAnswer,
    EvidenceRef,
    canonical_finding_from_dict,
    canonical_answer_for_count,
    canonical_answer_for_finding_list,
    canonical_answer_for_risk_type_breakdown,
    canonical_answer_for_selected_finding,
    canonical_answer_for_severity_distribution,
    metric_spec,
    render_canonical_answer,
)
from backend.copilot import capability_registry
from backend.copilot.capability_registry import render_capabilities
from backend.copilot.intent_router import IntentRoute, route_message
from backend.copilot.masking import mask_sensitive_text
from backend.copilot.skill_registry import DSPM_SKILL_REGISTRY, skill_for_task, is_deterministic_skill
from backend.copilot.skill_renderers import SKILL_RENDERERS, get_renderer
from backend.copilot.structured_queries import compare_findings, count_findings, filter_findings, normalize_finding, proactive_alert_summary, scan_delta_summary
from backend.copilot import professional_workflows as prof
from backend.copilot import conversation_repair as repair
from backend.copilot import language_service
from backend.copilot import language_runtime
from backend.copilot import llm_client
from backend.copilot.language_runtime import LanguageDecision, decide_language, explicit_language_request
from backend.copilot.conversation_state import ConversationState
from backend.copilot.workflow import WorkflowPlan, WorkflowStep, plan_workflow, is_compound_request
from backend.copilot.workflow_executor import (
    StepResult, WorkflowResult, combine_step_answers,
    merge_sources, merge_tools_used, resolve_step_dependency,
)
from backend.copilot.guardrails import (
    GuardrailError,
    clean_answer_text,
    clean_language_boilerplate,
    fallback_answer,
    is_bad_visible_answer,
    provider_unavailable_answer,
    validate_input,
    validate_output,
)
from backend.copilot.language import LanguageIntent, analyze_message, normalize_message
from backend.copilot.language_validator import (
    ensure_final_response_language,
    final_language_audit,
    polish_azerbaijani_prose,
    validate_response_language,
)
from backend.copilot.language_understanding import audit_metadata as language_understanding_audit_metadata
from backend.copilot.language_understanding import understand_message
from backend.copilot.language_detector import (
    is_azerbaijani_capability_question,
    is_explicit_azerbaijani_switch,
    is_explicit_english_switch,
)
from backend.copilot.llm_client import LLMError, call_ollama, check_ollama_model_health
from backend.copilot.planner import (
    RoutePlan,
    heuristic_plan,
    plan_request,
    requested_limit as planner_requested_limit,
    should_use_ai_planner,
)
from backend.copilot.prompts import (
    INTENT_TOOL_MAP,
    ContextBuilder,
    ContextTooLargeError,
    build_answer_messages,
    build_general_chat_messages,
    build_item_answer_messages,
    to_json_text,
)
from backend.copilot.schemas import ChatResponse, IntentResult, SourceRef, ToolResult
from backend.copilot.session_context import build_context, save_session_context, load_session_context
from backend.copilot.severity import severity_from_text
from backend.copilot.tools import NoEvidenceError, ToolError, role_filter
from backend.copilot.translator import LANGUAGE_CAPABILITY_EN, translate_to_azerbaijani
from backend.security import Principal


class CopilotError(Exception):
    def __init__(self, message: str, error_code: str) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code


ToolCallable = Callable[..., Awaitable[ToolResult]]

TOOL_REGISTRY: dict[str, ToolCallable] = {
    "get_executive_dashboard": tools.get_executive_dashboard,
    "get_scan_history": tools.get_scan_history,
    "get_scan_report": tools.get_scan_report,
    "search_findings": tools.search_findings,
    "get_findings_by_severity": tools.get_findings_by_severity,
    "get_high_risk_assets": tools.get_high_risk_assets,
    "explain_risk_for_asset": tools.explain_risk_for_asset,
    "get_recent_alerts": tools.get_recent_alerts,
    "search_audit_events": tools.search_audit_events,
    "generate_remediation_summary": tools.generate_remediation_summary,
    "get_finding_detail": tools.get_finding_detail,
    "compare_scans": tools.compare_scans,
    "get_finding_history": tools.get_finding_history,
    "get_remediation_status": tools.get_remediation_status,
    "get_severity_distribution": tools.get_severity_distribution,
    "get_compliance_mapping": tools.get_compliance_mapping,
    "get_posture_score": tools.get_posture_score,
    "get_compliance_report": tools.get_compliance_report,
    "get_trend_analysis": tools.get_trend_analysis,
}

_log = logging.getLogger(__name__)
_session_locks: dict[str, asyncio.Lock] = {}
_session_locks_guard = asyncio.Lock()
SUPPORTED_RESPONSE_LANGUAGES = {"az", "en", "ru"}

LIST_TASKS = {"list", "critical_findings_list", "severity_findings_list"}
DETAIL_TASKS = {"details", "critical_finding_details"}
REMEDIATION_TASKS = {"remediation", "critical_finding_remediation"}
RISK_EXPLANATION_TASKS = {"explanation", "critical_finding_risk_explanation"}

RANDOM_FINDING_RISK_ANSWERS: dict[str, str] = {
    "en": (
        "Selected finding: {name}\n"
        "File: {name}\n"
        "Severity: {severity}\n"
        "Risk score: {risk_score}\n"
        "Detected sensitive types: {types}\n\n"
        "It is risky because detected sensitive values may expose credentials or regulated data.\n"
        "Impact: unauthorized access, token misuse, or credential reuse may be possible.\n"
        "Recommendation: restrict access, rotate confirmed exposed secrets or tokens, and re-scan after remediation."
    ),
    "az": (
        "Seçilmiş tapıntı: {name}\n"
        "Fayl: {name}\n"
        "Ciddilik dərəcəsi: {severity}\n"
        "Risk skoru: {risk_score}\n"
        "Aşkarlanan həssas məlumat tipləri: {types}\n\n"
        "Risklidir, çünki aşkarlanan həssas dəyərlər credential-ları və ya tənzimlənən məlumatları ifşa edə bilər.\n"
        "Təsir: icazəsiz giriş, token sui-istifadəsi və ya credential təkrar istifadəsi mümkün ola bilər.\n"
        "Tövsiyə: girişi məhdudlaşdır, təsdiqlənmiş ifşa olunmuş secret və ya token-ləri rotate et və düzəlişdən sonra yenidən skan et."
    ),
}

_CLARIFICATION_ANSWERS: dict[str, str] = {
    "en": "What should I use as the context: a scan, finding, alert, or remediation item?",
    "az": "Nəyi nəzərdə tutduğunu bir az dəqiqləşdir: scan, finding, alert, yoxsa remediation?",
    "ru": "Уточните, пожалуйста: вы имеете в виду scan, finding, alert или remediation?",
}


def _clarification_answer(language: str) -> str:
    return _CLARIFICATION_ANSWERS.get(language, _CLARIFICATION_ANSWERS["en"])


_SELECTED_REMEDIATION_CLARIFICATION: dict[str, str] = {
    "en": "What should I use as the context: write the filename, or ask me to choose one finding for the step-by-step plan.",
    "az": "Hansı tapıntı üçün addım-addım plan istədiyini dəqiqləşdir: fayl adını yaz və ya bir tapıntı seçməyimi istə.",
    "ru": "Уточните, для какой находки нужен пошаговый план: укажите имя файла или попросите выбрать одну находку.",
}

_FILENAME_IN_MESSAGE_RE = re.compile(
    r"(?<![\w.-])([\w&+@%(){}\[\],.' -]+\.(?:ya?ml|json|docx?|xlsx?|pptx?|pdf|txt|csv|env|pem|key|sql|zip|7z|gz|tar|log|xml|ini|conf))\b",
    re.IGNORECASE,
)

_ACTION_ADVICE_SIGNAL_GROUPS: tuple[tuple[str, ...], ...] = (
    (
        "what should i do",
        "what i must do",
        "what must i do",
        "what do i do",
        "how to fix",
        "fix it",
        "remediate this",
        "remediation steps",
        "recommend next steps",
        "recommendation",
        "advice",
    ),
    (
        "ne etmeliyem",
        "nə etməliyəm",
        "ne etmeliyemse",
        "nə etməliyəmsə",
        "ne meslehet",
        "nə məsləhət",
        "meslehet gorursen",
        "məsləhət görürsən",
        "nece duzeldim",
        "necə düzəldim",
        "duzeltmek",
        "düzəltmək",
        "addim addim",
        "addım-addım",
        "step by step",
        "basa sal",
        "başa sal",
    ),
)


def _complaint_repair_answer(language: str, context: dict | None = None) -> str:
    # Do NOT append stale list metadata (e.g. "Göstərilən N nəticə.") to a
    # complaint/meta reply — that leaks unrelated context into the apology.
    if language == "az":
        return (
            "Haqlısınız, əvvəlki cavabda sualınızı səhv başa düşmüş ola bilərəm. "
            "Seçilmiş tapıntı kontekstindən bu cavabda istifadə etmirəm. "
            "Say, siyahı və ya müqayisə sualını yazın, mövcud skan məlumatına əsasən cavab verim."
        )
    if language == "ru":
        return (
            "Вы правы — я неправильно понял запрос. "
            "В этом ответе я не буду использовать контекст выбранной находки. "
            "Задайте count, list или compare вопрос, и я отвечу по dashboard scan данным."
        )
    return (
        "You are right to be frustrated. I likely reused the wrong selected finding context. "
        "I will not use that selected finding for this reply. Ask the count, list, or compare question again, "
        "and I will answer from the dashboard scan data."
    )
SELECTED_ITEM_TASKS = DETAIL_TASKS | REMEDIATION_TASKS | RISK_EXPLANATION_TASKS
CORRECTION_TASKS = {"correction", "follow_up_correction", "complaint_repair"}
FUNCTIONAL_TASKS = {
    "scan_comparison",
    "finding_history",
    "compliance_mapping",
    "severity_distribution",
    "remediation_status",
    "posture_score",
    "compliance_report",
    "trend_analysis",
}
SELECTED_ANSWER_TIMEOUT_SECONDS = 12.0
MODEL_UNAVAILABLE_GENERAL = provider_unavailable_answer("en")


def _format_insight_note(insights: list[dict], language: str = "en") -> str:
    count = len(insights)
    if count <= 0:
        return ""
    if language == "az":
        lines = [f"{count} aktiv təhlükəsizlik bildirişi var:"]
        for item in insights[:3]:
            lines.append(f"- {item.get('title_az') or item.get('title_en') or 'Bildiriş'}")
        if count > 3:
            lines.append(f"...və daha {count - 3} bildiriş")
        return "\n".join(lines)
    lines = [f"{count} active security notification{'s' if count != 1 else ''}:"]
    for item in insights[:3]:
        lines.append(f"- {item.get('title_en') or item.get('title_az') or 'Notification'}")
    if count > 3:
        lines.append(f"...and {count - 3} more")
    return "\n".join(lines)


def append_first_insight_note(response: ChatResponse, principal: Principal, is_first_message: bool) -> ChatResponse:
    if not is_first_message or not response.answer:
        return response
    try:
        from backend.copilot.insight_store import get_active_insights

        insights = [
            item
            for item in get_active_insights(5, tenant_id=principal.tenant_id)
            if item.get("severity") in {"critical", "warning"}
        ]
    except Exception:
        return response
    note = _format_insight_note(insights, response.language or "en")
    if not note:
        return response
    response.answer = f"{response.answer}\n\n{note}"
    return response


def _debug_metadata(timings: dict[str, int | str]) -> dict | None:
    if os.environ.get("COPILOT_ENABLE_DEBUG_TOOLS", "").lower() in {"1", "true", "yes"}:
        return {"timings": dict(timings)}
    return None


def _route_dispatch_audit_fields(decision: route_dispatcher.RouteDecision | None) -> dict:
    return route_dispatcher.decision_metadata(decision)


def _response_metadata(timings: dict[str, int | str], route_fields: dict | None = None, *, answer: str | None = None) -> dict | None:
    metadata = _debug_metadata(timings) or {}
    metadata.update(situation_runtime.response_length_metadata(answer))
    for key, value in (route_fields or {}).items():
        if key in {
            "route_dispatcher_used",
            "route_id",
            "route_priority",
            "route_reason",
            "route_signals",
            "route_handler_name",
            "provider_allowed",
            "translator_allowed",
            "selected_finding_used",
            "structured_renderer_used",
            "count_scope_used",
            "artifact_scope_used",
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
            "fallback_used",
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
            "brainmap_used",
            "brainmap_id",
            "brainmap_version",
            "brainmap_situation_family",
            "brainmap_situation_subtype",
            "brainmap_language",
            "brainmap_response_language",
            "brainmap_language_source",
            "brainmap_language_confidence",
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
            "selected_language_source",
            "language_decision_input",
            "language_decision_response",
            "language_decision_confidence",
            "language_decision_source",
            "language_decision_inherit_from_previous",
            "language_decision_explicit_override",
            "language_decision_reason",
        }:
            metadata[key] = value
    return metadata or None


def _elapsed_ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)


async def _get_session_lock(principal: Principal, conversation_id: str) -> asyncio.Lock:
    key = f"{principal.tenant_id}:{principal.subject}:{conversation_id}"
    async with _session_locks_guard:
        lock = _session_locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            _session_locks[key] = lock
        return lock


def _heuristic_intent(message: str) -> IntentResult:
    text = normalize_message(message)
    if any(term in text for term in ("audit", "who started", "login", "user action")):
        return IntentResult(intent="audit_query")
    if any(term in text for term in ("remediation", "remediate", "fix", "recommend", "what should i do now", "what next")):
        return IntentResult(intent="remediation_advice")
    if any(term in text for term in ("alert", "alerts", "alertleri", "alertlerin")):
        return IntentResult(intent="alert_summary")
    if any(term in text for term in ("why", "asset", "risky", "risk assets", "high risk assets", "assetleri", "fayllar", "files", "top 5")):
        return IntentResult(intent="asset_risk")
    if any(term in text for term in ("finding", "findings", "critical", "high", "medium", "low", "pii", "secret", "password")):
        return IntentResult(intent="finding_search")
    if any(term in text for term in ("summary", "dashboard", "posture", "latest scan", "son scan", "netice", "xulase")):
        return IntentResult(intent="executive_summary")
    return IntentResult(intent="general")



def _severity_from_message(message: str) -> str | None:
    return severity_from_text(message)


def _severity_from_session_context(context: dict | None) -> str | None:
    if not context:
        return None
    explicit = str(context.get("last_requested_severity") or "").upper()
    if explicit in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return explicit
    result_type = str(context.get("last_result_type") or "").lower()
    for severity in ("critical", "high", "medium", "low"):
        if result_type.startswith(f"{severity}_"):
            return severity.upper()
    for item in context.get("last_shown_items") or []:
        if not isinstance(item, dict):
            continue
        value = str(item.get("severity") or "").upper()
        if value in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            return value
    return None


def _severity_from_plan(message: str, plan: RoutePlan, context: dict | None) -> str:
    if plan.plan_fixup:
        severity = str(plan.plan_fixup.get("severity") or "").upper()
        if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            return severity
    return _severity_from_message(message) or _severity_from_session_context(context) or "CRITICAL"


def _is_another_one_followup(message: str) -> bool:
    text = normalize_message(message).lower()
    raw = str(message or "").lower()
    joined = f"{text} {raw}"
    return any(term in joined for term in (
        "basqa biri", "başqa biri", "basqa birini", "başqa birini",
        "basqa alert", "başqa alert", "basqa tapinti", "başqa tapinti",
        "o biri", "novbeti", "növbəti", "another one", "different one",
        "next one", "show another", "give me another",
    ))


def _has_selection_context(context: dict | None) -> bool:
    if not context:
        return False
    return bool(
        context.get("last_requested_severity")
        or context.get("last_shown_items")
        or context.get("last_item")
        or context.get("avoided_item_ids")
    )


def _another_one_clarification(language: str) -> str:
    if language == "az":
        return "Hansı severity üçün başqa tapıntı istəyirsiniz: CRITICAL, HIGH, MEDIUM, yoxsa LOW?"
    if language == "ru":
        return "Для какой severity нужен другой finding: CRITICAL, HIGH, MEDIUM или LOW?"
    return "Which severity should I use for another finding: CRITICAL, HIGH, MEDIUM, or LOW?"


def _selection_exclude_ids(plan: RoutePlan, context: dict | None) -> list[str]:
    values: list[str] = []
    for value in plan.exclude_ids or []:
        text = str(value or "").strip()
        if text and text not in values:
            values.append(text)
    if plan.selection_mode in {"random", "next_unshown"}:
        for value in (context or {}).get("avoided_item_ids") or []:
            text = str(value or "").strip()
            if text and text not in values:
                values.append(text)
        for item in (context or {}).get("last_shown_items") or []:
            if not isinstance(item, dict):
                continue
            text = str(item.get("id") or item.get("name") or item.get("safe_identifier") or "").strip()
            if text and text not in values:
                values.append(text)
    return values[:50]


async def _get_findings_by_severity_for_plan(
    principal: Principal,
    severity: str,
    limit: int,
    selection_mode: str | None = None,
    exclude_ids: list[str] | None = None,
) -> ToolResult:
    mode = selection_mode or "top"
    exclusions = [value for value in (exclude_ids or []) if value]
    if mode == "top" and not exclusions:
        return await tools.get_findings_by_severity(principal, severity, limit=limit)
    return await tools.get_findings_by_severity(
        principal,
        severity,
        limit=limit,
        selection_mode=mode,
        exclude_ids=exclusions,
    )


def _risk_types_for_item(item: dict) -> list[str]:
    values: list[str] = []
    for finding in item.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        value = str(finding.get("type") or "").strip()
        if value and value not in values:
            values.append(value)
    return values


def _render_severity_findings_list(payload: dict, severity: str, limit: int, language: str) -> str:
    items = [item for item in (payload.get("results") or []) if isinstance(item, dict)][:limit]
    total = int(payload.get("count") or len(items) or 0)
    scan_id = payload.get("scan_id") or "latest"
    if payload.get("no_more_results") and not items:
        if language == "az":
            return f"Bu sessiyada göstərilməmiş yeni {severity} tapıntı qalmayıb. Scan: {scan_id}."
        if language == "ru":
            return f"В этой сессии не осталось новых не показанных findings уровня {severity}. Scan: {scan_id}."
        return f"No new unshown {severity} findings remain in this session. Scan: {scan_id}."
    if language == "az":
        lines = [f"Son skana görə {total} ədəd {severity} tapıntı var.", f"Göstərilən: {len(items)}", f"Scan: {scan_id}", ""]
        for index, item in enumerate(items, 1):
            types = ", ".join(_risk_types_for_item(item)) or "qeyd olunmayıb"
            lines.append(f"{index}. {item.get('name') or item.get('path') or 'unknown'}")
            lines.append(f"   Severity: {item.get('severity') or severity}; risk score: {item.get('risk_score') if item.get('risk_score') is not None else 'unknown'}; detected types: {types}")
        return "\n".join(lines).strip()
    lines = [f"The latest scan has {total} {severity} findings.", f"Showing: {len(items)}", f"Scan: {scan_id}", ""]
    for index, item in enumerate(items, 1):
        types = ", ".join(_risk_types_for_item(item)) or "none recorded"
        lines.append(f"{index}. {item.get('name') or item.get('path') or 'unknown'}")
        lines.append(f"   Severity: {item.get('severity') or severity}; risk score: {item.get('risk_score') if item.get('risk_score') is not None else 'unknown'}; detected types: {types}")
    return "\n".join(lines).strip()


def _render_severity_count(payload: dict, severity: str, language: str) -> str:
    total = int(payload.get("count") or 0)
    scan_id = payload.get("scan_id") or "latest"
    if language == "az":
        return f"Son skana görə {total} ədəd {severity} tapıntı var. Scan: {scan_id}."
    if language == "ru":
        return f"По данным последнего сканирования, найдено {total} findings уровня {severity}. Scan: {scan_id}."
    return f"According to the latest scan, there are {total} {severity} findings. Scan: {scan_id}."


def _render_severity_compare(payload: dict, severity: str, limit: int, language: str) -> str:
    items = [item for item in (payload.get("results") or []) if isinstance(item, dict)][:limit]
    total = int(payload.get("count") or len(items) or 0)
    if len(items) < 2:
        if language == "az":
            return f"Son skanda {total} ədəd {severity} tapıntı var, amma müqayisə üçün ən azı 2 tapıntı lazımdır."
        return f"The latest scan has {total} {severity} findings, but comparison needs at least 2 findings."
    base = _render_severity_findings_list(payload, severity, limit, language)
    first, second = items[0], items[1]
    first_types = set(_risk_types_for_item(first))
    second_types = set(_risk_types_for_item(second))
    common = sorted(first_types & second_types)
    only_first = sorted(first_types - second_types)
    only_second = sorted(second_types - first_types)
    first_score = first.get("risk_score") or 0
    second_score = second.get("risk_score") or 0
    priority = first if first_score >= second_score else second
    if language == "az":
        lines = [
            base,
            "",
            "Müqayisə:",
            f"- Oxşarlıq: hər ikisi {severity} səviyyəsindədir" + (f" və ortaq tiplər: {', '.join(common)}." if common else "."),
            f"- Fərq: {first.get('name')} üçün xüsusi tiplər: {', '.join(only_first) or 'yox'}; {second.get('name')} üçün xüsusi tiplər: {', '.join(only_second) or 'yox'}.",
            f"- Prioritet: risk score daha yüksək olduğu üçün əvvəlcə {priority.get('name')} yoxlanmalıdır.",
            "- Tövsiyə: owner-i təsdiq edin, lazımsız paylaşımları bağlayın və remediation-dan sonra yenidən scan edin.",
        ]
        return "\n".join(lines)
    lines = [
        base,
        "",
        "Comparison:",
        f"- Similarity: both are {severity} findings" + (f" with shared detected types: {', '.join(common)}." if common else "."),
        f"- Difference: {first.get('name')} unique types: {', '.join(only_first) or 'none'}; {second.get('name')} unique types: {', '.join(only_second) or 'none'}.",
        f"- Priority: review {priority.get('name')} first because it has the higher risk score.",
        "- Recommendation: confirm the data owner, remove unnecessary sharing, and re-scan after remediation.",
    ]
    return "\n".join(lines)




def _asset_hint(message: str) -> str:
    for sep in ('"', "'", "`"):
        if sep in message:
            parts = message.split(sep)
            if len(parts) >= 3 and parts[1].strip():
                return parts[1].strip()
    return message.strip()


def _previous_was_critical_alerts(context: dict | None) -> bool:
    if not context:
        return False
    tools_used = set(context.get("last_tool_names") or [])
    return (
        context.get("last_intent") in {"critical_alerts", "alert_summary"}
        or bool(tools_used & {"get_findings_by_severity", "get_recent_alerts"})
    )


def _is_limit_correction(message: str) -> bool:
    normalized = normalize_message(message).replace(".", " ").replace(",", " ")
    words = set(normalized.split())
    has_number = any(word.isdigit() for word in words)
    return has_number and (
        len(words) <= 6
        or "dedim" in words
        or "not" in words
        or "yox" in words
        or "critical" in words
        or "alert" in words
    )


def _is_english_switch(message: str) -> bool:
    return is_explicit_english_switch(message)


def _metadata_with_answer_language(metadata: LanguageIntent, language: str) -> LanguageIntent:
    target = language if language in SUPPORTED_RESPONSE_LANGUAGES else "en"
    return replace(metadata, language=target, answer_language=target, style=replace(metadata.style, answer_language=target))


def _explicit_language_lock(message: str) -> str | None:
    text = normalize_message(message)
    if any(phrase in text for phrase in ("respond in english", "use english", "speak english", "ingilis dilinde danis", "ingilis dilinde danisaq")):
        return "en"
    if any(phrase in text for phrase in ("azerbaycanca cavab ver", "respond in azerbaijani", "use azerbaijani", "answer in azerbaijani")):
        return "az"
    if "azerbaycan dilinde danis" in text and "bilirsen" not in text and "?" not in message:
        return "az"
    return None


# --- Prompt 7: previous-answer re-render + language-complaint detection ------

_PREV_ANSWER_MODIFIERS = (
    "evvel", "evvelki", "onceki", "bayaq", "bayaqki", "hemin", "son cavab",
    "previous", "last", "that", "this", "preceding",
)


def _requested_language_from_message(message: str) -> str | None:
    return language_service.requested_language_from_message(message)


def _detect_previous_answer_rerender(message: str) -> tuple[bool, str | None]:
    """Detect 'translate/give the previous answer in <language>' requests."""
    norm = normalize_message(message)
    raw = (message or "").lower()
    answer_word = ("cavab" in norm) or ("answer" in norm) or ("ответ" in raw) or ("otvet" in norm)
    prev_mod = any(mod in norm for mod in _PREV_ANSWER_MODIFIERS) or ("предыд" in raw) or ("прошл" in raw)
    if not (answer_word and prev_mod):
        return False, None
    verb_or_lang = (
        any(tok in norm for tok in (
            "ver", "yaz", "translate", "say", "give", "rerender", "render",
            "azerbaycan", "azerbaijani", "english", "ingilis", "russian", "rus dilinde",
        ))
        or any(tok in raw for tok in ("перевед", "скажи", "повтори", "русск", "азербайдж"))
    )
    if not verb_or_lang:
        return False, None
    return True, _requested_language_from_message(message)


def _detect_language_complaint(message: str) -> bool:
    """Detect a grievance that the assistant replied in the wrong language."""
    matched, _ = _detect_previous_answer_rerender(message)
    if matched:
        return False
    if language_service.detect_malformed_output_complaint(message):
        return False
    return language_service.detect_language_complaint(message)


def _detect_count_conflict_explanation(message: str) -> bool:
    return correction_detection.detect_count_conflict_explanation(message)


def _detect_why_previous_answer(message: str) -> bool:
    return correction_detection.detect_why_previous_answer(message)


def _detect_complaint_about_wrong_route(message: str) -> bool:
    return correction_detection.detect_wrong_route_complaint(message)


def _count_conflict_context(message: str, session_state: dict | None, principal: Principal, scan_id: str | None) -> tuple[str, int | None, str | None]:
    severity = severity_from_text(message)
    if not severity and isinstance(session_state, dict):
        previous = str(session_state.get("last_requested_severity") or "").upper()
        if previous in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            severity = previous
    severity = severity or "CRITICAL"

    count_value: int | None = None
    resolved_scan_id: str | None = None
    if isinstance(session_state, dict):
        payload = session_state.get("last_answer_structured_payload")
        if isinstance(payload, dict) and payload.get("scan_id"):
            resolved_scan_id = str(payload.get("scan_id"))
        if session_state.get("last_scan_id"):
            resolved_scan_id = str(session_state.get("last_scan_id"))
    if isinstance(session_state, dict) and str(session_state.get("last_requested_severity") or "").upper() == severity:
        try:
            count_value = int(session_state.get("last_total_count"))
        except (TypeError, ValueError):
            count_value = None
    if count_value is None:
        report = read_scan_report(principal.tenant_id, scan_id)
        if isinstance(report, dict):
            resolved_scan_id = str(report.get("scan_id") or resolved_scan_id or scan_id or "")
            try:
                count_value = int(count_findings(report, severity=severity).get("count") or 0)
            except (TypeError, ValueError):
                count_value = None
    return severity, count_value, resolved_scan_id


def _numbers_in_message(message: str) -> list[str]:
    values: list[str] = []
    for value in re.findall(r"\b\d{1,5}\b", message or ""):
        if value not in values:
            values.append(value)
    return values


def _render_count_conflict_explanation(message: str, session_state: dict | None, principal: Principal, scan_id: str | None, language: str) -> str:
    severity, count_value, _resolved_scan_id = _count_conflict_context(message, session_state, principal, scan_id)
    mentioned = ", ".join(_numbers_in_message(message)) or "əvvəlki rəqəm"
    canonical = str(count_value) if count_value is not None else "mövcud deyil"
    return meta_renderers.render_count_conflict_text(mentioned, severity, canonical, language)


_render_why_previous_answer = meta_renderers.render_why_previous_answer
_render_wrong_route_complaint = meta_renderers.render_wrong_route_complaint


def _is_evidence_sensitive_question(message: str) -> bool:
    """True for questions about DSPM facts (alerts/findings/severity counts,
    breakdowns, lists, fact-asserting explanations) that must be answered from
    scan evidence, never from a free provider-final answer. Delegates to the
    first-class classifier in evidence_sensitivity.py."""
    return evidence_sensitivity.is_evidence_sensitive(message)


_evidence_guard_clarification = meta_renderers.evidence_guard_clarification


def _severity_correction_requested(message: str) -> bool:
    """True when a correction/complaint quotes severity numbers (e.g. a wrong
    breakdown) — those corrections should be answered with real evidence."""
    return correction_controller.severity_correction_requested(message)


def _severity_breakdown_answer(principal: Principal, scan_id: str | None, language: str) -> str | None:
    """Evidence-backed severity breakdown computed from the actual scan report."""
    report = read_scan_report(principal.tenant_id, scan_id)
    if not isinstance(report, dict):
        return None
    counts: dict[str, int] = {}
    total = 0
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        try:
            value = int(count_findings(report, severity=sev).get("count") or 0)
        except (TypeError, ValueError):
            value = 0
        counts[sev] = value
        total += value
    resolved = str(report.get("scan_id") or scan_id or "latest")
    lines = [f"{sev}: {counts[sev]}" for sev in counts]
    if language == "az":
        header = "Sonuncu scan üzrə düzgün severity bölgüsü:"
        footer = f"Cəmi: {total}\nSkan: {resolved}  Metrik: file_level_finding_count"
    elif language == "ru":
        header = "Корректная разбивка по severity по последнему scan:"
        footer = f"Всего: {total}\nСкан: {resolved}  Метрика: file_level_finding_count"
    else:
        header = "Correct severity breakdown from the latest scan:"
        footer = f"Total: {total}\nScan: {resolved}  Metric: file_level_finding_count"
    return "\n".join([header, *lines, footer])


def _wrong_route_complaint_answer(message: str, principal: Principal, scan_id: str | None, language: str) -> tuple[str, list[str]]:
    """Correction acknowledgement; when the user quotes wrong severity numbers,
    re-check the evidence and return the corrected breakdown instead of a
    generic apology. Returns (answer, tools_used)."""
    if _severity_correction_requested(message):
        breakdown = _severity_breakdown_answer(principal, scan_id, language)
        if breakdown:
            if language == "az":
                ack = "Haqlısınız — əvvəlki cavabdakı rəqəmlər düzgün deyildi. Real scan məlumatı ilə düzəldirəm."
            elif language == "ru":
                ack = "Вы правы — цифры в предыдущем ответе были неверными. Исправляю по реальным данным scan."
            else:
                ack = "You're right — the numbers in my earlier answer were not correct. Here is the evidence-backed correction."
            return f"{ack}\n{breakdown}", ["structured_count_findings"]
    return _render_wrong_route_complaint(language), []


_LANGUAGE_COMPLAINT_ANSWERS = meta_renderers.LANGUAGE_COMPLAINT_ANSWERS
_PREV_ANSWER_CANNOT_RECREATE = meta_renderers.PREV_ANSWER_CANNOT_RECREATE
_NO_PREV_ANSWER = meta_renderers.NO_PREV_ANSWER


def _mark_step_by_step_payload(state: dict | None) -> dict | None:
    """Tag the stored structured payload so a later re-render uses step-by-step."""
    if isinstance(state, dict) and isinstance(state.get("last_answer_structured_payload"), dict):
        state["last_answer_structured_payload"]["answer_type"] = "step_by_step_remediation"
    return state


def _render_previous_finding_list(items: list[dict], scan_id: str | None, language: str) -> str:
    lines: list[str] = []
    if language == "az":
        header = "Əvvəlki cavab (yenidən):"
    elif language == "ru":
        header = "Предыдущий ответ (повторно):"
    else:
        header = "Previous answer (re-rendered):"
    lines.append(header)
    for index, item in enumerate(items, 1):
        if not isinstance(item, dict):
            continue
        name = mask_sensitive_text(item.get("name") or item.get("path") or "unknown")
        severity = item.get("severity") or "UNKNOWN"
        score = item.get("risk_score")
        risk_types = ", ".join(item.get("risk_types") or [])
        suffix = f" | {risk_types}" if risk_types else ""
        lines.append(f"{index}. {name} - {severity} - risk score {score}{suffix}")
    if scan_id:
        evidence = {"az": "Mənbə: scan", "ru": "Источник: scan", "en": "Evidence: scan"}[language if language in ("az", "ru") else "en"]
        lines.append(f"{evidence} {scan_id}")
    return "\n".join(lines)


def _rerender_previous_answer(
    session_state: dict | None,
    history: list[dict],
    render_language: str,
) -> tuple[str, dict]:
    """Deterministically re-render the previous answer in the requested language.

    Prefers a stored structured payload; otherwise falls back to a safe
    deterministic translation of the previous answer text, and never retrieves
    new dashboard data.
    """
    lang = render_language if render_language in SUPPORTED_RESPONSE_LANGUAGES else "en"
    state = session_state or {}
    payload = state.get("last_answer_structured_payload") if isinstance(state.get("last_answer_structured_payload"), dict) else None
    audit_meta = {
        "previous_answer_rerender_used": True,
        "previous_answer_source": "none",
        "previous_answer_payload_type": None,
    }

    if payload:
        items = payload.get("items") or payload.get("shown_items") or []
        answer_type = str(payload.get("answer_type") or payload.get("result_type") or "").lower()
        scan_id = payload.get("scan_id") or state.get("last_scan_id")
        clean_items = [item for item in items if isinstance(item, dict)]
        if clean_items and ("remediation" in answer_type or "step_by_step" in answer_type):
            from backend.copilot.skill_renderers import render_step_by_step_remediation
            audit_meta["previous_answer_source"] = "structured_payload"
            audit_meta["previous_answer_payload_type"] = "step_by_step_remediation"
            return render_step_by_step_remediation(clean_items[0], lang, scan_id=scan_id), audit_meta
        if clean_items:
            audit_meta["previous_answer_source"] = "structured_payload"
            audit_meta["previous_answer_payload_type"] = "finding_list"
            return _render_previous_finding_list(clean_items, scan_id, lang), audit_meta

    previous_text = state.get("last_answer_text") or state.get("last_answer_summary")
    if not previous_text:
        for row in reversed(history or []):
            if row.get("role") == "assistant" and str(row.get("content") or "").strip():
                previous_text = str(row.get("content"))
                break

    if previous_text:
        previous_text = str(previous_text)
        audit_meta["previous_answer_source"] = "previous_text"
        audit_meta["previous_answer_payload_type"] = "general_answer_text"
        if lang == "az":
            from backend.copilot.translator import deterministic_az_translation
            deterministic = deterministic_az_translation(previous_text)
            if deterministic and any(ch in deterministic for ch in "əıöüçşğƏİÖÜÇŞĞ"):
                return mask_sensitive_text(deterministic), audit_meta
            return _PREV_ANSWER_CANNOT_RECREATE["az"], audit_meta
        # For en/ru: if the stored text already matches, return it; else say we cannot recreate.
        if lang == "en" and not any(ch in previous_text for ch in "əıöüçşğ") and "русск" not in previous_text.lower():
            return mask_sensitive_text(previous_text), audit_meta
        return _PREV_ANSWER_CANNOT_RECREATE.get(lang, _PREV_ANSWER_CANNOT_RECREATE["az"]), audit_meta

    audit_meta["previous_answer_source"] = "missing"
    return _NO_PREV_ANSWER.get(lang, _NO_PREV_ANSWER["az"]), audit_meta


async def _meta_no_provider_response(
    *,
    principal: Principal,
    conv_id: str,
    message: str,
    answer: str,
    intent: str,
    task_type: str,
    language: str,
    session_state: dict | None,
    selected_language: str | None,
    language_source: str,
    message_id: str,
    start: float,
    language_understanding_audit: dict | None = None,
    canonical_answer: CanonicalAnswer | None = None,
    audit_extra: dict | None = None,
    tools_used: list[str] | None = None,
    extra_state: dict | None = None,
    clear_selected_finding: bool = False,
) -> ChatResponse:
    next_session_state = _with_selected_language_metadata(session_state, principal, conv_id, language, selected_language, language_source)
    next_session_state = _with_language_preference(next_session_state, principal, conv_id, language, message)
    next_session_state = _with_canonical_answer_payload(next_session_state, canonical_answer)
    safe_answer = clean_answer_text(mask_sensitive_text(answer))
    next_session_state = state_writer.record_answer_envelope(
        next_session_state,
        task_type=task_type,
        answer_summary=safe_answer,
        answer_text=safe_answer,
        language=language,
    )
    if extra_state:
        next_session_state = state_writer.record_correction_effects(next_session_state, extra_state)
    if clear_selected_finding:
        next_session_state = state_writer.clear_selected_finding(next_session_state)
    next_session_state = state_writer.sync(next_session_state)
    await save_session_context(principal, conv_id, next_session_state)
    used_tools = list(tools_used or [])
    await memory.save_turn(principal.tenant_id, conv_id, message, answer, [], used_tools)
    total_ms = _elapsed_ms(start)
    audit_extra = dict(audit_extra or {})
    role_summary = audit_extra.get("provider_role_budget_summary")
    if not isinstance(role_summary, dict):
        audit_extra.update(situation_runtime.role_budget_metadata())
    audit_extra.update(
        situation_runtime.runtime_response_metadata(
            answer=answer,
            fallback_used=bool(audit_extra.get("fallback_used", False)),
            fallback_reason=audit_extra.get("fallback_reason"),
        )
    )
    provider_budget_total = int((audit_extra.get("provider_role_budget_summary") or {}).get("provider_call_count") or 0)
    await audit.log_interaction(
        principal, conv_id, len(message), intent, used_tools, {}, len(answer),
        total_ms, 0, None, language,
        task_type=task_type,
        provider_planning_called=False,
        provider_final_called=False,
        final_answer_mode=task_type,
        provider_call_count=provider_budget_total,
        translator_called=False,
        language_understanding=language_understanding_audit or {},
        elapsed_ms_total=total_ms,
        selected_language=next_session_state.get("selected_language") if isinstance(next_session_state, dict) else selected_language,
        response_language=language,
        language_source=language_source,
        **_canonical_audit_fields(canonical_answer),
        **_conversation_state_audit_fields(next_session_state, **audit_extra),
    )
    return ChatResponse(
        answer=answer,
        intent=intent,
        task_type=task_type,
        language=language,
        sources=[],
        tools_used=used_tools,
        conversation_id=conv_id,
        message_id=message_id,
        session_context_summary=_session_summary(next_session_state),
        metadata=_response_metadata({"total_ms": total_ms, "route": task_type}, {**_canonical_audit_fields(canonical_answer), **audit_extra}, answer=answer),
    )


def _arbiter_response_mode(decision) -> str:
    mode = getattr(decision, "response_mode", None)
    return str(getattr(mode, "value", mode) or "")


def _should_run_runtime_situation_arbiter(
    *,
    message: str,
    situation_decision,
    situation_context: situation_classifier.SituationClassificationContext,
    contract_route: IntentRoute,
    heuristic_for_gate: RoutePlan,
    planner_required: bool,
) -> bool:
    if not situation_arbiter.should_run_arbiter(situation_decision, situation_context):
        return False
    if planner_required:
        return False
    if contract_route.intent != "legacy":
        return False
    if heuristic_for_gate.task_type != "general":
        return False
    if any(
        situation_context.flag(name)
        for name in (
            "has_selected_finding",
            "has_shown_list",
            "has_count_scope",
            "has_artifact_scope",
            "has_previous_answer",
        )
    ):
        return False
    folded = normalize_message(message)
    raw = str(message or "").lower()
    joined = f"{folded} {raw}"
    has_ambiguous_analysis = any(
        marker in joined
        for marker in ("qerib", "qərib", "weird", "strange", "ambiguous", "analiz", "analyze")
    )
    has_loose_subject = any(
        marker in joined
        for marker in ("veziyy", "vəziyy", "situation", "this", "bu ")
    )
    return has_ambiguous_analysis and has_loose_subject


async def _handle_unknown_situation_arbiter(
    *,
    principal: Principal,
    conv_id: str,
    message: str,
    target_language: str,
    session_state: dict | None,
    selected_language: str | None,
    language_source: str,
    message_id: str,
    start: float,
    language_understanding_audit: dict | None,
    situation_context: situation_classifier.SituationClassificationContext,
    situation_decision,
) -> ChatResponse | None:
    if not situation_arbiter.should_run_arbiter(situation_decision, situation_context):
        return None

    fallback_candidates = situation_decision.candidates if situation_decision is not None else ()
    request = situation_arbiter.SituationArbiterRequest(
        message=message,
        normalized_message=situation_context.normalized_message or message,
        target_language=target_language,
        context_summary=situation_arbiter.safe_context_summary(situation_context),
        deterministic_decision=situation_decision,
        deterministic_candidates=fallback_candidates,
        allowed_situation_ids=situation_arbiter.allowed_situation_ids(),
    )
    result = await situation_arbiter.run_situation_arbiter(request)
    arbiter_decision = situation_arbiter.arbiter_result_to_decision(result, fallback_candidates)
    final_source = (
        "fallback_clarification"
        if result.invalid_json or result.timed_out or result.provider_error
        else "tiny_arbiter"
    )
    audit_extra: dict = {}
    if situation_decision is not None:
        audit_extra.update(situation_decision.to_route_metadata())
    if arbiter_decision is not None:
        audit_extra.update(arbiter_decision.to_route_metadata())
    audit_extra.update(result.to_metadata(final_source=final_source))
    audit_extra.update(situation_runtime.speed_budget_metadata(arbiter_decision or situation_decision))
    audit_extra.update(
        situation_runtime.role_budget_metadata(
            arbiter_call_count=1 if result.used else 0,
        )
    )
    audit_extra["arbiter_timeout_ms"] = request.timeout_ms
    audit_extra["fallback_used"] = bool(result.invalid_json or result.timed_out or result.provider_error)
    if result.timed_out:
        audit_extra["fallback_reason"] = "arbiter_timeout"
    elif result.invalid_json:
        audit_extra["fallback_reason"] = "arbiter_invalid_json"
    elif result.provider_error:
        audit_extra["fallback_reason"] = "arbiter_provider_error"

    mode = _arbiter_response_mode(arbiter_decision)
    if mode == "SAFE_REFUSAL":
        answer = situation_arbiter.safe_refusal_text(target_language)
        task_type = "safe_refusal"
    else:
        answer = result.clarification_question or situation_arbiter.default_clarification_question(target_language)
        task_type = "clarification"

    return await _meta_no_provider_response(
        principal=principal,
        conv_id=conv_id,
        message=message,
        answer=answer,
        intent=task_type,
        task_type=task_type,
        language=target_language,
        session_state=session_state,
        selected_language=selected_language,
        language_source=language_source,
        message_id=message_id,
        start=start,
        language_understanding_audit=language_understanding_audit,
        audit_extra=audit_extra,
    )


def _deterministic_situation_answer(situation_decision, language: str) -> tuple[str, str, str] | None:
    if situation_decision is None:
        return None
    situation_id = str(getattr(situation_decision, "situation_id", "") or "")
    if situation_id.startswith("safety."):
        return situation_arbiter.safe_refusal_text(language), "safe_refusal", "safe_refusal"
    if situation_id == "general.external_world":
        if language == "az":
            return (
                "Canlı hava və ya web məlumatına çıxışım yoxdur. DSPM scan nəticələri üzrə sual versəniz, "
                "yerli məlumatlara əsasən kömək edə bilərəm."
            ), "external_world_unsupported", "external_world_unsupported"
        return (
            "I do not have live weather or web access. Ask about DSPM scan results and I can answer from local evidence."
        ), "external_world_unsupported", "external_world_unsupported"
    if situation_id == "social.frustration_unclear":
        if language == "az":
            return (
                "Üzr istəyirəm. Hansı DSPM mövzusunu dəqiqləşdirim ki, sizə daha düzgün kömək edim?"
            ), "social_frustration_unclear", "social_frustration_unclear"
        return (
            "I'm sorry. Which DSPM topic should I clarify so I can help more accurately?"
        ), "social_frustration_unclear", "social_frustration_unclear"
    if situation_id == "edu.risk_score":
        if language == "az":
            return (
                "Risk score tapıntının nə qədər təcili və təhlükəli olduğunu göstərən baldır. Bal adətən "
                "severity, məlumat tipi, ekspozisiya və remediation prioritetinə əsaslanır."
            ), "risk_score_concept", "risk_score_concept"
        return (
            "Risk score is a priority score that shows how urgent and risky a finding is. It usually reflects severity, data type, exposure, and remediation priority."
        ), "risk_score_concept", "risk_score_concept"
    return None


# Social/meta situations whose safe canned draft may be passed through the fast
# verbalizer. Factual, workflow, artifact, safety, language-repair, capability,
# and unknown situations are intentionally excluded — they never get verbalized.
_VERBALIZER_ELIGIBLE_SOCIAL_IDS = {
    "social.praise",
    "social.thanks",
    "social.greeting",
    "social.greeting_status",
    "social.status_check",
    "social.casual_reaction",
    "social.farewell",
    "social.frustration_unclear",
}


# Maps deterministic contract greeting/status intents to their social situation
# id so their canned drafts can be micro-verbalized like the classifier path.
_CONTRACT_INTENT_TO_SOCIAL_SITUATION = {
    "greeting": "social.greeting",
    "small_talk_status": "social.status_check",
    "greeting_status": "social.greeting_status",
}


def _social_decision_for_situation(situation_id: str):
    """Build a minimal SituationDecision for a known social situation id."""
    if situation_policy.maybe_get_policy(situation_id) is None:
        return None
    candidate = situation_policy.SituationCandidate(
        situation_id=situation_id,
        confidence=0.95,
        priority=situation_policy.get_policy(situation_id).priority,
        matched=True,
        reason="deterministic social contract route",
        signals=("contract_social",),
    )
    return situation_policy.build_decision_from_candidate(candidate)


async def _verbalize_canned_social_draft(
    *,
    safe_draft: str,
    situation_decision,
    target_language: str,
    conversation_id: str,
) -> verbalizer.VerbalizerResult | None:
    if situation_decision is None:
        return None
    if situation_decision.situation_id not in _VERBALIZER_ELIGIBLE_SOCIAL_IDS:
        return None
    request = verbalizer.VerbalizerRequest(
        safe_draft=safe_draft,
        situation_decision=situation_decision,
        target_language=target_language,
        style_hint="short, warm, professional",
        max_words=20,
        max_tokens=80,
        timeout_ms=1500,
        allow_emoji=True,
        metadata={"conversation_id": conversation_id},
    )
    return await verbalizer.run_fast_verbalizer(request)


def _resolve_followup_item(session_state: dict | None) -> dict | None:
    """Return the finding the user is following up on, from safe session memory."""
    if not isinstance(session_state, dict):
        return None
    current = session_state.get("current_item")
    if isinstance(current, dict) and current.get("name"):
        return current
    last = session_state.get("last_item")
    if isinstance(last, dict) and last.get("name"):
        return last
    items = [i for i in (session_state.get("last_shown_items") or []) if isinstance(i, dict)]
    if len(items) == 1:
        return items[0]
    payload = session_state.get("last_answer_structured_payload")
    if isinstance(payload, dict):
        payload_items = [i for i in (payload.get("items") or payload.get("shown_items") or []) if isinstance(i, dict)]
        if len(payload_items) == 1 and payload_items[0].get("name"):
            return payload_items[0]
    return None


def _detect_action_advice_or_remediation_followup(message: str) -> bool:
    """Semantic signal group for selected-finding action/advice/remediation turns."""
    raw = str(message or "").lower()
    folded = normalize_message(raw).lower()
    intent_folded = language_service.normalize_for_intent(raw).lower()
    joined = f"{raw} {folded} {intent_folded}"
    for group in _ACTION_ADVICE_SIGNAL_GROUPS:
        if any(term in joined for term in group):
            return True
    action_terms = ("etməli", "etmeli", "fix", "remediat", "düzəlt", "duzelt", "məsləhət", "meslehet")
    explanation_terms = ("step", "addım", "addim", "başa sal", "basa sal", "plan", "steps")
    return any(term in joined for term in action_terms) and any(term in joined for term in explanation_terms)


def _extract_explicit_filename(message: str) -> str | None:
    for match in _FILENAME_IN_MESSAGE_RE.finditer(str(message or "")):
        name = re.sub(r"\s+", " ", match.group(1)).strip(" .,:;!?\"'")
        if name:
            return name
    return None


def _mentions_previous_set(message: str) -> bool:
    text = language_service.normalize_for_intent(str(message or "")).lower()
    raw = str(message or "").lower()
    joined = f"{text} {raw}"
    return any(term in joined for term in ("bunlar", "bunların", "onlar", "onlardan", "these", "those", "all of them", "hamısı"))


def _mentions_overall_scope(message: str) -> bool:
    text = language_service.normalize_for_intent(str(message or "")).lower()
    raw = str(message or "").lower()
    joined = f"{text} {raw}"
    return any(term in joined for term in ("umumiyyetle", "Ã¼mumiyyÉ™tlÉ™", "overall", "in general", "generally", "general advice"))


_PLURAL_COUNT_WORDS = ("two", "three", "four", "five", "six", "seven", "eight", "nine", "ten")


def _looks_like_numbered_item_reference(message: str) -> bool:
    text = language_service.normalize_for_intent(str(message or "")).lower()
    raw = str(message or "").lower()
    joined = f"{text} {raw}"
    nouns = ("number", "item", "finding", "tapinti", "tapÄ±ntÄ±", "alert", "bunu", "this")
    if bool(re.search(r"\b\d+\b", joined)) and any(term in joined for term in nouns):
        return True
    # Spelled-out plural counts (two..ten) name a list of items just like the
    # digit form above; without this "three alert and recommendation" is wrongly
    # swallowed by the single-finding remediation clarification.
    if any(re.search(rf"\b{word}\b", joined) for word in _PLURAL_COUNT_WORDS) and any(term in joined for term in nouns):
        return True
    return False


def _looks_like_legacy_pronoun_resolution(message: str) -> bool:
    text = language_service.normalize_for_intent(str(message or "")).lower()
    raw = str(message or "").lower()
    joined = f"{text} {raw}"
    return any(term in joined for term in ("about this", "about it"))


def _has_plural_shown_context(session_state: dict | None) -> bool:
    if not isinstance(session_state, dict):
        return False
    shown = [item for item in (session_state.get("last_shown_items") or []) if isinstance(item, dict)]
    return len(shown) > 1


def _looks_like_new_finding_selection_request(message: str) -> bool:
    text = language_service.normalize_for_intent(str(message or "")).lower()
    raw = str(message or "").lower()
    joined = f"{text} {raw}"
    has_selection = any(term in joined for term in ("random", "təsadüfi", "tesadufi", "bir ", "biri", "one ", "single "))
    has_object = any(term in joined for term in ("tapinti", "tapıntı", "finding", "alert", "risk"))
    has_scope = severity_from_text(message) is not None
    has_show = any(term in joined for term in ("ver", "goster", "göstər", "show", "give", "cixart", "çıxart", "tapib", "tapıb"))
    return (has_selection and has_object) or (has_scope and (has_show or has_object))


def _looks_like_risk_type_teaching_request(message: str) -> bool:
    text = language_service.normalize_for_intent(str(message or "")).lower()
    raw = str(message or "").lower()
    joined = f"{text} {raw}"
    teaching_terms = (
        "what does",
        "what is",
        "mean",
        "explain",
        "izah",
        "nÉ™ demÉ™kdir",
        "ne demekdir",
        "oyret",
        "Ã¶yrÉ™t",
    )
    risk_terms = (
        "private key",
        "private_key",
        "api key",
        "api_key",
        "jwt",
        "password",
        "secret",
        "token",
        "credential",
        "credit card",
        "credit_card",
        "finding type",
        "risk type",
    )
    return any(term in joined for term in teaching_terms) and any(term in joined for term in risk_terms)


def _has_non_selected_followup_context(session_state: dict | None) -> bool:
    if not isinstance(session_state, dict) or not session_state:
        return False
    selected_keys = ("current_item", "last_item", "last_shown_items")
    if any(session_state.get(key) for key in selected_keys):
        return False
    context_keys = (
        "last_task_type",
        "last_answer_type",
        "last_requested_severity",
        "last_requested_severities",
        "last_scope",
        "last_total_count",
        "last_result_type",
        "active_task_frame",
        "task_frame",
        "artifact",
        "active_artifact",
    )
    return any(session_state.get(key) for key in context_keys)


def _find_item_by_filename(principal: Principal, filename: str, scan_id: str | None) -> tuple[dict | None, str | None]:
    findings, resolved_scan_id = _report_findings_with_id(principal, scan_id)
    wanted = filename.replace("\\", "/").split("/")[-1].lower()
    for item in findings:
        names = {
            str(item.get("name") or "").lower(),
            str(item.get("path") or "").replace("\\", "/").split("/")[-1].lower(),
            str(item.get("safe_identifier") or "").lower(),
            str(item.get("detail_ref") or "").lower(),
            str(item.get("full_detail_ref") or "").lower(),
        }
        if wanted in names:
            return item, resolved_scan_id
    return None, resolved_scan_id


def _safe_selected_item_state(item: dict, scan_id: str | None, *, source: str) -> dict:
    name = item.get("name") or item.get("path") or item.get("safe_identifier")
    return {
        "index": item.get("index") or 1,
        "id": item.get("id") or name,
        "name": name,
        "severity": item.get("severity"),
        "risk_score": item.get("risk_score"),
        "risk_types": item.get("risk_types") or [],
        "scan_id": item.get("scan_id") or scan_id,
        "source": source,
        "source_type": "finding",
        "safe_identifier": name,
        "detail_ref": name,
        "full_detail_ref": name,
    }


def _selected_finding_context_update(
    session_state: dict | None,
    item: dict,
    scan_id: str | None,
    *,
    source: str,
    answer_type: str,
) -> dict:
    next_state = dict(session_state or {})
    selected = _safe_selected_item_state(item, scan_id, source=source)
    next_state = state_writer.record_selected_finding(next_state, selected)
    next_state["last_item"] = selected
    existing_shown = [shown for shown in (next_state.get("last_shown_items") or []) if isinstance(shown, dict)]
    if source == "explicit_filename" and len(existing_shown) > 1:
        next_state = state_writer.record_shown_items(next_state, existing_shown)
    else:
        next_state = state_writer.record_shown_items(next_state, [selected])
    next_state["last_requested_limit"] = 1
    next_state["last_total_count"] = next_state.get("last_total_count") or 1
    next_state["last_result_type"] = "selected_finding"
    severity = str(selected.get("severity") or "").upper()
    if severity:
        next_state["last_requested_severity"] = severity
    next_state["last_scan_id"] = scan_id or selected.get("scan_id") or next_state.get("last_scan_id")
    next_state["last_task_type"] = answer_type
    next_state["last_answer_type"] = answer_type
    next_state["last_answer_structured_payload"] = {
        "answer_type": answer_type,
        "scan_id": next_state.get("last_scan_id"),
        "metric": {"name": "file_level_finding_count", "scope": "selected_finding"},
        "items": [selected],
        "shown_items": [selected],
    }
    return state_writer.sync(next_state)


def _render_selected_finding_detail(item: dict, language: str, scan_id: str | None) -> str:
    name = str(item.get("name") or item.get("path") or "unknown")
    severity = str(item.get("severity") or "UNKNOWN").upper()
    score = item.get("risk_score")
    types = ", ".join([str(value) for value in (item.get("risk_types") or []) if str(value).strip()]) or ("unknown" if language == "en" else "bilinmir")
    sid = scan_id or item.get("scan_id") or "latest"
    if language == "en":
        return (
            f"Finding detail: {name}\n"
            f"- Severity: {severity}\n"
            f"- Risk score: {score if score is not None else 'unknown'}\n"
            f"- Risk types: {types}\n"
            f"Scan: {sid}  Metric: file_level_finding_count"
        )
    return (
        f"Tapıntı detalı: {name}\n"
        f"- Ciddilik: {severity}\n"
        f"- Risk balı: {score if score is not None else 'bilinmir'}\n"
        f"- Risk tipləri: {types}\n"
        f"Skan: {sid}  Metrik: file_level_finding_count"
    )


async def _handle_selected_finding_remediation_followup(
    *,
    principal: Principal,
    conv_id: str,
    message: str,
    language: str,
    session_state: dict | None,
    scan_id: str | None,
    selected_language: str | None,
    language_source: str,
    message_id: str,
    start: float,
    language_understanding_audit: dict | None = None,
) -> ChatResponse | None:
    explicit_filename = _extract_explicit_filename(message)
    if explicit_filename:
        item, resolved_scan_id = _find_item_by_filename(principal, explicit_filename, scan_id)
        if not item:
            return None
        answer = _render_selected_finding_detail(item, language, resolved_scan_id)
        source = "explicit_filename"
        task_type = "selected_finding_detail"
    elif _detect_action_advice_or_remediation_followup(message):
        if (
            _mentions_previous_set(message)
            or _mentions_overall_scope(message)
            or _looks_like_numbered_item_reference(message)
            or _looks_like_legacy_pronoun_resolution(message)
            or _looks_like_new_finding_selection_request(message)
            or _has_plural_shown_context(session_state)
        ):
            return None
        item = _resolve_followup_item(session_state)
        resolved_scan_id = scan_id or ((session_state or {}).get("last_scan_id") if isinstance(session_state, dict) else None)
        if not item:
            if (
                _looks_like_new_finding_selection_request(message)
                or _looks_like_risk_type_teaching_request(message)
                or _has_non_selected_followup_context(session_state)
            ):
                return None
            answer = _SELECTED_REMEDIATION_CLARIFICATION.get(language, _SELECTED_REMEDIATION_CLARIFICATION["az"])
            return await _meta_no_provider_response(
                principal=principal,
                conv_id=conv_id,
                message=message,
                answer=answer,
                intent="clarification",
                task_type="selected_finding_remediation_clarification",
                language=language,
                session_state=session_state,
                selected_language=selected_language,
                language_source=language_source,
                message_id=message_id,
                start=start,
                language_understanding_audit=language_understanding_audit,
                audit_extra={
                    "route_id": "selected_finding_remediation_followup",
                    "selected_finding_used": False,
                },
            )
        from backend.copilot.skill_renderers import render_step_by_step_remediation
        answer = render_step_by_step_remediation(item, language=language, scan_id=resolved_scan_id)
        source = "selected_finding_followup"
        task_type = "critical_finding_remediation"
    else:
        return None

    answer = clean_answer_text(mask_sensitive_text(answer))
    response_state = _selected_finding_context_update(
        session_state,
        item,
        resolved_scan_id,
        source=source,
        answer_type="selected_finding_remediation",
    )
    canonical_answer = canonical_answer_for_selected_finding(item, answer, resolved_scan_id, language)
    audit_extra = {
        "route_id": "selected_finding_remediation_followup",
        "selected_finding_used": True,
        "structured_renderer_used": True,
    }
    return await _meta_no_provider_response(
        principal=principal,
        conv_id=conv_id,
        message=message,
        answer=answer,
        intent="remediation_advice" if source == "selected_finding_followup" else "finding_detail",
        task_type=task_type,
        language=language,
        session_state=response_state,
        selected_language=selected_language,
        language_source=language_source,
        message_id=message_id,
        start=start,
        language_understanding_audit=language_understanding_audit,
        canonical_answer=canonical_answer,
        audit_extra=audit_extra,
        tools_used=["get_finding_detail"],
    )


def _report_findings_with_id(principal: Principal, scan_id: str | None) -> tuple[list[dict], str | None]:
    """Return (normalized safe findings, scan_id) from the latest scan report."""
    report = read_scan_report(principal.tenant_id, scan_id)
    if not isinstance(report, dict):
        return [], scan_id
    sid = report.get("scan_id") or scan_id
    findings = [
        normalize_finding(item, sid)
        for item in report.get("files") or []
        if isinstance(item, dict)
    ]
    return findings, sid


def _safe_item_risk_score(item: dict) -> float:
    try:
        return float(item.get("risk_score") or 0)
    except (TypeError, ValueError):
        return 0.0


def _latest_and_previous_reports(principal: Principal, scan_id: str | None = None) -> tuple[dict | None, dict | None]:
    history_limit = 50 if scan_id else 2
    history_rows = read_scan_history(principal.tenant_id, history_limit)
    latest_report = read_scan_report(principal.tenant_id, scan_id) if scan_id else read_scan_report(principal.tenant_id)
    if not isinstance(latest_report, dict):
        return None, None
    latest_id = str(latest_report.get("scan_id") or scan_id or "")
    previous_id: str | None = None
    for row in reversed(history_rows):
        row_id = str(row.get("scan_id") or "")
        if row_id and row_id != latest_id:
            previous_id = row_id
            break
    previous_report = read_scan_report(principal.tenant_id, previous_id) if previous_id else None
    return latest_report, previous_report


def _canonical_scan_delta(payload: dict, answer: str, language: str) -> CanonicalAnswer:
    metric = metric_spec("file_level_finding_count", scope="latest_vs_previous")
    latest = payload.get("latest_scan_id")
    previous = payload.get("previous_scan_id")
    severity_delta = payload.get("severity_delta") if isinstance(payload.get("severity_delta"), dict) else {}
    counts = {
        "latest_total_findings": int(payload.get("latest_total_findings") or 0),
        "previous_total_findings": int(payload.get("previous_total_findings") or 0),
        "total_finding_count_delta": int(payload.get("total_finding_count_delta") or 0),
        "new_findings_count": int(payload.get("new_findings_count") or 0),
        "resolved_findings_count": int(payload.get("resolved_findings_count") or 0),
        "common_findings_count": int(payload.get("common_findings_count") or 0),
    }
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        counts[f"severity_delta_{severity}"] = int(severity_delta.get(severity, 0) or 0)
    evidence = [EvidenceRef(source="latest scan report", scan_id=latest, metric=metric.name, confidence="high")]
    if previous:
        evidence.append(EvidenceRef(source="previous scan report", scan_id=previous, metric=metric.name, confidence="high"))
    return CanonicalAnswer(
        answer_type="scan_delta",
        display_text=answer,
        scan_id=str(latest) if latest else None,
        metric=metric,
        counts=counts,
        evidence=evidence,
        metadata={
            "latest_scan_id": str(latest) if latest else None,
            "previous_scan_id": str(previous) if previous else None,
            "verdict": str(payload.get("verdict") or "unavailable"),
        },
        language=language,
    )


def _canonical_fix_now(items: list[dict], answer: str, scan_id: str | None, language: str, total_count: int) -> CanonicalAnswer:
    metric = metric_spec("file_level_finding_count", scope="whole_scan_top_5")
    canonical_items = [canonical_finding_from_dict(item, scan_id) for item in items[:5]]
    return CanonicalAnswer(
        answer_type="fix_now_top_risks",
        display_text=answer,
        scan_id=scan_id,
        metric=metric,
        items=canonical_items,
        counts={"shown_count": len(canonical_items), "total_matching_count": int(total_count or 0)},
        evidence=[
            EvidenceRef(
                source="latest scan report",
                scan_id=scan_id,
                metric=metric.name,
                item_id=item.id,
                item_name=item.name,
                confidence="high",
            )
            for item in canonical_items
        ] or [EvidenceRef(source="latest scan report", scan_id=scan_id, metric=metric.name, confidence="high")],
        metadata={"ranking_policy": "severity,risk_score,credential_first,name"},
        language=language,
    )


def _shown_items_state(items: list[dict], scan_id: str | None) -> list[dict]:
    shown: list[dict] = []
    for index, item in enumerate(items[:5], 1):
        name = item.get("name")
        if not name:
            continue
        shown.append(
            {
                "index": index,
                "id": item.get("id") or name,
                "name": name,
                "severity": item.get("severity"),
                "risk_score": item.get("risk_score"),
                "risk_types": item.get("risk_types") or [],
                "scan_id": item.get("scan_id") or scan_id,
                "source_type": "finding",
                "safe_identifier": name,
                "detail_ref": name,
                "full_detail_ref": name,
            }
        )
    return shown


async def _handle_professional_followup(
    *,
    intent: str,
    principal: Principal,
    conv_id: str,
    message: str,
    language: str,
    session_state: dict | None,
    scan_id: str | None,
    selected_language: str | None,
    language_source: str,
    message_id: str,
    start: float,
    language_understanding_audit: dict | None = None,
    dispatch_decision: route_dispatcher.RouteDecision | None = None,
) -> ChatResponse | None:
    """Deterministic, zero-provider handler for professional follow-ups."""
    items = [i for i in ((session_state or {}).get("last_shown_items") or []) if isinstance(i, dict)]
    canonical_answer: CanonicalAnswer | None = None
    response_session_state = dict(session_state or {})
    audit_extra: dict = {"selected_finding_used": False, **_route_dispatch_audit_fields(dispatch_decision)}

    if intent == prof.SCAN_DELTA:
        latest_report, previous_report = _latest_and_previous_reports(principal, scan_id)
        payload = scan_delta_summary(latest_report, previous_report)
        answer = prof.render_scan_delta(payload, language)
        task_type = "scan_delta"
        response_session_state["current_topic"] = "scan_comparison"
        response_session_state["last_answer_type"] = task_type
        canonical_answer = _canonical_scan_delta(payload, answer, language)
    elif intent == prof.FIX_NOW_TOP_RISKS:
        findings, resolved_scan_id = _report_findings_with_id(principal, scan_id)
        ranked = prof.rank_fix_now_items(findings)
        top_items = ranked[:5]
        answer = prof.render_fix_now_top_risks(findings, language, scan_id=resolved_scan_id, top_n=5)
        task_type = "fix_now_top_risks"
        response_session_state["current_topic"] = "risk_triage"
        response_session_state["last_result_type"] = "fix_now_top_risks"
        response_session_state["last_requested_limit"] = len(top_items)
        response_session_state["last_total_count"] = len(findings)
        response_session_state["last_shown_items"] = _shown_items_state(top_items, resolved_scan_id)
        response_session_state.pop("last_item", None)
        response_session_state.pop("current_item", None)
        response_session_state["last_answer_type"] = task_type
        response_session_state["last_task_type"] = task_type
        canonical_answer = _canonical_fix_now(top_items, answer, resolved_scan_id, language, len(findings))
    elif intent == prof.RISKIEST:
        # Empty list -> render_riskiest returns a smart clarification.
        answer = prof.render_riskiest(items, language)
        task_type = "riskiest_item" if items else "clarification_followup"
        if items:
            audit_extra["selected_finding_used"] = True
            top = sorted(items, key=lambda item: (-_safe_item_risk_score(item), str(item.get("name") or "")))[0]
            canonical_answer = canonical_answer_for_selected_finding(top, answer, top.get("scan_id") or scan_id, language)
    elif intent == prof.TRIAGE:
        # Explicit "fix first" ask with no list -> clarify instead of a provider call.
        answer = prof.render_triage(items, language)
        task_type = "triage_priorities" if items else "clarification_followup"
        if items:
            canonical_answer = canonical_answer_for_finding_list(
                {
                    "scan_id": scan_id or items[0].get("scan_id"),
                    "items": items,
                    "count": len(items),
                    "returned": len(items),
                    "severity": (session_state or {}).get("last_requested_severity"),
                },
                answer,
                language,
            )
    elif intent == prof.CONDENSE:
        previous = (session_state or {}).get("last_answer_text") or (session_state or {}).get("last_answer_summary") or ""
        answer = prof.condense_answer(previous, language)
        task_type = "condense_previous"
        response_session_state["preferred_verbosity"] = "short"
        response_session_state["last_answer_type"] = task_type
    elif intent == prof.MANAGER_SUMMARY:
        item = _resolve_followup_item(session_state)
        if not item:
            return None
        answer = prof.render_manager_summary(item, language)
        sid = item.get("scan_id") or scan_id or "latest"
        footer = f"Scan: {sid}  Metric: file_level_finding_count" if language != "az" else f"Skan: {sid}  Metrik: file_level_finding_count"
        if footer not in answer:
            answer = f"{answer}\n\n{footer}"
        task_type = "manager_summary"
        response_session_state["preferred_framing"] = "manager"
        response_session_state["last_answer_type"] = task_type
        audit_extra["selected_finding_used"] = True
        canonical_answer = canonical_answer_for_selected_finding(item, answer, item.get("scan_id") or scan_id, language)
    elif intent == prof.TECHNICAL_REMEDIATION:
        item = _resolve_followup_item(session_state)
        if not item:
            return None
        answer = prof.render_technical_remediation(item, language, scan_id=scan_id)
        task_type = "technical_remediation"
        response_session_state["preferred_framing"] = "technical"
        response_session_state["last_answer_type"] = task_type
        audit_extra["selected_finding_used"] = True
        canonical_answer = canonical_answer_for_selected_finding(item, answer, item.get("scan_id") or scan_id, language)
    elif intent == prof.RISK_TYPE_BREAKDOWN:
        return await _handle_risk_type_breakdown(
            principal=principal, conv_id=conv_id, message=message, language=language,
            session_state=session_state, scan_id=scan_id, selected_language=selected_language,
            language_source=language_source, message_id=message_id, start=start,
            language_understanding_audit=language_understanding_audit,
            dispatch_decision=dispatch_decision,
        )
    else:
        return None

    if canonical_answer and task_type not in {"manager_summary", "technical_remediation"}:
        answer = render_canonical_answer(canonical_answer, language)
        if task_type == "triage_priorities":
            canonical_answer = canonical_answer_for_finding_list(
                {
                    "scan_id": scan_id or (items[0].get("scan_id") if items else None),
                    "items": items,
                    "count": len(items),
                    "returned": len(items),
                    "severity": (session_state or {}).get("last_requested_severity"),
                },
                answer,
                language,
            )
        elif items and task_type == "riskiest_item":
            top = sorted(items, key=lambda item: (-_safe_item_risk_score(item), str(item.get("name") or "")))[0]
            canonical_answer = canonical_answer_for_selected_finding(top, answer, top.get("scan_id") or scan_id, language)
        elif task_type in {"manager_summary", "technical_remediation"}:
            item = _resolve_followup_item(session_state) or {}
            canonical_answer = canonical_answer_for_selected_finding(item, answer, item.get("scan_id") or scan_id, language)
    answer = clean_answer_text(mask_sensitive_text(answer))
    return await _meta_no_provider_response(
        principal=principal,
        conv_id=conv_id,
        message=message,
        answer=answer,
        intent=task_type,
        task_type=task_type,
        language=language,
        session_state=response_session_state,
        selected_language=selected_language,
        language_source=language_source,
        message_id=message_id,
        start=start,
        language_understanding_audit=language_understanding_audit,
        canonical_answer=canonical_answer,
        audit_extra=audit_extra,
    )


async def _handle_risk_type_breakdown(
    *,
    principal: Principal,
    conv_id: str,
    message: str,
    language: str,
    session_state: dict | None,
    scan_id: str | None,
    selected_language: str | None,
    language_source: str,
    message_id: str,
    start: float,
    language_understanding_audit: dict | None = None,
    dispatch_decision: route_dispatcher.RouteDecision | None = None,
) -> ChatResponse | None:
    """Risk-type breakdown grounded in the latest scan report (real evidence)."""
    findings, resolved_scan_id = _report_findings_with_id(principal, scan_id)
    if not findings:
        # Fall back to shown items if a report is unavailable.
        findings = [i for i in ((session_state or {}).get("last_shown_items") or []) if isinstance(i, dict)]
    if not findings:
        return None
    # Severity comes from the message; only inherit the previous list's severity
    # when the user explicitly points back at that set ("bu kritikdən ...").
    severity = severity_from_text(message)
    if not severity and prof.refers_to_previous_set(message) and isinstance(session_state, dict):
        prev = str(session_state.get("last_requested_severity") or "").upper()
        if prev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            severity = prev
    queried = prof._queried_category(prof._norm(message))
    answer = prof.render_risk_type_breakdown(
        findings, language, severity=severity, queried_category=queried, scan_id=resolved_scan_id
    )
    canonical_answer = canonical_answer_for_risk_type_breakdown(
        findings,
        answer,
        scan_id=resolved_scan_id,
        language=language,
        severity=severity,
        queried_category=queried,
    )
    answer = render_canonical_answer(canonical_answer, language)
    canonical_answer = canonical_answer_for_risk_type_breakdown(
        findings,
        answer,
        scan_id=resolved_scan_id,
        language=language,
        severity=severity,
        queried_category=queried,
    )
    answer = clean_answer_text(mask_sensitive_text(answer))

    payload = {"scan_id": resolved_scan_id, "result_type": "risk_type_breakdown"}
    sources = _contract_sources(payload)
    used = ["structured_count_findings"]

    next_session_state = _with_selected_language_metadata(session_state, principal, conv_id, language, selected_language, language_source)
    next_session_state = _with_language_preference(next_session_state, principal, conv_id, language, message)
    next_session_state = _with_canonical_answer_payload(next_session_state, canonical_answer)
    await save_session_context(principal, conv_id, next_session_state)
    await memory.save_turn(principal.tenant_id, conv_id, message, answer, used, [s.model_dump() for s in sources])
    total_ms = _elapsed_ms(start)
    await audit.log_interaction(
        principal, conv_id, len(message), "risk_type_breakdown", used, {}, len(answer),
        total_ms, len(sources), None, language,
        task_type="risk_type_breakdown",
        provider_planning_called=False,
        provider_final_called=False,
        final_answer_mode="deterministic_contract",
        provider_call_count=0,
        translator_called=False,
        language_understanding=language_understanding_audit or {},
        elapsed_ms_total=total_ms,
        selected_language=next_session_state.get("selected_language") if isinstance(next_session_state, dict) else selected_language,
        response_language=language,
        language_source=language_source,
        **_canonical_audit_fields(canonical_answer),
        **_route_dispatch_audit_fields(dispatch_decision),
    )
    return ChatResponse(
        answer=answer,
        intent="risk_type_breakdown",
        task_type="risk_type_breakdown",
        language=language,
        sources=sources,
        tools_used=used,
        conversation_id=conv_id,
        message_id=message_id,
        session_context_summary=_session_summary(next_session_state),
        metadata=_response_metadata({"total_ms": total_ms, "route": "risk_type_breakdown"}, _route_dispatch_audit_fields(dispatch_decision)),
    )


# --- Conversation-repair active-context keys ------------------------------
_ACTIVE_CONTEXT_KEYS = (
    "latest_artifact", "last_artifact_id", "last_artifact_name", "last_artifact_url",
    "last_artifact_type", "last_artifact_scan_id", "last_artifact_filter",
    "current_item", "last_item", "last_shown_items", "last_result_type",
    "last_count_scope_severities", "last_count_scope_scan_id", "last_count_scope_metric", "last_answer_type",
    "avoided_item_ids", "last_unshown_pool_ids", "last_answer_structured_payload",
    "last_requested_severity", "last_selection_mode", "current_topic", "topic_switch_detected",
)


def _clear_active_context(session_state: dict | None) -> dict:
    cleared = dict(session_state or {})
    for key in _ACTIVE_CONTEXT_KEYS:
        cleared.pop(key, None)
    return ConversationState.from_legacy_context(cleared).clear_active_focus(clear_artifact=True).to_legacy_context(cleared)


def _clear_selected_focus_context(session_state: dict | None) -> dict:
    cleared = dict(session_state or {})
    for key in (
        "current_item", "last_item", "last_shown_items", "last_result_type",
        "avoided_item_ids", "last_unshown_pool_ids", "last_requested_severity",
        "last_selection_mode",
    ):
        cleared.pop(key, None)
    return ConversationState.from_legacy_context(cleared).clear_active_focus(clear_artifact=False).to_legacy_context(cleared)


def _render_general_scope_advice(language: str) -> str:
    if language == "en":
        return (
            "General DSPM advice: prioritize CRITICAL and HIGH items first, group work by risk type, "
            "review access for exposed personal or credential data, mask or remove unnecessary data, "
            "then re-scan to confirm the change."
        )
    if language == "ru":
        return (
            "Общий совет по DSPM: сначала приоритизируйте CRITICAL и HIGH, сгруппируйте работу по типам риска, "
            "проверьте доступ к персональным данным и credential-данным, замаскируйте или удалите лишние данные, "
            "затем повторите scan."
        )
    return (
        "Ümumi DSPM məsləhəti: əvvəlcə CRITICAL və HIGH riskləri prioritetləşdirin, işi risk növünə görə qruplaşdırın, "
        "şəxsi və credential məlumatlarına access-i yoxlayın, lazımsız məlumatı maskalayın və ya silin, sonra yenidən scan edin."
    )


async def _repair_no_provider(
    *,
    principal: Principal,
    conv_id: str,
    message: str,
    answer: str,
    intent: str,
    task_type: str,
    language: str,
    session_state: dict | None,
    selected_language: str | None,
    language_source: str,
    message_id: str,
    start: float,
    language_understanding_audit: dict | None,
    extra_state: dict | None = None,
    artifact: dict | None = None,
    tools_used: list[str] | None = None,
    canonical_answer: CanonicalAnswer | None = None,
    audit_extra: dict | None = None,
) -> ChatResponse:
    answer = clean_answer_text(mask_sensitive_text(answer))
    base_state = dict(session_state or {})
    if extra_state is not None:
        base_state = dict(extra_state)
    next_session_state = _with_selected_language_metadata(base_state, principal, conv_id, language, selected_language, language_source)
    next_session_state = _with_language_preference(next_session_state, principal, conv_id, language, message)
    next_session_state = _with_canonical_answer_payload(next_session_state, canonical_answer)
    if extra_state is not None:
        # Preserve repair-specific keys that the language helpers do not know about.
        for key, value in extra_state.items():
            next_session_state.setdefault(key, value)
    next_session_state["last_answer_summary"] = answer[:500]
    next_session_state["last_answer_text"] = answer[:1200]
    next_session_state["last_answer_language"] = language
    next_session_state["last_task_type"] = task_type
    next_session_state["last_answer_type"] = next_session_state.get("last_answer_type") or task_type
    next_session_state = _normalize_conversation_state(next_session_state)
    await save_session_context(principal, conv_id, next_session_state)
    used = tools_used or []
    await memory.save_turn(principal.tenant_id, conv_id, message, answer, used, [])
    total_ms = _elapsed_ms(start)
    audit_extra = audit_extra or {}
    await audit.log_interaction(
        principal, conv_id, len(message), intent, used, {}, len(answer),
        total_ms, 0, None, language,
        task_type=task_type,
        provider_planning_called=False,
        provider_final_called=False,
        final_answer_mode=task_type,
        provider_call_count=0,
        translator_called=False,
        language_understanding=language_understanding_audit or {},
        elapsed_ms_total=total_ms,
        selected_language=next_session_state.get("selected_language") if isinstance(next_session_state, dict) else selected_language,
        response_language=language,
        language_source=language_source,
        **_canonical_audit_fields(canonical_answer),
        **_conversation_state_audit_fields(next_session_state, **audit_extra),
    )
    return ChatResponse(
        answer=answer,
        intent=intent,
        task_type=task_type,
        language=language,
        sources=[],
        tools_used=used,
        conversation_id=conv_id,
        message_id=message_id,
        artifact=artifact,
        session_context_summary=_session_summary(next_session_state),
        metadata=_response_metadata({"total_ms": total_ms, "route": task_type}, audit_extra),
    )


async def _handle_conversation_repair(
    *,
    message: str,
    principal: Principal,
    conv_id: str,
    scan_id: str | None,
    session_state: dict | None,
    target_language: str,
    selected_language: str | None,
    language_source: str,
    message_id: str,
    start: float,
    language_understanding_audit: dict | None,
    dispatch_decision: route_dispatcher.RouteDecision | None = None,
) -> ChatResponse | None:
    """Deterministic zero-provider repairs for real broken-conversation patterns."""
    lang = target_language if target_language in SUPPORTED_RESPONSE_LANGUAGES else "en"
    dispatch_fields = _route_dispatch_audit_fields(dispatch_decision)

    def allowed(*route_ids: str, repair_intent: str | None = None) -> bool:
        if dispatch_decision is None:
            return True
        return dispatch_decision.route_id in route_ids or (
            repair_intent is not None and dispatch_decision.metadata.get("repair_intent") == repair_intent
        )

    def merged(extra: dict | None = None) -> dict:
        fields = dict(dispatch_fields)
        fields.update(extra or {})
        return fields

    # 1. Cancel / reset the active topic.
    if allowed("cancel_or_reset_topic") and repair.detect_cancel_topic(message):
        return await _repair_no_provider(
            principal=principal, conv_id=conv_id, message=message,
            answer=repair.render_cancel(lang), intent="cancel_current_topic",
            task_type="cancel_current_topic", language=lang, session_state=session_state,
            selected_language=selected_language, language_source=language_source,
            message_id=message_id, start=start, language_understanding_audit=language_understanding_audit,
            extra_state=_clear_active_context(session_state),
            audit_extra=merged({"topic_switch_detected": True, "selected_finding_used": False, "artifact_scope_used": False}),
        )

    # 2. Malformed-output / fabricated-word complaint ("önçük nədir").
    if allowed("malformed_output_complaint") and repair.detect_malformed_output_complaint(message):
        return await _repair_no_provider(
            principal=principal, conv_id=conv_id, message=message,
            answer=repair.render_malformed_output(message, lang), intent="malformed_output_complaint",
            task_type="malformed_output_complaint", language=lang, session_state=session_state,
            selected_language=selected_language, language_source=language_source,
            message_id=message_id, start=start, language_understanding_audit=language_understanding_audit,
            audit_extra=merged({"selected_finding_used": False}),
        )

    # 3. Aggregate-remediation complaint ("I did not ask for a finding") — acknowledge + re-answer.
    complaint_scope = None if _explicit_single_finding_request(message) else repair.detect_aggregate_remediation_complaint(message, session_state)
    if allowed("aggregate_scope_remediation") and complaint_scope:
        findings, _sid = _report_findings_with_id(principal, scan_id)
        cats = repair.scope_risk_categories(findings, complaint_scope)
        answer = repair.render_aggregate_remediation(complaint_scope, lang, cats, acknowledge_mistake=True)
        extra = dict(session_state or {})
        extra["last_failed_route"] = "selected_finding_hijack"
        extra["last_user_correction"] = message
        return await _repair_no_provider(
            principal=principal, conv_id=conv_id, message=message, answer=answer,
            intent="aggregate_scope_remediation", task_type="aggregate_scope_remediation",
            language=lang, session_state=session_state, selected_language=selected_language,
            language_source=language_source, message_id=message_id, start=start,
            language_understanding_audit=language_understanding_audit,
            extra_state=extra,
            audit_extra=merged({"count_scope_used": True, "selected_finding_used": False}),
        )

    # 4. Aggregate remediation for the stored severity scope ("bunlar haqqında step by step").
    agg_scope = None if _explicit_single_finding_request(message) else repair.detect_aggregate_remediation(message, session_state)
    if allowed("aggregate_scope_remediation") and agg_scope:
        findings, _sid = _report_findings_with_id(principal, scan_id)
        cats = repair.scope_risk_categories(findings, agg_scope)
        answer = repair.render_aggregate_remediation(agg_scope, lang, cats)
        return await _repair_no_provider(
            principal=principal, conv_id=conv_id, message=message, answer=answer,
            intent="aggregate_scope_remediation", task_type="aggregate_scope_remediation",
            language=lang, session_state=session_state, selected_language=selected_language,
            language_source=language_source, message_id=message_id, start=start,
            language_understanding_audit=language_understanding_audit,
            audit_extra=merged({"count_scope_used": True, "selected_finding_used": False}),
        )

    # 5. "Why didn't you understand me the first time?" — explain the route mistake.
    if allowed("wrong_route_complaint") and repair.detect_why_misunderstood(message, session_state):
        return await _repair_no_provider(
            principal=principal, conv_id=conv_id, message=message,
            answer=repair.render_why_misunderstood(session_state, lang),
            intent="why_misunderstood_previous_request", task_type="why_misunderstood_previous_request",
            language=lang, session_state=session_state, selected_language=selected_language,
            language_source=language_source, message_id=message_id, start=start,
            language_understanding_audit=language_understanding_audit,
            audit_extra=merged({"selected_finding_used": False}),
        )

    if allowed("deterministic_contract_route") and repair.detect_general_topic_switch(message):
        return await _repair_no_provider(
            principal=principal, conv_id=conv_id, message=message,
            answer=_render_general_scope_advice(lang), intent="general_scope_advice",
            task_type="general_scope_advice", language=lang, session_state=session_state,
            selected_language=selected_language, language_source=language_source,
            message_id=message_id, start=start, language_understanding_audit=language_understanding_audit,
            extra_state=_clear_selected_focus_context(session_state),
            audit_extra=merged({"topic_switch_detected": True, "selected_finding_used": False}),
        )

    # 6. Artifact / PDF download UX.
    artifact_intent = repair.detect_artifact_intent(message, session_state)
    if allowed("artifact_link_or_download_help", repair_intent=repair.ARTIFACT_LINK) and artifact_intent == repair.ARTIFACT_LINK:
        artifact = (session_state or {}).get("latest_artifact") if isinstance(session_state, dict) else None
        if isinstance(artifact, dict):
            answer = repair.render_artifact_answer(artifact, lang)
            extra = dict(session_state or {})
            extra.update(repair.artifact_session_fields(artifact))
            return await _repair_no_provider(
                principal=principal, conv_id=conv_id, message=message, answer=answer,
                intent="artifact_link", task_type="artifact_link", language=lang,
                session_state=session_state, selected_language=selected_language,
                language_source=language_source, message_id=message_id, start=start,
                language_understanding_audit=language_understanding_audit,
                extra_state=extra, artifact=artifact,
                audit_extra=merged({"artifact_scope_used": True, "selected_finding_used": False}),
            )
        return await _repair_no_provider(
            principal=principal, conv_id=conv_id, message=message,
            answer=repair.render_missing_artifact_link(lang), intent="artifact_link",
            task_type="artifact_link_missing", language=lang, session_state=session_state,
            selected_language=selected_language, language_source=language_source,
            message_id=message_id, start=start, language_understanding_audit=language_understanding_audit,
            audit_extra=merged({"artifact_scope_used": False, "selected_finding_used": False}),
        )
    if allowed("artifact_link_or_download_help", repair_intent=repair.ARTIFACT_CREATE) and artifact_intent == repair.ARTIFACT_CREATE:
        reports_feature = repair.detect_reports_feature_request(message)
        if reports_feature:
            return await _repair_no_provider(
                principal=principal, conv_id=conv_id, message=message,
                answer=repair.render_reports_feature_answer(reports_feature, lang),
                intent="reports_feature_help", task_type="reports_feature_help", language=lang,
                session_state=session_state, selected_language=selected_language,
                language_source=language_source, message_id=message_id, start=start,
                language_understanding_audit=language_understanding_audit,
                audit_extra=merged({
                    "artifact_scope_used": False,
                    "selected_finding_used": False,
                    "reports_feature": reports_feature,
                }),
            )
        report_scope = repair.resolve_report_scope(message, session_state)
        try:
            artifact = await asyncio.to_thread(
                create_report_artifact, principal, session_state, scan_id, None, scope=report_scope
            )
        except ArtifactError:
            answer = repair.render_artifact_error(lang)
            return await _repair_no_provider(
                principal=principal, conv_id=conv_id, message=message, answer=answer,
                intent="artifact_create", task_type="artifact_create", language=lang,
                session_state=session_state, selected_language=selected_language,
                language_source=language_source, message_id=message_id, start=start,
                language_understanding_audit=language_understanding_audit,
                audit_extra=merged({"artifact_scope_used": False, "selected_finding_used": False}),
            )
        answer = repair.render_artifact_answer(artifact, lang, report_scope)
        extra = dict(session_state or {})
        extra["latest_artifact"] = artifact
        extra.update(repair.artifact_session_fields(artifact, report_scope))
        # Remember the scope just reported so a following bare "pdf" / "give as a
        # pdf" regenerates the same scope instead of a stale earlier one.
        if isinstance(report_scope, dict) and report_scope.get("kind"):
            extra["last_reportable_scope"] = dict(report_scope)
        return await _repair_no_provider(
            principal=principal, conv_id=conv_id, message=message, answer=answer,
            intent="artifact_create", task_type="artifact_create", language=lang,
            session_state=session_state, selected_language=selected_language,
            language_source=language_source, message_id=message_id, start=start,
            language_understanding_audit=language_understanding_audit,
            extra_state=extra, artifact=artifact,
            audit_extra=merged({"artifact_scope_used": True, "selected_finding_used": False}),
        )

    # 7. Partial / subset severity count (and its correction).
    subset = repair.detect_severity_subset_correction(message, session_state) or repair.detect_severity_subset_count(message)
    if allowed("deterministic_contract_route", repair_intent=repair.SEVERITY_SUBSET_COUNT) and subset:
        report = read_scan_report(principal.tenant_id, scan_id)
        resolved_scan_id = report.get("scan_id") if isinstance(report, dict) else scan_id
        counts = {sev: int(count_findings(report, severity=sev).get("count") or 0) if isinstance(report, dict) else 0 for sev in subset}
        answer = repair.render_severity_subset_count(counts, subset, resolved_scan_id, lang)
        subset_payload = {"scan_id": resolved_scan_id, "result_type": "severity_distribution", "severity_counts": counts}
        canonical_answer = canonical_answer_for_severity_distribution(
            subset_payload, answer, lang, requested_severities=subset
        )
        answer = render_canonical_answer(canonical_answer, lang)
        canonical_answer = canonical_answer_for_severity_distribution(
            subset_payload, answer, lang, requested_severities=subset
        )
        extra = dict(session_state or {})
        extra["last_count_scope_severities"] = subset
        extra["last_count_scope_scan_id"] = resolved_scan_id
        extra["last_count_scope_metric"] = "severity_distribution_file_level"
        extra["last_answer_type"] = "severity_count_subset"
        return await _repair_no_provider(
            principal=principal, conv_id=conv_id, message=message, answer=answer,
            intent="severity_subset_count", task_type="severity_subset_count", language=lang,
            session_state=session_state, selected_language=selected_language,
            language_source=language_source, message_id=message_id, start=start,
            language_understanding_audit=language_understanding_audit,
            extra_state=extra, tools_used=["structured_count_findings"],
            canonical_answer=canonical_answer,
            audit_extra=merged({"count_scope_used": True, "selected_finding_used": False}),
        )

    return None


def _p0_scan_boundary_answer(situation_id: str, language: str = "az") -> str:
    if situation_id == "incomplete_scan_action_request":
        if language == "en":
            return "Do you want to start a new scan, or should I show the latest scan result?"
        return "Yeni scan başlatmaq istəyirsiniz, yoxsa son scan nəticəsini göstərim?"
    if language == "en":
        return (
            "Starting a new scan from inside chat is not currently supported. You can start it from the File Server Scan page; "
            "after it finishes, I can analyze the results, prioritize risks, and provide a remediation plan."
        )
    return (
        "Hazırda chat içindən yeni scan başlatmaq dəstəklənmir. File Server Scan səhifəsindən yeni scan-i başlada bilərsiniz; "
        "scan bitəndən sonra mən nəticələri analiz edə, riskləri prioritetləşdirə və remediation planı verə bilərəm."
    )


def _explicit_single_finding_request(message: str) -> bool:
    folded = language_service.normalize_for_intent(message)
    return (
        any(term in folded for term in ("random", "bir ", "one ", "single "))
        and any(term in folded for term in ("tapinti", "finding"))
    )


def _p0_count_scope_detail_answer(
    *,
    message: str,
    session_state: dict | None,
    findings: list[dict],
    scan_id: str | None,
    language: str,
    acknowledge: bool = False,
    tracking_explanation: bool = False,
) -> tuple[str, dict]:
    scope = situation_guardrails.resolve_context_scope(message, None, session_state)
    severities = scope.severities
    scoped = [
        item for item in findings
        if str(item.get("severity") or "").upper() in set(severities)
    ] if severities else []
    audit_meta = scope.to_metadata()
    audit_meta.update({
        "count_scope_used": bool(severities),
        "selected_finding_used": False,
    })
    if tracking_explanation:
        prefix = (
            "Haqlısınız. Burada söhbət kontekstini düzgün izləməli idim: əvvəl LOW sayını soruşduğunuz üçün "
            "\"haqqında məlumat ver\" sualını LOW tapıntıya bağlamalı idim. Səhvən köhnə seçilmiş tapıntı kontekstini istifadə etməməliyəm."
        )
        if not scoped:
            return prefix, audit_meta
        answer, _ = _p0_scoped_findings_text(scoped, severities, scan_id, language)
        return f"{prefix}\n\nİndi düzgün scope üzrə cavab:\n{answer}", audit_meta
    if acknowledge:
        prefix = (
            "Haqlısınız. Siz LOW tapıntı haqqında soruşurdunuz, mən isə səhvən əvvəlki konteksti istifadə etmiş ola bilərdim. "
            "İndi LOW scope üzrə cavab verirəm:"
        )
    else:
        prefix = ""
    answer, answer_meta = _p0_scoped_findings_text(scoped, severities, scan_id, language)
    audit_meta.update(answer_meta)
    return f"{prefix}\n{answer}".strip(), audit_meta


def _finding_scope_footer(scan_id: str | None, language: str) -> str:
    sid = scan_id or "latest"
    if language == "az":
        return f"Skan: {sid}  Metrik: file_level_finding_count"
    return f"Scan: {sid}  Metric: file_level_finding_count"


def _p0_scoped_findings_text(scoped: list[dict], severities: list[str], scan_id: str | None, language: str) -> tuple[str, dict]:
    az = language == "az"
    scope_label = ", ".join(severities) if severities else ("seçilmiş" if az else "selected")
    footer = _finding_scope_footer(scan_id, language)
    score_word = "risk balı" if az else "risk score"
    if not scoped:
        if az:
            text = f"{scope_label} scope üzrə təhlükəsiz detal yüklənmədi. Zəhmət olmasa konkret severity və ya tapıntı adını yazın."
        else:
            text = f"No safe detail is loaded for the {scope_label} scope. Please name a specific severity or finding."
        return text, {"corrected_answer_returned": False}
    if len(scoped) == 1:
        item = scoped[0]
        name = mask_sensitive_text(str(item.get("name") or item.get("path") or "unknown"))
        no_types = "risk tipi yoxdur" if az else "no risk type"
        risk_types = ", ".join(str(rt) for rt in (item.get("risk_types") or [])[:4]) or no_types
        score = item.get("risk_score")
        head = f"{scope_label} scope üzrə 1 tapıntı var:" if az else f"The {scope_label} scope has 1 finding:"
        text = (
            f"{head}\n"
            f"- {name} - {item.get('severity') or scope_label} - {score_word} {score} | {risk_types}\n"
            f"{footer}"
        )
        return text, {"corrected_answer_returned": True}
    if az:
        header = f"{scope_label} scope üzrə {len(scoped)} tapıntı var. Hansını açmağımı istədiyinizi seçin:"
    else:
        header = f"The {scope_label} scope has {len(scoped)} findings. Tell me which one to open:"
    lines = [header]
    for index, item in enumerate(scoped[:10], 1):
        name = mask_sensitive_text(str(item.get("name") or item.get("path") or "unknown"))
        risk_types = ", ".join(str(rt) for rt in (item.get("risk_types") or [])[:3])
        suffix = f" | {risk_types}" if risk_types else ""
        lines.append(f"{index}. {name} - {item.get('severity') or scope_label} - {score_word} {item.get('risk_score')}{suffix}")
    lines.append(footer)
    return "\n".join(lines), {"corrected_answer_returned": True}


def _p1_scoped_detail_text(
    *,
    frame: task_frame_controller.TaskFrame,
    item: dict | None,
    scoped_count: int,
    scan_id: str | None,
    language: str,
    selection_reason: str,
    no_other: bool = False,
    correction: bool = False,
) -> str:
    az = language == "az"
    scope_label = ", ".join(frame.scope_values) if frame.scope_values else ("seçilmiş" if az else "selected")
    score_word = "risk balı" if az else "risk score"
    alias_note = ""
    if frame.object_alias == "alert_as_finding":
        if az:
            alias_note = "Bu sistemdə ayrıca alert obyekti yoxdursa, alert sorğusunu file-level tapıntı kimi hesablayıram.\n"
        else:
            alias_note = "This system has no separate alert object, so I count an alert request as a file-level finding.\n"
    if item is None:
        footer = _finding_scope_footer(scan_id or frame.scan_id, language)
        if az:
            body = f"{scope_label} scope üzrə başqa tapıntı yoxdur." if no_other else f"{scope_label} scope üzrə tapıntı yoxdur."
        else:
            body = f"There are no other findings in the {scope_label} scope." if no_other else f"There are no findings in the {scope_label} scope."
        return f"{alias_note}{body}\n{footer}".strip()
    footer = _finding_scope_footer(scan_id or item.get("scan_id") or frame.scan_id, language)
    name = mask_sensitive_text(str(item.get("name") or item.get("path") or "unknown"))
    no_types = "risk tipi yoxdur" if az else "no risk type"
    risk_types = ", ".join(str(rt) for rt in (item.get("risk_types") or [])[:4]) or no_types
    score = item.get("risk_score")
    if az:
        policy_text = "stabil random seçimlə" if selection_reason == "random_stable" else "ən yüksək risk balına görə"
    else:
        policy_text = "by a stable random pick" if selection_reason == "random_stable" else "by highest risk score"
    prefix = ""
    if correction:
        if az:
            prefix = (
                f"Haqlısınız. Siz {scope_label} alert/tapıntı haqqında soruşurdunuz, "
                "mən isə köhnə seçilmiş tapıntı kontekstini istifadə etməməli idim. "
                f"İndi {scope_label} scope üzrə bir tapıntını açıram:\n"
            )
        else:
            prefix = (
                f"You're right. You asked about a {scope_label} alert/finding, and I should not have used the "
                f"old selected-finding context. Here is one finding from the {scope_label} scope:\n"
            )
    elif scoped_count > 1:
        if az:
            prefix = f"{scope_label} scope üzrə {scoped_count} tapıntı var; birini {policy_text} açıram:\n"
        else:
            prefix = f"The {scope_label} scope has {scoped_count} findings; I'm opening one {policy_text}:\n"
    else:
        prefix = f"{scope_label} scope üzrə 1 tapıntını açıram:\n" if az else f"Opening the 1 finding in the {scope_label} scope:\n"
    return (
        f"{alias_note}{prefix}"
        f"- {name} - {item.get('severity') or scope_label} - {score_word} {score} | {risk_types}\n"
        f"{footer}"
    ).strip()


async def _handle_task_frame_resolution(
    *,
    message: str,
    principal: Principal,
    conv_id: str,
    scan_id: str | None,
    session_state: dict | None,
    target_language: str,
    selected_language: str | None,
    language_source: str,
    message_id: str,
    start: float,
    language_understanding_audit: dict | None,
) -> ChatResponse | None:
    resolution = task_frame_controller.resolve_task_frame(message, session_state)
    if not resolution.should_answer or resolution.frame is None:
        return None
    findings, resolved_scan_id = _report_findings_with_id(principal, scan_id or resolution.frame.scan_id)
    item, scoped, selection_reason = task_frame_controller.select_item(
        frame=resolution.frame,
        findings=findings,
        conversation_id=conv_id,
        another_one=resolution.another_one,
    )
    no_other = selection_reason == "no_other_available"
    frame = task_frame_controller.mark_selected(resolution.frame, item, pending=False)
    response_state = task_frame_controller.attach_frame(session_state, frame)
    response_state["task_frame_turn"] = frame.updated_turn
    if frame.scope_values:
        response_state["last_count_scope_severities"] = list(frame.scope_values)
        response_state["last_count_scope_scan_id"] = resolved_scan_id or frame.scan_id
        response_state["last_count_scope_metric"] = frame.metric_name or "file_level_finding_count"
    if item:
        response_state["current_item"] = {
            "name": item.get("name"),
            "id": item.get("id") or item.get("name"),
            "severity": item.get("severity"),
            "risk_score": item.get("risk_score"),
            "risk_types": item.get("risk_types") or [],
            "scan_id": item.get("scan_id") or resolved_scan_id,
            "safe_identifier": item.get("name"),
            "detail_ref": item.get("name"),
            "full_detail_ref": item.get("name"),
        }
        response_state["last_item"] = response_state["current_item"]
    answer = _p1_scoped_detail_text(
        frame=frame,
        item=item,
        scoped_count=len(scoped),
        scan_id=resolved_scan_id,
        language=target_language,
        selection_reason=selection_reason,
        no_other=no_other,
        correction=resolution.correction_recovery,
    )
    audit_extra = resolution.audit_metadata()
    scope_source = "last_count_scope" if (session_state or {}).get("last_count_scope_severities") else resolution.source
    audit_extra.update({
        "scope_resolution_used": True,
        "scope_source": scope_source,
        "scope_reason": resolution.reason,
        "last_count_scope_used": ",".join((session_state or {}).get("last_count_scope_severities") or []) or None,
        "pending_frame_fulfilled": bool(item) or no_other or not scoped,
        "pending_frame_clarification": False,
        "recovery_controller_used": resolution.correction_recovery or None,
        "recovery_type": "wrong_scope" if resolution.correction_recovery else None,
        "corrected_scope_used": bool(resolution.correction_recovery and frame.scope_values),
        "corrected_answer_returned": bool(item),
        "count_scope_used": bool(frame.scope_values),
        "selected_finding_used": False,
    })
    return await _meta_no_provider_response(
        principal=principal,
        conv_id=conv_id,
        message=message,
        answer=answer,
        intent="scoped_task_frame_detail",
        task_type="scoped_task_frame_detail",
        language=target_language,
        session_state=response_state,
        selected_language=selected_language,
        language_source=language_source,
        message_id=message_id,
        start=start,
        language_understanding_audit=language_understanding_audit,
        audit_extra=audit_extra,
    )


async def _handle_product_help(
    *,
    message: str,
    principal: Principal,
    conv_id: str,
    scan_id: str | None,
    session_state: dict | None,
    target_language: str,
    selected_language: str | None,
    language_source: str,
    message_id: str,
    start: float,
    language_understanding_audit: dict | None,
    dispatch_decision: route_dispatcher.RouteDecision,
) -> ChatResponse | None:
    """Deterministic product/help/navigation/taxonomy answers.

    Zero provider calls. Only the alert-type breakdown touches DSPM data, and
    it computes the distinct detected types from the real scan report.
    """
    kind = str(dispatch_decision.metadata.get("product_help_kind") or "")
    lang = target_language if target_language in SUPPORTED_RESPONSE_LANGUAGES else "en"
    audit_extra = _route_dispatch_audit_fields(dispatch_decision)
    tools_used: list[str] = []
    if kind == product_help.NAVIGATION:
        label = str(dispatch_decision.metadata.get("nav_target_label") or "Findings")
        answer = product_help.render_navigation_help(lang, label)
        audit_extra["nav_target"] = dispatch_decision.metadata.get("nav_target_key")
    elif kind == product_help.FILTER_HOWTO:
        answer = product_help.render_filter_howto(lang)
    elif kind == product_help.PRODUCT_FEATURES:
        answer = product_help.render_product_features(lang)
    elif kind == product_help.PRODUCT_OVERVIEW:
        answer = product_help.render_product_overview(lang)
    elif kind == product_help.RISK_SUMMARY_DELTA:
        answer = product_help.render_risk_summary_delta(lang)
    elif kind == product_help.ALERT_TYPES:
        findings, resolved_scan_id = _report_findings_with_id(principal, scan_id)
        type_counts = product_help.distinct_finding_types(findings)
        answer = product_help.render_alert_types(lang, type_counts, resolved_scan_id)
        if type_counts:
            tools_used = ["structured_finding_type_breakdown"]
            audit_extra.update({
                "retrieval_used": True,
                "evidence_count": len(type_counts),
                "alert_type_count": len(type_counts),
            })
    else:
        return None
    return await _meta_no_provider_response(
        principal=principal, conv_id=conv_id, message=message, answer=answer,
        intent=kind, task_type=kind, language=lang, session_state=session_state,
        selected_language=selected_language, language_source=language_source,
        message_id=message_id, start=start,
        language_understanding_audit=language_understanding_audit,
        tools_used=tools_used,
        audit_extra=audit_extra,
    )


async def _handle_p0_situation_guardrail(
    *,
    message: str,
    principal: Principal,
    conv_id: str,
    scan_id: str | None,
    session_state: dict | None,
    target_language: str,
    selected_language: str | None,
    language_source: str,
    message_id: str,
    start: float,
    language_understanding_audit: dict | None,
    dispatch_decision: route_dispatcher.RouteDecision,
) -> ChatResponse | None:
    p0_decision = dispatch_decision.metadata.get("p0_decision")
    situation_id = str(getattr(p0_decision, "situation_id", dispatch_decision.answer_type) or "")
    lang = target_language if target_language in SUPPORTED_RESPONSE_LANGUAGES else "en"
    audit_extra = _route_dispatch_audit_fields(dispatch_decision)
    audit_extra.update({key: value for key, value in dispatch_decision.metadata.items() if key != "p0_decision"})

    if situation_id == "capability_question_typo":
        answer = render_capabilities(lang, include_limitations=capability_registry.asks_about_limitations(message))
        capability_intent = "capability_help" if not re.search(r"\s", message or "") else "capability"
        return await _meta_no_provider_response(
            principal=principal, conv_id=conv_id, message=message, answer=answer,
            intent=capability_intent, task_type=capability_intent, language=lang, session_state=session_state,
            selected_language=selected_language, language_source=language_source, message_id=message_id,
            start=start, language_understanding_audit=language_understanding_audit,
            audit_extra=audit_extra,
        )

    if situation_id in {"scan_start_request", "scan_action_capability_question", "incomplete_scan_action_request"}:
        answer = _p0_scan_boundary_answer(situation_id, lang)
        return await _meta_no_provider_response(
            principal=principal, conv_id=conv_id, message=message, answer=answer,
            intent=situation_id, task_type=situation_id, language=lang, session_state=session_state,
            selected_language=selected_language, language_source=language_source, message_id=message_id,
            start=start, language_understanding_audit=language_understanding_audit,
            audit_extra=audit_extra,
        )

    if situation_id in {"count_scope_detail_followup", "scope_correction", "wrong_route_recovery", "conversation_tracking_complaint"}:
        findings, resolved_scan_id = _report_findings_with_id(principal, scan_id)
        answer, scope_meta = _p0_count_scope_detail_answer(
            message=message,
            session_state=session_state,
            findings=findings,
            scan_id=resolved_scan_id,
            language=lang,
            acknowledge=situation_id in {"scope_correction", "wrong_route_recovery"},
            tracking_explanation=situation_id == "conversation_tracking_complaint",
        )
        audit_extra.update(scope_meta)
        if situation_id == "wrong_route_recovery" and not scope_meta.get("count_scope_used"):
            answer = _render_wrong_route_complaint(lang)
            audit_extra["corrected_scope_used"] = False
            audit_extra["corrected_answer_returned"] = False
        if situation_id in {"scope_correction", "wrong_route_recovery"}:
            audit_extra.update({
                "recovery_controller_used": True,
                "recovery_type": "wrong_scope" if situation_id == "scope_correction" else "selected_hijack",
                "corrected_scope_used": bool(scope_meta.get("count_scope_used")),
                "fallback_family": "wrong_scope_recovery",
            })
        if situation_id == "conversation_tracking_complaint":
            audit_extra.update({
                "recovery_controller_used": True,
                "recovery_type": "conversation_tracking",
                "corrected_scope_used": bool(scope_meta.get("count_scope_used")),
                "fallback_family": "meta_tracking_explanation",
            })
        return await _meta_no_provider_response(
            principal=principal, conv_id=conv_id, message=message, answer=answer,
            intent="complaint_about_wrong_route" if situation_id == "wrong_route_recovery" else situation_id,
            task_type="complaint_about_wrong_route" if situation_id == "wrong_route_recovery" else situation_id,
            language=lang, session_state=session_state,
            selected_language=selected_language, language_source=language_source, message_id=message_id,
            start=start, language_understanding_audit=language_understanding_audit,
            audit_extra=audit_extra,
        )

    return None


def _resolve_selected_language(selected_language: str | None, context: dict | None) -> tuple[str | None, str]:
    if selected_language in SUPPORTED_RESPONSE_LANGUAGES:
        return selected_language, "ui_selector"
    for key in ("selected_language",):
        value = (context or {}).get(key)
        if value in SUPPORTED_RESPONSE_LANGUAGES:
            return value, "session"
    return None, "fallback_default"


def _resolve_answer_language(message: str, detected_language: str, context: dict | None, selected_language: str | None = None) -> str:
    """Resolve the response language.

    Use the dynamic language runtime. Legacy selected-language values are not
    authoritative unless the request separately marks them as explicit.
    """
    return decide_language(message, selected_language=selected_language, session_state=context).response_language


def _language_lock_from_message(message: str) -> str | None:
    explicit = explicit_language_request(message) or _explicit_language_lock(message)
    if explicit:
        return explicit
    understanding = understand_message(message)
    if understanding.language_preference_update in {"az", "en"}:
        return understanding.language_preference_update
    return None


def _with_language_preference(context: dict | None, principal: Principal, conversation_id: str, language: str, message: str | None = None) -> dict:
    next_context = dict(context or {})
    answer_language = language if language in SUPPORTED_RESPONSE_LANGUAGES else "en"
    lock = _language_lock_from_message(message or "") if message is not None else None
    previous_lock = next_context.get("language_preference_locked")
    next_context.update(
        {
            "version": 1,
            "conversation_id": conversation_id,
            "tenant_id": principal.tenant_id,
            "user_id": principal.subject,
            "last_language": answer_language,
            "user_language": answer_language,
            "answer_language": answer_language,
            "response_language": answer_language,
            "language_locked": bool(lock or previous_lock in SUPPORTED_RESPONSE_LANGUAGES),
            "language_preference": answer_language,
        }
    )
    if lock in SUPPORTED_RESPONSE_LANGUAGES:
        next_context["language_preference_locked"] = lock
    elif previous_lock in SUPPORTED_RESPONSE_LANGUAGES:
        next_context["language_preference_locked"] = previous_lock
    else:
        next_context.pop("language_preference_locked", None)
    return next_context


def _with_selected_language_metadata(
    context: dict | None,
    principal: Principal,
    conversation_id: str,
    response_language: str,
    selected_language: str | None,
    language_source: str,
    *,
    selected_language_source: str | None = None,
) -> dict:
    next_context = _with_language_preference(context, principal, conversation_id, response_language, None)
    previous_selected = (context or {}).get("selected_language")
    previous_source = (context or {}).get("selected_language_source")
    if selected_language_source == "explicit_user_selection" and selected_language in SUPPORTED_RESPONSE_LANGUAGES:
        next_context["selected_language"] = selected_language
        next_context["selected_language_source"] = "explicit_user_selection"
    elif previous_source == "explicit_user_selection" and previous_selected in SUPPORTED_RESPONSE_LANGUAGES:
        next_context["selected_language"] = previous_selected
        next_context["selected_language_source"] = "explicit_user_selection"
    else:
        next_context.pop("selected_language", None)
        next_context.pop("selected_language_source", None)
    next_context["response_language"] = response_language if response_language in SUPPORTED_RESPONSE_LANGUAGES else "en"
    next_context["language_source"] = language_source
    if language_source == "ui_selector" or previous_selected != next_context.get("selected_language"):
        from datetime import datetime, timezone

        next_context["last_language_change_at"] = datetime.now(timezone.utc).isoformat()
    return next_context


def _artifact_lookup_requested(message: str) -> bool:
    text = normalize_message(message)
    return "pdf" in text and any(term in text for term in ("where", "link", "download", "hardadir", "haradadir"))


def _artifact_answer(artifact: dict) -> str:
    # Single-sourced through repair.absolute_artifact_url so every code path
    # emits the same "/api/v1/copilot/artifacts/{id}?dl_token=..." shape
    # instead of a raw absolute host link that 401s without auth headers.
    url = repair.absolute_artifact_url(artifact.get("download_url"))
    scope_label = artifact.get("scope_label")
    scope_line = f"\nScope: {scope_label}" if scope_label and scope_label != "Full scan" else ""
    return (
        f"Report artifact is ready: {artifact.get('filename')}.\n"
        f"Download: {url}\n"
        f"Source scan: {artifact.get('source_scan_id')}{scope_line}"
    )


def _no_artifact_answer() -> str:
    return "No Copilot PDF artifact has been generated in this conversation yet."


def _raw_evidence_fallback(tool_results: list[ToolResult], task_type: str | None = None) -> str:
    lines = ["Model temporarily unavailable. I can still show the available evidence:", ""]
    for result in tool_results[:3]:
        payload = _payload(result)
        item = payload.get("item") if isinstance(payload.get("item"), dict) else None
        if item:
            lines.append(f"File: {item.get('name') or item.get('path') or 'unknown item'}")
            lines.append(f"Severity: {(item.get('severity') or 'unknown')}")
            lines.append(f"Risk score: {item.get('risk_score') if item.get('risk_score') is not None else 'unknown'}")
            risk_types = [str(finding.get("type")) for finding in item.get("findings") or [] if isinstance(finding, dict) and finding.get("type")]
            if risk_types:
                lines.append(f"Detected types: {', '.join(risk_types[:12])}")
            break
        results = payload.get("results") if isinstance(payload.get("results"), list) else []
        if results:
            lines.append(f"Tool: {result.tool_name}")
            for index, entry in enumerate(results[:5], 1):
                if isinstance(entry, dict):
                    lines.append(
                        f"{index}. {entry.get('name') or entry.get('path') or 'unknown item'} - "
                        f"severity {entry.get('severity') or 'unknown'}, risk score {entry.get('risk_score', 'unknown')}"
                    )
            break
        if payload:
            lines.append(f"Tool: {result.tool_name}")
            lines.append(json.dumps(payload, ensure_ascii=False, default=str)[:900])
            break
    lines.extend(["", "I cannot generate a full explanation until the model is available."])
    return "\n".join(lines).strip()


async def execute_tools(
    intent: IntentResult,
    principal: Principal,
    message: str,
    scan_id: str | None,
    requested_limit: int | None = None,
    selection_mode: str | None = None,
    exclude_ids: list[str] | None = None,
) -> list[ToolResult]:
    results: list[ToolResult] = []
    no_evidence = 0
    requested_limit = requested_limit or planner_requested_limit(message) or 10
    for tool_name in INTENT_TOOL_MAP[intent.intent]:
        try:
            if tool_name == "get_scan_history":
                result = await tools.get_scan_history(principal)
            elif tool_name == "get_scan_report":
                result = await tools.get_scan_report(principal, scan_id)
            elif tool_name == "search_findings":
                severity = [_severity_from_message(message)] if _severity_from_message(message) else None
                result = await tools.search_findings(principal, message, severity=severity, scan_id=scan_id, limit=requested_limit)
            elif tool_name == "get_findings_by_severity":
                severity_value = _severity_from_message(message) or ("CRITICAL" if intent.intent == "alert_summary" else None)
                if not severity_value:
                    continue
                result = await _get_findings_by_severity_for_plan(
                    principal,
                    severity_value,
                    limit=requested_limit,
                    selection_mode=selection_mode or "top",
                    exclude_ids=exclude_ids,
                )
            elif tool_name == "explain_risk_for_asset":
                result = await tools.explain_risk_for_asset(principal, _asset_hint(message))
            elif tool_name == "generate_remediation_summary":
                result = await tools.generate_remediation_summary(principal, scan_id)
            elif tool_name == "search_audit_events":
                result = await tools.search_audit_events(principal, message)
            elif tool_name == "get_recent_alerts":
                try:
                    result = await tools.get_recent_alerts(principal, limit=requested_limit)
                except NoEvidenceError:
                    severity_value = _severity_from_message(message)
                    if not severity_value:
                        raise
                    if any(existing.tool_name == "get_findings_by_severity" for existing in results):
                        continue
                    fallback = await _get_findings_by_severity_for_plan(
                        principal,
                        severity_value,
                        limit=requested_limit,
                        selection_mode=selection_mode or "top",
                        exclude_ids=exclude_ids,
                    )
                    try:
                        fallback_payload = json.loads(fallback.content)
                    except json.JSONDecodeError:
                        fallback_payload = {"summary": fallback.content}
                    content = json.dumps(
                        {
                            "requested_alerts_but_using_findings": True,
                            "note_code": "findings_files_not_separate_alert_objects",
                            "severity": severity_value,
                            "findings_context": fallback_payload,
                        },
                        ensure_ascii=False,
                        default=str,
                    )
                    result = ToolResult(tool_name="get_findings_by_severity", content=content, sources=fallback.sources, token_count=len(content.split()))
            elif tool_name == "get_high_risk_assets":
                result = await tools.get_high_risk_assets(principal)
            elif tool_name == "get_executive_dashboard":
                result = await tools.get_executive_dashboard(principal)
            else:
                continue
            results.append(role_filter(result, principal.role))
        except NoEvidenceError:
            no_evidence += 1
            continue
        except ToolError as exc:
            raise CopilotError("A DSPM tool failed while building context.", "TOOL_FAILURE") from exc
    if not results and no_evidence:
        raise NoEvidenceError("No DSPM evidence is available for this question.")
    return results


def _sources(tool_results: list[ToolResult]) -> list[SourceRef]:
    seen: set[tuple] = set()
    merged: list[SourceRef] = []
    for result in tool_results:
        for source in result.sources:
            key = (source.type, source.scan_id, source.path, source.severity, source.risk_score)
            if key not in seen:
                seen.add(key)
                merged.append(source)
    return merged


def _tool_counts(tool_results: list[ToolResult]) -> dict[str, int]:
    return {result.tool_name: len(result.sources) for result in tool_results}


def _payload(result: ToolResult) -> dict:
    try:
        data = json.loads(result.content)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
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


def _critical_payload(tool_results: list[ToolResult]) -> dict | None:
    findings = None
    alerts = []
    for result in tool_results:
        payload = _payload(result)
        if result.tool_name == "get_findings_by_severity" and payload.get("results"):
            findings = payload
        if payload.get("alerts"):
            alerts.extend(payload.get("alerts") or [])
    if findings:
        findings["alert_summary_count"] = len(alerts)
        return findings
    if alerts:
        return {"result_type": "alerts", "count": len(alerts), "results": alerts, "alert_summary_count": len(alerts)}
    return None


def _render_critical_findings(tool_results: list[ToolResult], language: str, requested_limit: int, repair: bool = False) -> str | None:
    payload = _critical_payload(tool_results)
    if not payload:
        return None
    items = payload.get("results") or []
    if not items:
        return None
    total = int(payload.get("count") or len(items))
    shown = min(len(items), requested_limit)
    scan_id = payload.get("scan_id") or "latest scan"
    uses_findings = str(payload.get("result_type", "")).endswith("_findings") or "note_codes" in payload
    lines: list[str] = []
    if repair and language == "en":
        lines.append("You are right to be frustrated. I re-checked the latest scan and returned the requested critical findings below.")
    if uses_findings:
        if language == "az":
            lines.append("Mövcud datada bunlar ayrıca alert obyekti kimi yox, critical finding/fayl kimi saxlanılır.")
            if payload.get("alert_summary_count"):
                lines.append(f"{payload.get('alert_summary_count')} alert summary row var, amma son scan {total} critical finding/fayl saxlayır.")
            lines.append(f"Scan yoxlandı: {scan_id}. Ümumi critical findings/fayllar: {total}. Göstərilən {shown}.")
        else:
            lines.append("The current data stores these as critical findings/files, not separate alert objects.")
            if payload.get("alert_summary_count"):
                lines.append(f"There are {payload.get('alert_summary_count')} alert summary rows, but the latest scan contains {total} critical findings/files.")
            lines.append(f"Scan checked: {scan_id}. Total critical findings/files: {total}. Showing {shown}.")
    else:
        lines.append(f"Scan checked: {scan_id}. Total critical alerts: {total}. Showing {shown}.")
    lines.append("")
    for index, item in enumerate(items[:requested_limit], 1):
        name = item.get("name") or item.get("path") or item.get("title") or "unknown item"
        severity = item.get("severity") or item.get("risk") or "CRITICAL"
        risk_score = item.get("risk_score") or "n/a"
        findings = item.get("findings") if isinstance(item.get("findings"), list) else []
        risk_type = ""
        if findings:
            types = [str(finding.get("type")) for finding in findings[:2] if isinstance(finding, dict) and finding.get("type")]
            if types:
                risk_type = f", type {', '.join(types)}"
        lines.append(f"{index}. {name} - severity {severity}, risk score {risk_score}{risk_type}")
    return "\n".join(lines)


def _session_summary(context: dict | None) -> str | None:
    if not context:
        return None
    parts = []
    if context.get("last_intent"):
        parts.append(f"intent={context.get('last_intent')}")
    if context.get("last_scan_id"):
        parts.append(f"scan={context.get('last_scan_id')}")
    if context.get("last_tool_result_summary"):
        parts.append(str(context.get("last_tool_result_summary")))
    return "; ".join(parts)[:500] if parts else None


def _contract_route_metadata(route: IntentRoute, validation_errors: list[str] | None = None, timings: dict | None = None) -> dict:
    metadata = {
        "contract_route": {
            "intent": route.intent,
            "language": route.language,
            "entities": dict(route.entities),
            "needs_structured_query": route.needs_structured_query,
            "retrieval_allowed": route.retrieval_allowed,
            "provider_allowed": route.provider_allowed,
            "reason": route.reason,
            "validation_errors": validation_errors or [],
        }
    }
    if timings:
        metadata["timings"] = dict(timings)
    return metadata


def _canonical_payload(answer: CanonicalAnswer | None) -> dict | None:
    return answer.to_dict() if isinstance(answer, CanonicalAnswer) else None


def _canonical_audit_fields(answer: CanonicalAnswer | None) -> dict:
    if not isinstance(answer, CanonicalAnswer):
        return {}
    return {
        "canonical_answer_used": True,
        "answer_type": answer.answer_type,
        "metric_name": answer.metric.name if answer.metric else None,
        "evidence_count": len(answer.evidence),
    }


def _conversation_state_audit_fields(context: dict | None, **overrides) -> dict:
    fields = ConversationState.from_legacy_context(context).audit_metadata()
    fields.update({key: value for key, value in overrides.items() if value is not None})
    return fields


def _normalize_conversation_state(context: dict | None) -> dict:
    return state_writer.sync(context)


def _controlled_verbalizer_runtime_block_reason(response: ChatResponse, metadata: dict, brainmap: response_brainmap.ResponseBrainmap) -> str | None:
    family = brainmap.situation.family
    if family in {
        response_brainmap.BrainmapFamily.DSPM_FACTUAL,
        response_brainmap.BrainmapFamily.TASK_FRAME,
        response_brainmap.BrainmapFamily.PROFESSIONAL_WORKFLOW,
        response_brainmap.BrainmapFamily.SCAN_OPERATION,
        response_brainmap.BrainmapFamily.ARTIFACT,
        response_brainmap.BrainmapFamily.MODEL_PROVIDER_STATUS,
        response_brainmap.BrainmapFamily.UTILITY,
    }:
        return "structured_renderer_required"
    if response.sources or metadata.get("canonical_answer_used") or metadata.get("evidence_count"):
        return "evidence_required"
    if any(
        metadata.get(key)
        for key in (
            "fast_verbalizer_used",
            "verbalizer_used",
            "structured_renderer_used",
            "selected_finding_used",
            "count_scope_used",
            "artifact_scope_used",
            "canonical_answer_expected",
        )
    ):
        return "structured_renderer_required"
    if metadata.get("provider_final_called"):
        return "provider_final_required"
    task_block_reason = task_types.verbalizer_block_reason(response.task_type)
    if task_block_reason:
        return task_block_reason
    # Content guard for fact-free meta tasks: some correction flows attach
    # evidence-backed content (real counts / severity breakdowns) under a
    # meta task type. If the draft carries numbers or severity words, it is
    # fact-bearing — keep it deterministic regardless of the task-name policy.
    if str(response.task_type or "") in task_types.FACT_FREE_META_TASKS:
        draft = str(response.answer or "")
        if re.search(r"\d", draft) or re.search(r"\b(critical|high|medium|low|kritik|yuksek|yüksək|orta|asagi|aşağı)\b", draft, re.IGNORECASE):
            return "evidence_required"
    if family == response_brainmap.BrainmapFamily.AMBIGUOUS_OR_UNKNOWN:
        return "structured_renderer_required"
    return None


def _with_canonical_answer_payload(context: dict | None, answer: CanonicalAnswer | None) -> dict:
    next_context = dict(context or {})
    payload = _canonical_payload(answer)
    if payload:
        next_context["last_answer_structured_payload"] = payload
        if payload.get("scan_id"):
            next_context["last_scan_id"] = payload.get("scan_id")
    return next_context


def _canonical_answer_for_contract_route(route: IntentRoute, payload: dict | None, answer: str) -> CanonicalAnswer | None:
    if not isinstance(payload, dict):
        return None
    if route.intent in {"count_findings", "severity_distribution", "filter_findings"} and not payload.get("scan_id"):
        return None
    if route.intent == "count_findings":
        return canonical_answer_for_count(payload, answer, route.language)
    if route.intent == "severity_distribution":
        return canonical_answer_for_severity_distribution(payload, answer, route.language)
    if route.intent == "filter_findings":
        return canonical_answer_for_finding_list(payload, answer, route.language)
    return None


def _contract_answer_for_non_dspm(route: IntentRoute) -> str:
    if route.intent == "greeting":
        if route.language == "en":
            return "Hello. I am ready to help with DSPM scans, findings, risk, and remediation."
        if route.language == "ru":
            return "Здравствуйте. Я готов помочь с DSPM scans, findings, risk и remediation."
        return "Salam! Mən DSPM Copilot-am. Tapıntılar, risklər, remediation və dashboard məlumatları ilə bağlı kömək edə bilərəm."
    if route.intent == "small_talk_status":
        if route.language == "en":
            return "I'm doing well, thank you. I am ready to help with DSPM findings and risks."
        if route.language == "ru":
            return "У меня всё хорошо, спасибо. Я готов помочь с DSPM findings и risk."
        return "Yaxşıyam, sağ ol! DSPM tapıntıları və risklərlə bağlı kömək etməyə hazıram."
    if route.intent == "greeting_status":
        if route.language == "en":
            return "Hello. I'm doing well, thank you. I am ready to help with DSPM findings and risks."
        if route.language == "ru":
            return "Здравствуйте. У меня всё хорошо, спасибо. Я готов помочь с DSPM findings и risk."
        return "Salam! Yaxşıyam, sağ ol. DSPM tapıntıları və risklərlə bağlı kömək etməyə hazıram."
    if route.intent == "capability":
        return render_capabilities(route.language)
    if route.intent in {"complaint", "correction"}:
        return safe_fallback_for_route(route)
    if route.intent in {"clarification", "clarification_followup"}:
        if route.language == "en":
            return "What should I use as the context: a scan, finding, alert, asset, remediation, or report?"
        if route.language == "ru":
            return "Уточните, пожалуйста: вы имеете в виду scan, finding, alert, asset, remediation или report?"
        return "Zəhmət olmasa dəqiqləşdirin: scan, finding, alert, asset, remediation, yoxsa report nəzərdə tutursunuz?"
    if route.intent == "report_export":
        if route.language == "en":
            return "Report/export depends on the local backend artifact feature. I will not claim a PDF file was created unless the backend creates one."
        if route.language == "ru":
            return "Report/export зависит от локальной backend artifact функции. Я не буду утверждать, что PDF создан, если backend не создал файл."
        return "Report/export lokal backend artifact funksiyasından asılıdır. Backend fayl yaratmayıbsa, PDF yaradıldığını iddia etməyəcəyəm."
    if route.language == "en":
        return "I can help with DSPM scan, finding, risk, compliance, remediation, and report questions."
    if route.language == "ru":
        return "Я могу помочь с DSPM scan, finding, risk, compliance, remediation и report вопросами."
    return "DSPM scan, finding, risk, compliance, remediation və report suallarında kömək edə bilərəm."


def _social_greeting_variant(session_state: dict | None, language: str) -> tuple[str, dict]:
    current = int((session_state or {}).get("social_repetition_count") or 0) + 1
    if language == "en":
        variants = [
            "Hello. I am ready to help with DSPM risks and findings.",
            "Hello again. What risk should we look at next?",
            "I am here. You can ask about the latest scan, findings, or remediation.",
            "Ready. We can prioritize risks from the latest scan.",
        ]
    else:
        variants = [
            "Salam! DSPM riskləri və tapıntıları üzrə kömək etməyə hazıram.",
            "Yenə Salam. Davam edək, hansı riskə baxaq?",
            "Salam, buradayam. Son scan, tapıntı və ya remediation üzrə sual verə bilərsiniz.",
            "Salam, hazıram. İstəsəniz, son scan üzrə riskləri prioritetləşdirə bilərik.",
        ]
    index = min(current, len(variants)) - 1
    return variants[index], {
        "social_repetition_count": current,
        "response_variant_id": f"greeting_{index + 1}",
    }


def _render_contract_count(payload: dict, route: IntentRoute) -> str:
    count = int(payload.get("count") or 0)
    severity = payload.get("severity")
    if route.language == "en":
        label = f"{severity} " if severity else ""
        return f"According to the latest scan, there are {count} {label}findings."
    if route.language == "ru":
        label = f" уровня {severity}" if severity else ""
        return f"По данным последнего сканирования, найдено {count} findings{label}."
    label = f"{severity} " if severity else "uyğun "
    return f"Son skana görə {count} ədəd {label}tapıntı var."


def _render_contract_list(payload: dict, route: IntentRoute) -> str:
    items = payload.get("items") or []
    count = int(payload.get("count") or 0)
    returned = int(payload.get("returned") or len(items))
    severity = payload.get("severity")
    scan_id = payload.get("scan_id")
    include_remediation = bool(route.entities.get("include_remediation"))
    if route.language == "en":
        lines = []
        if scan_id:
            lines.append(f"Latest scan: {scan_id}")
        if severity == "CRITICAL":
            lines.append(f"Total critical findings/files: {count}")
            lines.append(f"Showing {returned}.")
        else:
            lines.append(f"Available DSPM data has {count} matching findings. Showing {returned}.")
    elif route.language == "ru":
        lines = []
        if scan_id:
            lines.append(f"Последний scan: {scan_id}")
        if severity == "CRITICAL":
            lines.append(f"Всего CRITICAL findings/files: {count}")
            lines.append(f"Показано: {returned}.")
        else:
            lines.append(f"По доступным DSPM данным найдено {count} matching findings. Показано: {returned}.")
    else:
        if severity == "CRITICAL":
            label = "kritik/CRITICAL"
        elif severity:
            label = f"{severity}"
        else:
            label = ""
        risk_word = "riskli" if severity == "HIGH" else ""
        descriptor = " ".join(part for part in (label, risk_word) if part)
        lines = []
        if scan_id:
            lines.append(f"Yoxlanılan skan: {scan_id}")
        descriptor_text = f" {descriptor}" if descriptor else ""
        lines.append(f"Mövcud DSPM məlumatlarında {count} uyğun{descriptor_text} tapıntı var; {returned} nəticə göstərilir.")
    for index, item in enumerate(items, 1):
        name = mask_sensitive_text(item.get("name") or "unknown")
        score = item.get("risk_score")
        item_severity = item.get("severity") or severity or "UNKNOWN"
        risk_types = ", ".join(item.get("risk_types") or [])
        suffix = f" | {risk_types}" if risk_types else ""
        item_risk_label = "risk balı" if route.language == "az" else "risk score"
        lines.append(f"{index}. {name} - {item_severity} - {item_risk_label} {score}{suffix}")
        if include_remediation:
            from backend.copilot.remediation_policy import short_recommendation_for_types
            rec_language = route.language if route.language in {"en", "ru"} else "az"
            recommendation = short_recommendation_for_types(item.get("risk_types") or [], rec_language)
            label = {"en": "Recommendation", "ru": "Рекомендация", "az": "Tövsiyə"}[rec_language]
            lines.append(f"   {label}: {recommendation}.")
    if severity == "CRITICAL":
        note_en = "These are stored as critical findings/files, not separate alert objects."
        note_az = "Mövcud məlumatlarda bunlar ayrıca xəbərdarlıq obyekti kimi yox, kritik tapıntı/fayl kimi saxlanılır."
        note_ru = "В доступных данных это хранится как critical findings/files, а не как отдельные alert objects."
        lines.append(note_en if route.language == "en" else note_ru if route.language == "ru" else note_az)
    return "\n".join(lines)


def _render_contract_compare(payload: dict, route: IntentRoute) -> str:
    current_id = payload.get("current_scan_id")
    previous_id = payload.get("previous_scan_id")
    added = payload.get("added") or []
    resolved = payload.get("resolved") or []
    persisting = payload.get("persisting") or []
    if route.language == "en":
        lines = []
        if current_id:
            lines.append(f"Latest scan: {current_id}")
        if previous_id:
            lines.append(f"Previous scan: {previous_id}")
        lines.extend([
            f"New findings: {len(added)}",
            f"Resolved findings: {len(resolved)}",
            f"Recurring findings: {len(persisting)}",
            f"New critical findings: {int(payload.get('added_critical_count') or 0)}",
        ])
        return "\n".join(lines)
    if route.language == "ru":
        lines = []
        if current_id:
            lines.append(f"Последний scan: {current_id}")
        if previous_id:
            lines.append(f"Предыдущий scan: {previous_id}")
        lines.extend([
            f"Новые findings: {len(added)}",
            f"Исправленные findings: {len(resolved)}",
            f"Повторяющиеся findings: {len(persisting)}",
            f"Новые critical findings: {int(payload.get('added_critical_count') or 0)}",
        ])
        return "\n".join(lines)
    return (
        f"Scan müqayisəsi: {len(added)} yeni, "
        f"{len(resolved)} düzəlmiş, "
        f"{len(persisting)} davam edən finding."
    )


def _contract_sources(payload: dict | None) -> list[SourceRef]:
    if not isinstance(payload, dict):
        return []
    scan_id = payload.get("scan_id") or payload.get("current_scan_id")
    sources: list[SourceRef] = []
    for item in payload.get("items") or []:
        if isinstance(item, dict):
            sources.append(SourceRef(type="finding", scan_id=scan_id, path=item.get("name"), severity=item.get("severity"), risk_score=item.get("risk_score")))
    if not sources and scan_id:
        sources.append(SourceRef(type="scan", scan_id=scan_id))
    return sources


def _render_proactive_alert(payload: dict, route: IntentRoute) -> str:
    counts = payload.get("severity_counts") or {}
    deltas = payload.get("severity_deltas") or {}
    top_types = payload.get("top_risk_types") or []
    critical = int(counts.get("CRITICAL") or 0)
    high = int(counts.get("HIGH") or 0)
    medium = int(counts.get("MEDIUM") or 0)
    type_text = ", ".join(str(item) for item in top_types[:5]) if top_types else "available evidence does not show a dominant type"
    critical_delta = int(deltas.get("CRITICAL") or 0)
    high_delta = int(deltas.get("HIGH") or 0)
    sent = bool(payload.get("notification_sent"))
    if route.language == "en":
        lines = ["Proactive risk alert summary is ready."]
        if not sent:
            lines.append("External notification sending is not active, so I cannot send email/Slack/push. I can provide the dashboard alert summary here.")
        lines.extend(
            [
                f"Latest scan: {payload.get('scan_id') or 'latest available scan'}",
                f"- CRITICAL findings: {critical}",
                f"- HIGH findings: {high}",
                f"- MEDIUM findings: {medium}",
                f"- Change vs previous scan: CRITICAL {critical_delta:+d}, HIGH {high_delta:+d}" if payload.get("has_previous_scan") else "- No previous scan was available for comparison.",
                f"- Main risk types: {type_text}",
                "- Priority: investigate CRITICAL and HIGH findings first.",
                "Recommendation: start from the highest risk score findings and create a remediation plan.",
            ]
        )
        return "\n".join(lines)
    if route.language == "ru":
        lines = ["Сводка proactive risk alert готова."]
        if not sent:
            lines.append("Внешняя отправка уведомлений не активна, поэтому я не могу отправить email/Slack/push. Ниже dashboard summary.")
        lines.extend(
            [
                f"Последний scan: {payload.get('scan_id') or 'latest available scan'}",
                f"- CRITICAL findings: {critical}",
                f"- HIGH findings: {high}",
                f"- MEDIUM findings: {medium}",
                f"- Изменение к предыдущему scan: CRITICAL {critical_delta:+d}, HIGH {high_delta:+d}" if payload.get("has_previous_scan") else "- Предыдущий scan недоступен для сравнения.",
                f"- Основные risk types: {type_text}",
                "- Приоритет: сначала проверьте CRITICAL и HIGH findings.",
                "Рекомендация: начните с findings с самым высоким risk score и подготовьте remediation plan.",
            ]
        )
        return "\n".join(lines)
    lines = ["Proaktiv risk xəbərdarlığı hazırlandı."]
    if not sent:
        lines.append("Hazırda xarici bildiriş göndərmə sistemi aktiv deyil, buna görə email/Slack/push göndərə bilmirəm. Amma dashboard məlumatlarına əsasən xəbərdarlıq xülasəsini təqdim edirəm:")
    lines.extend(
        [
            f"Son skan: {payload.get('scan_id') or 'son mövcud skan'}",
            f"- CRITICAL tapıntılar: {critical}",
            f"- HIGH tapıntılar: {high}",
            f"- MEDIUM tapıntılar: {medium}",
            f"- Əvvəlki skanla dəyişiklik: CRITICAL {critical_delta:+d}, HIGH {high_delta:+d}" if payload.get("has_previous_scan") else "- Müqayisə üçün əvvəlki skan tapılmadı.",
            f"- Əsas risk tipləri: {type_text}",
            "- Prioritet: əvvəlcə CRITICAL və HIGH tapıntıları araşdırın.",
            "Tövsiyə: ən yüksək risk score olan tapıntılardan başlayın və remediation plan yaradın.",
        ]
    )
    return "\n".join(lines)


_MODEL_STATUS_DOWN_AZ = (
    "Model hazırda cavab vermir. Son provider xətası Ollama/CUDA server xətası kimi görünür, "
    "ona görə modelə yeni sorğu göndərmirəm. Dashboard əsaslı say, siyahı, scan müqayisəsi və "
    "remediation sorğuları model olmadan da işləyə bilər."
)
_MODEL_STATUS_OK_AZ = (
    "Model üçün son qeydə alınmış kritik xəta yoxdur. Struktur DSPM sorğuları yenə də modeldən "
    "asılı olmadan işləyir."
)
_MODEL_STATUS_DOWN_EN = (
    "The model is not responding right now. The last provider error looks like an Ollama/CUDA "
    "server crash, so I am not sending new requests to the model. Dashboard-based count, list, "
    "scan comparison and remediation queries still work without the model."
)
_MODEL_STATUS_OK_EN = (
    "No critical provider error is currently recorded for the model. Structured DSPM queries work "
    "independently of the model."
)
_PROVIDER_DOWN_FALLBACK_AZ = (
    "Model hazırda cavab vermir, ona görə bu tip sərbəst sualı generasiya edə bilmirəm. Amma "
    "dashboard məlumatları üzrə say, siyahı, müqayisə, posture score və remediation sorğularına "
    "cavab verə bilərəm."
)
_PROVIDER_DOWN_FALLBACK_EN = (
    "The model is not responding right now, so I cannot generate this kind of free-form answer. "
    "But I can still answer dashboard queries: counts, lists, comparisons, posture score and "
    "remediation."
)


def _model_status_answer(language: str, unhealthy: bool) -> str:
    if language == "en":
        return _MODEL_STATUS_DOWN_EN if unhealthy else _MODEL_STATUS_OK_EN
    return _MODEL_STATUS_DOWN_AZ if unhealthy else _MODEL_STATUS_OK_AZ


def _provider_down_fallback(language: str) -> str:
    return _PROVIDER_DOWN_FALLBACK_EN if language == "en" else _PROVIDER_DOWN_FALLBACK_AZ


def _render_ollama_status_meta(health, language: str) -> str:
    status = getattr(health, "status", "unknown")
    healthy = bool(getattr(health, "is_healthy", False))
    if language == "en":
        if healthy:
            return "Ollama daemon and the selected model are responding. Structured DSPM questions will still use dashboard data as the source of truth."
        return f"Ollama daemon may be running, but selected model readiness is separate. Current model health: {status}. I can still answer structured dashboard questions without the model."
    if language == "ru":
        if healthy:
            return "Ollama daemon и выбранная модель отвечают. Для структурированных DSPM вопросов я всё равно буду использовать dashboard data как источник истины."
        return f"Ollama daemon может быть запущен, но готовность выбранной модели проверяется отдельно. Текущий статус модели: {status}. Я всё ещё могу отвечать на структурированные dashboard вопросы без модели."
    if healthy:
        return "Ollama servisi və seçilmiş model cavab verir. Struktur DSPM sorğularında yenə də dashboard məlumatlarını əsas götürəcəyəm."
    return f"Ollama servisi işləyə bilər, amma seçilmiş modelin cavab verməsi ayrıca yoxlanmalıdır. Hazırkı model statusu: {status}. Struktur dashboard sorğularını modeldən asılı olmadan cavablandıra bilərəm."


def _store_contract_list_context(
    context: dict | None,
    principal: Principal,
    conversation_id: str,
    route: IntentRoute,
    payload: dict,
    answer: str,
    canonical_answer: CanonicalAnswer | None = None,
) -> dict:
    next_context = _with_language_preference(context, principal, conversation_id, route.language, None)
    next_context.update(
        {
            "last_intent": route.intent,
            "last_tool_names": [f"structured_{route.intent}"],
            "last_result_type": payload.get("result_type"),
            "last_requested_limit": payload.get("returned"),
            "last_total_count": payload.get("count"),
            "last_answer_summary": answer[:500],
            "last_tool_result_summary": f"{payload.get('count', 0)} matching findings",
        }
    )
    next_context = _with_canonical_answer_payload(next_context, canonical_answer)
    severity = str(payload.get("severity") or "").upper()
    if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        next_context["last_requested_severity"] = severity
        # A severity-scoped evidence result is the reportable scope a later bare
        # "pdf"/"give as a pdf" should turn into a report of that same scope.
        next_context["last_reportable_scope"] = {
            "kind": "severity", "severities": [severity], "label": severity,
        }
        if route.intent == "count_findings":
            next_context["last_count_scope_severities"] = [severity]
            next_context["last_count_scope_scan_id"] = payload.get("scan_id") or next_context.get("last_scan_id")
            next_context["last_count_scope_metric"] = "file_level_finding_count"
            next_context["last_answer_type"] = "severity_count"
            frame = task_frame_controller.create_count_frame(
                message=answer,
                severity=severity,
                scan_id=payload.get("scan_id") or next_context.get("last_scan_id"),
                source_route_id="count_findings",
                existing=next_context,
            )
            # Preserve alert-as-finding when the typed route already resolved that alias.
            if route.entities.get("object_alias") == "alert_as_finding":
                frame.object_alias = "alert_as_finding"
            next_context = task_frame_controller.attach_frame(next_context, frame)
            next_context["task_frame_turn"] = frame.updated_turn
    if route.intent == "greeting":
        next_context["social_repetition_count"] = int((context or {}).get("social_repetition_count") or 0) + 1
    if payload.get("items"):
        next_context["last_shown_items"] = [
            {
                "index": index,
                "name": item.get("name"),
                "severity": item.get("severity"),
                "risk_score": item.get("risk_score"),
                "risk_types": item.get("risk_types") or [],
                "scan_id": payload.get("scan_id") or next_context.get("last_scan_id"),
                "metric": "file_level_finding_count",
                "source": "shown_single_finding" if len(payload.get("items") or []) == 1 else "shown_finding_list",
            }
            for index, item in enumerate(payload.get("items") or [], 1)
            if isinstance(item, dict)
        ]
        if len(next_context["last_shown_items"]) == 1:
            selected = dict(next_context["last_shown_items"][0])
            selected["id"] = selected.get("id") or selected.get("name")
            selected["source_type"] = "finding"
            selected["safe_identifier"] = selected.get("name")
            selected["detail_ref"] = selected.get("name")
            selected["full_detail_ref"] = selected.get("name")
            next_context["current_item"] = selected
            next_context["last_item"] = selected
    return next_context


async def _handle_contract_route(
    route: IntentRoute,
    message: str,
    principal: Principal,
    conv_id: str,
    scan_id: str | None,
    session_state: dict | None,
    message_id: str,
    start: float,
    selected_language: str | None = None,
    language_source: str = "fallback_default",
    language_understanding_audit: dict | None = None,
    situation_decision=None,
) -> ChatResponse | None:
    direct_intents = {"greeting", "small_talk_status", "greeting_status", "capability", "complaint", "correction", "meta", "clarification", "clarification_followup"}
    payload: dict | None = None
    answer: str
    used: list[str] = []
    response_sources: list[SourceRef] = []
    if route.intent == "filter_findings" and route.entities.get("include_remediation"):
        try:
            requested_limit = int(route.entities.get("limit") or 0)
        except (TypeError, ValueError):
            requested_limit = 0
        if requested_limit == 1:
            return None
    if route.intent == "simple_arithmetic":
        raw = route.entities.get("arithmetic_result")
        if raw is not None:
            val = float(raw)
            if val == int(val) and abs(val) < 1e15:
                answer = str(int(val))
            else:
                answer = f"{round(val, 8):g}"
        else:
            answer = "?"
    elif route.intent == "general_non_dspm_question":
        # No retrieval, no dashboard prefix — fall through to provider-based flow
        return None
    elif route.intent == "ollama_status_meta":
        health = await check_ollama_model_health()
        payload = {"result_type": "ollama_model_health", "status": getattr(health, "status", "unknown")}
        answer = _render_ollama_status_meta(health, route.language)
    elif route.intent in direct_intents:
        if route.intent == "capability":
            answer = render_capabilities(
                route.language,
                include_limitations=capability_registry.asks_about_limitations(message),
            )
        else:
            answer = _contract_answer_for_non_dspm(route)
        if route.intent == "correction" and isinstance(session_state, dict) and session_state.get("last_total_count") is not None:
            total = session_state.get("last_total_count")
            if route.language == "az":
                answer += f" Əvvəlki nəticəyə görə ümumi say {total} idi; seçilmiş finding detalını bu cavabda istifadə etmirəm."
            else:
                answer += f" Based on the previous result, the total count was {total}; I am not using selected finding details in this reply."
    elif route.intent == "proactive_alert_request":
        history_rows = read_scan_history(principal.tenant_id, 2)
        current_report = read_scan_report(principal.tenant_id, scan_id)
        previous_report = None
        if current_report and history_rows:
            current_id = current_report.get("scan_id")
            previous_ids = [row.get("scan_id") for row in history_rows if row.get("scan_id") != current_id]
            if previous_ids:
                previous_report = read_scan_report(principal.tenant_id, str(previous_ids[-1]))
        elif len(history_rows) >= 1:
            current_report = read_scan_report(principal.tenant_id, str(history_rows[-1].get("scan_id")))
            if len(history_rows) >= 2:
                previous_report = read_scan_report(principal.tenant_id, str(history_rows[-2].get("scan_id")))
        payload = proactive_alert_summary(current_report, previous_report)
        answer = _render_proactive_alert(payload, route) if current_report else safe_fallback_for_route(route)
        used = ["get_executive_dashboard", "get_severity_distribution"]
        response_sources = _contract_sources(payload)
    elif route.intent == "count_findings":
        report = read_scan_report(principal.tenant_id, scan_id)
        payload = count_findings(report, severity=route.entities.get("severity")) if isinstance(report, dict) else {}
        answer = _render_contract_count(payload, route) if isinstance(report, dict) else safe_fallback_for_route(route)
        used = ["structured_count_findings"]
        response_sources = _contract_sources(payload)
    elif route.intent == "severity_distribution":
        tool_result = role_filter(await tools.get_severity_distribution(principal, scan_id), principal.role)
        payload = _payload(tool_result)
        answer = _render_severity_distribution(payload, route.language)
        used = [tool_result.tool_name]
        response_sources = list(tool_result.sources)
    elif route.intent == "filter_findings":
        report = read_scan_report(principal.tenant_id, scan_id)
        payload = filter_findings(report, severity=route.entities.get("severity"), limit=route.entities.get("limit") or 10) if isinstance(report, dict) else {}
        answer = _render_contract_list(payload, route) if isinstance(report, dict) else safe_fallback_for_route(route)
        used = ["get_findings_by_severity"] if route.entities.get("severity") else ["structured_filter_findings"]
        response_sources = _contract_sources(payload)
    elif route.intent == "compare_findings":
        history_rows = read_scan_history(principal.tenant_id, 2)
        if len(history_rows) >= 2:
            current = read_scan_report(principal.tenant_id, history_rows[-1].get("scan_id"))
            previous = read_scan_report(principal.tenant_id, history_rows[-2].get("scan_id"))
        else:
            current = read_scan_report(principal.tenant_id, scan_id)
            previous = None
        payload = compare_findings(current, previous, severity=route.entities.get("severity"))
        answer = _render_contract_compare(payload, route)
        used = ["compare_scans"]
        response_sources = _contract_sources(payload)
    elif route.intent == "posture_score":
        tool_result = role_filter(await tools.get_posture_score(principal, scan_id), principal.role)
        payload = _payload(tool_result)
        from backend.copilot.skill_renderers import render_posture_score

        answer = render_posture_score(payload, route.language)
        used = [tool_result.tool_name]
        response_sources = list(tool_result.sources)
    else:
        return None

    validation = validate_contract_answer(route, answer, payload)
    if not validation.ok:
        answer = safe_fallback_for_route(route, payload)
        validation = validate_contract_answer(route, answer, payload)
    canonical_answer = _canonical_answer_for_contract_route(route, payload, validation.answer)
    if canonical_answer:
        answer = render_canonical_answer(canonical_answer, route.language)
        canonical_answer = _canonical_answer_for_contract_route(route, payload, answer)
    else:
        answer = validation.answer
    answer = clean_language_boilerplate(clean_answer_text(mask_sensitive_text(answer)), route.language)
    situation_audit = situation_decision.to_route_metadata() if situation_decision is not None else {}
    verbalizer_audit: dict = {}
    if route.intent in _CONTRACT_INTENT_TO_SOCIAL_SITUATION and not canonical_answer:
        social_decision = _social_decision_for_situation(_CONTRACT_INTENT_TO_SOCIAL_SITUATION[route.intent])
        verbalizer_result = await _verbalize_canned_social_draft(
            safe_draft=answer,
            situation_decision=social_decision,
            target_language=route.language,
            conversation_id=conv_id,
        )
        if verbalizer_result is not None:
            verbalizer_audit = verbalizer_result.metadata
            answer = verbalizer_result.text
    if route.intent == "greeting":
        answer, social_meta = _social_greeting_variant(session_state, route.language)
        verbalizer_audit.update(social_meta)
    if route.intent == "count_findings" and "alert" in language_service.normalize_for_intent(message):
        if route.language == "az":
            answer = (
                f"{answer}\nQeyd: bu sistemdə ayrıca alert obyekti yoxdursa, alert sorğusu "
                "file-level tapıntı kimi hesablanır."
            )
        elif route.language == "en":
            answer = f"{answer}\nNote: if there is no separate alert object, this alert request is treated as file-level findings."
    combined_situation_audit = {**situation_audit, **verbalizer_audit}
    if "provider_role_budget_summary" not in combined_situation_audit:
        combined_situation_audit.update(situation_runtime.role_budget_metadata())
    combined_situation_audit.update(
        situation_runtime.runtime_response_metadata(
            answer=answer,
            decision=situation_decision,
            fallback_used=bool(combined_situation_audit.get("fallback_used", False)),
            fallback_reason=combined_situation_audit.get("fallback_reason"),
        )
    )
    next_session_state = _store_contract_list_context(session_state, principal, conv_id, route, payload or {}, answer, canonical_answer)
    next_session_state = _with_selected_language_metadata(next_session_state, principal, conv_id, route.language, selected_language, language_source)
    task_frame = task_frame_controller.active_frame(next_session_state)
    if route.intent == "count_findings" and task_frame:
        combined_situation_audit.update(task_frame.audit_metadata(source="count_route", selected_suppressed=False))
    await save_session_context(principal, conv_id, next_session_state)
    await memory.save_turn(principal.tenant_id, conv_id, message, answer, used, [source.model_dump() for source in response_sources])
    total_ms = int((time.perf_counter() - start) * 1000)
    if route.intent in {"greeting", "small_talk_status", "greeting_status"}:
        final_answer_mode = "fast_verbalizer" if verbalizer_audit.get("fast_verbalizer_used") else "canned_variant"
    elif route.intent == "filter_findings":
        final_answer_mode = "deterministic_list"
    else:
        final_answer_mode = "deterministic_contract"
    await audit.log_interaction(
        principal, conv_id, len(message), route.intent, used, {}, len(answer),
        total_ms, len(response_sources), None, route.language,
        task_type=route.intent,
        provider_planning_called=False,
        provider_final_called=False,
        final_answer_mode=final_answer_mode,
        provider_call_count=int((combined_situation_audit.get("provider_role_budget_summary") or {}).get("provider_call_count") or 0),
        translator_called=False,
        language_understanding=language_understanding_audit or {},
        elapsed_ms_total=total_ms,
        selected_language=next_session_state.get("selected_language") if isinstance(next_session_state, dict) else selected_language,
        response_language=route.language,
        language_source=language_source,
        language_validation_passed=validation.ok,
        language_validation_fallback_used=bool(validation.errors),
        **_canonical_audit_fields(canonical_answer),
        **combined_situation_audit,
    )
    if route.intent in {"greeting", "small_talk_status", "greeting_status"}:
        response_intent = "small_talk"
    elif route.intent == "capability" and "neleredebilirsen" in language_service.normalize_for_intent(message).replace(" ", ""):
        response_intent = "capability_help"
    elif route.intent == "count_findings" and route.entities.get("severity"):
        response_intent = "severity_distribution"
    elif route.intent == "filter_findings" and route.entities.get("severity") == "CRITICAL":
        response_intent = "critical_findings"
    else:
        response_intent = route.intent
    if route.intent in {"greeting", "small_talk_status", "greeting_status"}:
        response_task_type = "small_talk"
    elif route.intent == "count_findings" and route.entities.get("severity"):
        response_task_type = "severity_count"
    elif route.intent == "filter_findings" and route.entities.get("include_remediation"):
        response_task_type = "list_plus_remediation"
    elif route.intent == "filter_findings" and route.entities.get("severity") == "CRITICAL":
        response_task_type = "critical_findings_list"
    elif route.intent == "filter_findings" and route.entities.get("severity"):
        response_task_type = "severity_findings_list"
    elif route.intent == "compare_findings" and route.entities.get("severity"):
        response_task_type = "severity_findings_compare"
    else:
        response_task_type = route.intent
    timings = {"total_ms": total_ms, "route": "canned" if route.intent in {"greeting", "small_talk_status", "greeting_status"} else "deterministic_contract"}
    route_metadata = _contract_route_metadata(route, validation.errors, timings if _debug_metadata(timings) else None)
    route_metadata.update(combined_situation_audit)
    return ChatResponse(
        answer=answer,
        intent=response_intent,
        task_type=response_task_type,
        language=route.language,
        sources=response_sources,
        tools_used=used,
        conversation_id=conv_id,
        message_id=message_id,
        session_context_summary=_session_summary(next_session_state),
        metadata=route_metadata,
    )


def _trace_plan(
    conversation_id: str,
    message: str,
    plan: RoutePlan,
    tools_used: list[str] | None = None,
    provider_final_called: bool = False,
    evidence_checked: bool = False,
    final_answer_mode: str = "fallback",
) -> None:
    _log.info(
        "copilot_route_plan conversation_id=%s message=%r provider_planning_called=%s "
        "provider_final_called=%s intent=%s task_type=%s source=%s target_reference=%s "
        "tools_used=%s evidence_checked=%s final_answer_mode=%s",
        conversation_id,
        message[:200],
        plan.provider_planning_called,
        provider_final_called,
        plan.intent,
        plan.task_type,
        plan.source,
        plan.target_reference,
        tools_used or [],
        evidence_checked,
        final_answer_mode,
    )


def _planner_audit_metadata(plan: RoutePlan) -> dict:
    return {
        "planner_used": bool(plan.provider_planning_called),
        "planner_source": "structured_ai" if plan.provider_planning_called else "heuristic",
        "planner_intent": (plan.plan_fixup or {}).get("planner_intent") or plan.intent,
        "planner_confidence": plan.confidence,
        "planner_rejected": bool(plan.planner_rejected),
        "planner_rejection_reason": plan.planner_rejection_reason,
        "validated_intent": plan.intent if not plan.planner_rejected else None,
        "needs_dspm_evidence": plan.requires_evidence,
        "allowed_tools": plan.allowed_tools or [],
        "selection_mode": plan.selection_mode,
        "needs_step_by_step": plan.needs_step_by_step,
    }


def _intent_for_plan(plan: RoutePlan, message: str) -> IntentResult:
    if plan.intent == "critical_findings" or plan.task_type in LIST_TASKS | CORRECTION_TASKS:
        return IntentResult(intent="alert_summary")
    if plan.intent == "remediation_advice" or plan.task_type in REMEDIATION_TASKS:
        return IntentResult(intent="remediation_advice")
    if plan.intent in {"asset_risk", "finding_search", "executive_summary", "audit_query", "alert_summary", "general"}:
        return IntentResult(intent=plan.intent)  # type: ignore[arg-type]
    return _heuristic_intent(message)


def _resolve_plan_item(context: dict | None, plan: RoutePlan) -> dict | None:
    target_entity = (plan.target_entity or "").strip()
    if target_entity and context:
        current_item = context.get("current_item") if isinstance(context.get("current_item"), dict) else None
        if current_item:
            names = {
                str(current_item.get("name") or "").lower(),
                str(current_item.get("safe_identifier") or "").lower(),
                str(current_item.get("full_detail_ref") or "").lower(),
                str(current_item.get("detail_ref") or "").lower(),
            }
            if target_entity.lower() in names:
                return current_item
        for item in context.get("last_shown_items") or []:
            names = {
                str(item.get("name") or "").lower(),
                str(item.get("safe_identifier") or "").lower(),
                str(item.get("full_detail_ref") or "").lower(),
                str(item.get("detail_ref") or "").lower(),
            }
            if target_entity.lower() in names:
                return item
    if not context:
        return {"name": target_entity, "safe_identifier": target_entity, "full_detail_ref": target_entity} if target_entity else None
    items = context.get("last_shown_items") or []
    current_item = context.get("current_item") if isinstance(context.get("current_item"), dict) else None
    if current_item and plan.target_reference in {"current_session_item", "that_item"}:
        return current_item
    if not items:
        if current_item:
            return current_item
        return {"name": target_entity, "safe_identifier": target_entity, "full_detail_ref": target_entity} if target_entity else None
    if plan.target_index == -1 or plan.target_reference in {"last_item_from_previous_critical_findings", "last_shown_critical_finding"}:
        return items[-1] or context.get("last_item")
    if plan.target_index and plan.target_index > 0:
        for item in items:
            if int(item.get("index") or 0) == plan.target_index:
                return item
    if plan.target_reference in {"current_session_item", "that_item"}:
        return context.get("current_item") or context.get("last_item") or items[-1]
    return {"name": target_entity, "safe_identifier": target_entity, "full_detail_ref": target_entity} if target_entity else None


def _is_plural_remediation_followup(message: str) -> bool:
    normalized = normalize_message(message).lower()
    plural_signals = (
        "and recommendation", "and recommendations", "and remediation",
        "all of them", "all items", "all three", "all four",
        "hamısı", "hamısına", "bunların", "bunlar üçün",
        "for all", "each of them", "recommendations",
    )
    singular_signals = (
        "first one", "second", "ikinci", "3-cü", "number 2", "number 1",
        "birinci", "ucuncu", "last", "axirinci", "sonuncu",
        "that one", "this one", "onu", "bunu", "hemin",
    )
    has_plural = any(signal in normalized for signal in plural_signals)
    has_singular = any(signal in normalized for signal in singular_signals)
    return has_plural and not has_singular


def _resolve_plan_items(context: dict | None, plan: RoutePlan, message: str) -> list[dict]:
    if not context:
        return []
    items = context.get("last_shown_items") or []
    if not items:
        return []
    if _is_plural_remediation_followup(message) and len(items) > 1:
        return items
    return [items[-1]] if items else []


def _merge_previous_list_context(next_context: dict, previous_context: dict | None) -> dict:
    if not previous_context:
        return next_context
    for key in (
        "last_result_type",
        "last_requested_limit",
        "last_total_count",
        "last_requested_severity",
        "last_selection_mode",
        "last_task_type",
        "last_unshown_pool_ids",
        "last_answer_structured_payload",
        "last_shown_items",
        "last_item",
        "current_item",
    ):
        if previous_context.get(key) and not next_context.get(key):
            next_context[key] = previous_context[key]
    avoided: list[str] = []
    for source in (previous_context.get("avoided_item_ids") or [], next_context.get("avoided_item_ids") or []):
        for value in source:
            text = str(value or "").strip()
            if text and text not in avoided:
                avoided.append(text)
            if len(avoided) >= 50:
                break
    if avoided:
        next_context["avoided_item_ids"] = avoided[:50]
    for key in ("language_preference_locked", "language_locked"):
        if previous_context.get(key) and not next_context.get(key):
            next_context[key] = previous_context[key]
    return next_context


def _merge_language_lock(next_context: dict, previous_context: dict | None) -> dict:
    if not previous_context:
        return next_context
    if previous_context.get("language_preference_locked") in {"az", "en"}:
        next_context["language_preference_locked"] = previous_context["language_preference_locked"]
        next_context["language_locked"] = True
    if previous_context.get("selected_language_source") == "explicit_user_selection":
        for key in ("selected_language", "selected_language_source", "language_source", "last_language_change_at"):
            if previous_context.get(key):
                next_context[key] = previous_context[key]
    else:
        for key in ("language_source", "last_language_change_at"):
            if previous_context.get(key):
                next_context[key] = previous_context[key]
    return next_context


async def _selected_item_tool_result(principal: Principal, session_state: dict | None, plan: RoutePlan) -> ToolResult:
    item = _resolve_plan_item(session_state, plan)
    if not item:
        raise NoEvidenceError("No selected finding is available in the current session.")
    identifier = item.get("full_detail_ref") or item.get("safe_identifier") or item.get("name")
    scan_id = session_state.get("last_scan_id") if session_state and not plan.target_entity else None
    return role_filter(await tools.get_finding_detail(principal, str(identifier), scan_id), principal.role)


def _resolve_identifier_for_functional_task(session_state: dict | None, plan: RoutePlan) -> str | None:
    if plan.target_entity:
        return plan.target_entity
    item = _resolve_plan_item(session_state, plan)
    if not item:
        return None
    return str(item.get("full_detail_ref") or item.get("safe_identifier") or item.get("name") or "") or None


# Dispatch tables for functional (aggregate/whole-scan) tasks. Scan-scoped
# tools take the scan/limit context; item-scoped tools take the resolved
# finding identifier.
_FUNCTIONAL_SCAN_TOOLS = {
    "scan_comparison": lambda principal, plan, scan_id: tools.compare_scans(principal, plan.requested_limit or 2),
    "severity_distribution": lambda principal, plan, scan_id: tools.get_severity_distribution(principal, scan_id),
    "posture_score": lambda principal, plan, scan_id: tools.get_posture_score(principal, scan_id),
    "compliance_report": lambda principal, plan, scan_id: tools.get_compliance_report(principal, scan_id),
    "trend_analysis": lambda principal, plan, scan_id: tools.get_trend_analysis(principal, plan.requested_limit or 5),
}

_FUNCTIONAL_ITEM_TOOLS = {
    "finding_history": lambda principal, identifier: tools.get_finding_history(principal, identifier),
    "remediation_status": lambda principal, identifier: tools.get_remediation_status(principal, identifier),
    "compliance_mapping": lambda principal, identifier: tools.get_compliance_mapping(principal, identifier),
}


async def _functional_tool_result(principal: Principal, session_state: dict | None, plan: RoutePlan, scan_id: str | None) -> ToolResult:
    scan_tool = _FUNCTIONAL_SCAN_TOOLS.get(plan.task_type)
    if scan_tool is not None:
        return role_filter(await scan_tool(principal, plan, scan_id), principal.role)
    item_tool = _FUNCTIONAL_ITEM_TOOLS.get(plan.task_type)
    if item_tool is not None:
        identifier = _resolve_identifier_for_functional_task(session_state, plan)
        return role_filter(await item_tool(principal, identifier), principal.role)
    raise NoEvidenceError("The requested DSPM capability is not available.")


def _evidence_block(item: dict, scan_id: str | None = None, source: str = "latest scan report") -> list[str]:
    risk_types = item.get("risk_types") or [
        str(finding.get("type"))
        for finding in item.get("findings") or []
        if isinstance(finding, dict) and finding.get("type")
    ]
    return [
        "Evidence:",
        f"- Scan ID: {scan_id or item.get('scan_id') or 'unknown'}",
        f"- Finding: {item.get('name') or item.get('path') or 'unknown'}",
        f"- Severity: {item.get('severity') or 'unknown'}",
        f"- Risk score: {item.get('risk_score') if item.get('risk_score') is not None else 'unknown'}",
        f"- Detected types: {', '.join(risk_types) if risk_types else 'none recorded'}",
        f"- Source: {source}",
    ]


def _render_scan_comparison(payload: dict) -> str:
    latest = payload.get("latest_scan_id") or "latest scan"
    previous = payload.get("previous_scan_id") or "previous scan"
    latest_counts = payload.get("latest_severity_counts") or {}
    previous_counts = payload.get("previous_severity_counts") or {}
    lines = [
        f"Comparison of the last {payload.get('scan_count') or 2} scans:",
        "",
        f"Latest scan: {latest}",
        f"Previous scan: {previous}",
        "",
        f"- Critical findings: {previous_counts.get('CRITICAL', 0)} -> {latest_counts.get('CRITICAL', 0)} ({latest_counts.get('CRITICAL', 0) - previous_counts.get('CRITICAL', 0):+d})",
        f"- High findings: {previous_counts.get('HIGH', 0)} -> {latest_counts.get('HIGH', 0)} ({latest_counts.get('HIGH', 0) - previous_counts.get('HIGH', 0):+d})",
        f"- New findings: {payload.get('new_findings_count', 0)}",
        f"- Resolved findings: {payload.get('resolved_findings_count', 0)}",
        f"- Recurring findings: {payload.get('recurring_findings_count', 0)}",
        f"- New critical findings: {payload.get('new_critical_count', 0)}",
        f"- Resolved critical findings: {payload.get('resolved_critical_count', 0)}",
        f"- Recurring critical findings: {payload.get('recurring_critical_count', 0)}",
    ]
    new_findings = payload.get("new_findings") or []
    if new_findings:
        lines.extend(["", "Top new findings:"])
        for index, item in enumerate(new_findings[:5], 1):
            lines.append(f"{index}. {item.get('name')} - severity {item.get('severity')}, risk score {item.get('risk_score')}")
    return "\n".join(lines)


def _render_finding_history(payload: dict) -> str:
    item = payload.get("item") if isinstance(payload.get("item"), dict) else {}
    if payload.get("is_new"):
        status = "This appears to be a new finding in the latest scan history available."
    else:
        status = f"This is a recurring finding. It has appeared before; recurring since {payload.get('recurring_since')}."
    lines = [
        status,
        f"Previous scan IDs: {', '.join(payload.get('previous_scan_ids') or []) or 'none'}",
        "",
        *_evidence_block(item, payload.get("latest_scan_id")),
    ]
    return "\n".join(lines)


def _render_remediation_status(payload: dict) -> str:
    item = payload.get("item") if isinstance(payload.get("item"), dict) else {}
    lines = [
        str(payload.get("message") or "I do not have enough scan history to confirm remediation status."),
        "",
        *_evidence_block(item, payload.get("latest_scan_id")),
    ]
    return "\n".join(lines)


def _render_severity_distribution(payload: dict, language: str = "en") -> str:
    counts = payload.get("severity_counts") or {}
    if language == "az":
        lines = [
            "Son skanın ciddilik bölgüsü:",
            "",
            f"Skan: {payload.get('scan_id') or 'son skan'}",
            f"- CRITICAL: {counts.get('CRITICAL', 0)}",
            f"- HIGH: {counts.get('HIGH', 0)}",
            f"- MEDIUM: {counts.get('MEDIUM', 0)}",
            f"- LOW: {counts.get('LOW', 0)}",
        ]
        top_types = payload.get("top_risk_types") or []
        if top_types:
            lines.extend(["", "Ən çox rast gəlinən risk növləri:"])
            for item in top_types[:5]:
                lines.append(f"- {item.get('type')} count {item.get('count')}")
        return "\n".join(lines)
    if language == "az":
        lines = [
            "Son skanın ciddilik bölgüsü:",
            "",
            f"Skan: {payload.get('scan_id') or 'son skandakı ən son'}",
            f"- CRITICAL: {counts.get('CRITICAL', 0)}",
            f"- HIGH: {counts.get('HIGH', 0)}",
            f"- MEDIUM: {counts.get('MEDIUM', 0)}",
            f"- LOW: {counts.get('LOW', 0)}",
        ]
        top_types = payload.get("top_risk_types") or []
        if top_types:
            lines.extend(["", "Ən çox rast gəlinən risk növləri:"])
            for item in top_types[:5]:
                lines.append(f"- {item.get('type')}: {item.get('count')}")
        return "\n".join(lines)
    lines = [
        "Latest scan severity distribution:",
        "",
        f"Scan: {payload.get('scan_id') or 'latest scan'}",
        f"- CRITICAL: {counts.get('CRITICAL', 0)}",
        f"- HIGH: {counts.get('HIGH', 0)}",
        f"- MEDIUM: {counts.get('MEDIUM', 0)}",
        f"- LOW: {counts.get('LOW', 0)}",
    ]
    top_types = payload.get("top_risk_types") or []
    if top_types:
        lines.extend(["", "Top risk types:"])
        for item in top_types[:5]:
            lines.append(f"- {item.get('type')} count {item.get('count')}")
    return "\n".join(lines)


def _render_compliance_mapping(payload: dict) -> str:
    item = payload.get("item") if isinstance(payload.get("item"), dict) else {}
    frameworks = payload.get("frameworks") if isinstance(payload.get("frameworks"), dict) else {}
    lines = [
        "This finding may indicate compliance risk, but I cannot determine a legal violation from scan data alone.",
        "",
        *_evidence_block(item, item.get("scan_id")),
        "",
        "Possible framework relevance:",
    ]
    if not frameworks:
        lines.append("- No specific framework mapping was found for the detected risk types.")
    else:
        seen: set[str] = set()
        for risk_type, mappings in frameworks.items():
            for mapping in mappings or []:
                key = f"{mapping}:{risk_type}"
                if key in seen:
                    continue
                seen.add(key)
                lines.append(f"- {mapping}: related to detected type {risk_type}")
    lines.append("This is not legal advice.")
    return "\n".join(lines)


def _render_functional_answer(result: ToolResult, task_type: str) -> str:
    payload = _payload(result)
    local_renderer = {
        "scan_comparison": _render_scan_comparison,
        "finding_history": _render_finding_history,
        "remediation_status": _render_remediation_status,
        "severity_distribution": _render_severity_distribution,
        "compliance_mapping": _render_compliance_mapping,
    }.get(task_type)
    if local_renderer is not None:
        return local_renderer(payload)
    renderer_name = {
        "posture_score": "render_posture_score",
        "compliance_report": "render_compliance_report",
        "trend_analysis": "render_trend_analysis",
    }.get(task_type)
    renderer = get_renderer(renderer_name)
    if renderer:
        return renderer(payload, "en")
    return fallback_answer("en")


def _deterministic_item_answer(result: ToolResult, language: str, task_type: str) -> str:
    payload = _payload(result)
    item = payload.get("item") if isinstance(payload.get("item"), dict) else {}
    name = item.get("name") or item.get("path") or "unknown item"
    severity = item.get("severity") or "unknown"
    score = item.get("risk_score") if item.get("risk_score") is not None else "unknown"
    risk_types = [str(finding.get("type")) for finding in item.get("findings") or [] if isinstance(finding, dict) and finding.get("type")]
    from backend.copilot.remediation_policy import short_recommendation_for_types, why_it_matters
    if language == "az":
        lines = [f"Seçilmiş tapıntı: {name}", f"Ciddilik dərəcəsi: {severity}", f"Risk skoru: {score}"]
        if risk_types:
            lines.append(f"Aşkarlanan həssas məlumat tipləri: {', '.join(risk_types)}")
        if task_type in REMEDIATION_TASKS:
            lines.append(f"Tövsiyə: {short_recommendation_for_types(risk_types, 'az')}.")
        elif task_type in RISK_EXPLANATION_TASKS:
            lines.append(f"Niyə vacibdir: {why_it_matters(risk_types, 'az')}")
            lines.append(f"Növbəti addımlar: {short_recommendation_for_types(risk_types, 'az')}.")
        else:
            lines.append("Əlavə sahələr mövcud sübut daxilində yoxdursa, onları uydurmuram.")
        return "\n".join(lines)
    lines = [f"Selected finding: {name}", f"Severity: {severity}", f"Risk score: {score}"]
    if risk_types:
        lines.append(f"Detected sensitive types: {', '.join(risk_types)}")
    if task_type in REMEDIATION_TASKS:
        lines.append(f"Recommended next step: {short_recommendation_for_types(risk_types, 'en')}.")
    elif task_type in RISK_EXPLANATION_TASKS:
        lines.append(f"Why it matters: {why_it_matters(risk_types, 'en')}")
        lines.append(f"Next steps: {short_recommendation_for_types(risk_types, 'en')}.")
    else:
        lines.append("Unavailable fields are not inferred beyond the provided evidence.")
    return "\n".join(lines)


def _ensure_item_header(answer: str, result: ToolResult, language: str) -> str:
    payload = _payload(result)
    item = payload.get("item") if isinstance(payload.get("item"), dict) else {}
    name = str(item.get("name") or item.get("path") or "").strip()
    severity = str(item.get("severity") or "").strip()
    score = item.get("risk_score")
    if not name or name in answer:
        return answer
    if language == "az":
        header = [f"Fayl: {name}"]
    else:
        header = [f"File: {name}"]
    if severity and severity not in answer:
        header.append(f"Severity: {severity}")
    if score is not None and str(score) not in answer:
        header.append(f"Risk score: {score}")
    return "\n".join(header + ["", answer]).strip()


def _ensure_structured_evidence_block(answer: str, result: ToolResult) -> str:
    if "Evidence:" in answer:
        return answer
    payload = _payload(result)
    item = payload.get("item") if isinstance(payload.get("item"), dict) else {}
    if not item:
        return answer
    block = "\n".join(_evidence_block(item, payload.get("scan_id") or item.get("scan_id")))
    return f"{answer.strip()}\n\n{block}".strip()


def _looks_like_full_critical_list(answer: str) -> bool:
    text = clean_answer_text(answer).lower()
    if text.startswith("the current data stores these as critical findings/files"):
        return True
    if text.startswith("mövcud datada bunlar ayrıca alert obyekti kimi yox"):
        return True
    if "scan checked:" in text and re.search(r"(?m)^\s*1\.\s+.+\n\s*2\.\s+", text):
        return True
    return False


async def _finalize_visible_answer(canonical_answer: str, target_language: str, *, source_language: str | None = None) -> str:
    if target_language == "az" and source_language == "az":
        return clean_language_boilerplate(clean_answer_text(canonical_answer), "az") or fallback_answer("az")
    cleanup_language = "en" if target_language == "az" else target_language if target_language in SUPPORTED_RESPONSE_LANGUAGES else "en"
    cleaned = clean_language_boilerplate(clean_answer_text(canonical_answer), cleanup_language) or fallback_answer(cleanup_language)
    if cleaned == provider_unavailable_answer("en") or "local ai model is temporarily unavailable" in cleaned.lower():
        return provider_unavailable_answer(target_language)
    if target_language == "az":
        translated = await translate_to_azerbaijani(cleaned, provider=call_ollama)
        return clean_answer_text(translated) or cleaned
    return cleaned


async def generate_selected_item_answer(message: str, tool_result: ToolResult, metadata: LanguageIntent, plan: RoutePlan) -> tuple[str, bool]:
    deterministic = deterministic_selected_item_template(tool_result, metadata.language, plan.task_type)
    if deterministic:
        return _ensure_structured_evidence_block(deterministic, tool_result), False
    evidence = to_json_text(_payload(tool_result))
    prompt_language = metadata.answer_language if metadata.answer_language in {"en", "ru"} else "en"
    canonical_metadata = _metadata_with_answer_language(metadata, prompt_language)
    try:
        answer = await asyncio.wait_for(
            _call_ollama_with_language_retry(
                build_item_answer_messages(message, evidence, canonical_metadata, f"{plan.task_type}:{plan.detail_level or 'normal'}", plan.target_reference),
                canonical_metadata,
                task_type="remediation" if plan.task_type in REMEDIATION_TASKS else "explanation",
            ),
            timeout=SELECTED_ANSWER_TIMEOUT_SECONDS,
        )
        answer = clean_language_boilerplate(clean_answer_text(answer), canonical_metadata.language)
        if answer == fallback_answer(canonical_metadata.language) or is_bad_visible_answer(answer, canonical_metadata.language) or _looks_like_full_critical_list(answer):
            return _ensure_structured_evidence_block(_deterministic_item_answer(tool_result, canonical_metadata.language, plan.task_type), tool_result), False
        return _ensure_structured_evidence_block(_ensure_item_header(answer, tool_result, canonical_metadata.language), tool_result), True
    except (LLMError, TimeoutError, asyncio.TimeoutError):
        return _ensure_structured_evidence_block(_raw_evidence_fallback([tool_result], plan.task_type), tool_result), False


def deterministic_selected_item_template(tool_result: ToolResult, language: str, task_type: str) -> str | None:
    payload = _payload(tool_result)
    target_language = language if language in {"az", "en", "ru"} else "en"
    from backend.copilot.skill_renderers import render_known_finding_explanation, render_known_finding_remediation

    if task_type in REMEDIATION_TASKS:
        return render_known_finding_remediation(payload, target_language)
    return render_known_finding_explanation(payload, target_language)


async def generate_answer(message: str, tool_results: list[ToolResult], conversation_history: list[dict], metadata: LanguageIntent) -> str:
    if not tool_results:
        return fallback_answer("en")
    if any(result.tool_name == "get_findings_by_severity" for result in tool_results) and "alert" in normalize_message(message):
        rendered = _render_critical_findings(tool_results, "en", planner_requested_limit(message) or 5)
        if rendered:
            return rendered
    builder = ContextBuilder()
    try:
        context = builder.build(tool_results, conversation_history, message)
        history = builder.history_text(conversation_history)
    except ContextTooLargeError as exc:
        raise CopilotError("Context is too large for the local model.", "CONTEXT_TOO_LARGE") from exc
    if not context.strip():
        return fallback_answer("en")
    try:
        prompt_language = metadata.answer_language if metadata.answer_language in {"en", "ru"} else "en"
        canonical_metadata = _metadata_with_answer_language(metadata, prompt_language)
        messages = build_answer_messages(message, context, history, canonical_metadata)
        return await _call_ollama_with_language_retry(messages, canonical_metadata, task_type="short_answer")
    except LLMError:
        return _raw_evidence_fallback(tool_results)


async def generate_general_answer(message: str, conversation_history: list[dict], metadata: LanguageIntent) -> str:
    if metadata.intent == "capability_help" and is_azerbaijani_capability_question(message):
        return LANGUAGE_CAPABILITY_EN
    if is_explicit_azerbaijani_switch(message):
        return "I will answer in Azerbaijani."
    if is_explicit_english_switch(message):
        return "I will answer in English."
    builder = ContextBuilder()
    history = builder.minimal_history_text(conversation_history)
    prompt_language = metadata.answer_language if metadata.answer_language in {"en", "ru"} else "en"
    canonical_metadata = _metadata_with_answer_language(metadata, prompt_language)
    try:
        answer = await _call_ollama_with_language_retry(build_general_chat_messages(message, history, canonical_metadata), canonical_metadata, task_type="short_answer")
    except LLMError:
        return provider_unavailable_answer(canonical_metadata.language)
    return clean_language_boilerplate(clean_answer_text(answer), canonical_metadata.language) or fallback_answer(canonical_metadata.language)


async def _call_ollama_with_language_retry(messages: list[dict[str, str]], metadata: LanguageIntent, task_type: str = "general") -> str:
    answer = await call_ollama(messages, task_type=task_type)
    if not is_bad_visible_answer(answer, metadata.language):
        return answer
    language_name = {"az": "Azerbaijani", "ru": "Russian"}.get(metadata.language, "English")
    retry_messages = [
        *messages,
        {
            "role": "user",
            "content": (
                f"Rewrite the previous answer in {language_name} only. "
                "Remove all wrong-language boilerplate. Keep filenames, scan IDs, counts, and DSPM technical terms unchanged. "
                "No markdown headings and no debug footer."
            ),
        },
    ]
    retry = await call_ollama(retry_messages, task_type=task_type)
    return retry if not is_bad_visible_answer(retry, metadata.language) else fallback_answer(metadata.language)


async def _execute_single_skill(skill_id: str, principal: Principal, session_state: dict | None, scan_id: str | None, target_language: str, params: dict | None = None, message: str = "") -> StepResult:
    """Execute a single skill and return its result."""
    start = time.perf_counter()
    params = params or {}
    skill = DSPM_SKILL_REGISTRY.get(skill_id)
    if not skill:
        return StepResult(skill_id=skill_id, answer="", error="unknown_skill")

    try:
        if skill_id == "sk_critical_findings_list":
            severity = "CRITICAL"
            limit = params.get("requested_limit", 5)
            result = await _get_findings_by_severity_for_plan(principal, severity, limit=limit)
            result = role_filter(result, principal.role)
            payload = _payload(result)
            rendered = _render_critical_findings([result], target_language, limit)
            return StepResult(
                skill_id=skill_id, answer=rendered or fallback_answer(target_language),
                tool_results=[result], tools_used=["get_findings_by_severity"],
                sources=list(result.sources), elapsed_ms=int((time.perf_counter() - start) * 1000),
            )
        if skill_id == "sk_executive_dashboard":
            result = role_filter(await tools.get_executive_dashboard(principal), principal.role)
            payload = _payload(result)
            from backend.copilot.skill_renderers import render_executive_dashboard
            rendered = render_executive_dashboard(payload, target_language)
            return StepResult(
                skill_id=skill_id, answer=rendered,
                tool_results=[result], tools_used=["get_executive_dashboard"],
                sources=list(result.sources), elapsed_ms=int((time.perf_counter() - start) * 1000),
            )
        if skill_id == "sk_severity_distribution":
            result = role_filter(await tools.get_severity_distribution(principal, scan_id), principal.role)
            payload = _payload(result)
            rendered = _render_severity_distribution(payload, target_language)
            return StepResult(
                skill_id=skill_id, answer=rendered,
                tool_results=[result], tools_used=["get_severity_distribution"],
                sources=list(result.sources), elapsed_ms=int((time.perf_counter() - start) * 1000),
            )
        if skill_id == "sk_scan_comparison":
            result = role_filter(await tools.compare_scans(principal, 2), principal.role)
            payload = _payload(result)
            rendered = _render_scan_comparison(payload)
            return StepResult(
                skill_id=skill_id, answer=rendered,
                tool_results=[result], tools_used=["compare_scans"],
                sources=list(result.sources), elapsed_ms=int((time.perf_counter() - start) * 1000),
            )
        if skill_id == "sk_finding_detail":
            resolved_item = params.get("resolved_item")
            identifier = None
            if resolved_item:
                identifier = resolved_item.get("full_detail_ref") or resolved_item.get("safe_identifier") or resolved_item.get("name")
            if not identifier:
                identifier = params.get("target_entity")
            if not identifier:
                return StepResult(skill_id=skill_id, answer=_clarification_answer("en"), elapsed_ms=int((time.perf_counter() - start) * 1000))
            result = role_filter(await tools.get_finding_detail(principal, str(identifier), scan_id), principal.role)
            payload = _payload(result)
            from backend.copilot.skill_renderers import render_finding_detail
            rendered = render_finding_detail(payload, target_language)
            return StepResult(
                skill_id=skill_id, answer=rendered,
                tool_results=[result], tools_used=["get_finding_detail"],
                sources=list(result.sources), elapsed_ms=int((time.perf_counter() - start) * 1000),
            )
        if skill_id == "sk_report_generation":
            report_scope = repair.resolve_report_scope(message, session_state) if message else None
            try:
                artifact = await asyncio.to_thread(
                    create_report_artifact, principal, session_state, scan_id, None, scope=report_scope
                )
            except ArtifactError as exc:
                return StepResult(skill_id=skill_id, answer=f"Could not create report: {exc}", error="artifact_error", elapsed_ms=int((time.perf_counter() - start) * 1000))
            return StepResult(
                skill_id=skill_id, answer=_artifact_answer(artifact),
                elapsed_ms=int((time.perf_counter() - start) * 1000),
            )
        if skill_id == "sk_critical_filter":
            all_items = params.get("_all_previous_items") or []
            from backend.copilot.skill_renderers import render_critical_filter
            rendered = render_critical_filter(all_items, target_language)
            return StepResult(
                skill_id=skill_id, answer=rendered,
                tool_results=[], tools_used=[],
                elapsed_ms=int((time.perf_counter() - start) * 1000),
            )
        if skill_id == "sk_sort_by_time":
            all_items = params.get("_all_previous_items") or []
            from backend.copilot.skill_renderers import render_sort_by_time
            rendered = render_sort_by_time(all_items, target_language)
            return StepResult(
                skill_id=skill_id, answer=rendered,
                tool_results=[], tools_used=[],
                elapsed_ms=int((time.perf_counter() - start) * 1000),
            )
        if skill_id == "sk_teach_dspm":
            all_items = params.get("_all_previous_items") or []
            topic = params.get("topic")
            from backend.copilot.skill_renderers import render_teach_dspm
            rendered = render_teach_dspm(all_items, target_language, topic=topic)
            return StepResult(
                skill_id=skill_id, answer=rendered,
                tool_results=[], tools_used=[],
                elapsed_ms=int((time.perf_counter() - start) * 1000),
            )
        return StepResult(skill_id=skill_id, answer="", error="unimplemented_skill")
    except NoEvidenceError:
        return StepResult(skill_id=skill_id, answer=fallback_answer("en"), error="no_evidence", elapsed_ms=int((time.perf_counter() - start) * 1000))
    except Exception as exc:
        _log.warning("skill_execution_error skill=%s error=%s", skill_id, exc)
        return StepResult(skill_id=skill_id, answer=fallback_answer("en"), error=str(exc), elapsed_ms=int((time.perf_counter() - start) * 1000))


async def _execute_workflow(workflow: WorkflowPlan, principal: Principal, session_state: dict | None, scan_id: str | None, target_language: str, message: str = "") -> WorkflowResult:
    """Execute a multi-step workflow, chaining outputs between steps."""
    start = time.perf_counter()
    step_results: list[StepResult] = []

    for step in workflow.steps:
        params = resolve_step_dependency(step, step_results)
        result = await _execute_single_skill(step.skill_id, principal, session_state, scan_id, target_language, params, message)
        step_results.append(result)

    combined = combine_step_answers(step_results)
    total_llm = sum(1 for r in step_results if r.llm_called)
    elapsed = int((time.perf_counter() - start) * 1000)

    _log.info(
        "workflow_executed steps=%d llm_calls=%d elapsed_ms=%d skills=%s",
        len(step_results), total_llm, elapsed,
        [r.skill_id for r in step_results],
    )

    return WorkflowResult(
        steps=step_results,
        combined_answer=combined,
        total_elapsed_ms=elapsed,
        total_llm_calls=total_llm,
    )


async def handle_chat(
    message: str,
    principal: Principal,
    conversation_id: str | None,
    scan_id: str | None,
    selected_language: str | None = None,
    selected_language_source: str | None = None,
) -> ChatResponse:
    """Public entry point.

    Delegates to the full pipeline, then applies the terminal language validator
    as the last gate before returning: enforce the selected language on the final
    prose and re-mask sensitive text so masking stays active after polishing.
    """
    response = await _handle_chat_impl(
        message,
        principal,
        conversation_id,
        scan_id,
        selected_language,
        selected_language_source=selected_language_source,
    )
    if response.answer and response.language in SUPPORTED_RESPONSE_LANGUAGES:
        original = response.answer
        enforced = language_service.enforce_language(original, response.language)
        enforced = mask_sensitive_text(enforced)
        audit_fields = language_service.final_language_audit(enforced, response.language, original)
        session_state = await load_session_context(principal, response.conversation_id)
        metadata = dict(response.metadata or {})
        if "language_decision_response" not in metadata:
            language_decision = decide_language(
                message,
                selected_language=selected_language,
                selected_language_source=selected_language_source,
                session_state=session_state,
            )
            metadata.update(language_decision.to_metadata())
            metadata["selected_language_source"] = selected_language_source or "absent"
        metadata["language_validator"] = audit_fields
        metadata, _brainmap = response_brainmap.ensure_response_brainmap(
            metadata,
            message=message,
            language=response.language or "az",
            route_id=str(metadata.get("route_id") or metadata.get("brainmap_route_id") or "") or None,
            task_type=response.task_type,
            intent=response.intent,
            session_state=session_state,
            current_provider_final_allowed=bool(metadata.get("provider_final_called") or response.task_type == "general"),
            evidence_available=bool(response.sources or metadata.get("canonical_answer_used") or metadata.get("evidence_count")),
            scan_id=scan_id,
            source_label="response_sources" if response.sources else None,
        )
        force_block_reason = _controlled_verbalizer_runtime_block_reason(response, metadata, _brainmap)
        if force_block_reason:
            metadata["controlled_verbalizer_force_block_reason"] = force_block_reason
        verbalized = await controlled_verbalizer.finalize_brainmap_answer(
            answer=enforced,
            brainmap=_brainmap,
            metadata=metadata,
            conversation_state=session_state,
        )
        verbalized_answer = mask_sensitive_text(verbalized.text)
        original_provider_final_called = bool(metadata.get("provider_final_called", False))
        metadata.update(verbalized.metadata)
        metadata["provider_final_called"] = original_provider_final_called
        polish = conversation_polish.validate_final_answer(
            message=message,
            answer=verbalized_answer,
            language=response.language,
            metadata=metadata,
            session_state=session_state,
            task_type=response.task_type,
            intent=response.intent,
        )
        final_answer = mask_sensitive_text(polish.answer)
        metadata.update(polish.metadata)
        metadata["provider_final_called"] = original_provider_final_called
        if metadata.get("controlled_verbalizer_allowed"):
            next_session_state = controlled_verbalizer.fingerprint_update_payload(
                _brainmap,
                final_answer,
                session_state,
                variant_id=metadata.get("response_variant_id") or metadata.get("controlled_verbalizer_fallback_variant_id"),
                response_variant_seed=metadata.get("response_variant_seed"),
            )
            next_session_state["last_answer_summary"] = clean_answer_text(mask_sensitive_text(final_answer))[:500]
            next_session_state["last_answer_text"] = clean_answer_text(mask_sensitive_text(final_answer))[:1200]
            next_session_state["last_answer_language"] = response.language
            next_session_state = _normalize_conversation_state(next_session_state)
            await save_session_context(principal, response.conversation_id, next_session_state)
            metadata["controlled_verbalizer_fingerprint_saved"] = True
        response = response.model_copy(update={"answer": final_answer, "metadata": metadata})
    return response


async def _handle_chat_impl(
    message: str,
    principal: Principal,
    conversation_id: str | None,
    scan_id: str | None,
    selected_language: str | None = None,
    selected_language_source: str | None = None,
) -> ChatResponse:
    start = time.perf_counter()
    conv_id = conversation_id or memory.new_conversation_id()
    session_lock = await _get_session_lock(principal, conv_id)
    await session_lock.acquire()
    intent_value = "general"
    used_tools: list[str] = []
    sources: list[SourceRef] = []
    t_planner_done: float | None = None
    t_tools_done: float | None = None
    t_workflow_done: float | None = None
    t_provider_done: float | None = None
    t_translation_done: float | None = None
    t_rendering_done: float | None = None
    audit_language_token = None
    try:
        validate_input(message, principal)
        history = await memory.load_history(principal.tenant_id, conv_id)
        metadata = analyze_message(message)
        language_understanding = understand_message(message)
        language_understanding_audit = language_understanding_audit_metadata(language_understanding)
        session_state = await load_session_context(principal, conv_id)
        language_decision = decide_language(
            message,
            selected_language=selected_language,
            selected_language_source=selected_language_source,
            session_state=session_state,
        )
        target_language = language_decision.response_language
        language_source = language_decision.source
        language_decision_meta = language_decision.to_metadata()
        session_state = _with_selected_language_metadata(
            session_state,
            principal,
            conv_id,
            target_language,
            selected_language,
            language_source,
            selected_language_source=selected_language_source,
        )
        audit_language_token = audit.set_language_context(
            selected_language=session_state.get("selected_language"),
            response_language=target_language,
            language_source=language_source,
        )
        canonical_prompt_language = target_language if target_language in {"en", "ru"} else "en"
        canonical_metadata = _metadata_with_answer_language(metadata, canonical_prompt_language)
        message_id = f"msg-{uuid.uuid4().hex[:16]}"

        file_query = file_queries.parse_file_query(message, session_state)
        if file_query is not None:
            try:
                tool_result = await tools.query_files(
                    principal,
                    extension=file_query.extension,
                    severity=file_query.severity,
                    limit=file_query.limit,
                )
                tool_result = role_filter(tool_result, principal.role)
                payload = _payload(tool_result)
                file_sources = list(tool_result.sources)
                file_tools = [tool_result.tool_name]
            except NoEvidenceError:
                payload = {
                    "scan_id": None,
                    "evidence_available": False,
                    "count": 0,
                    "items": [],
                    "extension_counts": {},
                }
                file_sources = []
                file_tools = []
            answer = file_queries.render_file_query(file_query, payload)
            answer = validate_output(answer, principal, [tool_result] if file_tools else [])
            await memory.save_turn(
                principal.tenant_id,
                conv_id,
                message,
                answer,
                file_tools,
                [source.model_dump() for source in file_sources],
            )
            next_session_state = dict(session_state or {})
            state_action = file_query.action
            if state_action == file_queries.FILE_QUERY_EXPLANATION:
                previous_query = (session_state or {}).get("last_file_query")
                if isinstance(previous_query, dict):
                    state_action = str(previous_query.get("action") or file_queries.FILE_QUERY_LIST)
            query_state = file_query.state_payload()
            query_state.update({
                "action": state_action,
                "result_count": int(payload.get("count") or 0),
                "returned": int(payload.get("returned") or 0),
                "scan_id": payload.get("scan_id"),
                "evidence_available": bool(payload.get("evidence_available", True)),
            })
            next_session_state.update({
                "last_file_query": query_state,
                "last_task_type": "file_query",
                "last_answer_type": f"file_query_{state_action}",
                "last_result_type": "file_query",
                "last_scan_id": payload.get("scan_id"),
                "last_answer_text": answer[:1200],
                "last_answer_summary": answer[:500],
            })
            # A file *list* result is the reportable scope a later "give me that
            # as a pdf report" / bare "pdf" must export — preserving severity,
            # extension, and the top-N limit that was just shown.
            if state_action == file_queries.FILE_QUERY_LIST and payload.get("evidence_available", True):
                scope_severity = str(file_query.severity or "").upper()
                scope_extension = file_query.extension
                scope_limit = max(0, int(file_query.limit or 0))
                if scope_extension:
                    base = f"{scope_severity} {scope_extension} files".strip() if scope_severity else f"{scope_extension} files"
                    reportable: dict = {"kind": "extension", "extension": scope_extension, "label": base}
                    if scope_severity:
                        reportable["severities"] = [scope_severity]
                elif scope_severity:
                    reportable = {"kind": "severity", "severities": [scope_severity], "label": scope_severity}
                else:
                    reportable = {"kind": "full", "label": "Full scan"}
                if scope_limit > 0:
                    reportable["limit"] = scope_limit
                    base_label = reportable["label"] if reportable["kind"] != "full" else "files"
                    reportable["label"] = f"Top {scope_limit} {base_label}"
                next_session_state["last_reportable_scope"] = reportable
            if file_query.correction:
                next_session_state.update(correction_controller.correction_state_effects(
                    correction_controller.resolve_correction(message, session_state), message
                ))
            next_session_state = _with_language_preference(
                next_session_state, principal, conv_id, target_language, message
            )
            await save_session_context(principal, conv_id, _normalize_conversation_state(next_session_state))
            if file_query.explain_previous:
                task_type = "file_query_explanation"
            elif file_query.correction:
                task_type = "file_query_correction"
            else:
                task_type = f"file_query_{file_query.action}"
            total_ms = _elapsed_ms(start)
            await audit.log_interaction(
                principal, conv_id, len(message), "file_query", file_tools,
                {"query_files": int(payload.get("count") or 0)}, len(answer), total_ms,
                len(file_sources), None, target_language,
                task_type=task_type,
                provider_planning_called=False,
                provider_final_called=False,
                final_answer_mode="deterministic_file_query",
                provider_call_count=0,
                translator_called=False,
                language_understanding=language_understanding_audit,
                route_id="file_query",
                answer_type=task_type,
            )
            return ChatResponse(
                answer=answer,
                intent="file_query",
                task_type=task_type,
                language=target_language,
                sources=file_sources,
                tools_used=file_tools,
                conversation_id=conv_id,
                message_id=message_id,
                session_context_summary=_session_summary(next_session_state),
                metadata={
                    **language_decision_meta,
                    "route_id": "file_query",
                    "answer_type": task_type,
                    "provider_planning_called": False,
                    "provider_final_called": False,
                    "structured_renderer_used": True,
                    "evidence_count": int(payload.get("count") or 0),
                },
            )

        # Deterministic model-status route: always zero-provider; reads the local
        # circuit-breaker state instead of pinging the model.
        if provider_health.is_model_status_question(message):
            unhealthy = provider_health.is_unhealthy()
            status_answer = _model_status_answer(target_language, unhealthy)
            return await _meta_no_provider_response(
                principal=principal, conv_id=conv_id, message=message, answer=status_answer,
                intent="model_status", task_type="model_status", language=target_language,
                session_state=session_state, selected_language=selected_language,
                language_source=language_source, message_id=message_id, start=start,
                language_understanding_audit=language_understanding_audit,
                audit_extra={
                    **provider_health.snapshot(skip_reason="model_status_route"),
                    **llm_client.model_metadata(),
                    "route_id": "model_status",
                    "answer_type": "model_status",
                },
            )

        selected_followup_response = await _handle_selected_finding_remediation_followup(
            principal=principal,
            conv_id=conv_id,
            message=message,
            language=target_language,
            session_state=session_state,
            scan_id=scan_id,
            selected_language=selected_language,
            language_source=language_source,
            message_id=message_id,
            start=start,
            language_understanding_audit=language_understanding_audit,
        )
        if selected_followup_response is not None:
            return selected_followup_response

        routing_outcome = routing_authority.decide(
            message=message,
            normalized_message=(language_understanding.canonical_text_candidates[0] if language_understanding.canonical_text_candidates else language_understanding.normalized_text),
            target_language=target_language,
            session_state=session_state,
            principal=principal,
            scan_id=scan_id,
            selected_language=selected_language,
            canonical_language=canonical_prompt_language,
        )
        situation_context = routing_outcome.situation_context
        situation_decision = routing_outcome.situation_decision
        dispatch_decision = routing_outcome.dispatch_decision
        if routing_outcome.task_frame_compatible:
            task_frame_response = await _handle_task_frame_resolution(
                message=message,
                principal=principal,
                conv_id=conv_id,
                scan_id=scan_id,
                session_state=session_state,
                target_language=target_language,
                selected_language=selected_language,
                language_source=language_source,
                message_id=message_id,
                start=start,
                language_understanding_audit=language_understanding_audit,
            )
            if task_frame_response is not None:
                return task_frame_response
        pre_render_meta = {**_route_dispatch_audit_fields(dispatch_decision), **language_decision_meta}
        pre_brainmap = response_brainmap.build_response_brainmap(
            message=message,
            language=target_language,
            metadata=pre_render_meta,
            route_id=dispatch_decision.route_id if dispatch_decision is not None else None,
            task_type=dispatch_decision.answer_type if dispatch_decision is not None else None,
            intent=intent_value,
            session_state=session_state,
            current_provider_final_allowed=False,
            scan_id=scan_id,
            language_source=language_source,
            language_confidence=language_decision.confidence,
        )
        p4a_policy_subtypes = {
            "response_too_long_feedback",
            "response_too_short_feedback",
            "repeated_answer_complaint",
            "clarify_previous_response",
            "explain_previous_response",
        }
        if (
            pre_brainmap.situation.family == response_brainmap.BrainmapFamily.ASSISTANT_BEHAVIOR_META
            and pre_brainmap.situation.subtype in p4a_policy_subtypes
        ):
            answer = response_brainmap.deterministic_policy_answer(pre_brainmap, target_language)
            response_session_state = dict(session_state or {})
            if pre_brainmap.situation.subtype == "response_too_long_feedback":
                response_session_state["preferred_verbosity"] = "short"
            elif pre_brainmap.situation.subtype == "response_too_short_feedback":
                response_session_state["preferred_verbosity"] = "detailed"
            brainmap_meta = response_brainmap.brainmap_to_metadata(pre_brainmap)
            return await _meta_no_provider_response(
                principal=principal,
                conv_id=conv_id,
                message=message,
                answer=answer,
                intent="correction",
                task_type=pre_brainmap.situation.subtype,
                language=target_language,
                session_state=response_session_state,
                selected_language=selected_language,
                language_source=language_source,
                message_id=message_id,
                start=start,
                language_understanding_audit=language_understanding_audit,
                audit_extra={
                    **pre_render_meta,
                    **brainmap_meta,
                    "route_id": "assistant_behavior_meta",
                    "answer_type": pre_brainmap.situation.subtype,
                    "fallback_family": "assistant_behavior_meta",
                },
            )
        if dispatch_decision is not None:
            dispatch_audit = _route_dispatch_audit_fields(dispatch_decision)
            if dispatch_decision.handler_name == "p0_situation_guardrail":
                p0_response = await _handle_p0_situation_guardrail(
                    message=message,
                    principal=principal,
                    conv_id=conv_id,
                    scan_id=scan_id,
                    session_state=session_state,
                    target_language=target_language,
                    selected_language=selected_language,
                    language_source=language_source,
                    message_id=message_id,
                    start=start,
                    language_understanding_audit=language_understanding_audit,
                    dispatch_decision=dispatch_decision,
                )
                if p0_response is not None:
                    return p0_response
            if dispatch_decision.route_id == "product_help":
                product_help_response = await _handle_product_help(
                    message=message,
                    principal=principal,
                    conv_id=conv_id,
                    scan_id=scan_id,
                    session_state=session_state,
                    target_language=target_language,
                    selected_language=selected_language,
                    language_source=language_source,
                    message_id=message_id,
                    start=start,
                    language_understanding_audit=language_understanding_audit,
                    dispatch_decision=dispatch_decision,
                )
                if product_help_response is not None:
                    return product_help_response
            if dispatch_decision.route_id == "previous_answer_rerender_or_condense":
                if dispatch_decision.answer_type == "condense_previous":
                    professional_response = await _handle_professional_followup(
                        intent=prof.CONDENSE,
                        principal=principal,
                        conv_id=conv_id,
                        message=message,
                        language=target_language,
                        session_state=session_state,
                        scan_id=scan_id,
                        selected_language=selected_language,
                        language_source=language_source,
                        message_id=message_id,
                        start=start,
                        language_understanding_audit=language_understanding_audit,
                        dispatch_decision=dispatch_decision,
                    )
                    if professional_response is not None:
                        return professional_response
                else:
                    render_language = str(dispatch_decision.metadata.get("requested_language") or target_language)
                    answer, rerender_audit = _rerender_previous_answer(session_state, history, render_language)
                    next_session_state = _with_selected_language_metadata(session_state, principal, conv_id, render_language, selected_language, language_source)
                    next_session_state = _with_language_preference(next_session_state, principal, conv_id, render_language, message)
                    await save_session_context(principal, conv_id, next_session_state)
                    await memory.save_turn(principal.tenant_id, conv_id, message, answer, [], [])
                    total_ms = _elapsed_ms(start)
                    await audit.log_interaction(
                        principal, conv_id, len(message), "translate_previous_answer", [], {}, len(answer),
                        total_ms, 0, None, render_language,
                        task_type="rerender_previous_answer",
                        provider_planning_called=False,
                        provider_final_called=False,
                        final_answer_mode="previous_answer_rerender",
                        provider_call_count=0,
                        translator_called=False,
                        provider_translation_called=False,
                        language_understanding=language_understanding_audit,
                        elapsed_ms_total=total_ms,
                        **rerender_audit,
                        **dispatch_audit,
                    )
                    return ChatResponse(
                        answer=answer,
                        intent="translate_previous_answer",
                        task_type="rerender_previous_answer",
                        language=render_language,
                        sources=[],
                        tools_used=[],
                        conversation_id=conv_id,
                        message_id=message_id,
                        session_context_summary=_session_summary(next_session_state),
                        metadata=_response_metadata({"total_ms": total_ms, "route": "previous_answer_rerender"}, dispatch_audit),
                    )
            if dispatch_decision.route_id == "language_complaint":
                answer = language_service.localized_language_complaint_answer(
                    target_language,
                    has_previous_answer=bool((session_state or {}).get("last_answer_text")),
                )
                return await _meta_no_provider_response(
                    principal=principal,
                    conv_id=conv_id,
                    message=message,
                    answer=answer,
                    intent="language_complaint",
                    task_type="language_complaint",
                    language=target_language,
                    session_state=session_state,
                    selected_language=selected_language,
                    language_source=language_source,
                    message_id=message_id,
                    start=start,
                    language_understanding_audit=language_understanding_audit,
                    audit_extra=dispatch_audit,
                )
            if dispatch_decision.route_id == "count_conflict_or_why_previous_answer":
                if dispatch_decision.metadata.get("count_conflict"):
                    answer = _render_count_conflict_explanation(message, session_state, principal, scan_id, target_language)
                    severity, count_value, resolved_scan_id = _count_conflict_context(message, session_state, principal, scan_id)
                    canonical_answer = canonical_answer_for_count(
                        {"scan_id": resolved_scan_id, "result_type": "finding_count", "severity": severity, "count": count_value if count_value is not None else 0},
                        answer,
                        target_language,
                    )
                    answer = render_canonical_answer(canonical_answer, target_language)
                    canonical_answer = canonical_answer_for_count(
                        {"scan_id": resolved_scan_id, "result_type": "finding_count", "severity": severity, "count": count_value if count_value is not None else 0},
                        answer,
                        target_language,
                    )
                    return await _meta_no_provider_response(
                        principal=principal,
                        conv_id=conv_id,
                        message=message,
                        answer=answer,
                        intent="count_conflict_explanation",
                        task_type="count_conflict_explanation",
                        language=target_language,
                        session_state=session_state,
                        selected_language=selected_language,
                        language_source=language_source,
                        message_id=message_id,
                        start=start,
                        language_understanding_audit=language_understanding_audit,
                        canonical_answer=canonical_answer,
                        audit_extra=dispatch_audit,
                        extra_state=correction_controller.correction_state_effects(
                            correction_controller.resolve_correction(message, session_state), message
                        ),
                    )
                answer = _render_why_previous_answer(message, target_language)
                correction_decision = correction_controller.resolve_correction(message, session_state)
                return await _meta_no_provider_response(
                    principal=principal,
                    conv_id=conv_id,
                    message=message,
                    answer=answer,
                    intent="why_previous_answer",
                    task_type="why_previous_answer",
                    language=target_language,
                    session_state=session_state,
                    selected_language=selected_language,
                    language_source=language_source,
                    message_id=message_id,
                    start=start,
                    language_understanding_audit=language_understanding_audit,
                    audit_extra=dispatch_audit,
                    extra_state=correction_controller.correction_state_effects(correction_decision, message),
                )
            if dispatch_decision.route_id == "wrong_route_complaint" and not dispatch_decision.metadata.get("repair_why_misunderstood"):
                answer, correction_tools = _wrong_route_complaint_answer(message, principal, scan_id, target_language)
                correction_decision = correction_controller.resolve_correction(message, session_state)
                return await _meta_no_provider_response(
                    principal=principal,
                    conv_id=conv_id,
                    message=message,
                    answer=answer,
                    intent="complaint_about_wrong_route",
                    task_type="complaint_about_wrong_route",
                    language=target_language,
                    session_state=session_state,
                    selected_language=selected_language,
                    language_source=language_source,
                    message_id=message_id,
                    start=start,
                    language_understanding_audit=language_understanding_audit,
                    audit_extra=dispatch_audit,
                    tools_used=correction_tools,
                    extra_state=correction_controller.correction_state_effects(correction_decision, message),
                    clear_selected_finding=bool(correction_decision and correction_decision.clear_selected_finding),
                )
            if dispatch_decision.handler_name == "conversation_repair":
                repair_response = await _handle_conversation_repair(
                    message=message,
                    principal=principal,
                    conv_id=conv_id,
                    scan_id=scan_id,
                    session_state=session_state,
                    target_language=target_language,
                    selected_language=selected_language,
                    language_source=language_source,
                    message_id=message_id,
                    start=start,
                    language_understanding_audit=language_understanding_audit,
                    dispatch_decision=dispatch_decision,
                )
                if repair_response is not None:
                    return repair_response
            if dispatch_decision.handler_name == "professional_followup":
                professional_intent = str(dispatch_decision.metadata.get("professional_intent") or "")
                professional_response = await _handle_professional_followup(
                    intent=professional_intent,
                    principal=principal,
                    conv_id=conv_id,
                    message=message,
                    language=target_language,
                    session_state=session_state,
                    scan_id=scan_id,
                    selected_language=selected_language,
                    language_source=language_source,
                    message_id=message_id,
                    start=start,
                    language_understanding_audit=language_understanding_audit,
                    dispatch_decision=dispatch_decision,
                )
                if professional_response is not None:
                    return professional_response

        # Prompt 7: previous-answer re-render — do this before any retrieval.
        rerender_matched, requested_render_language = _detect_previous_answer_rerender(message)
        if rerender_matched:
            render_language = requested_render_language or target_language
            answer, rerender_audit = _rerender_previous_answer(session_state, history, render_language)
            next_session_state = _with_selected_language_metadata(session_state, principal, conv_id, render_language, selected_language, language_source)
            next_session_state = _with_language_preference(next_session_state, principal, conv_id, render_language, message)
            await save_session_context(principal, conv_id, next_session_state)
            await memory.save_turn(principal.tenant_id, conv_id, message, answer, [], [])
            total_ms = _elapsed_ms(start)
            await audit.log_interaction(
                principal, conv_id, len(message), "translate_previous_answer", [], {}, len(answer),
                total_ms, 0, None, render_language,
                task_type="rerender_previous_answer",
                provider_planning_called=False,
                provider_final_called=False,
                final_answer_mode="previous_answer_rerender",
                provider_call_count=0,
                translator_called=False,
                provider_translation_called=False,
                language_understanding=language_understanding_audit,
                elapsed_ms_total=total_ms,
                **rerender_audit,
            )
            return ChatResponse(
                answer=answer, intent="translate_previous_answer", task_type="rerender_previous_answer",
                language=render_language, sources=[], tools_used=[], conversation_id=conv_id,
                message_id=message_id, session_context_summary=_session_summary(next_session_state),
                metadata=_debug_metadata({"total_ms": total_ms, "route": "previous_answer_rerender"}),
            )

        # Prompt 7: language complaint — apologize in the selected language, no retrieval.
        if _detect_language_complaint(message):
            answer = language_service.localized_language_complaint_answer(
                target_language,
                has_previous_answer=bool((session_state or {}).get("last_answer_text")),
            )
            next_session_state = _with_selected_language_metadata(session_state, principal, conv_id, target_language, selected_language, language_source)
            next_session_state = _with_language_preference(next_session_state, principal, conv_id, target_language, message)
            await save_session_context(principal, conv_id, next_session_state)
            await memory.save_turn(principal.tenant_id, conv_id, message, answer, [], [])
            total_ms = _elapsed_ms(start)
            await audit.log_interaction(
                principal, conv_id, len(message), "language_complaint", [], {}, len(answer),
                total_ms, 0, None, target_language,
                task_type="language_complaint",
                provider_planning_called=False,
                provider_final_called=False,
                final_answer_mode="language_complaint",
                provider_call_count=0,
                translator_called=False,
                language_understanding=language_understanding_audit,
                elapsed_ms_total=total_ms,
            )
            return ChatResponse(
                answer=answer, intent="language_complaint", task_type="language_complaint",
                language=target_language, sources=[], tools_used=[], conversation_id=conv_id,
                message_id=message_id, session_context_summary=_session_summary(next_session_state),
                metadata=_debug_metadata({"total_ms": total_ms, "route": "language_complaint"}),
            )

        if _detect_count_conflict_explanation(message):
            answer = _render_count_conflict_explanation(message, session_state, principal, scan_id, target_language)
            severity, count_value, resolved_scan_id = _count_conflict_context(message, session_state, principal, scan_id)
            canonical_answer = canonical_answer_for_count(
                {
                    "scan_id": resolved_scan_id,
                    "result_type": "finding_count",
                    "severity": severity,
                    "count": count_value if count_value is not None else 0,
                },
                answer,
                target_language,
            )
            answer = render_canonical_answer(canonical_answer, target_language)
            canonical_answer = canonical_answer_for_count(
                {
                    "scan_id": resolved_scan_id,
                    "result_type": "finding_count",
                    "severity": severity,
                    "count": count_value if count_value is not None else 0,
                },
                answer,
                target_language,
            )
            return await _meta_no_provider_response(
                principal=principal,
                conv_id=conv_id,
                message=message,
                answer=answer,
                intent="count_conflict_explanation",
                task_type="count_conflict_explanation",
                language=target_language,
                session_state=session_state,
                selected_language=selected_language,
                language_source=language_source,
                message_id=message_id,
                start=start,
                language_understanding_audit=language_understanding_audit,
                canonical_answer=canonical_answer,
                extra_state=correction_controller.correction_state_effects(
                    correction_controller.resolve_correction(message, session_state), message
                ),
            )

        if _detect_complaint_about_wrong_route(message):
            answer, correction_tools = _wrong_route_complaint_answer(message, principal, scan_id, target_language)
            correction_decision = correction_controller.resolve_correction(message, session_state)
            return await _meta_no_provider_response(
                principal=principal,
                conv_id=conv_id,
                message=message,
                answer=answer,
                intent="complaint_about_wrong_route",
                task_type="complaint_about_wrong_route",
                language=target_language,
                session_state=session_state,
                selected_language=selected_language,
                language_source=language_source,
                message_id=message_id,
                start=start,
                language_understanding_audit=language_understanding_audit,
                tools_used=correction_tools,
                extra_state=correction_controller.correction_state_effects(correction_decision, message),
                clear_selected_finding=bool(correction_decision and correction_decision.clear_selected_finding),
            )

        if _detect_why_previous_answer(message):
            answer = _render_why_previous_answer(message, target_language)
            correction_decision = correction_controller.resolve_correction(message, session_state)
            return await _meta_no_provider_response(
                principal=principal,
                conv_id=conv_id,
                message=message,
                answer=answer,
                intent="why_previous_answer",
                task_type="why_previous_answer",
                language=target_language,
                session_state=session_state,
                selected_language=selected_language,
                language_source=language_source,
                message_id=message_id,
                start=start,
                language_understanding_audit=language_understanding_audit,
                extra_state=correction_controller.correction_state_effects(correction_decision, message),
            )

        repair_response = await _handle_conversation_repair(
            message=message,
            principal=principal,
            conv_id=conv_id,
            scan_id=scan_id,
            session_state=session_state,
            target_language=target_language,
            selected_language=selected_language,
            language_source=language_source,
            message_id=message_id,
            start=start,
            language_understanding_audit=language_understanding_audit,
        )
        if repair_response is not None:
            return repair_response

        professional_intent = prof.detect_professional_followup(message, session_state)
        if professional_intent is not None:
            professional_response = await _handle_professional_followup(
                intent=professional_intent,
                principal=principal,
                conv_id=conv_id,
                message=message,
                language=target_language,
                session_state=session_state,
                scan_id=scan_id,
                selected_language=selected_language,
                language_source=language_source,
                message_id=message_id,
                start=start,
                language_understanding_audit=language_understanding_audit,
            )
            if professional_response is not None:
                return professional_response

        contract_route = route_message(message, session_state)
        if target_language in SUPPORTED_RESPONSE_LANGUAGES:
            contract_route = replace(contract_route, language=target_language)
        heuristic_for_gate = heuristic_plan(message, metadata, session_state)
        planner_required = should_use_ai_planner(message, heuristic_for_gate, session_state, contract_route)
        # While the provider circuit is open, never invoke the AI planner (it would
        # only hit the open breaker); deterministic routes still work below.
        if planner_required and provider_health.circuit_open():
            planner_required = False
        if _is_another_one_followup(message) and not _has_selection_context(session_state):
            answer = _another_one_clarification(target_language)
            next_session_state = _with_selected_language_metadata(session_state, principal, conv_id, target_language, selected_language, language_source)
            next_session_state = _with_language_preference(next_session_state, principal, conv_id, target_language, message)
            await save_session_context(principal, conv_id, next_session_state)
            await memory.save_turn(principal.tenant_id, conv_id, message, answer, [], [])
            total_ms = _elapsed_ms(start)
            await audit.log_interaction(
                principal, conv_id, len(message), "followup_another_one", [], {}, len(answer),
                total_ms, 0, None, target_language,
                task_type="clarification",
                provider_planning_called=False,
                provider_final_called=False,
                final_answer_mode="followup_clarification",
                provider_call_count=0,
                translator_called=False,
                language_understanding=language_understanding_audit,
                elapsed_ms_total=total_ms,
            )
            return ChatResponse(
                answer=answer,
                intent="followup_another_one",
                task_type="clarification",
                language=target_language,
                sources=[],
                tools_used=[],
                conversation_id=conv_id,
                message_id=message_id,
                session_context_summary=_session_summary(next_session_state),
                metadata=_debug_metadata({"total_ms": total_ms, "route": "followup_clarification"}),
            )
        deterministic_situation = _deterministic_situation_answer(situation_decision, target_language)
        if dispatch_decision is None and deterministic_situation is not None:
            answer, deterministic_intent, deterministic_task = deterministic_situation
            return await _meta_no_provider_response(
                principal=principal,
                conv_id=conv_id,
                message=message,
                answer=answer,
                intent=deterministic_intent,
                task_type=deterministic_task,
                language=target_language,
                session_state=session_state,
                selected_language=selected_language,
                language_source=language_source,
                message_id=message_id,
                start=start,
                language_understanding_audit=language_understanding_audit,
                audit_extra=situation_decision.to_route_metadata() if situation_decision is not None else {},
            )
        if not planner_required:
            contract_response = await _handle_contract_route(
                contract_route,
                message,
                principal,
                conv_id,
                scan_id,
                session_state,
                message_id,
                start,
                selected_language=selected_language,
                language_source=language_source,
                language_understanding_audit=language_understanding_audit,
                situation_decision=situation_decision,
            )
            if contract_response is not None:
                return contract_response
        canned_answer = None if planner_required else get_canned_response(message, target_language, session_id=conv_id)
        if canned_answer:
            verbalizer_result = await _verbalize_canned_social_draft(
                safe_draft=canned_answer,
                situation_decision=situation_decision,
                target_language=target_language,
                conversation_id=conv_id,
            )
            verbalizer_audit = verbalizer_result.metadata if verbalizer_result is not None else {}
            final_answer = verbalizer_result.text if verbalizer_result is not None else canned_answer
            total_ms = _elapsed_ms(start)
            timings = {"total_ms": total_ms, "route": "canned"}
            if is_unsupported_language_message(message):
                intent_value = "unclear"
                task_value = "unsupported_language"
                target_language = "az" if target_language == "az" else "en"
            else:
                intent_value = metadata.intent if metadata.intent in {"small_talk", "capability_help", "complaint_or_misunderstanding"} else "small_talk"
                task_value = "complaint" if intent_value == "complaint_or_misunderstanding" else intent_value
            next_session_state = _with_selected_language_metadata(session_state, principal, conv_id, target_language, selected_language, language_source)
            next_session_state = _with_language_preference(next_session_state, principal, conv_id, target_language, message)
            await save_session_context(principal, conv_id, next_session_state)
            await memory.save_turn(principal.tenant_id, conv_id, message, final_answer, [], [])
            provider_call_count = int(verbalizer_audit.get("verbalizer_call_count") or 0)
            final_answer_mode = "fast_verbalizer" if verbalizer_audit.get("fast_verbalizer_used") else "canned_variant"
            await audit.log_interaction(
                principal, conv_id, len(message), intent_value, [], {}, len(final_answer),
                total_ms, 0, None, target_language,
                task_type=task_value,
                provider_planning_called=False,
                provider_final_called=False,
                final_answer_mode=final_answer_mode,
                provider_call_count=provider_call_count,
                translator_called=False,
                language_understanding=language_understanding_audit,
                elapsed_ms_total=total_ms,
                **verbalizer_audit,
            )
            return ChatResponse(
                answer=final_answer,
                intent=intent_value,
                task_type=task_value,
                language=target_language,
                sources=[],
                tools_used=[],
                conversation_id=conv_id,
                message_id=message_id,
                session_context_summary=_session_summary(next_session_state),
                metadata=_response_metadata(timings, verbalizer_audit, answer=final_answer),
            )
        if dispatch_decision is None and _should_run_runtime_situation_arbiter(
            message=message,
            situation_decision=situation_decision,
            situation_context=situation_context,
            contract_route=contract_route,
            heuristic_for_gate=heuristic_for_gate,
            planner_required=planner_required,
        ):
            arbiter_response = await _handle_unknown_situation_arbiter(
                principal=principal,
                conv_id=conv_id,
                message=message,
                target_language=target_language,
                session_state=session_state,
                selected_language=selected_language,
                language_source=language_source,
                message_id=message_id,
                start=start,
                language_understanding_audit=language_understanding_audit,
                situation_context=situation_context,
                situation_decision=situation_decision,
            )
            if arbiter_response is not None:
                return arbiter_response
        if _is_another_one_followup(message) and _has_selection_context(session_state):
            plan = heuristic_for_gate
        else:
            plan = await plan_request(message, session_state)
        t_planner_done = time.perf_counter()
        intent_value = plan.intent
        if plan.plan_fixup:
            fixup_payload = dict(plan.plan_fixup)
            fixup_payload.update({"conversation_id": conv_id, "message_id": message_id})
            await audit.log_plan_fixup(principal, fixup_payload)

        workflow = plan_workflow(message, plan.task_type, session_state)
        if workflow and workflow.is_compound:
            workflow_result = await _execute_workflow(workflow, principal, session_state, scan_id, target_language, message)
            workflow_tool_results = [tool_result for step in workflow_result.steps for tool_result in step.tool_results]
            canonical_answer = validate_output(workflow_result.combined_answer, principal, workflow_tool_results)
            answer = await _finalize_visible_answer(
                canonical_answer,
                target_language,
                source_language=target_language if target_language == "az" else None,
            )
            used_tools = merge_tools_used(workflow_result.steps)
            sources = merge_sources(workflow_result.steps)
            next_session_state = build_context(principal, conv_id, intent_value, target_language, workflow_tool_results, answer)
            next_session_state = _merge_previous_list_context(next_session_state, session_state)
            next_session_state = _merge_language_lock(next_session_state, session_state)
            next_session_state = _with_language_preference(next_session_state, principal, conv_id, target_language, message)
            await save_session_context(principal, conv_id, next_session_state)
            await memory.save_turn(principal.tenant_id, conv_id, message, answer, used_tools, [source.model_dump() for source in sources if isinstance(source, SourceRef)])
            skill_names = [step.skill_id for step in workflow_result.steps]
            provider_call_count = (1 if workflow_result.total_llm_calls > 0 else 0) + (1 if plan.provider_planning_called else 0)
            elapsed_ms_total = int((time.perf_counter() - start) * 1000)
            await audit.log_interaction(
                principal, conv_id, len(message), intent_value, used_tools, {}, len(answer),
                elapsed_ms_total, len(sources), None, target_language,
                task_type=plan.task_type,
                provider_planning_called=plan.provider_planning_called,
                provider_final_called=workflow_result.total_llm_calls > 0,
                final_answer_mode="compound_workflow",
                provider_call_count=provider_call_count,
                translator_called=False,
                is_compound=True,
                workflow_step_count=len(workflow_result.steps),
                skill_names=skill_names,
                teaching_mode="sk_teach_dspm" in skill_names,
                teaching_topic="finding_remediation" if "sk_teach_dspm" in skill_names else None,
                tasks_dropped=[],
                elapsed_ms_total=elapsed_ms_total,
                elapsed_ms_workflow=workflow_result.total_elapsed_ms,
                elapsed_ms_rendering=int((time.perf_counter() - start) * 1000) - workflow_result.total_elapsed_ms if workflow_result.total_elapsed_ms else None,
                **_planner_audit_metadata(plan),
            )
            return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=target_language, sources=[s for s in sources if isinstance(s, SourceRef)], tools_used=used_tools, conversation_id=conv_id, message_id=message_id, session_context_summary=_session_summary(next_session_state))

        if plan.task_type == "teaching":
            text = normalize_message(message)
            topic = "private_key" if "private key" in text or "private_key" in text else "secret"
            from backend.copilot.skill_renderers import render_teach_dspm
            teaching_language = (
                plan.response_language
                if selected_language is None and plan.response_language in SUPPORTED_RESPONSE_LANGUAGES
                else target_language
            )
            render_language = teaching_language if teaching_language == "az" else "en"
            canonical_answer = render_teach_dspm([], render_language, topic=topic)
            answer = await _finalize_visible_answer(
                clean_answer_text(canonical_answer),
                teaching_language,
                source_language="az" if render_language == "az" else None,
            )
            next_session_state = _with_language_preference(session_state, principal, conv_id, teaching_language, message)
            next_session_state["last_intent"] = "teaching"
            next_session_state["last_teaching_topic"] = topic
            await save_session_context(principal, conv_id, next_session_state)
            await memory.save_turn(principal.tenant_id, conv_id, message, answer, [], [])
            _trace_plan(conv_id, message, plan, [], False, False, "teaching")
            await audit.log_interaction(
                principal, conv_id, len(message), intent_value, [], {}, len(answer),
                int((time.perf_counter() - start) * 1000), 0, None, teaching_language,
                task_type=plan.task_type,
                provider_planning_called=False,
                provider_final_called=False,
                final_answer_mode="teaching",
                provider_call_count=0,
                translator_called=False,
                teaching_mode=True,
                teaching_topic=topic,
            )
            return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=teaching_language, sources=[], tools_used=[], conversation_id=conv_id, message_id=message_id, session_context_summary=_session_summary(next_session_state))

        if _artifact_lookup_requested(message):
            artifact = (session_state or {}).get("latest_artifact") if isinstance(session_state, dict) else None
            canonical_answer = _artifact_answer(artifact) if isinstance(artifact, dict) else _no_artifact_answer()
            answer = await _finalize_visible_answer(canonical_answer, target_language)
            next_session_state = _with_language_preference(session_state, principal, conv_id, target_language, message)
            await save_session_context(principal, conv_id, next_session_state)
            await memory.save_turn(principal.tenant_id, conv_id, message, answer, [], [])
            _trace_plan(conv_id, message, plan, [], False, False, "artifact_lookup")
            await audit.log_interaction(principal, conv_id, len(message), intent_value, [], {}, len(answer), int((time.perf_counter() - start) * 1000), 0, None, target_language)
            return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=target_language, sources=[], tools_used=[], conversation_id=conv_id, message_id=message_id, artifact=artifact if isinstance(artifact, dict) else None, session_context_summary=_session_summary(next_session_state))

        if plan.task_type in {"artifact_export", "report_generation", "report", "export"}:
            report_scope = repair.resolve_report_scope(message, session_state)
            try:
                artifact = await asyncio.to_thread(
                    create_report_artifact, principal, session_state, scan_id, None, scope=report_scope
                )
            except ArtifactError as exc:
                canonical_answer = f"I could not create a report artifact: {exc}"
                answer = canonical_answer
                await memory.save_turn(principal.tenant_id, conv_id, message, answer, [], [])
                _trace_plan(conv_id, message, plan, [], False, False, "artifact_error")
                await audit.log_interaction(principal, conv_id, len(message), intent_value, [], {}, len(answer), int((time.perf_counter() - start) * 1000), 0, "ARTIFACT_UNAVAILABLE", target_language)
                return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=target_language, sources=[], tools_used=[], conversation_id=conv_id, message_id=message_id, error=None, session_context_summary=_session_summary(session_state))
            canonical_answer = _artifact_answer(artifact)
            answer = await _finalize_visible_answer(canonical_answer, target_language)
            next_session_state = _with_language_preference(session_state, principal, conv_id, target_language, message)
            next_session_state["latest_artifact"] = artifact
            await save_session_context(principal, conv_id, next_session_state)
            await memory.save_turn(principal.tenant_id, conv_id, message, answer, [], [])
            _trace_plan(conv_id, message, plan, [], False, True, "artifact")
            await audit.log_interaction(principal, conv_id, len(message), intent_value, [], {}, len(answer), int((time.perf_counter() - start) * 1000), 0, None, target_language)
            return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=target_language, sources=[], tools_used=[], conversation_id=conv_id, message_id=message_id, artifact=artifact, session_context_summary=_session_summary(next_session_state))

        if plan.task_type == "language_switch":
            if target_language == "az":
                answer = "Az\u0259rbaycan dilind\u0259 cavab ver\u0259c\u0259y\u0259m."
            elif target_language == "ru":
                answer = "Буду отвечать на русском."
            else:
                answer = "I will answer in English."
            next_session_state = _with_language_preference(session_state, principal, conv_id, target_language, message)
            await save_session_context(principal, conv_id, next_session_state)
            await memory.save_turn(principal.tenant_id, conv_id, message, answer, [], [])
            _trace_plan(conv_id, message, plan, [], False, False, "language_switch")
            await audit.log_interaction(
                principal, conv_id, len(message), intent_value, [], {}, len(answer),
                int((time.perf_counter() - start) * 1000), 0, None, target_language,
                task_type=plan.task_type,
                provider_planning_called=False,
                provider_final_called=False,
                final_answer_mode="language_switch",
                provider_call_count=0,
                translator_called=False,
                language_understanding=language_understanding_audit,
            )
            return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=target_language, sources=[], tools_used=[], conversation_id=conv_id, message_id=message_id, session_context_summary=_session_summary(next_session_state))

        if plan.task_type == "complaint":
            answer = _complaint_repair_answer(target_language, session_state)
            next_session_state = _with_language_preference(session_state, principal, conv_id, target_language, message)
            if isinstance(next_session_state, dict):
                next_session_state.pop("current_item", None)
            await save_session_context(principal, conv_id, next_session_state)
            await memory.save_turn(principal.tenant_id, conv_id, message, answer, [], [])
            _trace_plan(conv_id, message, plan, [], False, False, "complaint_repair")
            total_ms = int((time.perf_counter() - start) * 1000)
            await audit.log_interaction(
                principal, conv_id, len(message), intent_value, [], {}, len(answer),
                total_ms, 0, None, target_language,
                task_type=plan.task_type,
                provider_planning_called=False,
                provider_final_called=False,
                final_answer_mode="complaint_repair",
                provider_call_count=0,
                translator_called=False,
                language_understanding=language_understanding_audit,
                elapsed_ms_total=total_ms,
            )
            return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=target_language, sources=[], tools_used=[], conversation_id=conv_id, message_id=message_id, session_context_summary=_session_summary(next_session_state))

        if plan.task_type == "clarification":
            answer = plan.clarifying_question or (plan.plan_fixup or {}).get("clarifying_question") or _clarification_answer(target_language)
            await memory.save_turn(principal.tenant_id, conv_id, message, answer, [], [])
            _trace_plan(conv_id, message, plan, [], False, False, "fallback")
            total_ms = int((time.perf_counter() - start) * 1000)
            await audit.log_interaction(
                principal, conv_id, len(message), intent_value, [], {}, len(answer), total_ms, 0, None, target_language,
                task_type=plan.task_type,
                provider_planning_called=plan.provider_planning_called,
                provider_final_called=False,
                final_answer_mode="planner_clarification" if plan.provider_planning_called else "fallback",
                provider_call_count=(1 if plan.provider_planning_called else 0),
                translator_called=False,
                elapsed_ms_total=total_ms,
                elapsed_ms_planner=int((t_planner_done - start) * 1000) if t_planner_done else None,
                **_planner_audit_metadata(plan),
            )
            return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=target_language, sources=[], tools_used=[], conversation_id=conv_id, message_id=message_id, session_context_summary=_session_summary(session_state))

        if not plan.requires_evidence:
            # Evidence guard: DSPM factual questions (counts, severity breakdowns,
            # lists, fact-asserting explanations, short contextual follow-ups)
            # must never be answered by a free provider-final call. The
            # first-class classifier runs for every plan that reaches this
            # provider-final branch, so no task-type misclassification can leak
            # an evidence question to the model. Contract-tested small-talk and
            # capability plans are exempt (they are fact-free by construction).
            if plan.task_type not in {"small_talk", "capability_help"}:
                evidence_decision = evidence_sensitivity.classify_evidence_sensitivity(message, session_state)
                if evidence_decision.required:
                    answer = _evidence_guard_clarification(target_language)
                    return await _meta_no_provider_response(
                        principal=principal, conv_id=conv_id, message=message, answer=answer,
                        intent="clarification_needed", task_type="evidence_guard_clarification",
                        language=target_language, session_state=session_state,
                        selected_language=selected_language, language_source=language_source,
                        message_id=message_id, start=start,
                        language_understanding_audit=language_understanding_audit,
                        audit_extra={
                            "route_id": "evidence_guard",
                            "answer_type": "evidence_guard_clarification",
                            "evidence_guard_triggered": True,
                            "evidence_topic": evidence_decision.topic,
                            "evidence_reason": evidence_decision.reason,
                        },
                    )
            allowed, skip_reason = provider_health.allow_provider_call()
            if not allowed:
                # Model is down: return a deterministic fallback without touching
                # the provider (no repeated /api/chat during cooldown).
                answer = _provider_down_fallback(target_language)
                return await _meta_no_provider_response(
                    principal=principal, conv_id=conv_id, message=message, answer=answer,
                    intent=intent_value, task_type="provider_unavailable", language=target_language,
                    session_state=session_state, selected_language=selected_language,
                    language_source=language_source, message_id=message_id, start=start,
                    language_understanding_audit=language_understanding_audit,
                    audit_extra={
                        **provider_health.snapshot(skip_reason=skip_reason or "circuit_open"),
                        "route_id": "provider_unavailable",
                        "answer_type": "provider_unavailable",
                        "fallback_used": True,
                    },
                )
            canonical_answer = await generate_general_answer(message, history, canonical_metadata)
            answer = await _finalize_visible_answer(canonical_answer, target_language)
            next_session_state = _with_language_preference(session_state, principal, conv_id, target_language, message)
            await save_session_context(principal, conv_id, next_session_state)
            await memory.save_turn(principal.tenant_id, conv_id, message, answer, [], [])
            _trace_plan(conv_id, message, plan, [], True, False, "llm_explanation")
            await audit.log_interaction(principal, conv_id, len(message), intent_value, [], {}, len(answer), int((time.perf_counter() - start) * 1000), 0, None, target_language)
            return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=target_language, sources=[], tools_used=[], conversation_id=conv_id, message_id=message_id, session_context_summary=_session_summary(next_session_state))

        if plan.task_type in FUNCTIONAL_TASKS:
            tool_result = await _functional_tool_result(principal, session_state, plan, scan_id)
            tool_results = [tool_result]
            used_tools = [tool_result.tool_name]
            sources = _sources(tool_results)
            canonical_answer = validate_output(_render_functional_answer(tool_result, plan.task_type), principal, tool_results)
            answer = await _finalize_visible_answer(canonical_answer, target_language)
            await memory.save_turn(principal.tenant_id, conv_id, message, answer, used_tools, [source.model_dump() for source in sources])
            next_session_state = build_context(principal, conv_id, intent_value, target_language, tool_results, answer)
            next_session_state = _merge_previous_list_context(next_session_state, session_state)
            next_session_state = _merge_language_lock(next_session_state, session_state)
            next_session_state = _with_language_preference(next_session_state, principal, conv_id, target_language, message)
            await save_session_context(principal, conv_id, next_session_state)
            _trace_plan(conv_id, message, plan, used_tools, False, True, "deterministic_functional")
            total_ms = int((time.perf_counter() - start) * 1000)
            await audit.log_interaction(
                principal, conv_id, len(message), intent_value, used_tools, _tool_counts(tool_results),
                len(answer), total_ms, len(sources), None, target_language,
                task_type=plan.task_type,
                provider_planning_called=plan.provider_planning_called,
                provider_final_called=False,
                final_answer_mode="deterministic_functional",
                provider_call_count=(1 if plan.provider_planning_called else 0),
                translator_called=target_language == "az",
                elapsed_ms_total=total_ms,
                elapsed_ms_planner=int((t_planner_done - start) * 1000) if t_planner_done else None,
                elapsed_ms_tools=int((t_tools_done - start) * 1000) if t_tools_done else None,
                **_planner_audit_metadata(plan),
            )
            return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=target_language, sources=sources, tools_used=used_tools, conversation_id=conv_id, message_id=message_id, session_context_summary=_session_summary(next_session_state))

        if plan.task_type in {"severity_count", "severity_findings_list", "severity_findings_compare"}:
            severity_value = _severity_from_plan(message, plan, session_state)
            limit = plan.requested_limit or (2 if plan.task_type == "severity_findings_compare" else 5)
            if plan.task_type == "severity_count":
                limit = 1
            selection_mode = "top" if plan.task_type == "severity_count" else (plan.selection_mode or "top")
            exclude_ids = [] if plan.task_type == "severity_count" else _selection_exclude_ids(plan, session_state)
            try:
                tool_result = await _get_findings_by_severity_for_plan(
                    principal,
                    severity_value,
                    limit=limit,
                    selection_mode=selection_mode,
                    exclude_ids=exclude_ids,
                )
                t_tools_done = time.perf_counter()
            except NoEvidenceError:
                if target_language == "az":
                    answer = f"Son skanda {severity_value} tapinti tapilmadi."
                else:
                    answer = f"No {severity_value} findings were found in the latest scan."
                await memory.save_turn(principal.tenant_id, conv_id, message, answer, [], [])
                await audit.log_interaction(
                    principal, conv_id, len(message), intent_value, [], {}, len(answer),
                    int((time.perf_counter() - start) * 1000), 0, None, target_language,
                    task_type=plan.task_type,
                    provider_planning_called=plan.provider_planning_called,
                    provider_final_called=False,
                    final_answer_mode="deterministic_severity",
                    provider_call_count=(1 if plan.provider_planning_called else 0),
                    translator_called=False,
                    language_understanding=language_understanding_audit,
                    **_planner_audit_metadata(plan),
                )
                return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=target_language, sources=[], tools_used=[], conversation_id=conv_id, message_id=message_id, session_context_summary=_session_summary(session_state))
            tool_results = [tool_result]
            used_tools = [tool_result.tool_name]
            sources = _sources(tool_results)
            payload = _payload(tool_result)
            if plan.task_type == "severity_count":
                canonical_answer = _render_severity_count(payload, severity_value, target_language)
            elif plan.task_type == "severity_findings_compare":
                canonical_answer = _render_severity_compare(payload, severity_value, limit, target_language)
            else:
                canonical_answer = _render_severity_findings_list(payload, severity_value, limit, target_language)
            answer = clean_answer_text(validate_output(canonical_answer, principal, tool_results))
            await memory.save_turn(principal.tenant_id, conv_id, message, answer, used_tools, [source.model_dump() for source in sources])
            next_session_state = build_context(principal, conv_id, intent_value, target_language, tool_results, answer)
            next_session_state = _merge_previous_list_context(next_session_state, session_state)
            next_session_state = _merge_language_lock(next_session_state, session_state)
            next_session_state = _with_language_preference(next_session_state, principal, conv_id, target_language, message)
            await save_session_context(principal, conv_id, next_session_state)
            _trace_plan(conv_id, message, plan, used_tools, False, True, "deterministic_severity")
            total_ms = int((time.perf_counter() - start) * 1000)
            await audit.log_interaction(
                principal, conv_id, len(message), intent_value, used_tools, _tool_counts(tool_results),
                len(answer), total_ms, len(sources), None, target_language,
                task_type=plan.task_type,
                provider_planning_called=plan.provider_planning_called,
                provider_final_called=False,
                final_answer_mode="deterministic_severity",
                provider_call_count=(1 if plan.provider_planning_called else 0),
                translator_called=False,
                language_understanding=language_understanding_audit,
                elapsed_ms_total=total_ms,
                elapsed_ms_planner=int((t_planner_done - start) * 1000) if t_planner_done else None,
                elapsed_ms_tools=int((t_tools_done - start) * 1000) if t_tools_done else None,
                **_planner_audit_metadata(plan),
            )
            return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=target_language, sources=sources, tools_used=used_tools, conversation_id=conv_id, message_id=message_id, session_context_summary=_session_summary(next_session_state))

        if plan.task_type == "list_plus_remediation":
            severity_value = _severity_from_plan(message, plan, session_state)
            limit = plan.requested_limit or 3
            selection_mode = plan.selection_mode or "top"
            exclude_ids = _selection_exclude_ids(plan, session_state)
            try:
                tool_result = await _get_findings_by_severity_for_plan(
                    principal,
                    severity_value,
                    limit=limit,
                    selection_mode=selection_mode,
                    exclude_ids=exclude_ids,
                )
                t_tools_done = time.perf_counter()
            except NoEvidenceError:
                return await _fallback_response(principal, conv_id, message, intent_value, used_tools, start)
            tool_results = [tool_result]
            used_tools = [tool_result.tool_name]
            sources = _sources(tool_results)
            payload = _payload(tool_result)
            items = (payload.get("results") or [])[:limit]
            if payload.get("no_more_results") and not items:
                canonical_answer = _render_severity_findings_list(payload, severity_value, limit, target_language)
            elif not items:
                canonical_answer = fallback_answer("en")
            elif plan.needs_step_by_step and len(items) == 1:
                from backend.copilot.skill_renderers import render_step_by_step_remediation
                canonical_answer = render_step_by_step_remediation(items[0], target_language, scan_id=payload.get("scan_id"))
            else:
                from backend.copilot.skill_renderers import render_list_plus_remediation
                canonical_answer = render_list_plus_remediation(items, payload.get("scan_id"), target_language)
            canonical_answer = validate_output(canonical_answer, principal, tool_results)
            answer = clean_answer_text(canonical_answer) if target_language == "az" else await _finalize_visible_answer(canonical_answer, target_language)
            await memory.save_turn(principal.tenant_id, conv_id, message, answer, used_tools, [source.model_dump() for source in sources])
            next_session_state = build_context(principal, conv_id, intent_value, target_language, tool_results, answer)
            if plan.needs_step_by_step and len(items) == 1:
                next_session_state = _mark_step_by_step_payload(next_session_state)
            next_session_state = _merge_previous_list_context(next_session_state, session_state)
            next_session_state = _merge_language_lock(next_session_state, session_state)
            next_session_state = _with_language_preference(next_session_state, principal, conv_id, target_language, message)
            await save_session_context(principal, conv_id, next_session_state)
            _trace_plan(conv_id, message, plan, used_tools, False, True, "list_plus_remediation")
            total_ms = int((time.perf_counter() - start) * 1000)
            await audit.log_interaction(
                principal, conv_id, len(message), intent_value, used_tools, _tool_counts(tool_results),
                len(answer), total_ms, len(sources), None, target_language,
                task_type=plan.task_type,
                provider_planning_called=plan.provider_planning_called,
                provider_final_called=False,
                final_answer_mode="list_plus_remediation",
                provider_call_count=(1 if plan.provider_planning_called else 0),
                translator_called=False,
                language_understanding=language_understanding_audit,
                elapsed_ms_total=total_ms,
                elapsed_ms_planner=int((t_planner_done - start) * 1000) if t_planner_done else None,
                elapsed_ms_tools=int((t_tools_done - start) * 1000) if t_tools_done else None,
                **_planner_audit_metadata(plan),
            )
            return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=target_language, sources=sources, tools_used=used_tools, conversation_id=conv_id, message_id=message_id, session_context_summary=_session_summary(next_session_state))

        if plan.task_type in SELECTED_ITEM_TASKS:
            if plan.task_type in REMEDIATION_TASKS:
                plural_items = _resolve_plan_items(session_state, plan, message)
                if len(plural_items) > 1:
                    from backend.copilot.skill_renderers import render_list_plus_remediation
                    limit = plan.requested_limit or len(plural_items)
                    scan_id = session_state.get("last_scan_id") if session_state else None
                    canonical_answer = render_list_plus_remediation(plural_items[:limit], scan_id, target_language)
                    canonical_answer = validate_output(canonical_answer, principal, [])
                    answer = clean_answer_text(canonical_answer) if target_language == "az" else await _finalize_visible_answer(canonical_answer, target_language)
                    await memory.save_turn(principal.tenant_id, conv_id, message, answer, [], [])
                    next_session_state = _merge_previous_list_context({}, session_state)
                    next_session_state = _merge_language_lock(next_session_state, session_state)
                    next_session_state = _with_language_preference(next_session_state, principal, conv_id, target_language, message)
                    await save_session_context(principal, conv_id, next_session_state)
                    _trace_plan(conv_id, message, plan, [], False, True, "plural_remediation_followup")
                    await audit.log_interaction(
                        principal, conv_id, len(message), intent_value, [], {}, len(answer),
                        int((time.perf_counter() - start) * 1000), 0, None, target_language,
                        task_type=plan.task_type,
                        provider_planning_called=plan.provider_planning_called,
                        provider_final_called=False,
                        final_answer_mode="plural_remediation_followup",
                        provider_call_count=(1 if plan.provider_planning_called else 0),
                        translator_called=False,
                        language_understanding=language_understanding_audit,
                        **_planner_audit_metadata(plan),
                    )
                    return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=target_language, sources=[], tools_used=[], conversation_id=conv_id, message_id=message_id, session_context_summary=_session_summary(next_session_state))
            selected_item = _resolve_plan_item(session_state, plan)
            if not selected_item:
                answer = _clarification_answer(target_language)
                await memory.save_turn(principal.tenant_id, conv_id, message, answer, [], [])
                _trace_plan(conv_id, message, plan, [], False, False, "fallback")
                await audit.log_interaction(
                    principal, conv_id, len(message), intent_value, [], {}, len(answer),
                    int((time.perf_counter() - start) * 1000), 0, None, target_language,
                    task_type=plan.task_type,
                    provider_planning_called=plan.provider_planning_called,
                    provider_final_called=False,
                    final_answer_mode="selected_item_clarification",
                    provider_call_count=(1 if plan.provider_planning_called else 0),
                    translator_called=False,
                    language_understanding=language_understanding_audit,
                    **_planner_audit_metadata(plan),
                )
                return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=target_language, sources=[], tools_used=[], conversation_id=conv_id, message_id=message_id, session_context_summary=_session_summary(session_state))
            tool_result = await _selected_item_tool_result(principal, session_state, plan)
            tool_results = [tool_result]
            used_tools = [tool_result.tool_name]
            sources = _sources(tool_results)
            step_by_step_remediation = plan.needs_step_by_step and plan.task_type in REMEDIATION_TASKS
            deterministic_template = None if step_by_step_remediation else deterministic_selected_item_template(tool_result, target_language, plan.task_type)
            if step_by_step_remediation:
                from backend.copilot.skill_renderers import render_step_by_step_remediation
                step_payload = _payload(tool_result)
                step_item = step_payload.get("item") if isinstance(step_payload.get("item"), dict) else step_payload
                step_scan_id = step_payload.get("scan_id") or (step_item.get("scan_id") if isinstance(step_item, dict) else None)
                canonical_answer = render_step_by_step_remediation(step_item, target_language, scan_id=step_scan_id)
                provider_final_called = False
                selected_final_answer_mode = "step_by_step_remediation"
                selected_answer_already_localized = target_language == "az"
            elif deterministic_template:
                canonical_answer = _ensure_structured_evidence_block(deterministic_template, tool_result)
                provider_final_called = False
                selected_final_answer_mode = "deterministic_template"
                selected_answer_already_localized = target_language == "az"
            elif target_language == "az":
                canonical_answer = _ensure_structured_evidence_block(_deterministic_item_answer(tool_result, "az", plan.task_type), tool_result)
                provider_final_called = False
                selected_final_answer_mode = "fallback"
                selected_answer_already_localized = True
            else:
                canonical_answer, provider_final_called = await generate_selected_item_answer(message, tool_result, canonical_metadata, plan)
                selected_final_answer_mode = "llm_explanation" if provider_final_called else "fallback"
                selected_answer_already_localized = False
            canonical_answer = validate_output(canonical_answer, principal, tool_results)
            answer = clean_answer_text(canonical_answer) if selected_answer_already_localized else await _finalize_visible_answer(canonical_answer, target_language)
            await memory.save_turn(principal.tenant_id, conv_id, message, answer, used_tools, [source.model_dump() for source in sources])
            next_session_state = build_context(principal, conv_id, intent_value, target_language, tool_results, answer)
            next_session_state = _merge_previous_list_context(next_session_state, session_state)
            next_session_state = _merge_language_lock(next_session_state, session_state)
            next_session_state["current_item"] = selected_item
            next_session_state = _with_language_preference(next_session_state, principal, conv_id, target_language, message)
            await save_session_context(principal, conv_id, next_session_state)
            _trace_plan(conv_id, message, plan, used_tools, provider_final_called, True, selected_final_answer_mode)
            total_ms = int((time.perf_counter() - start) * 1000)
            timings = {"total_ms": total_ms, "route": "selected_item"}
            await audit.log_interaction(
                principal, conv_id, len(message), intent_value, used_tools, _tool_counts(tool_results), len(answer), total_ms, len(sources), None, target_language,
                task_type=plan.task_type,
                provider_planning_called=plan.provider_planning_called,
                provider_final_called=provider_final_called,
                final_answer_mode=selected_final_answer_mode,
                provider_call_count=(1 if provider_final_called else 0) + (1 if plan.provider_planning_called else 0),
                translator_called=target_language == "az" and provider_final_called,
                elapsed_ms_total=total_ms,
                language_understanding=language_understanding_audit,
                **_planner_audit_metadata(plan),
            )
            return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=target_language, sources=sources, tools_used=used_tools, conversation_id=conv_id, message_id=message_id, session_context_summary=_session_summary(next_session_state), metadata=_debug_metadata(timings))

        intent = _intent_for_plan(plan, message)
        intent_value = plan.intent or intent.intent
        tool_results = await execute_tools(
            intent,
            principal,
            message,
            scan_id,
            plan.requested_limit,
            selection_mode=plan.selection_mode or "top",
            exclude_ids=_selection_exclude_ids(plan, session_state),
        )
        t_tools_done = time.perf_counter()
        used_tools = [result.tool_name for result in tool_results]
        if plan.task_type in LIST_TASKS | CORRECTION_TASKS and any(result.tool_name == "get_findings_by_severity" for result in tool_results):
            canonical_answer = _render_critical_findings(tool_results, "en", plan.requested_limit or planner_requested_limit(message) or 5, repair=plan.task_type in CORRECTION_TASKS and metadata.intent == "complaint_or_misunderstanding")
            final_answer_mode = "deterministic_list"
            provider_final_called = False
            if not canonical_answer:
                canonical_answer = fallback_answer("en")
        else:
            canonical_answer = await generate_answer(message, tool_results, history, canonical_metadata)
            final_answer_mode = "hybrid" if plan.requires_llm_final_answer else "llm_explanation"
            provider_final_called = True
        canonical_answer = validate_output(canonical_answer, principal, tool_results)
        answer = await _finalize_visible_answer(canonical_answer, target_language)
        sources = _sources(tool_results)
        await memory.save_turn(principal.tenant_id, conv_id, message, answer, used_tools, [source.model_dump() for source in sources])
        next_session_state = build_context(principal, conv_id, intent_value, target_language, tool_results, answer)
        next_session_state = _merge_language_lock(next_session_state, session_state)
        next_session_state = _with_language_preference(next_session_state, principal, conv_id, target_language, message)
        await save_session_context(principal, conv_id, next_session_state)
        _trace_plan(conv_id, message, plan, used_tools, provider_final_called, True, final_answer_mode)
        total_ms = int((time.perf_counter() - start) * 1000)
        await audit.log_interaction(
            principal, conv_id, len(message), intent_value, used_tools, _tool_counts(tool_results),
            len(answer), total_ms, len(sources), None, target_language,
            task_type=plan.task_type,
            provider_planning_called=plan.provider_planning_called,
            provider_final_called=provider_final_called,
            final_answer_mode=final_answer_mode,
            provider_call_count=(1 if provider_final_called else 0) + (1 if plan.provider_planning_called else 0),
            translator_called=target_language == "az" and provider_final_called,
            elapsed_ms_total=total_ms,
            elapsed_ms_planner=int((t_planner_done - start) * 1000) if t_planner_done else None,
            elapsed_ms_tools=int((t_tools_done - start) * 1000) if t_tools_done else None,
            language_understanding=language_understanding_audit,
            **_planner_audit_metadata(plan),
        )
        return ChatResponse(answer=answer, intent=intent_value, task_type=plan.task_type, language=target_language, sources=sources, tools_used=used_tools, conversation_id=conv_id, message_id=message_id, session_context_summary=_session_summary(next_session_state))
    except NoEvidenceError:
        return await _fallback_response(principal, conv_id, message, intent_value, used_tools, start)
    except GuardrailError as exc:
        return await _error_response(principal, conv_id, message, intent_value, used_tools, start, "GUARDRAIL_BLOCKED", str(exc))
    except CopilotError as exc:
        return await _error_response(principal, conv_id, message, intent_value, used_tools, start, exc.error_code, exc.message)
    finally:
        audit.reset_language_context(audit_language_token)
        session_lock.release()


async def _fallback_response(principal: Principal, conversation_id: str, message: str, intent: str, tools_used: list[str], start: float) -> ChatResponse:
    metadata = analyze_message(message)
    session_state = await load_session_context(principal, conversation_id)
    target_language = _resolve_answer_language(message, metadata.language, session_state)
    answer = await _finalize_visible_answer(fallback_answer("en"), target_language)
    next_session_state = _with_language_preference(session_state, principal, conversation_id, target_language, message)
    await save_session_context(principal, conversation_id, next_session_state)
    await audit.log_interaction(principal, conversation_id, len(message), intent, tools_used, {}, len(answer), int((time.perf_counter() - start) * 1000), 0, None, target_language)
    await memory.save_turn(principal.tenant_id, conversation_id, message, answer, tools_used, [])
    return ChatResponse(answer=answer, intent=intent, language=target_language, sources=[], tools_used=tools_used, conversation_id=conversation_id)


async def _error_response(principal: Principal, conversation_id: str, message: str, intent: str, tools_used: list[str], start: float, code: str, error_message: str) -> ChatResponse:
    metadata = analyze_message(message)
    session_state = await load_session_context(principal, conversation_id)
    target_language = _resolve_answer_language(message, metadata.language, session_state)
    await audit.log_interaction(principal, conversation_id, len(message), intent, tools_used, {}, 0, int((time.perf_counter() - start) * 1000), 0, code, target_language)
    return ChatResponse(answer=None, intent=intent, language=target_language, sources=[], tools_used=tools_used, conversation_id=conversation_id, error={"code": code, "message": error_message})


async def stream_chat(
    message: str,
    principal: Principal,
    conversation_id: str | None,
    scan_id: str | None,
    selected_language: str | None = None,
    selected_language_source: str | None = None,
) -> AsyncIterator[dict]:
    yield {"event": "status", "stage": "planning"}
    yield {"event": "status", "stage": "retrieving_evidence"}
    yield {"event": "status", "stage": "generating_answer"}
    response = await handle_chat(
        message,
        principal,
        conversation_id,
        scan_id,
        selected_language,
        selected_language_source=selected_language_source,
    )
    if response.error:
        yield {"event": "error", **response.error}
        return
    yield {"event": "token", "text": response.answer or ""}
    yield {
        "event": "done",
        "conversation_id": response.conversation_id,
        "intent": response.intent,
        "task_type": response.task_type,
        "message_id": response.message_id,
        "language": response.language,
        "sources": [source.model_dump() for source in response.sources],
        "tools_used": response.tools_used,
        "session_context_summary": response.session_context_summary,
    }
