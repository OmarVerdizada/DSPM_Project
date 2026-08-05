"""Typed, deterministic route dispatcher for early Copilot routes.

The dispatcher only decides which early route should execute. It never calls an
LLM provider, never reads raw files, and never executes tools. Existing service
handlers still own rendering and evidence retrieval.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
import re
from typing import Any, Mapping

from backend.copilot import conversation_repair as repair
from backend.copilot import correction_detection
from backend.copilot import language_service
from backend.copilot import product_help
from backend.copilot import professional_workflows as prof
from backend.copilot import situation_guardrails
from backend.copilot import situation_policy
from backend.copilot.language import normalize_message


class RoutePriority(IntEnum):
    MALFORMED_OUTPUT_COMPLAINT = 100
    P0_SITUATION_GUARDRAIL = 98
    LANGUAGE_COMPLAINT = 95
    CANCEL_OR_RESET_TOPIC = 90
    UI_NAVIGATION_HELP = 89
    ARTIFACT_LINK_OR_DOWNLOAD_HELP = 88
    PREVIOUS_ANSWER_RERENDER_OR_CONDENSE = 86
    COUNT_CONFLICT_OR_WHY_PREVIOUS_ANSWER = 84
    WRONG_ROUTE_COMPLAINT = 82
    AGGREGATE_SCOPE_REMEDIATION = 80
    SCAN_DELTA_OR_WHAT_CHANGED = 78
    FIX_NOW_TOP_RISKS = 76
    PROFESSIONAL_FOLLOWUP = 74
    PRODUCT_HELP = 72
    DETERMINISTIC_CONTRACT_ROUTE = 70
    CANNED_RESPONSE = 60
    STRUCTURED_AI_PLANNER_CANDIDATE = 50
    LEGACY_PROVIDER_FALLBACK = 40


@dataclass(frozen=True)
class RouteSignal:
    name: str
    value: str | bool | int | None = True


@dataclass(frozen=True)
class RouteCandidate:
    route_id: str
    answer_type: str | None
    priority: int
    matched: bool
    reason: str
    signals: list[str]
    uses_selected_finding: bool
    uses_count_scope: bool
    uses_artifact_scope: bool
    provider_allowed: bool
    translator_allowed: bool
    requires_dspm_evidence: bool
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RouteDecision:
    route_id: str
    answer_type: str | None
    priority: int
    reason: str
    signals: list[str]
    handler_name: str
    provider_allowed: bool
    translator_allowed: bool
    selected_finding_used: bool
    count_scope_used: bool
    artifact_scope_used: bool
    canonical_answer_expected: bool
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RouteHandlerSpec:
    route_id: str
    handler_name: str


@dataclass(frozen=True)
class RouteDispatchContext:
    message: str
    normalized_message: str = ""
    target_language: str = "az"
    conversation_state: Mapping[str, Any] | None = None
    legacy_context: Mapping[str, Any] | None = None
    principal: Any | None = None
    scan_id: str | None = None
    selected_language: str | None = None
    canonical_metadata: Mapping[str, Any] | None = None

    def context(self) -> Mapping[str, Any]:
        if self.legacy_context is not None:
            return self.legacy_context
        if self.conversation_state is not None:
            return self.conversation_state
        return {}

    def normalized(self) -> str:
        return self.normalized_message or language_service.normalize_for_intent(self.message)


_HANDLERS: dict[str, str] = {
    "p0_situation_guardrail": "p0_situation_guardrail",
    "malformed_output_complaint": "conversation_repair",
    "language_complaint": "language_complaint",
    "cancel_or_reset_topic": "conversation_repair",
    "artifact_link_or_download_help": "conversation_repair",
    "previous_answer_rerender_or_condense": "previous_answer_or_condense",
    "count_conflict_or_why_previous_answer": "meta_no_provider",
    "wrong_route_complaint": "meta_no_provider",
    "aggregate_scope_remediation": "conversation_repair",
    "scan_delta_or_what_changed": "professional_followup",
    "fix_now_top_risks": "professional_followup",
    "professional_followup": "professional_followup",
    "deterministic_contract_route": "conversation_repair",
    "product_help": "product_help",
}


_PREV_ANSWER_MODIFIERS = (
    "evvel", "evvelki", "onceki", "bayaq", "bayaqki", "hemin", "son cavab",
    "previous", "last", "that", "this", "preceding",
)


def detect_previous_answer_rerender(message: str) -> tuple[bool, str | None]:
    norm = normalize_message(message)
    raw = (message or "").lower()
    answer_word = ("cavab" in norm) or ("answer" in norm) or ("otvet" in norm)
    prev_mod = any(mod in norm for mod in _PREV_ANSWER_MODIFIERS)
    if not (answer_word and prev_mod):
        return False, None
    verb_or_lang = any(
        tok in norm
        for tok in (
            "ver", "yaz", "translate", "say", "give", "rerender", "render",
            "azerbaycan", "azerbaijani", "english", "ingilis", "russian", "rus dilinde",
        )
    )
    if not verb_or_lang:
        return False, None
    return True, language_service.requested_language_from_message(message)


def detect_count_conflict_explanation(message: str) -> bool:
    return correction_detection.detect_count_conflict_explanation(message)


def detect_why_previous_answer(message: str) -> bool:
    return correction_detection.detect_why_previous_answer(message)


def detect_wrong_route_complaint(message: str) -> bool:
    return correction_detection.detect_wrong_route_complaint(message)


def _candidate(
    *,
    route_id: str,
    priority: RoutePriority,
    matched: bool,
    reason: str,
    signals: list[str],
    answer_type: str | None = None,
    uses_selected_finding: bool = False,
    uses_count_scope: bool = False,
    uses_artifact_scope: bool = False,
    provider_allowed: bool = False,
    translator_allowed: bool = False,
    requires_dspm_evidence: bool = False,
    metadata: dict[str, Any] | None = None,
) -> RouteCandidate:
    return RouteCandidate(
        route_id=route_id,
        answer_type=answer_type,
        priority=int(priority),
        matched=matched,
        reason=reason,
        signals=signals,
        uses_selected_finding=uses_selected_finding,
        uses_count_scope=uses_count_scope,
        uses_artifact_scope=uses_artifact_scope,
        provider_allowed=provider_allowed,
        translator_allowed=translator_allowed,
        requires_dspm_evidence=requires_dspm_evidence,
        metadata=metadata or {},
    )


def build_candidates(ctx: RouteDispatchContext) -> list[RouteCandidate]:
    message = ctx.message
    session = ctx.context()
    candidates: list[RouteCandidate] = []

    p0_decision = situation_guardrails.classify_p0_situation(message, session)
    if p0_decision is not None:
        candidates.append(_candidate(
            route_id="p0_situation_guardrail",
            priority=RoutePriority.P0_SITUATION_GUARDRAIL,
            matched=True,
            answer_type=p0_decision.situation_id,
            reason=p0_decision.reason,
            signals=list(p0_decision.signals),
            uses_selected_finding=p0_decision.uses_selected_finding,
            uses_count_scope=p0_decision.uses_count_scope,
            uses_artifact_scope=p0_decision.uses_artifact_scope,
            provider_allowed=p0_decision.provider_allowed,
            requires_dspm_evidence=p0_decision.uses_dspm_data,
            metadata={"p0_decision": p0_decision, **p0_decision.to_metadata()},
        ))

    malformed = repair.detect_malformed_output_complaint(message)
    candidates.append(_candidate(
        route_id="malformed_output_complaint",
        priority=RoutePriority.MALFORMED_OUTPUT_COMPLAINT,
        matched=malformed,
        answer_type="malformed_output_complaint",
        reason="known malformed/fabricated language output token was referenced",
        signals=["malformed_output"] if malformed else [],
    ))

    rerender, requested_language = detect_previous_answer_rerender(message)
    language_complaint = language_service.detect_language_complaint(message) and not rerender
    candidates.append(_candidate(
        route_id="language_complaint",
        priority=RoutePriority.LANGUAGE_COMPLAINT,
        matched=language_complaint,
        answer_type="language_complaint",
        reason="user complained about wrong response language",
        signals=["language_complaint"] if language_complaint else [],
    ))

    cancel = repair.detect_cancel_topic(message)
    candidates.append(_candidate(
        route_id="cancel_or_reset_topic",
        priority=RoutePriority.CANCEL_OR_RESET_TOPIC,
        matched=cancel,
        answer_type="cancel_current_topic",
        reason="user asked to set aside or reset active context",
        signals=["cancel_topic"] if cancel else [],
    ))

    artifact_intent = repair.detect_artifact_intent(message, session)
    artifact_active = bool(session.get("latest_artifact")) if isinstance(session, Mapping) else False
    candidates.append(_candidate(
        route_id="artifact_link_or_download_help",
        priority=RoutePriority.ARTIFACT_LINK_OR_DOWNLOAD_HELP,
        matched=artifact_intent in {repair.ARTIFACT_LINK, repair.ARTIFACT_CREATE},
        answer_type=artifact_intent,
        reason="artifact create/link/download intent matched",
        signals=[f"artifact_intent:{artifact_intent}", f"artifact_active:{artifact_active}"] if artifact_intent else [],
        uses_artifact_scope=artifact_intent == repair.ARTIFACT_LINK and artifact_active,
        metadata={"repair_intent": artifact_intent, "artifact_active": artifact_active},
    ))

    professional_intent = prof.detect_professional_followup(message, session)
    condense = professional_intent == prof.CONDENSE
    candidates.append(_candidate(
        route_id="previous_answer_rerender_or_condense",
        priority=RoutePriority.PREVIOUS_ANSWER_RERENDER_OR_CONDENSE,
        matched=rerender or condense,
        answer_type="rerender_previous_answer" if rerender else ("condense_previous" if condense else None),
        reason="user asked to re-render or condense the previous answer",
        signals=(["previous_answer_rerender"] if rerender else []) + (["condense_previous"] if condense else []),
        metadata={"requested_language": requested_language, "professional_intent": professional_intent},
    ))

    count_conflict = detect_count_conflict_explanation(message)
    why_previous = detect_why_previous_answer(message)
    candidates.append(_candidate(
        route_id="count_conflict_or_why_previous_answer",
        priority=RoutePriority.COUNT_CONFLICT_OR_WHY_PREVIOUS_ANSWER,
        matched=count_conflict or why_previous,
        answer_type="count_conflict_explanation" if count_conflict else ("why_previous_answer" if why_previous else None),
        reason="user asked about a previous count/answer rather than selected finding detail",
        signals=(["count_conflict"] if count_conflict else []) + (["why_previous_answer"] if why_previous else []),
        requires_dspm_evidence=count_conflict,
        metadata={"count_conflict": count_conflict, "why_previous": why_previous},
    ))

    wrong_route = detect_wrong_route_complaint(message) or repair.detect_why_misunderstood(message, session)
    candidates.append(_candidate(
        route_id="wrong_route_complaint",
        priority=RoutePriority.WRONG_ROUTE_COMPLAINT,
        matched=wrong_route,
        answer_type="wrong_route_complaint",
        reason="user complained that the previous route/scope was wrong",
        signals=["wrong_route_complaint"] if wrong_route else [],
        metadata={"repair_why_misunderstood": repair.detect_why_misunderstood(message, session)},
    ))

    aggregate_scope = repair.detect_aggregate_remediation_complaint(message, session) or repair.detect_aggregate_remediation(message, session)
    folded_for_precedence = ctx.normalized()
    explicit_single_finding = (
        any(term in folded_for_precedence for term in ("random", "bir ", "one ", "single "))
        and any(term in folded_for_precedence for term in ("tapinti", "finding"))
    )
    if explicit_single_finding:
        aggregate_scope = None
    candidates.append(_candidate(
        route_id="aggregate_scope_remediation",
        priority=RoutePriority.AGGREGATE_SCOPE_REMEDIATION,
        matched=bool(aggregate_scope),
        answer_type="aggregate_scope_remediation",
        reason="message refers to stored aggregate count scope, not a selected finding",
        signals=["aggregate_scope", f"severities:{','.join(aggregate_scope or [])}"] if aggregate_scope else [],
        uses_count_scope=bool(aggregate_scope),
        metadata={"repair_intent": repair.AGGREGATE_REMEDIATION, "severities": aggregate_scope or []},
    ))

    candidates.append(_candidate(
        route_id="scan_delta_or_what_changed",
        priority=RoutePriority.SCAN_DELTA_OR_WHAT_CHANGED,
        matched=professional_intent == prof.SCAN_DELTA,
        answer_type="scan_delta",
        reason="message asks what changed between scans",
        signals=["professional_intent:scan_delta"] if professional_intent == prof.SCAN_DELTA else [],
        requires_dspm_evidence=professional_intent == prof.SCAN_DELTA,
        metadata={"professional_intent": professional_intent},
    ))

    candidates.append(_candidate(
        route_id="fix_now_top_risks",
        priority=RoutePriority.FIX_NOW_TOP_RISKS,
        matched=professional_intent == prof.FIX_NOW_TOP_RISKS,
        answer_type="fix_now_top_risks",
        reason="message asks which whole-scan risks to fix first",
        signals=["professional_intent:fix_now_top_risks"] if professional_intent == prof.FIX_NOW_TOP_RISKS else [],
        requires_dspm_evidence=professional_intent == prof.FIX_NOW_TOP_RISKS,
        metadata={"professional_intent": professional_intent},
    ))

    professional = professional_intent not in {None, prof.SCAN_DELTA, prof.FIX_NOW_TOP_RISKS, prof.CONDENSE}
    candidates.append(_candidate(
        route_id="professional_followup",
        priority=RoutePriority.PROFESSIONAL_FOLLOWUP,
        matched=professional,
        answer_type=professional_intent if professional else None,
        reason="message matched a deterministic professional follow-up",
        signals=[f"professional_intent:{professional_intent}"] if professional else [],
        uses_selected_finding=professional_intent in {prof.RISKIEST, prof.MANAGER_SUMMARY, prof.TECHNICAL_REMEDIATION},
        requires_dspm_evidence=professional_intent in {prof.RISKIEST, prof.TRIAGE, prof.RISK_TYPE_BREAKDOWN, prof.MANAGER_SUMMARY, prof.TECHNICAL_REMEDIATION},
        metadata={"professional_intent": professional_intent},
    ))

    help_decision = product_help.detect_product_help(message)
    if help_decision is not None:
        is_navigation = help_decision.kind == product_help.NAVIGATION
        candidates.append(_candidate(
            route_id="product_help",
            priority=RoutePriority.UI_NAVIGATION_HELP if is_navigation else RoutePriority.PRODUCT_HELP,
            matched=True,
            answer_type=help_decision.kind,
            reason="deterministic product-help / navigation / taxonomy question",
            signals=[f"product_help:{help_decision.kind}"],
            requires_dspm_evidence=help_decision.kind == product_help.ALERT_TYPES,
            metadata={
                "product_help_kind": help_decision.kind,
                "nav_target_key": help_decision.nav_target_key,
                "nav_target_label": help_decision.nav_target_label,
            },
        ))

    subset = repair.detect_severity_subset_correction(message, session) or repair.detect_severity_subset_count(message)
    general_switch = repair.detect_general_topic_switch(message)
    candidates.append(_candidate(
        route_id="deterministic_contract_route",
        priority=RoutePriority.DETERMINISTIC_CONTRACT_ROUTE,
        matched=bool(subset) or general_switch,
        answer_type="severity_subset_count" if subset else ("general_scope_advice" if general_switch else None),
        reason="deterministic repair/contract route matched before planner fallback",
        signals=(["severity_subset_count"] if subset else []) + (["general_topic_switch"] if general_switch else []),
        uses_count_scope=bool(subset),
        metadata={"repair_intent": repair.SEVERITY_SUBSET_COUNT if subset else "general_scope_advice", "severities": subset or []},
    ))

    return candidates


def dispatch(ctx: RouteDispatchContext) -> RouteDecision | None:
    matched = [candidate for candidate in build_candidates(ctx) if candidate.matched]
    if not matched:
        return None
    candidate = sorted(matched, key=lambda item: (-item.priority, item.route_id))[0]
    handler_name = _HANDLERS.get(candidate.route_id, "legacy_provider_fallback")
    return RouteDecision(
        route_id=candidate.route_id,
        answer_type=candidate.answer_type,
        priority=candidate.priority,
        reason=candidate.reason,
        signals=list(candidate.signals),
        handler_name=handler_name,
        provider_allowed=candidate.provider_allowed,
        translator_allowed=candidate.translator_allowed,
        selected_finding_used=candidate.uses_selected_finding,
        count_scope_used=candidate.uses_count_scope,
        artifact_scope_used=candidate.uses_artifact_scope,
        canonical_answer_expected=candidate.requires_dspm_evidence,
        metadata=dict(candidate.metadata),
    )


def decision_metadata(decision: RouteDecision | None) -> dict[str, Any]:
    if decision is None:
        return {}
    classifier_fields = decision.metadata.get("_situation_classifier_fields")
    metadata = {
        "route_dispatcher_used": True,
        "route_id": decision.route_id,
        "route_priority": int(decision.priority),
        "route_reason": decision.reason,
        "route_signals": list(decision.signals),
        "route_handler_name": decision.handler_name,
        "provider_allowed": bool(decision.provider_allowed),
        "translator_allowed": bool(decision.translator_allowed),
        "selected_finding_used": bool(decision.selected_finding_used),
        "count_scope_used": bool(decision.count_scope_used),
        "artifact_scope_used": bool(decision.artifact_scope_used),
        "canonical_answer_expected": bool(decision.canonical_answer_expected),
    }
    metadata.update(situation_policy.route_situation_metadata(decision))
    if isinstance(classifier_fields, Mapping):
        for key, value in classifier_fields.items():
            if key in metadata and key not in {
                "situation_classifier_used",
                "situation_candidates",
                "situation_conflict_detected",
                "situation_fallback_needed",
                "situation_classifier_latency_ms",
            }:
                continue
            metadata[key] = value
    for key, value in decision.metadata.items():
        if key in {
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
            "corrected_answer_returned",
            "corrected_scope_used",
            "fallback_family",
            "language_repair_applied",
            "turkish_leakage_blocked",
            "social_repetition_count",
            "response_variant_id",
            "situation_id",
            "situation_confidence",
            "situation_reason",
            "situation_signals",
            "situation_response_mode",
            "situation_provider_mode",
            "situation_zero_provider",
        }:
            metadata[key] = value
    return metadata
