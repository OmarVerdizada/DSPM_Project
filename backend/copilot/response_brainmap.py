"""Typed response brainmap contract and policy helpers.

P4A keeps final wording in the existing deterministic renderers, but every
visible response must carry a compact, safe brainmap describing what policy and
meaning controlled the answer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import re
from typing import Any, Mapping

from backend.copilot import ai_layers, language_service, provider_health
from backend.copilot.language import normalize_message


BRAINMAP_VERSION = "p4a.response_brainmap.v1"
DEFAULT_FALLBACK_AFTER_MS = 3000


class BrainmapFamily(str, Enum):
    SOCIAL = "SOCIAL"
    CAPABILITY = "CAPABILITY"
    ASSISTANT_BEHAVIOR_META = "ASSISTANT_BEHAVIOR_META"
    MODEL_PROVIDER_STATUS = "MODEL_PROVIDER_STATUS"
    DSPM_FACTUAL = "DSPM_FACTUAL"
    TASK_FRAME = "TASK_FRAME"
    SCAN_OPERATION = "SCAN_OPERATION"
    ARTIFACT = "ARTIFACT"
    PROFESSIONAL_WORKFLOW = "PROFESSIONAL_WORKFLOW"
    LANGUAGE_AND_OUTPUT_QUALITY = "LANGUAGE_AND_OUTPUT_QUALITY"
    UTILITY = "UTILITY"
    UNSUPPORTED_OR_OUT_OF_SCOPE = "UNSUPPORTED_OR_OUT_OF_SCOPE"
    AMBIGUOUS_OR_UNKNOWN = "AMBIGUOUS_OR_UNKNOWN"


@dataclass(frozen=True)
class BrainmapSituation:
    family: BrainmapFamily
    subtype: str
    route_id: str | None = None
    task_type: str | None = None
    confidence: float = 0.75
    importance: str = "normal"


@dataclass(frozen=True)
class BrainmapContext:
    language: str = "az"
    user_tone: str | None = None
    user_emotion: str | None = None
    language_source: str = "resolved"
    language_confidence: float = 0.9


@dataclass(frozen=True)
class BrainmapContent:
    content_goal: str
    must_say: list[str] = field(default_factory=list)
    may_say: list[str] = field(default_factory=list)
    must_not_say: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class BrainmapEvidence:
    evidence_required: bool = False
    evidence_available: bool = False
    metric_name: str | None = None
    scan_id: str | None = None
    source_label: str | None = None


@dataclass(frozen=True)
class BrainmapPolicy:
    context_policy: dict[str, Any] = field(default_factory=dict)
    response_policy: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BrainmapSafety:
    safety_policy: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BrainmapFallback:
    fallback_plan: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BrainmapStyle:
    style: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BrainmapRenderPlan:
    renderer_family: str = "deterministic_renderer"
    expected_answer_shape: str = "short_text"


@dataclass(frozen=True)
class ResponseBrainmap:
    brainmap_id: str
    version: str
    situation: BrainmapSituation
    context: BrainmapContext
    content: BrainmapContent
    evidence: BrainmapEvidence
    policy: BrainmapPolicy
    safety: BrainmapSafety
    fallback: BrainmapFallback
    style: BrainmapStyle
    render_plan: BrainmapRenderPlan
    debug_safe_metadata: dict[str, Any] = field(default_factory=dict)


def _fold(message: str) -> str:
    text = language_service.normalize_for_intent(message or "").lower()
    text = normalize_message(text).lower()
    replacements = {
        "ə": "e",
        "ı": "i",
        "ğ": "g",
        "ö": "o",
        "ş": "s",
        "ç": "c",
        "ü": "u",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    return re.sub(r"\s+", " ", text).strip()


def _has_any(text: str, terms: tuple[str, ...]) -> bool:
    return any(term in text for term in terms)


def _short_id(*parts: str | None) -> str:
    blob = "|".join(str(part or "") for part in parts)
    return "rbm_" + hashlib.sha1(blob.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _safe_str(value: Any, limit: int = 120) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:limit]


def _situation_from_message(
    *,
    message: str,
    language: str,
    metadata: Mapping[str, Any] | None,
    route_id: str | None,
    task_type: str | None,
    intent: str | None,
    session_state: Mapping[str, Any] | None,
) -> BrainmapSituation:
    meta = metadata or {}
    text = _fold(message)
    raw = (message or "").lower()
    joined = f"{text} {raw}"
    route = route_id or _safe_str(meta.get("route_id")) or _safe_str(meta.get("route"))
    task = task_type or _safe_str(meta.get("task_type"))
    active_previous = bool((session_state or {}).get("last_answer_text") or (session_state or {}).get("last_answer_summary"))

    repeat_signals = ("eyni cavab", "same answer", "tekrar", "təkrar", "tekrarl", "repeating", "repeat")
    if _has_any(joined, repeat_signals):
        return BrainmapSituation(BrainmapFamily.ASSISTANT_BEHAVIOR_META, "repeated_answer_complaint", route, task, 0.92, "high")

    too_long_signals = ("cox uzun", "çox uzun", "uzun yaz", "uzatma", "uzad", "too long", "shorter", "qisa cavab", "qısa cavab")
    if _has_any(joined, too_long_signals):
        return BrainmapSituation(BrainmapFamily.ASSISTANT_BEHAVIOR_META, "response_too_long_feedback", route, task, 0.9, "high")

    too_short_signals = ("cox qisa", "çox qısa", "daha etrafli", "daha ətraflı", "more detail", "too short")
    if _has_any(joined, too_short_signals):
        return BrainmapSituation(BrainmapFamily.ASSISTANT_BEHAVIOR_META, "response_too_short_feedback", route, task, 0.86, "normal")

    quality_signals = ("ne deyirsen", "nə deyirsən", "anlamadim", "anlamadım", "basa dusmedim", "başa düşmədim", "what are you saying")
    bare_clarify = text in {"ne", "ne?", "what", "what?", "huh", "why", "why?"} or raw.strip() in {"nə?", "nə", "what?", "huh?"}
    if _has_any(joined, quality_signals) or (bare_clarify and active_previous):
        return BrainmapSituation(BrainmapFamily.ASSISTANT_BEHAVIOR_META, "clarify_previous_response", route, task, 0.84, "high")

    answer_quality = ("bu ne cavab", "bu nə cavab", "pis cavab", "wrong answer", "bad answer")
    if _has_any(joined, answer_quality):
        return BrainmapSituation(BrainmapFamily.ASSISTANT_BEHAVIOR_META, "answer_quality_complaint", route, task, 0.84, "high")

    internal_leak = ("internal", "hidden prompt", "system prompt", "zəif azərbaycan", "zeif azerbaycan", "ceviri", "çeviri")
    if _has_any(joined, internal_leak):
        return BrainmapSituation(BrainmapFamily.ASSISTANT_BEHAVIOR_META, "internal_note_leakage_complaint", route, task, 0.82, "critical")

    # Fact-free correction/meta answers about the assistant's own previous
    # behavior: classify as ASSISTANT_BEHAVIOR_META (not ambiguous) so the
    # controlled verbalizer can reword them naturally and the fallback
    # variants stay correction-appropriate.
    if task == "complaint_about_wrong_route" or route == "wrong_route_complaint":
        return BrainmapSituation(BrainmapFamily.ASSISTANT_BEHAVIOR_META, "wrong_route_correction", route, task, 0.88, "high")
    if task == "why_misunderstood_previous_request":
        # Distinct from "explain_previous_response": that subtype is handled by
        # the early P4a policy-answer path; this one must reach the meta route.
        # (why_previous_answer is NOT classified here: its answers can embed
        # evidence facts and must never be replaced by a family variant.)
        return BrainmapSituation(BrainmapFamily.ASSISTANT_BEHAVIOR_META, "explain_previous_route", route, task, 0.86, "high")

    if provider_health.is_model_status_question(message) or task in {"model_status", "provider_unavailable"} or route == "model_status":
        subtype = "model_status_question" if task == "model_status" or route == "model_status" else "provider_unknown"
        return BrainmapSituation(BrainmapFamily.MODEL_PROVIDER_STATUS, subtype, route, task, 0.94, "high")

    if task in {"small_talk"} or intent in {"small_talk"} or route in {"greeting", "small_talk_status", "greeting_status"}:
        subtype = "casual_social"
        if "greeting" in str(route or "") or _has_any(text, ("salam", "hello", "hi")):
            count = int((meta.get("social_repetition_count") or (session_state or {}).get("social_repetition_count") or 0) or 0)
            subtype = "repeated_greeting" if count > 1 else "greeting"
        elif _has_any(text, ("necesen", "necəsən", "how are")):
            subtype = "status_check"
        elif _has_any(text, ("sag ol", "tesekkur", "thanks")):
            subtype = "thanks"
        elif _has_any(text, ("zorsan", "super", "bravo", "great", "good job")):
            subtype = "praise"
        return BrainmapSituation(BrainmapFamily.SOCIAL, subtype, route, task, 0.9, "normal")

    if task in {"capability", "capability_help"} or intent in {"capability", "capability_help"} or route == "capability":
        subtype = "capability_typo" if _has_any(text, ("edebilirsen", "ede bilersen", "neler", "neeler")) else "general_capability"
        return BrainmapSituation(BrainmapFamily.CAPABILITY, subtype, route, task, 0.9, "normal")

    if task in {"language_complaint"} or route in {"language_complaint", "malformed_output_complaint"}:
        subtype = "language_complaint" if route == "language_complaint" else "malformed_output_complaint"
        return BrainmapSituation(BrainmapFamily.LANGUAGE_AND_OUTPUT_QUALITY, subtype, route, task, 0.9, "high")

    if task in {"simple_arithmetic"} or route == "simple_arithmetic":
        return BrainmapSituation(BrainmapFamily.UTILITY, "arithmetic", route, task, 0.95, "low")

    if task in {"severity_count", "count_findings"}:
        return BrainmapSituation(BrainmapFamily.DSPM_FACTUAL, "severity_count", route, task, 0.92, "normal")
    if task in {"severity_distribution"}:
        return BrainmapSituation(BrainmapFamily.DSPM_FACTUAL, "severity_distribution", route, task, 0.9, "normal")
    if task in {"severity_findings_list", "critical_findings_list", "list"}:
        return BrainmapSituation(BrainmapFamily.DSPM_FACTUAL, "finding_list", route, task, 0.88, "normal")
    if task in {"details", "critical_finding_details"}:
        return BrainmapSituation(BrainmapFamily.DSPM_FACTUAL, "finding_detail", route, task, 0.88, "normal")
    if task in {"selected_finding_detail"}:
        return BrainmapSituation(BrainmapFamily.DSPM_FACTUAL, "selected_finding_detail", route, task, 0.9, "high")
    if task in {"selected_finding_remediation"} or route == "selected_finding_remediation_followup":
        return BrainmapSituation(BrainmapFamily.PROFESSIONAL_WORKFLOW, "selected_finding_remediation", route, task, 0.92, "high")
    if task in {"selected_finding_remediation_clarification"}:
        return BrainmapSituation(BrainmapFamily.TASK_FRAME, "selected_finding_remediation_clarification", route, task, 0.86, "high")

    situation_id = str(meta.get("situation_id") or "")
    p0_id = str(meta.get("p0_situation_id") or meta.get("answer_type") or "")
    if "scan_" in situation_id or "scan_" in p0_id or task in {"scan_delta"} or route == "scan_delta_or_what_changed":
        subtype = "scan_delta" if task == "scan_delta" or route == "scan_delta_or_what_changed" else "scan_action_capability_question"
        return BrainmapSituation(BrainmapFamily.SCAN_OPERATION, subtype, route, task, 0.88, "normal")

    if meta.get("task_frame_controller_used") or str(task or "").startswith("scoped_"):
        return BrainmapSituation(BrainmapFamily.TASK_FRAME, "short_followup_resolution", route, task, 0.86, "high")

    if task in {"artifact_export", "report_generation", "report", "export"} or route == "artifact_link_or_download_help":
        return BrainmapSituation(BrainmapFamily.ARTIFACT, "artifact_create", route, task, 0.82, "normal")

    if task in {"fix_now", "risk_type_breakdown", "technical_remediation", "manager_summary", "triage_plan"} or route in {"fix_now_top_risks", "professional_followup"}:
        subtype = "fix_now" if task == "fix_now" or route == "fix_now_top_risks" else str(task or "triage_plan")
        return BrainmapSituation(BrainmapFamily.PROFESSIONAL_WORKFLOW, subtype, route, task, 0.84, "normal")

    if task in {"provider_unavailable", "unsupported_operation"}:
        return BrainmapSituation(BrainmapFamily.UNSUPPORTED_OR_OUT_OF_SCOPE, "unavailable_capability", route, task, 0.8, "normal")

    if bare_clarify:
        subtype = "clarification_required"
        return BrainmapSituation(BrainmapFamily.AMBIGUOUS_OR_UNKNOWN, subtype, route, task, 0.65, "high")

    return BrainmapSituation(BrainmapFamily.AMBIGUOUS_OR_UNKNOWN, "ambiguous_complex_input", route, task, 0.55, "normal")


def _metric_for(situation: BrainmapSituation, metadata: Mapping[str, Any] | None) -> str | None:
    meta_metric = _safe_str((metadata or {}).get("metric_name"))
    if meta_metric:
        return meta_metric
    if situation.family == BrainmapFamily.DSPM_FACTUAL:
        if situation.subtype in {"severity_count", "finding_list", "finding_detail", "selected_finding_detail"}:
            return "file_level_finding_count"
        if situation.subtype == "severity_distribution":
            return "severity_distribution_file_level"
        if situation.subtype == "risk_type_breakdown":
            return "risk_type_file_count"
    if situation.family == BrainmapFamily.PROFESSIONAL_WORKFLOW and situation.subtype == "selected_finding_remediation":
        return "file_level_finding_count"
    return None


def _context_policy_for(situation: BrainmapSituation) -> dict[str, Any]:
    family = situation.family
    selected_allowed = family == BrainmapFamily.DSPM_FACTUAL and situation.subtype in {
        "finding_detail",
        "selected_finding_detail",
        "scoped_finding_detail",
    }
    if family == BrainmapFamily.PROFESSIONAL_WORKFLOW and situation.subtype in {
        "selected_finding_remediation",
        "technical_remediation",
        "manager_summary",
    }:
        selected_allowed = True
    previous_allowed = family == BrainmapFamily.ASSISTANT_BEHAVIOR_META and situation.subtype in {
        "clarify_previous_response",
        "explain_previous_response",
        "answer_quality_complaint",
        "internal_note_leakage_complaint",
    }
    return {
        "selected_finding_allowed": selected_allowed,
        "task_frame_allowed": family in {BrainmapFamily.TASK_FRAME, BrainmapFamily.DSPM_FACTUAL, BrainmapFamily.PROFESSIONAL_WORKFLOW},
        "previous_answer_allowed": previous_allowed,
        "count_scope_allowed": family in {BrainmapFamily.DSPM_FACTUAL, BrainmapFamily.TASK_FRAME, BrainmapFamily.PROFESSIONAL_WORKFLOW},
        "artifact_allowed": family == BrainmapFamily.ARTIFACT,
        "provider_health_required": family == BrainmapFamily.MODEL_PROVIDER_STATUS,
        "ai_arbiter_required": family == BrainmapFamily.AMBIGUOUS_OR_UNKNOWN and situation.importance in {"high", "critical"},
    }


def _response_policy_for(situation: BrainmapSituation, current_provider_final_allowed: bool | None) -> dict[str, Any]:
    family = situation.family
    fixed_provider_denied = {
        BrainmapFamily.SOCIAL,
        BrainmapFamily.CAPABILITY,
        BrainmapFamily.ASSISTANT_BEHAVIOR_META,
        BrainmapFamily.MODEL_PROVIDER_STATUS,
        BrainmapFamily.TASK_FRAME,
        BrainmapFamily.SCAN_OPERATION,
        BrainmapFamily.LANGUAGE_AND_OUTPUT_QUALITY,
        BrainmapFamily.UTILITY,
        BrainmapFamily.UNSUPPORTED_OR_OUT_OF_SCOPE,
        BrainmapFamily.DSPM_FACTUAL,
        BrainmapFamily.PROFESSIONAL_WORKFLOW,
        BrainmapFamily.ARTIFACT,
    }
    if family in fixed_provider_denied:
        provider_final_allowed = False
    elif family == BrainmapFamily.AMBIGUOUS_OR_UNKNOWN:
        provider_final_allowed = bool(current_provider_final_allowed)
    else:
        provider_final_allowed = False
    max_sentences = 2
    max_bullets = 0
    expected_shape = "short_text"
    if family == BrainmapFamily.SOCIAL:
        max_sentences = 1
    if family == BrainmapFamily.DSPM_FACTUAL:
        max_sentences = 6
        max_bullets = 8
        expected_shape = "evidence_grounded_fact"
    if family == BrainmapFamily.PROFESSIONAL_WORKFLOW:
        max_sentences = 8
        max_bullets = 6
        expected_shape = "structured_workflow"
    if situation.subtype == "selected_finding_remediation":
        max_sentences = 10
        max_bullets = 8
        expected_shape = "selected_finding_remediation_steps"
    return {
        "provider_final_allowed": provider_final_allowed,
        "ai_verbalizer_allowed": family in {
            BrainmapFamily.SOCIAL,
            BrainmapFamily.CAPABILITY,
            BrainmapFamily.ASSISTANT_BEHAVIOR_META,
            BrainmapFamily.LANGUAGE_AND_OUTPUT_QUALITY,
            BrainmapFamily.UNSUPPORTED_OR_OUT_OF_SCOPE,
            BrainmapFamily.AMBIGUOUS_OR_UNKNOWN,
        },
        "deterministic_renderer_allowed": True,
        "fallback_allowed": True,
        "fallback_after_ms": DEFAULT_FALLBACK_AFTER_MS,
        "max_sentences": max_sentences,
        "max_bullets": max_bullets,
        "response_length_budget": "short" if max_sentences <= 2 else "structured",
        "expected_answer_shape": expected_shape,
    }


def _style_for(situation: BrainmapSituation, metadata: Mapping[str, Any] | None, session_state: Mapping[str, Any] | None) -> dict[str, Any]:
    preferred = (metadata or {}).get("preferred_verbosity") or (session_state or {}).get("preferred_verbosity") or "default"
    variation_required = situation.family in {
        BrainmapFamily.SOCIAL,
        BrainmapFamily.ASSISTANT_BEHAVIOR_META,
        BrainmapFamily.CAPABILITY,
        BrainmapFamily.LANGUAGE_AND_OUTPUT_QUALITY,
    }
    if situation.family in {BrainmapFamily.SOCIAL, BrainmapFamily.ASSISTANT_BEHAVIOR_META}:
        avoid_last_n = 5
    elif situation.family in {BrainmapFamily.CAPABILITY, BrainmapFamily.LANGUAGE_AND_OUTPUT_QUALITY}:
        avoid_last_n = 3
    else:
        avoid_last_n = 1
    if situation.family == BrainmapFamily.DSPM_FACTUAL:
        variation_required = False
        avoid_last_n = 0
    return {
        "preferred_verbosity": preferred,
        "tone": "professional",
        "formality": "default",
        "avoid_repetition": True,
        "variation_required": variation_required,
        "avoid_repeating_last_n": avoid_last_n,
        "preferred_verbosity_applied": preferred != "default",
    }


def _content_for(situation: BrainmapSituation) -> BrainmapContent:
    must_not = ["raw secrets", "hidden prompt", "chain-of-thought", "unsupported capability claim"]
    if situation.family in {BrainmapFamily.SOCIAL, BrainmapFamily.ASSISTANT_BEHAVIOR_META}:
        must_not.extend(["selected finding context", "count/list/compare fallback"])
    goals = {
        BrainmapFamily.SOCIAL: "Answer the social turn briefly without DSPM evidence claims.",
        BrainmapFamily.CAPABILITY: "State supported Copilot capabilities and boundaries.",
        BrainmapFamily.ASSISTANT_BEHAVIOR_META: "Address the user's feedback about the assistant response behavior.",
        BrainmapFamily.MODEL_PROVIDER_STATUS: "Report stored provider health without probing the provider.",
        BrainmapFamily.DSPM_FACTUAL: "Answer using available scan evidence and metric policy.",
        BrainmapFamily.PROFESSIONAL_WORKFLOW: "Give evidence-grounded workflow guidance.",
        BrainmapFamily.SCAN_OPERATION: "Respect the scan-operation capability boundary.",
    }
    must_say: list[str] = []
    if situation.subtype == "response_too_long_feedback":
        must_say = ["acknowledge verbosity feedback", "use shorter answers going forward"]
    elif situation.subtype == "repeated_answer_complaint":
        must_say = ["acknowledge repetition", "require variation"]
    elif situation.family == BrainmapFamily.MODEL_PROVIDER_STATUS:
        must_say = ["stored provider health status", "deterministic routes still work"]
    elif situation.family == BrainmapFamily.DSPM_FACTUAL:
        must_say = ["evidence-backed count/list/detail", "scan id and metric when available"]
    elif situation.subtype == "selected_finding_remediation":
        must_say = ["selected filename", "severity", "risk types", "step-by-step remediation", "scan id and metric when available"]
    return BrainmapContent(
        content_goal=goals.get(situation.family, "Produce a safe, policy-controlled response."),
        must_say=must_say,
        may_say=[],
        must_not_say=must_not,
    )


def build_response_brainmap(
    *,
    message: str,
    language: str = "az",
    metadata: Mapping[str, Any] | None = None,
    route_id: str | None = None,
    task_type: str | None = None,
    intent: str | None = None,
    session_state: Mapping[str, Any] | None = None,
    current_provider_final_allowed: bool | None = None,
    evidence_available: bool | None = None,
    scan_id: str | None = None,
    source_label: str | None = None,
    language_source: str | None = None,
    language_confidence: float | None = None,
) -> ResponseBrainmap:
    situation = _situation_from_message(
        message=message,
        language=language,
        metadata=metadata,
        route_id=route_id,
        task_type=task_type,
        intent=intent,
        session_state=session_state,
    )
    context_policy = _context_policy_for(situation)
    response_policy = _response_policy_for(situation, current_provider_final_allowed)
    metric_name = _metric_for(situation, metadata)
    evidence_required = situation.family in {BrainmapFamily.DSPM_FACTUAL, BrainmapFamily.PROFESSIONAL_WORKFLOW}
    if evidence_available is None:
        evidence_available = bool((metadata or {}).get("canonical_answer_used") or (metadata or {}).get("evidence_count") or source_label)
        if situation.family == BrainmapFamily.DSPM_FACTUAL and (metadata or {}).get("contract_route"):
            evidence_available = True
    style = _style_for(situation, metadata, session_state)
    fallback_plan = {
        "fallback_family": situation.family.value.lower(),
        "fallback_variant_family": situation.subtype,
        "fallback_after_ms": DEFAULT_FALLBACK_AFTER_MS,
        "fallback_must_say": list(_content_for(situation).must_say[:4]),
        "fallback_must_not_say": ["raw secrets", "hidden prompt", "unsupported capability claim"],
    }
    safety_policy = {
        "no_raw_secrets": True,
        "no_hallucinated_findings": True,
        "no_internal_text": True,
        "no_unsupported_capability_claim": True,
        "language_lock": language if language in {"az", "en", "ru"} else "az",
        "forbidden_strings": ["Azerbaijani answer:", "hidden prompt", "chain-of-thought"],
    }
    resolved_language = language if language in {"az", "en", "ru"} else "az"
    meta_map = metadata or {}
    resolved_language_source = (
        language_source
        or _safe_str(meta_map.get("language_decision_source"))
        or "resolved"
    )
    if language_confidence is not None:
        resolved_language_confidence = float(language_confidence)
    else:
        try:
            resolved_language_confidence = float(meta_map.get("language_decision_confidence"))
        except (TypeError, ValueError):
            resolved_language_confidence = 0.9
    return ResponseBrainmap(
        brainmap_id=_short_id(BRAINMAP_VERSION, situation.family.value, situation.subtype, route_id, task_type, message[:80]),
        version=BRAINMAP_VERSION,
        situation=situation,
        context=BrainmapContext(
            language=resolved_language,
            language_source=resolved_language_source,
            language_confidence=resolved_language_confidence,
        ),
        content=_content_for(situation),
        evidence=BrainmapEvidence(
            evidence_required=evidence_required,
            evidence_available=bool(evidence_available),
            metric_name=metric_name,
            scan_id=_safe_str(scan_id or (metadata or {}).get("scan_id")),
            source_label=_safe_str(source_label),
        ),
        policy=BrainmapPolicy(context_policy=context_policy, response_policy=response_policy),
        safety=BrainmapSafety(safety_policy=safety_policy),
        fallback=BrainmapFallback(fallback_plan=fallback_plan),
        style=BrainmapStyle(style=style),
        render_plan=BrainmapRenderPlan(
            renderer_family="deterministic_renderer",
            expected_answer_shape=str(response_policy.get("expected_answer_shape") or "short_text"),
        ),
        debug_safe_metadata={
            "policy_source": "p4a_response_brainmap",
            "route_id": situation.route_id,
            "task_type": situation.task_type,
        },
    )


def brainmap_to_metadata(brainmap: ResponseBrainmap) -> dict[str, Any]:
    context_policy = brainmap.policy.context_policy
    response_policy = brainmap.policy.response_policy
    style = brainmap.style.style
    layer_meta = _layer_metadata_for_brainmap(brainmap)
    return {
        "brainmap_used": True,
        "brainmap_id": brainmap.brainmap_id,
        "brainmap_version": brainmap.version,
        "brainmap_situation_family": brainmap.situation.family.value,
        "brainmap_situation_subtype": brainmap.situation.subtype,
        "brainmap_language": brainmap.context.language,
        "brainmap_response_language": brainmap.context.language,
        "brainmap_language_source": brainmap.context.language_source,
        "brainmap_language_confidence": round(float(brainmap.context.language_confidence), 2),
        "brainmap_route_id": brainmap.situation.route_id,
        "brainmap_confidence": brainmap.situation.confidence,
        "brainmap_importance": brainmap.situation.importance,
        "brainmap_provider_final_allowed": bool(response_policy.get("provider_final_allowed")),
        "brainmap_ai_verbalizer_allowed": bool(response_policy.get("ai_verbalizer_allowed")),
        "brainmap_deterministic_renderer_allowed": bool(response_policy.get("deterministic_renderer_allowed")),
        "brainmap_fallback_after_ms": int(response_policy.get("fallback_after_ms") or DEFAULT_FALLBACK_AFTER_MS),
        "brainmap_variation_required": bool(style.get("variation_required")),
        "brainmap_avoid_repeating_last_n": int(style.get("avoid_repeating_last_n") or 0),
        "brainmap_preferred_verbosity": style.get("preferred_verbosity"),
        "brainmap_response_length_budget": response_policy.get("response_length_budget"),
        "brainmap_expected_answer_shape": response_policy.get("expected_answer_shape"),
        "brainmap_evidence_required": bool(brainmap.evidence.evidence_required),
        "brainmap_evidence_available": bool(brainmap.evidence.evidence_available),
        "brainmap_metric_name": brainmap.evidence.metric_name,
        "brainmap_previous_answer_allowed": bool(context_policy.get("previous_answer_allowed")),
        "brainmap_selected_finding_allowed": bool(context_policy.get("selected_finding_allowed")),
        "brainmap_task_frame_allowed": bool(context_policy.get("task_frame_allowed")),
        "brainmap_ai_arbiter_required": bool(context_policy.get("ai_arbiter_required")),
        "brainmap_policy_source": "p4a_response_brainmap",
        **layer_meta,
    }


def _provider_denied_reason_for(brainmap: ResponseBrainmap) -> str | None:
    if bool(brainmap.policy.response_policy.get("provider_final_allowed")):
        return None
    family = brainmap.situation.family
    subtype = brainmap.situation.subtype
    if family in {BrainmapFamily.DSPM_FACTUAL, BrainmapFamily.PROFESSIONAL_WORKFLOW}:
        return "structured_evidence_route"
    if family == BrainmapFamily.TASK_FRAME:
        return "structured_task_frame_route"
    if family == BrainmapFamily.ASSISTANT_BEHAVIOR_META:
        return "assistant_meta_no_provider"
    if family == BrainmapFamily.MODEL_PROVIDER_STATUS:
        return "model_status_route"
    if family == BrainmapFamily.SCAN_OPERATION:
        return "scan_operation_boundary"
    if family == BrainmapFamily.ARTIFACT:
        return "artifact_structured_route"
    if family == BrainmapFamily.UTILITY:
        return "utility_no_provider"
    if family == BrainmapFamily.CAPABILITY:
        return "capability_no_provider"
    if family == BrainmapFamily.SOCIAL:
        return "social_no_provider_final"
    if subtype == "selected_finding_remediation_clarification":
        return "missing_selected_finding"
    return "brainmap_policy_denied"


def _verbalizer_denied_reason_for(brainmap: ResponseBrainmap) -> str | None:
    if bool(brainmap.policy.response_policy.get("ai_verbalizer_allowed")) and not brainmap.evidence.evidence_required:
        return None
    if brainmap.evidence.evidence_required:
        return "evidence_required"
    if brainmap.situation.family in {
        BrainmapFamily.TASK_FRAME,
        BrainmapFamily.SCAN_OPERATION,
        BrainmapFamily.MODEL_PROVIDER_STATUS,
        BrainmapFamily.UTILITY,
        BrainmapFamily.ARTIFACT,
        BrainmapFamily.PROFESSIONAL_WORKFLOW,
        BrainmapFamily.DSPM_FACTUAL,
    }:
        return "structured_renderer_required"
    return "brainmap_policy_denied"


def _layer_metadata_for_brainmap(brainmap: ResponseBrainmap) -> dict[str, Any]:
    family = brainmap.situation.family
    subtype = brainmap.situation.subtype
    confidence = brainmap.situation.confidence
    has_previous_context = bool(brainmap.policy.context_policy.get("previous_answer_allowed"))
    is_short_context = subtype in {"clarify_previous_response", "explain_previous_response", "clarification_required"}
    importance = ai_layers.contextual_importance(
        brainmap.situation.importance,
        has_context=has_previous_context,
        is_short=is_short_context,
    )
    provider_denied = _provider_denied_reason_for(brainmap)
    verbalizer_denied = _verbalizer_denied_reason_for(brainmap)

    base_sources = [ai_layers.AILayer.INPUT_UNDERSTANDING, ai_layers.AILayer.SITUATION_ROUTE]
    if family == BrainmapFamily.DSPM_FACTUAL:
        return ai_layers.layer_transition_metadata(
            active_layer=ai_layers.AILayer.EVIDENCE_RAG,
            source_layers=[*base_sources, ai_layers.AILayer.CONVERSATION_STATE],
            next_layer=ai_layers.AILayer.POLISH_VALIDATION,
            blocked_layers=["CONTROLLED_VERBALIZER_PROVIDER_FINAL"],
            policy_reason="structured_evidence_route",
            provider_denied_reason=provider_denied,
            verbalizer_denied_reason=verbalizer_denied,
            route_confidence=confidence,
            importance=importance,
            should_use_deterministic_renderer=True,
            state_read="scan_evidence",
            state_write="selected_finding" if subtype in {"finding_detail", "selected_finding_detail"} else "shown_items",
            structured_only=True,
        )

    if family in {BrainmapFamily.TASK_FRAME, BrainmapFamily.PROFESSIONAL_WORKFLOW}:
        policy_reason = "selected_finding_structured_remediation" if subtype == "selected_finding_remediation" else "structured_workflow_route"
        return ai_layers.layer_transition_metadata(
            active_layer=ai_layers.AILayer.TASK_WORKFLOW,
            source_layers=[*base_sources, ai_layers.AILayer.CONVERSATION_STATE, ai_layers.AILayer.EVIDENCE_RAG],
            next_layer=ai_layers.AILayer.POLISH_VALIDATION,
            blocked_layers=["CONTROLLED_VERBALIZER_PROVIDER_FINAL"],
            policy_reason=policy_reason,
            provider_denied_reason=provider_denied,
            verbalizer_denied_reason=verbalizer_denied,
            route_confidence=confidence,
            importance=importance,
            should_use_deterministic_renderer=True,
            state_read="selected_finding",
            state_write="selected_finding",
            structured_only=True,
        )

    if family == BrainmapFamily.ASSISTANT_BEHAVIOR_META:
        is_preference = subtype in {"response_too_long_feedback", "response_too_short_feedback", "style_preference_update"}
        active = ai_layers.AILayer.MEMORY_PREFERENCE if is_preference else ai_layers.AILayer.CONVERSATION_STATE
        return ai_layers.layer_transition_metadata(
            active_layer=active,
            source_layers=[*base_sources, ai_layers.AILayer.CONVERSATION_STATE],
            next_layer=ai_layers.AILayer.POLISH_VALIDATION,
            blocked_layers=["PROVIDER_FINAL"],
            policy_reason="assistant_behavior_meta_policy",
            provider_denied_reason=provider_denied,
            verbalizer_denied_reason=verbalizer_denied,
            route_confidence=confidence,
            importance=importance,
            should_use_deterministic_renderer=True,
            state_read="last_answer_text" if not is_preference else "preferred_verbosity",
            state_write="preferred_verbosity" if is_preference else None,
        )

    if family == BrainmapFamily.MODEL_PROVIDER_STATUS:
        return ai_layers.layer_transition_metadata(
            active_layer=ai_layers.AILayer.FALLBACK,
            source_layers=[*base_sources, ai_layers.AILayer.SAFETY_POLICY],
            next_layer=ai_layers.AILayer.POLISH_VALIDATION,
            blocked_layers=["PROVIDER_FINAL", "CONTROLLED_VERBALIZER"],
            policy_reason="provider_health_snapshot_route",
            provider_denied_reason=provider_denied,
            verbalizer_denied_reason=verbalizer_denied,
            route_confidence=confidence,
            importance=importance,
            should_use_deterministic_renderer=True,
            state_read="provider_health_snapshot",
        )

    if family == BrainmapFamily.SCAN_OPERATION:
        return ai_layers.layer_transition_metadata(
            active_layer=ai_layers.AILayer.SAFETY_POLICY,
            source_layers=base_sources,
            next_layer=ai_layers.AILayer.POLISH_VALIDATION,
            blocked_layers=["PROVIDER_FINAL"],
            policy_reason="scan_operation_boundary",
            provider_denied_reason=provider_denied,
            verbalizer_denied_reason=verbalizer_denied,
            route_confidence=confidence,
            importance=importance,
            should_use_deterministic_renderer=True,
        )

    if family in {BrainmapFamily.SOCIAL, BrainmapFamily.CAPABILITY, BrainmapFamily.LANGUAGE_AND_OUTPUT_QUALITY, BrainmapFamily.UNSUPPORTED_OR_OUT_OF_SCOPE}:
        return ai_layers.layer_transition_metadata(
            active_layer=ai_layers.AILayer.CONTROLLED_VERBALIZER,
            source_layers=[*base_sources, ai_layers.AILayer.RESPONSE_BRAINMAP],
            next_layer=ai_layers.AILayer.POLISH_VALIDATION,
            blocked_layers=["PROVIDER_FINAL"],
            policy_reason="safe_non_evidence_verbalizer_boundary",
            provider_denied_reason=provider_denied,
            verbalizer_denied_reason=verbalizer_denied,
            route_confidence=confidence,
            importance=importance,
            should_use_deterministic_renderer=not bool(brainmap.policy.response_policy.get("ai_verbalizer_allowed")),
        )

    if family == BrainmapFamily.ARTIFACT:
        return ai_layers.layer_transition_metadata(
            active_layer=ai_layers.AILayer.TASK_WORKFLOW,
            source_layers=[*base_sources, ai_layers.AILayer.CONVERSATION_STATE],
            next_layer=ai_layers.AILayer.POLISH_VALIDATION,
            blocked_layers=["PROVIDER_FINAL", "CONTROLLED_VERBALIZER"],
            policy_reason="artifact_structured_route",
            provider_denied_reason=provider_denied,
            verbalizer_denied_reason=verbalizer_denied,
            route_confidence=confidence,
            importance=importance,
            should_use_deterministic_renderer=True,
            structured_only=True,
        )

    if family == BrainmapFamily.UTILITY:
        return ai_layers.layer_transition_metadata(
            active_layer=ai_layers.AILayer.RESPONSE_BRAINMAP,
            source_layers=base_sources,
            next_layer=ai_layers.AILayer.POLISH_VALIDATION,
            blocked_layers=["PROVIDER_FINAL", "CONTROLLED_VERBALIZER"],
            policy_reason="utility_deterministic_route",
            provider_denied_reason=provider_denied,
            verbalizer_denied_reason=verbalizer_denied,
            route_confidence=confidence,
            importance=importance,
            should_use_deterministic_renderer=True,
        )

    return ai_layers.layer_transition_metadata(
        active_layer=ai_layers.AILayer.SITUATION_ROUTE,
        source_layers=[ai_layers.AILayer.INPUT_UNDERSTANDING, ai_layers.AILayer.CONVERSATION_STATE],
        next_layer=ai_layers.AILayer.POLISH_VALIDATION,
        blocked_layers=[],
        policy_reason="ambiguous_route_policy",
        provider_denied_reason=provider_denied,
        verbalizer_denied_reason=verbalizer_denied,
        route_confidence=confidence,
        importance=importance,
        should_escalate_to_ai_arbiter=bool(brainmap.policy.context_policy.get("ai_arbiter_required")),
        should_clarify=subtype == "clarification_required",
        should_use_deterministic_renderer=not bool(brainmap.policy.response_policy.get("provider_final_allowed")),
        state_read="last_answer_text" if is_short_context else None,
    )


def ensure_response_brainmap(
    metadata: Mapping[str, Any] | None,
    *,
    message: str,
    language: str,
    route_id: str | None = None,
    task_type: str | None = None,
    intent: str | None = None,
    session_state: Mapping[str, Any] | None = None,
    current_provider_final_allowed: bool | None = None,
    evidence_available: bool | None = None,
    scan_id: str | None = None,
    source_label: str | None = None,
) -> tuple[dict[str, Any], ResponseBrainmap]:
    merged = dict(metadata or {})
    if merged.get("brainmap_used"):
        brainmap = build_response_brainmap(
            message=message,
            language=language,
            metadata=merged,
            route_id=route_id,
            task_type=task_type,
            intent=intent,
            session_state=session_state,
            current_provider_final_allowed=current_provider_final_allowed,
            evidence_available=evidence_available,
            scan_id=scan_id,
            source_label=source_label,
        )
        return merged, brainmap
    brainmap = build_response_brainmap(
        message=message,
        language=language,
        metadata=merged,
        route_id=route_id,
        task_type=task_type,
        intent=intent,
        session_state=session_state,
        current_provider_final_allowed=current_provider_final_allowed,
        evidence_available=evidence_available,
        scan_id=scan_id,
        source_label=source_label,
    )
    merged.update(brainmap_to_metadata(brainmap))
    return merged, brainmap


def apply_brainmap_policy(brainmap: ResponseBrainmap) -> dict[str, Any]:
    return {
        "provider_final_allowed": bool(brainmap.policy.response_policy.get("provider_final_allowed")),
        "deterministic_renderer_allowed": bool(brainmap.policy.response_policy.get("deterministic_renderer_allowed")),
        "fallback_after_ms": int(brainmap.policy.response_policy.get("fallback_after_ms") or DEFAULT_FALLBACK_AFTER_MS),
    }


def deterministic_policy_answer(brainmap: ResponseBrainmap, language: str = "az") -> str:
    subtype = brainmap.situation.subtype
    if language == "az":
        if subtype == "response_too_long_feedback":
            return "Oldu, bundan sonra daha qısa cavab verəcəyəm."
        if subtype == "response_too_short_feedback":
            return "Oldu, lazım olanda daha ətraflı izah verəcəyəm."
        if subtype == "repeated_answer_complaint":
            return "Haqlısınız, eyni cavab təkrarlanmamalıdır; növbəti sosial cavablarda variantlığı qoruyacağam."
        if subtype in {"clarify_previous_response", "explain_previous_response"}:
            return "Üzr istəyirəm, əvvəlki cavabım aydın deyildisə, onu daha sadə formada yenidən izah edə bilərəm."
        if subtype == "answer_quality_complaint":
            return "Haqlısınız, cavab keyfiyyəti zəifdirsə, onu daha qısa və aydın formada düzəldəcəyəm."
        if subtype == "internal_note_leakage_complaint":
            return "Haqlısınız, daxili qeyd istifadəçiyə görünməməlidir; cavabı təmiz formada yenidən quracağam."
        return "Hansı tapıntı üçün cavab istədiyini dəqiqləşdir: fayl adını yaz və ya bir tapıntı seçməyimi istə."
    if language == "ru":
        if subtype == "response_too_long_feedback":
            return "Понял, дальше буду отвечать короче."
        if subtype == "repeated_answer_complaint":
            return "Вы правы, одинаковый ответ не должен повторяться; дальше буду варьировать такие ответы."
        if subtype in {"clarify_previous_response", "explain_previous_response"}:
            return "Вы правы, если мой предыдущий ответ был неясным, я переформулирую его проще."
        return "Вы правы, я отвечу короче и точнее."
    if subtype == "response_too_long_feedback":
        return "Understood. I will keep the next answers shorter."
    if subtype == "repeated_answer_complaint":
        return "You are right; repeating the same answer should not happen, and I will vary those replies."
    if subtype in {"clarify_previous_response", "explain_previous_response"}:
        return "If my previous answer was unclear, I can restate it more simply."
    return "I will keep this response short and controlled."
