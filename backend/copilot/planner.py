from __future__ import annotations

import json
import asyncio
import os
import re
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

from backend.copilot.language import LanguageIntent, analyze_message, normalize_message
from backend.copilot.language_detector import is_explicit_azerbaijani_switch, is_explicit_english_switch
from backend.copilot.language_understanding import understand_message
from backend.copilot.llm_client import LLMError, call_ollama
from backend.copilot import correction_detection
from backend.copilot.severity import bare_severity_followup, is_severity_breakdown_request, mentioned_severities, severity_from_text


TaskType = Literal[
    "critical_findings_list",
    "critical_finding_details",
    "critical_finding_remediation",
    "critical_finding_risk_explanation",
    "critical_finding_summary",
    "random_finding_risk",
    "scan_summary",
    "scan_comparison",
    "posture_score",
    "compliance_report",
    "trend_analysis",
    "finding_history",
    "compliance_mapping",
    "severity_distribution",
    "severity_count",
    "severity_findings_list",
    "severity_findings_compare",
    "remediation_status",
    "report_generation",
    "artifact_export",
    "follow_up_correction",
    "complaint_repair",
    "list",
    "details",
    "remediation",
    "explanation",
    "correction",
    "report",
    "export",
    "small_talk",
    "capability_help",
    "complaint",
    "count_conflict_explanation",
    "why_previous_answer",
    "complaint_about_wrong_route",
    "meta_clarification",
    "language_switch",
    "clarification",
    "general",
    "list_plus_remediation",
    "teaching",
]

STRUCTURED_PLANNER_INTENTS: set[str] = {
    "finding_list",
    "list_plus_remediation",
    "single_finding_step_by_step_remediation",
    "random_finding_sample",
    "followup_another_one",
    "limit_correction",
    "severity_count",
    "posture_score",
    "dashboard_summary",
    "risk_explanation",
    "remediation_request",
    "teaching_request",
    "translate_previous_answer",
    "complaint_or_meta",
    "language_complaint",
    "general_non_dspm_question",
    "unknown_low_confidence",
}

STRUCTURED_PLANNER_SELECTION_MODES: set[str] = {
    "top",
    "random",
    "next_unshown",
    "representative",
    "explicit",
    "none",
}

STRUCTURED_PLANNER_SEVERITIES: set[str] = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

PLANNER_ALLOWED_TOOLS: set[str] = {
    "get_executive_dashboard",
    "get_scan_history",
    "get_scan_report",
    "search_findings",
    "get_findings_by_severity",
    "get_high_risk_assets",
    "explain_risk_for_asset",
    "get_recent_alerts",
    "search_audit_events",
    "generate_remediation_summary",
    "get_finding_detail",
    "compare_scans",
    "get_finding_history",
    "get_remediation_status",
    "get_severity_distribution",
    "get_compliance_mapping",
    "get_posture_score",
    "get_compliance_report",
    "get_trend_analysis",
}

UNSAFE_PLANNER_TOOLS: set[str] = {
    "shell",
    "bash",
    "powershell",
    "cmd",
    "git",
    "git_push",
    "read_file",
    "read_all_files",
    "write_file",
    "browser",
    "mcp",
    "python",
    "code_execution",
    "execute",
}


class StructuredPlannerDecision(BaseModel):
    intent: str
    confidence: float = 0.0
    language: str | None = None
    response_language: str | None = None
    severity: str | None = None
    limit: int | None = None
    selection_mode: str | None = None
    exclude_ids: list[str] = Field(default_factory=list)
    needs_dspm_evidence: bool = False
    needs_step_by_step: bool = False
    needs_previous_answer: bool = False
    allowed_tools: list[str] = Field(default_factory=list)
    renderer: str | None = None
    provider_final_allowed: bool = False
    clarifying_question: str | None = None

    @field_validator("confidence")
    @classmethod
    def _confidence_range(cls, value: float) -> float:
        return max(0.0, min(float(value), 1.0))

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize_severity(cls, value: Any) -> str | None:
        if value is None or value == "":
            return None
        text = str(value).strip().upper()
        return text if text in STRUCTURED_PLANNER_SEVERITIES else str(value)

    @field_validator("limit", mode="before")
    @classmethod
    def _safe_limit(cls, value: Any) -> int | None:
        if value is None or value == "":
            return None
        return max(1, min(int(value), 25))

    @field_validator("selection_mode", mode="before")
    @classmethod
    def _normalize_selection_mode(cls, value: Any) -> str | None:
        if value is None or value == "":
            return None
        return str(value).strip().lower()


@dataclass(frozen=True)
class PlannerValidationResult:
    ok: bool
    decision: StructuredPlannerDecision | None = None
    rejected: bool = False
    rejection_reason: str | None = None


@dataclass(frozen=True)
class RoutePlan:
    language: str
    intent: str
    task_type: TaskType
    source: str
    target_entity: str | None
    target_reference: str | None
    target_index: int | None
    requested_limit: int | None
    detail_level: str | None
    requires_evidence: bool
    requires_llm_final_answer: bool
    requires_artifact: bool
    confidence: float
    reason: str
    provider_planning_called: bool
    provider_planning_succeeded: bool
    provider_error: str | None = None
    plan_fixup: dict[str, Any] | None = None
    selection_mode: str | None = None
    exclude_ids: list[str] | None = None
    needs_step_by_step: bool = False
    requested_action: str | None = None
    allowed_tools: list[str] | None = None
    renderer: str | None = None
    needs_previous_answer: bool = False
    provider_final_allowed: bool = False
    clarifying_question: str | None = None
    planner_rejected: bool = False
    planner_rejection_reason: str | None = None
    response_language: str | None = None


PLANNER_SYSTEM = (
    "/no_think\n\n"
    "You are the DSPM Copilot planner. Return only valid JSON. "
    "Do not answer the user. Decide intent, required evidence, allowed tools, renderer, "
    "severity, limit, and selection mode. Use only allowed tools. Do not invent findings. "
    "Do not execute anything. Do not include reasoning or chain-of-thought."
)

PLANNER_PROMPT = """Create a structured planner decision for this DSPM Copilot message.

Return JSON only. Do not answer the user.

Allowed intent values:
finding_list, list_plus_remediation, single_finding_step_by_step_remediation,
random_finding_sample, followup_another_one, limit_correction, severity_count,
posture_score, dashboard_summary, risk_explanation, remediation_request,
teaching_request, translate_previous_answer, complaint_or_meta, language_complaint,
general_non_dspm_question, unknown_low_confidence.

Allowed selection_mode values: top, random, next_unshown, representative, explicit, none.
Allowed tools: {allowed_tools}

Rules:
- Use planner only for ambiguous, compound, follow-up, correction, translation, random, or teaching requests.
- Do not make up findings, counts, file names, or evidence.
- If DSPM evidence is needed, choose only allowed backend tools.
- If DSPM evidence is not needed, allowed_tools must be empty.
- Never request shell, Git, file, browser, MCP, or code execution tools.
- provider_final_allowed should be false for DSPM evidence questions.
- If unsure, intent=unknown_low_confidence and include a short clarifying_question in the selected response language.
- Do not include final prose or hidden reasoning.

Return JSON with these keys:
intent, confidence, language, response_language, severity, limit, selection_mode,
exclude_ids, needs_dspm_evidence, needs_step_by_step, needs_previous_answer,
allowed_tools, renderer, provider_final_allowed, clarifying_question.

Heuristic metadata:
{metadata}

Current session summary:
{session_summary}

User message:
{message}
"""

PLANNER_TIMEOUT = float(os.getenv("COPILOT_PLANNER_TIMEOUT", "2.5"))


_LIMIT_PATTERNS = [
    re.compile(r"\b(\d+)\s+eded\b", re.IGNORECASE),
    re.compile(r"\btop\s+(\d+)\b", re.IGNORECASE),
    re.compile(r"\blast\s+(\d+)\b", re.IGNORECASE),
    re.compile(r"\bgive\s+me\s+(\d+)\b", re.IGNORECASE),
    re.compile(r"\bshow\s+(\d+)\b", re.IGNORECASE),
    re.compile(r"\blist\s+(\d+)\b", re.IGNORECASE),
    re.compile(r"\b(\d+)\s+(?:critical|high|medium|low|kritik|tapinti|alert|finding)s?\b", re.IGNORECASE),
    re.compile(r"\bson\s+(\d+)\b", re.IGNORECASE),
    re.compile(r"\bilk\s+(\d+)\b", re.IGNORECASE),
]


@dataclass(frozen=True)
class LimitParseResult:
    limit: int | None
    source: str = "default"
    ignored_limits: tuple[int, ...] = ()
    confidence: float = 0.0


_LIMIT_ACTION_TERMS = (
    "ver", "give", "give me", "show", "list", "goster", "cixart", "Ã§Ä±xart",
    "getir", "pick", "select", "tap", "olsun",
)
_LIMIT_ITEM_TERMS = (
    "alert", "alerts", "finding", "findings", "tapinti", "tapintilar",
    "risk", "critical", "high", "medium", "low", "kritik", "random",
)
_LIMIT_UNIT_TERMS = ("eded", "dene", "tane", "item", "items", "piece", "pieces")
_LIMIT_NEGATION_TERMS = (
    "verme", "vermeyin", "vermÉ™", "yox", "deyil", "not", "dont", "do not",
    "don't", "instead of", "rather than",
)
_ONE_LIMIT_PATTERNS = (
    re.compile(r"\b(?:bir|one|single)\s+(?:eded|dene|tane|alert|finding|tapinti)\b", re.IGNORECASE),
    re.compile(r"\b(?:bir|one|single)\s+(?:critical|high|medium|low|kritik)\s+(?:alert|finding|tapinti)\b", re.IGNORECASE),
)


def _near_any(text: str, start: int, end: int, terms: tuple[str, ...], before: int = 28, after: int = 36) -> bool:
    window = text[max(0, start - before): min(len(text), end + after)]
    return any(term in window for term in terms)


def _is_negated_limit_candidate(text: str, start: int, end: int) -> bool:
    before = text[max(0, start - 24):start]
    after = text[end:min(len(text), end + 28)]
    for negation in ("not", "dont", "do not", "don't"):
        idx = before.rfind(negation)
        if idx >= 0:
            after_negation = before[idx + len(negation):]
            if not any(action in after_negation for action in _LIMIT_ACTION_TERMS):
                return True
    if any(term in after for term in ("verme", "vermÉ™", "yox", "deyil", "not")):
        return True
    return False


def _limit_candidate_score(text: str, start: int, end: int) -> int:
    score = 0
    if _near_any(text, start, end, _LIMIT_ACTION_TERMS, before=18, after=42):
        score += 6
    if _near_any(text, start, end, _LIMIT_ITEM_TERMS, before=18, after=42):
        score += 4
    if _near_any(text, start, end, _LIMIT_UNIT_TERMS, before=2, after=12):
        score += 3
    if _near_any(text, start, end, ("random",), before=32, after=32):
        score += 3
    if _near_any(text, start, end, ("eded", "dene"), before=2, after=12):
        score += 1
    return score


def parse_limit_with_negation(message: str, default: int | None = None, cap: int = 25) -> LimitParseResult:
    text = normalize_message(message)
    ignored: list[int] = []
    candidates: list[tuple[int, int, int, int]] = []

    correction_match = re.fullmatch(r"\s*(\d{1,3})\s+not\s+\d{1,3}\s*", text)
    if correction_match:
        return LimitParseResult(max(1, min(int(correction_match.group(1)), cap)), "correction", (), 0.9)

    for pattern in _ONE_LIMIT_PATTERNS:
        match = pattern.search(text)
        if match and not _is_negated_limit_candidate(text, match.start(), match.end()):
            candidates.append((1, match.start(), match.end(), _limit_candidate_score(text, match.start(), match.end()) + 4))

    for match in re.finditer(r"\b\d{1,4}\b", text):
        value = int(match.group(0))
        if value <= 0:
            continue
        if _is_negated_limit_candidate(text, match.start(), match.end()):
            ignored.append(value)
            continue
        score = _limit_candidate_score(text, match.start(), match.end())
        if score <= 0:
            continue
        candidates.append((value, match.start(), match.end(), score))

    if not candidates:
        return LimitParseResult(default, "default" if default is not None else "none", tuple(ignored), 0.0)

    # Prefer the strongest positive request. Ties go to the later mention so
    # corrections like "not 10, give 1" resolve to the corrected value.
    value, _start, _end, score = max(candidates, key=lambda item: (item[3], item[1]))
    return LimitParseResult(max(1, min(value, cap)), "explicit", tuple(ignored), min(1.0, score / 10.0))


def requested_limit(message: str, default: int | None = None) -> int | None:
    return parse_limit_with_negation(message, default).limit


def _target_index(message: str) -> int | None:
    text = normalize_message(message)
    if any(term in text for term in ("last", "axirinci", "sonuncu")):
        return -1
    match = re.search(r"\b(?:number|no|#)\s*(\d{1,2})\b", text)
    if match:
        return max(1, min(int(match.group(1)), 25))
    match = re.search(r"\b(\d{1,2})(?:st|nd|rd|th)\b", text)
    if match:
        return max(1, min(int(match.group(1)), 25))
    if re.fullmatch(r"\d{1,2}", text):
        return max(1, min(int(text), 25))
    az_match = re.search(r"\b(\d{1,2})-(?:ci|cÄ±|cu|cÃ¼)\b", text)
    if az_match:
        return max(1, min(int(az_match.group(1)), 25))
    ordinal_words = {
        "first": 1,
        "second": 2,
        "third": 3,
        "fourth": 4,
        "fifth": 5,
        "sixth": 6,
        "seventh": 7,
        "eighth": 8,
        "ninth": 9,
        "tenth": 10,
        "birinci": 1,
        "ikinci": 2,
        "ucuncu": 3,
        "dorduncu": 4,
        "besinci": 5,
    }
    for word, value in ordinal_words.items():
        if re.search(rf"\b{word}\b", text):
            return value
    return None


def _target_entity(message: str) -> str | None:
    match = re.search(r"\b([A-Za-z0-9_.-]+\.(?:ya?ml|json|txt|csv|env|pem|key|p12|pfx|xml|ini|conf|cfg|sql|py|js|ts|md))\b", message, re.IGNORECASE)
    return match.group(1) if match else None


def _has_any(text: str, terms: tuple[str, ...]) -> bool:
    return any(term in text for term in terms)


def _severity_from_context(context: dict | None) -> str | None:
    if not context:
        return None
    explicit = str(context.get("last_requested_severity") or "").lower()
    if explicit in {"critical", "high", "medium", "low"}:
        return explicit
    result_type = str(context.get("last_result_type") or "").lower()
    for severity in ("critical", "high", "medium", "low"):
        if result_type.startswith(f"{severity}_"):
            return severity
    for item in context.get("last_shown_items") or []:
        if isinstance(item, dict):
            value = str(item.get("severity") or "").lower()
            if value in {"critical", "high", "medium", "low"}:
                return value
    return None


_KNOWN_SIMPLE_MESSAGES = (
    "salam", "hi", "hello", "hey", "necesen", "netersen", "sag ol", "sagol", "tesekkur",
    "thanks", "thank you", "how are you", "how are u",
    "isleyirsan", "isleyirsen", "isleyir", "calisir", "calisirsan",
    "aktivsen", "aktivsÉ™n", "burdasan", "burda san", "ordasan",
    "are you working", "are you active", "are you there",
    "is it working", "do you work", "can you work",
    "is the copilot", "is the assistant",
    "test", "ok", "he", "hÉ™", "yox",
    "neler ede bilirsen", "neler edebilersen", "neler edebilirsen",
    "ne ede bilirsen", "ne edebilersen", "ne edebilirsen",
    "what can you do", "what can u do", "help",
)

_RANDOM_FINDING_RISK_RE = re.compile(
    r"(random|tÉ™sadÃ¼fi|tesadufi|bir tapinti|bir finding|one finding|pick a|show me one|"
    r"random tapinti|random finding|random alert|random critical)"
    r".*"
    r"(niyÉ™ risklidir|niye risklidir|niyÉ™ tÉ™hlÃ¼kÉ™lidir|niye tehlikelidir|riskini izah|explain why|risk|why)",
    re.IGNORECASE,
)

_RANDOM_FINDING_RISK_REVERSE = re.compile(
    r"(niyÉ™ risklidir|niye risklidir|niyÉ™ tÉ™hlÃ¼kÉ™lidir|niye tehlikelidir|riskini izah|explain why|risk|why)"
    r".*"
    r"(random|tÉ™sadÃ¼fi|tesadufi|bir tapinti|bir finding|one finding|pick a|show me one|"
    r"random tapinti|random finding|random alert|random critical)",
    re.IGNORECASE,
)


def _session_summary(context: dict | None) -> dict:
    if not context:
        return {}
    return {
        "last_intent": context.get("last_intent"),
        "last_result_type": context.get("last_result_type"),
        "last_scan_id": context.get("last_scan_id"),
        "last_requested_limit": context.get("last_requested_limit"),
        "last_total_count": context.get("last_total_count"),
        "last_item": context.get("last_item"),
        "shown_count": len(context.get("last_shown_items") or []),
        "selected_language": context.get("selected_language"),
        "response_language": context.get("response_language"),
    }


def validate_structured_planner_decision(data: dict[str, Any]) -> PlannerValidationResult:
    try:
        decision = StructuredPlannerDecision.model_validate(data)
    except (ValidationError, TypeError, ValueError) as exc:
        return PlannerValidationResult(False, rejected=True, rejection_reason=f"schema_error:{type(exc).__name__}")

    if decision.intent not in STRUCTURED_PLANNER_INTENTS:
        return PlannerValidationResult(False, rejected=True, rejection_reason=f"unknown_intent:{decision.intent}")
    if decision.severity is not None and decision.severity not in STRUCTURED_PLANNER_SEVERITIES:
        return PlannerValidationResult(False, rejected=True, rejection_reason=f"unknown_severity:{decision.severity}")
    if decision.selection_mode is not None and decision.selection_mode not in STRUCTURED_PLANNER_SELECTION_MODES:
        return PlannerValidationResult(False, rejected=True, rejection_reason=f"unknown_selection_mode:{decision.selection_mode}")

    unsupported = [
        tool for tool in decision.allowed_tools
        if tool not in PLANNER_ALLOWED_TOOLS or tool.lower() in UNSAFE_PLANNER_TOOLS
    ]
    if unsupported:
        return PlannerValidationResult(False, rejected=True, rejection_reason=f"unsupported_tool:{','.join(unsupported[:3])}")

    if not decision.needs_dspm_evidence and decision.allowed_tools:
        decision = decision.model_copy(update={"allowed_tools": []})
    if decision.needs_dspm_evidence and decision.provider_final_allowed:
        decision = decision.model_copy(update={"provider_final_allowed": False})
    if decision.intent == "unknown_low_confidence" and decision.provider_final_allowed:
        decision = decision.model_copy(update={"provider_final_allowed": False})
    if decision.confidence < 0.35 and decision.intent != "unknown_low_confidence":
        return PlannerValidationResult(False, rejected=True, rejection_reason="low_confidence")

    return PlannerValidationResult(True, decision=decision)


def should_use_ai_planner(
    message: str,
    heuristic: RoutePlan,
    session_context: dict | None,
    route: Any | None = None,
) -> bool:
    text = normalize_message(message)
    raw = str(message or "").lower()
    joined = f"{text} {raw}"
    if heuristic.task_type in {
        "small_talk",
        "capability_help",
        "complaint",
        "count_conflict_explanation",
        "why_previous_answer",
        "complaint_about_wrong_route",
        "meta_clarification",
        "language_switch",
        "severity_count",
        "posture_score",
    }:
        return False
    if heuristic.task_type in {"critical_findings_list", "severity_findings_list"} and not (
        heuristic.selection_mode
        or heuristic.needs_step_by_step
        or _has_any(text, ("remediation", "recommend", "neler etmeliyem", "ne etmeliyem", "what should i do"))
        or _has_any(text, ("not", "verme", "vermÉ™", "yox", "deyil", "dont", "do not"))
    ):
        return False
    if heuristic.task_type in {"scan_summary", "scan_comparison", "compliance_report", "trend_analysis", "severity_distribution"}:
        return False
    if (
        heuristic.task_type == "list_plus_remediation"
        and heuristic.needs_step_by_step
        and (heuristic.requested_limit in (None, 1))
        and heuristic.selection_mode in {None, "random", "top", "representative", "explicit"}
    ):
        return False

    ambiguous_or_compound_terms = (
        "tÉ™sadÃ¼fi", "baÅŸqa", "pillÉ™ pillÉ™", "baÅŸa sal",
        "random", "tesadufi", "tÉ™sadÃ¼fi", "basqa", "baÅŸqa", "another one", "different one",
        "next one", "not ", "dont", "do not", "verme", "vermÉ™", "yox", "deyil",
        "step by step", "pille pille", "pillÉ™ pillÉ™", "basa sal", "baÅŸa sal",
        "what should i do", "neler etmeliyem", "nÉ™lÉ™r etmÉ™liyÉ™m", "ne etmeliyem",
        "az evvel", "az É™vvÉ™l", "previous answer", "last answer", "cavabi",
        "niye bele cavab", "niyÉ™ belÉ™ cavab", "why did you answer",
    )
    if heuristic.selection_mode in {"random", "next_unshown"}:
        return True
    if heuristic.needs_step_by_step:
        return True
    if heuristic.task_type in {"list_plus_remediation", "random_finding_risk"}:
        return True
    if _has_any(joined, ambiguous_or_compound_terms):
        return True
    if session_context and re.search(r"\b(bunu|onu|it|that|this|for this|for that)\b", text):
        return True
    return False


def _reference_from_text(message: str, target_index: int | None) -> str | None:
    text = normalize_message(message)
    if target_index == -1:
        return "last_shown_critical_finding"
    if target_index:
        return "shown_item_index"
    if any(term in text for term in ("that one", "this one", "that alert", "that finding", "this finding", "that file", "bunu", "onu", "hemin", "this", "that", "it")):
        return "current_session_item"
    return None


_LIST_COUNT_SIGNALS = (
    "3 alert", "three alert", "four alert", "five alert", "last 3 critical", "last 3 alert",
    "give me last 3 critical", "give me 3 critical", "3 critical alert", "son 3 alert",
    "son 3 alerti", "son 5 alert", "3 kritik alert", "3 kritik tapinti",
    "son 5 kritik tapinti", "son 3 kritik alerti", "son 5 high finding",
    "not 1 alert", "not 1", "together", "birlikdÉ™", "birlikde",
    "3 finding", "three finding", "4 alert", "5 alert",
)

_LIST_PLURAL_REMEDIATION_SIGNALS = (
    "and recommendation", "and recommendations", "with recommendation", "with recommendations",
    "ve recommendation", "vÉ™ recommendation", "ve tavsiyye", "vÉ™ tÃ¶vsiyÉ™",
    "ve remediation", "vÉ™ remediation", "and remediation",
)

_REMEDIATION_SIGNALS = (
    "recommend", "recommendation", "remediate", "remediation",
    "what can i do", "what should i do", "what u recommend", "what do you recommend",
    "nÉ™lÉ™r etmÉ™liyÉ™m", "neler etmeliyem", "nÉ™ etmÉ™liyÉ™m", "ne etmeliyem",
    "nece duzeltmeliyem", "duzeltmeliyem",
    "tÃ¶vsiyÉ™", "tÃ¶vsiyem", "dÃ¼zÉ™liÅŸ", "hÉ™ll", "fix", "remediation",
)

_PLURAL_ALL_SIGNALS = (
    "all of them", "all items", "all findings", "all three", "all four", "all five",
    "hamÄ±sÄ±", "hamÄ±sÄ±na", "bunlarÄ±n", "bunlar Ã¼Ã§Ã¼n", "bu 3 alert",
    "bu 3 tapÄ±ntÄ±", "bu Ã¼Ã§", "for all", "each of them",
)


def _is_list_plus_remediation_compound(text: str, limit: int | None) -> bool:
    has_remediation = _has_any(text, _REMEDIATION_SIGNALS)
    has_list_action = _has_any(text, (
        "alertleri goster",
        "tapinti goster",
        "tapintilari goster",
        "kritik alertleri goster",
        "kritik tapinti goster",
        "critical alerts and",
        "critical findings and",
    ))
    if has_remediation and has_list_action:
        return True
    if limit is not None and limit >= 2:
        has_explicit_count = _has_any(text, _LIST_COUNT_SIGNALS)
        if has_remediation and has_explicit_count:
            return True
    if _has_any(text, _LIST_PLURAL_REMEDIATION_SIGNALS):
        return True
    if limit is not None and limit >= 2 and _has_any(text, _PLURAL_ALL_SIGNALS):
        return True
    return False


def _selection_mode(message: str) -> str | None:
    text = normalize_message(message)
    raw = str(message or "").lower()
    joined = f"{text} {raw}"
    if any(term in joined for term in ("random", "tesadufi", "t?sad", "tÉ™sad")):
        return "random"
    if any(term in joined for term in (
        "basqa", "ba?qa", "baÅŸqa", "another", "different one",
        "next one", "next unshown", "n?vb?ti", "nÃ¶vbÉ™ti", "novbeti",
    )):
        return "next_unshown"
    return None


def _needs_step_by_step(text: str) -> bool:
    return _has_any(text, (
        "step by step", "pille pille", "pillÉ™ pillÉ™", "addim addim",
        "basa sal", "baÅŸa sal", "teach", "oyret", "oyredici",
    ))


def _has_explicit_count_question(text: str, routing_text: str) -> bool:
    joined = f"{text} {routing_text}"
    if any(term in joined for term in (
        "how many", "how much", "nece eded", "nece dene", "necesi", "ne qeder",
        "sayi", "sayin", "count",
    )):
        return True
    return bool(re.search(r"\beded\b.{0,20}\bvar\b", joined) or re.search(r"\bvar\b.{0,20}\beded\b", joined))


def _mentioned_severities(text: str, routing_text: str) -> set[str]:
    return mentioned_severities(text, routing_text)


def _has_item_selection_action(text: str, routing_text: str) -> bool:
    joined = f"{text} {routing_text}"
    return any(term in joined for term in (
        "show", "list", "give", "give me", "goster", "ver", "cixart",
        "Ã§Ä±xart", "pick", "select", "random",
    ))


def _joined_route_text(text: str, routing_text: str) -> str:
    return f"{text} {routing_text}".lower()


def _is_count_conflict_question(text: str, routing_text: str) -> bool:
    return correction_detection.detect_count_conflict_explanation(text, extra_text=routing_text)


def _is_why_previous_answer_question(text: str, routing_text: str) -> bool:
    return correction_detection.detect_why_previous_answer(text, extra_text=routing_text)


def _is_wrong_route_complaint(text: str, routing_text: str) -> bool:
    return correction_detection.detect_wrong_route_complaint(text, extra_text=routing_text)


def _has_explicit_selected_item_reference(text: str, routing_text: str) -> bool:
    joined = _joined_route_text(text, routing_text)
    return any(term in joined for term in (
        "bu tapinti", "bu tapıntı", "bu fayl", "bunu", "bunun",
        "this finding", "this file", "this alert", "explain this finding",
        "why is this risky", "why this finding",
    ))


def heuristic_plan(message: str, metadata: LanguageIntent, context: dict | None, provider_error: str | None = None) -> RoutePlan:
    text = normalize_message(message)
    routing_text = understand_message(message).cleaned_text
    limit_parse = parse_limit_with_negation(message)
    limit = limit_parse.limit
    index = _target_index(message)
    entity = _target_entity(message)
    reference = _reference_from_text(message, index)
    selection_mode = _selection_mode(message)
    needs_step_by_step = _needs_step_by_step(text) or _needs_step_by_step(routing_text)
    if selection_mode == "random" and limit is None:
        limit = 1
    has_previous_list = bool((context or {}).get("last_shown_items"))
    has_current_item = bool((context or {}).get("current_item"))
    # Rejected-route memory: after a correction turn recorded a failed
    # selected-finding route, an ambiguous follow-up must not silently
    # re-select the same selected-finding context.
    _last_failed_route = str((context or {}).get("last_failed_route") or "").lower()
    selected_route_rejected = bool(_last_failed_route) and any(
        token in _last_failed_route for token in ("selected", "detail", "hijack")
    )
    detail_level = "wide" if _has_any(text, ("wide information", "detailed information", "deep information", "full information", "genis melumat", "geniÅŸ mÉ™lumat")) else None
    count_conflict_question = _is_count_conflict_question(text, routing_text)
    why_previous_answer_question = _is_why_previous_answer_question(text, routing_text)
    wrong_route_complaint = _is_wrong_route_complaint(text, routing_text)
    explicit_selected_item_reference = _has_explicit_selected_item_reference(text, routing_text)
    is_details_request = _has_any(text, ("detail", "details", "information", "info", "explain", "wide information", "about", "show me", "show the", "tell me about", "melumat", "haqqinda", "genis melumat"))
    is_risk_request = (
        _has_any(text, ("why", "risky", "riskli", "niye", "niyÉ™"))
        and not count_conflict_question
        and not why_previous_answer_question
        and not wrong_route_complaint
    )
    is_remediation_request = _has_any(text, ("recommend", "remediation", "remediate", "what should i do", "what u recommend", "what do you recommend", "indi ne etmeliyem", "ne etmeliyem", "neler etmeliyem", "neler etmeli", "ne etmeli"))
    is_comparison_request = _has_any(text, ("compare", "comparison", "changed since", "what changed", "previous scan", "last 2 scans", "last two scans", "since last scan", "new critical findings"))
    context_severity = _severity_from_context(context)
    detected_severity = severity_from_text(message) or severity_from_text(routing_text)
    requested_severity = (detected_severity.lower() if detected_severity else None) or context_severity
    has_finding_term = any(term in text or term in routing_text for term in ("tapinti", "finding", "findings", "alert", "alerts"))
    has_count_term = _has_explicit_count_question(text, routing_text)
    has_item_selection_action = _has_item_selection_action(text, routing_text)
    mentioned_severities = _mentioned_severities(text, routing_text)
    is_severity_distribution_request = bool(
        is_severity_breakdown_request(text)
        or is_severity_breakdown_request(routing_text)
        or _has_any(text, ("high vs critical", "critical vs high", "severity distribution", "risk summary"))
        or _has_any(routing_text, ("high vs critical", "critical vs high", "severity distribution", "risk summary"))
        or (
            len(mentioned_severities) >= 2
            and (
                has_count_term
                or bool(re.search(r"\b(vs|versus)\b", f"{text} {routing_text}"))
                or _has_any(text, ("muqayise", "ferq"))
                or _has_any(routing_text, ("muqayise", "ferq"))
            )
        )
    )
    # Short contextual severity follow-up ("low?", "and high?") after a count or
    # distribution answer inherits the count intent for that severity.
    bare_followup = bare_severity_followup(text) or bare_severity_followup(routing_text)
    context_result_type = str((context or {}).get("last_result_type") or "").lower()
    context_answer_type = str((context or {}).get("last_answer_type") or "").lower()
    has_count_context = bool(
        (context or {}).get("last_count_scope_severities")
        or "count" in context_result_type
        or "count" in context_answer_type
        or "distribution" in context_result_type
        or "distribution" in context_answer_type
    )
    severity_count_request = bool(
        requested_severity
        and has_count_term
        and (has_finding_term or context_severity)
        and not is_severity_distribution_request
    ) or bool(bare_followup and has_count_context)
    severity_list_request = bool(
        requested_severity
        and requested_severity != "critical"
        and (has_finding_term or (selection_mode and context_severity))
        and not severity_count_request
        and (limit is not None or has_item_selection_action)
    )
    severity_compare_request = bool(
        severity_list_request
        and any(term in text or term in routing_text for term in ("compare", "comparison", "muqayise", "mÃ¼qayisÉ™", "ferq", "fÉ™rq"))
    )
    is_posture_score_request = _has_any(text, ("posture score", "security posture", "security health", "health score", "risk posture", "dspm score", "overall score", "risk score"))
    is_trend_analysis_request = _has_any(text, ("trend", "trends", "over time", "progress", "evolution", "scan trend", "posture trend", "dinamika", "irÉ™lilÉ™yiÅŸ", "irelileyis"))
    is_history_request = _has_any(text, ("is this a new finding", "is this new", "appeared before", "appeared previously", "recurring", "seen before", "new finding"))
    is_remediation_status_request = _has_any(text, ("did we fix", "is this fixed", "still present", "fixed yet", "is it fixed"))
    is_compliance_request = _has_any(text, ("gdpr", "compliance", "framework", "regulatory", "pci", "iso 27001", "soc 2", "violate"))
    is_compliance_report_request = is_compliance_request and (
        entity is None
        and not reference
        and _has_any(text, ("report", "summary", "overall", "scan", "framework", "frameworks", "all", "umumi", "Ã¼mumi", "hesabat"))
    )
    is_random_finding_risk = bool(_RANDOM_FINDING_RISK_RE.search(message) or _RANDOM_FINDING_RISK_REVERSE.search(message))
    is_teaching_request = needs_step_by_step or _has_any(text, (
        "teach", "teach me", "step by step", "how to fix", "what does this mean",
        "oyret", "oyredici", "addim addim", "basa sal", "sade dille",
        "ne demekdir", "nece duzeltmek", "nece duzeltmeliyem", "nece edim",
    ))
    single_finding_remediation_request = bool(
        requested_severity
        and has_finding_term
        and (limit == 1 or selection_mode == "random")
        and (is_remediation_request or is_teaching_request)
    )

    if count_conflict_question:
        task: TaskType = "count_conflict_explanation"
        intent = "count_conflict_explanation"
        requires_evidence = False
        requires_final = False
        source = "none"
    elif wrong_route_complaint:
        task = "complaint_about_wrong_route"
        intent = "complaint_about_wrong_route"
        requires_evidence = False
        requires_final = False
        source = "none"
    elif why_previous_answer_question:
        task = "why_previous_answer"
        intent = "why_previous_answer"
        requires_evidence = False
        requires_final = False
        source = "none"
    elif (
        text in {"now", "now?", "niye", "niyÃ‰â„¢", "niye?", "niyÃ‰â„¢?", "bes indi nece", "bes indi nece?", "bÃ‰â„¢s indi necÃ‰â„¢", "bÃ‰â„¢s indi necÃ‰â„¢?"}
        or routing_text in {"now", "now?", "niye", "niye?", "niyÉ™", "niyÉ™?", "bes indi nece", "bes indi nece?", "bÉ™s indi necÉ™", "bÉ™s indi necÉ™?"}
        or re.fullmatch(r"niy\W{1,3}", text)
        or re.fullmatch(r"b.s indi nec\W{1,3}", text)
        or re.fullmatch(r"niy\W{1,3}", routing_text)
        or re.fullmatch(r"b.s indi nec\W{1,3}", routing_text)
    ):
        task = "complaint"
        intent = "complaint_or_misunderstanding"
        requires_evidence = False
        requires_final = False
        source = "none"
    elif is_explicit_english_switch(text) or is_explicit_azerbaijani_switch(text) or any(phrase in text for phrase in (
        "ingilis dilinde danisaq", "english dilinde danisaq", "switch to english",
        "lets speak english", "let us speak english", "speak english", "respond in english",
        "in english please", "use english", "ingilis dilinde", "ingilis dilinde danis",
        "azerbaycan dilinde danis", "azerbaycanca cavab ver", "respond in azerbaijani",
        "use azerbaijani", "answer in azerbaijani", "switch to azerbaijani",
        "lets speak azerbaijani", "respond in",
    )):
        task: TaskType = "language_switch"
        intent = "language_switch"
        requires_evidence = False
        requires_final = False
        source = "none"
    elif metadata.intent == "small_talk":
        task = "small_talk"
        intent = "small_talk"
        requires_evidence = False
        requires_final = True
        source = "none"
    elif metadata.intent == "capability_help":
        task = "capability_help"
        intent = "capability_help"
        requires_evidence = False
        requires_final = True
        source = "none"
    elif metadata.intent == "complaint_or_misunderstanding":
        task = "complaint"
        intent = "complaint_or_misunderstanding"
        requires_evidence = False
        requires_final = False
        source = "none"
    elif selection_mode == "next_unshown" and context_severity:
        task = "critical_findings_list" if context_severity == "CRITICAL" else "severity_findings_list"
        intent = "finding_search"
        requires_evidence = True
        requires_final = False
        source = "latest_scan"
        limit = limit or 1
    elif is_random_finding_risk:
        task = "random_finding_risk"
        intent = "finding_search"
        requires_evidence = True
        requires_final = True
        source = "latest_scan"
        limit = 1
    elif (
        is_teaching_request
        and limit is None
        and not any(term in text for term in ("critical", "kritik", "alert", "alerts"))
        and any(term in text for term in ("private key", "private_key", "jwt", "secret", "api key", "api_key", "tapinti", "finding"))
    ):
        task = "teaching"
        intent = "teaching"
        requires_evidence = False
        requires_final = False
        source = "none"
    elif is_posture_score_request:
        task = "posture_score"
        intent = "posture_score"
        requires_evidence = True
        requires_final = False
        source = "latest_scan"
    elif is_trend_analysis_request:
        task = "trend_analysis"
        intent = "trend_analysis"
        requires_evidence = True
        requires_final = False
        source = "scan_history"
        limit = limit or 5
    elif is_compliance_report_request:
        task = "compliance_report"
        intent = "compliance_report"
        requires_evidence = True
        requires_final = False
        source = "latest_scan"
        limit = None
    elif metadata.intent == "report_export" or "pdf" in text or "export" in text or ("report" in text and not is_compliance_request):
        task = "artifact_export" if "export" in text or "pdf" in text else "report_generation"
        intent = "report_export"
        requires_evidence = True
        requires_final = True
        source = "current_session" if has_previous_list else "latest_scan"
    elif single_finding_remediation_request or _is_list_plus_remediation_compound(text, limit) or _is_list_plus_remediation_compound(routing_text, limit):
        task = "list_plus_remediation"
        intent = "critical_findings"
        requires_evidence = True
        requires_final = False
        source = "latest_scan"
        if single_finding_remediation_request:
            limit = limit or 1
        elif limit is None and context and context.get("last_requested_limit"):
            try:
                limit = max(1, min(int(context.get("last_requested_limit")), 25))
            except (TypeError, ValueError):
                limit = None
    elif severity_compare_request:
        task = "severity_findings_compare"
        intent = "finding_search"
        requires_evidence = True
        requires_final = False
        source = "latest_scan"
        limit = limit or 2
        reference = None
        index = None
    elif severity_count_request:
        task = "severity_count"
        intent = "finding_search"
        requires_evidence = True
        requires_final = False
        source = "latest_scan"
        limit = 1
        reference = None
        index = None
    elif severity_list_request:
        task = "severity_findings_list"
        intent = "finding_search"
        requires_evidence = True
        requires_final = False
        source = "latest_scan"
        limit = limit or 5
        reference = None
        index = None
    elif is_comparison_request:
        task = "scan_comparison"
        intent = "scan_comparison"
        requires_evidence = True
        requires_final = False
        source = "scan_history"
        limit = limit or 2
    elif is_remediation_status_request:
        task = "remediation_status"
        intent = "remediation_status"
        requires_evidence = True
        requires_final = False
        source = "latest_scan_or_session"
        reference = "explicit_filename" if entity else reference or ("last_shown_critical_finding" if "last" in text else "current_session_item")
        index = index if index is not None else (-1 if "last" in text else None)
        limit = None
    elif is_history_request:
        task = "finding_history"
        intent = "finding_history"
        requires_evidence = True
        requires_final = False
        source = "latest_scan_or_session"
        reference = "explicit_filename" if entity else reference or ("last_shown_critical_finding" if "last" in text else "current_session_item")
        index = index if index is not None else (-1 if "last" in text else None)
        limit = None
    elif is_compliance_request:
        task = "compliance_mapping"
        intent = "compliance_mapping"
        requires_evidence = True
        requires_final = False
        source = "latest_scan_or_session"
        reference = "explicit_filename" if entity else reference or ("last_shown_critical_finding" if "last" in text else "current_session_item")
        index = index if index is not None else (-1 if "last" in text else None)
        limit = None
    elif is_severity_distribution_request:
        task = "severity_distribution"
        intent = "severity_distribution"
        requires_evidence = True
        requires_final = False
        source = "latest_scan"
    elif is_remediation_request:
        if has_previous_list or reference or entity:
            task = "critical_finding_remediation"
            intent = "critical_finding_remediation"
            requires_evidence = True
            requires_final = True
            source = "current_session" if has_previous_list and not entity else "latest_scan_or_session"
            reference = "explicit_filename" if entity else reference or ("last_shown_critical_finding" if "last" in text else "current_session_item" if has_current_item else "last_shown_critical_finding")
            index = index if index is not None else (-1 if reference == "last_shown_critical_finding" else None)
            limit = None
        elif any(term in text for term in ("remediation", "remediate", "recommend")):
            task = "remediation"
            intent = "remediation_advice"
            requires_evidence = True
            requires_final = True
            source = "latest_scan"
        else:
            task = "clarification"
            intent = "follow_up"
            requires_evidence = False
            requires_final = False
            source = "none"
    elif (
        is_details_request
        and not is_risk_request
        and selected_route_rejected
        and has_current_item
        and not entity
        and not explicit_selected_item_reference
        and not has_previous_list
    ):
        # The user rejected the previous selected-finding route; an ambiguous
        # "details" follow-up must ask what to detail instead of re-running
        # the rejected route with the same selected finding.
        task = "clarification"
        intent = "follow_up"
        requires_evidence = False
        requires_final = False
        source = "none"
    elif is_details_request and not is_risk_request and (entity or has_previous_list or has_current_item or "one" in text or "number" in text or "last critical alert" in text):
        task = "critical_finding_details"
        intent = "critical_finding_details"
        requires_evidence = True
        requires_final = True
        source = "current_session" if has_previous_list and not entity else "latest_scan_or_session"
        reference = "explicit_filename" if entity else reference or ("last_shown_critical_finding" if "last" in text else "current_session_item")
        index = index if index is not None else (-1 if "last" in text else None)
        limit = None
    elif is_risk_request and (
        entity
        or explicit_selected_item_reference
        or reference in {"shown_item_index", "last_shown_critical_finding"}
    ):
        task = "critical_finding_risk_explanation"
        intent = "critical_finding_explanation"
        requires_evidence = True
        requires_final = True
        source = "current_session" if has_previous_list and not entity else "latest_scan_or_session"
        reference = "explicit_filename" if entity else reference or "current_session_item"
        limit = None
    elif (limit is not None and has_previous_list and any(term in text for term in ("not", "dedim", "yox"))) or (limit is not None and re.fullmatch(r"\d{1,2}", text) and has_previous_list):
        task = "follow_up_correction"
        intent = "critical_findings"
        requires_evidence = True
        requires_final = False
        source = "latest_scan"
    elif any(term in text for term in ("critical alert", "critical alerts", "critical finding", "critical findings", "kritik tapinti", "kritik tapintilar", "alertleri", "alertlerin")):
        task = "critical_findings_list"
        intent = "critical_findings"
        requires_evidence = True
        requires_final = False
        source = "latest_scan"
        limit = limit or 5
        reference = None
        index = None
    elif _has_any(text, ("scan summary", "latest scan", "son skan", "skan xulasesi", "scan netice", "scan xulase", "scan report", "executive summary", "dashboard summary")):
        task = "scan_summary"
        intent = "executive_summary"
        requires_evidence = True
        requires_final = True
        source = "latest_scan"
    elif metadata.should_use_dspm_tools:
        task = "general"
        intent = metadata.intent
        requires_evidence = True
        requires_final = True
        source = "latest_scan"
    else:
        task = "general" if metadata.intent == "unclear" else metadata.intent  # type: ignore[assignment]
        intent = metadata.intent
        requires_evidence = False
        requires_final = True
        source = "none"

    return RoutePlan(
        language=metadata.language,
        intent=intent,
        task_type=task,
        source=source,
        target_entity=entity,
        target_reference=reference,
        target_index=index,
        requested_limit=limit,
        detail_level=detail_level,
        requires_evidence=requires_evidence,
        requires_llm_final_answer=requires_final,
        requires_artifact=task in {"report", "export"},
        confidence=0.72 if provider_error else 0.86,
        reason="Heuristic fallback route plan." if provider_error else "Heuristic route plan.",
        provider_planning_called=bool(provider_error),
        provider_planning_succeeded=False,
        provider_error=provider_error,
        selection_mode=selection_mode,
        exclude_ids=None,
        needs_step_by_step=needs_step_by_step,
        requested_action="remediation" if (is_remediation_request or is_teaching_request) else "list" if severity_list_request else None,
    )


def _coerce_plan(data: dict[str, Any], metadata: LanguageIntent, fallback: RoutePlan) -> RoutePlan:
    original_task = str(data.get("task_type") or fallback.task_type)
    task = original_task
    allowed = set(TaskType.__args__)  # type: ignore[attr-defined]
    if task not in allowed:
        task = fallback.task_type
    index = data.get("target_index", fallback.target_index)
    try:
        index = int(index) if index is not None else None
    except (TypeError, ValueError):
        index = fallback.target_index
    limit = data.get("requested_limit", fallback.requested_limit)
    try:
        limit = max(1, min(int(limit), 25)) if limit is not None else None
    except (TypeError, ValueError):
        limit = fallback.requested_limit
    source = str(data.get("source") or fallback.source)
    target_entity = data.get("target_entity") or fallback.target_entity
    target_reference = data.get("target_reference") or fallback.target_reference
    detail_level = data.get("detail_level") or fallback.detail_level
    selection_mode = data.get("selection_mode") or fallback.selection_mode
    needs_step_by_step = bool(data.get("needs_step_by_step", fallback.needs_step_by_step))
    requested_action = data.get("requested_action") or fallback.requested_action
    requires_evidence = bool(data.get("requires_evidence", fallback.requires_evidence))
    requires_llm_final_answer = bool(data.get("requires_llm_final_answer", fallback.requires_llm_final_answer))
    requires_artifact = bool(data.get("requires_artifact", fallback.requires_artifact))
    if source == "current_session" and fallback.source != "current_session" and not fallback.target_reference:
        source = fallback.source
        target_reference = fallback.target_reference
        task = fallback.task_type
    deterministic_dspm_tasks = {
        "critical_findings_list",
        "critical_finding_details",
        "critical_finding_remediation",
        "critical_finding_risk_explanation",
        "report_generation",
        "artifact_export",
        "follow_up_correction",
        "complaint_repair",
        "scan_comparison",
        "posture_score",
        "compliance_report",
        "trend_analysis",
        "finding_history",
        "compliance_mapping",
        "severity_distribution",
        "remediation_status",
        "list_plus_remediation",
    }
    if fallback.task_type in deterministic_dspm_tasks:
        task = fallback.task_type
        source = fallback.source
        target_entity = fallback.target_entity or target_entity
        target_reference = fallback.target_reference or target_reference
        index = fallback.target_index
        limit = fallback.requested_limit
        detail_level = fallback.detail_level
        selection_mode = fallback.selection_mode
        needs_step_by_step = fallback.needs_step_by_step
        requested_action = fallback.requested_action
        requires_evidence = fallback.requires_evidence
        requires_llm_final_answer = fallback.requires_llm_final_answer
        requires_artifact = fallback.requires_artifact
    plan_fixup = None
    if task != original_task:
        plan_fixup = {
            "original_llm_task_type": original_task,
            "fixed_task_type": task,
            "trigger": fallback.reason,
            "target_entity": fallback.target_entity or target_entity,
        }
    return RoutePlan(
        language=str(data.get("language") or metadata.language),
        intent=str(data.get("intent") or fallback.intent),
        task_type=task,  # type: ignore[arg-type]
        source=source,
        target_entity=str(target_entity) if target_entity else None,
        target_reference=target_reference,
        target_index=index,
        requested_limit=limit,
        detail_level=str(detail_level) if detail_level else None,
        requires_evidence=requires_evidence,
        requires_llm_final_answer=requires_llm_final_answer,
        requires_artifact=requires_artifact,
        confidence=float(data.get("confidence") or fallback.confidence),
        reason=str(data.get("reason") or "Provider route plan."),
        provider_planning_called=True,
        provider_planning_succeeded=True,
        provider_error=None,
        plan_fixup=plan_fixup,
        selection_mode=str(selection_mode) if selection_mode else None,
        exclude_ids=fallback.exclude_ids,
        needs_step_by_step=needs_step_by_step,
        requested_action=str(requested_action) if requested_action else None,
    )


def _route_plan_from_decision(
    decision: StructuredPlannerDecision,
    metadata: LanguageIntent,
    fallback: RoutePlan,
) -> RoutePlan:
    severity = decision.severity
    limit = decision.limit if decision.limit is not None else fallback.requested_limit
    selection_mode = decision.selection_mode if decision.selection_mode != "none" else None
    if selection_mode is None:
        selection_mode = fallback.selection_mode
    if selection_mode in {"random", "next_unshown"} and limit is None:
        limit = 1

    intent_to_task: dict[str, TaskType] = {
        "finding_list": "critical_findings_list" if severity == "CRITICAL" else "severity_findings_list",
        "random_finding_sample": "critical_findings_list" if severity == "CRITICAL" else "severity_findings_list",
        "followup_another_one": "critical_findings_list" if severity == "CRITICAL" else "severity_findings_list",
        "limit_correction": fallback.task_type if fallback.task_type != "severity_count" else "severity_findings_list",
        "list_plus_remediation": "list_plus_remediation",
        "single_finding_step_by_step_remediation": "list_plus_remediation",
        "remediation_request": "critical_finding_remediation" if fallback.target_reference or fallback.target_entity else "list_plus_remediation",
        "teaching_request": "teaching" if not decision.needs_dspm_evidence else "list_plus_remediation",
        "severity_count": "severity_count",
        "posture_score": "posture_score",
        "dashboard_summary": "scan_summary",
        "risk_explanation": "critical_finding_risk_explanation",
        "translate_previous_answer": "clarification",
        "complaint_or_meta": "complaint",
        "language_complaint": "complaint",
        "general_non_dspm_question": "general",
        "unknown_low_confidence": "clarification",
    }
    task = intent_to_task.get(decision.intent, "clarification")
    requires_evidence = bool(decision.needs_dspm_evidence)
    requires_final = bool(decision.provider_final_allowed and not requires_evidence)
    source = "latest_scan" if requires_evidence else "none"
    if task in {"critical_finding_details", "critical_finding_remediation", "critical_finding_risk_explanation"}:
        source = fallback.source if fallback.source != "none" else "current_session"

    if decision.intent == "unknown_low_confidence":
        requires_evidence = False
        requires_final = False
        source = "none"
    if task == "severity_count":
        limit = 1
    elif task in {"severity_findings_list", "critical_findings_list", "list_plus_remediation"} and limit is None:
        limit = 1 if selection_mode in {"random", "next_unshown"} else fallback.requested_limit

    plan_fixup = {
        "planner_intent": decision.intent,
        "planner_confidence": decision.confidence,
        "needs_dspm_evidence": decision.needs_dspm_evidence,
        "allowed_tools": list(decision.allowed_tools),
        "severity": severity,
        "renderer": decision.renderer,
    }
    if decision.clarifying_question:
        plan_fixup["clarifying_question"] = decision.clarifying_question

    return RoutePlan(
        language=decision.response_language or decision.language or metadata.language,
        intent=decision.intent,
        task_type=task,
        source=source,
        target_entity=fallback.target_entity,
        target_reference=fallback.target_reference,
        target_index=fallback.target_index,
        requested_limit=limit,
        detail_level=fallback.detail_level,
        requires_evidence=requires_evidence,
        requires_llm_final_answer=requires_final,
        requires_artifact=False,
        confidence=decision.confidence,
        reason="Structured AI planner decision.",
        provider_planning_called=True,
        provider_planning_succeeded=True,
        provider_error=None,
        plan_fixup=plan_fixup,
        selection_mode=selection_mode,
        exclude_ids=list(decision.exclude_ids),
        needs_step_by_step=decision.needs_step_by_step or fallback.needs_step_by_step,
        requested_action="remediation" if decision.intent in {
            "list_plus_remediation",
            "single_finding_step_by_step_remediation",
            "remediation_request",
            "teaching_request",
        } else fallback.requested_action,
        allowed_tools=list(decision.allowed_tools),
        renderer=decision.renderer,
        needs_previous_answer=decision.needs_previous_answer,
        provider_final_allowed=decision.provider_final_allowed,
        clarifying_question=decision.clarifying_question,
        response_language=decision.response_language,
    )


_HEURISTIC_TRUSTED_TASKS: set[str] = {
    "critical_findings_list",
    "critical_finding_details",
    "critical_finding_remediation",
    "critical_finding_risk_explanation",
    "critical_finding_summary",
    "random_finding_risk",
    "scan_summary",
    "scan_comparison",
    "posture_score",
    "compliance_report",
    "trend_analysis",
    "finding_history",
    "compliance_mapping",
    "severity_distribution",
    "severity_count",
    "severity_findings_list",
    "severity_findings_compare",
    "remediation_status",
    "report_generation",
    "artifact_export",
    "follow_up_correction",
    "complaint_repair",
    "list",
    "details",
    "remediation",
    "explanation",
    "correction",
    "report",
    "export",
    "small_talk",
    "capability_help",
    "complaint",
    "count_conflict_explanation",
    "why_previous_answer",
    "complaint_about_wrong_route",
    "meta_clarification",
    "language_switch",
    "list_plus_remediation",
    "teaching",
}


async def plan_request(message: str, session_context: dict | None = None) -> RoutePlan:
    metadata = analyze_message(message)
    fallback = heuristic_plan(message, metadata, session_context)
    if not should_use_ai_planner(message, fallback, session_context, None):
        return fallback
    prompt = PLANNER_PROMPT.format(
        allowed_tools=json.dumps(sorted(PLANNER_ALLOWED_TOOLS), ensure_ascii=False),
        metadata=json.dumps(metadata.model_dump(), ensure_ascii=False, default=str),
        session_summary=json.dumps(_session_summary(session_context), ensure_ascii=False, default=str),
        message=message,
    )
    try:
        raw = await asyncio.wait_for(
            call_ollama([{"role": "system", "content": PLANNER_SYSTEM}, {"role": "user", "content": prompt}], json_mode=True, task_type="classification"),
            timeout=PLANNER_TIMEOUT,
        )
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("planner JSON was not an object")
        validation = validate_structured_planner_decision(data)
        if not validation.ok or validation.decision is None:
            if (validation.rejection_reason or "").startswith("schema_error"):
                return heuristic_plan(message, metadata, session_context, provider_error="PlannerRejected")
            return RoutePlan(
                language=metadata.language,
                intent="clarification",
                task_type="clarification",
                source="none",
                target_entity=None,
                target_reference=None,
                target_index=None,
                requested_limit=fallback.requested_limit,
                detail_level=None,
                requires_evidence=False,
                requires_llm_final_answer=False,
                requires_artifact=False,
                confidence=0.0,
                reason="Structured AI planner output rejected.",
                provider_planning_called=True,
                provider_planning_succeeded=False,
                provider_error="PlannerRejected",
                plan_fixup={
                    "planner_rejected": True,
                    "planner_rejection_reason": validation.rejection_reason,
                    "fallback_task_type": fallback.task_type,
                },
                selection_mode=fallback.selection_mode,
                exclude_ids=fallback.exclude_ids,
                needs_step_by_step=fallback.needs_step_by_step,
                planner_rejected=True,
                planner_rejection_reason=validation.rejection_reason,
            )
        return _route_plan_from_decision(validation.decision, metadata, fallback)
    except (LLMError, TimeoutError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return heuristic_plan(message, metadata, session_context, provider_error=type(exc).__name__)

