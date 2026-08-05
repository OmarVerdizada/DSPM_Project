"""Final deterministic answer polish gate for Copilot responses.

This module is intentionally offline-only. It validates the visible answer
against high-risk route, scope, language, fallback, and conversation invariants
and either returns the answer unchanged with audit metadata or applies a compact
deterministic repair.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Mapping

from backend.copilot import (
    capability_registry,
    fast_situation_arbiter,
    language_service,
    situation_guardrails,
    task_frame_controller,
)


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
GENERIC_DATA_FALLBACK = "Mövcud DSPM məlumatlarına əsasən buna cavab verə bilmirəm"
UNSUPPORTED_SCAN_ANSWER = (
    "Hazırda chat içindən yeni scan başlatmaq dəstəklənmir. File Server Scan səhifəsindən yeni scan-i başlada bilərsiniz; "
    "scan bitəndən sonra mən nəticələri analiz edə, riskləri prioritetləşdirə və remediation planı verə bilərəm."
)
UNSUPPORTED_SCAN_ANSWER_EN = (
    "Starting a new scan from chat is not supported yet. You can start one from the File Server Scan page; "
    "once it finishes I can analyze the results, prioritize risks, and suggest a remediation plan."
)
SCAN_CLARIFICATION = "Yeni scan başlatmaq istəyirsiniz, yoxsa son scan nəticəsini göstərim?"
SCAN_CLARIFICATION_EN = "Do you want to start a new scan, or should I show the latest scan results?"


def _unsupported_scan_answer(language: str) -> str:
    return UNSUPPORTED_SCAN_ANSWER if language == "az" else UNSUPPORTED_SCAN_ANSWER_EN


def _scan_clarification(language: str) -> str:
    return SCAN_CLARIFICATION if language == "az" else SCAN_CLARIFICATION_EN


@dataclass(frozen=True)
class AnswerInvariant:
    family: str
    passed: bool
    reason: str


@dataclass(frozen=True)
class AnswerQualityReport:
    passed: bool
    severity: str
    failed_invariants: list[str] = field(default_factory=list)
    repair_action: str | None = None
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolishRepair:
    action: str
    answer: str
    reason: str


@dataclass(frozen=True)
class ResponseLengthPolicy:
    answer_type: str
    max_words: int
    preserve_evidence: bool = True


@dataclass(frozen=True)
class FrustrationContext:
    detected: bool
    signals: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PolishDecision:
    answer: str
    report: AnswerQualityReport
    metadata: dict[str, Any]
    repair: PolishRepair | None = None


FORBIDDEN_INTERNAL_TEXT = (
    "Cavab dili qarışmışdı",
    "Cavab dili qarÄ±ÅŸmÄ±ÅŸdÄ±",
    "Cavabda dil qarışığı aşkarlandı",
    "Cavabda dil qarÄ±ÅŸÄ±ÄŸÄ± aÅŸkarlandÄ±",
    "sualı təkrar göndərin",
    "sualÄ± tÉ™krar gÃ¶ndÉ™rin",
    "Azərbaycanca cavab:",
    "AzÉ™rbaycanca cavab:",
    "Azerbaijani answer:",
)

FORBIDDEN_LANGUAGE_TEXT = (
    "Report artifact is ready",
    "Download:",
    "Source scan:",
    "I apologize",
    "You can download",
    "In the context of DSPM",
    "Çok",
    "çok",
    "iyidir",
    "hazırım",
    "çekinmeyin",
    "soraq verməkdən çekinmeyin",
    "reviewyın",
    "reviewndı",
    "unauthorized giriş",
    "restrict giriş",
    "Göstərilən 10 nəticə",
)

# P3 — mixed Azerbaijani/English/Turkish capability terms that must never reach
# the user under the Azerbaijani lock. Deterministic single-token repairs live in
# _MIXED_TERM_REPAIRS; anything else triggers a clean local replacement.
FORBIDDEN_MIXED_TERMS = (
    "Scan summaryları",
    "scan summaryları",
    "summaryları",
    "Kəritik",
    "kəritik",
    "Remediasyon",
    "remediasyon",
    "Expose olunmuş",
    "expose olunmuş",
    "priotizasiya",
    "Priotizasiya",
    "Həساس",
    "həساس",
    "حساس",
    "çəkinmeyin",
    "çekinmeyin",
)

_MIXED_TERM_REPAIRS = (
    ("Scan summaryları", "scan xülasələri"),
    ("scan summaryları", "scan xülasələri"),
    ("Remediasyon", "remediation"),
    ("remediasyon", "remediation"),
    ("Kəritik", "kritik"),
    ("kəritik", "kritik"),
    ("priotizasiya", "prioritizasiya"),
    ("Priotizasiya", "Prioritizasiya"),
    ("Expose olunmuş", "ifşa olunmuş"),
    ("expose olunmuş", "ifşa olunmuş"),
)


TASK_OBLIGATION_FORBIDDEN = (
    *FORBIDDEN_INTERNAL_TEXT,
    GENERIC_DATA_FALLBACK,
    "Say, siyahı və ya müqayisə sualını yazın",
)

FRUSTRATION_TERMS = (
    "niyə anlamırsan",
    "niye anlamirsan",
    "sən niyə anlamırsan",
    "nə əlaqə",
    "ne elaqe",
    "dedim axı",
    "dedim axi",
    "e sən bu nədi verdin",
    "niyə söhbəti track etmirsən",
    "niye sohbeti track etmirsən",
    "bəs",
    "bes",
    "ver də",
    "ver de",
    "yox e",
)


def validate_final_answer(
    *,
    message: str,
    answer: str,
    language: str,
    metadata: Mapping[str, Any] | None,
    session_state: Mapping[str, Any] | None,
    task_type: str | None = None,
    intent: str | None = None,
) -> PolishDecision:
    original = answer or ""
    current = original
    meta = dict(metadata or {})
    context = session_state or {}
    failed: list[str] = []
    repair_action: str | None = None
    internal_blocked = _contains_any(current, FORBIDDEN_INTERNAL_TEXT)
    turkish_blocked = _contains_any(current, FORBIDDEN_LANGUAGE_TEXT)
    frustration = _frustration_context(message)
    scope_values = _active_scope(message, context)
    operation = situation_guardrails.classify_p0_situation(message, context)
    is_scan_operation = bool(operation and operation.situation_id in {
        "scan_start_request",
        "scan_action_capability_question",
        "incomplete_scan_action_request",
        "unsupported_operation_request",
    })
    short_obligation = _is_short_continuation(message) and bool(task_frame_controller.active_frame(context))

    scope_check_allowed = _scope_check_allowed(meta, task_type, intent)
    scope_violation = scope_check_allowed and _scope_violation(current, scope_values, message)
    if scope_violation:
        failed.append("scope_consistency")
        current = _scope_clarification(scope_values, context, language)
        repair_action = "clarify"
        meta["selected_finding_suppressed"] = True

    operation_boundary_checked = is_scan_operation
    if is_scan_operation and _looks_like_finding_list(current):
        failed.append("operation_boundary")
        current = _scan_clarification(language) if operation and operation.situation_id == "incomplete_scan_action_request" else _unsupported_scan_answer(language)
        repair_action = "unsupported_operation"

    fallback_checked = True
    if GENERIC_DATA_FALLBACK in current and _generic_fallback_forbidden(message, context, meta, operation):
        failed.append("fallback_family_correctness")
        current = _specific_fallback(message, context, language)
        repair_action = "specific_fallback"

    if short_obligation and _contains_any(current, TASK_OBLIGATION_FORBIDDEN):
        failed.append("task_frame_obligation")
        current = _scope_clarification(scope_values, context, language)
        repair_action = "fulfill_task_frame"

    if language == "az" and (internal_blocked or turkish_blocked or _contains_any(current, FORBIDDEN_LANGUAGE_TEXT)):
        failed.append("language_lock")
        current = language_service.enforce_language(current, "az")
        if _contains_any(current, (*FORBIDDEN_INTERNAL_TEXT, *FORBIDDEN_LANGUAGE_TEXT)):
            current = _language_safe_fallback(message, context, language)
        repair_action = repair_action or "language_repair"

    # ---- P3 script / mixed-term / truncation guards (non-evidence prose only) ----
    script_contamination_blocked = False
    script_contamination_ranges: list[str] = []
    truncation_detected = False
    truncation_repair_applied = False
    if language == "az" and not _is_evidence_answer(meta, task_type):
        script_present = fast_situation_arbiter.contains_foreign_script(current) and not _foreign_script_allowed(message)
        mixed_present = _contains_any(current, FORBIDDEN_MIXED_TERMS)
        truncation_detected = fast_situation_arbiter.is_truncated(current)
        if script_present or mixed_present or truncation_detected:
            capability_social = _is_capability_or_social(task_type, intent, meta, message)
            repaired = current
            if script_present:
                repaired = fast_situation_arbiter.repair_foreign_script(repaired)
                script_contamination_ranges = ["Arabic"]
            if mixed_present:
                for src, dst in _MIXED_TERM_REPAIRS:
                    repaired = repaired.replace(src, dst)
            if truncation_detected:
                dropped = fast_situation_arbiter.repair_truncation(repaired)
                repaired = dropped if dropped else repaired
            still_bad = (
                (fast_situation_arbiter.contains_foreign_script(repaired) and not _foreign_script_allowed(message))
                or _contains_any(repaired, FORBIDDEN_MIXED_TERMS)
                or fast_situation_arbiter.is_truncated(repaired)
                or not repaired.strip()
            )
            if still_bad or capability_social:
                capability_language = language if language in {"en", "az", "ru"} else "en"
                current = capability_registry.render_capabilities(capability_language) if capability_social else _language_safe_fallback(message, context, language)
            else:
                current = repaired
            if script_present:
                script_contamination_blocked = True
            if truncation_detected:
                truncation_repair_applied = True
            if "p3_capability_polish" not in failed:
                failed.append("p3_capability_polish")
            repair_action = repair_action or "p3_capability_polish"

    metric_added = False
    if _needs_metric(current, meta, task_type) and "Metrik:" not in current and "Metric:" not in current:
        metric = str(meta.get("metric_name") or "file_level_finding_count")
        scan_id = str(meta.get("scan_id") or context.get("last_count_scope_scan_id") or context.get("last_scan_id") or "latest")
        current = f"{current.rstrip()}\nSkan: {scan_id}  Metrik: {metric}"
        metric_added = True

    trimmed = False
    length_policy = _length_policy(task_type, intent, meta, message)
    if length_policy:
        current, trimmed = _apply_length_policy(current, length_policy)

    current = language_service.enforce_language(current, language) if language in {"az", "en", "ru"} else current

    final_scope_violation = scope_check_allowed and _scope_violation(current, scope_values, message)
    if final_scope_violation and "scope_consistency" not in failed:
        failed.append("scope_consistency")
    passed = not final_scope_violation and not _contains_any(current, (*FORBIDDEN_INTERNAL_TEXT, *FORBIDDEN_LANGUAGE_TEXT))
    severity = "pass" if passed and not failed else ("repair" if passed else "block")
    if not passed and not repair_action:
        repair_action = "safe_fallback"
        current = _language_safe_fallback(message, context, language)
        passed = True
        severity = "repair"

    polish_meta = {
        "polish_gate_used": True,
        "polish_passed": passed,
        "polish_failed_invariants": ",".join(failed) if failed else None,
        "polish_repair_action": repair_action or "none",
        "polish_scope_check": True,
        "polish_scope_violation": bool(final_scope_violation if not scope_violation else True),
        "polish_operation_boundary_checked": operation_boundary_checked,
        "polish_fallback_family_checked": fallback_checked,
        "polish_language_repair_applied": current != original and (internal_blocked or turkish_blocked or "language_lock" in failed),
        "polish_internal_text_blocked": internal_blocked,
        "polish_turkish_leakage_blocked": turkish_blocked,
        "polish_response_length_policy_applied": bool(length_policy),
        "polish_user_frustration_detected": frustration.detected,
        "polish_corrected_answer_returned": bool(repair_action and repair_action != "none"),
        "response_length_policy_applied": bool(length_policy),
        "response_length_budget": length_policy.max_words if length_policy else None,
        "response_trimmed": trimmed,
        "polish_metric_added": metric_added,
        "script_contamination_blocked": script_contamination_blocked,
        "script_contamination_ranges": script_contamination_ranges or None,
        "truncation_detected": truncation_detected,
        "truncation_repair_applied": truncation_repair_applied,
    }
    meta.update(polish_meta)
    report = AnswerQualityReport(
        passed=passed,
        severity=severity,
        failed_invariants=failed,
        repair_action=repair_action,
        reason="; ".join(failed) if failed else "all final answer invariants passed",
        metadata=polish_meta,
    )
    repair = PolishRepair(repair_action, current, report.reason) if repair_action and repair_action != "none" else None
    return PolishDecision(answer=current, report=report, metadata=meta, repair=repair)


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    lowered = (text or "").lower()
    return any(needle.lower() in lowered for needle in needles)


def _is_evidence_answer(metadata: Mapping[str, Any], task_type: str | None) -> bool:
    """True for factual/evidence answers whose prose may legitimately hold IDs or
    filenames — these are exempt from the P3 script/mixed-term replacement so we
    never clobber real DSPM evidence."""
    if metadata.get("canonical_answer_used"):
        return True
    answer_type = str(metadata.get("answer_type") or task_type or "")
    return any(
        key in answer_type
        for key in ("count", "finding", "list", "fix_now", "scan_delta", "risk_type", "compare", "posture")
    )


def _foreign_script_allowed(message: str) -> bool:
    # Allowed only when the user themselves wrote Arabic/Persian script.
    return fast_situation_arbiter.contains_foreign_script(message)


def _is_capability_or_social(
    task_type: str | None, intent: str | None, metadata: Mapping[str, Any], message: str
) -> bool:
    route = " ".join(
        str(value or "")
        for value in (task_type, intent, metadata.get("situation_id"), metadata.get("route"))
    ).lower()
    if any(term in route for term in ("capability", "greeting", "small_talk", "status", "thanks", "praise", "social")):
        return True
    return fast_situation_arbiter.is_capability_question(message)


def _active_scope(message: str, context: Mapping[str, Any]) -> list[str]:
    explicit = situation_guardrails.explicit_severities(message)
    if explicit:
        return explicit
    frame = task_frame_controller.active_frame(context)
    if frame and frame.scope_kind == "severity":
        return list(frame.scope_values)
    return [str(value).upper() for value in (context.get("last_count_scope_severities") or []) if str(value).upper() in SEVERITIES]


def _scope_violation(answer: str, scope_values: list[str], message: str) -> bool:
    if not scope_values:
        return False
    explicit = set(situation_guardrails.explicit_severities(message))
    allowed = set(scope_values) | explicit
    if "CRITICAL" in explicit:
        return False
    present = {severity for severity in SEVERITIES if re.search(rf"\b{severity}\b", answer or "")}
    return bool(present - allowed)


def _scope_check_allowed(metadata: Mapping[str, Any], task_type: str | None, intent: str | None) -> bool:
    family = str(metadata.get("fallback_family") or "")
    situation_id = str(metadata.get("situation_id") or "")
    route_id = str(metadata.get("route_id") or "")
    route = " ".join(str(value or "") for value in (task_type, intent, route_id, situation_id, family))
    if any(term in route for term in (
        "conversation_tracking", "meta_tracking", "language_complaint", "malformed_output", "wrong_route_recovery",
        # Answers that legitimately span all severities (distribution/breakdown,
        # evidence-backed corrections) must not be rewritten by the scope check.
        "severity_distribution", "distribution", "complaint", "count_conflict", "evidence_guard",
    )):
        return False
    return True


def _scope_clarification(scope_values: list[str], context: Mapping[str, Any], language: str = "az") -> str:
    if language == "az":
        scope = ", ".join(scope_values or [str(v) for v in (context.get("last_count_scope_severities") or [])]) or "seçilmiş"
        noun = "alert/tapıntı" if _frame_alias(context) == "alert_as_finding" else "tapıntı"
        return f"Bunu dəqiqləşdirim: {scope} {noun} scope-u üzrə cavab verməliyəm. Konkret fayl adı seçmək istəyirsiniz, yoxsa bu scope-dan bir tapıntını açım?"
    scope = ", ".join(scope_values or [str(v) for v in (context.get("last_count_scope_severities") or [])]) or "the selected"
    noun = "alert/finding" if _frame_alias(context) == "alert_as_finding" else "finding"
    return f"Let me confirm the scope: I should answer for the {scope} {noun} scope. Do you want a specific file, or should I open one finding from this scope?"


def _frame_alias(context: Mapping[str, Any]) -> str | None:
    frame = task_frame_controller.active_frame(context)
    return frame.object_alias if frame else None


def _looks_like_finding_list(answer: str) -> bool:
    value = answer or ""
    if re.search(r"(?m)^\s*\d+\.\s+.+(?:CRITICAL|HIGH|MEDIUM|LOW)", value):
        return True
    return bool(re.search(r"\b(?:CRITICAL|HIGH|MEDIUM|LOW)\s*-\s*risk bal", value, re.IGNORECASE) or "Göstərilən 10 nəticə" in value)


def _generic_fallback_forbidden(
    message: str,
    context: Mapping[str, Any],
    metadata: Mapping[str, Any],
    operation: situation_guardrails.P0SituationDecision | None,
) -> bool:
    text = language_service.normalize_for_intent(message)
    if task_frame_controller.active_frame(context):
        return True
    if metadata.get("fallback_family") in {"meta_tracking_explanation", "wrong_scope_recovery", "language_repair_fallback", "unsupported_operation", "ambiguous_action_clarification"}:
        return True
    if operation and operation.situation_id in {"scan_start_request", "scan_action_capability_question", "incomplete_scan_action_request"}:
        return True
    return any(term in text for term in ("track", "anlamirsan", "ne elaqe", "demedim", "salam", "ne ede bilirsen", "ver de", "dedim"))


def _specific_fallback(message: str, context: Mapping[str, Any], language: str = "az") -> str:
    text = language_service.normalize_for_intent(message)
    if "scan" in text:
        return _unsupported_scan_answer(language)
    if task_frame_controller.active_frame(context) or any(term in text for term in ("dedim", "ver de", "haqqinda")):
        return _scope_clarification(_active_scope(message, context), context, language)
    if any(term in text for term in ("track", "anlamirsan", "demedim", "ne elaqe")):
        if language == "az":
            return "Haqlısınız. Burada söhbət kontekstini düzgün izləməli idim. Hansı scope-u davam etdirməyimi bir cümlə ilə dəqiqləşdirin."
        return "You're right — I should have tracked the conversation context better here. Please tell me in one sentence which scope to continue with."
    if language == "az":
        return "Bu sorğu üçün təhlükəsiz cavab verə bilmədim. Zəhmət olmasa, DSPM scan, tapıntı və ya remediation scope-unu dəqiqləşdirin."
    return "I could not produce a safe answer for that request. Please clarify the DSPM scan, finding, or remediation scope you mean."


def _language_safe_fallback(message: str, context: Mapping[str, Any], language: str = "az") -> str:
    if _is_short_continuation(message) and task_frame_controller.active_frame(context):
        return _scope_clarification(_active_scope(message, context), context, language)
    if language == "az":
        return "Cavabı Azərbaycan dilində təhlükəsiz şəkildə davam etdirirəm. DSPM scan, tapıntı, risk və remediation suallarına kömək edə bilərəm."
    return "Let me keep this answer safe and on topic. I can help with DSPM scan results, findings, risks, and remediation questions."


def _needs_metric(answer: str, metadata: Mapping[str, Any], task_type: str | None) -> bool:
    answer_type = str(metadata.get("answer_type") or task_type or "")
    if any(key in answer_type for key in ("count", "finding", "fix_now", "scan_delta", "risk_type_breakdown", "scoped_task_frame_detail")):
        return bool("Skan:" in (answer or "") or "Scan:" in (answer or "") or metadata.get("canonical_answer_used"))
    return False


def _length_policy(task_type: str | None, intent: str | None, metadata: Mapping[str, Any], message: str) -> ResponseLengthPolicy | None:
    route = str(metadata.get("route") or task_type or intent or "")
    text = language_service.normalize_for_intent(message)
    if route in {"greeting", "small_talk_status"} or text in {"salam", "necesen", "necəsən"}:
        return ResponseLengthPolicy("social", 18, preserve_evidence=False)
    if any(key in route for key in ("complaint", "tracking", "fallback")):
        return ResponseLengthPolicy("meta", 60, preserve_evidence=True)
    if any(key in route for key in ("scan_start", "scan_action", "unsupported_operation")):
        return ResponseLengthPolicy("scan_operation", 55, preserve_evidence=True)
    return None


def _apply_length_policy(answer: str, policy: ResponseLengthPolicy) -> tuple[str, bool]:
    words = answer.split()
    if len(words) <= policy.max_words:
        return answer, False
    if policy.preserve_evidence and ("\nSkan:" in answer or "\nScan:" in answer):
        return answer, False
    sentences = re.split(r"(?<=[.!?])\s+", answer.strip())
    if sentences and len(sentences[0].split()) <= policy.max_words:
        return sentences[0].strip(), True
    return " ".join(words[: policy.max_words]).rstrip(" ,;") + ".", True


def _frustration_context(message: str) -> FrustrationContext:
    text = language_service.normalize_for_intent(message)
    signals = [term for term in FRUSTRATION_TERMS if term in text]
    return FrustrationContext(bool(signals), signals[:8])


def _is_short_continuation(message: str) -> bool:
    text = language_service.normalize_for_intent(message)
    return any(term in text for term in ("ver de", "ver de bes", "dedim axi", "biri haqqinda", "haqqinda melumat", "onu ac", "he onu ver", "birini ac"))
