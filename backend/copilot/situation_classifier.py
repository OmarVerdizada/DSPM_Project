"""Deterministic Situation Intelligence classifier.

This module builds ranked SituationCandidate objects and turns the selected
candidate into a SituationDecision through the policy registry. It does not call
providers, execute tools, read scan data, or render final user answers.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import re
import time
from typing import Any, Iterable, Mapping

from backend.copilot import language_service, situation_guardrails, situation_policy
from backend.copilot.situation_policy import SituationCandidate, SituationDecision


@dataclass(frozen=True)
class SituationClassificationContext:
    message: str
    normalized_message: str | None = None
    target_language: str | None = None
    conversation_state: Any | None = None
    legacy_context: Mapping[str, Any] | None = None
    selected_language: str | None = None
    scan_id: str | None = None
    has_active_scan: bool | None = None
    has_selected_finding: bool | None = None
    has_shown_list: bool | None = None
    has_count_scope: bool | None = None
    has_artifact_scope: bool | None = None
    has_previous_answer: bool | None = None
    last_route_id: str | None = None
    last_answer_type: str | None = None
    route_decision: Any | None = None

    def context(self) -> Mapping[str, Any]:
        if self.legacy_context is not None:
            return self.legacy_context
        if isinstance(self.conversation_state, Mapping):
            return self.conversation_state
        return {}

    def flag(self, name: str) -> bool:
        explicit = getattr(self, name)
        if explicit is not None:
            return bool(explicit)
        context = self.context()
        if name == "has_active_scan":
            return bool(self.scan_id or context.get("last_scan_id") or context.get("scan_id"))
        if name == "has_selected_finding":
            return bool(context.get("current_item") or context.get("last_item"))
        if name == "has_shown_list":
            return bool(context.get("last_shown_items"))
        if name == "has_count_scope":
            return bool(context.get("last_count_scope_severities") or str(context.get("last_answer_type") or "").startswith("severity_count"))
        if name == "has_artifact_scope":
            return bool(context.get("latest_artifact") or context.get("last_artifact_id") or context.get("last_artifact_url"))
        if name == "has_previous_answer":
            return bool(context.get("last_answer_text") or context.get("last_answer_summary") or context.get("last_answer_structured_payload"))
        return False


def classify_message_situation(
    message: str,
    *,
    normalized_message: str | None = None,
    target_language: str | None = None,
    conversation_state: Any | None = None,
    legacy_context: Mapping[str, Any] | None = None,
    selected_language: str | None = None,
    scan_id: str | None = None,
    has_active_scan: bool | None = None,
    has_selected_finding: bool | None = None,
    has_shown_list: bool | None = None,
    has_count_scope: bool | None = None,
    has_artifact_scope: bool | None = None,
    has_previous_answer: bool | None = None,
    last_route_id: str | None = None,
    last_answer_type: str | None = None,
    route_decision: Any | None = None,
    route_candidates: list[Any] | None = None,
) -> SituationDecision | None:
    del route_candidates
    return classify_situation(
        SituationClassificationContext(
            message=message,
            normalized_message=normalized_message,
            target_language=target_language,
            conversation_state=conversation_state,
            legacy_context=legacy_context,
            selected_language=selected_language,
            scan_id=scan_id,
            has_active_scan=has_active_scan,
            has_selected_finding=has_selected_finding,
            has_shown_list=has_shown_list,
            has_count_scope=has_count_scope,
            has_artifact_scope=has_artifact_scope,
            has_previous_answer=has_previous_answer,
            last_route_id=last_route_id,
            last_answer_type=last_answer_type,
            route_decision=route_decision,
        )
    )


def classify_situation(context: SituationClassificationContext) -> SituationDecision | None:
    started = time.perf_counter()
    folded = _fold(context.normalized_message or context.message)
    raw_folded = _fold(context.message)
    text = f"{folded} {raw_folded}".strip()
    candidates = build_situation_candidates(context, text)

    route_decision = situation_policy.decision_from_route_decision(context.route_decision)
    if route_decision is not None:
        candidates.append(
            _candidate(
                route_decision.situation_id,
                route_decision.confidence,
                "route decision bridge",
                tuple(route_decision.signals),
                {"route_bridge": True},
            )
        )

    selected = choose_situation_candidate(candidates)
    if selected is None:
        selected = _candidate("unknown.low_confidence", 0.6, "no deterministic high-confidence situation matched", ("fallback_unknown",))

    latency_ms = int((time.perf_counter() - started) * 1000)
    conflict = bool(selected.metadata.get("situation_conflict_detected"))
    selected = replace(
        selected,
        metadata={
            **_safe_context_flags(context),
            **selected.metadata,
            "situation_classifier_used": True,
            "situation_candidates": _candidate_summaries(candidates),
            "situation_conflict_detected": conflict,
            "situation_fallback_needed": selected.situation_id.startswith("unknown."),
            "situation_classifier_latency_ms": latency_ms,
        },
    )
    return situation_policy.build_decision_from_candidate(selected, candidates)


def build_situation_candidates(context: SituationClassificationContext, text: str | None = None) -> list[SituationCandidate]:
    text = text if text is not None else _fold(context.normalized_message or context.message)
    candidates: list[SituationCandidate] = []

    def add(situation_id: str, confidence: float, reason: str, signals: Iterable[str], metadata: Mapping[str, Any] | None = None) -> None:
        candidates.append(_candidate(situation_id, confidence, reason, tuple(signals), metadata))

    _add_safety(candidates, text)
    _add_language(candidates, context.message, text)
    _add_complaints(candidates, text)
    _add_artifacts(candidates, context, text)
    _add_contextual_workflows(candidates, context, text)
    _add_dspm_factual(candidates, context, text)
    _add_capability(candidates, text)
    _add_social(candidates, text)
    _add_educational(candidates, text)
    _add_general(candidates, text)

    if not [candidate for candidate in candidates if candidate.matched]:
        if _has_any(text, ("bu nedir", "bunu et", "this", "that")):
            add("unknown.unclear_pronoun", 0.72, "vague pronoun without sufficient deterministic scope", ("unclear_pronoun",))
        else:
            add("unknown.needs_ai_arbiter", 0.66, "no deterministic high-confidence situation matched", ("arbiter_fallback",))
    return candidates


def choose_situation_candidate(candidates: Iterable[SituationCandidate]) -> SituationCandidate | None:
    matched = [candidate for candidate in candidates if candidate.matched]
    if not matched:
        return None

    safety = [candidate for candidate in matched if candidate.situation_id.startswith("safety.")]
    if safety:
        return _sort_candidates(safety)[0]

    for situation_id in (
        "language.malformed_output",
        "language.invalid_az_word",
        "language.truncated_answer",
        "artifact.cancel_topic",
        "complaint.count_conflict",
        "language.complaint",
        "context.shown_list_followup",
        "workflow.aggregate_remediation",
    ):
        preferred = [candidate for candidate in matched if candidate.situation_id == situation_id and _meets_threshold(candidate)]
        if preferred:
            return _sort_candidates(preferred)[0]

    eligible = [candidate for candidate in matched if _meets_threshold(candidate)]
    if not eligible:
        return _candidate("unknown.low_confidence", 0.6, "matched candidates were below policy confidence threshold", ("below_threshold",))
    ranked = _sort_candidates(eligible)
    if len(ranked) > 1 and _ambiguous(ranked[0], ranked[1]):
        return _candidate(
            "unknown.needs_ai_arbiter",
            0.7,
            "top deterministic candidates were too close to choose safely",
            ("candidate_conflict",),
            {"situation_conflict_detected": True},
        )
    return ranked[0]


def _candidate(
    situation_id: str,
    confidence: float,
    reason: str,
    signals: tuple[str, ...],
    metadata: Mapping[str, Any] | None = None,
) -> SituationCandidate:
    policy = situation_policy.get_policy(situation_id)
    return SituationCandidate(
        situation_id=situation_id,
        confidence=max(0.0, min(float(confidence), 1.0)),
        priority=policy.priority,
        matched=True,
        reason=reason,
        signals=tuple(str(signal) for signal in signals),
        metadata=dict(metadata or {}),
    )


def _sort_candidates(candidates: Iterable[SituationCandidate]) -> list[SituationCandidate]:
    return sorted(
        candidates,
        key=lambda candidate: (
            -situation_policy.get_policy(candidate.situation_id).priority,
            -candidate.priority,
            -candidate.confidence,
            candidate.situation_id,
        ),
    )


def _meets_threshold(candidate: SituationCandidate) -> bool:
    if candidate.situation_id.startswith("unknown."):
        return True
    return candidate.confidence >= situation_policy.get_policy(candidate.situation_id).default_confidence_threshold


def _ambiguous(first: SituationCandidate, second: SituationCandidate) -> bool:
    first_policy = situation_policy.get_policy(first.situation_id)
    second_policy = situation_policy.get_policy(second.situation_id)
    if first_policy.family == second_policy.family:
        return False
    if first_policy.priority != second_policy.priority:
        return False
    return abs(first.confidence - second.confidence) < 0.03


def _candidate_summaries(candidates: Iterable[SituationCandidate]) -> list[dict[str, Any]]:
    return [
        {
            "situation_id": candidate.situation_id,
            "confidence": round(candidate.confidence, 3),
            "priority": int(candidate.priority),
            "signals": list(candidate.signals[:5]),
        }
        for candidate in _sort_candidates(candidate for candidate in candidates if candidate.matched)[:8]
    ]


def _safe_context_flags(context: SituationClassificationContext) -> dict[str, Any]:
    return {
        "has_active_scan": context.flag("has_active_scan"),
        "has_selected_finding": context.flag("has_selected_finding"),
        "has_shown_list": context.flag("has_shown_list"),
        "has_count_scope": context.flag("has_count_scope"),
        "has_artifact_scope": context.flag("has_artifact_scope"),
        "has_previous_answer": context.flag("has_previous_answer"),
        "target_language": context.target_language,
        "selected_language": context.selected_language,
        "last_route_id": context.last_route_id,
        "last_answer_type": context.last_answer_type,
    }


def _fold(text: str) -> str:
    value = language_service.normalize_for_intent(str(text or "")).lower()
    for src, dst in (
        ("ə", "e"), ("ı", "i"), ("ğ", "g"), ("ö", "o"), ("ş", "s"), ("ç", "c"), ("ü", "u"),
        ("Ə", "e"), ("İ", "i"), ("Ğ", "g"), ("Ö", "o"), ("Ş", "s"), ("Ç", "c"), ("Ü", "u"),
        ("é™", "e"), ("ä±", "i"), ("äŸ", "g"), ("ã¶", "o"), ("åŸ", "s"), ("ã§", "c"), ("ã¼", "u"),
    ):
        value = value.replace(src.lower(), dst)
    value = re.sub(r"[^a-z0-9_+\-*/?.]+", " ", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def _has_any(text: str, phrases: Iterable[str]) -> bool:
    return any(phrase in text for phrase in phrases)


def _has_word(text: str, word: str) -> bool:
    return bool(re.search(rf"(?<![a-z0-9_]){re.escape(word)}(?![a-z0-9_])", text))


def _severity_terms(text: str) -> set[str]:
    found: set[str] = set()
    aliases = {
        "CRITICAL": ("critical", "kritik"),
        "HIGH": ("high", "yuksek", "yuks?k"),
        "MEDIUM": ("medium", "orta"),
        "LOW": ("low", "asagi", "asa?i"),
    }
    for severity, terms in aliases.items():
        if any(re.search(rf"(?<![a-z0-9_]){term}[a-z]*(?![a-z0-9_])", text) for term in terms):
            found.add(severity)
    return found


def _add_safety(candidates: list[SituationCandidate], text: str) -> None:
    if _has_any(text, ("ignore previous instructions", "ignore all instructions", "system prompt", "developer message", "jailbreak")):
        candidates.append(_candidate("safety.prompt_injection", 0.99, "prompt-injection phrase matched", ("prompt_injection",)))
    if _has_any(text, ("raw secret", "secret values", "show tokens", "butun token", "api keyleri", "passwordlari", "private values")):
        candidates.append(_candidate("safety.raw_secrets", 0.98, "raw secret/private value request matched", ("raw_secret_request",)))
    if _has_any(text, ("basqa tenant", "other tenant", "another tenant", "tenant bypass", "cross tenant")):
        candidates.append(_candidate("safety.tenant_bypass", 0.98, "cross-tenant data request matched", ("tenant_bypass",)))
    imperative_tool = _has_any(text, ("shell islet", "run shell", "execute shell", "git push", "git commit", "powershell islet", "cmd islet", "code execution"))
    if imperative_tool:
        candidates.append(_candidate("safety.arbitrary_tools", 0.96, "arbitrary runtime tool execution request matched", ("arbitrary_tools",)))


def _add_language(candidates: list[SituationCandidate], raw_message: str, text: str) -> None:
    malformed = language_service.detect_malformed_output_complaint(raw_message) or _has_any(text, ("oncuk", "on cuk", "sondaki te", "sondaki t", "yarimciq qaldi"))
    if _has_any(text, ("oncuk", "on cuk")):
        candidates.append(_candidate("language.invalid_az_word", 0.99, "known invalid Azerbaijani word was referenced", ("invalid_az_word",)))
    elif malformed:
        sid = "language.truncated_answer" if _has_any(text, ("yarimciq", "truncated", "sondaki te", "sondaki t")) else "language.malformed_output"
        candidates.append(_candidate(sid, 0.97, "malformed language output marker matched", ("malformed_output",)))

    if _has_any(text, ("evvelki cavabi tercume", "previous answer translate", "last answer translate", "cavabi tercume et", "ingilis diline cevir")):
        candidates.append(_candidate("language.translate_previous", 0.94, "previous answer translation request matched", ("translate_previous",)))
    if _has_any(text, ("azerbaycanca cavab ver", "ingilis dilinde cavab ver", "switch to english", "answer in english", "rus dilinde cavab ver")):
        candidates.append(_candidate("language.switch_language", 0.9, "explicit language switch request matched", ("switch_language",)))
    language_complaint = language_service.detect_language_complaint(raw_message) or _has_any(
        text,
        ("niye ingilis", "ingilisce yazdin", "bu azerbaycanca deyil", "wrong language", "azerbaycanca deyil"),
    )
    if language_complaint:
        candidates.append(_candidate("language.complaint", 0.9, "response-language complaint matched", ("language_complaint",)))
    if _has_any(text, ("hem ingilis hem az", "mixed language", "qarisiq dil")):
        candidates.append(_candidate("language.mixed_repair", 0.88, "mixed-language repair request matched", ("mixed_language",)))


def _add_complaints(candidates: list[SituationCandidate], text: str) -> None:
    if _has_any(text, ("ne elaqe", "elaqesi yoxdur")):
        candidates.append(_candidate("complaint.ne_elaqe", 0.96, "user says previous answer was unrelated", ("ne_elaqe",)))
    if _has_any(text, ("bunu istemirdim", "bele sey istemedim", "i did not want", "i didnt ask")):
        candidates.append(_candidate("complaint.did_not_want_that", 0.94, "user says they did not ask for that", ("did_not_want_that",)))
    if _has_any(text, ("yox men sadece", "sadəcə medium", "sadece medium", "only medium", "scope correction")):
        candidates.append(_candidate("complaint.scope_correction", 0.94, "scope correction phrase matched", ("scope_correction",)))
    if _has_any(text, ("bayaq basqa reqem", "basqa reqem dedin", "ferqli cixdi", "count conflict")):
        candidates.append(_candidate("complaint.count_conflict", 0.94, "previous count conflict matched", ("count_conflict",)))
    elif _has_any(text, ("niye basqa reqem", "192 ve 72 ferqli", "file level count")):
        candidates.append(_candidate("dspm.metric.explain_count_basis", 0.9, "count basis explanation matched", ("count_basis",)))
    if _has_any(text, ("yene sehv", "again wrong", "repeated misunderstanding")):
        candidates.append(_candidate("complaint.repeated_misunderstanding", 0.92, "repeated misunderstanding complaint matched", ("repeated_misunderstanding",)))
    if _has_any(text, ("niye bele cavab verdin", "why did you answer this")):
        candidates.append(_candidate("complaint.why_answered_this", 0.91, "why-answer complaint matched", ("why_answered_this",)))
    if _has_any(text, ("niye ilk defe basa dusmursen", "why dont you understand first")):
        candidates.append(_candidate("complaint.why_failed", 0.91, "why-failed complaint matched", ("why_failed",)))
    if _has_any(text, ("azərbaycanca deyil", "azerbaycanca deyil")):
        candidates.append(_candidate("complaint.language_quality", 0.88, "language-quality complaint matched", ("language_quality",)))


def _add_artifacts(candidates: list[SituationCandidate], context: SituationClassificationContext, text: str) -> None:
    artifact_active = context.flag("has_artifact_scope")
    metadata = {"has_artifact_scope": artifact_active}
    if _has_any(text, ("bos verek", "bos ver", "bunu bos", "cancel", "nevermind", "forget it")):
        candidates.append(_candidate("artifact.cancel_topic", 0.97, "cancel/reset topic phrase matched", ("cancel_topic",), metadata))
    if _has_any(text, ("link islemir", "broken link", "link acilmir")):
        candidates.append(_candidate("artifact.broken_link_complaint", 0.95, "broken artifact link complaint matched", ("broken_artifact_link",), metadata))
    if _has_any(text, ("full link", "tam link", "url ver")):
        candidates.append(_candidate("artifact.full_link_request", 0.94, "artifact full-link request matched", ("artifact_full_link",), metadata))
    if _has_any(text, ("klik", "clickable", "ustune basanda", "link kimi", "acilsin")):
        candidates.append(_candidate("artifact.clickable_link_request", 0.92, "clickable artifact link request matched", ("artifact_clickable_link",), metadata))
    if _has_any(text, ("nece yukleyim", "download help", "yukleye bilmirem")):
        candidates.append(_candidate("artifact.download_help", 0.92, "artifact download-help request matched", ("artifact_download_help",), metadata))
    if _has_any(text, ("evvelki report", "previous report", "last reportu")):
        candidates.append(_candidate("artifact.reuse_previous", 0.9, "previous artifact reuse request matched", ("artifact_reuse_previous",), metadata))
    if _has_any(text, ("report hazirdir", "export status", "pdf hazirdir")):
        candidates.append(_candidate("artifact.export_status", 0.9, "artifact export status request matched", ("artifact_export_status",), metadata))
    create = _has_any(text, ("pdf kimi ver", "report yarat", "hesabat yarat", "pdf yarat", "export et"))
    if create and _severity_terms(text):
        candidates.append(_candidate("artifact.filter_report", 0.92, "filtered report creation request matched", ("artifact_filter_report",), metadata))
    elif create:
        candidates.append(_candidate("artifact.create_report", 0.9, "report creation request matched", ("artifact_create_report",), metadata))


def _add_contextual_workflows(candidates: list[SituationCandidate], context: SituationClassificationContext, text: str) -> None:
    has_shown = context.flag("has_shown_list")
    has_count = context.flag("has_count_scope")
    has_selected = context.flag("has_selected_finding")
    has_previous = context.flag("has_previous_answer")

    if has_shown and _has_any(text, ("onlardan", "bunlardan", "from those", "from them", "from these")):
        candidates.append(_candidate("context.shown_list_followup", 0.96, "message points to previously shown list", ("shown_list_reference",)))
    if has_shown and _has_any(text, ("birincini", "sonuncunu", "first one", "last one", "ikinci")):
        candidates.append(_candidate("context.ordinal_item", 0.95, "ordinal reference to shown list matched", ("ordinal_reference",)))
    if has_shown and _has_any(text, ("basqa birini", "another one", "next one")):
        candidates.append(_candidate("context.next_unshown", 0.94, "next/unshown item request matched", ("next_unshown",)))
    if has_shown and _has_any(text, ("compare", "muqayise", "hansi daha")):
        candidates.append(_candidate("context.compare_shown_items", 0.9, "shown-item comparison request matched", ("compare_shown_items",)))
    if has_previous and _has_any(text, ("evvelki cavabi qisa", "previous answer shorter", "make it shorter", "qisa de", "qisaca")):
        candidates.append(_candidate("context.previous_answer_condense", 0.95, "previous answer condense request matched", ("previous_answer_condense",)))
    if has_previous and _has_any(text, ("daha detalli", "expand", "more detail")):
        candidates.append(_candidate("context.previous_answer_expand", 0.92, "previous answer expansion request matched", ("previous_answer_expand",)))
    if has_previous and _has_any(text, ("evvelki cavabi tercume", "previous answer translate", "cavabi tercume et")):
        candidates.append(_candidate("context.previous_answer_translate", 0.93, "previous answer translation request matched", ("previous_answer_translate",)))
    if has_previous and _has_any(text, ("bullet point", "manager dilinde", "style", "tonunu")):
        candidates.append(_candidate("context.style_change", 0.9, "previous answer style-change request matched", ("style_change",)))

    if has_count and _has_any(text, ("bunlar haqqinda step by step", "bunlar haqqinda", "these step by step", "basa sal")):
        candidates.append(_candidate("workflow.aggregate_remediation", 0.96, "aggregate count-scope remediation request matched", ("aggregate_scope",)))
    if has_selected and _has_any(text, ("bu tapintini nece duzeldim", "this finding fix", "selected finding remediation")):
        candidates.append(_candidate("workflow.selected_finding_remediation", 0.93, "explicit selected-finding remediation request matched", ("selected_finding_remediation",)))
    if _has_any(text, ("ilk neyi duzeldim", "fix first", "top 5 fix now", "top 5 fix-now", "first fix", "fix now risk")):
        candidates.append(_candidate("workflow.fix_now_top_risks", 0.94, "whole-scan fix-now request matched", ("fix_now",)))
    if _has_any(text, ("triage", "prioritet", "prioritize")):
        candidates.append(_candidate("workflow.triage", 0.9, "triage/prioritization request matched", ("triage",)))
    if _has_any(text, ("ne deyisib", "what changed", "son scan evvel", "previous scan", "since last scan")):
        candidates.append(_candidate("workflow.scan_delta", 0.94, "scan delta request matched", ("scan_delta",)))
    if _has_any(text, ("manager summary", "menecer summary", "rehber xulase")):
        candidates.append(_candidate("workflow.manager_summary", 0.9, "manager summary request matched", ("manager_summary",)))
    if _has_any(text, ("technical remediation", "texniki remediation", "technical fix")):
        candidates.append(_candidate("workflow.technical_remediation", 0.9, "technical remediation request matched", ("technical_remediation",)))
    if _has_any(text, ("niye bunu birinci", "why first", "why priority")):
        candidates.append(_candidate("workflow.priority_explanation", 0.9, "priority explanation request matched", ("priority_explanation",)))
    if _has_any(text, ("checklist ver", "remediation checklist")):
        candidates.append(_candidate("workflow.remediation_checklist", 0.9, "remediation checklist request matched", ("remediation_checklist",)))
    if _has_any(text, ("evidence", "subut", "niye bu risk")):
        candidates.append(_candidate("workflow.evidence_explanation", 0.86, "evidence explanation request matched", ("evidence_explanation",)))


def _add_dspm_factual(candidates: list[SituationCandidate], context: SituationClassificationContext, text: str) -> None:
    severities = _severity_terms(text)
    count_terms = _has_any(text, ("nece", "how many", "count", "say", "sayi"))
    if severities and count_terms:
        candidates.append(_candidate("dspm.count.severity_subset", 0.95, "severity subset count request matched", ("severity_subset_count",), {"severities": sorted(severities)}))
    elif count_terms and _has_any(text, ("tapinti", "finding", "findings")):
        candidates.append(_candidate("dspm.count.total_findings", 0.92, "total findings count request matched", ("total_findings_count",)))
    if _has_any(text, ("severity distribution", "severity paylan", "severity breakdown")):
        candidates.append(_candidate("dspm.distribution.severity", 0.93, "severity distribution request matched", ("severity_distribution",)))
    if _has_any(text, ("risk type breakdown", "risk tipi", "risk type", "credential nece")):
        candidates.append(_candidate("dspm.breakdown.risk_type", 0.92, "risk-type breakdown request matched", ("risk_type_breakdown",)))
    if _has_any(text, ("show 3 critical", "list findings", "tapintilari goster", "findings goster")):
        candidates.append(_candidate("dspm.list.findings", 0.9, "finding list request matched", ("list_findings",)))
    if _has_any(text, ("bu tapintini izah et", "this finding explain")):
        candidates.append(_candidate("dspm.detail.selected_finding", 0.88, "explicit selected-finding detail request matched", ("selected_finding_detail",), {"has_selected_finding": context.flag("has_selected_finding")}))
    if _has_any(text, ("posture score", "posture skoru")):
        candidates.append(_candidate("dspm.metric.posture_score", 0.92, "posture score request matched", ("posture_score",)))
    if _has_any(text, ("niye 192 ve 72", "file level count", "count basis")):
        candidates.append(_candidate("dspm.metric.explain_count_basis", 0.92, "count-basis explanation request matched", ("count_basis",)))


def _add_capability(candidates: list[SituationCandidate], text: str) -> None:
    if _has_any(text, ("neler edebilirsen", "ne ede bilirsen", "what can you do", "what are you able")):
        candidates.append(_candidate("capability.what_can_you_do", 0.95, "capability question matched", ("what_can_you_do",)))
    elif situation_guardrails.is_capability_typo_question(text):
        candidates.append(_candidate("capability.what_can_you_do", 0.95, "typo-tolerant capability question matched", ("what_can_you_do", "capability_typo")))
    if _has_any(text, ("nece komek ede", "how can you help", "help me with")):
        candidates.append(_candidate("capability.how_can_you_help", 0.93, "help-capability question matched", ("how_can_you_help",)))
    if _has_any(text, ("hansi datani gore", "what data can you see", "what data do you have", "ne gore bilirsen")):
        candidates.append(_candidate("capability.data_access", 0.93, "data-access capability question matched", ("data_access",)))
    if _has_any(text, ("ne ede bilmirs", "limitations", "what cant you do")):
        candidates.append(_candidate("capability.limitations", 0.92, "limitations question matched", ("limitations",)))
    if _has_any(text, ("hansi model", "which model", "model isleyir", "model status")):
        candidates.append(_candidate("capability.model_status", 0.92, "model-status question matched", ("model_status",)))
    if _has_any(text, ("melumatlarim tehlukesiz", "privacy", "data safe", "private safe")):
        candidates.append(_candidate("capability.privacy_safety", 0.92, "privacy/safety capability question matched", ("privacy_safety",)))
    if _has_any(text, ("shell islede bilersen", "can you run shell", "git islede bilersen", "mcp islede bilersen")):
        candidates.append(_candidate("capability.tool_boundary", 0.91, "runtime tool-boundary question matched", ("tool_boundary",)))


def _add_social(candidates: list[SituationCandidate], text: str) -> None:
    greeting = _has_word(text, "salam") or _has_word(text, "hello") or _has_word(text, "hi")
    status = _has_any(text, ("necesen", "how are you", "nec?sen"))
    if greeting and status:
        candidates.append(_candidate("social.greeting_status", 0.97, "greeting plus status check matched", ("greeting", "status_check")))
    elif greeting:
        candidates.append(_candidate("social.greeting", 0.95, "greeting token matched", ("greeting",)))
    if status and not greeting:
        candidates.append(_candidate("social.status_check", 0.93, "status check matched", ("status_check",)))
    if _has_any(text, ("sag ol", "tesekkur", "thanks", "thank you")):
        candidates.append(_candidate("social.thanks", 0.94, "thanks phrase matched", ("thanks",)))
    if _has_any(text, (
        "cox agillisan", "agillisan", "elasan", "super", "great job", "good job",
        "zorsan", "supersen", "bravo", "bomba kimisen", "mohtesemsen",
        "mukemmelsen", "mukemmel", "cox yaxsisan", "yaxsisan", "great", "molodes", "nice",
    )):
        candidates.append(_candidate("social.praise", 0.94, "praise phrase matched", ("praise",)))
    tokens = text.split()
    if text in {"ok", "okay", "hmm", "lol", "he"} or (
        tokens and set(tokens).issubset({"ok", "okay", "hmm", "lol", "he"})
    ):
        candidates.append(_candidate("social.casual_reaction", 0.9, "casual reaction token matched", ("casual_reaction",)))
    if _has_any(text, ("bye", "goodbye", "goruserik", "sag ol helelik")):
        candidates.append(_candidate("social.farewell", 0.93, "farewell phrase matched", ("farewell",)))
    if _has_any(text, ("useless", "faydasiz", "islemirsen", "hec ne bacarmirsan")):
        candidates.append(_candidate("social.frustration_unclear", 0.88, "unclear frustration phrase matched", ("frustration",)))


def _add_educational(candidates: list[SituationCandidate], text: str) -> None:
    if _has_any(text, ("dspm nedir", "what is dspm")):
        candidates.append(_candidate("edu.dspm_concept", 0.92, "DSPM concept question matched", ("dspm_concept",)))
    if _has_any(text, ("pii nedir", "api key nedir", "private key nedir", "security concept")):
        candidates.append(_candidate("edu.security_concept", 0.9, "security concept question matched", ("security_concept",)))
    if _has_any(text, ("compliance nedir", "pci nedir", "gdpr nedir")):
        candidates.append(_candidate("edu.compliance_concept", 0.9, "compliance concept question matched", ("compliance_concept",)))
    if _has_any(text, ("risk score ne demek", "risk score nedir")):
        candidates.append(_candidate("edu.risk_score", 0.92, "risk score concept question matched", ("risk_score",)))
    if _has_any(text, ("severity nedir", "severity ne demek")):
        candidates.append(_candidate("edu.severity", 0.92, "severity concept question matched", ("severity",)))
    if _has_any(text, ("remediation nedir", "remediation ne demek")):
        candidates.append(_candidate("edu.remediation_concept", 0.92, "remediation concept question matched", ("remediation_concept",)))
    if _has_any(text, ("step by step", "addim addim", "pille pille")):
        candidates.append(_candidate("edu.step_by_step", 0.82, "step-by-step explanation style matched", ("step_by_step",)))
    if _has_any(text, ("sade dilde", "beginner", "for beginner")):
        candidates.append(_candidate("edu.beginner", 0.88, "beginner explanation request matched", ("beginner",)))
    if _has_any(text, ("file level count nedir", "metric semantics", "metric ne demek")):
        candidates.append(_candidate("edu.metric_semantics", 0.9, "metric semantics question matched", ("metric_semantics",)))


def _add_general(candidates: list[SituationCandidate], text: str) -> None:
    if re.search(r"(?<!\d)\d+(?:\.\d+)?\s*[+\-*/]\s*\d+(?:\.\d+)?(?!\d)", text) and not re.search(r"[a-z_]", text):
        candidates.append(_candidate("general.simple_arithmetic", 0.98, "simple arithmetic expression matched", ("simple_arithmetic",)))
    if _has_any(text, ("hava necedir", "weather today", "today weather", "xəbərlər", "news today")):
        candidates.append(_candidate("general.external_world", 0.9, "external-world request matched", ("external_world",)))
    if _has_any(text, ("joke", "zarafat", "poem", "recipe")):
        candidates.append(_candidate("general.unrelated_request", 0.82, "non-DSPM unrelated request matched", ("unrelated_request",)))
