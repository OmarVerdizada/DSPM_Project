"""P0 deterministic Situation Guardrails for trust-breaking chat flows.

This layer is intentionally small and offline-only. It classifies a narrow set
of high-risk conversation situations before provider fallback and selected
finding resolution, and provides an authoritative scope-resolution helper.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Mapping

from backend.copilot import fast_situation_arbiter, language_service


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


@dataclass(frozen=True)
class P0SituationDecision:
    situation_id: str
    confidence: float
    reason: str
    signals: list[str]
    response_policy: str
    uses_dspm_data: bool
    uses_selected_finding: bool
    uses_count_scope: bool
    uses_artifact_scope: bool
    provider_allowed: bool
    recovery_allowed: bool
    clarification_required: bool
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict[str, Any]:
        data = {
            "p0_guardrail_used": True,
            "situation_id": self.situation_id,
            "situation_confidence": self.confidence,
            "situation_reason": self.reason,
            "situation_signals": list(self.signals),
            "situation_response_mode": "DETERMINISTIC_RENDERER",
            "situation_provider_mode": "NO_PROVIDER",
            "situation_zero_provider": True,
            "provider_allowed": self.provider_allowed,
        }
        data.update(self.metadata)
        return data


@dataclass(frozen=True)
class ScopeResolution:
    scope_resolution_used: bool
    scope_source: str
    scope_reason: str
    current_explicit_scope: list[str]
    last_count_scope_used: list[str]
    selected_finding_suppressed: bool
    severities: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict[str, Any]:
        data = {
            "scope_resolution_used": self.scope_resolution_used,
            "scope_source": self.scope_source,
            "scope_reason": self.scope_reason,
            "current_explicit_scope": ",".join(self.current_explicit_scope) if self.current_explicit_scope else None,
            "last_count_scope_used": ",".join(self.last_count_scope_used) if self.last_count_scope_used else None,
            "selected_finding_suppressed": self.selected_finding_suppressed,
        }
        data.update(self.metadata)
        return data


def _fold(text: str) -> str:
    value = language_service.normalize_for_intent(text).lower()
    replacements = {
        "ə": "e",
        "ı": "i",
        "ğ": "g",
        "ö": "o",
        "ş": "s",
        "ç": "c",
        "ü": "u",
        "Ə": "e",
        "İ": "i",
        "Ğ": "g",
        "Ö": "o",
        "Ş": "s",
        "Ç": "c",
        "Ü": "u",
    }
    for src, dst in replacements.items():
        value = value.replace(src, dst)
    value = value.replace("skan", "scan")
    value = re.sub(r"[^a-z0-9_+*/?.-]+", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def _has_any(text: str, phrases: tuple[str, ...]) -> bool:
    return any(phrase in text for phrase in phrases)


def explicit_severities(message: str) -> list[str]:
    text = _fold(message)
    aliases = {
        "CRITICAL": ("critical", "kritik"),
        "HIGH": ("high", "yuksek", "yuks?k"),
        "MEDIUM": ("medium", "orta"),
        "LOW": ("low", "asagi", "asagi"),
    }
    positions: list[tuple[int, str]] = []
    for severity, terms in aliases.items():
        for term in terms:
            match = re.search(rf"(?<![a-z0-9_]){term}[a-z]*(?![a-z0-9_])", text)
            if match:
                positions.append((match.start(), severity))
                break
    positions.sort()
    result: list[str] = []
    for _pos, severity in positions:
        if severity not in result:
            result.append(severity)
    return result


def is_capability_typo_question(message: str) -> bool:
    # Delegate to the P3 fast arbiter's typo/merge/diacritic-tolerant matcher so
    # repeated letters (``nəələr edəbilirsən``) and merged words also route to the
    # existing zero-provider capability answer instead of slow provider fallback.
    return fast_situation_arbiter.is_capability_question(message)


def classify_p0_situation(message: str, context: Mapping[str, Any] | None = None) -> P0SituationDecision | None:
    context = context or {}
    text = _fold(message)
    raw = str(message or "").lower()
    joined = f"{text} {raw}"
    severities = explicit_severities(message)
    has_count_scope = bool(context.get("last_count_scope_severities"))

    if is_capability_typo_question(message):
        return _decision(
            "capability_question_typo",
            0.96,
            "typo-tolerant Azerbaijani capability question matched",
            ["capability_typo"],
            "deterministic_capability_answer",
            metadata={
                "fallback_family": "safe_out_of_scope",
                "capability_typo_normalized": True,
                "fast_situation_arbiter_used": True,
                "fast_situation_id": "capability_question_typo",
                "provider_suppressed_for_fast_situation": True,
            },
        )

    scan_decision = _classify_scan_action(joined)
    if scan_decision:
        return scan_decision

    if _is_conversation_tracking_complaint(joined):
        return _decision(
            "conversation_tracking_complaint",
            0.95,
            "user complained about conversation/context tracking",
            ["conversation_tracking_complaint"],
            "meta_tracking_explanation",
            uses_count_scope=has_count_scope,
            recovery_allowed=True,
            metadata={
                "fallback_family": "meta_tracking_explanation",
                "recovery_controller_used": True,
                "recovery_type": "conversation_tracking",
            },
        )

    if _is_scope_correction(joined, severities):
        return _decision(
            "scope_correction",
            0.94,
            "user corrected the requested severity/scope",
            ["scope_correction", *severities],
            "wrong_scope_recovery",
            uses_dspm_data=True,
            uses_count_scope=True,
            recovery_allowed=True,
            metadata={
                "fallback_family": "wrong_scope_recovery",
                "recovery_controller_used": True,
                "recovery_type": "wrong_scope",
            },
        )

    if has_count_scope and _is_count_scope_detail_followup(joined):
        return _decision(
            "count_scope_detail_followup",
            0.93,
            "detail follow-up binds to last count scope before selected finding",
            ["count_scope_detail_followup"],
            "scope_arbiter_detail",
            uses_dspm_data=True,
            uses_count_scope=True,
            metadata={"fallback_family": "safe_out_of_scope"},
        )

    if _is_wrong_route_recovery(joined):
        return _decision(
            "wrong_route_recovery",
            0.9,
            "user complained that previous route was wrong",
            ["wrong_route_recovery"],
            "wrong_scope_recovery",
            uses_count_scope=has_count_scope,
            recovery_allowed=True,
            metadata={
                "fallback_family": "wrong_scope_recovery",
                "recovery_controller_used": True,
                "recovery_type": "wrong_scope",
            },
        )

    return None


def _classify_scan_action(joined: str) -> P0SituationDecision | None:
    has_scan = "scan" in joined
    manual_delegate = _has_any(joined, ("manual etmiyim", "men manual", "mÉ™n manual", "manual etmÉ™yim"))
    if not has_scan and not manual_delegate:
        return None
    has_new = _has_any(joined, ("yeni", "new", "baslat", "basla", "start", "run", "manual"))
    has_action = _has_any(joined, (" et", " ele", " baslat", " start", " run", " manual", "islet"))
    has_file_server = "file server" in joined or "fiel server" in joined or "fileserver" in joined
    has_scan_page = "sehifesinden" in joined or "sÉ™hifÉ™sindÉ™n" in joined or "scan sehife" in joined or "scan sÉ™hifÉ™" in joined
    asks_capability = (has_file_server or has_scan_page or has_scan) and _has_any(joined, ("bilmirs", "bilmirsen", "edebilmir", "ede bilmir", "can you", "can't you"))
    incomplete = has_new and _has_any(joined, (" vere", " verə", " ver ")) and not has_action and not asks_capability

    if asks_capability:
        return _decision(
            "scan_action_capability_question",
            0.96,
            "scan action capability/boundary question matched",
            ["scan", "capability_question", "file_server"],
            "unsupported_operation",
            metadata={
                "operation_intent": "scan_capability",
                "operation_supported": False,
                "unsupported_action_answered": True,
                "fallback_family": "unsupported_operation",
            },
        )
    if incomplete:
        return _decision(
            "incomplete_scan_action_request",
            0.9,
            "scan action wording is incomplete and needs one clarification",
            ["scan", "incomplete_action"],
            "ambiguous_action_clarification",
            clarification_required=True,
            metadata={
                "operation_intent": "scan_start",
                "operation_supported": "unknown",
                "unsupported_action_answered": False,
                "fallback_family": "ambiguous_action_clarification",
            },
        )
    if (has_new or manual_delegate) and (has_action or _has_any(joined, ("manual etmiyim", "men manual", "mÉ™n manual", "sen scan", "sÉ™n scan", "sen et", "sÉ™n et"))):
        return _decision(
            "scan_start_request",
            0.95,
            "user asked chat to start a new scan",
            ["scan", "start_request"],
            "unsupported_operation",
            metadata={
                "operation_intent": "scan_start",
                "operation_supported": False,
                "unsupported_action_answered": True,
                "fallback_family": "unsupported_operation",
            },
        )
    return None


def _is_count_scope_detail_followup(joined: str) -> bool:
    return _has_any(
        joined,
        (
            "haqqinda melumat",
            "haqqında məlumat",
            "melumat ver",
            "detal ver",
            "detail ver",
            "about it",
            "about that",
        ),
    )


def _is_scope_correction(joined: str, severities: list[str]) -> bool:
    if not severities:
        return False
    has_correction = _has_any(joined, ("vermeliydin", "verməliydin", "sorusurdum", "soruşurdum", "bu nedi", "bu nədi", "what is this"))
    has_finding = _has_any(joined, ("tapinti", "tapıntı", "finding"))
    return has_correction and has_finding


def _is_wrong_route_recovery(joined: str) -> bool:
    if _has_any(joined, ("men bunu demedim", "niye anlamirsan", "niye anlamirs", "bunu demedim")):
        return True
    return _has_any(
        joined,
        (
            "ne elaqe",
            "nə əlaqə",
            "men sene bunu demedim",
            "mən sənə bunu demədim",
            "niye bele cavab verdin",
            "niyə belə cavab verdin",
            "wrong context",
        ),
    )


def _is_conversation_tracking_complaint(joined: str) -> bool:
    return _has_any(
        joined,
        (
            "sohbeti track",
            "söhbəti track",
            "context track",
            "konteksti izlem",
            "konteksti izləm",
            "conversation track",
            "niye sen sohbeti",
            "niyə sən söhbəti",
        ),
    )


def resolve_context_scope(
    message: str,
    conversation_state: Any | None,
    legacy_context: Mapping[str, Any] | None,
    route_decision: Any | None = None,
) -> ScopeResolution:
    del conversation_state, route_decision
    context = legacy_context or {}
    explicit = explicit_severities(message)
    correction = explicit if _is_scope_correction(f"{_fold(message)} {str(message or '').lower()}", explicit) else []
    last_count = [str(sev).upper() for sev in (context.get("last_count_scope_severities") or []) if str(sev).upper() in SEVERITIES]
    shown = context.get("last_shown_items") or []
    selected_exists = bool(context.get("current_item") or context.get("last_item") or (isinstance(shown, list) and shown))

    if explicit:
        return ScopeResolution(True, "current_message", "current explicit severity scope wins", explicit, [], selected_exists, explicit)
    if correction:
        return ScopeResolution(True, "current_correction", "current correction severity scope wins", correction, [], selected_exists, correction)
    if last_count:
        return ScopeResolution(True, "last_count_scope", "last count scope wins over selected finding", [], last_count, selected_exists, last_count)
    if isinstance(shown, list) and shown:
        return ScopeResolution(True, "shown_list", "last shown list used when no count scope exists", [], [], False, [])
    if selected_exists:
        return ScopeResolution(True, "selected_finding", "selected finding used only after explicit scopes are absent", [], [], False, [])
    return ScopeResolution(True, "none", "no safe context scope found", [], [], False, [])


def _decision(
    situation_id: str,
    confidence: float,
    reason: str,
    signals: list[str],
    response_policy: str,
    *,
    uses_dspm_data: bool = False,
    uses_selected_finding: bool = False,
    uses_count_scope: bool = False,
    uses_artifact_scope: bool = False,
    provider_allowed: bool = False,
    recovery_allowed: bool = False,
    clarification_required: bool = False,
    metadata: dict[str, Any] | None = None,
) -> P0SituationDecision:
    return P0SituationDecision(
        situation_id=situation_id,
        confidence=confidence,
        reason=reason,
        signals=signals,
        response_policy=response_policy,
        uses_dspm_data=uses_dspm_data,
        uses_selected_finding=uses_selected_finding,
        uses_count_scope=uses_count_scope,
        uses_artifact_scope=uses_artifact_scope,
        provider_allowed=provider_allowed,
        recovery_allowed=recovery_allowed,
        clarification_required=clarification_required,
        metadata=metadata or {},
    )
