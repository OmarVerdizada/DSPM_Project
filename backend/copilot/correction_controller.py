"""First-class, reusable correction handling for the DSPM Copilot.

Previously correction/complaint recovery was ~6 scattered detector functions
plus hardcoded template answers, with no shared model of "what kind of
correction is this" and no memory of the rejected route. This controller:

- resolves the user's message into a typed :class:`CorrectionType` using the
  single-source detectors in :mod:`backend.copilot.correction_detection`;
- captures the rejected route from session state so the runtime can record
  it (``last_failed_route``) and avoid re-selecting the same wrong route for
  the next ambiguous follow-up;
- flags when the correction quotes DSPM facts (wrong numbers/severities) and
  therefore requires an evidence re-check instead of a generic apology.

The controller only *decides*; renderers and evidence tools stay where they
are. It never calls a provider and never produces DSPM facts itself.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from backend.copilot import correction_detection, language_service
from backend.copilot.language import normalize_message
from backend.copilot.severity import mentioned_severities


class CorrectionType(str, Enum):
    COUNT_CONFLICT = "count_conflict"      # "why did you say 25?" — explain, never re-count blindly
    WRONG_FACT = "wrong_fact"              # quotes wrong numbers/severities — re-check evidence
    WRONG_ROUTE = "wrong_route"            # "I didn't ask for that" — acknowledge, drop wrong context
    META_WHY = "meta_why"                  # "why did you answer that?" — explain previous answer
    WRONG_LANGUAGE = "wrong_language"      # answer was in the wrong language


@dataclass(frozen=True)
class CorrectionDecision:
    correction_type: CorrectionType
    rejected_route: str | None = None
    needs_evidence_recheck: bool = False
    requested_language: str | None = None
    clear_selected_finding: bool = False


_LANGUAGE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "en": ("english", "ingilis"),
    "az": ("azerbaijani", "azerbaycan", "azerice"),
    "ru": ("russian", "rus dilinde", "русск"),
}

_LANGUAGE_DIRECTIVE_PREFIX_RE = re.compile(
    r"\b(?:in|use|to|answer|respond|reply|speak|switch|write)\b[\s\w]{0,12}$"
)


def _requested_language_for_correction(message: str) -> str | None:
    """Resolve the language a correction asks for. A directive-adjacent
    mention ("answer in english") outranks a bare complaint mention ("why are
    you writing in azerbaijani"); with several directives the last one wins."""
    joined = f"{normalize_message(message)} {str(message or '').lower()}"
    best: str | None = None
    best_pos = -1
    for code, keywords in _LANGUAGE_KEYWORDS.items():
        for keyword in keywords:
            for match in re.finditer(re.escape(keyword), joined):
                prefix = joined[max(0, match.start() - 25):match.start()]
                if _LANGUAGE_DIRECTIVE_PREFIX_RE.search(prefix) and match.start() > best_pos:
                    best_pos = match.start()
                    best = code
    return best or language_service.requested_language_from_message(message)


def severity_correction_requested(message: str) -> bool:
    """True when a correction/complaint quotes severity numbers (e.g. a wrong
    breakdown) — those corrections must be answered with real evidence."""
    norm = normalize_message(message)
    mentioned = len(mentioned_severities(norm))
    has_numbers = bool(re.search(r"\b\d{1,5}\b", norm))
    return mentioned >= 2 or (mentioned >= 1 and has_numbers)


def rejected_route_from_state(session_state: Mapping[str, Any] | None) -> str | None:
    """Identify the route the user is rejecting from the stored previous-answer
    state (most-specific key first)."""
    if not isinstance(session_state, Mapping):
        return None
    for key in ("last_task_type", "last_answer_type", "last_result_type"):
        value = str(session_state.get(key) or "").strip()
        if value:
            return value[:120]
    return None


def resolve_correction(
    message: str,
    session_state: Mapping[str, Any] | None = None,
) -> CorrectionDecision | None:
    """Resolve the message into a typed correction, or None when the message
    is not a correction. Detection order mirrors the runtime dispatch order
    (language complaint, count conflict, wrong route, meta why)."""
    if language_service.detect_malformed_output_complaint(message):
        return None
    if language_service.detect_language_complaint(message):
        return CorrectionDecision(
            CorrectionType.WRONG_LANGUAGE,
            rejected_route=rejected_route_from_state(session_state),
            requested_language=_requested_language_for_correction(message),
        )
    if correction_detection.detect_count_conflict_explanation(message):
        return CorrectionDecision(
            CorrectionType.COUNT_CONFLICT,
            rejected_route=rejected_route_from_state(session_state),
        )
    if correction_detection.detect_wrong_route_complaint(message):
        wrong_fact = severity_correction_requested(message)
        return CorrectionDecision(
            CorrectionType.WRONG_FACT if wrong_fact else CorrectionType.WRONG_ROUTE,
            rejected_route=rejected_route_from_state(session_state),
            needs_evidence_recheck=wrong_fact,
            clear_selected_finding=True,
        )
    if correction_detection.detect_why_previous_answer(message):
        return CorrectionDecision(
            CorrectionType.META_WHY,
            rejected_route=rejected_route_from_state(session_state),
        )
    return None


def correction_state_effects(decision: CorrectionDecision | None, message: str) -> dict[str, Any]:
    """Session-state updates a correction turn must persist: the rejected
    route and the user's correction text (sanitized/capped). The next-turn
    routers consult ``last_failed_route`` so the rejected route is not
    silently re-selected for ambiguous follow-ups."""
    if decision is None:
        return {}
    return {
        "last_failed_route": decision.rejected_route or f"corrected:{decision.correction_type.value}",
        "last_user_correction": str(message or "")[:300],
    }
