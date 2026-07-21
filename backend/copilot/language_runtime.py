"""Central dynamic language-decision runtime for the Copilot hot path.

This module owns the single question "which language should the current answer
be written in?" and returns a typed :class:`LanguageDecision` that downstream
layers (brainmap, controlled verbalizer, renderers, polish/validation, audit)
can trust.

Design policy (English-stable, multilingual-ready):

1. A live UI selector (this request) is authoritative.
2. A UI selection persisted in the session is authoritative and survives.
3. An explicit in-message imperative ("answer in English", "Azərbaycanca
   cavab ver") overrides automatic detection.
4. A clear current-turn detected language always beats the previous/inherited
   language.
5. A persisted explicit language lock is honored for ambiguous input.
6. Ambiguous short input inherits the previous response language.
7. Unknown fresh-session input defaults to English, never Azerbaijani.

Azerbaijani stays fully supported, but it is one supported language, not the
global default. The module is offline-only and adds no dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from backend.copilot import language_service
from backend.copilot.language import detect_language_metadata
from backend.copilot.language_detector import (
    is_cyrillic_or_mojibake_russian,
    is_explicit_azerbaijani_switch,
    is_explicit_english_switch,
    normalize_for_language_detection,
)

SUPPORTED_LANGUAGES = {"az", "en", "ru"}
DEFAULT_LANGUAGE = "en"

# A detected language at or above this confidence is treated as a clear
# current-turn signal that beats any inherited/previous language.
CLEAR_CONFIDENCE = 0.6

# Session keys that may carry a previous response language for inheritance.
_PREVIOUS_LANGUAGE_KEYS = (
    "last_answer_language",
    "response_language",
    "answer_language",
    "last_language",
    "user_language",
)


@dataclass(frozen=True)
class LanguageDecision:
    """Immutable, safe description of the language routing for one turn."""

    input_language: str
    response_language: str
    confidence: float
    source: str
    inherit_from_previous: bool
    explicit_user_override: bool
    reason: str

    def to_metadata(self) -> dict:
        return {
            "language_decision_input": self.input_language,
            "language_decision_response": self.response_language,
            "language_decision_confidence": round(float(self.confidence), 2),
            "language_decision_source": self.source,
            "language_decision_inherit_from_previous": bool(self.inherit_from_previous),
            "language_decision_explicit_override": bool(self.explicit_user_override),
            "language_decision_reason": self.reason,
        }


def _capability_question(message: str) -> bool:
    """A language *capability question* ("can you speak Azerbaijani?") must not be
    mistaken for an imperative switch ("Azərbaycanca cavab ver" = "answer in
    Azerbaijani"). Only genuine interrogative "can you speak X" phrasing counts;
    an imperative such as "cavab ver" / "answer" does not.
    """
    norm = normalize_for_language_detection(message)
    # "danışa bilirsən" ("are you able to speak") is a capability question with or
    # without a question mark.
    if any(marker in norm for marker in ("danisa bilir", "danisabilir", "danisa bilirsen")):
        return True
    if "?" not in (message or ""):
        return False
    return any(
        marker in norm
        for marker in (
            "can you",
            "could you",
            "are you able",
            "do you speak",
            "bilirsen",
        )
    )


def explicit_language_request(message: str) -> str | None:
    """Return a language only for a true imperative switch request.

    Mere mentions of a language name (e.g. "show azerbaijani email findings")
    and capability questions ("can you speak Azerbaijani?") must not force a
    language switch; only imperative "answer/respond in X" style phrases do.
    """
    if not message:
        return None
    if is_explicit_english_switch(message):
        return "en"
    if is_explicit_azerbaijani_switch(message) and not _capability_question(message):
        return "az"
    # Russian is only ever requested via an explicit instruction.
    requested = language_service.requested_language_from_message(message)
    if requested == "ru":
        return "ru"
    return None


def _previous_response_language(session_state: Mapping[str, object] | None) -> str | None:
    ctx = session_state or {}
    for key in _PREVIOUS_LANGUAGE_KEYS:
        value = ctx.get(key)
        if value in SUPPORTED_LANGUAGES:
            return str(value)
    return None


def decide_language(
    message: str,
    *,
    selected_language: str | None = None,
    selected_language_source: str | None = None,
    session_state: Mapping[str, object] | None = None,
    detected: tuple[str, float] | None = None,
) -> LanguageDecision:
    """Resolve the response language for the current turn.

    ``selected_language`` is the live UI selector for this request (if any).
    ``session_state`` carries persisted selection / previous-language context.
    """
    ctx = session_state or {}
    input_language, confidence = detect_language_metadata(message) if detected is None else detected
    # Russian/Cyrillic input (including double-encoded mojibake) is unsupported.
    # Mojibake Russian is otherwise misdetected as Azerbaijani with high
    # confidence; per the English-first contract such input must never resolve
    # to Azerbaijani via current-turn detection, so we neutralize the detected
    # language to "unknown" and let the normal precedence apply (an explicit UI
    # selection or lock still wins; a fresh session falls to English).
    if is_cyrillic_or_mojibake_russian(message):
        input_language = "unknown"
    input_norm = input_language if input_language in SUPPORTED_LANGUAGES else "unknown"
    selector_is_explicit = selected_language_source == "explicit_user_selection"

    # 1. Explicit in-message imperative switch overrides every stale/UI value.
    explicit = explicit_language_request(message)
    if explicit in SUPPORTED_LANGUAGES:
        return LanguageDecision(
            input_language=input_norm,
            response_language=str(explicit),
            confidence=0.99,
            source="explicit_user_override",
            inherit_from_previous=False,
            explicit_user_override=True,
            reason="explicit_request",
        )

    # 2. A clear current-turn language beats inherited/session language.
    if input_language in SUPPORTED_LANGUAGES and confidence >= CLEAR_CONFIDENCE:
        return LanguageDecision(
            input_language=input_norm,
            response_language=input_language,
            confidence=float(confidence),
            source="current_turn",
            inherit_from_previous=False,
            explicit_user_override=False,
            reason="clear_current_turn",
        )

    # 3. A selected language counts only when the UI marks it explicit.
    if selector_is_explicit and selected_language in SUPPORTED_LANGUAGES:
        return LanguageDecision(
            input_language=input_norm,
            response_language=str(selected_language),
            confidence=0.9,
            source="ui_selector_explicit",
            inherit_from_previous=False,
            explicit_user_override=False,
            reason="explicit_ui_selector",
        )

    session_selected = ctx.get("selected_language")
    session_selected_source = ctx.get("selected_language_source")
    if session_selected_source == "explicit_user_selection" and session_selected in SUPPORTED_LANGUAGES:
        return LanguageDecision(
            input_language=input_norm,
            response_language=str(session_selected),
            confidence=0.85,
            source="session_explicit_selector",
            inherit_from_previous=True,
            explicit_user_override=False,
            reason="persisted_explicit_ui_selector",
        )

    # 4. A durable explicit language lock from a prior turn persists until the
    #    user explicitly switches again. Only language-referencing messages set
    #    this lock, so ordinary greetings and DSPM queries never establish one
    #    and still fall through to current-turn detection below.
    locked = ctx.get("language_preference_locked")
    if locked in SUPPORTED_LANGUAGES:
        return LanguageDecision(
            input_language=input_norm,
            response_language=str(locked),
            confidence=max(float(confidence), 0.7),
            source="previous_lock",
            inherit_from_previous=True,
            explicit_user_override=False,
            reason="persisted_language_lock",
        )

    # 6. Ambiguous short input inherits the previous response language.
    previous = _previous_response_language(ctx)
    if previous in SUPPORTED_LANGUAGES:
        return LanguageDecision(
            input_language=input_norm,
            response_language=str(previous),
            confidence=max(float(confidence), 0.4),
            source="previous_turn_fallback",
            inherit_from_previous=True,
            explicit_user_override=False,
            reason="ambiguous_inherit_previous",
        )

    # 7. Unknown fresh-session fallback defaults to English.
    return LanguageDecision(
        input_language=input_norm,
        response_language=DEFAULT_LANGUAGE,
        confidence=max(float(confidence), 0.3),
        source="default_english",
        inherit_from_previous=False,
        explicit_user_override=False,
        reason="unknown_default_english",
    )
