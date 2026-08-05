"""Single-source correction / meta-question detectors for the DSPM Copilot.

The same complaint/correction detection used to be re-implemented with
divergent phrase lists in ``route_dispatcher``, ``service``, and ``planner``.
This module is now the only place these phrase families live; every runtime
surface delegates here so the lists cannot drift apart again.

Detectors accept the raw user message plus an optional ``extra_text`` channel
(the planner passes its cleaned routing text) and match against the union of
the normalized and raw-lowercase forms, exactly as the previous per-module
copies did.
"""
from __future__ import annotations

import re

from backend.copilot import language_service
from backend.copilot.language import normalize_message


def _joined(message: str, extra_text: str = "") -> str:
    norm = normalize_message(message)
    raw = str(message or "").lower()
    extra = str(extra_text or "").lower()
    return f"{norm} {raw} {extra}".strip()


_WHY_TERMS = ("why", "niye", "niyə")

# Markers that the user is talking about a previous assistant answer.
_PREVIOUS_ANSWER_MARKERS = (
    "dedin", "dediniz", "said", "answer", "cavab", "yazdin", "yazdın", "yazdiniz",
    "bayaq", "bayaqlari", "beyaqlari", "bəyaq", "bəyaqları", "evvel", "evvelki", "əvvəl",
)

_WHY_PREVIOUS_MARKERS = (
    "dedin", "dediniz", "said", "answer", "cavab", "yazdin", "yazdın", "yazdiniz",
    "niye bele cavab", "niyə belə cavab", "why did you answer",
)

_WRONG_ROUTE_TERMS = (
    "ne elaqe", "nə əlaqə", "elaqesi yoxdur", "unrelated",
    "bele bir sey istemedim", "belə bir şey istəmədim",
    "men bele bir sey istemedim", "mən belə bir şey istəmədim",
    "men bunu istemedim", "mən bunu istəmədim",
    "i did not ask", "i didnt ask", "i didnt want", "didnt want",
    "not what i asked", "not what i wanted", "thats not what i asked",
    "that is not what i asked", "that isnt what i asked", "not what im asking",
    "wrong route", "wrong context",
    "that is incorrect", "thats incorrect", "is incorrect", "was incorrect",
    "that is wrong", "thats wrong", "incorrect answer", "incorrect information",
)

WHY_ASSISTANT_ACTION_RE = re.compile(
    r"\bwhy\b.{0,60}\b(?:you|u|did you|do you)\b.{0,60}"
    r"\b(?:give|gave|giving|show|showed|showing|list|listed|send|sent|answer|answered)\b"
)


def detect_count_conflict_explanation(message: str, *, extra_text: str = "") -> bool:
    """User quotes a number from a previous answer and asks why ("why did you
    say 25?"). Must be answered as a meta explanation, never a new count."""
    joined = _joined(message, extra_text)
    has_number = bool(re.search(r"\b\d{1,5}\b", joined))
    has_why = any(term in joined for term in _WHY_TERMS)
    has_previous = any(term in joined for term in _PREVIOUS_ANSWER_MARKERS)
    return has_number and has_why and (has_previous or "say" in joined)


def detect_why_previous_answer(message: str, *, extra_text: str = "") -> bool:
    """User asks why the assistant answered/showed/listed something. A meta
    question about the previous answer — must not re-run the previous route."""
    if language_service.detect_malformed_output_complaint(message):
        return False
    joined = _joined(message, extra_text)
    if WHY_ASSISTANT_ACTION_RE.search(joined):
        return True
    has_why = any(term in joined for term in _WHY_TERMS)
    has_previous = any(term in joined for term in _WHY_PREVIOUS_MARKERS)
    return has_why and has_previous


def detect_wrong_route_complaint(message: str, *, extra_text: str = "") -> bool:
    """User states the previous answer was the wrong thing ("I didn't ask for
    that", "that is incorrect"). Includes the incorrect-fact family so wrong
    quoted numbers are treated as corrections, not new task requests."""
    if language_service.detect_malformed_output_complaint(message):
        return False
    joined = _joined(message, extra_text)
    return any(term in joined for term in _WRONG_ROUTE_TERMS)
