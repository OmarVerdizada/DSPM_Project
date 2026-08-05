"""P3 fast situation arbiter — zero-provider, no-think classification for short,
casual, or typo-heavy inputs.

This module is intentionally offline-only. It never calls a provider, planner,
translator, or tool, never reads scan data, and never returns raw secrets. Its
job is to (a) recognise lightweight social / capability / meta situations from
malformed input so they never reach slow provider fallback, and (b) provide
deterministic guards (foreign-script contamination, truncated final answers)
that keep the final visible Azerbaijani answer clean.

Capability typo detection is reused by ``situation_guardrails`` so the existing
zero-provider ``capability_question_typo`` route also survives repeated letters,
merged words, and diacritic variants.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Mapping

from backend.copilot import language_service


# ---------------------------------------------------------------------------
# Response modes
# ---------------------------------------------------------------------------
NO_MODEL_STATIC_RENDERER = "NO_MODEL_STATIC_RENDERER"
NO_MODEL_VARIANT_RENDERER = "NO_MODEL_VARIANT_RENDERER"
FAST_VERBALIZER_ALLOWED = "FAST_VERBALIZER_ALLOWED"
CLARIFY_SHORT = "CLARIFY_SHORT"
ESCALATE_STRUCTURED_PLANNER = "ESCALATE_STRUCTURED_PLANNER"

RESPONSE_MODES = (
    NO_MODEL_STATIC_RENDERER,
    NO_MODEL_VARIANT_RENDERER,
    FAST_VERBALIZER_ALLOWED,
    CLARIFY_SHORT,
    ESCALATE_STRUCTURED_PLANNER,
)

# Configurable lightweight-input threshold (Part F).
LIGHTWEIGHT_MAX_WORDS = 5
LIGHTWEIGHT_MAX_CHARS = 60


@dataclass(frozen=True)
class FastSituationDecision:
    situation_id: str
    confidence: float
    reason: str
    signals: list[str]
    response_mode: str
    speed_budget_ms: int = 40
    provider_allowed: bool = False
    planner_allowed: bool = False
    translator_allowed: bool = False
    selected_finding_allowed: bool = False
    uses_dspm_data: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict[str, Any]:
        data = {
            "fast_situation_arbiter_used": True,
            "fast_situation_id": self.situation_id,
            "fast_situation_confidence": self.confidence,
            "fast_response_mode": self.response_mode,
            "speed_budget_ms": self.speed_budget_ms,
            "provider_suppressed_for_fast_situation": not self.provider_allowed,
            "fast_situation_signals": list(self.signals),
        }
        data.update(self.metadata)
        return data


# ---------------------------------------------------------------------------
# Normalization (detection only — never applied to evidence/filenames/IDs)
# ---------------------------------------------------------------------------
_AZ_FOLD = {
    "ə": "e", "ı": "i", "ğ": "g", "ö": "o", "ş": "s", "ç": "c", "ü": "u",
    "Ə": "e", "İ": "i", "Ğ": "g", "Ö": "o", "Ş": "s", "Ç": "c", "Ü": "u",
}


def _fold(text: str) -> str:
    value = language_service.normalize_for_intent(text).lower()
    for src, dst in _AZ_FOLD.items():
        value = value.replace(src, dst)
    value = re.sub(r"[^a-z0-9_+*/?.-]+", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def collapse_repeats(text: str) -> str:
    """Collapse any run of the same character (2+) to a single character.

    Used only on a folded copy for situation detection so ``nəəələr`` /
    ``saalam`` / ``neeler`` normalise to a canonical stem.
    """
    return re.sub(r"(.)\1+", r"\1", text or "")


def normalize_fast_text(text: str) -> str:
    """Folded + repeat-collapsed text for lightweight situation detection."""
    return collapse_repeats(_fold(text))


def _has_any(text: str, phrases: tuple[str, ...]) -> bool:
    return any(phrase in text for phrase in phrases)


# ---------------------------------------------------------------------------
# Capability question detection (typo/merge/diacritic tolerant)
# ---------------------------------------------------------------------------
# All ability signals require 2nd-person ("-sən/-san") verb forms so that
# 1st-person remediation/advice ("nələr edəbilərəm", "nə məsləhət görürsən")
# is NOT misread as a capability question.
_CAPABILITY_MERGED_PATTERNS = (
    r"n[ea]g?a?r?a?bilirs[ea]n",                  # nağarabilirsən
    r"neyniy[ea]bilirs[ea]n",                     # neyniyə bilirsən
    r"n[ea]l?[ea]?r?ed[ea]bil[ie]?[ae]?rs[ea]n",  # nə/nələr edəbilirsən/edə bilərsən
    r"n[ea]e?d[ea]bil[ie]?[ae]?rs[ea]n",          # nə edəbilirsən (merged 'ne'+'edebil')
)
_CAPABILITY_ABILITY_STEMS = (
    "edebilirsen", "edebilersen", "ede bilirsen", "ede bilersen",
    "bacarirsan", "bacararsan", "is gorursen", "isgorursen", "is goresen",
    "komek edirsen", "komek ede bilersen", "edirsen",
)
_CAPABILITY_SAFE_PHRASES = (
    "what can you do", "what can u do", "what can i do with you",
    "ne bacarirsan", "ne bacararsan", "ne ede bilirsen", "ne ede bilersen",
    "ne is gorursen", "ne is goresen", "sen ne ede bilirsen", "neynen komek",
)
_CAPABILITY_STEM_RE = re.compile(r"\bn[ea](l[ea]r|ler|yn[ea]n|yniy[ea])?\b")


_SCAN_ACTION_CONTEXT_RE = re.compile(r"\b(scan|fileserver)\b")


def is_capability_question(message: str) -> bool:
    """True for capability questions even when typo-heavy, merged, or malformed.

    Scan / file-server action-capability questions are deferred to the dedicated
    scan-action classifier (they must get the unsupported-operation boundary
    answer, not the generic capability list).
    """
    folded = normalize_fast_text(message)
    compact = folded.replace(" ", "")
    if _SCAN_ACTION_CONTEXT_RE.search(folded) or "file server" in folded:
        return False
    if _has_any(folded, _CAPABILITY_SAFE_PHRASES):
        return True
    if any(re.search(pattern, compact) for pattern in _CAPABILITY_MERGED_PATTERNS):
        return True
    has_stem = bool(_CAPABILITY_STEM_RE.search(folded) or "neynen" in compact)
    has_ability = _has_any(folded, _CAPABILITY_ABILITY_STEMS) or _has_any(compact, _CAPABILITY_ABILITY_STEMS)
    return has_stem and has_ability


# ---------------------------------------------------------------------------
# Lightweight social / meta detection
# ---------------------------------------------------------------------------
_GREETING = ("salam", "hi", "hello", "hey")
_STATUS = (
    "necesen", "netersen", "ozun necesen", "sen necesen", "ne var ne yox",
    "ne xeber", "nece gedir", "how are you", "how are u", "are you okay",
)
_THANKS = ("sag ol", "sagol", "cox sag ol", "cox sagol", "saol", "tesekkur", "tesekkurler", "thanks", "thank you", "thx")
_PRAISE_PHRASES = ("cox agillisan", "cox sagolsan")
_PRAISE_TOKENS = {"agillisan", "elasan", "ela", "super", "perfect", "great", "molodes", "mükemmel", "mukemmel"}


def is_lightweight_input(message: str) -> bool:
    folded = _fold(message)
    return bool(folded) and (len(folded.split()) <= LIGHTWEIGHT_MAX_WORDS or len(folded) <= LIGHTWEIGHT_MAX_CHARS)


def classify_fast_situation(
    message: str,
    context: Mapping[str, Any] | None = None,
) -> FastSituationDecision | None:
    """Classify a lightweight situation, or return None to defer to the main pipeline.

    Never calls a provider. All returned decisions are zero-provider.
    """
    del context  # reserved for future scope-aware refinements; not needed for P3
    folded = normalize_fast_text(message)
    if not folded:
        return None

    if is_capability_question(message):
        return FastSituationDecision(
            situation_id="capability_question_typo",
            confidence=0.95,
            reason="typo-tolerant capability question",
            signals=["capability_typo"],
            response_mode=NO_MODEL_STATIC_RENDERER,
            metadata={"capability_typo_normalized": True},
        )
    if folded in _GREETING:
        return FastSituationDecision("greeting", 0.97, "greeting", ["greeting"], NO_MODEL_STATIC_RENDERER)
    if folded in _STATUS:
        return FastSituationDecision("status_check", 0.95, "status check", ["status"], NO_MODEL_STATIC_RENDERER)
    if _has_any(folded, _THANKS):
        return FastSituationDecision("thanks", 0.95, "thanks", ["thanks"], NO_MODEL_STATIC_RENDERER)
    if folded in _PRAISE_PHRASES or (set(folded.split()) & _PRAISE_TOKENS):
        return FastSituationDecision("praise", 0.9, "praise", ["praise"], NO_MODEL_STATIC_RENDERER)

    if is_lightweight_input(message):
        # Short casual/meta input with no clear DSPM ask: do not go to provider.
        return FastSituationDecision(
            situation_id="unknown_short_input",
            confidence=0.55,
            reason="short lightweight input without a clear DSPM request",
            signals=["short_input"],
            response_mode=CLARIFY_SHORT,
            metadata={"lightweight_input_provider_blocked": True},
        )
    return None


# ---------------------------------------------------------------------------
# Part D — Foreign-script contamination guard
# ---------------------------------------------------------------------------
_FOREIGN_SCRIPT_RE = re.compile(r"[؀-ۿݐ-ݿࢠ-ࣿ]")
# Narrow deterministic repairs for contaminated tokens seen from the model.
_SCRIPT_TOKEN_REPAIRS = (
    (re.compile(r"H[əe]?[؀-ۿ]+s?"), "Həssas"),
    (re.compile(r"h[əe]?[؀-ۿ]+s?"), "həssas"),
)


def contains_foreign_script(text: str) -> bool:
    return bool(_FOREIGN_SCRIPT_RE.search(text or ""))


def foreign_script_ranges(text: str) -> list[str]:
    return ["Arabic"] if contains_foreign_script(text) else []


def repair_foreign_script(text: str) -> str:
    """Best-effort deterministic repair; leftover script chars are stripped."""
    value = text or ""
    for pattern, replacement in _SCRIPT_TOKEN_REPAIRS:
        value = pattern.sub(replacement, value)
    # Strip any residual foreign-script runs to avoid mixed-script prose.
    value = _FOREIGN_SCRIPT_RE.sub("", value)
    return re.sub(r"\s{2,}", " ", value).strip()


# ---------------------------------------------------------------------------
# Part E — Truncation / incomplete-sentence guard
# ---------------------------------------------------------------------------
_DANGLING_CONNECTORS = {
    "ve", "ile", "ucun", "ki", "amma", "eger", "ya", "yoxsa", "hem",
    "ancaq", "lakin", "cunki", "hemcinin",
}
_INCOMPLETE_STEMS = {"istey", "iste", "ede", "vere", "kome", "varsa", "melu", "veri"}
_SENTENCE_END_RE = re.compile(r"[.!?…:)\]»”\"']$")
_BULLET_RE = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+")


def _last_prose_line(answer: str) -> str:
    lines = [line for line in (answer or "").splitlines() if line.strip()]
    return lines[-1].strip() if lines else ""


def is_truncated(answer: str) -> bool:
    text = (answer or "").rstrip()
    if not text:
        return False
    last = _last_prose_line(text)
    if not last:
        return False
    if _BULLET_RE.match(last):
        # A trailing bullet is a complete list item, not truncated prose.
        return False
    if _SENTENCE_END_RE.search(last):
        return False
    words = re.findall(r"[a-zəığöşçü0-9]+", collapse_repeats(_fold(last)))
    if not words:
        return False
    last_word = words[-1]
    return last_word in _DANGLING_CONNECTORS or last_word in _INCOMPLETE_STEMS


def repair_truncation(answer: str) -> str:
    """Drop the trailing unfinished sentence, preserving useful content.

    Returns "" when nothing safe remains (caller should use a route fallback).
    """
    text = (answer or "").rstrip()
    if not text:
        return ""
    lines = text.splitlines()
    bullet_indexes = [i for i, line in enumerate(lines) if _BULLET_RE.match(line)]
    if bullet_indexes and bullet_indexes[-1] < len(lines) - 1:
        # Keep the heading + bullet list; drop trailing unfinished prose.
        kept = "\n".join(lines[: bullet_indexes[-1] + 1]).rstrip()
        return kept
    sentences = re.split(r"(?<=[.!?…])\s+", text)
    if len(sentences) > 1:
        return " ".join(sentences[:-1]).rstrip()
    return ""
