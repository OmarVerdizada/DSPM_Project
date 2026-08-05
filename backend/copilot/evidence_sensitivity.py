"""First-class evidence-sensitivity classifier for the DSPM Copilot.

Decides, before any provider-final call, whether answering the current
message would require asserting a DSPM fact (counts, severity breakdowns,
findings, scan/file contents, risk scores, security posture). When evidence
is required and no evidence tool ran, the runtime must answer with a safe
deterministic clarification instead of a free provider answer, so the model
can never invent scan numbers or severities.

Unlike the earlier quantity-keyed helper this classifier is:

- keyed on "would the answer assert a DSPM fact", covering explanation-style
  questions ("why is this high?", "is this critical?") that carry a severity
  or posture assertion without a quantity word; and
- context-aware: a short follow-up ("and the rest?", "why?") inherits
  evidence sensitivity from the previous count/list/distribution answer
  stored in session context.

Definitional / teaching questions ("what is severity") remain exempt.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from backend.copilot.language import normalize_message
from backend.copilot.severity import severity_from_normalized_text

EVIDENCE_NONE = "none"
EVIDENCE_REQUIRED = "required"


@dataclass(frozen=True)
class EvidenceDecision:
    mode: str
    topic: str | None = None
    reason: str = ""

    @property
    def required(self) -> bool:
        return self.mode == EVIDENCE_REQUIRED


_EVIDENCE_NOUNS = (
    "alert", "alerts", "finding", "findings", "tapinti", "severity", "severities",
    "scan result", "scan results", "posture", "risk score", "risk level",
    "vulnerabilit", "sensitive file", "sensitive data",
)

_QUANTITY_TERMS = (
    "how many", "count", "counts", "number of", "exist", "exists",
    "divide", "split", "breakdown", "break down", "distribution",
    "list", "show", "top", "most", "total", "sum", "nece", "sayi",
)

_DEFINITIONAL_STARTS = (
    "what is", "what are", "what does", "explain what", "define", "meaning of",
    "ne demekdir", "nedir",
)

_STRONG_QUANTITY_TERMS = ("how many", "count", "exist", "in the system", "in my", "in our")

# Explanation-style questions that assert a DSPM fact without a quantity word.
# The negative lookahead keeps generic adjective uses ("high security
# standards") out of the evidence gate.
_SEVERITY_WORD = r"(?:critical|high|medium|low)(?!\s+(?:security|quality|performance|availability|standard|level\s+language))"
_FACT_ASSERTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    # "why is this high?", "why was that classified medium?"
    re.compile(rf"\bwhy\b.{{0,50}}\b(?:is|was|are|did)\b.{{0,50}}\b{_SEVERITY_WORD}\b"),
    # "is this critical?", "is it high risk?"
    re.compile(rf"\bis\s+(?:this|that|it)\b.{{0,30}}\b{_SEVERITY_WORD}\b"),
    # "why did it classify this as medium?"
    re.compile(rf"\bclassif\w+\b.{{0,40}}\bas\b.{{0,30}}\b{_SEVERITY_WORD}\b"),
    # "how risky is our environment?"
    re.compile(r"\bhow\s+(?:risky|secure|safe)\b.{0,50}\b(?:environment|system|company|network|data|files?|we\b|my\b|our\b)"),
    # "give me the security posture rundown" / "what's the posture status"
    re.compile(r"\bposture\b.{0,40}\b(?:rundown|overview|status|summary|score|now|today)\b"),
    re.compile(r"\b(?:rundown|overview|status|summary)\b.{0,40}\bposture\b"),
)

# Cues that a short message continues the previous evidence-backed task.
_CONTEXT_FOLLOWUP_CUES = (
    "rest", "others", "other ones", "remaining", "what about", "and the",
    "why", "how many", "breakdown", "again",
)

_EVIDENCE_CONTEXT_MARKERS = ("count", "distribution", "finding", "severity", "list")
_FILE_EVIDENCE_RE = re.compile(r"\b(?:files?|extensions?|file\s+types?)\b")


def _has_evidence_context(session_state: Mapping[str, Any] | None) -> bool:
    if not isinstance(session_state, Mapping):
        return False
    if session_state.get("last_count_scope_severities"):
        return True
    for key in ("last_answer_type", "last_result_type", "last_task_type"):
        value = str(session_state.get(key) or "").lower()
        if value and any(marker in value for marker in _EVIDENCE_CONTEXT_MARKERS):
            return True
    if session_state.get("active_task_frame"):
        return True
    return False


def _is_short_contextual_followup(norm: str) -> bool:
    words = norm.split()
    if not words or len(words) > 6:
        return False
    if any(cue in norm for cue in _CONTEXT_FOLLOWUP_CUES):
        return True
    return severity_from_normalized_text(norm) is not None


def classify_evidence_sensitivity(
    message: str,
    session_state: Mapping[str, Any] | None = None,
) -> EvidenceDecision:
    """Classify whether answering ``message`` would assert a DSPM fact.

    Runs deterministically with zero provider calls. ``session_state`` is the
    per-conversation session context; when present, short follow-ups inherit
    evidence sensitivity from the previous evidence-backed answer.
    """
    norm = normalize_message(message)
    if not norm:
        return EvidenceDecision(EVIDENCE_NONE, reason="empty")

    if any(norm.startswith(prefix) for prefix in _DEFINITIONAL_STARTS) and not any(
        term in norm for term in _STRONG_QUANTITY_TERMS
    ):
        return EvidenceDecision(EVIDENCE_NONE, reason="definitional")

    has_noun = (
        any(term in norm for term in _EVIDENCE_NOUNS)
        or severity_from_normalized_text(norm) is not None
        or bool(_FILE_EVIDENCE_RE.search(norm))
    )
    has_quantity = any(term in norm for term in _QUANTITY_TERMS)
    if has_noun and has_quantity:
        return EvidenceDecision(EVIDENCE_REQUIRED, topic="dspm_quantity", reason="noun_and_quantity")

    for pattern in _FACT_ASSERTION_PATTERNS:
        if pattern.search(norm):
            return EvidenceDecision(EVIDENCE_REQUIRED, topic="dspm_fact_assertion", reason="fact_assertion_pattern")

    if _has_evidence_context(session_state) and _is_short_contextual_followup(norm):
        return EvidenceDecision(
            EVIDENCE_REQUIRED,
            topic="contextual_followup",
            reason="short_followup_with_evidence_context",
        )

    return EvidenceDecision(EVIDENCE_NONE, reason="no_dspm_fact_signal")


def is_evidence_sensitive(message: str, session_state: Mapping[str, Any] | None = None) -> bool:
    return classify_evidence_sensitivity(message, session_state).required
