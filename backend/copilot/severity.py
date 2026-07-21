from __future__ import annotations

import re

from backend.copilot import language_service


SEVERITY_ALIASES = {
    "critical": "CRITICAL",
    "kritik": "CRITICAL",
    "high": "HIGH",
    "yuksek": "HIGH",
    "yuksək": "HIGH",
    "yüksək": "HIGH",
    "medium": "MEDIUM",
    "orta": "MEDIUM",
    "low": "LOW",
    "asagi": "LOW",
    "asağı": "LOW",
    "aşağı": "LOW",
}

AZ_SEVERITY_SUFFIXES = (
    "larinin",
    "lerinin",
    "lardan",
    "lerden",
    "larin",
    "lerin",
    "lara",
    "lere",
    "lari",
    "leri",
    "dan",
    "den",
    "dir",
    "dur",
    "lar",
    "ler",
    "nin",
    "di",
    "du",
    "da",
    "de",
    "in",
    "i",
)
_SUFFIX_PATTERN = "|".join(re.escape(suffix) for suffix in AZ_SEVERITY_SUFFIXES)


def normalize_for_severity(message: str) -> str:
    return language_service.normalize_for_intent(message)


def severity_from_normalized_text(normalized: str) -> str | None:
    for key, value in sorted(SEVERITY_ALIASES.items(), key=lambda item: len(item[0]), reverse=True):
        if re.search(rf"(?<![a-z0-9_]){re.escape(key)}(?:{_SUFFIX_PATTERN})?(?![a-z0-9_])", normalized or ""):
            return value
    return None


def severity_from_text(message: str) -> str | None:
    return severity_from_normalized_text(normalize_for_severity(message))


# Single source for "which severities does this text mention" — previously
# re-implemented with identical spec tables in intent_router and planner.
SEVERITY_MENTION_PATTERNS: dict[str, tuple[str, ...]] = {
    "CRITICAL": (r"\bcritical\w*\b", r"\bkritik\w*\b"),
    "HIGH": (r"\bhigh\w*\b", r"\byuksek\w*\b", r"\byuksak\w*\b"),
    "MEDIUM": (r"\bmedium\w*\b", r"\borta\w*\b"),
    "LOW": (r"\blow\w*\b", r"\basagi\w*\b", r"\ba[sz]agi\w*\b"),
}


def mentioned_severities(*texts: str) -> set[str]:
    """Return the set of severities mentioned across the given text fragments."""
    joined = " ".join(str(text or "") for text in texts)
    found: set[str] = set()
    for severity, patterns in SEVERITY_MENTION_PATTERNS.items():
        if any(re.search(pattern, joined) for pattern in patterns):
            found.add(severity)
    return found


_BREAKDOWN_VERBS = (
    "divide", "split", "break down", "breakdown", "break", "group",
    "distribution", "distribute", "categorize", "categorise",
    "bolusdur", "bölüşdür", "qrupla", "paylasdir", "paylaşdır",
)

_BREAKDOWN_PHRASES = (
    "by severity", "per severity", "severity breakdown", "severity distribution",
    "base on severity", "based on severity", "severity uzre", "severity üzrə",
    "ciddiliye gore", "ciddiliyə görə",
)


def is_severity_breakdown_request(normalized: str) -> bool:
    """True when the user asks to split/group findings by severity, in any phrasing.

    This is a concept-level check (breakdown verb + severity noun), not an exact
    phrase list, so wordings like "divide base on severity" route to the
    evidence-backed severity distribution instead of a free provider answer.
    """
    text = normalized or ""
    if any(phrase in text for phrase in _BREAKDOWN_PHRASES):
        return True
    mentions_severity_word = "severity" in text or "severities" in text or "ciddilik" in text
    return mentions_severity_word and any(verb in text for verb in _BREAKDOWN_VERBS)


_BARE_SEVERITY_RE = re.compile(
    r"^(?:and\s+|what\s+about\s+|how\s+about\s+|bes\s+|bəs\s+)?"
    r"(critical|high|medium|low|kritik|yuksek|yüksək|orta|asagi|aşağı)"
    r"(?:\s+(?:ones?|alerts?|findings?|tapinti(?:lar)?|tapıntı(?:lar)?))?\s*\??$"
)


def bare_severity_followup(normalized: str) -> str | None:
    """Return the severity for short contextual follow-ups like "low?",
    "and high?", "what about medium" — else None."""
    match = _BARE_SEVERITY_RE.match((normalized or "").strip())
    if not match:
        return None
    return SEVERITY_ALIASES.get(match.group(1))
