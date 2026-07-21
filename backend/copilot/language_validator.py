"""Terminal (final) response-language validation and Azerbaijani polish.

This is the last language gate before a Copilot answer is returned to the user.
It is deterministic and offline: it never calls the LLM and never fabricates
content. It does two things for the selected UI language:

1. `polish_azerbaijani_prose` — fix a small, known set of ASCII-Azerbaijani prose
   tokens (e.g. ``secilmis`` -> ``seçilmiş``) without touching filenames, code
   identifiers, JSON keys, or allowed technical tokens.
2. `validate_response_language` / `ensure_final_response_language` — when
   Azerbaijani is the selected language, reject full English paragraphs and known
   English fallback markers and repair them to Azerbaijani (or a safe Azerbaijani
   fallback), while allowing technical tokens (API key, JWT, IBAN, DLP, scan,
   finding, severity labels, file names, ...).

It is intentionally conservative: an Azerbaijani answer that already contains
Azerbaijani letters plus technical tokens must pass unchanged.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from backend.copilot.guardrails import FALLBACK_ANSWER_AZ

# Azerbaijani-specific letters; presence signals real Azerbaijani prose.
_AZ_CHAR_RE = re.compile(r"[əƏıİöÖüÜçÇşŞğĞ]")

# Deterministic ASCII-AZ -> proper-AZ prose corrections (lowercase keys).
_AZ_PROSE_FIXES: dict[str, str] = {
    "gore": "görə",
    "eded": "ədəd",
    "ededler": "ədədlər",
    "tapinti": "tapıntı",
    "tapintilar": "tapıntılar",
    "tapintini": "tapıntını",
    "istifade": "istifadə",
    "secilmis": "seçilmiş",
    "melumat": "məlumat",
    "melumatlar": "məlumatlar",
    "melumatlari": "məlumatları",
    "sualini": "sualını",
    "sualiniz": "sualınız",
    "yazin": "yazın",
    "yaziin": "yazın",
    "asasen": "əsasən",
    "esasen": "əsasən",
    "etmirem": "etmirəm",
    "movcud": "mövcud",
    "danisirsan": "danışırsan",
    "danisirsiniz": "danışırsınız",
}

# Prose tokens that mark a still-broken Azerbaijani answer (violation signal).
_ASCII_AZ_VIOLATION_TOKENS = (
    "secilmis",
    "istifade",
    "tapinti",
    "melumat",
    "sualini",
    "yazin",
)

# Word token bounded by non-alphanumeric/underscore; filename/identifier adjacency
# (dots that form extensions, underscores, hyphens) is handled in the callback so
# that sentence-final words (before a period) are still corrected.
_WORD_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z]+)(?![A-Za-z0-9_])")

# Explicit English fallback/marker phrases that must never survive AZ lock.
_ENGLISH_MARKERS = (
    "high-risk findings require",
    "please ask a question",
    "i can help with",
    "the local ai model is unavailable",
    "the local ai model is temporarily unavailable",
    "according to the dspm dashboard",
    "review the details and remediate",
    "immediate attention",
    "you can download",
    "using the following link",
    "as a text file",
    "i apologize",
    "i cannot directly",
    "in the context of dspm",
    "report artifact is ready",
)

# English "explanatory" words that indicate a full English paragraph (not just
# a technical token). Kept small and conservative.
_ENGLISH_PROSE_WORDS = {
    "the", "and", "require", "requires", "attention", "immediate", "immediately",
    "please", "review", "details", "remediate", "should", "need", "needs",
    "according", "unavailable", "findings", "finding", "high-risk", "with",
    "this", "that", "your", "answer", "please", "based",
    "you", "can", "download", "using", "following", "apologize", "cannot",
    "directly", "provide", "ready", "here", "context",
}

_MIXED_LANGUAGE_CORRUPTION_PATTERNS = (
    (re.compile(r"\breview(?:y|nd|la|lə|in|ın|un|ün)\w*", re.IGNORECASE), "mixed_language:review_suffix"),
    (re.compile(r"\bunauthorized\s+giriş\b", re.IGNORECASE), "mixed_language:unauthorized_giris"),
    (re.compile(r"\brestrict\s+giriş\b", re.IGNORECASE), "mixed_language:restrict_giris"),
)

# Safe Azerbaijani fallback when a full English paragraph cannot be re-rendered.
LANGUAGE_LOCK_FALLBACK_AZ = (
    "Cavabı Azərbaycan dilində hazırlaya bilmədim. "
    "Zəhmət olmasa sualı yenidən verin və ya başqa formada soruşun."
)

# Redundant "answer in Azerbaijani:" prefixes that translation paths sometimes
# prepend. They add nothing and read as unprofessional — strip them entirely.
_ANSWER_PREFIX_RE = re.compile(
    r"^\s*(?:az(?:ə|e)rbaycan(?:ca| dilin(?:ə|e))?\s+cavab(?:\s+ver(?:ə|e)c(?:ə|e)y(?:ə|e)m)?|"
    r"cavab|answer|ответ)\s*[:：]\s*",
    re.IGNORECASE,
)

# Fabricated / malformed AZ tokens that have leaked from translation. Repaired to
# the intended word so the answer never presents a non-word as real Azerbaijani.
_FABRICATED_WORD_FIXES = (
    (re.compile(r"\bön[çc]ük\b", re.IGNORECASE), "öncəki"),
    (re.compile(r"\bon[çc]uk\b", re.IGNORECASE), "öncəki"),
)

# Stray list metadata that must not trail a non-list answer.
_STRAY_RESULT_COUNT_RE = re.compile(r"\s*Göstərilən\s+\d+\s+nəticə\.?\s*$")


def _repair_known_defects(text: str) -> str:
    """Deterministically strip redundant prefixes, repair fabricated words, and
    drop stray list metadata. Safe for any language; never fabricates content."""
    if not text:
        return text
    repaired = _ANSWER_PREFIX_RE.sub("", text, count=1)
    # Do not rewrite the fabricated token inside an answer that is itself
    # explaining that the token is not a real word (it must quote it verbatim).
    lowered = repaired.lower()
    explaining_malformed = any(
        marker in lowered for marker in ("düzgün söz deyil", "not a real", "не настоящее")
    )
    if not explaining_malformed:
        for pattern, replacement in _FABRICATED_WORD_FIXES:
            repaired = pattern.sub(replacement, repaired)
    repaired = _STRAY_RESULT_COUNT_RE.sub("", repaired)
    return repaired.strip() or text


@dataclass
class LanguageValidationResult:
    ok: bool
    text: str
    target_language: str
    repaired: bool = False
    violations: list[str] = field(default_factory=list)


def _preserve_case(original: str, replacement: str) -> str:
    if original[:1].isupper():
        return replacement[:1].upper() + replacement[1:]
    return replacement


def polish_azerbaijani_prose(text: str) -> str:
    """Deterministically fix known ASCII-Azerbaijani prose tokens.

    Only whole prose words are touched; filenames, code identifiers, JSON keys,
    and hyphen/underscore/dot-joined tokens are left intact by the word regex.
    """
    if not text:
        return text

    def _sub(match: re.Match[str]) -> str:
        word = match.group(1)
        fix = _AZ_PROSE_FIXES.get(word.lower())
        if fix is None:
            return word
        start, end = match.start(1), match.end(1)
        prev_c = text[start - 1] if start > 0 else ""
        next_c = text[end] if end < len(text) else ""
        next_next = text[end + 1] if end + 1 < len(text) else ""
        # Part of an identifier or filename (e.g. report.gore, melumat.txt, a_gore) — skip.
        if prev_c and prev_c in "._-":
            return word
        if next_c and next_c in "_-":
            return word
        if next_c == "." and next_next.isalnum():
            return word
        return _preserve_case(word, fix)

    return _WORD_RE.sub(_sub, text)


def _looks_like_full_english(text: str) -> bool:
    if _AZ_CHAR_RE.search(text):
        return False
    words = [w.lower() for w in _WORD_RE.findall(text)]
    if len(words) < 3:
        return False
    english_hits = sum(1 for w in words if w in _ENGLISH_PROSE_WORDS)
    return english_hits >= 2


def validate_response_language(text: str, target_language: str) -> LanguageValidationResult:
    """Detect language-lock violations. Conservative; technical tokens allowed."""
    violations: list[str] = []
    value = text or ""
    if target_language == "az":
        lowered = value.lower()
        if any(marker in lowered for marker in _ENGLISH_MARKERS):
            violations.append("english_marker")
        if _looks_like_full_english(value):
            violations.append("english_paragraph")
        for token in _ASCII_AZ_VIOLATION_TOKENS:
            if re.search(rf"(?<![A-Za-z0-9_.\-]){token}(?![A-Za-z0-9_.\-])", lowered):
                violations.append(f"ascii_az:{token}")
        for pattern, code in _MIXED_LANGUAGE_CORRUPTION_PATTERNS:
            if pattern.search(value):
                violations.append(code)
    # For en/ru we do not aggressively reject; upstream localizes those paths.
    return LanguageValidationResult(
        ok=not violations,
        text=value,
        target_language=target_language,
        violations=violations,
    )


def ensure_final_response_language(
    text: str,
    target_language: str,
    context: dict | None = None,
) -> str:
    """Terminal enforcement of the selected language on the final prose.

    - Azerbaijani: polish ASCII-AZ tokens; if a full English paragraph or English
      fallback marker remains and the text has no Azerbaijani content, replace it
      with a safe Azerbaijani fallback. Otherwise return the polished text.
    - English/Russian: returned unchanged (upstream renderers localize these).
    """
    if not text:
        return text
    # Strip redundant answer prefixes, repair fabricated words, drop stray list
    # metadata — for every language (these defects are language-agnostic).
    text = _repair_known_defects(text)
    if target_language != "az":
        return text

    polished = polish_azerbaijani_prose(text)
    result = validate_response_language(polished, "az")
    if result.ok:
        return polished

    # If it is essentially a full English paragraph with no Azerbaijani content,
    # we cannot safely translate it here (offline) — return a localized fallback.
    if not _AZ_CHAR_RE.search(polished) and (
        "english_paragraph" in result.violations or "english_marker" in result.violations
    ):
        return LANGUAGE_LOCK_FALLBACK_AZ

    # Mixed content with only ASCII-AZ token issues: the polish already applied;
    # return the best-effort polished text.
    return polished


def final_language_audit(text: str, target_language: str, original: str) -> dict:
    """Compact audit metadata about the terminal language validation."""
    result = validate_response_language(text, target_language)
    return {
        "language_validator_applied": True,
        "language_validator_passed": result.ok,
        "language_validator_repaired": text != original,
        "language_validator_violations": result.violations,
    }


# Prompt 5 consolidation: keep this legacy module as a compatibility surface,
# but route active behavior through the central deterministic facade.
from backend.copilot import language_service as _language_service


def polish_azerbaijani_prose(text: str) -> str:  # type: ignore[no-redef]
    return _language_service.polish_azerbaijani(text)


def validate_response_language(text: str, target_language: str):  # type: ignore[no-redef]
    return _language_service.validate_mixed_language(text, target_language)


def ensure_final_response_language(  # type: ignore[no-redef]
    text: str,
    target_language: str,
    context: dict | None = None,
) -> str:
    return _language_service.enforce_language(text, target_language, context)


def final_language_audit(text: str, target_language: str, original: str) -> dict:  # type: ignore[no-redef]
    return _language_service.final_language_audit(text, target_language, original)
