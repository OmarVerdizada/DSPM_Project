"""Central deterministic language facade for active Copilot routes.

This module consolidates the language operations that are used on the hot chat
path: response-language resolution, intent normalization, complaint detection,
terminal Azerbaijani enforcement, and small terminology/polish fixes. It is
offline-only and intentionally wraps existing behavior incrementally rather than
removing the older modules.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Mapping

SUPPORTED_LANGUAGES = {"az", "en", "ru"}

AZ_TERMINOLOGY: dict[str, str] = {
    "finding": "tapıntı",
    "selected finding": "seçilmiş tapıntı",
    "download": "yüklə",
    "click": "klikləyin",
    "previous": "əvvəlki",
    "latest": "son",
    "resolved": "bağlanmış",
    "new findings": "yeni tapıntılar",
    "common findings": "dəyişməyən tapıntılar",
    "what changed": "nə dəyişib",
    "fix first": "ilk düzəldiləcək risklər",
    "next best action": "növbəti ən yaxşı addım",
}

ALLOWED_TECHNICAL_TOKENS = (
    "DSPM",
    "scan",
    "finding",
    "remediation",
    "dashboard",
    "risk score",
    "API key",
    "JWT",
    "IBAN",
    "PCI",
    "DLP",
    "secret",
    "token",
    "credential",
    "access",
    "revoke",
    "rotate",
    "secret manager",
    "least-privilege",
    "compliance",
    "data",
    "CI/CD",
    "manager",
    "HIGH",
    "MEDIUM",
    "LOW",
    "CRITICAL",
    "file_level_finding_count",
)

_AZ_CHAR_RE = re.compile(r"[əƏıİöÖüÜçÇşŞğĞ]")
_WORD_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z]+)(?![A-Za-z0-9_])")
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+|\n+")
_ANSWER_PREFIX_RE = re.compile(
    r"^\s*(?:az(?:ə|e)rbaycan(?:ca| dilin(?:ə|e))?\s+cavab(?:\s+ver(?:ə|e)c(?:ə|e)y(?:ə|e)m)?|"
    r"azerbaijani\s+answer|answer|cavab|ответ)\s*[:：]\s*",
    re.IGNORECASE,
)
_STRAY_RESULT_COUNT_RE = re.compile(r"\s*Göstərilən\s+\d+\s+nəticə\.?", re.IGNORECASE)

_PROTECTED_RE = re.compile(
    r"https?://\S+|"
    r"/(?:[A-Za-z0-9._~:-]+/)*[A-Za-z0-9._~:-]+|"
    r"\b[A-Za-z0-9_.-]+\.(?:pdf|json|txt|xlsx|xls|csv|env|pem|key|yaml|yml|docx|zip)\b|"
    r"\b[A-Za-z0-9]+(?:_[A-Za-z0-9]+)+\b"
)

_AZ_PROSE_FIXES: dict[str, str] = {
    "gore": "görə",
    "eded": "ədəd",
    "ededler": "ədədlər",
    "tapinti": "tapıntı",
    "tapintilar": "tapıntılar",
    "tapintini": "tapıntını",
    "melumat": "məlumat",
    "melumatlar": "məlumatlar",
    "melumatlari": "məlumatları",
    "secilmis": "seçilmiş",
    "istifade": "istifadə",
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
    "kecirek": "keçirək",
    "yukluyum": "yükləyim",
    "yukluyebilirem": "yükləyə bilirəm",
    "yukluye bilmirəm": "yükləyə bilmirəm",
    "yukluye bilmirem": "yükləyə bilmirəm",
}

_PHRASE_FIXES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bÇok\b", re.IGNORECASE), "Çox"),
    (re.compile(r"\bçok\b", re.IGNORECASE), "çox"),
    (re.compile(r"\biyidir\b", re.IGNORECASE), "yaxşıdır"),
    (re.compile(r"\bhazırım\b", re.IGNORECASE), "hazıram"),
    (re.compile(r"\bçekinmeyin\b", re.IGNORECASE), "çəkinməyin"),
    (re.compile(r"\breviewy[ıi]n\b", re.IGNORECASE), "yoxlayın"),
    (re.compile(r"\breviewnd[ıi]\b", re.IGNORECASE), "yoxlanıldı"),
    (re.compile(r"\bunauthorized\s+giriş\b", re.IGNORECASE), "icazəsiz giriş"),
    (re.compile(r"\brestrict\s+giriş\b", re.IGNORECASE), "girişi məhdudlaşdırın"),
    (re.compile(r"\brevoke\s+or\s+rotate\s+the\s+credential\b", re.IGNORECASE), "credential-i ləğv edin və ya rotasiya edin"),
    (re.compile(r"\bən\s+sondak[ıi]?\b", re.IGNORECASE), "sonuncu"),
    (re.compile(r"\bsondaki\b", re.IGNORECASE), "sondakı"),
)

_ENGLISH_MARKERS = (
    "çok",
    "iyidir",
    "hazırım",
    "çekinmeyin",
    "you can download",
    "i apologize",
    "in the context of dspm",
    "report artifact is ready",
    "download:",
    "source scan:",
    "if leaked",
    "revoke or rotate",
    "restrict giriş",
    "unauthorized giriş",
    "the selected finding",
    "selected finding",
)

_ENGLISH_PROSE_WORDS = {
    "the",
    "and",
    "answer",
    "apologize",
    "inconvenience",
    "you",
    "can",
    "download",
    "report",
    "artifact",
    "ready",
    "here",
    "source",
    "if",
    "leaked",
    "enable",
    "unauthorized",
    "misuse",
    "reuse",
    "selected",
    "revoke",
    "rotate",
    "restrict",
    "provide",
    "context",
    "following",
    "link",
}

_MIXED_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:Çok|çok)\b", re.IGNORECASE), "mixed_language:turkish_cok"),
    (re.compile(r"\biyidir\b", re.IGNORECASE), "mixed_language:turkish_iyidir"),
    (re.compile(r"\bhazırım\b", re.IGNORECASE), "mixed_language:turkish_hazirim"),
    (re.compile(r"\bçekinmeyin\b", re.IGNORECASE), "mixed_language:turkish_cekinmeyin"),
    (re.compile(r"\bunauthorized\s+giriş\b", re.IGNORECASE), "mixed_language:unauthorized_giris"),
    (re.compile(r"\brestrict\s+giriş\b", re.IGNORECASE), "mixed_language:restrict_giris"),
    (re.compile(r"\brevoke\s+or\s+rotate\s+the\s+credential\b", re.IGNORECASE), "mixed_language:english_remediation"),
    (re.compile(r"\bthe\s+selected\s+finding\b", re.IGNORECASE), "mixed_language:selected_finding"),
    (re.compile(r"\breview(?:y|nd|la|lə|in|ın|un|ün)\w*", re.IGNORECASE), "mixed_language:review_suffix"),
)

_MALFORMED_WORDS = ("önçük", "öncük", "oncuk")
_LANGUAGE_COMPLAINT_TERMS = (
    "niye ingilis",
    "niyə ingilis",
    "hem azerbaycan hem ingilis",
    "həm azərbaycan həm ingilis",
    "həm azərbaycanca həm ingiliscə",
    "azerbaycanca cavab ver",
    "azərbaycanca cavab ver",
    "azerbaycan dili secmisem",
    "azərbaycan dili seçmişəm",
    "azerbaycan dili seceneyi",
    "azərbaycan dili seçənəyi",
)


@dataclass
class LanguageValidationResult:
    ok: bool
    text: str
    target_language: str
    repaired: bool = False
    violations: list[str] = field(default_factory=list)


def _strip_accents_and_az(text: str) -> str:
    value = unicodedata.normalize("NFKD", text or "")
    value = "".join(ch for ch in value if not unicodedata.combining(ch))
    value = value.lower()
    replacements = {
        "ə": "e",
        "ı": "i",
        "ğ": "g",
        "ö": "o",
        "ş": "s",
        "ç": "c",
        "ü": "u",
    }
    for src, dst in replacements.items():
        value = value.replace(src, dst)
    return value


def normalize_user_text(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()


def normalize_for_intent(text: str) -> str:
    value = _strip_accents_and_az(text)
    replacements: tuple[tuple[str, str], ...] = (
        ("əəd", "eded"),
        ("eed", "eded"),
        ("saalam", "salam"),
        ("neleredebilirsen", "neler edebilirsen"),
        ("nagarabilirsen", "ne ede bilirsen"),
        ("nagarabilersen", "ne ede bilirsen"),
        ("neyniye bilirsen", "ne ede bilirsen"),
        ("nele redebilirsen", "neler edebilirsen"),
        ("neler ede bilersen", "neler edebilirsen"),
        ("edebilersen", "edebilirsen"),
        ("yukluyum", "yukleyim"),
        ("yukluyebilmirəm", "yukleye bilmirem"),
        ("yukluye bilmirem", "yukleye bilmirem"),
        ("yukleye bilmirəm", "yukleye bilmirem"),
        ("bos verek", "bos verek"),
    )
    for src, dst in replacements:
        value = value.replace(src, dst)
    value = re.sub(r"\bsa+lam\b", "salam", value)
    value = re.sub(r"\b(?:e+ded|eed)\b", "eded", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def resolve_language(
    *,
    message: str,
    selected_language: str | None = None,
    session_language: str | None = None,
    explicit_language: str | None = None,
    detected_language: str | None = None,
    default_language: str = "en",
) -> str:
    for candidate in (
        selected_language,
        session_language,
        explicit_language,
        detected_language,
        default_language,
    ):
        if candidate in SUPPORTED_LANGUAGES:
            return candidate
    if "azerbaycan" in normalize_for_intent(message):
        return "az"
    return "en"


def requested_language_from_message(message: str) -> str | None:
    norm = normalize_for_intent(message)
    raw = str(message or "").lower()
    if "azerbaycan" in norm or "azərbaycan" in raw or "azerbaijani" in norm or "azerice" in norm:
        return "az"
    if "ingilis" in norm or "english" in norm:
        return "en"
    if "rus dilinde" in norm or "russian" in norm or "русск" in raw:
        return "ru"
    return None


def detect_language_complaint(message: str) -> bool:
    norm = normalize_for_intent(message)
    raw = str(message or "").lower()
    joined = f"{norm} {raw}"
    if any(term in joined for term in _LANGUAGE_COMPLAINT_TERMS):
        return True
    has_en_ref = "ingilis" in joined or "english" in joined
    has_az_ref = "azerbaycan" in joined or "azərbaycan" in joined or "azerbaijan" in joined
    grievance = any(term in joined for term in ("niye", "niyə", "why", "neden"))
    mixed = has_en_ref and has_az_ref and any(term in joined for term in ("hem", "həm", "both"))
    wrong_language = has_en_ref and any(term in joined for term in ("yazdin", "yazdın", "danis", "danış", "cavab verdin"))
    # A grievance about the language the assistant is *speaking/answering in*
    # ("why are you speaking Azerbaijani?", "why do you answer in English?").
    speaking_ref = any(
        term in joined
        for term in ("speak", "talk", "answer", "reply", "respond", "writing", "write", "danis", "danış", "cavab")
    )
    complains_about_language = grievance and (has_az_ref or has_en_ref) and speaking_ref
    return bool((grievance and (mixed or wrong_language)) or mixed or complains_about_language)


def detect_malformed_output_complaint(message: str) -> bool:
    norm = normalize_for_intent(message)
    raw = str(message or "").lower()
    mentions_bad_word = any(word in raw for word in _MALFORMED_WORDS) or "oncuk" in norm
    mentions_truncated_te = bool(re.search(r"\b(?:sondaki|sondakı|axirda|axırda|sonda)\b.*\bt[əe]\b", raw)) or (
        "sondaki" in norm and re.search(r"\bte\b", norm)
    )
    return mentions_bad_word or mentions_truncated_te


def malformed_output_answer(language: str = "az") -> str:
    if language == "en":
        return (
            "\"Önçük\" is not a valid Azerbaijani word. It was a language error in the previous answer. "
            "The correct expression should have been \"əvvəlki\" or \"öncəki\". The trailing \"tə\" was a truncated answer fragment."
        )
    if language == "ru":
        return (
            "«Önçük» не является правильным азербайджанским словом. Это языковая ошибка в предыдущем ответе. "
            "Правильное выражение: «əvvəlki» или «öncəki». Финальное «tə» было оборванным фрагментом ответа."
        )
    return (
        "Önçük Azərbaycan dilində düzgün söz deyil. Bu, əvvəlki cavabda yaranmış dil xətasıdır. "
        "Düzgün ifadə əvvəlki və ya öncəki olmalı idi. Sondakı tə isə yarımçıq qalmış cavab hissəsidir."
    )


def localized_language_complaint_answer(language: str = "az", has_previous_answer: bool = False) -> str:
    if language == "en":
        return "You're right — I should reply in the language you're using. I'll continue in English."
    if language == "ru":
        return "Вы правы, ответ должен быть на выбранном языке. Дальше буду отвечать по-русски."
    suffix = " İstəsəniz, əvvəlki cavabı da Azərbaycan dilində yenidən verə bilərəm." if has_previous_answer else ""
    return (
        "Haqlısınız, cavab seçilmiş dilə uyğun olmalı idi. Bundan sonra cavabı Azərbaycan dilində verəcəyəm."
        + suffix
    )


def _protect(text: str) -> tuple[str, dict[str, str]]:
    protected: dict[str, str] = {}

    def _sub(match: re.Match[str]) -> str:
        key = f"__LANG_PROTECT_{len(protected)}__"
        protected[key] = match.group(0)
        return key

    return _PROTECTED_RE.sub(_sub, text), protected


def _restore(text: str, protected: Mapping[str, str]) -> str:
    restored = text
    for key, value in protected.items():
        restored = restored.replace(key, value)
    return restored


def _preserve_case(original: str, replacement: str) -> str:
    if original[:1].isupper():
        return replacement[:1].upper() + replacement[1:]
    return replacement


def _repair_known_defects(text: str) -> str:
    if not text:
        return text
    repaired = text
    previous = None
    while repaired != previous:
        previous = repaired
        repaired = _ANSWER_PREFIX_RE.sub("", repaired, count=1)
    repaired = _STRAY_RESULT_COUNT_RE.sub("", repaired)
    explaining_malformed = "düzgün söz deyil" in repaired.lower()
    if not explaining_malformed:
        repaired = re.sub(r"\bön[çc]ük\b", "öncəki", repaired, flags=re.IGNORECASE)
        repaired = re.sub(r"\boncuk\b", "öncəki", repaired, flags=re.IGNORECASE)
    repaired = re.sub(r"(?:^|\s)t[əe]\s*$", "", repaired).strip()
    return repaired or text


def polish_azerbaijani(text: str) -> str:
    if not text:
        return text
    repaired = _repair_known_defects(text)
    protected_text, protected = _protect(repaired)
    for pattern, replacement in _PHRASE_FIXES:
        protected_text = pattern.sub(replacement, protected_text)

    def _replace_word(match: re.Match[str]) -> str:
        word = match.group(1)
        replacement = _AZ_PROSE_FIXES.get(word.lower())
        if replacement is None:
            return word
        start, end = match.start(1), match.end(1)
        prev_c = protected_text[start - 1] if start > 0 else ""
        next_c = protected_text[end] if end < len(protected_text) else ""
        next_next = protected_text[end + 1] if end + 1 < len(protected_text) else ""
        if (prev_c and prev_c in "._-/") or (next_c and next_c in "_-/"):
            return word
        if next_c == "." and next_next.isalnum():
            return word
        return _preserve_case(word, replacement)

    protected_text = _WORD_RE.sub(_replace_word, protected_text)
    protected_text = re.sub(r"(?m)(^|[.!?]\s+)sondakı\b", lambda m: f"{m.group(1)}Sondakı", protected_text)
    return _restore(protected_text, protected).strip()


def _text_without_allowed_tokens(text: str) -> str:
    stripped = _PROTECTED_RE.sub(" ", text)
    for token in sorted(ALLOWED_TECHNICAL_TOKENS, key=len, reverse=True):
        stripped = re.sub(re.escape(token), " ", stripped, flags=re.IGNORECASE)
    return stripped


def validate_mixed_language(text: str, target_language: str = "az") -> LanguageValidationResult:
    value = text or ""
    violations: list[str] = []
    if target_language != "az":
        return LanguageValidationResult(True, value, target_language)

    lowered = value.lower()
    if _ANSWER_PREFIX_RE.search(value):
        violations.append("language_prefix")
    for marker in _ENGLISH_MARKERS:
        if marker in lowered:
            violations.append("english_marker")
    for pattern, code in _MIXED_PATTERNS:
        if pattern.search(value):
            violations.append(code)
    for token in ("secilmis", "istifade", "tapinti", "melumat", "eded", "gore"):
        if re.search(rf"(?<![A-Za-z0-9_.\-]){token}(?![A-Za-z0-9_.\-])", lowered):
            violations.append(f"ascii_az:{token}")

    for sentence in [part.strip() for part in _SENTENCE_RE.split(value) if part.strip()]:
        prose = _text_without_allowed_tokens(sentence)
        words = [w.lower() for w in re.findall(r"[A-Za-z]+", prose)]
        if not words:
            continue
        english_hits = sum(1 for word in words if word in _ENGLISH_PROSE_WORDS)
        has_az = bool(_AZ_CHAR_RE.search(sentence))
        if english_hits >= 3 or (english_hits >= 2 and not has_az):
            violations.append("english_sentence")
            break

    return LanguageValidationResult(
        ok=not violations,
        text=value,
        target_language=target_language,
        violations=violations,
    )


def localized_fallback(language: str = "az", reason: str | None = None) -> str:
    if language == "en":
        return "The answer contained a language mismatch. I will continue safely in English."
    if language == "ru":
        return "В ответе было смешение языков. Дальше буду отвечать безопасно по-русски."
    return (
        "Cavab dili qarışmışdı, ona görə cavabı təhlükəsiz şəkildə Azərbaycan dilində saxlayıram. "
        "DSPM scan, tapıntı, risk və remediation suallarınıza davam edə bilərəm."
    )


# Azerbaijani canned social fragments that must never leak into an English or
# Russian answer. These are deliberately high-precision: they do not appear in
# legitimate English DSPM prose.
_AZ_CANNED_LEAKAGE = (
    "salam",
    "buradayam",
    "haziram",
    "necesen",
    "netersen",
    "yaxsiyam",
    "istesen",
    "isteseniz",
    "hansi tapinti",
    "hansi riske",
    "komek etmeye",
    "davam edek",
    "tapintilar uzre",
    "riskleri uzre",
)

_AZ_ONLY_LETTERS_RE = re.compile(r"[əƏıışŞğĞ]")


def english_leakage_violations(text: str) -> list[str]:
    """High-precision Azerbaijani-leak detection for non-Azerbaijani answers."""
    value = text or ""
    if not value.strip():
        return []
    violations: list[str] = []
    folded = _strip_accents_and_az(value)
    for fragment in _AZ_CANNED_LEAKAGE:
        if fragment in folded:
            violations.append(f"az_canned:{fragment}")
    # Distinctly Azerbaijani letters in prose (outside protected tokens/paths).
    prose = _PROTECTED_RE.sub(" ", value)
    az_letter_words = {
        word.lower()
        for word in re.findall(r"[A-Za-zəƏıİöÖüÜçÇşŞğĞ]+", prose)
        if _AZ_ONLY_LETTERS_RE.search(word)
    }
    if len(az_letter_words) >= 2:
        violations.append("az_script")
    return violations


def enforce_language(text: str, target_language: str, context: dict | None = None) -> str:
    if not text:
        return text
    repaired = _repair_known_defects(text)
    if target_language != "az":
        if target_language in {"en", "ru"} and english_leakage_violations(repaired):
            return localized_fallback(target_language)
        return repaired
    polished = polish_azerbaijani(repaired)
    result = validate_mixed_language(polished, "az")
    if result.ok:
        return polished

    # Try one more deterministic pass after phrase-level repairs.
    repaired_again = polished
    for pattern, replacement in _PHRASE_FIXES:
        repaired_again = pattern.sub(replacement, repaired_again)
    repaired_again = polish_azerbaijani(repaired_again)
    second = validate_mixed_language(repaired_again, "az")
    if second.ok:
        return repaired_again

    if set(second.violations) <= {"english_sentence"} and _AZ_CHAR_RE.search(repaired_again):
        native_az_signals = (
            "tapıntı",
            "Skan:",
            "Metrik:",
            "İlk addım",
            "Addım-addım",
            "Seçilmiş",
            "Növbəti",
            "Niyə",
        )
        if any(signal in repaired_again for signal in native_az_signals):
            return repaired_again

    if any(v in second.violations for v in ("english_sentence", "english_marker")):
        return localized_fallback("az", ",".join(second.violations))
    return repaired_again


def final_language_audit(text: str, target_language: str, original: str) -> dict:
    result = validate_mixed_language(text, target_language)
    return {
        "language_validator_applied": True,
        "language_validator_passed": result.ok,
        "language_validator_repaired": text != original,
        "language_validator_violations": result.violations,
    }


def clean_language_boilerplate(text: str, target_language: str = "az") -> str:
    return enforce_language(text, target_language)
