from __future__ import annotations

import re
import unicodedata
from typing import Literal


DetectedLanguage = Literal["az", "en", "ru", "tr", "unknown"]

AZ_CHARS_RE = re.compile(r"[əƏıİöÖüÜçÇşŞğĞ]")
CYRILLIC_RE = re.compile(r"[\u0400-\u04ff]")
TURKISH_ONLY_HINTS = {
    "cevap",
    "cevapla",
    "nasıl",
    "değil",
    "lütfen",
    "yapabilir",
    "bulgu",
    "öneri",
}
ENGLISH_HINTS = {
    "give",
    "show",
    "what",
    "why",
    "how",
    "can",
    "you",
    "speak",
    "english",
    "azerbaijani",
    "critical",
    "alert",
    "alerts",
    "finding",
    "findings",
    "risk",
    "details",
    "recommend",
    "compare",
    "comparison",
    "history",
    "histories",
    "timestamp",
    "base",
    "based",
}
AZ_HINTS = {
    "azərbaycan",
    "azerbaycan",
    "azərbaycanca",
    "azerbaycanca",
    "dilində",
    "dilinde",
    "danış",
    "danis",
    "danışa",
    "danisa",
    "bilirsən",
    "bilirsen",
    "mənə",
    "mene",
    "göstər",
    "goster",
    "nə",
    "ne",
    "niyə",
    "niye",
    "necəsən",
    "necesen",
    "nətərsən",
    "netersen",
    "son",
    "saalam",
    "cox",
    "chox",
    "uzun",
    "yazirsan",
    "yazdin",
    "verdin",
    "sozu",
    "soz",
    "yoxdur",
    "hem",
    "veziyyeti",
    "veziyyet",
    "qeribe",
    "qerib",
    "formada",
    "analiz",
    "ederdin",
    "isleyir",
    "hazirda",
    "skan",
    "scan",
    "tapıntı",
    "tapinti",
    "tapıntılar",
    "tapintilar",
    "xəbərdarlıq",
    "xeberdarliq",
    "kritik",
    "məlumat",
    "melumat",
    "haqqında",
    "haqqinda",
    "geniş",
    "genis",
    "tövsiyə",
    "tovsiye",
    "etməliyəm",
    "etmeliyem",
    "cavab",
    "ver",
    "ingilis",
}


def repair_mojibake(text: str) -> str:
    value = text or ""
    if not any(marker in value for marker in ("Ã", "Ä", "Å", "É", "Æ")):
        return unicodedata.normalize("NFKC", value)
    try:
        repaired = value.encode("cp1252").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return unicodedata.normalize("NFKC", value)
    return unicodedata.normalize("NFKC", repaired)


_AZ_TRANSLATION = str.maketrans(
    {
        "ə": "e",
        "Ə": "e",
        "ı": "i",
        "İ": "i",
        "ö": "o",
        "Ö": "o",
        "ü": "u",
        "Ü": "u",
        "ç": "c",
        "Ç": "c",
        "ş": "s",
        "Ş": "s",
        "ğ": "g",
        "Ğ": "g",
    }
)


def normalize_for_language_detection(text: str) -> str:
    repaired = repair_mojibake(text)
    lowered = unicodedata.normalize("NFKC", repaired).strip().lower()
    lowered = lowered.translate(_AZ_TRANSLATION)
    lowered = re.sub(r"[^\w\s?.-]", " ", lowered, flags=re.UNICODE)
    return re.sub(r"\s+", " ", lowered).strip()


def _tokens(text: str) -> list[str]:
    return normalize_for_language_detection(text).replace("-", " ").split()


def _filename_only(tokens: list[str]) -> bool:
    useful = [token for token in tokens if token not in {"the", "a", "an"}]
    return bool(useful) and all(re.search(r"\.(ya?ml|json|env|txt|csv|xml|pem|key|py|js|ts|md)$", token) for token in useful)


def detect_language(text: str) -> tuple[DetectedLanguage, float]:
    repaired = repair_mojibake(text)
    normalized = normalize_for_language_detection(repaired)
    tokens = _tokens(repaired)
    if not tokens:
        return "unknown", 0.0
    if _filename_only(tokens):
        return "unknown", 0.25

    if CYRILLIC_RE.search(repaired):
        return "ru", 0.75

    token_set = set(tokens)
    az_score = sum(1.0 for token in token_set if token in AZ_HINTS)
    en_score = sum(1.0 for token in token_set if token in ENGLISH_HINTS)
    tr_score = sum(1.0 for token in token_set if token in TURKISH_ONLY_HINTS)

    if AZ_CHARS_RE.search(repaired):
        az_score += 2.5
    if "azerbaijani" in token_set and {"speak", "can", "you"} & token_set:
        en_score += 2.0
    if "azərbaycan" in repaired.lower() or "azerbaycan" in normalized:
        az_score += 2.0
    if any(
        phrase in normalized
        for phrase in (
            "genis melumat",
            "son kritik tapinti",
            "ne etmeliyem",
            "mene son",
            "cox uzun",
            "chox uzun",
            "hem azerbaycan hem ingilis",
            "bu veziyyeti qeribe",
            "veziyyeti qeribe formada",
            "model isleyir",
            "hazirda islemir",
        )
    ):
        az_score += 2.0
    if normalized.startswith(("give ", "show ", "what ", "why ", "how ", "can ")):
        en_score += 2.0

    if tr_score > az_score and tr_score >= en_score + 1:
        return "tr", 0.65
    if az_score == 0 and en_score == 0:
        return "unknown", 0.25
    total = max(az_score + en_score, 1.0)
    if az_score > en_score:
        return "az", round(min(0.99, 0.58 + (az_score - en_score) / total), 2)
    if en_score > az_score:
        return "en", round(min(0.99, 0.58 + (en_score - az_score) / total), 2)
    return "unknown", 0.4


def is_explicit_english_switch(text: str) -> bool:
    normalized = normalize_for_language_detection(text)
    if (
        any(term in normalized for term in ("niye", "why", "neden"))
        and "ingilis" in normalized
        and any(term in normalized for term in ("danisirsan", "cavab verdin", "yazdin"))
    ):
        return False
    if normalized in {"english", "english please", "ingilis", "ingilisce"}:
        return True
    if any(
        phrase in normalized
        for phrase in (
            "ingilis dilinde cavab vermeliydin",
            "ingilis dilinde cavab vermeli idin",
            "ingilisce cavab vermeliydin",
        )
    ):
        return True
    if "azerbaycan" in normalized and any(
        phrase in normalized
        for phrase in (
            "do not speak",
            "dont speak",
            "don't speak",
            "not speak",
            "yox azerbaycan",
            "azerbaycan dilinde danisma",
            "azerbaycanca danisma",
        )
    ):
        return True
    return any(
        phrase in normalized
        for phrase in (
            "lets speak english",
            "let us speak english",
            "speak english",
            "switch to english",
            "respond in english",
            "answer in english",
            "reply in english",
            "use english",
            "in english please",
            "ingilis dilinde danisaq",
            "ingilis dilinde danis",
            "ingilis dilinde cavab ver",
            "ingiliscə cavab ver",
            "gel ingilis dilinde danisaq",
        )
    )


def is_explicit_azerbaijani_switch(text: str) -> bool:
    normalized = normalize_for_language_detection(text)
    return any(
        phrase in normalized
        for phrase in (
            "azerbaycan dilinde danis",
            "azerbaycanca cavab ver",
            "speak azerbaijani",
            "respond in azerbaijani",
            "use azerbaijani",
            "answer in azerbaijani",
            "azerbaijani cavab ver",
        )
    )


def is_azerbaijani_capability_question(text: str) -> bool:
    normalized = normalize_for_language_detection(text)
    return (
        ("azerbaycan" in normalized or "azerbaijani" in normalized or "azerbaycanca" in normalized)
        and any(term in normalized for term in ("danisa bilirsen", "danisirsan", "speak", "bilirsen", "cavab ver"))
    )


# Mojibake shapes produced when UTF-8 Russian text is decoded through a
# Turkish/Latin code page. Kept next to detection so both the language runtime
# and the canned-response layer share one definition (no drift).
_MOJIBAKE_RUSSIAN_MARKERS = ("ğ¿ñ", "ñ‡ñ", "ğ¾ñ", "ñ€ñ", "ñƒğ", "ğ²ğµñ")


def is_cyrillic_or_mojibake_russian(message: str) -> bool:
    """True for Russian/Cyrillic input, including the common double-encoded
    mojibake form. Such input is unsupported and, per the English-first
    contract, must never be treated as a clear Azerbaijani signal."""
    text = (message or "").strip().lower()
    if any("Ѐ" <= ch <= "ӿ" for ch in text):
        return True
    return any(marker in text for marker in _MOJIBAKE_RUSSIAN_MARKERS)
