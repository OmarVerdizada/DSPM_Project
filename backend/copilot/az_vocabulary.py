from __future__ import annotations

import re

from backend.copilot.language_detector import repair_mojibake


AZ_SECURITY_TERMS = {
    "finding": "tapıntı",
    "findings": "tapıntılar",
    "alert": "xəbərdarlıq",
    "alerts": "xəbərdarlıqlar",
    "scan": "skan",
    "report": "hesabat",
    "severity": "ciddilik dərəcəsi",
    "risk": "risk",
    "remediation": "düzəliş",
    "recommendation": "tövsiyə",
    "sensitive data": "həssas məlumat",
    "exposure": "məruz qalma",
    "access": "giriş",
    "permission": "icazə",
    "attack": "hücum",
    "attacker": "təcavüzkar",
    "latest scan": "son skan",
    "critical": "kritik",
    "high": "yüksək",
    "medium": "orta",
    "low": "aşağı",
}

DO_NOT_TRANSLATE = {
    "private_key",
    "jwt",
    "api_key",
    "password",
    "secret_key",
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "yaml",
    "json",
    "env",
    "xml",
    "sh",
    "SHA",
    "RSA",
    "AES",
    "TLS",
    "SSL",
    "DSPM",
}

AZ_CORRECTIONS = [
    (r"\bneqliyetim\b", ""),
    (r"\bmövqeydən təsdiqlənmək\b", "yoxlamaq"),
    (r"\btəsdiqlənmək üçün\b", "yoxlamaq üçün"),
    (r"\büçün vermək üçün\b", "üçün"),
    (r"\bvuru(?:ş|lar|ları)\b", "tapıntı"),
    (r"\bqızıq(?:lıq|lıqlar|lıqları)?\b", "kritik"),
    (r"\bqiziq(?:liq|liqlar|liqlari)?\b", "kritik"),
    (r"\byenilənilmiş\b", "güncəllənmiş"),
    (r"\byenilikli\b", "yeni"),
    (r"\bnümunə təqdim\b", "son skan"),
    (r"\bqadim təqdim\b", "əvvəlki skan"),
    (r"\böyrünç\b", "məlumat"),
    (r"\bogrunc\b", "məlumat"),
    (r"\bidarəetkinlik\b", "idarəetmə"),
    (r"\bçözmüş\b", "həll etmiş"),
    (r"\bsalsan[ıi]z\b", "göndərsəniz"),
    (r"\btapacağam\b", "tapa bilərəm"),
    (r"\bişleyi[yj]os\b", "istifadə edir"),
    (r"\bediyosunuz\b", "edirsiniz"),
    (r"\btilindəki\b", "dilindəki"),
    (r"\btilindən\b", "dilindən"),
    (r"\btilind[əe]\b", "dilində"),
    (r"\bxox\b", "çox"),
    (r"\bprevious\b", "əvvəlki"),
    (r"\breport(?:lar)?\b", "hesabat"),
    (r"\balert(?:lər)?\b", "xəbərdarlıq"),
]

BROKEN_AZ_FRAGMENTS = {
    "tilində",
    "xox",
    "röportlarda",
    "previous",
    "bilmək xox",
    "danışıbsəm",
    "bilmiyom",
    "tapanamayacaq",
    "sənabledar",
    "məcbürüstdür",
    "cevaplayırak",
    "cevaplayarak",
    "qəbul olunur məlumatlarla",
    "xalqarılardan",
    "təzələm",
    "yediniyyatlar",
    "neqliyetim",
    "mövqeydən təsdiqlənmək",
    "öyrünç",
    "idarəetkinlik",
    "previous report",
    "qızıqlıq",
    "qiziqliq",
    "vuruları",
    "vurular",
    "lütfen",
    "lutfen",
    "buraxılıram",
    "buraxiliram",
    "başa təsir etdim",
    "basa tesir etdim",
    "tələb etdiyiniz üç qeyd",
    "teleb etdiyiniz uc qeyd",
    "yardım etmək üçün buraxılıram",
    "yardim etmek ucun buraxiliram",
    "nə deməkdən danışın",
    "ne demekden danisin",
    "yardımcı olurum",
    "yardimci olurum",
}

BROKEN_AZ_FRAGMENTS.update({repair_mojibake(item) for item in list(BROKEN_AZ_FRAGMENTS)})
BROKEN_AZ_FRAGMENTS.update(
    {
        "rÃ¶port",
        "mÉ™cburÃ¼stÃ¼r",
        "Ä±smariqlÉ™nmiÅŸdur",
        "tilindÉ™",
        "xox",
        "danÄ±ÅŸÄ±bsÉ™m",
        "bilmiyom",
        "tapanamayacaq",
        "sÉ™nabledar",
        "cevaplayÄ±rak",
    }
)
BROKEN_AZ_FRAGMENTS.update({repair_mojibake(item) for item in list(BROKEN_AZ_FRAGMENTS)})

AZ_CHAR_RE = re.compile(r"[əƏıİöÖüÜçÇşŞğĞ]")
CYRILLIC_RE = re.compile(r"[\u0400-\u04ff]")
CJK_RE = re.compile(r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff]")
AZ_LETTERS = "ƏəıİöÖüÜçÇşŞğĞ"
ASCII_WORD_RE = re.compile(rf"(?<![A-Za-z{AZ_LETTERS}])[A-Za-z][A-Za-z'-]*(?![A-Za-z{AZ_LETTERS}])")
FILENAME_RE = re.compile(r"\b[\w.-]+\.(?:ya?ml|json|env|txt|csv|xml|pem|key|py|js|ts|md)\b", re.IGNORECASE)

ALLOWED_ENGLISH_TERMS = {item.lower() for item in DO_NOT_TRANSLATE}
ALLOWED_ENGLISH_TERMS.update(
    {
        "dspm",
        "scan",
        "id",
        "ids",
        "private",
        "key",
        "jwt",
        "api",
        "yaml",
        "json",
        "critical",
        "high",
        "medium",
        "low",
        "skan",
        "fayl",
        "fayllar",
        "kritik",
        "tapinti",
        "tapintilar",
        "ciddilik",
        "risk",
        "skoru",
        "tip",
        "olunan",
        "rotate",
        "et",
        "sonra",
        "token-",
        "umumi",
        "gosterilen",
        "cryptographic",
        "material",
        "connection",
        "string",
        "email",
        "phone",
        "number",
        "azerbaijan",
        "fin",
        "confidential",
        "keyword",
        "credential",
        "credentials",
        "token",
        "secret",
    }
)

NORMAL_ENGLISH_WORDS = {
    "previous",
    "based",
    "provided",
    "current",
    "data",
    "stores",
    "separate",
    "objects",
    "showing",
    "total",
    "checked",
    "recommended",
    "next",
    "step",
    "found",
    "contains",
    "because",
    "review",
    "restrict",
    "rotate",
    "remove",
    "public",
    "sharing",
    "answer",
    "report",
    "finding",
    "findings",
    "alert",
    "alerts",
}

TURKISH_RUSSIAN_HYBRID_RE = re.compile(
    r"(cevap|zorunda|gerekir|raporlar|bulunuyor|tespit|privet|spasibo|dannyi|narushen)",
    re.IGNORECASE,
)


def apply_az_security_vocabulary(text: str) -> str:
    value = repair_mojibake(text)
    for pattern, replacement in AZ_CORRECTIONS:
        value = re.sub(pattern, replacement, value, flags=re.IGNORECASE)
    for source, replacement in sorted(AZ_SECURITY_TERMS.items(), key=lambda item: len(item[0]), reverse=True):
        pattern = re.compile(rf"(?<![A-Za-z0-9_.-]){re.escape(source)}(?![A-Za-z0-9_.-])", re.IGNORECASE)

        def replace(match: re.Match[str]) -> str:
            original = match.group(0)
            if original in DO_NOT_TRANSLATE:
                return original
            return replacement

        value = pattern.sub(replace, value)
    value = re.sub(r" {2,}", " ", value)
    value = re.sub(r"\n +\n", "\n\n", value)
    return value.strip()


def apply_az_corrections(text: str) -> str:
    return apply_az_security_vocabulary(text)


def _without_filenames(text: str) -> str:
    return FILENAME_RE.sub("", text)


def az_quality_failed(text: str, original_english: str | None = None) -> tuple[bool, str]:
    value = repair_mojibake(text).strip()
    if not value:
        return True, "empty"
    lowered = value.lower()
    for fragment in BROKEN_AZ_FRAGMENTS:
        if fragment.lower() in lowered:
            return True, f"broken_fragment:{fragment}"
    if CJK_RE.search(value):
        return True, "unexpected_cjk"
    if CYRILLIC_RE.search(value):
        return True, "unexpected_cyrillic"
    if value.strip().lower() == (original_english or "").strip().lower():
        return True, "identical_to_english"

    if len(value) > 30 and not AZ_CHAR_RE.search(value):
        return True, "no_azerbaijani_specific_chars"

    non_filename_text = _without_filenames(value)
    ascii_words = [word.lower() for word in ASCII_WORD_RE.findall(non_filename_text)]
    normal_english = [
        word
        for word in ascii_words
        if word not in ALLOWED_ENGLISH_TERMS and word in NORMAL_ENGLISH_WORDS
    ]
    if len(normal_english) >= 2:
        return True, "too_many_english_words"
    if len(ascii_words) >= 10:
        suspicious = [word for word in ascii_words if word not in ALLOWED_ENGLISH_TERMS]
        if len(suspicious) / max(len(ascii_words), 1) > 0.45:
            return True, "english_word_ratio"

    if TURKISH_RUSSIAN_HYBRID_RE.search(value):
        return True, "turkish_russian_hybrid"

    for term in DO_NOT_TRANSLATE:
        pattern = re.compile(rf"(?<![A-Za-z0-9_.-]){re.escape(term)}(?![A-Za-z0-9_.-])")
        if pattern.search(original_english or "") and term not in value:
            return True, f"technical_term_corrupted:{term}"
    return False, "ok"


def az_translation_quality_failed(text: str, original_english: str) -> bool:
    failed, _ = az_quality_failed(text, original_english)
    return failed
