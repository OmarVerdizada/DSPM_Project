from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass
from typing import Literal

from backend.copilot.language_detector import detect_language as detect_supported_language
from backend.copilot.language_detector import normalize_for_language_detection
from backend.copilot.language_understanding import understand_message


LanguageCode = Literal["en", "az", "ru", "unknown"]
IntentName = Literal["dspm_query", "small_talk", "capability_help", "complaint_or_misunderstanding", "follow_up", "report_export", "unclear"]


@dataclass(frozen=True)
class CopilotStyle:
    answer_language: LanguageCode
    tone: str = "professional_concise"
    max_lines_default: int = 7
    allow_markdown_headings: bool = False


@dataclass(frozen=True)
class LanguageIntent:
    language: LanguageCode
    language_confidence: float
    intent: IntentName
    intent_confidence: float
    should_use_dspm_tools: bool
    answer_language: LanguageCode
    style: CopilotStyle
    normalized_message: str
    query_hints: tuple[str, ...] = ()

    def model_dump(self) -> dict:
        return asdict(self)


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
        "ş": "s",
        "Ş": "s",
        "ğ": "g",
        "Ğ": "g",
        "ç": "c",
        "Ç": "c",
    }
)

_MOJIBAKE_REPLACEMENTS = (
    ("É™", "e"),
    ("Æ", "e"),
    ("Ä±", "i"),
    ("Ä°", "i"),
    ("Ã¶", "o"),
    ("Ã–", "o"),
    ("Ã¼", "u"),
    ("Ãœ", "u"),
    ("ÅŸ", "s"),
    ("Å", "s"),
    ("ÄŸ", "g"),
    ("Ä", "g"),
    ("Ã§", "c"),
    ("Ã‡", "c"),
)

_AZ_CHARS_RE = re.compile(r"[əƏıİöÖüÜşŞğĞçÇ]|É™|Æ|Ä±|Ä°|Ã¶|Ã–|Ã¼|Ãœ|ÅŸ|Å|ÄŸ|Ä|Ã§|Ã‡")

_AZ_TRANSLATION.update(
    str.maketrans(
        {
            "\u0259": "e",
            "\u018f": "e",
            "\u0131": "i",
            "\u0130": "i",
            "\u00f6": "o",
            "\u00d6": "o",
            "\u00fc": "u",
            "\u00dc": "u",
            "\u015f": "s",
            "\u015e": "s",
            "\u011f": "g",
            "\u011e": "g",
            "\u00e7": "c",
            "\u00c7": "c",
        }
    )
)

_EN_COMMAND_WORDS = {
    "give",
    "five",
    "show",
    "find",
    "summarize",
    "summary",
    "compare",
    "comparison",
    "explain",
    "list",
    "top",
    "latest",
    "help",
    "what",
    "where",
    "how",
}

_AZ_COMMAND_WORDS = {
    "goster",
    "cixart",
    "tap",
    "ver",
    "de",
    "xulase",
    "et",
    "izah",
    "sorus",
    "bilirsen",
    "gorebilirsen",
}

_EN_WORDS = {
    "give",
    "five",
    "me",
    "top",
    "files",
    "file",
    "high",
    "risk",
    "assets",
    "asset",
    "show",
    "alerts",
    "alert",
    "latest",
    "scan",
    "critical",
    "findings",
    "finding",
    "what",
    "can",
    "you",
    "u",
    "do",
    "help",
    "how",
    "are",
    "not",
    "understanding",
    "understand",
    "explain",
    "this",
    "remediation",
    "steps",
    "audit",
    "logs",
    "summary",
    "sensitive",
    "data",
    "private",
    "key",
    "secret",
    "permissions",
    "score",
    "english",
    "switch",
    "compare",
    "comparison",
    "history",
    "histories",
    "timestamp",
    "base",
    "based",
    # Common English social / greeting / meta / model-status tokens. These are
    # distinctly English and never appear in Azerbaijani prose, so they give the
    # detector a clear current-turn signal for short social inputs.
    "hello",
    "hi",
    "hey",
    "thanks",
    "thank",
    "please",
    "the",
    "is",
    "working",
    "running",
    "provider",
    "status",
    "model",
    "why",
    "mean",
    "your",
    "answer",
    "long",
    "short",
    "shorter",
    "longer",
    "repeat",
    "same",
    "should",
    "great",
    "good",
    "bad",
    "tell",
    "about",
    "step",
}

_AZ_WORDS = {
    "salam",
    "en",
    "yuksek",
    "riskli",
    "fayllari",
    "fayllar",
    "goster",
    "son",
    "alertleri",
    "alertlerin",
    "alertler",
    "cixart",
    "assetleri",
    "tap",
    "neticesini",
    "netice",
    "remediation",
    "addimlarini",
    "de",
    "ele",
    "sen",
    "ne",
    "ede",
    "bilirsen",
    "mene",
    "umumi",
    "isler",
    "gor",
    "gorebilirsen",
    "ozun",
    "necesen",
    "netersen",
    "neleredebilirsen",
    "neleredebilersen",
    "neler",
    "yox",
    "var",
    "gedir",
    "gorum",
    "meni",
    "basa",
    "dusmursen",
    "mence",
    "dediklerimi",
    "yaxsi",
    "anlayabilmirsen",
    "anlamirsan",
    "icazeler",
    "loglar",
    "sag",
    "ol",
    "tesekkur",
    "indi",
    "etmeliyem",
    "edim",
    "etmeliyik",
    "sonra",
    "bunu",
    "report",
    "hazirla",
    "pdf",
    "evvelki",
    "muqayise",
    "cixart",
    "dene",
    "eded",
    "say",
    "dedim",
    "ingilis",
    "dilinde",
    "danisaq",
    "zorsan",
    "salamlar",
    "sagol",
    "hardasan",
}

_TECHNICAL_TERMS = {
    "dspm",
    "scan",
    "finding",
    "findings",
    "high-risk",
    "high",
    "medium",
    "low",
    "risk",
    "asset",
    "assets",
    "alert",
    "alerts",
    "audit",
    "log",
    "logs",
    "remediation",
    "acl",
    "pii",
    "private",
    "key",
    "secret",
    "sensitive",
    "data",
    "aleti",
    "alerti",
    "alertin",
    "alerler",
    "alerleri",
    "tapinti",
    "tapintilari",
    "tapintini",
    "tapintilar",
    "tapıntı",
    "tapıntını",
    "tapıntıları",
    "tapıntılar",
}

_DSPM_PATTERNS = (
    "high risk",
    "high-risk",
    "top file",
    "top files",
    "critical finding",
    "critical findings",
    "critical alert",
    "critical alerts",
    "kritik tapinti",
    "kritik tapintilar",
    "tapinti",
    "tapintilar",
    "medium",
    "latest alert",
    "latest alerts",
    "latest scan",
    "scan summary",
    "audit log",
    "audit logs",
    "remediation",
    "sensitive data",
    "private key",
    "risk score",
    "permission",
    "permissions",
    "riskli fayl",
    "riskli fayllar",
    "en yuksek riskli",
    "alertleri goster",
    "alertleri cixart",
    "alertlerin sayin",
    "son alert",
    "son alertler",
    "son scan",
    "scan netice",
    "scan neticesi",
    "findingler",
    "findingleri",
    "assetleri",
    "fayllari",
    "icazeler",
    "audit loglar",
)

_SMALL_TALK_PATTERNS = (
    "salam",
    "hi",
    "hello",
    "hey",
    "necesen",
    "netersen",
    "sen necesen",
    "sen netersen",
    "ozun necesen",
    "ozun netersen",
    "ne var ne yox",
    "nece gedir",
    "sen de gorum netersen",
    "yox e sen de gorum netersen",
    "how are you",
    "how are u",
    "thanks",
    "thank you",
    "sag ol",
    "sagol",
    "tesekkur",
)

_CAPABILITY_PATTERNS = (
    "what can you do",
    "what can u do",
    "what do you do",
    "can you speak azerbaijani",
    "azerbaycan dilinde danisa bilirsen",
    "azerbaycan dilinde danisirsan",
    "azerbaycanca bilirsen",
    "help",
    "show commands",
    "how can you help",
    "neler ede bilirsen",
    "neler edebilersen",
    "neler edebilirsen",
    "neleredebilirsen",
    "neleredebilersen",
    "ne ede bilirsen",
    "ne edebilersen",
    "ne edebilirsen",
    "sen ne ede bilirsen",
    "sen ne ede bilersen",
    "ne isler gore bilirsen",
    "ne isler gorebilirsen",
    "mene umumi de sen ne ede bilirsen",
    "umumi deye bilersen mene sen ne isler gorebilirsen",
    "umumi deyebilersen mene sen ne isler gorebilirsen",
    "umumi deyebilersen mene sen ne isler gorebilersen",
    "umumi deyebilersen mene sen ne isler gore bilersen",
)

_COMPLAINT_PATTERNS = (
    "you are not understanding me",
    "you do not understand me",
    "you don't understand me",
    "are u dumb",
    "are you dumb",
    "what are you doing",
    "why give information",
    "why did you give",
    "i did not ask",
    "i didnt want",
    "that is unrelated",
    "are u okay",
    "are you okay",
    "you are not okay",
    "this makes no sense",
    "thats not what i meant",
    "that is not what i meant",
    "wrong answer",
    "meni basa dusmursen",
    "sen dediklerimi yaxsi anlayabilmirsen",
    "mence sen dediklerimi yaxsi anlayabilmirsen",
    "dediklerimi yaxsi anlamirsan",
    "bu nedir",
    "bu nedi",
    "bu nedi cixartdin",
    "ne elaqe",
    "niye bunu verdin",
    "men bunu istemedim",
    "bele bir sey istemedim",
    "ne danisirsan",
    "basa dusmursen",
    "anlamiram ne deyirsen",
    "bu cavab duzgun deyil",
    "bu ne demekdi",
    "bu ne toyreyir",
    "ne yazmisan onu anlamadim",
    "neyi yazmisan",
    "anlamirsan",
    "anlayabilmirsen",
    "dediklerimi anlamirsan",
    "eyni anda is",
    "birden artiq is",
    "birdesin artiq",
    "beraber isleye bilmirsen",
    "birlikde ede bilmirsen",
)

_FOLLOW_UP_PATTERNS = (
    "what should i do now",
    "what next",
    "what should we do",
    "give remediation",
    "remediation ver",
    "explain this",
    "bunu izah et",
    "niye risklidir",
    "why is this risky",
    "compare with previous scan",
    "evvelki scan ile muqayise et",
    "indi ne etmeliyem",
    "sonra ne edim",
    "ne etmeliyik",
)

_REPORT_EXPORT_PATTERNS = (
    "export this",
    "export this as pdf",
    "turn this into pdf",
    "make this a report",
    "bunu pdf et",
    "pdf cixart",
    "bunu report et",
    "report hazirla",
)

_UNCLEAR_PATTERNS = (
    "buna bax",
    "bunu de",
    "davam",
    "ok",
    "he",
    "yox",
    "hmm",
)

_AZ_LIST_REMEDIATION_PATTERNS = (
    "son 3 aleti",
    "son 3 alert",
    "son 5 aleti",
    "son 5 alert",
    "son 5 tapinti",
    "son 3 tapinti",
    "son 5 kritik tapinti",
    "son 3 kritik tapinti",
    "son 3 kritik aleti",
    "son 3 kritik alert",
    "kritik aleti tapib",
    "kritik alert tapib",
    "kritik tapinti tapib",
    "kritik tapintini tapib",
    "kritik tapintilari tapib",
    "3 kritik tapinti",
    "3 kritik alert",
    "3 alert ve",
    "3 alert və",
    "5 kritik tapinti",
    "son 5 high finding",
    "high finding ve neler",
    "high finding və nələr",
    "high finding goster ve",
    "high finding göstər və",
)

_AZ_REMEDIATION_SIGNALS = (
    "neler etmeliyem",
    "nələr etməliyəm",
    "ne etmeliyem",
    "nə etməliyəm",
    "tövsiyə",
    "tövsiyem",
    "tövsiyə ver",
    "tövsiyə edin",
    "düzəliş",
    "remediation",
)

_AZ_LIST_REMEDIATION_REGEXES = (
    re.compile(r"son\s+\d+\s+(?:kritik\s+)?alerti?", re.IGNORECASE),
    re.compile(r"son\s+\d+\s+(?:kritik\s+)?tap[iı]nt[iı]n?[ı]?"),
    re.compile(r"son\s+\d+\s+high\s+finding", re.IGNORECASE),
    re.compile(r"\b\d+\s+kritik\s+(?:tap[iı]nt[iı]|alert)s?\b"),
    re.compile(r"kritik\s+(?:tap[iı]nt[iı]|alert)s?\s+(?:tap[iı]b|göstər|goster)\b"),
    re.compile(r"high\s+finding"),
    re.compile(r"\b\d+\s+(?:kritik\s+)?tap[iı]nt[iı]"),
    re.compile(r"son\s+\d+\s+alert\b"),
    re.compile(r"\balert[iı]?\b"),
    re.compile(r"\btap[iı]nt[iı]\b"),
)

_AZ_REMEDIATION_REGEXES = (
    re.compile(r"nel(?:ə|e)a?r?\s+etm(?:ə|e)liy(?:ə|e)m?", re.IGNORECASE),
    re.compile(r"ne\s+etm(?:ə|e)liy(?:ə|e)m?", re.IGNORECASE),
    re.compile(r"tövsiyə", re.IGNORECASE),
    re.compile(r"düzəliş", re.IGNORECASE),
    re.compile(r"remediation", re.IGNORECASE),
    re.compile(r"fix\b", re.IGNORECASE),
)


def _is_az_compound_list_remediation(normalized: str) -> bool:
    if not any(char in normalized for char in ("ə", "e", "i", "ı", "ü", "o", "a", "ş", "ç", "ğ", "ö", "Ə", "İ", "Ü", "O", "A", "Ş", "Ç", "Ğ", "Ö")):
        return False
    has_list_signal = any(r.search(normalized) for r in _AZ_LIST_REMEDIATION_REGEXES)
    has_remediation = any(r.search(normalized) for r in _AZ_REMEDIATION_REGEXES)
    return has_list_signal and has_remediation


def normalize_message(message: str) -> str:
    # Repair mojibake before generic Unicode normalization. NFKC expands the
    # trademark sign in common broken Azerbaijani text (É™) to "TM", which
    # prevents the cp1252->utf-8 repair path from recovering ə.
    text = normalize_for_language_detection((message or "").strip())
    for source, replacement in _MOJIBAKE_REPLACEMENTS:
        text = text.replace(source.lower(), replacement)
    text = text.translate(_AZ_TRANSLATION)
    text = re.sub(r"[^\w\s?-]", " ", text, flags=re.UNICODE)
    return re.sub(r"\s+", " ", text).strip()


def _tokens(message: str) -> list[str]:
    return normalize_message(message).replace("-", " ").split()


def _contains_phrase(normalized: str, phrase: str) -> bool:
    phrase = phrase.strip()
    if not phrase:
        return False
    if " " not in phrase and "-" not in phrase:
        return phrase in set(normalized.replace("-", " ").split())
    return phrase in normalized


def _contains_any(normalized: str, patterns: tuple[str, ...]) -> bool:
    return any(_contains_phrase(normalized, pattern) for pattern in patterns)


def _command_language(normalized: str) -> LanguageCode | None:
    words = normalized.replace("-", " ").split()
    first_words = set(words[:4])
    if first_words & _EN_COMMAND_WORDS:
        if any(word.endswith(("leri", "lari")) for word in words[:2]) and any(word in {"ele", "goster", "cixart", "ver"} for word in words):
            return "az"
        if any(word.startswith("fayl") for word in words) and any(word in {"ver", "goster", "cixart", "tap"} for word in words):
            return "az"
        if "ver" in words and not {"give", "show", "find"} & set(words[:2]):
            return "az"
        return "en"
    if first_words & _AZ_COMMAND_WORDS:
        return "az"
    if any(pattern in normalized for pattern in ("goster", "cixart", "tap", " neticesini", " ver")):
        return "az"
    if any(pattern in normalized for pattern in (" ele", " eley")):
        return "az"
    if any(pattern in normalized for pattern in ("give me", "five me", "show ", "latest ", "top ")):
        return "en"
    return None


# Universal format/technical tokens carry no language signal. A message made up
# only of these (e.g. bare "pdf", "csv", "json") must not be detected as a
# specific language with high confidence, or it would override the established
# conversation language — the source of the "pdf" -> Azerbaijani report leak.
_LANGUAGE_NEUTRAL_TOKENS = {
    "pdf", "csv", "json", "xml", "yaml", "yml", "html", "htm", "url", "uri",
    "ok", "okay", "http", "https", "api", "id", "txt", "doc", "docx", "xls",
    "xlsx", "ppt", "pptx", "sql", "zip", "png", "jpg", "jpeg", "gif", "svg",
    "md", "log", "ini", "env", "csv", "tsv", "pem", "kdbx",
}


def detect_language_metadata(message: str) -> tuple[LanguageCode, float]:
    neutral_tokens = re.findall(r"[a-z0-9]+", normalize_message(message))
    if neutral_tokens and all(tok in _LANGUAGE_NEUTRAL_TOKENS for tok in neutral_tokens):
        return "unknown", 0.2
    understanding = understand_message(message)
    if understanding.detected_language in {"az", "en"} and understanding.confidence >= 0.65:
        candidate = next(
            (item for item in understanding.language_candidates if item.get("language") == understanding.detected_language),
            None,
        )
        confidence = float(candidate.get("confidence", understanding.confidence)) if candidate else understanding.confidence
        return understanding.detected_language, round(min(max(confidence, 0.62), 0.99), 2)
    normalized = normalize_message(message)
    if normalized in {"niye", "niye?", "niyə", "niyə?", "bes indi nece", "bes indi nece?", "bəs indi necə", "bəs indi necə?"} or re.fullmatch(r"niy\W{1,3}", normalized) or re.fullmatch(r"b.s indi nec\W{1,3}", normalized):
        return "az", 0.86
    words = _tokens(message)
    if not words:
        return "unknown", 0.0
    detector_language, detector_confidence = detect_supported_language(message)

    az_score = sum(1.0 for word in words if word in _AZ_WORDS)
    en_score = sum(1.0 for word in words if word in _EN_WORDS)
    az_score += 2.0 if _AZ_CHARS_RE.search(message or "") else 0.0
    if detector_language == "az":
        az_score += 3.0 * detector_confidence
    elif detector_language == "en":
        en_score += 2.5 * detector_confidence

    # Technical terms are allowed in Azerbaijani sentences and should not
    # overwhelm the command language.
    tech_count = sum(1 for word in words if word in _TECHNICAL_TERMS)
    en_score -= min(tech_count * 0.35, 2.0)

    command_language = _command_language(normalized)
    if command_language == "en":
        en_score += 3.0
    elif command_language == "az":
        az_score += 3.0

    if az_score <= 0 and en_score <= 0:
        if detector_language in {"ru", "tr"}:
            return "unknown", detector_confidence
        return "unknown", 0.25

    total = max(az_score + en_score, 1.0)
    if az_score > en_score:
        return "az", round(min(0.99, 0.55 + (az_score - en_score) / total), 2)
    if en_score > az_score:
        return "en", round(min(0.99, 0.55 + (en_score - az_score) / total), 2)
    if command_language:
        return command_language, 0.62
    return "unknown", 0.4


def detect_language(message: str) -> LanguageCode:
    language, _confidence = detect_language_metadata(message)
    return "en" if language == "unknown" else language


def user_prefers_azerbaijani(message: str) -> bool:
    return detect_language(message) == "az"


def detect_intent(message: str) -> tuple[IntentName, float, tuple[str, ...]]:
    understanding = understand_message(message)
    if understanding.confidence >= 0.65:
        intent_map: dict[str, IntentName] = {
            "capability": "capability_help",
            "small_talk": "small_talk",
            "language_preference": "complaint_or_misunderstanding",
            "language_complaint": "complaint_or_misunderstanding",
            "previous_answer_clarification": "complaint_or_misunderstanding",
            "findings_list": "dspm_query",
            "list_plus_remediation": "dspm_query",
            "risk_explanation": "dspm_query",
            "remediation": "follow_up",
            "scan_comparison": "follow_up",
            "compliance_mapping": "dspm_query",
            "general_dspm_question": "dspm_query",
            "report_generation": "report_export",
        }
        mapped = intent_map.get(understanding.best_intent or "")
        if mapped:
            hints = tuple(item for item in understanding.canonical_text_candidates[:4] if item)
            return mapped, understanding.confidence, hints
    normalized = normalize_message(message)
    words = set(normalized.replace("-", " ").split())
    hints: list[str] = []

    if normalized in {"now", "now?", "niye", "niye?", "niyə", "niyə?", "bes indi nece", "bes indi nece?", "bəs indi necə", "bəs indi necə?"} or re.fullmatch(r"niy\W{1,3}", normalized) or re.fullmatch(r"b.s indi nec\W{1,3}", normalized):
        return "complaint_or_misunderstanding", 0.9, tuple(hints)
    if _contains_any(normalized, _COMPLAINT_PATTERNS):
        return "complaint_or_misunderstanding", 0.95, tuple(hints)
    if _contains_any(normalized, _REPORT_EXPORT_PATTERNS):
        return "report_export", 0.94, tuple(hints)
    if _contains_any(normalized, _FOLLOW_UP_PATTERNS):
        return "follow_up", 0.93, tuple(hints)
    if _contains_any(normalized, _CAPABILITY_PATTERNS):
        return "capability_help", 0.94, tuple(hints)
    if _contains_any(normalized, _SMALL_TALK_PATTERNS):
        return "small_talk", 0.9, tuple(hints)
    if _contains_any(normalized, _DSPM_PATTERNS):
        hints.extend(pattern for pattern in _DSPM_PATTERNS if _contains_phrase(normalized, pattern))
        return "dspm_query", 0.9, tuple(hints[:6])

    dspm_terms = words & _TECHNICAL_TERMS
    if {"top", "files"} <= words or {"top", "file"} <= words:
        return "dspm_query", 0.86, ("top files",)
    number_words = {str(item) for item in range(1, 26)}
    if dspm_terms and (words & (_EN_COMMAND_WORDS | _AZ_COMMAND_WORDS | {"top", "latest", "son", "en"}) or words & number_words):
        return "dspm_query", 0.74, tuple(sorted(dspm_terms))
    if _is_az_compound_list_remediation(normalized):
        return "dspm_query", 0.96, ("az_compound_list_remediation",)
    if normalized in _UNCLEAR_PATTERNS or len(words) <= 2:
        return "unclear", 0.72, tuple(hints)
    return "unclear", 0.45, tuple(hints)


def analyze_message(message: str) -> LanguageIntent:
    language, language_confidence = detect_language_metadata(message)
    if language == "unknown":
        language = "en"
    intent, intent_confidence, query_hints = detect_intent(message)
    return LanguageIntent(
        language=language,
        language_confidence=language_confidence,
        intent=intent,
        intent_confidence=intent_confidence,
        should_use_dspm_tools=intent == "dspm_query",
        answer_language=language,
        style=CopilotStyle(answer_language=language),
        normalized_message=normalize_message(message),
        query_hints=query_hints,
    )


def is_dspm_question(message: str) -> bool:
    return analyze_message(message).intent == "dspm_query"


def pre_route_message(message: str, has_history: bool = False) -> LanguageIntent | None:
    del has_history
    metadata = analyze_message(message)
    return None if metadata.should_use_dspm_tools else metadata


# Backward-compatible helpers for older imports. The service no longer uses
# these as answer generators; natural replies are produced by Ollama prompts.
def small_talk_response(message: str) -> str | None:
    return "" if analyze_message(message).intent == "small_talk" else None


def capability_help_response(message: str) -> str | None:
    return "" if analyze_message(message).intent == "capability_help" else None


def complaint_response(message: str) -> str | None:
    return "" if analyze_message(message).intent == "complaint_or_misunderstanding" else None


def clarification_response(message: str, has_history: bool) -> str | None:
    del has_history
    return "" if analyze_message(message).intent == "unclear" else None
