from __future__ import annotations

import base64
import binascii
import functools
import ipaddress
import re
import threading
from datetime import date

from classification import masking


EMAIL_RE = re.compile(r"\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b")
PHONE_RE = re.compile(r"(?<![\w@])(?:\+994|0|\+\d{1,3})[\s().-]?\d{2,3}[\s().-]?\d{3}[\s().-]?\d{2}[\s().-]?\d{2}(?![\w@])")
DATE_RE = re.compile(r"\b(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})\b")
FIN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{7}(?![A-Za-z0-9])")
# A series is written in capitals. Case-insensitive, the English word "or" was one:
# "Ship order 10020030 or 10020031" reported a HIGH national ID.
NATIONAL_ID_RE = re.compile(r"(?<![A-Za-z0-9])(?:AZE|OR|AA)[ -]?\d{7,8}(?![A-Za-z0-9])")
# A passport number has a digit in it. Without one, any nine-letter word near the word
# "passport" was one: "bring your passport and identity DOCUMENTS to RECEPTION".
PASSPORT_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z](?=[A-Za-z]{0,7}\d)[A-Za-z0-9]{8}(?![A-Za-z0-9])")
MRZ_RE = re.compile(r"\bP<[A-Z]{3}[A-Z0-9<]{20,}", re.IGNORECASE)
DIGITAL_SIGNATURE_RE = re.compile(
    r"(?:<SignatureValue>[^<]{40,}</SignatureValue>|/ByteRange\s*\[|/SubFilter\s*/adbe\.pkcs7|signature[_-]?(?:value|hash|digest)\s*[:=]\s*[A-Za-z0-9+/=_-]{32,})",
    re.IGNORECASE,
)
BASE64_IMAGE_RE = re.compile(r"data:image/(?:png|jpe?g|webp|tiff|bmp);base64,[A-Za-z0-9+/=]{40,}", re.IGNORECASE)
IMAGE_MIME_RE = re.compile(r"\bimage/(?:png|jpe?g|webp|bmp|gif|tiff|heic|heif)\b", re.IGNORECASE)
VIDEO_MIME_RE = re.compile(r"\bvideo/(?:mp4|quicktime|webm|x-msvideo|x-matroska)\b", re.IGNORECASE)
AZ_PLATE_RE = re.compile(r"(?<![A-Za-z0-9])\d{2}[-\s]?[A-Z]{2}[-\s]?\d{3}(?![A-Za-z0-9])", re.IGNORECASE)
VIN_RE = re.compile(r"(?<![A-Za-z0-9])[A-HJ-NPR-Z0-9]{17}(?![A-Za-z0-9])", re.IGNORECASE)
VEHICLE_SERIAL_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z0-9][A-Z0-9-]{5,24}(?![A-Za-z0-9])", re.IGNORECASE)
IPV4_CANDIDATE_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_CANDIDATE_RE = re.compile(r"(?<![\w:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9:.%]{1,}(?![\w:])")
HASHED_IP_RE = re.compile(r"\b[A-Fa-f0-9]{32,64}\b")
MASKED_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){1,3}(?:x{1,3}|\*{1,3}|0)(?![\w.])", re.IGNORECASE)
UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.IGNORECASE)
COOKIE_VALUE_RE = re.compile(r"\b[A-Za-z0-9._~+/=-]{16,256}\b")
GA_CLIENT_ID_RE = re.compile(r"\bGA\d\.\d\.\d{6,}\.\d{6,}\b", re.IGNORECASE)
CLICK_ID_RE = re.compile(r"\b(?:gclid|fbclid|msclkid|ttclid|yclid|gbraid|wbraid)[=:]\s*[A-Za-z0-9_-]{12,}\b", re.IGNORECASE)
# Starts only where a run of token characters starts, and takes the run whole: from every
# word boundary inside a run ("x-x-x...") the old \b start re-read the rest of it.
PUSH_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{80,}+:[A-Za-z0-9_-]{20,}\b")
TCF_STRING_RE = re.compile(r"\b(?:CO|CP|BO)[A-Za-z0-9._-]{40,}\b")
MAC_ADDRESS_RE = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{2}[:-]){5}[A-Fa-f0-9]{2}(?![A-Fa-f0-9])")
MAC_DOTTED_RE = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4}(?![A-Fa-f0-9])")
IMEI_RE = re.compile(r"(?<!\d)\d{15}(?!\d)")
IMEISV_RE = re.compile(r"(?<!\d)\d{16}(?!\d)")
MEID_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{14}(?![A-Fa-f0-9])")
ESN_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{8}(?![A-Fa-f0-9])")
IMSI_RE = re.compile(r"(?<!\d)\d{14,15}(?!\d)")
ICCID_RE = re.compile(r"(?<!\d)89\d{17,20}(?!\d)")
COORDINATE_PAIR_RE = re.compile(
    r"(?<![\d.-])(-?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?))\s*,\s*(-?(?:1[0-7]\d|[1-9]?\d|180)(?:\.\d+)?)(?![\d.-])"
)
LAT_FIELD_RE = re.compile(r"\b(?:lat|latitude|enlik)\s*[:=]\s*(-?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?))\b", re.IGNORECASE)
LNG_FIELD_RE = re.compile(r"\b(?:lng|long|longitude|uzunluq)\s*[:=]\s*(-?(?:1[0-7]\d|[1-9]?\d|180)(?:\.\d+)?)\b", re.IGNORECASE)
URL_RE = re.compile(r"\bhttps?://[^\s<>\"']{4,2048}", re.IGNORECASE)
SEARCH_QUERY_RE = re.compile(r"\b(?:q|query|search|search_query|axtaris|sorgu)\s*[:=]\s*([^\r\n;&]{2,160})", re.IGNORECASE)
USERNAME_VALUE_RE = re.compile(r"@?[A-Za-z0-9][A-Za-z0-9._-]{1,78}[A-Za-z0-9]")
ICD_CODE_RE = re.compile(r"\b[A-TV-Z][0-9][0-9A-Z](?:\.[0-9A-Z]{1,4})?\b", re.IGNORECASE)
CPT_CODE_RE = re.compile(r"(?<!\d)\d{5}(?!\d)")
MEDICAL_RECORD_ID_RE = re.compile(r"\b(?:MRN|MR|MED|PAT)[- _]?[A-Za-z0-9]{5,20}\b", re.IGNORECASE)
BIOMETRIC_HASH_RE = re.compile(r"\b[A-Fa-f0-9]{32,128}\b")
BIOMETRIC_VECTOR_RE = re.compile(r"\[\s*-?\d+(?:\.\d+)?(?:\s*,\s*-?\d+(?:\.\d+)?){7,}\s*\]")
DNA_SEQUENCE_RE = re.compile(r"(?<![A-Za-z])[ACGTN]{12,}(?![A-Za-z])", re.IGNORECASE)
RSID_RE = re.compile(r"\brs\d{3,12}\b", re.IGNORECASE)
GENETIC_VARIANT_RE = re.compile(r"\b(?:c|g|p|m)\.[A-Za-z0-9_>*?+\-delinsdup]+(?:>[A-Za-z0-9]+)?\b", re.IGNORECASE)
CHROMOSOME_RE = re.compile(r"\b(?:chr(?:omosome)?\s*)?(?:[1-9]|1[0-9]|2[0-2]|X|Y|MT)[:qpg.-][A-Za-z0-9_.-]{2,40}\b", re.IGNORECASE)
KARYOTYPE_RE = re.compile(r"\b(?:4[5-7]|[0-9]{2}),\s*(?:XX|XY)(?:,[A-Za-z0-9()+\-;/]+)?\b", re.IGNORECASE)
ALIEN_NUMBER_RE = re.compile(r"\bA[- ]?\d{7,9}\b", re.IGNORECASE)
I94_RE = re.compile(r"\bI[- ]?94[- :]?[A-Za-z0-9]{6,15}\b", re.IGNORECASE)
SEVIS_RE = re.compile(r"\bN\d{10}\b", re.IGNORECASE)
DS160_RE = re.compile(r"\bAA[A-Z0-9]{8,12}\b", re.IGNORECASE)
VISA_PERMIT_RE = re.compile(r"\b(?:visa|permit|residence|work authorization)[- _]?(?:no|number|id)?[- :]?[A-Za-z0-9-]{5,24}\b", re.IGNORECASE)
CASE_RECORD_RE = re.compile(r"\b(?:case|record|file|registry|certificate|clearance)[- _]?(?:no|number|id)?[- :]?[A-Za-z0-9-]{5,30}\b", re.IGNORECASE)
PAYMENT_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
MASKED_CARD_RE = re.compile(r"(?<!\w)(?:\*{4}|x{4}|X{4})[ -]?(?:\*{4}|x{4}|X{4})?[ -]?(?:\*{4}|x{4}|X{4})?[ -]?\d{4}(?!\w)")
CARD_EXPIRY_RE = re.compile(r"\b(?:0[1-9]|1[0-2])\s*/\s*(?:\d{2}|\d{4})\b")
CARD_CVV_RE = re.compile(r"(?<!\d)\d{3,4}(?!\d)")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", re.IGNORECASE)
SWIFT_BIC_RE = re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b", re.IGNORECASE)
ROUTING_ACCOUNT_RE = re.compile(r"\b(?:routing|aba|account(?: number)?|hesab(?: nomresi)?)\s*[:=]?\s*[A-Z0-9 -]{8,34}\b", re.IGNORECASE)
# Whitespace belongs to an amount only after its currency. A leading \s* made every
# position of a whitespace run a start that re-read the rest of the run - quadratic in
# the run - and put the run into the matched text (values are fingerprinted stripped).
MONEY_AMOUNT_RE = re.compile(r"(?<!\w)(?:(?:[$€£₼]|AZN|USD|EUR|GBP)\s*)?\d{1,3}(?:[ ,]\d{3})*(?:\.\d{2})?\s*(?:AZN|USD|EUR|GBP|manat)?(?!\w)", re.IGNORECASE)
CREDIT_SCORE_RE = re.compile(r"\b(?:[3-8]\d{2}|900)\b")
# A match starts where an identifier run starts, a lookahead finds the keyword in the
# run, and the run is then taken whole. The old leading [A-Za-z0-9_.-]* re-read the rest
# of the run from every word boundary in it, quadratic in the run ("a.a.a...", "9-9-...").
# The value (group 1) is the same; a match may now start at the run's leading "." or "-".
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?=[A-Za-z0-9_.-]*?(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|client[_-]?secret|private[_-]?key))"
    r"[A-Za-z0-9_.-]*+\s*[:=]\s*([^\s'\";,#]{6,512}|['\"][^'\"]{6,512}['\"])",
    re.IGNORECASE,
)
PASSWORD_HASH_RE = re.compile(
    r"(?:\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}|\$argon2(?:id|i|d)\$[A-Za-z0-9$=,+/.-]{40,}|\$pbkdf2-[A-Za-z0-9-]+\$[A-Za-z0-9$=,+/.-]{40,}|[A-Fa-f0-9]{32,128})"
)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
GITHUB_TOKEN_RE = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b")
OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")
PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{40,}?-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
    re.IGNORECASE,
)
# In a raw string "\\r" is a backslash and an "r": these patterns forbade the letters r and n
# in a value and wanted a literal backslash after each ';', so no ordinary connection string
# ("Server=db01;Database=hr;...") and no mongodb+srv URI ever matched.
DATABASE_URI_RE = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|mssql|sqlserver|oracle|jdbc:[a-z0-9]+)://[^\s'\"<>]{8,512}",
    re.IGNORECASE,
)
DB_KV_CONNECTION_RE = re.compile(
    r"\b(?:server|host|data source|user id|uid|username|password|pwd|database|initial catalog)\s*=\s*[^;\r\n]{1,160}(?:;\s*(?:server|host|data source|user id|uid|username|password|pwd|database|initial catalog)\s*=\s*[^;\r\n]{1,160}){1,}",
    re.IGNORECASE,
)
MFA_RECOVERY_CODE_RE = re.compile(r"\b[A-Z0-9]{4,8}(?:[-\s][A-Z0-9]{4,8}){1,5}\b", re.IGNORECASE)
OTPAUTH_URI_RE = re.compile(r"\botpauth://[^\s'\"<>]{12,512}", re.IGNORECASE)

NAME_PART_RE = re.compile(r"^[A-Za-zƏəÖöÜüĞğÇçŞşİıI]+$")
TECHNICAL_VALUES = {"admin", "administrator", "test", "system", "root", "null", "none", "unknown", "user", "username"}
PLACEHOLDER_VALUES = TECHNICAL_VALUES | {"demo", "sample", "n/a", "na", "other", "not applicable"}
GENERIC_USERNAME_VALUES = PLACEHOLDER_VALUES | {"support", "operator", "agent", "owner", "member", "customer"}
ADDRESS_MARKERS = {
    "street", "avenue", "road", "boulevard", "district", "city", "village", "apt", "apartment",
    "building", "house", "floor", "block", "baku", "azerbaijan", "kuce", "prospekt", "rayon",
    "seher", "qesebe", "kend", "bina", "menzil", "blok", "mertebe",
}
RELATIONSHIP_TERMS = {
    "mother", "father", "spouse", "husband", "wife", "partner", "guardian", "parent",
    "brother", "sister", "child", "son", "daughter", "caregiver", "carer", "relative",
    "next of kin", "legal guardian", "life partner", "ana", "ata", "valideyn", "qardas",
    "baci", "heyat yoldasi", "qeyyum", "qohum", "ovlad",
}
PHOTO_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif", ".tif", ".tiff", ".heic", ".heif", ".pdf"}
VIDEO_EXTENSIONS = {".mp4", ".mov", ".webm", ".avi", ".mkv"}


def redact(value: str, data_class: str = masking.GENERIC) -> str:
    """What a GDPR or NIST sample shows: the value masked for its class (A6).

    This used to keep the first three and last two characters of anything, so a
    seven-character FIN showed five of them and a password "Hunter2!" read
    "Hun***2!" - while the generic detector showed the same password as stars.
    """
    return masking.mask(" ".join(str(value or "").strip().split()), data_class)


# ── The keyword helpers ──────────────────────────────────────────────────
# All three answer a question about a rule's keyword catalog: does one occur
# near this value, and what follows one. A catalog is 600 to 1,000 terms, and
# each helper used to work against the whole of it on every call - re.escape
# over every term, a sort, a join, and a fresh alternation compiled and run
# across the file.
#
# At most a handful of those terms are in any one file. So the catalog is
# narrowed to the ones that are, once per (file, catalog), and everything
# below works on that handful instead. The narrowing itself is a substring
# test per term against the lowered content, which is a C memmem and about
# ten times cheaper than the alternation it replaces.
#
# Measured on one 7KB HR export against the GDPR catalog: 828 calls into these
# helpers, 411,000 keyword comparisons, 350ms of the detector's 360ms.

# Keyed by object identity, because the catalogs are module-level constants
# reused thousands of times a file and hashing a 1,000-item tuple costs as
# much as the work it would save. The tuple is held alongside so its id cannot
# be reused, and the cap bounds the ad-hoc tuples some rules build by
# concatenation.
_LOWERED_CACHE: dict[int, tuple[tuple[str, ...], tuple[str, ...]]] = {}
_PRESENT_STATE = threading.local()


def _lowered_terms(keywords: tuple[str, ...]) -> tuple[str, ...]:
    key = id(keywords)
    cached = _LOWERED_CACHE.get(key)
    if cached is not None and cached[0] is keywords:
        return cached[1]
    if len(_LOWERED_CACHE) > 1024:
        _LOWERED_CACHE.clear()
    # Empty terms are kept: "" is a substring of everything, which is the
    # answer the any()-over-`in` form gave.
    lowered = tuple(str(item or "").lower() for item in keywords)
    _LOWERED_CACHE[key] = (keywords, lowered)
    return lowered


# P1 (2026-09-24). Narrowing a catalog is a loop over every term of it, and it runs for
# every catalog a file's rules ask about: 8.1 of the 91 CPU-seconds of the quality audit's
# workload scanned in one process, over 126,632 calls. Two faster-looking answers were
# measured in that scan and lost. The Aho-Corasick index keyword_index builds walks the
# text a character at a time in Python. A trie-shaped regex tried at every position cost
# 11.2 s against the loop's 8.1: most files are small, and a C substring test is hard to
# beat on a small string. What wins is testing fewer terms. A term cannot occur unless
# its first three characters do, so each catalog is indexed by that trigram once, each
# file's trigrams are taken once, and only the terms whose trigram the file contains are
# tested - with the same `in`, so the answer is the loop's, in the catalog's order.
_TRIGRAM_INDEXES: dict[int, tuple[tuple[str, ...], "_TrigramIndex"]] = {}


class _TrigramIndex:
    __slots__ = ("by_trigram", "keys", "short")

    def __init__(self, lowered: tuple[str, ...]) -> None:
        by_trigram: dict[str, list[tuple[int, str]]] = {}
        short: list[tuple[int, str]] = []
        for position, term in enumerate(lowered):
            if len(term) < 3:
                # "" and one- or two-character terms have no trigram: always tested.
                short.append((position, term))
            else:
                by_trigram.setdefault(term[:3], []).append((position, term))
        self.by_trigram = {trigram: tuple(entries) for trigram, entries in by_trigram.items()}
        self.keys = frozenset(by_trigram)
        self.short = tuple(short)


def _trigram_index(keywords: tuple[str, ...]) -> _TrigramIndex:
    key = id(keywords)
    cached = _TRIGRAM_INDEXES.get(key)
    if cached is not None and cached[0] is keywords:
        return cached[1]
    index = _TrigramIndex(_lowered_terms(keywords))
    if len(_TRIGRAM_INDEXES) > 1024:
        _TRIGRAM_INDEXES.clear()
    _TRIGRAM_INDEXES[key] = (keywords, index)
    return index


def _content_trigrams(lowered_content: str) -> frozenset[str]:
    return frozenset(lowered_content[i:i + 3] for i in range(len(lowered_content) - 2))


def _present_keywords(content: str, keywords: tuple[str, ...]) -> tuple[str, ...]:
    """The terms from this catalog that occur anywhere in this content.

    A term that is not in the file cannot be in a window of it, and cannot be
    the keyword an alternation matches - so dropping it changes no answer.
    """
    state = getattr(_PRESENT_STATE, "slot", None)
    if state is None or state[0] is not content:
        # [content, lowered, per-catalog answers, the content's trigrams once asked for]
        state = [content, content.lower(), {}, None]
        _PRESENT_STATE.slot = state
    lowered_content = state[1]
    per_catalog = state[2]
    key = id(keywords)
    cached = per_catalog.get(key)
    if cached is not None and cached[0] is keywords:
        return cached[1]
    index = _trigram_index(keywords)
    hits = [(position, term) for position, term in index.short if term in lowered_content]
    if index.keys:
        trigrams = state[3]
        if trigrams is None:
            trigrams = state[3] = _content_trigrams(lowered_content)
        by_trigram = index.by_trigram
        for trigram in index.keys & trigrams:
            hits.extend((position, term) for position, term in by_trigram[trigram] if term in lowered_content)
    hits.sort()
    present = tuple(term for _, term in hits)
    per_catalog[key] = (keywords, present)
    return present


@functools.lru_cache(maxsize=2048)
def _context_value_pattern(terms: tuple[str, ...], max_chars: int, capture_keyword: bool) -> re.Pattern | None:
    """Cached on the NARROWED term tuple, which is small enough to hash."""
    keyword_pattern = "|".join(sorted((re.escape(item) for item in terms if item), key=len, reverse=True))
    if not keyword_pattern:
        return None
    group = f"({keyword_pattern})" if capture_keyword else f"(?:{keyword_pattern})"
    return re.compile(
        rf"(?<![A-Za-z0-9_]){group}(?![A-Za-z0-9_])\s*(?:[:=,-]|\bis\b)?\s*([^\r\n;]{{1,{max_chars}}})",
        re.IGNORECASE,
    )


def context_values(content: str, keywords: tuple[str, ...], max_chars: int = 140) -> list[str]:
    values: list[str] = []
    pattern = _context_value_pattern(_present_keywords(content, keywords), max_chars, False)
    if pattern is None:
        return values
    for match in pattern.finditer(content):
        value = match.group(1).strip(" \t:=-,")
        if value:
            values.append(value)
        if len(values) >= 20:
            break
    return values


def context_keyword_values(content: str, keywords: tuple[str, ...], max_chars: int = 140) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    pattern = _context_value_pattern(_present_keywords(content, keywords), max_chars, True)
    if pattern is None:
        return values
    for match in pattern.finditer(content):
        value = match.group(2).strip(" \t:=-,")
        if value:
            values.append((match.group(1), value))
        if len(values) >= 20:
            break
    return values


def has_keyword_context(content: str, value_start: int, keywords: tuple[str, ...], window: int = 80) -> bool:
    present = _present_keywords(content, keywords)
    if not present:
        return False
    left = content[max(0, value_start - window):value_start].lower()
    return any(term in left for term in present)


def is_valid_email(value: str) -> bool:
    if ".." in value:
        return False
    local, _, domain = value.partition("@")
    if not local or not domain or local.startswith(".") or local.endswith("."):
        return False
    return all(not part.startswith("-") and not part.endswith("-") for part in domain.split("."))


def is_valid_phone(value: str) -> bool:
    if "@" in value:
        return False
    digits = re.sub(r"\D", "", value)
    if not 10 <= len(digits) <= 15:
        return False
    if value.strip().startswith("+994"):
        return len(digits) == 12
    if value.strip().startswith("0"):
        return len(digits) == 10
    return value.strip().startswith("+")


def is_valid_name(value: str) -> bool:
    cleaned = " ".join(value.strip().split())
    if not 2 <= len(cleaned) <= 100:
        return False
    if any(token in cleaned for token in ("@", "/", "\\", "_", "#", ":", ";", ".", ",")):
        return False
    parts = cleaned.split(" ")
    if not 1 <= len(parts) <= 5:
        return False
    for part in parts:
        lowered = part.lower()
        if lowered in TECHNICAL_VALUES or not 2 <= len(part) <= 30 or not NAME_PART_RE.fullmatch(part):
            return False
    return True


def is_valid_date(value: str) -> bool:
    parts = [int(item) for item in re.findall(r"\d+", value)]
    if len(parts) != 3:
        return False
    candidates = []
    if parts[0] > 31:
        candidates.append((parts[0], parts[1], parts[2]))
    else:
        year = parts[2] + 2000 if parts[2] < 100 and parts[2] <= 30 else parts[2] + 1900 if parts[2] < 100 else parts[2]
        candidates.extend([(year, parts[1], parts[0]), (year, parts[0], parts[1])])
    for year, month, day in candidates:
        try:
            parsed = date(year, month, day)
        except ValueError:
            continue
        if 1900 <= parsed.year <= date.today().year:
            return True
    return False


def is_valid_address(value: str) -> bool:
    if "@" in value or len(value.strip()) < 8:
        return False
    lowered = value.lower()
    components = 0
    if re.search(r"\d", value):
        components += 1
    if any(marker in lowered for marker in ADDRESS_MARKERS):
        components += 1
    if re.search(r"\b(?:az|aze|azerbaijan|baku|city|rayon|district|zip|postal)\b", lowered):
        components += 1
    return components >= 2


def looks_like_base64(value: str) -> bool:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 40:
        return False
    try:
        base64.b64decode(compact[: min(len(compact), 160)], validate=False)
        return True
    except (binascii.Error, ValueError):
        return False


def is_valid_free_text_secret(value: str, max_length: int = 150) -> bool:
    cleaned = " ".join(value.strip().split())
    lowered = cleaned.lower()
    if not 2 <= len(cleaned) <= max_length or lowered in PLACEHOLDER_VALUES:
        return False
    if any(marker in lowered for marker in ("http://", "https://", "<html", "{", "}", "[", "]")):
        return False
    if EMAIL_RE.search(cleaned) or PHONE_RE.search(cleaned):
        return False
    return True


def is_relationship_value(value: str) -> bool:
    cleaned = " ".join(value.strip().lower().split())
    if cleaned in PLACEHOLDER_VALUES:
        return False
    if cleaned in RELATIONSHIP_TERMS:
        return True
    return 1 <= len(cleaned.split()) <= 4 and any(term in cleaned for term in RELATIONSHIP_TERMS)


def is_valid_ip(value: str) -> bool:
    candidate = value.strip().strip("[]")
    if "%" in candidate:
        candidate = candidate.split("%", 1)[0]
    if "/" in candidate:
        candidate = candidate.split("/", 1)[0]
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def is_valid_imei(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 15:
        return False
    total = 0
    for index, char in enumerate(digits[:-1]):
        number = int(char)
        if index % 2 == 1:
            number *= 2
            number = number // 10 + number % 10
        total += number
    check = (10 - (total % 10)) % 10
    return check == int(digits[-1])


def is_luhn_valid(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        number = int(char)
        if index % 2 == parity:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def is_valid_iban(value: str) -> bool:
    compact = re.sub(r"\s+", "", value).upper()
    if not 15 <= len(compact) <= 34 or not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(ord(char) - 55) if char.isalpha() else char for char in rearranged)
    return int(numeric) % 97 == 1


def is_valid_mac(value: str) -> bool:
    compact = re.sub(r"[^A-Fa-f0-9]", "", value)
    if len(compact) != 12:
        return False
    return compact.lower() not in {"000000000000", "ffffffffffff"}


def is_valid_coordinate_pair(latitude: str, longitude: str) -> bool:
    try:
        lat_value = float(latitude)
        lng_value = float(longitude)
    except (TypeError, ValueError):
        return False
    return -90 <= lat_value <= 90 and -180 <= lng_value <= 180


def is_valid_username_value(value: str) -> bool:
    candidate = value.strip().strip("`'\"[](){}<>")
    lowered = candidate.lower().lstrip("@")
    if lowered in GENERIC_USERNAME_VALUES or not 3 <= len(candidate) <= 80:
        return False
    if "://" in candidate or EMAIL_RE.fullmatch(candidate) or is_valid_ip(candidate):
        return False
    if re.fullmatch(r"\d{1,6}", candidate):
        return False
    return bool(USERNAME_VALUE_RE.fullmatch(candidate))


def is_valid_contextual_text(value: str, min_length: int = 3, max_length: int = 220) -> bool:
    cleaned = " ".join(value.strip().split())
    lowered = cleaned.lower()
    if not min_length <= len(cleaned) <= max_length or lowered in PLACEHOLDER_VALUES:
        return False
    if EMAIL_RE.fullmatch(cleaned) or PHONE_RE.fullmatch(cleaned) or is_valid_ip(cleaned):
        return False
    return True


def is_valid_secret_value(value: str) -> bool:
    cleaned = value.strip().strip("'\"")
    lowered = cleaned.lower()
    if not 6 <= len(cleaned) <= 512:
        return False
    if lowered in PLACEHOLDER_VALUES or any(marker in lowered for marker in ("example", "sample", "placeholder", "changeme", "your_", "_here")):
        return False
    if re.fullmatch(r"[*xX.-]{6,}", cleaned):
        return False
    return bool(re.search(r"[A-Za-z]", cleaned) and (re.search(r"\d", cleaned) or re.search(r"[^A-Za-z0-9]", cleaned)))
