from __future__ import annotations

import hashlib
import hmac
import os
import base64
import unicodedata
import re
from urllib.parse import unquote
from collections.abc import Iterable
from datetime import date

from classification.compliance.evidence_keys import evidence_hmac_key
from classification.compliance.keyword_index import keyword_hits_indexed
from classification.compliance.validators import is_luhn_valid


PAN_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])(?:\d[\s\u00a0-]?){11,18}\d(?![A-Za-z0-9])")
MASKED_PAN_RE = re.compile(r"(?<!\w)(?:\d{0,6}[\s-]?)?(?:\*{2,}|x{2,}|X{2,})[\s*-]*(?:\*{2,}|x{2,}|X{2,})?[\s-]*\d{4}(?!\w)")
HASH_RE = re.compile(r"\b[A-Fa-f0-9]{32,128}\b")
CIPHERTEXT_RE = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")
CARDHOLDER_NAME_VALUE_RE = re.compile(r"[^\r\n;,|]{2,120}")
EXPIRY_DELIMITED_RE = re.compile(r"(?<!\d)(0?[1-9]|1[0-2])\s*[/-]\s*(\d{2}|\d{4})(?!\d)")
EXPIRY_COMPACT_RE = re.compile(r"(?<!\d)(\d{4})(?!\d)")
EXPIRY_MONTH_FIELD_RE = re.compile(r"\b(?:exp(?:iry|iration)?[_ -]?month|card[_ -]?exp[_ -]?month|mm)\s*[:=]\s*(0?[1-9]|1[0-2])\b", re.IGNORECASE)
EXPIRY_YEAR_FIELD_RE = re.compile(r"\b(?:exp(?:iry|iration)?[_ -]?year|card[_ -]?exp[_ -]?year|yyyy|yy)\s*[:=]\s*(\d{2}|\d{4})\b", re.IGNORECASE)
SERVICE_CODE_VALUE_RE = re.compile(r"(?<!\d)(\d{3})(?!\d)")
CVV_VALUE_RE = re.compile(r"(?<!\d)(\d{3,4})(?!\d)")
PIN_VALUE_RE = re.compile(r"(?<!\d)(\d{4,12})(?!\d)")
PIN_BLOCK_HEX_RE = re.compile(r"(?<![A-Fa-f0-9])([A-Fa-f0-9]{16,32})(?![A-Fa-f0-9])")
TRACK1_RE = re.compile(r"%B(\d{12,19})\^([^^]{2,80})\^(\d{4})(\d{3})([A-Za-z0-9 =?]{1,80})\??", re.IGNORECASE)
TRACK2_RE = re.compile(r";(\d{12,19})([=D])(\d{4})(\d{3})([A-Za-z0-9=?]{1,80})\??", re.IGNORECASE)
TRACK2_EQUIV_RE = re.compile(r"(?<![A-Fa-f0-9])(\d{12,19})D(\d{4})(\d{3})([A-Fa-f0-9]{1,80})F?(?![A-Fa-f0-9])", re.IGNORECASE)

TEST_PAN_CATALOG = {
    "4111111111111111": "visa_test",
    "4012888888881881": "visa_test",
    "5555555555554444": "mastercard_test",
    "5105105105105100": "mastercard_test",
    "378282246310005": "amex_test",
    "371449635398431": "amex_test",
    "6011111111111117": "discover_test",
}


def normalize_pan_candidate(value: str) -> str:
    if re.search(r"[A-Za-z*Xx]", value or ""):
        return ""
    normalized = re.sub(r"[\s\u00a0-]+", "", value or "")
    if not re.fullmatch(r"\d{12,19}", normalized):
        return ""
    return normalized


def is_valid_pan(value: str) -> bool:
    normalized = normalize_pan_candidate(value)
    return bool(normalized and is_luhn_valid(normalized))


def card_brand_info(value: str) -> dict:
    pan = normalize_pan_candidate(value)
    brand = "unknown"
    valid_length = False
    if re.match(r"^4", pan):
        brand = "visa"
        valid_length = len(pan) in {13, 16, 19}
    elif re.match(r"^(5[1-5]|2[2-7])", pan):
        brand = "mastercard"
        valid_length = len(pan) == 16
    elif re.match(r"^3[47]", pan):
        brand = "amex"
        valid_length = len(pan) == 15
    elif re.match(r"^(6011|65|64[4-9])", pan):
        brand = "discover"
        valid_length = len(pan) in {16, 19}
    return {
        "card_brand": brand,
        "pan_length_valid_for_brand": valid_length,
        "test_card": pan in TEST_PAN_CATALOG,
        "test_card_label": TEST_PAN_CATALOG.get(pan, ""),
        "iin_bin": pan[:8] if len(pan) >= 8 else pan[:6],
        "bin_metadata_version": "local-test-catalog-v1",
    }


def mask_pan(value: str) -> str:
    normalized = normalize_pan_candidate(value)
    if not normalized:
        return "***"
    if len(normalized) <= 10:
        return f"{normalized[:2]}***{normalized[-2:]}"
    return f"{normalized[:6]}******{normalized[-4:]}"


def mask_fragment(value: str) -> str:
    compact = " ".join(str(value or "").strip().split())
    if len(compact) <= 8:
        return "***"
    return f"{compact[:3]}***{compact[-4:]}"


def _tenant_evidence_key(tenant_id: str = "default") -> bytes:
    secret = evidence_hmac_key()
    return f"{secret}:{tenant_id or 'default'}".encode("utf-8")


def secure_fingerprint(value: str, tenant_id: str = "default") -> str:
    normalized = normalize_pan_candidate(value)
    if not normalized:
        normalized = " ".join(str(value or "").strip().split()).lower()
    return hmac.new(_tenant_evidence_key(tenant_id), f"pci-pan-v1:{normalized}".encode("utf-8"), hashlib.sha256).hexdigest()


def secure_text_fingerprint(value: str, scope: str = "pci-text-v1", tenant_id: str = "default") -> str:
    normalized = normalize_cardholder_name(value) or " ".join(str(value or "").strip().split()).lower()
    return hmac.new(_tenant_evidence_key(tenant_id), f"{scope}:{normalized}".encode("utf-8"), hashlib.sha256).hexdigest()


def normalize_cardholder_name(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", str(value or ""))
    normalized = " ".join(normalized.replace("\u00a0", " ").strip().split())
    return normalized


def is_valid_cardholder_name(value: str) -> bool:
    candidate = normalize_cardholder_name(value).strip(" :=,-")
    if not 2 <= len(candidate) <= 80:
        return False
    if any(marker in candidate.lower() for marker in ("http://", "https://", "@", "\\", "/", "{", "}", "[", "]")):
        return False
    letters = sum(1 for char in candidate if char.isalpha())
    digits = sum(1 for char in candidate if char.isdigit())
    allowed_punctuation = {" ", "'", "-", "."}
    if digits or letters < 2:
        return False
    if any(not (char.isalpha() or char in allowed_punctuation) for char in candidate):
        return False
    if letters / max(len(candidate.replace(" ", "")), 1) < 0.6:
        return False
    tokens = [token.strip("'.-") for token in candidate.split()]
    if not 1 <= len([token for token in tokens if token]) <= 6:
        return False
    blocked = {"admin", "administrator", "test", "sample", "demo", "unknown", "null", "none", "system", "merchant", "company"}
    return not any(token.lower() in blocked for token in tokens if token)


def mask_cardholder_name(value: str) -> str:
    candidate = normalize_cardholder_name(value)
    if not candidate:
        return "***"
    parts = candidate.split()
    masked: list[str] = []
    for part in parts[:4]:
        stripped = part.strip()
        if len(stripped) <= 2:
            masked.append(f"{stripped[:1]}*")
        else:
            masked.append(f"{stripped[:1]}***{stripped[-1:]}")
    return " ".join(masked)


def normalize_expiration_date(month: str | int, year: str | int) -> str:
    try:
        month_value = int(str(month).strip())
        raw_year = str(year).strip()
        year_value = _normalize_expiry_year(raw_year)
    except (TypeError, ValueError):
        return ""
    if not 1 <= month_value <= 12 or not _is_plausible_expiry_year(year_value):
        return ""
    return f"{month_value:02d}/{year_value:04d}"


def parse_expiration_value(value: str, context_hint: str = "display") -> str:
    candidate = str(value or "").strip()
    delimited = EXPIRY_DELIMITED_RE.search(candidate)
    if delimited:
        return normalize_expiration_date(delimited.group(1), delimited.group(2))
    compact = EXPIRY_COMPACT_RE.search(candidate)
    if not compact:
        return ""
    digits = compact.group(1)
    if context_hint == "track":
        parsed = normalize_expiration_date(digits[2:], digits[:2])
        if parsed:
            return parsed
    return normalize_expiration_date(digits[:2], digits[2:])


def parse_service_code_value(value: str) -> str:
    match = SERVICE_CODE_VALUE_RE.search(str(value or ""))
    if not match:
        return ""
    return match.group(1)


def parse_cvv_value(value: str, explicit: bool = True) -> str:
    raw = str(value or "").strip()
    lowered = raw.lower()
    if not raw or lowered in {"null", "none", "n/a", "na", "empty", "redacted", "masked", "placeholder"}:
        return ""
    if re.fullmatch(r"[*xX.-]{1,8}", raw):
        return ""
    match = CVV_VALUE_RE.search(raw)
    if not match:
        return ""
    candidate = match.group(1)
    if explicit and 3 <= len(candidate) <= 4:
        return candidate
    if 3 <= len(candidate) <= 4:
        return candidate
    return ""


def mask_cvv_value(value: str) -> str:
    parsed = parse_cvv_value(value, explicit=True)
    if not parsed:
        return "CVV_LEN=0"
    return f"CVV_LEN={len(parsed)}"


def redact_cvv_fields(content: str, keywords: Iterable[str]) -> str:
    redacted = content
    keyword_pattern = "|".join(sorted((re.escape(item) for item in keywords if item), key=len, reverse=True))
    if not keyword_pattern:
        return redacted
    pattern = re.compile(
        rf"(?<![A-Za-z0-9_])({keyword_pattern})(?![A-Za-z0-9_])(\s*(?:[:=,-]|\bis\b)?\s*)(\d{{1,4}})(?!\d)",
        re.IGNORECASE,
    )
    return pattern.sub(lambda match: f"{match.group(1)}{match.group(2)}***", redacted)


def parse_pin_value(value: str) -> str:
    raw = str(value or "").strip()
    lowered = raw.lower()
    if not raw or lowered in {"null", "none", "n/a", "na", "redacted", "masked", "placeholder"}:
        return ""
    if re.fullmatch(r"[*xX.-]{1,16}", raw):
        return ""
    match = PIN_VALUE_RE.search(raw)
    return match.group(1) if match else ""


def parse_pin_block_value(value: str) -> str:
    match = PIN_BLOCK_HEX_RE.search(str(value or ""))
    return match.group(1).upper() if match else ""


def analyze_pin_block_value(value: str) -> dict:
    parsed = parse_pin_block_value(value)
    if not parsed:
        return {}
    format_nibble = parsed[0]
    return {
        "pin_block_format": f"ISO_FORMAT_{format_nibble}" if format_nibble in {"0", "1", "3", "4"} else "UNKNOWN",
        "pin_block_length": len(parsed),
        "pin_block_length_valid": len(parsed) in {16, 32},
        "pin_block_requires_pan_validation": format_nibble in {"0", "3", "4"},
        "pin_block_test_vector_excluded": parsed in {"0000000000000000", "FFFFFFFFFFFFFFFF"},
    }


def mask_pin_value(value: str) -> str:
    parsed = parse_pin_value(value)
    return f"PIN_LEN={len(parsed)}" if parsed else "PIN_LEN=0"


def mask_pin_block_value(value: str) -> str:
    parsed = parse_pin_block_value(value)
    return f"PIN_BLOCK_LEN={len(parsed)}" if parsed else "PIN_BLOCK_LEN=0"


def redact_pin_fields(content: str, keywords: Iterable[str]) -> str:
    keyword_pattern = "|".join(sorted((re.escape(item) for item in keywords if item), key=len, reverse=True))
    if not keyword_pattern:
        return content
    pattern = re.compile(
        rf"(?<![A-Za-z0-9_])({keyword_pattern})(?![A-Za-z0-9_])(\s*(?:[:=,-]|\bis\b)?\s*)([A-Fa-f0-9]{{4,32}})(?![A-Fa-f0-9])",
        re.IGNORECASE,
    )
    return pattern.sub(lambda match: f"{match.group(1)}{match.group(2)}***", content)


def decode_track_payloads(content: str) -> list[tuple[str, str]]:
    payloads = [("ascii", content or "")]
    decoded = unquote(content or "")
    if decoded != (content or ""):
        payloads.append(("percent_encoded", decoded))
    for token in re.findall(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{28,}={0,2}(?![A-Za-z0-9+/=])", content or ""):
        try:
            decoded_bytes = base64.b64decode(token, validate=True)
            decoded_text = decoded_bytes.decode("ascii", errors="ignore")
        except Exception:
            continue
        if decoded_text and decoded_text not in {payload for _, payload in payloads}:
            payloads.append(("base64", decoded_text))
    for token in re.findall(r"\b(?:25|3B|3D|3F|5E|37|34|31|32|39|30|42)[A-Fa-f0-9]{30,512}\b", content or ""):
        try:
            decoded_text = bytes.fromhex(token).decode("ascii", errors="ignore")
        except ValueError:
            continue
        if decoded_text and decoded_text not in {payload for _, payload in payloads}:
            payloads.append(("hex", decoded_text))
    return payloads


def parse_track_data(content: str) -> list[dict]:
    parsed: list[dict] = []
    for encoding, payload in decode_track_payloads(content):
        parsed.extend(_parse_emv_tlv_payload(payload, encoding))
        for match in TRACK1_RE.finditer(payload):
            pan = match.group(1)
            expiry = parse_expiration_value(match.group(3), context_hint="track")
            service_code = match.group(4)
            if not is_luhn_valid(pan) or not expiry:
                continue
            parsed.append(
                {
                    "track_type": "track_1",
                    "encoding": encoding,
                    "raw": match.group(0),
                    "pan": pan,
                    "cardholder_name": normalize_cardholder_name(match.group(2).replace("/", " ")),
                    "expiry": expiry,
                    "service_code": service_code,
                    "separator": "^",
                    "discretionary_length": len(match.group(5)),
                    "confidence": 96,
                }
            )
        for match in TRACK2_RE.finditer(payload):
            pan = match.group(1)
            expiry = parse_expiration_value(match.group(3), context_hint="track")
            service_code = match.group(4)
            if not is_luhn_valid(pan) or not expiry:
                continue
            parsed.append(
                {
                    "track_type": "track_2",
                    "encoding": encoding,
                    "raw": match.group(0),
                    "pan": pan,
                    "expiry": expiry,
                    "service_code": service_code,
                    "separator": match.group(2),
                    "discretionary_length": len(match.group(5).rstrip("?")),
                    "confidence": 95,
                }
            )
        for match in TRACK2_EQUIV_RE.finditer(payload):
            pan = match.group(1)
            expiry = parse_expiration_value(match.group(2), context_hint="track")
            service_code = match.group(3)
            if not is_luhn_valid(pan) or not expiry:
                continue
            parsed.append(
                {
                    "track_type": "emv_track_2_equivalent",
                    "encoding": encoding,
                    "raw": match.group(0),
                    "pan": pan,
                    "expiry": expiry,
                    "service_code": service_code,
                    "separator": "D",
                    "discretionary_length": len(match.group(4).rstrip("F")),
                    "confidence": 92,
                }
            )
    return _dedupe_track_data(parsed)


def _parse_emv_tlv_payload(payload: str, encoding: str) -> list[dict]:
    candidates = [payload]
    for token in re.findall(r"\b[A-Fa-f0-9]{20,512}\b", payload or ""):
        candidates.append(token)
    for token in re.findall(r"\b[A-Za-z0-9+/]{28,}={0,2}\b", payload or ""):
        try:
            decoded = base64.b64decode(token, validate=True).hex().upper()
            candidates.append(decoded)
        except Exception:
            continue
    parsed: list[dict] = []
    for candidate in candidates:
        hex_payload = re.sub(r"[^A-Fa-f0-9]", "", candidate or "").upper()
        for tag57 in _extract_tlv_tag57_values(hex_payload):
            track = _parse_tag57_track2(tag57)
            if track:
                track["encoding"] = "ber_tlv_hex" if encoding == "ascii" else f"{encoding}+ber_tlv_hex"
                parsed.append(track)
    return parsed


def _extract_tlv_tag57_values(hex_payload: str) -> list[str]:
    values: list[str] = []
    index = 0
    while index + 4 <= len(hex_payload):
        tag = hex_payload[index:index + 2]
        index += 2
        if tag in {"9F", "5F", "BF"} and index + 2 <= len(hex_payload):
            tag += hex_payload[index:index + 2]
            index += 2
        if index + 2 > len(hex_payload):
            break
        length_byte = _safe_hex_int(hex_payload[index:index + 2])
        if length_byte is None:
            break
        index += 2
        if length_byte & 0x80:
            length_len = length_byte & 0x7F
            if length_len == 0 or length_len > 2 or index + length_len * 2 > len(hex_payload):
                break
            length = _safe_hex_int(hex_payload[index:index + length_len * 2])
            if length is None:
                break
            index += length_len * 2
        else:
            length = length_byte
        value = hex_payload[index:index + length * 2]
        index += length * 2
        if len(value) != length * 2:
            break
        if tag == "57":
            values.append(value)
    return values


def _safe_hex_int(value: str) -> int | None:
    if not value:
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def _parse_tag57_track2(value_hex: str) -> dict:
    digits = "".join("D" if char.upper() == "D" else char for char in value_hex.upper()).rstrip("F")
    match = re.match(r"^(\d{12,19})D(\d{4})(\d{3})([A-Fa-f0-9]*)$", digits)
    if not match:
        return {}
    pan = match.group(1)
    expiry = parse_expiration_value(match.group(2), context_hint="track")
    if not is_luhn_valid(pan) or not expiry:
        return {}
    return {
        "track_type": "emv_track_2_equivalent",
        "raw": f"57:{mask_fragment(value_hex)}",
        "pan": pan,
        "expiry": expiry,
        "service_code": match.group(3),
        "separator": "D",
        "discretionary_length": len(match.group(4)),
        "confidence": 96,
        "emv_parser": "ber_tlv_tag_57",
        "tag": "57",
        "tag_length_nibbles": len(value_hex),
        "padding_nibble_valid": value_hex.upper().endswith("F") or len(value_hex) % 2 == 0,
    }


def mask_track_data(track: dict) -> str:
    return (
        f"{track.get('track_type', 'track')} "
        f"PAN={mask_pan(str(track.get('pan') or ''))} "
        f"EXP={track.get('expiry', '')} "
        f"SVC={track.get('service_code', '')} "
        f"DISC_LEN={track.get('discretionary_length', 0)}"
    )


def _dedupe_track_data(items: list[dict]) -> list[dict]:
    deduped: dict[tuple[str, str, str, str], dict] = {}
    for item in items:
        key = (
            str(item.get("track_type") or ""),
            str(item.get("pan") or ""),
            str(item.get("expiry") or ""),
            str(item.get("service_code") or ""),
        )
        current = deduped.get(key)
        if not current or int(item.get("confidence") or 0) > int(current.get("confidence") or 0):
            deduped[key] = item
    return list(deduped.values())


def _normalize_expiry_year(value: str) -> int:
    year = int(value)
    if year >= 100:
        return year
    current_year = date.today().year
    current_century = (current_year // 100) * 100
    candidates = [current_century - 100 + year, current_century + year, current_century + 100 + year]
    return min(candidates, key=lambda item: abs(item - current_year))


def _is_plausible_expiry_year(year: int) -> bool:
    current_year = date.today().year
    return current_year - 30 <= year <= current_year + 30


def keyword_hits(blob: str, keywords: Iterable[str], limit: int = 10) -> list[str]:
    return keyword_hits_indexed(blob, keywords, cache_namespace="pci_dss", limit=limit)


def local_context(content: str, start: int, window: int = 120) -> str:
    return content[max(0, start - window): min(len(content), start + window)]


def classify_protection_state(context: str, raw_value: str) -> str:
    lowered = context.lower()
    if MASKED_PAN_RE.search(raw_value):
        return "MASKED_DISPLAY"
    normalized_pan = normalize_pan_candidate(raw_value)
    if normalized_pan and is_luhn_valid(normalized_pan):
        return "READABLE_FULL"
    if any(marker in lowered for marker in ("truncated", "truncation", "partial pan", "last four", "last_four", "last4", "last 4")):
        return "TRUNCATED_AT_REST"
    if any(marker in lowered for marker in ("tokenized", "tokenised", "pan token", "card token", "vault token", "network token", "dpan", "fpe")):
        return "TOKENIZED_NONREVERSIBLE_OR_OUT_OF_SCOPE_CANDIDATE"
    if any(marker in lowered for marker in ("hmac", "keyed hash", "keyed_hash", "keyed pan hash")):
        return "HASHED_KEYED"
    if any(marker in lowered for marker in ("hashed", "pan hash", "digest", "fingerprint")):
        return "HASHED_UNKEYED_OR_UNKNOWN"
    if any(marker in lowered for marker in ("encrypted", "ciphertext", "cipher", "decrypt")):
        return "ENCRYPTED"
    if any(marker in lowered for marker in ("redacted", "[redacted]", "<redacted>")):
        return "REDACTED"
    return "READABLE_FULL"


def claimed_protection_state(context: str, raw_value: str = "") -> str:
    lowered = context.lower()
    if MASKED_PAN_RE.search(raw_value):
        return "MASKED_DISPLAY"
    if any(marker in lowered for marker in ("truncated", "truncation", "partial pan", "last four", "last_four", "last4", "last 4")):
        return "TRUNCATED_AT_REST"
    if any(marker in lowered for marker in ("tokenized", "tokenised", "pan token", "card token", "vault token", "network token", "dpan", "fpe")):
        return "TOKENIZED_NONREVERSIBLE_OR_OUT_OF_SCOPE_CANDIDATE"
    if any(marker in lowered for marker in ("hmac", "keyed hash", "keyed_hash", "keyed pan hash")):
        return "HASHED_KEYED"
    if any(marker in lowered for marker in ("hashed", "pan hash", "digest", "fingerprint")):
        return "HASHED_UNKEYED_OR_UNKNOWN"
    if any(marker in lowered for marker in ("encrypted", "ciphertext", "cipher", "decrypt")):
        return "ENCRYPTED"
    if any(marker in lowered for marker in ("redacted", "[redacted]", "<redacted>")):
        return "REDACTED"
    return "NOT_CLAIMED"
