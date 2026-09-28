"""What an analyst is shown instead of the value.

A finding's samples used to render as `[redacted:30840604a1b4]` - a keyed HMAC of
the matched value. As a FINGERPRINT that is exactly right: it counts distinct
values without storing any, and it survives being written to a report. As the
thing a person reads it is useless. It does not say what was found, whether the
card is a test number, whether the email is a personal address or a distribution
list, or whether the "secret" is a placeholder. An analyst cannot triage it, so
they open the file - which is the one thing a data-security console exists to
make unnecessary.

So the two jobs are separated. The HMAC stays on the finding as
`secure_value_fingerprints` and keeps doing the counting. What is DISPLAYED is a
partial value, masked to the minimum that identifies the class:

    PAN            411111******1111     (PCI DSS 3.4: first six, last four)
    IBAN           AZ21NABZ********1944
    Email          j***@example.com
    Phone          +994******45
    Government ID  ****12
    Secret         AKIA************WXYZ
    Private key    [private key]

Two rules the formats follow, both learned the hard way:

  * ASCII only. A mask reads the same in every place it lands - the console,
    a CSV, a SIEM event, the Word and Excel exports and the PDF (which drew
    in Latin-1 Helvetica until C9 embedded a Unicode font, and printed a
    bullet character as `?`).
  * Never widen an existing reveal. The PCI family already masks to its own
    rules - and CVV and PIN deliberately show only a LENGTH, because PCI DSS
    forbids keeping sensitive authentication data at all. This module does not
    touch those.
"""

from __future__ import annotations

import re

MASK_VERSION = "mask-v1"

# Data classes, by what the mask has to preserve.
PAN = "pan"
IBAN = "iban"
EMAIL = "email"
PHONE = "phone"
GOVERNMENT_ID = "government_id"
SECRET = "secret"
PRIVATE_KEY = "private_key"
CONNECTION_STRING = "connection_string"
PASSWORD = "password"
GENERIC = "generic"

CLASS_LABELS = {
    PAN: "Payment card",
    IBAN: "IBAN",
    EMAIL: "Email address",
    PHONE: "Phone number",
    GOVERNMENT_ID: "Government identifier",
    SECRET: "Credential",
    PRIVATE_KEY: "Private key",
    CONNECTION_STRING: "Connection string",
    PASSWORD: "Password",
    GENERIC: "Sensitive value",
}

# Which class each generic detection rule produces. A rule absent from this map
# masks generically, which is the safe direction.
RULE_DATA_CLASSES = {
    "credit_card": PAN,
    "iban": IBAN,
    "email": EMAIL,
    "phone_number": PHONE,
    "passport_number": GOVERNMENT_ID,
    "national_id": GOVERNMENT_ID,
    "ssn": GOVERNMENT_ID,
    "azerbaijan_fin": GOVERNMENT_ID,
    "employee_id": GOVERNMENT_ID,
    "routing_account": IBAN,
    "swift_bic": IBAN,
    "private_key": PRIVATE_KEY,
    "saml_private_key": PRIVATE_KEY,
    "gcp_service_account": PRIVATE_KEY,
    "password": PASSWORD,
    "connection_string": CONNECTION_STRING,
    "database_uri": CONNECTION_STRING,
    "jdbc_connection": CONNECTION_STRING,
    "basic_auth_url": CONNECTION_STRING,
    "redis_uri": CONNECTION_STRING,
    "mongodb_uri": CONNECTION_STRING,
}

# Everything else that is credential material.
_SECRET_MARKERS = frozenset({"key", "token", "secret", "dsn", "auth", "credential", "jwt", "sas"})


def data_class_for_rule(rule_name: str) -> str:
    """The data class a generic detection rule produces."""

    name = str(rule_name or "").lower()
    if name in RULE_DATA_CLASSES:
        return RULE_DATA_CLASSES[name]
    # Whole words, not substrings: "confidential_keyword" contains "key", and
    # a context keyword is not credential material - its raw text IS the
    # evidence and it is deliberately shown unmasked.
    if set(re.split(r"[^a-z0-9]+", name)) & _SECRET_MARKERS:
        return SECRET
    return GENERIC


def class_label(data_class: str) -> str:
    return CLASS_LABELS.get(str(data_class or GENERIC), CLASS_LABELS[GENERIC])


def _stars(count: int) -> str:
    return "*" * max(1, count)


def _keep_ends(value: str, lead: int, tail: int) -> str:
    """`lead` characters, stars for the middle, `tail` characters.

    Falls back to full masking when the value is too short for the reveal to
    leave anything hidden - a four-character "secret" shown as itself is not a
    mask.
    """

    if len(value) <= lead + tail:
        return _stars(len(value) or 3)
    # `value[-0:]` is the WHOLE string, not the empty one - a tail of zero would
    # append the very value being masked.
    suffix = value[-tail:] if tail else ""
    return f"{value[:lead]}{_stars(len(value) - lead - tail)}{suffix}"


def _mask_pan(value: str) -> str:
    digits = re.sub(r"[^0-9]", "", value)
    if len(digits) <= 10:
        return _keep_ends(digits, 2, 2)
    # The maximum PCI DSS 3.4 permits anyone to display.
    return f"{digits[:6]}{_stars(len(digits) - 10)}{digits[-4:]}"


def _mask_iban(value: str) -> str:
    compact = re.sub(r"\s", "", value).upper()
    if len(compact) <= 8:
        return _stars(len(compact))
    # Country and bank identifier stay: they are what routes a question to the
    # right finance team, and neither identifies an account on its own.
    return f"{compact[:8]}{_stars(len(compact) - 12)}{compact[-4:]}"


def _mask_email(value: str) -> str:
    local, at, domain = str(value).partition("@")
    if not at:
        return _keep_ends(value, 1, 0)
    # The domain is the actionable half - a personal address, a customer's, or
    # an internal distribution list are three different findings.
    return f"{local[:1]}{_stars(max(1, len(local) - 1))}@{domain}"


def _mask_phone(value: str) -> str:
    digits = re.sub(r"[^0-9+]", "", value)
    if len(digits) <= 4:
        return _stars(len(digits) or 3)
    lead = 4 if digits.startswith("+") else 0
    return f"{digits[:lead]}{_stars(len(digits) - lead - 2)}{digits[-2:]}"


def _mask_connection_string(value: str) -> str:
    """Keep the scheme and host; the credential inside is the secret."""

    match = re.match(r"^([a-zA-Z][\w+.-]*://)([^@/\s]*@)?(.*)$", str(value).strip())
    if not match:
        return _keep_ends(str(value), 4, 0)
    scheme, credential, rest = match.group(1), match.group(2) or "", match.group(3)
    host = rest.split("/", 1)[0].split("?", 1)[0]
    return f"{scheme}{_stars(8) + '@' if credential else ''}{host or _stars(6)}"


_MASKS = {
    PAN: _mask_pan,
    IBAN: _mask_iban,
    EMAIL: _mask_email,
    PHONE: _mask_phone,
    GOVERNMENT_ID: lambda value: _keep_ends(re.sub(r"\s", "", str(value)), 0, 2),
    SECRET: lambda value: _keep_ends(str(value).strip(), 4, 4),
    PRIVATE_KEY: lambda _value: "[private key]",
    CONNECTION_STRING: _mask_connection_string,
    PASSWORD: lambda value: _stars(min(len(str(value).strip()) or 3, 12)),
    GENERIC: lambda value: _keep_ends(str(value).strip(), 2, 2),
}


def mask(value: str, data_class: str = GENERIC) -> str:
    """The partial value an analyst is shown. ASCII, never the whole thing."""

    text = str(value or "").strip()
    if not text:
        return ""
    masked = _MASKS.get(str(data_class or GENERIC), _MASKS[GENERIC])(text)
    # Belt and braces: a mask that returns its input reveals everything, which
    # is the one outcome this module must never produce.
    return masked if masked != text else _stars(len(text))


# ---- Text that leaves the product ------------------------------------------------
# C9: a report or an export is built from scan results - file names, owners, reasons,
# and whatever a page composed from them - and it leaves the building: attached to a
# ticket, mailed to an auditor. The samples in it are masked where they are made; this
# is the second line, run over every string on its way into the file, for the value
# that reached a report by another road: a file NAMED after a card number, an IBAN in a
# share name, a key pasted into an owner field. The same function serves the PDF, the
# Word document and the workbook, so no format is the one that forgot.
#
# It masks only what is unambiguous without context. A card number is issuer-valid,
# Luhn-valid and not a structural non-card (the shared validator's rules, minus the
# nearby-words test - in a file bound for a customer, a bare card number is masked
# whether or not a payment word is near it). An IBAN passes its mod-97 check. A
# private key block is replaced whole.
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)", re.S)
_IBAN_CANDIDATE = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}(?![A-Za-z0-9])")


def _iban_valid(candidate: str) -> bool:
    compact = re.sub(r"\s", "", candidate).upper()
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        return int("".join(str(int(char, 36)) for char in rearranged)) % 97 == 1
    except ValueError:
        return False


def mask_in_text(value: object) -> tuple[str, int]:
    """`value` as text with every whole card number, IBAN and private key in it
    masked, and how many were."""

    from classification.pan_validator import (
        PAN_CANDIDATE_RE, card_issuer, is_luhn_valid, normalize_candidate, structural_exclusion)

    text = "" if value is None else str(value)
    if not text:
        return "", 0
    count = 0

    def _key(_match: re.Match) -> str:
        nonlocal count
        count += 1
        return _MASKS[PRIVATE_KEY]("")

    def _pan(match: re.Match) -> str:
        nonlocal count
        digits = normalize_candidate(match.group(0))
        if not digits or not is_luhn_valid(digits) or not card_issuer(digits)[1] or structural_exclusion(digits):
            return match.group(0)
        count += 1
        return mask(digits, PAN)

    def _iban(match: re.Match) -> str:
        nonlocal count
        if not _iban_valid(match.group(0)):
            return match.group(0)
        count += 1
        return mask(match.group(0), IBAN)

    if "PRIVATE KEY" in text:
        text = _PRIVATE_KEY_BLOCK.sub(_key, text)
    if any(char.isdigit() for char in text):
        text = PAN_CANDIDATE_RE.sub(_pan, text)
        text = _IBAN_CANDIDATE.sub(_iban, text)
    return text, count
