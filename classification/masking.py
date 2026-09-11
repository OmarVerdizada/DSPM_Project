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

  * ASCII only. `backend/reporting/report_pdf.py` encodes every cell latin-1
    with `replace`, so a bullet character renders as `?` in the PDF a customer
    is handed.
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
