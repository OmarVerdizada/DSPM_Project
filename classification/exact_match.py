"""Exact-data matching: is this value one the organisation listed as personal data (D2)?

A workspace uploads an approved reference set - its customers' e-mail addresses, the
national IDs of its employees - and a finding whose value is in it is confirmed rather
than guessed. Nothing of the set is kept but a keyed fingerprint of each value:

    HMAC( evidence key : tenant,  "edm-v1:<ENTITY TYPE>:<normalised value>" )

- **keyed**, with the installation's evidence key, so a stolen table cannot be tested
  against a guess list without the key (an unsalted SHA-256 of an e-mail address is a
  lookup away from the address);
- **per tenant**, so the same address in two workspaces fingerprints differently, and
  one workspace's reference rows can never match another's findings;
- **its own domain** (``edm-v1``), separate from the evidence and entity fingerprints, so
  neither can be compared with, or stand in for, the other;
- **normalised per type**, so the formatting a spreadsheet adds does not stop a match:
  e-mail lower-cased, phone and ID digits and letters only, a name's case and spacing.

The raw values are read once, fingerprinted, and dropped; they are never written, logged
or returned. ``key_digest`` names the evidence key a set was built with: a set built with
another key cannot match anything and is shown as needing rebuilding.
"""

from __future__ import annotations

import hashlib
import hmac
import re

EDM_VERSION = "edm-v1"

# What a reference set may hold, and the GDPR finding types that carry each.
ENTITY_TYPES = {
    "EMAIL_ADDRESS": ("gdpr_email_address",),
    "PHONE_NUMBER": ("gdpr_phone_number",),
    "GOVERNMENT_ID": ("gdpr_national_id", "gdpr_fin_pin"),
    "PASSPORT_NUMBER": ("gdpr_passport_number",),
    "PERSON_NAME": ("gdpr_full_name",),
}
ENTITY_BY_FINDING = {finding: entity for entity, findings in ENTITY_TYPES.items() for finding in findings}


def normalize(entity_type: str, value: str) -> str:
    text = " ".join(str(value or "").split())
    kind = str(entity_type or "").upper()
    if kind == "EMAIL_ADDRESS":
        return text.lower()
    if kind == "PHONE_NUMBER":
        digits = re.sub(r"\D", "", text)
        return digits[2:] if digits.startswith("00") else digits
    if kind in {"GOVERNMENT_ID", "PASSPORT_NUMBER"}:
        return re.sub(r"[^0-9A-Za-z]", "", text).upper()
    if kind == "PERSON_NAME":
        return text.casefold()
    return text


def _key() -> str:
    from classification.compliance.evidence_keys import evidence_hmac_key

    return str(evidence_hmac_key())


def key_digest() -> str:
    """Which evidence key fingerprints are made with - a name for it, not the key."""
    return hashlib.sha256(f"edm-key:{_key()}".encode("utf-8")).hexdigest()[:16]


def fingerprint(entity_type: str, value: str, tenant_id: str, *, key: str | None = None) -> str:
    normalized = normalize(entity_type, value)
    if not normalized:
        return ""
    secret = key if key is not None else _key()
    payload = f"{EDM_VERSION}:{str(entity_type).upper()}:{normalized}"
    return hmac.new(f"{secret}:{tenant_id}".encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def fingerprints(entity_type: str, values, tenant_id: str) -> set[str]:
    """The fingerprints of a reference set's values (blank values dropped)."""
    secret = _key()
    found = set()
    for value in values:
        item = fingerprint(entity_type, value, tenant_id, key=secret)
        if item:
            found.add(item)
    return found
