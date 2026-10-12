from __future__ import annotations

import re


COUNTRY_IDENTIFIER_PLUGINS = {
    "AZ": {
        "country": "AZ",
        "version": "az-id-v1",
        "identifiers": {
            "FIN": {
                "normalize": "uppercase_alnum",
                "validate": "7_alphanumeric_contextual",
                "checksum": "none_public",
                "context": ("fin", "pin", "fincode", "şəxsiyyət", "sexsiyyet", "passport", "national id"),
                "exclusions": ("sample", "example", "placeholder"),
            },
            "NATIONAL_ID_SERIAL": {"normalize": "uppercase_no_space", "validate": "serial_contextual"},
            "PASSPORT": {"normalize": "uppercase_no_space", "validate": "passport_contextual"},
            "VOEN": {"normalize": "digits_only", "validate": "10_digit_tax_identifier"},
        },
    },
    "US": {
        "country": "US",
        "version": "us-id-plugin-placeholder-v1",
        "identifiers": {
            "SSN": {"normalize": "digits_only", "validate": "area_group_serial_with_exclusions"},
            "EIN": {"normalize": "digits_only", "validate": "irs_prefix_format"},
            "DRIVER_LICENSE": {"normalize": "state_specific", "validate": "state_plugin_required"},
        },
    },
    "EU": {
        "country": "EU",
        "version": "eu-id-plugin-placeholder-v1",
        "identifiers": {
            "NATIONAL_ID": {"normalize": "country_specific", "validate": "member_state_plugin_required"},
            "TAX_IDENTIFIER": {"normalize": "country_specific", "validate": "member_state_plugin_required"},
            "RESIDENCE_PERMIT": {"normalize": "country_specific", "validate": "member_state_plugin_required"},
        },
    },
}


def validate_country_identifier(country: str, identifier: str, value: str, context: str = "") -> dict:
    country_key = str(country or "").upper()
    identifier_key = str(identifier or "").upper()
    plugin = COUNTRY_IDENTIFIER_PLUGINS.get(country_key, {})
    spec = (plugin.get("identifiers") or {}).get(identifier_key, {})
    normalized = _normalize(value, str(spec.get("normalize") or "uppercase_alnum"))
    valid = False
    confidence = 40
    if country_key == "AZ" and identifier_key == "FIN":
        valid = bool(re.fullmatch(r"[A-Z0-9]{7}", normalized)) and any(term in context.lower() for term in spec.get("context", ()))
        confidence = 82 if valid else 45
    return {
        "country": country_key,
        "identifier": identifier_key,
        "plugin_version": str(plugin.get("version") or ""),
        "normalized": normalized,
        "valid": valid,
        "confidence": confidence,
        "checksum": str(spec.get("checksum") or "not_available"),
    }


def _normalize(value: str, mode: str) -> str:
    if mode == "digits_only":
        return re.sub(r"\D", "", value or "")
    if mode == "uppercase_no_space":
        return re.sub(r"\s+", "", value or "").upper()
    return re.sub(r"[^A-Za-z0-9]", "", value or "").upper()
