"""How sure a GDPR finding is (D2): a confidence from 0 to 99 and its tier.

GDPR findings carried no confidence, so every GDPR finding counted the same - a
signature line's e-mail address and a column of national IDs, a name-shaped phrase in a
manual and a named patient. Each now states what its detector actually established:

* **what kind of detector** found it: a secret assignment (``password = ...``) or a
  value with a checkable shape (an e-mail address, an IP, a FIN, a passport or national
  ID, a card or bank number) starts higher than a name, an address or a phone number,
  and those higher than a finding made of context words - a special category (health,
  beliefs, union membership) or a kind of business document;
* whether the **words around it** say what it is (the rule's keywords were in the file);
* how many **distinct values** the file holds - one e-mail address is a signature line,
  a column of them is a list of people;
* a **country validator** that passed (or failed);
* an **exact match** against the workspace's approved reference set: the organisation
  says this value is personal data. Only that reaches CONFIRMED.

Tiers: CONFIRMED (an exact match), HIGH (>= 85), MEDIUM (>= 60), LOW. What each tier is
worth is measured on ``tests/gdpr_corpus.py`` - precision and recall per tier, and the
false positives a MEDIUM threshold removes - and recorded in docs/evidence.
"""

from __future__ import annotations

import re

from classification.confidence import confidence_label

GDPR_CONFIDENCE_VERSION = "gdpr-confidence-1"

SECRET = {
    "gdpr_password_secret", "gdpr_api_token_oauth_secret", "gdpr_private_key_certificate_secret",
    "gdpr_database_connection_string", "gdpr_encryption_key_material", "gdpr_session_token_jwt",
    "gdpr_mfa_seed_recovery_code", "gdpr_account_recovery_secret",
}
STRONG_IDENTIFIER = {
    "gdpr_email_address", "gdpr_fin_pin", "gdpr_national_id", "gdpr_passport_number", "gdpr_ip_identifier",
    "gdpr_payment_card_data", "gdpr_bank_account_data", "gdpr_vehicle_identifier",
    "gdpr_device_hardware_identifier",
}
IDENTIFIER = {
    "gdpr_full_name", "gdpr_phone_number", "gdpr_postal_address", "gdpr_birth_details",
    "gdpr_cookie_device_identifier", "gdpr_geolocation", "gdpr_account_username", "gdpr_emergency_contact",
}
SPECIAL_CONTEXT = {
    "gdpr_health_medical_record", "gdpr_mental_health_substance_use", "gdpr_disability_status",
    "gdpr_biometric_special_category", "gdpr_genetic_dna_data", "gdpr_race_ethnicity",
    "gdpr_religious_philosophical_belief", "gdpr_political_affiliation", "gdpr_sexual_orientation_sex_life",
    "gdpr_trade_union_membership", "gdpr_immigration_citizenship_status", "gdpr_criminal_record_background_check",
    "gdpr_signature", "gdpr_photo_face_image", "gdpr_browsing_history", "gdpr_tax_record",
    "gdpr_credit_score_report", "gdpr_background_check_drug_test",
}
# Anything else - business, legal, security and HR documents - is recognised by its words.
BASE = {"secret": 75, "strong_identifier": 70, "identifier": 55, "special_context": 50, "business_context": 45}

# Findings that are personal data only when they are about a person: a special category,
# or an HR record. The same words in a runbook, a news item or a policy are not.
PERSONAL_CONTEXT = SPECIAL_CONTEXT | {
    "gdpr_hr_employee_file", "gdpr_benefits_insurance_enrollment", "gdpr_salary_compensation",
    "gdpr_timesheet_attendance", "gdpr_org_chart_directory", "gdpr_termination_layoff_plan",
}
# A line that names a person by their role in the document: "Patient: Leyla Aliyeva".
PERSON_LABEL_RE = re.compile(
    r"^\s*(?:full name|name|employee|patient|member|candidate|applicant|traveller|traveler|customer|client|"
    r"staff|student|beneficiary|insured|claimant|holder|technician)\s*(?:name)?\s*[:=-]\s*"
    r"[A-Z][a-z'À-ɏ-]+(?:\s+[A-Z][a-z'À-ɏ-]+)+",
    re.IGNORECASE | re.MULTILINE,
)
_EXPRESSION_RE = re.compile(r"[()\[\]{}$%]|\benviron\b|\bgetenv\b|\bsecrets?\.|\bconfig\.|\bsettings\.", re.IGNORECASE)

PERSON_LINK_BONUS = 15
NO_PERSON_PENALTY = 10
SECRET_NOT_LITERAL_PENALTY = 40
MANY_VALUES = 3
MANY_VALUES_BONUS = 10
VALIDATOR_BONUS = 20
VALIDATOR_PENALTY = 15
CEILING = 95  # only an exact match goes higher
CONFIRMED = 99


def keywords_bonus(count: int) -> int:
    """One of a rule's words in a file is weak evidence; several are not."""
    return 0 if count <= 0 else 5 if count == 1 else 10 if count == 2 else 15


def person_in(content: str, findings: list[dict]) -> bool:
    """Does the file name a person - an identifier finding, or a line naming one by role?"""
    if any(detector_class(str(item.get("type") or "")) in {"identifier", "strong_identifier"} for item in findings):
        return True
    return bool(PERSON_LABEL_RE.search(content or ""))


def looks_like_secret_literal(value: str) -> bool:
    """A secret's value, not a reference to one: no spaces, not a code expression or a
    lookup, at least eight characters of at least three kinds (or a long random token)."""
    text = str(value or "").strip().strip("'\"")
    if "=" in text:
        text = text.split("=", 1)[1].strip().strip("'\"")
    if ":" in text and "://" not in text:
        text = text.split(":", 1)[1].strip().strip("'\"")
    if len(text) < 8 or any(ch.isspace() for ch in text) or _EXPRESSION_RE.search(text):
        return False
    kinds = sum((any(ch.islower() for ch in text), any(ch.isupper() for ch in text),
                 any(ch.isdigit() for ch in text), any(not ch.isalnum() for ch in text)))
    return kinds >= 3 or (len(text) >= 20 and kinds >= 2)


def detector_class(finding_type: str) -> str:
    if finding_type in SECRET:
        return "secret"
    if finding_type in STRONG_IDENTIFIER:
        return "strong_identifier"
    if finding_type in IDENTIFIER:
        return "identifier"
    if finding_type in SPECIAL_CONTEXT:
        return "special_context"
    return "business_context"


def score(finding: dict, *, person_linked: bool | None = None) -> tuple[int, list[str]]:
    """(confidence, why) for a GDPR finding, from what its detector established and - for
    a special category or an HR record - whether the file names a person."""
    finding_type = str(finding.get("type") or "")
    kind = detector_class(finding_type)
    value = BASE[kind]
    basis = [f"detector:{kind}"]
    keyword_count = len(finding.get("matched_keywords") or [])
    if keyword_count:
        value += keywords_bonus(keyword_count)
        basis.append(f"{keyword_count} context keyword(s)")
    if finding_type in PERSONAL_CONTEXT and person_linked is not None:
        if person_linked:
            value += PERSON_LINK_BONUS
            basis.append("about a named person")
        else:
            value -= NO_PERSON_PENALTY
            basis.append("no person in the file")
    if kind == "secret" and finding.get("secret_literal") is False:
        value -= SECRET_NOT_LITERAL_PENALTY
        basis.append("no secret-shaped value")
    if int(finding.get("unique_value_count") or 0) >= MANY_VALUES:
        value += MANY_VALUES_BONUS
        basis.append(f"{MANY_VALUES}+ distinct values")
    validation = finding.get("country_identifier")
    if isinstance(validation, dict) and "valid" in validation:
        if validation.get("valid"):
            value += VALIDATOR_BONUS
            basis.append("country validator passed")
        else:
            value -= VALIDATOR_PENALTY
            basis.append("country validator failed")
    return max(5, min(CEILING, value)), basis


def apply_confidence(finding: dict, *, person_linked: bool | None = None) -> dict:
    """Give a GDPR finding its confidence, tier and the reasons for them."""
    value, basis = score(finding, person_linked=person_linked)
    finding["confidence"] = value
    finding["confidence_tier"] = confidence_label(value)
    finding["confidence_basis"] = basis
    finding["confidence_version"] = GDPR_CONFIDENCE_VERSION
    return finding


def confirm(finding: dict, sets: list[str], matched: int) -> dict:
    """An exact match against the workspace's reference set: confirmed."""
    finding["confidence"] = CONFIRMED
    finding["confidence_tier"] = "CONFIRMED"
    finding["confidence_basis"] = [*(finding.get("confidence_basis") or []), "exact match"]
    finding["exact_match"] = {"sets": sorted(sets), "matched_values": int(matched)}
    return finding
