from __future__ import annotations

import hashlib
import hmac
import os

from classification.compliance.evidence_keys import evidence_hmac_key


GDPR_ARTICLE_CATALOG = {
    "personal_data_definition": {"article": "Article 4(1)", "title": "Personal data definition"},
    "processing_principles": {"article": "Article 5", "title": "Principles relating to processing of personal data"},
    "lawfulness": {"article": "Article 6", "title": "Lawfulness of processing"},
    "consent": {"article": "Article 7", "title": "Conditions for consent"},
    "children_consent": {"article": "Article 8", "title": "Child consent for information society services"},
    "special_category_processing": {"article": "Article 9", "title": "Processing of special categories of personal data"},
    "criminal_conviction_data": {"article": "Article 10", "title": "Criminal convictions and offences data"},
    "transparency": {"article": "Articles 12-14", "title": "Transparency and information duties"},
    "data_subject_rights": {"article": "Articles 15-22", "title": "Data subject rights"},
    "privacy_by_design": {"article": "Article 25", "title": "Data protection by design and by default"},
    "records_of_processing": {"article": "Article 30", "title": "Records of processing activities"},
    "security_of_processing": {"article": "Article 32", "title": "Security of processing"},
    "breach_notification": {"article": "Articles 33-34", "title": "Personal data breach notification"},
    "dpia": {"article": "Article 35", "title": "Data protection impact assessment"},
    "international_transfers": {"article": "Chapter V / Articles 44-49", "title": "International transfers"},
}


SPECIAL_CATEGORY_MAP = {
    "gdpr_health_medical_record": "health_data",
    "gdpr_mental_health_substance_use": "health_data",
    "gdpr_disability_status": "health_data",
    "gdpr_biometric_special_category": "biometric_unique_identification",
    "gdpr_genetic_dna_data": "genetic_data",
    "gdpr_race_ethnicity": "racial_or_ethnic_origin",
    "gdpr_religious_philosophical_belief": "religious_or_philosophical_beliefs",
    "gdpr_political_affiliation": "political_opinions",
    "gdpr_sexual_orientation_sex_life": "sex_life_or_sexual_orientation",
    "gdpr_trade_union_membership": "trade_union_membership",
}


ARTICLE_10_TYPES = {"gdpr_criminal_record_background_check"}


DIRECT_IDENTIFIER_TYPES = {
    "gdpr_full_name",
    "gdpr_email_address",
    "gdpr_phone_number",
    "gdpr_postal_address",
    "gdpr_fin_pin",
    "gdpr_national_id",
    "gdpr_passport_number",
    "gdpr_signature",
}


INDIRECT_IDENTIFIER_TYPES = {
    "gdpr_birth_details",
    "gdpr_photo_face_image",
    "gdpr_vehicle_identifier",
    "gdpr_ip_identifier",
    "gdpr_cookie_device_identifier",
    "gdpr_device_hardware_identifier",
    "gdpr_geolocation",
    "gdpr_browsing_history",
    "gdpr_account_username",
}


def gdpr_metadata_for_finding(finding_type: str, category: str = "") -> dict:
    special_category = SPECIAL_CATEGORY_MAP.get(finding_type, "")
    article_10 = finding_type in ARTICLE_10_TYPES
    direct = finding_type in DIRECT_IDENTIFIER_TYPES
    indirect = finding_type in INDIRECT_IDENTIFIER_TYPES or bool(special_category) or article_10
    article_keys = ["personal_data_definition"]
    if special_category:
        article_keys.append("special_category_processing")
    if article_10:
        article_keys.append("criminal_conviction_data")
    if finding_type in {"gdpr_geolocation", "gdpr_browsing_history", "gdpr_biometric_special_category", "gdpr_genetic_dna_data"}:
        article_keys.append("dpia")
    return {
        "personal_data_type": _personal_data_type(finding_type, category, special_category, article_10),
        "identifier_type": "direct_identifier" if direct else "indirect_identifier" if indirect else "contextual_personal_data",
        "direct_or_indirect": "direct" if direct else "indirect",
        "data_subject_type": "natural_person",
        "special_category": bool(special_category),
        "special_category_type": special_category,
        "article_10_data": article_10,
        "children_data": "unknown",
        "controller_or_processor": "unknown",
        "processing_purpose": "unknown",
        "lawful_basis": "unknown",
        "consent_status": "unknown",
        "retention_period": "unknown",
        "retention_expired": "unknown",
        "data_residency": "unknown",
        "cross_border_transfer": "unknown",
        "transfer_mechanism": "unknown",
        "data_owner": "unknown",
        "processing_system": "unknown",
        "pseudonymized": "unknown",
        "anonymized": "unknown",
        "encryption_state": "unknown",
        "DPIA_required": "needs_review" if "dpia" in article_keys or special_category else "unknown",
        "RoPA_reference": "",
        "breach_relevance": "security_exposure_dependent",
        "data_presence": True,
        "compliance_violation": False,
        "scope_candidate": True,
        "needs_review": bool(special_category or article_10),
        "gdpr_article_mappings": [_article_mapping(key, "classification") for key in article_keys],
    }


def custom_context_metadata(group: dict, matched_keywords: list[str]) -> dict:
    mode = str(group.get("mode") or group.get("rule_mode") or "CONTEXT_ONLY").strip().upper() or "CONTEXT_ONLY"
    return {
        "type": str(group.get("type") or "gdpr_custom_context"),
        "framework": "gdpr",
        "risk": str(group.get("risk") or "LOW").upper() if str(group.get("risk") or "LOW").upper() in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "LOW",
        "description": "Tenant-defined GDPR context keyword matched. Context-only rules require analyst review and do not confirm personal data by themselves.",
        "count": len(matched_keywords),
        "occurrence_count": len(matched_keywords),
        "unique_value_count": len({item.lower() for item in matched_keywords}),
        "samples": [],
        "framework": "gdpr",
        "category": str(group.get("category") or "custom_context"),
        "tier": "context",
        "label": str(group.get("label") or str(group.get("type") or "Custom GDPR Context").replace("_", " ").title()),
        "matched_keywords": matched_keywords,
        "custom_rule_mode": mode,
        "finding_role": "custom_context_observation",
        "data_presence": False,
        "compliance_violation": False,
        "scope_candidate": False,
        "needs_review": True,
        "gdpr_article_mappings": [],
    }


def value_fingerprinter(tenant_id: str = "default"):
    """``secure_value_fingerprint`` with the key resolved once (W4.3): a file's values share it."""
    key = f"{evidence_hmac_key()}:{tenant_id}".encode("utf-8")

    def fingerprint(value: str) -> str:
        normalized = " ".join(str(value or "").strip().split()).lower()
        return hmac.new(key, f"gdpr-value-v1:{normalized}".encode("utf-8"), hashlib.sha256).hexdigest()

    return fingerprint


def secure_value_fingerprint(value: str, tenant_id: str = "default") -> str:
    secret = evidence_hmac_key()
    normalized = " ".join(str(value or "").strip().split()).lower()
    return hmac.new(f"{secret}:{tenant_id}".encode("utf-8"), f"gdpr-value-v1:{normalized}".encode("utf-8"), hashlib.sha256).hexdigest()


def _article_mapping(key: str, mapping_type: str) -> dict:
    article = GDPR_ARTICLE_CATALOG[key]
    return {
        "legal_area": key,
        "article": article["article"],
        "title": article["title"],
        "mapping_type": mapping_type,
        "mapping_confidence": "high",
        "violation": False,
    }


def _personal_data_type(finding_type: str, category: str, special_category: str, article_10: bool) -> str:
    if special_category:
        return "special_category_personal_data"
    if article_10:
        return "criminal_convictions_and_offences_data"
    if "government" in category or finding_type in {"gdpr_fin_pin", "gdpr_national_id", "gdpr_passport_number"}:
        return "official_identifier"
    if "online" in category or finding_type.startswith("gdpr_ip") or finding_type.startswith("gdpr_cookie"):
        return "online_identifier"
    return "personal_data"
