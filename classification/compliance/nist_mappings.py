from __future__ import annotations


NIST_DATA_CATEGORY_MAP = {
    "nist_privacy_pii": ["pii", "personal_data", "government_ids"],
    "nist_health": ["phi", "health_data"],
    "nist_financial": ["financial_records"],
    "nist_credentials_secrets": ["credentials_secrets", "identity_access"],
    "nist_source_code": ["source_code", "intellectual_property"],
    "nist_security_operations": ["security_operations"],
    "nist_legal": ["legal_documents"],
    "nist_hr": ["hr_documents", "pii"],
    "nist_customer": ["customer_data", "personal_data"],
    "nist_intellectual_property": ["intellectual_property", "confidential_business"],
}


def nist_data_categories_for_finding(finding: dict) -> list[str]:
    category_id = str(finding.get("category_id") or "")
    category = str(finding.get("category") or "").lower().replace(" ", "_")
    categories = list(NIST_DATA_CATEGORY_MAP.get(category_id, []))
    if not categories:
        if "credential" in category or "secret" in category:
            categories.extend(["credentials_secrets"])
        elif "health" in category:
            categories.extend(["phi", "health_data"])
        elif "financial" in category or "tax" in category:
            categories.extend(["financial_records"])
        elif "legal" in category:
            categories.extend(["legal_documents"])
        elif "customer" in category:
            categories.extend(["customer_data"])
        elif "hr" in category or "human" in category:
            categories.extend(["hr_documents"])
        else:
            categories.extend(["confidential_business"])
    return list(dict.fromkeys(categories))


def nist_framework_mapping_row(finding: dict) -> dict:
    return {
        "framework": "NIST SP 800-60 Enterprise",
        "framework_id": "nist_sp800_60_enterprise",
        "category": finding.get("category") or "",
        "category_id": finding.get("category_id") or "",
        "matched_data_categories": nist_data_categories_for_finding(finding),
        "source_basis": finding.get("framework_mappings") or [],
        "confidence": finding.get("confidence") or "medium",
        "evidence": {
            "rule_id": finding.get("rule_id"),
            "catalog_version": finding.get("catalog_version"),
            "catalog_hash": finding.get("catalog_hash"),
            "matched_signal_groups": finding.get("matched_signal_groups") or [],
            "samples": finding.get("samples") or [],
        },
    }

