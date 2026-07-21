from __future__ import annotations

from backend.copilot.skills.scan_comparison import finding_history, risk_types
from backend.security import Principal


COMPLIANCE_MAP = {
    "pii": ["GDPR Art. 5", "GDPR Art. 32"],
    "personal_data": ["GDPR Art. 5", "GDPR Art. 32"],
    "email": ["GDPR Art. 5", "GDPR Art. 32"],
    "phone_number": ["GDPR Art. 5", "GDPR Art. 32"],
    "azerbaijan_fin": ["GDPR Art. 5", "GDPR Art. 32"],
    "payment_card": ["PCI-DSS Req. 3"],
    "credit_card": ["PCI-DSS Req. 3"],
    "private_key": ["ISO 27001 Annex A.8/A.10", "SOC 2 Security"],
    "private cryptographic key": ["ISO 27001 Annex A.8/A.10", "SOC 2 Security"],
    "jwt": ["ISO 27001 Access Control", "SOC 2 Security"],
    "api_key": ["ISO 27001 Access Control", "SOC 2 Security"],
}


def compliance_mapping(principal: Principal, identifier: str | None = None) -> dict:
    history = finding_history(principal, identifier)
    item = history.get("item") or {}
    detected = [str(value) for value in item.get("risk_types") or []]
    frameworks: dict[str, list[str]] = {}
    for value in detected:
        mapped = COMPLIANCE_MAP.get(value.lower())
        if not mapped:
            continue
        frameworks[value] = mapped
    return {
        "result_type": "compliance_mapping",
        "assessment": "may_indicate_compliance_risk",
        "legal_advice": False,
        "item": item,
        "risk_types": detected,
        "frameworks": frameworks,
        "history": {
            "is_new": history.get("is_new"),
            "seen_in_previous_scan": history.get("seen_in_previous_scan"),
            "recurring_since": history.get("recurring_since"),
            "previous_scan_ids": history.get("previous_scan_ids") or [],
        },
    }

