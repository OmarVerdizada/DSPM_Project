from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass(frozen=True)
class ComplianceMapping:
    framework: str
    control: str
    reason: str
    finding_type: str

    def to_dict(self) -> dict:
        return asdict(self)


FINDING_TYPE_ALIASES = {
    "private_key": "private_key_exposure",
    "private cryptographic key": "private_key_exposure",
    "jwt": "jwt_token_exposure",
    "jwt_token": "jwt_token_exposure",
    "api_key": "secret_exposure",
    "password": "secret_exposure",
    "secret": "secret_exposure",
    "connection_string": "secret_exposure",
    "aws_access_key": "secret_exposure",
    "azure_access_token": "secret_exposure",
    "pii": "pii_exposure",
    "personal_data": "pii_exposure",
    "email": "pii_exposure",
    "phone_number": "pii_exposure",
    "credit_card": "payment_data_exposure",
    "payment_card": "payment_data_exposure",
    "financial_data": "payment_data_exposure",
    "iban": "payment_data_exposure",
    "public": "public_exposure",
    "public_link": "public_exposure",
    "public_share": "public_exposure",
    "over_permissioned": "permission_risk",
    "permission": "permission_risk",
    "acl": "permission_risk",
}


COMPLIANCE_MAPPINGS = {
    "private_key_exposure": [
        ComplianceMapping("ISO 27001", "A.5/A.8/A.10", "Cryptographic key material requires controlled handling.", "private_key_exposure"),
        ComplianceMapping("SOC 2", "Security CC6/CC7", "Credential exposure can affect logical access controls.", "private_key_exposure"),
    ],
    "jwt_token_exposure": [
        ComplianceMapping("ISO 27001", "A.5/A.8", "Session tokens require access control and protection.", "jwt_token_exposure"),
        ComplianceMapping("SOC 2", "Security CC6", "Token exposure can weaken authentication boundaries.", "jwt_token_exposure"),
    ],
    "secret_exposure": [
        ComplianceMapping("ISO 27001", "A.5/A.8", "Secrets and credentials require protection from unauthorized access.", "secret_exposure"),
        ComplianceMapping("SOC 2", "Security CC6/CC7", "Credential leakage can affect access and monitoring controls.", "secret_exposure"),
    ],
    "pii_exposure": [
        ComplianceMapping("GDPR", "Articles 5 and 32", "Personal data must be protected with appropriate security.", "pii_exposure"),
        ComplianceMapping("SOC 2", "Confidentiality C1", "Personal data exposure may affect confidentiality commitments.", "pii_exposure"),
    ],
    "payment_data_exposure": [
        ComplianceMapping("PCI DSS", "Requirement 3", "Stored cardholder data must be protected.", "payment_data_exposure"),
        ComplianceMapping("GDPR", "Articles 5 and 32", "Financial personal data requires appropriate security.", "payment_data_exposure"),
    ],
    "public_exposure": [
        ComplianceMapping("ISO 27001", "A.5/A.8", "Public sharing can violate information access restrictions.", "public_exposure"),
        ComplianceMapping("SOC 2", "Security CC6", "Public access may weaken logical access controls.", "public_exposure"),
    ],
    "permission_risk": [
        ComplianceMapping("ISO 27001", "A.5/A.8", "Excessive access conflicts with least-privilege controls.", "permission_risk"),
        ComplianceMapping("SOC 2", "Security CC6", "Permissions should be limited to authorized users.", "permission_risk"),
    ],
}


def normalize_finding_type(finding_type: str | None) -> str:
    raw = str(finding_type or "").strip().lower().replace("-", "_")
    return FINDING_TYPE_ALIASES.get(raw, raw)


def normalize_framework(framework: str | None) -> str | None:
    if not framework:
        return None
    value = str(framework).strip().lower().replace("-", " ")
    aliases = {
        "gdpr": "GDPR",
        "iso": "ISO 27001",
        "iso 27001": "ISO 27001",
        "soc2": "SOC 2",
        "soc 2": "SOC 2",
        "pci": "PCI DSS",
        "pci dss": "PCI DSS",
    }
    return aliases.get(value, str(framework).strip().upper())


def get_compliance_for_finding(finding_type: str | None, framework: str | None = None) -> list[ComplianceMapping]:
    normalized = normalize_finding_type(finding_type)
    requested_framework = normalize_framework(framework)
    mappings = COMPLIANCE_MAPPINGS.get(normalized, [])
    if requested_framework:
        mappings = [mapping for mapping in mappings if mapping.framework == requested_framework]
    return list(mappings)


def _iter_finding_types(findings: Iterable[dict]) -> Iterable[str]:
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if finding.get("type"):
            yield str(finding.get("type"))
        nested = finding.get("findings")
        if isinstance(nested, list):
            for child in nested:
                if isinstance(child, dict) and child.get("type"):
                    yield str(child.get("type"))


def get_compliance_summary(findings: Iterable[dict], framework: str | None = None) -> dict:
    summary: dict[str, dict] = {"frameworks": {}, "total_mapped_findings": 0}
    for finding_type in _iter_finding_types(findings):
        mappings = get_compliance_for_finding(finding_type, framework)
        if not mappings:
            continue
        for mapping in mappings:
            row = summary["frameworks"].setdefault(
                mapping.framework,
                {"finding_count": 0, "controls": {}, "finding_types": []},
            )
            row["finding_count"] += 1
            row["controls"].setdefault(mapping.control, mapping.reason)
            if mapping.finding_type not in row["finding_types"]:
                row["finding_types"].append(mapping.finding_type)
            summary["total_mapped_findings"] += 1
    return summary
