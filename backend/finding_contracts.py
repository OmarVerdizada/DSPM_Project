from __future__ import annotations

import re
from typing import Any


CANONICAL_FRAMEWORKS = {
    "gdpr": "gdpr",
    "pci": "pci_dss",
    "pci_dss": "pci_dss",
    "pci dss": "pci_dss",
    "nist": "nist_sp800_60_enterprise",
    "nist_sp800_60": "nist_sp800_60_enterprise",
    "nist sp800 60": "nist_sp800_60_enterprise",
    "nist_sp800_60_enterprise": "nist_sp800_60_enterprise",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "": 4}

NIST_RULE_NAME_TAXONOMY = {
    "nist_identity_management": ["User Identity Records", "Account Registry Records", "Access Entitlement Records", "Privileged Access Records", "Authentication Event Records", "Identity Proofing Records", "Directory Synchronization Records"],
    "nist_privacy_pii": ["Sensitive Personally Identifiable Information", "General Privacy Information", "Contact Information", "Government Identifier Records", "Demographic Records", "Biometric Identifier Records", "Online Identifier Records", "Location Privacy Records", "Household and Family Records", "Financial Privacy Records", "Education Privacy Records", "Employment Privacy Records", "Health Privacy Records", "Behavioral Privacy Records", "Consent and Preference Records", "Privacy Case Records"],
    "nist_financial": ["Financial Account Records", "Payment Card and Transaction Records", "Bank Routing and Transfer Records", "Invoice and Billing Records", "Payroll Financial Records", "Treasury and Cash Management Records", "Audit-Ready Financial Statements"],
    "nist_health": ["Health Information", "Clinical Encounter Records", "Medication and Prescription Records", "Insurance and Benefits Records", "Genetic Information", "Mental Health and Substance Use Records", "Medical Device and Laboratory Records"],
    "nist_legal": ["Legal Matter Records", "Contract Records", "Law Enforcement Records", "Litigation Hold Records", "Case Investigation Records", "Regulatory Filing Records", "Evidence and Discovery Records"],
    "nist_hr": ["Personnel Records", "Military Personnel Records", "Employee Benefits Records", "Recruiting and Applicant Records", "Performance Review Records", "Workforce Investigation Records", "Training and Certification Records"],
    "nist_customer": ["Customer Records", "CRM Account Records", "Customer Support Records", "Sales Opportunity Records", "Customer Contract Records", "Customer Billing Records", "Customer Communications Records"],
    "nist_research": ["Research Data", "Experiment Results", "Clinical Research Records", "Product Design Records", "Prototype Evaluation Records", "Grant and Sponsored Research Records", "Research Collaboration Records"],
    "nist_security_operations": ["Sensitive Security Information", "Vulnerability Scans and Penetration Test Reports", "Incident Response Records", "Threat Intelligence Records", "Security Monitoring Logs", "Security Architecture Review Records", "Security Exception Records"],
    "nist_credentials_secrets": ["API Keys, Access Tokens and OAuth Secrets", "Private Keys and Certificates", "Service Account Credentials", "Database Connection Secrets", "Cloud Access Credentials", "Encryption Key Material", "Password and Recovery Secrets"],
    "nist_source_code": ["Source Code and Algorithms", "Build Pipeline Records", "Repository Metadata", "Software Bill of Materials", "Release and Deployment Records", "Code Review Records", "Package Signing Records"],
    "nist_infrastructure": ["Network Diagrams and Architecture", "System Architecture Records", "Firewall and Routing Configurations", "Cloud Infrastructure Inventory", "Endpoint and Server Inventory", "Privileged Infrastructure Access Records", "Backup and Recovery Architecture"],
    "nist_procurement": ["Procurement Records", "Vendor Due Diligence Records", "Purchase Order Records", "Supplier Contract Records", "Third-Party Risk Records", "Solicitation and Bid Records", "Vendor Performance Records"],
    "nist_export_control": ["Controlled Technical Information", "Export Controlled Research Records", "ITAR Technical Data", "EAR Controlled Technology Records", "Sanctions Screening Records", "Foreign National Access Records"],
    "nist_tax": ["Federal Taxpayer Information", "Tax Return Records", "Tax Account Transcripts", "Withholding and Payroll Tax Records", "Treasury Reporting Records", "Tax Audit Records"],
    "nist_audit": ["Audit and Compliance Evidence", "Control Test Evidence", "Policy Exception Records", "Risk Assessment Records", "Compliance Attestation Records", "Internal Audit Workpapers"],
    "nist_education": ["Student Records", "Academic Transcript Records", "Enrollment and Registration Records", "Financial Aid Records", "Student Conduct Records", "Education Accommodation Records"],
    "nist_public_safety": ["Public Safety Information", "Emergency Response Records", "Dispatch and Incident Records", "Critical Infrastructure Safety Records", "Responder Credential Records", "Public Warning Records"],
    "nist_geospatial": ["Geospatial and Facility Information", "Facility Floor Plans", "Critical Site Coordinates", "Utility and Infrastructure Maps", "Asset Location Records", "Restricted Area Mapping Records"],
    "nist_intellectual_property": ["Trade Secrets and Intellectual Property", "Patent Draft Records", "Invention Disclosure Records", "Product Roadmap Records", "Competitive Strategy Records", "Confidential Design Records"],
    "nist_public_context": ["Approved Public Release Context", "Publication Review Records", "Press Release Approval Records", "Public Dataset Release Records", "Disclosure Review Records", "Communication Clearance Records"],
    "nist_records_management": ["Records Retention Metadata", "Legal Hold Metadata", "Disposition Schedule Records", "Archive Inventory Records", "Records Classification Metadata", "Retention Exception Records"],
}

NIST_RULE_NAME_TAXONOMY_AZ = {
    "nist_education": ["Tələbə qeydləri", "Akademik transkript qeydləri", "Qeydiyyat qeydləri", "Maliyyə yardımı qeydləri", "Tələbə intizam qeydləri", "Təhsil uyğunlaşdırma qeydləri"],
    "nist_privacy_pii": ["Həssas şəxsi identifikasiya məlumatı", "Ümumi məxfilik məlumatı"],
    "nist_credentials_secrets": ["API açarları, giriş tokenləri və OAuth sirləri"],
    "nist_export_control": ["Nəzarət olunan texniki məlumat"],
    "nist_tax": ["Federal vergi ödəyicisi məlumatı"],
    "nist_security_operations": ["Həssas təhlükəsizlik məlumatı", "Zəiflik skanları və penetrasiya test hesabatları"],
    "nist_infrastructure": ["Şəbəkə diaqramları və arxitektura"],
}


def normalize_framework_id(value: Any) -> str:
    raw = str(value or "").strip().lower().replace("-", "_")
    squashed = re.sub(r"[^a-z0-9_ ]+", " ", raw).strip()
    compact = re.sub(r"[^a-z0-9]+", "", raw)
    if compact in {"nist", "nistsp80060", "nistsp80060enterprise"}:
        return "nist_sp800_60_enterprise"
    if compact in {"pcidss", "pci"}:
        return "pci_dss"
    return CANONICAL_FRAMEWORKS.get(raw) or CANONICAL_FRAMEWORKS.get(squashed) or (raw if raw in {"hipaa", "iso27001", "nist_csf"} else "generic")


def get_finding_display_name(finding: dict[str, Any], language: str = "en") -> str:
    category_id = str(finding.get("category_id") or finding.get("category") or "").strip().lower().replace(" ", "_")
    is_nist = normalize_framework_id(finding.get("framework")) == "nist_sp800_60_enterprise" or str(finding.get("type") or "").startswith("nist_")
    if is_nist:
        taxonomy_name = _nist_taxonomy_name(finding, category_id, language)
        if taxonomy_name:
            return taxonomy_name
    candidates = []
    if language.lower().startswith("az"):
        candidates.append(finding.get("label_az"))
    candidates.extend(
        [
            finding.get("label"),
            finding.get("data_type"),
            finding.get("service"),
            finding.get("official_name"),
            finding.get("display_name"),
            finding.get("type"),
            finding.get("rule_id"),
        ]
    )
    for value in candidates:
        cleaned = _clean_display_name(value)
        if cleaned:
            return cleaned
    return "Unnamed NIST finding" if is_nist else "Unnamed rule"


def build_nist_finding_detail(finding: dict[str, Any], language: str = "en") -> dict[str, Any]:
    display_name = get_finding_display_name(finding, language)
    return {
        "summary": _section(
            {
                "display_name": display_name,
                "severity": finding.get("product_severity") or finding.get("risk"),
                "confidence": finding.get("confidence"),
                "occurrence_count": finding.get("occurrence_count") or finding.get("count"),
                "framework": "NIST",
                "category": finding.get("category"),
                "handling_tier": finding.get("handling_tier"),
                "overall_impact": finding.get("overall_impact"),
            }
        ),
        "identity": _section(
            {
                "Rule ID": finding.get("rule_id"),
                "Framework": "NIST",
                "Catalog version": finding.get("catalog_version"),
                "Catalog hash": finding.get("catalog_hash"),
                "Source kind": finding.get("source_kind"),
                "Source catalog": finding.get("source_catalog"),
                "Source version": finding.get("source_version"),
                "Source status": finding.get("source_status"),
                "Category": finding.get("category"),
                "Category ID": finding.get("category_id"),
                "Data type": finding.get("data_type"),
                "Technical type": finding.get("type"),
                "Label EN": finding.get("label"),
                "Label AZ": finding.get("label_az"),
                "CUI control type": finding.get("cui_control_type"),
            }
        ),
        "classification": _section(
            {
                "Product severity": finding.get("product_severity"),
                "Base risk score": finding.get("base_risk_score"),
                "Final risk score": finding.get("final_risk_score") or finding.get("risk_score"),
                "Risk factor breakdown": finding.get("risk_factor_breakdown"),
                "Handling tier": finding.get("handling_tier"),
                "Confidentiality impact": finding.get("confidentiality_impact"),
                "Integrity impact": finding.get("integrity_impact"),
                "Availability impact": finding.get("availability_impact"),
                "Overall impact": finding.get("overall_impact"),
                "Impact basis": finding.get("impact_basis"),
                "Confidence": finding.get("confidence"),
                "Confidence score": finding.get("confidence_score"),
                "Review status": finding.get("review_status"),
                "Exception status": finding.get("exception_status"),
            }
        ),
        "detection": _section(
            {
                "Detection mode": finding.get("detection_mode"),
                "Matched signal groups": finding.get("matched_signal_groups"),
                "Contributing signals": finding.get("contributing_signals"),
                "Negative signals": finding.get("negative_signals"),
                "Context score": finding.get("confidence_score"),
                "Threshold": finding.get("threshold"),
                "Logical boundary": finding.get("logical_boundary"),
                "Occurrence count": finding.get("occurrence_count") or finding.get("count"),
            }
        ),
        "source": _section(
            {
                "File/path": finding.get("source_path"),
                "Asset": finding.get("source_asset"),
                "Table": finding.get("source_table"),
                "Column": finding.get("source_column"),
                "Object": finding.get("source_object"),
                "Environment": finding.get("environment"),
                "Storage state": finding.get("storage_state"),
                "Exposure state": finding.get("exposure_state"),
                "Authorization state": finding.get("authorization_state"),
                "Entity role": finding.get("entity_role"),
            }
        ),
        "evidence": _section(
            {
                "Masked preview": finding.get("masked_preview") or finding.get("samples"),
                "Secure fingerprints": finding.get("secure_value_fingerprints") or finding.get("secure_fingerprints"),
                "Why matched": finding.get("why"),
                "Correlation": finding.get("correlation") or finding.get("correlation_references"),
                "Deduplication": finding.get("logical_boundary_id"),
            }
        ),
        "protection": _section(
            {
                "Protection state": finding.get("protection_state"),
                "Claimed protection": finding.get("claimed_protection_state"),
                "Verified protection": finding.get("verified_protection_state"),
                "Algorithm": finding.get("encryption_algorithm") or finding.get("hash_algorithm"),
            }
        ),
        "mappings": _section({"Framework mappings": finding.get("framework_mappings"), "Entity mappings": finding.get("entity_framework_mapping_details")}),
        "remediation": _section({"Remediation": finding.get("remediation"), "Owner": finding.get("owner"), "SLA": finding.get("sla_due"), "Review required": finding.get("needs_review")}),
        "governance": _section({"Governance": finding.get("governance"), "Governance status": finding.get("governance_status"), "Source status": finding.get("source_status"), "Audit references": finding.get("audit_references")}),
    }


def _clean_display_name(value: Any) -> str:
    text = " ".join(str(value or "").replace("_", " ").split())
    if not text:
        return ""
    text = re.sub(r"\bType\s+\d+\b", "", text, flags=re.IGNORECASE).strip(" -:/")
    if not text:
        return ""
    return text[0].upper() + text[1:]


def _section(values: dict[str, Any]) -> dict[str, Any]:
    cleaned = {}
    for key, value in values.items():
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, (list, dict)) and not value:
            continue
        cleaned[key] = value
    return cleaned


def _nist_taxonomy_name(finding: dict[str, Any], category_id: str, language: str) -> str:
    candidates = []
    if language.lower().startswith("az"):
        candidates.append(finding.get("label_az"))
    candidates.extend([finding.get("official_name"), finding.get("service"), finding.get("label"), finding.get("data_type")])
    for value in candidates:
        cleaned = _clean_display_name(value)
        if cleaned and not _is_generated_type_name(value):
            return cleaned
    ordinal = _rule_ordinal(finding)
    taxonomy = NIST_RULE_NAME_TAXONOMY_AZ.get(category_id) if language.lower().startswith("az") else None
    if taxonomy and 1 <= ordinal <= len(taxonomy):
        return taxonomy[ordinal - 1]
    taxonomy = NIST_RULE_NAME_TAXONOMY.get(category_id) or []
    if 1 <= ordinal <= len(taxonomy):
        return taxonomy[ordinal - 1]
    if taxonomy:
        return taxonomy[(ordinal - 1) % len(taxonomy)]
    return ""


def _rule_ordinal(finding: dict[str, Any]) -> int:
    for value in (finding.get("type"), finding.get("rule_id"), finding.get("label"), finding.get("data_type")):
        match = re.search(r"(?:type[_\s-]?|[-_])0*(\d{1,3})\b", str(value or ""), flags=re.IGNORECASE)
        if match:
            return max(1, int(match.group(1)))
    return 1


def _is_generated_type_name(value: Any) -> bool:
    text = str(value or "")
    return bool(re.search(r"\bType\s+\d+\b", text, flags=re.IGNORECASE) or re.search(r"_type_0*\d+\b", text, flags=re.IGNORECASE))
