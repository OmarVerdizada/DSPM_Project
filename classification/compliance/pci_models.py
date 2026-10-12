from __future__ import annotations

from dataclasses import dataclass, field


def pci_data_category(pci_category: str) -> str:
    category = str(pci_category or "").upper()
    if category == "SAD":
        return "pci_sensitive_authentication_data"
    if category == "CHD":
        return "pci_cardholder_data"
    return "pci_scope_context"


@dataclass(frozen=True, slots=True)
class PCIFinding:
    finding_type: str
    label: str
    risk: str
    description: str
    pci_category: str
    pci_treatment: str
    protection_state: str
    confidence: int
    count: int
    rule_id: str = ""
    data_element: str = ""
    finding_category: str = "Data Presence"
    samples: list[str] = field(default_factory=list)
    matched_keywords: list[str] = field(default_factory=list)
    secure_fingerprints: list[str] = field(default_factory=list)
    canonical_entity_type: str = ""
    canonical_entity_fingerprints: list[str] = field(default_factory=list)
    pci_requirements: list[str] = field(default_factory=list)
    requirement_mappings: list[dict] = field(default_factory=list)
    severity_rationale: str = "Readable full PAN is the anchor element that brings storage locations and connected systems into PCI DSS scope."
    remediation: str = "Remove unapproved PAN storage, make retained PAN unreadable with validated PCI controls, restrict access, and verify retention need."
    correlated_elements: list[str] = field(default_factory=list)
    logical_boundary: str = "text_proximity_window"
    source_format: str = "unstructured_text"
    environment: str = "unknown"
    storage_state: str = "unknown"
    entity_role: str = "unknown"
    authorization_state: str = "unknown"
    scope_candidate: bool = True
    exception_required: bool = False
    exception_status: str = "not_required"
    exception_reason: str = ""
    review_status: str = "unreviewed"
    display_state: str = "primary"
    parent_finding_type: str = ""
    child_finding_types: list[str] = field(default_factory=list)
    suppressed_by: list[str] = field(default_factory=list)
    claimed_protection_state: str = "NOT_CLAIMED"
    verified_protection_state: str = ""
    impact_severity: str = "CRITICAL"
    detection_confidence: int = 0
    validation_status: str = "CONFIRMED"
    operational_risk_score: int = 0
    fingerprint_algorithm: str = "HMAC-SHA-256"
    fingerprint_key_version: str = "tenant-evidence-v1"
    tenant_id: str = "default"
    rotation_version: str = "v1"
    card_brand: str = "unknown"
    pan_length_valid_for_brand: bool = False
    # Why this digit run was accepted as a card, and how strongly.
    pan_confidence: str = ""
    pan_issuer: str = ""
    pan_context_terms: list[str] = field(default_factory=list)
    pan_density: int = 0
    pan_validator_version: str = ""
    confidence_basis: str = ""
    test_card: bool = False
    test_card_label: str = ""
    iin_bin: str = ""
    bin_metadata_version: str = ""
    synthetic_value: bool = False
    synthetic_value_confidence_reduction: int = 0
    production_test_pan_policy: bool = False

    def to_dict(self) -> dict:
        return {
            "type": self.finding_type,
            "framework": "pci_dss",
            "risk": self.risk,
            "category": pci_data_category(self.pci_category),
            "pci_category": self.pci_category,
            "official_category": "Sensitive Authentication Data" if self.pci_category == "SAD" else "Cardholder Data" if self.pci_category == "CHD" else "Contextual PCI Signal",
            "rule_id": self.rule_id,
            "data_element": self.data_element,
            "finding_category": self.finding_category,
            "pci_treatment": self.pci_treatment,
            "label": self.label,
            "description": self.description,
            "count": self.count,
            "samples": self.samples,
            "matched_keywords": self.matched_keywords,
            "confidence": self.confidence,
            "protection_state": self.protection_state,
            "claimed_protection_state": self.claimed_protection_state,
            "verified_protection_state": self.verified_protection_state or self.protection_state,
            "impact_severity": self.impact_severity,
            "detection_confidence": self.detection_confidence or self.confidence,
            "validation_status": self.validation_status,
            "operational_risk_score": self.operational_risk_score or self.confidence,
            "secure_fingerprints": self.secure_fingerprints,
            "canonical_entity_type": self.canonical_entity_type,
            "canonical_entity_fingerprints": self.canonical_entity_fingerprints,
            "fingerprint_algorithm": self.fingerprint_algorithm,
            "fingerprint_key_version": self.fingerprint_key_version,
            "tenant_id": self.tenant_id,
            "rotation_version": self.rotation_version,
            "card_brand": self.card_brand,
            "pan_length_valid_for_brand": self.pan_length_valid_for_brand,
            **({
                "pan_confidence": self.pan_confidence,
                "pan_issuer": self.pan_issuer,
                "pan_context_terms": self.pan_context_terms,
                "pan_density": self.pan_density,
                "pan_validator_version": self.pan_validator_version,
                "confidence_basis": self.confidence_basis,
            } if self.pan_confidence else {}),
            "test_card": self.test_card,
            "test_card_label": self.test_card_label,
            "iin_bin": self.iin_bin,
            "bin_metadata_version": self.bin_metadata_version,
            "synthetic_value": self.synthetic_value,
            "synthetic_value_confidence_reduction": self.synthetic_value_confidence_reduction,
            "production_test_pan_policy": self.production_test_pan_policy,
            "pci_requirements": self.pci_requirements,
            "requirement_mappings": self.requirement_mappings,
            "severity_rationale": self.severity_rationale,
            "remediation": self.remediation,
            "correlated_elements": self.correlated_elements,
            "logical_boundary": self.logical_boundary,
            "source_format": self.source_format,
            "environment": self.environment,
            "storage_state": self.storage_state,
            "entity_role": self.entity_role,
            "authorization_state": self.authorization_state,
            "scope_candidate": self.scope_candidate,
            "exception_required": self.exception_required,
            "exception_status": self.exception_status,
            "exception_reason": self.exception_reason,
            "review_status": self.review_status,
            "display_state": self.display_state,
            "parent_finding_type": self.parent_finding_type,
            "child_finding_types": self.child_finding_types,
            "suppressed_by": self.suppressed_by,
        }
