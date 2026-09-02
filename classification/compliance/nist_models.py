from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


NIST_FRAMEWORK_ID = "nist_sp800_60_enterprise"
NIST_DISPLAY_NAME = "NIST SP 800-60 Enterprise"
NIST_DETECTOR_VERSION = "nist-sp800-60-detector-v1"

DetectionMode = Literal[
    "DOCUMENT_MARKING_AND_CONTEXT",
    "ENTITY_CONTEXT_COMPOSITE",
    "VALUE_PATTERN_PLUS_CONTEXT",
    "SECRET_PATTERN_COMPOSITE",
    "TECHNICAL_ARTIFACT_COMPOSITE",
]
CiaImpact = Literal["LOW", "MODERATE", "HIGH"]
ProductSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
HandlingTier = Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]


class NISTModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class NISTCIA(NISTModel):
    confidentiality: CiaImpact
    integrity: CiaImpact
    availability: CiaImpact
    overall: CiaImpact


class NISTCategory(NISTModel):
    category: str
    category_id: str
    label_az: str
    rule_count: int
    source_kind: str
    context_terms_en: list[str] = Field(default_factory=list)
    context_terms_az: list[str] = Field(default_factory=list)
    negative_context: list[str] = Field(default_factory=list)
    default_cia: NISTCIA


class NISTRegexPattern(NISTModel):
    id: str
    pattern: str
    flags: str = ""
    validator: str = ""
    confidence: str = ""
    notes: str = ""


class NISTKeywordGroups(NISTModel):
    primary_and_aliases: list[str]
    schema_and_field_names: list[str] = Field(default_factory=list)
    azerbaijani_terms: list[str] = Field(default_factory=list)
    supporting_context: list[str] = Field(default_factory=list)
    negative_and_exclusion_context: list[str] = Field(default_factory=list)


class NISTDetection(NISTModel):
    mode: DetectionMode
    minimum_context_score: int = 0
    proximity_characters: int = 0
    keyword_groups: NISTKeywordGroups
    regex_patterns: list[NISTRegexPattern] = Field(default_factory=list)
    conditions: list[str] = Field(default_factory=list)
    score_model: dict[str, Any] = Field(default_factory=dict)
    allowed_file_types: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)


class NISTClassification(NISTModel):
    product_severity: ProductSeverity
    base_risk_score: int
    confidentiality_impact: CiaImpact
    integrity_impact: CiaImpact
    availability_impact: CiaImpact
    overall_impact: CiaImpact
    impact_basis: str
    risk_modifiers: list[dict[str, Any]] = Field(default_factory=list)


class NISTRule(NISTModel):
    rule_id: str
    framework: Literal["nist_sp800_60_enterprise"]
    source_kind: str
    source_catalog: str = ""
    source_version: str = ""
    source_status: str = ""
    category: str
    category_id: str
    data_type: str
    type: str
    label: str
    label_az: str = ""
    tier_original: str
    handling_tier: HandlingTier
    why: str
    cui_control_type: str | None = None
    official_definition_en: str
    operational_definition_az: str
    classification: NISTClassification
    detection: NISTDetection
    correlation: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: list[str]
    framework_mappings: list[dict[str, Any]] = Field(default_factory=list)
    governance: dict[str, Any] = Field(default_factory=dict)
    test_cases: list[dict[str, Any]]


class NISTCatalogEnvelope(NISTModel):
    framework: Literal["nist_sp800_60_enterprise"]
    language: str
    mode: str
    catalog: dict[str, Any]
    global_models: dict[str, Any]
    categories: list[NISTCategory]
    rules: list[NISTRule]


class NISTValidationResult(NISTModel):
    valid: bool
    framework: str = NIST_FRAMEWORK_ID
    catalog_version: str = ""
    schema_version: str = ""
    source_version: str = ""
    source_status: str = ""
    rule_count: int = 0
    category_count: int = 0
    added_rules: int = 0
    updated_rules: int = 0
    removed_rules: int = 0
    unchanged_rules: int = 0
    conflicts: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    duplicate_rule_ids: list[str] = Field(default_factory=list)
    duplicate_types: list[str] = Field(default_factory=list)
    invalid_regex: list[dict[str, str]] = Field(default_factory=list)
    invalid_mappings: list[str] = Field(default_factory=list)
    test_case_count: int = 0
    catalog_hash: str = ""
    approval_required: bool = False

