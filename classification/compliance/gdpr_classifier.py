from __future__ import annotations

import os
import re
import threading
import time

from classification.compliance.country_identifiers import validate_country_identifier
from classification.compliance.canonical_entities import canonical_entity_fingerprint, canonical_entity_type_for_finding
from classification.compliance.gdpr_metadata import custom_context_metadata, gdpr_metadata_for_finding, secure_value_fingerprint
from classification.compliance.gdpr_rules import GDPR_RULES
from classification.compliance.keyword_index import compiled_keyword_index
from classification.compliance.validators import redact


NON_PERSONAL_CONTEXT_RULE_TYPES = {
    "gdpr_source_code_algorithm",
    "gdpr_trade_secret_design",
    "gdpr_patent_pending_unfiled",
    "gdpr_ma_due_diligence",
    "gdpr_board_materials_minutes",
    "gdpr_strategy_roadmap_plan",
    "gdpr_contract_nda_legal",
    "gdpr_litigation_privileged_legal",
    "gdpr_vendor_supplier_terms",
    "gdpr_network_architecture_diagram",
    "gdpr_vulnerability_pentest_report",
    "gdpr_security_config_firewall_rule",
}
GDPR_DETECTOR_VERSION = "gdpr-detector-v2"
GDPR_RULE_CATALOG_VERSION = "gdpr-rules-v2"
GDPR_DETECTOR_TIMEOUT_SECONDS = float(os.getenv("DSPM_GDPR_DETECTOR_TIMEOUT_SECONDS", "8"))
ALWAYS_RUN_RULE_TYPES = {
    "gdpr_full_name",
    "gdpr_email_address",
    "gdpr_phone_number",
    "gdpr_postal_address",
    "gdpr_birth_details",
    "gdpr_fin_pin",
    "gdpr_national_id",
    "gdpr_passport_number",
    "gdpr_signature",
    "gdpr_payment_card_data",
    "gdpr_bank_account_data",
    "gdpr_password_secret",
    "gdpr_api_token_oauth_secret",
    "gdpr_private_key_certificate_secret",
    "gdpr_database_connection_string",
    "gdpr_session_token_jwt",
}
RULE_PREFILTER_TERMS = {
    rule.finding_type: tuple(" ".join(str(keyword or "").strip().split()).lower() for keyword in rule.keywords if keyword)
    for rule in GDPR_RULES
}

# Perf: the builtin GDPR keyword catalog (~40k terms across 67 rules) is STATIC, so
# building the group list and its sha256 signature on every file - just to look up
# the already-cached Aho-Corasick index - wasted ~60 ms/file. Cache the index by a
# cheap key over only the (usually empty) custom groups; the builtin catalog is
# pinned by catalog_version.
_GDPR_INDEX_CACHE: dict = {}
_GDPR_INDEX_LOCK = threading.Lock()


def _custom_groups_key(custom_keyword_groups: list[dict]) -> tuple:
    return tuple(sorted(
        (
            str(group.get("type") or ""),
            str(group.get("language") or ""),
            tuple(sorted({str(term).strip().lower() for term in (group.get("terms") or []) if str(term).strip()})),
        )
        for group in custom_keyword_groups
    ))


def _gdpr_keyword_index(custom_keyword_groups: list[dict], catalog_version: str, language: str):
    key = (catalog_version, language, _custom_groups_key(custom_keyword_groups))
    with _GDPR_INDEX_LOCK:
        cached = _GDPR_INDEX_CACHE.get(key)
    if cached is not None:
        return cached
    index = compiled_keyword_index(
        framework="gdpr",
        catalog_version=catalog_version,
        language=language,
        groups=_gdpr_keyword_groups(custom_keyword_groups),
    )
    with _GDPR_INDEX_LOCK:
        _GDPR_INDEX_CACHE[key] = index
    return index


def classify_gdpr_content(content: str, metadata: dict | None = None, custom_keyword_groups: list[dict] | None = None) -> list[dict]:
    if not content and not metadata:
        return []

    metadata = metadata or {}
    findings: list[dict] = []
    finding_index: dict[str, dict] = {}
    evidence_blob = " ".join(
        [
            content or "",
            str(metadata.get("name") or ""),
            str(metadata.get("path") or ""),
            str(metadata.get("extension") or ""),
        ]
    ).lower()
    tenant_id = str(metadata.get("tenant_id") or metadata.get("tenant") or "default")
    keyword_index = _gdpr_keyword_index(
        custom_keyword_groups or [],
        str(metadata.get("rule_catalog_version") or GDPR_RULE_CATALOG_VERSION),
        str(metadata.get("language") or "all"),
    )
    indexed_keyword_matches = keyword_index.search(evidence_blob)
    started = time.perf_counter()
    skipped_by_prefilter = 0
    timed_out = False
    normalized_content_length = len(content or "")
    for rule in GDPR_RULES:
        if time.perf_counter() - started > GDPR_DETECTOR_TIMEOUT_SECONDS:
            timed_out = True
            break
        if rule.finding_type in NON_PERSONAL_CONTEXT_RULE_TYPES:
            continue
        if not _rule_prefilter(rule.finding_type, evidence_blob, metadata, indexed_keyword_matches):
            skipped_by_prefilter += 1
            continue
        matches = []
        raw_fingerprints = []
        canonical_fingerprints = []
        occurrences = []
        occurrence_count = 0
        first_raw_value = ""
        entity_type = canonical_entity_type_for_finding({"type": rule.finding_type, "category": rule.category})
        for value in rule.detector(content or "", metadata):
            occurrence_count += 1
            if not first_raw_value:
                first_raw_value = str(value or "")
            fingerprint = secure_value_fingerprint(value, tenant_id)
            if fingerprint not in raw_fingerprints:
                raw_fingerprints.append(fingerprint)
            if entity_type:
                canonical_fingerprint = canonical_entity_fingerprint(entity_type, value, tenant_id)
                if canonical_fingerprint not in canonical_fingerprints:
                    canonical_fingerprints.append(canonical_fingerprint)
            redacted = redact(value)
            if redacted not in matches:
                matches.append(redacted)
            if len(occurrences) < 20:
                occurrences.append(_location_for_value(content or "", value, redacted, metadata, occurrence_count))
        if not matches:
            continue
        matched_keywords = indexed_keyword_matches.get(rule.finding_type, [])[:10]
        finding = {
            "type": rule.finding_type,
            "risk": rule.risk,
            "description": rule.description,
            "count": occurrence_count,
            "occurrence_count": occurrence_count,
            "unique_value_count": len(raw_fingerprints),
            "sample_count": len(matches[:10]),
            "samples": matches[:10],
            "occurrences": occurrences,
            "secure_value_fingerprints": raw_fingerprints[:10],
            "canonical_entity_type": entity_type,
            "canonical_entity_fingerprints": canonical_fingerprints[:10],
            "framework": "gdpr",
            "category": rule.category,
            "tier": rule.tier,
            "label": rule.label,
            "matched_keywords": matched_keywords,
            "detector_version": GDPR_DETECTOR_VERSION,
            "rule_catalog_version": GDPR_RULE_CATALOG_VERSION,
            "detector_metrics": {
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "prefilter_skipped_rules": skipped_by_prefilter,
                "timed_out": timed_out,
                "content_length": normalized_content_length,
                "prefilter": "aho_corasick_keyword_index",
                "keyword_index_created_at": keyword_index.created_at,
                "keyword_index_catalog_version": keyword_index.catalog_version,
            },
            **gdpr_metadata_for_finding(rule.finding_type, rule.category),
        }
        if "pseudonym" in evidence_blob or "pseudonymous" in evidence_blob:
            finding["pseudonymized"] = True
            finding["anonymized"] = False
        if rule.finding_type == "gdpr_fin_pin":
            finding["country_identifier"] = validate_country_identifier("AZ", "FIN", first_raw_value, evidence_blob)
        findings.append(finding)
        finding_index[rule.finding_type] = finding
    _apply_custom_keyword_groups(indexed_keyword_matches, findings, finding_index, custom_keyword_groups or [])
    return findings


def _apply_custom_keyword_groups(indexed_keyword_matches: dict[str, list[str]], findings: list[dict], finding_index: dict[str, dict], groups: list[dict]) -> None:
    if not groups:
        return
    rule_map = {rule.finding_type: rule for rule in GDPR_RULES}
    for group in groups:
        finding_type = str(group.get("type") or "").strip()
        rule = rule_map.get(finding_type)
        if not rule and not _is_custom_group(group):
            continue
        matched_keywords = indexed_keyword_matches.get(finding_type, [])[:10]
        if not matched_keywords:
            continue
        finding = finding_index.get(finding_type)
        if not finding:
            findings.append(custom_context_metadata(group, matched_keywords))
            continue
        existing = set(finding.get("matched_keywords") or [])
        for keyword in matched_keywords:
            if keyword not in existing:
                finding.setdefault("matched_keywords", []).append(keyword)
                existing.add(keyword)


def _keyword_matches(evidence_blob: str, keyword: str) -> bool:
    normalized = " ".join(str(keyword or "").strip().split()).lower()
    if not normalized:
        return False
    if normalized[0].isalnum() and normalized[-1].isalnum():
        return re.search(rf"(?<![A-Za-z0-9_]){re.escape(normalized)}(?![A-Za-z0-9_])", evidence_blob) is not None
    return normalized in evidence_blob


def _rule_prefilter(finding_type: str, evidence_blob: str, metadata: dict, indexed_keyword_matches: dict[str, list[str]]) -> bool:
    if finding_type in ALWAYS_RUN_RULE_TYPES:
        return True
    extension = str(metadata.get("extension") or "").lower()
    if finding_type == "gdpr_photo_face_image" and extension in {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif", ".tif", ".tiff", ".heic", ".heif", ".pdf"}:
        return True
    return bool(indexed_keyword_matches.get(finding_type))


def _gdpr_keyword_groups(custom_keyword_groups: list[dict]) -> list[dict]:
    groups = [
        {
            "framework": "gdpr",
            "language": "built-in",
            "type": rule.finding_type,
            "terms": list(rule.keywords),
        }
        for rule in GDPR_RULES
    ]
    for group in custom_keyword_groups:
        if group.get("terms"):
            groups.append(
                {
                    "framework": "gdpr",
                    "language": group.get("language") or "custom",
                    "type": group.get("type") or "",
                    "terms": list(group.get("terms") or []),
                }
            )
    return groups


def _is_custom_group(group: dict) -> bool:
    return bool(group.get("category") and group.get("label") and group.get("risk"))


def _location_for_value(content: str, value: str, redacted: str, metadata: dict, ordinal: int) -> dict:
    start = content.find(str(value or ""))
    if start < 0:
        start = 0
    end = start + len(str(value or ""))
    line = content.count("\n", 0, start) + 1 if content else 1
    return {
        "sample": redacted,
        "occurrence_index": ordinal,
        "file": metadata.get("path") or metadata.get("name") or "",
        "offset_start": start,
        "offset_end": end,
        "line": line,
        "page": metadata.get("page") or None,
        "sheet": metadata.get("sheet") or None,
        "row": metadata.get("row") or None,
        "column": metadata.get("column") or None,
        "JSONPath": metadata.get("json_path") or metadata.get("JSONPath") or "",
        "XPath": metadata.get("xpath") or metadata.get("XPath") or "",
        "database": metadata.get("database") or "",
        "schema": metadata.get("schema") or "",
        "table": metadata.get("table") or "",
        "record_identifier": metadata.get("record_id") or metadata.get("id") or "",
    }
