from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from pydantic import ValidationError

from classification.compliance.nist_models import NISTCatalogEnvelope, NIST_FRAMEWORK_ID, NISTValidationResult


ALLOWED_DETECTION_MODES = {
    "DOCUMENT_MARKING_AND_CONTEXT",
    "ENTITY_CONTEXT_COMPOSITE",
    "VALUE_PATTERN_PLUS_CONTEXT",
    "SECRET_PATTERN_COMPOSITE",
    "TECHNICAL_ARTIFACT_COMPOSITE",
}
ALLOWED_CIA = {"LOW", "MODERATE", "HIGH"}
ALLOWED_SEVERITY = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALLOWED_HANDLING = {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}
MAX_REGEX_LENGTH = 500


def validate_nist_catalog_payload(payload: dict[str, Any], *, active_catalog: dict[str, Any] | None = None) -> NISTValidationResult:
    errors: list[str] = []
    warnings: list[str] = []
    invalid_regex: list[dict[str, str]] = []
    duplicate_rule_ids: list[str] = []
    duplicate_types: list[str] = []
    invalid_mappings: list[str] = []

    if not isinstance(payload, dict):
        return NISTValidationResult(valid=False, errors=["catalog root must be an object"])
    if payload.get("framework") != NIST_FRAMEWORK_ID:
        errors.append(f"framework must be {NIST_FRAMEWORK_ID}")

    try:
        envelope = NISTCatalogEnvelope.model_validate(payload)
    except ValidationError as exc:
        errors.extend(_validation_error_messages(exc))
        envelope = None

    rules = payload.get("rules") if isinstance(payload.get("rules"), list) else []
    categories = payload.get("categories") if isinstance(payload.get("categories"), list) else []
    category_ids = {str(item.get("category_id") or "") for item in categories if isinstance(item, dict)}
    rule_ids = [str(item.get("rule_id") or "") for item in rules if isinstance(item, dict)]
    types = [str(item.get("type") or "") for item in rules if isinstance(item, dict)]
    duplicate_rule_ids = sorted(item for item, count in Counter(rule_ids).items() if item and count > 1)
    duplicate_types = sorted(item for item, count in Counter(types).items() if item and count > 1)
    if duplicate_rule_ids:
        errors.append("duplicate rule_id values found")
    if duplicate_types:
        errors.append("duplicate type values found")

    category_counts = Counter()
    for rule in rules:
        if not isinstance(rule, dict):
            errors.append("rule must be an object")
            continue
        category_id = str(rule.get("category_id") or "")
        category_counts[category_id] += 1
        if category_id not in category_ids:
            errors.append(f"unknown category_id for {rule.get('rule_id')}: {category_id}")
        classification = rule.get("classification") or {}
        for field in ("confidentiality_impact", "integrity_impact", "availability_impact", "overall_impact"):
            if classification.get(field) not in ALLOWED_CIA:
                errors.append(f"invalid CIA impact for {rule.get('rule_id')}.{field}")
        if classification.get("product_severity") not in ALLOWED_SEVERITY:
            errors.append(f"invalid product severity for {rule.get('rule_id')}")
        if rule.get("handling_tier") not in ALLOWED_HANDLING:
            errors.append(f"invalid handling tier for {rule.get('rule_id')}")
        if _overall_impact(classification) != classification.get("overall_impact"):
            errors.append(f"overall_impact must be CIA high-water-mark for {rule.get('rule_id')}")
        detection = rule.get("detection") or {}
        if detection.get("mode") not in ALLOWED_DETECTION_MODES:
            errors.append(f"invalid detection mode for {rule.get('rule_id')}")
        _validate_score_model(rule, errors, warnings)
        for pattern in detection.get("regex_patterns") or []:
            issue = _regex_issue(pattern)
            if issue:
                invalid_regex.append({"rule_id": str(rule.get("rule_id") or ""), "pattern_id": str(pattern.get("id") or ""), "error": issue})
        for mapping in rule.get("framework_mappings") or []:
            if not isinstance(mapping, dict) or not mapping.get("framework"):
                invalid_mappings.append(str(rule.get("rule_id") or ""))
        if len(rule.get("test_cases") or []) < 2:
            errors.append(f"at least two test_cases required for {rule.get('rule_id')}")

    for category in categories:
        if not isinstance(category, dict):
            continue
        expected = int(category.get("rule_count") or 0)
        actual = category_counts[str(category.get("category_id") or "")]
        if expected != actual:
            errors.append(f"category {category.get('category_id')} rule_count {expected} does not match {actual}")

    if invalid_regex:
        errors.append("invalid regex patterns found")
    if invalid_mappings:
        warnings.append("framework mappings without a framework were ignored")

    active_rules = {item.get("rule_id"): item for item in (active_catalog or {}).get("rules", []) if isinstance(item, dict)}
    incoming_rules = {item.get("rule_id"): item for item in rules if isinstance(item, dict)}
    added = len(set(incoming_rules) - set(active_rules))
    removed = len(set(active_rules) - set(incoming_rules))
    updated = sum(1 for key in set(incoming_rules) & set(active_rules) if incoming_rules[key] != active_rules[key])
    unchanged = sum(1 for key in set(incoming_rules) & set(active_rules) if incoming_rules[key] == active_rules[key])
    catalog = payload.get("catalog") if isinstance(payload.get("catalog"), dict) else {}
    result = NISTValidationResult(
        valid=not errors,
        catalog_version=str(catalog.get("catalog_version") or ""),
        schema_version=str(catalog.get("schema_version") or ""),
        source_version=str(catalog.get("source_version") or ""),
        source_status=str(catalog.get("source_status") or ""),
        rule_count=len(rules),
        category_count=len(categories),
        added_rules=added,
        updated_rules=updated,
        removed_rules=removed,
        unchanged_rules=unchanged,
        warnings=warnings,
        errors=sorted(set(errors)),
        duplicate_rule_ids=duplicate_rule_ids,
        duplicate_types=duplicate_types,
        invalid_regex=invalid_regex,
        invalid_mappings=sorted(set(invalid_mappings)),
        test_case_count=sum(len(item.get("test_cases") or []) for item in rules if isinstance(item, dict)),
        catalog_hash=_hash_payload(payload),
        approval_required=True,
    )
    if envelope is not None:
        result.framework = envelope.framework
    return result


def _validate_score_model(rule: dict[str, Any], errors: list[str], warnings: list[str]) -> None:
    score_model = ((rule.get("detection") or {}).get("score_model") or {})
    thresholds = score_model.get("thresholds") or {}
    ordered = [thresholds.get("low", 0), thresholds.get("medium", 0), thresholds.get("high", 0), thresholds.get("confirmed", 0)]
    if any(not isinstance(item, int) or item < 0 or item > 100 for item in ordered):
        errors.append(f"invalid score threshold for {rule.get('rule_id')}")
    if ordered != sorted(ordered):
        errors.append(f"inconsistent score thresholds for {rule.get('rule_id')}")
    if score_model.get("keyword_only_max_status") not in {None, "low", "medium", "rejected"}:
        warnings.append(f"unknown keyword_only_max_status for {rule.get('rule_id')}")


def _regex_issue(pattern: dict[str, Any]) -> str:
    raw = str(pattern.get("pattern") or "")
    if len(raw) > MAX_REGEX_LENGTH:
        return "regex length exceeds limit"
    if _regex_complexity_score(raw) > 85:
        return "regex complexity exceeds limit"
    try:
        re.compile(raw, _regex_flags(str(pattern.get("flags") or "")))
    except re.error as exc:
        return str(exc)
    return ""


def _regex_complexity_score(pattern: str) -> int:
    nested = len(re.findall(r"\([^)]*[+*][^)]*\)[+*]", pattern))
    broad = len(re.findall(r"\.\*|\.\+", pattern))
    groups = pattern.count("(")
    alternation = pattern.count("|")
    return nested * 45 + broad * 12 + groups * 2 + alternation


def _regex_flags(value: str) -> int:
    flags = 0
    if "i" in value.lower():
        flags |= re.IGNORECASE
    if "m" in value.lower():
        flags |= re.MULTILINE
    return flags


def _overall_impact(classification: dict[str, Any]) -> str:
    order = {"LOW": 0, "MODERATE": 1, "HIGH": 2}
    values = [
        classification.get("confidentiality_impact"),
        classification.get("integrity_impact"),
        classification.get("availability_impact"),
    ]
    return max((str(item) for item in values), key=lambda item: order.get(item, -1), default="")


def _validation_error_messages(exc: ValidationError) -> list[str]:
    return [f"{'.'.join(str(part) for part in err.get('loc', ()))}: {err.get('msg')}" for err in exc.errors()]


def _hash_payload(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    import hashlib

    return hashlib.sha256(raw).hexdigest()

