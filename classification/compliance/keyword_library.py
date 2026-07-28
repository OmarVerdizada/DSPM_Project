from __future__ import annotations

import csv
import io
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from classification.compliance.gdpr_rules import GDPR_RULES
from classification.compliance.nist_catalog import built_in_nist_keyword_groups
from classification.compliance.nist_models import NIST_FRAMEWORK_ID
from classification.compliance import pci_keywords


BASE_DIR = Path(__file__).resolve().parents[2]
CUSTOM_KEYWORD_DIR = BASE_DIR / "data" / "compliance_keywords"
SUPPORTED_FRAMEWORKS = {"gdpr", "pci_dss", NIST_FRAMEWORK_ID}
FRAMEWORK_EXPORT_NAMES = {
    "gdpr": "GDPR",
    "pci_dss": "PCI DSS",
    NIST_FRAMEWORK_ID: "NIST",
}
IMPORT_MODES = {"merge", "replace_type", "replace_category", "replace_framework", "replace_language"}
SUPPORTED_RISKS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
MAX_GROUPS_PER_REQUEST = 200
MAX_TERMS_PER_GROUP = 1000
MAX_TOTAL_TERMS_PER_REQUEST = 20000
MAX_PAYLOAD_BYTES = 1_000_000
MAX_TERMS_PER_TENANT = 100000
MAX_DUPLICATE_RATIO = 0.85
MAX_REGEX_LENGTH = 320
MAX_COMPILED_CATALOG_BYTES = 2_000_000
_lock = threading.RLock()
_catalog_cache: dict[tuple[str, str, str, int], dict] = {}
_custom_groups_cache: dict[tuple[str, str, str, int], list[dict]] = {}


def framework_options() -> list[dict]:
    return [
        {"id": "gdpr", "name": "GDPR", "custom_count": len(load_custom_keywords("default", "gdpr"))},
        {"id": "pci_dss", "name": "PCI DSS", "custom_count": len(load_custom_keywords("default", "pci_dss"))},
        {"id": NIST_FRAMEWORK_ID, "name": "NIST", "custom_count": len(load_custom_keywords("default", NIST_FRAMEWORK_ID))},
    ]


def gdpr_rule_map() -> dict[str, object]:
    return {rule.finding_type: rule for rule in GDPR_RULES}


def pci_rule_map() -> dict[str, dict]:
    groups = _pci_builtin_group_specs()
    return {group["type"]: group for group in groups}


def framework_rule_map(framework: str) -> dict[str, object]:
    framework = _clean_framework(framework)
    if framework == "pci_dss":
        return pci_rule_map()
    if framework == NIST_FRAMEWORK_ID:
        return {group["type"]: group for group in built_in_nist_keyword_groups()}
    if framework == "gdpr":
        return gdpr_rule_map()
    raise ValueError(f"Unsupported compliance framework: {framework}")


def built_in_keyword_groups(framework: str = "gdpr") -> list[dict]:
    framework = _clean_framework(framework)
    if framework == NIST_FRAMEWORK_ID:
        return built_in_nist_keyword_groups()
    if framework == "pci_dss":
        return [
            {
                "framework": "pci_dss",
                "language": "built-in",
                "category": group["category"],
                "type": group["type"],
                "label": group["label"],
                "risk": group["risk"],
                "source": "built-in",
                "terms": list(group["terms"]),
                "count": len(group["terms"]),
                "updated_at": "",
            }
            for group in _pci_builtin_group_specs()
        ]
    groups: list[dict] = []
    for rule in GDPR_RULES:
        groups.append(
            {
                "framework": "gdpr",
                "language": "built-in",
                "category": rule.category,
                "type": rule.finding_type,
                "label": rule.label,
                "source": "built-in",
                "terms": list(rule.keywords),
                "count": len(rule.keywords),
                "updated_at": "",
            }
        )
    return groups


def load_custom_keywords(tenant_id: str, framework: str = "gdpr") -> list[dict]:
    catalog = _read_custom_catalog(tenant_id, framework)
    status = catalog.get("catalog_status", "OK")
    cache_key = _catalog_cache_key(tenant_id, framework)
    groups = _custom_groups_cache.get(cache_key)
    if groups is None:
        groups = [_normalize_group(item, default_framework=framework) for item in catalog.get("keywords", [])]
        _custom_groups_cache[cache_key] = groups
    groups = [dict(group) for group in groups]
    if status != "OK":
        for group in groups:
            group["catalog_status"] = status
            group["degraded_mode"] = True
            group["catalog_error"] = catalog.get("catalog_error", "")
    return groups


def keyword_catalog_status(tenant_id: str, framework: str = "gdpr") -> dict:
    catalog = _read_custom_catalog(tenant_id, framework)
    return {
        "framework": _clean_framework(framework),
        "catalog_status": catalog.get("catalog_status", "OK"),
        "catalog_version": catalog.get("catalog_version", ""),
        "last_known_good_version": catalog.get("last_known_good_version", ""),
        "degraded_mode": catalog.get("catalog_status") != "OK",
        "catalog_error": catalog.get("catalog_error", ""),
    }


def _read_custom_catalog(tenant_id: str, framework: str = "gdpr") -> dict:
    path = _custom_path(tenant_id, framework)
    if not path.exists():
        return {"framework": _clean_framework(framework), "catalog_status": "OK", "keywords": []}
    cache_key = _catalog_cache_key(tenant_id, framework)
    cached = _catalog_cache.get(cache_key)
    if cached is not None:
        return copy_catalog(cached)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("keyword catalog root must be an object")
        data.setdefault("catalog_status", "OK")
        data.setdefault("keywords", [])
        _catalog_cache[cache_key] = data
        return copy_catalog(data)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        _record_catalog_error(tenant_id, framework, str(exc))
        fallback = _last_good_path(tenant_id, framework)
        if fallback.exists():
            try:
                data = json.loads(fallback.read_text(encoding="utf-8"))
                data["catalog_status"] = "ERROR"
                data["catalog_error"] = str(exc)
                data["last_known_good_version"] = data.get("catalog_version") or data.get("updated_at", "")
                return data
            except (OSError, json.JSONDecodeError, ValueError):
                pass
        return {"framework": _clean_framework(framework), "catalog_status": "ERROR", "catalog_error": str(exc), "keywords": []}


def list_keyword_groups(
    tenant_id: str,
    framework: str = "gdpr",
    language: str = "",
    category: str = "",
    source: str = "all",
) -> dict:
    framework = _clean_framework(framework)
    language = _clean_language(language)
    category = _clean_token(category)
    source = (source or "all").strip().lower()
    groups = [*built_in_keyword_groups(framework), *load_custom_keywords(tenant_id, framework)]

    if language:
        groups = [item for item in groups if item.get("language") == language]
    if category:
        groups = [item for item in groups if item.get("category") == category]
    if source in {"built-in", "custom"}:
        groups = [item for item in groups if item.get("source") == source]

    languages = sorted({item.get("language", "") for item in groups if item.get("language")})
    categories = sorted({item.get("category", "") for item in groups if item.get("category")})
    return {
        "framework": framework,
        "catalog_status": keyword_catalog_status(tenant_id, framework),
        "groups": groups,
        "languages": languages,
        "categories": categories,
        "total_groups": len(groups),
        "total_terms": sum(len(item.get("terms") or []) for item in groups),
        "custom_terms": sum(len(item.get("terms") or []) for item in groups if item.get("source") == "custom"),
    }


def validate_keyword_import(tenant_id: str, payload: dict) -> dict:
    framework = _clean_framework(payload.get("framework") or "gdpr")
    mode = _clean_mode(payload.get("mode") or "merge")
    limit_errors = _validate_import_limits(tenant_id, framework, payload)
    if limit_errors:
        return {
            "valid": False,
            "framework": framework,
            "mode": mode,
            "new_terms": 0,
            "duplicates": 0,
            "duplicate_ratio": 0,
            "unknown_types": [],
            "limit_errors": limit_errors,
            "approval_required": True,
            "groups": [],
            "group_count": 0,
        }
    groups = normalize_import_groups(payload)
    existing_terms = _existing_terms(tenant_id, framework, mode, groups)
    seen_import: set[tuple[str, str, str, str]] = set()
    new_terms = 0
    duplicate_terms = 0
    unknown_types: set[str] = set()
    normalized_groups: list[dict] = []
    rule_map = framework_rule_map(framework)

    for group in groups:
        if group["type"] not in rule_map and not _is_custom_group(group):
            unknown_types.add(group["type"])
            continue
        terms: list[str] = []
        for term in group["terms"]:
            key = (group["framework"], group["language"], group["type"], term.lower())
            if key in seen_import or key in existing_terms:
                duplicate_terms += 1
                continue
            seen_import.add(key)
            terms.append(term)
            new_terms += 1
        if terms or group.get("regex"):
            copy = dict(group)
            copy["terms"] = terms
            copy["count"] = len(terms)
            normalized_groups.append(copy)

    duplicate_ratio = duplicate_terms / max(new_terms + duplicate_terms, 1)
    compiled_size = len(json.dumps(normalized_groups, ensure_ascii=False).encode("utf-8"))
    limit_errors = []
    if duplicate_ratio > MAX_DUPLICATE_RATIO and duplicate_terms:
        limit_errors.append(f"Duplicate ratio {duplicate_ratio:.0%} exceeds {MAX_DUPLICATE_RATIO:.0%}")
    if compiled_size > MAX_COMPILED_CATALOG_BYTES:
        limit_errors.append("Compiled catalog size limit exceeded")
    return {
        "valid": not unknown_types and bool(normalized_groups) and not limit_errors,
        "framework": framework,
        "mode": mode,
        "new_terms": new_terms,
        "duplicates": duplicate_terms,
        "duplicate_ratio": round(duplicate_ratio, 4),
        "unknown_types": sorted(unknown_types),
        "limit_errors": limit_errors,
        "approval_required": new_terms > 5000 or compiled_size > 500000,
        "groups": normalized_groups,
        "group_count": len(normalized_groups),
    }


def import_keyword_groups(tenant_id: str, payload: dict) -> dict:
    preview = validate_keyword_import(tenant_id, payload)
    if preview.get("limit_errors"):
        raise ValueError("; ".join(preview["limit_errors"]))
    if preview["unknown_types"]:
        raise ValueError(f"Unknown finding types: {', '.join(preview['unknown_types'])}")
    if not preview["groups"]:
        return {**preview, "imported": False}

    framework = preview["framework"]
    mode = preview["mode"]
    incoming = preview["groups"]
    current = load_custom_keywords(tenant_id, framework)
    if mode == "replace_framework":
        current = []
    elif mode == "replace_type":
        finding_types = {item["type"] for item in incoming}
        current = [item for item in current if item.get("type") not in finding_types]
    elif mode == "replace_category":
        categories = {item["category"] for item in incoming}
        current = [item for item in current if item.get("category") not in categories]
    elif mode == "replace_language":
        languages = {item["language"] for item in incoming}
        current = [item for item in current if item.get("language") not in languages]

    merged = _merge_groups([*current, *incoming])
    _write_custom_keywords(tenant_id, framework, merged)
    _invalidate_catalog_cache(tenant_id, framework)
    return {**preview, "imported": True, "custom_groups": len(merged), "custom_terms": sum(len(item["terms"]) for item in merged)}


def export_keyword_groups(tenant_id: str, framework: str = "gdpr", language: str = "", source: str = "all", fmt: str = "json") -> tuple[str, str, str]:
    library = list_keyword_groups(tenant_id, framework, language=language, source=source)
    fmt = (fmt or "json").strip().lower()
    export_library = _keyword_library_export_view(library)
    export_framework = str(export_library["framework"]).replace(" ", "_")
    filename = f"{export_framework}_keywords_{language or source or 'all'}.{fmt}"
    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["framework", "language", "category", "type", "label", "source", "keyword"])
        for group in export_library["groups"]:
            for term in group.get("terms") or []:
                writer.writerow([group["framework"], group["language"], group["category"], group["type"], group.get("label", ""), group["source"], term])
        return filename, "text/csv;charset=utf-8-sig", f"\ufeff{output.getvalue()}"
    if fmt == "txt":
        lines: list[str] = []
        for group in export_library["groups"]:
            lines.append(f"# {group['framework']} / {group['language']} / {group['type']} / {group['category']}")
            lines.extend(group.get("terms") or [])
            lines.append("")
        return filename, "text/plain;charset=utf-8", "\n".join(lines)
    return filename, "application/json;charset=utf-8", json.dumps(export_library, ensure_ascii=False, indent=2)


def _framework_export_name(framework: str) -> str:
    return FRAMEWORK_EXPORT_NAMES.get(_clean_framework(framework), framework)


def _keyword_library_export_view(library: dict) -> dict:
    exported = copy_catalog(library)
    framework = _clean_framework(exported.get("framework") or "gdpr")
    display_name = _framework_export_name(framework)
    exported["framework"] = display_name
    catalog_status = exported.get("catalog_status")
    if isinstance(catalog_status, dict):
        catalog_status["framework"] = display_name
    for group in exported.get("groups") or []:
        if isinstance(group, dict) and group.get("framework"):
            group["framework"] = _framework_export_name(group["framework"])
    return exported


def custom_keyword_groups_for_scan(tenant_id: str, framework: str = "gdpr") -> list[dict]:
    status = keyword_catalog_status(tenant_id, framework)
    groups = load_custom_keywords(tenant_id, framework)
    if status.get("degraded_mode"):
        for group in groups:
            group["degraded_mode"] = True
            group["catalog_status"] = "ERROR"
            group["catalog_error"] = status.get("catalog_error", "")
    return groups


def normalize_import_groups(payload: dict) -> list[dict]:
    framework = _clean_framework(payload.get("framework") or "gdpr")
    default_language = _clean_language(payload.get("language") or "custom") or "custom"
    raw_keywords = payload.get("keywords") or payload.get("groups") or []
    if isinstance(raw_keywords, str):
        raw_keywords = [{"language": default_language, "type": payload.get("type") or "gdpr_full_name", "terms": raw_keywords}]
    groups: list[dict] = []
    rule_map = framework_rule_map(framework)
    for item in raw_keywords:
        if not isinstance(item, dict):
            continue
        finding_type = _clean_token(item.get("type") or item.get("finding_type") or "")
        language = _clean_language(item.get("language") or default_language) or default_language
        terms = _normalize_terms(item.get("terms") or item.get("keywords") or item.get("keyword") or [])
        negative_terms = _normalize_terms(item.get("negative_keywords") or item.get("negative_terms") or [])
        regex_patterns = _normalize_regex_patterns(item.get("regex") or item.get("patterns") or [])
        if not finding_type or (not terms and not regex_patterns):
            continue
        rule = rule_map.get(finding_type)
        groups.append(
            {
                "framework": framework,
                "language": language,
                "category": _clean_category(framework, item.get("category") or _rule_attr(rule, "category", "custom")),
                "type": finding_type,
                "label": str(item.get("label") or _rule_attr(rule, "label", finding_type.replace("_", " ").title())).strip(),
                "risk": _clean_risk(item.get("risk") or _rule_attr(rule, "risk", "MEDIUM")),
                "confidence": _clean_confidence(item.get("confidence") or "medium"),
                "source": "custom",
                "mode": _clean_rule_mode(item.get("mode") or item.get("rule_mode") or "CONTEXT_ONLY"),
                "positive_keywords": terms,
                "negative_keywords": negative_terms,
                "regex": regex_patterns,
                "validator": _clean_token(item.get("validator") or ""),
                "normalizer": _clean_token(item.get("normalizer") or ""),
                "checksum": _clean_token(item.get("checksum") or ""),
                "minimum_context_score": _clean_int(item.get("minimum_context_score"), 0, 100, 0),
                "proximity": _clean_int(item.get("proximity"), 0, 10000, 0),
                "structured_field_names": _normalize_terms(item.get("structured_field_names") or []),
                "allowed_file_types": _normalize_file_types(item.get("allowed_file_types") or []),
                "excluded_paths": _normalize_terms(item.get("excluded_paths") or []),
                "framework_mapping": _normalize_framework_mapping(item.get("framework_mapping") or []),
                "version": str(item.get("version") or "1.0.0").strip()[:40],
                "owner": str(item.get("owner") or "").strip()[:120],
                "status": _clean_rule_status(item.get("status") or "draft"),
                "effective_date": str(item.get("effective_date") or "").strip()[:40],
                "expiration_date": str(item.get("expiration_date") or "").strip()[:40],
                "test_cases": _normalize_test_cases(item.get("test_cases") or []),
                "terms": terms,
                "count": len(terms),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )
    return _merge_groups(groups)


def parse_csv_import(text: str, framework: str = "gdpr", language: str = "custom") -> dict:
    reader = csv.DictReader(io.StringIO(text))
    buckets: dict[tuple[str, str, str], dict] = {}
    for row in reader:
        finding_type = _clean_token(row.get("type") or row.get("finding_type") or "")
        term = " ".join(str(row.get("keyword") or row.get("term") or "").split())
        if not finding_type or not term:
            continue
        lang = _clean_language(row.get("language") or language) or "custom"
        category = _clean_category(framework, row.get("category") or "custom")
        risk = _clean_risk(row.get("risk") or "MEDIUM")
        key = (lang, category, finding_type)
        bucket = buckets.setdefault(key, {"framework": framework, "language": lang, "category": category, "type": finding_type, "risk": risk, "terms": []})
        bucket["terms"].append(term)
    return {"framework": framework, "language": language, "keywords": list(buckets.values())}


def _merge_groups(groups: Iterable[dict]) -> list[dict]:
    merged: dict[tuple[str, str, str, str], dict] = {}
    for group in groups:
        normalized = _normalize_group(group)
        key = (normalized["framework"], normalized["language"], normalized["category"], normalized["type"])
        bucket = merged.setdefault(key, {**normalized, "terms": []})
        existing = {term.lower() for term in bucket["terms"]}
        for term in normalized["terms"]:
            if term.lower() not in existing:
                bucket["terms"].append(term)
                existing.add(term.lower())
        bucket["count"] = len(bucket["terms"])
        bucket["updated_at"] = normalized.get("updated_at") or bucket.get("updated_at", "")
    return sorted(merged.values(), key=lambda item: (item["framework"], item["language"], item["category"], item["type"]))


def _normalize_group(group: dict, default_framework: str = "gdpr") -> dict:
    framework = _clean_framework(group.get("framework") or default_framework)
    rule = framework_rule_map(framework).get(_clean_token(group.get("type") or ""))
    terms = _normalize_terms(group.get("terms") or group.get("keywords") or [])
    return {
        "framework": framework,
        "language": _clean_language(group.get("language") or "custom") or "custom",
        "category": _clean_category(framework, group.get("category") or _rule_attr(rule, "category", "custom")),
        "type": _clean_token(group.get("type") or ""),
        "label": str(group.get("label") or _rule_attr(rule, "label", "")).strip(),
        "risk": _clean_risk(group.get("risk") or _rule_attr(rule, "risk", "MEDIUM")),
        "confidence": _clean_confidence(group.get("confidence") or "medium"),
        "source": group.get("source") or "custom",
        "mode": _clean_rule_mode(group.get("mode") or group.get("rule_mode") or "CONTEXT_ONLY"),
        "positive_keywords": _normalize_terms(group.get("positive_keywords") or group.get("terms") or group.get("keywords") or []),
        "negative_keywords": _normalize_terms(group.get("negative_keywords") or []),
        "regex": _normalize_regex_patterns(group.get("regex") or []),
        "validator": _clean_token(group.get("validator") or ""),
        "normalizer": _clean_token(group.get("normalizer") or ""),
        "checksum": _clean_token(group.get("checksum") or ""),
        "minimum_context_score": _clean_int(group.get("minimum_context_score"), 0, 100, 0),
        "proximity": _clean_int(group.get("proximity"), 0, 10000, 0),
        "structured_field_names": _normalize_terms(group.get("structured_field_names") or []),
        "allowed_file_types": _normalize_file_types(group.get("allowed_file_types") or []),
        "excluded_paths": _normalize_terms(group.get("excluded_paths") or []),
        "framework_mapping": _normalize_framework_mapping(group.get("framework_mapping") or []),
        "version": str(group.get("version") or "1.0.0").strip()[:40],
        "owner": str(group.get("owner") or "").strip()[:120],
        "status": _clean_rule_status(group.get("status") or "draft"),
        "effective_date": str(group.get("effective_date") or "").strip()[:40],
        "expiration_date": str(group.get("expiration_date") or "").strip()[:40],
        "test_cases": _normalize_test_cases(group.get("test_cases") or []),
        "terms": terms,
        "count": len(terms),
        "updated_at": group.get("updated_at") or "",
    }


def _normalize_terms(value) -> list[str]:
    if isinstance(value, str):
        raw = re.split(r"[\r\n,;\t|]+", value)
    else:
        raw = list(value or [])
    terms: list[str] = []
    seen: set[str] = set()
    for item in raw:
        term = _clean_term(item)
        key = term.lower()
        if 1 <= len(term) <= 160 and key not in seen:
            terms.append(term)
            seen.add(key)
    return terms


def _normalize_regex_patterns(value) -> list[str]:
    # H4 (roadmap 0.5): length + compile-validity only, no complexity heuristic.
    # These stored patterns are NOT executed today (the keyword matcher is a
    # literal Aho-Corasick automaton - see keyword_index.py); if that ever
    # changes, they MUST run on a non-backtracking engine, not behind a denylist.
    patterns = _normalize_terms(value)
    valid: list[str] = []
    for pattern in patterns:
        if len(pattern) > MAX_REGEX_LENGTH:
            continue
        try:
            re.compile(pattern)
        except re.error:
            continue
        valid.append(pattern)
    return valid


def _normalize_file_types(value) -> list[str]:
    return sorted({item if item.startswith(".") else f".{item}" for item in (_clean_token(term).replace("_", ".") for term in _normalize_terms(value)) if len(item) > 1})


def _normalize_framework_mapping(value) -> list[dict]:
    rows = value if isinstance(value, list) else [value] if isinstance(value, dict) else []
    mappings: list[dict] = []
    for row in rows[:25]:
        if not isinstance(row, dict):
            continue
        mappings.append(
            {
                "framework": str(row.get("framework") or "").strip()[:80],
                "framework_version": str(row.get("framework_version") or "").strip()[:40],
                "requirement_id": str(row.get("requirement_id") or "").strip()[:80],
                "mapping_type": str(row.get("mapping_type") or "contextual").strip()[:40],
                "mapping_confidence": _clean_confidence(row.get("mapping_confidence") or "medium"),
            }
        )
    return mappings


def _normalize_test_cases(value) -> list[dict]:
    rows = value if isinstance(value, list) else []
    cases: list[dict] = []
    for row in rows[:50]:
        if not isinstance(row, dict):
            continue
        cases.append(
            {
                "name": str(row.get("name") or "").strip()[:120],
                "input": str(row.get("input") or "")[:2000],
                "expected_match": bool(row.get("expected_match")),
            }
        )
    return cases


def _clean_int(value, minimum: int, maximum: int, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


def _clean_confidence(value: str) -> str:
    confidence = str(value or "medium").strip().lower()
    return confidence if confidence in {"low", "medium", "high"} else "medium"


def _clean_rule_status(value: str) -> str:
    status = str(value or "draft").strip().lower()
    allowed = {"draft", "pending_approval", "approved", "deployed", "disabled", "expired"}
    return status if status in allowed else "draft"


def _validate_import_limits(tenant_id: str, framework: str, payload: dict) -> list[str]:
    errors: list[str] = []
    payload_bytes = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    if payload_bytes > MAX_PAYLOAD_BYTES:
        errors.append(f"Payload exceeds {MAX_PAYLOAD_BYTES} bytes")
    raw_keywords = payload.get("keywords") or payload.get("groups") or []
    raw_groups = [{"terms": raw_keywords}] if isinstance(raw_keywords, str) else list(raw_keywords or [])
    if len(raw_groups) > MAX_GROUPS_PER_REQUEST:
        errors.append(f"Group count exceeds {MAX_GROUPS_PER_REQUEST}")
    total_terms = 0
    for item in raw_groups:
        if not isinstance(item, dict):
            continue
        terms = _normalize_terms(item.get("terms") or item.get("keywords") or item.get("keyword") or [])
        total_terms += len(terms)
        if len(terms) > MAX_TERMS_PER_GROUP:
            errors.append(f"Terms per group exceeds {MAX_TERMS_PER_GROUP}")
            break
        for pattern in _normalize_terms(item.get("regex") or item.get("patterns") or []):
            if len(pattern) > MAX_REGEX_LENGTH:
                errors.append("Regex length limit exceeded")
                break
    if total_terms > MAX_TOTAL_TERMS_PER_REQUEST:
        errors.append(f"Total terms per request exceeds {MAX_TOTAL_TERMS_PER_REQUEST}")
    existing_total = sum(len(group.get("terms") or []) for group in load_custom_keywords(tenant_id, framework))
    if existing_total + total_terms > MAX_TERMS_PER_TENANT:
        errors.append(f"Terms per tenant exceeds {MAX_TERMS_PER_TENANT}")
    return sorted(set(errors))


def _rule_attr(rule: object, name: str, default: str) -> str:
    if isinstance(rule, dict):
        return str(rule.get(name) or default)
    return str(getattr(rule, name, default) or default)


def _clean_rule_mode(value: str) -> str:
    mode = str(value or "CONTEXT_ONLY").strip().upper()
    allowed = {
        "CONTEXT_ONLY",
        "FIELD_NAME",
        "VALUE_PATTERN",
        "KEYWORD_PLUS_VALUE",
        "STRUCTURED_SCHEMA",
        "PROXIMITY_RULE",
        "REGEX_VALIDATOR",
        "COMPOSITE_RULE",
    }
    return mode if mode in allowed else "CONTEXT_ONLY"


def _pci_builtin_group_specs() -> list[dict]:
    protection_claims = _pci_terms_matching(("protected", "protection", "secure", "unreadable", "masked"), pci_keywords.PAN_PROTECTION_KEYWORDS)
    encryption_controls = _pci_terms_matching(("encrypt", "cipher", "crypto", "key", "kms", "hsm"), pci_keywords.PAN_PROTECTION_KEYWORDS)
    tokenization_terms = _pci_terms_matching(("token", "vault", "detoken"), pci_keywords.PAN_PROTECTION_KEYWORDS)
    truncation_terms = _pci_terms_matching(("trunc", "last4", "last four", "mask"), pci_keywords.PAN_PROTECTION_KEYWORDS)
    negative_terms = _pci_terms_matching(("test", "dummy", "sample", "sandbox", "fake", "redacted"), pci_keywords.PAN_PROTECTION_KEYWORDS)
    return [
        {
            "type": "pci_chd_pan",
            "category": "pci_cardholder_data",
            "label": "Primary Account Number",
            "risk": "CRITICAL",
            "terms": pci_keywords.PAN_KEYWORDS,
        },
        {
            "type": "pci_pan_schema_keyword",
            "category": "pci_cardholder_data",
            "label": "PAN schema keywords",
            "risk": "HIGH",
            "terms": pci_keywords.PAN_KEYWORDS,
        },
        {
            "type": "pci_pan_payment_context",
            "category": "pci_scope_context",
            "label": "PAN payment-context keywords",
            "risk": "MEDIUM",
            "terms": pci_keywords.PAYMENT_CONTEXT_KEYWORDS,
        },
        {
            "type": "pci_pan_protection_claim",
            "category": "pci_scope_context",
            "label": "PAN protection claim keywords",
            "risk": "MEDIUM",
            "terms": protection_claims,
        },
        {
            "type": "pci_pan_encryption_control",
            "category": "pci_payment_secret",
            "label": "PAN encryption-control keywords",
            "risk": "HIGH",
            "terms": encryption_controls,
        },
        {
            "type": "pci_pan_tokenization",
            "category": "pci_scope_context",
            "label": "PAN tokenization keywords",
            "risk": "MEDIUM",
            "terms": tokenization_terms,
        },
        {
            "type": "pci_pan_truncation",
            "category": "pci_scope_context",
            "label": "PAN truncation keywords",
            "risk": "MEDIUM",
            "terms": truncation_terms,
        },
        {
            "type": "pci_pan_negative_context",
            "category": "pci_scope_context",
            "label": "PAN negative keywords",
            "risk": "LOW",
            "terms": negative_terms,
        },
        {
            "type": "pci_chd_cardholder_name",
            "category": "pci_cardholder_data",
            "label": "Cardholder Name",
            "risk": "HIGH",
            "terms": pci_keywords.CARDHOLDER_NAME_KEYWORDS,
        },
        {
            "type": "pci_chd_expiration_date",
            "category": "pci_cardholder_data",
            "label": "Expiration Date",
            "risk": "HIGH",
            "terms": pci_keywords.EXPIRATION_DATE_KEYWORDS,
        },
        {
            "type": "pci_chd_service_code",
            "category": "pci_cardholder_data",
            "label": "Service Code",
            "risk": "HIGH",
            "terms": pci_keywords.SERVICE_CODE_KEYWORDS,
        },
        {
            "type": "pci_sad_track_data",
            "category": "pci_sensitive_authentication_data",
            "label": "Full Track Data",
            "risk": "CRITICAL",
            "terms": pci_keywords.TRACK_DATA_KEYWORDS,
        },
        {
            "type": "pci_sad_cvv",
            "category": "pci_sensitive_authentication_data",
            "label": "Card Verification Code / Value",
            "risk": "CRITICAL",
            "terms": pci_keywords.CVV_KEYWORDS,
        },
        {
            "type": "pci_sad_pin",
            "category": "pci_sensitive_authentication_data",
            "label": "PIN and PIN Block",
            "risk": "CRITICAL",
            "terms": pci_keywords.PIN_KEYWORDS,
        },
        {
            "type": "pci_payment_context",
            "category": "pci_scope_context",
            "label": "Payment Context",
            "risk": "MEDIUM",
            "terms": pci_keywords.PAYMENT_CONTEXT_KEYWORDS,
        },
    ]


def _pci_terms_matching(markers: tuple[str, ...], terms: Iterable[str]) -> list[str]:
    return [term for term in terms if any(marker in term.lower() for marker in markers)]


def _existing_terms(tenant_id: str, framework: str, mode: str, groups: list[dict]) -> set[tuple[str, str, str, str]]:
    existing_groups = [*built_in_keyword_groups(framework), *load_custom_keywords(tenant_id, framework)]
    if mode == "replace_framework":
        existing_groups = built_in_keyword_groups(framework)
    elif mode == "replace_type":
        finding_types = {item["type"] for item in groups}
        existing_groups = [item for item in existing_groups if item.get("source") == "built-in" or item.get("type") not in finding_types]
    elif mode == "replace_category":
        categories = {item["category"] for item in groups}
        existing_groups = [item for item in existing_groups if item.get("source") == "built-in" or item.get("category") not in categories]
    elif mode == "replace_language":
        languages = {item["language"] for item in groups}
        existing_groups = [item for item in existing_groups if item.get("source") == "built-in" or item.get("language") not in languages]
    return {
        (item["framework"], item["language"], item["type"], term.lower())
        for item in existing_groups
        for term in item.get("terms") or []
    }


def _write_custom_keywords(tenant_id: str, framework: str, groups: list[dict]) -> None:
    path = _custom_path(tenant_id, framework)
    path.parent.mkdir(parents=True, exist_ok=True)
    updated_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "framework": framework,
        "catalog_status": "OK",
        "catalog_version": updated_at,
        "storage_backend": "file_atomic_local",
        "enterprise_storage_model": {
            "recommended_backend": "database",
            "tables": [
                "rule_catalog",
                "rule_versions",
                "keyword_groups",
                "keyword_terms",
                "rule_approvals",
                "rule_test_cases",
                "rule_deployments",
                "rule_audit_history",
            ],
        },
        "updated_at": updated_at,
        "keywords": groups,
    }
    with _lock:
        tmp_path = path.with_suffix(f".{os.getpid()}.tmp")
        tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp_path, path)
        _last_good_path(tenant_id, framework).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        _append_catalog_audit(tenant_id, framework, "catalog.write", {"groups": len(groups), "terms": sum(len(item.get("terms") or []) for item in groups)})
        _invalidate_catalog_cache(tenant_id, framework)


def copy_catalog(catalog: dict) -> dict:
    return json.loads(json.dumps(catalog, ensure_ascii=False))


def _catalog_cache_key(tenant_id: str, framework: str) -> tuple[str, str, str, int]:
    path = _custom_path(tenant_id, framework)
    try:
        mtime_ns = path.stat().st_mtime_ns
    except OSError:
        mtime_ns = 0
    return (_safe_tenant(tenant_id), _clean_framework(framework), str(path), int(mtime_ns))


def _invalidate_catalog_cache(tenant_id: str, framework: str) -> None:
    tenant = _safe_tenant(tenant_id)
    normalized_framework = _clean_framework(framework)
    stale_catalog_keys = [key for key in _catalog_cache if key[0] == tenant and key[1] == normalized_framework]
    stale_group_keys = [key for key in _custom_groups_cache if key[0] == tenant and key[1] == normalized_framework]
    for key in stale_catalog_keys:
        _catalog_cache.pop(key, None)
    for key in stale_group_keys:
        _custom_groups_cache.pop(key, None)


def _custom_path(tenant_id: str, framework: str) -> Path:
    return CUSTOM_KEYWORD_DIR / _safe_tenant(tenant_id) / f"{_clean_framework(framework)}_custom.json"


def _last_good_path(tenant_id: str, framework: str) -> Path:
    return CUSTOM_KEYWORD_DIR / _safe_tenant(tenant_id) / f"{_clean_framework(framework)}_custom.last_good.json"


def _catalog_audit_path(tenant_id: str, framework: str) -> Path:
    return CUSTOM_KEYWORD_DIR / _safe_tenant(tenant_id) / f"{_clean_framework(framework)}_audit.jsonl"


def _catalog_alert_path(tenant_id: str, framework: str) -> Path:
    return CUSTOM_KEYWORD_DIR / _safe_tenant(tenant_id) / f"{_clean_framework(framework)}_admin_alerts.jsonl"


def _record_catalog_error(tenant_id: str, framework: str, error: str) -> None:
    event = {"severity": "ERROR", "message": "Custom keyword catalog could not be parsed; using last known good version when available.", "error": error}
    _append_jsonl(_catalog_alert_path(tenant_id, framework), event)
    _append_catalog_audit(tenant_id, framework, "catalog.error", event)


def _append_catalog_audit(tenant_id: str, framework: str, action: str, detail: dict) -> None:
    _append_jsonl(_catalog_audit_path(tenant_id, framework), {"action": action, "detail": detail})


def _append_jsonl(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {"timestamp": datetime.now(timezone.utc).isoformat(), **payload}
    with _lock:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _safe_tenant(value: str) -> str:
    return "".join(ch for ch in str(value or "default") if ch.isalnum() or ch in {"-", "_"}) or "default"


def _clean_framework(value: str) -> str:
    framework = _clean_token(value or "gdpr")
    if framework == "nist":
        framework = NIST_FRAMEWORK_ID
    elif framework in {"pci", "pcidss"}:
        framework = "pci_dss"
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ValueError(f"Unsupported compliance framework: {value}")
    return framework


def _clean_mode(value: str) -> str:
    mode = str(value or "merge").strip().lower()
    if mode == "replace_custom":
        mode = "replace_framework"
    if mode not in IMPORT_MODES:
        raise ValueError(f"Unsupported import mode: {value}")
    return mode


def _clean_language(value: str) -> str:
    return re.sub(r"[^a-z0-9_-]", "", str(value or "").strip().lower())[:32]


def _clean_token(value: str) -> str:
    return re.sub(r"[^a-z0-9_]", "_", str(value or "").strip().lower().replace("-", "_")).strip("_")[:80]


def _clean_category(framework: str, value: str) -> str:
    category = _clean_token(value or "custom")
    if framework == NIST_FRAMEWORK_ID:
        return category if category.startswith("nist_") or category == "custom" else f"nist_{category}"
    if framework != "pci_dss":
        return category
    aliases = {
        "pci": "pci_scope_context",
        "pci_payment": "pci_scope_context",
        "payment": "pci_scope_context",
        "payment_card": "pci_scope_context",
        "cardholder_data": "pci_cardholder_data",
        "chd": "pci_cardholder_data",
        "sensitive_authentication_data": "pci_sensitive_authentication_data",
        "sad": "pci_sensitive_authentication_data",
        "payment_secret": "pci_payment_secret",
    }
    if category in aliases:
        return aliases[category]
    return category if category.startswith("pci_") else f"pci_{category}"


def _clean_risk(value: str) -> str:
    risk = str(value or "MEDIUM").strip().upper()
    return risk if risk in SUPPORTED_RISKS else "MEDIUM"


def _is_custom_group(group: dict) -> bool:
    return bool(group.get("category") and group.get("label") and group.get("risk"))


def _clean_term(value) -> str:
    term = re.sub(r"^[\s\-*•]+|[\s,;|]+$", "", str(value or ""))
    term = term.strip().strip("\"'")
    return " ".join(term.split())
