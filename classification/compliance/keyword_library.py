from __future__ import annotations

import csv
import io
import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from classification.compliance.gdpr_rules import GDPR_RULES


BASE_DIR = Path(__file__).resolve().parents[2]
CUSTOM_KEYWORD_DIR = BASE_DIR / "data" / "compliance_keywords"
SUPPORTED_FRAMEWORKS = {"gdpr"}
IMPORT_MODES = {"merge", "replace_type", "replace_category", "replace_framework", "replace_language"}
_lock = threading.Lock()


def framework_options() -> list[dict]:
    return [{"id": "gdpr", "name": "GDPR", "custom_count": len(load_custom_keywords("default", "gdpr"))}]


def gdpr_rule_map() -> dict[str, object]:
    return {rule.finding_type: rule for rule in GDPR_RULES}


def built_in_keyword_groups(framework: str = "gdpr") -> list[dict]:
    framework = _clean_framework(framework)
    if framework != "gdpr":
        return []
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
    path = _custom_path(tenant_id, framework)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [_normalize_group(item, default_framework=framework) for item in data.get("keywords", [])]


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
    groups = normalize_import_groups(payload)
    existing_terms = _existing_terms(tenant_id, framework, mode, groups)
    seen_import: set[tuple[str, str, str, str]] = set()
    new_terms = 0
    duplicate_terms = 0
    unknown_types: set[str] = set()
    normalized_groups: list[dict] = []
    rule_map = gdpr_rule_map()

    for group in groups:
        if group["type"] not in rule_map:
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
        if terms:
            copy = dict(group)
            copy["terms"] = terms
            copy["count"] = len(terms)
            normalized_groups.append(copy)

    return {
        "valid": not unknown_types and bool(normalized_groups),
        "framework": framework,
        "mode": mode,
        "new_terms": new_terms,
        "duplicates": duplicate_terms,
        "unknown_types": sorted(unknown_types),
        "groups": normalized_groups,
        "group_count": len(normalized_groups),
    }


def import_keyword_groups(tenant_id: str, payload: dict) -> dict:
    preview = validate_keyword_import(tenant_id, payload)
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
    return {**preview, "imported": True, "custom_groups": len(merged), "custom_terms": sum(len(item["terms"]) for item in merged)}


def export_keyword_groups(tenant_id: str, framework: str = "gdpr", language: str = "", source: str = "all", fmt: str = "json") -> tuple[str, str, str]:
    library = list_keyword_groups(tenant_id, framework, language=language, source=source)
    fmt = (fmt or "json").strip().lower()
    filename = f"{library['framework']}_keywords_{language or source or 'all'}.{fmt}"
    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["framework", "language", "category", "type", "label", "source", "keyword"])
        for group in library["groups"]:
            for term in group.get("terms") or []:
                writer.writerow([group["framework"], group["language"], group["category"], group["type"], group.get("label", ""), group["source"], term])
        return filename, "text/csv;charset=utf-8-sig", f"\ufeff{output.getvalue()}"
    if fmt == "txt":
        lines: list[str] = []
        for group in library["groups"]:
            lines.append(f"# {group['framework']} / {group['language']} / {group['type']} / {group['category']}")
            lines.extend(group.get("terms") or [])
            lines.append("")
        return filename, "text/plain;charset=utf-8", "\n".join(lines)
    return filename, "application/json;charset=utf-8", json.dumps(library, ensure_ascii=False, indent=2)


def custom_keyword_groups_for_scan(tenant_id: str, framework: str = "gdpr") -> list[dict]:
    return load_custom_keywords(tenant_id, framework)


def normalize_import_groups(payload: dict) -> list[dict]:
    framework = _clean_framework(payload.get("framework") or "gdpr")
    default_language = _clean_language(payload.get("language") or "custom") or "custom"
    raw_keywords = payload.get("keywords") or payload.get("groups") or []
    if isinstance(raw_keywords, str):
        raw_keywords = [{"language": default_language, "type": payload.get("type") or "gdpr_full_name", "terms": raw_keywords}]
    groups: list[dict] = []
    rule_map = gdpr_rule_map()
    for item in raw_keywords:
        if not isinstance(item, dict):
            continue
        finding_type = _clean_token(item.get("type") or item.get("finding_type") or "")
        language = _clean_language(item.get("language") or default_language) or default_language
        terms = _normalize_terms(item.get("terms") or item.get("keywords") or item.get("keyword") or [])
        if not finding_type or not terms:
            continue
        rule = rule_map.get(finding_type)
        groups.append(
            {
                "framework": framework,
                "language": language,
                "category": _clean_token(item.get("category") or getattr(rule, "category", "custom")),
                "type": finding_type,
                "label": str(item.get("label") or getattr(rule, "label", finding_type.replace("_", " ").title())).strip(),
                "source": "custom",
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
        category = _clean_token(row.get("category") or "custom")
        key = (lang, category, finding_type)
        bucket = buckets.setdefault(key, {"framework": framework, "language": lang, "category": category, "type": finding_type, "terms": []})
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
    rule = gdpr_rule_map().get(_clean_token(group.get("type") or ""))
    terms = _normalize_terms(group.get("terms") or group.get("keywords") or [])
    return {
        "framework": framework,
        "language": _clean_language(group.get("language") or "custom") or "custom",
        "category": _clean_token(group.get("category") or getattr(rule, "category", "custom")),
        "type": _clean_token(group.get("type") or ""),
        "label": str(group.get("label") or getattr(rule, "label", "")).strip(),
        "source": group.get("source") or "custom",
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
    payload = {"framework": framework, "updated_at": datetime.now(timezone.utc).isoformat(), "keywords": groups}
    with _lock:
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _custom_path(tenant_id: str, framework: str) -> Path:
    return CUSTOM_KEYWORD_DIR / _safe_tenant(tenant_id) / f"{_clean_framework(framework)}_custom.json"


def _safe_tenant(value: str) -> str:
    return "".join(ch for ch in str(value or "default") if ch.isalnum() or ch in {"-", "_"}) or "default"


def _clean_framework(value: str) -> str:
    framework = _clean_token(value or "gdpr")
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


def _clean_term(value) -> str:
    term = re.sub(r"^[\s\-*•]+|[\s,;|]+$", "", str(value or ""))
    term = term.strip().strip("\"'")
    return " ".join(term.split())
