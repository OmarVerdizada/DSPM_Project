from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Iterable

from backend.compliance_rules import CRITICALITY_WEIGHTS, FINDING_CATEGORY_MAP, PATH_CATEGORY_KEYWORDS

PROFILE_PATH = Path(__file__).with_name("compliance_profiles.json")


def load_compliance_profiles() -> list[dict]:
    with PROFILE_PATH.open("r", encoding="utf-8") as handle:
        profiles = json.load(handle)
    return profiles


def allowed_framework_ids() -> set[str]:
    return {profile["id"] for profile in load_compliance_profiles()}


def normalize_framework_ids(frameworks: Iterable[str] | None) -> list[str]:
    allowed = allowed_framework_ids()
    normalized: list[str] = []
    for item in frameworks or []:
        framework_id = str(item or "").strip().lower().replace("-", "_")
        if not framework_id:
            continue
        if framework_id not in allowed:
            raise ValueError(f"Unsupported compliance framework: {item}")
        if framework_id not in normalized:
            normalized.append(framework_id)
    return normalized


def selected_profiles(frameworks: Iterable[str] | None) -> list[dict]:
    requested = normalize_framework_ids(frameworks)
    profile_map = {profile["id"]: profile for profile in load_compliance_profiles()}
    return [profile_map[item] for item in requested if item in profile_map]


def enrich_report_with_compliance(report: dict, enabled: bool, frameworks: Iterable[str] | None) -> dict:
    framework_ids = normalize_framework_ids(frameworks)
    if not enabled or not framework_ids:
        report["compliance_summary"] = {
            "enabled": False,
            "selected_frameworks": [],
            "total_compliance_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "top_violated_categories": [],
            "top_risky_files": [],
            "remediation_priorities": [],
        }
        return report

    profiles = selected_profiles(framework_ids)
    files = report.get("files") or []
    for file_obj in files:
        compliance = evaluate_file(file_obj, profiles)
        if compliance["matched_frameworks"]:
            file_obj["compliance"] = compliance

    report["compliance_summary"] = build_compliance_summary(files, profiles)
    return report


def evaluate_file(file_obj: dict, profiles: list[dict]) -> dict:
    categories = infer_data_categories(file_obj)
    base_score = min(int(file_obj.get("risk", {}).get("score") or 0), 100)
    permissions = file_obj.get("permissions") or {}
    matched_profiles: list[dict] = []
    framework_mapping: list[dict] = []
    reasons: list[str] = []
    reason_details: list[dict] = []
    remediations: list[str] = []
    controls: list[str] = []
    score_candidates: list[int] = []
    evidence = _finding_evidence(file_obj)

    for profile in profiles:
        critical_categories = set(profile.get("critical_data_categories") or [])
        matched_categories = sorted(categories & critical_categories)
        exposure_match = permissions.get("wide_access") or permissions.get("writable")
        if not matched_categories and not (profile["id"] in {"nist_csf", "iso27001"} and exposure_match and categories):
            continue

        matched_profiles.append(profile)
        data_weight = _data_weight(matched_categories)
        finding_weight = _finding_weight(file_obj, matched_categories)
        exposure_weight = _exposure_weight(file_obj)
        location_weight = _location_weight(file_obj)
        protection_weight = _protection_weight(file_obj, categories)
        base_component = round(min(base_score, 90) * 0.35)
        score = max(1, min(100, base_component + data_weight + finding_weight + exposure_weight + location_weight + protection_weight))
        score_candidates.append(score)

        category_label = _control_category(profile, matched_categories, exposure_match)
        controls.append(category_label)
        reason = (
            f"{profile['name']}: {', '.join(_category_labels(matched_categories or sorted(categories)))} matched {category_label}; "
            f"risk +{base_component}, data +{data_weight}, evidence +{finding_weight}, exposure +{exposure_weight}, location +{location_weight}."
        )
        reasons.append(reason)
        reason_details.append(
            {
                "framework": profile["name"],
                "category": category_label,
                "data_types": _category_labels(matched_categories or sorted(categories)),
                "reason": reason,
                "score_parts": {
                    "risk": base_component,
                    "data": data_weight,
                    "evidence": finding_weight,
                    "exposure": exposure_weight,
                    "location": location_weight,
                    "protection": protection_weight,
                },
            }
        )
        remediations.append(profile.get("remediation", "Restrict access and validate business need."))
        framework_mapping.append(
            {
                "framework": profile["name"],
                "framework_id": profile["id"],
                "category": category_label,
                "matched_data_categories": matched_categories or sorted(categories),
                "source_basis": profile.get("source_basis", []),
                "confidence": profile.get("confidence", "medium"),
                "evidence": evidence,
            }
        )

    final_score = max(score_candidates, default=0)
    severity = _severity(final_score)
    return {
        "matched_frameworks": [profile["id"] for profile in matched_profiles],
        "matched_framework_names": [profile["name"] for profile in matched_profiles],
        "data_categories": sorted(categories),
        "compliance_score": final_score,
        "compliance_severity": severity,
        "compliance_criticality": _criticality_label(categories, permissions),
        "relevant_controls": _dedupe(controls),
        "explanation": " ".join(reasons) if reasons else "",
        "remediation": " ".join(_dedupe(remediations)),
        "framework_mapping": framework_mapping,
        "reason_for_score": reasons,
        "reason_details": reason_details,
        "evidence": evidence,
    }


def infer_data_categories(file_obj: dict) -> set[str]:
    categories: set[str] = set()
    for finding in file_obj.get("findings") or []:
        categories.update(FINDING_CATEGORY_MAP.get(str(finding.get("type") or "").lower(), []))
        categories.update(FINDING_CATEGORY_MAP.get(str(finding.get("label") or "").lower(), []))
        if finding.get("category"):
            categories.update(_categories_from_finding_category(str(finding.get("category") or "")))
    path_blob = " ".join(str(file_obj.get(key) or "").lower() for key in ("name", "path", "share", "extension"))
    for keyword, keyword_categories in PATH_CATEGORY_KEYWORDS:
        if keyword in path_blob:
            categories.update(keyword_categories)
    return categories


def build_compliance_summary(files: list[dict], profiles: list[dict]) -> dict:
    severity_counts = Counter()
    category_counts = Counter()
    remediation_counts = Counter()
    findings: list[dict] = []
    for file_obj in files:
        compliance = file_obj.get("compliance") or {}
        if not compliance.get("matched_frameworks"):
            continue
        severity = str(compliance.get("compliance_severity") or "LOW").lower()
        severity_counts[severity] += 1
        for category in compliance.get("data_categories") or []:
            category_counts[category] += 1
        for control in compliance.get("relevant_controls") or []:
            remediation_counts[control] += 1
        findings.append(
            {
                "file": file_obj.get("name") or file_obj.get("path") or "",
                "path": file_obj.get("path") or "",
                "score": compliance.get("compliance_score", 0),
                "severity": compliance.get("compliance_severity", "LOW"),
                "frameworks": compliance.get("matched_framework_names") or compliance.get("matched_frameworks") or [],
                "categories": compliance.get("data_categories") or [],
                "remediation": compliance.get("remediation", ""),
            }
        )

    findings.sort(key=lambda item: int(item.get("score") or 0), reverse=True)
    return {
        "enabled": True,
        "selected_frameworks": [profile["id"] for profile in profiles],
        "selected_framework_names": [profile["name"] for profile in profiles],
        "total_compliance_findings": len(findings),
        "critical": severity_counts["critical"],
        "high": severity_counts["high"],
        "medium": severity_counts["medium"],
        "low": severity_counts["low"],
        "top_violated_categories": [{"category": item, "count": count} for item, count in category_counts.most_common(8)],
        "top_risky_files": findings[:10],
        "remediation_priorities": [{"control": item, "count": count} for item, count in remediation_counts.most_common(8)],
    }


def _exposure_weight(file_obj: dict) -> int:
    permissions = file_obj.get("permissions") or {}
    weight = min(round(int(permissions.get("score") or 0) * 0.35), 12)
    if permissions.get("wide_access"):
        weight += 8
    if permissions.get("writable"):
        weight += 5
    return min(weight, 20)


def _data_weight(categories: list[str]) -> int:
    if not categories:
        return 8
    strongest = max((CRITICALITY_WEIGHTS.get(item, 0) for item in categories), default=8)
    breadth = min(max(len(categories) - 1, 0) * 3, 9)
    return min(strongest + breadth, 30)


def _finding_weight(file_obj: dict, matched_categories: list[str]) -> int:
    weights = {"CRITICAL": 20, "HIGH": 15, "MEDIUM": 9, "LOW": 4}
    score = 0
    relevant = set(matched_categories)
    for finding in file_obj.get("findings") or []:
        finding_categories = set(FINDING_CATEGORY_MAP.get(str(finding.get("type") or "").lower(), []))
        if finding.get("category"):
            finding_categories.update(_categories_from_finding_category(str(finding.get("category") or "")))
        if relevant and not (finding_categories & relevant):
            continue
        count = max(int(finding.get("count") or 1), 1)
        score += weights.get(str(finding.get("risk") or "LOW").upper(), 4)
        score += min(count - 1, 4)
    return min(score, 25)


def _location_weight(file_obj: dict) -> int:
    path = str(file_obj.get("path") or file_obj.get("name") or "").lower()
    extension = str(file_obj.get("extension") or "").lower()
    score = 0
    if any(marker in path for marker in ("downloads", "desktop", "temp", "export", "backup", "share")):
        score += 5
    if extension in {".csv", ".xlsx", ".xls", ".zip", ".pst", ".ost", ".sql", ".db", ".bak", ".json"}:
        score += 5
    if file_obj.get("is_hidden") or file_obj.get("is_system"):
        score += 2
    return min(score, 10)


def _protection_weight(file_obj: dict, categories: set[str]) -> int:
    if not categories:
        return 0
    if file_obj.get("protected") or "encrypted" in str(file_obj.get("content_status") or "").lower():
        return -5
    return 5


def _control_category(profile: dict, categories: list[str], exposure_match: bool) -> str:
    controls = profile.get("control_categories") or {}
    if exposure_match and controls.get("exposure"):
        return controls["exposure"]
    if "phi" in categories and controls.get("phi"):
        return controls["phi"]
    if "pci_payment" in categories and controls.get("cardholder_data"):
        return controls["cardholder_data"]
    if ("credentials_secrets" in categories or "identity_access" in categories) and controls.get("access"):
        return controls["access"]
    if categories and controls:
        return next(iter(controls.values()))
    return "Compliance Exposure Risk"


def _finding_evidence(file_obj: dict) -> list[dict]:
    evidence: list[dict] = []
    for finding in file_obj.get("findings") or []:
        finding_type = str(finding.get("type") or finding.get("label") or "finding")
        categories = FINDING_CATEGORY_MAP.get(finding_type.lower(), [])
        if finding.get("category"):
            categories = _dedupe([*categories, *_categories_from_finding_category(str(finding.get("category") or ""))])
        evidence.append(
            {
                "type": finding_type,
                "label": finding.get("label") or finding_type.replace("_", " ").title(),
                "description": finding.get("description") or "",
                "risk": finding.get("risk") or "",
                "count": finding.get("count") or 1,
                "data_types": _category_labels(categories),
                "keywords": finding.get("matched_keywords") or finding.get("keywords") or finding.get("samples") or [],
                "samples": finding.get("samples") or [],
            }
        )
    return evidence


def _categories_from_finding_category(category: str) -> list[str]:
    normalized = category.strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in CRITICALITY_WEIGHTS:
        return [normalized]
    category_map = {
        "personal_data": ["pii"],
        "identifier": ["pii"],
        "identity": ["pii", "government_ids"],
        "special_category": ["special_category_context"],
        "health": ["phi"],
        "medical": ["phi"],
        "financial": ["financial_records"],
        "employment": ["hr_documents", "pii"],
        "hr": ["hr_documents", "pii"],
        "security": ["security_operations"],
        "secret": ["credentials_secrets"],
    }
    return category_map.get(normalized, [])


def _category_labels(categories: Iterable[str]) -> list[str]:
    labels = {
        "pii": "Personal data",
        "government_ids": "Government ID",
        "phi": "Health / PHI",
        "biometric_data": "Biometric data",
        "genetic_data": "Genetic data",
        "special_category_context": "Special-category data",
        "financial_records": "Financial records",
        "customer_data": "Customer data",
        "hr_documents": "HR / employee data",
        "online_identifiers": "Online identifier",
        "device_identifiers": "Device identifier",
        "location_data": "Location data",
        "behavioral_data": "Behavioral data",
        "credentials_secrets": "Credentials / secrets",
        "identity_access": "Identity access",
        "security_operations": "Security operations",
        "confidential_business": "Confidential business data",
        "source_code": "Source code",
        "legal_documents": "Legal documents",
        "contracts": "Contracts",
        "audit_accounting": "Audit evidence",
        "pci_payment": "Payment card data",
    }
    return [labels.get(str(item), str(item).replace("_", " ").title()) for item in categories if item]


def _criticality_label(categories: set[str], permissions: dict) -> str:
    if permissions.get("wide_access") and categories:
        return "Sensitive or regulated data with broad access"
    if {"pci_payment", "phi", "credentials_secrets", "government_ids"} & categories:
        return "High-impact regulated or security-sensitive data"
    if categories:
        return "Compliance-relevant data detected"
    return "No compliance match"


def _severity(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))
