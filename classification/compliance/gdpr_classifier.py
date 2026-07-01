from __future__ import annotations

import re

from classification.compliance.gdpr_rules import GDPR_RULES
from classification.compliance.validators import redact


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
    for rule in GDPR_RULES:
        matches = []
        for value in rule.detector(content or "", metadata):
            redacted = redact(value)
            if redacted not in matches:
                matches.append(redacted)
            if len(matches) >= 10:
                break
        if not matches:
            continue
        matched_keywords = []
        for keyword in rule.keywords:
            normalized = " ".join(str(keyword or "").strip().split())
            if normalized and _keyword_matches(evidence_blob, normalized) and normalized not in matched_keywords:
                matched_keywords.append(normalized)
            if len(matched_keywords) >= 10:
                break
        findings.append(
            finding := {
                "type": rule.finding_type,
                "risk": rule.risk,
                "description": rule.description,
                "count": len(matches),
                "samples": matches,
                "framework": "gdpr",
                "category": rule.category,
                "tier": rule.tier,
                "label": rule.label,
                "matched_keywords": matched_keywords,
            }
        )
        finding_index[rule.finding_type] = finding
    _apply_custom_keyword_groups(evidence_blob, findings, finding_index, custom_keyword_groups or [])
    return findings


def _apply_custom_keyword_groups(evidence_blob: str, findings: list[dict], finding_index: dict[str, dict], groups: list[dict]) -> None:
    if not groups:
        return
    rule_map = {rule.finding_type: rule for rule in GDPR_RULES}
    for group in groups:
        finding_type = str(group.get("type") or "").strip()
        rule = rule_map.get(finding_type)
        if not rule and not _is_custom_group(group):
            continue
        matched_keywords = []
        for term in group.get("terms") or []:
            keyword = " ".join(str(term or "").strip().split())
            if keyword and _keyword_matches(evidence_blob, keyword) and keyword not in matched_keywords:
                matched_keywords.append(keyword)
            if len(matched_keywords) >= 10:
                break
        if not matched_keywords:
            continue
        finding = finding_index.get(finding_type)
        if not finding:
            category = str(group.get("category") or getattr(rule, "category", "custom") or "custom").strip() or "custom"
            label = str(group.get("label") or getattr(rule, "label", "") or finding_type.replace("_", " ").title()).strip()
            risk = str(group.get("risk") or getattr(rule, "risk", "MEDIUM") or "MEDIUM").strip().upper()
            finding = {
                "type": finding_type,
                "risk": risk if risk in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "MEDIUM",
                "description": getattr(rule, "description", "") or f"Custom GDPR keyword group matched for {label}.",
                "count": 0,
                "samples": [],
                "framework": "gdpr",
                "category": category,
                "tier": getattr(rule, "tier", "custom"),
                "label": label,
                "matched_keywords": [],
            }
            findings.append(finding)
            finding_index[finding_type] = finding
        existing = set(finding.get("matched_keywords") or [])
        for keyword in matched_keywords:
            if keyword not in existing:
                finding.setdefault("matched_keywords", []).append(keyword)
                finding.setdefault("samples", []).append(redact(keyword))
                finding["count"] = int(finding.get("count") or 0) + 1
                existing.add(keyword)


def _keyword_matches(evidence_blob: str, keyword: str) -> bool:
    normalized = " ".join(str(keyword or "").strip().split()).lower()
    if not normalized:
        return False
    if normalized[0].isalnum() and normalized[-1].isalnum():
        return re.search(rf"(?<![A-Za-z0-9_]){re.escape(normalized)}(?![A-Za-z0-9_])", evidence_blob) is not None
    return normalized in evidence_blob


def _is_custom_group(group: dict) -> bool:
    return bool(group.get("category") and group.get("label") and group.get("risk"))
