from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from backend.finding_contracts import get_finding_display_name, normalize_framework_id


SEVERITY_SCORE = {"CRITICAL": 95, "HIGH": 80, "MEDIUM": 55, "LOW": 20}


def apply_canonical_finding_model(finding: dict, file_obj: dict, *, seen_at: str | None = None) -> dict:
    timestamp = seen_at or datetime.now(timezone.utc).isoformat()
    asset_id = _asset_id(file_obj)
    location_id = _location_id(file_obj)
    logical_boundary_id = _logical_boundary_id(finding, file_obj)
    rule_id = str(finding.get("rule_id") or finding.get("type") or "unknown_rule")
    entity_type = _entity_type(finding)
    severity = str(finding.get("impact_severity") or finding.get("risk") or "LOW").upper()
    confidence = _confidence(finding)
    occurrence_count = max(int(finding.get("occurrence_count") or finding.get("count") or 1), 1)
    unique_value_count = _unique_value_count(finding)
    finding_id = _stable_id(
        "finding",
        asset_id,
        location_id,
        rule_id,
        entity_type,
        str(finding.get("protection_state") or finding.get("encryption_state") or ""),
        str(finding.get("parent_finding_type") or ""),
    )

    occurrences = _canonical_occurrences(finding, file_obj, finding_id, location_id)
    evidence_ids = [item["occurrence_id"] for item in occurrences]
    risk_score = int(finding.get("risk_score") or finding.get("operational_risk_score") or _severity_floor(severity, confidence))

    finding.update(
        {
            "finding_id": finding.get("finding_id") or finding_id,
            "rule_id": rule_id,
            "rule_version": str(finding.get("rule_version") or finding.get("rule_catalog_version") or finding.get("version") or "1.0.0"),
            "detector_version": str(finding.get("detector_version") or file_obj.get("detector_version") or "unknown"),
            "entity_type": entity_type,
            "framework_mappings": _framework_mappings(finding),
            "framework": normalize_framework_id(finding.get("framework")),
            "display_name": finding.get("display_name") or get_finding_display_name(finding),
            "display_name_az": finding.get("display_name_az") or get_finding_display_name(finding, "az"),
            "technical_type": finding.get("technical_type") or finding.get("type") or "",
            "impact_severity": severity,
            "confidence": confidence,
            "risk_score": risk_score,
            "asset_id": asset_id,
            "location_id": location_id,
            "logical_boundary_id": logical_boundary_id,
            "occurrence_count": occurrence_count,
            "unique_value_count": unique_value_count,
            "protection_state": str(finding.get("protection_state") or finding.get("encryption_state") or "NOT_ASSESSED").upper(),
            "exposure_state": _exposure_state(finding, file_obj),
            "environment": str(finding.get("environment") or file_obj.get("environment") or "UNKNOWN").upper(),
            "retention_state": _retention_state(finding, file_obj),
            "first_seen": str(finding.get("first_seen") or timestamp),
            "last_seen": str(finding.get("last_seen") or timestamp),
            "status": str(finding.get("status") or finding.get("review_status") or "OPEN").upper(),
            "owner": str(finding.get("owner") or finding.get("data_owner") or file_obj.get("owner") or file_obj.get("department") or "unknown"),
            "sla_due": str(finding.get("sla_due") or _sla_due(timestamp, severity)),
            "parent_finding_id": finding.get("parent_finding_id"),
            "evidence_ids": evidence_ids,
            "occurrences": occurrences,
        }
    )
    return finding


def _canonical_occurrences(finding: dict, file_obj: dict, finding_id: str, location_id: str) -> list[dict]:
    source = finding.get("occurrences") if isinstance(finding.get("occurrences"), list) else []
    if not source:
        samples = finding.get("samples") if isinstance(finding.get("samples"), list) else []
        fingerprints = finding.get("secure_value_fingerprints") or finding.get("secure_fingerprints") or []
        source = [
            {
                "sample": sample,
                "secure_fingerprint": fingerprints[index] if index < len(fingerprints) else "",
                "occurrence_index": index + 1,
                "file": file_obj.get("path") or file_obj.get("name") or "",
            }
            for index, sample in enumerate(samples[:20] or [""])
        ]

    file_id = _file_id(file_obj)
    rows: list[dict] = []
    for index, item in enumerate(source[:100]):
        secure_fingerprint = str(
            item.get("secure_fingerprint")
            or item.get("fingerprint")
            or _fingerprint_at(finding, index)
            or ""
        )
        redacted_sample = str(item.get("redacted_sample") or item.get("sample") or _sample_at(finding, index) or "")
        occurrence_id = _stable_id(
            "occurrence",
            finding_id,
            file_id,
            str(item.get("page") or ""),
            str(item.get("row") or ""),
            str(item.get("column") or ""),
            str(item.get("offset_start") or ""),
            secure_fingerprint,
            redacted_sample,
            str(item.get("occurrence_index") or index + 1),
        )
        rows.append(
            {
                "occurrence_id": occurrence_id,
                "finding_id": finding_id,
                "file_id": file_id,
                "location_id": item.get("location_id") or location_id,
                "page": item.get("page"),
                "row": item.get("row"),
                "column": item.get("column") or item.get("JSONPath") or item.get("XPath") or "",
                "offset_start": int(item.get("offset_start") or 0),
                "offset_end": int(item.get("offset_end") or 0),
                "secure_fingerprint": secure_fingerprint,
                "redacted_sample": redacted_sample,
            }
        )
    return rows


def _framework_mappings(finding: dict) -> list[str]:
    frameworks = []
    for item in finding.get("frameworks") or []:
        frameworks.append(_framework_label(item))
    if finding.get("framework"):
        frameworks.append(_framework_label(finding["framework"]))
    for mapping in finding.get("requirement_mappings") or []:
        frameworks.append(_framework_label(mapping.get("framework") or "PCI DSS"))
    for mapping in finding.get("gdpr_article_mappings") or []:
        frameworks.append(_framework_label(mapping.get("framework") or "GDPR"))
    return list(dict.fromkeys(item for item in frameworks if item))


def _entity_type(finding: dict) -> str:
    if finding.get("data_element"):
        return str(finding["data_element"]).upper().replace(" ", "_")
    if finding.get("pci_category") == "SAD":
        return "SAD"
    finding_type = str(finding.get("type") or "").lower()
    category = str(finding.get("category") or finding.get("personal_data_type") or "").lower()
    if "pan" in finding_type:
        return "PAN"
    if "cvv" in finding_type:
        return "CVV"
    if "pin" in finding_type:
        return "PIN"
    if "email" in finding_type:
        return "EMAIL_ADDRESS"
    if "passport" in finding_type:
        return "PASSPORT_NUMBER"
    if "health" in category or "health" in finding_type:
        return "HEALTH_DATA"
    return str(finding.get("entity_type") or category or finding_type or "SENSITIVE_DATA").upper()


def _asset_id(file_obj: dict) -> str:
    return str(file_obj.get("asset_id") or file_obj.get("host_id") or file_obj.get("source_id") or file_obj.get("device_id") or _stable_id("asset", str(file_obj.get("source") or ""), str(file_obj.get("share") or ""), str(file_obj.get("path") or file_obj.get("name") or "")))


def _file_id(file_obj: dict) -> str:
    return str(file_obj.get("file_id") or file_obj.get("sha256") or file_obj.get("file_hash") or _stable_id("file", str(file_obj.get("path") or file_obj.get("name") or ""), str(file_obj.get("size") or ""), str(file_obj.get("modified") or "")))


def _location_id(file_obj: dict) -> str:
    return str(file_obj.get("location_id") or _stable_id("location", str(file_obj.get("path") or file_obj.get("name") or ""), str(file_obj.get("share") or ""), str(file_obj.get("source") or "")))


def _logical_boundary_id(finding: dict, file_obj: dict) -> str:
    return str(finding.get("logical_boundary_id") or _stable_id("boundary", str(finding.get("logical_boundary") or ""), str(file_obj.get("source") or ""), str(file_obj.get("share") or "")))


def _confidence(finding: dict) -> int:
    value = finding.get("confidence")
    if value is None:
        value = finding.get("detection_confidence")
    if isinstance(value, (int, float)):
        return max(0, min(100, int(value)))
    normalized = str(value or "").lower()
    if normalized in {"high", "confirmed", "verified"}:
        return 90
    if normalized in {"medium", "review", "needs_review", "probable"}:
        return 70
    if normalized:
        return 40
    return 50


def _unique_value_count(finding: dict) -> int:
    if finding.get("unique_value_count") is not None:
        return max(int(finding.get("unique_value_count") or 0), 0)
    fingerprints = finding.get("secure_value_fingerprints") or finding.get("secure_fingerprints") or []
    if fingerprints:
        return len(set(str(item) for item in fingerprints))
    samples = finding.get("samples") or []
    return len(set(str(item) for item in samples)) if samples else 1


def _exposure_state(finding: dict, file_obj: dict) -> str:
    if finding.get("exposure_state"):
        return str(finding["exposure_state"]).upper()
    permissions = file_obj.get("permissions") or {}
    if permissions.get("public"):
        return "PUBLIC"
    if permissions.get("wide_access"):
        return "BROAD_INTERNAL"
    if permissions.get("writable"):
        return "WRITABLE_INTERNAL"
    if file_obj.get("source") == "smb":
        return "NETWORK_SHARE"
    return "UNKNOWN"


def _retention_state(finding: dict, file_obj: dict) -> str:
    value = finding.get("retention_state")
    if value:
        return str(value).upper()
    if str(finding.get("retention_expired") or file_obj.get("retention_expired") or "").lower() in {"true", "yes", "expired"}:
        return "EXPIRED"
    if finding.get("retention_period"):
        return "DEFINED"
    return "UNKNOWN"


def _sla_due(timestamp: str, severity: str) -> str:
    try:
        base = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        base = datetime.now(timezone.utc)
    days = {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 14, "LOW": 30}.get(severity, 30)
    return (base + timedelta(days=days)).isoformat()


def _severity_floor(severity: str, confidence: int) -> int:
    return min(100, max(SEVERITY_SCORE.get(severity, 20), confidence))


def _framework_label(value: str) -> str:
    normalized = str(value or "").strip().lower().replace("-", "_")
    return {"pci_dss": "PCI DSS", "gdpr": "GDPR", "hipaa": "HIPAA", "nist_sp800_60_enterprise": "NIST SP 800-60 Enterprise"}.get(normalized, str(value or "").strip())


def _sample_at(finding: dict, index: int) -> str:
    samples = finding.get("samples") or []
    return str(samples[index]) if index < len(samples) else ""


def _fingerprint_at(finding: dict, index: int) -> str:
    fingerprints = finding.get("secure_value_fingerprints") or finding.get("secure_fingerprints") or []
    return str(fingerprints[index]) if index < len(fingerprints) else ""


def _stable_id(prefix: str, *parts: str) -> str:
    raw = "|".join(str(part or "") for part in parts)
    return f"{prefix}_{hashlib.sha256(raw.encode('utf-8', errors='ignore')).hexdigest()[:24]}"
