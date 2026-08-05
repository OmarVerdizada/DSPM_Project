from __future__ import annotations

from collections import Counter
from pathlib import PurePosixPath
from typing import Any

from backend.security import Principal
from backend.store import read_scan_history, read_scan_report


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


class ScanComparisonError(Exception):
    """Raised when scan comparison evidence cannot be computed."""


def safe_name(value: Any) -> str:
    text = str(value or "").replace("\\", "/").rstrip("/")
    return PurePosixPath(text).name or text


def risk_level(file_obj: dict) -> str:
    return str((file_obj.get("risk") or {}).get("level") or "LOW").upper()


def risk_score(file_obj: dict) -> float:
    try:
        return float((file_obj.get("risk") or {}).get("score") or 0)
    except (TypeError, ValueError):
        return 0.0


def risk_types(file_obj: dict) -> list[str]:
    values: list[str] = []
    for finding in file_obj.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        value = str(finding.get("type") or "").strip()
        if value and value not in values:
            values.append(value)
    return values


def stable_identifier(file_obj: dict) -> str:
    explicit = file_obj.get("safe_identifier") or file_obj.get("hash") or file_obj.get("sha256")
    if explicit:
        return str(explicit)
    name = safe_name(file_obj.get("name") or file_obj.get("path"))
    types = ",".join(sorted(risk_types(file_obj)))
    return f"{name}|{types}" if types else name


def finding_brief(file_obj: dict, scan_id: str | None) -> dict:
    return {
        "scan_id": scan_id,
        "safe_identifier": stable_identifier(file_obj),
        "name": safe_name(file_obj.get("name") or file_obj.get("path")),
        "path": safe_name(file_obj.get("path")),
        "severity": risk_level(file_obj),
        "risk_score": risk_score(file_obj),
        "risk_types": risk_types(file_obj),
    }


def load_recent_reports(principal: Principal, limit: int = 2) -> list[dict]:
    safe_limit = max(1, min(int(limit or 2), 10))
    history = read_scan_history(principal.tenant_id, limit=safe_limit)
    reports: list[dict] = []
    for row in history:
        scan_id = row.get("scan_id")
        if not scan_id:
            continue
        report = read_scan_report(principal.tenant_id, str(scan_id))
        if report:
            reports.append(report)
    return reports


def _index_report(report: dict) -> dict[str, dict]:
    indexed: dict[str, dict] = {}
    for file_obj in report.get("files") or []:
        if isinstance(file_obj, dict):
            indexed[stable_identifier(file_obj)] = file_obj
    return indexed


def _severity_counts(files: list[dict]) -> dict[str, int]:
    counts = Counter(risk_level(item) for item in files if isinstance(item, dict))
    return {severity: int(counts.get(severity, 0)) for severity in SEVERITIES}


def compare_recent_scans(principal: Principal, limit: int = 2) -> dict:
    reports = load_recent_reports(principal, limit)
    if len(reports) < 2:
        raise ScanComparisonError("At least two scans are required for comparison.")
    previous = reports[-2]
    latest = reports[-1]
    previous_index = _index_report(previous)
    latest_index = _index_report(latest)
    previous_ids = set(previous_index)
    latest_ids = set(latest_index)

    new_ids = sorted(latest_ids - previous_ids)
    resolved_ids = sorted(previous_ids - latest_ids)
    recurring_ids = sorted(latest_ids & previous_ids)
    severity_changes = []
    for item_id in recurring_ids:
        before = risk_level(previous_index[item_id])
        after = risk_level(latest_index[item_id])
        if before != after:
            severity_changes.append(
                {
                    "safe_identifier": item_id,
                    "name": safe_name(latest_index[item_id].get("name") or latest_index[item_id].get("path")),
                    "previous_severity": before,
                    "latest_severity": after,
                }
            )

    latest_files = [item for item in latest.get("files") or [] if isinstance(item, dict)]
    previous_files = [item for item in previous.get("files") or [] if isinstance(item, dict)]
    latest_counts = _severity_counts(latest_files)
    previous_counts = _severity_counts(previous_files)
    return {
        "result_type": "scan_comparison",
        "scan_count": len(reports),
        "latest_scan_id": latest.get("scan_id"),
        "previous_scan_id": previous.get("scan_id"),
        "latest_total_findings": len(latest_files),
        "previous_total_findings": len(previous_files),
        "latest_severity_counts": latest_counts,
        "previous_severity_counts": previous_counts,
        "new_findings_count": len(new_ids),
        "resolved_findings_count": len(resolved_ids),
        "recurring_findings_count": len(recurring_ids),
        "new_critical_count": sum(1 for item_id in new_ids if risk_level(latest_index[item_id]) == "CRITICAL"),
        "resolved_critical_count": sum(1 for item_id in resolved_ids if risk_level(previous_index[item_id]) == "CRITICAL"),
        "recurring_critical_count": sum(1 for item_id in recurring_ids if risk_level(latest_index[item_id]) == "CRITICAL"),
        "new_findings": [finding_brief(latest_index[item_id], latest.get("scan_id")) for item_id in new_ids[:10]],
        "resolved_findings": [finding_brief(previous_index[item_id], previous.get("scan_id")) for item_id in resolved_ids[:10]],
        "recurring_findings": [finding_brief(latest_index[item_id], latest.get("scan_id")) for item_id in recurring_ids[:10]],
        "severity_changes": severity_changes[:10],
    }


def finding_history(principal: Principal, identifier: str | None = None, limit: int = 10) -> dict:
    reports = load_recent_reports(principal, limit)
    if not reports:
        raise ScanComparisonError("No scan history is available.")
    latest = reports[-1]
    needle = safe_name(identifier).lower() if identifier else ""
    target_id: str | None = None
    target_item: dict | None = None
    target_scan_id: str | None = None
    latest_index = _index_report(latest)
    for item_id, item in latest_index.items():
        names = {safe_name(item.get("name") or item.get("path")).lower(), safe_name(item.get("path")).lower(), item_id.lower()}
        if (needle and needle in names) or (not needle and not target_item):
            target_id = item_id
            target_item = item
            target_scan_id = latest.get("scan_id")
            break
    if not target_id and needle:
        for report in reversed(reports):
            for item_id, item in _index_report(report).items():
                names = {safe_name(item.get("name") or item.get("path")).lower(), safe_name(item.get("path")).lower(), item_id.lower()}
                if needle in names:
                    target_id = item_id
                    target_item = item
                    target_scan_id = report.get("scan_id")
                    break
            if target_id:
                break
    if not target_id or not target_item:
        raise ScanComparisonError("The referenced finding was not found in available scan history.")

    appearances: list[dict] = []
    for report in reports:
        item = _index_report(report).get(target_id)
        if item:
            appearances.append(
                {
                    "scan_id": report.get("scan_id"),
                    "timestamp": report.get("timestamp"),
                    "severity": risk_level(item),
                    "risk_score": risk_score(item),
                }
            )
    latest_scan_id = latest.get("scan_id")
    previous_scan_ids = [str(item["scan_id"]) for item in appearances if item.get("scan_id") != latest_scan_id]
    seen_in_previous = bool(previous_scan_ids)
    return {
        "result_type": "finding_history",
        "latest_scan_id": latest_scan_id,
        "item": finding_brief(target_item, target_scan_id),
        "is_new": not seen_in_previous,
        "seen_in_previous_scan": seen_in_previous,
        "recurring_since": appearances[0].get("scan_id") if seen_in_previous and appearances else None,
        "previous_scan_ids": previous_scan_ids,
        "appearances": appearances,
    }


def remediation_status(principal: Principal, identifier: str | None = None, limit: int = 10) -> dict:
    reports = load_recent_reports(principal, limit)
    if len(reports) < 2:
        raise ScanComparisonError("I do not have enough scan history to confirm remediation status.")
    history = finding_history(principal, identifier, limit)
    latest_scan_id = reports[-1].get("scan_id")
    appears_latest = any(item.get("scan_id") == latest_scan_id for item in history.get("appearances") or [])
    if appears_latest:
        status = "still_present"
        message = "This finding is still present in the latest scan, so it does not appear to be fixed yet."
    elif history.get("previous_scan_ids"):
        status = "possibly_remediated"
        message = "This finding was not detected in the latest scan. It may have been remediated, but I recommend re-scanning or reviewing remediation evidence before marking it fixed."
    else:
        status = "insufficient_history"
        message = "I do not have enough scan history to confirm remediation status."
    return {
        "result_type": "remediation_status",
        "status": status,
        "message": message,
        **history,
    }
