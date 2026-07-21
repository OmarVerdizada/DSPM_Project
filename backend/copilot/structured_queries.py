from __future__ import annotations

from collections import Counter
from typing import Any


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _severity(value: Any) -> str:
    text = str(value or "").upper()
    if text in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return text
    return "UNKNOWN"


def _risk_score(file_item: dict[str, Any]) -> float:
    risk = file_item.get("risk") if isinstance(file_item.get("risk"), dict) else {}
    try:
        return float(risk.get("score") if risk.get("score") is not None else file_item.get("risk_score") or 0)
    except (TypeError, ValueError):
        return 0.0


def _risk_level(file_item: dict[str, Any]) -> str:
    risk = file_item.get("risk") if isinstance(file_item.get("risk"), dict) else {}
    return _severity(risk.get("level") or file_item.get("severity"))


def _finding_types(file_item: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for finding in file_item.get("findings") or []:
        if isinstance(finding, dict):
            finding_type = str(finding.get("type") or finding.get("name") or "").strip()
            if finding_type:
                values.append(finding_type)
    return sorted(set(values))


def normalize_finding(file_item: dict[str, Any], scan_id: str | None = None) -> dict[str, Any]:
    name = str(file_item.get("name") or file_item.get("path") or "unknown")
    return {
        "name": name.split("\\")[-1].split("/")[-1],
        "scan_id": scan_id,
        "severity": _risk_level(file_item),
        "risk_score": _risk_score(file_item),
        "risk_types": _finding_types(file_item),
        "source_type": "finding",
    }


def _items(report: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(report, dict):
        return []
    scan_id = report.get("scan_id")
    return [normalize_finding(item, scan_id) for item in report.get("files") or [] if isinstance(item, dict)]


def _stable_identity(file_item: dict[str, Any]) -> str:
    explicit = file_item.get("safe_identifier") or file_item.get("id") or file_item.get("finding_id")
    if explicit:
        return str(explicit)
    name = str(file_item.get("name") or file_item.get("path") or "unknown").replace("\\", "/").rstrip("/")
    name = name.split("/")[-1] or name
    types = ",".join(_finding_types(file_item))
    return f"{name}|{types}" if types else name


def _indexed_items(report: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(report, dict):
        return {}
    scan_id = report.get("scan_id")
    indexed: dict[str, dict[str, Any]] = {}
    for file_item in report.get("files") or []:
        if isinstance(file_item, dict):
            normalized = normalize_finding(file_item, scan_id)
            normalized["id"] = _stable_identity(file_item)
            indexed[str(normalized["id"])] = normalized
    return indexed


def _severity_counts_from_items(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(_severity(item.get("severity")) for item in items)
    return {severity: int(counts.get(severity, 0)) for severity in SEVERITIES}


def _average_risk_score(items: list[dict[str, Any]]) -> float | None:
    scores = []
    for item in items:
        try:
            scores.append(float(item.get("risk_score") or 0))
        except (TypeError, ValueError):
            continue
    if not scores:
        return None
    return round(sum(scores) / len(scores), 2)


def _posture_value(report: dict[str, Any] | None) -> int | float | None:
    if not isinstance(report, dict):
        return None
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    for container in (summary, report):
        for key in ("posture_score", "security_posture_score", "risk_posture_score"):
            value = container.get(key)
            if value is None:
                continue
            try:
                score = float(value)
            except (TypeError, ValueError):
                continue
            return int(score) if score.is_integer() else score
    return None


def _scan_delta_verdict(severity_deltas: dict[str, int], new_count: int, resolved_count: int) -> str:
    worsened_signals = (
        severity_deltas.get("CRITICAL", 0) > 0
        or severity_deltas.get("HIGH", 0) > 0
        or new_count > resolved_count
    )
    improved_signals = (
        severity_deltas.get("CRITICAL", 0) < 0
        or severity_deltas.get("HIGH", 0) < 0
        or resolved_count > new_count
    )
    if not worsened_signals and not improved_signals and all(value == 0 for value in severity_deltas.values()):
        return "unchanged"
    if worsened_signals and improved_signals:
        return "mixed"
    if worsened_signals:
        return "worsened"
    return "improved"


def compare_scan_reports(
    latest_report: dict[str, Any] | None,
    previous_report: dict[str, Any] | None,
) -> dict[str, Any]:
    latest_index = _indexed_items(latest_report)
    previous_index = _indexed_items(previous_report)
    latest_ids = set(latest_index)
    previous_ids = set(previous_index)
    new_ids = sorted(latest_ids - previous_ids)
    resolved_ids = sorted(previous_ids - latest_ids)
    common_ids = sorted(latest_ids & previous_ids)

    latest_items = list(latest_index.values())
    previous_items = list(previous_index.values())
    latest_counts = _severity_counts_from_items(latest_items)
    previous_counts = _severity_counts_from_items(previous_items)
    severity_delta = {severity: latest_counts.get(severity, 0) - previous_counts.get(severity, 0) for severity in SEVERITIES}

    severity_changes = []
    for item_id in common_ids:
        before = _severity(previous_index[item_id].get("severity"))
        after = _severity(latest_index[item_id].get("severity"))
        if before != after:
            severity_changes.append({
                "id": item_id,
                "name": latest_index[item_id].get("name"),
                "previous_severity": before,
                "latest_severity": after,
            })

    latest_avg = _average_risk_score(latest_items)
    previous_avg = _average_risk_score(previous_items)
    risk_score_delta = None
    if latest_avg is not None and previous_avg is not None:
        risk_score_delta = round(latest_avg - previous_avg, 2)
    latest_posture = _posture_value(latest_report)
    previous_posture = _posture_value(previous_report)
    posture_delta = None
    if latest_posture is not None and previous_posture is not None:
        posture_delta = latest_posture - previous_posture

    return {
        "result_type": "scan_delta",
        "latest_scan_id": (latest_report or {}).get("scan_id") if isinstance(latest_report, dict) else None,
        "previous_scan_id": (previous_report or {}).get("scan_id") if isinstance(previous_report, dict) else None,
        "latest_total_findings": len(latest_items),
        "previous_total_findings": len(previous_items),
        "total_finding_count_delta": len(latest_items) - len(previous_items),
        "latest_severity_counts": latest_counts,
        "previous_severity_counts": previous_counts,
        "severity_delta": severity_delta,
        "new_findings_count": len(new_ids),
        "resolved_findings_count": len(resolved_ids),
        "common_findings_count": len(common_ids),
        "new_findings": [latest_index[item_id] for item_id in new_ids[:10]],
        "resolved_findings": [previous_index[item_id] for item_id in resolved_ids[:10]],
        "common_findings": [latest_index[item_id] for item_id in common_ids[:10]],
        "severity_changes": severity_changes[:10],
        "latest_average_risk_score": latest_avg,
        "previous_average_risk_score": previous_avg,
        "risk_score_delta": risk_score_delta,
        "latest_posture_score": latest_posture,
        "previous_posture_score": previous_posture,
        "posture_delta": posture_delta,
        "verdict": _scan_delta_verdict(severity_delta, len(new_ids), len(resolved_ids)),
        "metric": "file_level_finding_count",
    }


def scan_delta_summary(
    latest_report: dict[str, Any] | None,
    previous_report: dict[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(latest_report, dict):
        return {
            "result_type": "scan_delta",
            "has_latest_scan": False,
            "has_previous_scan": False,
            "metric": "file_level_finding_count",
        }
    if not isinstance(previous_report, dict):
        latest_items = _items(latest_report)
        return {
            "result_type": "scan_delta",
            "has_latest_scan": True,
            "has_previous_scan": False,
            "latest_scan_id": latest_report.get("scan_id"),
            "latest_total_findings": len(latest_items),
            "latest_severity_counts": _severity_counts_from_items(latest_items),
            "metric": "file_level_finding_count",
        }
    payload = compare_scan_reports(latest_report, previous_report)
    payload["has_latest_scan"] = True
    payload["has_previous_scan"] = True
    return payload


def _matches(item: dict[str, Any], severity: str | None = None, risk_type: str | None = None) -> bool:
    if severity and item.get("severity") != severity.upper():
        return False
    if risk_type:
        needle = risk_type.lower()
        if not any(needle in str(value).lower() for value in item.get("risk_types") or []):
            return False
    return True


def count_findings(report: dict[str, Any] | None, severity: str | None = None, risk_type: str | None = None) -> dict[str, Any]:
    items = [item for item in _items(report) if _matches(item, severity, risk_type)]
    return {
        "scan_id": (report or {}).get("scan_id") if isinstance(report, dict) else None,
        "result_type": "finding_count",
        "severity": severity.upper() if severity else None,
        "risk_type": risk_type,
        "count": len(items),
    }


def filter_findings(
    report: dict[str, Any] | None,
    severity: str | None = None,
    risk_type: str | None = None,
    limit: int | None = None,
    sort_by: str = "risk_score",
) -> dict[str, Any]:
    matched = [item for item in _items(report) if _matches(item, severity, risk_type)]
    if sort_by == "name":
        matched.sort(key=lambda item: str(item.get("name") or ""))
    else:
        matched.sort(key=lambda item: (-float(item.get("risk_score") or 0), str(item.get("name") or "")))
    safe_limit = max(1, min(int(limit or 10), 50))
    return {
        "scan_id": (report or {}).get("scan_id") if isinstance(report, dict) else None,
        "result_type": "finding_list",
        "severity": severity.upper() if severity else None,
        "risk_type": risk_type,
        "count": len(matched),
        "returned": min(len(matched), safe_limit),
        "items": matched[:safe_limit],
    }


def compare_findings(
    current_report: dict[str, Any] | None,
    previous_report: dict[str, Any] | None,
    severity: str | None = None,
) -> dict[str, Any]:
    current = [item for item in _items(current_report) if _matches(item, severity)]
    previous = [item for item in _items(previous_report) if _matches(item, severity)]
    current_names = {str(item["name"]) for item in current}
    previous_names = {str(item["name"]) for item in previous}
    current_by_name = {str(item["name"]): item for item in current}
    previous_by_name = {str(item["name"]): item for item in previous}
    added_names = sorted(current_names - previous_names)
    resolved_names = sorted(previous_names - current_names)
    persisting_names = sorted(current_names & previous_names)
    return {
        "current_scan_id": (current_report or {}).get("scan_id") if isinstance(current_report, dict) else None,
        "previous_scan_id": (previous_report or {}).get("scan_id") if isinstance(previous_report, dict) else None,
        "result_type": "finding_comparison",
        "severity": severity.upper() if severity else None,
        "added": added_names,
        "resolved": resolved_names,
        "persisting": persisting_names,
        "added_critical_count": sum(1 for name in added_names if current_by_name.get(name, {}).get("severity") == "CRITICAL"),
        "resolved_critical_count": sum(1 for name in resolved_names if previous_by_name.get(name, {}).get("severity") == "CRITICAL"),
        "persisting_critical_count": sum(1 for name in persisting_names if current_by_name.get(name, {}).get("severity") == "CRITICAL"),
    }


def summarize_risks(report: dict[str, Any] | None) -> dict[str, Any]:
    items = _items(report)
    severity_counts = Counter(item.get("severity") for item in items)
    risk_type_counts: Counter[str] = Counter()
    for item in items:
        risk_type_counts.update(item.get("risk_types") or [])
    top = sorted(items, key=lambda item: (-float(item.get("risk_score") or 0), str(item.get("name") or "")))[:10]
    return {
        "scan_id": (report or {}).get("scan_id") if isinstance(report, dict) else None,
        "result_type": "risk_summary",
        "total": len(items),
        "severity_counts": dict(severity_counts),
        "risk_type_counts": dict(risk_type_counts),
        "top_risks": top,
    }


def proactive_alert_summary(report: dict[str, Any] | None, previous_report: dict[str, Any] | None = None) -> dict[str, Any]:
    summary = summarize_risks(report)
    previous = summarize_risks(previous_report) if isinstance(previous_report, dict) else None
    current_counts = {key: int(value or 0) for key, value in (summary.get("severity_counts") or {}).items()}
    previous_counts = {key: int(value or 0) for key, value in ((previous or {}).get("severity_counts") or {}).items()}
    deltas = {severity: current_counts.get(severity, 0) - previous_counts.get(severity, 0) for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    risk_type_counts = summary.get("risk_type_counts") or {}
    top_types = [name for name, _count in sorted(risk_type_counts.items(), key=lambda item: (-int(item[1] or 0), str(item[0])))[:5]]
    return {
        "scan_id": summary.get("scan_id"),
        "result_type": "proactive_alert_summary",
        "severity_counts": current_counts,
        "severity_deltas": deltas,
        "top_risk_types": top_types,
        "top_risks": summary.get("top_risks") or [],
        "notification_available": False,
        "notification_sent": False,
        "has_previous_scan": previous is not None,
    }
