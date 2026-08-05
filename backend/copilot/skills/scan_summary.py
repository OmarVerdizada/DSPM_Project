from __future__ import annotations

from collections import Counter

from backend.copilot.skills.scan_comparison import risk_level, risk_types, safe_name
from backend.security import Principal
from backend.store import read_scan_report


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


class ScanSummaryError(Exception):
    """Raised when scan summary evidence cannot be computed."""


def severity_distribution(principal: Principal, scan_id: str | None = None) -> dict:
    report = read_scan_report(principal.tenant_id, scan_id)
    if not report:
        raise ScanSummaryError("No DSPM scan report is available for this tenant.")
    files = [item for item in report.get("files") or [] if isinstance(item, dict)]
    severity_counts = Counter(risk_level(item) for item in files)
    type_counts: Counter[str] = Counter()
    for item in files:
        for value in risk_types(item):
            type_counts[value] += 1
    return {
        "result_type": "severity_distribution",
        "scan_id": report.get("scan_id"),
        "timestamp": report.get("timestamp"),
        "total_findings": len(files),
        "severity_counts": {severity: int(severity_counts.get(severity, 0)) for severity in SEVERITIES},
        "top_risk_types": [{"type": value, "count": count} for value, count in type_counts.most_common(10)],
        "top_items": [
            {
                "name": safe_name(item.get("name") or item.get("path")),
                "severity": risk_level(item),
                "risk_types": risk_types(item)[:5],
            }
            for item in sorted(files, key=lambda value: (value.get("risk") or {}).get("score") or 0, reverse=True)[:5]
        ],
    }

