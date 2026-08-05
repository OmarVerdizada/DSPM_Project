from __future__ import annotations

import logging
from collections import Counter

from backend.copilot.insight_store import save_insights
from backend.copilot.insights import generate_insights
from backend.copilot.posture import compute_posture_score
from backend.store import read_scan_history, read_scan_report


_log = logging.getLogger(__name__)


def _risk_level(file_obj: dict) -> str:
    return str((file_obj.get("risk") or {}).get("level") or "LOW").lower()


def _scan_context(report: dict) -> dict:
    files = [item for item in report.get("files") or [] if isinstance(item, dict)]
    severity_counts = Counter(_risk_level(item) for item in files)
    findings_by_severity = {
        "critical": int(severity_counts.get("critical", 0)),
        "high": int(severity_counts.get("high", 0)),
        "medium": int(severity_counts.get("medium", 0)),
        "low": int(severity_counts.get("low", 0)),
    }
    exposed_assets = sum(1 for item in files if _risk_level(item) in {"critical", "high"})
    return {
        "scan_id": report.get("scan_id"),
        "scan_date": report.get("timestamp"),
        "findings_by_severity": findings_by_severity,
        "total_assets": len(files),
        "exposed_assets": exposed_assets,
    }


def _posture(scan: dict) -> int:
    score = compute_posture_score(
        scan.get("findings_by_severity") or {},
        total_assets=int(scan.get("total_assets") or 0),
        exposed_assets=int(scan.get("exposed_assets") or 0),
        remediated_count=0,
        total_actionable=sum((scan.get("findings_by_severity") or {}).values()),
    )
    return score.total_score


def _previous_report(tenant_id: str, scan_id: str) -> dict | None:
    history = read_scan_history(tenant_id, limit=50)
    ids = [str(item.get("scan_id")) for item in history if item.get("scan_id")]
    try:
        index = ids.index(scan_id)
    except ValueError:
        return None
    if index <= 0:
        return None
    return read_scan_report(tenant_id, ids[index - 1])


def on_scan_complete(tenant_id: str, scan_id: str) -> int:
    """Generate and persist proactive insight cards after a scan is saved."""

    current_report = read_scan_report(tenant_id, scan_id)
    if not current_report:
        return 0
    previous_report = _previous_report(tenant_id, scan_id)
    current_scan = _scan_context(current_report)
    previous_scan = _scan_context(previous_report) if previous_report else None
    current_score = _posture(current_scan)
    previous_score = _posture(previous_scan) if previous_scan else None
    insights = generate_insights(current_scan, previous_scan, current_score, previous_score)
    save_insights(insights, tenant_id=tenant_id)
    _log.info("copilot_insights_generated tenant=%s scan_id=%s count=%d", tenant_id, scan_id, len(insights))
    return len(insights)
