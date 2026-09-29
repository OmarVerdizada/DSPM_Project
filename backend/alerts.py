"""What a scan raises (D3).

An alert is recorded, written to the audit trail (and so to the SIEM when one is set),
and queued for each of the workspace's channels in one transaction (store.save_alerts);
the deliverer (backend.alert_delivery) sends it. Nothing is sent from inside the scan's
request, and a receiver that is down delays an alert rather than losing it.
"""

from __future__ import annotations

from backend.store import save_alerts


def evaluate_alerts(tenant_id: str, report: dict) -> list[dict]:
    summary = report.get("summary", {})
    alerts: list[dict] = []
    if summary.get("critical", 0) > 0:
        alerts.append(
            {
                "severity": "CRITICAL",
                "title": "Critical sensitive exposure detected",
                "message": f"{summary.get('critical')} critical files found in scan {report.get('scan_id', '')}",
            }
        )
    if alerts:
        for alert, alert_id in zip(alerts, save_alerts(tenant_id, report.get("scan_id"), alerts)):
            alert["alert_id"] = alert_id
        from backend.alert_delivery import kick

        kick()
    return alerts
