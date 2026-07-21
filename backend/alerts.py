from __future__ import annotations

import json
import os
from urllib import request

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
        save_alerts(tenant_id, report.get("scan_id"), alerts)
        _send_webhook(alerts)
    return alerts


def _send_webhook(alerts: list[dict]) -> None:
    url = os.getenv("DSPM_ALERT_WEBHOOK_URL")
    if not url:
        return
    payload = json.dumps({"alerts": alerts}).encode()
    req = request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        request.urlopen(req, timeout=5).read()
    except Exception:
        return
