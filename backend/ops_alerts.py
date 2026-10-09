"""Alerts about the installation itself (D11): a stuck scan queue, a backup that failed or is
too old, a SIEM that stopped accepting events.

Checked every DSPM_OPS_ALERT_INTERVAL_SECONDS (300) by the alert deliverer, and raised as
alerts of the `default` workspace - the installation's - so they reach its channels
(webhook, e-mail) and the SIEM like any other alert (backend.alert_delivery). A condition
raises one alert when it starts and is not raised again until it has cleared: a queue that
stays stuck for a day is one alert, not 288. The same conditions are metrics
(backend.metrics) for a Prometheus that pages on its own.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

TENANT = "default"
STATE_SETTING = "ops_alerts.active"
_last_run = 0.0


def _float(name: str, default: float) -> float:
    try:
        return max(0.0, float(os.getenv(name, str(default))))
    except ValueError:
        return default


def interval_seconds() -> float:
    return max(30.0, _float("DSPM_OPS_ALERT_INTERVAL_SECONDS", 300))


def _age(iso: str) -> float:
    if not iso:
        return 0.0
    try:
        moment = datetime.fromisoformat(str(iso))
    except ValueError:
        return 0.0
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - moment).total_seconds())


def conditions() -> dict[str, dict]:
    """Every condition that holds now: {key: {"severity", "title", "message"}}."""
    from backend import backup, store

    found: dict[str, dict] = {}
    stuck = _float("DSPM_QUEUE_STUCK_MINUTES", 30) * 60
    jobs, partitions = store.metrics_scan_jobs(), store.metrics_scan_partitions()
    oldest = max(_age(jobs["oldest_queued"]), _age(partitions["oldest_queued"]))
    if stuck and oldest > stuck:
        found["queue_stuck"] = {"severity": "HIGH", "title": "Scan queue is not moving",
                                "message": f"A scan has waited {int(oldest // 60)} minutes to start. Check that the "
                                           "worker service is running (python main.py worker)."}
    attempt = json.loads(store.get_app_setting("backup.last_attempt") or "{}")
    if attempt and not attempt.get("ok"):
        found["backup_failed"] = {"severity": "HIGH", "title": "The last backup failed",
                                  "message": f"The backup attempted at {attempt.get('at')} failed "
                                             f"({attempt.get('error') or 'see the backup log'}). Run python main.py "
                                             "backup create --verify and read what it says."}
    max_age = _float("DSPM_BACKUP_MAX_AGE_HOURS", 26) * 3600
    # The newest VERIFIED set, as readiness measures it: a set that failed its verification
    # restores nothing, and hourly retries of one kept the newest-set age fresh.
    age = backup.latest_backup_age_seconds(verified=True)
    production = os.getenv("DSPM_ENV", "local").strip().lower() in {"prod", "production"}
    if max_age and ((age is not None and age > max_age) or (age is None and production)):
        found["backup_stale"] = {"severity": "HIGH", "title": "No recent backup",
                                 "message": ("There is no verified backup yet." if age is None else
                                             f"The newest verified backup is {int(age // 3600)} hours old.")
                                 + " Backups are what an upgrade and a recovery restore from."}
    outbox = store.audit_outbox_status()
    if outbox.get("failing") and float(outbox.get("oldest_seconds") or 0) > 900:
        found["siem_failing"] = {"severity": "HIGH", "title": "The SIEM is not accepting audit events",
                                 "message": f"{outbox.get('pending')} audit events are waiting; the oldest for "
                                            f"{int(float(outbox.get('oldest_seconds') or 0) // 60)} minutes. They are "
                                            "kept and sent when the SIEM answers."}
    return found


def evaluate() -> list[str]:
    """Raise an alert for each condition that has just started; forget those that cleared.
    Returns the keys raised."""
    from backend import alert_delivery, store

    now_holding = conditions()
    try:
        active = set(json.loads(store.get_app_setting(STATE_SETTING) or "[]"))
    except ValueError:
        active = set()
    started = [key for key in now_holding if key not in active]
    cleared = [key for key in active if key not in now_holding]
    if started:
        store.save_alerts(TENANT, None, [{**now_holding[key], "kind": f"ops.{key}"} for key in started])
        alert_delivery.kick()
    for key in cleared:
        store.audit(TENANT, "sentro", "ops.recovered", {"condition": key})
    if started or cleared:
        store.set_app_setting(STATE_SETTING, json.dumps(sorted(now_holding)))
    return started


def maybe_evaluate() -> None:
    """Called from the deliverer's loop; runs at most once an interval, never raises. Raises
    and records nothing on a database a newer release has upgraded (C0.4)."""
    global _last_run
    from backend import schema_guard

    if time.monotonic() - _last_run < interval_seconds():
        return
    if schema_guard.stand_down("installation's own alerting"):
        return
    _last_run = time.monotonic()
    try:
        evaluate()
    except Exception:
        logger.exception("Checking the installation's health for alerts failed")
