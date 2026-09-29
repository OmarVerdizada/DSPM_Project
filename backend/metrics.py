"""Prometheus metrics for the pilot's monitoring (D11).

`GET /metrics` answers in the Prometheus text format (0.0.4). A scraper authenticates
with `Authorization: Bearer <DSPM_METRICS_TOKEN>` (compared in constant time; unset, the
endpoint answers only the installation's administrator). What it exposes is the
installation's health, counted across every workspace and never broken down by one: no
workspace name, path, value or secret is in a metric.

    sentro_up, sentro_build_info, sentro_ready
    sentro_http_requests_total{method,code}, sentro_http_request_duration_seconds (histogram)
    sentro_scan_jobs{state}, sentro_scan_job_oldest_queued_seconds
    sentro_scan_partitions{state}, sentro_scan_partition_oldest_queued_seconds
    sentro_siem_outbox_events, sentro_siem_outbox_failing, sentro_siem_outbox_oldest_seconds
    sentro_alert_deliveries_pending, sentro_alert_deliveries_failing
    sentro_backup_age_seconds, sentro_backup_sets, sentro_backup_last_attempt_success,
    sentro_backup_last_attempt_timestamp_seconds
    sentro_licence_valid
    sentro_collector_up{collector}      - 0 when a collector failed; the rest still answer

`deploy/monitoring/` holds a scrape configuration and the alert rules that page on these
(the queue stuck, a backup failed or too old, the SIEM or an alert channel failing).
"""

from __future__ import annotations

import hmac
import json
import os
import threading
import time
from datetime import datetime, timezone

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

_lock = threading.Lock()
_requests: dict[tuple[str, str], int] = {}
_durations = [0] * (len(BUCKETS) + 1)
_duration_sum = 0.0
_duration_count = 0


def record_request(method: str, status: int, seconds: float) -> None:
    """Called by the request middleware; the path is not recorded (it can carry ids)."""
    global _duration_sum, _duration_count
    key = (str(method or "GET").upper()[:10], str(int(status or 0)))
    with _lock:
        _requests[key] = _requests.get(key, 0) + 1
        index = next((position for position, bound in enumerate(BUCKETS) if seconds <= bound), len(BUCKETS))
        _durations[index] += 1
        _duration_sum += max(0.0, float(seconds))
        _duration_count += 1


def token_allowed(header: str) -> bool:
    """Whether an Authorization header carries the configured metrics token."""
    expected = os.getenv("DSPM_METRICS_TOKEN", "").strip()
    if not expected or not header.lower().startswith("bearer "):
        return False
    return hmac.compare_digest(header[7:].strip().encode("utf-8"), expected.encode("utf-8"))


def _escape(value) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class _Out:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.declared: set[str] = set()

    def metric(self, name: str, kind: str, text: str, value, labels: dict | None = None) -> None:
        if name not in self.declared:
            self.lines.append(f"# HELP {name} {text}")
            self.lines.append(f"# TYPE {name} {kind}")
            self.declared.add(name)
        label = ""
        if labels:
            label = "{" + ",".join(f'{key}="{_escape(item)}"' for key, item in sorted(labels.items())) + "}"
        number = float(value)
        self.lines.append(f"{name}{label} {int(number) if number.is_integer() else round(number, 6)}")


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


def _build(out: _Out, info: dict) -> None:
    out.metric("sentro_build_info", "gauge", "The running release.", 1,
               {"release": info.get("label") or info.get("release") or "dev", "commit": str(info.get("commit") or "")[:12],
                "schema_revision": info.get("schema_revision") or ""})


def _queue(out: _Out) -> None:
    from backend import store

    jobs = store.metrics_scan_jobs()
    # The states an alert rule reads are always there, at 0 when nothing is in them.
    for state in sorted(set(jobs["states"]) | {"queued", "running"}):
        out.metric("sentro_scan_jobs", "gauge", "Scan jobs by state, every workspace together.",
                   jobs["states"].get(state, 0), {"state": state})
    out.metric("sentro_scan_job_oldest_queued_seconds", "gauge", "Age of the oldest scan job still queued.",
               _age(jobs["oldest_queued"]))
    partitions = store.metrics_scan_partitions()
    for state in sorted(set(partitions["states"]) | {"queued", "running"}):
        out.metric("sentro_scan_partitions", "gauge", "Scan partitions by state.", partitions["states"].get(state, 0),
                   {"state": state})
    out.metric("sentro_scan_partition_oldest_queued_seconds", "gauge", "Age of the oldest partition still queued.",
               _age(partitions["oldest_queued"]))


def _siem(out: _Out) -> None:
    from backend import store

    status = store.audit_outbox_status()
    out.metric("sentro_siem_outbox_events", "gauge", "Audit events waiting for the SIEM.", status.get("pending") or 0)
    out.metric("sentro_siem_outbox_failing", "gauge", "Waiting audit events that failed at least once.",
               status.get("failing") or 0)
    out.metric("sentro_siem_outbox_oldest_seconds", "gauge", "Age of the oldest audit event waiting for the SIEM.",
               status.get("oldest_seconds") or 0)


def _alerts(out: _Out) -> None:
    from backend import store

    deliveries = store.metrics_alert_deliveries()
    out.metric("sentro_alert_deliveries_pending", "gauge", "Alert deliveries and tickets waiting.",
               deliveries["pending"])
    out.metric("sentro_alert_deliveries_failing", "gauge", "Waiting alert deliveries and tickets that failed at least once.",
               deliveries["failing"])


def _backup(out: _Out) -> None:
    from backend import backup, store

    age = backup.latest_backup_age_seconds()
    out.metric("sentro_backup_sets", "gauge", "Backup sets kept.", len(backup.list_manifests()))
    out.metric("sentro_backup_age_seconds", "gauge", "Age of the newest backup (-1: none yet).",
               -1 if age is None else round(age, 1))
    attempt = json.loads(store.get_app_setting("backup.last_attempt") or "{}")
    if attempt:
        out.metric("sentro_backup_last_attempt_success", "gauge", "Whether the last backup attempt succeeded.",
                   1 if attempt.get("ok") else 0)
        out.metric("sentro_backup_last_attempt_timestamp_seconds", "gauge", "When the last backup was attempted.",
                   datetime.fromisoformat(attempt["at"]).timestamp())


def _licence(out: _Out) -> None:
    from backend import licensing

    state = licensing.status(licensing.installed())["state"]
    out.metric("sentro_licence_valid", "gauge", "1 while the licence is valid or in its grace period.",
               1 if state in {"valid", "grace"} else 0)


def render(*, ready: bool, build: dict) -> str:
    out = _Out()
    out.metric("sentro_up", "gauge", "The backend answers.", 1)
    out.metric("sentro_ready", "gauge", "1 when /api/ready would answer ready.", 1 if ready else 0)
    _build(out, build)
    with _lock:
        requests = dict(_requests)
        durations, total, count = list(_durations), _duration_sum, _duration_count
    for (method, code), value in sorted(requests.items()):
        out.metric("sentro_http_requests_total", "counter", "HTTP requests answered, by method and status.",
                   value, {"method": method, "code": code})
    name = "sentro_http_request_duration_seconds"
    out.lines.append(f"# HELP {name} Time to answer a request.")
    out.lines.append(f"# TYPE {name} histogram")
    running = 0
    for bound, hits in zip((*BUCKETS, "+Inf"), durations):
        running += hits
        out.lines.append(f'{name}_bucket{{le="{bound}"}} {running}')
    out.lines.append(f"{name}_sum {round(total, 6)}")
    out.lines.append(f"{name}_count {count}")
    for collector, function in (("queue", _queue), ("siem", _siem), ("alerts", _alerts), ("backup", _backup),
                                ("licence", _licence)):
        started, declared = len(out.lines), set(out.declared)
        try:
            function(out)
            up = 1
        except Exception:  # one collector failing must not take the rest down with it
            del out.lines[started:]
            out.declared = declared
            up = 0
        out.metric("sentro_collector_up", "gauge", "Whether each collector answered.", up, {"collector": collector})
    return "\n".join(out.lines) + "\n"


def monotonic() -> float:
    return time.perf_counter()
