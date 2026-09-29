"""Delivering alerts, and creating and following tickets, from a queue (D3).

An alert is queued for each of its workspace's channels in the transaction that records
it (store.save_alerts). A deliverer thread - one per backend, the queue leased so two
backends never send the same delivery - sends what is due:

- a **webhook** is an HTTPS POST of the alert as JSON, signed:
  ``X-Sentro-Signature: t=<unix time>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>``.
  A receiver recomputes the HMAC with the signing secret it was shown and refuses a
  signature older than five minutes (``verify_signature`` is that check);
- an **e-mail** is a plain-text message through the workspace's relay.

A delivery that fails stays queued and is retried with a back-off that grows to five
minutes, until it is delivered - it is marked delivered only after the receiver
accepted it (a 2xx answer; a relay that took the message). Turning a channel off or
removing it cancels what was waiting, visibly. Each delivery, and a delivery's first
failure, is in the workspace's audit trail; the alert itself went there when it was
raised, and from there to the SIEM when one is set (syslog, CEF or JSON - C4).

Tickets go through a second queue in `finding_tickets`: created (safely repeatable,
backend.ticketing), then asked for their status every DSPM_TICKET_SYNC_SECONDS until the
ticket system says they are done - when the finding is resolved in Sentro.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import socket
import threading
import time
from datetime import datetime, timedelta, timezone

from backend import integrations
from backend.outbound import OutboundRefused, https_request, send_mail

logger = logging.getLogger(__name__)

MAX_BACKOFF_SECONDS = 300
LEASE_SECONDS = 120
SIGNATURE_TOLERANCE_SECONDS = 300
ACTOR = "sentro:delivery"


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _owner() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


def backoff(attempts: int) -> float:
    return float(min(MAX_BACKOFF_SECONDS, 2 ** max(1, attempts)))


# ── Signing ────────────────────────────────────────────────────────────────────────
def signature_header(secret: str, body: bytes, timestamp: int | None = None) -> str:
    moment = int(time.time()) if timestamp is None else int(timestamp)
    digest = hmac.new(secret.encode("utf-8"), f"{moment}.".encode("ascii") + body, hashlib.sha256).hexdigest()
    return f"t={moment},v1={digest}"


def verify_signature(secret: str, header: str, body: bytes, *, now: float | None = None,
                     tolerance: int = SIGNATURE_TOLERANCE_SECONDS) -> bool:
    """What a receiver checks: the HMAC over the timestamp and the body, and its age."""
    try:
        parts = dict(item.split("=", 1) for item in str(header or "").split(","))
        moment = int(parts["t"])
    except (ValueError, KeyError):
        return False
    current = time.time() if now is None else now
    if abs(current - moment) > tolerance:
        return False
    expected = signature_header(secret, body, moment).split("v1=", 1)[1]
    return hmac.compare_digest(expected, str(parts.get("v1") or ""))


# ── Sending ────────────────────────────────────────────────────────────────────────
def webhook_body(tenant_id: str, delivery_id: int, event: dict, *, kind: str = "alert.raised") -> bytes:
    return json.dumps({"event": kind, "delivery_id": delivery_id, "workspace": tenant_id,
                       "sent_at": _stamp(), "alert": event}, ensure_ascii=False, sort_keys=True).encode("utf-8")


def send_webhook(config: dict, secret: str, body: bytes, *, delivery: str, kind: str = "alert.raised") -> None:
    if not secret:
        raise OutboundRefused("The webhook has no signing secret; save it again to make one.")
    status, _ = https_request("POST", config["url"], body=body, ca_pem=str(config.get("ca_pem") or ""), headers={
        "Content-Type": "application/json", "X-Sentro-Event": kind, "X-Sentro-Delivery": delivery,
        "X-Sentro-Signature": signature_header(secret, body)})
    if not 200 <= status < 300:
        raise OutboundRefused(f"The webhook answered HTTP {status}; it was not accepted.")


def email_text(tenant_id: str, event: dict) -> tuple[str, str]:
    subject = f"[Sentro] {event.get('severity') or 'ALERT'}: {event.get('title') or 'Alert'}"[:200]
    lines = [
        f"{event.get('title') or 'Alert'}",
        "",
        str(event.get("message") or ""),
        "",
        f"Severity:  {event.get('severity') or '-'}",
        f"Workspace: {tenant_id}",
        f"Scan:      {event.get('scan_id') or '-'}",
        f"Raised:    {event.get('created_at') or '-'}",
        "",
        "Open Sentro DSPM -> Alerts to acknowledge it. This message holds no sensitive value.",
    ]
    return subject, "\n".join(lines)


def send_email(tenant_id: str, config: dict, secret: str, event: dict) -> None:
    subject, text = email_text(tenant_id, event)
    send_mail(host=config["host"], port=int(config["port"]), security=config["security"], sender=config["sender"],
              recipients=list(config["recipients"]), subject=subject, text=text,
              username=str(config.get("username") or ""), password=secret, ca_pem=str(config.get("ca_pem") or ""))


def _audit(tenant_id: str, action: str, detail: dict) -> None:
    from backend import store

    try:
        store.audit(tenant_id, ACTOR, action, detail)
    except Exception:  # an audit write that fails must not undo a delivery that happened
        logger.exception("Could not audit %s", action)


def deliver(row: dict) -> str:
    """Send one claimed delivery. Returns its outcome: delivered, cancelled or retry."""
    from backend import store

    tenant_id, channel = row["tenant_id"], row["channel"]
    attempts = int(row.get("attempts") or 0) + 1
    record, secret = integrations.load(tenant_id, channel)
    if record is None or not record.get("enabled"):
        store.finish_alert_delivery(tenant_id, row["id"], status="cancelled", attempts=attempts - 1,
                                    error="The channel was turned off or removed.")
        return "cancelled"
    config = record["config"]
    signature = integrations.config_signature(channel, config)
    event = json.loads(row["payload"])
    try:
        if channel == "webhook":
            send_webhook(config, secret, webhook_body(tenant_id, int(row["id"]), event), delivery=str(row["id"]))
        else:
            send_email(tenant_id, config, secret, event)
    except OutboundRefused as exc:
        message = str(exc)[:300]
        store.finish_alert_delivery(tenant_id, row["id"], status="pending", attempts=attempts, error=message,
                                    next_attempt_at=time.time() + backoff(attempts))
        store.record_alert_channel_status(tenant_id, channel, last_error=message, last_error_at=_stamp(),
                                          error_signature=signature)
        if attempts == 1:
            _audit(tenant_id, "alert.delivery_failed", {"alert_id": row["alert_id"], "channel": channel,
                                                        "error": message})
        return "retry"
    store.finish_alert_delivery(tenant_id, row["id"], status="delivered", attempts=attempts)
    store.record_alert_channel_status(tenant_id, channel, last_delivery_at=_stamp(), delivery_signature=signature)
    _audit(tenant_id, "alert.delivered", {"alert_id": row["alert_id"], "channel": channel, "attempts": attempts})
    return "delivered"


def drain(*, limit: int = 100, now: float | None = None) -> dict:
    """One pass over the alert queue."""
    from backend import store

    counts = {"delivered": 0, "retry": 0, "cancelled": 0}
    rows = store.claim_alert_deliveries(limit=limit, now=time.time() if now is None else now,
                                        lease_seconds=LEASE_SECONDS, owner=_owner())
    for row in rows:
        try:
            counts[deliver(row)] += 1
        except Exception:  # one bad row must not stop the rest; it is retried
            logger.exception("Alert delivery %s failed unexpectedly", row.get("id"))
            store.finish_alert_delivery(row["tenant_id"], row["id"], status="pending",
                                        attempts=int(row.get("attempts") or 0) + 1, error="Internal error.",
                                        next_attempt_at=time.time() + MAX_BACKOFF_SECONDS)
            counts["retry"] += 1
    return counts


# ── Tickets ────────────────────────────────────────────────────────────────────────
def sync_seconds() -> float:
    try:
        return max(30.0, float(os.getenv("DSPM_TICKET_SYNC_SECONDS", "300")))
    except ValueError:
        return 300.0


def ticket_text(finding: dict, tenant_id: str, finding_id: str) -> tuple[str, str]:
    """A ticket's summary and description: what the finding is and where - never a value."""
    kind = str(finding.get("type_label") or finding.get("label") or finding.get("type") or "Sensitive data")
    path = str(finding.get("path") or finding.get("file_path") or finding.get("asset_path") or "")
    risk = str(finding.get("risk_level") or finding.get("severity") or finding.get("level") or "")
    summary = f"[Sentro] {kind}" + (f" in {path.rsplit('/', 1)[-1].rsplit(chr(92), 1)[-1]}" if path else "")
    description = "\n".join(line for line in (
        "Sentro DSPM found sensitive data that needs remediation.",
        "",
        f"Finding: {finding_id}",
        f"Type: {kind}",
        f"Risk: {risk}" if risk else "",
        f"Location: {path}" if path else "",
        f"Workspace: {tenant_id}",
        "",
        "Close this ticket when it is remediated; Sentro resolves the finding when it sees the ticket closed.",
    ) if line is not None)
    return summary[:250], description


def _ticket_client(tenant_id: str, system: str):
    from backend import ticketing

    record, secret = integrations.load(tenant_id, system)
    if record is None or not record.get("enabled"):
        return None, record
    return ticketing.client(system, record["config"], secret), record


def create_ticket(row: dict) -> str:
    from backend import store

    tenant_id, ticket_id, system = row["tenant_id"], row["ticket_id"], row["system"]
    attempts = int(row.get("attempts") or 0) + 1
    client, record = _ticket_client(tenant_id, system)
    if client is None:
        store.update_finding_ticket(tenant_id, ticket_id, status="cancelled", attempts=attempts - 1,
                                    last_error="The ticket system was turned off or removed.")
        return "cancelled"
    payload = store.ticket_payload(tenant_id, ticket_id)
    try:
        found = client.find(ticket_id) or client.create(ticket_id, str(payload.get("summary") or "Sentro finding"),
                                                        str(payload.get("description") or ""))
    except OutboundRefused as exc:
        message = str(exc)[:300]
        store.update_finding_ticket(tenant_id, ticket_id, attempts=attempts, last_error=message,
                                    next_attempt_at=time.time() + backoff(attempts))
        store.record_alert_channel_status(tenant_id, system, last_error=message, last_error_at=_stamp(),
                                          error_signature=integrations.config_signature(system, record["config"]))
        if attempts == 1:
            _audit(tenant_id, "ticket.create_failed", {"ticket_id": ticket_id, "finding_id": row["finding_id"],
                                                       "system": system, "error": message})
        return "retry"
    now = _stamp()
    store.update_finding_ticket(tenant_id, ticket_id, status="open", attempts=attempts, last_error="",
                                opened_at=now, last_synced_at=now, **found)
    store.record_alert_channel_status(tenant_id, system, last_delivery_at=now,
                                      delivery_signature=integrations.config_signature(system, record["config"]))
    _audit(tenant_id, "ticket.created", {"ticket_id": ticket_id, "finding_id": row["finding_id"], "system": system,
                                         "external_key": found["external_key"]})
    return "created"


def sync_ticket(row: dict) -> str:
    """Ask the ticket system whether an open ticket is done; resolve its finding if so."""
    from backend import store

    tenant_id, ticket_id, system = row["tenant_id"], row["ticket_id"], row["system"]
    client, _ = _ticket_client(tenant_id, system)
    now = _stamp()
    if client is None:
        store.update_finding_ticket(tenant_id, ticket_id, last_synced_at=now,
                                    last_error="The ticket system is turned off; the ticket is not followed.")
        return "skipped"
    try:
        closed, external_status = client.status(str(row["external_id"]))
    except OutboundRefused as exc:
        store.update_finding_ticket(tenant_id, ticket_id, last_synced_at=now, last_error=str(exc)[:300])
        return "failed"
    if not closed:
        store.update_finding_ticket(tenant_id, ticket_id, last_synced_at=now, external_status=external_status,
                                    last_error="")
        return "open"
    store.update_finding_ticket(tenant_id, ticket_id, status="closed", closed_at=now, last_synced_at=now,
                                external_status=external_status, last_error="")
    key = str(row.get("external_key") or row["external_id"])
    resolved = False
    try:
        resolved = store.update_finding_lifecycle(
            tenant_id, row["finding_id"], "resolve",
            {"resolution": f"Ticket {key} closed in {system} ({external_status})",
             "comment": f"Resolved because {system} ticket {key} was closed."},
            f"{system}:{key}") is not None
    except ValueError:
        resolved = False  # a historical finding is read-only; the ticket is still recorded closed
    _audit(tenant_id, "ticket.closed", {"ticket_id": ticket_id, "finding_id": row["finding_id"], "system": system,
                                        "external_key": key, "finding_resolved": resolved})
    return "closed"


def drain_tickets(*, limit: int = 50, now: float | None = None) -> dict:
    from backend import store

    counts = {"created": 0, "retry": 0, "cancelled": 0, "open": 0, "closed": 0, "failed": 0, "skipped": 0}
    moment = time.time() if now is None else now
    sync_before = (datetime.now(timezone.utc) - timedelta(seconds=sync_seconds())).isoformat()
    for row in store.claim_ticket_work(limit=limit, now=moment, lease_seconds=LEASE_SECONDS, owner=_owner(),
                                       sync_before=sync_before):
        try:
            outcome = create_ticket(row) if row["status"] == "pending" else sync_ticket(row)
        except Exception:
            logger.exception("Ticket %s failed unexpectedly", row.get("ticket_id"))
            store.update_finding_ticket(row["tenant_id"], row["ticket_id"], last_error="Internal error.",
                                        next_attempt_at=time.time() + MAX_BACKOFF_SECONDS)
            outcome = "failed"
        counts[outcome] += 1
    return counts


def sync_tenant(tenant_id: str) -> dict:
    """Ask about every open ticket of one workspace now (the console's Sync now)."""
    from backend import store

    counts = {"open": 0, "closed": 0, "failed": 0, "skipped": 0}
    for row in store.open_tickets(tenant_id):
        counts[sync_ticket(row)] += 1
    return counts


# ── Testing a channel ──────────────────────────────────────────────────────────────
def test_channel(tenant_id: str, channel: str) -> dict:
    """Try a channel with its saved configuration. Returns {"ok", "message"}; the message is
    written here. A webhook test is a signed ``sentro.test`` event; a mail test, a message."""
    from backend import ticketing

    record, secret = integrations.load(tenant_id, channel)
    if record is None or not record.get("config"):
        return {"ok": False, "message": "Save the configuration first."}
    config = record["config"]
    try:
        if channel == "webhook":
            body = webhook_body(tenant_id, 0, {"title": "Sentro DSPM connection test - not an alert"}, kind="sentro.test")
            send_webhook(config, secret, body, delivery="test", kind="sentro.test")
            message = "The webhook accepted a signed test event."
        elif channel == "email":
            send_email(tenant_id, config, secret, {"severity": "TEST", "title": "Sentro DSPM connection test",
                                                   "message": "A test message - not an alert."})
            message = f"The relay accepted a test message for {len(config.get('recipients') or [])} recipient(s)."
        else:
            message = ticketing.client(channel, config, secret).test()
    except OutboundRefused as exc:
        return {"ok": False, "message": str(exc)[:300], "signature": integrations.config_signature(channel, config)}
    return {"ok": True, "message": message, "signature": integrations.config_signature(channel, config)}


# ── The thread ─────────────────────────────────────────────────────────────────────
_thread: threading.Thread | None = None
_thread_lock = threading.Lock()
_stop = threading.Event()
_wake = threading.Event()


def interval_seconds() -> float:
    try:
        return max(0.5, float(os.getenv("DSPM_ALERT_DELIVERY_INTERVAL_SECONDS", "5")))
    except ValueError:
        return 5.0


def kick() -> None:
    """Something was queued: send it now rather than at the next interval."""
    _wake.set()


def _loop(interval: float) -> None:
    while not _stop.is_set():
        _wake.wait(interval)
        _wake.clear()
        if _stop.is_set():
            return
        try:
            drain()
            drain_tickets()
        except Exception:  # the deliverer must outlive a bad pass
            logger.exception("Alert delivery pass failed")


def start_alert_deliverer() -> bool:
    global _thread
    with _thread_lock:
        if _thread is not None and _thread.is_alive():
            return True
        _stop.clear()
        _thread = threading.Thread(target=_loop, args=(interval_seconds(),), name="alert-deliverer", daemon=True)
        _thread.start()
    return True


def stop_alert_deliverer() -> None:
    global _thread
    with _thread_lock:
        _stop.set()
        _wake.set()
        if _thread is not None:
            _thread.join(timeout=5)
        _thread = None
