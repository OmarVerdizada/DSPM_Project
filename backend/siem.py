"""Audit events to a SIEM, and never lost on the way (C4).

The receiver is configured in the console - Settings -> Features -> SIEM Integration -
and kept in the install's settings (backend.siem_settings): a syslog receiver over TLS,
TCP or UDP, CEF or JSON, the system trust store or a private CA. An install configured
with DSPM_SIEM_URL before that existed is imported once. When forwarding is on, every audit
row is also written to an OUTBOX in the same transaction as the row itself, so an event
cannot be recorded without being queued, or queued without being recorded. A forwarder
thread sends what is due and deletes what was delivered; a SIEM that is down leaves the
rows where they are, retried with a back-off that grows to five minutes, until it is up.

Each event carries its tenant's chain position - `seq` and `row_hash` (backend.audit_chain)
- so the SIEM holds an independent copy of every chain: an edit made in the database and
covered up by recomputing its hashes still disagrees with what the SIEM received.

Format: CEF (the default) or JSON, inside an RFC 5424 syslog line.
Delivery is at least once: a row sent but not yet deleted when a process dies is sent again,
and `seq` lets the SIEM discard the duplicate.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import ssl
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

PRODUCT_VERSION = "1.0"
_DEFAULT_PORTS = {"tcp": 514, "udp": 514, "tls": 6514}
_MAX_BACKOFF_SECONDS = 300
_LEASE_SECONDS = 60
# Actions a SOC would page on, and actions that remove things.
_HIGH = {"auth.login_blocked", "auth.refresh_replayed", "user.password_change_refused", "tenant.legal_hold.lifted"}
_MEDIUM = {"auth.login_failed", "tenant.deleted", "user.deleted", "role.deleted", "api_key.revoked",
           "user.role_updated", "role.updated", "settings.feature_toggled", "settings.siem_changed",
           "settings.siem_test_failed"}
# Turning the SIEM off, or removing its receiver, is what someone covering tracks does first.
_HIGH |= {"settings.siem_disabled", "settings.siem_removed"}


def siem_target(conn=None) -> dict | None:
    """Where events go, from the install's SIEM settings; None when forwarding is off."""
    from backend import siem_settings

    return siem_settings.target(conn)


def forwarding_enabled(conn=None) -> bool:
    """Whether an audit row written now is queued. The audit write asks through its own
    connection, inside its own transaction."""
    return siem_target(conn) is not None


def _severity(action: str) -> int:
    if action in _HIGH:
        return 7
    if action in _MEDIUM:
        return 5
    return 3


def _header(value) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _extension(value) -> str:
    return (str(value).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\r", "\\r").replace("\n", "\\n"))


def format_event(event: dict, fmt: str = "cef") -> str:
    """One syslog line for one audit event."""
    detail = dict(event.get("detail") or {})
    client_ip = str(detail.pop("client_ip", "") or "")
    user_agent = str(detail.pop("user_agent", "") or "")
    timestamp = str(event.get("timestamp") or "")
    action = str(event.get("action") or "")
    if fmt == "json":
        body = json.dumps({
            "product": "Sentro DSPM", "tenant_id": event.get("tenant_id"), "seq": event.get("seq"),
            "row_hash": event.get("row_hash"), "timestamp": timestamp, "actor": event.get("actor"),
            "action": action, "client_ip": client_ip, "user_agent": user_agent, "detail": detail,
        }, ensure_ascii=False, separators=(",", ":"))
    else:
        try:
            epoch_ms = int(datetime.fromisoformat(timestamp).timestamp() * 1000)
        except ValueError:
            epoch_ms = 0
        fields = [
            ("rt", epoch_ms),
            ("suser", event.get("actor") or ""),
            ("cs1Label", "tenant"), ("cs1", event.get("tenant_id") or ""),
            ("cs2Label", "auditSeq"), ("cs2", event.get("seq") or ""),
            ("cs3Label", "auditRowHash"), ("cs3", event.get("row_hash") or ""),
        ]
        try:
            ipaddress.ip_address(client_ip)
            fields.append(("src", client_ip))
        except ValueError:
            pass
        if user_agent:
            fields.append(("requestClientApplication", user_agent))
        fields.append(("msg", json.dumps(detail, ensure_ascii=False, separators=(",", ":"))[:1000]))
        extension = " ".join(f"{key}={_extension(value)}" for key, value in fields)
        body = (f"CEF:0|Sentro|DSPM|{PRODUCT_VERSION}|{_header(action)}|{_header(action.replace('.', ' '))}"
                f"|{_severity(action)}|{extension}")
    # RFC 5424: facility 13 (log audit); notice, or warning for what a SOC pages on.
    priority = 13 * 8 + (4 if _severity(action) >= 7 else 5)
    return f"<{priority}>1 {timestamp or '-'} {socket.gethostname()} sentro - - - {body}"


class _Sender:
    """One connection to the SIEM for one pass. TCP and TLS frame each event with a
    newline (RFC 6587 non-transparent framing); UDP sends one datagram per event."""

    def __init__(self, target: dict, timeout: float = 5.0) -> None:
        self.target = target
        address = (target["host"], target["port"])
        if target["scheme"] == "udp":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(timeout)
            self.sock.connect(address)
            return
        raw = socket.create_connection(address, timeout=timeout)
        if target["scheme"] == "tls":
            # The chain and the name are always checked: the only choice is whose CAs -
            # the system's, or the private CA uploaded in the console.
            context = ssl.create_default_context(cadata=target.get("ca_pem") or None)
            try:
                raw = context.wrap_socket(raw, server_hostname=target["host"])
            except BaseException:
                raw.close()
                raise
        self.sock = raw

    def send(self, line: str) -> None:
        data = line.encode("utf-8")
        if self.target["scheme"] == "udp":
            self.sock.send(data[:65000])
        else:
            self.sock.sendall(data + b"\n")

    def close(self) -> None:
        if isinstance(self.sock, ssl.SSLSocket):
            # A TLS 1.3 server sends session tickets after the handshake, and this sender
            # never reads them. Closing a socket with unread data makes the OS send a reset
            # instead of a normal close, and a reset lets the receiver drop what it had not
            # read yet: events counted as delivered, lost on the way - in 53 of 80 passes
            # against a local TLS receiver, measured. Ending the session with close_notify
            # reads what is pending and closes in order: none of 80 lost anything.
            try:
                self.sock.settimeout(2.0)
                self.sock = self.sock.unwrap()
            except (OSError, ValueError):
                pass
        try:
            self.sock.close()
        except OSError:
            pass


def _failure(exc: OSError) -> str:
    """What went wrong, for the outbox row and the log. The type alone does not say why a
    SIEM's certificate was refused - an unknown CA and a name the certificate does not
    carry need different fixes - so a verification failure keeps OpenSSL's reason."""
    if isinstance(exc, ssl.SSLCertVerificationError) and exc.verify_message:
        return f"{type(exc).__name__}: {exc.verify_message}"[:200]
    return type(exc).__name__


def drain(*, limit: int = 200, now: float | None = None, owner: str = "") -> dict:
    """Send what is due, once. Returns {"sent", "failed", "pending"}.

    A connection that cannot be opened, or a send that fails, stops the pass: the rest
    are put back with the same back-off rather than hammering a receiver that is down.
    """
    from backend import store

    from backend import siem_settings

    target = siem_target()
    if target is None:
        return {"sent": 0, "failed": 0, "pending": 0}
    moment = time.time() if now is None else now
    rows = store.claim_audit_outbox(limit=limit, now=moment, lease_seconds=_LEASE_SECONDS,
                                    owner=owner or f"{socket.gethostname()}:{os.getpid()}")
    if not rows:
        return {"sent": 0, "failed": 0, "pending": store.audit_outbox_status()["pending"]}
    delivered: list[int] = []
    failed: list[dict] = []
    failure_exc: OSError | None = None
    sender = None
    try:
        sender = _Sender(target)
        for index, row in enumerate(rows):
            try:
                sender.send(format_event(json.loads(row["payload"]), target["format"]))
            except OSError as exc:
                failed = rows[index:]
                error = _failure(exc)
                failure_exc = exc
                break
            delivered.append(row["id"])
    except OSError as exc:
        failed = rows
        error = _failure(exc)
        failure_exc = exc
    finally:
        if sender is not None:
            sender.close()
    if delivered:
        store.delete_audit_outbox(delivered)
    signature = siem_settings.config_signature(siem_settings.load()[1])
    stamp = datetime.now(timezone.utc).isoformat()
    if delivered:
        siem_settings.record(last_delivery_at=stamp, last_attempt_at=stamp, delivery_signature=signature)
    if failed:
        siem_settings.record(last_attempt_at=stamp, last_error_at=stamp, error_signature=signature,
                             last_error=siem_settings.safe_message(failure_exc, target) if failure_exc else error)
    for row in failed:
        attempts = int(row["attempts"] or 0) + 1
        store.retry_audit_outbox(row["id"], attempts, moment + min(_MAX_BACKOFF_SECONDS, 2 ** attempts), error)
    if failed:
        logger.warning("SIEM forwarding: %s event(s) not delivered (%s); retrying with back-off", len(failed), error)
    return {"sent": len(delivered), "failed": len(failed), "pending": store.audit_outbox_status()["pending"]}


_thread: threading.Thread | None = None
_thread_lock = threading.Lock()
_stop = threading.Event()


def forwarder_interval_seconds() -> float:
    try:
        return max(0.5, float(os.getenv("DSPM_SIEM_INTERVAL_SECONDS", "2")))
    except ValueError:
        return 2.0


def _loop(interval: float) -> None:
    while not _stop.wait(interval):
        try:
            drain()
        except Exception:  # the forwarder must outlive a bad pass
            logger.exception("SIEM forwarding pass failed")


def test_connection(target: dict, timeout: float = 5.0) -> dict:
    """Open the connection the forwarder would, send one test line, and close it the way
    the forwarder does. Nothing is queued and no audit row is sent: the line says it is a
    test. Returns {"ok", "message", "transport"} - the message is written here, never an
    exception's text. UDP has no handshake, so "sent" is all it can say."""
    from backend import siem_settings

    line = format_event({
        "tenant_id": "-", "seq": 0, "row_hash": "", "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": "sentro", "action": "siem.connection_test",
        "detail": {"message": "Sentro DSPM connection test - not an audit event"},
    }, target.get("format") or "cef")
    try:
        sender = _Sender(target, timeout)
        try:
            sender.send(line)
        finally:
            sender.close()
    except OSError as exc:
        return {"ok": False, "transport": target["scheme"], "message": siem_settings.safe_message(exc, target)}
    address = f"{target['host']}:{target['port']}"
    if target["scheme"] == "udp":
        message = (f"Sent a test line to {address} over UDP. UDP returns no acknowledgement - "
                   "confirm it arrived at the receiver.")
    elif target["scheme"] == "tls":
        message = f"Connected to {address}, verified its certificate and delivered a test line."
    else:
        message = f"Connected to {address} and delivered a test line."
    return {"ok": True, "transport": target["scheme"], "message": message}


def start_siem_forwarder() -> bool:
    """Start the forwarder thread. It runs whether or not forwarding is on, and reads the
    settings on every pass, so turning the SIEM on in the console takes effect on every
    backend within one interval - no restart."""
    global _thread
    with _thread_lock:
        if _thread is not None and _thread.is_alive():
            return True
        _stop.clear()
        _thread = threading.Thread(target=_loop, args=(forwarder_interval_seconds(),), name="siem-forwarder", daemon=True)
        _thread.start()
    return True


def stop_siem_forwarder() -> None:
    global _thread
    _stop.set()
    with _thread_lock:
        thread = _thread
        _thread = None
    if thread is not None and thread.is_alive():
        thread.join(timeout=5.0)
