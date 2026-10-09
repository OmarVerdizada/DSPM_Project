"""SIEM integration settings: what the console configures, and what it may see (C4).

The forwarding engine - outbox, retries, TLS, delivery - is backend.siem. This module is
the configuration it reads and the status it reports, kept in the install-wide
``app_settings`` table so every backend sees the same answer at once:

* ``siem.enabled``  - "1" or "0". Off keeps the configuration; only an explicit removal
  deletes it.
* ``siem.config``   - transport, host, port, format, certificate trust, and the private CA
  certificate when one is used. RFC 5424 syslog over TCP, UDP or TLS carries no
  credential, so there is no secret here: the CA certificate is public material. It is
  still never sent back to the browser - the console gets its name, fingerprint, subject
  and expiry - and an upload that contains a private key is refused, not stored.
* ``siem.status``   - last delivery, last attempt, last error (a sentence written here,
  never an exception's text), last connection test.

Certificate verification cannot be weakened from here: the choices are the system trust
store or a private CA, and both check the chain and the name.

An install configured with DSPM_SIEM_URL before this existed is imported once, as the
starting configuration; after that the console decides, and removing the configuration
does not bring the environment's back.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

ENABLED_KEY = "siem.enabled"
CONFIG_KEY = "siem.config"
STATUS_KEY = "siem.status"
ENV_IMPORTED_KEY = "siem.env_imported"

TRANSPORTS = ("tls", "tcp", "udp")
FORMATS = ("cef", "json")
TRUST = ("system", "custom")
DEFAULT_PORTS = {"tcp": 514, "udp": 514, "tls": 6514}
CA_MAX_BYTES = 64 * 1024
# Events that have waited this long are a delivery problem even before a retry has failed.
QUEUE_STALE_SECONDS = 120

logger = logging.getLogger(__name__)
# The DSPM_SIEM_URL values already reported as unusable, so each is logged once, not at
# every audit write.
_REFUSED_URLS: set[str] = set()

_HOSTNAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")


class SiemSettingsError(ValueError):
    """A refused configuration; the text is written for the operator and safe to show."""

    client_safe = True


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Reading ────────────────────────────────────────────────────────────────────────
def _get(conn, key: str) -> str | None:
    row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    return None if row is None else row["value"]


def _put(conn, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, value, _now()),
    )


def _json(value: str | None) -> dict:
    try:
        loaded = json.loads(value or "{}")
    except ValueError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def load(conn=None) -> tuple[bool, dict, dict]:
    """(enabled, config, status). Reads through `conn` when a caller is already inside a
    transaction - the audit write asks inside its own, so an event is queued exactly when
    forwarding was on at the moment it was recorded."""
    if conn is None:
        from backend import store

        with store._connect() as own:
            return load(own)
    enabled = _get(conn, ENABLED_KEY)
    config_text = _get(conn, CONFIG_KEY)
    if config_text is None and enabled is None and _get(conn, ENV_IMPORTED_KEY) is None:
        imported = _from_environment()
        if imported is not None:
            _put(conn, CONFIG_KEY, json.dumps(imported, ensure_ascii=False))
            _put(conn, ENABLED_KEY, "1")
            _put(conn, ENV_IMPORTED_KEY, _now())
            return True, imported, {}
    return enabled == "1", _json(config_text), _json(_get(conn, STATUS_KEY))


def _from_environment() -> dict | None:
    """DSPM_SIEM_URL / _FORMAT / _CA_FILE as a starting configuration, or None."""
    url = os.getenv("DSPM_SIEM_URL", "").strip()
    if not url:
        return None
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        # A port out of range or not a number raised here - inside every audit write, the
        # first of which imports this - so every audited action failed, sign-in included.
        # Not imported; `config check` names the setting. Logged once, without the value.
        if url not in _REFUSED_URLS:
            _REFUSED_URLS.add(url)
            logger.warning("DSPM_SIEM_URL is not a valid tls://, tcp:// or udp:// host:port address and was "
                           "not imported; configure the SIEM under Settings -> Features -> SIEM Integration.")
        return None
    transport = (parsed.scheme or "").lower()
    if transport not in TRANSPORTS or not parsed.hostname:
        return None
    config = {
        "transport": transport,
        "host": parsed.hostname,
        "port": port or DEFAULT_PORTS[transport],
        "format": (os.getenv("DSPM_SIEM_FORMAT", "cef").strip().lower() or "cef"),
        "trust": "system",
        "changed_at": _now(),
    }
    if config["format"] not in FORMATS:
        config["format"] = "cef"
    ca_file = os.getenv("DSPM_SIEM_CA_FILE", "").strip()
    if transport == "tls" and ca_file:
        try:
            pem = open(ca_file, encoding="utf-8").read()
            config.update(trust="custom", **ca_metadata(pem, os.path.basename(ca_file)))
        except (OSError, SiemSettingsError):
            pass  # an unreadable CA file leaves the system store, which then refuses the peer
    return config


def target(conn=None) -> dict | None:
    """Where the forwarder sends, or None when forwarding is off or not configured."""
    enabled, config, _status = load(conn)
    if not enabled or not config.get("host"):
        return None
    return target_from(config)


def target_from(config: dict) -> dict:
    return {
        "scheme": config.get("transport") or "tls",
        "host": config["host"],
        "port": int(config.get("port") or DEFAULT_PORTS.get(config.get("transport") or "tls", 6514)),
        "format": config.get("format") or "cef",
        "ca_pem": config.get("ca_pem") if config.get("trust") == "custom" else None,
    }


# ── Validating ─────────────────────────────────────────────────────────────────────
def validate_host(value: str | None) -> str:
    host = str(value or "").strip()
    if not host:
        raise SiemSettingsError("Enter the receiver's host name or IP address.")
    if "://" in host or "/" in host or " " in host:
        raise SiemSettingsError("Enter only the host name or IP address - the transport and port have their own fields.")
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        pass
    if not _HOSTNAME.match(host):
        raise SiemSettingsError("That is not a valid host name or IP address.")
    return host.rstrip(".").lower()


def ca_metadata(pem: str, name: str) -> dict:
    """The CA certificate to store, with what the console is shown of it. Refuses a
    private key - pasted by mistake it would otherwise sit in the settings table."""
    text = str(pem or "")
    if len(text.encode("utf-8")) > CA_MAX_BYTES:
        raise SiemSettingsError("The certificate file is larger than 64 KB; upload the CA certificate only.")
    if "PRIVATE KEY" in text.upper():
        raise SiemSettingsError("That file contains a private key. Upload the CA's certificate only - a private key is never needed or stored.")
    if "-----BEGIN CERTIFICATE-----" not in text:
        raise SiemSettingsError("Upload a PEM certificate (-----BEGIN CERTIFICATE-----).")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    try:
        certificates = x509.load_pem_x509_certificates(text.encode("utf-8"))
        ssl.create_default_context(cadata=text)
    except (ValueError, ssl.SSLError) as exc:
        raise SiemSettingsError("That certificate could not be read. Upload the CA certificate as PEM.") from exc
    first = certificates[0]
    names = first.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return {
        "ca_pem": text.strip() + "\n",
        "ca_name": (os.path.basename(str(name or "")) or "ca.pem")[:120],
        "ca_fingerprint": first.fingerprint(hashes.SHA256()).hex(":").upper(),
        "ca_subject": str(names[0].value) if names else first.subject.rfc4514_string()[:200],
        "ca_not_after": first.not_valid_after_utc.isoformat(),
        "ca_count": len(certificates),
    }


def merge(saved: dict, request: dict) -> dict:
    """A new configuration from the saved one and a request. The CA certificate follows
    the rule a stored secret would: omitted, it is kept; a new one replaces it; only
    `remove_ca` deletes it."""
    transport = str(request.get("transport") or saved.get("transport") or "tls").lower()
    if transport not in TRANSPORTS:
        raise SiemSettingsError("Choose TLS, TCP or UDP.")
    fmt = str(request.get("format") or saved.get("format") or "cef").lower()
    if fmt not in FORMATS:
        raise SiemSettingsError("Choose CEF or JSON.")
    try:
        port = int(request.get("port") or saved.get("port") or DEFAULT_PORTS[transport])
    except (TypeError, ValueError) as exc:
        raise SiemSettingsError("The port must be a number from 1 to 65535.") from exc
    if not 1 <= port <= 65535:
        raise SiemSettingsError("The port must be a number from 1 to 65535.")
    trust = str(request.get("trust") or saved.get("trust") or "system").lower()
    if trust not in TRUST:
        raise SiemSettingsError("Choose the system trust store or a private CA.")
    config = {
        "transport": transport,
        "host": validate_host(request.get("host") if "host" in request else saved.get("host", "")),
        "port": port,
        "format": fmt,
        "trust": trust,
    }
    ca_keys = ("ca_pem", "ca_name", "ca_fingerprint", "ca_subject", "ca_not_after", "ca_count")
    if request.get("remove_ca"):
        pass
    elif request.get("ca_pem"):
        config.update(ca_metadata(request["ca_pem"], request.get("ca_name") or "ca.pem"))
    else:
        config.update({key: saved[key] for key in ca_keys if key in saved})
    if transport == "tls" and trust == "custom" and not config.get("ca_pem"):
        raise SiemSettingsError("A private CA needs its certificate. Upload it, or use the system trust store.")
    return config


def changed_fields(before: dict, after: dict) -> list[str]:
    keys = ("transport", "host", "port", "format", "trust", "ca_fingerprint")
    return [key for key in keys if before.get(key) != after.get(key)]


# ── Writing ────────────────────────────────────────────────────────────────────────
def save_config(config: dict) -> None:
    from backend import store

    with store._lock:
        with store._connect() as conn:
            _put(conn, CONFIG_KEY, json.dumps({**config, "changed_at": _now()}, ensure_ascii=False))
            _put(conn, ENV_IMPORTED_KEY, _get(conn, ENV_IMPORTED_KEY) or "superseded")


def set_enabled(enabled: bool) -> None:
    from backend import store

    with store._lock:
        with store._connect() as conn:
            _put(conn, ENABLED_KEY, "1" if enabled else "0")
            _put(conn, ENV_IMPORTED_KEY, _get(conn, ENV_IMPORTED_KEY) or "superseded")


def remove_config() -> None:
    """Delete the configuration and its status; forwarding is off afterwards. Events
    already queued stay queued - they go when a receiver is configured again."""
    from backend import store

    with store._lock:
        with store._connect() as conn:
            conn.execute("DELETE FROM app_settings WHERE key IN (?, ?)", (CONFIG_KEY, STATUS_KEY))
            _put(conn, ENABLED_KEY, "0")
            _put(conn, ENV_IMPORTED_KEY, _get(conn, ENV_IMPORTED_KEY) or "superseded")


def record(**changes) -> None:
    """Merge into the status: delivery, error and test outcomes. Never an exception's text."""
    from backend import store

    with store._lock:
        with store._connect() as conn:
            status = _json(_get(conn, STATUS_KEY))
            status.update(changes)
            _put(conn, STATUS_KEY, json.dumps(status, ensure_ascii=False))


def config_signature(config: dict) -> str:
    material = json.dumps([config.get(k) for k in ("transport", "host", "port", "format", "trust", "ca_fingerprint")])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


# ── Explaining ─────────────────────────────────────────────────────────────────────
def safe_message(exc: BaseException, where: dict) -> str:
    """What went wrong, for a person, without an exception's own text (which can carry
    paths, addresses of other hosts, or whatever the peer sent)."""
    address = f"{where.get('host')}:{where.get('port')}"
    if isinstance(exc, ssl.SSLCertVerificationError):
        reason = (exc.verify_message or "").lower()
        if "hostname mismatch" in reason or "ip address mismatch" in reason:
            return f"The certificate at {address} is not issued for {where.get('host')}. Use the name on its certificate."
        if "expired" in reason:
            return f"The certificate at {address} has expired."
        if "self-signed" in reason or "local issuer" in reason or "unable to get" in reason:
            return f"The certificate at {address} is not trusted. Upload the CA that issued it, under Private CA."
        return f"The certificate at {address} was refused ({exc.verify_message or 'verification failed'})."
    if isinstance(exc, ssl.SSLError):
        return f"The TLS handshake with {address} failed. Check that the receiver expects TLS on this port."
    if isinstance(exc, socket.gaierror):
        return f"The host name {where.get('host')} could not be resolved."
    if isinstance(exc, ConnectionRefusedError):
        return f"{address} refused the connection. Check the port and that the receiver is running."
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return f"No answer from {address} within the time allowed."
    if isinstance(exc, ConnectionResetError):
        return f"{address} closed the connection. Check that the transport matches the receiver."
    return f"Could not reach {address} ({type(exc).__name__})."


def state(enabled: bool, config: dict, status: dict, queue: dict) -> str:
    """disabled | not_configured | degraded | connected | not_connected.

    Enabled is not connected: only a delivery or a passed test of THIS configuration,
    not followed by a failure, is."""
    if not enabled:
        return "disabled"
    if not config.get("host"):
        return "not_configured"
    if queue.get("failing") or float(queue.get("oldest_seconds") or 0) > QUEUE_STALE_SECONDS:
        return "degraded"
    signature = config_signature(config)
    successes = [status.get("last_delivery_at") if status.get("delivery_signature") == signature else None]
    test = status.get("last_test") or {}
    if test.get("ok") and test.get("signature") == signature:
        successes.append(test.get("at"))
    success = max((value for value in successes if value), default="")
    failure = status.get("last_error_at") if status.get("error_signature") == signature else ""
    if success and (not failure or failure <= success):
        return "connected"
    return "not_connected"


def public_view(enabled: bool, config: dict, status: dict, queue: dict, *, editable: bool) -> dict:
    """Everything the console may see. The CA certificate itself is not in it."""
    has_ca = bool(config.get("ca_pem"))
    return {
        "enabled": enabled,
        "configured": bool(config.get("host")),
        "state": state(enabled, config, status, queue),
        "editable": editable,
        "config": {
            "transport": config.get("transport") or "tls",
            "host": config.get("host") or "",
            "port": config.get("port") or DEFAULT_PORTS.get(config.get("transport") or "tls", 6514),
            "format": config.get("format") or "cef",
            "trust": config.get("trust") or "system",
            "ca_configured": has_ca,
            "ca": {key[3:]: config.get(key) for key in ("ca_name", "ca_fingerprint", "ca_subject", "ca_not_after", "ca_count")}
            if has_ca else None,
        },
        "status": {
            "last_delivery_at": status.get("last_delivery_at") or "",
            "last_attempt_at": status.get("last_attempt_at") or "",
            "last_error": status.get("last_error") or "",
            "last_error_at": status.get("last_error_at") or "",
            "last_test": status.get("last_test") or None,
        },
        "queue": {
            "pending": int(queue.get("pending") or 0),
            "failing": int(queue.get("failing") or 0),
            "oldest_seconds": float(queue.get("oldest_seconds") or 0),
        },
    }
