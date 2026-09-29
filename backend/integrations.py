"""Where a workspace's alerts and tickets go (D3): a signed webhook, a mail relay, Jira
and ServiceNow.

Each is configured per workspace by its administrator, in Settings -> Integrations. What
is not secret is kept in `alert_channels`; the secret - the webhook's signing secret, the
relay's password, the Jira API token, the ServiceNow password - is sealed in the vault
(kind ``integration``) and never returned: the console is told only that one is set.

Secret rules, the same as the SIEM's CA and every other saved credential:
    field omitted  -> the stored secret is kept
    new value      -> it replaces the stored secret
    remove_secret  -> the stored secret is deleted
A value made only of mask characters is refused, so a mask sent back is never saved as
a password. The webhook's signing secret is never typed: Sentro makes it, shows it once
when it is made (or rotated), and signs every delivery with it.

Enabled is not connected: a channel's state is connected only after a delivery or a
passed test of its current configuration, not followed by a failure.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import datetime, timezone
from urllib.parse import urlsplit

CHANNELS = ("webhook", "email", "jira", "servicenow")
ALERT_CHANNELS = ("webhook", "email")
TICKET_SYSTEMS = ("jira", "servicenow")
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
SECRET_FIELD = {"webhook": "", "email": "password", "jira": "token", "servicenow": "password"}
LABELS = {"webhook": "Alert webhook signing secret", "email": "Alert mail relay password",
          "jira": "Jira API token", "servicenow": "ServiceNow password"}
_EMAIL = re.compile(r"^[^@\s,;<>]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")
_PROJECT = re.compile(r"^[A-Z][A-Z0-9_]{0,19}$")
_MASK = re.compile(r"^[•*●·\s]+$")
_SMTP_PORTS = {"starttls": 587, "tls": 465, "none": 25}
MAX_SECRET_CHARS = 4096


class IntegrationError(ValueError):
    """A configuration that cannot be saved. `str()` is safe to show."""

    client_safe = True  # backend.errors: every message here is written for the person


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _https_url(value, what: str) -> str:
    url = str(value or "").strip().rstrip("/")
    if not url:
        raise IntegrationError(f"Enter the {what} address.")
    if len(url) > 2000:
        raise IntegrationError(f"The {what} address is too long.")
    parts = urlsplit(url)
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise IntegrationError(f"The {what} address must be an HTTPS address - Sentro does not send over plain HTTP.")
    if parts.username or parts.password:
        raise IntegrationError(f"Put no user name or password in the {what} address; use the fields for them.")
    if parts.fragment:
        raise IntegrationError(f"The {what} address cannot carry a #fragment.")
    try:
        parts.port
    except ValueError as exc:
        raise IntegrationError(f"The {what} address has an invalid port.") from exc
    return url


def _severity(value, saved: str = "HIGH") -> str:
    severity = str(value or saved or "HIGH").upper()
    if severity not in SEVERITIES:
        raise IntegrationError("Choose the lowest severity to send: LOW, MEDIUM, HIGH or CRITICAL.")
    return severity


def _text(value, what: str, *, limit: int, required: bool = False) -> str:
    text = " ".join(str(value or "").split())
    if required and not text:
        raise IntegrationError(f"Enter the {what}.")
    if len(text) > limit:
        raise IntegrationError(f"The {what} is longer than {limit} characters.")
    return text


def _ca(request: dict, saved: dict) -> dict:
    from backend.siem_settings import SiemSettingsError, ca_metadata

    keys = ("ca_pem", "ca_name", "ca_fingerprint", "ca_subject", "ca_not_after", "ca_count")
    if request.get("remove_ca"):
        return {}
    if request.get("ca_pem"):
        try:
            return ca_metadata(request["ca_pem"], request.get("ca_name") or "ca.pem")
        except SiemSettingsError as exc:
            raise IntegrationError(str(exc)) from exc
    return {key: saved[key] for key in keys if key in saved}


def merge(channel: str, saved: dict, request: dict) -> dict:
    """A channel's new configuration (no secret in it) from the saved one and a request.
    A field left out keeps its saved value."""
    def pick(name, default=None):
        return request[name] if name in request else saved.get(name, default)

    if channel == "webhook":
        config = {"url": _https_url(pick("url"), "webhook"), "min_severity": _severity(pick("min_severity"))}
    elif channel == "email":
        security = str(pick("security", "starttls") or "starttls").lower()
        if security not in _SMTP_PORTS:
            raise IntegrationError("Choose STARTTLS, TLS or none.")
        try:
            port = int(pick("port") or _SMTP_PORTS[security])
        except (TypeError, ValueError) as exc:
            raise IntegrationError("The port must be a number from 1 to 65535.") from exc
        if not 1 <= port <= 65535:
            raise IntegrationError("The port must be a number from 1 to 65535.")
        from backend.siem_settings import SiemSettingsError, validate_host

        try:
            host = validate_host(pick("host"))
        except SiemSettingsError as exc:
            raise IntegrationError(str(exc).replace("receiver", "mail relay")) from exc
        sender = _text(pick("sender"), "sender address", limit=254, required=True)
        if not _EMAIL.match(sender):
            raise IntegrationError("The sender must be an e-mail address.")
        raw = pick("recipients") or []
        recipients = [item.strip() for item in (raw.split(",") if isinstance(raw, str) else raw) if str(item).strip()]
        if not recipients or len(recipients) > 20:
            raise IntegrationError("Enter from one to twenty recipient addresses.")
        for item in recipients:
            if not _EMAIL.match(str(item)):
                raise IntegrationError(f"{str(item)[:80]} is not an e-mail address.")
        config = {"host": host, "port": port, "security": security, "sender": sender, "recipients": recipients,
                  "username": _text(pick("username"), "user name", limit=254), "min_severity": _severity(pick("min_severity"))}
    elif channel == "jira":
        project = _text(pick("project_key"), "project key", limit=20, required=True).upper()
        if not _PROJECT.match(project):
            raise IntegrationError("The project key is letters, digits and underscores, starting with a letter (e.g. SEC).")
        config = {"base_url": _https_url(pick("base_url"), "Jira"), "project_key": project,
                  "issue_type": _text(pick("issue_type", "Task") or "Task", "issue type", limit=60, required=True),
                  "username": _text(pick("username"), "user name", limit=254)}
    elif channel == "servicenow":
        config = {"instance_url": _https_url(pick("instance_url"), "ServiceNow"),
                  "username": _text(pick("username"), "user name", limit=254, required=True),
                  "assignment_group": _text(pick("assignment_group"), "assignment group", limit=80)}
    else:
        raise IntegrationError("Unknown integration.")
    config.update(_ca(request, saved))
    return config


def secret_change(channel: str, request: dict) -> tuple[str, str | None]:
    """What the request does to the stored secret: ("keep"|"replace"|"remove"|"rotate", value).
    The webhook's secret is Sentro's to make: it is rotated, never typed."""
    if channel == "webhook":
        return ("rotate", None) if request.get("rotate_secret") else ("keep", None)
    if request.get("remove_secret"):
        return "remove", None
    field = SECRET_FIELD[channel]
    if field not in request or request[field] is None:
        return "keep", None
    value = str(request[field])
    if not value.strip():
        return "keep", None
    if _MASK.match(value):
        raise IntegrationError("That is the mask of the saved secret, not a new one. Leave the field empty to keep it.")
    if len(value) > MAX_SECRET_CHARS:
        raise IntegrationError("That secret is too long.")
    return "replace", value


def new_signing_secret() -> str:
    return "whsec_" + secrets.token_urlsafe(32)


def config_signature(channel: str, config: dict) -> str:
    material = json.dumps({key: config.get(key) for key in sorted(config) if key != "ca_pem"}, sort_keys=True, default=str)
    return hashlib.sha256(f"{channel}:{material}".encode("utf-8")).hexdigest()[:16]


def state(channel: str, enabled: bool, config: dict, status: dict, queue: dict, *, has_secret: bool) -> str:
    """disabled | not_configured | degraded | connected | not_connected."""
    if not enabled:
        return "disabled"
    required_secret = channel in ("webhook", "jira", "servicenow") or bool(config.get("username"))
    if not config or (required_secret and not has_secret):
        return "not_configured"
    if int(queue.get("failing") or 0):
        return "degraded"
    signature = config_signature(channel, config)
    successes = []
    if status.get("delivery_signature") == signature:
        successes.append(status.get("last_delivery_at") or "")
    test = status.get("last_test") or {}
    if test.get("ok") and test.get("signature") == signature:
        successes.append(test.get("at") or "")
    success = max((value for value in successes if value), default="")
    failure = status.get("last_error_at") if status.get("error_signature") == signature else ""
    if success and (not failure or failure <= success):
        return "connected"
    return "not_connected"


def public_view(channel: str, record: dict | None, queue: dict) -> dict:
    """Everything the console may see of one channel: never a secret, never the CA itself."""
    record = record or {}
    config = dict(record.get("config") or {})
    status = record.get("status") or {}
    has_secret = bool(record.get("secret_ref"))
    has_ca = bool(config.pop("ca_pem", ""))
    ca = {key[3:]: config.pop(key) for key in ("ca_name", "ca_fingerprint", "ca_subject", "ca_not_after", "ca_count")
          if key in config}
    secret_name = "signing_secret" if channel == "webhook" else SECRET_FIELD[channel]
    return {
        "channel": channel,
        "enabled": bool(record.get("enabled")),
        "configured": bool(record.get("config")),
        "state": state(channel, bool(record.get("enabled")), record.get("config") or {}, status, queue,
                       has_secret=has_secret),
        "config": {**config, f"{secret_name}_configured": has_secret, "ca_configured": has_ca, "ca": ca or None},
        "status": {key: status.get(key) or "" for key in ("last_delivery_at", "last_error", "last_error_at")}
        | {"last_test": status.get("last_test") or None},
        "queue": {"pending": int(queue.get("pending") or 0), "failing": int(queue.get("failing") or 0),
                  "oldest": queue.get("oldest") or ""},
        "updated_by": record.get("updated_by") or "",
        "updated_at": record.get("updated_at") or "",
    }


def changed_fields(before: dict, after: dict) -> list[str]:
    keys = sorted(set(before) | set(after))
    return [key for key in keys if key != "ca_pem" and before.get(key) != after.get(key)]


def load(tenant_id: str, channel: str) -> tuple[dict | None, str]:
    """(the channel's record, its secret) - the secret opened from the vault, for sending."""
    from backend import store
    from backend.vault import CredentialVault

    record = store.get_alert_channel(tenant_id, channel)
    if record is None or not record.get("secret_ref"):
        return record, ""
    try:
        value = CredentialVault().resolve(tenant_id, record["secret_ref"], kind="integration")
    except KeyError:
        return record, ""
    return record, str(value.get("password") or "")


def store_secret(tenant_id: str, channel: str, value: str, previous_ref: str) -> str:
    """Seal `value` in the vault; the previous secret, if any, is deleted."""
    from backend.vault import CredentialVault

    vault = CredentialVault()
    ref = vault.store(tenant_id, channel, value, "", kind="integration", label=LABELS[channel])
    if previous_ref:
        vault.delete(tenant_id, previous_ref)
    return ref


def delete_secret(tenant_id: str, ref: str) -> None:
    if ref:
        from backend.vault import CredentialVault

        CredentialVault().delete(tenant_id, ref)


_IMPORTED = "alerts.webhook_env_imported"


def import_environment() -> bool:
    """An install that named its webhook in DSPM_ALERT_WEBHOOK_URL before the console could
    is given it as the default workspace's webhook, once - signed from now on (the new
    signing secret is shown when the administrator rotates it in the console). Only an
    https:// address is imported; the old unsigned, unqueued call is gone."""
    import logging
    import os

    from backend import store

    url = os.getenv("DSPM_ALERT_WEBHOOK_URL", "").strip()
    if not url or store.get_app_setting(_IMPORTED):
        return False
    try:
        config = merge("webhook", {}, {"url": url, "min_severity": "HIGH"})
    except IntegrationError as exc:
        logging.getLogger(__name__).warning("DSPM_ALERT_WEBHOOK_URL was not imported: %s", exc)
        return False
    if store.get_alert_channel("default", "webhook") is None:
        ref = store_secret("default", "webhook", new_signing_secret(), "")
        store.save_alert_channel("default", "webhook", enabled=True, config=config, secret_ref=ref, actor="environment")
        store.audit("default", "sentro", "integration.changed",
                    {"channel": "webhook", "changed": ["url"], "secret": "replaced", "source": "DSPM_ALERT_WEBHOOK_URL"})
    store.set_app_setting(_IMPORTED, _now())
    return True
