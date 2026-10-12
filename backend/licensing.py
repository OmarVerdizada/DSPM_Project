"""The offline licence (D10).

A licence is a JSON document the publisher signs with its licence key (Ed25519,
backend.signing), delivered as a file - nothing is fetched, nothing phones home:

    {"licence": {"format": "sentro-licence-v1", "licence_id": ..., "customer": ...,
                 "issued_at": ..., "not_before": ..., "expires_at": ..., "features": [...],
                 "limits": {...}},
     "key_id": ..., "signature": ...}

It is installed by the platform administrator (Settings, or `python main.py licence
install <file>` on the host - the offline recovery path, which needs neither the console
nor a network), and kept in the install's settings. A licence that was altered, is signed
by a key this install does not trust for licences, is not yet valid or has expired is
refused, and the licence already installed stays.

Enforcement is the operator's choice (DSPM_LICENCE_REQUIRED): when it is on and the
licence is missing or has run out, new scans are refused - with the reason - and nothing
else is: every finding, report and export stays readable, and nothing is deleted. An
expired licence keeps scans running for DSPM_LICENCE_GRACE_DAYS (14) so a renewal can
arrive by post.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend import signing

FORMAT = "sentro-licence-v1"
SETTING = "licence.document"
MAX_BYTES = 64 * 1024
REQUIRED_FIELDS = ("licence_id", "customer", "issued_at", "not_before", "expires_at")


class LicenceError(ValueError):
    """A licence that is refused. `str()` says why."""

    client_safe = True  # backend.errors: every message here is written for the person


def trust_file() -> Path:
    """The installer names it in the configuration (<DataRoot>\\trust\\publishers.json); a
    development checkout uses data/trust/ beside the code."""
    configured = os.getenv("DSPM_TRUST_FILE", "").strip()
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[1] / "data" / "trust" / "publishers.json"


def required() -> bool:
    return os.getenv("DSPM_LICENCE_REQUIRED", "0").strip().lower() in {"1", "true", "yes", "on"}


def grace_days() -> int:
    try:
        return max(0, int(os.getenv("DSPM_LICENCE_GRACE_DAYS", "14")))
    except ValueError:
        return 14


def _when(value, field: str) -> datetime:
    try:
        moment = datetime.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise LicenceError(f"The licence's {field} is not a date.") from exc
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def parse(raw: str | bytes) -> dict:
    """The licence file's envelope, checked for shape (not yet for its signature)."""
    if len(raw) > MAX_BYTES:
        raise LicenceError("That file is too large to be a licence.")
    try:
        envelope = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise LicenceError("That file is not a Sentro licence (it is not JSON).") from exc
    licence = envelope.get("licence") if isinstance(envelope, dict) else None
    if not isinstance(licence, dict) or licence.get("format") != FORMAT:
        raise LicenceError("That file is not a Sentro licence.")
    missing = [field for field in REQUIRED_FIELDS if not licence.get(field)]
    if missing:
        raise LicenceError(f"The licence is missing {', '.join(missing)}.")
    return envelope


def verify(envelope: dict, *, now: datetime | None = None, trust: dict | None = None) -> dict:
    """The licence, verified and in force; raises LicenceError otherwise."""
    licence = envelope["licence"]
    try:
        key = signing.verify_signed(licence, envelope, signing.load_trust(trust_file()) if trust is None else trust,
                                    "licence")
    except signing.TrustError as exc:
        raise LicenceError(f"The licence is refused: {exc}") from exc
    moment = now or datetime.now(timezone.utc)
    if _when(licence["not_before"], "start date") > moment:
        raise LicenceError(f"The licence is not valid before {licence['not_before']}.")
    if _when(licence["expires_at"], "expiry date") <= moment:
        raise LicenceError(f"The licence expired on {licence['expires_at']}. Install its renewal.")
    return {**licence, "key_id": key}


def status(envelope: dict | None, *, now: datetime | None = None, trust: dict | None = None) -> dict:
    """What the installed licence is worth now: valid, grace, expired, invalid or missing."""
    moment = now or datetime.now(timezone.utc)
    if envelope is None:
        return {"state": "missing", "scans_allowed": not required(), "required": required(),
                "message": "No licence is installed."}
    licence = envelope.get("licence") or {}
    summary = {key: licence.get(key) for key in ("licence_id", "customer", "issued_at", "not_before", "expires_at",
                                                 "features", "limits")}
    try:
        verify(envelope, now=moment, trust=trust)
    except LicenceError as exc:
        expired = False
        try:
            expiry = _when(licence.get("expires_at"), "expiry date")
            signing.verify_signed(licence, envelope, signing.load_trust(trust_file()) if trust is None else trust,
                                  "licence")
            expired = expiry <= moment
        except (LicenceError, signing.TrustError):
            expired = False
        if expired:
            ends = expiry + timedelta(days=grace_days())
            if moment < ends:
                return {**summary, "state": "grace", "scans_allowed": True, "required": required(),
                        "grace_ends": ends.isoformat(),
                        "message": f"The licence expired; scans continue until {ends:%Y-%m-%d}. Install its renewal."}
            return {**summary, "state": "expired", "scans_allowed": not required(), "required": required(),
                    "message": str(exc)}
        return {**summary, "state": "invalid", "scans_allowed": not required(), "required": required(),
                "message": str(exc)}
    expires = _when(licence["expires_at"], "expiry date")
    return {**summary, "state": "valid", "scans_allowed": True, "required": required(),
            "days_left": (expires - moment).days,
            "message": f"Licensed to {licence.get('customer')} until {expires:%Y-%m-%d} ({(expires - moment).days} days)."}


def installed() -> dict | None:
    from backend import store

    raw = store.get_app_setting(SETTING)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def install(raw: str | bytes, *, now: datetime | None = None) -> dict:
    """Verify and install a licence file; the one installed before stays if it is refused."""
    from backend import store

    envelope = parse(raw)
    licence = verify(envelope, now=now)
    store.set_app_setting(SETTING, json.dumps(envelope, sort_keys=True))
    return licence


def scans_allowed() -> tuple[bool, str]:
    """Whether a new scan may start, and why not."""
    if not required():
        return True, ""
    current = status(installed())
    allowed = bool(current["scans_allowed"])
    return allowed, "" if allowed else str(current["message"])
