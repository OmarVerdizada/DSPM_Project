"""C2: a second factor for privileged identities - TOTP (RFC 6238), offline, no cloud.

Administrators (`tenant.admin`, `platform.admin`) cannot obtain a session without it, and
nobody may EXERCISE an MFA-scoped permission (those two, and `credential.manage`) from a
session that has not proved it (`security.require_permission`). The factor is an
authenticator app: a shared secret, a 30-second step, six digits - the RFC 6238 defaults
every authenticator implements, so nothing here depends on a vendor or the Internet.

* The secret is shown once, at enrollment, and never again. It is stored encrypted with
  the vault key (C12 rotates it with the credentials) and only after the person proves
  they captured it by entering a code.
* A code is accepted for its own step and one step either side (clock skew), and a step
  is accepted at most once and never one older than the last accepted - a replayed or
  shoulder-surfed code fails (`store.consume_mfa_step`).
* Ten recovery codes of 80 random bits each are shown once and stored as SHA-256 hashes;
  each works once. At 80 bits a hash needs no salt or stretching to resist guessing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

PERIOD_SECONDS = 30
DIGITS = 6
SKEW_STEPS = 1
RECOVERY_CODES = 10
ENROLLMENT_SECONDS = 600
ISSUER = "Sentro DSPM"

# Who needs it. A role holding any of these must pass MFA before a session exists.
SIGN_IN_PERMISSIONS = frozenset({"tenant.admin", "platform.admin"})
# And no session may use one of these without having passed MFA - including a role
# that only manages credentials, which does not force MFA at sign-in but is refused
# here until the session steps up.
GATED_PERMISSIONS = frozenset({"tenant.admin", "platform.admin", "credential.manage",
                               # C13: a raw value is revealed only to a session that proved
                               # the factor - and so never to an API key.
                               "evidence.reveal"})


def generate_secret() -> str:
    """160 random bits, base32 - the size RFC 4226 recommends for HMAC-SHA1."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    cleaned = "".join(secret.split()).upper()
    return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))


def code_at(secret: str, step: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % (10 ** DIGITS)).zfill(DIGITS)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // PERIOD_SECONDS)


def matching_step(secret: str, code: str, now: float | None = None) -> int | None:
    """The time step `code` belongs to, within the allowed skew, or None."""
    cleaned = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(cleaned) != DIGITS:
        return None
    here = current_step(now)
    for step in range(here - SKEW_STEPS, here + SKEW_STEPS + 1):
        if hmac.compare_digest(code_at(secret, step), cleaned):
            return step
    return None


def provisioning_uri(secret: str, account: str) -> str:
    """The otpauth:// URI an authenticator app imports (by QR code or by pasting)."""
    label = quote(f"{ISSUER}:{account}", safe="")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER, safe='')}"
            f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD_SECONDS}")


def generate_recovery_codes() -> list[str]:
    """Ten codes shaped XXXX-XXXX-XXXX-XXXX (base32, 80 bits each)."""
    codes = []
    for _ in range(RECOVERY_CODES):
        raw = base64.b32encode(secrets.token_bytes(10)).decode("ascii")
        codes.append("-".join(raw[index:index + 4] for index in range(0, 16, 4)))
    return codes


def normalize_recovery_code(code: str) -> str:
    return "".join(ch for ch in str(code or "").upper() if ch.isalnum())


def recovery_hash(code: str) -> str:
    return hashlib.sha256(f"sentro-recovery.{normalize_recovery_code(code)}".encode()).hexdigest()


def requires_sign_in_mfa(permissions: frozenset | set) -> bool:
    return bool(set(permissions) & SIGN_IN_PERMISSIONS)
