from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import string
import time
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from pathlib import Path

from backend.store import (
    consume_one_time_token,
    consume_refresh_token,
    create_user,
    custom_role_permissions,
    forget_session,
    get_active_api_key,
    get_user,
    is_token_revoked,
    mark_user_login,
    record_session,
    revoke_refresh_family,
    revoke_token_jti,
    role_exists,
    token_state,
    session_last_seen,
    tenant_exists,
    touch_api_key,
    touch_session,
    update_user_password,
    update_user_role,
)
from backend.breached_passwords import password_is_breached
from backend.mfa import GATED_PERMISSIONS, requires_sign_in_mfa
from backend.permissions import AUTHENTICATED, PERMISSIONS, PLATFORM_ONLY, is_known_role, role_permissions
from backend.store import issue_refresh_token as store_issue_refresh_token


logger = logging.getLogger(__name__)

ENVIRONMENT = os.getenv("DSPM_ENV", "local").strip().lower()
IS_PRODUCTION = ENVIRONMENT in {"prod", "production"}
BASE_DIR = Path(__file__).resolve().parent.parent


def _load_secret_key() -> str:
    configured = os.getenv("DSPM_SECRET_KEY", "").strip()
    if configured:
        if len(configured) < 32:
            raise RuntimeError("DSPM_SECRET_KEY must be at least 32 characters long")
        return configured
    if IS_PRODUCTION:
        raise RuntimeError("DSPM_SECRET_KEY must be set in production")
    # M1 (Phase 1.1): the dev signing key lives OUTSIDE data/ so a data/ backup
    # never carries auth key material (a stolen backup could otherwise forge an
    # admin token). Default ~/.dspm/ mirrors the vault key's externalization.
    key_path = Path(os.getenv("DSPM_LOCAL_JWT_SECRET_PATH", str(Path.home() / ".dspm" / "jwt_secret")))
    legacy_path = BASE_DIR / "data" / ".jwt_secret"
    try:
        if key_path.exists():
            return key_path.read_text(encoding="utf-8").strip()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        # The old data/.jwt_secret was duplicated across working trees, so it is
        # ROTATED (a fresh key is generated), not migrated, and the old copy is
        # removed from data/ so it can no longer reach a backup.
        generated = secrets.token_urlsafe(48)
        key_path.write_text(generated, encoding="utf-8")
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        legacy_path.unlink(missing_ok=True)
        return generated
    except OSError:
        raise RuntimeError("Unable to load or persist DSPM_SECRET_KEY")


SECRET_KEY = _load_secret_key()
DEFAULT_SECRET_IN_USE = "DSPM_SECRET_KEY" not in os.environ
# C1: the ACCESS token's life, now bounded to half an hour. It used to be eight, which
# made it a bearer credential with an eight-hour blast radius - whoever lifted it from a
# browser, a proxy log or a crash dump held the account for the rest of the working day.
# The session is still eight hours long; it is the refresh token below that carries it,
# and that token is single use (see issue_refresh_token / rotate_refresh_token).
TOKEN_TTL_SECONDS = int(os.getenv("DSPM_TOKEN_TTL_SECONDS", "1800"))

# How long a token may go unused before it stops working. An 8-hour token with
# no idle timeout means a console left open on an unlocked machine at 09:00 is
# still signed in at 17:00.
#
# Last-seen is held IN THIS PROCESS, deliberately: a per-request database write
# is exactly what the performance work removed from the authenticated path, and
# a new table would be a schema revision for a one-day control. The trade is
# stated rather than hidden - on a restart every session is admitted once more,
# and with several workers each tracks what IT has seen, so a session idle in
# one worker and active in another stays alive. The single-instance on-prem
# deployment this ships into has neither problem, and the CONSEQUENCE is not
# local: an expired session is revoked in the database, so it dies everywhere.
# 0 disables the check.
SESSION_IDLE_SECONDS = int(os.getenv("DSPM_SESSION_IDLE_SECONDS", "3600"))
# jti -> (last seen in this process, when the durable row was last written)
_session_last_seen: dict[str, tuple[float, float]] = {}
API_KEYS = {
    item.split(":", 1)[0]: item.split(":", 1)[1]
    for item in os.getenv("DSPM_API_KEYS", "").split(",")
    if ":" in item
}

bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    role: str
    tenant_id: str
    auth_type: str = "jwt"
    # The tenant selected by X-Tenant-ID is an effective data scope, not a new
    # identity.  Preserve the authenticated account's home tenant so the
    # built-in Local Administrator remains a platform administrator after a
    # pivot (and can therefore list/switch tenants or create another one).
    home_tenant_id: str = ""
    # C8: the session (access-token jti) this principal was authenticated by, so a
    # credential minted on its behalf - a download token - can be bound to it and die
    # with it. Empty for API keys and system principals, which have no session.
    session_id: str = ""
    # C2: the session proved a second factor (TOTP or a recovery code) - required to
    # exercise an MFA-scoped permission (backend.mfa.GATED_PERMISSIONS).
    mfa_verified: bool = False


# C8: the policy a NEW password is held to. Existing passwords keep working at sign-in
# whatever they are; this only decides what may be chosen from now on.
PASSWORD_MIN_LENGTH_FLOOR = 8


def password_min_length() -> int:
    """Twelve by default. An operator may raise it, and may lower it to eight - never
    below, which is where it already stood."""
    try:
        configured = int(os.getenv("DSPM_PASSWORD_MIN_LENGTH", "12"))
    except ValueError:
        configured = 12
    return max(PASSWORD_MIN_LENGTH_FLOOR, min(configured, 64))


def _refuse_password(reason: str) -> None:
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=reason)


def validate_password_strength(password: str, *, username: str = "") -> None:
    """Refuse a new password that is short, trivial, personal or known to be bad.

    C8 raised the floor from eight characters to twelve and added the refusals that do
    the most against real guessing: a password on the common/breached list (see
    backend.breached_passwords - checked offline), one made mostly of one character,
    and one that contains the account's own name. The letters-and-digits rule stays,
    so nothing that was refused before is accepted now.
    """

    minimum = password_min_length()
    if len(password or "") < minimum:
        _refuse_password(f"Password must be at least {minimum} characters")
    if len(password) > 200:
        _refuse_password("Password is too long")
    if not any(ch.isalpha() for ch in password) or not any(ch.isdigit() for ch in password):
        _refuse_password("Password must include letters and numbers")
    if len(set(password.lower())) < 4:
        _refuse_password("Password is too repetitive")
    name = str(username or "").strip().lower()
    if len(name) >= 3 and name in password.lower():
        _refuse_password("Password must not contain the username")
    if password_is_breached(password):
        _refuse_password("This password is too common or has appeared in a breach. Choose another.")


def pbkdf2_rounds() -> int:
    """C8 raised the default work factor from 310,000 to 600,000 (OWASP's current figure
    for PBKDF2-HMAC-SHA256). Clamped as before: an operator cannot weaken the install
    below 210,000 or make a sign-in take seconds above 1,200,000."""
    try:
        rounds = int(os.getenv("DSPM_PBKDF2_ROUNDS", "600000"))
    except ValueError:
        rounds = 600_000
    return max(210_000, min(rounds, 1_200_000))


def _pbkdf2_hash(password: str, rounds: int | None = None) -> str:
    salt = secrets.token_hex(16)
    work = rounds or pbkdf2_rounds()
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), work).hex()
    return f"pbkdf2_sha256${work}${salt}${digest}"


def hash_password(password: str, *, username: str = "") -> str:
    validate_password_strength(password, username=username)
    return _pbkdf2_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    if password_hash.startswith("pbkdf2_sha256$"):
        # C8: a stored hash that does not parse - cut short by a bad restore, edited by
        # hand - used to raise out of the sign-in path as a 500. It is a failed sign-in.
        try:
            _, rounds, salt, digest = password_hash.split("$", 3)
            work = int(rounds)
            if not salt or not digest or work <= 0:
                return False
            candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), work).hex()
        except (ValueError, OverflowError):
            logger.warning("A stored password hash could not be parsed; the sign-in is refused")
            return False
        return hmac.compare_digest(candidate, digest)
    if os.getenv("DSPM_ALLOW_LEGACY_SHA256_PASSWORDS", "0") == "1":
        return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), password_hash)
    return False


def password_needs_rehash(password_hash: str) -> bool:
    """Whether a hash that just verified was made with weaker parameters than now.

    A work-factor increase would otherwise only protect passwords set after it. The
    moment a user signs in is the only moment the plaintext is available to re-hash, so
    that is when it happens - silently, and without signing anyone out.
    """

    if not password_hash.startswith("pbkdf2_sha256$"):
        return True  # legacy SHA-256, which only verifies at all behind its opt-in
    try:
        return int(password_hash.split("$", 3)[1]) < pbkdf2_rounds()
    except (ValueError, IndexError):
        return False


def sanitize_username(username: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._@-]", "", username.strip().lower())
    return cleaned[:80]


def _generate_dev_admin_password(length: int = 20) -> str:
    """Random password guaranteed to satisfy validate_password_strength()."""
    alphabet = string.ascii_letters + string.digits
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.isalpha() for c in candidate) and any(c.isdigit() for c in candidate):
            return candidate


def _dev_admin_password() -> str:
    """Resolve the local built-in admin password without a static default (SC-5).

    Uses DSPM_DEV_ADMIN_PASSWORD when set; otherwise generates a strong random
    password and prints it once so a local operator can sign in. Only reached in
    non-production (production requires DSPM_ADMIN_PASSWORD and raises above).
    The previous hardcoded 'admin123' default allowed trivial admin takeover on
    any install that forgot to set an env var.
    """
    configured = os.getenv("DSPM_DEV_ADMIN_PASSWORD", "").strip()
    if configured:
        return configured
    generated = _generate_dev_admin_password()
    print(
        "[dspm] No DSPM_ADMIN_PASSWORD or DSPM_DEV_ADMIN_PASSWORD is set. "
        f"Generated a one-time local admin password for 'admin': {generated}",
        flush=True,
    )
    return generated


def ensure_default_admin() -> None:
    """Create the built-in admin only when explicitly safe.

    Production must set DSPM_ADMIN_PASSWORD. Local installs use
    DSPM_DEV_ADMIN_PASSWORD or a generated one-time password (never a static
    default), and existing admin passwords are not silently reset unless
    DSPM_SYNC_BUILTIN_ADMIN=1 is explicitly enabled.
    """
    username = "admin"
    configured_password = os.getenv("DSPM_ADMIN_PASSWORD", "").strip()
    if IS_PRODUCTION and not configured_password:
        raise RuntimeError("DSPM_ADMIN_PASSWORD must be set in production")
    user = get_user(username)
    if user is None:
        password = configured_password or _dev_admin_password()
        create_user(
            username,
            _admin_password_hash(password),
            "admin",
            "default",
            "Local Administrator",
        )
        return

    if os.getenv("DSPM_SYNC_BUILTIN_ADMIN", "0") != "1":
        return

    if user.get("role") != "admin" or user.get("tenant_id") != "default":
        update_user_role(username, "admin", "default")
    if configured_password and not verify_password(configured_password, user["password_hash"]):
        update_user_password(username, _admin_password_hash(configured_password))


def _admin_password_hash(password: str) -> str:
    """The built-in admin's password is chosen in an environment variable, so a policy
    refusal surfaces at startup - where an HTTP 400 means nothing. Say what to change."""
    try:
        return hash_password(password, username="admin")
    except HTTPException as exc:
        raise RuntimeError(
            f"The built-in admin password (DSPM_ADMIN_PASSWORD or DSPM_DEV_ADMIN_PASSWORD) "
            f"does not meet the password policy: {exc.detail}."
        ) from None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _sign(message: str) -> str:
    return _b64url(hmac.new(SECRET_KEY.encode(), message.encode(), hashlib.sha256).digest())


REFRESH_TTL_SECONDS = int(os.getenv("DSPM_REFRESH_TOKEN_TTL_SECONDS", "28800"))
REFRESH_COOKIE = "dspm_refresh"


def _refresh_hash(secret: str) -> str:
    """What the database holds. The secret itself never lands in a row, so a copy of
    the table (a backup, a dump, a support bundle) is not a set of working sessions."""
    return hashlib.sha256(f"refresh.{secret}".encode()).hexdigest()


def issue_refresh_token(subject: str, session_jti: str, family_id: str = "", *,
                        mfa_verified: bool = False) -> tuple[str, str, int]:
    """Mint the next link in a refresh chain. Returns (secret, family_id, expires_at).

    The family is the chain: rotation keeps it, and a replay revokes all of it.
    """

    secret = secrets.token_urlsafe(48)
    family = family_id or secrets.token_hex(16)
    now = int(time.time())
    expires_at = now + REFRESH_TTL_SECONDS
    store_issue_refresh_token(_refresh_hash(secret), family, subject, session_jti, now, expires_at,
                              mfa_verified=mfa_verified)
    return secret, family, expires_at


def rotate_refresh_token(secret: str) -> dict:
    """Exchange a refresh token for the next access token and the next refresh token.

    Returns {"status": "ok", "access_token", "refresh_token", "expires_at", "principal"}
    or {"status": "replayed"|"expired"|"unknown"|"inactive"} - never a partial success:
    a caller that gets anything other than "ok" must send the user back to sign in.
    """

    if not secret:
        return {"status": "unknown"}
    record = consume_refresh_token(_refresh_hash(secret))
    status = record.get("status")
    if status == "replayed":
        # Two parties hold this chain. Which one is presenting it cannot be known, so
        # neither keeps it: the family goes, including the access sessions it issued.
        revoke_refresh_family(str(record.get("family_id") or ""))
        return {"status": "replayed", "family_id": record.get("family_id", "")}
    if status != "ok":
        return {"status": status or "unknown"}

    username = str(record.get("username") or "")
    user = get_user(sanitize_username(username))
    if not user or not user.get("is_active"):
        revoke_refresh_family(str(record.get("family_id") or ""))
        return {"status": "inactive"}
    if user.get("auth_source") == "ldap":
        # C2: a directory account's groups are re-read when they are older than the
        # revalidation window, so a removed group or a disabled account loses its
        # sessions here - not whenever the chain happens to end.
        from backend.identity import revalidate_directory_account

        verdict = revalidate_directory_account(user)
        if verdict != "ok":
            if verdict in {"inactive", "demoted"}:
                revoke_refresh_family(str(record.get("family_id") or ""))
            return {"status": "inactive" if verdict in {"inactive", "demoted"} else "directory_unavailable"}
        user = get_user(user["username"]) or user
    mfa_verified = bool(record.get("mfa_verified"))
    if not mfa_verified and requires_sign_in_mfa(role_permissions_in(str(user.get("role") or ""),
                                                                     str(user.get("tenant_id") or "default"))):
        # A session from before MFA was required, or an account promoted since: it
        # cannot be renewed into an administrator's session without the second factor.
        revoke_refresh_family(str(record.get("family_id") or ""))
        return {"status": "mfa_required"}
    # The role and tenant come from the row on every refresh, exactly as verify_token
    # reads them on every request: a demotion must not wait for the chain to end.
    role = str(user.get("role") or "viewer")
    tenant_id = str(user.get("tenant_id") or "default")

    previous_jti = str(record.get("session_jti") or "")
    if previous_jti:
        revoke_token_jti(previous_jti, int(record.get("expires_at") or 0))
        _session_last_seen.pop(previous_jti, None)
        forget_session(previous_jti)

    access = create_token(user["username"], role, tenant_id, mfa_verified=mfa_verified)
    next_secret, family, expires_at = issue_refresh_token(
        user["username"], _token_jti(access), str(record.get("family_id") or ""), mfa_verified=mfa_verified
    )
    return {
        "status": "ok",
        "access_token": access,
        "refresh_token": next_secret,
        "family_id": family,
        "expires_at": expires_at,
        "principal": Principal(user["username"], role, tenant_id),
    }


def _token_jti(token: str) -> str:
    try:
        return str(json.loads(_b64url_decode(token.split(".")[1])).get("jti") or "")
    except Exception:
        return ""


# The only header an access token has. verify_token requires it byte for byte: the MFA
# challenge ("mfa.<payload>") and the download token ("artifact_dl.<payload>") are
# signed with the same key over "<prefix>.<payload>", so without this check either one,
# given its prefix back as a header, verified as a session (M3 exit review).
_TOKEN_HEADER = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())


def create_token(subject: str, role: str, tenant_id: str, *, mfa_verified: bool = False) -> str:
    """An access token and its session row. `mfa_verified` records that the session proved a
    second factor; every production caller states it (sign-in, MFA completion, refresh)."""
    now = int(time.time())
    claims = {
        "sub": subject,
        "role": role,
        "tenant": tenant_id,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
        "jti": secrets.token_hex(8),
    }
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    message = f"{_TOKEN_HEADER}.{payload}"
    # C1: every issued token is a session row, so the idle timeout survives a restart,
    # a password change can end all of them, and the per-account cap has something to
    # count. The token itself is unchanged - an install upgrading mid-session keeps
    # working, and its sessions become rows the first time they are used.
    record_session(claims["jti"], subject, now, claims["exp"], mfa_verified=mfa_verified)
    return f"{message}.{_sign(message)}"


def verify_token(token: str) -> Principal:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("malformed token")
        header, payload, signature = parts
        if not hmac.compare_digest(header, _TOKEN_HEADER):
            raise ValueError("not an access token")
        message = f"{header}.{payload}"
        if not hmac.compare_digest(_sign(message), signature):
            raise ValueError("bad signature")
        claims = json.loads(_b64url_decode(payload))
        exp = int(claims.get("exp", 0))
        if exp < int(time.time()):
            raise ValueError("expired token")
        jti = str(claims.get("jti") or "")
        subject = sanitize_username(str(claims.get("sub") or ""))
        # C1: revocation and the account in one read, from the database every time a
        # token is not already known to be revoked - so a sign-out or a password change
        # on another backend is refused here at once (store.token_state).
        revoked, user = token_state(jti, subject)
        if revoked:
            raise ValueError("revoked token")
        if not _touch_session(jti, exp):
            raise ValueError("idle session")
        if not user or not user.get("is_active"):
            raise ValueError("inactive user")
        role = str(user.get("role") or claims.get("role") or "viewer")
        tenant_id = str(user.get("tenant_id") or claims.get("tenant") or "default")
        if not role_exists(role, tenant_id):
            raise ValueError("invalid role")
        return Principal(subject, role, tenant_id, session_id=jti,
                         mfa_verified=bool(user.get("session_mfa_verified")))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token") from exc


def _touch_session(jti: str, exp: int) -> bool:
    """Mark a session used. False when it had already gone idle.

    C1 made this durable. It used to be a per-process dictionary and nothing else,
    which meant a restart admitted every session once more - the process that had been
    watching them had simply forgotten - and with several workers each knew only what
    it had seen itself. The row in `user_sessions` is now the authority the FIRST time
    a process sees a session; after that the in-process record answers, and the row is
    written at most once per SESSION_TOUCH_INTERVAL_SECONDS.

    That throttle is the point: a per-request write to the authenticated path is what
    the performance work removed, and correctness here does not need one. The cost of
    the throttle is that a session idle in one worker can be seen as active by another
    for up to the interval, which is a fraction of an idle timeout measured in hours.

    A session with no row at all is admitted and recorded - that is what keeps tokens
    issued before this release working. Going idle REVOKES the token rather than just
    refusing it here, so the decision outlives the process that made it.
    """

    if SESSION_IDLE_SECONDS <= 0 or not jti:
        return True
    now = time.time()
    previous, written = _session_last_seen.get(jti, (None, 0.0))
    if previous is None:
        stored = session_last_seen(jti)
        previous = float(stored) if stored is not None else None
    if previous is not None and now - previous > SESSION_IDLE_SECONDS:
        _session_last_seen.pop(jti, None)
        revoke_token_jti(jti, exp)
        forget_session(jti)
        return False
    if now - written > _session_touch_interval():
        touch_session(jti, int(now))
        written = now
    _session_last_seen[jti] = (now, written)
    if len(_session_last_seen) > 4096:
        cutoff = now - max(SESSION_IDLE_SECONDS, TOKEN_TTL_SECONDS)
        for stale in [key for key, (seen, _) in _session_last_seen.items() if seen < cutoff]:
            _session_last_seen.pop(stale, None)
    return True


def _session_touch_interval() -> float:
    """How rarely the durable last-seen may be written. Never more than a quarter of
    the idle window, so a short idle timeout cannot be defeated by the throttle."""
    try:
        configured = float(os.getenv("DSPM_SESSION_TOUCH_SECONDS", "60"))
    except ValueError:
        configured = 60.0
    return max(0.0, min(configured, SESSION_IDLE_SECONDS / 4 if SESSION_IDLE_SECONDS > 0 else configured))


def revoke_token(token: str) -> None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return
        claims = json.loads(_b64url_decode(parts[1]))
        jti = str(claims.get("jti") or "")
        revoke_token_jti(jti, int(claims.get("exp", 0)))
        # The revocation is what refuses the token; the row is the session's
        # bookkeeping, and leaving it behind would make the account look busier
        # than it is to the per-account cap.
        _session_last_seen.pop(jti, None)
        forget_session(jti)
    except Exception:
        return


@functools.lru_cache(maxsize=1)
def _dummy_password_hash() -> str:
    """A real hash of a password nobody has, at this install's work factor.

    C1: an unknown account used to return before any hashing happened, so a sign-in
    attempt for a name that exists came back measurably later than one for a name that
    does not - which is an account enumeration oracle that needs no failed-login audit
    entry and trips no throttle. Verifying against this hash spends the same work on
    both, and it is computed once because the point of PBKDF2 is that it is slow.
    """

    return hash_password(f"absent-account-{secrets.token_hex(16)}1")


def authenticate_user(username: str, password: str, *, user: dict | None = None) -> Principal | None:
    """A LOCAL account's password check. `user` is the account already found (by
    workspace and sign-in name); otherwise the name is the account key. A directory
    account has no local password and is refused here, after the same work."""
    user = user if user is not None else get_user(sanitize_username(username))
    if not user or not user["is_active"] or user.get("auth_source", "local") != "local":
        # Deliberately not `return None` before hashing - see _dummy_password_hash.
        verify_password(password or "", _dummy_password_hash())
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    if password_needs_rehash(user["password_hash"]):
        # C8: bring the stored hash up to today's work factor while the plaintext is in
        # hand. Deliberately no policy check - the user proved they know this password,
        # and refusing their sign-in because the policy has since tightened would lock
        # accounts out rather than protect them.
        update_user_password(user["username"], _pbkdf2_hash(password))
        logger.info("Password hash upgraded to the current work factor for %s", user["username"])
    mark_user_login(user["username"])
    return Principal(user["username"], user["role"], user["tenant_id"])


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key() -> tuple[str, str]:
    raw = f"dspm_{secrets.token_urlsafe(32)}"
    return raw, hash_api_key(raw)


def is_platform_admin(principal: Principal) -> bool:
    """The built-in platform admin (the ``admin`` user in the ``default`` tenant).

    Only this identity may operate across tenants. A tenant-scoped admin (role
    ``admin`` in their own tenant) must not. This is the same definition already
    enforced on the tenant-management routes; SC-15 makes the X-Tenant-ID pivot
    consistent with it.
    """
    home_tenant_id = principal.home_tenant_id or principal.tenant_id
    return principal.role == "admin" and principal.subject == "admin" and home_tenant_id == "default"


def require_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    x_tenant_id: Annotated[str | None, Header(alias="X-Tenant-ID")] = None,
) -> Principal:
    if credentials and credentials.scheme.lower() == "bearer":
        principal = verify_token(credentials.credentials)
        # SC-15: only the platform admin may pivot tenants via X-Tenant-ID. A
        # tenant-scoped admin previously could read any other tenant by setting
        # this header (existence was the only check). Non-platform callers now
        # simply operate in their own token tenant; the header is ignored.
        if x_tenant_id and is_platform_admin(principal):
            requested_tenant = "".join(ch for ch in x_tenant_id.strip() if ch.isalnum() or ch in {"-", "_"})
            if not requested_tenant or not tenant_exists(requested_tenant):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant is not valid")
            return Principal(
                principal.subject,
                principal.role,
                requested_tenant,
                principal.auth_type,
                principal.home_tenant_id or principal.tenant_id,
                principal.session_id,
                principal.mfa_verified,
            )
        return principal

    if x_api_key:
        key_hash = hash_api_key(x_api_key)
        # M18: DB-backed keys first - revocable and expiring WITHOUT a redeploy. The
        # lookup already excludes revoked/expired rows; usage updates last_used_at.
        db_key = get_active_api_key(key_hash)
        if db_key:
            if x_tenant_id and x_tenant_id != db_key["tenant_id"]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="API key is not valid for this tenant")
            touch_api_key(db_key["id"])
            return Principal("api-key", db_key["role"], db_key["tenant_id"], "api_key")
        # Legacy env-configured keys (static; kept for backward compatibility).
        for tenant_id, stored_hash in API_KEYS.items():
            if hmac.compare_digest(key_hash, stored_hash):
                # API keys are tenant-scoped. Do not allow a caller to pivot into another tenant with X-Tenant-ID.
                if x_tenant_id and x_tenant_id != tenant_id:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="API key is not valid for this tenant")
                return Principal("api-key", "analyst", tenant_id, "api_key")

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


MFA_CHALLENGE_SECONDS = 300


def create_mfa_challenge(subject: str, purpose: str) -> str:
    """Proof that `subject` passed the first factor, good for five minutes, to be
    completed with a code (purpose "verify") or by enrolling (purpose "enroll"). It is
    not a session: it opens nothing but the MFA endpoints, and it is spent on success."""
    claims = {"sub": subject, "purpose": purpose, "exp": int(time.time()) + MFA_CHALLENGE_SECONDS,
              "jti": secrets.token_hex(12)}
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signature = _b64url(hmac.new(SECRET_KEY.encode(), f"mfa.{payload}".encode(), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def read_mfa_challenge(token: str, purposes: tuple[str, ...]) -> dict | None:
    """The claims of a live challenge for one of `purposes`, or None. Not spent here."""
    if not token or "." not in token:
        return None
    payload, _, signature = token.partition(".")
    expected = _b64url(hmac.new(SECRET_KEY.encode(), f"mfa.{payload}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, signature):
        return None
    try:
        claims = json.loads(_b64url_decode(payload))
    except Exception:
        return None
    if not isinstance(claims, dict) or claims.get("purpose") not in purposes:
        return None
    if int(claims.get("exp", 0)) < int(time.time()) or not claims.get("jti"):
        return None
    if is_token_revoked(_spent_challenge_key(claims["jti"])):
        return None
    return claims


def _spent_challenge_key(jti: str) -> str:
    # consume_one_time_token files a spent id under "dl:<id>"; the check must read the
    # same key, or a spent challenge reads as unspent (M3 exit review).
    return f"dl:mfa:{jti}"


def spend_mfa_challenge(claims: dict) -> bool:
    return consume_one_time_token(f"mfa:{claims.get('jti')}", int(claims.get("exp") or 0))


ARTIFACT_DL_TOKEN_TTL_SECONDS = int(os.getenv("DSPM_ARTIFACT_DL_TOKEN_TTL_SECONDS", "300"))


def create_artifact_download_token(
    artifact_id: str,
    tenant_id: str,
    subject: str,
    role: str,
    ttl_seconds: int = ARTIFACT_DL_TOKEN_TTL_SECONDS,
    *,
    session_id: str = "",
) -> str:
    """A one-time credential for fetching one artifact.

    C8: it carries its own id (`jti`) so it can be spent exactly once, and the id of the
    session that minted it (`sid`) so it dies with that session. The role and tenant are
    recorded so the account can be checked against them when it is used.
    """

    claims = {
        "aid": artifact_id,
        "tenant": tenant_id,
        "sub": subject,
        "role": role,
        "exp": int(time.time()) + ttl_seconds,
        "jti": secrets.token_hex(12),
        "sid": session_id,
    }
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signature = _b64url(hmac.new(SECRET_KEY.encode(), f"artifact_dl.{payload}".encode(), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def _download_claims(token: str, artifact_id: str) -> dict | None:
    """The token's claims if it is well formed, signed here, for this artifact and in
    date - and nothing else checked yet."""
    if not token or "." not in token:
        return None
    payload_b64, _, signature = token.partition(".")
    expected = _b64url(hmac.new(SECRET_KEY.encode(), f"artifact_dl.{payload_b64}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, signature):
        return None
    try:
        claims = json.loads(_b64url_decode(payload_b64))
    except Exception:
        return None
    if not isinstance(claims, dict):
        return None
    if str(claims.get("aid") or "") != artifact_id or int(claims.get("exp", 0)) < int(time.time()):
        return None
    tenant_id, subject, role = (str(claims.get(key) or "") for key in ("tenant", "sub", "role"))
    if not tenant_id or not subject or not role_exists(role, tenant_id):
        return None
    return claims


def _download_account_still_holds(claims: dict) -> bool:
    """Whether the account behind a download token still has what it had when minted.

    The token used to be trusted on its own contents: a disabled account, a signed-out
    session and a demoted role all still downloaded for the rest of its life. It is now
    held to the same standard as the session it came from - and a stricter one on role,
    because a link minted under one set of privileges is not re-interpreted under
    another; it simply stops working.
    """

    subject = str(claims.get("sub") or "")
    tenant_id = str(claims.get("tenant") or "")
    if subject == "api-key":
        # Minted for an API-key caller, who has no session and fetches with the key
        # itself; single use and the five-minute life are its bounds.
        return True
    session_id = str(claims.get("sid") or "")
    if not session_id:
        return False
    revoked, user = token_state(session_id, sanitize_username(subject))
    if revoked or not user or not user.get("is_active"):
        return False
    if str(user.get("role") or "") != str(claims.get("role") or ""):
        return False
    if str(user.get("tenant_id") or "") != tenant_id:
        # A platform administrator mints tokens while pivoted into another tenant.
        pivoted = Principal(subject, str(user.get("role") or ""), str(user.get("tenant_id") or ""))
        if not (is_platform_admin(pivoted) and tenant_exists(tenant_id)):
            return False
    return True


def verify_artifact_download_token(token: str, artifact_id: str, *, consume: bool = True) -> Principal | None:
    """The principal a download token stands for, or None.

    `consume` spends the token: a second presentation is refused. It is atomic in the
    database, so two requests racing with one copied link cannot both succeed.
    """

    claims = _download_claims(token, artifact_id)
    if claims is None or not _download_account_still_holds(claims):
        return None
    token_id = str(claims.get("jti") or "")
    if not token_id:
        # Minted before C8: no id to spend, so it cannot be single use - and it was
        # never bound to a session. Refused; the console mints a fresh one per fetch.
        return None
    if consume and not consume_one_time_token(token_id, int(claims.get("exp") or 0)):
        return None
    return Principal(
        str(claims["sub"]), str(claims["role"]), str(claims["tenant"]), "artifact_dl_token",
        session_id=str(claims.get("sid") or ""),
    )


# A query string is written to every proxy and web-server access log in the path, so
# a token carried there is a credential written to disk by machines Sentro does not
# control. C8: the console fetches with the header and shows a same-origin blob, so the
# query form is off. DSPM_ALLOW_DL_TOKEN_QUERY=1 turns it back on for a non-production
# install whose browser refuses blob navigation; production ignores it.
def _query_tokens_allowed() -> bool:
    if os.getenv("DSPM_ENV", "local").strip().lower() in {"prod", "production"}:
        return False
    return os.getenv("DSPM_ALLOW_DL_TOKEN_QUERY", "0").strip().lower() in {"1", "true", "yes", "on"}


def require_artifact_principal(
    artifact_id: str,
    dl_token: Annotated[str | None, Query()] = None,
    x_artifact_token: Annotated[str | None, Header(alias="X-Artifact-Token")] = None,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)] = None,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    x_tenant_id: Annotated[str | None, Header(alias="X-Tenant-ID")] = None,
) -> Principal:
    token = x_artifact_token or (dl_token if _query_tokens_allowed() else None)
    principal = verify_artifact_download_token(token, artifact_id) if token else None
    return principal or require_principal(credentials, x_api_key, x_tenant_id)


def require_artifact_download(principal: Annotated[Principal, Depends(require_artifact_principal)]) -> Principal:
    """C3: fetching a filed report is part of filing reports. Checked on the resolved
    principal, so it holds however the caller authenticated - session, API key or a
    one-time download token (whose role is re-read when it is spent)."""
    if not has_permission(principal, "report.create"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Your role does not allow this (it needs report.create)")
    return principal


require_artifact_download.required_permissions = ("report.create",)


def role_permissions_in(role: str, tenant_id: str) -> frozenset[str]:
    """What a role grants in a tenant: a built-in role anywhere, a custom role only in the
    tenant that defined it. An unknown role grants nothing."""
    if is_known_role(role):
        return role_permissions(role)
    return custom_role_permissions(tenant_id, role) or frozenset()


def principal_permissions(principal: Principal) -> frozenset[str]:
    """What this caller may do: its role's permissions - resolved in the tenant the account
    belongs to, not one a platform administrator has pivoted into - and `platform.admin`
    for the installation's own administrator identity, which no role can grant."""
    granted = role_permissions_in(principal.role, principal.home_tenant_id or principal.tenant_id)
    if is_platform_admin(principal):
        granted = granted | PLATFORM_ONLY
    return granted


def has_permission(principal: Principal, permission: str) -> bool:
    return permission in principal_permissions(principal)


def require_permission(*permissions: str, mfa: bool | None = None):
    """C3: a route names the capability it needs; any one of `permissions` admits.

    Replaces `require_role`, whose ranks could not say "may run scans but not read what
    they found". The names are checked here, at import, so a typo fails the application
    rather than silently admitting nobody; the route matrix test reads
    `required_permissions` off the dependency to pin every route.
    """

    unknown = [name for name in permissions if name != AUTHENTICATED and name not in PERMISSIONS]
    if not permissions or unknown:
        raise ValueError(f"require_permission needs known permissions, got {permissions!r}")
    wanted = frozenset(permissions)

    # C2: by default a session must have proved MFA when the permission that admits it is
    # MFA-scoped. `mfa=True` makes the route itself MFA-scoped whichever permission admits
    # (storing a vault credential: a scan operator may, but not from an unverified session).
    gated = wanted & GATED_PERMISSIONS

    def dependency(principal: Annotated[Principal, Depends(require_principal)]) -> Principal:
        if AUTHENTICATED in wanted:
            return principal
        held = principal_permissions(principal) & wanted
        if not held:
            needed = " or ".join(sorted(wanted))
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=f"Your role does not allow this (it needs {needed})")
        if (mfa is True or (mfa is None and gated and held <= gated)) and not principal.mfa_verified:
            # C2: an MFA-scoped permission is exercised only from a session that proved a
            # second factor. An API key has no second factor, so it never holds one.
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={
                "code": "mfa_required",
                "message": "This needs a session verified with your authenticator app.",
                "hint": "Confirm a code from your authenticator (or set one up in your profile), then try again.",
            })
        return principal

    dependency.required_permissions = tuple(permissions)
    dependency.requires_mfa = mfa is True or (mfa is None and bool(gated))
    return dependency


ensure_default_admin()
