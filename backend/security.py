from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.store import create_user, get_user, list_users, mark_user_login


ROLES = {"admin": 3, "analyst": 2, "viewer": 1}
SECRET_KEY = os.getenv("DSPM_SECRET_KEY", "dev-only-change-me")
TOKEN_TTL_SECONDS = int(os.getenv("DSPM_TOKEN_TTL_SECONDS", "28800"))
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


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 210_000).hex()
    return f"pbkdf2_sha256$210000${salt}${digest}"


def verify_password(password: str, password_hash: str) -> bool:
    if password_hash.startswith("pbkdf2_sha256$"):
        _, rounds, salt, digest = password_hash.split("$", 3)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(rounds)).hex()
        return hmac.compare_digest(candidate, digest)
    return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), password_hash)


def sanitize_username(username: str) -> str:
    return username.strip().lower()


def ensure_default_admin() -> None:
    users = list_users()
    if users:
        return
    create_user(
        "admin",
        hash_password(os.getenv("DSPM_ADMIN_PASSWORD", "admin123")),
        "admin",
        "default",
        "Local Administrator",
    )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _sign(message: str) -> str:
    return _b64url(hmac.new(SECRET_KEY.encode(), message.encode(), hashlib.sha256).digest())


def create_token(subject: str, role: str, tenant_id: str) -> str:
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(
        json.dumps(
            {
                "sub": subject,
                "role": role,
                "tenant": tenant_id,
                "iat": now,
                "exp": now + TOKEN_TTL_SECONDS,
                "jti": secrets.token_hex(8),
            },
            separators=(",", ":"),
        ).encode()
    )
    message = f"{header}.{payload}"
    return f"{message}.{_sign(message)}"


def verify_token(token: str) -> Principal:
    try:
        header, payload, signature = token.split(".")
        message = f"{header}.{payload}"
        if not hmac.compare_digest(_sign(message), signature):
            raise ValueError("bad signature")
        claims = json.loads(_b64url_decode(payload))
        if int(claims.get("exp", 0)) < int(time.time()):
            raise ValueError("expired token")
        role = str(claims.get("role", "viewer"))
        if role not in ROLES:
            raise ValueError("invalid role")
        return Principal(str(claims["sub"]), role, str(claims.get("tenant") or "default"))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token") from exc


def authenticate_user(username: str, password: str) -> Principal | None:
    user = get_user(sanitize_username(username))
    if not user or not user["is_active"]:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    mark_user_login(user["username"])
    return Principal(user["username"], user["role"], user["tenant_id"])


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key() -> tuple[str, str]:
    raw = f"dspm_{secrets.token_urlsafe(32)}"
    return raw, hash_api_key(raw)


def require_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    x_tenant_id: Annotated[str | None, Header(alias="X-Tenant-ID")] = None,
) -> Principal:
    if credentials and credentials.scheme.lower() == "bearer":
        principal = verify_token(credentials.credentials)
        if x_tenant_id and principal.role == "admin":
            return Principal(principal.subject, principal.role, x_tenant_id, principal.auth_type)
        return principal

    if x_api_key:
        key_hash = hash_api_key(x_api_key)
        for tenant_id, stored_hash in API_KEYS.items():
            if hmac.compare_digest(key_hash, stored_hash):
                return Principal("api-key", "analyst", x_tenant_id or tenant_id, "api_key")

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


def require_role(*roles: str):
    min_rank = min(ROLES[role] for role in roles)

    def dependency(principal: Annotated[Principal, Depends(require_principal)]) -> Principal:
        if ROLES.get(principal.role, 0) < min_rank:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return principal

    return dependency


ensure_default_admin()
