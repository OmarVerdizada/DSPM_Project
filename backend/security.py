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


ROLES = {"admin": 3, "analyst": 2, "viewer": 1}
SECRET_KEY = os.getenv("DSPM_SECRET_KEY", "dev-only-change-me")
TOKEN_TTL_SECONDS = int(os.getenv("DSPM_TOKEN_TTL_SECONDS", "28800"))
DEFAULT_USERS = {
    "admin": {
        "password_hash": hashlib.sha256(os.getenv("DSPM_ADMIN_PASSWORD", "admin123").encode()).hexdigest(),
        "role": "admin",
        "tenant": "default",
    }
}
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
    user = DEFAULT_USERS.get(username)
    if not user:
        return None
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if not hmac.compare_digest(password_hash, user["password_hash"]):
        return None
    return Principal(username, user["role"], user["tenant"])


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
