from __future__ import annotations

import hmac
import ipaddress
import os
import platform
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from backend.alerts import evaluate_alerts
from backend.jobs import cancel_job, cleanup_jobs, create_job, create_scan_job, get_job
from backend.security import (
    Principal,
    authenticate_user,
    create_token,
    generate_api_key,
    hash_password,
    require_principal,
    require_role,
    revoke_token,
    sanitize_username,
)
from backend.store import (
    audit,
    clear_login_failures,
    count_login_failures,
    create_tenant,
    create_user,
    data_retention_summary,
    delete_user,
    delete_tenant_with_data,
    get_tenant,
    get_user,
    list_tenants,
    list_users,
    read_audit_log,
    read_scan_history,
    read_scan_report,
    record_login_failure,
    rotate_registration_code,
    save_scan_history,
    tenant_exists,
    update_user_password,
    update_user_profile,
    update_user_role,
    update_user_active,
)
from backend.vault import CredentialVault
from collectors.file_scanner import normalize_extension_filter, scan_directory
from collectors.winrm_endpoint_scanner import (
    ENDPOINT_PATH_ALIASES,
    WinRMEndpointConfig,
    WinRMEndpointScanner,
    activate_local_winrm,
    normalize_endpoint_target_paths,
)
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from risk.risk_engine import get_risk_rules
from scripts.generate_enterprise_test_data import generate as generate_enterprise_test_data
from scripts.report import generate_report

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
vault = CredentialVault()
PROTECTED_USERS = {"admin"}
DEFAULT_CORS_ORIGINS = [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
]
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("DSPM_CORS_ORIGINS", ",".join(DEFAULT_CORS_ORIGINS)).split(",")
    if origin.strip()
]
TRUSTED_HOSTS = [
    host.strip()
    for host in os.getenv("DSPM_TRUSTED_HOSTS", "").split(",")
    if host.strip()
]
LOGIN_WINDOW_SECONDS = int(os.getenv("DSPM_LOGIN_WINDOW_SECONDS", "600"))
LOGIN_MAX_ATTEMPTS = int(os.getenv("DSPM_LOGIN_MAX_ATTEMPTS", "8"))
ENVIRONMENT = os.getenv("DSPM_ENV", "local").strip().lower()
IS_PRODUCTION = ENVIRONMENT in {"prod", "production"}
REPORT_DIR = Path(os.getenv("DSPM_REPORT_DIR", BASE_DIR / "data" / "reports")).resolve()
REPORT_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="DSPM DLP Discovery API",
    description="Discovers sensitive data on AD file servers and produces DLP-ready risk context.",
    version="1.0.0",
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
)

if TRUSTED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=TRUSTED_HOSTS)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Tenant-ID"],
)

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.middleware("http")
async def secure_response_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    )
    if request.url.scheme == "https" or IS_PRODUCTION:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, __: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": "Invalid request. Check required fields and formats."})


class ConnectionRequest(BaseModel):
    server: str = Field(default="", description="AD file server hostname or IP", max_length=255)
    username: str = Field(default="", max_length=160)
    password: str = Field(default="", max_length=512)
    credential_ref: str = Field(default="", max_length=120)
    domain: str = Field(default="WORKGROUP", max_length=120)
    local_path: str = Field(default="enterprise_test_data", max_length=260)
    max_depth: int = Field(default=4, ge=1, le=12)
    allowed_extensions: list[str] = Field(default_factory=list, max_length=160)
    extension_filter_enabled: bool = False
    include_hidden: bool = True
    include_system: bool = False
    hidden_filter_enabled: bool = False
    system_filter_enabled: bool = False
    include_admin_shares: bool = False
    inspect_archives: bool = False

    @field_validator("server", "username", "domain", "credential_ref")
    @classmethod
    def _clean_short_text(cls, value: str) -> str:
        return re.sub(r"[\x00-\x1f\x7f]", "", value or "").strip()

    @field_validator("local_path")
    @classmethod
    def _validate_local_path(cls, value: str) -> str:
        cleaned = re.sub(r"[\x00-\x1f\x7f]", "", value or "").strip() or "enterprise_test_data"
        candidate = Path(cleaned)
        if candidate.is_absolute() or cleaned.startswith(("//", "\\")) or ".." in candidate.parts:
            raise ValueError("local_path must be a project-local folder or file path without traversal")
        return cleaned

    @field_validator("allowed_extensions")
    @classmethod
    def _validate_extensions(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for item in values or []:
            extension = str(item or "").strip().lower()
            if not extension:
                continue
            if not extension.startswith("."):
                extension = f".{extension}"
            if not re.fullmatch(r"\.[a-z0-9][a-z0-9._+-]{0,40}", extension):
                raise ValueError("Invalid file extension filter")
            if extension not in normalized:
                normalized.append(extension)
        return normalized


class AssetOverride(BaseModel):
    pattern: str = Field(description="Customer-specific asset name, folder, extension, or path fragment", min_length=1, max_length=240)
    level: str = Field(pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$")
    reason: str = Field(default="", max_length=500)

    @field_validator("pattern", "reason")
    @classmethod
    def _clean_asset_text(cls, value: str) -> str:
        return re.sub(r"[\x00-\x1f\x7f]", "", value or "").strip()


class ScanRequest(ConnectionRequest):
    save_report: bool = True
    async_scan: bool = False
    asset_overrides: list[AssetOverride] = Field(default_factory=list)


class EndpointScanRequest(BaseModel):
    host: str = Field(description="Endpoint hostname or IP", max_length=255)
    target_username: str = Field(default="", description="Windows profile username under C:\\Users", max_length=160)
    domain: str = Field(default="WORKGROUP", max_length=120)
    username: str = Field(default="", max_length=160)
    password: str = Field(default="", max_length=512)
    credential_ref: str = Field(default="", max_length=120)
    paths: list[str] = Field(default_factory=lambda: ["desktop", "documents", "downloads"], max_length=40)
    max_depth: int = Field(default=12, ge=1, le=12)
    read_content: bool = True
    read_acl: bool = False
    inspect_archives: bool = False
    async_scan: bool = False
    allowed_extensions: list[str] = Field(default_factory=list)
    extension_filter_enabled: bool = False
    include_hidden: bool = True
    include_system: bool = False
    hidden_filter_enabled: bool = False
    system_filter_enabled: bool = False
    save_report: bool = True
    asset_overrides: list[AssetOverride] = Field(default_factory=list)

    @field_validator("host", "domain", "username", "credential_ref")
    @classmethod
    def _clean_endpoint_text(cls, value: str) -> str:
        return re.sub(r"[\x00-\x1f\x7f]", "", value or "").strip()

    @field_validator("target_username")
    @classmethod
    def _validate_target_username(cls, value: str) -> str:
        cleaned = re.sub(r"[\x00-\x1f\x7f]", "", value or "").strip()
        if not cleaned:
            return ""
        if cleaned in {".", ".."} or ".." in cleaned or "/" in cleaned or "\\" in cleaned:
            raise ValueError("target_username must be a simple Windows profile name")
        if not re.fullmatch(r"[A-Za-z0-9._ -]{1,80}", cleaned):
            raise ValueError("target_username contains unsupported characters")
        return cleaned

    @field_validator("paths")
    @classmethod
    def _validate_endpoint_paths(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in values or []:
            value = re.sub(r"[\x00-\x1f\x7f]", "", str(item or "")).strip()
            if not value:
                continue
            if re.match(r"^[A-Za-z]:/", value):
                value = value.replace("/", "\\")
            is_drive_path = bool(re.fullmatch(r"[A-Za-z]:\\[^<>|?*]{0,240}", value))
            is_unc_path = bool(re.fullmatch(r"\\\\[^\\/:*?\"<>|\r\n]+\\[^\\/:*?\"<>|\r\n]+(?:\\[^:*?\"<>|\r\n]{0,240})?", value))
            if value.lower() in ENDPOINT_PATH_ALIASES or is_drive_path or is_unc_path:
                cleaned.append(value)
                continue
            raise ValueError("Endpoint paths must be known aliases or absolute Windows paths")
        return cleaned or ["desktop", "documents", "downloads"]


class LocalWinRMActivationRequest(BaseModel):
    domain: str = Field(default="WORKGROUP", max_length=120)
    username: str = Field(default="", max_length=160)
    password: str = Field(default="", max_length=512)

    @field_validator("domain", "username")
    @classmethod
    def _clean_activation_text(cls, value: str) -> str:
        return re.sub(r"[\x00-\x1f\x7f]", "", value or "").strip()


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=8, max_length=200)
    full_name: str = Field(default="", max_length=120)
    tenant_id: str = Field(default="default", max_length=80)
    registration_code: str = Field(default="", max_length=200)


class UserCreateRequest(RegisterRequest):
    role: str = Field(default="viewer", pattern="^(admin|analyst|viewer)$")


class TenantRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=80)
    display_name: str = Field(default="", max_length=120)


class UserRoleRequest(BaseModel):
    role: str = Field(pattern="^(admin|analyst|viewer)$")
    tenant_id: str = Field(default="", max_length=80)


class PasswordResetRequest(BaseModel):
    password: str = Field(min_length=8, max_length=200)


class UserActiveRequest(BaseModel):
    is_active: bool


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=200)


class ProfileUpdateRequest(BaseModel):
    full_name: str = Field(default="", max_length=120)


class CredentialRequest(BaseModel):
    username: str = Field(min_length=1, max_length=160)
    password: str = Field(min_length=1, max_length=512)
    domain: str = Field(default="WORKGROUP", max_length=120)


class ApiKeyRequest(BaseModel):
    label: str = Field(default="default", max_length=80)


class DemoDataRequest(BaseModel):
    output: str = Field(default="enterprise_test_data", max_length=120)
    files_per_share: int = Field(default=10, ge=1, le=40)


@app.get("/")
def login_root() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "login.html")


@app.get("/login")
def login_page() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "login.html")


@app.get("/register")
def register_page() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "register.html")


@app.get("/profile")
def profile_page() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "profile.html")


@app.get("/dashboard")
def dashboard() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "dspm-discovery"}


@app.get("/api/risk-rules")
def risk_rules(_: Principal = Depends(require_role("viewer"))) -> dict:
    return {"rules": get_risk_rules()}


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request) -> dict:
    login_key = _login_rate_key(payload.username, request)
    if _too_many_login_failures(login_key):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
    principal = authenticate_user(payload.username, payload.password)
    if principal is None:
        _record_login_failure(login_key)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    _clear_login_failures(login_key)
    audit(principal.tenant_id, principal.subject, "auth.login")
    return {
        "access_token": create_token(principal.subject, principal.role, principal.tenant_id),
        "token_type": "bearer",
        "role": principal.role,
        "tenant_id": principal.tenant_id,
    }


@app.post("/api/logout")
@app.post("/api/auth/logout")
def logout(
    authorization: str | None = Header(default=None, alias="Authorization"),
    principal: Principal = Depends(require_role("viewer")),
) -> dict:
    if authorization and authorization.lower().startswith("bearer "):
        revoke_token(authorization.split(" ", 1)[1].strip())
    audit(principal.tenant_id, principal.subject, "auth.logout")
    return {"status": "logged_out"}


@app.post("/api/auth/register")
def register(payload: RegisterRequest) -> dict:
    username = sanitize_username(payload.username)
    tenant_id = _safe_tenant(payload.tenant_id)
    if not tenant_exists(tenant_id):
        raise HTTPException(status_code=403, detail="Registration failed")
    if not _valid_registration_code(tenant_id, payload.registration_code):
        raise HTTPException(status_code=403, detail="Registration failed")
    if get_user(username):
        raise HTTPException(status_code=409, detail="Registration failed")
    user = create_user(username, hash_password(payload.password), "viewer", tenant_id, payload.full_name.strip())
    audit(tenant_id, username, "user.registered", {"role": "viewer"})
    return {"user": _public_user(user)}


@app.post("/api/auth/change-password")
def change_password(payload: PasswordChangeRequest, principal: Principal = Depends(require_role("viewer"))) -> dict:
    if principal.subject in PROTECTED_USERS:
        raise HTTPException(status_code=403, detail="Built-in admin account is protected")
    authenticated = authenticate_user(principal.subject, payload.current_password)
    if authenticated is None:
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    update_user_password(principal.subject, hash_password(payload.new_password))
    audit(principal.tenant_id, principal.subject, "user.password_changed")
    return {"status": "updated"}


@app.get("/api/profile")
def profile(principal: Principal = Depends(require_role("viewer"))) -> dict:
    user = get_user(principal.subject)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user": _public_user(user), "protected": principal.subject in PROTECTED_USERS}


@app.put("/api/profile")
def update_profile(payload: ProfileUpdateRequest, principal: Principal = Depends(require_role("viewer"))) -> dict:
    if principal.subject in PROTECTED_USERS:
        raise HTTPException(status_code=403, detail="Built-in admin account is protected")
    user = update_user_profile(principal.subject, payload.full_name.strip())
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    audit(principal.tenant_id, principal.subject, "user.profile_updated")
    return {"user": _public_user(user)}


@app.get("/api/users")
def users(principal: Principal = Depends(require_role("admin"))) -> dict:
    tenant_id = None if _is_platform_admin(principal) else principal.tenant_id
    return {"users": [_public_user(user) for user in list_users(tenant_id)]}


@app.post("/api/users")
def admin_create_user(payload: UserCreateRequest, principal: Principal = Depends(require_role("admin"))) -> dict:
    username = sanitize_username(payload.username)
    tenant_id = _safe_tenant(payload.tenant_id)
    if not _can_manage_tenant(principal, tenant_id):
        raise HTTPException(status_code=403, detail="Tenant access denied")
    if not tenant_exists(tenant_id):
        raise HTTPException(status_code=400, detail="Tenant does not exist")
    if get_user(username):
        raise HTTPException(status_code=409, detail="Username already exists")
    user = create_user(username, hash_password(payload.password), payload.role, tenant_id, payload.full_name.strip())
    audit(principal.tenant_id, principal.subject, "user.created", {"username": username, "role": payload.role, "tenant_id": tenant_id})
    return {"user": _public_user(user)}


@app.put("/api/users/{username}/role")
def admin_update_user_role(username: str, payload: UserRoleRequest, principal: Principal = Depends(require_role("admin"))) -> dict:
    target = sanitize_username(username)
    if target in PROTECTED_USERS:
        raise HTTPException(status_code=403, detail="Built-in admin account is protected")
    tenant_id = _safe_tenant(payload.tenant_id) if payload.tenant_id.strip() else None
    current_user = get_user(target)
    if current_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    effective_tenant = tenant_id or current_user["tenant_id"]
    if not _can_manage_tenant(principal, current_user["tenant_id"]) or not _can_manage_tenant(principal, effective_tenant):
        raise HTTPException(status_code=403, detail="Tenant access denied")
    if tenant_id and not tenant_exists(tenant_id):
        raise HTTPException(status_code=400, detail="Tenant does not exist")
    if target == principal.subject and payload.role != "admin":
        admins = [user for user in list_users(current_user["tenant_id"]) if user["role"] == "admin" and user["is_active"]]
        if len(admins) <= 1:
            raise HTTPException(status_code=400, detail="At least one active admin must remain")
    user = update_user_role(target, payload.role, tenant_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    audit(principal.tenant_id, principal.subject, "user.role_updated", {"username": target, "role": payload.role, "tenant_id": tenant_id})
    return {"user": _public_user(user)}


@app.post("/api/users/{username}/reset-password")
def admin_reset_password(username: str, payload: PasswordResetRequest, principal: Principal = Depends(require_role("admin"))) -> dict:
    target = sanitize_username(username)
    if target in PROTECTED_USERS:
        raise HTTPException(status_code=403, detail="Built-in admin account is protected")
    current_user = get_user(target)
    if current_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if not _can_manage_tenant(principal, current_user["tenant_id"]):
        raise HTTPException(status_code=403, detail="Tenant access denied")
    user = update_user_password(target, hash_password(payload.password))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    audit(principal.tenant_id, principal.subject, "user.password_reset", {"username": target})
    return {"status": "updated", "user": _public_user(user)}


@app.put("/api/users/{username}/active")
def admin_update_user_active(username: str, payload: UserActiveRequest, principal: Principal = Depends(require_role("admin"))) -> dict:
    target = sanitize_username(username)
    if target in PROTECTED_USERS:
        raise HTTPException(status_code=403, detail="Built-in admin account is protected")
    current_user = get_user(target)
    if current_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if not _can_manage_tenant(principal, current_user["tenant_id"]):
        raise HTTPException(status_code=403, detail="Tenant access denied")
    if target == principal.subject and not payload.is_active:
        raise HTTPException(status_code=400, detail="You cannot suspend your own signed-in account")
    if current_user["role"] == "admin" and current_user["is_active"] and not payload.is_active:
        admins = [item for item in list_users(current_user["tenant_id"]) if item["role"] == "admin" and item["is_active"]]
        if len(admins) <= 1:
            raise HTTPException(status_code=400, detail="At least one active admin must remain")
    user = update_user_active(target, payload.is_active)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    audit(principal.tenant_id, principal.subject, "user.status_updated", {"username": target, "is_active": payload.is_active})
    return {"status": "updated", "user": _public_user(user)}


@app.post("/api/users/{username}/delete")
@app.delete("/api/users/{username}")
def admin_delete_user(username: str, principal: Principal = Depends(require_role("admin"))) -> dict:
    target = sanitize_username(username)
    if target in PROTECTED_USERS:
        raise HTTPException(status_code=403, detail="Built-in admin account is protected")
    user = get_user(target)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if not _can_manage_tenant(principal, user["tenant_id"]):
        raise HTTPException(status_code=403, detail="Tenant access denied")
    if target == principal.subject:
        raise HTTPException(status_code=400, detail="You cannot delete your own signed-in account")
    if user["role"] == "admin" and user["is_active"]:
        admins = [item for item in list_users(user["tenant_id"]) if item["role"] == "admin" and item["is_active"]]
        if len(admins) <= 1:
            raise HTTPException(status_code=400, detail="At least one active admin must remain")
    deleted = delete_user(target)
    if deleted is None:
        raise HTTPException(status_code=404, detail="User not found")
    audit(principal.tenant_id, principal.subject, "user.deleted", {"username": target, "tenant_id": deleted["tenant_id"]})
    return {"deleted": True, "user": _public_user(deleted)}


@app.get("/api/users/activity")
def user_activity(principal: Principal = Depends(require_role("admin"))) -> dict:
    events = [event for event in read_audit_log(principal.tenant_id, 500) if str(event.get("action", "")).startswith(("auth.", "user."))]
    return {"events": events}


@app.post("/api/tenants")
def admin_create_tenant(payload: TenantRequest, principal: Principal = Depends(require_role("admin"))) -> dict:
    _require_platform_admin(principal)
    tenant_id = _safe_tenant(payload.tenant_id)
    if tenant_exists(tenant_id):
        raise HTTPException(status_code=409, detail="Tenant already exists")
    tenant = create_tenant(tenant_id, payload.display_name.strip())
    audit(principal.tenant_id, principal.subject, "tenant.created", {"tenant_id": tenant_id})
    return {"tenant": _public_tenant(tenant)}


@app.post("/api/tenants/{tenant_id}/regenerate-registration-code")
@app.post("/api/tenants/{tenant_id}/registration-code")
def admin_rotate_tenant_registration_code(tenant_id: str, principal: Principal = Depends(require_role("admin"))) -> dict:
    target = _safe_tenant(tenant_id)
    if not _can_manage_tenant(principal, target):
        raise HTTPException(status_code=403, detail="Tenant access denied")
    if not tenant_exists(target):
        raise HTTPException(status_code=404, detail="Tenant not found")
    code = rotate_registration_code(target)
    if not code:
        raise HTTPException(status_code=404, detail="Tenant not found")
    audit(principal.tenant_id, principal.subject, "tenant.registration_code_rotated", {"tenant_id": target})
    tenant = get_tenant(target)
    return {"tenant": _public_tenant(tenant), "registration_code": code}


@app.delete("/api/tenants/{tenant_id}")
def admin_delete_tenant(tenant_id: str, principal: Principal = Depends(require_role("admin"))) -> dict:
    _require_platform_admin(principal)
    target = _safe_tenant(tenant_id)
    if target == "default":
        raise HTTPException(status_code=400, detail="Default tenant cannot be removed")
    if not tenant_exists(target):
        raise HTTPException(status_code=404, detail="Tenant not found")
    deleted_usage = delete_tenant_with_data(target)
    audit_tenant = principal.tenant_id if principal.tenant_id != target else "default"
    audit(audit_tenant, principal.subject, "tenant.deleted", {"tenant_id": target, "deleted": deleted_usage})
    return {"deleted": True, "tenant_id": target, "deleted_data": deleted_usage}


@app.post("/api/api-keys")
def create_api_key(payload: ApiKeyRequest, principal: Principal = Depends(require_role("admin"))) -> dict:
    raw, key_hash = generate_api_key()
    audit(principal.tenant_id, principal.subject, "api_key.created", {"label": payload.label, "hash": key_hash[:12]})
    return {
        "label": payload.label,
        "api_key": raw,
        "hash": key_hash,
        "message": "Persist this hash in DSPM_API_KEYS as tenant_id:hash. The raw key is shown once.",
    }


@app.post("/api/credentials")
def store_credentials(payload: CredentialRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    secret_ref = vault.store(
        principal.tenant_id,
        payload.username.strip(),
        payload.password,
        payload.domain.strip() or "WORKGROUP",
    )
    audit(principal.tenant_id, principal.subject, "credential.stored", {"secret_ref": secret_ref})
    return {"credential_ref": secret_ref, "domain": payload.domain.strip() or "WORKGROUP"}


@app.post("/api/test-connection")
def test_connection(payload: ConnectionRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    if not _is_local_endpoint_host(payload.server):
        _validate_scan_target(payload.server)
    engine = DSPMDiscoveryEngine(_to_config(payload, principal.tenant_id))
    audit(principal.tenant_id, principal.subject, "connection.test", {"server": _safe_target_label(payload.server)})
    return engine.test_connection()


@app.post("/api/endpoint/test-connection")
def endpoint_test_connection(payload: EndpointScanRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    if _is_local_endpoint_host(payload.host):
        if platform.system().lower() != "windows":
            return {
                "connected": False,
                "host": payload.host,
                "user": os.getenv("USER") or os.getenv("USERNAME") or "",
                "computer": socket.gethostname(),
                "message": "Local endpoint scan is available only when the DSPM backend runs on Windows.",
            }
        return {
            "connected": True,
            "host": payload.host,
            "user": os.getenv("USERNAME") or "",
            "computer": socket.gethostname(),
            "message": "Local workstation scan is available without WinRM.",
        }
    _validate_scan_target(payload.host)
    scanner = WinRMEndpointScanner(_to_endpoint_config(payload, principal.tenant_id))
    audit(principal.tenant_id, principal.subject, "endpoint.connection.test", {"host": _safe_target_label(payload.host), "target_username": payload.target_username})
    return scanner.test_connection()


@app.post("/api/endpoint/activate-local-winrm")
def endpoint_activate_local_winrm(payload: LocalWinRMActivationRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    try:
        result = activate_local_winrm(payload.username, payload.password, payload.domain)
    except Exception as exc:
        raise _safe_operation_error("Endpoint operation failed", exc) from exc
    audit(
        principal.tenant_id,
        principal.subject,
        "endpoint.winrm.activate_local",
        {"host": result.get("host"), "activated": result.get("activated")},
    )
    return result


@app.post("/api/endpoint/activate-winrm")
def endpoint_activate_winrm(payload: EndpointScanRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    if _is_local_endpoint_host(payload.host):
        return endpoint_activate_local_winrm(
            LocalWinRMActivationRequest(domain=payload.domain, username=payload.username, password=payload.password),
            principal,
        )
    _validate_scan_target(payload.host)
    scanner = WinRMEndpointScanner(_to_endpoint_config(payload, principal.tenant_id))
    try:
        result = scanner.activate_winrm()
    except Exception as exc:
        raise _safe_operation_error("Endpoint operation failed", exc) from exc
    audit(
        principal.tenant_id,
        principal.subject,
        "endpoint.winrm.activate",
        {"host": payload.host, "activated": result.get("activated"), "connected": result.get("connected")},
    )
    return result


@app.post("/api/endpoint/repair-winrm")
def endpoint_repair_winrm(payload: EndpointScanRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    if _is_local_endpoint_host(payload.host):
        return endpoint_activate_local_winrm(
            LocalWinRMActivationRequest(domain=payload.domain, username=payload.username, password=payload.password),
            principal,
        )
    _validate_scan_target(payload.host)
    scanner = WinRMEndpointScanner(_to_endpoint_config(payload, principal.tenant_id))
    try:
        result = scanner.activate_winrm()
    except Exception as exc:
        raise _safe_operation_error("Endpoint operation failed", exc) from exc
    audit(
        principal.tenant_id,
        principal.subject,
        "endpoint.winrm.repair",
        {
            "host": payload.host,
            "activated": result.get("activated"),
            "connected": result.get("connected"),
        },
    )
    return result


@app.post("/api/endpoint/scan")
def endpoint_scan(payload: EndpointScanRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    try:
        if not _is_local_endpoint_host(payload.host):
            _validate_scan_target(payload.host)
        config = _to_endpoint_config(payload, principal.tenant_id)
        if payload.async_scan:
            job = create_job(principal.tenant_id, lambda job: _run_endpoint_scan_payload(config, payload, principal, job))
            audit(principal.tenant_id, principal.subject, "endpoint.scan.queued", {"job_id": job.id, "host": payload.host})
            return job.to_dict()

        data = _run_endpoint_scan_payload(config, payload, principal)
        audit(principal.tenant_id, principal.subject, "endpoint.scan.completed", {"scan_id": data.get("scan_id"), "host": payload.host})
        return data
    except HTTPException:
        raise
    except Exception as exc:
        raise _safe_operation_error("Endpoint operation failed", exc) from exc


@app.post("/api/demo-data/generate")
def generate_demo_data(payload: DemoDataRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    try:
        output = _safe_demo_output(payload.output)
        generate_enterprise_test_data(output, payload.files_per_share)
    except HTTPException:
        raise
    except Exception as exc:
        raise _safe_operation_error("Demo data generation failed", exc) from exc
    manifest = _read_demo_manifest(output)
    audit(
        principal.tenant_id,
        principal.subject,
        "demo_data.generated",
        {"output": str(output.relative_to(BASE_DIR)), "files_per_share": payload.files_per_share, "file_count": manifest.get("file_count", 0)},
    )
    return {
        "status": "generated",
        "local_path": str(output.relative_to(BASE_DIR)),
        "file_count": manifest.get("file_count", 0),
        "generated": manifest.get("generated", ""),
    }


@app.post("/api/scan")
def scan(payload: ScanRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    try:
        if not _is_local_endpoint_host(payload.server):
            _validate_scan_target(payload.server)
        if payload.async_scan:
            job = create_scan_job(principal.tenant_id, _to_config(payload, principal.tenant_id), lambda data: _persist_scan(data, payload, principal))
            audit(principal.tenant_id, principal.subject, "scan.queued", {"job_id": job.id, "server": _safe_target_label(payload.server)})
            return job.to_dict()

        engine = DSPMDiscoveryEngine(_to_config(payload, principal.tenant_id))
        report = engine.run()
        data = report.to_dict()
        _persist_scan(data, payload, principal)
        audit(principal.tenant_id, principal.subject, "scan.completed", {"scan_id": data.get("scan_id")})
        return data
    except HTTPException:
        raise
    except Exception as exc:
        raise _safe_operation_error("Scan failed", exc) from exc


@app.get("/api/scans/{job_id}")
def scan_job(job_id: str, principal: Principal = Depends(require_role("viewer"))) -> dict:
    cleanup_jobs()
    job = get_job(job_id)
    if job is None or job.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job.to_dict()


@app.post("/api/scans/{job_id}/cancel")
def stop_scan(job_id: str, principal: Principal = Depends(require_role("analyst"))) -> dict:
    job = get_job(job_id)
    if job is None or job.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="Scan job not found")
    stopped = cancel_job(job_id)
    audit(principal.tenant_id, principal.subject, "scan.cancel", {"job_id": job_id, "stopped": stopped})
    return {"cancelled": stopped}


@app.get("/api/history")
def scan_history(
    principal: Principal = Depends(require_role("viewer")),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict:
    return {"history": read_scan_history(principal.tenant_id, limit=limit)}


@app.get("/api/history/latest/report")
def latest_scan_report(principal: Principal = Depends(require_role("viewer"))) -> dict:
    report = read_scan_report(principal.tenant_id)
    if report is None:
        raise HTTPException(status_code=404, detail="No saved scan report found")
    return {"report": report}


@app.get("/api/history/{scan_id}/report")
def saved_scan_report(scan_id: str, principal: Principal = Depends(require_role("viewer"))) -> dict:
    report = read_scan_report(principal.tenant_id, scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Saved scan report not found")
    return {"report": report}


def _file_hash_value(file_record: dict) -> str:
    return str(file_record.get("sha256") or file_record.get("file_hash") or "").strip().lower()


def _file_compare_key(file_record: dict) -> str:
    path = str(file_record.get("path") or file_record.get("full_path") or file_record.get("name") or "")
    source = str(file_record.get("source") or "")
    share = str(file_record.get("share") or file_record.get("host") or file_record.get("server") or "")
    return f"{source}|{share}|{path}".lower()


def _hash_index(report: dict | None) -> dict[str, dict]:
    files = report.get("files", []) if isinstance(report, dict) else []
    indexed: dict[str, dict] = {}
    for file_record in files:
        if not isinstance(file_record, dict):
            continue
        key = _file_compare_key(file_record)
        sha256 = _file_hash_value(file_record)
        if key and sha256:
            indexed[key] = file_record
    return indexed


@app.get("/api/history/hash-changes")
def scan_hash_changes(principal: Principal = Depends(require_role("viewer"))) -> dict:
    history = read_scan_history(principal.tenant_id, limit=2)
    if len(history) < 2:
        return {
            "algorithm": "SHA-256",
            "latest_scan_id": history[-1].get("scan_id") if history else "",
            "previous_scan_id": "",
            "changed": [],
            "changed_count": 0,
            "added_count": 0,
            "removed_count": 0,
        }

    previous_item, latest_item = history[-2], history[-1]
    previous_report = read_scan_report(principal.tenant_id, previous_item.get("scan_id"))
    latest_report = read_scan_report(principal.tenant_id, latest_item.get("scan_id"))
    previous_files = _hash_index(previous_report)
    latest_files = _hash_index(latest_report)

    changed = []
    for key, latest_file in latest_files.items():
        previous_file = previous_files.get(key)
        if not previous_file:
            continue
        previous_hash = _file_hash_value(previous_file)
        latest_hash = _file_hash_value(latest_file)
        if previous_hash and latest_hash and previous_hash != latest_hash:
            changed.append(
                {
                    "key": key,
                    "name": latest_file.get("name") or latest_file.get("path") or "Unknown file",
                    "path": latest_file.get("path") or "",
                    "source": latest_file.get("source") or latest_file.get("share") or "",
                    "previous_hash": previous_hash,
                    "current_hash": latest_hash,
                }
            )

    changed.sort(key=lambda item: str(item.get("path") or item.get("name") or "").lower())
    return {
        "algorithm": "SHA-256",
        "latest_scan_id": latest_item.get("scan_id") or "",
        "previous_scan_id": previous_item.get("scan_id") or "",
        "changed": changed[:100],
        "changed_count": len(changed),
        "added_count": len(set(latest_files) - set(previous_files)),
        "removed_count": len(set(previous_files) - set(latest_files)),
    }


@app.get("/api/tenants")
def tenant_portfolio(principal: Principal = Depends(require_role("admin"))) -> dict:
    tenants = list_tenants() if _is_platform_admin(principal) else [item for item in list_tenants() if item["tenant_id"] == principal.tenant_id]
    return {"tenants": [_public_tenant(item) for item in tenants]}


@app.get("/api/audit")
def audit_log(
    principal: Principal = Depends(require_role("admin")),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict:
    return {"events": read_audit_log(principal.tenant_id, limit)}


@app.get("/api/executive-dashboard")
def executive_dashboard(principal: Principal = Depends(require_role("viewer"))) -> dict:
    history = read_scan_history(principal.tenant_id, limit=200)
    latest = history[-1] if history else {"summary": {}}
    summary = latest.get("summary", {})
    score = _posture_score(summary)
    return {
        "tenant_id": principal.tenant_id,
        "risk_posture_score": score,
        "latest": latest,
        "trend": history[-14:],
        "retention": data_retention_summary(principal.tenant_id),
    }


def _login_rate_key(username: str, request: Request) -> str:
    client = request.client.host if request.client else "unknown"
    safe_user = sanitize_username(username) or "unknown"
    return f"{client}:{safe_user}"


def _too_many_login_failures(key: str) -> bool:
    return count_login_failures(key, LOGIN_WINDOW_SECONDS) >= LOGIN_MAX_ATTEMPTS


def _record_login_failure(key: str) -> None:
    record_login_failure(key, LOGIN_WINDOW_SECONDS)


def _clear_login_failures(key: str) -> None:
    clear_login_failures(key)



def _is_platform_admin(principal: Principal) -> bool:
    return principal.role == "admin" and principal.subject == "admin" and principal.tenant_id == "default"


def _can_manage_tenant(principal: Principal, tenant_id: str) -> bool:
    return _is_platform_admin(principal) or principal.tenant_id == tenant_id


def _require_platform_admin(principal: Principal) -> None:
    if not _is_platform_admin(principal):
        raise HTTPException(status_code=403, detail="Platform admin access required")


def _mask_secret(value: str) -> str:
    value = str(value or "")
    if not value:
        return ""
    return f"{value[:8]}â€¦{value[-4:]}" if len(value) > 14 else "â€¢â€¢â€¢â€¢"


def _safe_operation_error(message: str, exc: Exception) -> HTTPException:
    raw = str(exc or "")
    lowered = raw.lower()
    code = "operation_failed"
    hint = "Check the target, credentials, and scan scope, then retry."
    if "pywinrm" in lowered:
        code = "missing_dependency"
        hint = "Install requirements.txt on the DSPM backend host before running WinRM endpoint scans."
    elif "access denied" in lowered or "unauthorized" in lowered:
        code = "access_denied"
        hint = "Use a credential that is local admin on the target and can read the selected paths."
    elif "winrm" in lowered or "connection" in lowered or "timed out" in lowered:
        code = "endpoint_unreachable"
        hint = "Verify WinRM service, firewall, DNS/IP reachability, and the credential."
    elif "cancel" in lowered:
        code = "scan_cancelled"
        hint = "The scan was cancelled by the user."
    return HTTPException(status_code=400, detail={"message": message, "code": code, "hint": hint})


def _safe_target_label(target: str) -> str:
    target = (target or "").strip()
    if not target:
        return "local"
    return target[:80]


def _is_local_endpoint_host(host: str) -> bool:
    target = (host or "").strip().strip("[]").lower()
    if target in {"localhost", "127.0.0.1", "::1", "."}:
        return True
    local_names = {
        socket.gethostname().lower(),
        socket.getfqdn().lower(),
        (os.getenv("COMPUTERNAME") or "").strip().lower(),
    }
    return bool(target and target in {name for name in local_names if name})


def _host_addresses(host: str) -> set[ipaddress._BaseAddress]:
    target = (host or "").strip().strip("[]")
    if not target:
        return set()
    try:
        return {ipaddress.ip_address(target)}
    except ValueError:
        pass
    addresses: set[ipaddress._BaseAddress] = set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(target, None):
            if family in {socket.AF_INET, socket.AF_INET6}:
                addresses.add(ipaddress.ip_address(sockaddr[0]))
    except socket.gaierror:
        return set()
    return addresses


def _validate_scan_target(target: str) -> None:
    target = (target or "").strip()
    if not target:
        return
    addresses = _host_addresses(target)
    if not addresses:
        return
    allow_private = os.getenv("DSPM_ALLOW_PRIVATE_TARGETS", "0" if IS_PRODUCTION else "1") == "1"
    for address in addresses:
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved or address.is_unspecified:
            raise HTTPException(status_code=400, detail="Target address is not allowed")
        if str(address) == "169.254.169.254":
            raise HTTPException(status_code=400, detail="Target address is not allowed")
        if address.is_private and not allow_private:
            raise HTTPException(status_code=400, detail="Private network targets are disabled by configuration")

def _safe_tenant(tenant_id: str) -> str:
    safe = "".join(ch for ch in tenant_id.strip() if ch.isalnum() or ch in {"-", "_"}) or "default"
    return safe


def _valid_registration_code(tenant_id: str, registration_code: str) -> bool:
    tenant = get_tenant(tenant_id)
    expected = tenant.get("registration_code", "") if tenant else ""
    if not expected:
        return False
    return hmac.compare_digest(registration_code.strip(), expected)


def _public_user(user: dict) -> dict:
    return {
        "username": user["username"],
        "role": user["role"],
        "tenant_id": user["tenant_id"],
        "full_name": user.get("full_name", ""),
        "is_active": user.get("is_active", True),
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at"),
        "last_login_at": user.get("last_login_at"),
    }


def _public_tenant(tenant: dict) -> dict:
    return {
        "tenant_id": tenant["tenant_id"],
        "display_name": tenant.get("display_name") or tenant["tenant_id"],
        "registration_code": "",
        "registration_code_preview": _mask_secret(tenant.get("registration_code", "")),
        "created_at": tenant.get("created_at"),
        "updated_at": tenant.get("updated_at"),
        "scan_count": tenant.get("scan_count", 0),
        "latest": tenant.get("latest", {"summary": {}}),
        "retention": tenant.get("retention", {}),
    }


def _safe_demo_output(output: str) -> Path:
    name = output.strip() or "enterprise_test_data"
    target = Path(name)
    if target.is_absolute() or ".." in target.parts:
        raise HTTPException(status_code=400, detail="Demo data output must be a project-local folder")
    resolved = (BASE_DIR / target).resolve()
    if not resolved.is_relative_to(BASE_DIR.resolve()):
        raise HTTPException(status_code=400, detail="Demo data output must stay inside the project")
    return resolved


def _read_demo_manifest(output: Path) -> dict:
    manifest = output / "_manifest.json"
    if not manifest.exists():
        return {}
    try:
        import json

        return json.loads(manifest.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _posture_score(summary: dict) -> int:
    total = int(summary.get("total_files") or 0)
    if total <= 0:
        return 100

    exposure = (
        int(summary.get("critical") or 0) * 95
        + int(summary.get("high") or 0) * 80
        + int(summary.get("medium") or 0) * 55
        + int(summary.get("low") or 0) * 20
    ) / total
    return max(0, min(100, round(100 - exposure)))


def _scan_extension_settings(extensions: list[str], enabled: bool) -> tuple[list[str], bool]:
    normalized = sorted(normalize_extension_filter(extensions))
    if not enabled or not normalized:
        return [], False
    return normalized, True


@app.post("/api/dlp-policy")
def export_dlp_policy(payload: ScanRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    return {
        "format": "generic-json",
        "tenant_id": principal.tenant_id,
        "rules": [
            {
                "name": item.pattern,
                "severity": item.level,
                "action": "block-and-alert" if item.level in {"CRITICAL", "HIGH"} else "monitor",
                "reason": item.reason,
            }
            for item in payload.asset_overrides
        ],
    }


def _persist_scan(data: dict, payload: ScanRequest | EndpointScanRequest, principal: Principal) -> None:
    scan_id = save_scan_history(principal.tenant_id, data)
    data["scan_id"] = scan_id
    alerts = evaluate_alerts(principal.tenant_id, data)
    data["alerts"] = alerts
    if payload.save_report:
        report_id = str(data.get("scan_id") or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f"))
        generate_report(data, REPORT_DIR / f"{principal.tenant_id}_{report_id}.json")


def _run_endpoint_scan_payload(
    config: WinRMEndpointConfig,
    payload: EndpointScanRequest,
    principal: Principal,
    job=None,
) -> dict:
    if _is_local_endpoint_host(config.host):
        return _run_local_endpoint_scan_payload(config, payload, principal, job)

    if job:
        job.progress = 8
        job.message = "Connecting to endpoint"
    scanner = WinRMEndpointScanner(config)
    records = scanner.scan()
    if job:
        if job.cancel_requested:
            raise RuntimeError("Scan cancelled")
        job.progress = 70
        job.message = "Analyzing endpoint files"
    report = DSPMDiscoveryEngine(
        ScanConfig(
            server="",
            use_sample_when_empty=False,
            asset_overrides=[
                {
                    "pattern": item.pattern.strip(),
                    "level": item.level.strip().upper(),
                    "reason": item.reason.strip(),
                }
                for item in payload.asset_overrides
                if item.pattern.strip()
            ],
        )
    )
    analyzed = [report._analyze_record(record) for record in records]
    extension_counts: dict[str, int] = {}
    for record in records:
        extension = str(record.get("extension") or "no extension").lower()
        extension_counts[extension] = extension_counts.get(extension, 0) + 1
    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "endpoint-winrm",
        "summary": report._build_summary(analyzed).to_dict(),
        "files": analyzed,
        "endpoint": {
            "host": config.host,
            "target_username": config.target_username,
            "paths": config.paths,
            "max_depth": config.max_depth,
            "allowed_extensions": config.allowed_extensions or [],
            "extension_filter_enabled": config.extension_filter_enabled,
            "include_hidden": config.include_hidden,
            "include_system": config.include_system,
            "hidden_filter_enabled": config.hidden_filter_enabled,
            "system_filter_enabled": config.system_filter_enabled,
            "read_content": config.read_content,
            "read_acl": config.read_acl,
            "inspect_archives": config.inspect_archives,
            "raw_record_count": len(records),
            "extension_counts": extension_counts,
            "scan_diagnostics": scanner.last_scan_diagnostics,
        },
    }
    if job:
        job.progress = 92
        job.message = "Saving endpoint report"
    _persist_scan(data, payload, principal)
    return data


def _run_local_endpoint_scan_payload(
    config: WinRMEndpointConfig,
    payload: EndpointScanRequest,
    principal: Principal,
    job=None,
) -> dict:
    if platform.system().lower() != "windows":
        raise RuntimeError("Local endpoint scan is available only when the DSPM backend runs on Windows.")
    if job:
        job.progress = 10
        job.message = "Resolving local workstation paths"

    scan_paths, missing_paths = _local_endpoint_paths(config)
    records: list[dict] = []
    scan_errors: list[str] = []
    local_scan_diagnostics: dict = {
        "mode": "local_endpoint",
        "requested_roots": list(config.paths),
        "resolved_roots": [],
        "missing_roots": list(missing_paths),
        "visited_files": 0,
        "matched_files": 0,
        "skipped_dirs": 0,
        "unreadable_dirs": [],
        "extension_histogram": {},
    }

    for index, path in enumerate(scan_paths, start=1):
        if job and job.cancel_requested:
            raise RuntimeError("Scan cancelled")
        if job:
            job.progress = min(65, 10 + int((index - 1) / max(len(scan_paths), 1) * 55))
            job.message = f"Scanning {path}"
        try:
            path_records = scan_directory(
                path,
                allowed_extensions=config.allowed_extensions,
                extension_filter_enabled=config.extension_filter_enabled,
                include_hidden=config.include_hidden,
                include_system=config.include_system,
                hidden_filter_enabled=config.hidden_filter_enabled,
                system_filter_enabled=config.system_filter_enabled,
                max_depth=config.max_depth,
                inspect_archives=config.inspect_archives,
                diagnostics=local_scan_diagnostics,
            )
        except (FileNotFoundError, OSError) as exc:
            scan_errors.append(f"{path}: {exc}")
            continue

        for record in path_records:
            if not config.read_content:
                record["content"] = ""
                record["content_status"] = record.get("content_status") or "metadata_only"
                record["content_scannable"] = False
            record["source"] = "endpoint-local"
            record["share"] = config.host or socket.gethostname()
            owner = record.get("owner", "")
            record["acl"] = {
                "owner": owner,
                "principals": [],
                "permissions": [],
            }
            records.append(record)

    if job:
        if job.cancel_requested:
            raise RuntimeError("Scan cancelled")
        job.progress = 72
        job.message = "Analyzing local workstation files"

    report = DSPMDiscoveryEngine(
        ScanConfig(
            server="",
            use_sample_when_empty=False,
            asset_overrides=[
                {
                    "pattern": item.pattern.strip(),
                    "level": item.level.strip().upper(),
                    "reason": item.reason.strip(),
                }
                for item in payload.asset_overrides
                if item.pattern.strip()
            ],
        )
    )
    analyzed = [report._analyze_record(record) for record in records]
    extension_counts: dict[str, int] = {}
    for record in records:
        extension = str(record.get("extension") or "no extension").lower()
        extension_counts[extension] = extension_counts.get(extension, 0) + 1

    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "endpoint-local",
        "summary": report._build_summary(analyzed).to_dict(),
        "files": analyzed,
        "endpoint": {
            "host": config.host or socket.gethostname(),
            "target_username": config.target_username,
            "paths": config.paths,
            "resolved_paths": [str(path) for path in scan_paths],
            "max_depth": config.max_depth,
            "allowed_extensions": config.allowed_extensions or [],
            "extension_filter_enabled": config.extension_filter_enabled,
            "include_hidden": config.include_hidden,
            "include_system": config.include_system,
            "hidden_filter_enabled": config.hidden_filter_enabled,
            "system_filter_enabled": config.system_filter_enabled,
            "read_content": config.read_content,
            "read_acl": False,
            "inspect_archives": config.inspect_archives,
            "raw_record_count": len(records),
            "extension_counts": extension_counts,
            "scan_diagnostics": {
                **local_scan_diagnostics,
                "missing_paths": missing_paths,
                "scan_errors": scan_errors[:20],
            },
        },
    }
    if job:
        job.progress = 92
        job.message = "Saving local endpoint report"
    _persist_scan(data, payload, principal)
    return data


def _local_user_profile_roots(users_root: Path) -> list[Path]:
    skip_names = {"all users", "default", "default user", "public", "defaultapppool"}
    try:
        candidates = [item for item in users_root.iterdir() if item.is_dir()]
    except OSError:
        return []
    return [
        item
        for item in candidates
        if item.name.lower() not in skip_names and not item.name.lower().startswith("default.")
    ]


def _local_profile_standard_paths(profile_root: Path) -> list[Path]:
    candidates = [profile_root / folder for folder in ("Desktop", "Documents", "Downloads")]
    if profile_root.exists():
        try:
            candidates.extend(
                onedrive / folder
                for onedrive in profile_root.iterdir()
                if onedrive.is_dir() and (onedrive.name == "OneDrive" or onedrive.name.startswith("OneDrive - "))
                for folder in ("Desktop", "Documents", "Downloads")
            )
        except OSError:
            pass
    existing = [path for path in candidates if path.exists()]
    return existing or [profile_root]


def _local_matching_profile_roots(users_root: Path, profile: str) -> list[Path]:
    profile = profile.strip()
    if not profile:
        return []
    exact = users_root / profile
    if exact.exists():
        return [exact]
    profile_lower = profile.lower()
    try:
        candidates = [item for item in users_root.iterdir() if item.is_dir()]
    except OSError:
        return []
    return [
        item
        for item in candidates
        if (
            item.name.lower() == profile_lower
            or item.name.lower().startswith(f"{profile_lower}.")
            or item.name.lower().startswith(f"{profile_lower}_")
            or item.name.lower().endswith(f".{profile_lower}")
        )
    ]


def _local_profile_folder_paths(profile_root: Path, folder_name: str) -> list[Path]:
    candidates = [profile_root / folder_name]
    if profile_root.exists():
        try:
            candidates.extend(
                onedrive / folder_name
                for onedrive in profile_root.iterdir()
                if onedrive.is_dir() and (onedrive.name == "OneDrive" or onedrive.name.startswith("OneDrive - "))
            )
        except OSError:
            pass
    return [path for path in candidates if path.exists()]


def _local_onedrive_roots(profile_root: Path) -> list[Path]:
    if not profile_root.exists():
        return []
    try:
        return [
            item
            for item in profile_root.iterdir()
            if item.is_dir() and (item.name == "OneDrive" or item.name.startswith("OneDrive - "))
        ]
    except OSError:
        return []


def _resolve_local_endpoint_token(token: str, users_root: Path) -> list[Path]:
    if token == "__DSPM_ALL_PROFILES__":
        return _local_user_profile_roots(users_root)
    if token == "__DSPM_FIXED_DRIVES__":
        return [Path(f"{letter}:/") for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if Path(f"{letter}:/").exists()]
    if token == "__DSPM_ALL_ONEDRIVE__":
        roots: list[Path] = []
        for profile_root in _local_user_profile_roots(users_root):
            roots.extend(_local_onedrive_roots(profile_root))
        return roots
    if token == "__DSPM_PROFILE_STANDARD__":
        roots: list[Path] = []
        for profile_root in _local_user_profile_roots(users_root):
            roots.extend(_local_profile_standard_paths(profile_root))
        return roots
    if token.startswith("__DSPM_PROFILE_FOLDER__:"):
        folder_name = token.removeprefix("__DSPM_PROFILE_FOLDER__:").strip()
        roots: list[Path] = []
        for profile_root in _local_user_profile_roots(users_root):
            roots.extend(_local_profile_folder_paths(profile_root, folder_name))
        return roots
    if token.startswith("__DSPM_PROFILE_STANDARD_FOR__:"):
        profile = token.removeprefix("__DSPM_PROFILE_STANDARD_FOR__:").strip()
        roots: list[Path] = []
        for profile_root in _local_matching_profile_roots(users_root, profile):
            roots.extend(_local_profile_standard_paths(profile_root))
        return roots
    if token.startswith("__DSPM_PROFILE_ROOT_FOR__:"):
        profile = token.removeprefix("__DSPM_PROFILE_ROOT_FOR__:").strip()
        return [root for root in _local_matching_profile_roots(users_root, profile) if root.exists()]
    if token.startswith("__DSPM_PROFILE_FOLDER_FOR__:"):
        payload = token.removeprefix("__DSPM_PROFILE_FOLDER_FOR__:")
        profile, _, folder_name = payload.partition(":")
        roots: list[Path] = []
        for profile_root in _local_matching_profile_roots(users_root, profile.strip()):
            roots.extend(_local_profile_folder_paths(profile_root, folder_name.strip()))
        return roots
    if token.startswith("__DSPM_PROFILE_RELATIVE_FOR__:"):
        payload = token.removeprefix("__DSPM_PROFILE_RELATIVE_FOR__:")
        profile, _, relative_path = payload.partition(":")
        return [
            profile_root / relative_path.strip().strip("\\/")
            for profile_root in _local_matching_profile_roots(users_root, profile.strip())
        ]
    if token.startswith("__DSPM_ONEDRIVE_FOR__:"):
        profile = token.removeprefix("__DSPM_ONEDRIVE_FOR__:").strip()
        roots: list[Path] = []
        for profile_root in _local_matching_profile_roots(users_root, profile):
            roots.extend(_local_onedrive_roots(profile_root))
        return roots
    return [Path(token)]


def _local_endpoint_paths(config: WinRMEndpointConfig) -> tuple[list[Path], list[str]]:
    profile = config.target_username.strip() or (os.getenv("USERNAME") or "").strip()
    users_root = Path("C:/Users")
    resolved: list[Path] = []
    requested_tokens = normalize_endpoint_target_paths(config.paths, profile)

    for token in requested_tokens:
        resolved.extend(candidate.expanduser().resolve() for candidate in _resolve_local_endpoint_token(token, users_root))

    unique: list[Path] = []
    missing: list[str] = []
    seen: set[str] = set()
    for path in resolved:
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        if path.exists():
            unique.append(path)
        else:
            missing.append(str(path))
    return unique, missing


def _to_config(payload: ConnectionRequest, tenant_id: str) -> ScanConfig:
    username = payload.username.strip()
    password = payload.password
    domain = payload.domain.strip() or "WORKGROUP"
    server = "" if _is_local_endpoint_host(payload.server) else payload.server.strip()
    allowed_extensions, extension_filter_enabled = _scan_extension_settings(
        payload.allowed_extensions,
        payload.extension_filter_enabled,
    )
    if payload.credential_ref:
        secret = vault.resolve(tenant_id, payload.credential_ref)
        username = secret.get("username", "")
        password = secret.get("password", "")
        domain = secret.get("domain", domain)

    return ScanConfig(
        server=server,
        username=username,
        password=password,
        domain=domain,
        local_path=payload.local_path.strip() or "enterprise_test_data",
        max_depth=payload.max_depth,
        allowed_extensions=allowed_extensions,
        extension_filter_enabled=extension_filter_enabled,
        include_hidden=payload.include_hidden,
        include_system=payload.include_system,
        hidden_filter_enabled=payload.hidden_filter_enabled,
        system_filter_enabled=payload.system_filter_enabled,
        include_admin_shares=payload.include_admin_shares,
        inspect_archives=payload.inspect_archives,
        asset_overrides=[
            {
                "pattern": item.pattern.strip(),
                "level": item.level.strip().upper(),
                "reason": item.reason.strip(),
            }
            for item in getattr(payload, "asset_overrides", [])
            if item.pattern.strip()
        ],
    )


def _to_endpoint_config(payload: EndpointScanRequest, tenant_id: str) -> WinRMEndpointConfig:
    username = payload.username.strip()
    password = payload.password
    domain = payload.domain.strip() or "WORKGROUP"
    allowed_extensions, extension_filter_enabled = _scan_extension_settings(
        payload.allowed_extensions,
        payload.extension_filter_enabled,
    )
    if payload.credential_ref:
        secret = vault.resolve(tenant_id, payload.credential_ref)
        username = secret.get("username", "")
        password = secret.get("password", "")
        domain = secret.get("domain", domain)

    return WinRMEndpointConfig(
        host=payload.host.strip(),
        username=username,
        password=password,
        domain=domain,
        target_username=payload.target_username.strip(),
        paths=[item.strip() for item in payload.paths if item.strip()] or ["desktop", "documents", "downloads"],
        max_depth=payload.max_depth,
        read_content=payload.read_content,
        allowed_extensions=allowed_extensions,
        extension_filter_enabled=extension_filter_enabled,
        include_hidden=payload.include_hidden,
        include_system=payload.include_system,
        hidden_filter_enabled=payload.hidden_filter_enabled,
        system_filter_enabled=payload.system_filter_enabled,
        read_acl=payload.read_acl,
        inspect_archives=payload.inspect_archives,
    )


