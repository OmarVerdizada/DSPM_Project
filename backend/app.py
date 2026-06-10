from __future__ import annotations

import hmac
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.alerts import evaluate_alerts
from backend.jobs import cancel_job, create_scan_job, get_job
from backend.security import (
    Principal,
    authenticate_user,
    create_token,
    generate_api_key,
    hash_password,
    require_principal,
    require_role,
    sanitize_username,
)
from backend.store import (
    audit,
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
    rotate_registration_code,
    save_scan_history,
    tenant_exists,
    update_user_password,
    update_user_profile,
    update_user_role,
)
from backend.vault import CredentialVault
from collectors.winrm_endpoint_scanner import WinRMEndpointConfig, WinRMEndpointScanner, activate_local_winrm
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

app = FastAPI(
    title="DSPM DLP Discovery API",
    description="Discovers sensitive data on AD file servers and produces DLP-ready risk context.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, __: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": "Invalid request. Check required fields and formats."})


class ConnectionRequest(BaseModel):
    server: str = Field(default="", description="AD file server hostname or IP")
    username: str = ""
    password: str = ""
    credential_ref: str = ""
    domain: str = "WORKGROUP"
    local_path: str = "enterprise_test_data"
    max_depth: int = Field(default=4, ge=1, le=12)
    allowed_extensions: list[str] = Field(default_factory=list)
    extension_filter_enabled: bool = False
    include_hidden: bool = False
    include_system: bool = False
    hidden_filter_enabled: bool = False
    system_filter_enabled: bool = False
    include_admin_shares: bool = False


class AssetOverride(BaseModel):
    pattern: str = Field(description="Customer-specific asset name, folder, extension, or path fragment")
    level: str = Field(pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$")
    reason: str = ""


class ScanRequest(ConnectionRequest):
    save_report: bool = True
    async_scan: bool = False
    asset_overrides: list[AssetOverride] = Field(default_factory=list)


class EndpointScanRequest(BaseModel):
    host: str = Field(description="Endpoint hostname or IP")
    target_username: str = Field(default="", description="Windows profile username under C:\\Users")
    domain: str = "WORKGROUP"
    username: str = ""
    password: str = ""
    credential_ref: str = ""
    paths: list[str] = Field(default_factory=lambda: ["desktop", "documents", "downloads"])
    max_depth: int = Field(default=12, ge=1, le=12)
    read_content: bool = True
    allowed_extensions: list[str] = Field(default_factory=list)
    extension_filter_enabled: bool = False
    include_hidden: bool = False
    include_system: bool = False
    hidden_filter_enabled: bool = False
    system_filter_enabled: bool = False
    save_report: bool = True
    asset_overrides: list[AssetOverride] = Field(default_factory=list)


class LocalWinRMActivationRequest(BaseModel):
    domain: str = "WORKGROUP"
    username: str = ""
    password: str = ""


class LoginRequest(BaseModel):
    username: str
    password: str


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


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=200)


class ProfileUpdateRequest(BaseModel):
    full_name: str = Field(default="", max_length=120)


class CredentialRequest(BaseModel):
    username: str
    password: str
    domain: str = "WORKGROUP"


class ApiKeyRequest(BaseModel):
    label: str = "default"


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
def login(payload: LoginRequest) -> dict:
    principal = authenticate_user(payload.username, payload.password)
    if principal is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    audit(principal.tenant_id, principal.subject, "auth.login")
    return {
        "access_token": create_token(principal.subject, principal.role, principal.tenant_id),
        "token_type": "bearer",
        "role": principal.role,
        "tenant_id": principal.tenant_id,
    }


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
    return {"users": [_public_user(user) for user in list_users()]}


@app.post("/api/users")
def admin_create_user(payload: UserCreateRequest, principal: Principal = Depends(require_role("admin"))) -> dict:
    username = sanitize_username(payload.username)
    tenant_id = _safe_tenant(payload.tenant_id)
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
    if tenant_id and not tenant_exists(tenant_id):
        raise HTTPException(status_code=400, detail="Tenant does not exist")
    if target == principal.subject and payload.role != "admin":
        admins = [user for user in list_users() if user["role"] == "admin" and user["is_active"]]
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
    user = update_user_password(target, hash_password(payload.password))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    audit(principal.tenant_id, principal.subject, "user.password_reset", {"username": target})
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
    if target == principal.subject:
        raise HTTPException(status_code=400, detail="You cannot delete your own signed-in account")
    if user["role"] == "admin" and user["is_active"]:
        admins = [item for item in list_users() if item["role"] == "admin" and item["is_active"]]
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
    engine = DSPMDiscoveryEngine(_to_config(payload, principal.tenant_id))
    audit(principal.tenant_id, principal.subject, "connection.test", {"server": payload.server})
    return engine.test_connection()


@app.post("/api/endpoint/test-connection")
def endpoint_test_connection(payload: EndpointScanRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    scanner = WinRMEndpointScanner(_to_endpoint_config(payload, principal.tenant_id))
    audit(principal.tenant_id, principal.subject, "endpoint.connection.test", {"host": payload.host, "target_username": payload.target_username})
    return scanner.test_connection()


@app.post("/api/endpoint/activate-local-winrm")
def endpoint_activate_local_winrm(payload: LocalWinRMActivationRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    try:
        result = activate_local_winrm(payload.username, payload.password, payload.domain)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(
        principal.tenant_id,
        principal.subject,
        "endpoint.winrm.activate_local",
        {"host": result.get("host"), "activated": result.get("activated")},
    )
    return result


@app.post("/api/endpoint/activate-winrm")
def endpoint_activate_winrm(payload: EndpointScanRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    scanner = WinRMEndpointScanner(_to_endpoint_config(payload, principal.tenant_id))
    try:
        result = scanner.activate_winrm()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(
        principal.tenant_id,
        principal.subject,
        "endpoint.winrm.activate",
        {"host": payload.host, "activated": result.get("activated"), "connected": result.get("connected")},
    )
    return result


@app.post("/api/endpoint/repair-winrm")
def endpoint_repair_winrm(payload: EndpointScanRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    scanner = WinRMEndpointScanner(_to_endpoint_config(payload, principal.tenant_id))
    try:
        result = scanner.activate_winrm()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
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
        config = _to_endpoint_config(payload, principal.tenant_id)
        scanner = WinRMEndpointScanner(config)
        records = scanner.scan()
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
                "raw_record_count": len(records),
                "extension_counts": extension_counts,
                "scan_diagnostics": scanner.last_scan_diagnostics,
            },
        }
        _persist_scan(data, payload, principal)
        audit(principal.tenant_id, principal.subject, "endpoint.scan.completed", {"scan_id": data.get("scan_id"), "host": payload.host})
        return data
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/demo-data/generate")
def generate_demo_data(payload: DemoDataRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    output = _safe_demo_output(payload.output)
    generate_enterprise_test_data(output, payload.files_per_share)
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
    if payload.async_scan:
        job = create_scan_job(principal.tenant_id, _to_config(payload, principal.tenant_id), lambda data: _persist_scan(data, payload, principal))
        audit(principal.tenant_id, principal.subject, "scan.queued", {"job_id": job.id, "server": payload.server})
        return job.to_dict()

    engine = DSPMDiscoveryEngine(_to_config(payload, principal.tenant_id))
    report = engine.run()
    data = report.to_dict()
    _persist_scan(data, payload, principal)
    audit(principal.tenant_id, principal.subject, "scan.completed", {"scan_id": data.get("scan_id")})
    return data


@app.get("/api/scans/{job_id}")
def scan_job(job_id: str, principal: Principal = Depends(require_role("viewer"))) -> dict:
    job = get_job(job_id)
    if job is None or job.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job.to_dict()


@app.post("/api/scans/{job_id}/cancel")
def stop_scan(job_id: str, principal: Principal = Depends(require_role("analyst"))) -> dict:
    stopped = cancel_job(job_id)
    audit(principal.tenant_id, principal.subject, "scan.cancel", {"job_id": job_id, "stopped": stopped})
    return {"cancelled": stopped}


@app.get("/api/history")
def scan_history(principal: Principal = Depends(require_role("viewer"))) -> dict:
    return {"history": read_scan_history(principal.tenant_id)}


@app.get("/api/tenants")
def tenant_portfolio(principal: Principal = Depends(require_role("admin"))) -> dict:
    return {"tenants": list_tenants()}


@app.get("/api/audit")
def audit_log(principal: Principal = Depends(require_role("admin"))) -> dict:
    return {"events": read_audit_log(principal.tenant_id)}


@app.get("/api/executive-dashboard")
def executive_dashboard(principal: Principal = Depends(require_role("viewer"))) -> dict:
    history = read_scan_history(principal.tenant_id)
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
        "registration_code": tenant.get("registration_code", ""),
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


def _persist_scan(data: dict, payload: ScanRequest, principal: Principal) -> None:
    scan_id = save_scan_history(principal.tenant_id, data)
    data["scan_id"] = scan_id
    alerts = evaluate_alerts(principal.tenant_id, data)
    data["alerts"] = alerts
    if payload.save_report:
        generate_report(data, BASE_DIR / "report.json")


def _to_config(payload: ConnectionRequest, tenant_id: str) -> ScanConfig:
    username = payload.username.strip()
    password = payload.password
    domain = payload.domain.strip() or "WORKGROUP"
    if payload.credential_ref:
        secret = vault.resolve(tenant_id, payload.credential_ref)
        username = secret.get("username", "")
        password = secret.get("password", "")
        domain = secret.get("domain", domain)

    return ScanConfig(
        server=payload.server.strip(),
        username=username,
        password=password,
        domain=domain,
        local_path=payload.local_path.strip() or "enterprise_test_data",
        max_depth=payload.max_depth,
        allowed_extensions=payload.allowed_extensions,
        extension_filter_enabled=payload.extension_filter_enabled,
        include_hidden=payload.include_hidden,
        include_system=payload.include_system,
        hidden_filter_enabled=payload.hidden_filter_enabled,
        system_filter_enabled=payload.system_filter_enabled,
        include_admin_shares=payload.include_admin_shares,
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
        allowed_extensions=payload.allowed_extensions,
        extension_filter_enabled=payload.extension_filter_enabled,
        include_hidden=payload.include_hidden,
        include_system=payload.include_system,
        hidden_filter_enabled=payload.hidden_filter_enabled,
        system_filter_enabled=payload.system_filter_enabled,
    )
