from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
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
    delete_tenant,
    get_user,
    list_tenants,
    list_users,
    read_audit_log,
    read_scan_history,
    save_scan_history,
    tenant_exists,
    tenant_usage,
    update_user_password,
    update_user_role,
)
from backend.vault import CredentialVault
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from risk.risk_engine import get_risk_rules
from scripts.report import generate_report

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
vault = CredentialVault()

app = FastAPI(
    title="DSPM DLP Discovery API",
    description="Discovers sensitive data on AD file servers and produces DLP-ready risk context.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


class ConnectionRequest(BaseModel):
    server: str = Field(default="", description="AD file server hostname or IP")
    username: str = ""
    password: str = ""
    credential_ref: str = ""
    domain: str = "WORKGROUP"
    local_path: str = "enterprise_test_data"
    max_depth: int = Field(default=4, ge=1, le=12)


class AssetOverride(BaseModel):
    pattern: str = Field(description="Customer-specific asset name, folder, extension, or path fragment")
    level: str = Field(pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$")
    reason: str = ""


class ScanRequest(ConnectionRequest):
    save_report: bool = True
    async_scan: bool = False
    asset_overrides: list[AssetOverride] = Field(default_factory=list)


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=8, max_length=200)
    full_name: str = Field(default="", max_length=120)
    tenant_id: str = Field(default="default", max_length=80)


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


class CredentialRequest(BaseModel):
    username: str
    password: str
    domain: str = "WORKGROUP"


class ApiKeyRequest(BaseModel):
    label: str = "default"


@app.get("/")
def login_root() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "login.html")


@app.get("/login")
def login_page() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "login.html")


@app.get("/register")
def register_page() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "register.html")


@app.get("/dashboard")
def dashboard() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "dspm-discovery"}


@app.get("/api/risk-rules")
def risk_rules(_: Principal = Depends(require_role("viewer"))) -> dict:
    return {"rules": get_risk_rules()}


@app.get("/api/auth/tenants")
def public_tenants() -> dict:
    return {"tenants": [_public_tenant(tenant) for tenant in list_tenants()]}


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
        raise HTTPException(status_code=400, detail="Tenant does not exist")
    if get_user(username):
        raise HTTPException(status_code=409, detail="Username already exists")
    user = create_user(username, hash_password(payload.password), "viewer", tenant_id, payload.full_name.strip())
    audit(tenant_id, username, "user.registered", {"role": "viewer"})
    return {"user": _public_user(user)}


@app.post("/api/auth/change-password")
def change_password(payload: PasswordChangeRequest, principal: Principal = Depends(require_role("viewer"))) -> dict:
    authenticated = authenticate_user(principal.subject, payload.current_password)
    if authenticated is None:
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    update_user_password(principal.subject, hash_password(payload.new_password))
    audit(principal.tenant_id, principal.subject, "user.password_changed")
    return {"status": "updated"}


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
    user = update_user_password(target, hash_password(payload.password))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    audit(principal.tenant_id, principal.subject, "user.password_reset", {"username": target})
    return {"status": "updated", "user": _public_user(user)}


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


@app.delete("/api/tenants/{tenant_id}")
def admin_delete_tenant(tenant_id: str, principal: Principal = Depends(require_role("admin"))) -> dict:
    target = _safe_tenant(tenant_id)
    if target == "default":
        raise HTTPException(status_code=400, detail="Default tenant cannot be removed")
    if not tenant_exists(target):
        raise HTTPException(status_code=404, detail="Tenant not found")
    usage = tenant_usage(target)
    if any(usage.values()):
        raise HTTPException(status_code=400, detail=f"Tenant is not empty: {usage}")
    delete_tenant(target)
    audit(principal.tenant_id, principal.subject, "tenant.deleted", {"tenant_id": target})
    return {"deleted": True, "tenant_id": target}


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
        "created_at": tenant.get("created_at"),
        "updated_at": tenant.get("updated_at"),
        "scan_count": tenant.get("scan_count", 0),
        "latest": tenant.get("latest", {"summary": {}}),
        "retention": tenant.get("retention", {}),
    }


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
