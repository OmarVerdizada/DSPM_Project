from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.alerts import evaluate_alerts
from backend.jobs import cancel_job, create_scan_job, get_job
from backend.security import Principal, authenticate_user, create_token, generate_api_key, require_principal, require_role
from backend.store import audit, data_retention_summary, read_audit_log, read_scan_history, save_scan_history
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
    local_path: str = "test_data"
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


class CredentialRequest(BaseModel):
    username: str
    password: str
    domain: str = "WORKGROUP"


class ApiKeyRequest(BaseModel):
    label: str = "default"


@app.get("/")
def dashboard() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/login")
def login_page() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "login.html")


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


@app.get("/api/audit")
def audit_log(principal: Principal = Depends(require_role("admin"))) -> dict:
    return {"events": read_audit_log(principal.tenant_id)}


@app.get("/api/executive-dashboard")
def executive_dashboard(principal: Principal = Depends(require_role("viewer"))) -> dict:
    history = read_scan_history(principal.tenant_id)
    latest = history[-1] if history else {"summary": {}}
    summary = latest.get("summary", {})
    score = max(0, 100 - summary.get("critical", 0) * 20 - summary.get("high", 0) * 8 - summary.get("medium", 0) * 3)
    return {
        "tenant_id": principal.tenant_id,
        "risk_posture_score": score,
        "latest": latest,
        "trend": history[-14:],
        "retention": data_retention_summary(principal.tenant_id),
    }


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
        local_path=payload.local_path.strip() or "test_data",
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
