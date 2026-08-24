from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import os
import platform
import re
import secrets
import socket
import time
from contextlib import asynccontextmanager, suppress
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from backend.alerts import evaluate_alerts
from backend.copilot.router import router as copilot_router
from backend.copilot.session_context import session_context_sweeper
from backend.compliance_service import enrich_report_with_compliance, normalize_framework_ids
from backend.finding_contracts import build_nist_finding_detail, get_finding_display_name, normalize_framework_id
from backend.jobs import cancel_job, cleanup_jobs, collection_heartbeat, create_job, create_scan_job, get_job
from backend.inventory_export import inventory_export_response_metadata, inventory_export_stream
from backend.security import (
    Principal,
    authenticate_user,
    create_token,
    generate_api_key,
    hash_password,
    is_platform_admin,
    require_principal,
    require_role,
    revoke_token,
    sanitize_username,
)
from backend.store import (
    InventoryReadUnavailable,
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
    prune_job_records,
    read_audit_log,
    read_job,
    read_scan_history,
    read_scan_report,
    recover_interrupted_jobs,
    record_login_failure,
    rotate_registration_code,
    create_registration_invite,
    redeem_registration_invite,
    list_registration_invites,
    revoke_registration_invite,
    create_api_key_record,
    list_api_keys,
    revoke_api_key,
    save_scan_history,
    tenant_exists,
    get_finding,
    get_finding_history,
    get_finding_occurrences,
    get_inventory_asset,
    inventory_facets,
    inventory_export_ready,
    incremental_baseline_exists,
    list_findings,
    list_inventory,
    probe_incremental_object,
    update_finding_lifecycle,
    update_finding_workflow,
    update_user_password,
    update_user_profile,
    update_user_role,
    update_user_active,
)
from backend.vault import CredentialVault
from classification.compliance.keyword_library import (
    export_keyword_groups,
    import_keyword_groups,
    list_keyword_groups,
    validate_keyword_import,
)
from classification.compliance.nist_catalog import (
    activate_nist_catalog,
    export_nist_catalog,
    get_nist_rule,
    import_nist_catalog,
    list_nist_rules,
    load_nist_catalog,
    nist_catalog_status,
    rollback_nist_catalog,
    validate_nist_catalog,
)
from collectors.file_scanner import normalize_extension_filter, scan_directory
from collectors.net_guard import ip_disallowed_reason
from collectors.winrm_endpoint_scanner import (
    ENDPOINT_PATH_ALIASES,
    WinRMEndpointConfig,
    WinRMEndpointScanner,
    activate_local_winrm,
    normalize_endpoint_target_paths,
)
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.incremental import (
    apply_reuse_snapshot,
    incremental_scope_key,
    qualified_object_key,
    reuse_snapshot_from_result,
)
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
# M4: an aggregate per-IP failure cap alongside the per-(IP,username) cap, so one
# IP spraying a password across many usernames is throttled even though no single
# (IP,username) counter trips. Higher than the per-user cap to tolerate a shared
# NAT/office IP with a few users and the odd typo.
LOGIN_IP_MAX_ATTEMPTS = int(os.getenv("DSPM_LOGIN_IP_MAX_ATTEMPTS", "30"))
ENVIRONMENT = os.getenv("DSPM_ENV", "local").strip().lower()
IS_PRODUCTION = ENVIRONMENT in {"prod", "production"}
# ARCH-002: Copilot is an optional subsystem. DSPM_COPILOT_ENABLED=0 deploys the
# core platform without it - no router, no session sweeper, no post-scan hook.
COPILOT_ENABLED = os.getenv("DSPM_COPILOT_ENABLED", "1").strip() != "0"
REPORT_DIR = Path(os.getenv("DSPM_REPORT_DIR", BASE_DIR / "data" / "reports")).resolve()
REPORT_DIR.mkdir(parents=True, exist_ok=True)


@asynccontextmanager
async def app_lifespan(_: FastAPI):
    # M3: fail CLOSED at startup on a missing (prod) or malformed vault key, before
    # any credential operation. NOT wrapped in try/except - a bad key must abort.
    from backend.vault import validate_vault_key

    validate_vault_key()
    # ARCH-003: at server startup, mark jobs orphaned by a prior process as
    # failed and prune old terminal records. Done here (not at import) so tools
    # and tests that import the app do not mutate persisted job state.
    try:
        recover_interrupted_jobs()
        prune_job_records(30 * 24 * 3600)
    except Exception:
        pass
    with suppress(Exception):
        from backend.search import start_search_reconciler

        start_search_reconciler()
    # Make the OCR posture observable: opt-in OCR was silently off before, so a
    # user who enabled it had no way to confirm. Log it once at startup.
    try:
        from collectors.ocr import ocr_enabled, ocr_status_line, warmup
        from scripts.logger import get_logger

        get_logger("backend.app").info(ocr_status_line())
        if ocr_enabled():
            # Warm the OCR engine in the background so the first scan's first image
            # does not pay the one-time model-load + graph-optimisation cost.
            import threading

            threading.Thread(target=warmup, name="ocr-warmup", daemon=True).start()
    except Exception:
        pass
    sweeper = asyncio.create_task(session_context_sweeper()) if COPILOT_ENABLED else None
    try:
        yield
    finally:
        with suppress(Exception):
            from backend.search import stop_search_reconciler

            stop_search_reconciler()
        if sweeper is not None:
            sweeper.cancel()
            with suppress(asyncio.CancelledError):
                await sweeper
        # Close the DB connection pool cleanly on shutdown (no-op on SQLite).
        with suppress(Exception):
            from backend import db

            db.close_pool()


app = FastAPI(
    title="DSPM DLP Discovery API",
    description="Discovers sensitive data on AD file servers and produces DLP-ready risk context.",
    version="1.0.0",
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
    lifespan=app_lifespan,
)

if TRUSTED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=TRUSTED_HOSTS)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Tenant-ID"],
)

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
if COPILOT_ENABLED:  # ARCH-002: flag defined near IS_PRODUCTION above
    app.include_router(copilot_router)


@app.middleware("http")
async def secure_response_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; "
        "font-src 'self' data: https://fonts.gstatic.com; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    )
    if request.url.scheme == "https" or IS_PRODUCTION:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


# M13: perimeter body-size limit. Reject a request whose body exceeds the cap
# BEFORE any handler reads/parses it, so a giant POST can never be buffered into
# memory or handed to the JSON parser. All API bodies are small JSON (no uploads),
# so the default cap is generous; override with DSPM_MAX_BODY_BYTES, 0 disables.
MAX_BODY_BYTES = int(os.getenv("DSPM_MAX_BODY_BYTES", str(25 * 1024 * 1024)))


class BodySizeLimitMiddleware:
    """Pure-ASGI limiter (added OUTERMOST so it sees the raw receive channel and is
    not affected by BaseHTTPMiddleware body buffering). It refuses an oversized
    Content-Length up front (no body read at all), and otherwise reads the body
    only up to the cap+1 - aborting a chunked / lying-Content-Length flood in
    bounded memory - before replaying the (small) body to the app."""

    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or self.max_bytes <= 0:
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers") or ():
            if name == b"content-length":
                try:
                    if int(value) > self.max_bytes:
                        await self._reject(send)
                        return
                except (TypeError, ValueError):
                    pass
                break
        body = b""
        while True:
            message = await receive()
            if message.get("type") != "http.request":
                break  # e.g. http.disconnect - stop reading
            body += message.get("body", b"") or b""
            if len(body) > self.max_bytes:  # chunked / lying Content-Length flood
                await self._reject(send)
                return
            if not message.get("more_body", False):
                break
        replayed = False

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            # Do not synthesize a disconnect after replaying the request. A
            # StreamingResponse listens for this event and would otherwise cancel
            # its body immediately. Propagate the real client channel so an actual
            # disconnect still cancels database/export work promptly.
            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _reject(send) -> None:
        payload = b'{"detail":"Request body exceeds the configured limit"}'
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": payload})


app.add_middleware(BodySizeLimitMiddleware, max_bytes=MAX_BODY_BYTES)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, __: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": "Invalid request. Check required fields and formats."})


@app.exception_handler(InventoryReadUnavailable)
async def inventory_unavailable_handler(_: Request, __: InventoryReadUnavailable) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"detail": "Normalized inventory is temporarily unavailable. Retry shortly."},
        headers={"Retry-After": "5", "Cache-Control": "no-store"},
    )


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
        # Tolerant + canonical (shared with every scan type): split multi-token
        # items, strip globs/quotes, drop invalid tokens - never raise. A typo or
        # a "*.pdf" no longer fails the whole scan, and every scan type agrees.
        return sorted(normalize_extension_filter(values))


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
    compact_result: bool = False
    asset_overrides: list[AssetOverride] = Field(default_factory=list)
    compliance_enabled: bool = False
    compliance_frameworks: list[str] = Field(default_factory=list, max_length=12)
    incremental_enabled: bool = True

    @field_validator("compliance_frameworks")
    @classmethod
    def _validate_compliance_frameworks(cls, values: list[str]) -> list[str]:
        try:
            return normalize_framework_ids(values)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc


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
    compact_result: bool = False
    allowed_extensions: list[str] = Field(default_factory=list, max_length=160)
    extension_filter_enabled: bool = False
    include_hidden: bool = True
    include_system: bool = False
    hidden_filter_enabled: bool = False
    system_filter_enabled: bool = False
    save_report: bool = True
    asset_overrides: list[AssetOverride] = Field(default_factory=list)
    compliance_enabled: bool = False
    compliance_frameworks: list[str] = Field(default_factory=list, max_length=12)
    incremental_enabled: bool = True

    @field_validator("host", "domain", "username", "credential_ref")
    @classmethod
    def _clean_endpoint_text(cls, value: str) -> str:
        return re.sub(r"[\x00-\x1f\x7f]", "", value or "").strip()

    @field_validator("allowed_extensions")
    @classmethod
    def _validate_endpoint_extensions(cls, values: list[str]) -> list[str]:
        # Same canonical, tolerant normalization as the file-server scan, so the
        # endpoint scan no longer silently accepts a garbage filter (e.g. "*.pdf"
        # -> ".*.pdf") that matches nothing.
        return sorted(normalize_extension_filter(values))

    @field_validator("compliance_frameworks")
    @classmethod
    def _validate_endpoint_compliance_frameworks(cls, values: list[str]) -> list[str]:
        try:
            return normalize_framework_ids(values)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc

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


class FindingWorkflowUpdate(BaseModel):
    path: str = Field(min_length=1, max_length=1000)
    type: str = Field(min_length=1, max_length=120)
    fingerprint: str = Field(default="", max_length=128)
    action: str = Field(default="update", max_length=40)
    review_status: str = Field(default="", max_length=40)
    exception_status: str = Field(default="", max_length=40)
    exception_reason: str = Field(default="", max_length=500)
    owner: str = Field(default="", max_length=160)
    due_date: str = Field(default="", max_length=40)
    sla: str = Field(default="", max_length=80)
    comment: str = Field(default="", max_length=1000)

    @field_validator("path", "type", "fingerprint", "action", "review_status", "exception_status", "exception_reason", "owner", "due_date", "sla", "comment")
    @classmethod
    def _clean_workflow_text(cls, value: str) -> str:
        return re.sub(r"[\x00-\x1f\x7f]", "", value or "").strip()


class FindingLifecyclePayload(BaseModel):
    status: str = Field(default="", max_length=40)
    owner: str = Field(default="", max_length=160)
    comment: str = Field(default="", max_length=1000)
    reason: str = Field(default="", max_length=1000)
    resolution: str = Field(default="", max_length=1000)
    business_justification: str = Field(default="", max_length=2000)
    approver: str = Field(default="", max_length=160)
    expiration_date: str = Field(default="", max_length=40)
    compensating_controls: list[str] = Field(default_factory=list, max_length=20)
    affected_assets: list[str] = Field(default_factory=list, max_length=200)
    accepted_volume: int = Field(default=0, ge=0, le=100000000)
    review_date: str = Field(default="", max_length=40)
    sla_due: str = Field(default="", max_length=40)

    @field_validator("status", "owner", "comment", "reason", "resolution", "business_justification", "approver", "expiration_date", "review_date", "sla_due")
    @classmethod
    def _clean_lifecycle_text(cls, value: str) -> str:
        return re.sub(r"[\x00-\x1f\x7f]", "", value or "").strip()

    @field_validator("compensating_controls", "affected_assets")
    @classmethod
    def _clean_lifecycle_list(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in values or []:
            value = re.sub(r"[\x00-\x1f\x7f]", "", str(item or "")).strip()
            if value:
                cleaned.append(value[:240])
        return cleaned


class ComplianceKeywordGroup(BaseModel):
    framework: str = Field(default="gdpr", max_length=40)
    language: str = Field(default="custom", max_length=32)
    category: str = Field(default="", max_length=80)
    type: str = Field(default="", max_length=80)
    finding_type: str = Field(default="", max_length=80)
    label: str = Field(default="", max_length=160)
    risk: str = Field(default="MEDIUM", pattern="^(LOW|MEDIUM|HIGH|CRITICAL|low|medium|high|critical)$")
    terms: list[str] = Field(default_factory=list, max_length=5000)

    @field_validator("framework", "language", "category", "type", "label", "risk")
    @classmethod
    def _clean_keyword_text(cls, value: str) -> str:
        return re.sub(r"[\x00-\x1f\x7f]", "", value or "").strip()

    @field_validator("terms")
    @classmethod
    def _clean_terms(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in values or []:
            term = " ".join(re.sub(r"[\x00-\x1f\x7f]", "", str(item or "")).strip().split())
            key = term.lower()
            if term and key not in seen:
                cleaned.append(term[:160])
                seen.add(key)
        return cleaned


class ComplianceKeywordImportRequest(BaseModel):
    framework: str = Field(default="gdpr", max_length=40)
    language: str = Field(default="custom", max_length=32)
    mode: str = Field(default="merge", pattern="^(merge|replace_type|replace_category|replace_framework|replace_language|replace_custom)$")
    keywords: list[ComplianceKeywordGroup] = Field(default_factory=list, max_length=1000)


class NISTCatalogPayload(BaseModel):
    catalog: dict = Field(default_factory=dict)
    dry_run: bool = True


class NISTCatalogActivationPayload(BaseModel):
    catalog_hash: str = Field(min_length=64, max_length=64)


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
    role: str = Field(default="analyst", max_length=20)
    ttl_days: int = Field(default=365, ge=1, le=3650)  # default 1 year, max 10 years


class DemoDataRequest(BaseModel):
    output: str = Field(default="enterprise_test_data", max_length=120)
    files_per_share: int = Field(default=10, ge=1, le=40)


@app.get("/")
def login_root() -> FileResponse:
    # The product starts at login: no marketing landing page ships on-prem.
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
    from collectors.ocr import ocr_status
    from backend.search import search_health

    return {"status": "ok", "service": "dspm-discovery", "ocr": ocr_status(), "search": search_health()}


@app.get("/api/risk-rules")
def risk_rules(_: Principal = Depends(require_role("viewer"))) -> dict:
    return {"rules": get_risk_rules()}


@app.get("/api/compliance-keywords")
def compliance_keywords(
    framework: str = Query(default="gdpr", max_length=40),
    language: str = Query(default="", max_length=32),
    category: str = Query(default="", max_length=80),
    source: str = Query(default="all", max_length=20),
    principal: Principal = Depends(require_role("viewer")),
) -> dict:
    return list_keyword_groups(principal.tenant_id, framework, language=language, category=category, source=source)


@app.post("/api/compliance-keywords/validate")
def compliance_keywords_validate(payload: ComplianceKeywordImportRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    return validate_keyword_import(principal.tenant_id, payload.model_dump())


@app.post("/api/compliance-keywords/import")
def compliance_keywords_import(payload: ComplianceKeywordImportRequest, principal: Principal = Depends(require_role("analyst"))) -> dict:
    try:
        result = import_keyword_groups(principal.tenant_id, payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(
        principal.tenant_id,
        principal.subject,
        "compliance_keywords.imported",
        {
            "framework": result.get("framework"),
            "mode": result.get("mode"),
            "new_terms": result.get("new_terms"),
            "duplicates": result.get("duplicates"),
        },
    )
    return result


@app.get("/api/compliance-keywords/export")
def compliance_keywords_export(
    framework: str = Query(default="gdpr", max_length=40),
    language: str = Query(default="", max_length=32),
    source: str = Query(default="all", max_length=20),
    format: str = Query(default="json", max_length=10),
    principal: Principal = Depends(require_role("viewer")),
) -> Response:
    filename, media_type, content = export_keyword_groups(principal.tenant_id, framework, language=language, source=source, fmt=format)
    return Response(content=content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.get("/api/compliance-keywords/template")
def compliance_keywords_template(
    framework: str = Query(default="gdpr", max_length=40),
    language: str = Query(default="ru", max_length=32),
    principal: Principal = Depends(require_role("viewer")),
) -> dict:
    _ = principal
    normalized_framework = framework.strip().lower().replace("-", "_")
    if normalized_framework == "pci_dss":
        return {
            "framework": "pci_dss",
            "language": language,
            "mode": "merge",
            "keywords": [
                {
                    "framework": "pci_dss",
                    "language": language,
                    "category": "pci_cardholder_data",
                    "type": "pci_chd_pan",
                    "label": "Primary Account Number",
                    "risk": "CRITICAL",
                    "terms": ["primary account number", "card number", "full pan"],
                },
                {
                    "framework": "pci_dss",
                    "language": language,
                    "category": "pci_sensitive_authentication_data",
                    "type": "pci_sad_cvv",
                    "label": "Card Verification Code / Value",
                    "risk": "CRITICAL",
                    "terms": ["cvv", "cvc2", "card security code"],
                },
                {
                    "framework": "pci_dss",
                    "language": language,
                    "category": "pci_scope_context",
                    "type": "pci_payment_context",
                    "label": "Payment Scope Context",
                    "risk": "MEDIUM",
                    "terms": ["payment gateway", "cardholder data environment", "processor export"],
                },
            ],
            "notes": [
                "PCI DSS imports should use pci_cardholder_data, pci_sensitive_authentication_data, or pci_scope_context categories.",
                "Custom PCI context terms help triage scope but do not confirm CHD/SAD without structural detector evidence.",
                "Raw PAN, CVV, PIN, and track values are not stored in finding evidence.",
            ],
        }
    if normalized_framework == "nist_sp800_60_enterprise":
        return {
            "framework": "nist_sp800_60_enterprise",
            "language": language,
            "mode": "merge",
            "keywords": [
                {
                    "framework": "nist_sp800_60_enterprise",
                    "language": language,
                    "category": "nist_privacy_pii",
                    "type": "nist_privacy_pii_type_01",
                    "label": "Local PII synonym overlay",
                    "risk": "HIGH",
                    "terms": ["local personal identifier", "müştəri fin kodu"],
                },
                {
                    "framework": "nist_sp800_60_enterprise",
                    "language": language,
                    "category": "nist_credentials_secrets",
                    "type": "nist_credentials_secrets_type_01",
                    "label": "Local credential synonym overlay",
                    "risk": "CRITICAL",
                    "terms": ["breakglass token", "platform secret"],
                },
            ],
            "notes": [
                "This endpoint imports tenant overlays only; it does not replace official NIST baseline rules.",
                "Allowed overlay fields include terms, structured_field_names, negative_keywords, allowed_file_types, excluded_paths, owner, and status metadata.",
                "Use /api/nist/catalog/import and /api/nist/catalog/activate for full admin-managed baseline upgrades.",
            ],
        }
    return {
        "framework": framework,
        "language": language,
        "mode": "merge",
        "keywords": [
            {
                "framework": framework,
                "language": language,
                "category": "pii",
                "type": "gdpr_full_name",
                "label": "Full name",
                "risk": "LOW",
                "terms": ["subject full legal name", "employee legal name", "customer full name"],
            },
            {
                "framework": framework,
                "language": language,
                "category": "government_ids",
                "type": "gdpr_passport_number",
                "label": "Passport number",
                "risk": "HIGH",
                "terms": ["passport number", "passport document number", "travel document identifier"],
            },
            {
                "framework": framework,
                "language": language,
                "category": "health",
                "type": "gdpr_health_medical_record",
                "label": "Health / medical",
                "risk": "HIGH",
                "terms": ["medical record number", "clinical diagnosis", "patient treatment plan"],
            },
            {
                "framework": framework,
                "language": language,
                "category": "custom",
                "type": "custom_sensitive_contract",
                "label": "Custom sensitive contract",
                "risk": "MEDIUM",
                "terms": ["custom board contract marker", "restricted vendor agreement"],
            },
        ],
        "notes": [
            "JSON imports accept keywords/groups with framework, language, category, type, label, risk, and terms.",
            "CSV imports should include keyword,type,category,label,risk columns when adding custom findings.",
            "TXT imports use the selected finding type/category/risk from the UI and split terms by comma, semicolon, pipe, tab, or new line.",
        ],
    }


@app.get("/api/nist/catalog/status")
def nist_catalog_status_endpoint(_: Principal = Depends(require_role("viewer"))) -> dict:
    return nist_catalog_status()


@app.get("/api/nist/catalog")
def nist_catalog_endpoint(
    category: str = Query(default="", max_length=120),
    source_kind: str = Query(default="", max_length=40),
    handling_tier: str = Query(default="", max_length=40),
    severity: str = Query(default="", max_length=40),
    cia_impact: str = Query(default="", max_length=40),
    detection_mode: str = Query(default="", max_length=80),
    search: str = Query(default="", max_length=160),
    include_keywords: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(require_role("viewer")),
) -> dict:
    _ = principal
    return list_nist_rules(
        category=category,
        source_kind=source_kind,
        handling_tier=handling_tier,
        severity=severity,
        cia_impact=cia_impact,
        detection_mode=detection_mode,
        search=search,
        include_keywords=include_keywords,
        limit=limit,
        offset=offset,
    )


@app.get("/api/nist/catalog/rules/{rule_id}")
def nist_catalog_rule(rule_id: str, principal: Principal = Depends(require_role("viewer"))) -> dict:
    _ = principal
    rule = get_nist_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="NIST rule not found")
    return {"rule": rule, "catalog_status": nist_catalog_status()}


@app.post("/api/nist/catalog/validate")
def nist_catalog_validate(payload: NISTCatalogPayload, principal: Principal = Depends(require_role("analyst"))) -> dict:
    result = validate_nist_catalog(payload.catalog)
    audit(principal.tenant_id, principal.subject, "nist.catalog.validated", {"valid": result.get("valid"), "catalog_hash": result.get("catalog_hash")})
    return result


@app.post("/api/nist/catalog/import")
def nist_catalog_import(payload: NISTCatalogPayload, principal: Principal = Depends(require_role("admin"))) -> dict:
    # H3: the NIST catalog is a platform-global, vendor-maintained baseline shared
    # by every tenant's classifier. Only the platform admin may mutate it - a
    # tenant-scoped admin must not be able to change detection for other tenants.
    _require_platform_admin(principal)
    try:
        result = import_nist_catalog(payload.catalog, dry_run=payload.dry_run, actor=principal.subject)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(principal.tenant_id, principal.subject, "nist.catalog.imported", {"dry_run": payload.dry_run, "catalog_hash": result.get("catalog_hash"), "valid": result.get("valid")})
    return result


@app.post("/api/nist/catalog/activate")
def nist_catalog_activate(payload: NISTCatalogActivationPayload, principal: Principal = Depends(require_role("admin"))) -> dict:
    _require_platform_admin(principal)  # H3: platform-global resource (see import)
    try:
        result = activate_nist_catalog(payload.catalog_hash, actor=principal.subject)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(principal.tenant_id, principal.subject, "nist.catalog.activated", {"catalog_hash": result.get("catalog_hash")})
    return result


@app.post("/api/nist/catalog/rollback")
def nist_catalog_rollback(principal: Principal = Depends(require_role("admin"))) -> dict:
    _require_platform_admin(principal)  # H3: platform-global resource (see import)
    try:
        result = rollback_nist_catalog(actor=principal.subject)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(principal.tenant_id, principal.subject, "nist.catalog.rollback", {"catalog_hash": result.get("catalog_hash")})
    return result


@app.get("/api/nist/catalog/export")
def nist_catalog_export(principal: Principal = Depends(require_role("viewer"))) -> Response:
    _ = principal
    filename, media_type, content = export_nist_catalog()
    return Response(content=content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request) -> dict:
    login_key = _login_rate_key(payload.username, request)
    ip_key = _login_ip_rate_key(request)
    # M4: trip on EITHER the per-(IP,username) cap OR the aggregate per-IP cap, so a
    # username-spray from one IP is throttled even though no single username does.
    if _too_many_login_failures(login_key) or _too_many_ip_login_failures(ip_key):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
    principal = authenticate_user(payload.username, payload.password)
    if principal is None:
        _record_login_failure(login_key)
        _record_login_failure(ip_key)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    # Clear this user's counter; the per-IP aggregate is NOT cleared by one success
    # (a sprayer who guesses one valid credential must not reset the IP's history).
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
    code = payload.registration_code.strip()
    # M5: prefer a time-boxed, use-capped invite token (atomically redeemed); fall
    # back to the legacy static per-tenant code for backward compatibility.
    invite = redeem_registration_invite(tenant_id, _hash_invite_token(code)) if code else None
    if invite is None and not _valid_registration_code(tenant_id, code):
        raise HTTPException(status_code=403, detail="Registration failed")
    if get_user(username):
        raise HTTPException(status_code=409, detail="Registration failed")
    role = invite["role"] if invite else "viewer"
    pending = bool(invite and invite["requires_approval"])
    create_user(username, hash_password(payload.password), role, tenant_id, payload.full_name.strip())
    if pending:
        update_user_active(username, False)  # M5: admin-approval - inactive until an admin activates
    detail = {"role": role, "source": "invite" if invite else "registration_code"}
    if invite:
        detail.update({"invite_id": invite["id"], "remaining_uses": invite["remaining_uses"], "pending_approval": pending})
    audit(tenant_id, username, "user.registered", detail)  # M5: per-redemption audit
    return {"user": _public_user(get_user(username)), "pending_approval": pending}


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


class InviteCreateRequest(BaseModel):
    role: str = Field(default="viewer", max_length=20)
    max_uses: int = Field(default=1, ge=1, le=1000)
    ttl_hours: int = Field(default=168, ge=1, le=8760)  # 7-day default, 1-year max
    requires_approval: bool = False


@app.post("/api/tenants/{tenant_id}/invites")
def admin_create_invite(tenant_id: str, payload: InviteCreateRequest, principal: Principal = Depends(require_role("admin"))) -> dict:
    target = _safe_tenant(tenant_id)
    if not _can_manage_tenant(principal, target):
        raise HTTPException(status_code=403, detail="Tenant access denied")
    if not tenant_exists(target):
        raise HTTPException(status_code=404, detail="Tenant not found")
    role = payload.role.strip().lower()
    if role not in {"viewer", "analyst"}:
        # Self-registration invites never mint admins - create admins via /api/users.
        raise HTTPException(status_code=400, detail="Invite role must be 'viewer' or 'analyst'")
    token = f"inv_{secrets.token_urlsafe(24)}"
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=payload.ttl_hours)).isoformat()
    invite_id = create_registration_invite(
        target, _hash_invite_token(token), role, payload.max_uses, expires_at, payload.requires_approval, principal.subject,
    )
    audit(principal.tenant_id, principal.subject, "tenant.invite_created", {
        "tenant_id": target, "invite_id": invite_id, "role": role,
        "max_uses": payload.max_uses, "expires_at": expires_at, "requires_approval": payload.requires_approval,
    })
    # The plaintext token is returned ONCE here; only its hash is stored.
    return {
        "invite_id": invite_id, "token": token, "role": role,
        "max_uses": payload.max_uses, "expires_at": expires_at, "requires_approval": payload.requires_approval,
    }


@app.get("/api/tenants/{tenant_id}/invites")
def admin_list_invites(tenant_id: str, principal: Principal = Depends(require_role("admin"))) -> dict:
    target = _safe_tenant(tenant_id)
    if not _can_manage_tenant(principal, target):
        raise HTTPException(status_code=403, detail="Tenant access denied")
    return {"invites": list_registration_invites(target)}


@app.post("/api/tenants/{tenant_id}/invites/{invite_id}/revoke")
def admin_revoke_invite(tenant_id: str, invite_id: str, principal: Principal = Depends(require_role("admin"))) -> dict:
    target = _safe_tenant(tenant_id)
    if not _can_manage_tenant(principal, target):
        raise HTTPException(status_code=403, detail="Tenant access denied")
    if not revoke_registration_invite(target, invite_id):
        raise HTTPException(status_code=404, detail="Invite not found or already revoked")
    audit(principal.tenant_id, principal.subject, "tenant.invite_revoked", {"tenant_id": target, "invite_id": invite_id})
    return {"revoked": True, "invite_id": invite_id}


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
    role = payload.role.strip().lower()
    if role not in {"viewer", "analyst"}:
        # Machine keys never carry admin - create admins via /api/users.
        raise HTTPException(status_code=400, detail="API key role must be 'viewer' or 'analyst'")
    raw, key_hash = generate_api_key()
    expires_at = (datetime.now(timezone.utc) + timedelta(days=payload.ttl_days)).isoformat()
    key_id = create_api_key_record(principal.tenant_id, key_hash, payload.label, role, principal.subject, expires_at)
    audit(principal.tenant_id, principal.subject, "api_key.created", {"key_id": key_id, "label": payload.label, "role": role, "expires_at": expires_at})
    return {
        "key_id": key_id,
        "label": payload.label,
        "role": role,
        "expires_at": expires_at,
        "api_key": raw,  # shown once; only the sha256 is stored
        "message": "Store this key now - it is shown once. It is revocable via /api/api-keys/{key_id}/revoke.",
    }


@app.get("/api/api-keys")
def list_api_keys_route(principal: Principal = Depends(require_role("admin"))) -> dict:
    return {"api_keys": list_api_keys(principal.tenant_id)}


@app.post("/api/api-keys/{key_id}/revoke")
def revoke_api_key_route(key_id: str, principal: Principal = Depends(require_role("admin"))) -> dict:
    if not revoke_api_key(principal.tenant_id, key_id):
        raise HTTPException(status_code=404, detail="API key not found or already revoked")
    audit(principal.tenant_id, principal.subject, "api_key.revoked", {"key_id": key_id})
    return {"revoked": True, "key_id": key_id}


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
        return _compact_scan_report(data) if payload.compact_result else data
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
        _prepare_local_scan_data(payload)
        if payload.async_scan:
            job = create_scan_job(principal.tenant_id, _to_config(payload, principal.tenant_id), lambda data: _persist_compliance_scan(data, payload, principal))
            audit(principal.tenant_id, principal.subject, "scan.queued", {"job_id": job.id, "server": _safe_target_label(payload.server)})
            return job.to_dict()

        engine = DSPMDiscoveryEngine(_to_config(payload, principal.tenant_id))
        report = engine.run()
        data = report.to_dict()
        _apply_compliance(data, payload)
        _persist_scan(data, payload, principal)
        audit(principal.tenant_id, principal.subject, "scan.completed", {"scan_id": data.get("scan_id")})
        return _compact_scan_report(data) if payload.compact_result else data
    except HTTPException:
        raise
    except Exception as exc:
        raise _safe_operation_error("Scan failed", exc) from exc


@app.get("/api/scans/{job_id}")
def scan_job(job_id: str, principal: Principal = Depends(require_role("viewer"))) -> dict:
    cleanup_jobs()
    job = get_job(job_id)
    if job is not None and job.tenant_id == principal.tenant_id:
        return job.to_dict()
    # ARCH-003: fall back to the durable record so a job that outlived its
    # in-memory entry (retention cleanup, or a backend restart) is still visible.
    record = read_job(principal.tenant_id, job_id)
    if record is not None:
        return record
    raise HTTPException(status_code=404, detail="Scan job not found")


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
def latest_scan_report(
    principal: Principal = Depends(require_role("viewer")),
    include_files: bool = Query(default=True),
) -> dict:
    report = read_scan_report(principal.tenant_id)
    if report is None:
        raise HTTPException(status_code=404, detail="No saved scan report found")
    return {"report": report if include_files else _compact_scan_report(report)}


@app.get("/api/history/{scan_id}/report")
def saved_scan_report(
    scan_id: str,
    principal: Principal = Depends(require_role("viewer")),
    include_files: bool = Query(default=True),
) -> dict:
    report = read_scan_report(principal.tenant_id, scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Saved scan report not found")
    return {"report": report if include_files else _compact_scan_report(report)}


@app.get("/api/findings")
def findings_index(
    principal: Principal = Depends(require_role("viewer")),
    status: str = Query(default="", max_length=40),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict:
    return {"findings": list_findings(principal.tenant_id, status=status, limit=limit)}


@app.get("/api/inventory")
def inventory_index(
    principal: Principal = Depends(require_role("viewer")),
    risk: str = Query(default="", max_length=20),
    source: str = Query(default="", max_length=40),
    framework: str = Query(default="", max_length=200),
    finding_type: str = Query(default="", max_length=160),
    protected: bool | None = Query(default=None),
    q: str = Query(default="", max_length=200),
    extension: str = Query(default="", max_length=20),
    sort: str = Query(default="risk_score", max_length=20),
    after: str = Query(default="", max_length=512),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    """S-C: keyset-paginated file inventory. The DB filters/sorts/searches so the
    browser fetches one page instead of the whole file list."""
    return list_inventory(
        principal.tenant_id, risk=risk, source=source, framework=framework,
        finding_type=finding_type, protected=protected, q=q, extension=extension,
        sort=sort, cursor=after, limit=limit,
    )


@app.get("/api/inventory/export")
def inventory_export(
    principal: Principal = Depends(require_role("viewer")),
    format: str = Query(default="csv", pattern="^(csv|ndjson)$"),
    risk: str = Query(default="", max_length=20),
    source: str = Query(default="", max_length=40),
    framework: str = Query(default="", max_length=200),
    finding_type: str = Query(default="", max_length=160),
    protected: bool | None = Query(default=None),
    q: str = Query(default="", max_length=200),
    extension: str = Query(default="", max_length=20),
) -> StreamingResponse:
    """S-G: tenant-scoped keyset export with bounded DB and response chunks."""
    if not inventory_export_ready(principal.tenant_id):
        raise HTTPException(
            status_code=409,
            detail=(
                "Streaming export requires a complete normalized inventory. "
                "Run the normalized scan backfill and retry; report-blob fallback is intentionally disabled."
            ),
        )
    filters = {
        "risk": risk, "source": source, "framework": framework,
        "finding_type": finding_type, "protected": protected, "q": q,
        "extension": extension,
    }
    filename, media_type = inventory_export_response_metadata(principal.tenant_id, format)
    audit(
        principal.tenant_id,
        principal.subject,
        "inventory.export.started",
        {"format": format, "filtered": any(value not in ("", None) for value in filters.values())},
    )
    return StreamingResponse(
        inventory_export_stream(principal.tenant_id, format, **filters),
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
            "X-Content-Type-Options": "nosniff",
            "X-Sentro-Export-Order": "asset-id-asc",
        },
    )


@app.get("/api/inventory/facets")
def inventory_facet_index(principal: Principal = Depends(require_role("viewer"))) -> dict:
    return inventory_facets(principal.tenant_id)


@app.get("/api/inventory/{asset_id}")
def inventory_asset_detail(asset_id: str, principal: Principal = Depends(require_role("viewer"))) -> dict:
    asset = get_inventory_asset(principal.tenant_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Inventory asset not found")
    return {"asset": asset}


@app.get("/api/findings/{finding_id}")
def finding_detail(finding_id: str, principal: Principal = Depends(require_role("viewer"))) -> dict:
    finding = get_finding(principal.tenant_id, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    framework = normalize_framework_id(finding.get("framework"))
    detail = build_nist_finding_detail(finding) if framework == "nist_sp800_60_enterprise" else {"summary": {"display_name": get_finding_display_name(finding), "framework": framework}}
    finding["display_name"] = finding.get("display_name") or get_finding_display_name(finding)
    return {"finding": finding, "framework": framework, "detail": detail}


@app.post("/api/findings/detail")
def finding_detail_preview(payload: dict, principal: Principal = Depends(require_role("viewer"))) -> dict:
    _ = principal
    finding = payload.get("finding") if isinstance(payload, dict) else {}
    if not isinstance(finding, dict):
        raise HTTPException(status_code=400, detail="finding must be an object")
    framework = normalize_framework_id(finding.get("framework"))
    finding["display_name"] = finding.get("display_name") or get_finding_display_name(finding)
    detail = build_nist_finding_detail(finding) if framework == "nist_sp800_60_enterprise" else {"summary": {"display_name": finding["display_name"], "framework": framework}}
    return {"finding": finding, "framework": framework, "detail": detail}


@app.patch("/api/findings/{finding_id}/status")
def finding_status_update(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_role("analyst"))) -> dict:
    return _finding_lifecycle_action(finding_id, "status", payload, principal)


@app.post("/api/findings/{finding_id}/assign")
def finding_assign(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_role("analyst"))) -> dict:
    return _finding_lifecycle_action(finding_id, "assign", payload, principal)


@app.post("/api/findings/{finding_id}/comment")
def finding_comment(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_role("analyst"))) -> dict:
    return _finding_lifecycle_action(finding_id, "comment", payload, principal)


@app.post("/api/findings/{finding_id}/suppress")
def finding_suppress(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_role("analyst"))) -> dict:
    return _finding_lifecycle_action(finding_id, "suppress", payload, principal)


@app.post("/api/findings/{finding_id}/false-positive")
def finding_false_positive(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_role("analyst"))) -> dict:
    return _finding_lifecycle_action(finding_id, "false-positive", payload, principal)


@app.post("/api/findings/{finding_id}/risk-acceptance")
def finding_risk_acceptance(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_role("analyst"))) -> dict:
    return _finding_lifecycle_action(finding_id, "risk-acceptance", payload, principal)


@app.post("/api/findings/{finding_id}/resolve")
def finding_resolve(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_role("analyst"))) -> dict:
    return _finding_lifecycle_action(finding_id, "resolve", payload, principal)


@app.post("/api/findings/{finding_id}/reopen")
def finding_reopen(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_role("analyst"))) -> dict:
    return _finding_lifecycle_action(finding_id, "reopen", payload, principal)


@app.post("/api/findings/{finding_id}/validate")
def finding_validate(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_role("analyst"))) -> dict:
    return _finding_lifecycle_action(finding_id, "validate", payload, principal)


@app.get("/api/findings/{finding_id}/history")
def finding_history(finding_id: str, principal: Principal = Depends(require_role("viewer"))) -> dict:
    history = get_finding_history(principal.tenant_id, finding_id)
    if history is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"history": history}


@app.get("/api/findings/{finding_id}/occurrences")
def finding_occurrences(finding_id: str, principal: Principal = Depends(require_role("viewer"))) -> dict:
    occurrences = get_finding_occurrences(principal.tenant_id, finding_id)
    if occurrences is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"occurrences": occurrences}


def _finding_lifecycle_action(finding_id: str, action: str, payload: FindingLifecyclePayload, principal: Principal) -> dict:
    try:
        finding = update_finding_lifecycle(principal.tenant_id, finding_id, action, payload.model_dump(), principal.subject)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding": finding}


@app.patch("/api/history/{scan_id}/findings/workflow")
def finding_workflow_update(
    scan_id: str,
    payload: FindingWorkflowUpdate,
    principal: Principal = Depends(require_role("analyst")),
) -> dict:
    try:
        finding = update_finding_workflow(
            principal.tenant_id,
            scan_id,
            {"path": payload.path, "type": payload.type, "fingerprint": payload.fingerprint},
            payload.model_dump(exclude={"path", "type", "fingerprint"}),
            principal.subject,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found in saved scan report")
    return {"finding": finding}


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


def _duplicate_hash_paths(report: dict | None) -> list[dict]:
    files = report.get("files", []) if isinstance(report, dict) else []
    grouped: dict[str, list[dict]] = {}
    seen: set[tuple[str, str]] = set()
    for file_record in files:
        if not isinstance(file_record, dict):
            continue
        sha256 = _file_hash_value(file_record)
        key = _file_compare_key(file_record)
        if not sha256 or not key or (sha256, key) in seen:
            continue
        seen.add((sha256, key))
        grouped.setdefault(sha256, []).append(file_record)

    duplicate_groups: list[dict] = []
    for sha256, hash_files in grouped.items():
        if len(hash_files) < 2:
            continue
        paths = []
        keys = []
        for file_record in sorted(hash_files, key=lambda item: _file_compare_key(item)):
            keys.append(_file_compare_key(file_record))
            paths.append(
                {
                    "key": _file_compare_key(file_record),
                    "name": file_record.get("name") or file_record.get("path") or "Unknown file",
                    "path": file_record.get("path") or file_record.get("full_path") or "",
                    "source": file_record.get("source") or file_record.get("share") or "",
                }
            )
        duplicate_groups.append(
            {
                "hash": sha256,
                "count": len(paths),
                "name": paths[0].get("name") or "Duplicate content",
                "keys": keys,
                "paths": paths[:20],
            }
        )

    duplicate_groups.sort(key=lambda item: (-int(item.get("count") or 0), str(item.get("name") or "").lower()))
    return duplicate_groups


@app.get("/api/history/hash-changes")
def scan_hash_changes(principal: Principal = Depends(require_role("viewer"))) -> dict:
    history = read_scan_history(principal.tenant_id, limit=2)
    if len(history) < 2:
        latest_report = read_scan_report(principal.tenant_id, history[-1].get("scan_id")) if history else None
        duplicate_hash_paths = _duplicate_hash_paths(latest_report)
        return {
            "algorithm": "SHA-256",
            "latest_scan_id": history[-1].get("scan_id") if history else "",
            "previous_scan_id": "",
            "changed": [],
            "changed_count": 0,
            "added_count": 0,
            "removed_count": 0,
            "duplicate_hash_paths": duplicate_hash_paths[:100],
            "duplicate_hash_path_count": len(duplicate_hash_paths),
        }

    previous_item, latest_item = history[-2], history[-1]
    previous_report = read_scan_report(principal.tenant_id, previous_item.get("scan_id"))
    latest_report = read_scan_report(principal.tenant_id, latest_item.get("scan_id"))
    previous_files = _hash_index(previous_report)
    latest_files = _hash_index(latest_report)
    duplicate_hash_paths = _duplicate_hash_paths(latest_report)

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
        "duplicate_hash_paths": duplicate_hash_paths[:100],
        "duplicate_hash_path_count": len(duplicate_hash_paths),
    }


@app.get("/api/tenants")
def tenant_portfolio(principal: Principal = Depends(require_role("admin"))) -> dict:
    tenants = list_tenants() if _is_platform_admin(principal) else list_tenants(principal.tenant_id)
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


def _login_ip_rate_key(request: Request) -> str:
    # M4: distinct namespace ("ip:") so the per-IP aggregate cannot collide with a
    # per-(IP,username) key.
    client = request.client.host if request.client else "unknown"
    return f"ip:{client}"


def _too_many_login_failures(key: str) -> bool:
    return count_login_failures(key, LOGIN_WINDOW_SECONDS) >= LOGIN_MAX_ATTEMPTS


def _too_many_ip_login_failures(key: str) -> bool:
    return count_login_failures(key, LOGIN_WINDOW_SECONDS) >= LOGIN_IP_MAX_ATTEMPTS


def _record_login_failure(key: str) -> None:
    record_login_failure(key, LOGIN_WINDOW_SECONDS)


def _clear_login_failures(key: str) -> None:
    clear_login_failures(key)



def _is_platform_admin(principal: Principal) -> bool:
    # Single source of truth in backend.security (SC-15).
    return is_platform_admin(principal)


def _can_manage_tenant(principal: Principal, tenant_id: str) -> bool:
    return _is_platform_admin(principal) or principal.tenant_id == tenant_id


def _require_platform_admin(principal: Principal) -> None:
    if not _is_platform_admin(principal):
        raise HTTPException(status_code=403, detail="Platform admin access required")


def _mask_secret(value: str) -> str:
    value = str(value or "")
    if not value:
        return ""
    return f"{value[:8]}...{value[-4:]}" if len(value) > 14 else "****"


def _safe_operation_error(message: str, exc: Exception) -> HTTPException:
    raw = str(exc or "")
    lowered = raw.lower()
    code = "operation_failed"
    hint = "Check the target, credentials, and scan scope, then retry."
    if isinstance(exc, FileNotFoundError) or "no such file or directory" in lowered or "cannot find the path" in lowered:
        code = "scan_path_not_found"
        message = "Scan path was not found"
        hint = "Generate the synthetic dataset or select an existing local folder, SMB share, or endpoint path, then retry."
    elif "pysmb" in lowered:
        code = "missing_dependency"
        hint = "Install requirements.txt on the DSPM backend host before running SMB file-server scans."
    elif "pywinrm" in lowered:
        code = "missing_dependency"
        hint = "Install requirements.txt on the DSPM backend host before running WinRM endpoint scans."
    elif "access denied" in lowered or "unauthorized" in lowered:
        code = "access_denied"
        hint = "Use a credential that is local admin on the target and can read the selected paths."
    elif "winrm" in lowered:
        code = "endpoint_unreachable"
        hint = "Verify WinRM service, firewall, DNS/IP reachability, and the credential."
    elif "smb" in lowered or "connection" in lowered or "timed out" in lowered:
        code = "file_server_unreachable"
        hint = "Verify the file-server name/IP, TCP 445 reachability, share access, domain, and credential."
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
    # M12: single source of truth for "is this a permissible scan-target address",
    # shared with the collectors' resolve-and-pin connect guard (collectors/net_guard).
    for address in addresses:
        reason = ip_disallowed_reason(address, allow_private)
        if reason:
            raise HTTPException(status_code=400, detail=f"Target address is not allowed: {reason}")

def _safe_tenant(tenant_id: str) -> str:
    safe = "".join(ch for ch in tenant_id.strip() if ch.isalnum() or ch in {"-", "_"}) or "default"
    return safe


def _valid_registration_code(tenant_id: str, registration_code: str) -> bool:
    tenant = get_tenant(tenant_id)
    expected = tenant.get("registration_code", "") if tenant else ""
    if not expected:
        return False
    return hmac.compare_digest(registration_code.strip(), expected)


def _hash_invite_token(token: str) -> str:
    # M5: invite tokens are high-entropy random secrets; store/lookup by sha256 so
    # the plaintext token never lives in the database.
    return hashlib.sha256((token or "").strip().encode("utf-8")).hexdigest()


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


def _compact_scan_report(report: dict) -> dict:
    """Metadata-only scan payload used by the windowed console.

    Full reports remain available to explicit API callers. The compact form
    preserves summaries/diagnostics but replaces the unbounded file array with
    an omission marker so browsers never deserialize it accidentally.
    """
    compact = dict(report or {})
    files = report.get("files") if isinstance(report, dict) else []
    files = files if isinstance(files, list) else []
    file_count = len(files) or int((compact.get("summary") or {}).get("total_files") or 0)
    sample_count = sum(
        1 for file_obj in files
        if re.search(
            r"(^|[\\/])enterprise_test_data([\\/]|$)|(^|[\\/])README_enterprise_dataset\.md$|(^|[\\/])_manifest\.json$",
            str(file_obj.get("path") or file_obj.get("full_path") or file_obj.get("name") or ""),
            flags=re.IGNORECASE,
        )
    )
    compact["files"] = []
    compact["files_omitted"] = True
    compact["file_count"] = file_count
    compact["result_file_count"] = file_count
    compact["result_truncated"] = bool(file_count)
    compact["is_demo_sample"] = bool(compact.get("is_demo_sample") or (files and sample_count / len(files) >= 0.5))
    return compact


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
    warnings: list[dict] = []
    try:
        data["alerts"] = evaluate_alerts(principal.tenant_id, data)
    except Exception as exc:
        data["alerts"] = []
        warnings.append({"stage": "alerts", "error": type(exc).__name__})
    if payload.save_report:
        try:
            report_id = str(data.get("scan_id") or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f"))
            generate_report(data, REPORT_DIR / f"{principal.tenant_id}_{report_id}.json")
        except Exception as exc:
            warnings.append({"stage": "report_export", "error": type(exc).__name__})
    if COPILOT_ENABLED:
        try:
            from backend.copilot.insight_hooks import on_scan_complete

            on_scan_complete(principal.tenant_id, scan_id)
        except Exception as exc:
            warnings.append({"stage": "copilot_insights", "error": type(exc).__name__})
    if warnings:
        data["scan_warnings"] = warnings
        try:
            audit(principal.tenant_id, principal.subject, "scan.secondary_operations_degraded", {"scan_id": scan_id, "warnings": warnings})
        except Exception:
            pass


def _apply_compliance(data: dict, payload: ScanRequest | EndpointScanRequest) -> dict:
    return enrich_report_with_compliance(
        data,
        bool(getattr(payload, "compliance_enabled", False)),
        getattr(payload, "compliance_frameworks", []),
    )


def _persist_compliance_scan(data: dict, payload: ScanRequest | EndpointScanRequest, principal: Principal) -> None:
    _apply_compliance(data, payload)
    _persist_scan(data, payload, principal)


def _analyze_endpoint_records(report: DSPMDiscoveryEngine, records: list[dict], job=None, floor: int = 70) -> list[dict]:
    """Analyze endpoint records with the same adaptive pool as file scans."""
    # Keep the helper's small duck-typed contract for tests and integrations
    # that supply only _analyze_record. Real discovery engines take the adaptive
    # branch below.
    if not hasattr(report, "config") or not hasattr(report, "_analyze_records"):
        analyzed: list[dict] = []
        total = max(len(records), 1)
        for index, record in enumerate(records, start=1):
            if job and job.cancel_requested:
                raise RuntimeError("Scan cancelled")
            analyzed.append(report._analyze_record(record))
            if job and (index % 10 == 0 or index == len(records)):
                job.progress = max(job.progress, min(90, floor + int((index / total) * (90 - floor))))
                job.message = f"Analyzing endpoint files {index}/{len(records)}"
        return analyzed

    prior_cancel = report.config.cancel_check
    prior_progress = report.config.progress_callback

    if job:
        report.config.cancel_check = lambda: job.cancel_requested

        def update_progress(stage: str, completed: int, total: int) -> None:
            if stage != "analyzing":
                return
            total_n = max(int(total or 0), 1)
            completed_n = max(0, min(int(completed or 0), total_n))
            job.progress = max(job.progress, min(90, floor + int((completed_n / total_n) * (90 - floor))))
            job.message = f"Analyzing endpoint files {completed_n}/{len(records)}"

        report.config.progress_callback = update_progress

    try:
        return report._analyze_records(records)
    finally:
        report.config.cancel_check = prior_cancel
        report.config.progress_callback = prior_progress


def _run_endpoint_scan_payload(
    config: WinRMEndpointConfig,
    payload: EndpointScanRequest,
    principal: Principal,
    job=None,
) -> dict:
    if _is_local_endpoint_host(config.host):
        return _run_local_endpoint_scan_payload(config, payload, principal, job)

    report = _endpoint_analysis_engine(config, payload, principal)
    if job:
        job.progress = 8
        job.message = "Enumerating remote endpoint metadata"
    scanner = WinRMEndpointScanner(config)
    collection_diagnostics: dict = {}
    if payload.incremental_enabled and config.read_content:
        # WinRM cannot callback into the server for each file while its
        # PowerShell walk is running. Enumerate size/mtime without content,
        # owner/ACL or hashing, resolve the baseline locally, then fetch only
        # new/changed paths in bounded commands.
        metadata_scanner = WinRMEndpointScanner(
            replace(
                config,
                read_content=False,
                read_acl=False,
                inspect_archives=False,
                hash_files=False,
                read_owner=False,
            )
        )
        with collection_heartbeat(job, ceiling=45):
            metadata_records = metadata_scanner.scan()
        collection_diagnostics = dict(metadata_scanner.last_scan_diagnostics or {})
        records_by_path: dict[str, dict] = {}
        reused_archive_records: list[dict] = []
        changed_paths: list[str] = []
        host_key = config.host or metadata_scanner.last_connection_host
        for record in metadata_records:
            object_key = qualified_object_key("endpoint-winrm", host_key, str(record.get("path") or ""))
            snapshot = report._reuse_probe(
                object_key,
                int(record.get("size") or 0),
                str(record.get("modified_at") or ""),
            )
            path_key = str(record.get("path") or "").casefold()
            if isinstance(snapshot, dict):
                records_by_path[path_key] = apply_reuse_snapshot(record, snapshot, object_key)
                for prior in snapshot.get("archive_records") or []:
                    if not isinstance(prior, dict):
                        continue
                    child_key = str(prior.get("reuse_key") or qualified_object_key(
                        "endpoint-winrm", host_key, str(prior.get("path") or "")
                    ))
                    reused_archive_records.append(
                        apply_reuse_snapshot(prior, reuse_snapshot_from_result(prior), child_key)
                    )
            else:
                changed_paths.append(str(record.get("path") or ""))

        fetch_errors: list[str] = []
        fetch_commands = 0
        for offset in range(0, len(changed_paths), 32):
            if job and job.cancel_requested:
                raise RuntimeError("Scan cancelled")
            chunk = [path for path in changed_paths[offset : offset + 32] if path]
            if not chunk:
                continue
            fetch_commands += 1
            if job:
                job.progress = max(job.progress, min(65, 46 + int((offset / max(len(changed_paths), 1)) * 19)))
                job.message = f"Reading changed endpoint files {min(offset + len(chunk), len(changed_paths))}/{len(changed_paths)}"
            changed_scanner = WinRMEndpointScanner(
                replace(config, paths=chunk, max_depth=1, hash_files=True, read_owner=True)
            )
            try:
                with collection_heartbeat(job, ceiling=65):
                    changed_records = changed_scanner.scan()
            except Exception as exc:
                fetch_errors.append(type(exc).__name__)
                continue
            for record in changed_records:
                path_key = str(record.get("path") or "").casefold()
                record["reuse_key"] = qualified_object_key("endpoint-winrm", host_key, str(record.get("path") or ""))
                records_by_path[path_key] = record

        records = []
        for metadata in metadata_records:
            path_key = str(metadata.get("path") or "").casefold()
            record = records_by_path.get(path_key)
            if record is None:
                record = dict(metadata)
                record["scan_error"] = record.get("scan_error") or "Changed file could not be fetched during incremental scan"
                record["reuse_key"] = qualified_object_key("endpoint-winrm", host_key, str(record.get("path") or ""))
            records.append(record)
        records.extend(reused_archive_records)
        collection_diagnostics.update(
            {
                "incremental_metadata_pass": True,
                "incremental_changed_paths": len(changed_paths),
                "incremental_content_fetch_commands": fetch_commands,
                "incremental_fetch_errors": fetch_errors[:20],
            }
        )
    else:
        # Explicit full scan: one pass, always reads/hashes selected content.
        with collection_heartbeat(job, ceiling=60):
            records = scanner.scan()
        collection_diagnostics = dict(scanner.last_scan_diagnostics or {})
        host_key = config.host or scanner.last_connection_host
        for record in records:
            record["reuse_key"] = qualified_object_key("endpoint-winrm", host_key, str(record.get("path") or ""))
    if job:
        if job.cancel_requested:
            raise RuntimeError("Scan cancelled")
        job.progress = max(job.progress, 70)
        job.message = f"Analyzing {len(records)} endpoint files"
    report.last_scan_diagnostics = collection_diagnostics
    analyzed = _analyze_endpoint_records(report, records, job)
    report._finalize_incremental_diagnostics(analyzed)
    if not config.read_content:
        report.last_scan_diagnostics["incremental"]["content_reads"] = 0
        report.last_scan_diagnostics["incremental"]["delta_ratio"] = 0.0
    extension_counts: dict[str, int] = {}
    for record in records:
        extension = str(record.get("extension") or "no extension").lower()
        extension_counts[extension] = extension_counts.get(extension, 0) + 1
    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "endpoint-winrm",
        "mode": "incremental" if payload.incremental_enabled else "full",
        "summary": report._build_summary(analyzed).to_dict(),
        "files": analyzed,
        "scan_diagnostics": report.last_scan_diagnostics,
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
            "scan_diagnostics": report.last_scan_diagnostics,
        },
    }
    _apply_compliance(data, payload)
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

    report = _endpoint_analysis_engine(config, payload, principal)
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
                reuse_probe=report._reuse_probe if payload.incremental_enabled else None,
                reuse_key_builder=lambda item: qualified_object_key(
                    "endpoint-local",
                    config.host or socket.gethostname(),
                    item,
                ),
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

    collection_diagnostics = {
        **local_scan_diagnostics,
        "missing_paths": missing_paths,
        "scan_errors": scan_errors[:20],
    }
    report.last_scan_diagnostics = collection_diagnostics
    analyzed = _analyze_endpoint_records(report, records, job)
    report._finalize_incremental_diagnostics(analyzed)
    if not config.read_content:
        report.last_scan_diagnostics["incremental"]["content_reads"] = 0
        report.last_scan_diagnostics["incremental"]["delta_ratio"] = 0.0
    extension_counts: dict[str, int] = {}
    for record in records:
        extension = str(record.get("extension") or "no extension").lower()
        extension_counts[extension] = extension_counts.get(extension, 0) + 1

    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "endpoint-local",
        "mode": "incremental" if payload.incremental_enabled else "full",
        "summary": report._build_summary(analyzed).to_dict(),
        "files": analyzed,
        "scan_diagnostics": report.last_scan_diagnostics,
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
            "scan_diagnostics": report.last_scan_diagnostics,
        },
    }
    _apply_compliance(data, payload)
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


def _incremental_probe(tenant_id: str, scope_key: str, enabled: bool):
    """Bind a scan to one tenant/scope without querying on a cold baseline."""

    if not enabled or not scope_key:
        return None
    baseline_available = incremental_baseline_exists(tenant_id, scope_key)
    if not baseline_available:
        return lambda _key, _size, _mtime, _version: {"state": "new"}
    return lambda key, size, mtime, version: probe_incremental_object(
        tenant_id,
        scope_key,
        key,
        size,
        mtime,
        version,
    )


def _file_scan_scope(
    payload: ConnectionRequest,
    server: str,
    allowed_extensions: list[str],
    extension_filter_enabled: bool,
) -> str:
    source = "smb" if server else "local"
    target = server or str((BASE_DIR / (payload.local_path.strip() or "enterprise_test_data")).resolve())
    return incremental_scope_key(
        source,
        target,
        {
            "max_depth": payload.max_depth,
            "allowed_extensions": allowed_extensions,
            "extension_filter_enabled": extension_filter_enabled,
            "include_hidden": payload.include_hidden,
            "include_system": payload.include_system,
            "hidden_filter_enabled": payload.hidden_filter_enabled,
            "system_filter_enabled": payload.system_filter_enabled,
            "include_admin_shares": payload.include_admin_shares,
            "inspect_archives": payload.inspect_archives,
        },
    )


def _endpoint_scan_scope(config: WinRMEndpointConfig) -> str:
    source = "endpoint-local" if _is_local_endpoint_host(config.host) else "endpoint-winrm"
    return incremental_scope_key(
        source,
        config.host or socket.gethostname(),
        {
            "target_username": config.target_username,
            "paths": sorted(config.paths, key=str.lower),
            "max_depth": config.max_depth,
            "read_content": config.read_content,
            "read_acl": config.read_acl,
            "allowed_extensions": sorted(config.allowed_extensions or []),
            "extension_filter_enabled": config.extension_filter_enabled,
            "include_hidden": config.include_hidden,
            "include_system": config.include_system,
            "hidden_filter_enabled": config.hidden_filter_enabled,
            "system_filter_enabled": config.system_filter_enabled,
            "inspect_archives": config.inspect_archives,
        },
    )


def _endpoint_analysis_engine(
    config: WinRMEndpointConfig,
    payload: EndpointScanRequest,
    principal: Principal,
) -> DSPMDiscoveryEngine:
    enabled = bool(payload.incremental_enabled)
    scope_key = _endpoint_scan_scope(config)
    return DSPMDiscoveryEngine(
        ScanConfig(
            tenant_id=principal.tenant_id,
            server="",
            use_sample_when_empty=False,
            compliance_enabled=bool(payload.compliance_enabled),
            compliance_frameworks=list(payload.compliance_frameworks or []),
            asset_overrides=[
                {
                    "pattern": item.pattern.strip(),
                    "level": item.level.strip().upper(),
                    "reason": item.reason.strip(),
                }
                for item in payload.asset_overrides
                if item.pattern.strip()
            ],
            incremental_enabled=enabled,
            incremental_scope=scope_key,
            baseline_probe=_incremental_probe(principal.tenant_id, scope_key, enabled),
        )
    )


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

    incremental_enabled = bool(getattr(payload, "incremental_enabled", True))
    scope_key = _file_scan_scope(payload, server, allowed_extensions, extension_filter_enabled)

    return ScanConfig(
        tenant_id=tenant_id,
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
        compliance_enabled=bool(getattr(payload, "compliance_enabled", False)),
        compliance_frameworks=list(getattr(payload, "compliance_frameworks", []) or []),
        asset_overrides=[
            {
                "pattern": item.pattern.strip(),
                "level": item.level.strip().upper(),
                "reason": item.reason.strip(),
            }
            for item in getattr(payload, "asset_overrides", [])
            if item.pattern.strip()
        ],
        incremental_enabled=incremental_enabled,
        incremental_scope=scope_key,
        baseline_probe=_incremental_probe(tenant_id, scope_key, incremental_enabled),
    )


def _prepare_local_scan_data(payload: ConnectionRequest) -> None:
    """Make the built-in synthetic scan work on a fresh checkout.

    Custom local paths are never created implicitly; those return a useful,
    actionable API error instead of the former generic "Scan failed" message.
    """
    if payload.server.strip():
        return
    relative_path = payload.local_path.strip() or "enterprise_test_data"
    target = (BASE_DIR / relative_path).resolve()
    if target.exists():
        return
    if relative_path.replace("\\", "/").strip("/") == "enterprise_test_data":
        generate_enterprise_test_data(target, 10)
        return
    raise FileNotFoundError(f"Local scan path does not exist: {relative_path}")


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
        hash_files=payload.read_content,
        read_owner=True,
    )
