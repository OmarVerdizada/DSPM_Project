from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import json
import hmac
import ipaddress
import os
import platform
import re
import secrets
import socket
import threading
import time
from contextlib import asynccontextmanager, contextmanager, nullcontext, suppress
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, model_validator

# C5: the network boundary is checked before any other backend module loads - an unsafe
# production configuration refuses to start, it is not logged (backend/deployment_boundary).
from backend import deployment_boundary

deployment_boundary.enforce(deployment_boundary.trusted_hosts_setting(), deployment_boundary.cors_origins_setting())

from backend.alerts import evaluate_alerts
from backend.client_address import request_address, request_scheme
from backend.errors import client_message, new_reference
from backend.evidence import without_evidence
from backend.permissions import (
    AUTHENTICATED,
    BUILTIN_ROLES,
    CUSTOM_ROLE_NAME,
    is_known_role,
    permission_catalogue,
    role_catalogue,
    validate_custom_role,
)
from backend.partitioned_scan import (
    continue_partitioned_scan,
    enqueue_partitioned_scan,
    follow_partitioned_scan,
    partition_max_files,
    partitioned_scans_enabled,
    queued_execution,
    run_partitioned_scan,
    start_partitioned_scan,
)
from backend.partitioned_scan import register_unit_runner as partitioned_register_unit_runner
from backend.reporting.router import router as reporting_router
from backend.compliance_service import enrich_report_with_compliance, load_compliance_profiles, normalize_framework_ids
from backend.finding_contracts import build_nist_finding_detail, get_finding_display_name, normalize_framework_id
from backend.jobs import cleanup_jobs, collection_heartbeat, create_job, create_scan_job, get_job
from backend.inventory_export import inventory_export_response_metadata, inventory_export_stream
from backend.security import (
    REFRESH_COOKIE,
    REFRESH_TTL_SECONDS,
    TOKEN_TTL_SECONDS,
    Principal,
    authenticate_user,
    create_token,
    generate_api_key,
    has_permission,
    hash_password,
    is_platform_admin,
    issue_refresh_token,
    principal_permissions,
    require_principal,
    role_permissions_in,
    require_permission,
    revoke_token,
    rotate_refresh_token,
    sanitize_username,
)
from backend.security import _token_jti
from backend.store import (
    allocate_account_key,
    create_scan_partitions,
    read_partitioned_scan,
    register_partitioned_scan,
    delete_directory_settings,
    find_user_by_login,
    get_directory_settings,
    save_directory_settings,
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
    verify_audit_chain,
    read_job,
    read_scan_history,
    read_scan_report,
    read_scan_report_compact,
    compact_scan_report,
    recover_interrupted_jobs,
    record_login_failure,
    take_throttle_slot,
    rotate_registration_code,
    create_registration_invite,
    redeem_registration_invite,
    list_registration_invites,
    revoke_registration_invite,
    create_api_key_record,
    list_api_keys,
    revoke_api_key,
    save_scan_history,
    save_scan_profile,
    list_scan_profiles,
    delete_scan_profile,
    create_scan_schedule,
    list_scan_schedules,
    update_scan_schedule,
    delete_scan_schedule,
    scan_request_is_resumable,
    create_suppression_rule,
    list_suppression_rules,
    get_suppression_rule,
    update_suppression_rule,
    delete_suppression_rule,
    suppression_rules_for_scan,
    tenant_exists,
    get_finding,
    get_finding_history,
    get_finding_occurrences,
    get_inventory_asset,
    inventory_facets,
    inventory_export_ready,
    incremental_baseline_exists,
    list_findings,
    list_remediation_findings,
    list_inventory,
    probe_incremental_object,
    revoke_refresh_tokens_for_user,
    revoke_sessions_for_user,
    update_finding_lifecycle,
    update_finding_workflow,
    update_user_password,
    update_user_profile,
    update_user_avatar,
    get_app_setting,
    set_app_setting,
    update_user_role,
    update_user_active,
)
from backend import credential_preflight
from backend.vault import CredentialVault, credential_listing, rotation_days
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
from collectors import scan_scope
from collectors.file_scanner import normalize_extension_filter, scan_directory
from collectors.net_guard import resolve_addresses
from backend import target_scope
from backend import directory, identity
from backend.permissions import PERSON_ONLY_PERMISSIONS
from collectors.win_security import security_for_path
from collectors.winrm_endpoint_scanner import (
    ENDPOINT_PATH_ALIASES,
    WinRMEndpointConfig,
    WinRMEndpointScanner,
    activate_local_winrm,
    normalize_certificate_thumbprint,
    normalize_endpoint_target_paths,
)
from collectors.winrm_endpoint_scanner import _winrm_ssl_required as winrm_ssl_required
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig, product_private_paths
from discovery.suppression import MAX_SUPPRESSION_RULES
from discovery.incremental import (
    apply_reuse_snapshot,
    incremental_scope_key,
    qualified_object_key,
    reuse_snapshot_from_result,
)
from backend.reporting.posture import PostureInputs, compute_posture, posture_from_summary
from backend.store import posture_inputs, set_request_origin
from risk.risk_engine import get_risk_rules
from scripts.generate_enterprise_test_data import generate as generate_enterprise_test_data
from scripts.generate_enterprise_test_data import is_generated_dataset
from scripts.report import generate_report

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
vault = CredentialVault()
PROTECTED_USERS = {"admin"}
# C5: the console is served by this backend, so it needs no cross-origin access. The
# localhost list is a development convenience; production starts with none and refuses a
# wildcard, local or plain-HTTP origin (checked at the top of this module).
DEFAULT_CORS_ORIGINS = list(deployment_boundary.DEVELOPMENT_CORS_ORIGINS)
CORS_ORIGINS = deployment_boundary.cors_origins_setting()
TRUSTED_HOSTS = deployment_boundary.trusted_hosts_setting()
ENDPOINT_INCREMENTAL_FETCH_BATCH_SIZE = 256
# A file whose text is larger than this is read up to here and marked truncated. The
# collector's own default is the local one - a hundred megabytes - which one file can
# spend on its own, and every byte of it crosses WinRM and is held on both sides (B4).
ENDPOINT_DEFAULT_MAX_FILE_TEXT_BYTES = 5 * 1024 * 1024
# What one fetch command may ask for. A response is held whole on both sides, so this,
# not the file count, is the bound that matters.
ENDPOINT_DEFAULT_FETCH_BATCH_BYTES = 32 * 1024 * 1024


def endpoint_max_file_text_bytes() -> int:
    """How much text an endpoint scan reads from one file (``DSPM_ENDPOINT_MAX_FILE_TEXT_BYTES``).

    Enough for the detectors to classify a file; the record says when it was truncated,
    and reports it as a partial scan of that file rather than a complete one.
    """
    try:
        wanted = int(os.getenv("DSPM_ENDPOINT_MAX_FILE_TEXT_BYTES", str(ENDPOINT_DEFAULT_MAX_FILE_TEXT_BYTES)))
    except ValueError:
        wanted = ENDPOINT_DEFAULT_MAX_FILE_TEXT_BYTES
    return max(64 * 1024, min(wanted, 100 * 1024 * 1024))


def endpoint_fetch_batch_bytes() -> int:
    """How many bytes of file content one endpoint fetch may ask for (``DSPM_ENDPOINT_FETCH_BATCH_BYTES``)."""
    try:
        wanted = int(os.getenv("DSPM_ENDPOINT_FETCH_BATCH_BYTES", str(ENDPOINT_DEFAULT_FETCH_BATCH_BYTES)))
    except ValueError:
        wanted = ENDPOINT_DEFAULT_FETCH_BATCH_BYTES
    return max(1024 * 1024, min(wanted, 512 * 1024 * 1024))


def _endpoint_fetch_batches(paths: list[str], sizes: dict[str, int]) -> list[list[str]]:
    """Cut the paths to fetch into batches bounded by count and by bytes (B4).

    Two hundred and fifty-six files of a megabyte each is a quarter-gigabyte response,
    held whole on the endpoint and again here, so the byte budget decides where a batch
    ends. Each file is capped at what the scan will actually read, and a file that fills
    the budget on its own is a batch of its own rather than a reason to refuse it.
    """
    per_file_cap = endpoint_max_file_text_bytes()
    budget = endpoint_fetch_batch_bytes()
    batches: list[list[str]] = []
    current: list[str] = []
    carried = 0
    for path in paths:
        if not path:
            continue
        size = min(max(0, int(sizes.get(path.casefold(), 0) or 0)), per_file_cap)
        if current and (len(current) >= ENDPOINT_INCREMENTAL_FETCH_BATCH_SIZE or carried + size > budget):
            batches.append(current)
            current, carried = [], 0
        current.append(path)
        carried += size
    if current:
        batches.append(current)
    return batches


ENDPOINT_REUSED_SCANNER_DIAGNOSTIC_FIELDS = (
    "session_reused",
    "session_reuse_count",
    "session_creations",
    "session_negotiations",
    "session_failovers",
    "connection_transport",
    "delivery_mode",
    "delivery_ms",
    "delivery_last_ms",
    "delivery_invocations",
    "delivery_remote_commands",
    "delivery_response_envelopes",
    "delivery_fallback_reason",
    "remote_commands",
    "response_envelopes",
)
LOGIN_WINDOW_SECONDS = int(os.getenv("DSPM_LOGIN_WINDOW_SECONDS", "600"))
LOGIN_MAX_ATTEMPTS = int(os.getenv("DSPM_LOGIN_MAX_ATTEMPTS", "8"))
# M4: an aggregate per-IP failure cap alongside the per-(IP,username) cap, so one
# IP spraying a password across many usernames is throttled even though no single
# (IP,username) counter trips. Higher than the per-user cap to tolerate a shared
# NAT/office IP with a few users and the odd typo.
LOGIN_IP_MAX_ATTEMPTS = int(os.getenv("DSPM_LOGIN_IP_MAX_ATTEMPTS", "30"))


@dataclass(frozen=True)
class RouteThrottle:
    """C8: failures on one route, counted per key; refused once `limit` land inside
    `window_seconds`. Each throttle has its own namespace in the failure table, so a
    failure on one route never counts against another, and the store keeps each key's
    history for its own window (up to its 24-hour horizon)."""

    name: str
    limit: int
    window_seconds: int

    def _key(self, who: str) -> str:
        return f"{self.name}:{who}"

    def exhausted(self, who: str) -> bool:
        return count_login_failures(self._key(who), self.window_seconds) >= self.limit

    def failed(self, who: str) -> None:
        record_login_failure(self._key(who), self.window_seconds)

    def take(self, who: str) -> bool:
        """Count one attempt and say whether it is within the limit - as ONE step, so
        parallel requests cannot all pass the check before any of them is counted."""
        return take_throttle_slot(self._key(who), self.window_seconds, self.limit)

    def clear(self, who: str) -> None:
        clear_login_failures(self._key(who))


# Changing a password checks the current one, so a stolen access token would otherwise
# be an unlimited oracle for the password behind it. Counted per ACCOUNT, wherever the
# attempts come from; a correct password clears it.
PASSWORD_CHANGE_THROTTLE = RouteThrottle(
    "password_change", max(1, int(os.getenv("DSPM_PASSWORD_CHANGE_MAX_FAILURES", "5"))), 900)
# Registration checks an invite or registration code. It is public, so it is counted
# per client address - and a success does not clear it: one valid code must not reset
# the history of an address that has been guessing.
REGISTER_THROTTLE = RouteThrottle(
    "register", max(1, int(os.getenv("DSPM_REGISTER_MAX_FAILURES", "10"))), 3600)
# A refresh cookie cannot be guessed, but it can be REPLAYED, and every replay writes an
# audit row and ends a family. Per client address, generous enough for a console whose
# cookie has simply expired in several tabs at once.
REFRESH_THROTTLE = RouteThrottle(
    "refresh", max(1, int(os.getenv("DSPM_REFRESH_MAX_FAILURES", "30"))), 300)
# Verifying reads a tenant's whole audit trail (1.4 s at 20,000 rows, measured), so it
# is counted per tenant: every verification, not only failed ones.
AUDIT_VERIFY_THROTTLE = RouteThrottle(
    "audit_verify", max(1, int(os.getenv("DSPM_AUDIT_VERIFY_MAX_PER_HOUR", "20"))), 3600)

# How many scan runs the executive dashboard's posture trend plots, and therefore
# how many history rows that endpoint needs to read.
DASHBOARD_TREND_POINTS = 14
ENVIRONMENT = os.getenv("DSPM_ENV", "local").strip().lower()
IS_PRODUCTION = ENVIRONMENT in {"prod", "production"}
# Phase 0 (DB-01): one database authority. Production refuses SQLite, and a
# configured expected identity refuses a mis-pointed DSN. Runs at import so a
# wrong deployment never serves a single request.
from backend import db as _db
from backend import store as store_module
from backend.artifacts import ArtifactCorrupted, ArtifactMissing
from backend.runtime_identity import APP_VERSION

DATABASE_IDENTITY = _db.enforce_database_authority(IS_PRODUCTION)
REPORT_DIR = Path(os.getenv("DSPM_REPORT_DIR", BASE_DIR / "data" / "reports")).resolve()
REPORT_DIR.mkdir(parents=True, exist_ok=True)
# A saved scan's body lives in the ENCRYPTED artifact tier (gzip + Fernet,
# content-addressed, covered by the backup set and by tenant erasure). This
# directory is the pre-artifact-tier copy of the same thing in clear text,
# previews included - 28 full reports, 319 MB, on this tree. Off by default;
# set DSPM_PLAINTEXT_REPORT_EXPORT=1 only if an external tool still reads them.
PLAINTEXT_REPORT_EXPORT = os.getenv("DSPM_PLAINTEXT_REPORT_EXPORT", "0").strip().lower() in {"1", "true", "yes", "on"}


@asynccontextmanager
async def app_lifespan(_: FastAPI):
    # M3: fail CLOSED at startup on a missing (prod) or malformed vault key, before
    # any credential operation. NOT wrapped in try/except - a bad key must abort.
    from backend.vault import validate_vault_key

    validate_vault_key()
    # P4: one idle connection for the life of the server, so a request's own connection
    # is never the last one to close - which on SQLite checkpointed the WAL every time.
    with suppress(Exception):
        from backend import db as _db

        _db.hold_sqlite_open(store_module.DB_PATH)
    # B5: production never writes a plaintext dump of every scanned file. The switch
    # exists for an install with an external reader; enabling it in production is a
    # configuration mistake, and startup says so rather than filling data/ with previews.
    if ENVIRONMENT in {"prod", "production"} and PLAINTEXT_REPORT_EXPORT:
        raise RuntimeError(
            "DSPM_PLAINTEXT_REPORT_EXPORT=1 is refused in production: it writes every "
            "scanned file, previews included, to DSPM_REPORT_DIR as plaintext."
        )
    # C0.2: nor does it serve beside a plaintext copy of its database. A pg_dump left
    # unencrypted in the backup directory outlived every encrypted backup taken after
    # it; refusing to start is what makes somebody look. Not suppressed, like the vault
    # key check above: the refusal is the point.
    if ENVIRONMENT in {"prod", "production"}:
        from backend.backup import backup_dir, plaintext_dump_problem

        problem = plaintext_dump_problem(backup_dir())
        if problem:
            raise RuntimeError(problem)
    with suppress(Exception):
        from backend.housekeeping import plaintext_report_files, report_file_days
        from scripts.logger import get_logger

        existing = plaintext_report_files(REPORT_DIR)
        if existing:
            days = report_file_days()
            get_logger("backend.app").warning(
                "%s plaintext scan report file(s) in %s. They are not written by default any more; %s",
                len(existing), REPORT_DIR,
                f"housekeeping removes each {days} days after it was written (DSPM_RETAIN_REPORT_FILE_DAYS)."
                if days else "DSPM_RETAIN_REPORT_FILE_DAYS=0 keeps them; set a number of days to age them out.",
            )
    # Which build this is, the schema it supports and the database it serves, in the log;
    # and registered on that database, so another build there can be told apart - and
    # an import from another checkout does not upgrade the database under this server.
    with suppress(Exception):
        from backend import migrations as _migrations
        from backend import runtime_identity

        with store_module._connect() as _conn:
            _applied = _migrations.current_revision(_conn)
        runtime_identity.log_startup(_applied)
        runtime_identity.register("server")
    # ARCH-003: at server startup, mark jobs orphaned by a prior process as
    # failed and prune old terminal records. Done here (not at import) so tools
    # and tests that import the app do not mutate persisted job state.
    try:
        from backend.scan_resumer import resume_interval_seconds

        # A job whose scan will be resumed says so; with resuming off, it asks for a re-run.
        recover_interrupted_jobs(resuming=resume_interval_seconds() > 0)
        prune_job_records(30 * 24 * 3600)
    except Exception:
        pass
    # B2.4: a partitioned scan a stopped process left unfinished is continued, once it
    # has been quiet for a partition lease, under the job id it had.
    with suppress(Exception):
        from backend.scan_resumer import start_scan_resumer

        start_scan_resumer(_resume_partitioned_scan)
    # B3: the scans nobody starts - schedules that have fallen due.
    with suppress(Exception):
        from backend.scan_scheduler import start_scan_scheduler

        start_scan_scheduler(_start_scheduled_scan)
    # B5: retention, on the same model - claimed through the database, once a day.
    with suppress(Exception):
        from backend.housekeeping import start_housekeeping

        start_housekeeping(REPORT_DIR)
    with suppress(Exception):
        from backend.search import start_search_reconciler

        start_search_reconciler()
    with suppress(Exception):
        from backend.siem import start_siem_forwarder

        # C4: audit events to the SIEM, when DSPM_SIEM_URL names one.
        start_siem_forwarder()
    with suppress(Exception):
        from backend.alert_delivery import start_alert_deliverer
        from backend.integrations import import_environment

        # D3: alerts to webhooks and e-mail, tickets to Jira and ServiceNow, from a queue.
        import_environment()
        start_alert_deliverer()
    # Runtime feature flags: a persisted admin toggle overrides the env default
    # so the setting survives restarts, and flipping it at runtime needs no
    # restart at all (collectors read the env per call).
    try:
        _apply_persisted_feature_flags()
    except Exception:
        pass
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
    try:
        yield
    finally:
        # The planner's statistics are cheap to refresh at shutdown and
        # expensive to be without at the next start.
        with suppress(Exception):
            from backend import db as _db
            from backend.store import DB_PATH as _db_path

            _db.optimize_sqlite(_db_path)
        with suppress(Exception):
            from backend.scan_resumer import stop_scan_resumer

            stop_scan_resumer()
        with suppress(Exception):
            from backend.scan_scheduler import stop_scan_scheduler

            stop_scan_scheduler()
        with suppress(Exception):
            from backend.housekeeping import stop_housekeeping

            stop_housekeeping()
        with suppress(Exception):
            from backend.siem import stop_siem_forwarder

            stop_siem_forwarder()
        with suppress(Exception):
            from backend.alert_delivery import stop_alert_deliverer

            stop_alert_deliverer()
        with suppress(Exception):
            from backend.search import stop_search_reconciler

            stop_search_reconciler()
        with suppress(Exception):
            from backend import runtime_identity

            runtime_identity.deregister()
        # Close the DB connection pool cleanly on shutdown (no-op on SQLite), and the
        # held SQLite connection last, after optimize and every thread above.
        with suppress(Exception):
            from backend import db

            db.close_pool()
        with suppress(Exception):
            from backend import db

            db.release_sqlite_anchor()


app = FastAPI(
    title="DSPM DLP Discovery API",
    description="Discovers sensitive data on AD file servers and produces DLP-ready risk context.",
    version=APP_VERSION,
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
    lifespan=app_lifespan,
)

if TRUSTED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=TRUSTED_HOSTS)

# 1.5MB of JS and CSS, and JSON pages of 100-200KB, were served uncompressed.
# The 1000-byte floor keeps the small status responses off the compressor.
app.add_middleware(GZipMiddleware, minimum_size=1000)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Tenant-ID"],
)

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
app.include_router(reporting_router)


# C0.4: a database moved to a newer schema while this process runs (another install's
# upgrade, a manual migration) is noticed within DSPM_SCHEMA_CHECK_SECONDS, and from then
# on this build answers its data routes with 503 and the reason instead of writing rows in
# a shape the newer code does not expect. Health and readiness keep answering - readiness
# already reports the mismatch - so the operator sees why. The state is backend.schema_guard's,
# shared with the scan worker and every background writer.
from backend import schema_guard as _schema_guard

_SCHEMA_GUARD: dict = _schema_guard.STATE
_SCHEMA_GUARD_OPEN = {"/api/health", "/api/ready"}


def schema_problem() -> str:
    """Why this build must not serve data now ("" when it may). Cached for the interval."""
    return _schema_guard.problem()


@app.middleware("http")
async def count_requests(request: Request, call_next):
    """D11: every request counted by method and status, and timed - never by path."""
    from backend import metrics

    started = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        metrics.record_request(request.method, status, time.perf_counter() - started)


@app.middleware("http")
async def schema_guard(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and path not in _SCHEMA_GUARD_OPEN:
        problem = schema_problem()
        if problem:
            # The console reads `reason` to tell the operator once, on every page, what
            # happened and what to do; `detail` stays the sentence for everything else.
            revision = _schema_guard.revision()
            return JSONResponse(status_code=503, content={
                "detail": problem, "reason": "schema_mismatch",
                "applied": revision.get("applied"), "expected": revision.get("expected")})
    return await call_next(request)


@app.middleware("http")
async def secure_response_headers(request: Request, call_next):
    # Before the handler runs, so anything it audits carries the origin.
    set_request_origin(
        # C4: the client, not the reverse proxy - X-Forwarded-For is believed only from a
        # peer named in DSPM_TRUSTED_PROXIES (backend.client_address).
        request_address(request),
        request.headers.get("user-agent", ""),
    )
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    if request_scheme(request) == "https" or IS_PRODUCTION:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    response.headers.setdefault("Cache-Control", _cache_control(request, response))
    return response


# C6: everything the console loads is served by the install itself - fonts included - and
# no page carries a style attribute or a <style> block, so the policy names no other origin
# and has no 'unsafe-inline'. Style set from script through the CSSOM is not inline style.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; object-src 'none'; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


def _cache_control(request: Request, response: Response) -> str:
    """C6: a file whose URL carries its version (?v=) never changes under that URL, so the
    browser keeps it for a year; anything else is revalidated every time, so an upgraded
    install never serves a stale page or asset. The API is never stored."""
    path = request.url.path
    if path.startswith("/api/"):
        return "no-store"
    if path.startswith("/static/") and request.query_params.get("v") and response.status_code == 200:
        return "public, max-age=31536000, immutable"
    return "no-cache"


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


def evidence_scoped(route):
    """C3: a route that can return a scanned record returns its evidence only to a caller
    holding `evidence.view`; anyone else gets the record without it (backend.evidence).
    It fails closed - a call it cannot attribute is treated as one without the permission."""

    @functools.wraps(route)
    def wrapper(*args, **kwargs):
        result = route(*args, **kwargs)
        principal = kwargs.get("principal")
        if isinstance(principal, Principal) and has_permission(principal, "evidence.view"):
            return result
        return without_evidence(result)

    wrapper.evidence_scoped = True
    return wrapper


@app.exception_handler(Exception)
async def unexpected_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """C8 / ASVS V7.4.1: an error nobody anticipated gets a generic answer and a
    reference; the detail - which can name paths, tables and library internals - goes
    to the log under that reference, where support can find it."""
    from scripts.logger import get_logger

    reference = new_reference()
    get_logger("backend.app").exception("Unhandled error, reference %s, on %s %s", reference, request.method, request.url.path)
    return JSONResponse(
        {"detail": "The server could not complete this request.", "reference": reference},
        status_code=500,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    # Which field, and what kind of problem - never the value sent or the validator's own
    # words (a validator may quote the input). Without it a refused request said only
    # "check required fields", and an API client had nothing to fix.
    fields = []
    for error in exc.errors()[:10]:
        where = ".".join(str(part)[:60] for part in error.get("loc", ()) if isinstance(part, (str, int)))
        fields.append({"field": where[:200], "problem": str(error.get("type", "invalid"))[:40]})
    return JSONResponse(status_code=400, content={"detail": "Invalid request. Check required fields and formats.",
                                                  "fields": fields})


class SavedCredentialMissing(KeyError):
    """A scan, a connection test or an endpoint action named a saved credential that is
    not there (deleted, or another workspace's). The vault's KeyError reached the generic
    handler as a 500 on the test and endpoint routes and as a 400 "check target,
    credentials" on /api/scan; the database, SFTP and SharePoint routes already said 404."""

    client_safe = True


@app.exception_handler(SavedCredentialMissing)
async def saved_credential_missing_handler(_: Request, __: SavedCredentialMissing) -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": "Saved credential not found"})


@app.exception_handler(InventoryReadUnavailable)
async def inventory_unavailable_handler(_: Request, __: InventoryReadUnavailable) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"detail": "Normalized inventory is temporarily unavailable. Retry shortly."},
        headers={"Retry-After": "5", "Cache-Control": "no-store"},
    )


@app.exception_handler(ArtifactMissing)
async def artifact_missing_handler(_: Request, __: ArtifactMissing) -> JSONResponse:
    """A referenced report body is not in the store (Phase 5, DB-07).

    This is an infrastructure condition, not a bad request: the row is intact
    and the body is elsewhere - typically a database restored without its
    artifact tier. A bare 500 would send the operator hunting through a stack
    trace for a fact this can simply state.
    """
    return JSONResponse(
        status_code=503,
        content={"detail": "A stored report body is missing from the artifact tier. "
                           "Restore the artifact store alongside the database, then run "
                           "`python scripts/db_artifacts.py verify`."},
        headers={"Retry-After": "30", "Cache-Control": "no-store"},
    )


@app.exception_handler(ArtifactCorrupted)
async def artifact_corrupted_handler(_: Request, __: ArtifactCorrupted) -> JSONResponse:
    """A stored body no longer hashes to its content id - it is not served."""
    return JSONResponse(
        status_code=503,
        content={"detail": "A stored report body failed its integrity check and was not "
                           "served. Run `python scripts/db_artifacts.py verify` and restore "
                           "the affected object."},
        headers={"Cache-Control": "no-store"},
    )


class ScanScope(BaseModel):
    """Advanced scan scope (collectors.scan_scope): what a scan leaves out before it reads it.

    Every rule is optional, and an exclusion always wins. On a file server, paths are
    relative to the scan's target - ``Finance/Archive`` under the local folder, or
    ``share/folder`` (or ``\\server\share\folder``) over SMB; on an endpoint, absolute.
    The extension policy (``allowed_extensions``) stays the include side for file types.
    """

    exclude_extensions: list[str] = Field(default_factory=list, max_length=200,
                                          description="Never scan files with these extensions")
    min_size_bytes: int | None = Field(default=None, ge=0, le=scan_scope.MAX_SCOPE_BYTES,
                                       description="Skip files smaller than this")
    max_size_bytes: int | None = Field(default=None, ge=1, le=scan_scope.MAX_SCOPE_BYTES,
                                       description="Skip files larger than this")
    include_paths: list[str] = Field(default_factory=list, max_length=100,
                                     description="Walk only these folders (and what is under them)")
    exclude_paths: list[str] = Field(default_factory=list, max_length=200,
                                     description="Skip these folders or files and everything under them")
    exclude_folder_patterns: list[str] = Field(default_factory=list, max_length=100,
                                               description="Skip any folder whose name matches (* and ?)")
    modified_after: date | None = Field(default=None, description="Skip files last modified before this date (UTC)")

    @field_validator("exclude_extensions")
    @classmethod
    def _clean_extensions(cls, values: list[str]) -> list[str]:
        return scan_scope.clean_extensions(values)

    @field_validator("exclude_folder_patterns")
    @classmethod
    def _clean_patterns(cls, values: list[str]) -> list[str]:
        return scan_scope.clean_patterns(values)

    @field_validator("include_paths", "exclude_paths")
    @classmethod
    def _clean_paths(cls, values: list[str]) -> list[str]:
        # What holds for any target - no wildcard, no "..", no control character; whether a
        # path must be relative or absolute is the scan type's, checked by the request.
        return scan_scope.clean_paths(values, absolute=None)

    @field_validator("modified_after")
    @classmethod
    def _not_in_the_future(cls, value: date | None) -> date | None:
        if value is not None and value > datetime.now(timezone.utc).date():
            raise ValueError("the modified-after date is in the future: no file would be scanned")
        return value

    @model_validator(mode="after")
    def _limits_in_order(self) -> "ScanScope":
        if self.min_size_bytes is not None and self.max_size_bytes is not None \
                and self.min_size_bytes > self.max_size_bytes:
            raise ValueError("the minimum file size is larger than the maximum: no file would be scanned")
        return self

    def canonical(self, *, absolute: bool) -> dict | None:
        """The rules a scan's configuration carries, or None when none is set."""
        return scan_scope.canonical(self.model_dump(mode="json"), absolute=absolute)


class ConnectionRequest(BaseModel):
    server: str = Field(default="", description="AD file server hostname or IP", max_length=255)
    username: str = Field(default="", max_length=160)
    password: str = Field(default="", max_length=512)
    credential_ref: str = Field(default="", max_length=120)
    scan_label: str = Field(default="", max_length=80)
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
    # D1: read the server over SMB 3.1.1 with the session encrypted - required, never
    # downgraded - naming the shares (they cannot be listed over that transport).
    smb_encryption: bool = False
    smb_shares: list[str] = Field(default_factory=list, max_length=200)
    # Advanced scan scope: part of the scan's definition, so a resumed, scheduled or
    # queued run - and every incremental one - applies exactly these rules.
    scope: ScanScope = Field(default_factory=ScanScope)

    @field_validator("smb_shares")
    @classmethod
    def _clean_share_names(cls, values: list[str]) -> list[str]:
        names = [re.sub(r"[\x00-\x1f\x7f\\/]", "", str(value or "")).strip()[:80] for value in values]
        return [name for name in names if name]

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

    @model_validator(mode="after")
    def _scope_paths_for_target(self) -> "ConnectionRequest":
        """A file server's scope paths are relative to its target: an SMB scan's are
        ``share/folder`` - a UNC path naming this server is turned into one - and a local
        scan's are folders under its local path."""
        scope = self.scope
        if not (scope.include_paths or scope.exclude_paths):
            return self
        server = "" if _is_local_endpoint_host(self.server) else self.server.strip()

        def tidy(values: list[str]) -> list[str]:
            cleaned = scan_scope.clean_paths(values, absolute=False)
            if server:
                return [scan_scope.unc_to_share_path(value, server) for value in cleaned]
            for value in cleaned:
                if value.startswith(("\\\\", "//")):
                    raise ValueError(f"{value!r}: a local scan's paths are folders under its local path, "
                                     "not network paths")
            return cleaned

        self.scope = scope.model_copy(update={"include_paths": tidy(scope.include_paths),
                                              "exclude_paths": tidy(scope.exclude_paths)})
        return self


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
    # W2.6: how much of each file the scan reads - inventory (metadata and access only),
    # standard (content within the caps), full (standard, every framework, archives).
    scan_level: Literal["inventory", "standard", "full"] = "standard"
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
    scan_label: str = Field(default="", max_length=80)
    paths: list[str] = Field(default_factory=lambda: ["desktop", "documents", "downloads"], max_length=40)
    max_depth: int = Field(default=12, ge=1, le=12)
    read_content: bool = True
    read_acl: bool = True
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
    # Advanced scan scope, with absolute paths; the folders to walk are ``paths``.
    scope: ScanScope = Field(default_factory=ScanScope)
    # C0.1: how this scan reaches the endpoint. The collector has spoken TLS all
    # along; until these existed the API could not ask for it, so every scan and
    # preflight the console started was cleartext HTTP on 5985 - and an install
    # that requires TLS could only fail, mid-scan.
    use_ssl: bool = Field(default=False, description="Carry WinRM over TLS (port 5986 by default)")
    port: int | None = Field(default=None, ge=1, le=65535)
    cert_trust: Literal["system", "ca_bundle", "thumbprint", "insecure"] = Field(
        default="system",
        description="How the endpoint's certificate is trusted: the host's trust store, a CA "
                    "bundle, a pinned thumbprint, or (non-production only) nothing.",
    )
    ca_bundle: str = Field(default="", max_length=400)
    cert_thumbprint: str = Field(default="", max_length=200)
    kerberos: Literal["", "off", "prefer", "require"] = Field(
        default="",
        description="Authentication policy for this scan; empty uses the install default "
                    "(DSPM_WINRM_KERBEROS). 'require' never falls back to NTLM.",
    )

    @field_validator("cert_thumbprint")
    @classmethod
    def _validate_thumbprint(cls, value: str) -> str:
        try:
            return normalize_certificate_thumbprint(value)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("ca_bundle")
    @classmethod
    def _validate_ca_bundle(cls, value: str) -> str:
        cleaned = re.sub(r"[\x00-\x1f\x7f]", "", value or "").strip()
        if cleaned and not Path(cleaned).is_file():
            raise ValueError(
                "The CA bundle must be a file on the machine running Sentro; "
                f"this path is not: {cleaned}"
            )
        return cleaned

    @model_validator(mode="after")
    def _scope_paths_on_the_endpoint(self) -> "EndpointScanRequest":
        """An endpoint's folders are chosen by ``paths``; its scope only leaves things out,
        by absolute path."""
        if self.scope.include_paths:
            raise ValueError("On an endpoint, the folders to scan are its paths; scope can only leave folders out")
        if self.scope.exclude_paths:
            self.scope = self.scope.model_copy(
                update={"exclude_paths": scan_scope.clean_paths(self.scope.exclude_paths, absolute=True)})
        return self

    @model_validator(mode="after")
    def _validate_endpoint_transport(self) -> "EndpointScanRequest":
        """Refuse a transport combination before anything connects.

        Each of these used to surface either as a mid-scan RuntimeError or - worse -
        as a scan that quietly did something other than what was asked for.
        """

        if self.cert_trust != "system" and not self.use_ssl:
            raise ValueError("A certificate trust choice only applies when the scan uses TLS.")
        if self.cert_trust == "ca_bundle" and not self.ca_bundle:
            raise ValueError("Choose the CA bundle file that signs the endpoint's certificate.")
        if self.cert_trust == "thumbprint" and not self.cert_thumbprint:
            raise ValueError("Paste the endpoint certificate's thumbprint to pin it.")
        if self.cert_trust != "thumbprint" and self.cert_thumbprint:
            raise ValueError("A thumbprint was given but the trust choice is not 'thumbprint'.")
        if self.cert_trust != "ca_bundle" and self.ca_bundle:
            raise ValueError("A CA bundle was given but the trust choice is not 'ca_bundle'.")
        if self.cert_trust == "insecure" and IS_PRODUCTION:
            raise ValueError(
                "Scanning without checking the endpoint's certificate is refused in production. "
                "Pin the certificate's thumbprint, or point the scan at a CA bundle that signs it."
            )
        if not self.use_ssl and winrm_ssl_required() and not _is_local_endpoint_host(self.host):
            raise ValueError(
                "This install requires WinRM over TLS. Turn on TLS for this scan (port 5986 by "
                "default) and choose how the endpoint's certificate is trusted."
            )
        return self

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


class SuppressionRulePayload(BaseModel):
    """What a scan must not report again (B6)."""

    finding_type: str = Field(default="", max_length=80)
    source: str = Field(default="", max_length=40)
    path_pattern: str = Field(default="", max_length=1024)
    fingerprint: str = Field(default="", max_length=128)
    reason: str = Field(default="", max_length=500)
    expires_at: str = Field(default="", max_length=40)

    @field_validator("finding_type", "source", "path_pattern", "fingerprint", "reason", "expires_at")
    @classmethod
    def _clean_rule_text(cls, value: str) -> str:
        return re.sub(r"[\x00-\x1f\x7f]", "", value or "").strip()


class SuppressionRuleUpdate(BaseModel):
    active: bool | None = None
    reason: str | None = Field(default=None, max_length=500)
    expires_at: str | None = Field(default=None, max_length=40)


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
    # B6: dismissing a finding can also write the rule that stops the next scan
    # creating it again. Off unless asked for: a dismissal is about one finding
    # until somebody says it is about more.
    suppress_future: bool = False
    suppression_scope: str = Field(default="file", max_length=20)

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
    # C2: the sign-in name (or, with no workspace, the account key), and the workspace
    # (tenant) it belongs to - optional, so every existing account signs in as before.
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=200)
    workspace: str = Field(default="", max_length=80)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=8, max_length=200)
    full_name: str = Field(default="", max_length=120)
    tenant_id: str = Field(default="default", max_length=80)
    registration_code: str = Field(default="", max_length=200)


def _known_role(value: str) -> str:
    # The shape of a role name. Whether a custom role exists depends on the tenant, which
    # the route knows and the request model does not; the route checks that.
    role = str(value or "").strip().lower()
    if not (is_known_role(role) or CUSTOM_ROLE_NAME.match(role)):
        raise ValueError("Unknown role")
    return role


def _require_role_in(role: str, tenant_id: str) -> None:
    if not store_module.role_exists(role, tenant_id):
        raise HTTPException(status_code=400, detail=f"Unknown role in tenant {tenant_id}: {role}")


def _delegable(role: str, tenant_id: str) -> bool:
    """A role an invite or an API key may carry: one that exists in the tenant and does
    not administer it. An administrator is made deliberately, through the user routes."""
    return store_module.role_exists(role, tenant_id) and "tenant.admin" not in role_permissions_in(role, tenant_id)


def _active_admins(tenant_id: str, *, role_override: tuple[str, frozenset[str]] | None = None) -> list[dict]:
    """The active accounts that can administer a tenant - optionally as they would be if
    one role's permissions changed."""
    def grants(role: str) -> frozenset[str]:
        if role_override and role == role_override[0]:
            return role_override[1]
        return role_permissions_in(role, tenant_id)

    return [user for user in list_users(tenant_id) if user["is_active"] and "tenant.admin" in grants(user["role"])]


class UserCreateRequest(RegisterRequest):
    role: str = Field(default="viewer", max_length=40)

    @field_validator("role")
    @classmethod
    def _role_is_known(cls, value: str) -> str:
        return _known_role(value)


class TenantRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=80)
    display_name: str = Field(default="", max_length=120)


class UserRoleRequest(BaseModel):
    role: str = Field(max_length=40)
    tenant_id: str = Field(default="", max_length=80)

    @field_validator("role")
    @classmethod
    def _role_is_known(cls, value: str) -> str:
        return _known_role(value)


class PasswordResetRequest(BaseModel):
    password: str = Field(min_length=8, max_length=200)


class UserActiveRequest(BaseModel):
    is_active: bool


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=200)


class ProfileUpdateRequest(BaseModel):
    full_name: str = Field(default="", max_length=120)


class AvatarUpdateRequest(BaseModel):
    # A cropped 256px data URL from the settings page; empty string removes it.
    avatar: str = Field(default="", max_length=400_000)


class FeatureSettingsRequest(BaseModel):
    ocr_enabled: bool


class SiemSettingsRequest(BaseModel):
    """The SIEM receiver. There is no credential field: syslog over TLS, TCP or UDP carries
    none. The CA certificate follows the stored-secret rule anyway - omitted, the saved one
    is kept; sent, it replaces it; `remove_ca` deletes it."""
    # Every field defaults to "not sent": an omitted field keeps the saved value, so a
    # test of the saved configuration is an empty body and a save may change one field.
    transport: str | None = Field(default=None, max_length=8)
    host: str | None = Field(default=None, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    format: str | None = Field(default=None, max_length=8)
    trust: str | None = Field(default=None, max_length=8)
    ca_pem: str | None = Field(default=None, max_length=70_000)
    ca_name: str | None = Field(default=None, max_length=200)
    remove_ca: bool = False


class SiemEnabledRequest(BaseModel):
    enabled: bool


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


# C6 caches a `?v=` static file for a year, so the version in a page's URL must change
# whenever the file does - or every browser that saw the old file keeps running it. A
# hand-bumped number is a promise someone forgets, so each page is served with every
# /static/ reference versioned by the file's own content digest.
_STATIC_REFERENCE = re.compile(r"(/static/([A-Za-z0-9_./-]+))\?v=[A-Za-z0-9_.-]*")


@functools.lru_cache(maxsize=128)
def _asset_digest(path: str, mtime_ns: int, size: int) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:12]


def _asset_version(match: re.Match) -> str:
    root = FRONTEND_DIR.resolve()
    path = (root / match.group(2)).resolve()
    if root not in path.parents or not path.is_file():
        return match.group(0)
    stat = path.stat()
    return f"{match.group(1)}?v={_asset_digest(str(path), stat.st_mtime_ns, stat.st_size)}"


def _page(name: str) -> HTMLResponse:
    html = (FRONTEND_DIR / name).read_text(encoding="utf-8")
    return HTMLResponse(_STATIC_REFERENCE.sub(_asset_version, html))


@app.get("/")
def login_root() -> HTMLResponse:
    # The product starts at login: no marketing landing page ships on-prem.
    return _page("login.html")


@app.get("/login")
def login_page() -> HTMLResponse:
    return _page("login.html")


@app.get("/register")
def register_page() -> HTMLResponse:
    return _page("register.html")


@app.get("/profile")
def profile_page() -> HTMLResponse:
    return _page("profile.html")


@app.get("/dashboard")
@app.get("/findings")
@app.get("/remediation")
@app.get("/scan")
@app.get("/evidence")
@app.get("/administration")
def dashboard() -> HTMLResponse:
    # Every sidebar destination is a real, reloadable path. The console is one
    # page; app.js reads location.pathname (+#member) to open the right view.
    return _page("index.html")


def _siem_health() -> dict:
    from backend.siem import forwarding_enabled
    from backend.store import audit_outbox_status

    try:
        enabled = forwarding_enabled()
    except Exception:  # health must answer even if the settings cannot be read
        return {"enabled": None}
    if not enabled:
        return {"enabled": False}
    try:
        status = audit_outbox_status()
    except Exception:  # health must answer even if the outbox cannot be read
        return {"enabled": True, "pending": None}
    return {"enabled": True, "pending": status["pending"], "oldest_seconds": status["oldest_seconds"]}


@app.get("/api/health")
def health() -> dict:
    from collectors.ocr import ocr_status
    from backend.search import search_health

    return {
        "status": "ok",
        "service": "dspm-discovery",
        # C0.4/C11: which build is answering - the package label and commit, or "development".
        "build": _build_info(),
        "ocr": ocr_status(),
        "search": search_health(),
        # C4: whether audit events are reaching the SIEM - a count and an age, never content.
        "siem": _siem_health(),
        # Operator diagnostics (Phase 0): which database this instance serves.
        # Phase 1: how stale the newest backup is - a backup that stopped
        # happening must be visible before it becomes a recovery incident.
        # Phase 2: the applied schema revision vs what this build expects.
        "database": {
            "backend": DATABASE_IDENTITY.get("backend"),
            "identity": DATABASE_IDENTITY.get("identity"),
            "backup_age_seconds": _backup_age_or_none(),
            "schema_revision": _schema_revision_or_none(),
        },
    }


@app.get("/api/ready")
def readiness() -> "JSONResponse":
    """Readiness (roadmap Phase 6, DB-09): can this instance actually serve?

    Liveness (/api/health) answers "is the process up"; readiness performs a
    bounded database READ probe - the server answers, and the application's own
    revision history reads - and verifies the schema revision matches this build,
    returning 503 with reasons when it cannot serve. It writes nothing (C0.4): it
    is open while the schema guard has stopped the data routes, and a probe row
    written then would be a write landing on a database a newer release upgraded.
    C0.3: in production a stale or failed backup is a failure; elsewhere, and for
    every other advisory signal, a warning.
    """
    from fastapi.responses import JSONResponse

    failures: list[str] = []
    warnings: list[str] = []
    probe: dict = {}
    installed_at = None
    started = time.perf_counter()
    try:
        from backend import migrations, store

        with store._connect() as conn:
            row = conn.execute("SELECT 1 AS one").fetchone()
            if row is None or int(row["one"]) != 1:
                failures.append("database read probe returned no row")
            applied = migrations.current_revision(conn)
            installed_at = migrations.installed_at(conn)
        expected = migrations.expected_revision()
        probe["schema_revision"] = {"applied": applied, "expected": expected}
        if applied != expected:
            failures.append(f"schema revision {applied} != expected {expected}")
    except Exception as exc:
        failures.append(f"database probe failed: {type(exc).__name__}")
    probe["probe_seconds"] = round(time.perf_counter() - started, 3)

    # Phase 4 polish: revisions 0003/0004 enumerate the tables that exist when
    # they run, so a table added later inherits neither its tenant foreign key
    # nor RLS unless its own revision asks. Nothing in the schema forces that,
    # so the gap is reported. It is a warning rather than a failure: the
    # application still filters by tenant, and taking a serving instance out of
    # rotation over a defence-in-depth gap would be the larger harm.
    # (Checksum drift is deliberately NOT reported here - see
    # migrations.checksum_drift: it is expected for convergent revisions.)
    try:
        from backend import store

        coverage = store.tenant_isolation_coverage()
        for label, key in (("tenant foreign key", "missing_foreign_key"),
                           ("row-level security", "missing_rls")):
            missing = coverage.get(key) or []
            if missing:
                warnings.append(
                    f"{len(missing)} tenant-scoped table(s) without {label}: "
                    + ", ".join(missing[:5])
                )
    except Exception as exc:
        warnings.append(f"tenant isolation check unavailable: {type(exc).__name__}")

    try:
        from backend import backup as backup_module

        state = backup_module.readiness(production=backup_module.is_production(), installed_at=installed_at)
        probe.update(state["probe"])
        failures.extend(state["failures"])
        warnings.extend(state["warnings"])
    except Exception as exc:
        probe["backup_age_seconds"] = None
        warnings.append(f"backup state unavailable: {type(exc).__name__}")
    if os.getenv("DSPM_ALLOW_PRIVATE_TARGETS", "").strip():
        # C5: an install upgraded with the old switch set would otherwise not know why
        # its scans are now refused (production) or unrestricted (development, no list).
        warnings.append("DSPM_ALLOW_PRIVATE_TARGETS is set but no longer read: each workspace lists its "
                        "scan targets under Security operations -> Scan targets")

    body = {
        "ready": not failures,
        "database": probe,
        "failures": failures,
        "warnings": warnings,
    }
    return JSONResponse(status_code=200 if not failures else 503, content=body)


@app.get("/api/admin/db-metrics")
def database_metrics(principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    """Operational metrics for the database tier (Phase 6, DB-09).

    Admin-only: pool saturation, storage headroom, backup age, WAL archive
    health, replication lag, long transactions and lock waits describe the
    deployment, not one tenant, so they are platform diagnostics rather than
    tenant data. `warnings` is the short list an operator should act on.
    """
    from backend import observability

    return observability.collect()


@app.get("/api/admin/runtime")
def runtime_status(principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    """Which build serves this database, and which others do (startup diagnostics).

    This process - version, commit, source tree, the schema revision it supports and the
    one its source tree on disk supports now - the database's location (never a
    credential) and revision, and every server or worker registered on it with its
    build. Two builds on one database, or a process older than its own checkout, show
    here before they show as a refused sign-in.
    """
    from backend import migrations, runtime_identity

    info = migrations.status()
    with store_module._connect() as conn:
        newest = conn.execute("SELECT revision, name, applied_at FROM schema_migrations "
                              "ORDER BY revision DESC LIMIT 1").fetchone()
    return {
        "this": {**runtime_identity.identity("server"), "on_disk_revision": runtime_identity.on_disk_revision()},
        "database": {**runtime_identity.database_location(), "applied_revision": info["applied_revision"],
                     "expected_revision": info["expected_revision"],
                     "pending": [item["revision"] for item in info["pending"]],
                     "checksum_drift": len(info["checksum_drift"]),
                     "newest_revision": dict(newest) if newest is not None else None},
        "instances": store_module.runtime_instances(runtime_identity.STALE_SECONDS),
    }


@app.get("/api/admin/db-slow-queries")
def database_slow_queries(
    principal: Principal = Depends(require_permission("platform.admin")),
    limit: int = Query(default=20, ge=1, le=100),
) -> dict:
    """Top statements by total execution time (Phase 6, DB-12).

    Query text is sensitive even normalized - it describes the schema and the
    estate - so this is admin-only and deliberately absent from health,
    readiness and logs.
    """
    from backend import observability

    result = observability.slow_queries(limit)
    audit(principal.tenant_id, principal.subject, "db.slow_queries.viewed",
          {"returned": len(result.get("statements") or [])})
    return result


@app.get("/api/admin/db-activity")
def database_activity(principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    """Privacy-bounded database activity monitoring for regulated tiers.

    The payload is aggregate-only: it never returns statement text, client
    addresses, roles or tenant identifiers.  Access itself is audited.
    """
    from backend import observability

    result = observability.database_activity_monitoring()
    audit(principal.tenant_id, principal.subject, "db.activity.viewed", {
        "enabled": bool(result.get("enabled")),
        "applicable": bool(result.get("applicable")),
    })
    return result


def _metrics_reader(request: Request) -> Principal:
    """D11: who may read /metrics - a scraper with the DSPM_METRICS_TOKEN, or the
    installation's administrator."""
    from backend import metrics
    from backend.security import verify_token

    header = request.headers.get("authorization", "")
    if metrics.token_allowed(header):
        return Principal(subject="metrics-scraper", role="metrics", tenant_id="default", auth_type="metrics-token")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Metrics need the scrape token or an administrator.")
    principal = verify_token(header[7:].strip())
    if not is_platform_admin(principal):
        raise HTTPException(status_code=403, detail="Metrics are the installation administrator's.")
    return principal


@app.get("/metrics", include_in_schema=False)
def prometheus_metrics(principal: Principal = Depends(_metrics_reader)) -> Response:
    """D11: Prometheus text. A scraper sends `Authorization: Bearer <DSPM_METRICS_TOKEN>`;
    without a token configured, only the installation's administrator may read it."""
    from backend import metrics

    ready = readiness().status_code == 200
    return Response(content=metrics.render(ready=ready, build=_build_info()), media_type=metrics.CONTENT_TYPE,
                    headers={"Cache-Control": "no-store"})


@functools.lru_cache(maxsize=1)
def _build_info() -> dict:
    """What the offline package wrote into app/BUILD.json; a source checkout has none."""
    path = Path(__file__).resolve().parents[1] / "BUILD.json"
    try:
        build = json.loads(path.read_text(encoding="utf-8"))
        return {"label": str(build.get("label", "")), "commit": str(build.get("commit", ""))[:12],
                "schema_revision": build.get("schema_revision")}
    except (OSError, ValueError):
        return {"label": "development", "commit": "", "schema_revision": None}


def _schema_revision_or_none():
    try:
        from backend import migrations, store

        with store._connect() as conn:
            return {
                "applied": migrations.current_revision(conn),
                "expected": migrations.expected_revision(),
            }
    except Exception:
        return None


def _backup_age_or_none():
    try:
        from backend.backup import latest_backup_age_seconds

        age = latest_backup_age_seconds()
        return round(age, 1) if age is not None else None
    except Exception:
        return None


@app.get("/api/risk-rules")
def risk_rules(_: Principal = Depends(require_permission("inventory.view"))) -> dict:
    return {"rules": get_risk_rules()}


@app.get("/api/compliance-keywords")
def compliance_keywords(
    framework: str = Query(default="gdpr", max_length=40),
    language: str = Query(default="", max_length=32),
    category: str = Query(default="", max_length=80),
    source: str = Query(default="all", max_length=20),
    principal: Principal = Depends(require_permission("inventory.view")),
) -> dict:
    # An unknown framework is the caller's mistake, not the server's: 400, never a 500
    # (found by the M2 polish DAST run, which sent a URL as the framework).
    try:
        return list_keyword_groups(principal.tenant_id, framework, language=language, category=category, source=source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "Unknown compliance framework")) from exc


@app.post("/api/compliance-keywords/validate")
def compliance_keywords_validate(payload: ComplianceKeywordImportRequest, principal: Principal = Depends(require_permission("rules.manage"))) -> dict:
    return validate_keyword_import(principal.tenant_id, payload.model_dump())


@app.post("/api/compliance-keywords/import")
def compliance_keywords_import(payload: ComplianceKeywordImportRequest, principal: Principal = Depends(require_permission("rules.manage"))) -> dict:
    try:
        result = import_keyword_groups(principal.tenant_id, payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The keyword import could not be processed")) from exc
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
    principal: Principal = Depends(require_permission("export")),
) -> Response:
    try:
        filename, media_type, content = export_keyword_groups(principal.tenant_id, framework, language=language,
                                                              source=source, fmt=format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "Unknown compliance framework or format")) from exc
    audit(
        principal.tenant_id,
        principal.subject,
        "compliance_keywords.exported",
        {"framework": framework, "language": language, "source": source, "format": format, "bytes": len(content or "")},
    )
    return Response(content=content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.get("/api/compliance-keywords/template")
def compliance_keywords_template(
    framework: str = Query(default="gdpr", max_length=40),
    language: str = Query(default="ru", max_length=32),
    principal: Principal = Depends(require_permission("inventory.view")),
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
def nist_catalog_status_endpoint(_: Principal = Depends(require_permission("inventory.view"))) -> dict:
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
    principal: Principal = Depends(require_permission("inventory.view")),
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
def nist_catalog_rule(rule_id: str, principal: Principal = Depends(require_permission("inventory.view"))) -> dict:
    _ = principal
    rule = get_nist_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="NIST rule not found")
    return {"rule": rule, "catalog_status": nist_catalog_status()}


@app.post("/api/nist/catalog/validate")
def nist_catalog_validate(payload: NISTCatalogPayload, principal: Principal = Depends(require_permission("rules.manage"))) -> dict:
    result = validate_nist_catalog(payload.catalog)
    audit(principal.tenant_id, principal.subject, "nist.catalog.validated", {"valid": result.get("valid"), "catalog_hash": result.get("catalog_hash")})
    return result


@app.post("/api/nist/catalog/import")
def nist_catalog_import(payload: NISTCatalogPayload, principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    # H3: the NIST catalog is a platform-global, vendor-maintained baseline shared
    # by every tenant's classifier. Only the platform admin may mutate it - a
    # tenant-scoped admin must not be able to change detection for other tenants.
    _require_platform_admin(principal)
    try:
        result = import_nist_catalog(payload.catalog, dry_run=payload.dry_run, actor=principal.subject)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The NIST catalog could not be imported")) from exc
    audit(principal.tenant_id, principal.subject, "nist.catalog.imported", {"dry_run": payload.dry_run, "catalog_hash": result.get("catalog_hash"), "valid": result.get("valid")})
    return result


@app.post("/api/nist/catalog/activate")
def nist_catalog_activate(payload: NISTCatalogActivationPayload, principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    _require_platform_admin(principal)  # H3: platform-global resource (see import)
    try:
        result = activate_nist_catalog(payload.catalog_hash, actor=principal.subject)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The NIST catalog could not be activated")) from exc
    audit(principal.tenant_id, principal.subject, "nist.catalog.activated", {"catalog_hash": result.get("catalog_hash")})
    return result


@app.post("/api/nist/catalog/rollback")
def nist_catalog_rollback(principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    _require_platform_admin(principal)  # H3: platform-global resource (see import)
    try:
        result = rollback_nist_catalog(actor=principal.subject)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The NIST catalog could not be rolled back")) from exc
    audit(principal.tenant_id, principal.subject, "nist.catalog.rollback", {"catalog_hash": result.get("catalog_hash")})
    return result


@app.get("/api/nist/catalog/export")
def nist_catalog_export(principal: Principal = Depends(require_permission("export"))) -> Response:
    filename, media_type, content = export_nist_catalog()
    audit(principal.tenant_id, principal.subject, "nist.catalog.exported", {"bytes": len(content or "")})
    return Response(content=content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request) -> Response:
    login_key = _login_rate_key(payload.username, request)
    ip_key = _login_ip_rate_key(request)
    # M4: trip on EITHER the per-(IP,username) cap OR the aggregate per-IP cap, so a
    # username-spray from one IP is throttled even though no single username does.
    # A trail that records only successful sign-ins cannot show an attempt to
    # break in - which is the thing it is most often asked for. C4: the row goes to the
    # tenant the attempted name belongs to, so that tenant's administrator sees attacks
    # on their own users; a name that belongs to nobody is recorded in "default".
    attempted = sanitize_username(payload.username)
    known = get_user(attempted) if attempted else None
    attempt_tenant = str(known["tenant_id"]) if known else "default"
    user_blocked = _too_many_login_failures(login_key)
    if user_blocked or _too_many_ip_login_failures(ip_key):
        # C4: one row per order of magnitude, not one per attempt. A thousand blocked
        # attempts write four rows (the 1st, 10th, 100th and 1000th), each saying how
        # many there have been; a spray across usernames counts against the address.
        blocked = _record_blocked_attempt(login_key if user_blocked else ip_key)
        if _is_power_of_ten(blocked):
            audit(attempt_tenant, attempted or "unknown", "auth.login_blocked",
                  {"username": attempted, "blocked_attempts": blocked, "window_seconds": LOGIN_WINDOW_SECONDS})
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
    result = identity.sign_in(payload.username, payload.password, payload.workspace)
    attempt_tenant = result.tenant_id or attempt_tenant
    if result.principal is None:
        _record_login_failure(login_key)
        _record_login_failure(ip_key)
        detail = {"username": attempted}
        if result.source == "ldap" or result.failure not in {"", "invalid"}:
            # C2: why a directory sign-in failed is for the administrator, not the caller.
            detail.update({"source": result.source, "reason": result.failure})
        audit(attempt_tenant, attempted or "unknown", "auth.login_failed", detail)
        if result.failure in {"unavailable", "tls_failure", "misconfigured"}:
            raise HTTPException(status_code=503, detail="The directory could not complete the sign-in. "
                                                        "Try again shortly, or sign in with a local account.")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    # Clear this user's counter; the per-IP aggregate is NOT cleared by one success
    # (a sprayer who guesses one valid credential must not reset the IP's history).
    _clear_login_failures(login_key)
    principal = result.principal
    audit(principal.tenant_id, principal.subject, "auth.login", {"source": result.source} if result.source != "local" else None)
    return _issue_session(principal, request)


def _refresh_cookie_is_secure(request: Request) -> bool:
    """Secure on HTTPS and in production. Not on a plain-HTTP development console,
    where a Secure cookie would simply never be sent and refresh would never work."""
    return IS_PRODUCTION or request_scheme(request) == "https"


def _with_refresh_cookie(response: Response, request: Request, secret: str) -> Response:
    response.set_cookie(
        REFRESH_COOKIE,
        secret,
        max_age=REFRESH_TTL_SECONDS,
        httponly=True,
        secure=_refresh_cookie_is_secure(request),
        samesite="strict",
        # The cookie is only ever presented to the refresh and logout endpoints, so it
        # is not attached to the hundreds of ordinary API calls a console makes.
        path="/api/auth",
    )
    return response


def _clear_refresh_cookie(response: Response, request: Request) -> Response:
    response.delete_cookie(
        REFRESH_COOKIE,
        path="/api/auth",
        httponly=True,
        secure=_refresh_cookie_is_secure(request),
        samesite="strict",
    )
    return response


@app.post("/api/auth/refresh")
def refresh_session(request: Request) -> Response:
    """Exchange the refresh cookie for the next access token, and the next cookie.

    Unauthenticated on purpose: the cookie IS the credential, and the access token it
    replaces has usually expired by the time this is called. Every failure clears the
    cookie and says the same thing, so a caller cannot learn from the difference between
    an unknown token, an expired one and a replayed one.
    """

    client = _client_host(request)
    if REFRESH_THROTTLE.exhausted(client):
        # The cookie is left alone: this address is refused, the cookie may be sound.
        raise HTTPException(status_code=429, detail="Too many session renewals. Try again later.")
    presented = request.cookies.get(REFRESH_COOKIE, "")
    result = rotate_refresh_token(presented)
    if result.get("status") != "ok":
        REFRESH_THROTTLE.failed(client)
        if result.get("status") == "replayed":
            # The one case worth recording: a refresh token was presented twice, and
            # every session in its family has just been ended.
            audit("default", "unknown", "auth.refresh_replayed", {"family": str(result.get("family_id", ""))[:12]})
        response = JSONResponse({"detail": "Session expired"}, status_code=401)
        return _clear_refresh_cookie(response, request)

    principal = result["principal"]
    audit(principal.tenant_id, principal.subject, "auth.refreshed")
    body = {
        "access_token": result["access_token"],
        "token_type": "bearer",
        "role": principal.role,
        "permissions": sorted(principal_permissions(principal)),
        "tenant_id": principal.tenant_id,
        "expires_in": TOKEN_TTL_SECONDS,
    }
    return _with_refresh_cookie(JSONResponse(body), request, result["refresh_token"])


@app.post("/api/logout")
@app.post("/api/auth/logout")
def logout(
    request: Request,
    authorization: str | None = Header(default=None, alias="Authorization"),
    principal: Principal = Depends(require_permission(AUTHENTICATED)),
) -> Response:
    if authorization and authorization.lower().startswith("bearer "):
        revoke_token(authorization.split(" ", 1)[1].strip())
    # C1: signing out has to end the refresh chain too, or the cookie still mints
    # access tokens for the rest of its life.
    families = revoke_refresh_tokens_for_user(principal.subject)
    audit(principal.tenant_id, principal.subject, "auth.logout", {"refresh_tokens_ended": families})
    return _clear_refresh_cookie(JSONResponse({"status": "logged_out"}), request)


@app.post("/api/auth/register")
def register(payload: RegisterRequest, request: Request) -> dict:
    client = _client_host(request)
    if REGISTER_THROTTLE.exhausted(client):
        raise HTTPException(status_code=429, detail="Too many registration attempts. Try again later.")
    username = sanitize_username(payload.username)
    tenant_id = _safe_tenant(payload.tenant_id)
    if not tenant_exists(tenant_id):
        REGISTER_THROTTLE.failed(client)
        raise HTTPException(status_code=403, detail="Registration failed")
    code = payload.registration_code.strip()
    # M5: prefer a time-boxed, use-capped invite token (atomically redeemed); fall
    # back to the legacy static per-tenant code for backward compatibility.
    invite = redeem_registration_invite(tenant_id, _hash_invite_token(code)) if code else None
    if invite is None and not _valid_registration_code(tenant_id, code):
        REGISTER_THROTTLE.failed(client)
        raise HTTPException(status_code=403, detail="Registration failed")
    # C2: a sign-in name is unique within its workspace. Another workspace using the same
    # name no longer blocks this one - or tells the caller that it exists.
    key = None if find_user_by_login(tenant_id, username) else allocate_account_key(username, tenant_id)
    if key is None:
        REGISTER_THROTTLE.failed(client)
        raise HTTPException(status_code=409, detail="Registration failed")
    role = invite["role"] if invite else "viewer"
    pending = bool(invite and invite["requires_approval"])
    create_user(key, hash_password(payload.password, username=username), role, tenant_id, payload.full_name.strip(),
                login_name=username)
    if pending:
        update_user_active(key, False)  # M5: admin-approval - inactive until an admin activates
    detail = {"role": role, "source": "invite" if invite else "registration_code", "login_name": username}
    if invite:
        detail.update({"invite_id": invite["id"], "remaining_uses": invite["remaining_uses"], "pending_approval": pending})
    audit(tenant_id, key, "user.registered", detail)  # M5: per-redemption audit
    return {"user": _public_user(get_user(key)), "pending_approval": pending}


# ---- Sessions --------------------------------------------------------------------
def _issue_session(principal: Principal, request: Request) -> Response:
    access = create_token(principal.subject, principal.role, principal.tenant_id)
    # C1: the access token is short, and the session is carried by a single-use refresh
    # token in an HttpOnly cookie - out of reach of any script on the page.
    secret, _family, _expires = issue_refresh_token(principal.subject, _token_jti(access))
    body = {
        "access_token": access,
        "token_type": "bearer",
        "role": principal.role,
        "permissions": sorted(principal_permissions(principal)),
        "tenant_id": principal.tenant_id,
        "expires_in": TOKEN_TTL_SECONDS,
    }
    return _with_refresh_cookie(JSONResponse(body), request, secret)


# ---- C2: directory sign-in settings ---------------------------------------------
class DirectoryMapping(BaseModel):
    group_dn: str = Field(max_length=400)
    role: str = Field(max_length=64)


class DirectorySettingsRequest(BaseModel):
    enabled: bool | None = None
    host: str | None = Field(default=None, max_length=253)
    port: int | None = None
    security: str | None = Field(default=None, max_length=10)
    trust: str | None = Field(default=None, max_length=10)
    ca_pem: str | None = Field(default=None, max_length=65536)
    ca_name: str | None = Field(default=None, max_length=200)
    base_dn: str | None = Field(default=None, max_length=400)
    bind_dn: str | None = Field(default=None, max_length=400)
    # The service account's password: omitted keeps the stored one, a value replaces
    # it, remove_bind_password deletes it. It is never sent back.
    bind_password: str | None = Field(default=None, max_length=500)
    remove_bind_password: bool = False
    user_attribute: str | None = Field(default=None, max_length=40)
    group_search: str | None = Field(default=None, max_length=20)
    group_base_dn: str | None = Field(default=None, max_length=400)
    timeout_seconds: int | None = None
    mappings: list[DirectoryMapping] | None = Field(default=None, max_length=50)


class DirectoryTestRequest(BaseModel):
    login: str = Field(default="", max_length=120)


@app.get("/api/settings/directory")
def directory_settings_view(principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    return directory.public_view(get_directory_settings(principal.tenant_id), editable=True)


@app.put("/api/settings/directory")
def directory_settings_save(payload: DirectorySettingsRequest,
                            principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    tenant_id = principal.tenant_id
    saved = get_directory_settings(tenant_id)
    request = payload.model_dump(exclude_none=True, exclude={"bind_password", "remove_bind_password", "enabled"})
    try:
        config = directory.validate(request, (saved or {}).get("config"), lambda role: store_module.role_exists(role, tenant_id))
    except directory.DirectoryError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The directory settings were refused")) from exc
    ref = (saved or {}).get("bind_secret_ref", "")
    secret_action = "kept" if ref else "none"
    if payload.remove_bind_password and ref:
        vault.delete(tenant_id, ref)
        ref, secret_action = "", "removed"
    elif payload.bind_password:
        new_ref = vault.store(tenant_id, config["bind_dn"], payload.bind_password, "", kind="directory",
                              label=config["bind_dn"])
        if ref:
            vault.delete(tenant_id, ref)
        secret_action = "replaced" if ref else "set"
        ref = new_ref
    enabled = payload.enabled if payload.enabled is not None else bool(saved and saved.get("enabled"))
    if enabled and not ref:
        raise HTTPException(status_code=400, detail="Enter the service account's password before turning directory sign-in on.")
    save_directory_settings(tenant_id, enabled, config, ref, principal.subject)
    before = (saved or {}).get("config") or {}
    changed = sorted(key for key in set(before) | set(config) if key != "ca_pem" and before.get(key) != config.get(key))
    audit(tenant_id, principal.subject, "directory.settings_changed", {
        "host": config["host"], "security": config["security"], "fields": changed,
        "bind_password": secret_action, "mappings": len(config["mappings"]), "enabled": enabled})
    if saved is None or bool(saved.get("enabled")) != enabled:
        audit(tenant_id, principal.subject, "directory.enabled" if enabled else "directory.disabled")
    return directory.public_view(get_directory_settings(tenant_id), editable=True)


@app.delete("/api/settings/directory")
def directory_settings_remove(principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    saved = get_directory_settings(principal.tenant_id)
    if saved and saved.get("bind_secret_ref"):
        vault.delete(principal.tenant_id, saved["bind_secret_ref"])
    delete_directory_settings(principal.tenant_id)
    audit(principal.tenant_id, principal.subject, "directory.removed", {"had_settings": saved is not None})
    return directory.public_view(None, editable=True)


@app.post("/api/settings/directory/test")
def directory_settings_test(payload: DirectoryTestRequest,
                            principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    saved = get_directory_settings(principal.tenant_id)
    if saved is None:
        raise HTTPException(status_code=400, detail="Save the directory settings first.")
    report = directory.test(saved["config"], identity.bind_password(principal.tenant_id, saved), payload.login.strip())
    audit(principal.tenant_id, principal.subject, "directory.tested",
          {"ok": report["ok"], "status": report["status"], "with_user": bool(payload.login.strip())})
    return report


@app.post("/api/auth/change-password")
def change_password(payload: PasswordChangeRequest, principal: Principal = Depends(require_permission(AUTHENTICATED))) -> dict:
    if principal.subject in PROTECTED_USERS:
        raise HTTPException(status_code=403, detail="Built-in admin account is protected")
    if PASSWORD_CHANGE_THROTTLE.exhausted(principal.subject):
        raise HTTPException(status_code=429, detail="Too many incorrect passwords. Try again later.")
    authenticated = authenticate_user(principal.subject, payload.current_password)
    if authenticated is None:
        PASSWORD_CHANGE_THROTTLE.failed(principal.subject)
        audit(principal.tenant_id, principal.subject, "user.password_change_refused")
        # 403, not 401: the session is sound, the proof offered with it is not. A 401
        # is what the console reads as an expired access token - it would renew the
        # session and send the wrong password again.
        raise HTTPException(status_code=403, detail="Current password is incorrect")
    PASSWORD_CHANGE_THROTTLE.clear(principal.subject)
    update_user_password(principal.subject, hash_password(payload.new_password, username=principal.subject))
    # C1: changing a password after a compromise is only worth doing if it signs
    # out whoever had the old one - everywhere, including this caller's own
    # session and any this process never saw.
    ended = revoke_sessions_for_user(principal.subject)
    audit(principal.tenant_id, principal.subject, "user.password_changed", {"sessions_ended": ended})
    return {"status": "updated", "sessions_ended": ended, "reauthenticate": True}


@app.get("/api/profile")
def profile(principal: Principal = Depends(require_permission(AUTHENTICATED))) -> dict:
    user = get_user(principal.subject)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "user": _public_user(user),
        "protected": principal.subject in PROTECTED_USERS,
        "avatar": user.get("avatar", ""),
        # C3: what this account may do, read fresh - the console gates on this, and a
        # role changed since sign-in shows here on the next page load.
        "permissions": sorted(principal_permissions(principal)),
    }


@app.put("/api/profile")
def update_profile(payload: ProfileUpdateRequest, principal: Principal = Depends(require_permission(AUTHENTICATED))) -> dict:
    if principal.subject in PROTECTED_USERS:
        raise HTTPException(status_code=403, detail="Built-in admin account is protected")
    user = update_user_profile(principal.subject, payload.full_name.strip())
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    audit(principal.tenant_id, principal.subject, "user.profile_updated")
    return {"user": _public_user(user)}


_AVATAR_DATA_PREFIXES = ("data:image/png;base64,", "data:image/jpeg;base64,", "data:image/webp;base64,")


@app.put("/api/profile/avatar")
def update_profile_avatar(payload: AvatarUpdateRequest, principal: Principal = Depends(require_permission(AUTHENTICATED))) -> dict:
    """Set or clear the account's profile photo. Allowed for every account,
    including the protected built-in admin - the photo is cosmetic and cannot
    change identity, role, or credentials."""
    avatar = (payload.avatar or "").strip()
    if avatar:
        if not avatar.startswith(_AVATAR_DATA_PREFIXES):
            raise HTTPException(status_code=400, detail="Avatar must be a PNG, JPEG, or WebP data URL")
        encoded = avatar.split(",", 1)[1]
        try:
            base64.b64decode(encoded, validate=True)
        except Exception:
            raise HTTPException(status_code=400, detail="Avatar image data is not valid base64")
    user = update_user_avatar(principal.subject, avatar)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    audit(principal.tenant_id, principal.subject, "user.avatar_updated", {"removed": not avatar})
    return {"user": _public_user(user), "avatar": user.get("avatar", "")}


# Runtime feature flags. Stored install-wide, applied to this process's env on
# write, and re-applied at startup - the collectors read the env per call, so a
# toggle takes effect on the next scan with no restart.
_FEATURE_OCR_SETTING = "feature.ocr_enabled"


def _apply_persisted_feature_flags() -> None:
    value = get_app_setting(_FEATURE_OCR_SETTING)
    if value is not None:
        os.environ["DSPM_OCR_ENABLED"] = "1" if value == "1" else "0"


def _feature_settings_payload(principal: Principal) -> dict:
    from collectors.ocr import ocr_status

    status = ocr_status()
    return {
        "features": {
            "ocr": {
                "enabled": status["enabled"],
                "dependency_installed": status["dependency_installed"],
                "state": status["state"],
                # Install-wide: turning OCR on changes every tenant's scans.
                "editable": has_permission(principal, "platform.admin"),
            },
            # Everyone sees whether the audit trail reaches a SIEM; the receiver and its
            # certificate are for whoever may change them (/api/settings/siem).
            "siem": _siem_summary(principal),
        }
    }


def _siem_view(principal: Principal) -> dict:
    from backend import siem_settings
    from backend.store import audit_outbox_status

    enabled, config, status = siem_settings.load()
    return siem_settings.public_view(enabled, config, status, audit_outbox_status(),
                                     editable=has_permission(principal, "platform.admin"))


def _siem_summary(principal: Principal) -> dict:
    try:
        view = _siem_view(principal)
    except Exception:  # the features page must load even if the outbox cannot be read
        return {"enabled": False, "state": "unavailable", "editable": False}
    return {"enabled": view["enabled"], "state": view["state"], "editable": view["editable"]}


@app.get("/api/settings/features")
def get_feature_settings(principal: Principal = Depends(require_permission(AUTHENTICATED))) -> dict:
    return _feature_settings_payload(principal)


@app.put("/api/settings/features")
def update_feature_settings(payload: FeatureSettingsRequest, principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    value = "1" if payload.ocr_enabled else "0"
    set_app_setting(_FEATURE_OCR_SETTING, value)
    os.environ["DSPM_OCR_ENABLED"] = value
    audit(principal.tenant_id, principal.subject, "settings.feature_toggled", {"feature": "ocr", "enabled": payload.ocr_enabled})
    return _feature_settings_payload(principal)


# ── C4: SIEM integration, configured in the console ─────────────────────────────────
# The engine - outbox, retries, TLS, delivery - is backend.siem; these routes are the
# configuration, the switch, the connection test and the status, all install-wide and all
# platform.admin, like the OCR switch. Nothing here returns the CA certificate itself.

def _siem_audit(principal: Principal, action: str, detail: dict) -> None:
    audit(principal.tenant_id, principal.subject, action, detail)


@app.get("/api/settings/siem")
def siem_settings_read(principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    return _siem_view(principal)


@app.put("/api/settings/siem")
def siem_settings_save(payload: SiemSettingsRequest, principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    from backend import siem_settings

    _enabled, saved, _status = siem_settings.load()
    try:
        config = siem_settings.merge(saved, payload.model_dump(exclude_none=True))
    except siem_settings.SiemSettingsError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The SIEM settings were refused.")) from exc
    changed = siem_settings.changed_fields(saved, config)
    siem_settings.save_config(config)
    if changed or not saved:
        _siem_audit(principal, "settings.siem_changed", {
            "changed": changed, "transport": config["transport"], "host": config["host"], "port": config["port"],
            "format": config["format"], "trust": config["trust"], "ca_fingerprint": config.get("ca_fingerprint", ""),
        })
    return _siem_view(principal)


@app.put("/api/settings/siem/enabled")
def siem_settings_enable(payload: SiemEnabledRequest, principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    from backend import siem, siem_settings

    enabled, config, _status = siem_settings.load()
    if payload.enabled == enabled:
        return _siem_view(principal)
    if payload.enabled:
        siem_settings.set_enabled(True)
        _siem_audit(principal, "settings.siem_enabled", {"host": config.get("host", ""), "port": config.get("port", "")})
    else:
        # Recorded while forwarding is still on, and sent before it stops, so the SIEM is
        # told it has been turned off. If it cannot be reached, the event stays queued.
        _siem_audit(principal, "settings.siem_disabled", {"host": config.get("host", ""), "port": config.get("port", "")})
        with suppress(Exception):
            siem.drain(limit=50)
        siem_settings.set_enabled(False)
    return _siem_view(principal)


@app.post("/api/settings/siem/test")
def siem_settings_test(payload: SiemSettingsRequest, principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    """Test the receiver in the form - saved or not - without saving it."""
    from backend import siem, siem_settings

    _enabled, saved, _status = siem_settings.load()
    try:
        config = siem_settings.merge(saved, payload.model_dump(exclude_none=True))
    except siem_settings.SiemSettingsError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The SIEM settings were refused.")) from exc
    result = siem.test_connection(siem_settings.target_from(config))
    stamp = datetime.now(timezone.utc).isoformat()
    siem_settings.record(last_test={"at": stamp, "ok": result["ok"], "message": result["message"],
                                    "signature": siem_settings.config_signature(config)})
    _siem_audit(principal, "settings.siem_test_succeeded" if result["ok"] else "settings.siem_test_failed", {
        "transport": config["transport"], "host": config["host"], "port": config["port"], "ok": result["ok"],
    })
    return {"test": {**result, "at": stamp}, **_siem_view(principal)}


@app.post("/api/settings/siem/retry")
def siem_settings_retry(principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    """Send what is queued now instead of at its next back-off. Delivery is still at least
    once and still acknowledged only by the receiver: this only moves the wait."""
    from backend import siem
    from backend.store import reset_audit_outbox_backoff

    made_due = reset_audit_outbox_backoff()
    # Recorded first, so the same pass carries it to the SIEM with the rest.
    _siem_audit(principal, "settings.siem_retry", {"made_due": made_due})
    result = siem.drain(limit=500)
    return {"retry": result, **_siem_view(principal)}


@app.delete("/api/settings/siem")
def siem_settings_remove(principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    """Delete the receiver's configuration and its certificate; forwarding is off after.
    Events already queued stay queued until a receiver is configured again."""
    from backend import siem, siem_settings

    enabled, config, _status = siem_settings.load()
    _siem_audit(principal, "settings.siem_removed", {"host": config.get("host", ""), "port": config.get("port", ""),
                                                     "was_enabled": enabled})
    if enabled:
        with suppress(Exception):
            siem.drain(limit=50)
    siem_settings.remove_config()
    return _siem_view(principal)


class CustomRoleRequest(BaseModel):
    name: str = Field(default="", max_length=40)
    label: str = Field(default="", max_length=80)
    description: str = Field(default="", max_length=300)
    permissions: list[str] = Field(default_factory=list, max_length=20)


def _roles_payload(tenant_id: str) -> dict:
    custom = []
    for role in store_module.list_custom_roles(tenant_id):
        custom.append({**role, "holders": store_module.role_holders(tenant_id, role["name"])})
    roles = role_catalogue() + custom
    return {
        "roles": roles,
        "permissions": permission_catalogue(),
        "delegable": [role["name"] for role in roles if _delegable(role["name"], tenant_id)],
    }


@app.get("/api/roles")
def roles_index(principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    """C3: the roles an administrator can give - built-in and this tenant's own - and
    what each one allows."""
    return _roles_payload(principal.tenant_id)


@app.post("/api/roles")
def custom_role_create(payload: CustomRoleRequest, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    try:
        name, granted = validate_custom_role(payload.name, payload.permissions)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The role could not be created")) from exc
    if store_module.get_custom_role(principal.tenant_id, name) is not None:
        raise HTTPException(status_code=409, detail=f"This tenant already has a role named {name}")
    role = store_module.save_custom_role(principal.tenant_id, name, payload.label.strip() or name,
                                         payload.description.strip(), granted, principal.subject)
    audit(principal.tenant_id, principal.subject, "role.created", {"role": name, "permissions": sorted(granted)})
    return {"role": role, **_roles_payload(principal.tenant_id)}


@app.put("/api/roles/{name}")
def custom_role_update(name: str, payload: CustomRoleRequest, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    if name in BUILTIN_ROLES:
        raise HTTPException(status_code=400, detail="A built-in role cannot be changed; define a custom one")
    current = store_module.get_custom_role(principal.tenant_id, name)
    if current is None:
        raise HTTPException(status_code=404, detail="Role not found")
    try:
        _, granted = validate_custom_role(name, payload.permissions)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The role could not be changed")) from exc
    # Taking administration away from a role must not leave the tenant with nobody who
    # can give it back.
    if "tenant.admin" in current["permissions"] and "tenant.admin" not in granted:
        if not _active_admins(principal.tenant_id, role_override=(name, granted)):
            raise HTTPException(status_code=400, detail="At least one active admin must remain")
    role = store_module.save_custom_role(principal.tenant_id, name, payload.label.strip() or current["label"],
                                         payload.description.strip(), granted, principal.subject)
    audit(principal.tenant_id, principal.subject, "role.updated", {
        "role": name, "permissions": sorted(granted), "previous": current["permissions"],
    })
    return {"role": role, **_roles_payload(principal.tenant_id)}


@app.delete("/api/roles/{name}")
def custom_role_delete(name: str, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    if name in BUILTIN_ROLES:
        raise HTTPException(status_code=400, detail="A built-in role cannot be deleted")
    if store_module.get_custom_role(principal.tenant_id, name) is None:
        raise HTTPException(status_code=404, detail="Role not found")
    holders = store_module.role_holders(principal.tenant_id, name)
    if any(holders.values()):
        raise HTTPException(status_code=409, detail=(
            f"The role is still held by {holders['users']} user(s), {holders['api_keys']} API key(s) "
            f"and {holders['invites']} open invite(s); give them another role first"))
    store_module.delete_custom_role(principal.tenant_id, name)
    audit(principal.tenant_id, principal.subject, "role.deleted", {"role": name})
    return _roles_payload(principal.tenant_id)


# ── Scan targets (C5) ────────────────────────────────────────────────────────────
# The networks and host names a workspace may scan. Reading them is for whoever runs
# scans; changing them is the workspace administrator's, and every change is audited.
class ScanTargetRequest(BaseModel):
    value: str = Field(default="", max_length=253)
    note: str = Field(default="", max_length=200)


class ScanTargetCheckRequest(BaseModel):
    host: str = Field(default="", max_length=253)


def _scan_targets_view(principal: Principal) -> dict:
    entries = store_module.list_scan_targets(principal.tenant_id)
    production = deployment_boundary.is_production()
    return {
        "entries": entries,
        # list: only what is listed; closed: nothing (production, no list); open: anything
        # but the addresses that are never targets (development, no list).
        "mode": "list" if entries else ("closed" if production else "open"),
        "production": production,
        "editable": has_permission(principal, "tenant.admin"),
        "limit": target_scope.MAX_ENTRIES,
    }


@app.get("/api/scan-targets")
def scan_targets_read(principal: Principal = Depends(require_permission("scan.run", "tenant.admin"))) -> dict:
    return _scan_targets_view(principal)


@app.post("/api/scan-targets")
def scan_targets_add(payload: ScanTargetRequest, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    try:
        kind, value = target_scope.parse_entry(payload.value)
        entry = store_module.add_scan_target(principal.tenant_id, kind, value, payload.note.strip(), principal.subject,
                                             limit=target_scope.MAX_ENTRIES)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "That scan target was refused.")) from exc
    audit(principal.tenant_id, principal.subject, "scan_targets.added",
          {"kind": kind, "value": value, "note": entry["note"]})
    return _scan_targets_view(principal)


@app.delete("/api/scan-targets/{entry_id}")
def scan_targets_remove(entry_id: str, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    removed = store_module.delete_scan_target(principal.tenant_id, entry_id)
    if removed is None:
        raise HTTPException(status_code=404, detail="Scan target not found")
    audit(principal.tenant_id, principal.subject, "scan_targets.removed",
          {"kind": removed["kind"], "value": removed["value"]})
    return _scan_targets_view(principal)


@app.post("/api/scan-targets/check")
def scan_targets_check(payload: ScanTargetCheckRequest, principal: Principal = Depends(require_permission("scan.run", "tenant.admin"))) -> dict:
    """Would this host be scanned? Asked before a scan, so it records nothing."""
    host = payload.host.strip()
    if not host:
        raise HTTPException(status_code=400, detail="Enter a host name or address.")
    addresses = resolve_addresses(host)
    reason = target_scope.decide(target_scope.scope_for(principal.tenant_id), host, addresses)
    return {"host": host, "allowed": reason is None, "reason": reason or "",
            "addresses": [str(address) for address in addresses[:5]]}


@app.get("/api/users")
def users(principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    tenant_id = None if _is_platform_admin(principal) else principal.tenant_id
    return {"users": [_public_user(user) for user in list_users(tenant_id)]}


@app.post("/api/users")
def admin_create_user(payload: UserCreateRequest, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    username = sanitize_username(payload.username)
    tenant_id = _safe_tenant(payload.tenant_id)
    if not _can_manage_tenant(principal, tenant_id):
        raise HTTPException(status_code=403, detail="Tenant access denied")
    if not tenant_exists(tenant_id):
        raise HTTPException(status_code=400, detail="Tenant does not exist")
    # C2: unique within the workspace; the installation-wide account key is allocated.
    key = None if find_user_by_login(tenant_id, username) else allocate_account_key(username, tenant_id)
    if key is None:
        raise HTTPException(status_code=409, detail="That sign-in name is already used in this workspace")
    _require_role_in(payload.role, tenant_id)
    user = create_user(key, hash_password(payload.password, username=username), payload.role, tenant_id,
                       payload.full_name.strip(), login_name=username)
    audit(principal.tenant_id, principal.subject, "user.created",
          {"username": key, "login_name": username, "role": payload.role, "tenant_id": tenant_id})
    return {"user": _public_user(user)}


@app.put("/api/users/{username}/role")
def admin_update_user_role(username: str, payload: UserRoleRequest, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
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
    _require_role_in(payload.role, effective_tenant)
    if target == principal.subject and "tenant.admin" not in role_permissions_in(payload.role, effective_tenant):
        admins = _active_admins(current_user["tenant_id"])
        if len(admins) <= 1:
            raise HTTPException(status_code=400, detail="At least one active admin must remain")
    user = update_user_role(target, payload.role, tenant_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    audit(principal.tenant_id, principal.subject, "user.role_updated", {"username": target, "role": payload.role, "tenant_id": tenant_id})
    return {"user": _public_user(user)}


@app.post("/api/users/{username}/reset-password")
def admin_reset_password(username: str, payload: PasswordResetRequest, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    target = sanitize_username(username)
    if target in PROTECTED_USERS:
        raise HTTPException(status_code=403, detail="Built-in admin account is protected")
    current_user = get_user(target)
    if current_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if not _can_manage_tenant(principal, current_user["tenant_id"]):
        raise HTTPException(status_code=403, detail="Tenant access denied")
    if (current_user.get("auth_source") or "local") != "local":
        # C2: its password is the directory's. A local one would never be used (sign-in
        # refuses local passwords on directory accounts) and would only mislead.
        raise HTTPException(status_code=400, detail="This account signs in with the directory; reset its password there.")
    user = update_user_password(target, hash_password(payload.password,
                                                      username=current_user.get("login_name") or target))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    # C1: an administrator resetting a password is usually doing it because the
    # account is suspect. Leaving its sessions alive would defeat the reset.
    ended = revoke_sessions_for_user(target)
    audit(principal.tenant_id, principal.subject, "user.password_reset", {"username": target, "sessions_ended": ended})
    return {"status": "updated", "user": _public_user(user), "sessions_ended": ended}


@app.put("/api/users/{username}/active")
def admin_update_user_active(username: str, payload: UserActiveRequest, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
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
def admin_delete_user(username: str, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
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
def user_activity(principal: Principal = Depends(require_permission("audit.view"))) -> dict:
    events = [event for event in read_audit_log(principal.tenant_id, 500) if str(event.get("action", "")).startswith(("auth.", "user."))]
    return {"events": events}


@app.post("/api/tenants")
def admin_create_tenant(payload: TenantRequest, principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    _require_platform_admin(principal)
    tenant_id = _safe_tenant(payload.tenant_id)
    if tenant_exists(tenant_id):
        raise HTTPException(status_code=409, detail="Tenant already exists")
    tenant = create_tenant(tenant_id, payload.display_name.strip())
    audit(principal.tenant_id, principal.subject, "tenant.created", {"tenant_id": tenant_id})
    return {"tenant": _public_tenant(tenant)}


@app.post("/api/tenants/{tenant_id}/regenerate-registration-code")
@app.post("/api/tenants/{tenant_id}/registration-code")
def admin_rotate_tenant_registration_code(tenant_id: str, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
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
def admin_create_invite(tenant_id: str, payload: InviteCreateRequest, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    target = _safe_tenant(tenant_id)
    if not _can_manage_tenant(principal, target):
        raise HTTPException(status_code=403, detail="Tenant access denied")
    if not tenant_exists(target):
        raise HTTPException(status_code=404, detail="Tenant not found")
    role = payload.role.strip().lower()
    if not _delegable(role, target):
        # Self-registration invites never mint admins - create admins via /api/users.
        raise HTTPException(status_code=400, detail="An invite's role must exist in this tenant and not administer it")
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
def admin_list_invites(tenant_id: str, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    target = _safe_tenant(tenant_id)
    if not _can_manage_tenant(principal, target):
        raise HTTPException(status_code=403, detail="Tenant access denied")
    return {"invites": list_registration_invites(target)}


@app.post("/api/tenants/{tenant_id}/invites/{invite_id}/revoke")
def admin_revoke_invite(tenant_id: str, invite_id: str, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    target = _safe_tenant(tenant_id)
    if not _can_manage_tenant(principal, target):
        raise HTTPException(status_code=403, detail="Tenant access denied")
    if not revoke_registration_invite(target, invite_id):
        raise HTTPException(status_code=404, detail="Invite not found or already revoked")
    audit(principal.tenant_id, principal.subject, "tenant.invite_revoked", {"tenant_id": target, "invite_id": invite_id})
    return {"revoked": True, "invite_id": invite_id}


@app.delete("/api/tenants/{tenant_id}")
def admin_delete_tenant(tenant_id: str, principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    _require_platform_admin(principal)
    target = _safe_tenant(tenant_id)
    if target == "default":
        raise HTTPException(status_code=400, detail="Default tenant cannot be removed")
    if not tenant_exists(target):
        raise HTTPException(status_code=404, detail="Tenant not found")
    try:
        deleted_usage = delete_tenant_with_data(target)
    except store_module.LegalHoldActive as exc:
        # 409: the request is well formed, the state forbids it.
        raise HTTPException(status_code=409, detail=client_message(exc, "The tenant could not be removed")) from exc
    audit_tenant = principal.tenant_id if principal.tenant_id != target else "default"
    audit(audit_tenant, principal.subject, "tenant.deleted", {"tenant_id": target, "deleted": deleted_usage})
    return {"deleted": True, "tenant_id": target, "deleted_data": deleted_usage}


class LegalHoldRequest(BaseModel):
    active: bool
    reason: str = Field(default="", max_length=500)


@app.get("/api/tenants/{tenant_id}/legal-hold")
def read_legal_hold(tenant_id: str, principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    _require_platform_admin(principal)
    target = _safe_tenant(tenant_id)
    if not tenant_exists(target):
        raise HTTPException(status_code=404, detail="Tenant not found")
    return store_module.get_legal_hold(target)


@app.put("/api/tenants/{tenant_id}/legal-hold")
def write_legal_hold(
    tenant_id: str,
    payload: LegalHoldRequest,
    principal: Principal = Depends(require_permission("platform.admin")),
) -> dict:
    """Place or lift a legal hold (Phase 6, DB-11).

    A hold makes the tenant's data undeletable - erasure and retention both
    refuse it - so placing one requires a stated reason and both directions
    are audited.
    """
    _require_platform_admin(principal)
    target = _safe_tenant(tenant_id)
    if not tenant_exists(target):
        raise HTTPException(status_code=404, detail="Tenant not found")
    try:
        hold = store_module.set_legal_hold(target, payload.active, payload.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The legal hold could not be changed")) from exc
    audit_tenant = principal.tenant_id if principal.tenant_id != target else "default"
    audit(audit_tenant, principal.subject,
          "tenant.legal_hold.set" if payload.active else "tenant.legal_hold.lifted",
          {"tenant_id": target, "reason": hold["reason"]})
    return hold


@app.post("/api/api-keys")
def create_api_key(payload: ApiKeyRequest, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    role = payload.role.strip().lower()
    if not _delegable(role, principal.tenant_id):
        # Machine keys never carry admin - create admins via /api/users.
        raise HTTPException(status_code=400, detail="An API key's role must exist in this tenant and not administer it")
    if role_permissions_in(role, principal.tenant_id) & PERSON_ONLY_PERMISSIONS:
        # A leaked machine key must not administer, handle stored credentials or reveal values.
        raise HTTPException(status_code=400, detail="An API key's role may not administer, manage credentials "
                                                    "or reveal values; those are for a person")
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
def list_api_keys_route(principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    return {"api_keys": list_api_keys(principal.tenant_id)}


@app.post("/api/api-keys/{key_id}/revoke")
def revoke_api_key_route(key_id: str, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    if not revoke_api_key(principal.tenant_id, key_id):
        raise HTTPException(status_code=404, detail="API key not found or already revoked")
    audit(principal.tenant_id, principal.subject, "api_key.revoked", {"key_id": key_id})
    return {"revoked": True, "key_id": key_id}


def _credential_privilege(tenant_id: str, secret_ref: str, username: str, domain: str) -> dict:
    """C12: how much the account can do, checked when it is saved and on request, kept with
    it. A failed check says so; it never blocks saving."""
    try:
        result = credential_preflight.assess(tenant_id, username, domain)
    except Exception as exc:
        result = {"level": "unchecked", "findings": [f"The privilege check could not run ({type(exc).__name__})."],
                  "source": "none", "advice": ""}
    store_module.set_secret_privilege(tenant_id, secret_ref, result)
    return result


@app.post("/api/credentials")
def store_credentials(payload: CredentialRequest,
                      principal: Principal = Depends(require_permission("scan.run", "credential.manage", person_only=True))) -> dict:
    username = payload.username.strip()
    domain = payload.domain.strip() or "WORKGROUP"
    secret_ref = vault.store(principal.tenant_id, username, payload.password, domain)
    privilege = _credential_privilege(principal.tenant_id, secret_ref, username, domain)
    audit(principal.tenant_id, principal.subject, "credential.stored",
          {"secret_ref": secret_ref, "account": username, "privilege": privilege["level"]})
    return {"credential_ref": secret_ref, "domain": domain, "privilege": privilege}


@app.get("/api/credentials")
def list_credentials(principal: Principal = Depends(require_permission("credential.manage"))) -> dict:
    """C12: the workspace's saved credentials - account, dates, key, privilege - never a secret."""
    return {"credentials": credential_listing(principal.tenant_id), "rotation_days": rotation_days()}


def _own_credential(tenant_id: str, secret_ref: str) -> dict:
    entry = next((item for item in store_module.list_secret_metadata(tenant_id)
                  if item["credential_ref"] == secret_ref), None)
    if entry is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    return entry


@app.put("/api/credentials/{secret_ref}")
def replace_credential(secret_ref: str, payload: CredentialRequest,
                       principal: Principal = Depends(require_permission("credential.manage"))) -> dict:
    """The account's password changed: seal the new one under the same reference, so the
    scan profiles and schedules that use it keep working."""
    entry = _own_credential(principal.tenant_id, secret_ref)
    if entry["kind"] != "scan":
        raise HTTPException(status_code=400, detail="This credential belongs to directory sign-in; change it there.")
    username = payload.username.strip()
    domain = payload.domain.strip() or "WORKGROUP"
    vault.replace(principal.tenant_id, secret_ref, username, payload.password, domain)
    privilege = _credential_privilege(principal.tenant_id, secret_ref, username, domain)
    audit(principal.tenant_id, principal.subject, "credential.rotated",
          {"secret_ref": secret_ref, "account": username, "privilege": privilege["level"]})
    return {"credential_ref": secret_ref, "privilege": privilege}


@app.post("/api/credentials/{secret_ref}/preflight")
def check_credential_privilege(secret_ref: str, principal: Principal = Depends(require_permission("credential.manage"))) -> dict:
    _own_credential(principal.tenant_id, secret_ref)
    account = vault.resolve(principal.tenant_id, secret_ref, kind=None)  # only the account name is read
    privilege = _credential_privilege(principal.tenant_id, secret_ref, account.get("username", ""),
                                      account.get("domain", ""))
    audit(principal.tenant_id, principal.subject, "credential.preflight",
          {"secret_ref": secret_ref, "privilege": privilege["level"]})
    return {"credential_ref": secret_ref, "privilege": privilege}


@app.delete("/api/credentials/{secret_ref}")
def delete_credential(secret_ref: str, principal: Principal = Depends(require_permission("credential.manage"))) -> dict:
    entry = _own_credential(principal.tenant_id, secret_ref)
    if entry["kind"] != "scan":
        raise HTTPException(status_code=400, detail="This credential belongs to directory sign-in; remove it there.")
    vault.delete(principal.tenant_id, secret_ref)
    audit(principal.tenant_id, principal.subject, "credential.deleted", {"secret_ref": secret_ref, "account": entry["label"]})
    return {"deleted": True, "credential_ref": secret_ref}


class ScanProfileRequest(BaseModel):
    profile_id: str = Field(default="", max_length=40)
    kind: str = Field(pattern="^(file-server|endpoint)$")
    name: str = Field(min_length=1, max_length=80)
    config: dict = Field(default_factory=dict)


@app.get("/api/scan-profiles")
def scan_profiles_index(principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    return {
        "tenant_id": principal.tenant_id,
        "profiles": list_scan_profiles(principal.tenant_id),
    }


@app.post("/api/scan-profiles")
def scan_profiles_save(payload: ScanProfileRequest, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    try:
        profile = save_scan_profile(
            principal.tenant_id,
            profile_id=payload.profile_id or None,
            kind=payload.kind,
            name=payload.name,
            config=payload.config,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=client_message(exc, "The scan profile could not be saved")) from exc
    audit(principal.tenant_id, principal.subject, "scan_profile.saved", {"profile_id": profile["profile_id"], "kind": payload.kind})
    return profile


@app.delete("/api/scan-profiles/{profile_id}")
def scan_profiles_delete(profile_id: str, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    removed = delete_scan_profile(principal.tenant_id, profile_id)
    if not removed:
        # C3: the same answer for another tenant's profile as for no profile at all -
        # every other identifier route refuses with a 404, and so does this one.
        raise HTTPException(status_code=404, detail="Scan profile not found")
    audit(principal.tenant_id, principal.subject, "scan_profile.deleted", {"profile_id": profile_id})
    return {"deleted": True}


class ScheduleRequest(BaseModel):
    """A scan to run unattended: what to scan, how often, and when it first falls due."""

    name: str = Field(default="", max_length=120)
    interval_seconds: int = Field(default=86400, ge=300, le=366 * 24 * 3600)
    enabled: bool = True
    first_run_at: str = Field(default="", max_length=40)
    scan: ScanRequest


class ScheduleUpdateRequest(BaseModel):
    name: str | None = Field(default=None, max_length=120)
    interval_seconds: int | None = Field(default=None, ge=300, le=366 * 24 * 3600)
    enabled: bool | None = None
    scan: ScanRequest | None = None


def _schedule_first_run(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="first_run_at must be an ISO 8601 time") from exc
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def _schedulable(request: dict) -> dict:
    """A schedule must be able to run with nobody there, so its credential must be one
    the vault holds: a typed password is never stored, and a schedule that needed one
    would fail every night at the same point."""
    if not scan_request_is_resumable(request):
        raise HTTPException(
            status_code=422,
            detail="A scheduled scan needs a saved credential: a typed password is never stored.",
        )
    return request


@app.get("/api/scan-schedules")
def scan_schedules_index(principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    return {
        "tenant_id": principal.tenant_id,
        "schedules": list_scan_schedules(principal.tenant_id),
    }


@app.post("/api/scan-schedules")
def scan_schedules_create(payload: ScheduleRequest, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    schedule = create_scan_schedule(
        principal.tenant_id,
        name=payload.name,
        request=_schedulable(payload.scan.model_dump(mode="json")),
        interval_seconds=payload.interval_seconds,
        first_run_at=_schedule_first_run(payload.first_run_at),
        enabled=payload.enabled,
        created_by=principal.subject,
    )
    audit(principal.tenant_id, principal.subject, "schedule.created",
          {"schedule_id": schedule["schedule_id"], "interval_seconds": schedule["interval_seconds"]})
    return schedule


@app.patch("/api/scan-schedules/{schedule_id}")
def scan_schedules_update(schedule_id: str, payload: ScheduleUpdateRequest,
                          principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    request = _schedulable(payload.scan.model_dump(mode="json")) if payload.scan is not None else None
    schedule = update_scan_schedule(
        principal.tenant_id, schedule_id,
        name=payload.name, request=request,
        interval_seconds=payload.interval_seconds, enabled=payload.enabled,
    )
    if schedule is None:
        raise HTTPException(status_code=404, detail="Scan schedule not found")
    audit(principal.tenant_id, principal.subject, "schedule.updated", {"schedule_id": schedule_id})
    return schedule


@app.delete("/api/scan-schedules/{schedule_id}")
def scan_schedules_delete(schedule_id: str, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    removed = delete_scan_schedule(principal.tenant_id, schedule_id)
    if not removed:
        # C3: as its own PATCH and run-now already did - a schedule this tenant does not
        # have is a 404, whoever else has it.
        raise HTTPException(status_code=404, detail="Schedule not found")
    audit(principal.tenant_id, principal.subject, "schedule.deleted", {"schedule_id": schedule_id})
    return {"deleted": True}


@app.post("/api/scan-schedules/{schedule_id}/run")
def scan_schedules_run_now(schedule_id: str, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    """Make a schedule due now; the scheduler starts it on its next sweep."""
    schedule = update_scan_schedule(
        principal.tenant_id, schedule_id, enabled=True, next_run_at=datetime.now(timezone.utc),
    )
    if schedule is None:
        raise HTTPException(status_code=404, detail="Scan schedule not found")
    audit(principal.tenant_id, principal.subject, "schedule.updated", {"schedule_id": schedule_id, "run_now": True})
    return schedule


@app.post("/api/test-connection")
def test_connection(payload: ConnectionRequest, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    if not _is_local_endpoint_host(payload.server):
        _validate_scan_target(payload.server, principal)
    engine = DSPMDiscoveryEngine(_to_config(payload, principal.tenant_id))
    audit(principal.tenant_id, principal.subject, "connection.test", {"server": _safe_target_label(payload.server)})
    return engine.test_connection()


@app.post("/api/endpoint/test-connection")
def endpoint_test_connection(payload: EndpointScanRequest, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
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
    _validate_scan_target(payload.host, principal)
    scanner = WinRMEndpointScanner(_to_endpoint_config(payload, principal.tenant_id))
    transport = scanner.transport_summary()
    audit(
        principal.tenant_id,
        principal.subject,
        "endpoint.connection.test",
        {
            "host": _safe_target_label(payload.host),
            "target_username": payload.target_username,
            # C0.1: the audit trail says how the console proposed to reach the
            # endpoint, not merely that someone tested it.
            "transport": f"{transport['scheme']}:{transport['port']}",
            "certificate_trust": transport["certificate_trust"],
            "authentication": transport["authentication"],
        },
    )
    return {**scanner.test_connection(), "transport": transport}


@app.post("/api/endpoint/check-access")
def endpoint_check_access(payload: EndpointScanRequest, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    """What the supplied credential can actually reach on the target.

    An endpoint scan needs no administrator - it reads, and stages one file in
    the connecting user's own temp - but two Windows defaults make a privileged
    account the path of least resistance: only local Administrators may open a
    WinRM session, and one account cannot read another's profile folder. Both
    are grantable, and this is how an operator confirms a least-privilege
    account is sufficient without discovering it half way through a scan.
    """

    if _is_local_endpoint_host(payload.host):
        return {
            "ok": platform.system().lower() == "windows",
            "host": payload.host,
            "user": os.getenv("USERNAME") or "",
            "computer": socket.gethostname(),
            "verdict": "A local scan runs as the account the DSPM backend runs as; there is no WinRM credential to check.",
            "profiles": [],
        }
    _validate_scan_target(payload.host, principal)
    scanner = WinRMEndpointScanner(_to_endpoint_config(payload, principal.tenant_id))
    transport = scanner.transport_summary()
    audit(
        principal.tenant_id,
        principal.subject,
        "endpoint.access.check",
        {
            "host": _safe_target_label(payload.host),
            "target_username": payload.target_username,
            "transport": f"{transport['scheme']}:{transport['port']}",
            "certificate_trust": transport["certificate_trust"],
        },
    )
    try:
        return {**scanner.check_access(), "transport": transport}
    except Exception as exc:
        raise _safe_operation_error("Endpoint access check failed", exc) from exc


@app.post("/api/endpoint/activate-local-winrm")
def endpoint_activate_local_winrm(payload: LocalWinRMActivationRequest, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
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
def endpoint_activate_winrm(payload: EndpointScanRequest, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    if _is_local_endpoint_host(payload.host):
        return endpoint_activate_local_winrm(
            LocalWinRMActivationRequest(domain=payload.domain, username=payload.username, password=payload.password),
            principal,
        )
    _validate_scan_target(payload.host, principal)
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
def endpoint_repair_winrm(payload: EndpointScanRequest, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    if _is_local_endpoint_host(payload.host):
        return endpoint_activate_local_winrm(
            LocalWinRMActivationRequest(domain=payload.domain, username=payload.username, password=payload.password),
            principal,
        )
    _validate_scan_target(payload.host, principal)
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
@evidence_scoped
def endpoint_scan(payload: EndpointScanRequest, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    _require_scan_licence()
    try:
        if not _is_local_endpoint_host(payload.host):
            _validate_scan_target(payload.host, principal)
        config = _to_endpoint_config(payload, principal.tenant_id)
        if payload.async_scan:
            job = create_job(principal.tenant_id, lambda job: _run_endpoint_scan_payload(config, payload, principal, job))
            audit(principal.tenant_id, principal.subject, "endpoint.scan.queued", {"job_id": job.id, "host": payload.host})
            return job.to_dict()

        data = _run_endpoint_scan_payload(config, payload, principal)
        audit(principal.tenant_id, principal.subject, "endpoint.scan.completed", {"scan_id": data.get("scan_id"), "host": payload.host})
        return _compact_scan_report(data) if payload.compact_result else data
    except (HTTPException, SavedCredentialMissing):
        raise
    except Exception as exc:
        raise _safe_operation_error("Endpoint operation failed", exc) from exc


@app.post("/api/demo-data/generate")
def generate_demo_data(payload: DemoDataRequest, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
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


def _require_scan_licence() -> None:
    """D10: with DSPM_LICENCE_REQUIRED on, a scan needs a valid licence (or one in its
    grace period). Nothing else is refused: findings, reports and exports stay readable.

    A scan also needs room to write (backend.disk_guard): below DSPM_MIN_FREE_DISK_MB on a
    volume it writes to, it is refused with 507 rather than started into a full disk."""
    from backend import disk_guard, licensing

    full = disk_guard.low_space_reason()
    if full:
        raise HTTPException(status_code=507, detail=f"Scan not started: {full}. Free space on that volume "
                            "(or lower DSPM_MIN_FREE_DISK_MB) and start it again.")

    allowed, why = licensing.scans_allowed()
    if not allowed:
        raise HTTPException(status_code=402, detail=f"{why} New scans need a valid licence; everything already "
                            "found stays available. Install the licence in Settings, or on the host with "
                            "`python main.py licence install <file>`.")


@app.post("/api/scan")
@evidence_scoped
def scan(payload: ScanRequest, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    _require_scan_licence()
    try:
        if not _is_local_endpoint_host(payload.server):
            _validate_scan_target(payload.server, principal)
        _prepare_local_scan_data(payload)
        if partitioned_scans_enabled():
            # Local targets split into runs of their walk, SMB servers into groups of
            # shares; a target that does not split runs as an ordinary scan.
            config = _to_config(payload, principal.tenant_id)
            if payload.async_scan:
                job = create_job(principal.tenant_id, lambda job: _run_partitioned_scan_payload(config, payload, principal, job))
                audit(principal.tenant_id, principal.subject, "scan.queued", {"job_id": job.id, "server": _safe_target_label(payload.server)})
                return job.to_dict()
            data = _run_partitioned_scan_payload(config, payload, principal)
            audit(principal.tenant_id, principal.subject, "scan.completed", {"scan_id": data.get("scan_id")})
            return _compact_scan_report(data) if payload.compact_result else data
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
    except (HTTPException, SavedCredentialMissing):
        raise
    except Exception as exc:
        raise _safe_operation_error("Scan failed", exc) from exc


# ── D6: database column sampling ───────────────────────────────────────────────────
class DatabaseScanRequest(BaseModel):
    """A database to sample. The password is typed for this scan and never stored, or a
    saved credential's reference is given instead."""
    engine: str = Field(default="postgresql", max_length=20)
    host: str = Field(min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    database: str = Field(min_length=1, max_length=128)
    username: str = Field(default="", max_length=128)
    password: str | None = Field(default=None, max_length=1024)
    credential_ref: str | None = Field(default=None, max_length=128)
    sslmode: str = Field(default="verify-full", max_length=20)
    schemas: list[str] = Field(default_factory=list, max_length=100)
    include_tables: list[str] = Field(default_factory=list, max_length=100)
    sample_rows: int = Field(default=1000, ge=1, le=10_000)
    max_tables: int = Field(default=500, ge=1, le=5000)
    scan_label: str = Field(default="", max_length=80)
    save_report: bool = True
    compact_result: bool = True
    compliance_enabled: bool = True
    compliance_frameworks: list[str] = Field(default_factory=lambda: ["gdpr", "pci_dss"], max_length=10)


_DB_SSLMODES = ("verify-full", "verify-ca", "require", "prefer", "disable")


def _database_source(payload: DatabaseScanRequest, principal: Principal):
    from collectors import database_scanner
    from collectors.net_guard import TargetNotAllowed, resolve_and_pin

    engine = payload.engine.strip().lower()
    if engine not in database_scanner.ENGINES:
        raise HTTPException(status_code=400, detail="Choose postgresql, mysql or sqlserver.")
    sslmode = payload.sslmode.strip().lower()
    if sslmode not in _DB_SSLMODES:
        raise HTTPException(status_code=400, detail="sslmode must be verify-full, verify-ca, require, prefer or disable.")
    if IS_PRODUCTION and sslmode not in {"verify-full", "verify-ca"}:
        raise HTTPException(status_code=400, detail="In production a database is read over verified TLS: "
                            "sslmode verify-full or verify-ca.")
    _validate_scan_target(payload.host, principal)
    try:
        address = resolve_and_pin(payload.host, tenant_id=principal.tenant_id)
    except TargetNotAllowed as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "That database host is not allowed.")) from exc
    username, password = payload.username.strip(), payload.password or ""
    if payload.credential_ref:
        try:
            account = CredentialVault().resolve(principal.tenant_id, payload.credential_ref)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Saved credential not found") from exc
        username, password = account.get("username") or username, account.get("password") or ""
    if not username:
        raise HTTPException(status_code=400, detail="Give the database user name, or a saved credential.")
    source = database_scanner.DatabaseSource(
        engine=engine, host=payload.host.strip(), port=payload.port or database_scanner.DEFAULT_PORTS[engine],
        database=payload.database.strip(), username=username, password=password, sslmode=sslmode,
        schemas=[item.strip() for item in payload.schemas if item.strip()],
        include_tables=[item.strip() for item in payload.include_tables if item.strip()],
        sample_rows=payload.sample_rows, max_tables=payload.max_tables, address=address)
    return source.bounded()


@app.post("/api/database/scan")
@evidence_scoped
def database_scan(payload: DatabaseScanRequest, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    """D6: sample a database's text columns and report the ones holding sensitive data -
    table and row counts, the sample's size, masked samples only."""
    from collectors import database_scanner
    from discovery.database_engine import DatabaseDiscoveryEngine

    _require_scan_licence()
    source = _database_source(payload, principal)
    config = ScanConfig(tenant_id=principal.tenant_id, compliance_enabled=payload.compliance_enabled,
                        compliance_frameworks=list(payload.compliance_frameworks),
                        suppression_rules=suppression_rules_for_scan(principal.tenant_id),
                        exact_match=_exact_match_for_scan(principal.tenant_id))
    try:
        data = DatabaseDiscoveryEngine(config, source).run().to_dict()
    except database_scanner.DatabaseScanError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The database could not be scanned.")) from exc
    except Exception as exc:
        raise _safe_operation_error("Database scan failed", exc) from exc
    data["source"] = f"{source.engine}://{source.host}:{source.port}/{source.database}"
    _apply_compliance(data, payload)
    _persist_scan(data, payload, principal)
    audit(principal.tenant_id, principal.subject, "scan.completed", {
        "scan_id": data.get("scan_id"), "database": data["source"],
        "columns": len(data.get("files") or []), "sample_rows": source.sample_rows})
    return _compact_scan_report(data) if payload.compact_result else data


# ── D5: SharePoint Online / OneDrive through Microsoft Graph ───────────────────────
class SharePointScanRequest(BaseModel):
    """A SharePoint site to scan. The saved credential is the Entra application: its id as
    the user name, its secret as the password, the Entra tenant as the domain."""
    site: str = Field(min_length=3, max_length=400)
    credential_ref: str = Field(min_length=1, max_length=120)
    scan_label: str = Field(default="", max_length=80)
    full: bool = False
    allowed_extensions: list[str] = Field(default_factory=list, max_length=160)
    extension_filter_enabled: bool = False
    save_report: bool = True
    compact_result: bool = True
    compliance_enabled: bool = True
    compliance_frameworks: list[str] = Field(default_factory=lambda: ["gdpr", "pci_dss"], max_length=10)


def _graph_source(payload: SharePointScanRequest, principal: Principal):
    from collectors import graph_scanner

    site = payload.site.strip()
    host = site.split(":", 1)[0].strip().lower()
    _validate_scan_target(host, principal)
    try:
        account = CredentialVault().resolve(principal.tenant_id, payload.credential_ref)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Saved credential not found") from exc
    if not (account.get("username") and account.get("password") and account.get("domain")):
        raise HTTPException(status_code=400, detail="The saved credential must hold the application id (user name), "
                            "its secret (password) and the Entra tenant (domain).")
    ca_file = os.getenv("DSPM_GRAPH_CA_FILE", "").strip()
    hosts = tuple(item.strip().lower() for item in os.getenv("DSPM_GRAPH_DOWNLOAD_HOSTS", "").split(",") if item.strip())
    return graph_scanner.GraphSource(
        tenant=str(account["domain"]), client_id=str(account["username"]), client_secret=str(account["password"]),
        site=site, authority=os.getenv("DSPM_GRAPH_AUTHORITY", "https://login.microsoftonline.com").strip(),
        graph=os.getenv("DSPM_GRAPH_ENDPOINT", "https://graph.microsoft.com").strip(),
        ca_pem=Path(ca_file).read_text(encoding="utf-8") if ca_file else "",
        download_hosts=hosts or graph_scanner.GraphSource.__dataclass_fields__["download_hosts"].default)


def _connector_scan_label(readable: str, scope_key: str) -> str:
    """The automatic name of a connector scan that was given none.

    A complete scan prunes by its name (store._prune_unseen_assets): every asset of an
    earlier scan of that name that this one did not see leaves the estate. So two scans
    that see different things - another path, port or extension filter - must not share
    a name. The scope's digest ends it, and it is the readable part that is cut to fit,
    never the digest: two long site addresses cut to 80 characters used to be one name.
    """
    suffix = f" #{scope_key[:12]}"
    return readable[:80 - len(suffix)].rstrip() + suffix


@app.post("/api/sharepoint/scan")
@evidence_scoped
def sharepoint_scan(payload: SharePointScanRequest, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    """D5: a SharePoint site's libraries through Graph. The first scan reads every file;
    each later one only what changed, from the checkpoint the last completed scan kept."""
    from collectors import graph_scanner
    from discovery.graph_engine import GraphDiscoveryEngine

    _require_scan_licence()
    source = _graph_source(payload, principal)
    # The checkpoint follows the site whatever the filter: it holds every file of the site,
    # and a file is reused only while its size and modified time match. The scope - the
    # baseline a complete scan prunes, and its automatic name - follows what it sees.
    key = f"sharepoint:{source.site.lower()}"
    allowed_extensions, extension_filter_enabled = _scan_extension_settings(
        payload.allowed_extensions, payload.extension_filter_enabled)
    scope = incremental_scope_key("sharepoint", source.site, {"allowed_extensions": allowed_extensions})
    checkpoint = None if payload.full else store_module.get_source_checkpoint(principal.tenant_id, key)
    label = payload.scan_label.strip()[:80] or _connector_scan_label(
        " ".join(["SharePoint", source.site, *allowed_extensions]), scope)
    config = ScanConfig(tenant_id=principal.tenant_id, compliance_enabled=payload.compliance_enabled,
                        compliance_frameworks=list(payload.compliance_frameworks),
                        allowed_extensions=allowed_extensions,
                        extension_filter_enabled=extension_filter_enabled,
                        incremental_enabled=True, incremental_scope=scope,
                        baseline_probe=_incremental_probe(principal.tenant_id, scope, True),
                        suppression_rules=suppression_rules_for_scan(principal.tenant_id),
                        exact_match=_exact_match_for_scan(principal.tenant_id))
    engine = GraphDiscoveryEngine(config, source, checkpoint)
    try:
        data = engine.run().to_dict()
    except graph_scanner.GraphScanError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The SharePoint site could not be scanned.")) from exc
    except Exception as exc:
        raise _safe_operation_error("SharePoint scan failed", exc) from exc
    data["source"] = f"sharepoint://{source.site}"
    payload.scan_label = label
    _apply_compliance(data, payload)
    _persist_scan(data, payload, principal)
    if engine.next_checkpoint is not None:
        # Kept only once the scan's report is stored: a scan that failed does not move it.
        store_module.save_source_checkpoint(principal.tenant_id, key, engine.next_checkpoint)
    facts = engine.last_scan_diagnostics or {}
    audit(principal.tenant_id, principal.subject, "scan.completed", {
        "scan_id": data.get("scan_id"), "sharepoint": source.site, "incremental": bool(checkpoint),
        **{name: int(facts.get(name) or 0) for name in ("changed", "deleted", "downloaded", "reused")},
        "unreadable": len(facts.get("unreadable") or [])})
    return _compact_scan_report(data) if payload.compact_result else data


# ── D9: Linux and macOS over SSH/SFTP ──────────────────────────────────────────────
class SftpScanRequest(BaseModel):
    """A host to read over SFTP with an ordinary account. The host key's SHA-256 fingerprint
    (as `ssh-keygen -lf` prints it) is required: an unknown or changed key is refused."""
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    credential_ref: str = Field(min_length=1, max_length=120)
    host_key_fingerprint: str = Field(pattern=r"^SHA256:[A-Za-z0-9+/]{43}$")
    paths: list[str] = Field(default_factory=lambda: ["/home"], min_length=1, max_length=50)
    max_depth: int = Field(default=8, ge=1, le=20)
    scan_label: str = Field(default="", max_length=80)
    allowed_extensions: list[str] = Field(default_factory=list, max_length=160)
    extension_filter_enabled: bool = False
    save_report: bool = True
    compact_result: bool = True
    compliance_enabled: bool = True
    compliance_frameworks: list[str] = Field(default_factory=lambda: ["gdpr", "pci_dss"], max_length=10)


@app.post("/api/sftp/scan")
@evidence_scoped
def sftp_scan(payload: SftpScanRequest, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    """D9: a Linux or macOS host's files over SFTP. The saved credential is the account: a
    password, or - with the domain set to `ssh-key` - an OpenSSH private key."""
    from collectors import sftp_scanner
    from collectors.net_guard import TargetNotAllowed, resolve_and_pin
    from discovery.sftp_engine import SftpDiscoveryEngine

    _require_scan_licence()
    host = payload.host.strip()
    _validate_scan_target(host, principal)
    try:
        address = resolve_and_pin(host, tenant_id=principal.tenant_id)
    except TargetNotAllowed as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "That host is not allowed.")) from exc
    try:
        account = CredentialVault().resolve(principal.tenant_id, payload.credential_ref)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Saved credential not found") from exc
    key = str(account.get("domain") or "").lower() == "ssh-key"
    source = sftp_scanner.SftpSource(
        host=host, port=payload.port, username=str(account.get("username") or ""), address=address,
        password="" if key else str(account.get("password") or ""),
        private_key=str(account.get("password") or "") if key else "",
        host_key_fingerprint=payload.host_key_fingerprint, paths=list(payload.paths), max_depth=payload.max_depth)
    allowed_extensions, extension_filter_enabled = _scan_extension_settings(
        payload.allowed_extensions, payload.extension_filter_enabled)
    # Everything that changes what the scan sees is in its scope, and so in its automatic
    # name: a scan of /srv must not prune /home's assets, nor port 2222 port 22's.
    where = sftp_scanner.authority(source)
    paths = sorted({sftp_scanner.root_path(item) for item in source.paths})
    scope = incremental_scope_key("sftp", where, {
        "port": source.port, "paths": paths, "max_depth": source.max_depth,
        "allowed_extensions": allowed_extensions, "include_hidden": source.include_hidden})
    label = payload.scan_label.strip()[:80] or _connector_scan_label(" ".join(["SFTP", where, *paths]), scope)
    config = ScanConfig(tenant_id=principal.tenant_id, compliance_enabled=payload.compliance_enabled,
                        compliance_frameworks=list(payload.compliance_frameworks),
                        allowed_extensions=allowed_extensions,
                        extension_filter_enabled=extension_filter_enabled,
                        incremental_enabled=True, incremental_scope=scope,
                        baseline_probe=_incremental_probe(principal.tenant_id, scope, True),
                        suppression_rules=suppression_rules_for_scan(principal.tenant_id),
                        exact_match=_exact_match_for_scan(principal.tenant_id))
    try:
        data = SftpDiscoveryEngine(config, source).run().to_dict()
    except sftp_scanner.SftpScanError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The host could not be scanned.")) from exc
    except Exception as exc:
        raise _safe_operation_error("SFTP scan failed", exc) from exc
    data["source"] = f"sftp://{where}"
    payload.scan_label = label
    _apply_compliance(data, payload)
    _persist_scan(data, payload, principal)
    facts = data.get("scan_diagnostics") or {}
    audit(principal.tenant_id, principal.subject, "scan.completed", {
        "scan_id": data.get("scan_id"), "sftp": host, "files": int(facts.get("files") or 0),
        "read": int(facts.get("read") or 0), "reused": int(facts.get("reused") or 0),
        "unreadable": len(facts.get("unreadable") or []) + len(facts.get("unreadable_dirs") or [])})
    return _compact_scan_report(data) if payload.compact_result else data


@app.get("/api/scans/{job_id}")
@evidence_scoped
def scan_job(job_id: str, principal: Principal = Depends(require_permission("inventory.view"))) -> dict:
    cleanup_jobs()
    job = get_job(job_id)
    if job is not None and job.tenant_id == principal.tenant_id:
        current = job.to_dict()
        if current.get("status") != "paused":
            return current
    # A paused job is followed through its row: what continues it (here or elsewhere)
    # and what reconciles it write there, not into this process's copy (W2.4).
    # ARCH-003: fall back to the durable record so a job that outlived its
    # in-memory entry (retention cleanup, or a backend restart) is still visible.
    # B3.1: it is also how a console on this backend watches a scan running on another
    # one, which is why a running job's progress reaches the record once a second.
    record = read_job(principal.tenant_id, job_id)
    if record is not None:
        return record
    raise HTTPException(status_code=404, detail="Scan job not found")


@app.post("/api/scans/{job_id}/cancel")
def stop_scan(job_id: str, principal: Principal = Depends(require_permission("scan.run"))) -> dict:
    from backend.jobs import request_cancel

    job = get_job(job_id)
    if (job is None or job.tenant_id != principal.tenant_id) and read_job(principal.tenant_id, job_id) is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    # W2.4: a job another backend or worker runs is cancelled through its row.
    stopped = request_cancel(principal.tenant_id, job_id)
    audit(principal.tenant_id, principal.subject, "scan.cancel", {"job_id": job_id, "stopped": stopped})
    return {"cancelled": stopped}


@app.get("/api/history")
def scan_history(
    principal: Principal = Depends(require_permission("inventory.view")),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict:
    return {
        "tenant_id": principal.tenant_id,
        "history": read_scan_history(principal.tenant_id, limit=limit),
    }


@app.get("/api/history/latest/report")
@evidence_scoped
def latest_scan_report(
    principal: Principal = Depends(require_permission("inventory.view")),
    include_files: bool = Query(default=True),
) -> dict:
    report = read_scan_report(principal.tenant_id)
    if report is None:
        raise HTTPException(status_code=404, detail="No saved scan report found")
    if include_files:
        _audit_full_report(principal, report)
    return {"report": report if include_files else _compact_scan_report(report)}


@app.get("/api/history/{scan_id}/report")
@evidence_scoped
def saved_scan_report(
    scan_id: str,
    principal: Principal = Depends(require_permission("inventory.view")),
    include_files: bool = Query(default=True),
) -> dict:
    if include_files:
        report = read_scan_report(principal.tenant_id, scan_id)
    else:
        report = read_scan_report_compact(principal.tenant_id, scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Saved scan report not found")
    if include_files:
        _audit_full_report(principal, report)
    return {"report": report}


def _audit_full_report(principal: Principal, report: dict) -> None:
    """C4: a full scan report is every file record a scan produced; fetching one is an
    export in all but name, so it is recorded. The console never asks for it - only an
    API client does - so this is not a row per page view."""
    files = report.get("files") if isinstance(report, dict) else None
    audit(principal.tenant_id, principal.subject, "scan_report.viewed", {
        "scan_id": str(report.get("scan_id") or "") if isinstance(report, dict) else "",
        "files": len(files) if isinstance(files, list) else 0,
        "evidence_included": has_permission(principal, "evidence.view"),
    })


@app.get("/api/findings")
def findings_index(
    principal: Principal = Depends(require_permission("inventory.view")),
    scope: str = Query(default="current", max_length=20),
    status: str = Query(default="active", max_length=200),
    severity: str = Query(default="", max_length=120),
    owner: str = Query(default="", max_length=600),
    framework: str = Query(default="", max_length=400),
    data_type: str = Query(default="", max_length=600),
    category: str = Query(default="", max_length=400),
    asset: str = Query(default="", max_length=600),
    sla: str = Query(default="", max_length=120),
    q: str = Query(default="", max_length=200),
    sort: str = Query(default="risk_score", max_length=30),
    direction: str = Query(default="", max_length=4),
    after: str = Query(default="", max_length=2048),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict:
    """Bounded remediation page.

    ``items`` is only the current page. Exact global counts come from
    ``summary`` and therefore never equal page length by inference.
    """
    return {
        **list_remediation_findings(
            principal.tenant_id,
            scope=scope,
            status=status,
            severity=severity,
            owner=owner,
            framework=framework,
            data_type=data_type,
            category=category,
            asset=asset,
            sla=sla,
            q=q,
            sort=sort,
            direction=direction,
            after=after,
            limit=limit,
        ),
        "tenant_id": principal.tenant_id,
    }


@app.get("/api/inventory")
def inventory_index(
    principal: Principal = Depends(require_permission("inventory.view")),
    risk: str = Query(default="", max_length=200),
    source: str = Query(default="", max_length=400),
    framework: str = Query(default="", max_length=400),
    finding_type: str = Query(default="", max_length=600),
    protected: bool | None = Query(default=None),
    q: str = Query(default="", max_length=200),
    extension: str = Query(default="", max_length=200),
    sort: str = Query(default="risk_score", max_length=20),
    direction: str = Query(default="", max_length=4),
    after: str = Query(default="", max_length=512),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    """S-C: keyset-paginated file inventory. The DB filters/sorts/searches so the
    browser fetches one page instead of the whole file list."""
    result = list_inventory(
        principal.tenant_id, risk=risk, source=source, framework=framework,
        finding_type=finding_type, protected=protected, q=q, extension=extension,
        sort=sort, direction=direction, cursor=after, limit=limit,
    )
    # The collapsed table shows real reason/action numbers. They are columns on
    # the row now; reading them from detail_json cost 11.3MB and 127ms of a
    # 165ms request. Only rows an older build wrote - and the backfill has not
    # reached - still need the blob.
    missing = [
        str(item.get("id") or "")
        for item in result.get("items", [])
        if item.get("reason_count") is None or item.get("dlp_count") is None
    ]
    if missing:
        try:
            from backend.store import inventory_reason_action_counts

            counts = inventory_reason_action_counts(principal.tenant_id, missing)
            for item in result.get("items", []):
                pair = counts.get(str(item.get("id") or ""))
                if pair is not None:
                    item["reason_count"], item["dlp_count"] = pair
        except Exception:
            pass
    # Echo the effective server-side scope so the browser can reject a stale
    # response if an MSSP administrator changes tenant while this request is in
    # flight. The data query itself is already tenant-predicated above.
    result["tenant_id"] = principal.tenant_id
    return result


@app.get("/api/inventory/export")
def inventory_export(
    principal: Principal = Depends(require_permission("export")),
    format: str = Query(default="csv", pattern="^(csv|ndjson)$"),
    risk: str = Query(default="", max_length=200),
    source: str = Query(default="", max_length=400),
    framework: str = Query(default="", max_length=400),
    finding_type: str = Query(default="", max_length=600),
    protected: bool | None = Query(default=None),
    q: str = Query(default="", max_length=200),
    extension: str = Query(default="", max_length=200),
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
def inventory_facet_index(
    principal: Principal = Depends(require_permission("inventory.view")),
    source: str = Query(default="", max_length=400),
) -> dict:
    return {
        **inventory_facets(principal.tenant_id, source=source),
        "tenant_id": principal.tenant_id,
    }


@app.get("/api/inventory-detail-counts")
def inventory_detail_counts(
    principal: Principal = Depends(require_permission("inventory.view")),
    ids: str = Query(default="", max_length=20_000),
) -> dict:
    """Batch reason/fix counts for specific assets. The row cells must show
    real numbers the moment a page renders; this backstops any data path
    whose payload predates (or misses) the per-page count attachment."""
    from backend.store import inventory_reason_action_counts

    wanted = [item.strip() for item in ids.split(",") if item.strip()][:500]
    counts = inventory_reason_action_counts(principal.tenant_id, wanted)
    return {
        "tenant_id": principal.tenant_id,
        "counts": {key: {"reasons": pair[0], "fixes": pair[1]} for key, pair in counts.items()},
    }


@app.get("/api/inventory/{asset_id}")
@evidence_scoped
def inventory_asset_detail(
    asset_id: str,
    principal: Principal = Depends(require_permission("inventory.view")),
    scan_id: str = Query(default="", max_length=100),
) -> dict:
    asset = get_inventory_asset(principal.tenant_id, asset_id, scan_id=scan_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Inventory asset not found")
    return {"tenant_id": principal.tenant_id, "asset": asset}


@app.get("/api/findings/{finding_id}")
@evidence_scoped
def finding_detail(finding_id: str, principal: Principal = Depends(require_permission("inventory.view"))) -> dict:
    finding = get_finding(principal.tenant_id, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    framework = normalize_framework_id(finding.get("framework"))
    detail = build_nist_finding_detail(finding) if framework == "nist_sp800_60_enterprise" else {"summary": {"display_name": get_finding_display_name(finding), "framework": framework}}
    finding["display_name"] = finding.get("display_name") or get_finding_display_name(finding)
    return {"finding": finding, "framework": framework, "detail": detail}


def _exact_match_for_scan(tenant_id: str) -> dict:
    """D2: the workspace's reference fingerprints, read once when a scan is configured."""
    from classification import exact_match

    return store_module.exact_match_index_for_scan(tenant_id, exact_match.key_digest())


class ExactMatchSetRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    entity_type: str = Field(min_length=1, max_length=40)
    values: list[str] = Field(min_length=1, max_length=50_000)


def _edm_max_rows() -> int:
    try:
        return max(1, int(os.getenv("DSPM_EDM_MAX_ROWS", "250000")))
    except ValueError:
        return 250_000


@app.post("/api/exact-match/sets")
def create_exact_match_set(payload: ExactMatchSetRequest,
                           principal: Principal = Depends(require_permission("rules.manage", person_only=True))) -> dict:
    """D2: an approved reference set. Its values are fingerprinted with the workspace's key
    and dropped: only the fingerprints are kept, never a value, and nothing about the
    values is logged, audited or returned. A GDPR finding whose value is in a set is
    confirmed from the next scan on."""
    from classification import exact_match

    entity_type = payload.entity_type.strip().upper()
    if entity_type not in exact_match.ENTITY_TYPES:
        raise HTTPException(status_code=400, detail="entity_type must be one of "
                            + ", ".join(sorted(exact_match.ENTITY_TYPES)))
    fingerprints = exact_match.fingerprints(entity_type, payload.values, principal.tenant_id)
    payload.values.clear()
    if not fingerprints:
        raise HTTPException(status_code=400, detail="The set holds no usable values.")
    set_id = secrets.token_hex(8)
    name = " ".join(payload.name.split())[:80]
    try:
        # The limit is checked by the store, in the transaction that inserts the set: a
        # count taken here, before it, let two uploads at once both fit (M4 exit review).
        rows = store_module.create_edm_set(principal.tenant_id, set_id, name, entity_type, fingerprints,
                                           exact_match.key_digest(), principal.subject, max_rows=_edm_max_rows())
    except store_module.EdmCapacityExceeded as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The reference set was refused.")) from exc
    audit(principal.tenant_id, principal.subject, "exact_match.set_created",
          {"set_id": set_id, "name": name, "entity_type": entity_type, "values": rows})
    return {"set_id": set_id, "name": name, "entity_type": entity_type, "values": rows}


@app.get("/api/exact-match/sets")
def list_exact_match_sets(principal: Principal = Depends(require_permission("rules.manage"))) -> dict:
    """D2: the workspace's reference sets - names, types and sizes, never a value or a
    fingerprint. A set built with a different evidence key matches nothing: `current`."""
    from classification import exact_match

    current = exact_match.key_digest()
    return {"sets": [{"set_id": item["set_id"], "name": item["name"], "entity_type": item["entity_type"],
                      "values": item["row_count"], "created_by": item["created_by"], "created_at": item["created_at"],
                      "current": item["key_digest"] == current}
                     for item in store_module.list_edm_sets(principal.tenant_id)],
            "entity_types": sorted(exact_match.ENTITY_TYPES)}


@app.delete("/api/exact-match/sets/{set_id}")
def delete_exact_match_set(set_id: str, principal: Principal = Depends(require_permission("rules.manage"))) -> dict:
    if not store_module.delete_edm_set(principal.tenant_id, set_id):
        raise HTTPException(status_code=404, detail="Reference set not found")
    audit(principal.tenant_id, principal.subject, "exact_match.set_deleted", {"set_id": set_id})
    return {"deleted": True, "set_id": set_id}


_ACCESS_KINDS = {"", "broad", "privileged", "service"}


@app.get("/api/access/principals")
def access_principals(kind: str = Query(default="", max_length=20), limit: int = Query(default=200, ge=1, le=1000),
                      principal: Principal = Depends(require_permission("inventory.view"))) -> dict:
    """D7: who can read files in this workspace's estate - each principal, how many files it
    can read and write, and how many of those hold findings; `kind` narrows it to broad
    groups, privileged accounts, or service and indexer accounts."""
    if kind not in _ACCESS_KINDS:
        raise HTTPException(status_code=400, detail="kind must be broad, privileged or service")
    return {"principals": store_module.list_access_principals(principal.tenant_id, kind=kind, limit=limit)}


@app.get("/api/access/files")
def access_files(key: str = Query(default="", max_length=256), kind: str = Query(default="", max_length=20),
                 sensitive_only: bool = True, writable_only: bool = False,
                 # Bounded like every sibling list: a 20-digit offset reached SQLite as an
                 # integer it cannot hold and answered 500.
                 limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0, le=1_000_000),
                 cursor: str = Query(default="", max_length=1024),
                 principal: Principal = Depends(require_permission("inventory.view"))) -> dict:
    """D7: the files a principal (its `key` from /api/access/principals) can read - or
    write - or, with `kind`, the files a broad group, privileged or service/indexer
    account can; by default only files holding findings, riskiest first."""
    if kind not in _ACCESS_KINDS:
        raise HTTPException(status_code=400, detail="kind must be broad, privileged or service")
    if not key and not kind:
        raise HTTPException(status_code=400, detail="Name a principal (key) or a kind (broad, privileged or service).")
    after = None
    if cursor:
        # W2.5: the next page starts after the last file of this one (risk, path, id).
        try:
            decoded = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8"))
            after = (float(decoded[0]), str(decoded[1]), str(decoded[2]))
        except (ValueError, TypeError, IndexError):
            raise HTTPException(status_code=400, detail="cursor is not one this list issued") from None
    files = store_module.list_access_assets(principal.tenant_id, principal_key=key.strip()[:256], kind=kind,
                                            sensitive_only=sensitive_only, writable_only=writable_only,
                                            limit=limit, offset=offset, after=after)
    next_cursor = ""
    if len(files) == limit:
        last = files[-1]
        next_cursor = base64.urlsafe_b64encode(json.dumps(
            [last["risk_score"], last["path"], last["asset_id"]]).encode("utf-8")).decode("ascii")
    return {"files": files, "key": key, "kind": kind, "sensitive_only": sensitive_only,
            "writable_only": writable_only, "next_cursor": next_cursor}


class RevealRequest(BaseModel):
    fingerprint: str = Field(min_length=8, max_length=64)
    reason: str = Field(min_length=1, max_length=500)


# C13: reveals are counted per account, successful or not: a reveal reads a file from its
# source and returns a raw value, and a burst of them is exactly what a stolen session does.
REVEAL_THROTTLE = RouteThrottle("reveal", max(1, int(os.getenv("DSPM_REVEAL_MAX_PER_HOUR", "20"))), 3600)


# ── D10: the offline licence ───────────────────────────────────────────────────────
class LicenceRequest(BaseModel):
    licence: str = Field(min_length=2, max_length=65_536)


@app.get("/api/licence")
def licence_read(principal: Principal = Depends(require_permission("platform.admin"))) -> dict:
    from backend import licensing

    return {"licence": licensing.status(licensing.installed())}


@app.put("/api/licence")
def licence_install(payload: LicenceRequest,
                    principal: Principal = Depends(require_permission("platform.admin", person_only=True))) -> dict:
    """Install a licence file's content. It must be signed by a key the install trusts for
    licences, and in force; otherwise it is refused and the installed one stays."""
    from backend import licensing

    try:
        licence = licensing.install(payload.licence)
    except licensing.LicenceError as exc:
        reason = client_message(exc, "The licence was refused.")
        audit(principal.tenant_id, principal.subject, "licence.refused", {"reason": reason})
        raise HTTPException(status_code=400, detail=reason) from exc
    audit(principal.tenant_id, principal.subject, "licence.installed", {
        "licence_id": licence["licence_id"], "customer": licence["customer"], "expires_at": licence["expires_at"],
        "key_id": licence["key_id"]})
    return {"licence": licensing.status(licensing.installed())}


# ── D3: alerts, where they go, and tickets ─────────────────────────────────────────
class IntegrationRequest(BaseModel):
    """One channel's settings. A field left out keeps its saved value; a secret left out
    keeps the saved secret (see backend.integrations)."""
    enabled: bool | None = None
    url: str | None = Field(default=None, max_length=2000)
    min_severity: str | None = Field(default=None, max_length=10)
    rotate_secret: bool | None = None
    host: str | None = Field(default=None, max_length=255)
    port: int | None = None
    security: str | None = Field(default=None, max_length=10)
    sender: str | None = Field(default=None, max_length=254)
    recipients: list[str] | None = Field(default=None, max_length=20)
    username: str | None = Field(default=None, max_length=254)
    password: str | None = Field(default=None, max_length=4096)
    token: str | None = Field(default=None, max_length=4096)
    remove_secret: bool | None = None
    base_url: str | None = Field(default=None, max_length=2000)
    project_key: str | None = Field(default=None, max_length=20)
    issue_type: str | None = Field(default=None, max_length=60)
    instance_url: str | None = Field(default=None, max_length=2000)
    assignment_group: str | None = Field(default=None, max_length=80)
    ca_pem: str | None = Field(default=None, max_length=70_000)
    ca_name: str | None = Field(default=None, max_length=200)
    remove_ca: bool | None = None


class IntegrationEnabledRequest(BaseModel):
    enabled: bool


class TicketRequest(BaseModel):
    system: str | None = Field(default=None, max_length=20)


def _integration_channel(channel: str) -> str:
    from backend import integrations

    if channel not in integrations.CHANNELS:
        raise HTTPException(status_code=404, detail="Unknown integration.")
    return channel


def _integration_view(tenant_id: str, channel: str) -> dict:
    from backend import integrations

    return integrations.public_view(channel, store_module.get_alert_channel(tenant_id, channel),
                                    store_module.alert_delivery_queue(tenant_id, channel))


@app.get("/api/alerts")
def alerts_list(principal: Principal = Depends(require_permission("inventory.view")),
                status: str = Query(default="", pattern="^(|open|acknowledged)$"),
                limit: int = Query(default=200, ge=1, le=500)) -> dict:
    """D3: the workspace's alerts, newest first, each with where it was delivered."""
    return {"alerts": store_module.read_alerts(principal.tenant_id, limit, status=status),
            "open": store_module.count_open_alerts(principal.tenant_id)}


@app.post("/api/alerts/{alert_id}/acknowledge")
def alerts_acknowledge(alert_id: int, principal: Principal = Depends(require_permission("findings.triage"))) -> dict:
    if not store_module.acknowledge_alert(principal.tenant_id, alert_id, principal.subject):
        raise HTTPException(status_code=404, detail="No open alert with that id.")
    audit(principal.tenant_id, principal.subject, "alert.acknowledged", {"alert_id": alert_id})
    return {"alert_id": alert_id, "status": "acknowledged"}


@app.get("/api/integrations")
def integrations_read(principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    """D3: the workspace's webhook, mail relay, Jira and ServiceNow - never a secret."""
    from backend import integrations

    return {"integrations": [_integration_view(principal.tenant_id, channel) for channel in integrations.CHANNELS]}


@app.put("/api/integrations/{channel}")
def integrations_save(channel: str, payload: IntegrationRequest,
                      principal: Principal = Depends(require_permission("tenant.admin", person_only=True))) -> dict:
    from backend import integrations

    channel = _integration_channel(channel)
    request = payload.model_dump(exclude_none=True)
    record = store_module.get_alert_channel(principal.tenant_id, channel)
    saved = (record or {}).get("config") or {}
    try:
        config = integrations.merge(channel, saved, request)
        action, value = integrations.secret_change(channel, request)
    except integrations.IntegrationError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The integration settings were refused.")) from exc
    secret_ref = (record or {}).get("secret_ref") or ""
    if action == "keep" and secret_ref and integrations.destination_changed(channel, saved, config):
        raise HTTPException(status_code=400, detail="The destination changed: enter the password or token again. "
                            "A saved secret is only sent where it was entered for.")
    # Checked before anything is sealed: sealing a new secret deletes the one it replaces.
    if channel == "email" and config.get("security") == "none" and (
            config.get("username") or action == "replace" or (action == "keep" and secret_ref)):
        raise HTTPException(status_code=400, detail="A mail relay user name and password are only sent over TLS: "
                            "choose STARTTLS or TLS, or remove them.")
    shown_secret = ""
    if channel == "webhook" and (action == "rotate" or not secret_ref):
        shown_secret = integrations.new_signing_secret()
        action, value = "replace", shown_secret
    if action == "replace":
        secret_ref = integrations.store_secret(principal.tenant_id, channel, value or "", secret_ref)
    elif action == "remove" and secret_ref:
        integrations.delete_secret(principal.tenant_id, secret_ref)
        secret_ref = ""
    enabled = bool(record and record.get("enabled")) if payload.enabled is None else payload.enabled
    store_module.save_alert_channel(principal.tenant_id, channel, enabled=enabled, config=config,
                                    secret_ref=secret_ref, actor=principal.subject)
    changed = integrations.changed_fields(saved, config)
    if changed or record is None or action in ("replace", "remove"):
        audit(principal.tenant_id, principal.subject, "integration.changed", {
            "channel": channel, "changed": changed, "secret": {"replace": "replaced", "remove": "removed"}.get(action, "kept"),
            "ca_fingerprint": config.get("ca_fingerprint", "")})
    if (record is not None and bool(record.get("enabled")) != enabled) or (record is None and enabled):
        audit(principal.tenant_id, principal.subject, "integration.enabled" if enabled else "integration.disabled",
              {"channel": channel})
    view = _integration_view(principal.tenant_id, channel)
    if shown_secret:
        # Shown once: it is not stored anywhere Sentro can read it back from for the console.
        view["signing_secret"] = shown_secret
    return view


@app.put("/api/integrations/{channel}/enabled")
def integrations_enable(channel: str, payload: IntegrationEnabledRequest,
                        principal: Principal = Depends(require_permission("tenant.admin", person_only=True))) -> dict:
    channel = _integration_channel(channel)
    record = store_module.get_alert_channel(principal.tenant_id, channel)
    if record is None:
        raise HTTPException(status_code=400, detail="Save the integration's settings first.")
    if bool(record["enabled"]) != payload.enabled:
        store_module.save_alert_channel(principal.tenant_id, channel, enabled=payload.enabled, config=record["config"],
                                        secret_ref=record["secret_ref"], actor=principal.subject)
        audit(principal.tenant_id, principal.subject,
              "integration.enabled" if payload.enabled else "integration.disabled", {"channel": channel})
    return _integration_view(principal.tenant_id, channel)


@app.post("/api/integrations/{channel}/test")
def integrations_test(channel: str, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    """Try the saved settings: a signed test event, a test message, or a sign-in to the
    ticket system. Nothing is queued."""
    from backend import alert_delivery

    channel = _integration_channel(channel)
    result = alert_delivery.test_channel(principal.tenant_id, channel)
    stamp = datetime.now(timezone.utc).isoformat()
    if result.get("signature"):
        store_module.record_alert_channel_status(principal.tenant_id, channel, last_test={
            "at": stamp, "ok": result["ok"], "message": result["message"], "signature": result["signature"]})
    audit(principal.tenant_id, principal.subject,
          "integration.test_succeeded" if result["ok"] else "integration.test_failed",
          {"channel": channel, "message": result["message"]})
    return {"test": {"ok": result["ok"], "message": result["message"], "at": stamp},
            **_integration_view(principal.tenant_id, channel)}


@app.post("/api/integrations/{channel}/retry")
def integrations_retry(channel: str, principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    """Send what is waiting for this channel now instead of after its back-off."""
    from backend import alert_delivery

    channel = _integration_channel(channel)
    made_due = store_module.retry_alert_deliveries_now(principal.tenant_id, channel)
    audit(principal.tenant_id, principal.subject, "integration.retry", {"channel": channel, "made_due": made_due})
    alert_delivery.kick()
    return {"made_due": made_due, **_integration_view(principal.tenant_id, channel)}


@app.delete("/api/integrations/{channel}")
def integrations_remove(channel: str, principal: Principal = Depends(require_permission("tenant.admin", person_only=True))) -> dict:
    """Delete a channel's settings and its secret. What was waiting for it is cancelled."""
    from backend import integrations

    channel = _integration_channel(channel)
    ref = store_module.delete_alert_channel(principal.tenant_id, channel)
    if ref is None:
        raise HTTPException(status_code=404, detail="That integration is not configured.")
    integrations.delete_secret(principal.tenant_id, ref)
    audit(principal.tenant_id, principal.subject, "integration.removed", {"channel": channel})
    return _integration_view(principal.tenant_id, channel)


@app.post("/api/findings/{finding_id}/ticket")
def finding_ticket_create(finding_id: str, payload: TicketRequest,
                          principal: Principal = Depends(require_permission("findings.triage"))) -> dict:
    """D3: send a finding to Jira or ServiceNow. The ticket is created from the queue - a
    ticket system that is down delays it, and it is not lost."""
    from backend import alert_delivery

    finding = store_module.get_finding(principal.tenant_id, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    enabled = _ticket_systems(principal.tenant_id)
    system = (payload.system or "").lower() or (enabled[0] if len(enabled) == 1 else "")
    if system not in enabled:
        raise HTTPException(status_code=400, detail="Name a ticket system that is turned on: " + (", ".join(enabled) or "none is"))
    summary, description = alert_delivery.ticket_text(finding, principal.tenant_id, finding_id)
    ticket = store_module.create_finding_ticket(principal.tenant_id, secrets.token_hex(8), finding_id, system,
                                                {"summary": summary, "description": description}, principal.subject)
    if ticket is None:
        raise HTTPException(status_code=409, detail=f"This finding already has an open {system} ticket.")
    audit(principal.tenant_id, principal.subject, "ticket.requested",
          {"ticket_id": ticket["ticket_id"], "finding_id": finding_id, "system": system})
    alert_delivery.kick()
    return {"ticket": ticket}


def _ticket_systems(tenant_id: str) -> list[str]:
    from backend import integrations

    return [system for system in integrations.TICKET_SYSTEMS
            if (store_module.get_alert_channel(tenant_id, system) or {}).get("enabled")]


@app.get("/api/tickets/systems")
def ticket_systems(principal: Principal = Depends(require_permission("findings.triage"))) -> dict:
    """Which ticket systems a finding can be sent to - names only."""
    return {"systems": _ticket_systems(principal.tenant_id)}


@app.get("/api/tickets")
def tickets_list(principal: Principal = Depends(require_permission("inventory.view")),
                 finding_id: str = Query(default="", max_length=128),
                 status: str = Query(default="", pattern="^(|pending|open|closed|cancelled)$"),
                 limit: int = Query(default=200, ge=1, le=500)) -> dict:
    return {"tickets": store_module.list_finding_tickets(principal.tenant_id, finding_id=finding_id,
                                                         status=status, limit=limit)}


@app.post("/api/tickets/sync")
def tickets_sync(principal: Principal = Depends(require_permission("findings.triage"))) -> dict:
    """Ask the ticket systems about this workspace's open tickets now."""
    from backend import alert_delivery

    result = alert_delivery.sync_tenant(principal.tenant_id)
    audit(principal.tenant_id, principal.subject, "ticket.synced", result)
    return {"sync": result}


@app.post("/api/findings/{finding_id}/reveal")
def reveal_finding_value(finding_id: str, payload: RevealRequest, request: Request,
                         principal: Principal = Depends(require_permission("evidence.reveal", person_only=True))) -> dict:
    """One raw value behind a finding, read again from its source now, never stored.
    Every attempt past the permission check is audited - revealed, refused, throttled or
    failed - with where the value would have come from once that is known."""
    from backend import evidence_reveal

    detail = {"finding_id": finding_id, "fingerprint": payload.fingerprint,
              "reason": " ".join(payload.reason.split())[:500]}

    def where(location: dict) -> dict:
        return {"source": location.get("source") or "", "server": location.get("server") or "",
                "share": location.get("share") or "", "target": location.get("path") or ""}

    if not REVEAL_THROTTLE.take(principal.subject):
        audit(principal.tenant_id, principal.subject, "evidence.reveal_refused", {**detail, "result": "throttled"})
        raise HTTPException(status_code=429, detail="Too many reveals in the last hour. Try again later.")
    try:
        result = evidence_reveal.reveal(principal.tenant_id, finding_id, payload.fingerprint, payload.reason)
    except evidence_reveal.RevealRefused as refused:
        audit(principal.tenant_id, principal.subject, "evidence.reveal_refused",
              {**detail, **where(refused.location), "result": refused.code})
        raise HTTPException(status_code=refused.status, detail={"code": refused.code, "message": str(refused)}) from refused
    except Exception as exc:
        # A lost SMB session, an unreadable credential, a database error: nothing was
        # revealed, and the attempt is still on the record.
        audit(principal.tenant_id, principal.subject, "evidence.reveal_refused",
              {**detail, "result": "error", "error": type(exc).__name__})
        raise HTTPException(status_code=502, detail={
            "code": "reveal_failed",
            "message": "The file could not be read again; nothing was revealed. The attempt is in the audit trail."}) from exc
    audit(principal.tenant_id, principal.subject, "evidence.revealed",
          {**detail, **where(result["location"]), "result": "revealed", "type": result["type"]})
    return {key: result[key] for key in ("finding_id", "type", "fingerprint", "value", "masked")}


@app.post("/api/findings/detail")
def finding_detail_preview(payload: dict, principal: Principal = Depends(require_permission("inventory.view"))) -> dict:
    _ = principal
    finding = payload.get("finding") if isinstance(payload, dict) else {}
    if not isinstance(finding, dict):
        raise HTTPException(status_code=400, detail="finding must be an object")
    framework = normalize_framework_id(finding.get("framework"))
    finding["display_name"] = finding.get("display_name") or get_finding_display_name(finding)
    detail = build_nist_finding_detail(finding) if framework == "nist_sp800_60_enterprise" else {"summary": {"display_name": finding["display_name"], "framework": framework}}
    return {"finding": finding, "framework": framework, "detail": detail}


@app.patch("/api/findings/{finding_id}/status")
@evidence_scoped
def finding_status_update(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_permission("findings.triage"))) -> dict:
    return _finding_lifecycle_action(finding_id, "status", payload, principal)


@app.post("/api/findings/{finding_id}/assign")
@evidence_scoped
def finding_assign(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_permission("findings.triage"))) -> dict:
    return _finding_lifecycle_action(finding_id, "assign", payload, principal)


@app.post("/api/findings/{finding_id}/comment")
@evidence_scoped
def finding_comment(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_permission("findings.triage"))) -> dict:
    return _finding_lifecycle_action(finding_id, "comment", payload, principal)


@app.post("/api/findings/{finding_id}/suppress")
@evidence_scoped
def finding_suppress(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_permission("findings.triage"))) -> dict:
    return _finding_lifecycle_action(finding_id, "suppress", payload, principal)


@app.post("/api/findings/{finding_id}/false-positive")
@evidence_scoped
def finding_false_positive(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_permission("findings.triage"))) -> dict:
    return _finding_lifecycle_action(finding_id, "false-positive", payload, principal)


@app.post("/api/findings/{finding_id}/risk-acceptance")
@evidence_scoped
def finding_risk_acceptance(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_permission("findings.triage"))) -> dict:
    return _finding_lifecycle_action(finding_id, "risk-acceptance", payload, principal)


@app.post("/api/findings/{finding_id}/resolve")
@evidence_scoped
def finding_resolve(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_permission("findings.triage"))) -> dict:
    return _finding_lifecycle_action(finding_id, "resolve", payload, principal)


@app.post("/api/findings/{finding_id}/reopen")
@evidence_scoped
def finding_reopen(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_permission("findings.triage"))) -> dict:
    return _finding_lifecycle_action(finding_id, "reopen", payload, principal)


@app.post("/api/findings/{finding_id}/validate")
@evidence_scoped
def finding_validate(finding_id: str, payload: FindingLifecyclePayload, principal: Principal = Depends(require_permission("findings.triage"))) -> dict:
    return _finding_lifecycle_action(finding_id, "validate", payload, principal)


@app.get("/api/findings/{finding_id}/history")
def finding_history(finding_id: str, principal: Principal = Depends(require_permission("inventory.view"))) -> dict:
    history = get_finding_history(principal.tenant_id, finding_id)
    if history is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"history": history}


@app.get("/api/findings/{finding_id}/occurrences")
@evidence_scoped
def finding_occurrences(finding_id: str, principal: Principal = Depends(require_permission("inventory.view"))) -> dict:
    occurrences = get_finding_occurrences(principal.tenant_id, finding_id)
    if occurrences is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"occurrences": occurrences}


BACKSLASH = chr(92)
SUPPRESSION_SCOPES = ("file", "folder", "type", "value")


def _suppression_rule_from_finding(finding: dict, scope: str, reason: str) -> dict:
    """Turn a dismissed finding into the rule that keeps it dismissed (B6).

    The scope is the analyst's answer to "and what else?": this finding in this file,
    anything of this kind under this folder, this kind of finding anywhere, or this one
    value wherever it turns up.
    """
    scope = str(scope or "file").strip().lower()
    if scope not in SUPPRESSION_SCOPES:
        raise HTTPException(status_code=400, detail=f"Unsupported suppression scope: {scope}")
    file_obj = finding.get("file") if isinstance(finding.get("file"), dict) else {}
    finding_type = str(finding.get("type") or finding.get("data_type") or "").strip()
    path = str(file_obj.get("path") or finding.get("file_path") or "")
    source = str(file_obj.get("source") or finding.get("source") or "")
    if not finding_type:
        raise HTTPException(status_code=400, detail="This finding does not say what kind it is")
    rule = {"finding_type": finding_type, "source": source, "reason": reason}
    if scope == "file":
        if not path:
            raise HTTPException(status_code=400, detail="This finding does not say which file it is in")
        rule["path_pattern"] = path
    elif scope == "folder":
        normalized = path.replace(BACKSLASH, "/")
        folder = normalized.rsplit("/", 1)[0] if "/" in normalized else ""
        if not folder:
            raise HTTPException(status_code=400, detail="This finding is not in a folder that can be named")
        rule["path_pattern"] = f"{folder}/*"
    elif scope == "value":
        fingerprints = finding.get("secure_value_fingerprints") or finding.get("secure_fingerprints") or []
        if not fingerprints:
            raise HTTPException(status_code=400, detail="This finding carries no value fingerprint to suppress")
        if len(set(str(item) for item in fingerprints)) > 1:
            raise HTTPException(
                status_code=400,
                detail="This finding carries several values; suppress the file or the folder instead",
            )
        rule["fingerprint"] = str(fingerprints[0])
        rule["source"] = ""
    else:
        # "type": everywhere. Deliberately keeps no path and no source.
        rule["source"] = ""
    return rule


@app.get("/api/suppression-rules")
def suppression_rules_index(principal: Principal = Depends(require_permission("inventory.view"))) -> dict:
    """What this tenant's scans have been told not to report again."""
    return {"rules": list_suppression_rules(principal.tenant_id)}


@app.post("/api/suppression-rules")
def suppression_rule_create(
    payload: SuppressionRulePayload,
    principal: Principal = Depends(require_permission("rules.manage")),
) -> dict:
    try:
        rule = create_suppression_rule(
            principal.tenant_id,
            finding_type=payload.finding_type,
            source=payload.source,
            path_pattern=payload.path_pattern,
            fingerprint=payload.fingerprint,
            reason=payload.reason,
            expires_at=payload.expires_at,
            created_by=principal.subject,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The suppression rule could not be created")) from exc
    audit(principal.tenant_id, principal.subject, "suppression.created", {
        "rule_id": rule["rule_id"],
        "finding_type": rule["finding_type"],
        "path_pattern": rule["path_pattern"],
        "scope": "manual",
    })
    return {"rule": rule}


@app.patch("/api/suppression-rules/{rule_id}")
def suppression_rule_update(
    rule_id: str,
    payload: SuppressionRuleUpdate,
    principal: Principal = Depends(require_permission("rules.manage")),
) -> dict:
    update = {key: value for key, value in payload.model_dump().items() if value is not None}
    try:
        rule = update_suppression_rule(principal.tenant_id, rule_id, update)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The suppression rule could not be updated")) from exc
    if rule is None:
        raise HTTPException(status_code=404, detail="Suppression rule not found")
    audit(principal.tenant_id, principal.subject, "suppression.updated", {
        "rule_id": rule["rule_id"],
        "active": rule["active"],
    })
    return {"rule": rule}


@app.delete("/api/suppression-rules/{rule_id}")
def suppression_rule_delete(
    rule_id: str,
    principal: Principal = Depends(require_permission("rules.manage")),
) -> dict:
    rule = get_suppression_rule(principal.tenant_id, rule_id)
    if rule is None or not delete_suppression_rule(principal.tenant_id, rule_id):
        raise HTTPException(status_code=404, detail="Suppression rule not found")
    audit(principal.tenant_id, principal.subject, "suppression.deleted", {
        "rule_id": rule_id,
        "finding_type": rule["finding_type"],
    })
    return {"deleted": True, "rule_id": rule_id}


def _finding_lifecycle_action(finding_id: str, action: str, payload: FindingLifecyclePayload, principal: Principal) -> dict:
    rule_fields = None
    stored: dict = {}
    if payload.suppress_future and action in {"false-positive", "suppress"}:
        # A file-scoped rule repeats this one decision about this one file; a folder,
        # type or value rule silences findings across the workspace, which is the rules
        # permission's to grant (POST /api/suppression-rules needs it) - triage alone
        # used to create them.
        scope = str(payload.suppression_scope or "file").strip().lower()
        if scope != "file" and not has_permission(principal, "rules.manage"):
            raise HTTPException(status_code=403, detail="A folder, type or value suppression rule needs the "
                                "rules permission; dismiss with a file-scoped rule instead.")
        # Everything the rule needs is checked before the finding changes: a refusal
        # after the write left the finding dismissed while answering 400.
        stored = get_finding(principal.tenant_id, finding_id) or {}
        if not stored:
            raise HTTPException(status_code=404, detail="Finding not found")
        reason = payload.reason or payload.comment or f"Dismissed as a false positive by {principal.subject}"
        rule_fields = _suppression_rule_from_finding(stored, payload.suppression_scope, reason)
        if len(list_suppression_rules(principal.tenant_id)) >= MAX_SUPPRESSION_RULES:
            raise HTTPException(status_code=400, detail=f"A workspace may hold at most {MAX_SUPPRESSION_RULES} "
                                "suppression rules; remove one first.")
    try:
        finding = update_finding_lifecycle(principal.tenant_id, finding_id, action, payload.model_dump(), principal.subject)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=client_message(exc, "The finding could not be updated")) from exc
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    response = {"finding": finding}
    if rule_fields is not None:
        # The dismissal changed this row; the rule is what stops the next scan
        # creating the same finding for somebody to dismiss again (B6).
        try:
            rule = create_suppression_rule(
                principal.tenant_id,
                **rule_fields,
                created_by=principal.subject,
                source_finding_id=finding_id,
                source_scan_id=str(stored.get("scan_id") or ""),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=client_message(exc, "The suppression rule could not be created")) from exc
        audit(principal.tenant_id, principal.subject, "suppression.created", {
            "rule_id": rule["rule_id"],
            "finding_type": rule["finding_type"],
            "path_pattern": rule["path_pattern"],
            "scope": payload.suppression_scope,
            "finding_id": finding_id,
        })
        response["suppression_rule"] = rule
    return response


@app.patch("/api/history/{scan_id}/findings/workflow")
@evidence_scoped
def finding_workflow_update(
    scan_id: str,
    payload: FindingWorkflowUpdate,
    principal: Principal = Depends(require_permission("findings.triage")),
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
        raise HTTPException(status_code=400, detail=client_message(exc, "The finding could not be updated")) from exc
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
def scan_hash_changes(principal: Principal = Depends(require_permission("inventory.view"))) -> dict:
    history = read_scan_history(principal.tenant_id, limit=2)
    if len(history) < 2:
        latest_report = read_scan_report(principal.tenant_id, history[-1].get("scan_id")) if history else None
        duplicate_hash_paths = _duplicate_hash_paths(latest_report)
        return {
            "tenant_id": principal.tenant_id,
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
        "tenant_id": principal.tenant_id,
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
def tenant_portfolio(principal: Principal = Depends(require_permission("tenant.admin"))) -> dict:
    tenants = list_tenants() if _is_platform_admin(principal) else list_tenants(principal.tenant_id)
    return {"tenants": [_public_tenant(item) for item in tenants]}


@app.get("/api/audit")
def audit_log(
    principal: Principal = Depends(require_permission("audit.view")),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict:
    return {
        "tenant_id": principal.tenant_id,
        "events": read_audit_log(principal.tenant_id, limit),
    }


@app.get("/api/audit/verify")
def audit_verify_route(principal: Principal = Depends(require_permission("audit.view"))) -> dict:
    """C4: whether this workspace's audit trail is intact - the check `python main.py audit
    verify` makes, for this tenant only, by someone who can read its trail. The
    verification is itself recorded, with its outcome."""
    if AUDIT_VERIFY_THROTTLE.exhausted(principal.tenant_id):
        raise HTTPException(status_code=429, detail="The audit trail has been verified too often in the last hour. Try again later.")
    AUDIT_VERIFY_THROTTLE.failed(principal.tenant_id)
    result = verify_audit_chain(principal.tenant_id)[0]
    audit(principal.tenant_id, principal.subject, "audit.verified", {
        "ok": result["ok"], "rows": result["rows"], "problems": result["problem_count"],
    })
    return {
        "tenant_id": principal.tenant_id,
        "ok": result["ok"],
        "rows": result["rows"],
        "problem_count": result["problem_count"],
        "problems": result["problems"][:50],
        "sealed_through_seq": result["sealed_through_seq"],
        "sealed_at": result["sealed_at"],
        "pruned_through_seq": result["pruned_through_seq"],
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/executive-dashboard")
def executive_dashboard(principal: Principal = Depends(require_permission("inventory.view"))) -> dict:
    # The trend is the last 14 runs and `latest` is the newest of them, so this
    # is every row the response can use. It read 200 and threw 186 away on the
    # console's most-requested call.
    history = read_scan_history(principal.tenant_id, limit=DASHBOARD_TREND_POINTS)
    latest = history[-1] if history else {"summary": {}}
    # Posture is a statement about the ESTATE, measured from the normalized
    # tables - not about the last scan. Scoring the last scan is what let the
    # number be improved by pointing the scanner at a smaller folder.
    posture = compute_posture(PostureInputs(**posture_inputs(principal.tenant_id)))
    trend = [
        {**entry, "posture_score": posture_from_summary(entry.get("summary") or {}).total_score}
        for entry in history[-DASHBOARD_TREND_POINTS:]
    ]
    return {
        "tenant_id": principal.tenant_id,
        "risk_posture_score": posture.total_score,
        "posture": posture.to_dict(),
        "latest": latest,
        "trend": trend,
        "retention": data_retention_summary(principal.tenant_id),
    }


def _client_host(request: Request) -> str:
    # C4: behind a trusted proxy, the client it names - so a per-address throttle counts
    # the attacker, not every user who shares the proxy.
    return request_address(request) or "unknown"


def _login_rate_key(username: str, request: Request) -> str:
    client = _client_host(request)
    safe_user = sanitize_username(username) or "unknown"
    return f"{client}:{safe_user}"


def _login_ip_rate_key(request: Request) -> str:
    # M4: distinct namespace ("ip:") so the per-IP aggregate cannot collide with a
    # per-(IP,username) key.
    return f"ip:{_client_host(request)}"


def _record_blocked_attempt(key: str) -> int:
    """Count one more refused sign-in against `key`; returns how many this window."""
    blocked_key = f"blocked:{key}"
    record_login_failure(blocked_key, LOGIN_WINDOW_SECONDS)
    return count_login_failures(blocked_key, LOGIN_WINDOW_SECONDS)


def _is_power_of_ten(value: int) -> bool:
    while value >= 10 and value % 10 == 0:
        value //= 10
    return value == 1


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
    if "dspm_winrm_kerberos" in lowered:
        # Asking for Kerberos on an install that cannot speak it is the
        # operator's own configuration, and the exception already says which
        # package is missing and what the alternative setting is. Flattening it
        # into "install requirements.txt" would send them to a file that has
        # never contained requests-kerberos.
        return HTTPException(status_code=400, detail={
            "message": "Kerberos was required but is not available on this host",
            "code": "kerberos_unavailable",
            "hint": raw,
        })
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
        # Two different refusals used to share one hint that told the operator
        # to reach for a local administrator. A scan needs no administrator; it
        # needs to be let in, and to be allowed to read what it was pointed at.
        # Saying "use an admin" for a single NTFS denial is what makes a domain
        # admin the account of least resistance.
        if "winrm" in lowered or "wsman" in lowered or "5985" in lowered or "5986" in lowered:
            hint = ("The target refused the WinRM session. Windows allows only local administrators to "
                    "connect until the account is added to the Remote Management Users group on that "
                    "machine - that grant alone is enough, and does not make the account an administrator.")
        else:
            hint = ("The credential connected but was refused a path. Grant it read access to the folders "
                    "you are scanning, or narrow the scope to what it can already read. Run the endpoint "
                    "access check to see which profiles it can reach.")
    elif "winrm" in lowered:
        code = "endpoint_unreachable"
        hint = "Verify WinRM service, firewall, DNS/IP reachability, and the credential."
    elif "smb" in lowered or "connection" in lowered or "timed out" in lowered:
        code = "file_server_unreachable"
        hint = "Verify the file-server name/IP, TCP 445 reachability, share access, domain, and credential."
    elif "cancel" in lowered:
        code = "scan_cancelled"
        hint = "The scan was cancelled by the user."
    elif "too many active scans" in lowered:
        # The workspace's scan slots are full - nothing is wrong with the target, so the
        # "check the target, credentials" hint pointed the operator the wrong way.
        return HTTPException(status_code=429, detail={
            "message": "This workspace is already running as many scans as it may",
            "code": "scan_capacity",
            "hint": "Wait for a running scan to finish, or cancel one, then start this again.",
        }, headers={"Retry-After": "30"})
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


def _validate_scan_target(target: str, principal: Principal) -> None:
    """C5: the workspace's scan targets decide (backend/target_scope); a refusal is
    audited and the scan never starts. The collectors ask again when they connect."""
    target = (target or "").strip()
    if not target:
        return
    reason = target_scope.check(principal.tenant_id, target, actor=principal.subject, where="api")
    if reason:
        raise HTTPException(status_code=403, detail=reason)


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
        # C2: what the person types, with their workspace; `username` is the account key.
        "login_name": user.get("login_name") or user["username"],
        "auth_source": user.get("auth_source") or "local",
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
    # Generating replaces the folder. "." named the install itself and "data" the database
    # and backups, and scan.run - an operator's or an API key's permission - deleted them.
    if resolved == BASE_DIR.resolve() or any(
            resolved == private.resolve() or resolved.is_relative_to(private.resolve()) or private.resolve().is_relative_to(resolved)
            for private in product_private_paths()):
        raise HTTPException(status_code=400, detail="Demo data cannot be written to the install folder or its data folder")
    if not is_generated_dataset(resolved):
        raise HTTPException(status_code=409, detail="That folder holds files the demo generator did not write, and "
                            "generating would replace them. Choose a new folder name.")
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
    """One scan's posture. Delegates, so it cannot drift from the estate's.

    This used to be its own formula - a severity-weighted mean over the file
    count - and it disagreed with both the dashboard's and the report's.
    """

    return posture_from_summary(summary).total_score


_compact_scan_report = compact_scan_report

def _scan_extension_settings(extensions: list[str], enabled: bool) -> tuple[list[str], bool]:
    normalized = sorted(normalize_extension_filter(extensions))
    if not enabled or not normalized:
        return [], False
    return normalized, True


@app.post("/api/dlp-policy")
def export_dlp_policy(payload: ScanRequest, principal: Principal = Depends(require_permission("export"))) -> dict:
    audit(principal.tenant_id, principal.subject, "dlp_policy.exported", {"rules": len(payload.asset_overrides)})
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


def _record_scan_source(tenant_id: str, scan_id: str, payload) -> None:
    """C13: how this scan reached its files - never a password, only whether one was
    typed, and a saved credential's reference - so a finding's value can be read again."""
    if not scan_id:
        return
    endpoint = isinstance(payload, EndpointScanRequest)
    database = isinstance(payload, DatabaseScanRequest)
    server = str(getattr(payload, "host", "") if endpoint or database else getattr(payload, "server", "") or "").strip()
    ref = str(getattr(payload, "credential_ref", "") or "").strip()
    typed = bool(str(getattr(payload, "password", "") or ""))
    kind = "saved" if ref else ("typed" if typed else "none")
    smb = "smb3" if _smb_encryption_required(payload) else "smb"
    source = ("endpoint-winrm" if endpoint else "database" if database
              else (smb if server and not _is_local_endpoint_host(server) else "local"))
    try:
        store_module.record_scan_source(tenant_id, scan_id, source, server, kind, ref)
    except Exception as exc:  # a lost record only makes the scan unrevealable
        from scripts.logger import get_logger

        get_logger("backend.app").warning("Could not record how scan %s reached its files: %s", scan_id,
                                          type(exc).__name__)


def _persist_scan(data: dict, payload: ScanRequest | EndpointScanRequest, principal: Principal) -> None:
    # The scan's operator-facing name travels with the report so every asset it
    # produces can be filtered by that name in Data Inventory.
    label = str(getattr(payload, "scan_label", "") or "").strip()[:80]
    if label:
        data["scan_label"] = label
    scan_id = save_scan_history(principal.tenant_id, data)
    data["scan_id"] = scan_id
    _record_scan_source(principal.tenant_id, scan_id, payload)
    warnings: list[dict] = []
    try:
        data["alerts"] = evaluate_alerts(principal.tenant_id, data)
    except Exception as exc:
        data["alerts"] = []
        warnings.append({"stage": "alerts", "error": type(exc).__name__})
    if payload.save_report and PLAINTEXT_REPORT_EXPORT:
        try:
            report_id = str(data.get("scan_id") or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f"))
            generate_report(data, REPORT_DIR / f"{principal.tenant_id}_{report_id}.json")
        except Exception as exc:
            warnings.append({"stage": "report_export", "error": type(exc).__name__})
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


def _run_partitioned_scan_payload(config: ScanConfig, payload: ScanRequest, principal: Principal, job=None) -> dict:
    """A scan that writes each partition as it finishes (``DSPM_PARTITIONED_SCANS=1``, B2.2b).

    Returns the compact report - a partitioned scan never has every file in one list,
    which is the point of it. A target that does not split runs as an ordinary scan
    and returns what an ordinary scan returns.

    With ``DSPM_SCAN_EXECUTION=queue`` an asynchronous scan is planned here, published to
    the work queue, and run by ``python main.py worker`` processes; this job then only
    follows the ledger (B3). A synchronous request is always run here: its caller is
    holding a connection open for the answer.
    """
    if job is not None:
        job.progress = max(job.progress, 7)
        job.message = "Planning scan partitions"
        config.cancel_check = lambda: job.cancel_requested
    # The validated request is what lets the scan be continued after a restart, or run
    # by a worker at all; the store keeps it without secrets.
    started = dict(
        request=payload.model_dump(mode="json") if isinstance(payload, BaseModel) else None,
        requested_by=str(getattr(principal, "subject", "") or ""),
        scan_label=str(getattr(payload, "scan_label", "") or ""),
        compliance_enabled=bool(getattr(payload, "compliance_enabled", False)),
        compliance_frameworks=list(getattr(payload, "compliance_frameworks", []) or []),
    )
    data = None
    if job is not None and queued_execution():
        record = start_partitioned_scan(principal.tenant_id, config, job=job, **started)
        if record is not None and not record["resumable"]:
            # Workers only take scans they can rebuild, and a typed password was never
            # stored: published, nothing would ever run this scan, and the resume sweep
            # would fail it a lease later for a credential it never needed again. This
            # process holds the password, so it runs the scan itself.
            data = continue_partitioned_scan(principal.tenant_id, record["scan_id"], config, job=job)
        elif record is not None:
            data = _queued_partitioned_scan(record, config, principal, job)
    else:
        data = run_partitioned_scan(principal.tenant_id, config, job=job, **started)
    if data is None:
        # Not worth partitioning - one partition's worth of files, or the demo dataset.
        if job is not None:
            from backend.jobs import _run_scan_job

            return _run_scan_job(job, config, lambda report: _persist_compliance_scan(report, payload, principal))
        data = DSPMDiscoveryEngine(config).run().to_dict()
        _persist_compliance_scan(data, payload, principal)
        return data
    return _finish_partitioned_scan_payload(data, payload, principal)


def _queued_partitioned_scan(record: dict, config: ScanConfig, principal: Principal, job) -> dict:
    """Publish a planned scan to the work queue and follow it; run it here if the queue is unreachable.

    The plan is already in the ledger when this is called, so a queue that cannot be
    reached costs the scan nothing: it is run in this process instead, exactly as it
    would have been with execution inline, and the audit trail says which happened.
    """
    from scripts.logger import get_logger

    scan_id = record["scan_id"]
    try:
        published = enqueue_partitioned_scan(record)
    except Exception as exc:
        get_logger("backend.app").warning(
            "Work queue unavailable for scan %s (%s); running it here", scan_id, type(exc).__name__,
        )
        with suppress(Exception):
            audit(principal.tenant_id, principal.subject, "scan.queue_unavailable",
                  {"scan_id": scan_id, "error": type(exc).__name__})
        return continue_partitioned_scan(principal.tenant_id, scan_id, config, job=job)
    with suppress(Exception):
        audit(principal.tenant_id, principal.subject, "scan.published",
              {"scan_id": scan_id, "partitions": published})
    job.message = f"Queued {published} partitions for the workers"
    return follow_partitioned_scan(principal.tenant_id, scan_id, job=job)


def _continue_partitioned_scan_payload(scan_id: str, config: ScanConfig, payload: ScanRequest,
                                       principal: Principal, job) -> dict:
    """The job that runs what is left of a resumed partitioned scan (B2.4)."""
    job.progress = max(job.progress, 7)
    job.message = "Resuming scan"
    config.cancel_check = lambda: job.cancel_requested
    data = continue_partitioned_scan(principal.tenant_id, scan_id, config, job=job)
    return _finish_partitioned_scan_payload(data, payload, principal)


def rebuild_scan_config(record: dict) -> ScanConfig:
    """A recorded partitioned scan's engine configuration, rebuilt from its stored request.

    The same validation and credential resolution a scan started from the console
    gets. A resumed scan (B2.4) and a queue worker (B3) both start here.
    """
    if str((record.get("header") or {}).get("source") or "") == "endpoint-winrm":
        # An endpoint page is run by its own runner, from the scan's stored request (W1.3);
        # the engine configuration only carries the workspace.
        return ScanConfig(tenant_id=record["tenant_id"])
    return _to_config(ScanRequest.model_validate(record["request"]), record["tenant_id"])


def _resume_partitioned_scan(record: dict) -> None:
    """Continue a partitioned scan a stopped process left unfinished (B2.4).

    The engine is rebuilt from the request the scan was recorded with, through the
    same validation and credential resolution a new scan gets - an SMB scan's vaulted
    credential is resolved again, and a typed password never reaches this point, since
    such a scan is recorded as not resumable - and the scan continues under the job id
    it had, so a console still polling that job sees it running again.
    """
    from backend.scan_resumer import ResumeLater
    from backend.store import bind_partitioned_scan_job

    if str((record.get("header") or {}).get("source") or "") == "endpoint-winrm":
        _resume_endpoint_scan(record)
        return
    tenant_id = record["tenant_id"]
    scan_id = record["scan_id"]
    payload = ScanRequest.model_validate(record["request"])
    config = rebuild_scan_config(record)
    principal = Principal(
        subject=str((record.get("header") or {}).get("requested_by") or "system:scan-resumer"),
        role="analyst",
        tenant_id=tenant_id,
        auth_type="system",
    )
    try:
        job = create_job(
            tenant_id,
            lambda job: _continue_partitioned_scan_payload(scan_id, config, payload, principal, job),
            job_id=record.get("job_id") or None,
        )
    except (RuntimeError, ValueError) as exc:
        # A full queue, or the old job still winding down: a later sweep tries again.
        raise ResumeLater(str(exc)) from exc
    bind_partitioned_scan_job(tenant_id, scan_id, job.id)
    audit(tenant_id, "system:scan-resumer", "scan.resumed", {"scan_id": scan_id, "job_id": job.id})


def _start_scheduled_scan(schedule: dict) -> None:
    """Start the scan a schedule is due for, as the console would have started it (B3).

    The stored request goes through the same validation and vault resolution a request
    from the console gets, and the scan runs as an ordinary asynchronous job:
    partitioned when the flag is on, published to the workers when execution is queued.
    What became of the run is written back to the schedule, so a week of unattended
    nights can be read afterwards.
    """
    from backend.store import job_is_active, record_schedule_run

    tenant_id = schedule["tenant_id"]
    previous = str(schedule.get("last_job_id") or "")
    if previous and job_is_active(tenant_id, previous):
        # W2.4: the last run is still going - queued, running, or paused to be resumed. Two
        # runs of one schedule would scan the same estate at once; this one is skipped,
        # said on the schedule, and the next is due an interval from now.
        record_schedule_run(tenant_id, schedule["schedule_id"], status="skipped",
                            error="The previous run of this schedule is still going; this run was skipped.")
        audit(tenant_id, "system:scheduler", "scan.schedule_skipped",
              {"schedule_id": schedule["schedule_id"], "running_job_id": previous})
        return
    payload = ScanRequest.model_validate({**(schedule.get("request") or {}), "async_scan": True})
    # The same preparation a scan from the console gets: the bundled demo dataset is
    # generated if it is missing, and a custom path that does not exist fails here,
    # where the failure is recorded on the schedule.
    _prepare_local_scan_data(payload)
    config = _to_config(payload, tenant_id)
    principal = Principal(
        subject=f"system:scheduler:{schedule['schedule_id']}",
        role="analyst",
        tenant_id=tenant_id,
        auth_type="system",
    )
    job = create_job(tenant_id, lambda job: _scheduled_scan_payload(schedule, config, payload, principal, job))
    record_schedule_run(tenant_id, schedule["schedule_id"], status="started", job_id=job.id)
    audit(tenant_id, "system:scheduler", "scan.scheduled",
          {"schedule_id": schedule["schedule_id"], "job_id": job.id, "name": schedule.get("name", "")})


def _scheduled_scan_payload(schedule: dict, config: ScanConfig, payload: ScanRequest,
                            principal: Principal, job) -> dict:
    """The job a schedule starts, and the note it leaves on the schedule either way."""
    from backend.store import record_schedule_run

    tenant_id, schedule_id = schedule["tenant_id"], schedule["schedule_id"]
    try:
        if partitioned_scans_enabled():
            data = _run_partitioned_scan_payload(config, payload, principal, job)
        else:
            from backend.jobs import _run_scan_job

            data = _run_scan_job(job, config, lambda report: _persist_compliance_scan(report, payload, principal))
    except BaseException as exc:
        from backend.jobs import _is_pause, _resume_follows

        # A run paused to be resumed is not over - the resume sweep continues it under
        # this job - and is not called failed.
        status = "paused" if _is_pause(exc) and _resume_follows(exc) else "failed"
        with suppress(Exception):
            record_schedule_run(tenant_id, schedule_id, status=status, error=type(exc).__name__)
        raise
    from backend.jobs import completion_of

    with suppress(Exception):
        record_schedule_run(tenant_id, schedule_id, scan_id=str(data.get("scan_id") or ""),
                            status=completion_of(data)[0])
    return data


def _finish_partitioned_scan_payload(data: dict, payload, principal: Principal) -> dict:
    """What a partitioned scan does once its report is written: alerts, and saying what it could not do."""
    _record_scan_source(principal.tenant_id, str(data.get("scan_id") or ""), payload)
    warnings: list[dict] = []
    try:
        data["alerts"] = evaluate_alerts(principal.tenant_id, data)
    except Exception as exc:
        data["alerts"] = []
        warnings.append({"stage": "alerts", "error": type(exc).__name__})
    if getattr(payload, "save_report", False) and PLAINTEXT_REPORT_EXPORT:
        # A plaintext export needs every file in one document, which a partitioned
        # scan never builds. Said out loud rather than skipped silently.
        warnings.append({"stage": "report_export", "error": "NotAvailableForPartitionedScan"})
    if warnings:
        data["scan_warnings"] = warnings
        try:
            audit(principal.tenant_id, principal.subject, "scan.secondary_operations_degraded",
                  {"scan_id": data.get("scan_id"), "warnings": warnings})
        except Exception:
            pass
    return data


def _analyze_endpoint_records(
    report: DSPMDiscoveryEngine,
    records: list[dict],
    job=None,
    floor: int = 70,
    ceiling: int = 90,
    close_index: bool = True,
) -> list[dict]:
    """Analyze endpoint records with the same adaptive pool as file scans.

    ``floor``/``ceiling`` bound the job progress this call may report: a content
    batch is analyzed while collection is still running (B4), and its progress
    belongs in the collection band rather than at the end of the scan.

    ``close_index`` releases the engine's reuse index when the analysis finishes.
    A per-batch call passes False - the index serves every batch and is closed
    once, by the last analysis or by the caller's outer ``finally``.
    """
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
                job.progress = max(job.progress, min(ceiling, floor + int((index / total) * (ceiling - floor))))
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
            job.progress = max(job.progress, min(ceiling, floor + int((completed_n / total_n) * (ceiling - floor))))
            job.message = f"Analyzing endpoint files {completed_n}/{len(records)}"

        report.config.progress_callback = update_progress

    try:
        return report._analyze_records(records)
    finally:
        report.config.cancel_check = prior_cancel
        report.config.progress_callback = prior_progress
        # Endpoint analysis drives the engine without run(), so nothing else would
        # ever write its reuse entries or release the index file. Before this, an
        # endpoint scan built its whole L1 index in memory and then discarded it.
        close_meta_index = getattr(report, "close_meta_index", None) if close_index else None
        if callable(close_meta_index):
            close_meta_index()


def _fetch_endpoint_content_in_batches(
    scanner,
    config: WinRMEndpointConfig,
    report: DSPMDiscoveryEngine,
    job,
    host_key: str,
    wanted_paths: list[str],
    sizes_by_path: dict[str, int],
    *,
    message: str,
    scan_overrides: dict | None = None,
) -> tuple[dict[str, dict], list[dict], int, list[str], dict]:
    """Read the content of ``wanted_paths`` in bounded commands, analyzing each batch (B4).

    One command is one WinRM response, held whole on the endpoint and again here, so a
    batch is bounded by bytes as well as by count. Each batch is analyzed as it arrives
    and only the analyzed records are kept - findings, risk and metadata, no file text -
    so what an endpoint scan holds follows the batch, not the size of the profile.

    Returns the analyzed records by path key, the analyzed archive children, how many
    commands it took, what went wrong, and the scanner diagnostics worth carrying over.
    """
    analyzed_by_path: dict[str, dict] = {}
    analyzed_archive_records: list[dict] = []
    fetch_errors: list[str] = []
    scanner_fields: dict = {}
    fetch_commands = 0
    fetched = 0
    total = max(len(wanted_paths), 1)
    for chunk in _endpoint_fetch_batches(wanted_paths, sizes_by_path):
        if job and job.cancel_requested:
            raise RuntimeError("Scan cancelled")
        fetch_commands += 1
        fetched += len(chunk)
        if job:
            job.progress = max(job.progress, min(60, 46 + int((fetched / total) * 14)))
            job.message = f"{message} {fetched}/{len(wanted_paths)}"
        scanner.config = replace(config, paths=chunk, max_depth=1, **(scan_overrides or {}))
        try:
            with collection_heartbeat(job, ceiling=65):
                batch = scanner.scan()
        except Exception as exc:
            fetch_errors.append(type(exc).__name__)
            continue
        batch_diagnostics = dict(scanner.last_scan_diagnostics or {})
        for field in ENDPOINT_REUSED_SCANNER_DIAGNOSTIC_FIELDS:
            if field in batch_diagnostics:
                scanner_fields[field] = batch_diagnostics[field]
        for marker in (
            "scan_truncated",
            "record_limit_reached",
            "unreadable_dirs",
            "missing_roots",
            "worker_errors",
            "archive_errors",
        ):
            if batch_diagnostics.get(marker):
                fetch_errors.append(marker)
        for record in batch:
            record["reuse_key"] = qualified_object_key("endpoint-winrm", host_key, str(record.get("path") or ""))
        # Analyzed here rather than with the rest of the scan: analysis is what turns a
        # file's text into findings, and until it runs that text is held. The index is
        # not closed between batches - it serves all of them.
        for record in _analyze_endpoint_records(report, batch, job, floor=60, ceiling=68, close_index=False):
            record_path = str(record.get("path") or "")
            if "::" in record_path:
                analyzed_archive_records.append(record)
            else:
                analyzed_by_path[record_path.casefold()] = record
        batch = None
    scanner.config = config
    return analyzed_by_path, analyzed_archive_records, fetch_commands, fetch_errors, scanner_fields


def _assembled_endpoint_records(
    report: DSPMDiscoveryEngine,
    job,
    metadata_records: list[dict],
    host_key: str,
    *,
    analyzed_by_path: dict[str, dict],
    reused_by_path: dict[str, dict],
    reused_archive_records: list[dict],
    analyzed_archive_records: list[dict],
    unreadable_note: str,
) -> tuple[list[dict], list[str]]:
    """Put the scan back in walk order, with every record analyzed exactly once (B4).

    By now a path is one of three things: it arrived in a content batch and was
    analyzed there, it was reused from the baseline, or it could not be read. The
    first is done; the other two are analyzed together here, which costs little
    because neither carries file text. Walk order is the metadata pass's order,
    because the sections of a report follow it (B2.2).
    """
    order: list[str] = []
    by_key: dict[str, dict] = {}
    pending: list[dict] = []
    missing: list[str] = []
    for metadata in metadata_records:
        path = str(metadata.get("path") or "")
        key = path.casefold()
        order.append(key)
        analyzed = analyzed_by_path.get(key)
        if analyzed is not None:
            by_key[key] = analyzed
            continue
        record = reused_by_path.get(key)
        if record is None:
            record = dict(metadata)
            record["scan_error"] = record.get("scan_error") or unreadable_note
            record["reuse_key"] = qualified_object_key("endpoint-winrm", host_key, path)
            missing.append(path)
        pending.append(record)
    for record in reused_archive_records:
        order.append(str(record.get("path") or "").casefold())
        pending.append(record)
    if pending:
        # Matched back by path rather than by position: a cancelled analysis returns
        # fewer records than it was given, and a record under the wrong path is worse
        # than a record missing from the report.
        for record in _analyze_endpoint_records(report, pending, job):
            by_key[str(record.get("path") or "").casefold()] = record
    records = [by_key[key] for key in order if key in by_key]
    records.extend(analyzed_archive_records)
    return records, missing


def _read_endpoint_metadata(
    scanner,
    config: WinRMEndpointConfig,
    report: DSPMDiscoveryEngine,
    job,
    metadata_records: list[dict],
    host_key: str,
    incremental_baseline_available: bool,
) -> tuple[list[dict], dict]:
    """A metadata pass's records, analyzed: reused from the baseline, or read in bounded
    content batches (B4), and put back in walk order. Returns them with the diagnostics that
    say how - the whole scan's on the single path, one page's on the frontier (W1.3)."""
    reused_by_path: dict[str, dict] = {}
    reused_archive_records: list[dict] = []
    wanted_paths: list[str] = []
    for record in metadata_records:
        path = str(record.get("path") or "")
        object_key = qualified_object_key("endpoint-winrm", host_key, path)
        snapshot = (
            report._reuse_probe(
                object_key,
                int(record.get("size") or 0),
                str(record.get("modified_at") or ""),
            )
            if incremental_baseline_available
            else None
        )
        if isinstance(snapshot, dict):
            reused_by_path[path.casefold()] = apply_reuse_snapshot(record, snapshot, object_key)
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
            wanted_paths.append(path)

    sizes_by_path = {
        str(record.get("path") or "").casefold(): int(record.get("size") or 0)
        for record in metadata_records
    }
    (
        analyzed_by_path,
        analyzed_archive_records,
        fetch_commands,
        fetch_errors,
        scanner_fields,
    ) = _fetch_endpoint_content_in_batches(
        scanner,
        config,
        report,
        job,
        host_key,
        wanted_paths,
        sizes_by_path,
        message="Reading changed endpoint files" if incremental_baseline_available else "Reading endpoint files",
        # A reused record is compared against a stored hash and owner, so a
        # warm scan reads both whatever the request asked for. A first scan
        # has nothing to compare against and keeps the request's own answer.
        scan_overrides={"hash_files": True, "read_owner": True} if incremental_baseline_available else None,
    )
    records, missing_paths = _assembled_endpoint_records(
        report,
        job,
        metadata_records,
        host_key,
        analyzed_by_path=analyzed_by_path,
        reused_by_path=reused_by_path,
        reused_archive_records=reused_archive_records,
        analyzed_archive_records=analyzed_archive_records,
        unreadable_note=(
            "Changed file could not be fetched during incremental scan"
            if incremental_baseline_available
            else "File could not be read during the scan"
        ),
    )
    if missing_paths:
        fetch_errors.append("MissingChangedRecords" if incremental_baseline_available else "MissingRecords")
    return records, {
        **scanner_fields,
        "incremental_metadata_pass": True,
        "incremental_first_scan_single_pass": not incremental_baseline_available and fetch_commands <= 1,
        "incremental_changed_paths": len(wanted_paths),
        "incremental_content_fetch_commands": fetch_commands,
        "incremental_fetch_batch_size": ENDPOINT_INCREMENTAL_FETCH_BATCH_SIZE,
        "incremental_fetch_batch_bytes": endpoint_fetch_batch_bytes(),
        "endpoint_max_file_text_bytes": endpoint_max_file_text_bytes(),
        "incremental_fetch_errors": fetch_errors[:20],
        "incremental_missing_changed_paths": missing_paths[:20],
    }


# ---- W1.3: an endpoint scan in the ledger, paged by a folder frontier ---------------------------------


def endpoint_page_folders() -> int:
    """How many folders one page command lists at most (``DSPM_ENDPOINT_PAGE_FOLDERS``, 500)."""
    try:
        return max(1, min(int(os.getenv("DSPM_ENDPOINT_PAGE_FOLDERS") or "500"), 10_000))
    except ValueError:
        return 500


@dataclass
class _EndpointRun:
    """What every page of one endpoint scan shares while it runs in this process."""

    config: WinRMEndpointConfig
    payload: EndpointScanRequest
    principal: Principal
    scanner: WinRMEndpointScanner
    baseline_available: bool
    lock: threading.Lock = dataclass_field(default_factory=threading.Lock)


_ENDPOINT_RUNS: dict[tuple[str, str], _EndpointRun] = {}


def _endpoint_run_for(tenant_id: str, scan_id: str) -> _EndpointRun:
    """The run's shared state: the job's own, or - for a resumed scan, or a page a queue worker
    took - rebuilt from the scan's stored request, its vaulted credential resolved again."""
    run = _ENDPOINT_RUNS.get((tenant_id, scan_id))
    if run is not None:
        return run
    record = read_partitioned_scan(tenant_id, scan_id)
    if record is None:
        raise LookupError(f"endpoint scan {scan_id} is not recorded")
    payload = EndpointScanRequest.model_validate(record["request"])
    config = _to_endpoint_config(payload, tenant_id)
    header = record.get("header") or {}
    principal = Principal(subject=str(header.get("requested_by") or "system:scan-resumer"), role="analyst",
                          tenant_id=tenant_id, auth_type="system")
    baseline = bool(payload.incremental_enabled) and incremental_baseline_exists(tenant_id, _endpoint_scan_scope(config))
    run = _EndpointRun(config, payload, principal, WinRMEndpointScanner(config), baseline)
    _ENDPOINT_RUNS[(tenant_id, scan_id)] = run
    return run


def _endpoint_frontier_units(hand_on: dict, max_folders: int) -> list[dict]:
    """The units a page hands on: where its listing stopped, then the subfolders it met."""
    units: list[dict] = []
    rest = [dict(item) for item in hand_on.get("continuation") or [] if isinstance(item, dict)]
    if rest:
        units.append({"kind": "endpoint_page", "folders": rest})
    found = [dict(item) for item in hand_on.get("folders") or [] if isinstance(item, dict)]
    for start in range(0, len(found), max_folders):
        units.append({"kind": "endpoint_page", "folders": found[start:start + max_folders]})
    return units


def _run_endpoint_page(scan, unit: dict, *, job, stop_reason) -> tuple[dict, list[dict], list[dict]]:
    """One page of an endpoint scan: list its folders, read and analyze what changed, and hand
    on the rest of the frontier. Returns the partition's header, records and new units."""
    from backend.compliance_service import ComplianceReportAccumulator

    run = _endpoint_run_for(scan.tenant_id, scan.scan_id)
    max_folders = endpoint_page_folders()
    page = {"folders": list(unit["spec"].get("folders") or []),
            "page_size": partition_max_files(), "max_folders": max_folders}
    # One WinRM session serves the scan; pages of one scan take turns on it.
    with run.lock:
        scanner, config = run.scanner, run.config
        scanner.config = replace(config, read_content=False, read_acl=False, inspect_archives=False,
                                 hash_files=False, read_owner=False)
        try:
            with collection_heartbeat(job, max_seconds=0) if job is not None else nullcontext():
                metadata_records = scanner.scan(page=page)
        finally:
            scanner.config = config
        hand_on = dict(scanner.last_page or {})
        page_diagnostics = dict(scanner.last_scan_diagnostics or {})
        host_key = config.host or scanner.last_connection_host
        report = _endpoint_analysis_engine(config, run.payload, run.principal, baseline_available=run.baseline_available)
        with _releasing_reuse_index(report):
            if config.read_content:
                report.last_scan_diagnostics = page_diagnostics
                analyzed, read_diagnostics = _read_endpoint_metadata(
                    scanner, config, report, job, metadata_records, host_key, run.baseline_available,
                )
            else:
                for record in metadata_records:
                    record["reuse_key"] = qualified_object_key("endpoint-winrm", host_key, str(record.get("path") or ""))
                report.last_scan_diagnostics = page_diagnostics
                analyzed = _analyze_endpoint_records(report, metadata_records, job, close_index=False)
                read_diagnostics = {}
            report.last_scan_diagnostics = {**dict(report.last_scan_diagnostics or {}), **page_diagnostics,
                                            **read_diagnostics}
            report._finalize_incremental_diagnostics(analyzed)
            if run.payload.incremental_enabled and config.read_content and not run.baseline_available:
                incremental = report.last_scan_diagnostics.get("incremental") or {}
                incremental["new_objects"] = len(analyzed)
                incremental["changed_objects"] = 0
                incremental["unclassified_fresh_objects"] = 0
            if not config.read_content:
                report.last_scan_diagnostics["incremental"]["content_reads"] = 0
                report.last_scan_diagnostics["incremental"]["delta_ratio"] = 0.0
            summary = {**report._build_summary(analyzed).to_dict(),
                       **scan_scope.summary_fields(report.last_scan_diagnostics)}
            diagnostics = dict(report.last_scan_diagnostics or {})
    reason = stop_reason()
    if reason:
        raise RuntimeError(reason)
    enrichment = ComplianceReportAccumulator(scan.compliance_enabled, list(scan.compliance_frameworks))
    for record in analyzed:
        enrichment.prepare(record)
    diagnostics["frontier_page_folders"] = len(page["folders"])
    header = {
        "timestamp": scan.timestamp,
        "source": "endpoint-winrm",
        "mode": "incremental" if run.payload.incremental_enabled else "full",
        "summary": summary,
        "scan_diagnostics": diagnostics,
    }
    if scan.label:
        header["scan_label"] = scan.label
    return header, analyzed, _endpoint_frontier_units(hand_on, max_folders)


partitioned_register_unit_runner("endpoint-winrm", _run_endpoint_page)


def _endpoint_report_extra(config: WinRMEndpointConfig) -> dict:
    """The ``endpoint`` section a partitioned endpoint report carries beside its files."""
    return {"endpoint": {
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
        "frontier": True,
    }}


def _run_partitioned_endpoint_scan(config: WinRMEndpointConfig, payload: EndpointScanRequest,
                                   principal: Principal, job=None) -> dict:
    """An endpoint scan of any size (W1.3): pages of a folder frontier, each a unit of the ledger.

    The single path listed the whole endpoint in one command, kept the first 5,000 files and
    dropped the rest, and held every record until one save. Here the first unit lists the
    scan's roots; each page lists at most a partition's worth of files and DSPM_ENDPOINT_PAGE_FOLDERS
    folders, reads what changed in bounded batches (B4), is written as it finishes, and hands
    on the subfolders it met and where it stopped. Nothing caps the record count; what the
    backend holds follows the page. A restart continues from the frontier in the ledger.
    """
    if job is not None:
        job.progress = max(job.progress, 7)
        job.message = "Listing the endpoint"
    scanner = WinRMEndpointScanner(config)
    scan_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    header = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "endpoint-winrm",
        "scan_label": str(getattr(payload, "scan_label", "") or "").strip()[:80],
        "compliance_enabled": bool(payload.compliance_enabled),
        "compliance_frameworks": list(payload.compliance_frameworks or []),
        "requested_by": str(getattr(principal, "subject", "") or ""),
        "host": config.host,
        "report_extra": _endpoint_report_extra(config),
    }
    register_partitioned_scan(principal.tenant_id, scan_id, job_id=str(getattr(job, "id", "") or ""),
                              request=payload.model_dump(mode="json"), header=header)
    create_scan_partitions(principal.tenant_id, scan_id, str(getattr(job, "id", "") or ""), [{
        "kind": "endpoint_page",
        "folders": [{"path": path, "depth": 0, "after": "", "root": True} for path in scanner._target_paths()],
    }])
    baseline = bool(payload.incremental_enabled) and incremental_baseline_exists(
        principal.tenant_id, _endpoint_scan_scope(config))
    _ENDPOINT_RUNS[(principal.tenant_id, scan_id)] = _EndpointRun(config, payload, principal, scanner, baseline)
    return _continue_endpoint_scan(scan_id, payload, principal, job)


def _continue_endpoint_scan(scan_id: str, payload: EndpointScanRequest, principal: Principal, job) -> dict:
    run = _endpoint_run_for(principal.tenant_id, scan_id)
    try:
        # One WinRS shell for every page and content batch of the scan (W1.3).
        with run.scanner.reusing_shell():
            data = continue_partitioned_scan(principal.tenant_id, scan_id, ScanConfig(tenant_id=principal.tenant_id),
                                             job=job)
    finally:
        _ENDPOINT_RUNS.pop((principal.tenant_id, scan_id), None)
    return _finish_partitioned_scan_payload(data, payload, principal)


def _resume_endpoint_scan(record: dict) -> None:
    """Continue an endpoint scan a stopped process left unfinished, from its frontier."""
    from backend.scan_resumer import ResumeLater
    from backend.store import bind_partitioned_scan_job

    tenant_id = record["tenant_id"]
    scan_id = record["scan_id"]
    payload = EndpointScanRequest.model_validate(record["request"])
    run = _endpoint_run_for(tenant_id, scan_id)
    try:
        job = create_job(tenant_id, lambda job: _continue_endpoint_scan(scan_id, payload, run.principal, job),
                         job_id=record.get("job_id") or None)
    except (RuntimeError, ValueError) as exc:
        _ENDPOINT_RUNS.pop((tenant_id, scan_id), None)
        raise ResumeLater(str(exc)) from exc
    bind_partitioned_scan_job(tenant_id, scan_id, job.id)
    audit(tenant_id, "system:scan-resumer", "scan.resumed", {"scan_id": scan_id, "job_id": job.id})


@contextmanager
def _releasing_reuse_index(engine):
    """Close the engine's reuse index however an endpoint scan ends.

    `_analyze_endpoint_records` closes it too, but collection probes the index
    before analysis starts, and a cancellation or a collector error raised between
    the two would leave the file open until the engine was garbage collected
    (B1 review). Closing twice is harmless.
    """
    try:
        yield engine
    finally:
        close_meta_index = getattr(engine, "close_meta_index", None)
        if callable(close_meta_index):
            close_meta_index()


def _run_endpoint_scan_payload(
    config: WinRMEndpointConfig,
    payload: EndpointScanRequest,
    principal: Principal,
    job=None,
) -> dict:
    if _is_local_endpoint_host(config.host):
        return _run_local_endpoint_scan_payload(config, payload, principal, job)
    if partitioned_scans_enabled():
        return _run_partitioned_endpoint_scan(config, payload, principal, job)

    incremental_baseline_available = bool(payload.incremental_enabled) and incremental_baseline_exists(
        principal.tenant_id,
        _endpoint_scan_scope(config),
    )
    report = _endpoint_analysis_engine(
        config,
        payload,
        principal,
        baseline_available=incremental_baseline_available,
    )
    with _releasing_reuse_index(report):
        return _collect_and_persist_remote_endpoint(
            config, payload, principal, job, report, incremental_baseline_available,
        )


def _collect_and_persist_remote_endpoint(
    config: WinRMEndpointConfig,
    payload: EndpointScanRequest,
    principal: Principal,
    job,
    report: DSPMDiscoveryEngine,
    incremental_baseline_available: bool,
) -> dict:
    if job:
        job.progress = 8
        # Every endpoint scan now starts the same way: enumerate, then read what
        # needs reading (B4). A scan that reads nothing is the enumeration alone.
        job.message = "Enumerating remote endpoint metadata"
    scanner = WinRMEndpointScanner(config)
    collection_diagnostics: dict = {}
    analyzed: list[dict] | None = None
    if config.read_content:
        # WinRM cannot callback into the server for each file while its
        # PowerShell walk is running. Enumerate size/mtime without content,
        # owner/ACL or hashing, resolve the baseline locally, then read what is
        # left in bounded commands.
        # P4: keep one job-local scanner so the working WinRM host, transport,
        # and pywinrm Session survive from metadata enumeration into every
        # content batch. Only scan-script options change between invocations.
        # B4: a first scan is read this way too. It costs one extra round-trip,
        # and it is what stops a five-gigabyte profile from arriving as a single
        # response, held whole on the endpoint and again here.
        scanner.config = replace(
            config,
            read_content=False,
            read_acl=False,
            inspect_archives=False,
            hash_files=False,
            read_owner=False,
        )
        with collection_heartbeat(job, ceiling=45):
            metadata_records = scanner.scan()
        collection_diagnostics = dict(scanner.last_scan_diagnostics or {})
        report.last_scan_diagnostics = collection_diagnostics
        host_key = config.host or scanner.last_connection_host
        records, read_diagnostics = _read_endpoint_metadata(
            scanner, config, report, job, metadata_records, host_key, incremental_baseline_available,
        )
        analyzed = records
        # Analysis rebinds the engine's diagnostics to a copy of its own, so the
        # collection facts are re-applied over what analysis left behind.
        collection_diagnostics = {
            **dict(report.last_scan_diagnostics or {}),
            **collection_diagnostics,
            **read_diagnostics,
        }
    else:
        # Nothing to read: the walk is the scan, and a metadata record is small.
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
        job.message = (
            f"Analyzed {len(records)} endpoint files"
            if analyzed is not None
            else f"Analyzing {len(records)} endpoint files"
        )
    report.last_scan_diagnostics = collection_diagnostics
    if analyzed is None:
        analyzed = _analyze_endpoint_records(report, records, job)
    report._finalize_incremental_diagnostics(analyzed)
    if payload.incremental_enabled and config.read_content and not incremental_baseline_available:
        # A cold baseline has nothing to probe against, so every file read is new
        # work - classify it explicitly instead of leaving it unclassified.
        incremental = report.last_scan_diagnostics.get("incremental") or {}
        incremental["new_objects"] = len(analyzed)
        incremental["changed_objects"] = 0
        incremental["unclassified_fresh_objects"] = 0
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
        "summary": {**report._build_summary(analyzed).to_dict(),
                    **scan_scope.summary_fields(report.last_scan_diagnostics)},
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


def _apply_local_endpoint_acl(record: dict, *, read_acl: bool) -> None:
    """Give local-endpoint records the same owner/DACL shape as SMB/WinRM."""

    owner = str(record.get("owner") or "")
    acl = record.get("acl") if isinstance(record.get("acl"), dict) else {}
    if (
        read_acl
        and not (record.get("cache_reused") or record.get("incremental_reused"))
        and "::" not in str(record.get("path") or "")
    ):
        acl = security_for_path(str(record.get("path") or ""), with_dacl=True)
    if read_acl:
        owner = str((acl or {}).get("owner") or owner)
        record["owner"] = owner
        record["acl"] = {
            "owner": owner,
            "principals": [str(item) for item in ((acl or {}).get("principals") or [])],
            "permissions": [str(item) for item in ((acl or {}).get("permissions") or [])],
        }
    else:
        record["acl"] = {
            "owner": owner,
            "principals": [],
            "permissions": [],
        }


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
    with _releasing_reuse_index(report):
        return _collect_and_persist_local_endpoint(config, payload, principal, job, report)


def _collect_and_persist_local_endpoint(
    config: WinRMEndpointConfig,
    payload: EndpointScanRequest,
    principal: Principal,
    job,
    report: DSPMDiscoveryEngine,
) -> dict:
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
                # the install's own data folder, database and key folder are never data here
                excluded_paths=product_private_paths(),
                scope=config.scope,
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
            _apply_local_endpoint_acl(record, read_acl=config.read_acl)
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
        "summary": {**report._build_summary(analyzed).to_dict(),
                    **scan_scope.summary_fields(report.last_scan_diagnostics)},
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


def _incremental_probe(
    tenant_id: str,
    scope_key: str,
    enabled: bool,
    *,
    baseline_available: bool | None = None,
):
    """Bind a scan to one tenant/scope without querying on a cold baseline."""

    if not enabled or not scope_key:
        return None
    if baseline_available is None:
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
            # W2.6: an inventory or full scan keeps its own baseline - an inventory scan's
            # "nothing found" must never be replayed into a content scan. A standard scan
            # keeps the scope it always had, so no baseline is orphaned.
            **({"scan_level": payload.scan_level}
               if getattr(payload, "scan_level", "standard") != "standard" else {}),
            # Advanced scope changes which files the scan can see: a scoped scan keeps its
            # own baseline, or a narrower run would read as the broader one's deletions.
            # A scan without one keeps the key it always had.
            **({"scope": scan_scope.digest(rules)}
               if (rules := payload.scope.canonical(absolute=False)) else {}),
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
            **({"scope": scan_scope.digest(config.scope)} if config.scope else {}),
        },
    )


def _endpoint_analysis_engine(
    config: WinRMEndpointConfig,
    payload: EndpointScanRequest,
    principal: Principal,
    *,
    baseline_available: bool | None = None,
) -> DSPMDiscoveryEngine:
    enabled = bool(payload.incremental_enabled)
    scope_key = _endpoint_scan_scope(config)
    if baseline_available is None:
        baseline_available = enabled and incremental_baseline_exists(principal.tenant_id, scope_key)
    return DSPMDiscoveryEngine(
        ScanConfig(
            tenant_id=principal.tenant_id,
            server="",
            walk_local_path=False,
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
            # B6: read once, here, so one scan is explained by one set of rules.
            suppression_rules=suppression_rules_for_scan(principal.tenant_id),
            exact_match=_exact_match_for_scan(principal.tenant_id),
            baseline_probe=_incremental_probe(
                principal.tenant_id,
                scope_key,
                enabled,
                baseline_available=baseline_available,
            ),
        )
    )


def _smb_encryption_required(payload) -> bool:
    """D1: this scan asked for it, or the installation requires it of every SMB scan."""
    from backend.config import smb_encryption_required

    return bool(getattr(payload, "smb_encryption", False)) or smb_encryption_required()


def _resolve_saved_credential(tenant_id: str, credential_ref: str) -> dict:
    try:
        return vault.resolve(tenant_id, credential_ref)
    except KeyError as exc:
        raise SavedCredentialMissing("Saved credential not found") from exc


def _apply_scan_level(payload: ConnectionRequest) -> ConnectionRequest:
    """What a scan level means for the request (W2.6). Applied wherever a request becomes a
    configuration - a new scan, a resumed one, a queue worker's - so they agree."""
    level = str(getattr(payload, "scan_level", "standard") or "standard")
    if level == "inventory":
        return payload.model_copy(update={"inspect_archives": False, "compliance_enabled": False,
                                           "compliance_frameworks": []})
    if level == "full":
        frameworks = list(getattr(payload, "compliance_frameworks", []) or []) or [
            str(profile["id"]) for profile in load_compliance_profiles()]
        return payload.model_copy(update={"inspect_archives": True, "compliance_enabled": True,
                                           "compliance_frameworks": frameworks[:12]})
    return payload


def _to_config(payload: ConnectionRequest, tenant_id: str) -> ScanConfig:
    payload = _apply_scan_level(payload)
    username = payload.username.strip()
    password = payload.password
    domain = payload.domain.strip() or "WORKGROUP"
    server = "" if _is_local_endpoint_host(payload.server) else payload.server.strip()
    allowed_extensions, extension_filter_enabled = _scan_extension_settings(
        payload.allowed_extensions,
        payload.extension_filter_enabled,
    )
    if payload.credential_ref:
        secret = _resolve_saved_credential(tenant_id, payload.credential_ref)
        username = secret.get("username", "")
        password = secret.get("password", "")
        domain = secret.get("domain", domain)

    shares = tuple(getattr(payload, "smb_shares", None) or ())
    if server and getattr(payload, "smb_encryption", False) and not shares:
        # D1: smbprotocol cannot list a server's shares, so a scan that asks for encryption
        # names them - said here, where the caller reads it (a model error's text is not
        # returned). An installation-wide DSPM_SMB_REQUIRE_ENCRYPTION is refused by the
        # collector with the same reason.
        raise HTTPException(status_code=400, detail="Name the shares to scan: an SMB 3 encrypted scan cannot "
                                                    "list a server's shares.")
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
        read_content=str(getattr(payload, "scan_level", "standard") or "standard") != "inventory",
        smb_shares=shares or None,
        smb_require_encryption=_smb_encryption_required(payload),
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
        suppression_rules=suppression_rules_for_scan(tenant_id),
        exact_match=_exact_match_for_scan(tenant_id),
        baseline_probe=_incremental_probe(tenant_id, scope_key, incremental_enabled),
        scope=payload.scope.canonical(absolute=False),
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
        secret = _resolve_saved_credential(tenant_id, payload.credential_ref)
        username = secret.get("username", "")
        password = secret.get("password", "")
        domain = secret.get("domain", domain)

    return WinRMEndpointConfig(
        tenant_id=tenant_id,
        host=payload.host.strip(),
        username=username,
        password=password,
        domain=domain,
        target_username=payload.target_username.strip(),
        paths=[item.strip() for item in payload.paths if item.strip()] or ["desktop", "documents", "downloads"],
        max_depth=payload.max_depth,
        read_content=payload.read_content,
        # B4: one file may not spend a hundred megabytes of WinRM response on its own.
        max_read_bytes=endpoint_max_file_text_bytes(),
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
        # C0.1: the transport the operator chose, including the default port for it.
        use_ssl=payload.use_ssl,
        port=payload.port or (5986 if payload.use_ssl else None),
        ca_bundle=payload.ca_bundle if payload.cert_trust == "ca_bundle" else "",
        cert_thumbprint=payload.cert_thumbprint if payload.cert_trust == "thumbprint" else "",
        insecure_tls=payload.cert_trust == "insecure",
        kerberos_mode=payload.kerberos,
        scope=payload.scope.canonical(absolute=True),
    )


# Registered LAST so every real route and the /static mount win first: an
# unknown page URL redirects to the dashboard instead of leaking a raw JSON
# 404, while unknown API/static paths keep failing loudly for clients.
@app.api_route(
    "/{unmatched_path:path}",
    include_in_schema=False,
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
def unknown_page_redirect(unmatched_path: str, request: Request):
    """Every verb, so an unknown API path 404s instead of reporting 405.

    Registered for GET alone, this route still MATCHED a POST by path - and
    Starlette answers a path match with no method match as 405 Method Not
    Allowed, without ever calling the handler. So a POST to an endpoint the
    running server does not have came back as "Method Not Allowed", which reads
    as a bug in the request rather than as a missing route, and is exactly what
    a server left running across an upgrade looks like.
    """

    is_api = unmatched_path.startswith(("api/", "static/"))
    if is_api:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Unknown endpoint: /{unmatched_path}. If this worked before an upgrade, "
                "the running server predates it - restart it and retry."
            ),
        )
    # A redirect is only meaningful for a page navigation, which is a GET.
    if request.method != "GET" or "." in unmatched_path.rsplit("/", 1)[-1]:
        raise HTTPException(status_code=404, detail="Not Found")
    return RedirectResponse("/dashboard", status_code=302)
