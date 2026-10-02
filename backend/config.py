"""One validated configuration source for a Sentro install (C11).

Every setting the product reads is a `DSPM_*` name, documented in `.env.example`. An
install may keep them in a TOML file instead of the environment:

    # C:\\ProgramData\\Sentro\\config\\sentro.toml
    [settings]
    DSPM_ENV = "production"
    DSPM_DB_URL_FILE = 'C:\\ProgramData\\Sentro\\secrets\\db_url'
    DSPM_LOG_DIR = 'C:\\ProgramData\\Sentro\\logs'

The file is found through `DSPM_CONFIG_FILE` (or `main.py --config`). Precedence is fixed
and the same for every command: the process environment, then the file, then the
built-in default. A name the product does not know is refused - a misspelt setting
silently doing nothing is how an install ends up weaker than its operator believes.

Secrets never go in the file. Each secret setting also accepts `<NAME>_FILE`, the path
of a file holding the value (for a service: readable by its account and Administrators
only), so no key, password or credential-bearing URL appears in the configuration, a
service definition or a command line.

In production, combinations that weaken the install are refused before anything starts
(`production_problems`). `python main.py config check` shows the effective settings -
secrets only as "set" - with where each came from.

This module imports nothing from the product: it runs before the rest is imported.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, MutableMapping

CONFIG_ENV = "DSPM_CONFIG_FILE"
SECRET_FILE_SUFFIX = "_FILE"
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off", ""}


class ConfigError(ValueError):
    """The configuration cannot be used; the message says which setting and why."""


@dataclass(frozen=True)
class Setting:
    name: str
    kind: str = "str"          # str | int | float | bool | path | enum | secret
    default: str | None = None
    choices: tuple[str, ...] = ()
    minimum: float | None = None
    maximum: float | None = None


def _settings(*rows: tuple) -> dict[str, Setting]:
    table: dict[str, Setting] = {}
    for row in rows:
        name, kind, *rest = row
        options = rest[0] if rest else {}
        table[name] = Setting(name, kind, **options)
    return table


# Every setting the product reads. tests/test_c11_config.py fails when code reads a
# DSPM_* name that is not here (or in NOT_SETTINGS), so the catalogue cannot fall behind.
SETTINGS: dict[str, Setting] = _settings(
    # the install
    ("DSPM_ENV", "enum", {"default": "local", "choices": ("local", "development", "dev", "test", "production", "prod")}),
    ("DSPM_CONFIG_FILE", "path"),
    ("DSPM_DATA_DIR", "path"),
    ("DSPM_LOG_DIR", "path"),
    ("DSPM_LOG_MAX_MB", "int", {"default": "10", "minimum": 1, "maximum": 1024}),
    ("DSPM_LOG_BACKUPS", "int", {"default": "10", "minimum": 1, "maximum": 100}),
    ("DSPM_LOG_LEVEL", "enum", {"default": "INFO", "choices": ("debug", "info", "warning", "error")}),
    ("DSPM_SCHEMA_CHECK_SECONDS", "int", {"default": "30", "minimum": 5, "maximum": 3600}),
    ("DSPM_ALLOW_EXTERNAL_BIND", "bool"),
    ("DSPM_TRUSTED_PROXIES", "str"),
    ("DSPM_TRUSTED_HOSTS", "str"),
    ("DSPM_CORS_ORIGINS", "str"),
    ("DSPM_MAX_BODY_BYTES", "int", {"minimum": 1024}),
    # keys and secrets (each also as <NAME>_FILE)
    ("DSPM_SECRET_KEY", "secret"),
    ("DSPM_VAULT_KEY", "secret"),
    ("DSPM_ARTIFACT_KEY", "secret"),
    ("DSPM_BACKUP_KEY", "secret"),
    ("DSPM_EVIDENCE_HMAC_KEY", "secret"),
    ("DSPM_DB_EVIDENCE_SIGNING_KEY", "secret"),
    ("DSPM_ADMIN_PASSWORD", "secret"),
    ("DSPM_DEV_ADMIN_PASSWORD", "secret"),
    ("DSPM_API_KEYS", "secret"),
    ("DSPM_MEILISEARCH_API_KEY", "secret"),
    ("DSPM_ALERT_WEBHOOK_URL", "secret"),
    # D11: the bearer token a Prometheus scraper sends to /metrics.
    ("DSPM_METRICS_TOKEN", "secret"),
    ("DSPM_LOCAL_ARTIFACT_KEY_PATH", "path"),
    ("DSPM_LOCAL_BACKUP_KEY_PATH", "path"),
    ("DSPM_LOCAL_EVIDENCE_KEY_PATH", "path"),
    ("DSPM_LOCAL_JWT_SECRET_PATH", "path"),
    ("DSPM_LOCAL_VAULT_KEY_PATH", "path"),
    # C12: the versioned key ring (a file holding keys: protect it like one), and the
    # recommended interval between a saved credential's password changes.
    ("DSPM_VAULT_KEYRING", "path"),
    ("DSPM_CREDENTIAL_ROTATION_DAYS", "int", {"default": "90", "minimum": 1, "maximum": 3650}),
    # database
    ("DSPM_DB_URL", "secret"),
    ("DSPM_DB_PATH", "path"),
    ("DSPM_BACKUP_DB_URL", "secret"),
    ("DSPM_DB_EXPECTED_IDENTITY", "str"),
    ("DSPM_DB_CONNECT_TIMEOUT", "int", {"minimum": 1, "maximum": 600}),
    ("DSPM_DB_POOL_MIN", "int", {"minimum": 0}),
    ("DSPM_DB_POOL_MAX", "int", {"minimum": 1}),
    ("DSPM_DB_POOL_MAX_IDLE", "int", {"minimum": 0}),
    ("DSPM_DB_POOL_CHECK", "bool"),
    ("DSPM_DB_ACTIVITY_MONITORING", "bool"),
    ("DSPM_DB_ACTIVITY_MONITORING_REQUIRED", "bool"),
    ("DSPM_SLOW_QUERY_MEAN_MS", "float", {"minimum": 0}),
    ("DSPM_SQLITE_CACHE_KB", "int"),
    ("DSPM_SQLITE_HOLD_OPEN", "bool"),
    ("DSPM_SQLITE_JOURNAL_MODE", "enum", {"choices": ("wal", "delete", "truncate")}),
    ("DSPM_SQLITE_MMAP_MB", "int", {"minimum": 0}),
    ("DSPM_SQLITE_WAL_LIMIT_MB", "int", {"minimum": 0}),
    ("DSPM_JSON_COMPRESS_MIN", "int", {"minimum": 0}),
    ("DSPM_NORMALIZED_WRITE_BEST_EFFORT", "bool"),
    ("DSPM_READ_FROM_NORMALIZED", "bool"),
    ("DSPM_INVENTORY_FROM_NORMALIZED", "bool"),
    ("DSPM_FINDING_INDEX_KEEP_SCANS", "int", {"minimum": 1}),
    # PostgreSQL provisioning (scripts/provision_postgres.py, scripts/db_roles.py)
    ("DSPM_PG_ADMIN_URL", "secret"),
    ("DSPM_PG_APP_PASSWORD", "secret"),
    ("DSPM_PG_SUPERUSER_PASSWORD", "secret"),
    ("DSPM_PG_APP_ROLE", "str"),
    ("DSPM_PG_BIN", "path"),
    ("DSPM_PG_DB", "str"),
    ("DSPM_PG_HOST", "str"),
    ("DSPM_PG_PORT", "int", {"minimum": 1, "maximum": 65535}),
    ("DSPM_PG_SSLMODE", "enum", {"choices": ("disable", "allow", "prefer", "require", "verify-ca", "verify-full")}),
    ("DSPM_MIGRATE_DEST_URL", "secret"),
    # storage
    ("DSPM_ARTIFACT_DIR", "path"),
    ("DSPM_BACKUP_DIR", "path"),
    ("DSPM_BACKUP_MAX_AGE_HOURS", "float", {"minimum": 0}),
    # C0.3: the backend's own backup schedule (0: off), the age past which production
    # readiness fails, the off-host copy, and how many verified sets / days retention keeps.
    ("DSPM_BACKUP_SCHEDULE_HOURS", "float", {"default": "24", "minimum": 0, "maximum": 744}),
    ("DSPM_BACKUP_READY_MAX_AGE_HOURS", "float", {"default": "48", "minimum": 0}),
    ("DSPM_BACKUP_COPY_DIR", "path"),
    ("DSPM_RETAIN_BACKUP_SETS", "int", {"default": "7", "minimum": 1, "maximum": 1000}),
    ("DSPM_RETAIN_BACKUP_DAYS", "int", {"default": "0", "minimum": 0}),
    ("DSPM_REPORT_DIR", "path"),
    ("DSPM_REPORT_ARTIFACTS", "bool"),
    ("DSPM_PLAINTEXT_REPORT_EXPORT", "bool"),
    ("DSPM_SCAN_CACHE_DIR", "path"),
    # C0.2: the scan cache is sealed with the artifact key; 0 is for an evaluation
    # install only, and production refuses it.
    ("DSPM_SCAN_CACHE_ENCRYPT", "bool", {"default": "1"}),
    ("DSPM_RETAIN_ALERT_DAYS", "int", {"minimum": 0}),
    ("DSPM_RETAIN_AUDIT_DAYS", "int", {"minimum": 0}),
    # C0.2: plaintext report files are aged out after a quarter; 0 keeps them.
    ("DSPM_RETAIN_REPORT_FILE_DAYS", "int", {"default": "90", "minimum": 0}),
    ("DSPM_RETENTION_INTERVAL_SECONDS", "int", {"minimum": 0}),
    ("DSPM_RETENTION_PRUNE_ARTIFACTS", "bool"),
    # sessions and sign-in
    ("DSPM_TOKEN_TTL_SECONDS", "int", {"minimum": 60}),
    ("DSPM_REFRESH_TOKEN_TTL_SECONDS", "int", {"minimum": 60}),
    ("DSPM_TOKEN_REVOCATION_CACHE_SECONDS", "int", {"minimum": 0}),
    ("DSPM_SESSION_IDLE_SECONDS", "int", {"minimum": 0}),
    ("DSPM_SESSION_TOUCH_SECONDS", "int", {"minimum": 1}),
    ("DSPM_MAX_SESSIONS_PER_USER", "int", {"minimum": 1}),
    ("DSPM_LOGIN_MAX_ATTEMPTS", "int", {"minimum": 1}),
    ("DSPM_LOGIN_WINDOW_SECONDS", "int", {"minimum": 1}),
    ("DSPM_LOGIN_IP_MAX_ATTEMPTS", "int", {"minimum": 1}),
    ("DSPM_PASSWORD_CHANGE_MAX_FAILURES", "int", {"minimum": 1}),
    ("DSPM_REGISTER_MAX_FAILURES", "int", {"minimum": 1}),
    ("DSPM_REFRESH_MAX_FAILURES", "int", {"minimum": 1}),
    ("DSPM_DIRECTORY_REVALIDATE_SECONDS", "int", {"minimum": 60, "maximum": 3600}),
    ("DSPM_PBKDF2_ROUNDS", "int", {"minimum": 210000, "maximum": 1200000}),
    ("DSPM_PASSWORD_MIN_LENGTH", "int", {"minimum": 8, "maximum": 128}),
    ("DSPM_BREACHED_PASSWORDS_FILE", "path"),
    ("DSPM_ALLOW_LEGACY_SHA256_PASSWORDS", "bool"),
    ("DSPM_SYNC_BUILTIN_ADMIN", "bool"),
    ("DSPM_ALLOW_DL_TOKEN_QUERY", "bool"),
    ("DSPM_ARTIFACT_DL_TOKEN_TTL_SECONDS", "int", {"minimum": 10}),
    ("DSPM_AUDIT_VERIFY_MAX_PER_HOUR", "int", {"minimum": 1}),
    ("DSPM_REVEAL_MAX_PER_HOUR", "int", {"default": "20", "minimum": 1, "maximum": 1000}),
    # SIEM, alerts, search
    ("DSPM_SIEM_URL", "str"),
    ("DSPM_SIEM_CA_FILE", "path"),
    ("DSPM_SIEM_FORMAT", "enum", {"choices": ("cef", "json")}),
    ("DSPM_SIEM_INTERVAL_SECONDS", "int", {"minimum": 1}),
    ("DSPM_SEARCH_ENGINE", "enum", {"choices": ("", "database", "meilisearch")}),
    ("DSPM_MEILISEARCH_URL", "str"),
    ("DSPM_MEILISEARCH_INDEX", "str"),
    ("DSPM_SEARCH_BATCH_SIZE", "int", {"minimum": 1}),
    ("DSPM_SEARCH_DUAL_WRITE", "bool"),
    ("DSPM_SEARCH_READ_ENABLED", "bool"),
    ("DSPM_SEARCH_RECONCILE_REPAIR", "bool"),
    ("DSPM_SEARCH_RECONCILE_SECONDS", "int", {"minimum": 0}),
    ("DSPM_SEARCH_TIMEOUT_SECONDS", "float", {"minimum": 0}),
    # scanning
    ("DSPM_SCAN_EXECUTION", "enum", {"choices": ("inline", "queue")}),
    ("DSPM_WORK_QUEUE", "str"),
    ("DSPM_JOB_WORKERS", "int", {"minimum": 1}),
    ("DSPM_MAX_JOBS_TOTAL", "int", {"minimum": 1}),
    ("DSPM_MAX_JOBS_PER_TENANT", "int", {"minimum": 1}),
    ("DSPM_JOB_RETENTION_SECONDS", "int", {"minimum": 0}),
    ("DSPM_PARTITIONED_SCANS", "bool"),
    # D7: read each local file's access-control entries (Windows, in-process)
    ("DSPM_LOCAL_ACL", "bool", {"default": "1"}),
    # D7: accounts that index or crawl content, flagged like service accounts (comma list)
    ("DSPM_INDEXER_PRINCIPALS", "str"),
    # D2: how many reference values a workspace's exact-match sets may hold in all
    ("DSPM_EDM_MAX_ROWS", "int", {"minimum": 1}),
    # D3: how often the alert deliverer looks for due work, and how often an open ticket
    # is asked whether it is done.
    ("DSPM_ALERT_DELIVERY_INTERVAL_SECONDS", "int", {"minimum": 1}),
    ("DSPM_TICKET_SYNC_SECONDS", "int", {"minimum": 30}),
    # D10: the publisher keys this install trusts (pinned by the installer), whether a scan
    # needs a valid licence, and how long an expired one keeps scans running.
    ("DSPM_TRUST_FILE", "path"),
    ("DSPM_LICENCE_REQUIRED", "bool"),
    ("DSPM_LICENCE_GRACE_DAYS", "int", {"minimum": 0}),
    # D11: log lines as JSON for a shipper; when the installation's own alerts are checked,
    # and how long a queued scan may wait before it is "stuck".
    ("DSPM_LOG_FORMAT", "enum", {"default": "text", "choices": ("text", "json")}),
    # D1: every SMB scan over SMB 3.1.1 with encryption required; and whether an SMB 3 scan
    # given no account may use the backend service's own Windows identity.
    ("DSPM_SMB_REQUIRE_ENCRYPTION", "bool"),
    ("DSPM_SMB_ALLOW_SERVICE_IDENTITY", "bool"),
    # D5: Microsoft Graph for SharePoint/OneDrive - a national cloud's endpoints, a private
    # CA for a TLS-inspecting proxy, and the hosts a file's download link may be on.
    ("DSPM_GRAPH_AUTHORITY", "str"),
    ("DSPM_GRAPH_ENDPOINT", "str"),
    ("DSPM_GRAPH_CA_FILE", "path"),
    ("DSPM_GRAPH_DOWNLOAD_HOSTS", "str"),
    ("DSPM_OPS_ALERT_INTERVAL_SECONDS", "int", {"minimum": 30}),
    ("DSPM_QUEUE_STUCK_MINUTES", "int", {"minimum": 0}),
    ("DSPM_PARTITION_LEASE_SECONDS", "int", {"minimum": 5}),
    ("DSPM_PARTITION_MAX_ATTEMPTS", "int", {"minimum": 1}),
    ("DSPM_PARTITION_MAX_FILES", "int", {"minimum": 1}),
    ("DSPM_PARTITION_WORKERS", "int", {"minimum": 1}),
    ("DSPM_SCAN_HEARTBEAT_SECONDS", "int", {"minimum": 1}),
    ("DSPM_SCAN_MAX_SECONDS", "int", {"minimum": 0}),
    ("DSPM_SCAN_QUEUE_MAX_SECONDS", "int", {"minimum": 0}),
    ("DSPM_SCAN_RESUME_INTERVAL_SECONDS", "int", {"minimum": 0}),
    ("DSPM_SCAN_SCHEDULER_INTERVAL_SECONDS", "int", {"minimum": 0}),
    ("DSPM_SCAN_REPORT_ROWS_CACHE", "int", {"minimum": 0}),
    ("DSPM_ANALYSIS_WORKERS", "int", {"minimum": 1}),
    ("DSPM_IO_WORKERS", "int", {"minimum": 1}),
    ("DSPM_DETECTOR_PROCESSES", "int", {"minimum": 0}),
    ("DSPM_DETECTOR_POOL_START_AFTER", "int", {"minimum": 0}),
    ("DSPM_DETECTOR_PREFILTER", "bool"),
    ("DSPM_GDPR_DETECTOR_TIMEOUT_SECONDS", "float", {"minimum": 0}),
    ("DSPM_NIST_DETECTOR_TIMEOUT_SECONDS", "float", {"minimum": 0}),
    ("DSPM_ARCHIVE_TIMEOUT_SECONDS", "float", {"minimum": 0}),
    ("DSPM_TEXT_SCAN_MAX_BYTES", "int", {"minimum": 1}),
    ("DSPM_HOST_IO_BUDGET", "int", {"minimum": 1}),
    ("DSPM_PIPELINE_ENABLED", "bool"),
    ("DSPM_PIPELINE_BUFFER", "int", {"minimum": 1}),
    ("DSPM_TRIAGE_ENABLED", "bool"),
    ("DSPM_TRIAGE_BINARY_SKIP", "bool"),
    ("DSPM_TRIAGE_ORDER", "str"),
    ("DSPM_TRIAGE_SAMPLE_BYTES", "int", {"minimum": 0}),
    ("DSPM_SMB_PARALLEL", "int", {"minimum": 1}),
    ("DSPM_SMB_FILE_PARALLEL", "int", {"minimum": 1}),
    ("DSPM_SMB_SINGLE_PASS", "bool"),
    ("DSPM_SMB_ACL_BATCH", "bool"),
    ("DSPM_SMB_ACL_BATCH_SIZE", "int", {"minimum": 1}),
    ("DSPM_SMB_ACL_BATCH_TIMEOUT_SECONDS", "float", {"minimum": 1}),
    ("DSPM_WINRM_PARALLEL", "int", {"minimum": 1}),
    ("DSPM_WINRM_WORKERS", "int", {"minimum": 1}),
    ("DSPM_WINRM_KERBEROS", "bool"),
    ("DSPM_WINRM_RESPONSE_MAX_BYTES", "int", {"minimum": 1024}),
    ("DSPM_WINRM_SSL_SKIP_CA_CHECK", "bool"),
    ("DSPM_REQUIRE_WINRM_SSL", "bool"),
    ("DSPM_ALLOW_WINRM_ACTIVATION", "bool"),
    ("DSPM_WINRM_ACTIVATION_HTTPS", "bool"),
    ("DSPM_ENDPOINT_FETCH_BATCH_BYTES", "int", {"minimum": 1024}),
    ("DSPM_ENDPOINT_MAX_FILE_TEXT_BYTES", "int", {"minimum": 1024}),
    ("DSPM_OCR_ENABLED", "bool"),
    ("DSPM_OCR_CACHE_MAX", "int", {"minimum": 0}),
    ("DSPM_OCR_INTRA_OP_THREADS", "int", {"minimum": 1}),
    ("DSPM_OCR_MAX_CHARS", "int", {"minimum": 1}),
    ("DSPM_OCR_MAX_DIMENSION", "int", {"minimum": 1}),
    ("DSPM_OCR_MAX_FILE_BYTES", "int", {"minimum": 1}),
    ("DSPM_OCR_MAX_PIXELS", "int", {"minimum": 1}),
    ("DSPM_OCR_MIN_CONFIDENCE", "float", {"minimum": 0, "maximum": 1}),
    ("DSPM_OCR_TIMEOUT_SECONDS", "float", {"minimum": 0}),
    ("DSPM_ML_NER_ENABLED", "bool"),
    ("DSPM_DEMO_ASSETS_IN_INVENTORY", "bool"),
    ("DSPM_EXPORT_BATCH_SIZE", "int", {"minimum": 1}),
    # caches
    ("DSPM_LIVE_CACHE", "bool"),
    ("DSPM_LIVE_CACHE_SECONDS", "int", {"minimum": 0}),
    ("DSPM_TENANT_EXISTS_CACHE_SECONDS", "int", {"minimum": 0}),
    ("DSPM_READINESS_CACHE_SECONDS", "int", {"minimum": 0}),
    ("DSPM_INVENTORY_COUNT_CACHE_SECONDS", "int", {"minimum": 0}),
    ("DSPM_INVENTORY_FACETS_CACHE_SECONDS", "int", {"minimum": 0}),
    # removed; still recognised so an old file says so instead of failing as unknown
    ("DSPM_ALLOW_PRIVATE_TARGETS", "bool"),
    ("DSPM_RAW_EVIDENCE_PREVIEW", "bool"),
    # benchmark and tooling switches
    ("DSPM_INVENTORY_BENCHMARK_ALLOW_WRITE", "bool"),
    ("DSPM_SEARCH_BENCHMARK_ALLOW_WRITE", "bool"),
    ("DSPM_MAX_JOB_RESULT_FILES", "int", {"minimum": 1}),
)

# DSPM_* names in the code that are not settings, with why.
NOT_SETTINGS = {
    "DSPM_A": "a fragment in a docstring example",
    "DSPM_PG_": "a prefix matched when listing PostgreSQL settings",
    "DSPM_WINRM_": "a prefix matched when listing WinRM settings",
    "DSPM_MIGRATIONS_CLI": "set by the migrations command itself to keep the store import inert",
    "DSPM_ACTIVATION_PW": "a variable of the remote PowerShell activation script, not of Sentro",
    "DSPM_SMB_ACL_PW": "a variable of a remote PowerShell script, not of Sentro",
    "DSPM_TASK_ARG": "a variable of the remote scheduled-task script, not of Sentro",
    "DSPM_TASK_PW": "a variable of the remote scheduled-task script, not of Sentro",
    "DSPM_TASK_RU": "a variable of the remote scheduled-task script, not of Sentro",
    "DSPM_TASK_TN": "a variable of the remote scheduled-task script, not of Sentro",
}

# Test-suite switches: recognised (never "unknown"), refused in production.
TEST_ONLY = {"DSPM_PG_TEST_RESET", "DSPM_RUN_LARGE_TESTS", "DSPM_TEST_KEEP_DB",
             "DSPM_MEILISEARCH_LIVE_URL", "DSPM_MEILISEARCH_LIVE_KEY"}

REMOVED = {
    "DSPM_ALLOW_PRIVATE_TARGETS": "each workspace now lists the networks it may scan (Scan targets)",
    "DSPM_RAW_EVIDENCE_PREVIEW": "evidence is governed by the evidence.view permission",
}


# Test-suite switches that hold a credential: never shown by `config check`, redacted
# from logs like any other secret.
TEST_ONLY_SECRETS = {"DSPM_MEILISEARCH_LIVE_KEY"}


def is_secret(name: str) -> bool:
    setting = SETTINGS.get(name)
    return bool(setting and setting.kind == "secret") or name in TEST_ONLY_SECRETS


def is_production_value(value: str | None) -> bool:
    return str(value or "local").strip().lower() in {"prod", "production"}


@dataclass
class Resolved:
    """The effective value of one setting and where it came from."""
    name: str
    value: str | None
    source: str             # environment | file | secret file | default
    detail: str = ""        # the file a value or a secret was read from


@dataclass
class Effective:
    path: Path | None
    values: dict[str, Resolved] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def production(self) -> bool:
        resolved = self.values.get("DSPM_ENV")
        return is_production_value(resolved.value if resolved else None)

    def get(self, name: str) -> str | None:
        resolved = self.values.get(name)
        return resolved.value if resolved else None

    def describe(self, *, show_defaults: bool = False) -> list[tuple[str, str, str]]:
        """(name, shown value, source) rows; a secret is never shown, only that it is set."""
        rows = []
        for name in sorted(self.values):
            resolved = self.values[name]
            if resolved.source == "default" and not show_defaults:
                continue
            if is_secret(name):
                shown = "(set)" if resolved.value else "(not set)"
            else:
                shown = "" if resolved.value is None else resolved.value
            source = resolved.source + (f" {resolved.detail}" if resolved.detail else "")
            rows.append((name, shown, source))
        return rows


def read_file(path: Path) -> dict[str, str]:
    """The [settings] table of a TOML file, as the strings the environment would hold."""
    import tomllib

    try:
        with open(path, "rb") as handle:
            document = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"The configuration file {path} does not exist.") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"The configuration file {path} is not valid TOML: {exc}") from exc
    extra = sorted(key for key in document if key != "settings")
    if extra:
        raise ConfigError(f"{path}: only a [settings] table is read; found {', '.join(extra)}.")
    table = document.get("settings", {})
    if not isinstance(table, dict):
        raise ConfigError(f"{path}: [settings] must be a table of DSPM_* names.")
    values: dict[str, str] = {}
    for key, value in table.items():
        if isinstance(value, bool):
            values[key] = "1" if value else "0"
        elif isinstance(value, (int, float, str)):
            values[key] = str(value)
        else:
            raise ConfigError(f"{path}: {key} must be a string, number or true/false.")
    return values


def _known(name: str) -> bool:
    if name in SETTINGS or name in TEST_ONLY:
        return True
    base = name[: -len(SECRET_FILE_SUFFIX)] if name.endswith(SECRET_FILE_SUFFIX) else ""
    return bool(base) and is_secret(base)


def _check_value(setting: Setting, value: str) -> str | None:
    """An error message when `value` is not valid for `setting`."""
    text = value.strip()
    if setting.kind == "bool":
        if text.lower() not in _TRUE | _FALSE:
            return f"{setting.name} must be 1 or 0 (or true/false), not {text!r}."
    elif setting.kind in {"int", "float"}:
        if text == "":
            return None
        try:
            number = int(text) if setting.kind == "int" else float(text)
        except ValueError:
            return f"{setting.name} must be {'a whole number' if setting.kind == 'int' else 'a number'}, not {text!r}."
        if setting.minimum is not None and number < setting.minimum:
            return f"{setting.name} must be at least {setting.minimum:g}, not {text}."
        if setting.maximum is not None and number > setting.maximum:
            return f"{setting.name} must be at most {setting.maximum:g}, not {text}."
    elif setting.kind == "enum" and setting.choices:
        # The readers lower-case what they read, so the check does too.
        if text.lower() not in setting.choices:
            return f"{setting.name} must be one of {', '.join(c or '(empty)' for c in setting.choices)}, not {text!r}."
    return None


def truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in _TRUE


def smb_encryption_required() -> bool:
    """D1: the installation requires SMB 3 encryption of every SMB read - a scan's, and a
    reveal's re-read of a file an older, unencrypted scan found. Read in one place so the
    two cannot disagree about what the setting says."""
    return truthy(os.getenv("DSPM_SMB_REQUIRE_ENCRYPTION"))


def plaintext_export_allowed(environ: Mapping[str, str] | None = None) -> bool:
    """Whether a scan report may be written to disk as plaintext JSON.

    One policy for every writer of such a copy - the console's report export and
    `main.py scan --output` (C0.2): only when DSPM_PLAINTEXT_REPORT_EXPORT=1, and never in
    production, where the switch itself is refused.
    """
    env = os.environ if environ is None else environ
    return truthy(env.get("DSPM_PLAINTEXT_REPORT_EXPORT")) and not is_production_value(env.get("DSPM_ENV"))


def resolve(environ: Mapping[str, str], path: Path | None = None) -> Effective:
    """Effective settings from the environment and an optional file. Pure: changes nothing."""
    effective = Effective(path=path)
    file_values: dict[str, str] = {}
    if path is not None:
        try:
            file_values = read_file(path)
        except ConfigError as exc:
            effective.errors.append(str(exc))
    for name in sorted(file_values):
        if not _known(name):
            effective.errors.append(f"{path}: {name} is not a Sentro setting (misspelt?).")
    for name in sorted(key for key in environ if key.startswith("DSPM_")):
        if not _known(name) and name not in NOT_SETTINGS:
            effective.warnings.append(f"The environment sets {name}, which is not a Sentro setting (misspelt?).")

    for name, setting in SETTINGS.items():
        file_ref = name + SECRET_FILE_SUFFIX
        if name in environ:
            effective.values[name] = Resolved(name, environ[name], "environment")
        elif name in file_values:
            effective.values[name] = Resolved(name, file_values[name], "file", str(path))
        elif setting.kind == "secret" and (environ.get(file_ref) or file_values.get(file_ref)):
            secret_path = Path(environ.get(file_ref) or file_values[file_ref])
            try:
                secret = secret_path.read_text(encoding="utf-8").strip()
            except OSError as exc:
                effective.errors.append(f"{file_ref} names {secret_path}, which cannot be read ({type(exc).__name__}).")
                secret = None
            if secret == "":
                effective.errors.append(f"{file_ref} names {secret_path}, which is empty.")
                secret = None
            effective.values[name] = Resolved(name, secret, "secret file", str(secret_path))
        else:
            effective.values[name] = Resolved(name, setting.default, "default")
        value = effective.values[name].value
        if value is not None and setting.kind != "secret":
            problem = _check_value(setting, value)
            if problem:
                effective.errors.append(problem)
        if name in file_values and setting.kind == "secret":
            message = (f"{path}: {name} is a secret and does not belong in the configuration file; "
                       f"put it in a file readable only by the service and set {name}{SECRET_FILE_SUFFIX}.")
            # DSPM_ENV is resolved first, so this already knows the mode.
            (effective.errors if effective.production else effective.warnings).append(message)
        if value not in (None, "") and name in REMOVED:
            effective.warnings.append(f"{name} is no longer read: {REMOVED[name]}.")
    for name in sorted(TEST_ONLY):
        if name in environ or name in file_values:
            effective.values[name] = Resolved(name, environ.get(name, file_values.get(name)),
                                              "environment" if name in environ else "file")
    if effective.production:
        effective.errors.extend(production_problems(effective))
    return effective


def _loopback(host: str) -> bool:
    return host in {"localhost", "127.0.0.1", "::1", ""} or host.startswith("127.")


def production_problems(effective: Effective) -> list[str]:
    """Combinations a production install must not run with. Each names its setting."""
    get = effective.get
    problems: list[str] = []
    for name, why in (
        ("DSPM_ALLOW_LEGACY_SHA256_PASSWORDS", "it accepts unsalted SHA-256 password hashes"),
        ("DSPM_SYNC_BUILTIN_ADMIN", "it resets the administrator's password at every start"),
        ("DSPM_WINRM_SSL_SKIP_CA_CHECK", "it scans endpoints without checking their certificate"),
        ("DSPM_PLAINTEXT_REPORT_EXPORT", "it writes plaintext copies of every report to disk"),
        ("DSPM_ALLOW_DL_TOKEN_QUERY", "it puts download tokens in URLs"),
    ):
        if truthy(get(name)):
            problems.append(f"{name}=1 is refused in production: {why}.")
    if not truthy(get("DSPM_SCAN_CACHE_ENCRYPT") or "1"):
        problems.append("DSPM_SCAN_CACHE_ENCRYPT=0 is refused in production: it writes every scanned file's path, "
                        "owner and findings to the scan cache in clear.")
    # A switch that is on by default and set to nothing: whether that means "the default"
    # or "off" is up to each reader, and production does not leave that to chance.
    for name, setting in SETTINGS.items():
        resolved = effective.values.get(name)
        if (setting.kind == "bool" and truthy(setting.default) and resolved is not None
                and resolved.source != "default" and not str(resolved.value or "").strip()):
            problems.append(f"{name} is set to nothing, which is refused in production: write 1 or 0, or "
                            "remove it to keep the default (on).")
    if get("DSPM_DEV_ADMIN_PASSWORD"):
        problems.append("DSPM_DEV_ADMIN_PASSWORD is for local installs; production uses DSPM_ADMIN_PASSWORD(_FILE).")
    for name in sorted(TEST_ONLY):
        if effective.values.get(name) and effective.values[name].value:
            problems.append(f"{name} is a test-suite switch and is refused in production.")
    keyring = str(get("DSPM_VAULT_KEYRING") or "").strip()
    for name in ("DSPM_SECRET_KEY", "DSPM_VAULT_KEY", "DSPM_ARTIFACT_KEY", "DSPM_BACKUP_KEY",
                 "DSPM_EVIDENCE_HMAC_KEY", "DSPM_ADMIN_PASSWORD", "DSPM_DB_URL"):
        if name == "DSPM_VAULT_KEY" and keyring and Path(keyring).exists():
            continue  # C12: the key ring holds the vault's keys; the single key is not read
        if not get(name):
            problems.append(f"{name} (or {name}{SECRET_FILE_SUFFIX}) must be set in production.")
    origins = [item.strip() for item in (get("DSPM_CORS_ORIGINS") or "").split(",") if item.strip()]
    if "*" in origins:
        problems.append("DSPM_CORS_ORIGINS=* is refused in production: name the console's origin.")
    url = get("DSPM_DB_URL") or ""
    if url and not url.startswith(("postgres://", "postgresql://")):
        problems.append("DSPM_DB_URL must be a PostgreSQL URL in production.")
    for name in ("DSPM_DB_URL", "DSPM_BACKUP_DB_URL", "DSPM_MIGRATE_DEST_URL"):
        value = get(name) or ""
        if value.startswith(("postgres://", "postgresql://")) and _remote_without_verified_tls(value):
            problems.append(f"{name} reaches a remote PostgreSQL without verifying its certificate: set "
                            "sslmode=verify-full (or verify-ca) with sslrootcert naming the server's CA.")
    return problems


def _url_hosts(url: str) -> list[str]:
    """Every host a PostgreSQL URL may connect to: the authority (one or several,
    comma-separated) and any host/hostaddr query parameter - libpq honours both."""
    from urllib.parse import parse_qs, urlsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return ["(unparseable)"]
    hosts: list[str] = []
    for item in parts.netloc.rsplit("@", 1)[-1].split(","):
        item = item.strip()
        host = item[1:].split("]", 1)[0] if item.startswith("[") else item.split(":", 1)[0]
        if host:
            hosts.append(host.lower())
    query = parse_qs(parts.query)
    for key in ("host", "hostaddr"):
        for value in query.get(key, []):
            hosts.extend(item.strip().lower() for item in value.split(",") if item.strip())
    return hosts


def _remote_without_verified_tls(url: str) -> bool:
    """A host that is neither loopback nor a local socket directory, reached with anything
    less than a verified certificate. No sslmode means libpq's `prefer`, which falls back to
    plaintext; `require` encrypts but accepts any certificate."""
    from urllib.parse import parse_qs, urlsplit

    remote = [host for host in _url_hosts(url) if not (_loopback(host) or host.startswith("/"))]
    if not remote:
        return False
    try:
        mode = (parse_qs(urlsplit(url).query).get("sslmode") or [""])[-1].strip().lower()
    except ValueError:
        mode = ""
    return mode not in {"verify-ca", "verify-full"}


def apply(effective: Effective, environ: MutableMapping[str, str]) -> None:
    """Put file and secret-file values into the environment the product reads, and write
    every true/false setting as 1 or 0 so each reader sees the same answer.

    An empty switch is left empty. Its readers take empty as "not set: the default" - the
    scan cache's sealing, WinRM's TLS requirement in production, report bodies in the
    artifact tier - and production_problems judged it the same way; rewritten to 0 after
    that check, it turned each of them off."""
    for name, resolved in effective.values.items():
        if resolved.source in {"file", "secret file"} and resolved.value is not None and name not in environ:
            environ[name] = resolved.value
        setting = SETTINGS.get(name)
        if setting and setting.kind == "bool" and name in environ and str(environ[name]).strip():
            environ[name] = "1" if truthy(environ[name]) else "0"


_BOOTSTRAPPED: Effective | None = None


def bootstrap(config_path: str | os.PathLike | None = None,
              environ: MutableMapping[str, str] | None = None) -> Effective:
    """Resolve, refuse on errors, and apply - once, before the product is imported."""
    global _BOOTSTRAPPED
    env = os.environ if environ is None else environ
    raw = str(config_path or env.get(CONFIG_ENV) or "").strip()
    path = Path(raw) if raw else None
    if path is not None:
        env[CONFIG_ENV] = str(path)
    effective = resolve(env, path)
    if effective.errors:
        raise ConfigError("The configuration cannot be used:\n  - " + "\n  - ".join(effective.errors))
    apply(effective, env)
    if environ is None:
        _BOOTSTRAPPED = effective
    return effective


def bootstrapped() -> Effective | None:
    return _BOOTSTRAPPED


def config_path_from_argv(argv: list[str]) -> str | None:
    """`--config PATH` or `--config=PATH`, wherever it appears."""
    for index, arg in enumerate(argv):
        if arg == "--config" and index + 1 < len(argv):
            return argv[index + 1]
        if arg.startswith("--config="):
            return arg.split("=", 1)[1]
    return None


def command_from_argv(argv: list[str]) -> str:
    """The first word that is neither an option nor the value of --config."""
    skip = False
    for arg in argv:
        if skip:
            skip = False
            continue
        if arg == "--config":
            skip = True
            continue
        if not arg.startswith("-"):
            return arg
    return ""


def secret_values(environ: Mapping[str, str] | None = None) -> list[str]:
    """The configured secret values (for log redaction), longest first."""
    env = os.environ if environ is None else environ
    found = {str(env.get(name) or "").strip() for name, setting in SETTINGS.items() if setting.kind == "secret"}
    found |= {str(env.get(name) or "").strip() for name in TEST_ONLY_SECRETS}
    return sorted((value for value in found if len(value) >= 6), key=len, reverse=True)
