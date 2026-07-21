"""In-memory provider health circuit breaker for the local Ollama model.

When the local model crashes (HTTP 500 / CUDA / llama-server terminated /
connection refused / timeout) the Copilot must stop hammering the provider. This
module holds a tiny process-local circuit-breaker state and a deterministic
model-status question detector. It never stores raw prompts or sensitive values —
only a short, redacted error summary.

All provider calls funnel through ``llm_client.call_ollama``, which records
success/failure here and refuses to issue an HTTP call while the circuit is open.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
import threading
import time
from typing import Any


COOLDOWN_SECONDS = float(os.getenv("COPILOT_PROVIDER_COOLDOWN_SECONDS", "60"))
_FAILURE_OPEN_THRESHOLD = 1  # one crash is enough to open the breaker

# Error signatures that indicate the provider is unhealthy (not a normal refusal).
_CRASH_PATTERNS = (
    "http 500",
    "500 internal server error",
    "llama-server process has terminated",
    "terminated",
    "cuda",
    "shared object initialization failed",
    "connection refused",
    "timeout",
    "timed out",
    "ollama unavailable",
    "cannot connect to ollama",
)
_CRASH_ERROR_CODES = {
    "OLLAMA_ERROR",
    "OLLAMA_TIMEOUT",
    "OLLAMA_UNREACHABLE",
    "OLLAMA_STREAM_ERROR",
}

_SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{12,}", re.IGNORECASE),
    re.compile(r"sk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"(?i)(api[_-]?key|password|secret|token)\s*[:=]\s*\S+"),
    re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


@dataclass
class _ProviderHealthState:
    provider_status: str = "unknown"          # healthy | unhealthy | unknown
    circuit_state: str = "closed"             # closed | open | half_open
    last_failure_time: float | None = None
    last_success_time: float | None = None
    last_error_type: str | None = None
    last_error_message_safe: str | None = None
    failure_count: int = 0
    cooldown_until: float | None = None


_state = _ProviderHealthState()
_lock = threading.Lock()


def reset() -> None:
    """Reset the breaker (used by tests and startup)."""
    global _state
    with _lock:
        _state = _ProviderHealthState()


def _now() -> float:
    return time.monotonic()


def _safe_message(message: str) -> str:
    text = str(message or "")
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:160]


def classify_error(error_code: str | None, message: str | None) -> str:
    blob = f"{error_code or ''} {message or ''}".lower()
    if any(term in blob for term in ("cuda", "terminated", "shared object", "500", "0xc0000409")):
        return "ollama_cuda_or_server_crash"
    if "timeout" in blob or "timed out" in blob:
        return "ollama_timeout"
    if "connection refused" in blob or "cannot connect" in blob or "unreachable" in blob:
        return "ollama_unreachable"
    return "provider_error"


def is_crash_error(error_code: str | None, message: str | None) -> bool:
    blob = f"{error_code or ''} {message or ''}".lower()
    if (error_code or "").upper() in _CRASH_ERROR_CODES:
        return True
    return any(pattern in blob for pattern in _CRASH_PATTERNS)


def record_success() -> None:
    with _lock:
        _state.provider_status = "healthy"
        _state.circuit_state = "closed"
        _state.failure_count = 0
        _state.last_success_time = _now()
        _state.last_error_type = None
        _state.last_error_message_safe = None
        _state.cooldown_until = None


def record_failure(error_code: str | None, message: str | None) -> bool:
    """Record a provider failure. Returns True if it opened/kept-open the circuit."""
    if not is_crash_error(error_code, message):
        return False
    with _lock:
        _state.failure_count += 1
        _state.last_failure_time = _now()
        _state.last_error_type = classify_error(error_code, message)
        _state.last_error_message_safe = _safe_message(message or error_code or "provider error")
        if _state.failure_count >= _FAILURE_OPEN_THRESHOLD:
            _state.provider_status = "unhealthy"
            _state.circuit_state = "open"
            _state.cooldown_until = _now() + COOLDOWN_SECONDS
        return True


def allow_provider_call() -> tuple[bool, str]:
    """Return (allowed, skip_reason). Transitions open→half_open after cooldown."""
    with _lock:
        if _state.circuit_state == "closed":
            return True, ""
        if _state.circuit_state == "half_open":
            return True, "half_open_probe"
        # open
        if _state.cooldown_until is not None and _now() >= _state.cooldown_until:
            _state.circuit_state = "half_open"
            return True, "half_open_probe"
        return False, "circuit_open"


def circuit_open() -> bool:
    with _lock:
        if _state.circuit_state == "open" and _state.cooldown_until is not None and _now() >= _state.cooldown_until:
            return False
        return _state.circuit_state == "open"


def cooldown_remaining_ms() -> int:
    with _lock:
        if _state.cooldown_until is None:
            return 0
        remaining = _state.cooldown_until - _now()
        return int(max(0.0, remaining) * 1000)


def snapshot(skip_reason: str | None = None) -> dict[str, Any]:
    with _lock:
        return {
            "provider_health_status": _state.provider_status,
            "provider_circuit_state": _state.circuit_state,
            "provider_circuit_open": _state.circuit_state == "open",
            "provider_skip_reason": skip_reason,
            "provider_last_error_type": _state.last_error_type,
            "provider_last_error_message_safe": _state.last_error_message_safe,
            "provider_failure_count": _state.failure_count,
            "provider_cooldown_remaining_ms": (
                int(max(0.0, (_state.cooldown_until - _now())) * 1000) if _state.cooldown_until else 0
            ),
        }


def is_unhealthy() -> bool:
    with _lock:
        return _state.provider_status == "unhealthy" or _state.circuit_state in {"open", "half_open"}


# ---------------------------------------------------------------------------
# Deterministic model-status question detection (zero-provider)
# ---------------------------------------------------------------------------
def _fold(text: str) -> str:
    from backend.copilot import language_service

    value = language_service.normalize_for_intent(text).lower()
    for src, dst in {"ə": "e", "ı": "i", "ğ": "g", "ö": "o", "ş": "s", "ç": "c", "ü": "u"}.items():
        value = value.replace(src, dst)
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ?]+", " ", value)).strip()


def is_model_status_question(message: str) -> bool:
    text = _fold(message)
    if not text:
        return False
    # Explicit status phrases.
    if any(phrase in text for phrase in ("model status", "provider status", "ollama status", "ai model down", "model down")):
        return True
    # "model" + a down/not-responding/running signal. This route reads the
    # stored snapshot only; it must not probe the provider.
    if "model" in text and any(term in text for term in ("isleyir", "islemir", "cavab vermir", "niye cavab", "isləmir", "down", "cavab vermr", "running", "up")):
        return True
    # AZ "ollama işləyir?" (folds to "ollama isleyir") — distinct from EN "ollama is running".
    if "ollama" in text and any(term in text for term in ("isleyir", "islemir", "down")):
        return True
    return False
