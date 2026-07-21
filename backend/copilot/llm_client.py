from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import httpx

from backend.copilot import provider_health

_log = logging.getLogger(__name__)

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma3n:e4b")
OLLAMA_MODEL_PROFILE = os.getenv("OLLAMA_MODEL_PROFILE", "gemma3n_e4b")
OLLAMA_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "35"))
OLLAMA_MAX_CONCURRENT = int(os.getenv("OLLAMA_MAX_CONCURRENT", "1"))
OLLAMA_NUM_PREDICT = int(os.getenv("OLLAMA_NUM_PREDICT", "512"))
_ollama_semaphore = asyncio.Semaphore(OLLAMA_MAX_CONCURRENT)
MODEL_HEALTH_TIMEOUT = float(os.getenv("OLLAMA_MODEL_HEALTH_TIMEOUT", "5"))
MODEL_HEALTH_TTL_SECONDS = float(os.getenv("OLLAMA_MODEL_HEALTH_TTL_SECONDS", "45"))


@dataclass(frozen=True)
class ModelHealth:
    status: str
    model: str
    daemon_reachable: bool
    model_present: bool
    detail_code: str | None = None
    checked_at: float = 0.0

    @property
    def is_healthy(self) -> bool:
        return self.status == "healthy"


_MODEL_HEALTH_CACHE: ModelHealth | None = None

TASK_TOKEN_BUDGETS = {
    "classification": 32,
    "short_answer": 128,
    "explanation": 256,
    "remediation": 256,
    "report_narration": 512,
    "teaching": 384,
    "translation": 128,
    "general": OLLAMA_NUM_PREDICT,
}

DEFAULT_OPTIONS: dict[str, Any] = {
    "temperature": float(os.getenv("OLLAMA_TEMPERATURE", "0.2")),
    "top_p": float(os.getenv("OLLAMA_TOP_P", "0.8")),
    "num_ctx": int(os.getenv("OLLAMA_NUM_CTX", "4096")),
    "num_predict": OLLAMA_NUM_PREDICT,
    "repeat_penalty": float(os.getenv("OLLAMA_REPEAT_PENALTY", "1.1")),
}

MODEL_STOP_TOKENS: list[str] = []

# Descriptive metadata for the local model profiles we evaluated for the Copilot.
# This NEVER changes the runtime default — the active model stays env-driven via
# OLLAMA_MODEL / OLLAMA_MODEL_PROFILE. Every profile runs with think=False (no
# visible chain-of-thought) and supports Ollama JSON mode. Roles:
#   primary          controlled verbalizer + situation arbiter (single-model)
#   primary_upgrade  proven upgrade if the operator pulls it (deferred)
#   fast_arbiter     lighter English/JSON model for a split strategy
#   deep_mode        higher-quality but slower optional profile
SUPPORTED_MODEL_PROFILES: dict[str, dict[str, Any]] = {
    "gemma3n_e4b": {
        "model": "gemma3n:e4b",
        "role": "primary",
        "param_class": "6.9B (E4B)",
        "multilingual": True,
        "ollama_verified": True,
        "recommended_default": True,
    },
    "llama31_8b": {
        "model": "llama3.1:8b",
        "role": "primary_upgrade",
        "param_class": "8B",
        "multilingual": True,
        "ollama_verified": True,
        "recommended_default": False,
    },
    "phi4_mini": {
        "model": "phi4-mini",
        "role": "fast_arbiter",
        "param_class": "3.8B",
        "multilingual": False,
        "ollama_verified": True,
        "recommended_default": False,
    },
    "gemma3_12b": {
        "model": "gemma3:12b-it-q4_K_M",
        "role": "deep_mode",
        "param_class": "12B",
        "multilingual": True,
        "ollama_verified": True,
        "recommended_default": False,
    },
}


def model_metadata() -> dict[str, Any]:
    """Return safe, non-sensitive model diagnostics for status/audit surfaces.

    Reflects the env-configured model so operators can confirm which local model
    is active without exposing hosts, keys, or prompts.
    """
    profile = SUPPORTED_MODEL_PROFILES.get(OLLAMA_MODEL_PROFILE)
    return {
        "model_name": OLLAMA_MODEL,
        "model_profile": OLLAMA_MODEL_PROFILE,
        "model_role": (profile or {}).get("role", "primary"),
        "model_param_class": (profile or {}).get("param_class"),
        "model_profile_known": profile is not None,
        "model_suppresses_cot": True,       # every call sends think=False
        "model_supports_json_mode": True,
    }


class LLMError(Exception):
    """Raised when the local model is unavailable or returns invalid data.

    Attributes:
        error_code: Machine-readable code (e.g. MODEL_NOT_FOUND, OLLAMA_TIMEOUT).
    """

    def __init__(self, message: str, error_code: str | None = None):
        super().__init__(message)
        self.error_code = error_code or "LLM_ERROR"


def get_token_budget(task_type: str) -> int:
    """Return the Ollama output token budget for a task type."""

    return int(TASK_TOKEN_BUDGETS.get(task_type, TASK_TOKEN_BUDGETS["general"]))


def _http_error_detail(exc: httpx.HTTPStatusError) -> str:
    """Extract a developer-facing detail string from an HTTP error."""
    status = exc.response.status_code
    try:
        body = exc.response.json()
        msg = body.get("error", "") if isinstance(body, dict) else str(body)
    except Exception:
        msg = exc.response.text[:200]
    return f"HTTP {status}: {msg}"


def _classify_health_http_error(exc: httpx.HTTPStatusError) -> str:
    text = f"{exc.response.status_code} {exc.response.text}".lower()
    if exc.response.status_code == 404:
        return "model_missing"
    if exc.response.status_code >= 500:
        if "cuda" in text or "llama-server process has terminated" in text or "terminated" in text:
            return "model_crashed"
        return "model_500"
    return "model_show_ok_but_generate_failed"


async def check_ollama_model_health(model_name: str | None = None, ttl_seconds: float = MODEL_HEALTH_TTL_SECONDS) -> ModelHealth:
    """Check daemon reachability, model presence, and tiny generation health."""

    global _MODEL_HEALTH_CACHE
    model = model_name or OLLAMA_MODEL
    now = time.monotonic()
    if (
        _MODEL_HEALTH_CACHE is not None
        and _MODEL_HEALTH_CACHE.model == model
        and ttl_seconds > 0
        and now - _MODEL_HEALTH_CACHE.checked_at < ttl_seconds
    ):
        return _MODEL_HEALTH_CACHE

    def health(status: str, daemon: bool, present: bool, detail: str | None = None) -> ModelHealth:
        global _MODEL_HEALTH_CACHE
        result = ModelHealth(status=status, model=model, daemon_reachable=daemon, model_present=present, detail_code=detail, checked_at=time.monotonic())
        _MODEL_HEALTH_CACHE = result
        return result

    try:
        async with httpx.AsyncClient(timeout=MODEL_HEALTH_TIMEOUT) as client:
            daemon_response = await client.get(f"{OLLAMA_HOST}/")
            daemon_response.raise_for_status()
            try:
                show_response = await client.post(f"{OLLAMA_HOST}/api/show", json={"model": model})
                show_response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                status = _classify_health_http_error(exc)
                return health(status, True, status != "model_missing", status)
            try:
                generate_response = await client.post(
                    f"{OLLAMA_HOST}/api/generate",
                    json={
                        "model": model,
                        "prompt": "OK",
                        "stream": False,
                        "think": False,
                        "options": {"num_predict": 4, "temperature": 0},
                    },
                )
                generate_response.raise_for_status()
            except httpx.TimeoutException:
                return health("model_timeout", True, True, "model_timeout")
            except httpx.HTTPStatusError as exc:
                status = _classify_health_http_error(exc)
                return health(status, True, True, status)
            except httpx.HTTPError:
                return health("model_load_failed", True, True, "model_load_failed")
    except httpx.TimeoutException:
        return health("daemon_unreachable", False, False, "daemon_timeout")
    except httpx.HTTPError:
        return health("daemon_unreachable", False, False, "daemon_unreachable")
    return health("healthy", True, True)


async def call_ollama(
    messages: list[dict[str, str]],
    json_mode: bool = False,
    options: dict[str, Any] | None = None,
    max_tokens: int | None = None,
    task_type: str = "general",
) -> str:
    merged_options = dict(DEFAULT_OPTIONS)
    merged_options["num_predict"] = max_tokens if max_tokens is not None else get_token_budget(task_type)
    if options:
        merged_options.update(options)
    payload: dict[str, Any] = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        "think": False,
        "options": merged_options,
    }
    if json_mode:
        payload["format"] = "json"
    if MODEL_STOP_TOKENS:
        payload["stop"] = MODEL_STOP_TOKENS

    # Circuit breaker: while the provider is known-crashed, do not issue an HTTP
    # call during the cooldown (prevents repeated 500/CUDA spam).
    allowed, skip_reason = provider_health.allow_provider_call()
    if not allowed:
        raise LLMError(
            "Provider is temporarily unavailable (circuit open after a recent model crash).",
            "PROVIDER_CIRCUIT_OPEN",
        )

    async with _ollama_semaphore:
        try:
            async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
                response = await client.post(f"{OLLAMA_HOST}/api/chat", json=payload)
                response.raise_for_status()
        except httpx.ConnectError:
            _log.error("Ollama server unreachable at %s", OLLAMA_HOST)
            provider_health.record_failure("OLLAMA_UNREACHABLE", "connection refused: cannot connect to ollama")
            raise LLMError(
                "Cannot connect to Ollama. Is the Ollama server running?",
                "OLLAMA_UNREACHABLE",
            ) from None
        except httpx.TimeoutException:
            _log.error("Ollama request timed out after %.1fs", OLLAMA_TIMEOUT)
            provider_health.record_failure("OLLAMA_TIMEOUT", f"ollama timeout after {int(OLLAMA_TIMEOUT)}s")
            raise LLMError(
                f"Ollama did not respond within {int(OLLAMA_TIMEOUT)}s. The model may be loading or the request is too complex.",
                "OLLAMA_TIMEOUT",
            ) from None
        except httpx.HTTPStatusError as exc:
            detail = _http_error_detail(exc)
            if exc.response.status_code == 404:
                _log.error("Model '%s' not found in Ollama. %s", OLLAMA_MODEL, detail)
                raise LLMError(
                    f"Model '{OLLAMA_MODEL}' is not installed in Ollama. Run: ollama pull {OLLAMA_MODEL}",
                    "MODEL_NOT_FOUND",
                ) from exc
            _log.error("Ollama HTTP error: %s", detail)
            provider_health.record_failure("OLLAMA_ERROR", detail)
            raise LLMError(
                f"Ollama returned an error: {detail}",
                "OLLAMA_ERROR",
            ) from exc
        except httpx.HTTPError as exc:
            _log.error("Ollama connection error: %s", exc)
            provider_health.record_failure("OLLAMA_UNREACHABLE", f"cannot connect to ollama: {exc}")
            raise LLMError(
                "Cannot connect to Ollama. Is the Ollama server running?",
                "OLLAMA_UNREACHABLE",
            ) from exc

    try:
        data = response.json()
        content = str(data.get("message", {}).get("content", "")).strip()
        provider_health.record_success()
        return content
    except (ValueError, TypeError) as exc:
        _log.error("Ollama returned invalid JSON: %s", exc)
        raise LLMError(
            "Ollama returned an invalid response.",
            "OLLAMA_INVALID_RESPONSE",
        ) from exc


async def stream_ollama(messages: list[dict[str, str]]) -> AsyncIterator[str]:
    payload = {"model": OLLAMA_MODEL, "messages": messages, "stream": True, "think": False, "options": dict(DEFAULT_OPTIONS)}
    async with _ollama_semaphore:
        try:
            async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT + 5) as client:
                async with client.stream("POST", f"{OLLAMA_HOST}/api/chat", json=payload, timeout=OLLAMA_TIMEOUT) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if not line:
                            continue
                        try:
                            chunk = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        content = str(chunk.get("message", {}).get("content", ""))
                        if content:
                            yield content
                        if chunk.get("done") is True:
                            break
        except httpx.ConnectError:
            raise LLMError(
                "Cannot connect to Ollama for streaming.",
                "OLLAMA_UNREACHABLE",
            ) from None
        except httpx.TimeoutException:
            raise LLMError(
                f"Ollama streaming timed out after {int(OLLAMA_TIMEOUT)}s.",
                "OLLAMA_TIMEOUT",
            ) from None
        except (httpx.TimeoutException, httpx.HTTPError) as exc:
            _log.error("Ollama streaming error: %s", exc)
            raise LLMError(
                "Ollama streaming is unavailable.",
                "OLLAMA_STREAM_ERROR",
            ) from exc


async def check_ollama() -> bool:
    """Check Ollama server is reachable."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(f"{OLLAMA_HOST}/api/tags")
            response.raise_for_status()
        return True
    except httpx.HTTPError:
        return False


async def check_ollama_model() -> dict[str, Any]:
    """Check if the configured Ollama model is available.

    Returns a dict with keys:
      - configured: the configured model name
      - available: list of installed model names
      - ready: bool, whether the configured model is in the available list
    """
    available: list[str] = []
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{OLLAMA_HOST}/api/tags")
            response.raise_for_status()
            data = response.json()
            for model in data.get("models", []):
                name = model.get("name", "")
                if name:
                    available.append(name)
    except httpx.HTTPError:
        pass
    return {
        "configured": OLLAMA_MODEL,
        "available": available,
        "ready": OLLAMA_MODEL in available,
    }
