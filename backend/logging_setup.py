"""Service logs: rotating files with a fixed bound, and no secrets in them (C11).

A service writes `<DSPM_LOG_DIR>/<service>.log`, rolled at `DSPM_LOG_MAX_MB` (10) with
`DSPM_LOG_BACKUPS` (10) old files kept, so the logs never take more than
(backups + 1) x size of the disk. Files are appended to, so a restart continues the log
rather than replacing it. Standard error gets the same lines, for a console run and for
the service wrapper's own capture.

Every line passes `RedactingFilter` first: the configured secret values themselves (keys,
passwords, credential-bearing URLs - `config.secret_values`), bearer and signed tokens,
`password=...`-shaped pairs, and the password in a database URL are replaced before any
handler sees the text, tracebacks included. It is a net, not the policy: code must still
not log secrets.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import re
import sys
from pathlib import Path
from typing import Callable, Iterable

REDACTED = "[redacted]"
FORMAT = "%(asctime)s | %(levelname)s | %(process)d | %(name)s | %(message)s"

_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    # a signed token (JWT, or this product's HMAC challenge tokens)
    (re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]{6,})?"), REDACTED),
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"), r"\1" + REDACTED),
    (re.compile(r"(?i)\b(postgres(?:ql)?://[^:/@\s]+:)([^@\s]+)(@)"), r"\1" + REDACTED + r"\3"),
    (re.compile(r"(?i)\b((?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|authorization)"
                r"\s*[=:]\s*)(?!\[redacted\])([^\s,;&'\"}]+)"), r"\1" + REDACTED),
)


def redact(text: str, secrets: Iterable[str] = ()) -> str:
    for secret in secrets:
        if secret and secret in text:
            text = text.replace(secret, REDACTED)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class RedactingFilter(logging.Filter):
    """Rewrites a record's message (and its traceback) with the secrets removed."""

    def __init__(self, secrets: Callable[[], Iterable[str]] | None = None) -> None:
        super().__init__()
        self._secrets = secrets or (lambda: ())

    def filter(self, record: logging.LogRecord) -> bool:
        secrets = list(self._secrets())
        try:
            message = record.getMessage()
        except Exception:  # a record whose arguments do not fit its format
            message = str(record.msg)
        cleaned = redact(message, secrets)
        if cleaned != message or record.args:
            record.msg, record.args = cleaned, ()
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text, secrets)
        if record.stack_info:
            record.stack_info = redact(record.stack_info, secrets)
        return True


def _int(name: str, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(int(os.getenv(name, str(default)) or default), high))
    except ValueError:
        return default


class JsonFormatter(logging.Formatter):
    """D11: one JSON object a line (DSPM_LOG_FORMAT=json), for a log shipper - the same
    redacted message and traceback the text format carries."""

    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        import json
        from datetime import datetime, timezone

        document = {"ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
                    "level": record.levelname, "service": self.service, "pid": record.process,
                    "logger": record.name, "message": record.getMessage()}
        if record.exc_text:
            document["exception"] = record.exc_text
        return json.dumps(document, ensure_ascii=False)


def configure(service: str, *, log_dir: str | os.PathLike | None = None) -> Path | None:
    """Route the root logger (and uvicorn's) through the redacting filter, to standard
    error and - when a log directory is configured - to a rotating file. Returns the
    file, if any."""
    from backend.config import secret_values

    directory = str(log_dir or os.getenv("DSPM_LOG_DIR", "")).strip()
    level = getattr(logging, os.getenv("DSPM_LOG_LEVEL", "INFO").strip().upper() or "INFO", logging.INFO)
    redactor = RedactingFilter(secret_values)
    json_lines = os.getenv("DSPM_LOG_FORMAT", "text").strip().lower() == "json"
    formatter = JsonFormatter(service) if json_lines else logging.Formatter(FORMAT)
    handlers: list[logging.Handler] = []
    stream = logging.StreamHandler(sys.stderr)
    handlers.append(stream)
    path = None
    if directory:
        folder = Path(directory)
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{service}.log"
        handlers.append(logging.handlers.RotatingFileHandler(
            path, maxBytes=_int("DSPM_LOG_MAX_MB", 10, 1, 1024) * 1024 * 1024,
            backupCount=_int("DSPM_LOG_BACKUPS", 10, 1, 100), encoding="utf-8", delay=True))
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    for handler in handlers:
        handler.setFormatter(formatter)
        handler.addFilter(redactor)
        root.addHandler(handler)
    root.setLevel(level)
    # uvicorn's loggers keep no handlers of their own and reach these through the root.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        named = logging.getLogger(name)
        for handler in list(named.handlers):
            named.removeHandler(handler)
        named.propagate = True
    logging.captureWarnings(True)
    return path
