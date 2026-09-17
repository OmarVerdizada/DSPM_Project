"""B3.1: the derived state several backends may share, and what Memurai is allowed to hold.

The case for Redis was never the queue. It was **aggregate reads hitting the database
while a scan is running**: one dashboard refresh is four O(estate) aggregates, measured at
7.31 ms against 1,369 assets on this host's PostgreSQL, which extrapolates to 5.34 s per
refresh at a million - so a 3.9-hour scan spends about 6.95 hours of database time
answering the console (§2 of the plan). A per-process, thirty-second TTL cache does not
help: every backend and every worker keeps its own copy, and each one pays the aggregate
again.

This is that cache, shared:

- **only derived state.** Counts, facets, posture inputs, a job's progress. Never file
  content, previews, credentials or PAN/PII samples - Phase A spent its effort removing
  plaintext at rest, and a cache is a new place for it to accumulate. Everything here is
  reconstructible from PostgreSQL after a total loss of Memurai, which is the boundary
  the plan draws;
- **every key expires.** Memurai runs `noeviction` (evicting an unacknowledged job would
  be data loss), so a key without a TTL would live forever;
- **invalidation without `KEYS`.** A tenant's cached values carry a version segment, and
  a write bumps the version - the old keys become unreachable and expire on their own.
  The product's Redis user is not allowed to run `KEYS`, `SCAN` or `FLUSHDB`, and this is
  why it does not need them;
- **absent by default.** With no `DSPM_REDIS_URL` every call here is a no-op and the
  product behaves exactly as it did before. Memurai is an accelerator, never a
  dependency: if it is down, the reads fall through to the database.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Any, Callable

KEY_PREFIX = "dspm:"
DEFAULT_TTL_SECONDS = 60
PROGRESS_TTL_SECONDS = 600
# One connection per process, rebuilt if the server went away.
_client_lock = threading.Lock()
_client: Any = None
_client_url: str = ""
_client_failed_at: float = 0.0
# How long to leave a broken connection alone before trying again, so a Memurai that is
# down costs one failed connection per interval rather than one per request.
_RETRY_AFTER_SECONDS = 30.0

_counters = {"hits": 0, "misses": 0, "errors": 0, "writes": 0}
_counter_lock = threading.Lock()


def configured() -> bool:
    return bool(os.getenv("DSPM_REDIS_URL", "").strip()) and os.getenv("DSPM_LIVE_CACHE", "1") != "0"


def client():
    """The shared client, or None when Redis is not configured or not reachable."""
    global _client, _client_url, _client_failed_at
    if not configured():
        return None
    url = os.getenv("DSPM_REDIS_URL", "").strip()
    with _client_lock:
        if _client is not None and _client_url == url:
            return _client
        if time.monotonic() - _client_failed_at < _RETRY_AFTER_SECONDS and _client_url == url:
            return None
        try:
            import redis  # type: ignore[import-not-found]

            candidate = redis.Redis.from_url(
                url, decode_responses=True, socket_connect_timeout=2, socket_timeout=2,
            )
            candidate.ping()
        except Exception:
            _client, _client_url, _client_failed_at = None, url, time.monotonic()
            _note("errors")
            return None
        _client, _client_url, _client_failed_at = candidate, url, 0.0
        return _client


def _note(name: str) -> None:
    with _counter_lock:
        _counters[name] = _counters.get(name, 0) + 1


def diagnostics() -> dict:
    """What the cache did, for the scan diagnostics and the health endpoint."""
    with _counter_lock:
        counts = dict(_counters)
    return {"enabled": configured(), "connected": client() is not None, **counts}


def reset_for_tests() -> None:
    global _client, _client_url, _client_failed_at
    with _client_lock:
        _client, _client_url, _client_failed_at = None, "", 0.0
    with _counter_lock:
        for key in _counters:
            _counters[key] = 0


def _version_key(tenant_id: str) -> str:
    return f"{KEY_PREFIX}ver:{tenant_id}"


def version(tenant_id: str) -> str:
    """The tenant's cache generation. Unknown - or unreachable - reads as generation 0."""
    connection = client()
    if connection is None:
        return "0"
    try:
        return str(connection.get(_version_key(tenant_id)) or "0")
    except Exception:
        _note("errors")
        return "0"


def bump(tenant_id: str) -> None:
    """Make everything cached for this tenant unreachable; the old keys expire on their own.

    Called after a write that changes what an aggregate would answer - a saved scan, a
    finalized partitioned scan - so the console shows the new estate at once rather than
    at the end of a TTL.
    """
    connection = client()
    if connection is None:
        return
    try:
        connection.incr(_version_key(tenant_id))
        # The version itself is derived state; a fortnight is longer than any scan.
        connection.expire(_version_key(tenant_id), 14 * 24 * 3600)
        _note("writes")
    except Exception:
        _note("errors")


def _cache_key(tenant_id: str, name: str, params: Any) -> str:
    digest = hashlib.sha256(
        json.dumps(params, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:16]
    return f"{KEY_PREFIX}agg:{tenant_id}:{version(tenant_id)}:{name}:{digest}"


def cached_json(
    tenant_id: str,
    name: str,
    params: Any,
    builder: Callable[[], Any],
    *,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
):
    """Answer from Memurai when it can, otherwise build it and share the answer.

    `builder` is the database read. When Redis is absent, unreachable, or the value does
    not round-trip as JSON, this is exactly `builder()` - the cache can never change what
    an answer IS, only who has to compute it.
    """
    connection = client()
    if connection is None:
        return builder()
    key = _cache_key(tenant_id, name, params)
    try:
        stored = connection.get(key)
        if stored is not None:
            _note("hits")
            return json.loads(stored)
    except Exception:
        _note("errors")
        return builder()

    _note("misses")
    value = builder()
    try:
        connection.set(key, json.dumps(value, default=str, ensure_ascii=False), ex=max(1, int(ttl_seconds)))
        _note("writes")
    except Exception:
        _note("errors")
    return value


def progress_key(tenant_id: str, job_id: str) -> str:
    return f"{KEY_PREFIX}progress:{tenant_id}:{job_id}"


def publish_progress(tenant_id: str, job_id: str, payload: dict) -> None:
    """What a scan is doing, where every backend can see it.

    A queued scan runs in a worker process; the console polling a different backend has
    no other way to see its progress without asking the database on every poll. Progress
    is derived state with a short life, so it expires rather than being cleaned up.
    """
    connection = client()
    if connection is None or not job_id:
        return
    try:
        connection.set(
            progress_key(tenant_id, job_id),
            json.dumps(payload, default=str, ensure_ascii=False),
            ex=PROGRESS_TTL_SECONDS,
        )
        _note("writes")
    except Exception:
        _note("errors")


def read_progress(tenant_id: str, job_id: str) -> dict | None:
    connection = client()
    if connection is None or not job_id:
        return None
    try:
        stored = connection.get(progress_key(tenant_id, job_id))
    except Exception:
        _note("errors")
        return None
    if stored is None:
        return None
    try:
        value = json.loads(stored)
    except (TypeError, ValueError):
        return None
    _note("hits")
    return value if isinstance(value, dict) else None
