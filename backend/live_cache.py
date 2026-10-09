"""B3.1: the derived state several backends share, kept in the database the product already owns.

The problem this solves was measured before any of it was written: one dashboard refresh
is four O(estate) aggregates - 7.31 ms against 1,369 assets on this host's PostgreSQL,
5.34 s per refresh extrapolated to a million - so a 3.9-hour scan spends about 6.95 hours
of database time answering the console (§2 of the plan). A per-process, thirty-second
cache does not help: every backend and every worker keeps its own copy, and each one
pays the aggregate again.

This cache first lived in Memurai. The product owner removed Memurai on 2026-09-18, and
what it was doing here needs no second server: the answers live in ``derived_cache``
(revision 0017), keyed per tenant and stamped with the estate generation they describe.

- **only derived state.** Counts, facets, posture inputs. Never file content, previews,
  credentials or PAN/PII samples - Phase A spent its effort removing plaintext at rest,
  and a cache is a new place for it to accumulate. Every row is rebuilt from the tables
  it summarises, so deleting the whole table loses nothing;
- **a write makes the old answers unservable at once.** ``tenants.estate_generation``
  moves on every authoritative estate write (``store._invalidate_inventory_query_cache``
  is the single hook), and an answer is served only for the generation it was computed
  at. Nothing is ever scanned for or deleted to invalidate;
- **every answer expires.** A TTL bounds how long an answer can be served even if a
  write path were ever to miss the hook;
- **it never changes an answer, only who computes it.** Any failure here - a missing
  table on an unmigrated database, a lock, a value that does not round-trip as JSON -
  is exactly the database read it always was. ``DSPM_LIVE_CACHE=0`` turns it off.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from typing import Any, Callable

DEFAULT_TTL_SECONDS = 30
# How long a reader waits for another reader of this process that is already building the
# same answer before it builds its own (W2.5).
SHARED_BUILD_WAIT_SECONDS = 120

_counters = {"hits": 0, "misses": 0, "errors": 0, "writes": 0, "coalesced": 0}
_counter_lock = threading.Lock()


class _Build:
    """One answer being built in this process, for the readers that asked for it meanwhile."""

    def __init__(self) -> None:
        self.done = threading.Event()
        self.encoded: str | None = None


_building: dict[tuple, _Build] = {}
_building_lock = threading.Lock()


def enabled() -> bool:
    return os.getenv("DSPM_LIVE_CACHE", "1").strip() != "0"


def answer_ttl_seconds() -> int:
    """How long an answer may be served; a write ends it sooner."""
    try:
        return max(1, min(3600, int(os.getenv("DSPM_LIVE_CACHE_SECONDS", str(DEFAULT_TTL_SECONDS)))))
    except ValueError:
        return DEFAULT_TTL_SECONDS


def _note(name: str) -> None:
    with _counter_lock:
        _counters[name] = _counters.get(name, 0) + 1


def diagnostics() -> dict:
    """What the cache did, for the scan diagnostics and the health endpoint."""
    with _counter_lock:
        counts = dict(_counters)
    return {"enabled": enabled(), "backend": "database", "ttl_seconds": answer_ttl_seconds(), **counts}


def reset_for_tests() -> None:
    with _counter_lock:
        for key in _counters:
            _counters[key] = 0


def bump(tenant_id: str | None) -> None:
    """The estate changed: nothing cached about it is served again.

    ``store`` does this itself after every authoritative write; this is for a caller
    that changes what an aggregate would answer by some other route.
    """
    from backend import store

    try:
        store.bump_estate_generation(tenant_id)
        _note("writes")
    except Exception:
        _note("errors")


def cache_key(name: str, params: Any) -> str:
    digest = hashlib.sha256(
        json.dumps(params, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:16]
    return f"{name}:{digest}"


def cached_json(
    tenant_id: str,
    name: str,
    params: Any,
    builder: Callable[[], Any],
    *,
    ttl_seconds: int | None = None,
):
    """Answer from ``derived_cache`` when a current answer is there, otherwise build and share it.

    `builder` is the database read. The generation is read BEFORE the builder runs, and
    the answer is stored under it: a write that lands while the builder is reading moves
    the generation past it, so that answer is kept but never served.
    """
    if not enabled():
        return builder()
    from backend import store

    key = cache_key(name, params)
    try:
        stored, generation = store.derived_lookup(tenant_id, key)
    except Exception:
        _note("errors")
        return builder()
    if stored is not None:
        try:
            value = json.loads(stored)
        except (TypeError, ValueError):
            _note("errors")
        else:
            _note("hits")
            return value

    _note("misses")
    # W2.5: one reader of this process builds an answer; the ones that ask for the same
    # answer at the same generation meanwhile wait for it instead of each running the same
    # O(estate) aggregate. Across backends the shared row does the same job a moment later.
    flight = (str(tenant_id), key, generation)
    with _building_lock:
        build = _building.get(flight)
        leader = build is None
        if leader:
            build = _building[flight] = _Build()
    if not leader:
        if build.done.wait(SHARED_BUILD_WAIT_SECONDS) and build.encoded is not None:
            _note("coalesced")
            return json.loads(build.encoded)
        return builder()
    try:
        value = builder()
        try:
            encoded = json.dumps(value, default=str, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError):
            _note("errors")
            return value
        build.encoded = encoded
        try:
            store.derived_store(
                tenant_id, key, generation, encoded,
                ttl_seconds if ttl_seconds is not None else answer_ttl_seconds(),
            )
            _note("writes")
        except Exception:
            _note("errors")
        # The reader that computed the answer gets it in the shape every later reader will:
        # a tuple or a date that JSON turns into a list or a string must not differ between
        # the first refresh and the second.
        return json.loads(encoded)
    finally:
        build.done.set()
        with _building_lock:
            _building.pop(flight, None)
