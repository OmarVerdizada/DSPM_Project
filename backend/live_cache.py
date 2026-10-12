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
- **every answer expires.** A TTL bounds how long an answer is current even if a write
  path were ever to miss the hook;
- **a stale answer is served as stale, and nobody waits** (W3.4, decision D1). When the
  estate has moved past an answer, the reader gets the previous answer marked STALE - with
  the exact time it was computed and whether a rebuild is running or failed - and one
  rebuild runs, for every backend and worker together (a compare-and-set on the answer's
  row), on a small pool of its own. A rebuild that outlasts the writes behind it is not
  joined by a second. The API carries the marks (``collecting()``) and the console shows
  them: a stale answer is never presented as current;
- **it never changes an answer, only who computes it.** Any failure here - a missing
  table on an unmigrated database, a lock, a value that does not round-trip as JSON -
  is exactly the database read it always was. ``DSPM_LIVE_CACHE=0`` turns it off.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import socket
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 30
# How long a reader waits for another reader of this process that is already building the
# same answer before it builds its own (W2.5).
SHARED_BUILD_WAIT_SECONDS = 120

_counters = {"hits": 0, "misses": 0, "errors": 0, "writes": 0, "coalesced": 0, "stale": 0, "rebuilds": 0,
             "rebuild_failures": 0}
# W3.4: a rebuild that has not finished in this long is taken over (its owner is gone); after
# a failed one the next waits this long.
REBUILD_STALE_SECONDS = 600
REBUILD_RETRY_SECONDS = 30
_rebuild_pool: ThreadPoolExecutor | None = None
_rebuild_pool_lock = threading.Lock()
_rebuilding: set = set()
_rebuilding_lock = threading.Lock()
_rebuilds_idle = threading.Condition(_rebuilding_lock)
_freshness: ContextVar[list | None] = ContextVar("dspm_live_cache_freshness", default=None)
_counter_lock = threading.Lock()


class _Build:
    """One answer being built in this process, for the readers that asked for it meanwhile."""

    def __init__(self) -> None:
        self.done = threading.Event()
        self.encoded: str | None = None
        self.computed_at = ""


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


class _Collected:
    """The freshness of every cached answer one request served (W3.4)."""

    def __init__(self) -> None:
        self.parts: list[dict] = []

    def summary(self) -> dict:
        """``stale`` if any answer was; ``computed_at`` - the time of the oldest figure shown;
        ``rebuild`` - ``rebuilding``, ``rebuild failed`` or empty."""
        stale = [part for part in self.parts if part["stale"]]
        times = [part["computed_at"] for part in (stale or self.parts) if part.get("computed_at")]
        statuses = {part.get("rebuild") or "" for part in stale}
        rebuild = "rebuild failed" if "rebuild failed" in statuses else "rebuilding" if "rebuilding" in statuses else ""
        return {"stale": bool(stale), "computed_at": min(times) if times else "", "rebuild": rebuild}


@contextlib.contextmanager
def collecting():
    """For an endpoint: gather the freshness of the cached answers it serves."""
    collected = _Collected()
    token = _freshness.set(collected.parts)
    try:
        yield collected
    finally:
        _freshness.reset(token)


def _report(name: str, *, stale: bool, computed_at: str, rebuild: str = "") -> None:
    parts = _freshness.get()
    if parts is not None:
        parts.append({"name": name, "stale": bool(stale), "computed_at": str(computed_at or ""),
                      "rebuild": rebuild})


def _pool() -> ThreadPoolExecutor:
    global _rebuild_pool
    with _rebuild_pool_lock:
        if _rebuild_pool is None:
            _rebuild_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="derived-rebuild")
        return _rebuild_pool


def wait_for_rebuilds(timeout: float = 30.0) -> bool:
    """Until no rebuild of this process runs; for tests and an orderly shutdown."""
    with _rebuilds_idle:
        return _rebuilds_idle.wait_for(lambda: not _rebuilding, timeout)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build(builder: Callable[[], Any]):
    """An aggregate is a heavy read: its own pool and bounds, not the request's (W3.4)."""
    from backend import db

    with db.workload("heavy"):
        return builder()


def _start_rebuild(tenant_id: str, key: str, builder: Callable[[], Any], ttl: int) -> bool:
    """Claim the answer's one rebuild and run it on the rebuild pool; True if this did."""
    from backend import store

    owner = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
    try:
        if not store.derived_claim_rebuild(tenant_id, key, owner, stale_after_seconds=REBUILD_STALE_SECONDS,
                                           retry_after_seconds=REBUILD_RETRY_SECONDS):
            return False
    except Exception:
        _note("errors")
        return False
    flight = (str(tenant_id), key)
    with _rebuilding_lock:
        _rebuilding.add(flight)

    def rebuild() -> None:
        try:
            # The generation is read before the reads, so a write that lands meanwhile
            # leaves this answer stale, as it is.
            generation = int(store.derived_read(tenant_id, key).get("generation", -1))
            started = _now()
            value = _build(builder)
            encoded = json.dumps(value, default=str, ensure_ascii=False, separators=(",", ":"))
            store.derived_store(tenant_id, key, generation, encoded, ttl, computed_at=started, owner=owner)
            _note("rebuilds")
        except Exception as exc:  # noqa: BLE001 - the previous answer stands, marked as such
            _note("rebuild_failures")
            logger.warning("Rebuilding a cached answer failed: %s", type(exc).__name__)
            with contextlib.suppress(Exception):
                store.derived_rebuild_failed(tenant_id, key, owner)
        finally:
            with _rebuilds_idle:
                _rebuilding.discard(flight)
                _rebuilds_idle.notify_all()

    try:
        _pool().submit(rebuild)
    except RuntimeError:  # the pool is shut down: the process is ending
        with _rebuilds_idle:
            _rebuilding.discard(flight)
            _rebuilds_idle.notify_all()
        with contextlib.suppress(Exception):
            store.derived_rebuild_failed(tenant_id, key, owner)
        return False
    return True


def cached_json(
    tenant_id: str,
    name: str,
    params: Any,
    builder: Callable[[], Any],
    *,
    ttl_seconds: int | None = None,
):
    """Answer from ``derived_cache``: the current answer, or else the previous one marked
    stale while one rebuild runs (W3.4); with no answer at all, build it.

    `builder` is the database read. The generation is read BEFORE the builder runs, and
    the answer is stored under it: a write that lands while the builder is reading moves
    the generation past it, so that answer is kept, and served only marked stale.
    """
    if not enabled():
        return builder()
    from backend import store

    key = cache_key(name, params)
    ttl = ttl_seconds if ttl_seconds is not None else answer_ttl_seconds()
    try:
        state = store.derived_read(tenant_id, key)
    except Exception:
        _note("errors")
        return builder()
    stored = state.get("value_json")
    if stored is not None:
        try:
            value = json.loads(stored)
        except (TypeError, ValueError):
            _note("errors")
        else:
            if state.get("current"):
                _note("hits")
                _report(name, stale=False, computed_at=state.get("computed_at") or "")
                return value
            # D1: the estate moved past this answer. It is served as what it is - stale, with
            # when it was computed - while one rebuild runs, here or in another process.
            rebuild = state.get("rebuild_status") or ""
            if _start_rebuild(tenant_id, key, builder, ttl):
                rebuild = "rebuilding"
            _note("stale")
            _report(name, stale=True, computed_at=state.get("computed_at") or "",
                    rebuild="rebuild failed" if rebuild == "failed" else rebuild)
            return value
    generation = int(state.get("generation", -1))

    _note("misses")
    # No answer at all: this reader builds it. W2.5: one reader of this process builds an
    # answer; the ones that ask for the same answer at the same generation meanwhile wait
    # for it instead of each running the same O(estate) aggregate.
    flight = (str(tenant_id), key, generation)
    with _building_lock:
        build = _building.get(flight)
        leader = build is None
        if leader:
            build = _building[flight] = _Build()
    if not leader:
        if build.done.wait(SHARED_BUILD_WAIT_SECONDS) and build.encoded is not None:
            _note("coalesced")
            _report(name, stale=False, computed_at=build.computed_at)
            return json.loads(build.encoded)
        return _build(builder)
    try:
        started = _now()
        value = _build(builder)
        try:
            encoded = json.dumps(value, default=str, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError):
            _note("errors")
            return value
        build.encoded = encoded
        build.computed_at = started
        try:
            store.derived_store(tenant_id, key, generation, encoded, ttl, computed_at=started)
            _note("writes")
        except Exception:
            _note("errors")
        _report(name, stale=False, computed_at=started)
        # The reader that computed the answer gets it in the shape every later reader will:
        # a tuple or a date that JSON turns into a list or a string must not differ between
        # the first refresh and the second.
        return json.loads(encoded)
    finally:
        build.done.set()
        with _building_lock:
            _building.pop(flight, None)
