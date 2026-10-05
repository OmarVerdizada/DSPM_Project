"""A process pool for the detector stage, and the rules it obeys.

Classification is pure-Python CPU work, so on a GIL build the engine's six
analysis threads run one detector at a time between them. Processes are the
only way to use the other five cores.

Three rules, because a scan must never be worse off for having tried:

1. **Never block on it.** The pool warms in the background while the collector
   is still walking the tree. Until every worker is warm, the caller runs the
   stage in-process. A cold pool costs a scan nothing.
2. **Never fail because of it.** A worker that dies, a payload that will not
   pickle, a platform that refuses to spawn - every one of those falls back to
   running in-process, and the pool is disabled for the rest of the scan.
3. **Never start it when it cannot pay.** One core, or compliance disabled
   (the generic detector alone is 8ms a file), and there is nothing to win
   against ~2.5 seconds of per-worker warm-up.
"""

from __future__ import annotations

import logging
import os
import threading
from concurrent.futures import ProcessPoolExecutor

from discovery.detector_stage import run_detector_stage, warm_up

logger = logging.getLogger(__name__)

# A worker that has not answered in this long is assumed lost; the caller runs
# the stage itself rather than waiting on it.
_RESULT_TIMEOUT_SECONDS = 120.0
_MAX_WORKERS = 8
# Warming five workers costs about 12 seconds of CPU - 2.5 each - and it is
# taken from the same cores the scan is using. A 44-file scan measured 75%
# SLOWER for having started a pool it barely used, so the pool is not started
# until a scan has proved it is big enough to repay that. Files seen, not files
# routed: the count has to grow whether or not the pool exists yet.
_START_AFTER_FILES = int(os.getenv("DSPM_DETECTOR_POOL_START_AFTER", "96") or 96)


def _configured_workers() -> int:
    """0 disables. Unset leaves one core for the parent, which is still doing
    collection, extraction and the write path while the workers classify."""
    raw = os.getenv("DSPM_DETECTOR_PROCESSES", "").strip()
    if raw:
        try:
            return max(0, min(_MAX_WORKERS, int(raw)))
        except ValueError:
            logger.warning("DSPM_DETECTOR_PROCESSES is not a number; using the default")
    cpu_count = int(os.cpu_count() or 1)
    if cpu_count < 3:
        return 0
    return min(_MAX_WORKERS, cpu_count - 1)


class DetectorPool:
    """One pool per scan. Start it early, use it when it is warm, close it."""

    def __init__(self, workers: int) -> None:
        self._workers = workers
        self._lock = threading.Lock()
        self._executor: ProcessPoolExecutor | None = None
        self._warm = 0
        self._disabled = False
        self._reason = ""
        self._ran_in_workers = 0
        self._ran_in_process = 0
        self._seen = 0

    @property
    def enabled(self) -> bool:
        return bool(self._workers) and not self._disabled

    @property
    def ready(self) -> bool:
        """Every worker has built its catalogs, so no real file waits for one."""
        return self.enabled and self._executor is not None and self._warm >= self._workers

    def consider_start(self, files_found: int) -> None:
        """Start warming once the collector has found enough files to repay it.

        Called with the COLLECTOR's count rather than the analyzer's, because
        warming has to overlap collection. Started later - once analysis is
        already running - the five warm-ups compete with the scan for the same
        cores and a 360-file scan measured *slower* than no pool at all.
        """
        if not self.enabled or self._executor is not None:
            return
        if files_found >= _START_AFTER_FILES:
            self.start()

    def start(self) -> None:
        """Spawn the workers and warm them. Returns immediately."""
        if not self.enabled or self._executor is not None:
            return
        try:
            executor = ProcessPoolExecutor(max_workers=self._workers)
            for _ in range(self._workers):
                future = executor.submit(warm_up)
                future.add_done_callback(self._warmed)
        except Exception as exc:  # pragma: no cover - platform/permission failure
            self._disable(f"pool did not start: {type(exc).__name__}")
            return
        self._executor = executor

    def _warmed(self, future) -> None:
        try:
            future.result()
        except Exception as exc:
            # This runs on the executor's OWN manager thread when the pool breaks:
            # CPython fails every pending future from inside `terminate_broken`, which
            # holds the executor's `_shutdown_lock` while it calls these callbacks. Asking
            # the executor to shut down from here takes that same non-reentrant lock on the
            # thread already holding it, and the process can then never exit - a service
            # that finishes its work and hangs on stop. So record the failure and nothing
            # else; the scan's `finally` closes the pool, and `run` closes it sooner.
            self._record_failure(f"worker failed to warm: {type(exc).__name__}")
            return
        with self._lock:
            self._warm += 1

    def _record_failure(self, reason: str) -> bool:
        """Mark the pool unusable. True when this call is the one that disabled it.

        Safe from any thread, including the executor's: it touches nothing but this
        object's own state.
        """
        with self._lock:
            if self._disabled:
                return False
            self._disabled = True
            self._reason = reason
        logger.warning("Detector process pool disabled (%s); classifying in-process", reason)
        return True

    def _disable(self, reason: str) -> None:
        """Record the failure and close the pool. Only from a thread that owns neither
        the executor's manager loop nor its lock - `start` and `run`, never a callback."""
        if self._record_failure(reason):
            self.shutdown()

    def run(self, payload: dict) -> dict | None:
        """The stage's result from a worker, or None to run it in-process."""
        with self._lock:
            self._seen += 1
        if not self.ready:
            with self._lock:
                self._ran_in_process += 1
            return None
        executor = self._executor
        if executor is None:
            return None
        try:
            result = executor.submit(run_detector_stage, payload).result(timeout=_RESULT_TIMEOUT_SECONDS)
        except Exception as exc:
            # A broken pool stays broken, so this is decided once, not per file.
            self._disable(f"{type(exc).__name__}: {exc}"[:160])
            return None
        with self._lock:
            self._ran_in_workers += 1
        return result

    def shutdown(self) -> None:
        with self._lock:
            executor, self._executor = self._executor, None
        if executor is not None:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except Exception:  # pragma: no cover - shutdown races on interpreter exit
                pass

    def diagnostics(self) -> dict:
        """Read after the scan, so it reports what happened rather than what is
        still true - the pool is closed by then, which is not a failure."""
        return {
            "workers": self._workers,
            "enabled": bool(self._workers) and not self._disabled,
            "warm_workers": self._warm,
            "start_after_files": _START_AFTER_FILES,
            "files_seen": self._seen,
            "files_in_workers": self._ran_in_workers,
            "files_in_process": self._ran_in_process,
            "disabled_reason": self._reason,
        }


# W2 parallelism: a partitioned scan builds an engine - and so a pool - per partition. Each
# pool spawned its workers, warmed them (about 2.5 s of CPU each) and was shut down when its
# partition ended, so every partition paid the warm-up again and classified its first files
# in-process while it ran. Engines now lease one pool the process keeps: it is warmed once,
# and shut down once nothing has leased it for DSPM_DETECTOR_POOL_IDLE_SECONDS (60).
# DSPM_DETECTOR_POOL_SHARED=0 gives every engine its own pool again.
_DEFAULT_IDLE_SECONDS = 60.0
_shared_lock = threading.Lock()
_shared_pool: DetectorPool | None = None
# Leases on _shared_pool - that pool's alone. A lease still held on a pool that was
# replaced or closed is not one of them, and giving it back does not count against the
# pool that is there now: it used to, and a lease left over from a closed pool kept the
# next one from ever being reaped.
_shared_leases = 0
_shared_reaper: threading.Timer | None = None


def _sharing_enabled() -> bool:
    return os.getenv("DSPM_DETECTOR_POOL_SHARED", "1").strip().lower() not in {"0", "false", "no", "off"}


def _idle_seconds() -> float:
    try:
        return max(0.0, float(os.getenv("DSPM_DETECTOR_POOL_IDLE_SECONDS") or _DEFAULT_IDLE_SECONDS))
    except ValueError:
        return _DEFAULT_IDLE_SECONDS


def _lease_shared(workers: int) -> DetectorPool:
    """The process's pool, leased; a broken or retired one is replaced."""
    global _shared_pool, _shared_leases, _shared_reaper
    stale = None
    with _shared_lock:
        if _shared_reaper is not None:
            _shared_reaper.cancel()
            _shared_reaper = None
        if _shared_pool is None or not _shared_pool.enabled:
            stale, _shared_pool = _shared_pool, DetectorPool(workers)
            _shared_leases = 0
        _shared_leases += 1
        pool = _shared_pool
    if stale is not None:
        stale.shutdown()
    return pool


def _release_shared(pool: DetectorPool) -> None:
    global _shared_leases, _shared_reaper
    with _shared_lock:
        if pool is not _shared_pool:
            return
        _shared_leases = max(0, _shared_leases - 1)
        if _shared_leases:
            return
        reaper = threading.Timer(_idle_seconds(), _reap_shared, args=(pool,))
        reaper.daemon = True
        _shared_reaper = reaper
    reaper.start()


def _reap_shared(pool: DetectorPool) -> None:
    """Nothing has leased the pool for the idle time: its workers go."""
    global _shared_pool
    with _shared_lock:
        if _shared_leases or pool is not _shared_pool:
            return
        _shared_pool = None
    pool.shutdown()


def shutdown_shared_pool() -> None:
    """Close the process's pool now (tests, and a process on its way out)."""
    global _shared_pool, _shared_leases, _shared_reaper
    with _shared_lock:
        pool, _shared_pool = _shared_pool, None
        _shared_leases = 0
        if _shared_reaper is not None:
            _shared_reaper.cancel()
            _shared_reaper = None
    if pool is not None:
        pool.shutdown()


class PoolLease:
    """One engine's use of the process's pool: the pool's workers, this engine's counts.
    ``shutdown`` gives the lease back; the pool stays warm for the next engine."""

    def __init__(self, pool: DetectorPool) -> None:
        self._pool = pool
        self._lock = threading.Lock()
        self._released = False
        self._seen = 0
        self._in_workers = 0
        self._in_process = 0

    @property
    def enabled(self) -> bool:
        return self._pool.enabled

    @property
    def ready(self) -> bool:
        return self._pool.ready

    def consider_start(self, files_found: int) -> None:
        self._pool.consider_start(files_found)

    def start(self) -> None:
        self._pool.start()

    def run(self, payload: dict) -> dict | None:
        result = self._pool.run(payload)
        with self._lock:
            self._seen += 1
            if result is None:
                self._in_process += 1
            else:
                self._in_workers += 1
        return result

    def shutdown(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
        _release_shared(self._pool)

    def diagnostics(self) -> dict:
        with self._lock:
            mine = {"files_seen": self._seen, "files_in_workers": self._in_workers,
                    "files_in_process": self._in_process}
        return {**self._pool.diagnostics(), **mine, "shared": True}


def build_pool(*, compliance_enabled: bool) -> DetectorPool | PoolLease:
    """A pool sized for this host, or a disabled one when it cannot pay - a lease on the
    process's shared pool unless DSPM_DETECTOR_POOL_SHARED=0."""
    workers = _configured_workers() if compliance_enabled else 0
    if not workers or not _sharing_enabled():
        return DetectorPool(workers)
    return PoolLease(_lease_shared(workers))
