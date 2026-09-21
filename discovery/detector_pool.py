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


def build_pool(*, compliance_enabled: bool) -> DetectorPool:
    """A pool sized for this host, or a disabled one when it cannot pay."""
    workers = _configured_workers() if compliance_enabled else 0
    return DetectorPool(workers)
