"""B3: the scans a backend runs unattended.

A pilot's real value is the scan nobody has to start. A schedule is a stored scan
request, how often it should run, and when it is next due; this sweep finds the ones
that are due and hands each to a callback that starts the scan exactly as the console
would - the same validation, the same vault resolution, the same job.

Two rules make it safe to leave alone for a week:

- **A due schedule is claimed, not just read.** The claim is a compare-and-set on the
  due time (:func:`backend.store.claim_due_schedules`), so several backends sharing one
  database start a schedule once between them, and the next run is counted from now -
  a backend that was off for a week owes one scan, not a week of them.
- **A run that fails is a run, not the end of the schedule.** The failure is recorded on
  the schedule, where it can be seen, and the next run is already set.
"""

from __future__ import annotations

import logging
import os
import threading
from contextlib import suppress
from datetime import datetime
from typing import Callable

from backend import schema_guard, store

logger = logging.getLogger(__name__)


def scheduler_interval_seconds() -> int:
    """How often due schedules are looked for; ``0`` turns the scheduler off."""
    try:
        return max(0, min(int(os.getenv("DSPM_SCAN_SCHEDULER_INTERVAL_SECONDS", "30")), 3600))
    except ValueError:
        return 30


def run_due_schedules(
    start: Callable[[dict], object], *, now: datetime | None = None, limit: int = 10,
) -> list[str]:
    """Start every schedule that is due; returns the ids of the ones started.

    ``start`` is given the claimed schedule and starts its scan. If it raises - a full
    job queue, a credential that is gone from the vault - the run is recorded as failed
    and the sweep moves on; the schedule keeps its place. On a database a newer release
    has upgraded nothing is claimed (C0.4): the schedules wait, due, for that release.
    """
    if schema_guard.stand_down("scan scheduler"):
        return []
    started: list[str] = []
    from backend import licensing

    allowed, why = licensing.scans_allowed()
    for schedule in store.claim_due_schedules(now=now, limit=limit):
        if not allowed:
            # D10: said on the schedule's run, where its owner looks - not a silent skip.
            with suppress(Exception):
                store.record_schedule_run(schedule["tenant_id"], schedule["schedule_id"], status="failed",
                                          error=f"not started: {why}"[:300])
            continue
        try:
            start(schedule)
        except Exception as exc:
            logger.warning(
                "Scheduled scan %s could not be started: %s", schedule["schedule_id"], type(exc).__name__,
            )
            with suppress(Exception):
                store.record_schedule_run(
                    schedule["tenant_id"], schedule["schedule_id"],
                    status="failed", error=f"could not be started ({type(exc).__name__})",
                )
            continue
        started.append(schedule["schedule_id"])
    return started


_stop = threading.Event()
_thread: threading.Thread | None = None
_thread_lock = threading.Lock()


def _loop(start: Callable[[dict], object], interval: int) -> None:
    while True:
        try:
            run_due_schedules(start)
        except Exception as exc:  # pragma: no cover - a sweep must never end the thread
            logger.warning("Looking for due scans failed: %s", type(exc).__name__)
        if _stop.wait(interval):
            return


def start_scan_scheduler(start: Callable[[dict], object]) -> bool:
    """Start the sweep; returns whether it runs (``DSPM_SCAN_SCHEDULER_INTERVAL_SECONDS=0`` turns it off)."""
    global _thread
    interval = scheduler_interval_seconds()
    if interval <= 0:
        return False
    with _thread_lock:
        if _thread is not None and _thread.is_alive():
            return True
        _stop.clear()
        _thread = threading.Thread(target=_loop, args=(start, interval), name="scan-scheduler", daemon=True)
        _thread.start()
    return True


def stop_scan_scheduler() -> None:
    global _thread
    _stop.set()
    with _thread_lock:
        thread = _thread
        _thread = None
    if thread is not None and thread.is_alive():
        thread.join(timeout=5.0)
