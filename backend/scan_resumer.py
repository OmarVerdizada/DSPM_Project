"""B2.4: a partitioned scan a stopped process left unfinished is continued, not lost.

A partitioned scan writes each partition as it finishes, so a process that dies part
way through leaves finished partitions in the estate and no report. Everything needed
to continue it is recorded before its first partition runs - the plan, the request
without secrets, and the header - so a periodic sweep here finds such scans and hands
each one to a resume callback, which rebuilds its engine and continues it under the job
id it had.

A scan is taken over only once nothing has touched it for a partition lease, and the
take-over is a compare-and-set: a live runner - in this process or another - keeps its
scan, and two sweeps never both continue one. A scan whose only credential was a typed
password cannot be continued, because that password was never stored; it is marked
failed, and says why.
"""

from __future__ import annotations

import logging
import os
import threading
import uuid
from typing import Callable

from backend import partitioned_scan, schema_guard, store

logger = logging.getLogger(__name__)

TYPED_PASSWORD_ERROR = (
    "Scan was interrupted and cannot continue: its credential was a typed password, which is "
    "never stored. Run the scan again, or save the credential to the vault first."
)
NO_REQUEST_ERROR = (
    "Scan was interrupted and cannot continue: it was started without a request that could be "
    "stored to rebuild it from. Run the scan again."
)


class ResumeLater(RuntimeError):
    """A scan cannot be continued right now - the job queue is full - but can be by a later sweep."""


def resume_interval_seconds() -> int:
    """How often unfinished partitioned scans are looked for; ``0`` turns resuming off."""
    try:
        return max(0, min(int(os.getenv("DSPM_SCAN_RESUME_INTERVAL_SECONDS", "60")), 86_400))
    except ValueError:
        return 60


def resume_stale_scans(resume: Callable[[dict], object], *, stale_after_seconds: int | None = None) -> list[str]:
    """Take over every unfinished partitioned scan nobody has touched for a lease; returns their ids.

    ``resume`` receives the scan's record with the job id it continues under - its old
    one, so a console still polling that job sees it running again. It raises
    :class:`ResumeLater` to leave the scan to a later sweep; any other error marks the
    scan failed, since it would fail the same way next time. On a database a newer release
    has upgraded nothing is taken over (C0.4): the scans wait for that release.
    """
    if schema_guard.stand_down("scan resumer"):
        return []
    stale =partitioned_scan.partition_lease_seconds() if stale_after_seconds is None else max(0, int(stale_after_seconds))
    # A finalize cannot show it is alive while its write runs, so it is given far longer.
    finalizing = partitioned_scan.finalize_stale_seconds() if stale_after_seconds is None else stale
    taken: list[str] = []
    for record in store.list_unfinished_partitioned_scans():
        tenant_id, scan_id = record["tenant_id"], record["scan_id"]
        if partitioned_scan.is_running_here(tenant_id, scan_id):
            continue
        if record["resumable"] and not partitioned_scan.runs_here(record):
            # A local scan names folders on the host that planned it. Resumed here, it
            # would walk this host's disk into that host's estate - and finalize would
            # prune the rest - or fail for good on a root it cannot reach. That host's
            # own sweep continues it. (One that cannot be resumed is only marked failed,
            # which any host may do.)
            continue
        job_id = record["job_id"] or str(uuid.uuid4())
        if not store.claim_partitioned_scan_resume(
            tenant_id, scan_id, job_id=job_id, stale_after_seconds=stale, finalizing_stale_after_seconds=finalizing,
        ):
            continue
        taken.append(scan_id)
        if not record["resumable"]:
            # The stored request has been through the secret filter: what is left of a
            # typed-password request is its other settings, and a scan started without a
            # request has none.
            error = TYPED_PASSWORD_ERROR if record["request"] else NO_REQUEST_ERROR
            store.mark_partitioned_scan(tenant_id, scan_id, "failed", error=error)
            continue
        try:
            resume({**record, "job_id": job_id, "status": "running"})
        except ResumeLater as exc:
            logger.info("Partitioned scan %s will be resumed by a later sweep: %s", scan_id, exc)
        except Exception as exc:
            logger.warning("Partitioned scan %s could not be resumed: %s", scan_id, type(exc).__name__)
            store.mark_partitioned_scan(
                tenant_id, scan_id, "failed",
                error=f"Scan was interrupted and could not be resumed ({type(exc).__name__}). Run the scan again.",
            )
    return taken


_stop = threading.Event()
_thread: threading.Thread | None = None
_thread_lock = threading.Lock()


def _loop(resume: Callable[[dict], object], interval: int) -> None:
    while True:
        try:
            resume_stale_scans(resume)
        except Exception as exc:  # pragma: no cover - a sweep must never end the thread
            logger.warning("Resuming interrupted partitioned scans failed: %s", type(exc).__name__)
        if _stop.wait(interval):
            return


def start_scan_resumer(resume: Callable[[dict], object]) -> bool:
    """Start the periodic sweep; returns whether it runs (``DSPM_SCAN_RESUME_INTERVAL_SECONDS=0`` turns it off)."""
    global _thread
    interval = resume_interval_seconds()
    if interval <= 0:
        return False
    with _thread_lock:
        if _thread is not None and _thread.is_alive():
            return True
        _stop.clear()
        _thread = threading.Thread(target=_loop, args=(resume, interval), name="scan-resumer", daemon=True)
        _thread.start()
    return True


def stop_scan_resumer() -> None:
    global _thread
    _stop.set()
    with _thread_lock:
        thread = _thread
        _thread = None
    if thread is not None and thread.is_alive():
        thread.join(timeout=5.0)
