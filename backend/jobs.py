from __future__ import annotations

import contextlib
import logging
import os
import socket
import sys
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterator

from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from backend import store


logger = logging.getLogger(__name__)

# W2.4: the process that runs this module's jobs, as their rows name it. The instance id
# tells this process from an earlier one that had the same pid.
INSTANCE_ID = uuid.uuid4().hex
HOST = socket.gethostname()
PID = os.getpid()


# Jobs whose last milestone write did not land. The heartbeat writes them again: a lost
# terminal write would otherwise leave the row "running" - and, since W2.4, its schedule
# skipping every run - until a restart (W2.4 review).
_unpersisted: set[str] = set()


def _persist(job: "ScanJob") -> None:
    """Best-effort durable-state write (ARCH-003); never breaks a running job. The row
    names this process as the job's owner, and the scan its result is once it has one."""
    try:
        result_scan_id = ""
        if isinstance(job.result, dict):
            result_scan_id = str(job.result.get("scan_id") or "")
        store.record_job({**job.to_dict(), "owner_host": HOST, "owner_pid": PID, "owner_instance": INSTANCE_ID,
                          "result_scan_id": result_scan_id})
    except Exception:
        _unpersisted.add(job.id)
    else:
        _unpersisted.discard(job.id)
    publish_progress(job, force=True)


# When each job last had its progress written, so a scan reporting every record does
# not write the database every record.
_published_at: dict[str, float] = {}
PROGRESS_PUBLISH_INTERVAL_SECONDS = 1.0


def publish_progress(job: "ScanJob", *, force: bool = False) -> None:
    """Write what this job is doing where a console on another backend can see it (B3.1).

    A queued scan runs in a worker process, and a console polling a different backend
    sees only what the database knows. The job record used to move only at milestones,
    so a scan looked frozen from anywhere but the process running it; its progress and
    message now reach the record at most once a second. `force` is the milestone write,
    which `_persist` has just made in full.
    """
    try:
        now = time.monotonic()
        if not force and now - _published_at.get(job.id, 0.0) < PROGRESS_PUBLISH_INTERVAL_SECONDS:
            return
        if len(_published_at) > 512:
            # A job that never reaches a terminal state would otherwise leave its entry
            # here forever; the oldest are the ones nothing is publishing about.
            for stale in sorted(_published_at, key=_published_at.get)[:256]:
                _published_at.pop(stale, None)
        _published_at[job.id] = now
        if job.status in _TERMINAL_STATES:
            _published_at.pop(job.id, None)
            return
        if not force:
            store.record_job_progress(job.tenant_id, job.id, job.progress, job.message)
    except Exception:
        pass


# "incomplete" is a scan that finished but could not see all of its target - a share
# whose session kept resetting, a folder it could not list, a stop before the end. It is
# over, like "completed", and never shown as one (W2.4 operator states).
_TERMINAL_STATES = frozenset({"completed", "incomplete", "failed", "cancelled"})
# Not over, and not running here: a partitioned scan that stopped making progress, or ran
# out of disk, and that the resume sweep continues under the same job (W2.4). It holds no
# slot, a cancel ends it, and it is never shown as failed.
PAUSED = "paused"
_ACTIVE_STATES = frozenset({"queued", "running"})


def _finalize(job: "ScanJob", status: str, *, message: str, error: str | None = None,
              progress: int | None = None, result: dict | None = None) -> bool:
    """Atomically move a job to a terminal state, first-writer-wins (F5).

    The heartbeat thread (deadline -> failed) and the worker thread (runner
    result -> completed/failed) race for the final state. Without this guard a
    late heartbeat could overwrite a completed job as failed, or a completing
    worker could overwrite a deadline failure as success. Under ``_lock`` we
    refuse to overwrite an already-terminal job, so exactly one outcome sticks.
    Returns True if this call is the one that finalized the job.
    """
    with _lock:
        if job.status in _TERMINAL_STATES:
            return False
        if result is not None:
            job.result = result
        if progress is not None:
            job.progress = progress
        job.status = status
        job.message = message
        job.error = error
        job.finished_at = datetime.now(timezone.utc).isoformat()
    _persist(job)
    return True


MAX_WORKERS = int(os.getenv("DSPM_JOB_WORKERS", "4"))
MAX_JOBS_TOTAL = int(os.getenv("DSPM_MAX_JOBS_TOTAL", "200"))
MAX_JOBS_PER_TENANT = int(os.getenv("DSPM_MAX_JOBS_PER_TENANT", "10"))
JOB_RETENTION_SECONDS = int(os.getenv("DSPM_JOB_RETENTION_SECONDS", "3600"))

# Collection runs as one blocking call with no per-object progress, so the
# job would otherwise sit frozen at the initial "Collecting files" value until
# the first "collected" callback lifts it. A lightweight heartbeat nudges the
# bar during collection so it never looks stuck, and a wall-clock deadline
# turns a genuine hang (unreachable target, oversized tree) into a *failed*
# job the frontend can display instead of an eternal "running/7".
COLLECT_HEARTBEAT_SECONDS = float(os.getenv("DSPM_SCAN_HEARTBEAT_SECONDS", "2"))
COLLECT_HEARTBEAT_CEILING = 14
SCAN_MAX_SECONDS = int(os.getenv("DSPM_SCAN_MAX_SECONDS", "1800"))

executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
_jobs: dict[str, "ScanJob"] = {}
_lock = threading.Lock()

# ARCH-003 note: recovery of jobs orphaned by a restart is triggered once from
# the app startup (app_lifespan), NOT at import time - importing this module for
# tooling/tests must not mutate persisted job state. The in-memory executor is
# single-process; run the server with a single worker.


@dataclass(slots=True)
class ScanJob:
    id: str
    tenant_id: str
    status: str = "queued"
    progress: int = 0
    message: str = "Queued"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str | None = None
    result: dict | None = None
    error: str | None = None
    cancel_requested: bool = False
    # Set once the scan's result is being written (see `begin_saving`).
    saving: bool = False

    # Times this job was taken up again after it paused or its process stopped (W2.4).
    resumes: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "status": self.status,
            "progress": self.progress,
            "message": self.message,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "elapsed_seconds": _elapsed_seconds(self.created_at, self.finished_at),
            "result": self.result,
            "error": self.error,
            "resumes": self.resumes,
            "cancel_requested": self.cancel_requested,
        }


def create_scan_job(tenant_id: str, config: ScanConfig, on_complete: Callable[[dict], None]) -> ScanJob:
    return create_job(tenant_id, lambda job: _run_scan_job(job, config, on_complete))


def _parse_time(value: str | None) -> float:
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return 0.0


def _elapsed_seconds(created_at: str, finished_at: str | None = None) -> float:
    start = _parse_time(created_at)
    end = _parse_time(finished_at) if finished_at else datetime.now(timezone.utc).timestamp()
    return round(max(0.0, end - start), 3)


def cleanup_jobs() -> None:
    cutoff = datetime.now(timezone.utc).timestamp() - JOB_RETENTION_SECONDS
    with _lock:
        stale = [
            job_id
            for job_id, job in _jobs.items()
            if job.status in _TERMINAL_STATES and _parse_time(job.finished_at) < cutoff
        ]
        for job_id in stale:
            _jobs.pop(job_id, None)


def active_job_count(tenant_id: str | None = None) -> int:
    cleanup_jobs()
    with _lock:
        return sum(
            1
            for job in _jobs.values()
            if job.status in {"queued", "running"} and (tenant_id is None or job.tenant_id == tenant_id)
        )


def create_job(tenant_id: str, runner: Callable[[ScanJob], dict], *, job_id: str | None = None) -> ScanJob:
    """Queue ``runner`` as a job; returns it.

    ``job_id`` reuses an id - a resumed scan continues under the job its console is
    still polling (B2.4). An id whose job is still active here is refused.
    """
    cleanup_jobs()
    with _lock:
        active_total = sum(1 for job in _jobs.values() if job.status in {"queued", "running"})
        active_tenant = sum(1 for job in _jobs.values() if job.tenant_id == tenant_id and job.status in {"queued", "running"})
        if active_total >= MAX_JOBS_TOTAL:
            raise RuntimeError("Async scan queue is full")
        if active_tenant >= MAX_JOBS_PER_TENANT:
            raise RuntimeError("Too many active scans for this tenant")
        if job_id and job_id in _jobs and _jobs[job_id].status in {"queued", "running"}:
            raise ValueError(f"job {job_id} is still active")
        previous = _jobs.get(str(job_id)) if job_id else None
        job = ScanJob(id=str(job_id or uuid.uuid4()), tenant_id=tenant_id)
        if previous is not None:
            job.resumes = previous.resumes + (1 if previous.status in {PAUSED, "failed"} else 0)
        _jobs[job.id] = job
    _persist(job)
    _ensure_heartbeat()
    executor.submit(_run_custom_job, job, runner)
    return job


def get_job(job_id: str) -> ScanJob | None:
    with _lock:
        return _jobs.get(job_id)


def cancel_job(job_id: str) -> bool:
    job = get_job(job_id)
    if not job or job.status not in {"queued", "running"}:
        return False
    with _lock:
        if job.saving:
            # The result is being written and will land: calling the job cancelled now
            # would be untrue, and would free its slot while the save still runs.
            return False
        # Signal the runner to stop at its next checkpoint, then take the terminal
        # slot atomically. If the worker/heartbeat finalized first (race), _finalize
        # no-ops and we report that we did not cancel it.
        job.cancel_requested = True
    return _finalize(job, "cancelled", message="Cancellation requested")


def request_cancel(tenant_id: str, job_id: str) -> bool:
    """Cancel a job wherever it runs (W2.4); returns whether a cancel was made or asked for.

    A job this process runs is cancelled here. A paused job has no runner, so it is
    cancelled at once - its scan with it. A job another process runs is asked to stop
    through its row, and that process carries the cancel out at its next heartbeat; if
    it is gone, recovery records the job cancelled.
    """
    job = get_job(job_id)
    if job is not None and job.tenant_id == tenant_id:
        if job.status in _ACTIVE_STATES:
            return cancel_job(job_id)
        if job.status != PAUSED:
            return False
    if store.cancel_paused_job(tenant_id, job_id):
        if job is not None:
            with _lock:
                if job.status == PAUSED:
                    job.status, job.message, job.error = "cancelled", "Cancelled", "Scan was cancelled."
                    job.finished_at = datetime.now(timezone.utc).isoformat()
        return True
    # Not paused in its row: another backend took the job up again, or it ended. This
    # process's paused copy is stale, so the cancel goes to the row - which refuses a job
    # that has ended, and which the backend now running it reads at its next heartbeat.
    return store.request_job_cancel(tenant_id, job_id)


def _pause(job: ScanJob, message: str) -> bool:
    """The job's scan stopped for now and will be resumed: paused, not failed (W2.4)."""
    with _lock:
        if job.status in _TERMINAL_STATES:
            return False
        job.status = PAUSED
        job.message = message
        job.error = None
    _persist(job)
    return True


def _is_pause(exc: BaseException) -> bool:
    from backend.partitioned_scan import ScanPaused

    return isinstance(exc, ScanPaused)


def _resume_follows(exc: BaseException) -> bool:
    """Whether anything will continue a paused scan: it can be resumed, and resuming is on.
    A job paused with nothing to continue it would stay paused for ever - and hold its
    schedule, which skips a run while the last one is going (W2.4 review)."""
    from backend import scan_resumer

    return bool(getattr(exc, "resumable", True)) and scan_resumer.resume_interval_seconds() > 0


def _stopped_for_good(exc: BaseException) -> str:
    """Why a scan that paused with nothing to continue it failed instead."""
    reason = "free disk space ran low" if "free disk" in str(exc).lower() else "it stopped making progress"
    if not getattr(exc, "resumable", True):
        return (f"Scan stopped because {reason}, and it cannot be resumed: it was started without a request "
                "to rebuild it from. Run the scan again.")
    return (f"Scan stopped because {reason}, and resuming is turned off on this backend "
            "(DSPM_SCAN_RESUME_INTERVAL_SECONDS=0), so nothing will continue it. Run the scan again.")


def active_job_ids() -> set[str]:
    """The jobs this process is running now."""
    with _lock:
        return {job.id for job in _jobs.values() if job.status in _ACTIVE_STATES}


# W2.4: while this process runs jobs it says so through their rows, and carries out the
# cancels other backends asked for.
HEARTBEAT_SECONDS = max(1.0, float(os.getenv("DSPM_JOB_HEARTBEAT_SECONDS") or "15"))
_heartbeat_thread: threading.Thread | None = None
_heartbeat_lock = threading.Lock()
_heartbeat_stop = threading.Event()


def heartbeat_once() -> int:
    """Renew this process's jobs and carry out the cancels asked for them; returns the jobs renewed.
    A milestone write that did not land is made again first."""
    for job_id in list(_unpersisted):
        job = get_job(job_id)
        if job is None:
            _unpersisted.discard(job_id)
        else:
            _persist(job)
    with _lock:
        active = [job.id for job in _jobs.values() if job.status in _ACTIVE_STATES]
    if not active:
        return 0
    renewed = store.heartbeat_jobs(INSTANCE_ID, active)
    for job_id in store.pending_job_cancellations(INSTANCE_ID):
        cancel_job(job_id)
    return renewed


def _heartbeat_loop() -> None:
    while not _heartbeat_stop.wait(HEARTBEAT_SECONDS):
        try:
            heartbeat_once()
        except Exception as exc:  # noqa: BLE001 - a heartbeat must never end the thread
            logger.warning("Job heartbeat failed: %s", type(exc).__name__)


def _ensure_heartbeat() -> None:
    global _heartbeat_thread
    with _heartbeat_lock:
        if _heartbeat_thread is not None and _heartbeat_thread.is_alive():
            return
        _heartbeat_stop.clear()
        _heartbeat_thread = threading.Thread(target=_heartbeat_loop, name="job-heartbeat", daemon=True)
        _heartbeat_thread.start()


def begin_saving(job: ScanJob) -> bool:
    """Mark that the job is writing its result; returns False if it was cancelled first.

    From here a cancel is refused: the save is one transaction that will land, so the job
    finishes as what it is, and keeps its slot until its runner returns.
    """
    with _lock:
        if job.cancel_requested:
            return False
        job.saving = True
        return True


def _shrink_result(data: dict) -> dict:
    if not isinstance(data, dict):
        return {}
    files = data.get("files")
    if isinstance(files, list) and files:
        trimmed = dict(data)
        # S-E: a completed job is a notification/metadata payload, not a second
        # report transport. The normalized inventory/detail APIs serve bounded
        # reads after persistence; retaining even a 500-file preview kept an
        # unnecessary duplicate alive in the worker and browser.
        trimmed["files"] = []
        trimmed["files_omitted"] = True
        trimmed["result_truncated"] = True
        trimmed["result_file_count"] = len(files)
        trimmed["file_count"] = len(files)
        return trimmed
    return data


def _safe_job_error(exc: Exception) -> str:
    raw = str(exc or "").lower()
    if "cancel" in raw:
        return "Scan was cancelled."
    if "invalid literal" in raw or "base 16" in raw or "valueerror" in raw:
        return "Scan failed while parsing malformed encoded data. Refresh the backend and retry; malformed evidence is skipped by the current parser."
    if "access denied" in raw or "unauthorized" in raw:
        return "Scan failed because the credential cannot read one or more selected paths."
    if "connection" in raw or "timed out" in raw or "winrm" in raw:
        return "Scan failed because the target is unreachable or timed out."
    if "database is locked" in raw or "database table is locked" in raw:
        return "Scan could not save because the local DSPM database is busy. Wait a few seconds and retry."
    if "permission denied" in raw or "winerror 5" in raw:
        return "Scan could not read or save one of the selected paths. Check filesystem permissions and retry."
    if "scan paused" in raw and "free disk" in raw:
        # Below the disk floor (backend.disk_guard): left to the resume sweep, not failed.
        return ("Scan paused: free disk space is low on a volume the scan writes to. It continues automatically "
                "once there is room; nothing already scanned is lost.")
    if "scan paused" in raw:
        # A partitioned scan that stopped making progress (W1.1): left to the resume sweep.
        return "Scan paused: no part of it finished for a long time. It continues automatically; nothing already scanned is lost."
    if "no space left" in raw or "disk full" in raw:
        return "Scan stopped because the backend storage is full. Free disk space and retry."
    if "no such file" in raw or "cannot find the path" in raw or "winerror 3" in raw:
        return "Scan path was not found. Verify the local path or file-server target and retry."
    return "Scan failed. Check backend logs for diagnostic details."


def _run_custom_job(job: ScanJob, runner: Callable[[ScanJob], dict]) -> None:
    if job.cancel_requested:
        return
    # Enter "running" only if a cancel/terminal has not already landed (a job can
    # be cancelled while still queued). Guarded so it composes with _finalize's
    # first-writer-wins rule below.
    with _lock:
        if job.status in _TERMINAL_STATES:
            return
        job.status = "running"
        job.progress = max(job.progress, 5)
        job.message = job.message if job.message != "Queued" else "Running"
    _persist(job)
    try:
        data = runner(job)
    except Exception as exc:
        if job.cancel_requested:
            return
        if _is_pause(exc):
            if _resume_follows(exc):
                # Left for the resume sweep - paused, which is not failed (W2.4).
                _pause(job, _safe_job_error(exc))
            else:
                _finalize(job, "failed", message="Failed", error=_stopped_for_good(exc))
            return
        _finalize(job, "failed", message="Failed", error=_safe_job_error(exc))
        print(f"[scan-job-error] job={job.id} error={exc}\n{traceback.format_exc()}", file=sys.stderr)
        return
    if job.cancel_requested:
        return
    # If the deadline heartbeat already failed this job, _finalize no-ops and the
    # failure stands; otherwise this completes it - or says it is incomplete.
    status, message = completion_of(data)
    _finalize(job, status, message=message, progress=100, result=_shrink_result(data))


def completion_of(data) -> tuple[str, str]:
    """("completed" | "incomplete", the message) for a scan's result. A scan that did not
    see all of its target says so, and what it missed, rather than "Completed"."""
    diagnostics = data.get("scan_diagnostics") if isinstance(data, dict) else None
    incremental = diagnostics.get("incremental") if isinstance(diagnostics, dict) else None
    if not isinstance(incremental, dict) or incremental.get("complete") is not False:
        return "completed", "Completed"
    gaps: list[str] = []
    reset = diagnostics.get("shares_connection_reset") or []
    if reset:
        gaps.append(f"{len(reset)} share(s) kept resetting the connection")
    unreadable = diagnostics.get("unreadable_dirs") or []
    if unreadable:
        gaps.append(f"{len(unreadable)} folder(s) could not be listed")
    if diagnostics.get("record_limit_reached"):
        gaps.append("the file limit was reached")
    if diagnostics.get("scan_aborted_reason"):
        gaps.append("collection stopped early")
    detail = "; ".join(gaps) or "part of the target could not be read"
    return "incomplete", f"Completed with gaps: {detail}. Nothing it missed was treated as deleted."


@contextlib.contextmanager
def collection_heartbeat(job: ScanJob | None, *, ceiling: int = COLLECT_HEARTBEAT_CEILING,
                         max_seconds: int | None = None) -> Iterator[None]:
    """Keep a long blocking collection phase honest.

    While the wrapped call runs, nudge ``job.progress`` up to ``ceiling`` (a
    bounded keepalive band, never fake completion) and enforce the wall-clock
    deadline ``SCAN_MAX_SECONDS`` so a hung remote/local collection becomes a
    *failed* job the frontend can display instead of an eternal "running".

    ``max_seconds=0`` keeps the progress and drops the deadline. A partitioned scan
    passes it (W1.1): each unit's engine carries its own budget, and this deadline -
    measured per wrapped call - failed the whole scan when one unit ran long.
    """
    if job is None:
        yield
        return
    stop_heartbeat = threading.Event()
    started = time.monotonic()
    limit = SCAN_MAX_SECONDS if max_seconds is None else int(max_seconds)

    def _heartbeat() -> None:
        while not stop_heartbeat.wait(COLLECT_HEARTBEAT_SECONDS):
            if job.cancel_requested or job.status not in {"queued", "running"}:
                return
            if limit > 0 and (time.monotonic() - started) > limit:
                job.cancel_requested = True
                _finalize(
                    job,
                    "failed",
                    message="Failed",
                    error=(
                        "Scan exceeded the maximum allowed time and was stopped. The target may be "
                        "unreachable or too large; narrow the scope and retry."
                    ),
                )
                return
            if job.progress < ceiling:
                job.progress = min(ceiling, job.progress + 1)
                publish_progress(job)

    heartbeat = threading.Thread(target=_heartbeat, name=f"scan-heartbeat-{job.id}", daemon=True)
    heartbeat.start()
    try:
        yield
    finally:
        stop_heartbeat.set()


def _run_scan_job(job: ScanJob, config: ScanConfig, on_complete: Callable[[dict], None]) -> dict:
    if job.cancel_requested:
        raise RuntimeError("Scan cancelled")
    job.progress = 7
    job.message = "Collecting files"
    config.cancel_check = lambda: job.cancel_requested
    config.progress_callback = lambda stage, completed, total: _update_scan_job_progress(job, stage, completed, total)

    with collection_heartbeat(job):
        engine = DSPMDiscoveryEngine(config)
        report = engine.run()
    data = report.to_dict()
    if not begin_saving(job):
        raise RuntimeError("Scan cancelled")
    job.progress = max(job.progress, 96)
    job.message = "Saving report"
    on_complete(data)
    return data


def _update_scan_job_progress(job: ScanJob, stage: str, completed: int, total: int) -> None:
    _advance_scan_job_progress(job, stage, completed, total)
    publish_progress(job)


def _advance_scan_job_progress(job: ScanJob, stage: str, completed: int, total: int) -> None:
    completed_raw = max(0, int(completed or 0))
    if stage == "collecting":
        # Real collection progress: completed = files discovered, total = files
        # reused from cache. Collection has no known total, so move within a
        # bounded band that advances past the old 14 ceiling as files stream in.
        discovered = completed_raw
        reused = max(0, int(total or 0))
        job.progress = max(job.progress, min(40, 8 + discovered // 5))
        message = f"Discovering files… {discovered} found"
        if reused:
            message += f", {reused} reused from cache"
        job.message = message
        return
    if stage == "pipelining":
        # Collection is still active, so the final total is not known yet.
        # Report useful overlap without allowing the bar to reach the
        # post-collection analysis band prematurely.
        submitted = max(completed_raw, int(total or 0))
        job.progress = max(job.progress, min(70, 15 + completed_raw // 5))
        job.message = f"Discovering and analyzing files… {completed_raw}/{submitted} ready"
        return
    total_n = max(int(total or 0), 1)
    completed_c = max(0, min(completed_raw, total_n))
    if stage == "collected":
        job.progress = max(job.progress, 42)
        job.message = f"Collected {completed_c} files. Analyzing"
        return
    if stage == "analyzing":
        ratio = completed_c / total_n
        job.progress = max(job.progress, min(95, 45 + int(ratio * 50)))
        job.message = f"Analyzing files {completed_c}/{total_n}"
