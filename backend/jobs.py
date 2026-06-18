from __future__ import annotations

import os
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig


MAX_WORKERS = int(os.getenv("DSPM_JOB_WORKERS", "4"))
MAX_JOBS_TOTAL = int(os.getenv("DSPM_MAX_JOBS_TOTAL", "200"))
MAX_JOBS_PER_TENANT = int(os.getenv("DSPM_MAX_JOBS_PER_TENANT", "10"))
MAX_RESULT_FILES_IN_MEMORY = int(os.getenv("DSPM_MAX_JOB_RESULT_FILES", "500"))
JOB_RETENTION_SECONDS = int(os.getenv("DSPM_JOB_RETENTION_SECONDS", "3600"))

executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
_jobs: dict[str, "ScanJob"] = {}
_lock = threading.Lock()


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

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "status": self.status,
            "progress": self.progress,
            "message": self.message,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "result": self.result,
            "error": self.error,
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


def cleanup_jobs() -> None:
    cutoff = datetime.now(timezone.utc).timestamp() - JOB_RETENTION_SECONDS
    with _lock:
        stale = [
            job_id
            for job_id, job in _jobs.items()
            if job.status in {"completed", "failed", "cancelled"} and _parse_time(job.finished_at) < cutoff
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


def create_job(tenant_id: str, runner: Callable[[ScanJob], dict]) -> ScanJob:
    cleanup_jobs()
    with _lock:
        active_total = sum(1 for job in _jobs.values() if job.status in {"queued", "running"})
        active_tenant = sum(1 for job in _jobs.values() if job.tenant_id == tenant_id and job.status in {"queued", "running"})
        if active_total >= MAX_JOBS_TOTAL:
            raise RuntimeError("Async scan queue is full")
        if active_tenant >= MAX_JOBS_PER_TENANT:
            raise RuntimeError("Too many active scans for this tenant")
        job = ScanJob(id=str(uuid.uuid4()), tenant_id=tenant_id)
        _jobs[job.id] = job
    executor.submit(_run_custom_job, job, runner)
    return job


def get_job(job_id: str) -> ScanJob | None:
    with _lock:
        return _jobs.get(job_id)


def cancel_job(job_id: str) -> bool:
    job = get_job(job_id)
    if not job or job.status not in {"queued", "running"}:
        return False
    job.cancel_requested = True
    job.status = "cancelled"
    job.message = "Cancellation requested"
    job.finished_at = datetime.now(timezone.utc).isoformat()
    return True


def _shrink_result(data: dict) -> dict:
    if not isinstance(data, dict):
        return {}
    files = data.get("files")
    if isinstance(files, list) and len(files) > MAX_RESULT_FILES_IN_MEMORY:
        trimmed = dict(data)
        trimmed["files"] = files[:MAX_RESULT_FILES_IN_MEMORY]
        trimmed["result_truncated"] = True
        trimmed["result_file_count"] = len(files)
        return trimmed
    return data


def _safe_job_error(exc: Exception) -> str:
    return "Scan failed or was cancelled" if not str(exc) else str(exc).splitlines()[0][:180]


def _run_custom_job(job: ScanJob, runner: Callable[[ScanJob], dict]) -> None:
    if job.cancel_requested:
        return
    try:
        job.status = "running"
        job.progress = max(job.progress, 5)
        job.message = job.message if job.message != "Queued" else "Running"
        data = runner(job)
        if job.cancel_requested:
            return
        job.result = _shrink_result(data)
        job.status = "completed"
        job.progress = 100
        job.message = "Completed"
    except Exception as exc:
        if job.cancel_requested:
            return
        job.status = "failed"
        job.error = _safe_job_error(exc)
        job.message = "Failed"
    finally:
        job.finished_at = datetime.now(timezone.utc).isoformat()


def _run_scan_job(job: ScanJob, config: ScanConfig, on_complete: Callable[[dict], None]) -> dict:
    if job.cancel_requested:
        raise RuntimeError("Scan cancelled")
    job.progress = 10
    job.message = "Collecting files"
    engine = DSPMDiscoveryEngine(config)
    report = engine.run()
    data = report.to_dict()
    if job.cancel_requested:
        raise RuntimeError("Scan cancelled")
    job.progress = 95
    job.message = "Saving report"
    on_complete(data)
    return data
