from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig


executor = ThreadPoolExecutor(max_workers=4)
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
    job = ScanJob(id=str(uuid.uuid4()), tenant_id=tenant_id)
    with _lock:
        _jobs[job.id] = job
    executor.submit(_run_job, job, config, on_complete)
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


def _run_job(job: ScanJob, config: ScanConfig, on_complete: Callable[[dict], None]) -> None:
    if job.cancel_requested:
        return
    try:
        job.status = "running"
        job.progress = 10
        job.message = "Collecting files"
        engine = DSPMDiscoveryEngine(config)
        report = engine.run()
        data = report.to_dict()
        if job.cancel_requested:
            return
        job.progress = 95
        job.message = "Saving report"
        on_complete(data)
        job.result = data
        job.status = "completed"
        job.progress = 100
        job.message = "Completed"
    except Exception as exc:
        job.status = "failed"
        job.error = str(exc)
        job.message = "Failed"
    finally:
        job.finished_at = datetime.now(timezone.utc).isoformat()
