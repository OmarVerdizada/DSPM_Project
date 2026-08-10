"""Bounded, workload-aware concurrency policy for discovery scans.

Track P-B deliberately keeps policy separate from the collectors and detector
implementation.  A value of zero means "auto"; explicit positive values remain
available for constrained installations and deterministic tests.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
import threading
import time


MAX_ANALYSIS_WORKERS = 32
MAX_IO_WORKERS = 64
MAX_PIPELINE_BUFFER = 1024
# Hard ceiling on the process-wide collector-I/O admission budget (P-B.2). This
# caps concurrent connection-holding collector workers across ALL scan jobs, so
# N concurrent DSPM_JOB_WORKERS scans each using io_workers threads cannot open
# N x io_workers connections and oversubscribe one target host.
MAX_HOST_IO_BUDGET = 128


def _env_int(name: str, default: int = 0) -> int:
    try:
        return int(os.getenv(name, str(default)).strip() or default)
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _bounded(value: int, default: int, maximum: int) -> int:
    selected = value if value > 0 else default
    return max(1, min(int(selected), maximum))


@dataclass(frozen=True, slots=True)
class ParallelismPlan:
    cpu_count: int
    analysis_workers: int
    io_workers: int
    ocr_workers: int
    pipeline_buffer: int
    pipeline_enabled: bool
    analysis_source: str
    io_source: str

    def to_dict(self) -> dict:
        return {
            "cpu_count": self.cpu_count,
            "analysis_workers": self.analysis_workers,
            "io_workers": self.io_workers,
            "ocr_workers": self.ocr_workers,
            "pipeline_buffer": self.pipeline_buffer,
            "pipeline_enabled": self.pipeline_enabled,
            "analysis_source": self.analysis_source,
            "io_source": self.io_source,
        }


def resolve_parallelism(
    *,
    analysis_workers: int = 0,
    io_workers: int = 0,
    pipeline_buffer: int = 0,
    pipeline_enabled: bool = True,
) -> ParallelismPlan:
    """Resolve explicit/configured values into a bounded per-scan plan.

    Analysis defaults to one worker per logical CPU (capped at 32).  I/O gets a
    larger budget because those workers spend most of their time waiting, but it
    is only a policy value until a collector opts into parallel acquisition.
    OCR stays at one inference per process: one ONNX inference already consumes
    the configured intra-op CPU threads and concurrent inference benchmarked
    worse on the reference host.
    """

    cpu_count = max(1, int(os.cpu_count() or 1))

    env_analysis = _env_int("DSPM_ANALYSIS_WORKERS")
    if analysis_workers > 0:
        selected_analysis = analysis_workers
        analysis_source = "scan_config"
    elif env_analysis > 0:
        selected_analysis = env_analysis
        analysis_source = "environment"
    else:
        selected_analysis = cpu_count
        analysis_source = "auto_cpu"

    env_io = _env_int("DSPM_IO_WORKERS")
    if io_workers > 0:
        selected_io = io_workers
        io_source = "scan_config"
    elif env_io > 0:
        selected_io = env_io
        io_source = "environment"
    else:
        selected_io = max(4, cpu_count * 2)
        io_source = "auto_io"

    resolved_analysis = _bounded(selected_analysis, cpu_count, MAX_ANALYSIS_WORKERS)
    resolved_io = _bounded(selected_io, max(4, cpu_count * 2), MAX_IO_WORKERS)
    env_buffer = _env_int("DSPM_PIPELINE_BUFFER")
    selected_buffer = pipeline_buffer if pipeline_buffer > 0 else env_buffer
    if selected_buffer <= 0:
        selected_buffer = max(resolved_analysis * 2, resolved_io)

    return ParallelismPlan(
        cpu_count=cpu_count,
        analysis_workers=resolved_analysis,
        io_workers=resolved_io,
        ocr_workers=1,
        pipeline_buffer=_bounded(selected_buffer, resolved_analysis * 2, MAX_PIPELINE_BUFFER),
        pipeline_enabled=bool(pipeline_enabled) and _env_bool("DSPM_PIPELINE_ENABLED", True),
        analysis_source=analysis_source,
        io_source=io_source,
    )


# ---------------------------------------------------------------------------
# P-B.2: process-wide collector-I/O admission budget.
# ---------------------------------------------------------------------------


class HostAdmissionBudget:
    """A process-wide cap on concurrently connected collector I/O workers.

    Each parallel collector connection (an SMB share worker, a WinRM session, a
    local acquisition worker) holds one slot for the duration of its network
    work. Because the budget is shared across every scan job in the process, a
    burst of concurrent ``DSPM_JOB_WORKERS`` scans cannot multiply
    ``io_workers`` into an unbounded connection count against one target host -
    excess workers block until a slot frees. Slots are counted (not fair-queued)
    and contention is recorded for diagnostics."""

    __slots__ = ("_limit", "_sem", "_lock", "_in_use", "_peak", "_grants", "_waits", "_wait_seconds")

    def __init__(self, limit: int) -> None:
        self._limit = max(1, int(limit))
        self._sem = threading.Semaphore(self._limit)
        self._lock = threading.Lock()
        self._in_use = 0
        self._peak = 0
        self._grants = 0
        self._waits = 0
        self._wait_seconds = 0.0

    @property
    def limit(self) -> int:
        return self._limit

    @contextmanager
    def slot(self, timeout: float | None = None):
        """Hold one admission slot for the duration of the ``with`` block. Blocks
        when the budget is exhausted; raises TimeoutError if ``timeout`` elapses."""
        waited = False
        if not self._sem.acquire(blocking=False):
            waited = True
            started = time.monotonic()
            if not self._sem.acquire(timeout=timeout):
                raise TimeoutError("host I/O admission budget exhausted")
            wait_seconds = time.monotonic() - started
        else:
            wait_seconds = 0.0
        with self._lock:
            self._in_use += 1
            self._grants += 1
            self._peak = max(self._peak, self._in_use)
            if waited:
                self._waits += 1
                self._wait_seconds += wait_seconds
        try:
            yield
        finally:
            self._sem.release()
            with self._lock:
                self._in_use -= 1

    def stats(self) -> dict:
        with self._lock:
            return {
                "limit": self._limit,
                "in_use": self._in_use,
                "peak_in_use": self._peak,
                "grants": self._grants,
                "waits": self._waits,
                "wait_seconds": round(self._wait_seconds, 4),
            }


def _resolve_host_io_budget() -> int:
    env = _env_int("DSPM_HOST_IO_BUDGET")
    cpu = max(1, int(os.cpu_count() or 1))
    return _bounded(env, max(4, cpu * 2), MAX_HOST_IO_BUDGET)


_host_budget: HostAdmissionBudget | None = None
_host_budget_lock = threading.Lock()


def host_admission_budget() -> HostAdmissionBudget:
    """The process-wide collector-I/O admission budget (lazy singleton, sized by
    DSPM_HOST_IO_BUDGET or ~2x CPU)."""
    global _host_budget
    if _host_budget is None:
        with _host_budget_lock:
            if _host_budget is None:
                _host_budget = HostAdmissionBudget(_resolve_host_io_budget())
    return _host_budget


def reset_host_admission_budget(limit: int | None = None) -> HostAdmissionBudget:
    """Replace the process-wide budget (used by tests / an explicit reconfigure)."""
    global _host_budget
    with _host_budget_lock:
        _host_budget = HostAdmissionBudget(limit if limit is not None else _resolve_host_io_budget())
    return _host_budget
