"""Partitioned scans: each partition persists as it finishes; finalize does the rest (B2.2b-B3).

A single scan holds every analyzed file until it saves them - the one holder of
the whole estate the earlier Phase B steps could not remove. A partitioned scan
analyzes one partition, writes it, and lets it go; memory follows the largest
partition instead of the estate. A local scan is cut into runs of its walk (B2.2b);
an SMB scan into groups of shares that no overlap crosses (B2.3).

What needs the whole scan happens once, at finalize, from what the partitions
stored: the summary is the sum of the partitions' summaries, the diagnostics are
merged, the compliance sections are folded one stored record at a time, and the
report body is streamed from the partitions' records in plan order.

A partitioned scan is recorded before its first partition runs - its plan, its
request without secrets, and the header every partition stamps - and each
partition is leased to the worker running it. A process that dies part way
through therefore leaves a scan that can be continued rather than a half-written
estate: :mod:`backend.scan_resumer` finds it, and :func:`continue_partitioned_scan`
runs what is left (B2.4). The same record lets a queue worker run any one partition
of a scan it did not start (:func:`run_queued_partition`, B3) - of a local scan, only
on the host that planned it.
"""

from __future__ import annotations

import gc
import logging
import os
import socket
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from backend import store
from backend.compliance_service import ComplianceReportAccumulator
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.partition import plan_bounded_partitions, plan_share_partitions

logger = logging.getLogger(__name__)


def summed_summary(units: list[dict]) -> dict:
    """The scan summary: each partition counted its own files, and counts add up.

    A partition's summary is the engine's, taken before compliance enrichment
    strips framework-only findings - the same moment a single scan counts - so the
    sum is exactly the single scan's summary.
    """
    total: dict = {}
    for unit in units:
        for key, value in (unit.get("summary") or {}).items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                total.setdefault(key, value)
            else:
                total[key] = total.get(key, 0) + value
    return total


def scan_diagnostics_for(
    units: list[dict], *, overrides: dict | None = None, increments: dict | None = None,
) -> dict:
    """The scan's diagnostics: the partitions' merged, then what describes the scan as a whole.

    ``overrides`` replace a merged value - the scan's own root and depth rather than
    the first partition's. ``increments`` add to one - folders the planner skipped
    that no partition walked.
    """
    merged = store.merge_partition_diagnostics([unit.get("diagnostics") or {} for unit in units])
    for key, value in (overrides or {}).items():
        merged[key] = value
    for key, value in (increments or {}).items():
        merged[key] = int(merged.get(key) or 0) + int(value or 0)
    files = [int(unit.get("files") or 0) for unit in units]
    merged["partitioned"] = {
        "enabled": True,
        "partitions": len(units),
        "files": sum(files),
        "largest_partition_files": max(files, default=0),
    }
    return merged


def _stored_files(tenant_id: str, scan_id: str):
    for _partition_id, records in store.iter_partition_records(tenant_id, scan_id):
        yield from records


def finalize_scan(
    tenant_id: str,
    scan_id: str,
    *,
    timestamp: str,
    source: str,
    scan_label: str = "",
    compliance_enabled: bool = False,
    compliance_frameworks: Iterable[str] | None = None,
    write_estate: bool = True,
    diagnostics_overrides: dict | None = None,
    diagnostics_increments: dict | None = None,
) -> dict:
    """Finish a partitioned scan whose partitions are all done; returns its compact report.

    Two passes over the stored records, one partition in memory at a time: the
    first folds the compliance sections and counts the files, the second streams
    the body - which has to carry ``summary`` before ``files``, the key order every
    report has. Finalizing a scan that is already finalized returns its report,
    including when another finalize of it committed while this one was reading.
    """
    units = store.list_scan_partitions(tenant_id, scan_id)
    if not units or any(unit["status"] != "done" for unit in units):
        raise store.PartitionsNotFinished(f"scan {scan_id} has partitions that are not done")
    if not any(unit["has_records"] for unit in units):
        existing = store.read_scan_report_compact(tenant_id, scan_id)
        if existing is not None:
            return existing
        raise store.PartitionsNotFinished(f"scan {scan_id} kept no records to finalize from")

    summary = summed_summary(units)
    diagnostics = scan_diagnostics_for(units, overrides=diagnostics_overrides, increments=diagnostics_increments)
    sections = ComplianceReportAccumulator(compliance_enabled, compliance_frameworks)
    file_count = 0
    sample_count = 0
    touched = time.monotonic()
    try:
        for record in _stored_files(tenant_id, scan_id):
            sections.add(record)
            file_count += 1
            if store.is_sample_data_path(record):
                sample_count += 1
            if time.monotonic() - touched > 30:
                # A long first pass must not look like a dead finalizer (B2.4 review).
                store.touch_partitioned_scan(tenant_id, scan_id)
                touched = time.monotonic()
    except store.PartitionsNotFinished:
        # Another finalize committed after the partitions were listed, and released
        # the records this pass was reading.
        existing = store.read_scan_report_compact(tenant_id, scan_id)
        if existing is None:
            raise
        return existing

    report = {
        "timestamp": timestamp,
        "source": source,
        "mode": str((diagnostics.get("incremental") or {}).get("mode") or "full"),
        "summary": summary,
        "files": store.StreamedFiles(lambda: _stored_files(tenant_id, scan_id)),
        "scan_diagnostics": diagnostics,
    }
    sections.apply(report)
    label = str(scan_label or "").strip()[:80]
    if label:
        report["scan_label"] = label
    try:
        store.finalize_partitioned_scan(
            tenant_id, scan_id, report,
            write_estate=write_estate, file_count=file_count, sample_count=sample_count,
        )
    except store.ScanAlreadyFinalized:
        existing = store.read_scan_report_compact(tenant_id, scan_id)
        if existing is None:
            raise
        return existing
    return store.compact_scan_report_from_counts(report, file_count, sample_count)


# ---- settings ----------------------------------------------------------------------------------------------


def partitioned_scans_enabled() -> bool:
    """Whether local and SMB scans run partitioned. Off by default.

    An interrupted partitioned scan is now continued rather than left half-written
    (B2.4). The default stays off until the B2 gates are measured at the scale they
    are about (plan §8): this is the path a pilot's largest scans take, and it should
    be turned on by that evidence, not by being finished.
    """
    return os.getenv("DSPM_PARTITIONED_SCANS", "0").strip().lower() in {"1", "true", "yes", "on"}


def partition_max_files() -> int:
    """The most files one local partition holds, and so what a local scan's memory follows."""
    try:
        return max(1, min(int(os.getenv("DSPM_PARTITION_MAX_FILES", "2000")), 1_000_000))
    except ValueError:
        return 2000


def partition_max_attempts() -> int:
    """How many times one partition is tried before its scan fails.

    A partition fails for reasons that may pass - a file locked for a moment, a
    folder briefly unreadable - so it is tried again once nothing else is queued. One
    that keeps failing, or whose holder keeps dying, stops the scan instead of
    retrying forever.
    """
    try:
        return max(1, min(int(os.getenv("DSPM_PARTITION_MAX_ATTEMPTS", "3")), 20))
    except ValueError:
        return 3


PARTITION_RETRY_SECONDS = 30.0


def partition_retry_seconds() -> float:
    """How long a failed partition waits before its next attempt; it doubles with each failure.

    A share that is unreachable for a minute should cost a minute, not every attempt the
    partition has. With three attempts the last one starts a minute and a half after the
    first failure. ``DSPM_PARTITION_RETRY_SECONDS`` (0 = at once, at most 900).
    """
    try:
        return max(0.0, min(float(os.getenv("DSPM_PARTITION_RETRY_SECONDS", str(PARTITION_RETRY_SECONDS))), 900.0))
    except ValueError:
        return PARTITION_RETRY_SECONDS


def partition_lease_seconds() -> int:
    """How long a claimed partition stays its worker's without a renewal.

    A running worker renews it every third of this. It is also how long the resume
    sweep waits after a scan's last sign of life before taking the scan over, so it
    bounds how soon an interrupted scan continues.
    """
    try:
        return max(1, min(int(os.getenv("DSPM_PARTITION_LEASE_SECONDS", str(store.DEFAULT_PARTITION_LEASE_SECONDS))), 86_400))
    except ValueError:
        return store.DEFAULT_PARTITION_LEASE_SECONDS


def finalize_stale_seconds() -> int:
    """How long a finalize may look idle before it is taken for dead: twelve leases, at least an hour.

    Finalize's write is one transaction that cannot touch the scan record while it
    streams the body, so a lease is far too short a judge of it (B2.4 review).
    """
    return max(12 * partition_lease_seconds(), 3600)


def queued_execution() -> bool:
    """Whether a scan the console starts is handed to workers (``DSPM_SCAN_EXECUTION=queue``).

    Inline by default: the process that takes the request runs the partitions itself, as
    it has since B2.2b. Set to ``queue``, it plans the scan, publishes its partitions and
    then only follows the ledger - the work is done by ``python main.py worker``
    processes (B3). The queue is chosen separately, by ``DSPM_WORK_QUEUE``.
    """
    return os.getenv("DSPM_SCAN_EXECUTION", "inline").strip().lower() == "queue"


def queue_wait_seconds() -> int:
    """How long a queued scan's job waits for workers to finish it (``DSPM_SCAN_QUEUE_MAX_SECONDS``).

    A scan waiting for a worker is not a scan taking too long, so this is a day by
    default rather than ``SCAN_MAX_SECONDS``. When it runs out the job says no worker
    finished the scan, and the scan itself is left exactly as it is: a worker may still
    be running it, and the ledger remains the truth about that. A partitioned scan run in
    this process has no such budget: see :func:`partition_max_seconds`.
    """
    try:
        return max(1, min(int(os.getenv("DSPM_SCAN_QUEUE_MAX_SECONDS", "86400")), 30 * 24 * 3600))
    except ValueError:
        return 86_400


def partition_max_seconds() -> int:
    """How long one partition's engine may run (``DSPM_PARTITION_MAX_SECONDS``; 0 = no limit).

    A partitioned scan has no time budget of its own (W1.1): two million files take as long
    as they take, and a scan cut off at a wall clock was failed for good with its finished
    partitions in the estate and no report. Each unit has one instead - by default the half
    hour a whole single scan gets. A unit that runs out of it is tried again, like one that
    failed; on its last attempt what it read is kept, and the scan says it is incomplete.
    """
    default = os.getenv("DSPM_SCAN_MAX_SECONDS") or "1800"
    try:
        return max(0, min(int(os.getenv("DSPM_PARTITION_MAX_SECONDS") or default), 86_400))
    except ValueError:
        return 1800


def scan_stall_seconds() -> int:
    """How long a scan may go without any partition finishing before its runner pauses it
    (``DSPM_SCAN_STALL_SECONDS``; 0 = never). Three unit budgets, and at least an hour."""
    default = max(3 * partition_max_seconds(), 3600)
    try:
        return max(0, min(int(os.getenv("DSPM_SCAN_STALL_SECONDS") or default), 30 * 24 * 3600))
    except ValueError:
        return default


def partition_workers() -> int:
    """How many units of one scan run at once in this process (``DSPM_PARTITION_WORKERS``).

    One by default. Each unit runs its own engine, and with compliance on each engine starts
    a detector process pool sized for the whole host, so N units cost N pools of processes
    and their memory. Raise it for I/O-bound scans - SMB, compliance off - until the pool is
    shared between units (roadmap E8).
    """
    try:
        return max(1, min(int(os.getenv("DSPM_PARTITION_WORKERS") or "1"), 8))
    except ValueError:
        return 1


def scan_sla_seconds() -> int:
    """``DSPM_SCAN_SLA_SECONDS``: past it a running scan is reported late - never stopped (0 = off)."""
    try:
        return max(0, min(int(os.getenv("DSPM_SCAN_SLA_SECONDS", "0")), 30 * 24 * 3600))
    except ValueError:
        return 0


# ---- running one -------------------------------------------------------------------------------------------


class ScanStopped(RuntimeError):
    """A partitioned scan stopped for good: cancelled, out of time, or a partition out of attempts.

    The scan is marked failed and never resumed. A scan whose process died has not
    stopped - it stays unfinished, and the resume sweep continues it.
    """


class ScanPaused(RuntimeError):
    """A partitioned scan stopped making progress, and its runner let it go (W1.1).

    Nothing is marked failed: the scan stays unfinished, and once nothing has touched it
    for a lease the resume sweep continues it under the same job. Only a scan that cannot
    be resumed - started without a request - is failed instead, since nothing would ever
    pick it up again.
    """


class PartitionOverBudget(RuntimeError):
    """A unit's engine ran out of its time budget before it had read everything."""


_running_here: set[tuple[str, str]] = set()
_running_here_lock = threading.Lock()


def is_running_here(tenant_id: str, scan_id: str) -> bool:
    """Whether this process is running the scan now; the resume sweep leaves such a scan alone.

    A scan being finalized cannot show it is alive - finalize is one transaction that
    holds the store for its whole length - so within a process this says so instead.
    Across processes the finalize guard makes a take-over harmless.
    """
    with _running_here_lock:
        return (str(tenant_id), str(scan_id)) in _running_here


def _this_host() -> str:
    return socket.gethostname().casefold()


def runs_here(record: dict) -> bool:
    """Whether this host can run the recorded scan's partitions.

    A local scan's paths name folders on the host that planned it. On another host the
    same path is another folder or none at all - and a partition that found nothing
    there would be written as empty, and finalize would prune everything under it (B3
    review). An SMB scan runs wherever the server can be reached.
    """
    header = record.get("header") or {}
    if str(header.get("source") or "local") != "local":
        return True
    host = str(header.get("host") or "")
    return not host or host.casefold() == _this_host()


def _stop_check(job) -> Callable[[], str | None]:
    """Why the scan must stop now: only a cancellation. A partitioned scan has no wall
    clock of its own (W1.1) - each unit has a budget, and a scan that stops making progress
    is paused for the resume sweep, never failed (see :func:`_run_partitions`)."""

    def stop_reason() -> str | None:
        if job is not None and job.cancel_requested:
            return "Scan cancelled"
        return None

    return stop_reason


def _scan_ended_check(tenant_id: str, scan_id: str, *, every_seconds: float = 2.0) -> Callable[[], str | None]:
    """A stop check for a worker: why the recorded scan is over, or ``None`` while it runs.

    The engine asks before every file, so the record is read at most every
    ``every_seconds``; once the scan has ended the answer never changes. A read that
    fails is not a stop - the write refuses a scan that is not running anyway.
    """
    lock = threading.Lock()
    state: dict = {"read_at": float("-inf"), "reason": None}

    def stop_reason() -> str | None:
        with lock:
            if state["reason"] is not None or time.monotonic() - state["read_at"] < every_seconds:
                return state["reason"]
            state["read_at"] = time.monotonic()
        try:
            record = store.read_partitioned_scan(tenant_id, scan_id)
        except Exception:
            return None
        status = str((record or {}).get("status") or "gone")
        if status in ("running", "finalizing"):
            return None
        reason = str((record or {}).get("error") or "") or f"scan {scan_id} is {status}"
        with lock:
            state["reason"] = reason
        return reason

    return stop_reason


@dataclass(frozen=True)
class _Scan:
    """What every partition of one scan shares, read back from the scan's record."""

    tenant_id: str
    scan_id: str
    config: ScanConfig
    source: str
    scan_root: str
    timestamp: str
    label: str
    compliance_enabled: bool
    compliance_frameworks: tuple[str, ...]
    local_path: str
    max_depth: int
    worker: str
    lease_seconds: int


def _scan_from_record(record: dict, config: ScanConfig, *, worker: str | None = None) -> _Scan:
    """What every partition of a recorded scan shares - from its header, whoever runs it."""
    header = record.get("header") or {}
    source = str(header.get("source") or "local")
    local = source == "local"
    return _Scan(
        tenant_id=str(record["tenant_id"]),
        scan_id=str(record["scan_id"]),
        config=config,
        source=source,
        scan_root=str(header.get("scan_root") or (Path(config.local_path).expanduser().resolve() if local else "")),
        timestamp=str(header.get("timestamp") or datetime.now(timezone.utc).isoformat()),
        label=str(header.get("scan_label") or "").strip()[:80],
        compliance_enabled=bool(header.get("compliance_enabled")),
        compliance_frameworks=tuple(header.get("compliance_frameworks") or ()),
        local_path=str(header.get("local_path") or config.local_path),
        max_depth=int(header.get("max_depth", config.max_depth)),
        worker=worker or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}",
        lease_seconds=partition_lease_seconds(),
    )


def _unit_config(config: ScanConfig, spec: dict, scan_root: str) -> ScanConfig:
    """One local partition's engine: the scan's policy, scope and reuse, over one run.

    Incremental reuse, the persistent cache and the baseline probe carry over
    unchanged - every partition probes and writes under the scan's own scope, and
    finalize prunes that scope once - so a partitioned re-scan reuses exactly what a
    single one would. Progress is the runner's to report, per partition.
    """
    return replace(
        config,
        local_path=str(spec["local_path"]),
        max_depth=int(spec["max_depth"]),
        local_entry_names=tuple(spec.get("names") or ()),
        scan_root=scan_root,
        progress_callback=None,
        max_seconds=partition_max_seconds(),
    )


def _share_unit_config(config: ScanConfig, spec: dict) -> ScanConfig:
    """One SMB partition's engine: the scan's policy, scope and reuse, over one group of shares."""
    return replace(config, smb_shares=tuple(spec.get("shares") or ()), progress_callback=None,
                   max_seconds=partition_max_seconds())


def _vanished_partition(timestamp: str, label: str, folder: str) -> tuple[dict, list]:
    """A run whose folder is gone by the time it is scanned holds nothing.

    A whole walk that cannot list a folder reports it unreadable, and that leaves the
    scan incomplete, so nothing under it is pruned; the partition says the same (B3
    review - it used to report nothing, and the scan called itself complete).
    """
    from discovery.discovery_engine import ScanSummary

    header = {
        "timestamp": timestamp, "source": "local", "mode": "full",
        "summary": ScanSummary(0, 0, 0, 0, 0, 0).to_dict(),
        # Completeness is merged from the partitions' incremental blocks alone, so the
        # unreadable folder has to say so there too.
        "scan_diagnostics": {
            "unreadable_dirs": [f"{folder}: folder no longer exists"],
            "incremental": {"complete": False},
        },
    }
    if label:
        header["scan_label"] = label
    return header, []


def start_partitioned_scan(
    tenant_id: str,
    config: ScanConfig,
    *,
    request: dict | None = None,
    requested_by: str = "",
    scan_label: str = "",
    compliance_enabled: bool = False,
    compliance_frameworks: Iterable[str] | None = None,
    job=None,
    max_files: int | None = None,
    stop_reason: Callable[[], str | None] | None = None,
) -> dict | None:
    """Plan a local or SMB scan into partitions and record it; returns the scan's record.

    Returns ``None`` when the target is not worth partitioning - a local target that
    fits one partition or is not a readable folder, a server whose shares form one
    group, or a server that cannot be planned - or when it holds the bundled demo
    dataset, whose files never enter the estate and which is small by definition. The
    caller then runs an ordinary scan.

    Everything a restart needs to continue the scan is written before its first
    partition runs: the plan in the ledger, and beside it the request - without
    secrets - and the header every partition stamps. The record is written first, so
    a process that dies in between leaves a scan the resume sweep can see and fail,
    not partitions nothing points at. A scan started without a request is recorded
    but cannot be resumed: nothing could rebuild its engine.
    """
    from backend.jobs import collection_heartbeat

    stop_reason = stop_reason or _stop_check(job)
    budget = max_files or partition_max_files()
    remote = bool(config.server)
    # Planning walks the whole target: no wall clock, only a cancel (W1.1).
    with collection_heartbeat(job, max_seconds=0) if job is not None else nullcontext():
        if remote:
            plan = plan_share_partitions(config, stop_check=stop_reason)
        else:
            plan = plan_bounded_partitions(config, max_files=budget, stop_check=stop_reason)
    if plan is None or plan["sample_paths"]:
        return None

    scan_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    job_id = str(getattr(job, "id", "") or "")
    header = {
        # One timestamp for the whole scan: every partition stamps it on the rows it
        # writes, and a single scan's rows all carry one.
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "smb" if remote else "local",
        "scan_label": str(scan_label or "").strip()[:80],
        "compliance_enabled": bool(compliance_enabled),
        "compliance_frameworks": list(compliance_frameworks or []),
        "requested_by": str(requested_by or ""),
    }
    if not remote:
        header.update(
            local_path=config.local_path,
            max_depth=config.max_depth,
            scan_root=str(Path(config.local_path).expanduser().resolve()),
            max_files=budget,
            host=socket.gethostname(),
        )
    record = store.register_partitioned_scan(
        tenant_id, scan_id, job_id=job_id, request=dict(request or {}), header=header,
        resumable=request is not None,
    )
    store.create_scan_partitions(tenant_id, scan_id, job_id, plan["units"])
    return record


def continue_partitioned_scan(
    tenant_id: str,
    scan_id: str,
    config: ScanConfig,
    *,
    job=None,
    stop_reason: Callable[[], str | None] | None = None,
    poll_seconds: float = 1.0,
) -> dict:
    """Run a recorded scan's remaining partitions and finalize it; returns the compact report.

    The same call runs a new scan's partitions and continues one a stopped process
    left behind: what is done stays done, a partition whose holder went quiet is
    taken back once its lease has run out, and a partition that failed is tried again
    up to ``DSPM_PARTITION_MAX_ATTEMPTS`` times. Each partition is leased to this call,
    and the lease is renewed while the partition runs, so a live worker never loses
    its partition to a sweep.

    A cancellation or a partition out of attempts stops the scan for good: it is marked
    failed and :class:`ScanStopped` is raised. Any other error marks it failed too, with
    the error's type. A scan that stops making progress is paused - :class:`ScanPaused`
    is raised and the scan is left unfinished - and so is one whose process dies: the
    resume sweep continues both.
    """
    record = store.read_partitioned_scan(tenant_id, scan_id)
    if record is None:
        raise LookupError(f"partitioned scan {scan_id} is not recorded")
    if record["status"] == "done":
        existing = store.read_scan_report_compact(tenant_id, scan_id)
        if existing is not None:
            return existing
    if record["status"] == "failed":
        raise ScanStopped(record["error"] or f"scan {scan_id} failed")
    key = (str(tenant_id), str(scan_id))
    with _running_here_lock:
        if key in _running_here:
            raise RuntimeError(f"scan {scan_id} is already running in this process")
        _running_here.add(key)
    try:
        scan = _scan_from_record(record, config)
        stop_reason = stop_reason or _stop_check(job)
        try:
            _run_partitions(scan, job=job, stop_reason=stop_reason, poll_seconds=poll_seconds)
            return _finalize_when_claimed(scan, job=job, stop_reason=stop_reason, poll_seconds=poll_seconds)
        except ScanPaused:
            if not record.get("resumable"):
                with suppress(Exception):
                    store.mark_partitioned_scan(
                        scan.tenant_id, scan.scan_id, "failed",
                        error="Scan stopped making progress and cannot be resumed: it was started without a "
                              "request to rebuild it from. Run the scan again.",
                    )
            raise
        except Exception as exc:
            with suppress(Exception):
                store.mark_partitioned_scan(
                    scan.tenant_id, scan.scan_id, "failed",
                    error=str(exc) if isinstance(exc, ScanStopped) else type(exc).__name__,
                )
            raise
    finally:
        with _running_here_lock:
            _running_here.discard(key)


def _run_partitions(scan: _Scan, *, job, stop_reason, poll_seconds: float) -> None:
    units = store.list_scan_partitions(scan.tenant_id, scan.scan_id)
    if not units:
        raise ScanStopped(f"scan {scan.scan_id} stopped before its plan was recorded")
    total = len(units)
    done = sum(1 for unit in units if unit["status"] == "done")
    max_attempts = partition_max_attempts()
    stall = scan_stall_seconds()
    sla = scan_sla_seconds()
    started = last_progress = time.monotonic()
    late = False
    workers = partition_workers()
    # One unit at a time runs here, in the job's own thread, as it always has. More than
    # one run on a pool of their own (W1.1); a stop or a pause claims nothing more.
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="partition") if workers > 1 else None
    running: dict = {}

    def finished_one() -> None:
        nonlocal done, last_progress
        done += 1
        last_progress = time.monotonic()
        if job is not None:
            job.progress = max(job.progress, min(94, 8 + int(86 * done / total)))
            _share_progress(job)

    def claim():
        return store.claim_next_partition(
            scan.tenant_id, scan.scan_id, worker_id=scan.worker, lease_seconds=scan.lease_seconds,
        )

    try:
        # A partition whose holder died is taken back once its lease has run out - or, on
        # its last attempt, failed.
        store.requeue_expired_partitions(tenant_id=scan.tenant_id, max_attempts=max_attempts)
        while True:
            reason = stop_reason()
            if reason:
                raise ScanStopped(reason)
            now = time.monotonic()
            if stall and now - last_progress > stall:
                raise ScanPaused(
                    f"Scan paused: no partition of scan {scan.scan_id} finished in {int(stall // 60)} minutes; "
                    "it continues automatically"
                )
            if sla and not late and now - started > sla:
                late = True
                logger.warning("Partitioned scan %s is past its %s s SLA with %s of %s partitions done; it continues",
                               scan.scan_id, sla, done, total)
                if job is not None:
                    job.message = f"Scanning partition {done + 1} of {total} (past its expected time)"
            store.touch_partitioned_scan(scan.tenant_id, scan.scan_id)
            if pool is None:
                unit = claim()
                if unit is not None:
                    if job is not None:
                        job.message = f"Scanning partition {done + 1} of {total}"
                    if _run_unit(scan, unit, job=job, stop_reason=stop_reason):
                        finished_one()
                    continue
            else:
                while len(running) < workers:
                    unit = claim()
                    if unit is None:
                        break
                    running[pool.submit(_run_unit, scan, unit, job=job, stop_reason=stop_reason)] = unit
                if running:
                    if job is not None:
                        job.message = f"Scanning partitions {done + 1}-{min(total, done + len(running))} of {total}"
                    complete, _pending = wait(list(running), timeout=poll_seconds, return_when=FIRST_COMPLETED)
                    for future in complete:
                        running.pop(future)
                        if future.result():
                            finished_one()
                    continue
            if store.requeue_failed_partitions(scan.tenant_id, scan.scan_id, max_attempts=max_attempts,
                                               backoff_seconds=partition_retry_seconds()):
                continue
            units = store.list_scan_partitions(scan.tenant_id, scan.scan_id)
            if all(unit["status"] == "done" for unit in units):
                return
            finished = sum(1 for unit in units if unit["status"] == "done")
            if finished > done:
                # Another worker finished one: that is progress too.
                done, last_progress = finished, time.monotonic()
            exhausted = [unit for unit in units if unit["status"] == "failed" and unit["attempt"] >= max_attempts]
            if exhausted:
                raise ScanStopped(_exhausted_message(exhausted[0]))
            # What is left runs under another worker's lease: take back any that ran out, or wait.
            if not store.requeue_expired_partitions(tenant_id=scan.tenant_id, max_attempts=max_attempts):
                time.sleep(poll_seconds)
    finally:
        if pool is not None:
            # Units still running end on their own - a cancel reaches their engines - or
            # are left to their leases; nothing waits here for one that hangs.
            pool.shutdown(wait=False, cancel_futures=True)


def _exhausted_message(unit: dict) -> str:
    return f"partition {unit['partition_id']} failed {unit['attempt']} times ({unit['error'] or 'no error recorded'})"


@contextmanager
def _holding_lease(scan: _Scan, unit: dict):
    """Keep a claimed partition's lease, and its scan's sign of life, fresh while the partition runs."""
    stop = threading.Event()

    def renew() -> None:
        while not stop.wait(max(0.5, scan.lease_seconds / 3)):
            try:
                if not store.renew_partition_lease(
                    scan.tenant_id, scan.scan_id, unit["partition_id"],
                    attempt=unit["attempt"], worker_id=scan.worker, lease_seconds=scan.lease_seconds,
                ):
                    return
                store.touch_partitioned_scan(scan.tenant_id, scan.scan_id)
            except Exception:
                continue

    thread = threading.Thread(target=renew, name=f"partition-lease-{unit['partition_id']}", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=5)


def _run_unit(scan: _Scan, unit: dict, *, job, stop_reason) -> bool:
    """Analyze, enrich and write one claimed partition; returns whether it was written.

    Nothing about the partition is kept once it is written but its ledger row. A
    partition that raises is marked failed under its attempt and the scan goes on; it
    is tried again once nothing else is queued, and so is one that ran out of its own
    time budget. A cancellation is not the partition's failure and stops the scan. A partition taken back
    while it ran, because its lease ran out, is left to its new holder.
    """
    from backend.jobs import collection_heartbeat

    try:
        with _holding_lease(scan, unit):
            if scan.source == "smb":
                engine_config = _share_unit_config(scan.config, unit["spec"])
            elif not Path(scan.scan_root).is_dir():
                # Not a folder that vanished: the whole scan is out of reach from here.
                # Writing that as an empty partition would let finalize prune the estate.
                raise FileNotFoundError(f"the scan root is not reachable from {socket.gethostname()}")
            elif Path(str(unit["spec"]["local_path"])).is_dir():
                engine_config = _unit_config(scan.config, unit["spec"], scan.scan_root)
            else:
                engine_config = None
            if engine_config is None:
                header, records = _vanished_partition(scan.timestamp, scan.label, str(unit["spec"]["local_path"]))
            else:
                with collection_heartbeat(job, max_seconds=0) if job is not None else nullcontext():
                    report = DSPMDiscoveryEngine(engine_config).run().to_dict()
                reason = stop_reason()
                if reason:
                    raise ScanStopped(reason)
                if (report.get("scan_diagnostics") or {}).get("scan_truncated") \
                        and int(unit["attempt"]) < partition_max_attempts():
                    # Out of its own time, not cancelled: tried again like a failure. On
                    # its last attempt what it read is written, and the engine has already
                    # marked it incomplete, so the scan prunes nothing it did not see.
                    raise PartitionOverBudget(
                        f"partition {unit['partition_id']} ran past its {partition_max_seconds()} s budget"
                    )
                records = report.get("files") or []
                enrichment = ComplianceReportAccumulator(scan.compliance_enabled, list(scan.compliance_frameworks))
                for record in records:
                    enrichment.prepare(record)
                header = {
                    "timestamp": scan.timestamp,
                    "source": report.get("source") or scan.source,
                    "mode": report.get("mode") or "full",
                    "summary": report.get("summary") or {},
                    "scan_diagnostics": report.get("scan_diagnostics") or {},
                }
                if scan.label:
                    header["scan_label"] = scan.label
                report = None
            store.persist_partition(
                scan.tenant_id, scan.scan_id, unit["partition_id"], unit["attempt"], header, records, write_estate=True,
            )
        return True
    except store.PartitionNotClaimed:
        return False
    except BaseException as exc:
        with suppress(Exception):
            store.fail_scan_partition(
                scan.tenant_id, scan.scan_id, unit["partition_id"], type(exc).__name__, attempt=unit["attempt"],
            )
        if not isinstance(exc, Exception) or isinstance(exc, ScanStopped):
            raise
        if isinstance(exc, store.ScanNotRunning):
            raise ScanStopped(str(exc)) from exc
        reason = stop_reason()
        if reason:
            raise ScanStopped(reason) from exc
        logger.warning(
            "Partition %s of scan %s failed on attempt %s: %s",
            unit["partition_id"], scan.scan_id, unit["attempt"], type(exc).__name__,
        )
        return False
    finally:
        # A partition's engine leaves its records, findings and worker futures in
        # reference cycles, which only a full collection frees - and full collections
        # grow rarer as the heap grows. Uncollected, every partition's garbage stayed:
        # the scan's peak grew with the corpus (37 KiB a file) instead of following the
        # partition size, the whole point of partitioning (C14). One full collection per
        # partition costs a fraction of a partition's scan.
        gc.collect()


def _finalize(scan: _Scan) -> dict:
    """Finalize a scan whose finalize this caller has claimed, and mark it done.

    Once the finalize has committed the scan has succeeded, whatever happens to the
    status update after it: a failure there leaves the scan ``finalizing``, the sweep
    later takes it back, and finalizing again returns the report and marks it done.
    It is never allowed to turn into a failed scan with a report (B3 review).
    """
    report = finalize_scan(
        scan.tenant_id, scan.scan_id,
        timestamp=scan.timestamp,
        source=scan.source,
        scan_label=scan.label,
        compliance_enabled=scan.compliance_enabled,
        compliance_frameworks=list(scan.compliance_frameworks),
        write_estate=True,
        # A local scan's diagnostics name its root and depth; each run's name its own.
        diagnostics_overrides=(
            {"local_path": scan.local_path, "max_depth": scan.max_depth} if scan.source == "local" else None
        ),
    )
    try:
        store.mark_partitioned_scan(scan.tenant_id, scan.scan_id, "done")
    except Exception as exc:
        logger.warning("Scan %s finalized, but could not be marked done: %s", scan.scan_id, type(exc).__name__)
    return report


def _share_progress(job) -> None:
    """Put the job's progress where a console on another backend reads it (B3.1).

    Throttled by `jobs.publish_progress`, so a scan with thousands of small partitions
    writes the job record at most once a second.
    """
    with suppress(Exception):
        from backend import jobs

        jobs.publish_progress(job)


def _finalize_when_claimed(scan: _Scan, *, job, stop_reason, poll_seconds: float) -> dict:
    if job is not None:
        job.message = "Finalizing report"
        job.progress = max(job.progress, 95)
    # Exactly one finalize runs. One left claimed by a process that died is taken back
    # once it has looked idle for far longer than a lease; the finalize guard makes a
    # take-back that raced a slow but live finalize return that finalize's report.
    while not store.claim_scan_finalize(scan.tenant_id, scan.scan_id, stale_after_seconds=finalize_stale_seconds()):
        current = store.read_partitioned_scan(scan.tenant_id, scan.scan_id) or {}
        if current.get("status") == "done":
            existing = store.read_scan_report_compact(scan.tenant_id, scan.scan_id)
            if existing is None:
                raise ScanStopped(f"scan {scan.scan_id} finished, but its report is gone")
            return existing
        if current.get("status") == "failed":
            raise ScanStopped(current.get("error") or f"scan {scan.scan_id} failed")
        reason = stop_reason()
        if reason:
            raise ScanStopped(reason)
        time.sleep(poll_seconds)
    if job is not None:
        from backend.jobs import begin_saving

        # The finalize is one transaction that will land; from here the job refuses a
        # cancel rather than call a scan that is being written cancelled.
        if not begin_saving(job):
            raise ScanStopped("Scan cancelled")
    return _finalize(scan)


# ---- run by a queue worker (B3) ----------------------------------------------------------------------------


def run_queued_partition(record: dict, config: ScanConfig, partition_id: str, *, worker_id: str) -> str:
    """Run one named partition of a recorded scan for a queue worker; returns what happened.

    ``written`` - this call ran and committed it. ``finished`` - it was already done.
    ``held`` - another worker holds it, or took it back while this call ran. ``retry`` -
    it failed and is queued in the ledger again. ``stopped`` - it failed its last
    attempt, and the scan is marked failed. ``dropped`` - the scan has no such partition,
    or it ended - cancelled, failed - while the partition ran, which was then not written.
    ``elsewhere`` - a local scan planned on another host, which this host must not run.

    The claim is the ledger's compare-and-set, so a duplicate delivery - the same
    partition handed to two workers, or handed out again after a commit - finds it done and
    runs nothing twice.
    """
    if not runs_here(record):
        return "elsewhere"
    scan = _scan_from_record(record, config, worker=worker_id)
    # A worker has no job to be cancelled through: cancelling a queued scan marks the scan
    # failed. The partition's engine and its write both ask the scan's status, so a
    # cancelled scan stops at its next file instead of writing estate rows for half an hour.
    stop_reason = _scan_ended_check(scan.tenant_id, scan.scan_id)
    scan = replace(scan, config=replace(scan.config, cancel_check=lambda: stop_reason() is not None))
    unit = store.claim_partition(
        scan.tenant_id, scan.scan_id, partition_id, worker_id=scan.worker, lease_seconds=scan.lease_seconds,
    )
    if unit is not None:
        try:
            if _run_unit(scan, unit, job=None, stop_reason=stop_reason):
                return "written"
        except ScanStopped:
            return "dropped"
    current = store.read_scan_partition(scan.tenant_id, scan.scan_id, partition_id)
    if current is None:
        return "dropped"
    if current["status"] == "done":
        return "finished"
    if current["status"] != "failed":
        return "held"
    max_attempts = partition_max_attempts()
    if current["attempt"] < max_attempts:
        # Queued again once its wait is over - here if that is now, else by a worker's
        # maintenance pass.
        store.requeue_failed_partitions(scan.tenant_id, scan.scan_id, max_attempts=max_attempts,
                                        backoff_seconds=partition_retry_seconds())
        return "retry"
    store.mark_partitioned_scan(scan.tenant_id, scan.scan_id, "failed", error=_exhausted_message(current))
    return "stopped"


def settle_if_finished(record: dict, config: ScanConfig) -> str | None:
    """Finish a recorded scan nothing is left to run for; returns ``finalized``, ``failed`` or ``None``.

    A partition out of attempts: mark the scan failed at once - it can never finish, and
    nothing else of it is worth running. Every partition done: finalize it, unless another
    caller already is. Anything else: nothing to do yet. Queue workers call this after
    their writes and while they idle, so a scan whose last worker died between its commit
    and the finalize is still finished (B3 review).
    """
    units = store.list_scan_partitions(record["tenant_id"], record["scan_id"])
    if not units:
        return None
    max_attempts = partition_max_attempts()
    exhausted = [unit for unit in units if unit["status"] == "failed" and unit["attempt"] >= max_attempts]
    if exhausted:
        store.mark_partitioned_scan(record["tenant_id"], record["scan_id"], "failed", error=_exhausted_message(exhausted[0]))
        return "failed"
    if any(unit["status"] != "done" for unit in units):
        return None
    scan = _scan_from_record(record, config)
    if not store.claim_scan_finalize(scan.tenant_id, scan.scan_id, stale_after_seconds=finalize_stale_seconds()):
        return None
    try:
        _finalize(scan)
    except Exception as exc:
        with suppress(Exception):
            store.mark_partitioned_scan(scan.tenant_id, scan.scan_id, "failed", error=type(exc).__name__)
        raise
    return "finalized"


def enqueue_partitioned_scan(record: dict, queue=None) -> int:
    """Hand a planned scan's queued partitions to the workers; returns how many (B3).

    On the ledger queue the partitions are already where workers look, so this counts
    them for the console and the audit trail. A delivery carries identifiers only;
    everything a worker needs it reads from the ledger. Publishing the same partition
    twice is harmless - the second delivery finds it done, or held by its worker.
    """
    from backend.work_queue import work_queue_from_env

    queue = work_queue_from_env() if queue is None else queue
    queued = [
        unit["partition_id"]
        for unit in store.list_scan_partitions(record["tenant_id"], record["scan_id"])
        if unit["status"] == "queued"
    ]
    return queue.publish(record["tenant_id"], record["scan_id"], queued)


def follow_partitioned_scan(
    tenant_id: str,
    scan_id: str,
    *,
    job=None,
    poll_seconds: float = 2.0,
    wait_seconds: int | None = None,
) -> dict:
    """Watch a scan that workers are running until it ends; returns its compact report (B3).

    This is the console's job when execution is queued: it runs no partition itself, it
    reports what the ledger says, and it ends when the scan does. Cancelling the job
    marks the scan failed, which is what stops the workers - each of them reads the
    scan's status before it runs anything.

    Raises :class:`ScanStopped` if the scan failed, or if no worker finished it within
    ``DSPM_SCAN_QUEUE_MAX_SECONDS``. In that last case the scan is left as it is: the
    job has waited long enough, but the work may still be going on.
    """
    deadline = time.monotonic() + (queue_wait_seconds() if wait_seconds is None else max(1, int(wait_seconds)))
    total = max(1, len(store.list_scan_partitions(tenant_id, scan_id)))
    while True:
        record = store.read_partitioned_scan(tenant_id, scan_id)
        if record is None:
            raise LookupError(f"partitioned scan {scan_id} is not recorded")
        if record["status"] == "done":
            report = store.read_scan_report_compact(tenant_id, scan_id)
            if report is None:
                raise ScanStopped(f"scan {scan_id} finished, but its report is gone")
            return report
        if record["status"] == "failed":
            raise ScanStopped(record["error"] or f"scan {scan_id} failed")
        if job is not None and job.cancel_requested:
            # The workers read the status before every partition, so this stops them.
            store.mark_partitioned_scan(tenant_id, scan_id, "failed", error="Scan cancelled")
            raise ScanStopped("Scan cancelled")
        if time.monotonic() > deadline:
            raise ScanStopped(f"no worker finished scan {scan_id} within the queue wait")
        if job is not None:
            state = store.scan_partition_summary(tenant_id, scan_id)
            done = int(state.get("done") or 0)
            job.progress = max(job.progress, min(94, 8 + int(86 * done / total)))
            job.message = (
                "Finalizing report" if state.get("complete")
                else f"A worker is scanning partition {min(done + 1, total)} of {total}"
            )
            _share_progress(job)
        time.sleep(poll_seconds)


def run_partitioned_scan(
    tenant_id: str,
    config: ScanConfig,
    *,
    request: dict | None = None,
    requested_by: str = "",
    scan_label: str = "",
    compliance_enabled: bool = False,
    compliance_frameworks: Iterable[str] | None = None,
    job=None,
    max_files: int | None = None,
) -> dict | None:
    """Scan a local or SMB target one partition at a time; returns the compact report.

    Returns ``None`` when the target is not worth partitioning (see
    :func:`start_partitioned_scan`); the caller then runs an ordinary scan.

    It is :func:`start_partitioned_scan` then :func:`continue_partitioned_scan`, with no
    wall clock over either: each unit has its budget, and a scan that stops making progress
    is paused (W1.1). ``request`` is the scan request as the API validated it: with it the
    scan can be continued after a restart, without it it cannot.
    """
    stop_reason = _stop_check(job)
    record = start_partitioned_scan(
        tenant_id, config,
        request=request,
        requested_by=requested_by,
        scan_label=scan_label,
        compliance_enabled=compliance_enabled,
        compliance_frameworks=compliance_frameworks,
        job=job,
        max_files=max_files,
        stop_reason=stop_reason,
    )
    if record is None:
        return None
    return continue_partitioned_scan(tenant_id, record["scan_id"], config, job=job, stop_reason=stop_reason)
