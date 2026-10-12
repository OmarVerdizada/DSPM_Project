"""Partitioned scans: each partition persists as it finishes; finalize does the rest (B2.2b-B3).

A single scan holds every analyzed file until it saves them - the one holder of
the whole estate the earlier Phase B steps could not remove. A partitioned scan
analyzes one partition, writes it, and lets it go; memory follows the largest
partition instead of the estate. A local scan is cut into runs of its walk (B2.2b);
an SMB scan into ranges of its shares' folders, overlapping shares paired inside one unit
(B2.3, W1.2, W3.1). The plan is written to the ledger while it is made, beside the units
already running, and an interrupted plan continues from its cursor (W3.1).

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
import json
import logging
import os
import socket
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from backend import disk_guard, failures, store
from backend.compliance_service import ComplianceReportAccumulator
from collectors import scan_scope
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


def _stored_files_alive(tenant_id: str, scan_id: str, *, every_seconds: float = 30.0):
    """The scan's stored records, touching its record while they stream (W3.2).

    A finalize that streams a large estate is outside any transaction now, so it can show
    it is alive; the sweep takes a finalize over only once it has gone quiet."""
    touched = time.monotonic()
    for record in _stored_files(tenant_id, scan_id):
        yield record
        if time.monotonic() - touched > every_seconds:
            with suppress(Exception):
                store.touch_partitioned_scan(tenant_id, scan_id)
            touched = time.monotonic()


# finalize_scan without a depth limit: the units' merged one stands.
_FROM_UNITS = object()

# A unit is finished - finalize does not wait for it - once it is done or quarantined (W3.2).
FINISHED_UNIT_STATES = frozenset({"done", "quarantined"})


def quarantined_units_diagnostics(units: list[dict]) -> list[dict]:
    """The units a scan left out after they failed every attempt, named for its report."""
    named = []
    for unit in units:
        if unit.get("status") != "quarantined":
            continue
        spec = unit.get("spec") or {}
        where = spec.get("local_path") or "/".join(
            str(part) for part in (spec.get("share") or ",".join(spec.get("shares") or []), spec.get("folder"))
            if part
        ) or spec.get("path") or ""
        named.append({
            "partition_id": unit.get("partition_id"),
            "where": str(where)[:300],
            "attempts": store.data_attempts(unit),
            "interruptions": int(unit.get("interruptions") or 0),
            "error": str(unit.get("error") or "")[:200],
        })
    return named


def _mark_incomplete_units(diagnostics: dict, units: list[dict]) -> None:
    """A scan with a quarantined unit, or a unit that does not say whether it saw everything,
    is not complete - so finalize prunes nothing - and names the units (W3.2).

    A unit that says it was incomplete is already counted by the merge, which makes the scan
    complete only if every unit that reports completeness was. One that reports nothing - an
    empty or skipped unit - and a quarantined one, which wrote nothing, are not in that
    merge: without this they read as complete."""
    quarantined = quarantined_units_diagnostics(units)
    unsure = [
        str(unit.get("partition_id")) for unit in units
        if unit.get("status") == "done"
        and "complete" not in ((unit.get("diagnostics") or {}).get("incremental") or {})
    ]
    if not quarantined and not unsure:
        return
    incremental = diagnostics.get("incremental")
    incremental = dict(incremental) if isinstance(incremental, dict) else {}
    incremental["complete"] = False
    diagnostics["incremental"] = incremental
    if quarantined:
        diagnostics["quarantined_units"] = quarantined
    if unsure:
        diagnostics["incomplete_units"] = unsure[:50]
        diagnostics["incomplete_unit_count"] = len(unsure)


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
    report_extra: dict | None = None,
    depth_limit=_FROM_UNITS,
) -> dict:
    """Finish a partitioned scan whose partitions are all finished; returns its compact report.

    In recorded steps (W3.2), each of which an interrupted finalize does not redo:

    1. ``folded`` - one pass over the stored records folds the compliance sections and
       counts the files, one partition in memory at a time. The result is recorded.
    2. ``body`` - the report body is streamed to the artifact store, outside any
       transaction, touching the scan's record as it goes. Its reference is recorded.
    3. The short transaction writes the scan run, the prunes, the report row naming the
       body, and releases the partitions' records.

    A quarantined unit is left out, and the scan is incomplete, so nothing is pruned.
    Finalizing a scan that is already finalized returns its report, including when
    another finalize of it committed while this one was reading.

    ``depth_limit`` is the scan's configured limit (None: none): each unit's walk was told
    one relative to its own folder, and the scope block says the scan's (W3.6).
    """
    units = store.list_scan_partitions(tenant_id, scan_id)
    if not units or any(unit["status"] not in FINISHED_UNIT_STATES for unit in units):
        raise store.PartitionsNotFinished(f"scan {scan_id} has partitions that are not done")
    kept = [unit for unit in units if unit["status"] == "done"]
    if kept and not any(unit["has_records"] for unit in kept):
        existing = store.read_scan_report_compact(tenant_id, scan_id)
        if existing is not None:
            return existing
        raise store.PartitionsNotFinished(f"scan {scan_id} kept no records to finalize from")

    record = store.read_partitioned_scan(tenant_id, scan_id) or {}
    state = dict(record.get("finalize_state") or {})
    summary = summed_summary(kept)
    diagnostics = scan_diagnostics_for(kept, overrides=diagnostics_overrides, increments=diagnostics_increments)
    _mark_incomplete_units(diagnostics, units)
    # W3.6: the scope block describes the scan - its configured depth limit, the folders its
    # units did not enter, and whether its coverage is full - and so does its summary.
    merged_block = diagnostics.get("scope")
    if isinstance(merged_block, dict):
        scan_scope.settle(diagnostics, depth_limit=merged_block.get("depth_limit")
                          if depth_limit is _FROM_UNITS else depth_limit)
        summary.update(scan_scope.summary_fields(diagnostics))

    merged = None if state.get("folded") else _merged_folds(kept, compliance_enabled, compliance_frameworks)
    if state.get("folded"):
        sections = _read_finalize_part(tenant_id, state.get("sections_ref"), state.get("sections"))
        file_count, sample_count = int(state.get("file_count") or 0), int(state.get("sample_count") or 0)
    elif merged is not None:
        sections, file_count, sample_count = merged
        state = {"folded": True, "file_count": file_count, "sample_count": sample_count,
                 **_write_finalize_part(tenant_id, "sections", sections)}
        store.record_finalize_step(tenant_id, scan_id, "folded", state)
    else:
        accumulator = ComplianceReportAccumulator(compliance_enabled, compliance_frameworks)
        file_count = 0
        sample_count = 0
        try:
            for stored in _stored_files_alive(tenant_id, scan_id):
                accumulator.add(stored)
                file_count += 1
                if store.is_sample_data_path(stored):
                    sample_count += 1
        except store.PartitionsNotFinished:
            # Another finalize committed after the partitions were listed, and released
            # the records this pass was reading.
            existing = store.read_scan_report_compact(tenant_id, scan_id)
            if existing is None:
                raise
            return existing
        sections = accumulator.apply({})
        state = {"folded": True, "file_count": file_count, "sample_count": sample_count,
                 **_write_finalize_part(tenant_id, "sections", sections)}
        store.record_finalize_step(tenant_id, scan_id, "folded", state)

    # The bundled demo dataset never stays in the estate (B1.4): a whole scan of it does not
    # write it, and one partitioned like any folder (W3.1 - a demo larger than one unit is
    # not run whole) writes it unit by unit and takes it out again here.
    demo = bool(file_count) and sample_count / file_count >= 0.5 and not store._demo_assets_allowed_in_inventory()
    if demo:
        write_estate = False
    report = {
        "timestamp": timestamp,
        "source": source,
        "mode": str((diagnostics.get("incremental") or {}).get("mode") or "full"),
        "summary": summary,
        "files": store.StreamedFiles(lambda: _stored_files_alive(tenant_id, scan_id)),
        "scan_diagnostics": diagnostics,
    }
    report.update(sections)
    for key, value in (report_extra or {}).items():
        report.setdefault(str(key), value)
    label = str(scan_label or "").strip()[:80]
    if label:
        report["scan_label"] = label

    # The body is written before the transaction that decides these: it says them anyway.
    store.preview_finalize_decisions(tenant_id, scan_id, report)
    body = None
    if state.get("body_ref"):
        body = (str(state["body_ref"]), int(state.get("body_bytes") or 0))
    elif store.store_report_body() and store.report_artifacts_enabled() and kept:
        try:
            body_ref, body_bytes, _inline = store._store_report_body(tenant_id, report)
        except store.PartitionsNotFinished:
            existing = store.read_scan_report_compact(tenant_id, scan_id)
            if existing is None:
                raise
            return existing
        body = (body_ref, body_bytes)
        state = {**state, "body_ref": body_ref, "body_bytes": body_bytes}
        store.record_finalize_step(tenant_id, scan_id, "body", state)
    try:
        store.finalize_partitioned_scan(
            tenant_id, scan_id, report,
            write_estate=write_estate, file_count=file_count, sample_count=sample_count, body=body,
        )
    except store.ScanAlreadyFinalized:
        existing = store.read_scan_report_compact(tenant_id, scan_id)
        if existing is None:
            raise
        return existing
    if demo:
        store.purge_demo_sample_assets(tenant_id)
    return store.compact_scan_report_from_counts(report, file_count, sample_count)


# W4.2: the version of a unit's fold - its section partial, files and demo samples.
_FOLD_VERSION = 1


def unit_fold(compliance_enabled: bool, compliance_frameworks: Iterable[str] | None) -> Callable[[list], dict]:
    """``fold(records)``: what finalize's pass over a unit's stored records would have
    folded, stated when the unit is written (W4.2) - so finalize merges states instead of
    reading every unit's records back, and a skipped unit keeps the state its last read had."""
    frameworks = list(compliance_frameworks or [])

    def fold(records: list) -> dict:
        accumulator = ComplianceReportAccumulator(compliance_enabled, frameworks)
        samples = 0
        for record in records:
            accumulator.add(record)
            if store.is_sample_data_path(record):
                samples += 1
        return {"v": _FOLD_VERSION, "sections": accumulator.partial(), "files": len(records), "samples": samples}

    return fold


def _merged_folds(units: list[dict], compliance_enabled: bool, compliance_frameworks) -> tuple[dict, int, int] | None:
    """The scan's sections, files and samples from its units' folds, in plan order - or
    None when a unit has none (written before W4.2) or folded under other frameworks, and
    finalize reads the records back as it always did."""
    folds = [unit.get("fold") for unit in units]
    if not units or any(not isinstance(fold, dict) or fold.get("v") != _FOLD_VERSION for fold in folds):
        return None
    accumulator = ComplianceReportAccumulator(compliance_enabled, list(compliance_frameworks or []))
    try:
        for position, fold in enumerate(folds):
            accumulator.merge(fold.get("sections") or {}, position)
    except ValueError:
        return None
    return (accumulator.apply({}), sum(int(fold.get("files") or 0) for fold in folds),
            sum(int(fold.get("samples") or 0) for fold in folds))


def _write_finalize_part(tenant_id: str, name: str, value) -> dict:
    """Keep a finalize step's result: an artifact when the tier is on, else inline."""
    if store.report_artifacts_enabled():
        from backend import artifacts

        ref = artifacts.put_stream(tenant_id, iter([json.dumps(value, ensure_ascii=False, default=str)]))
        return {f"{name}_ref": ref.content_id}
    return {name: value}


def _read_finalize_part(tenant_id: str, ref, inline):
    if ref:
        from backend import artifacts

        return json.loads(artifacts.get_text(tenant_id, str(ref)) or "{}")
    return inline if isinstance(inline, dict) else {}


# ---- settings ----------------------------------------------------------------------------------------------


def partitioned_scans_enabled() -> bool:
    """Every local, SMB and remote endpoint scan runs partitioned (W1.1; the switch retired
    in W4.6).

    The single path holds the whole estate in memory and had a wall clock; this one holds a
    unit at a time, has none, continues after a restart (B2.4), skips unchanged units
    (W4.2) and is what admission and the pre-flight bound (W4.6). A target that fits one
    unit still runs as an ordinary scan - the one case a scan runs whole. The
    ``DSPM_PARTITIONED_SCANS`` setting is no longer read, so no configuration opens the
    whole-estate path; its code stays only as the oracle the paging and endpoint parity
    tests compare against (they patch this function)."""
    return True


def partition_max_files() -> int:
    """The most files one local partition holds, and so what a local scan's memory follows."""
    try:
        return max(1, min(int(os.getenv("DSPM_PARTITION_MAX_FILES", "2000")), 1_000_000))
    except ValueError:
        return 2000


def partition_max_bytes() -> int:
    """The most an SMB partition reads, counting each file up to the read cap (W1.2).

    ``DSPM_PARTITION_MAX_BYTES``, half a gibibyte by default. A partition bounded by files
    alone could hold 2,000 files of 100 MB each; the scan holds what a partition reads.
    """
    try:
        return max(1, min(int(os.getenv("DSPM_PARTITION_MAX_BYTES") or str(512 * 1024 * 1024)), 1 << 40))
    except ValueError:
        return 512 * 1024 * 1024


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
    """How long a finalize may look idle before it is taken for dead: three leases, at least ten minutes.

    A finalize now streams the body outside any transaction and touches the scan's record as
    it goes (W3.2), and its one transaction is short; an hour was the price of the old single
    transaction that could not touch the record while it streamed."""
    return max(3 * partition_lease_seconds(), 600)


def infra_retries() -> int:
    """How many times in a row the runner retries an infrastructure failure - the database,
    the target, the disk - before it pauses the scan (``DSPM_INFRA_RETRIES``, W3.2)."""
    try:
        return max(1, min(int(os.getenv("DSPM_INFRA_RETRIES") or "4"), 20))
    except ValueError:
        return 4


def infra_retry_seconds() -> float:
    """The first wait between those retries; it doubles each time, to at most 30 s
    (``DSPM_INFRA_RETRY_SECONDS``)."""
    try:
        return max(0.0, min(float(os.getenv("DSPM_INFRA_RETRY_SECONDS") or "2"), 30.0))
    except ValueError:
        return 2.0


def breaker_seconds() -> int:
    """How long a scan whose target could not be reached stays paused before it is tried
    again (``DSPM_SCAN_BREAKER_SECONDS``, five minutes by default). Its units keep their
    attempts meanwhile."""
    try:
        return max(0, min(int(os.getenv("DSPM_SCAN_BREAKER_SECONDS") or "300"), 86_400))
    except ValueError:
        return 300


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


def max_running_scans() -> int:
    """``DSPM_MAX_RUNNING_SCANS`` (2; W4.6): how many scans run at once on this installation,
    across its processes. A node profile sets it (16 GB: 1, 32 GB: 2)."""
    try:
        return max(1, min(int(os.getenv("DSPM_MAX_RUNNING_SCANS") or 2), 64))
    except ValueError:
        return 2


# W4.6: how long a scan waiting for a slot sleeps before it is tried again.
ADMISSION_RETRY_SECONDS = 30


def _admit(scan: "_Scan") -> None:
    """Run only once admitted (W4.6); otherwise pause, saying how many are running.

    A scan holds its slot until it has looked idle as long as the sweep waits before taking
    a finalize for dead - a slow finalize touches its record only every 30 s. One whose
    runner died keeps the slot only until the sweep resumes it, and its new runner is the
    one already admitted."""
    limit = max_running_scans()
    admitted, running = store.admit_partitioned_scan(scan.tenant_id, scan.scan_id, limit=limit,
                                                     alive_seconds=finalize_stale_seconds())
    if not admitted:
        raise _pause_scan(scan, f"waiting for a scan slot: {running} of {limit} scans are running on this "
                                f"installation (DSPM_MAX_RUNNING_SCANS)", seconds=ADMISSION_RETRY_SECONDS)


def unchanged_unit_skip() -> bool:
    """``DSPM_UNCHANGED_UNIT_SKIP`` (on by default, W4.2): a local scan's unit whose listing
    is what its last read saw is not read again. Off, every unit is read - with per-file
    reuse - as before; a scan with incremental reuse off reads every unit either way."""
    return os.getenv("DSPM_UNCHANGED_UNIT_SKIP", "1").strip().lower() not in {"0", "false", "no", "off"}


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


CANCEL_REASON = "Scan cancelled"


class ScanStopped(RuntimeError):
    """A partitioned scan stopped for good. Only a cancel (``ScanCancelled``) or an error that
    is not an infrastructure one does this now (W3.2): a unit out of attempts is quarantined,
    and an outage pauses. A scan whose process died has not stopped - the resume sweep
    continues it.
    """


class ScanCancelled(ScanStopped):
    """The scan was cancelled: recorded as ``cancelled`` on the scan, so nothing resumes it."""


class UnitInterrupted(RuntimeError):
    """A unit stopped for an infrastructure reason; it was put back without spending an attempt."""

    def __init__(self, message: str, *, target: bool = False) -> None:
        super().__init__(message)
        self.target = target


def _stopped(reason: str) -> ScanStopped:
    return ScanCancelled(reason) if str(reason or "").startswith(CANCEL_REASON) else ScanStopped(reason)


class ScanPaused(RuntimeError):
    """A partitioned scan stopped making progress, and its runner let it go (W1.1).

    Nothing is marked failed: the scan stays unfinished, and once nothing has touched it
    for a lease the resume sweep continues it under the same job. Only a scan that cannot
    be resumed - started without a request - is failed instead, since nothing would ever
    pick it up again; ``resumable`` then says so to the job.
    """

    resumable = True


class PartitionOverBudget(RuntimeError):
    """A unit's engine ran out of its time budget before it had read everything."""


class PartitionConnectionLost(RuntimeError):
    """A unit's SMB session kept resetting, so it did not read everything (W1.2)."""


# W1.3: a source whose units are not an engine run - an endpoint's folder frontier - runs
# them through a runner of its own: runner(scan, unit, job=..., stop_reason=...) returns the
# partition's (header, records, new_units). backend.app registers the endpoint's.
_UNIT_RUNNERS: dict[str, Callable] = {}


def register_unit_runner(source: str, runner: Callable) -> None:
    _UNIT_RUNNERS[str(source)] = runner


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
            return CANCEL_REASON
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
        reason = (CANCEL_REASON if status == "cancelled"
                  else str((record or {}).get("error") or "") or f"scan {scan_id} is {status}")
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
    max_depth: int | None
    worker: str
    lease_seconds: int
    # What the finished report carries beside its files (an endpoint scan's "endpoint").
    report_extra: dict = field(default_factory=dict)


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
        max_depth=_depth(header.get("max_depth", config.max_depth)),
        worker=worker or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}",
        lease_seconds=partition_lease_seconds(),
        report_extra=dict(header.get("report_extra") or {}),
    )


def _depth(value) -> int | None:
    """A recorded depth limit: a number, or None - no limit (W3.6; every folder entered)."""
    return None if value in (None, "") else int(value)


def _unit_config(config: ScanConfig, spec: dict, scan_root: str) -> ScanConfig:
    """One local partition's engine: the scan's policy, scope and reuse, over one run.

    Incremental reuse, the persistent cache and the baseline probe carry over
    unchanged - every partition probes and writes under the scan's own scope, and
    finalize prunes that scope once - so a partitioned re-scan reuses exactly what a
    single one would. Progress is the runner's to report, per partition.
    """
    names = spec.get("names")
    return replace(
        config,
        local_path=str(spec["local_path"]),
        max_depth=_depth(spec.get("max_depth")),
        # No names: the whole folder (a resumed plan that found the target fits one unit).
        local_entry_names=tuple(names) if names is not None else None,
        scan_root=scan_root,
        progress_callback=None,
        max_seconds=partition_max_seconds(),
    )


def _share_unit_config(config: ScanConfig, spec: dict, *, tenant_id: str = "", listing_ref: str = "") -> ScanConfig:
    """One SMB partition's engine: the scan's policy, scope and reuse, over one group of
    shares - or, W1.2, over one range of one folder of a share - or, W3.1, over the same
    range in every share that reaches it, with the listing slices the planner kept."""
    if spec.get("kind") == "smb_range" and spec.get("ranges"):
        slices = _unit_listing(tenant_id, listing_ref)
        ranges = []
        for index, item in enumerate(spec["ranges"]):
            unit_range = {key: item.get(key) for key in ("share", "folder", "depth", "name_from", "name_to")}
            entries = slices[index] if isinstance(slices, list) and index < len(slices) else item.get("entries")
            if entries is not None:
                unit_range["entries"] = entries
            ranges.append(unit_range)
        shares = tuple(dict.fromkeys(str(item["share"]) for item in ranges))
        return replace(config, smb_shares=shares, smb_range=None, smb_ranges=tuple(ranges),
                       smb_covered=spec.get("covered") or None, progress_callback=None,
                       max_seconds=partition_max_seconds())
    if spec.get("kind") == "smb_range":
        unit = {key: spec.get(key) for key in ("share", "folder", "depth", "name_from", "name_to")}
        return replace(config, smb_shares=(str(spec["share"]),), smb_range=unit, progress_callback=None,
                       max_seconds=partition_max_seconds())
    return replace(config, smb_shares=tuple(spec.get("shares") or ()), progress_callback=None,
                   max_seconds=partition_max_seconds())


def _unit_listing(tenant_id: str, listing_ref: str):
    """A range unit's listing slices, kept by its planner (W3.1). A slice that is gone is
    listed again by the unit itself - slower, never wrong."""
    if not listing_ref:
        return None
    from backend import artifacts

    try:
        return json.loads(artifacts.get_text(tenant_id, str(listing_ref)) or "null")
    except (FileNotFoundError, KeyError, ValueError):
        logger.warning("Listing slice %s is gone; the unit lists its folder itself", listing_ref)
        return None


def _stash_listing(tenant_id: str, unit: dict) -> tuple[dict, str]:
    """An SMB range unit's listing slices go to an artifact its runner reads (W3.1), so the
    ledger row stays small. Without the artifact tier they stay in the unit."""
    ranges = unit.get("ranges")
    if not ranges or not any(item.get("entries") is not None for item in ranges) \
            or not store.report_artifacts_enabled():
        return unit, ""
    from backend import artifacts

    spec = dict(unit)
    spec["ranges"] = [{key: value for key, value in item.items() if key != "entries"} for item in ranges]
    slices = [item.get("entries") for item in ranges]
    ref = artifacts.put_stream(tenant_id, iter([json.dumps(slices, ensure_ascii=False, separators=(",", ":"),
                                                           default=str)]))
    return spec, ref.content_id


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


class _PreflightRefused(RuntimeError):
    """The scan's planned reads would not fit the disk (W4.6): the message has the numbers."""


class _PlanConflict(RuntimeError):
    """Another planner moved this scan's cursor first: this one stops."""


# A batch of units commits once it has this many, or once this long has passed.
_PLAN_BATCH_UNITS = 16
_PLAN_BATCH_SECONDS = 1.0
_planners: dict[tuple[str, str], "_LedgerPlanner"] = {}
_planners_lock = threading.Lock()


class _LedgerPlanner:
    """Walks a scan's target and appends its units to the ledger as they are cut (W3.1).

    It runs in a thread beside the scan's runner, so the first unit runs before planning
    ends. Each batch commits with the cursor after its last unit, under a compare-and-set
    on the cursor before it: a planner interrupted at any point - a restart, an outage -
    continues after the last batch that committed, and nothing is written twice.

    The first unit waits for a second: a plan of one unit is the one case a scan runs
    whole, and it is decided before a unit is written. A planning failure of the database,
    the disk or the target is retried with back-off and then pauses the scan (W3.2); the
    plan is continued by whoever resumes it. Nothing here ever runs a scan unpartitioned.
    """

    def __init__(self, record: dict, config: ScanConfig, *, stop_reason, files_budget: int, resumed: bool,
                 written: int) -> None:
        self.tenant_id = str(record["tenant_id"])
        self.scan_id = str(record["scan_id"])
        self.config = config
        self.remote = bool(config.server)
        self.files_budget = max(1, int(files_budget))
        self.bytes_budget = partition_max_bytes()
        self.cursor = record.get("plan_cursor")
        self.resumed = resumed
        self.written = int(written)
        self.pending: list[tuple[dict, dict]] = []
        self.outcome = ""
        self.error = ""
        self.last_activity = self.flushed_at = time.monotonic()
        self.decided = threading.Event()
        self.finished = threading.Event()
        self._job_stop = stop_reason
        self._scan_stop = _scan_ended_check(self.tenant_id, self.scan_id)
        self._touched = time.monotonic()
        self.thread: threading.Thread | None = None
        self._header = dict(record.get("header") or {})
        self._skip: dict | None = None

    def start(self) -> "_LedgerPlanner":
        self.thread = threading.Thread(target=self._run, name=f"plan-{self.scan_id}", daemon=True)
        self.thread.start()
        return self

    def alive(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    # -- the walk ------------------------------------------------------------------------

    def _stop(self) -> str | None:
        """The cutter asks before every folder: a stop, and the planner's sign of life."""
        reason = self._job_stop() or self._scan_stop()
        if reason:
            return reason
        now = time.monotonic()
        self.last_activity = now
        if now - self._touched > max(1.0, partition_lease_seconds() / 3):
            self._touched = now
            store.touch_partitioned_scan(self.tenant_id, self.scan_id)
        if self.pending and self.written and now - self.flushed_at >= _PLAN_BATCH_SECONDS:
            self._flush()  # units waiting while a large folder is walked: let them run
        return None

    def _emit(self, unit: dict, cursor) -> None:
        self.pending.append((unit, cursor if isinstance(cursor, dict) else {"path": list(cursor)}))
        held = self.written + len(self.pending)
        if held < 2:
            return  # one unit alone may be the whole plan
        if not self.written or len(self.pending) >= _PLAN_BATCH_UNITS \
                or time.monotonic() - self.flushed_at >= _PLAN_BATCH_SECONDS:
            self._flush()

    def _flush(self) -> None:
        if not self.pending:
            return
        batch, self.pending = self.pending, []
        specs: list[dict] = []
        refs: list[str] = []
        for unit, _cursor in batch:
            spec, ref = _stash_listing(self.tenant_id, unit)
            specs.append(spec)
            refs.append(ref)
        cursor = batch[-1][1]
        ids = store.append_planned_units(self.tenant_id, self.scan_id, specs, cursor=cursor,
                                         expected_cursor=self.cursor, listing_refs=refs, skip=self._skip_context())
        if ids is None:
            raise _PlanConflict(f"scan {self.scan_id} is no longer planned from this cursor")
        self.cursor = cursor
        self.written += len(ids)
        self.flushed_at = time.monotonic()
        if self.written >= 2:
            self.decided.set()
        self._preflight()

    def _preflight(self) -> None:
        """Refuse the scan while what its planned units still have to read will not fit
        (W4.6). Checked as the plan grows: an estate is known to be too large the moment the
        projection for its planned reads passes what the volumes can take above their floor
        - not when the disk fills. A unit skipped as unchanged writes nothing; one already
        written is in the free space measured."""
        reason = disk_guard.preflight_reason(store.pending_read_files(self.tenant_id, self.scan_id,
                                                                      self.files_budget))
        if reason:
            raise _PreflightRefused(reason)

    def _skip_context(self) -> dict | None:
        """What a unit's last read must have been made under for this scan to skip it (W4.2):
        the incremental scope, and the policy digest - the engine's version signature and the
        scan's compliance frameworks. None when this scan reads every unit."""
        if self._skip is None:
            self._skip = {}
            if (not self.remote and unchanged_unit_skip() and self.config.incremental_enabled
                    and self.config.incremental_scope and not store.store_report_body()):
                frameworks = ComplianceReportAccumulator(
                    bool(self._header.get("compliance_enabled")),
                    list(self._header.get("compliance_frameworks") or ())).framework_ids
                signature = DSPMDiscoveryEngine(self.config).version_signature()
                self._skip = {"scope_key": str(self.config.incremental_scope),
                              "policy_digest": store.unit_policy_digest(signature, frameworks)}
        return self._skip or None

    def _walk(self):
        if self.remote:
            return plan_share_partitions(self.config, stop_check=self._stop, max_files=self.files_budget,
                                         max_bytes=self.bytes_budget, emit=self._emit, cursor=self.cursor)
        return plan_bounded_partitions(self.config, max_files=self.files_budget, max_bytes=self.bytes_budget,
                                       stop_check=self._stop, emit=self._emit,
                                       cursor=tuple((self.cursor or {}).get("path") or ()))

    def _whole_unit(self) -> dict:
        """A resumed plan whose target now fits one unit: one unit over all of it."""
        root = str(Path(self.config.local_path).expanduser().resolve())
        return {"kind": "run", "local_path": root, "max_depth": _depth(self.config.max_depth)}

    def _run(self) -> None:
        strikes = 0
        try:
            while True:
                try:
                    found = self._walk()
                    break
                except _PlanConflict as conflict:
                    self.outcome, self.error = "conflict", str(conflict)
                    return
                except _PreflightRefused as refused:
                    # Paused, not failed: the resume sweep tries it again, and it runs once the
                    # space is there. Its reason says how much is missing where.
                    with suppress(Exception):
                        store.pause_partitioned_scan(self.tenant_id, self.scan_id, f"pre-flight: {refused}",
                                                     seconds=breaker_seconds())
                    self.outcome, self.error = "paused", str(refused)
                    return
                except Exception as exc:  # noqa: BLE001 - classified below; nothing escapes the thread
                    reason = self._job_stop() or self._scan_stop()
                    if reason:
                        self.outcome, self.error = "stopped", reason
                        return
                    if not failures.is_infrastructure(exc):
                        logger.exception("Planning scan %s failed", self.scan_id)
                        self.outcome, self.error = "failed", type(exc).__name__
                        return
                    strikes += 1
                    self.pending = []  # replanned from the last cursor that committed
                    logger.warning("Planning scan %s: infrastructure failure %s of %s (%s)", self.scan_id, strikes,
                                   infra_retries(), failures.describe(exc))
                    if strikes >= infra_retries():
                        target = self.remote or failures.is_target_unreachable(exc)
                        what = "its target cannot be reached" if target else failures.describe(exc)
                        with suppress(Exception):
                            store.pause_partitioned_scan(self.tenant_id, self.scan_id, f"planning stopped: {what}",
                                                         seconds=breaker_seconds() if target else 60)
                        self.outcome, self.error = "paused", what
                        return
                    if self._sleep(min(30.0, infra_retry_seconds() * 2 ** (strikes - 1))):
                        self.outcome, self.error = "stopped", self._job_stop() or self._scan_stop() or ""
                        return
            if found is None and not self.resumed and self.written == 0 and len(self.pending) <= 1:
                self.outcome = "whole"
                return
            if found is None and self.written == 0 and not self.pending and not self.remote:
                self.pending.append((self._whole_unit(), {"path": ["\U0010ffff"]}))
            for attempt in range(max(1, infra_retries())):
                try:
                    self._flush()
                    if not store.finish_planning(self.tenant_id, self.scan_id, expected_cursor=self.cursor):
                        self.outcome, self.error = "conflict", "the plan was finished elsewhere"
                        return
                    break
                except _PlanConflict as conflict:
                    self.outcome, self.error = "conflict", str(conflict)
                    return
                except _PreflightRefused as refused:
                    # Paused, not failed: the resume sweep tries it again, and it runs once the
                    # space is there. Its reason says how much is missing where.
                    with suppress(Exception):
                        store.pause_partitioned_scan(self.tenant_id, self.scan_id, f"pre-flight: {refused}",
                                                     seconds=breaker_seconds())
                    self.outcome, self.error = "paused", str(refused)
                    return
                except Exception as exc:  # noqa: BLE001
                    if not failures.is_infrastructure(exc) or attempt + 1 >= infra_retries():
                        self.outcome, self.error = ("paused" if failures.is_infrastructure(exc) else "failed",
                                                    failures.describe(exc))
                        return
                    time.sleep(min(30.0, infra_retry_seconds() * 2 ** attempt))
            self.outcome = "planned"
        finally:
            self.decided.set()
            self.finished.set()

    def _sleep(self, seconds: float) -> bool:
        """Back off; True if the scan was stopped meanwhile."""
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            if self._job_stop() or self._scan_stop():
                return True
            time.sleep(min(0.5, max(0.0, until - time.monotonic())))
        return False


def _start_planner(record: dict, config: ScanConfig, *, stop_reason, files_budget: int, resumed: bool,
                   written: int) -> _LedgerPlanner:
    key = (str(record["tenant_id"]), str(record["scan_id"]))
    with _planners_lock:
        current = _planners.get(key)
        if current is not None and current.alive():
            return current
        planner = _LedgerPlanner(record, config, stop_reason=stop_reason, files_budget=files_budget,
                                 resumed=resumed, written=written)
        _planners[key] = planner
    return planner.start()


def _planner_here(tenant_id: str, scan_id: str) -> _LedgerPlanner | None:
    with _planners_lock:
        return _planners.get((str(tenant_id), str(scan_id)))


def _forget_planner(tenant_id: str, scan_id: str) -> None:
    with _planners_lock:
        planner = _planners.get((str(tenant_id), str(scan_id)))
        if planner is not None and not planner.alive():
            _planners.pop((str(tenant_id), str(scan_id)), None)


def _ensure_planner(record: dict, config: ScanConfig, *, stop_reason) -> _LedgerPlanner | None:
    """A scan still being planned has a live planner in this process - this one's, or one
    started here from the scan's cursor (W3.1). ``None`` once its plan is finished."""
    if str(record.get("plan_state") or "planned") != "planning":
        return None
    if store.scan_is_paused(record):
        raise ScanPaused(f"Scan paused: {record.get('pause_reason') or 'planning stopped'}; it continues "
                         "automatically")
    current = _planner_here(record["tenant_id"], record["scan_id"])
    if current is not None and current.alive():
        return current
    written = int(store.scan_partition_summary(record["tenant_id"], record["scan_id"]).get("partitions") or 0)
    header = record.get("header") or {}
    return _start_planner(record, config, stop_reason=stop_reason,
                          files_budget=int(header.get("max_files") or partition_max_files()),
                          resumed=True, written=written)


def join_planners(timeout: float = 30.0) -> int:
    """Wait for every planner thread of this process to end; returns how many still run."""
    deadline = time.monotonic() + max(0.0, timeout)
    with _planners_lock:
        planners = list(_planners.values())
    for planner in planners:
        if planner.thread is not None:
            planner.thread.join(max(0.0, deadline - time.monotonic()))
    return sum(1 for planner in planners if planner.alive())


def wait_for_plan(tenant_id: str, scan_id: str, timeout: float | None = None) -> str:
    """Wait until this process's planner of a scan has finished; returns its outcome, or the
    scan's plan state when no planner of it runs here. For a caller that needs every unit -
    the units themselves run while the plan grows (W3.1)."""
    planner = _planner_here(tenant_id, scan_id)
    if planner is not None:
        planner.finished.wait(timeout)
        return planner.outcome or "planning"
    record = store.read_partitioned_scan(tenant_id, scan_id) or {}
    return str(record.get("plan_state") or "planned")


def _planning_settled(scan: "_Scan", *, stop_reason) -> bool:
    """Whether the scan's plan is finished; raises when its planner stopped for good or paused."""
    record = store.read_partitioned_scan(scan.tenant_id, scan.scan_id) or {}
    if str(record.get("plan_state") or "planned") == "planned":
        _forget_planner(scan.tenant_id, scan.scan_id)
        return True
    planner = _planner_here(scan.tenant_id, scan.scan_id)
    if planner is not None and planner.finished.is_set():
        _forget_planner(scan.tenant_id, scan.scan_id)
        if planner.outcome == "paused":
            raise ScanPaused(f"Scan paused: planning stopped - {planner.error}; it continues automatically")
        if planner.outcome == "stopped":
            raise _stopped(planner.error or CANCEL_REASON)
        if planner.outcome == "failed":
            raise ScanStopped(f"Planning the scan failed: {planner.error}")
        planner = None
    if planner is None:
        _ensure_planner(record, scan.config, stop_reason=stop_reason)
    return False


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
    """Record a local or SMB scan and start planning it into its ledger; returns the scan's record.

    The record is written before planning starts, and the plan is appended to the ledger
    while the planner walks (:class:`_LedgerPlanner`, W3.1): this returns as soon as the
    plan has two units, with the planner still running beside the units, so the first
    unit starts before planning ends - and a planner that is interrupted continues from
    its cursor. :func:`continue_partitioned_scan` runs the units and finalizes once the
    plan is finished.

    Returns ``None`` only when the plan proves the target fits one unit (a folder within
    the budgets, a server whose shares come to one unit): the caller runs an ordinary
    scan, and the record is discarded. A planning failure of the database, the disk or
    the target pauses the scan (:class:`ScanPaused`) instead of falling back to an
    unpartitioned scan; a target larger than one unit never runs whole (W3.1).

    The request is stored without secrets; a scan started without one is recorded but
    cannot be resumed - nothing could rebuild its engine.
    """
    from backend.jobs import collection_heartbeat

    stop_reason = stop_reason or _stop_check(job)
    budget = max_files or partition_max_files()
    remote = bool(config.server)
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
        "max_files": budget,
    }
    if not remote:
        header.update(
            local_path=config.local_path,
            max_depth=config.max_depth,
            scan_root=str(Path(config.local_path).expanduser().resolve()),
            host=socket.gethostname(),
        )
    record = store.register_partitioned_scan(
        tenant_id, scan_id, job_id=job_id, request=dict(request or {}), header=header,
        resumable=request is not None, planning=True,
    )
    planner = _start_planner(record, config, stop_reason=stop_reason, files_budget=budget, resumed=False, written=0)
    # Planning walks the target: no wall clock, only a cancel (W1.1).
    with collection_heartbeat(job, max_seconds=0) if job is not None else nullcontext():
        planner.decided.wait()
    if planner.outcome == "whole":
        _forget_planner(tenant_id, scan_id)
        for attempt in range(max(1, infra_retries())):
            try:
                store.discard_partitioned_scan(tenant_id, scan_id)
                break
            except Exception as exc:  # noqa: BLE001
                if not failures.is_infrastructure(exc) or attempt + 1 >= infra_retries():
                    raise
                time.sleep(min(30.0, infra_retry_seconds() * 2 ** attempt))
        return None
    if planner.outcome in {"stopped", "failed", "conflict"}:
        _forget_planner(tenant_id, scan_id)
        stopped = _stopped(planner.error) if planner.outcome == "stopped" \
            else ScanStopped(f"Planning the scan failed: {planner.error}")
        with suppress(Exception):
            store.mark_partitioned_scan(tenant_id, scan_id,
                                        "cancelled" if isinstance(stopped, ScanCancelled) else "failed",
                                        error=str(stopped))
        raise stopped
    if planner.outcome == "paused" and planner.written == 0:
        _forget_planner(tenant_id, scan_id)
        paused = ScanPaused(f"Scan paused: planning stopped - {planner.error}; it continues automatically")
        if not record.get("resumable"):
            paused.resumable = False
            with suppress(Exception):
                store.mark_partitioned_scan(
                    tenant_id, scan_id, "failed",
                    error="Planning the scan stopped and it cannot be resumed: it was started without a request "
                          "to rebuild it from. Run the scan again.",
                )
        raise paused
    return store.read_partitioned_scan(tenant_id, scan_id) or record


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

    What it costs to fail (W3.2): a unit out of attempts is quarantined and the scan
    finishes incomplete. An infrastructure failure - the database, the target, the disk -
    is retried with back-off and then pauses the scan (:class:`ScanPaused`); it is never
    marked failed for one, and no unit spends an attempt. A cancel is recorded on the scan
    as ``cancelled`` (:class:`ScanCancelled`), so nothing resumes it. Only an error of
    another kind - a defect - marks the scan failed.
    """
    record = store.read_partitioned_scan(tenant_id, scan_id)
    if record is None:
        raise LookupError(f"partitioned scan {scan_id} is not recorded")
    if record["status"] == "done":
        existing = store.read_scan_report_compact(tenant_id, scan_id)
        if existing is not None:
            return existing
    if record["status"] == "cancelled":
        raise ScanCancelled(CANCEL_REASON)
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
            # A scan still being planned continues its plan here, from its cursor (W3.1).
            _ensure_planner(record, config, stop_reason=stop_reason)
            _run_partitions(scan, job=job, stop_reason=stop_reason, poll_seconds=poll_seconds)
            return _finalize_when_claimed(scan, job=job, stop_reason=stop_reason, poll_seconds=poll_seconds)
        except ScanPaused as paused:
            if not record.get("resumable"):
                paused.resumable = False
                with suppress(Exception):
                    store.mark_partitioned_scan(
                        scan.tenant_id, scan.scan_id, "failed",
                        error="Scan stopped making progress and cannot be resumed: it was started without a "
                              "request to rebuild it from. Run the scan again.",
                    )
            raise
        except ScanCancelled:
            with suppress(Exception):
                store.mark_partitioned_scan(scan.tenant_id, scan.scan_id, "cancelled", error=CANCEL_REASON)
            raise
        except Exception as exc:
            if failures.is_infrastructure(exc) and not isinstance(exc, ScanStopped):
                # An outage is never a failed scan: the "failed" mark could land in a blip.
                paused = ScanPaused(f"Scan paused: {failures.describe(exc)}; it continues automatically")
                if not record.get("resumable"):
                    paused.resumable = False
                raise paused from exc
            with suppress(Exception):
                store.mark_partitioned_scan(
                    scan.tenant_id, scan.scan_id, "failed",
                    error=str(exc) if isinstance(exc, ScanStopped) else type(exc).__name__,
                )
            raise
    finally:
        with _running_here_lock:
            _running_here.discard(key)


def _pause_scan(scan: _Scan, reason: str, *, seconds: float) -> ScanPaused:
    """Pause the scan on its record - no worker or sweep takes it before ``seconds`` - and
    return the :class:`ScanPaused` to raise. The record may be out of reach (the database is
    the outage); the pause then rests on the scan going quiet for a lease."""
    with suppress(Exception):
        store.pause_partitioned_scan(scan.tenant_id, scan.scan_id, reason, seconds=seconds)
    return ScanPaused(f"Scan paused: {reason}; it continues automatically")


class _UnitProgress:
    """A scan's job as one of its units sees it (W5).

    A unit's runner reports progress as a whole scan would - an endpoint page moves the bar
    through the fetch band (46-60) and the analysis bands (60-90), and the collection
    heartbeat climbs to its ceiling - and wrote it straight onto the job. The first page of
    an endpoint scan, two files under the profile's roots, then left the bar at 94% while
    the 2,465 files under them were still to come. Through this proxy a unit's own
    progress (0-100) is a slice of the scan's bar, ``[base, base + span]``, and its message
    says which partition it is. Everything else is the job's.
    """

    def __init__(self, job, base: float, span: float, where: str) -> None:
        object.__setattr__(self, "scan_job", job)
        object.__setattr__(self, "_base", float(base))
        object.__setattr__(self, "_span", float(span))
        object.__setattr__(self, "_where", where)
        object.__setattr__(self, "_progress", 0)

    def __getattr__(self, name: str):
        if name == "progress":
            return self._progress
        return getattr(self.scan_job, name)

    def __setattr__(self, name: str, value) -> None:
        if name == "progress":
            local = max(0, min(100, int(value or 0)))
            object.__setattr__(self, "_progress", max(self._progress, local))
            mapped = int(self._base + self._span * self._progress / 100)
            if mapped > int(self.scan_job.progress or 0):
                self.scan_job.progress = mapped
        elif name == "message":
            self.scan_job.message = f"{value} - {self._where}" if value else value
        else:
            setattr(self.scan_job, name, value)


def _plan_may_grow(scan: _Scan) -> bool:
    """Whether units can still be added: an endpoint's folder frontier grows as its pages run
    (W1.3); a planned scan grows until its planner has recorded the whole plan (W3.1)."""
    if scan.source in _UNIT_RUNNERS:
        return True
    record = store.read_partitioned_scan(scan.tenant_id, scan.scan_id) or {}
    return str(record.get("plan_state") or "planned") != "planned"


def _record_may_grow(record: dict) -> bool:
    """``_plan_may_grow`` for a scan known only by its ledger record."""
    source = str((record.get("header") or {}).get("source") or "local")
    return source in _UNIT_RUNNERS or str(record.get("plan_state") or "planned") != "planned"


def _scan_progress(done: float, total: int, growing: bool) -> int:
    """The bar at ``done`` units of ``total``: 8-94, with one unit's room held back while the
    plan can grow - a scan whose remaining units are not yet known is never near done."""
    room = max(1, int(total) + (1 if growing else 0))
    return min(94, 8 + int(86 * min(float(done), room) / room))


def _unit_job(job, scan: _Scan, done: int, total: int, running: int = 1):
    """``job`` as the unit after ``done`` of ``total`` sees it, or None for no job."""
    if job is None:
        return None
    growing = _plan_may_grow(scan)
    room = max(1, int(total) + (1 if growing else 0))
    base = _scan_progress(done, total, growing)
    span = 86 / room
    where = (f"partition {min(done + 1, max(total, 1))} of {max(total, 1)}"
             + (", more may be found" if growing else ""))
    if running > 1:
        where = f"partitions {done + 1}-{done + running} of {max(total, done + running)}" \
                + (", more may be found" if growing else "")
    return _UnitProgress(job, base, span, where)


def _run_partitions(scan: _Scan, *, job, stop_reason, poll_seconds: float) -> None:
    state = store.scan_partition_summary(scan.tenant_id, scan.scan_id)
    record = store.read_partitioned_scan(scan.tenant_id, scan.scan_id) or {}
    if not state["partitions"] and str(record.get("plan_state") or "planned") != "planning":
        raise ScanStopped(f"scan {scan.scan_id} stopped before its plan was recorded")
    # W4.6: no unit is claimed before the scan holds one of the installation's slots.
    _admit(scan)
    total = int(state["partitions"])
    done = int(state["done"])
    max_attempts = partition_max_attempts()
    stall = scan_stall_seconds()
    sla = scan_sla_seconds()
    low_disk = disk_guard.ThrottledCheck()
    started = last_progress = time.monotonic()
    late = False
    workers = partition_workers()
    # Infrastructure failures in a row (W3.2): retried with back-off, then the scan pauses.
    strikes = 0
    # One unit at a time runs here, in the job's own thread, as it always has. More than
    # one run on a pool of their own (W1.1); a stop or a pause claims nothing more.
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="partition") if workers > 1 else None
    running: dict = {}

    def finished_one() -> None:
        nonlocal done, last_progress, total, strikes
        done += 1
        strikes = 0
        last_progress = time.monotonic()
        # A frontier grows as it runs (W1.3), and the units a page found are in the ledger
        # once it is written: the plan has as many as the ledger holds now (W5). The total
        # was only ever raised to the count done, so an endpoint scan's first page - its
        # plan's only unit when it started - took the bar to 94%.
        with suppress(Exception):
            total = max(total, int(store.scan_partition_summary(scan.tenant_id, scan.scan_id)["partitions"]))
        total = max(total, done)
        if job is not None:
            job.progress = max(job.progress, _scan_progress(done, total, _plan_may_grow(scan)))
            _share_progress(job)

    def claim():
        return store.claim_next_partition(
            scan.tenant_id, scan.scan_id, worker_id=scan.worker, lease_seconds=scan.lease_seconds,
        )

    def others_finished(finished: int, planned: int) -> None:
        nonlocal done, last_progress, total
        if finished > done:
            # Another worker finished one: that is progress too.
            done, last_progress = finished, time.monotonic()
        if planned > total:
            # The planner appended units (W3.1): progress, and a longer plan.
            total, last_progress = planned, time.monotonic()

    try:
        # A partition whose holder died is taken back once its lease has run out, with its
        # attempt given back (W3.2) - or quarantined, once it has been interrupted too often.
        store.requeue_expired_partitions(tenant_id=scan.tenant_id)
        while True:
            try:
                if _run_partitions_step(scan, job=job, stop_reason=stop_reason, poll_seconds=poll_seconds,
                                        low_disk=low_disk, pool=pool, running=running, workers=workers,
                                        claim=claim, finished_one=finished_one, max_attempts=max_attempts,
                                        progress=lambda: (done, total), others_finished=others_finished):
                    return
                now = time.monotonic()
                planner = _planner_here(scan.tenant_id, scan.scan_id)
                if planner is not None and planner.alive():
                    # A planner walking a large tree is the scan making progress.
                    last_progress = max(last_progress, planner.last_activity)
                if stall and now - last_progress > stall:
                    raise _pause_scan(scan, f"no partition of scan {scan.scan_id} finished in "
                                            f"{int(stall // 60)} minutes", seconds=0)
                if sla and not late and now - started > sla:
                    late = True
                    logger.warning("Partitioned scan %s is past its %s s SLA with %s of %s partitions done; it "
                                   "continues", scan.scan_id, sla, done, total)
                    if job is not None:
                        job.message = f"Scanning partition {done + 1} of {total} (past its expected time)"
            except (ScanStopped, ScanPaused):
                raise
            except Exception as exc:
                if not (isinstance(exc, UnitInterrupted) or failures.is_infrastructure(exc)):
                    raise
                strikes += 1
                target = getattr(exc, "target", False) or failures.is_target_unreachable(exc)
                logger.warning("Scan %s: infrastructure failure %s of %s (%s)", scan.scan_id, strikes,
                               infra_retries(), failures.describe(exc))
                if strikes >= infra_retries():
                    what = "its target cannot be reached" if target else f"{failures.describe(exc)}"
                    raise _pause_scan(scan, what, seconds=breaker_seconds() if target else 60) from exc
                time.sleep(min(30.0, infra_retry_seconds() * 2 ** (strikes - 1)))
    finally:
        if pool is not None:
            # Units still running end on their own - a cancel reaches their engines - or
            # are left to their leases; nothing waits here for one that hangs.
            pool.shutdown(wait=False, cancel_futures=True)


def _run_partitions_step(scan: _Scan, *, job, stop_reason, poll_seconds, low_disk, pool, running, workers,
                         claim, finished_one, max_attempts, progress, others_finished) -> bool:
    """One turn of the runner's loop; True once every unit is finished (done or quarantined)."""
    reason = stop_reason()
    if reason:
        raise _stopped(reason)
    full = low_disk()
    if full:
        # A volume this scan writes to is nearly full: writing on would stop PostgreSQL
        # (it cannot write WAL) and every scan and click with it. Paused, not failed -
        # the resume sweep continues the scan once there is room again.
        raise _pause_scan(scan, full, seconds=60)
    store.touch_partitioned_scan(scan.tenant_id, scan.scan_id)
    done, total = progress()
    if pool is None:
        unit = claim()
        if unit is not None:
            if job is not None:
                job.message = f"Scanning partition {done + 1} of {total}"
            if _run_unit(scan, unit, job=_unit_job(job, scan, done, total), stop_reason=stop_reason):
                finished_one()
            return False
    else:
        while len(running) < workers:
            unit = claim()
            if unit is None:
                break
            running[pool.submit(_run_unit, scan, unit, job=_unit_job(job, scan, done, total, workers),
                                stop_reason=stop_reason)] = unit
        if running:
            if job is not None:
                job.message = f"Scanning partitions {done + 1}-{min(total, done + len(running))} of {total}"
            complete, _pending = wait(list(running), timeout=poll_seconds, return_when=FIRST_COMPLETED)
            for future in complete:
                running.pop(future)
                if future.result():
                    finished_one()
            return False
    if store.requeue_failed_partitions(scan.tenant_id, scan.scan_id, max_attempts=max_attempts,
                                       backoff_seconds=partition_retry_seconds()):
        return False
    for unit in store.quarantine_exhausted_partitions(scan.tenant_id, scan.scan_id, max_attempts=max_attempts):
        logger.warning("Scan %s: %s - quarantined; the scan will finish incomplete",
                       scan.scan_id, _exhausted_message(unit))
    state = store.scan_partition_summary(scan.tenant_id, scan.scan_id)
    others_finished(int(state["done"]), int(state["partitions"]))
    if int(state["done"]) + int(state["quarantined"]) == int(state["partitions"]):
        # Every unit there is has finished: the scan has, once its plan has (W3.1).
        if _planning_settled(scan, stop_reason=stop_reason):
            return True
        time.sleep(poll_seconds)
        return False
    # What is left runs under another worker's lease: take back any that ran out, or wait.
    if not store.requeue_expired_partitions(tenant_id=scan.tenant_id):
        time.sleep(poll_seconds)
    return False


def _exhausted_message(unit: dict) -> str:
    return (f"partition {unit['partition_id']} failed {store.data_attempts(unit)} times "
            f"({unit['error'] or 'no error recorded'})")


@contextmanager
def _holding_lease(scan: _Scan, unit: dict):
    """Keep a claimed partition's lease, and its scan's sign of life, fresh while the partition runs.

    Only while the unit is inside its budget (W3.2): past ``DSPM_PARTITION_MAX_SECONDS`` and
    two leases more, a unit that has not ended is hung, and renewing its lease would keep its
    scan RUNNING for ever. The lease then runs out and the unit is taken back - with an
    interruption counted, and quarantined if it keeps happening.
    """
    stop = threading.Event()
    budget = partition_max_seconds()
    renew_until = time.monotonic() + budget + 2 * scan.lease_seconds if budget > 0 else None

    def renew() -> None:
        while not stop.wait(max(0.5, scan.lease_seconds / 3)):
            if renew_until is not None and time.monotonic() > renew_until:
                logger.warning("Partition %s of scan %s is past its %s s budget and has not ended: its lease is "
                               "no longer renewed", unit["partition_id"], scan.scan_id, budget)
                return
            try:
                if not store.renew_partition_lease(
                    scan.tenant_id, scan.scan_id, unit["partition_id"],
                    attempt=unit["attempt"], worker_id=scan.worker, lease_seconds=scan.lease_seconds,
                ):
                    return
                store.touch_partitioned_scan(scan.tenant_id, scan.scan_id)
            except Exception:  # noqa: BLE001 - a renewal that fails is tried again; the lease is the judge
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
            new_units: list[dict] | None = None
            runner = _UNIT_RUNNERS.get(scan.source)
            if runner is not None:
                header, records, new_units = runner(scan, unit, job=job, stop_reason=stop_reason)
                reason = stop_reason()
                if reason:
                    raise ScanStopped(reason)
                store.persist_partition(
                    scan.tenant_id, scan.scan_id, unit["partition_id"], unit["attempt"], header, records,
                    write_estate=True, new_units=new_units,
                    fold=unit_fold(scan.compliance_enabled, scan.compliance_frameworks),
                )
                return True
            if scan.source == "smb":
                engine_config = _share_unit_config(scan.config, unit["spec"], tenant_id=scan.tenant_id,
                                                   listing_ref=str(unit.get("listing_ref") or ""))
            elif not Path(scan.scan_root).is_dir():
                # Not a folder that vanished: the whole scan is out of reach from here.
                # Writing that as an empty partition would let finalize prune the estate.
                raise failures.TargetUnreachable(f"the scan root is not reachable from {socket.gethostname()}")
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
                diagnostics = report.get("scan_diagnostics") or {}
                over_budget = bool(diagnostics.get("scan_truncated")) \
                    or diagnostics.get("scan_aborted_reason") == "time_budget"
                if not over_budget \
                        and (diagnostics.get("shares_connection_reset") or diagnostics.get("scan_aborted_reason")) \
                        and int(unit.get("interruptions") or 0) + 1 < partition_max_attempts():
                    # A session that kept resetting: what it did not read is not gone, and
                    # writing the unit done would leave it missing until the next scan (W1.2).
                    # The target, not the unit: put back without an attempt (W3.2). After as
                    # many interruptions as the unit has attempts it is written, with the
                    # engine having marked the scan incomplete, so nothing under it is pruned;
                    # each run waits out the server's session backoff, so this is not more.
                    raise PartitionConnectionLost(
                        f"partition {unit['partition_id']}: the SMB session kept resetting "
                        f"({', '.join(map(str, diagnostics.get('shares_connection_reset') or [])) or 'aborted'})"
                    )
                if over_budget \
                        and store.data_attempts(unit) < partition_max_attempts():
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
                fold=unit_fold(scan.compliance_enabled, scan.compliance_frameworks),
            )
        return True
    except store.PartitionNotClaimed:
        return False
    except BaseException as exc:
        def give_back(why: str) -> None:
            with suppress(Exception):
                store.release_scan_partition(scan.tenant_id, scan.scan_id, unit["partition_id"], why,
                                             attempt=unit["attempt"])

        if not isinstance(exc, Exception) or isinstance(exc, ScanStopped):
            # A stop - a cancel, the process going down - is not the unit's failure.
            give_back("stopped")
            raise
        if isinstance(exc, store.ScanNotRunning):
            give_back("scan not running")
            raise ScanStopped(str(exc)) from exc
        reason = stop_reason()
        if reason:
            give_back("stopped")
            raise _stopped(reason) from exc
        if failures.is_infrastructure(exc):
            # The database, the target or the disk (W3.2): back in the queue with its
            # attempt, and the runner decides whether to retry or pause.
            give_back(failures.describe(exc))
            logger.warning("Partition %s of scan %s was interrupted on attempt %s: %s",
                           unit["partition_id"], scan.scan_id, unit["attempt"], failures.describe(exc))
            raise UnitInterrupted(failures.describe(exc), target=failures.is_target_unreachable(exc)) from exc
        with suppress(Exception):
            store.fail_scan_partition(
                scan.tenant_id, scan.scan_id, unit["partition_id"], type(exc).__name__, attempt=unit["attempt"],
            )
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

    A disk below its floor pauses the scan here too (W3.2): finalize writes the body and
    the report, and an out-of-space error there used to be a permanent ``failed``.
    """
    full = disk_guard.low_space_reason()
    if full:
        raise _pause_scan(scan, full, seconds=60)
    report = finalize_scan(
        scan.tenant_id, scan.scan_id,
        timestamp=scan.timestamp,
        source=scan.source,
        scan_label=scan.label,
        compliance_enabled=scan.compliance_enabled,
        compliance_frameworks=list(scan.compliance_frameworks),
        report_extra=scan.report_extra,
        write_estate=True,
        depth_limit=scan.max_depth,
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
        if current.get("status") == "cancelled":
            raise ScanCancelled(CANCEL_REASON)
        if current.get("status") == "failed":
            raise ScanStopped(current.get("error") or f"scan {scan.scan_id} failed")
        reason = stop_reason()
        if reason:
            raise _stopped(reason)
        time.sleep(poll_seconds)
    if job is not None:
        from backend.jobs import begin_saving

        # The finalize will land; from here the job refuses a cancel rather than call a
        # scan that is being written cancelled.
        if not begin_saving(job):
            raise ScanCancelled(CANCEL_REASON)
    return _finalize(scan)


# ---- run by a queue worker (B3) ----------------------------------------------------------------------------


def run_queued_partition(record: dict, config: ScanConfig, partition_id: str, *, worker_id: str) -> str:
    """Run one named partition of a recorded scan for a queue worker; returns what happened.

    ``written`` - this call ran and committed it. ``finished`` - it was already done.
    ``held`` - another worker holds it, or took it back while this call ran. ``retry`` -
    it failed and is queued in the ledger again. ``quarantined`` - it failed its last
    attempt and is left out; the scan will finish incomplete (W3.2). ``interrupted`` - the
    database, the target or the disk failed it; it is back in the queue with its attempt,
    and an unreachable target pauses the scan. ``paused`` - the disk is below its floor, or
    the scan is paused: nothing was run. ``dropped`` - the scan has no such partition, or it
    ended - cancelled, failed - while the partition ran, which was then not written.
    ``elsewhere`` - a local scan planned on another host, which this host must not run.

    The claim is the ledger's compare-and-set, so a duplicate delivery - the same
    partition handed to two workers, or handed out again after a commit - finds it done and
    runs nothing twice.
    """
    if not runs_here(record):
        return "elsewhere"
    if store.scan_is_paused(record):
        return "paused"
    scan = _scan_from_record(record, config, worker=worker_id)
    full = disk_guard.low_space_reason()
    if full:
        # W3.2: the floor holds in every executor, not only the console's own runner.
        with suppress(Exception):
            store.pause_partitioned_scan(scan.tenant_id, scan.scan_id, full, seconds=60)
        return "paused"
    # A worker has no job to be cancelled through: cancelling a queued scan marks the scan
    # cancelled. The partition's engine and its write both ask the scan's status, so a
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
        except UnitInterrupted as interrupted:
            if interrupted.target:
                # The target's breaker: no worker takes this scan's units until it ends.
                with suppress(Exception):
                    store.pause_partitioned_scan(scan.tenant_id, scan.scan_id, "its target cannot be reached",
                                                 seconds=breaker_seconds())
            return "interrupted"
    current = store.read_scan_partition(scan.tenant_id, scan.scan_id, partition_id)
    if current is None:
        return "dropped"
    if current["status"] == "done":
        return "finished"
    if current["status"] == "quarantined":
        return "quarantined"
    if current["status"] != "failed":
        return "held"
    max_attempts = partition_max_attempts()
    if store.data_attempts(current) < max_attempts:
        # Queued again once its wait is over - here if that is now, else by a worker's
        # maintenance pass.
        store.requeue_failed_partitions(scan.tenant_id, scan.scan_id, max_attempts=max_attempts,
                                        backoff_seconds=partition_retry_seconds())
        return "retry"
    store.quarantine_exhausted_partitions(scan.tenant_id, scan.scan_id, max_attempts=max_attempts)
    return "quarantined"


def settle_if_finished(record: dict, config: ScanConfig) -> str | None:
    """Finish a recorded scan nothing is left to run for; returns ``finalized`` or ``None``.

    A partition out of attempts is quarantined (W3.2) - it no longer fails the scan. Every
    partition done or quarantined: finalize it, unless another caller already is. Anything
    else: nothing to do yet. Queue workers call this after their writes and while they idle,
    so a scan whose last worker died between its commit and the finalize is still finished
    (B3 review). A finalize stopped by an outage or the disk floor is left for a later call;
    only an error of another kind marks the scan failed.
    """
    units = store.list_scan_partitions(record["tenant_id"], record["scan_id"])
    if not units:
        return None
    max_attempts = partition_max_attempts()
    if any(unit["status"] == "failed" and store.data_attempts(unit) >= max_attempts for unit in units):
        store.quarantine_exhausted_partitions(record["tenant_id"], record["scan_id"], max_attempts=max_attempts)
        units = store.list_scan_partitions(record["tenant_id"], record["scan_id"])
    if any(unit["status"] not in FINISHED_UNIT_STATES for unit in units):
        return None
    scan = _scan_from_record(record, config)
    if disk_guard.low_space_reason():
        return None
    if not store.claim_scan_finalize(scan.tenant_id, scan.scan_id, stale_after_seconds=finalize_stale_seconds()):
        return None
    try:
        _finalize(scan)
    except ScanPaused:
        return None
    except Exception as exc:
        if failures.is_infrastructure(exc):
            # Left finalizing; a later call takes it back once it has gone quiet.
            logger.warning("Finalize of scan %s was interrupted: %s", scan.scan_id, failures.describe(exc))
            return None
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
    total = max(1, int(store.scan_partition_summary(tenant_id, scan_id)["partitions"]))
    while True:
        record = store.read_partitioned_scan(tenant_id, scan_id)
        if record is None:
            raise LookupError(f"partitioned scan {scan_id} is not recorded")
        if record["status"] == "done":
            report = store.read_scan_report_compact(tenant_id, scan_id)
            if report is None:
                raise ScanStopped(f"scan {scan_id} finished, but its report is gone")
            return report
        if record["status"] == "cancelled":
            raise ScanCancelled(CANCEL_REASON)
        if record["status"] == "failed":
            raise ScanStopped(record["error"] or f"scan {scan_id} failed")
        if job is not None and job.cancel_requested:
            # The workers read the status before every partition, so this stops them; the
            # cancel is on the scan's record, so no restart resumes it (W3.2).
            store.mark_partitioned_scan(tenant_id, scan_id, "cancelled", error=CANCEL_REASON)
            raise ScanCancelled(CANCEL_REASON)
        if time.monotonic() > deadline:
            raise ScanStopped(f"no worker finished scan {scan_id} within the queue wait")
        planner = _planner_here(tenant_id, scan_id)
        if planner is not None and planner.finished.is_set() and planner.outcome == "paused" \
                and record.get("plan_state") == "planning" and not store.scan_is_paused(record):
            # This process planned the scan, and its pause is over: plan on (W3.1).
            with suppress(ScanPaused):
                _ensure_planner(record, planner.config, stop_reason=planner._job_stop)
        if job is not None:
            state = store.scan_partition_summary(tenant_id, scan_id)
            total = max(total, int(state.get("partitions") or 0))
            done = int(state.get("done") or 0)
            job.progress = max(job.progress, _scan_progress(done, total, _record_may_grow(record)))
            if store.scan_is_paused(record):
                # No worker takes a paused scan: said as a pause, with its reason, in the
                # words a paused job uses - not as a worker scanning the next partition.
                from backend.jobs import _safe_job_error

                job.message = _safe_job_error(Exception(f"Scan paused: {record.get('pause_reason') or ''}"))
            else:
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
