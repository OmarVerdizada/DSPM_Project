"""Partitioned scans: each partition persists as it finishes; finalize does the rest (B2.2b).

A single scan holds every analyzed file until it saves them - the one holder of
the whole estate the earlier Phase B steps could not remove. A partitioned scan
analyzes one partition, writes it, and lets it go; memory follows the largest
partition instead of the estate.

What needs the whole scan happens once, at finalize, from what the partitions
stored: the summary is the sum of the partitions' summaries, the diagnostics are
merged, the compliance sections are folded one stored record at a time, and the
report body is streamed from the partitions' records in plan order.
"""

from __future__ import annotations

import os
import time
from contextlib import nullcontext
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from backend import store
from backend.compliance_service import ComplianceReportAccumulator
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.partition import plan_bounded_partitions


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
    report has. Finalizing a scan that is already finalized returns its report.
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
    for record in _stored_files(tenant_id, scan_id):
        sections.add(record)
        file_count += 1
        if store.is_sample_data_path(record):
            sample_count += 1

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
    store.finalize_partitioned_scan(
        tenant_id, scan_id, report,
        write_estate=write_estate, file_count=file_count, sample_count=sample_count,
    )
    return store.compact_scan_report_from_counts(report, file_count, sample_count)


# ---- running one -------------------------------------------------------------------------------------------


def partitioned_scans_enabled() -> bool:
    """Whether local scans run partitioned. Off by default.

    It stays off until B2.4: a partitioned scan interrupted part way through leaves
    its finished partitions in the estate with no report, and until startup resumes
    it, that is a worse failure than a single scan that saved nothing.
    """
    return os.getenv("DSPM_PARTITIONED_SCANS", "0").strip().lower() in {"1", "true", "yes", "on"}


def partition_max_files() -> int:
    """The most files one partition holds, and so what a scan's memory follows."""
    try:
        return max(1, min(int(os.getenv("DSPM_PARTITION_MAX_FILES", "2000")), 1_000_000))
    except ValueError:
        return 2000


def _unit_config(config: ScanConfig, spec: dict, scan_root: str) -> ScanConfig:
    """One partition's engine: the scan's policy, scope and reuse, over one run.

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
    )


def _vanished_partition(timestamp: str, label: str) -> tuple[dict, list]:
    """A run whose folder is gone by the time it is scanned holds nothing - which is
    what a whole walk makes of a folder that disappears after its parent was listed."""
    from discovery.discovery_engine import ScanSummary

    header = {
        "timestamp": timestamp, "source": "local", "mode": "full",
        "summary": ScanSummary(0, 0, 0, 0, 0, 0).to_dict(), "scan_diagnostics": {},
    }
    if label:
        header["scan_label"] = label
    return header, []


def run_partitioned_local_scan(
    tenant_id: str,
    config: ScanConfig,
    *,
    scan_label: str = "",
    compliance_enabled: bool = False,
    compliance_frameworks: Iterable[str] | None = None,
    job=None,
    max_files: int | None = None,
) -> dict | None:
    """Scan a local target one partition at a time; returns the compact report.

    Returns ``None`` when the target is not worth partitioning - it fits one
    partition, or it is not a readable local folder - or when it holds the bundled
    demo dataset, whose files never enter the estate and which is small by
    definition. The caller then runs an ordinary scan.

    Each partition is analyzed by its own engine, enriched file by file, written,
    and released before the next one starts; nothing about it is kept but its
    ledger row. A partition that fails, or a cancellation, marks its unit failed and
    stops the scan without finalizing it.
    """
    from backend.jobs import collection_heartbeat
    from discovery.discovery_engine import SCAN_MAX_SECONDS

    # The scan's time budget covers the whole partitioned scan, planning included -
    # not each partition separately (B2.2b review).
    deadline = time.monotonic() + SCAN_MAX_SECONDS if SCAN_MAX_SECONDS > 0 else None

    def stop_reason() -> str | None:
        if job is not None and job.cancel_requested:
            return "Scan cancelled"
        if deadline is not None and time.monotonic() > deadline:
            return "Scan exceeded its time budget"
        return None

    with collection_heartbeat(job) if job is not None else nullcontext():
        plan = plan_bounded_partitions(
            config, max_files=max_files or partition_max_files(), stop_check=stop_reason,
        )
    if plan is None or plan["sample_paths"]:
        return None
    scan_root = str(Path(config.local_path).expanduser().resolve())

    scan_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    # One timestamp for the whole scan: every partition stamps it on the rows it
    # writes, and a single scan's rows all carry one.
    timestamp = datetime.now(timezone.utc).isoformat()
    label = str(scan_label or "").strip()[:80]
    units = plan["units"]
    store.create_scan_partitions(tenant_id, scan_id, str(getattr(job, "id", "") or ""), units)
    done = 0
    while True:
        reason = stop_reason()
        if reason:
            raise RuntimeError(reason)
        unit = store.claim_next_partition(tenant_id, scan_id)
        if unit is None:
            break
        if job is not None:
            job.message = f"Scanning partition {done + 1} of {len(units)}"
        try:
            if not Path(str(unit["spec"]["local_path"])).is_dir():
                header, records = _vanished_partition(timestamp, label)
                store.persist_partition(
                    tenant_id, scan_id, unit["partition_id"], unit["attempt"], header, records, write_estate=True,
                )
                done += 1
                continue
            with collection_heartbeat(job) if job is not None else nullcontext():
                report = DSPMDiscoveryEngine(_unit_config(config, unit["spec"], scan_root)).run().to_dict()
            if job is not None and job.cancel_requested:
                raise RuntimeError("Scan cancelled")
            records = report.get("files") or []
            enrichment = ComplianceReportAccumulator(compliance_enabled, compliance_frameworks)
            for record in records:
                enrichment.prepare(record)
            header = {
                "timestamp": timestamp,
                "source": report.get("source") or "local",
                "mode": report.get("mode") or "full",
                "summary": report.get("summary") or {},
                "scan_diagnostics": report.get("scan_diagnostics") or {},
            }
            if label:
                header["scan_label"] = label
            store.persist_partition(
                tenant_id, scan_id, unit["partition_id"], unit["attempt"], header, records, write_estate=True,
            )
        except BaseException as exc:
            try:
                store.fail_scan_partition(
                    tenant_id, scan_id, unit["partition_id"], type(exc).__name__, attempt=unit["attempt"],
                )
            except Exception:
                pass
            raise
        report = records = header = None
        done += 1
        if job is not None:
            job.progress = max(job.progress, min(94, 8 + int(86 * done / len(units))))
    if job is not None:
        job.message = "Finalizing report"
        job.progress = max(job.progress, 95)
    return finalize_scan(
        tenant_id, scan_id,
        timestamp=timestamp,
        source="local",
        scan_label=label,
        compliance_enabled=compliance_enabled,
        compliance_frameworks=compliance_frameworks,
        write_estate=True,
        diagnostics_overrides={"local_path": config.local_path, "max_depth": config.max_depth},
    )
