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

from typing import Iterable

from backend import store
from backend.compliance_service import ComplianceReportAccumulator


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


def scan_diagnostics_for(units: list[dict], *, overrides: dict | None = None) -> dict:
    """The scan's diagnostics: the partitions' merged, then what describes the scan as a whole."""
    merged = store.merge_partition_diagnostics([unit.get("diagnostics") or {} for unit in units])
    for key, value in (overrides or {}).items():
        merged[key] = value
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
    diagnostics = scan_diagnostics_for(units, overrides=diagnostics_overrides)
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
