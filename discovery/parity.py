"""Shared semantic-parity projection for the Track P benchmarks and the perf gate.

Every performance optimization in Track P (incremental reuse, parallel collection,
adaptive analysis, triage, the detector prefilter, partitioned scanning) is
required to be *findings-identical* to the un-optimized path. Each benchmark used
to carry its own copy of this projection, and they drifted — different volatile-key
sets, different sub-keys compared. This is the single source of truth so a parity
check can never silently weaken.

A scan report is "semantically identical" to another when, per file (keyed by
path), its ``findings``, ``risk``, ``permissions``, and sanitized ``preview`` match
after dropping per-run volatile fields (wall-clock stamps, the SLA due date derived
from ``first_seen``, per-run detector timings, and reuse markers).
"""

from __future__ import annotations

# Per-run fields that legitimately differ between two runs of the same scan and so
# must be excluded from a semantic comparison. Keep this list complete: a missing
# key causes false parity FAILURES (e.g. sla_due), an extra harmless one costs
# nothing. Applied recursively, so it covers both top-level and nested occurrences.
VOLATILE_KEYS = frozenset({
    "first_seen", "last_seen", "seen_at", "timestamp", "updated_at", "last_scanned_at",
    "detector_elapsed_ms", "detector_metrics", "incremental_scan_reason",
    "cache_reused", "incremental_reused", "sla_due", "triage_score",
})

# The per-file sub-objects that define a scan's semantic result.
_PROJECTED = ("findings", "risk", "permissions", "preview")


def semantic(value):
    """Return ``value`` with all VOLATILE_KEYS stripped, recursively."""
    if isinstance(value, dict):
        return {k: semantic(v) for k, v in value.items() if k not in VOLATILE_KEYS}
    if isinstance(value, list):
        return [semantic(v) for v in value]
    return value


def accuracy_projection(report: dict) -> dict:
    """Map ``report`` (a ScanReport.to_dict()) to ``{path: {findings, risk,
    permissions, preview}}`` with volatile fields removed — the canonical unit of
    "did this optimization change what we found?"."""
    return {
        str(item.get("path") or ""): {key: semantic(item.get(key) or ([] if key == "findings" else {})) for key in _PROJECTED}
        for item in report.get("files") or []
    }


def reports_equal(expected: dict, actual: dict) -> bool:
    """True when two scan reports are semantically identical (findings-parity)."""
    return accuracy_projection(expected) == accuracy_projection(actual)
