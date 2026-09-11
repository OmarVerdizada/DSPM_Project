"""Phase 1 normalized domain model (DATA-001).

Additive only: nothing here is wired into the running scan/persistence path yet.
See docs/phase1_kickoff_rfc.md for the migration strategy.
"""

from backend.domain.models import (
    AccessEdge,
    Asset,
    AssetVersion,
    Checkpoint,
    Event,
    Finding,
    FindingOccurrence,
    Identity,
    NormalizedScan,
    ScanRun,
    asset_identity,
    finding_identity,
    iter_normalized_assets,
    iter_normalized_chunks,
    normalize_scan_report,
    scan_run_from_report,
)

__all__ = [
    "AccessEdge",
    "Asset",
    "AssetVersion",
    "Checkpoint",
    "Event",
    "Finding",
    "FindingOccurrence",
    "Identity",
    "NormalizedScan",
    "ScanRun",
    "asset_identity",
    "finding_identity",
    "iter_normalized_assets",
    "iter_normalized_chunks",
    "normalize_scan_report",
    "scan_run_from_report",
]
