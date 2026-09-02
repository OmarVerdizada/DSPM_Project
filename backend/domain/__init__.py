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
    normalize_scan_report,
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
    "normalize_scan_report",
]
