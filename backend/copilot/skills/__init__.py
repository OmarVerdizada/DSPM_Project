"""Deterministic DSPM Copilot skills.

These helpers compute structured evidence from local DSPM scan reports.
They do not call remote services or generate user-facing model prose.

SKILL_REGISTRY provides a mapping of skill names to their implementation functions.
Each skill is a deterministic function that transforms scan data into structured output.
"""

from backend.copilot.skills.compliance import compliance_mapping
from backend.copilot.skills.scan_comparison import compare_recent_scans, finding_history, remediation_status
from backend.copilot.skills.scan_summary import severity_distribution


SKILL_REGISTRY: dict[str, callable] = {
    "compliance_mapping": compliance_mapping,
    "severity_distribution": severity_distribution,
    "scan_comparison": compare_recent_scans,
    "finding_history": finding_history,
    "remediation_status": remediation_status,
}


__all__ = [
    "SKILL_REGISTRY",
    "compliance_mapping",
    "severity_distribution",
    "compare_recent_scans",
    "finding_history",
    "remediation_status",
]

