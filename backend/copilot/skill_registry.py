"""DSPM Skill Registry — bounded capability layer above TOOL_REGISTRY.

Each skill represents a single DSPM capability with metadata about
whether it is deterministic, what tools it uses, and how to render output.
The registry is static and does not grow at runtime.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


SkillMode = Literal["deterministic", "hybrid", "llm_required"]


@dataclass(frozen=True)
class DSPMSkill:
    skill_id: str
    name: str
    mode: SkillMode
    tools: tuple[str, ...]
    renderer: str | None = None
    needs_item: bool = False
    needs_scan_id: bool = False
    description: str = ""
    tags: tuple[str, ...] = ()


DSPM_SKILL_REGISTRY: dict[str, DSPMSkill] = {}


def _reg(skill: DSPMSkill) -> DSPMSkill:
    DSPM_SKILL_REGISTRY[skill.skill_id] = skill
    return skill


# --- Data retrieval skills ---

sk_critical_findings_list = _reg(DSPMSkill(
    skill_id="sk_critical_findings_list",
    name="List Critical Findings",
    mode="deterministic",
    tools=("get_findings_by_severity",),
    renderer="render_critical_findings",
    description="List critical/high severity findings from latest scan",
    tags=("list", "critical", "findings"),
))

sk_severity_distribution = _reg(DSPMSkill(
    skill_id="sk_severity_distribution",
    name="Severity Distribution",
    mode="deterministic",
    tools=("get_severity_distribution",),
    renderer="render_severity_distribution",
    description="Breakdown of findings by severity level",
    tags=("severity", "distribution", "summary"),
))

sk_scan_comparison = _reg(DSPMSkill(
    skill_id="sk_scan_comparison",
    name="Scan Comparison",
    mode="deterministic",
    tools=("compare_scans",),
    renderer="render_scan_comparison",
    description="Compare latest vs previous scan",
    tags=("compare", "scan", "diff"),
))

sk_finding_history = _reg(DSPMSkill(
    skill_id="sk_finding_history",
    name="Finding History",
    mode="deterministic",
    tools=("get_finding_history",),
    renderer="render_finding_history",
    needs_item=True,
    description="Track a finding across multiple scans",
    tags=("history", "finding", "timeline"),
))

sk_remediation_status = _reg(DSPMSkill(
    skill_id="sk_remediation_status",
    name="Remediation Status",
    mode="deterministic",
    tools=("get_remediation_status",),
    renderer="render_remediation_status",
    needs_item=True,
    description="Check if a finding has been remediated",
    tags=("remediation", "status"),
))

sk_compliance_mapping = _reg(DSPMSkill(
    skill_id="sk_compliance_mapping",
    name="Compliance Mapping",
    mode="deterministic",
    tools=("get_compliance_mapping",),
    renderer="render_compliance_mapping",
    needs_item=True,
    description="Map finding risk types to compliance frameworks",
    tags=("compliance", "framework", "regulation"),
))

sk_posture_score = _reg(DSPMSkill(
    skill_id="sk_posture_score",
    name="Posture Score",
    mode="deterministic",
    tools=("get_posture_score",),
    renderer="render_posture_score",
    description="Compute deterministic DSPM security posture score from scan evidence",
    tags=("posture", "score", "health", "risk"),
))

sk_compliance_report = _reg(DSPMSkill(
    skill_id="sk_compliance_report",
    name="Compliance Report",
    mode="deterministic",
    tools=("get_compliance_report",),
    renderer="render_compliance_report",
    description="Summarize finding-to-framework mappings for a scan",
    tags=("compliance", "framework", "report"),
))

sk_trend_analysis = _reg(DSPMSkill(
    skill_id="sk_trend_analysis",
    name="Trend Analysis",
    mode="deterministic",
    tools=("get_trend_analysis",),
    renderer="render_trend_analysis",
    description="Analyze posture and critical finding trends across scans",
    tags=("trend", "scan", "history", "posture"),
))

sk_executive_dashboard = _reg(DSPMSkill(
    skill_id="sk_executive_dashboard",
    name="Executive Dashboard",
    mode="deterministic",
    tools=("get_executive_dashboard",),
    renderer="render_executive_dashboard",
    description="High-level security posture summary",
    tags=("dashboard", "summary", "executive"),
))

sk_scan_history = _reg(DSPMSkill(
    skill_id="sk_scan_history",
    name="Scan History",
    mode="deterministic",
    tools=("get_scan_history",),
    renderer="render_scan_history",
    description="List recent scans with timestamps",
    tags=("scan", "history", "list"),
))

sk_high_risk_assets = _reg(DSPMSkill(
    skill_id="sk_high_risk_assets",
    name="High Risk Assets",
    mode="deterministic",
    tools=("get_high_risk_assets",),
    renderer="render_high_risk_assets",
    description="Top risky files/assets",
    tags=("assets", "risk", "high"),
))

sk_recent_alerts = _reg(DSPMSkill(
    skill_id="sk_recent_alerts",
    name="Recent Alerts",
    mode="deterministic",
    tools=("get_recent_alerts",),
    renderer="render_recent_alerts",
    description="Latest security alerts",
    tags=("alerts", "recent"),
))

sk_audit_events = _reg(DSPMSkill(
    skill_id="sk_audit_events",
    name="Audit Events",
    mode="hybrid",
    tools=("search_audit_events",),
    renderer="render_audit_events",
    description="Search audit/activity log",
    tags=("audit", "events", "log"),
))

# --- Single-item analysis skills ---

sk_finding_detail = _reg(DSPMSkill(
    skill_id="sk_finding_detail",
    name="Finding Detail",
    mode="deterministic",
    tools=("get_finding_detail",),
    renderer="render_finding_detail",
    needs_item=True,
    description="Detailed view of a single finding",
    tags=("detail", "finding", "item"),
))

sk_finding_risk_explanation = _reg(DSPMSkill(
    skill_id="sk_finding_risk_explanation",
    name="Risk Explanation",
    mode="deterministic",
    tools=("get_finding_detail",),
    renderer="render_finding_risk_explanation",
    needs_item=True,
    description="Explain why a finding is risky",
    tags=("risk", "explanation", "why"),
))

sk_finding_remediation = _reg(DSPMSkill(
    skill_id="sk_finding_remediation",
    name="Finding Remediation",
    mode="deterministic",
    tools=("get_finding_detail",),
    renderer="render_finding_remediation",
    needs_item=True,
    description="Remediation advice for specific finding",
    tags=("remediation", "finding", "advice"),
))

sk_teach_dspm = _reg(DSPMSkill(
    skill_id="sk_teach_dspm",
    name="Guided DSPM Teaching",
    mode="deterministic",
    tools=(),
    renderer="render_teach_dspm",
    description="Teach DSPM concepts and remediation steps using available evidence",
    tags=("teach", "guided", "remediation", "risk"),
))

# --- Workflow processing skills ---

sk_critical_filter = _reg(DSPMSkill(
    skill_id="sk_critical_filter",
    name="Critical Filter",
    mode="deterministic",
    tools=(),
    renderer="render_critical_filter",
    description="Filter items to only critical severity",
    tags=("filter", "critical", "workflow"),
))

sk_sort_by_time = _reg(DSPMSkill(
    skill_id="sk_sort_by_time",
    name="Sort by Time",
    mode="deterministic",
    tools=(),
    renderer="render_sort_by_time",
    description="Sort items by timestamp (newest first)",
    tags=("sort", "time", "workflow"),
))

# --- Report/Export skills ---

sk_report_generation = _reg(DSPMSkill(
    skill_id="sk_report_generation",
    name="Report Generation",
    mode="deterministic",
    tools=(),
    renderer="render_artifact",
    description="Generate PDF/HTML report from session data",
    tags=("report", "pdf", "export"),
))

# --- Conversational skills ---

sk_small_talk = _reg(DSPMSkill(
    skill_id="sk_small_talk",
    name="Small Talk",
    mode="deterministic",
    tools=(),
    description="Greetings, thanks, goodbye",
    tags=("small_talk", "greeting"),
))

sk_capability_help = _reg(DSPMSkill(
    skill_id="sk_capability_help",
    name="Capability Help",
    mode="deterministic",
    tools=(),
    description="What can the copilot do",
    tags=("help", "capability"),
))

sk_clarification = _reg(DSPMSkill(
    skill_id="sk_clarification",
    name="Clarification",
    mode="deterministic",
    tools=(),
    description="Ask user to specify context",
    tags=("clarification",),
))

sk_general_dspm = _reg(DSPMSkill(
    skill_id="sk_general_dspm",
    name="General DSPM Query",
    mode="llm_required",
    tools=("get_scan_report", "get_executive_dashboard"),
    description="Open-ended DSPM question with evidence",
    tags=("general", "dspm"),
))


TASK_TO_SKILL: dict[str, str] = {
    "critical_findings_list": "sk_critical_findings_list",
    "list": "sk_critical_findings_list",
    "scan_comparison": "sk_scan_comparison",
    "finding_history": "sk_finding_history",
    "remediation_status": "sk_remediation_status",
    "severity_distribution": "sk_severity_distribution",
    "compliance_mapping": "sk_compliance_mapping",
    "posture_score": "sk_posture_score",
    "compliance_report": "sk_compliance_report",
    "trend_analysis": "sk_trend_analysis",
    "scan_summary": "sk_executive_dashboard",
    "critical_finding_details": "sk_finding_detail",
    "details": "sk_finding_detail",
    "critical_finding_risk_explanation": "sk_finding_risk_explanation",
    "explanation": "sk_finding_risk_explanation",
    "random_finding_risk": "sk_finding_risk_explanation",
    "critical_finding_remediation": "sk_finding_remediation",
    "remediation": "sk_finding_remediation",
    "teaching": "sk_teach_dspm",
    "guided_teaching": "sk_teach_dspm",
    "report_generation": "sk_report_generation",
    "artifact_export": "sk_report_generation",
    "report": "sk_report_generation",
    "export": "sk_report_generation",
    "follow_up_correction": "sk_critical_findings_list",
    "complaint_repair": "sk_critical_findings_list",
    "small_talk": "sk_small_talk",
    "capability_help": "sk_capability_help",
    "clarification": "sk_clarification",
    "general": "sk_general_dspm",
}


def skill_for_task(task_type: str) -> DSPMSkill | None:
    skill_id = TASK_TO_SKILL.get(task_type)
    if skill_id:
        return DSPM_SKILL_REGISTRY.get(skill_id)
    return None


def is_deterministic_skill(task_type: str) -> bool:
    skill = skill_for_task(task_type)
    return skill is not None and skill.mode == "deterministic"
