"""Typed task-type registry and dispatch policy for the DSPM Copilot.

Historically ``RoutePlan.task_type`` was a stringly-typed value and the
runtime derived critical policy (may the controlled verbalizer reword this
answer? is a provider-final answer expected? does this task assert DSPM
evidence?) from fragile string-prefix checks scattered in ``service.py``.
A new task name that missed the prefix list silently fell into the most
permissive policy.

This module makes the policy typed and table-driven:

- :class:`TaskSpec` — typed metadata per task type (category, final-answer
  policy, evidence requirement);
- :data:`TASK_REGISTRY` — the single policy table for every known task type
  (planner ``TaskType`` literals plus runtime-only answer types);
- :func:`resolve_task` — adapter from a legacy task-type string to a
  :class:`TaskSpec`; unknown names fall back to the documented legacy prefix
  rule so dynamically-built names (``severity_count_subset`` …) keep their
  protected policy, then to a permissive default identical to the historic
  fall-through.

The registry intentionally mirrors the pre-existing runtime behavior exactly;
it changes *where* the policy lives, not *what* the policy is. Behavior
changes belong in the registry table, reviewed line by line.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TaskCategory(str, Enum):
    EVIDENCE_FACTUAL = "evidence_factual"    # counts, lists, distributions, scan facts
    SELECTED_ITEM = "selected_item"          # selected/critical finding detail, remediation
    AGGREGATE_SCOPE = "aggregate_scope"      # posture, compliance, trends over whole scans
    ARTIFACT = "artifact"                    # report/export artifacts
    WORKFLOW = "workflow"                    # professional analyst workflows
    META_CORRECTION = "meta_correction"      # corrections, complaints, why-previous
    LANGUAGE = "language"                    # language switch / rerender
    SOCIAL = "social"                        # greeting / small talk / capability
    CLARIFICATION = "clarification"
    TEACHING = "teaching"
    GENERAL = "general"                      # non-DSPM general question
    UNKNOWN = "unknown"


class FinalAnswerPolicy(str, Enum):
    # A deterministic/structured renderer owns the final text; the controlled
    # verbalizer must never replace it.
    STRUCTURED_RENDERER = "structured_renderer"
    # A (gated) provider-final answer is the expected final text.
    PROVIDER_FINAL = "provider_final"
    # The controlled verbalizer may reword the final text (safe content only).
    VERBALIZER_ALLOWED = "verbalizer_allowed"


@dataclass(frozen=True)
class TaskSpec:
    name: str
    category: TaskCategory
    final_policy: FinalAnswerPolicy
    requires_evidence: bool = False
    # Where the spec came from: "registry" | "legacy_prefix" | "default".
    source: str = "registry"


def _spec(
    name: str,
    category: TaskCategory,
    final_policy: FinalAnswerPolicy,
    requires_evidence: bool = False,
) -> TaskSpec:
    return TaskSpec(name=name, category=category, final_policy=final_policy, requires_evidence=requires_evidence)


_STRUCTURED = FinalAnswerPolicy.STRUCTURED_RENDERER
_PROVIDER = FinalAnswerPolicy.PROVIDER_FINAL
_VERBALIZER = FinalAnswerPolicy.VERBALIZER_ALLOWED


# The single source of truth for task-type policy. Every planner TaskType
# literal must have an entry (enforced by tests); runtime-only answer types
# used by deterministic routes are listed after the planner block.
TASK_REGISTRY: dict[str, TaskSpec] = {
    spec.name: spec
    for spec in (
        # --- planner TaskType literals -----------------------------------
        _spec("critical_findings_list", TaskCategory.EVIDENCE_FACTUAL, _STRUCTURED, requires_evidence=True),
        _spec("critical_finding_details", TaskCategory.SELECTED_ITEM, _STRUCTURED, requires_evidence=True),
        _spec("critical_finding_remediation", TaskCategory.SELECTED_ITEM, _STRUCTURED, requires_evidence=True),
        _spec("critical_finding_risk_explanation", TaskCategory.SELECTED_ITEM, _STRUCTURED, requires_evidence=True),
        _spec("critical_finding_summary", TaskCategory.SELECTED_ITEM, _STRUCTURED, requires_evidence=True),
        # Historic fall-through: no protected prefix. The evidence/metadata
        # gates earlier in the block-reason chain still protect real payloads.
        _spec("random_finding_risk", TaskCategory.SELECTED_ITEM, _VERBALIZER, requires_evidence=True),
        _spec("scan_summary", TaskCategory.EVIDENCE_FACTUAL, _STRUCTURED, requires_evidence=True),
        _spec("scan_comparison", TaskCategory.EVIDENCE_FACTUAL, _STRUCTURED, requires_evidence=True),
        _spec("posture_score", TaskCategory.AGGREGATE_SCOPE, _VERBALIZER, requires_evidence=True),
        _spec("compliance_report", TaskCategory.AGGREGATE_SCOPE, _VERBALIZER, requires_evidence=True),
        _spec("trend_analysis", TaskCategory.AGGREGATE_SCOPE, _VERBALIZER, requires_evidence=True),
        _spec("finding_history", TaskCategory.EVIDENCE_FACTUAL, _STRUCTURED, requires_evidence=True),
        _spec("compliance_mapping", TaskCategory.AGGREGATE_SCOPE, _VERBALIZER, requires_evidence=True),
        _spec("severity_distribution", TaskCategory.EVIDENCE_FACTUAL, _STRUCTURED, requires_evidence=True),
        _spec("severity_count", TaskCategory.EVIDENCE_FACTUAL, _STRUCTURED, requires_evidence=True),
        _spec("severity_findings_list", TaskCategory.EVIDENCE_FACTUAL, _STRUCTURED, requires_evidence=True),
        _spec("severity_findings_compare", TaskCategory.EVIDENCE_FACTUAL, _STRUCTURED, requires_evidence=True),
        _spec("remediation_status", TaskCategory.EVIDENCE_FACTUAL, _STRUCTURED, requires_evidence=True),
        _spec("report_generation", TaskCategory.ARTIFACT, _VERBALIZER, requires_evidence=True),
        _spec("artifact_export", TaskCategory.ARTIFACT, _STRUCTURED, requires_evidence=True),
        _spec("follow_up_correction", TaskCategory.META_CORRECTION, _VERBALIZER),
        _spec("complaint_repair", TaskCategory.META_CORRECTION, _VERBALIZER),
        _spec("list", TaskCategory.EVIDENCE_FACTUAL, _STRUCTURED, requires_evidence=True),
        _spec("details", TaskCategory.SELECTED_ITEM, _VERBALIZER, requires_evidence=True),
        _spec("remediation", TaskCategory.SELECTED_ITEM, _VERBALIZER, requires_evidence=True),
        _spec("explanation", TaskCategory.SELECTED_ITEM, _VERBALIZER, requires_evidence=True),
        _spec("correction", TaskCategory.META_CORRECTION, _VERBALIZER),
        _spec("report", TaskCategory.ARTIFACT, _VERBALIZER, requires_evidence=True),
        _spec("export", TaskCategory.ARTIFACT, _VERBALIZER, requires_evidence=True),
        _spec("small_talk", TaskCategory.SOCIAL, _VERBALIZER),
        _spec("capability_help", TaskCategory.SOCIAL, _VERBALIZER),
        _spec("complaint", TaskCategory.META_CORRECTION, _VERBALIZER),
        _spec("count_conflict_explanation", TaskCategory.META_CORRECTION, _STRUCTURED),
        # why_previous_answer answers can embed evidence facts (the count-route
        # explanation quotes real counts/severities) — stays fact-frozen.
        _spec("why_previous_answer", TaskCategory.META_CORRECTION, _STRUCTURED),
        # Fact-free meta answers (no numbers, no DSPM facts by construction):
        # the controlled verbalizer may reword them so corrections sound
        # natural instead of scripted. The verbalizer's validator still
        # rejects any answer that introduces numbers not present in the safe
        # draft, so this cannot leak invented facts.
        _spec("complaint_about_wrong_route", TaskCategory.META_CORRECTION, _VERBALIZER),
        _spec("meta_clarification", TaskCategory.META_CORRECTION, _VERBALIZER),
        _spec("language_switch", TaskCategory.LANGUAGE, _STRUCTURED),
        _spec("clarification", TaskCategory.CLARIFICATION, _VERBALIZER),
        _spec("general", TaskCategory.GENERAL, _PROVIDER),
        _spec("list_plus_remediation", TaskCategory.EVIDENCE_FACTUAL, _STRUCTURED, requires_evidence=True),
        _spec("teaching", TaskCategory.TEACHING, _STRUCTURED),
        # --- runtime-only answer types (deterministic routes) -------------
        _spec("model_status", TaskCategory.META_CORRECTION, _STRUCTURED),
        _spec("provider_unavailable", TaskCategory.META_CORRECTION, _STRUCTURED),
        _spec("previous_answer", TaskCategory.META_CORRECTION, _STRUCTURED),
        # Fact-free meta (see note above) — verbalizer-eligible.
        _spec("why_misunderstood_previous_request", TaskCategory.META_CORRECTION, _VERBALIZER),
        # Cancel keeps its exact deterministic acknowledgement (contract-tested
        # phrase that also confirms the context was really cleared).
        _spec("cancel_current_topic", TaskCategory.META_CORRECTION, _STRUCTURED),
        # --- product-help routes (deterministic, fact-free unless noted) ---
        _spec("product_overview", TaskCategory.SOCIAL, _VERBALIZER),
        _spec("product_features", TaskCategory.SOCIAL, _VERBALIZER),
        _spec("filter_howto", TaskCategory.SOCIAL, _VERBALIZER),
        _spec("navigation_help", TaskCategory.SOCIAL, _VERBALIZER),
        _spec("reports_feature_help", TaskCategory.SOCIAL, _VERBALIZER),
        # Alert-type breakdown carries real scan counts — fact-frozen.
        _spec("alert_types_breakdown", TaskCategory.EVIDENCE_FACTUAL, _STRUCTURED, requires_evidence=True),
    )
}

# Fact-free meta tasks deliberately opened to the controlled verbalizer in P7
# (they were STRUCTURED before). Kept as an explicit, documented exception set
# so the legacy-parity test remains meaningful for everything else.
FACT_FREE_META_TASKS: frozenset[str] = frozenset({
    "complaint_about_wrong_route",
    "why_misunderstood_previous_request",
})


# Legacy adapter for dynamically-built task names that are not in the
# registry (e.g. "severity_count_subset", "count_scope_correction"). This is
# the historic protected-prefix rule, kept so unknown evidence-carrying names
# stay on the protected policy. New task types should get a registry entry
# instead of relying on this.
LEGACY_PROTECTED_PREFIXES: tuple[str, ...] = (
    "severity_",
    "count_",
    "critical_",
    "selected_",
    "aggregate_",
    "artifact_",
    "scan_",
    "remediation_",
    "risk_",
    "finding_",
    "fix_",
    "manager_",
    "technical_",
    "professional_",
)

_PREFIX_CATEGORY: dict[str, TaskCategory] = {
    "severity_": TaskCategory.EVIDENCE_FACTUAL,
    "count_": TaskCategory.EVIDENCE_FACTUAL,
    "critical_": TaskCategory.SELECTED_ITEM,
    "selected_": TaskCategory.SELECTED_ITEM,
    "aggregate_": TaskCategory.AGGREGATE_SCOPE,
    "artifact_": TaskCategory.ARTIFACT,
    "scan_": TaskCategory.EVIDENCE_FACTUAL,
    "remediation_": TaskCategory.SELECTED_ITEM,
    "risk_": TaskCategory.EVIDENCE_FACTUAL,
    "finding_": TaskCategory.EVIDENCE_FACTUAL,
    "fix_": TaskCategory.WORKFLOW,
    "manager_": TaskCategory.WORKFLOW,
    "technical_": TaskCategory.WORKFLOW,
    "professional_": TaskCategory.WORKFLOW,
}


def resolve_task(task_type: str | None) -> TaskSpec:
    """Resolve a (possibly legacy/dynamic) task-type string to a typed spec.

    Resolution order: registry entry → legacy protected-prefix adapter →
    permissive default (identical to the historic fall-through, where an
    unlisted task name allowed the controlled verbalizer).
    """
    name = str(task_type or "").strip()
    spec = TASK_REGISTRY.get(name)
    if spec is not None:
        return spec
    for prefix in LEGACY_PROTECTED_PREFIXES:
        if name.startswith(prefix):
            return TaskSpec(
                name=name,
                category=_PREFIX_CATEGORY.get(prefix, TaskCategory.UNKNOWN),
                final_policy=_STRUCTURED,
                requires_evidence=True,
                source="legacy_prefix",
            )
    return TaskSpec(name=name, category=TaskCategory.UNKNOWN, final_policy=_VERBALIZER, source="default")


def verbalizer_block_reason(task_type: str | None) -> str | None:
    """Task-name-level controlled-verbalizer policy.

    Returns the block reason string the runtime records in metadata, or None
    when the task name alone does not forbid verbalization (evidence,
    brainmap-family, and metadata gates still apply upstream).
    """
    spec = resolve_task(task_type)
    if spec.final_policy is FinalAnswerPolicy.PROVIDER_FINAL:
        return "provider_final_required"
    if spec.final_policy is FinalAnswerPolicy.STRUCTURED_RENDERER:
        return "structured_renderer_required"
    return None


def requires_evidence(task_type: str | None) -> bool:
    return resolve_task(task_type).requires_evidence
