"""Typed Situation Intelligence policy contracts.

This module is intentionally declarative. It defines situation ids, policies,
registry helpers, and safe metadata bridges. It does not classify raw messages,
call providers, execute tools, read scan data, or render final answers.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping


class SituationFamily(str, Enum):
    SOCIAL = "social"
    CAPABILITY = "capability"
    DSPM_FACTUAL = "dspm_factual"
    ANALYST_WORKFLOW = "analyst_workflow"
    CONVERSATION_CONTEXT = "conversation_context"
    COMPLAINT = "complaint"
    ARTIFACT = "artifact"
    LANGUAGE = "language"
    EDUCATIONAL = "educational"
    GENERAL = "general"
    SAFETY = "safety"
    UNKNOWN = "unknown"


class SituationId(str, Enum):
    SOCIAL_GREETING = "social.greeting"
    SOCIAL_GREETING_STATUS = "social.greeting_status"
    SOCIAL_STATUS_CHECK = "social.status_check"
    SOCIAL_THANKS = "social.thanks"
    SOCIAL_PRAISE = "social.praise"
    SOCIAL_CASUAL_REACTION = "social.casual_reaction"
    SOCIAL_FRUSTRATION_UNCLEAR = "social.frustration_unclear"
    SOCIAL_FAREWELL = "social.farewell"
    CAPABILITY_WHAT_CAN_YOU_DO = "capability.what_can_you_do"
    CAPABILITY_HOW_CAN_YOU_HELP = "capability.how_can_you_help"
    CAPABILITY_DATA_ACCESS = "capability.data_access"
    CAPABILITY_LIMITATIONS = "capability.limitations"
    CAPABILITY_MODEL_STATUS = "capability.model_status"
    CAPABILITY_PRIVACY_SAFETY = "capability.privacy_safety"
    CAPABILITY_TOOL_BOUNDARY = "capability.tool_boundary"
    DSPM_COUNT_TOTAL_FINDINGS = "dspm.count.total_findings"
    DSPM_COUNT_SEVERITY_SUBSET = "dspm.count.severity_subset"
    DSPM_DISTRIBUTION_SEVERITY = "dspm.distribution.severity"
    DSPM_BREAKDOWN_RISK_TYPE = "dspm.breakdown.risk_type"
    DSPM_LIST_FINDINGS = "dspm.list.findings"
    DSPM_DETAIL_SELECTED_FINDING = "dspm.detail.selected_finding"
    DSPM_METRIC_POSTURE_SCORE = "dspm.metric.posture_score"
    DSPM_METRIC_EXPLAIN_COUNT_BASIS = "dspm.metric.explain_count_basis"
    WORKFLOW_FIX_NOW_TOP_RISKS = "workflow.fix_now_top_risks"
    WORKFLOW_TRIAGE = "workflow.triage"
    WORKFLOW_SCAN_DELTA = "workflow.scan_delta"
    WORKFLOW_MANAGER_SUMMARY = "workflow.manager_summary"
    WORKFLOW_TECHNICAL_REMEDIATION = "workflow.technical_remediation"
    WORKFLOW_AGGREGATE_REMEDIATION = "workflow.aggregate_remediation"
    WORKFLOW_SELECTED_FINDING_REMEDIATION = "workflow.selected_finding_remediation"
    WORKFLOW_EVIDENCE_EXPLANATION = "workflow.evidence_explanation"
    WORKFLOW_PRIORITY_EXPLANATION = "workflow.priority_explanation"
    WORKFLOW_REMEDIATION_CHECKLIST = "workflow.remediation_checklist"
    CONTEXT_SHOWN_LIST_FOLLOWUP = "context.shown_list_followup"
    CONTEXT_SELECTED_FINDING_FOLLOWUP = "context.selected_finding_followup"
    CONTEXT_PREVIOUS_ANSWER_CONDENSE = "context.previous_answer_condense"
    CONTEXT_PREVIOUS_ANSWER_EXPAND = "context.previous_answer_expand"
    CONTEXT_PREVIOUS_ANSWER_TRANSLATE = "context.previous_answer_translate"
    CONTEXT_NEXT_UNSHOWN = "context.next_unshown"
    CONTEXT_ORDINAL_ITEM = "context.ordinal_item"
    CONTEXT_COMPARE_SHOWN_ITEMS = "context.compare_shown_items"
    CONTEXT_STYLE_CHANGE = "context.style_change"
    COMPLAINT_SCOPE_CORRECTION = "complaint.scope_correction"
    COMPLAINT_WRONG_ROUTE = "complaint.wrong_route"
    COMPLAINT_COUNT_CONFLICT = "complaint.count_conflict"
    COMPLAINT_PREVIOUS_CONTRADICTION = "complaint.previous_contradiction"
    COMPLAINT_REPEATED_MISUNDERSTANDING = "complaint.repeated_misunderstanding"
    COMPLAINT_NE_ELAQE = "complaint.ne_elaqe"
    COMPLAINT_DID_NOT_WANT_THAT = "complaint.did_not_want_that"
    COMPLAINT_WHY_ANSWERED_THIS = "complaint.why_answered_this"
    COMPLAINT_WHY_FAILED = "complaint.why_failed"
    COMPLAINT_LANGUAGE_QUALITY = "complaint.language_quality"
    ARTIFACT_CREATE_REPORT = "artifact.create_report"
    ARTIFACT_FILTER_REPORT = "artifact.filter_report"
    ARTIFACT_DOWNLOAD_HELP = "artifact.download_help"
    ARTIFACT_FULL_LINK_REQUEST = "artifact.full_link_request"
    ARTIFACT_CLICKABLE_LINK_REQUEST = "artifact.clickable_link_request"
    ARTIFACT_BROKEN_LINK_COMPLAINT = "artifact.broken_link_complaint"
    ARTIFACT_REUSE_PREVIOUS = "artifact.reuse_previous"
    ARTIFACT_CANCEL_TOPIC = "artifact.cancel_topic"
    ARTIFACT_EXPORT_STATUS = "artifact.export_status"
    ARTIFACT_UNAVAILABLE = "artifact.unavailable"
    LANGUAGE_COMPLAINT = "language.complaint"
    LANGUAGE_MALFORMED_OUTPUT = "language.malformed_output"
    LANGUAGE_INVALID_AZ_WORD = "language.invalid_az_word"
    LANGUAGE_TRUNCATED_ANSWER = "language.truncated_answer"
    LANGUAGE_SWITCH_LANGUAGE = "language.switch_language"
    LANGUAGE_TRANSLATE_PREVIOUS = "language.translate_previous"
    LANGUAGE_MIXED_REPAIR = "language.mixed_repair"
    LANGUAGE_ENFORCE_SELECTED = "language.enforce_selected"
    EDU_DSPM_CONCEPT = "edu.dspm_concept"
    EDU_SECURITY_CONCEPT = "edu.security_concept"
    EDU_COMPLIANCE_CONCEPT = "edu.compliance_concept"
    EDU_RISK_SCORE = "edu.risk_score"
    EDU_SEVERITY = "edu.severity"
    EDU_REMEDIATION_CONCEPT = "edu.remediation_concept"
    EDU_STEP_BY_STEP = "edu.step_by_step"
    EDU_BEGINNER = "edu.beginner"
    EDU_METRIC_SEMANTICS = "edu.metric_semantics"
    GENERAL_SIMPLE_ARITHMETIC = "general.simple_arithmetic"
    GENERAL_KNOWLEDGE = "general.knowledge"
    GENERAL_CASUAL_NON_DSPM = "general.casual_non_dspm"
    GENERAL_EXTERNAL_WORLD = "general.external_world"
    GENERAL_PERSONAL_ADVICE = "general.personal_advice"
    GENERAL_UNRELATED_REQUEST = "general.unrelated_request"
    GENERAL_PROVIDER_UNAVAILABLE = "general.provider_unavailable"
    SAFETY_RAW_SECRETS = "safety.raw_secrets"
    SAFETY_PRIVATE_VALUES = "safety.private_values"
    SAFETY_PROMPT_INJECTION = "safety.prompt_injection"
    SAFETY_ARBITRARY_TOOLS = "safety.arbitrary_tools"
    SAFETY_TENANT_BYPASS = "safety.tenant_bypass"
    SAFETY_DANGEROUS_ACTION = "safety.dangerous_action"
    SAFETY_HALLUCINATION_RISK = "safety.hallucination_risk"
    SAFETY_UNSUPPORTED_EXPORT_ACTION = "safety.unsupported_export_action"
    UNKNOWN_LOW_CONFIDENCE = "unknown.low_confidence"
    UNKNOWN_MULTI_INTENT = "unknown.multi_intent"
    UNKNOWN_MISSING_ENTITY = "unknown.missing_entity"
    UNKNOWN_MISSING_SCOPE = "unknown.missing_scope"
    UNKNOWN_MISSING_SCAN = "unknown.missing_scan"
    UNKNOWN_UNCLEAR_PRONOUN = "unknown.unclear_pronoun"
    UNKNOWN_NEEDS_CLARIFICATION = "unknown.needs_clarification"
    UNKNOWN_NEEDS_AI_ARBITER = "unknown.needs_ai_arbiter"
    UNKNOWN_NEEDS_STRUCTURED_PLANNER = "unknown.needs_structured_planner"


class ResponseMode(str, Enum):
    NO_MODEL_TEMPLATE = "NO_MODEL_TEMPLATE"
    FAST_VERBALIZER = "FAST_VERBALIZER"
    DETERMINISTIC_RENDERER = "DETERMINISTIC_RENDERER"
    CANONICAL_FACT_RENDERER = "CANONICAL_FACT_RENDERER"
    FAST_CLASSIFIER_ONLY = "FAST_CLASSIFIER_ONLY"
    STRUCTURED_AI_PLANNER = "STRUCTURED_AI_PLANNER"
    EVIDENCE_GROUNDED_FINAL = "EVIDENCE_GROUNDED_FINAL"
    CLARIFICATION = "CLARIFICATION"
    SAFE_REFUSAL = "SAFE_REFUSAL"


class ProviderMode(str, Enum):
    NO_PROVIDER = "NO_PROVIDER"
    TINY_NO_THINK_CLASSIFIER = "TINY_NO_THINK_CLASSIFIER"
    TINY_NO_THINK_VERBALIZER = "TINY_NO_THINK_VERBALIZER"
    STRUCTURED_PLANNER_JSON = "STRUCTURED_PLANNER_JSON"
    EVIDENCE_GROUNDED_SHORT_FINAL = "EVIDENCE_GROUNDED_SHORT_FINAL"
    DISALLOWED = "DISALLOWED"


class ContextUse(str, Enum):
    FORBIDDEN = "FORBIDDEN"
    ALLOWED = "ALLOWED"
    CONDITIONAL = "CONDITIONAL"


class EvidenceRequirement(str, Enum):
    NONE = "NONE"
    OPTIONAL = "OPTIONAL"
    REQUIRED = "REQUIRED"
    REQUIRED_CANONICAL = "REQUIRED_CANONICAL"


@dataclass(frozen=True)
class SpeedBudget:
    deterministic_ms: int | None = None
    provider_timeout_ms: int | None = None
    total_timeout_ms: int | None = None
    max_output_tokens: int | None = None
    max_answer_words: int | None = None
    short_answer_default: bool = True


@dataclass(frozen=True)
class ContextPolicy:
    selected_finding: ContextUse = ContextUse.FORBIDDEN
    shown_list: ContextUse = ContextUse.FORBIDDEN
    count_scope: ContextUse = ContextUse.FORBIDDEN
    artifact_scope: ContextUse = ContextUse.FORBIDDEN
    previous_answer: ContextUse = ContextUse.FORBIDDEN
    scan_comparison: ContextUse = ContextUse.FORBIDDEN
    fix_now_list: ContextUse = ContextUse.FORBIDDEN
    user_preferences: ContextUse = ContextUse.FORBIDDEN
    language_preference: ContextUse = ContextUse.FORBIDDEN
    failed_route_state: ContextUse = ContextUse.FORBIDDEN


@dataclass(frozen=True)
class ProviderPolicy:
    provider_mode: ProviderMode
    provider_allowed: bool
    planner_allowed: bool
    final_answer_allowed: bool
    verbalizer_allowed: bool
    translator_allowed: bool
    fallback_on_timeout: bool


@dataclass(frozen=True)
class EvidencePolicy:
    requirement: EvidenceRequirement
    canonical_answer_required: bool
    allowed_tool_groups: tuple[str, ...] = ()
    metric_required: bool = False
    source_refs_required: bool = False
    no_fake_data: bool = True


@dataclass(frozen=True)
class FallbackPolicy:
    fallback_mode: ResponseMode
    fallback_message_key: str | None = None
    ask_clarification: bool = False
    safe_refusal: bool = False
    no_context_message: bool = False
    no_evidence_message: bool = False


@dataclass(frozen=True)
class SituationPolicy:
    situation_id: str
    family: SituationFamily
    priority: int
    default_confidence_threshold: float
    response_mode: ResponseMode
    provider_policy: ProviderPolicy
    context_policy: ContextPolicy
    evidence_policy: EvidencePolicy
    speed_budget: SpeedBudget
    fallback_policy: FallbackPolicy
    audit_fields: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    description: str = ""
    examples: tuple[str, ...] = ()
    confusion_risks: tuple[str, ...] = ()

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not 0 <= float(self.default_confidence_threshold) <= 1:
            errors.append(f"{self.situation_id}: confidence threshold out of range")
        if self.priority <= 0:
            errors.append(f"{self.situation_id}: priority must be positive")
        if self.provider_policy.provider_mode in {ProviderMode.NO_PROVIDER, ProviderMode.DISALLOWED}:
            if any(
                (
                    self.provider_policy.provider_allowed,
                    self.provider_policy.planner_allowed,
                    self.provider_policy.final_answer_allowed,
                    self.provider_policy.verbalizer_allowed,
                )
            ):
                errors.append(f"{self.situation_id}: no-provider policy allows provider role")
        if self.evidence_policy.canonical_answer_required and self.evidence_policy.requirement not in {
            EvidenceRequirement.REQUIRED,
            EvidenceRequirement.REQUIRED_CANONICAL,
        }:
            errors.append(f"{self.situation_id}: canonical answer requires required evidence")
        if self.family == SituationFamily.SAFETY and self.provider_policy.provider_mode not in {
            ProviderMode.NO_PROVIDER,
            ProviderMode.DISALLOWED,
        }:
            errors.append(f"{self.situation_id}: safety policy allows provider")
        if self.family == SituationFamily.DSPM_FACTUAL and self.provider_policy.final_answer_allowed:
            evidence_ok = self.provider_policy.provider_mode == ProviderMode.EVIDENCE_GROUNDED_SHORT_FINAL
            evidence_ok = evidence_ok and self.evidence_policy.requirement in {
                EvidenceRequirement.REQUIRED,
                EvidenceRequirement.REQUIRED_CANONICAL,
            }
            if not evidence_ok:
                errors.append(f"{self.situation_id}: factual DSPM final answer is not evidence-grounded")
        return errors


@dataclass(frozen=True)
class SituationCandidate:
    situation_id: str
    confidence: float
    priority: int
    matched: bool
    reason: str
    signals: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    policy_snapshot: dict[str, Any] | None = None


@dataclass(frozen=True)
class SituationDecision:
    situation_id: str
    family: str
    confidence: float
    priority: int
    reason: str
    signals: tuple[str, ...]
    response_mode: ResponseMode
    provider_mode: ProviderMode
    provider_allowed: bool
    planner_allowed: bool
    final_answer_allowed: bool
    verbalizer_allowed: bool
    translator_allowed: bool
    selected_finding_allowed: bool
    shown_list_allowed: bool
    count_scope_allowed: bool
    artifact_scope_allowed: bool
    previous_answer_allowed: bool
    evidence_required: bool
    canonical_answer_required: bool
    speed_budget: dict[str, Any]
    fallback_mode: str
    candidates: tuple[SituationCandidate, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_audit_metadata(self) -> dict[str, Any]:
        metadata = {
            "situation_id": self.situation_id,
            "situation_family": self.family,
            "situation_confidence": self.confidence,
            "situation_priority": self.priority,
            "situation_reason": self.reason,
            "situation_signals": list(self.signals),
            "situation_response_mode": self.response_mode.value,
            "situation_provider_mode": self.provider_mode.value,
            "situation_provider_allowed": self.provider_allowed,
            "situation_planner_allowed": self.planner_allowed,
            "situation_final_answer_allowed": self.final_answer_allowed,
            "situation_verbalizer_allowed": self.verbalizer_allowed,
            "situation_translator_allowed": self.translator_allowed,
            "situation_evidence_required": self.evidence_required,
            "situation_canonical_required": self.canonical_answer_required,
            "situation_speed_budget_ms": self.speed_budget.get("total_timeout_ms") or self.speed_budget.get("deterministic_ms"),
            "situation_fallback_mode": self.fallback_mode,
            "situation_candidate_ids": [candidate.situation_id for candidate in self.candidates[:5]],
            "situation_zero_provider": self.is_zero_provider(),
        }
        for key in (
            "situation_classifier_used",
            "situation_candidates",
            "situation_conflict_detected",
            "situation_fallback_needed",
            "situation_classifier_latency_ms",
        ):
            if key in self.metadata:
                metadata[key] = self.metadata[key]
        return metadata

    def to_route_metadata(self) -> dict[str, Any]:
        metadata = {
            "situation_id": self.situation_id,
            "situation_family": self.family,
            "situation_confidence": self.confidence,
            "situation_reason": self.reason,
            "situation_signals": list(self.signals),
            "situation_response_mode": self.response_mode.value,
            "situation_provider_mode": self.provider_mode.value,
            "situation_zero_provider": self.is_zero_provider(),
            "situation_speed_budget_ms": self.speed_budget.get("total_timeout_ms") or self.speed_budget.get("deterministic_ms"),
            "situation_canonical_required": self.canonical_answer_required,
            "situation_evidence_required": self.evidence_required,
        }
        for key in (
            "situation_classifier_used",
            "situation_candidates",
            "situation_conflict_detected",
            "situation_fallback_needed",
            "situation_classifier_latency_ms",
        ):
            if key in self.metadata:
                metadata[key] = self.metadata[key]
        return metadata

    def is_zero_provider(self) -> bool:
        return not any((self.provider_allowed, self.planner_allowed, self.final_answer_allowed, self.verbalizer_allowed))

    def allows_context(self, context_name: str) -> bool:
        mapping = {
            "selected_finding": self.selected_finding_allowed,
            "shown_list": self.shown_list_allowed,
            "count_scope": self.count_scope_allowed,
            "artifact_scope": self.artifact_scope_allowed,
            "previous_answer": self.previous_answer_allowed,
        }
        return bool(mapping.get(context_name, False))

    def requires_canonical_answer(self) -> bool:
        return self.canonical_answer_required


NO_PROVIDER = ProviderPolicy(ProviderMode.NO_PROVIDER, False, False, False, False, False, True)
DISALLOWED_PROVIDER = ProviderPolicy(ProviderMode.DISALLOWED, False, False, False, False, False, False)
CLASSIFIER_PROVIDER = ProviderPolicy(ProviderMode.TINY_NO_THINK_CLASSIFIER, True, False, False, False, False, True)
VERBALIZER_PROVIDER = ProviderPolicy(ProviderMode.TINY_NO_THINK_VERBALIZER, True, False, False, True, False, True)
PLANNER_PROVIDER = ProviderPolicy(ProviderMode.STRUCTURED_PLANNER_JSON, True, True, False, False, False, True)

NO_EVIDENCE = EvidencePolicy(EvidenceRequirement.NONE, False)
OPTIONAL_EVIDENCE = EvidencePolicy(EvidenceRequirement.OPTIONAL, False, ("scan_report",), False, False)
REQUIRED_EVIDENCE = EvidencePolicy(EvidenceRequirement.REQUIRED, False, ("scan_report", "canonical_answer"), True, True)
CANONICAL_EVIDENCE = EvidencePolicy(EvidenceRequirement.REQUIRED_CANONICAL, True, ("scan_report", "canonical_answer"), True, True)
ARTIFACT_EVIDENCE = EvidencePolicy(EvidenceRequirement.OPTIONAL, False, ("local_artifact_store", "scan_report"), False, False)

CTX_NONE = ContextPolicy(language_preference=ContextUse.ALLOWED)
CTX_PREVIOUS = ContextPolicy(previous_answer=ContextUse.ALLOWED, language_preference=ContextUse.ALLOWED, user_preferences=ContextUse.ALLOWED)
CTX_COUNT = ContextPolicy(count_scope=ContextUse.CONDITIONAL, language_preference=ContextUse.ALLOWED)
CTX_SELECTED = ContextPolicy(selected_finding=ContextUse.ALLOWED, language_preference=ContextUse.ALLOWED)
CTX_SHOWN = ContextPolicy(shown_list=ContextUse.ALLOWED, language_preference=ContextUse.ALLOWED)
CTX_ARTIFACT = ContextPolicy(artifact_scope=ContextUse.ALLOWED, language_preference=ContextUse.ALLOWED)
CTX_SCAN_DELTA = ContextPolicy(scan_comparison=ContextUse.ALLOWED, language_preference=ContextUse.ALLOWED)
CTX_FIX_NOW = ContextPolicy(fix_now_list=ContextUse.ALLOWED, shown_list=ContextUse.CONDITIONAL, language_preference=ContextUse.ALLOWED)
CTX_FAILED_ROUTE = ContextPolicy(failed_route_state=ContextUse.ALLOWED, previous_answer=ContextUse.CONDITIONAL, language_preference=ContextUse.ALLOWED)

FAST = SpeedBudget(deterministic_ms=300, total_timeout_ms=500, max_output_tokens=160, max_answer_words=80, short_answer_default=True)
FACT_FAST = SpeedBudget(deterministic_ms=400, total_timeout_ms=500, max_output_tokens=220, max_answer_words=140, short_answer_default=True)
WORKFLOW_FAST = SpeedBudget(deterministic_ms=800, total_timeout_ms=1200, max_output_tokens=360, max_answer_words=220, short_answer_default=True)
CLASSIFIER_FAST = SpeedBudget(deterministic_ms=200, provider_timeout_ms=2000, total_timeout_ms=2000, max_output_tokens=96, max_answer_words=80, short_answer_default=True)
VERBALIZER_FAST = SpeedBudget(deterministic_ms=300, provider_timeout_ms=1500, total_timeout_ms=1500, max_output_tokens=120, max_answer_words=60, short_answer_default=True)


def _fallback(mode: ResponseMode, key: str | None = None, *, clarify: bool = False, refusal: bool = False) -> FallbackPolicy:
    return FallbackPolicy(mode, key, ask_clarification=clarify, safe_refusal=refusal, no_context_message=clarify)


def _policy(
    situation_id: str,
    family: SituationFamily,
    *,
    priority: int,
    response_mode: ResponseMode,
    provider_policy: ProviderPolicy = NO_PROVIDER,
    context_policy: ContextPolicy = CTX_NONE,
    evidence_policy: EvidencePolicy = NO_EVIDENCE,
    speed_budget: SpeedBudget = FAST,
    fallback_policy: FallbackPolicy | None = None,
    threshold: float = 0.8,
    tags: tuple[str, ...] = (),
    description: str = "",
) -> SituationPolicy:
    return SituationPolicy(
        situation_id=situation_id,
        family=family,
        priority=priority,
        default_confidence_threshold=threshold,
        response_mode=response_mode,
        provider_policy=provider_policy,
        context_policy=context_policy,
        evidence_policy=evidence_policy,
        speed_budget=speed_budget,
        fallback_policy=fallback_policy or _fallback(ResponseMode.NO_MODEL_TEMPLATE),
        audit_fields=("situation_id", "situation_family", "situation_response_mode", "situation_provider_mode"),
        tags=tags,
        description=description or situation_id,
        examples=(),
        confusion_risks=(),
    )


def _build_registry() -> dict[str, SituationPolicy]:
    policies: dict[str, SituationPolicy] = {}

    def add(policy: SituationPolicy) -> None:
        policies[policy.situation_id] = policy

    for sid in [
        "social.greeting", "social.greeting_status", "social.status_check", "social.thanks",
        "social.praise", "social.casual_reaction", "social.frustration_unclear", "social.farewell",
    ]:
        add(_policy(sid, SituationFamily.SOCIAL, priority=40, response_mode=ResponseMode.FAST_VERBALIZER, provider_policy=VERBALIZER_PROVIDER, speed_budget=VERBALIZER_FAST, tags=("social",)))

    for sid in [
        "capability.what_can_you_do", "capability.how_can_you_help", "capability.data_access",
        "capability.limitations", "capability.model_status", "capability.privacy_safety",
        "capability.tool_boundary",
    ]:
        add(_policy(sid, SituationFamily.CAPABILITY, priority=55, response_mode=ResponseMode.DETERMINISTIC_RENDERER, speed_budget=FAST, tags=("capability",)))

    for sid in [
        "dspm.count.total_findings", "dspm.count.severity_subset", "dspm.distribution.severity",
        "dspm.breakdown.risk_type", "dspm.list.findings", "dspm.metric.posture_score",
        "dspm.metric.explain_count_basis",
    ]:
        context = CTX_COUNT if sid in {"dspm.count.severity_subset", "dspm.metric.explain_count_basis"} else CTX_NONE
        add(_policy(sid, SituationFamily.DSPM_FACTUAL, priority=70, response_mode=ResponseMode.CANONICAL_FACT_RENDERER, context_policy=context, evidence_policy=CANONICAL_EVIDENCE, speed_budget=FACT_FAST, tags=("dspm", "canonical")))
    add(_policy("dspm.detail.selected_finding", SituationFamily.DSPM_FACTUAL, priority=70, response_mode=ResponseMode.CANONICAL_FACT_RENDERER, context_policy=CTX_SELECTED, evidence_policy=CANONICAL_EVIDENCE, speed_budget=FACT_FAST, tags=("dspm", "canonical")))

    workflow_contexts = {
        "workflow.scan_delta": CTX_SCAN_DELTA,
        "workflow.fix_now_top_risks": CTX_FIX_NOW,
        "workflow.aggregate_remediation": CTX_COUNT,
        "workflow.selected_finding_remediation": CTX_SELECTED,
        "workflow.evidence_explanation": CTX_SELECTED,
        "workflow.priority_explanation": CTX_FIX_NOW,
    }
    for sid in [
        "workflow.fix_now_top_risks", "workflow.triage", "workflow.scan_delta", "workflow.manager_summary",
        "workflow.technical_remediation", "workflow.aggregate_remediation", "workflow.selected_finding_remediation",
        "workflow.evidence_explanation", "workflow.priority_explanation", "workflow.remediation_checklist",
    ]:
        evidence = CANONICAL_EVIDENCE if sid in {"workflow.fix_now_top_risks", "workflow.scan_delta"} else REQUIRED_EVIDENCE
        add(_policy(sid, SituationFamily.ANALYST_WORKFLOW, priority=65, response_mode=ResponseMode.DETERMINISTIC_RENDERER, context_policy=workflow_contexts.get(sid, CTX_SHOWN), evidence_policy=evidence, speed_budget=WORKFLOW_FAST, tags=("workflow", "evidence")))

    context_map = {
        "context.selected_finding_followup": CTX_SELECTED,
        "context.previous_answer_condense": CTX_PREVIOUS,
        "context.previous_answer_expand": CTX_PREVIOUS,
        "context.previous_answer_translate": CTX_PREVIOUS,
        "context.style_change": CTX_PREVIOUS,
    }
    for sid in [
        "context.shown_list_followup", "context.selected_finding_followup", "context.previous_answer_condense",
        "context.previous_answer_expand", "context.previous_answer_translate", "context.next_unshown",
        "context.ordinal_item", "context.compare_shown_items", "context.style_change",
    ]:
        evidence = REQUIRED_EVIDENCE if sid not in {"context.previous_answer_condense", "context.previous_answer_translate", "context.style_change"} else OPTIONAL_EVIDENCE
        add(_policy(sid, SituationFamily.CONVERSATION_CONTEXT, priority=60, response_mode=ResponseMode.DETERMINISTIC_RENDERER, context_policy=context_map.get(sid, CTX_SHOWN), evidence_policy=evidence, speed_budget=FAST, fallback_policy=_fallback(ResponseMode.CLARIFICATION, "missing_context", clarify=True), tags=("context",)))

    complaint_response = {
        "complaint.ne_elaqe": ResponseMode.CLARIFICATION,
        "complaint.did_not_want_that": ResponseMode.CLARIFICATION,
        "complaint.why_failed": ResponseMode.CLARIFICATION,
    }
    for sid in [
        "complaint.scope_correction", "complaint.wrong_route", "complaint.count_conflict",
        "complaint.previous_contradiction", "complaint.repeated_misunderstanding", "complaint.ne_elaqe",
        "complaint.did_not_want_that", "complaint.why_answered_this", "complaint.why_failed",
        "complaint.language_quality",
    ]:
        evidence = CANONICAL_EVIDENCE if sid == "complaint.count_conflict" else OPTIONAL_EVIDENCE
        add(_policy(sid, SituationFamily.COMPLAINT, priority=80, response_mode=complaint_response.get(sid, ResponseMode.DETERMINISTIC_RENDERER), context_policy=CTX_FAILED_ROUTE, evidence_policy=evidence, speed_budget=FAST, fallback_policy=_fallback(ResponseMode.CLARIFICATION, "repair_scope", clarify=True), tags=("complaint",)))

    artifact_contexts = {
        "artifact.full_link_request": CTX_ARTIFACT,
        "artifact.clickable_link_request": CTX_ARTIFACT,
        "artifact.download_help": CTX_ARTIFACT,
        "artifact.reuse_previous": CTX_ARTIFACT,
        "artifact.export_status": CTX_ARTIFACT,
        "artifact.broken_link_complaint": CTX_ARTIFACT,
    }
    for sid in [
        "artifact.create_report", "artifact.filter_report", "artifact.download_help", "artifact.full_link_request",
        "artifact.clickable_link_request", "artifact.broken_link_complaint", "artifact.reuse_previous",
        "artifact.cancel_topic", "artifact.export_status", "artifact.unavailable",
    ]:
        add(_policy(sid, SituationFamily.ARTIFACT, priority=75, response_mode=ResponseMode.DETERMINISTIC_RENDERER, context_policy=artifact_contexts.get(sid, CTX_NONE), evidence_policy=ARTIFACT_EVIDENCE, speed_budget=FAST, fallback_policy=_fallback(ResponseMode.CLARIFICATION, "artifact_context", clarify=sid != "artifact.cancel_topic"), tags=("artifact",)))

    for sid in [
        "language.complaint", "language.malformed_output", "language.invalid_az_word", "language.truncated_answer",
        "language.switch_language", "language.translate_previous", "language.mixed_repair", "language.enforce_selected",
    ]:
        add(_policy(sid, SituationFamily.LANGUAGE, priority=85, response_mode=ResponseMode.DETERMINISTIC_RENDERER, context_policy=CTX_PREVIOUS if sid in {"language.translate_previous", "language.malformed_output", "language.truncated_answer"} else CTX_NONE, evidence_policy=NO_EVIDENCE, speed_budget=FAST, tags=("language",)))

    for sid in [
        "edu.dspm_concept", "edu.security_concept", "edu.compliance_concept", "edu.risk_score",
        "edu.severity", "edu.remediation_concept", "edu.step_by_step", "edu.beginner",
        "edu.metric_semantics",
    ]:
        add(_policy(sid, SituationFamily.EDUCATIONAL, priority=35, response_mode=ResponseMode.FAST_VERBALIZER, provider_policy=VERBALIZER_PROVIDER, evidence_policy=OPTIONAL_EVIDENCE, speed_budget=VERBALIZER_FAST, tags=("education",)))

    general_modes = {
        "general.provider_unavailable": (ResponseMode.NO_MODEL_TEMPLATE, NO_PROVIDER),
        "general.external_world": (ResponseMode.SAFE_REFUSAL, DISALLOWED_PROVIDER),
    }
    for sid in [
        "general.simple_arithmetic", "general.knowledge", "general.casual_non_dspm",
        "general.external_world", "general.personal_advice", "general.unrelated_request",
        "general.provider_unavailable",
    ]:
        mode, provider = general_modes.get(sid, (ResponseMode.FAST_VERBALIZER, VERBALIZER_PROVIDER))
        if sid == "general.simple_arithmetic":
            mode, provider = ResponseMode.NO_MODEL_TEMPLATE, NO_PROVIDER
        add(_policy(sid, SituationFamily.GENERAL, priority=25, response_mode=mode, provider_policy=provider, speed_budget=VERBALIZER_FAST if provider == VERBALIZER_PROVIDER else FAST, tags=("general",)))

    for sid in [
        "safety.raw_secrets", "safety.private_values", "safety.prompt_injection", "safety.arbitrary_tools",
        "safety.tenant_bypass", "safety.dangerous_action", "safety.hallucination_risk",
        "safety.unsupported_export_action",
    ]:
        add(_policy(sid, SituationFamily.SAFETY, priority=100, response_mode=ResponseMode.SAFE_REFUSAL, provider_policy=DISALLOWED_PROVIDER, speed_budget=FAST, fallback_policy=_fallback(ResponseMode.SAFE_REFUSAL, "safety_refusal", refusal=True), tags=("safety",)))

    unknown_specs = {
        "unknown.needs_ai_arbiter": (ResponseMode.FAST_CLASSIFIER_ONLY, CLASSIFIER_PROVIDER),
        "unknown.needs_structured_planner": (ResponseMode.STRUCTURED_AI_PLANNER, PLANNER_PROVIDER),
    }
    for sid in [
        "unknown.low_confidence", "unknown.multi_intent", "unknown.missing_entity", "unknown.missing_scope",
        "unknown.missing_scan", "unknown.unclear_pronoun", "unknown.needs_clarification",
        "unknown.needs_ai_arbiter", "unknown.needs_structured_planner",
    ]:
        mode, provider = unknown_specs.get(sid, (ResponseMode.CLARIFICATION, NO_PROVIDER))
        add(_policy(sid, SituationFamily.UNKNOWN, priority=20, response_mode=mode, provider_policy=provider, context_policy=ContextPolicy(selected_finding=ContextUse.CONDITIONAL, shown_list=ContextUse.CONDITIONAL, count_scope=ContextUse.CONDITIONAL, artifact_scope=ContextUse.CONDITIONAL, previous_answer=ContextUse.CONDITIONAL, language_preference=ContextUse.ALLOWED), evidence_policy=OPTIONAL_EVIDENCE, speed_budget=CLASSIFIER_FAST if provider != NO_PROVIDER else FAST, fallback_policy=_fallback(ResponseMode.CLARIFICATION, "unknown_clarification", clarify=True), threshold=0.6, tags=("unknown",)))

    return policies


SITUATION_POLICIES: dict[str, SituationPolicy] = _build_registry()


def maybe_get_policy(situation_id: str) -> SituationPolicy | None:
    return SITUATION_POLICIES.get(str(situation_id or ""))


def get_policy(situation_id: str) -> SituationPolicy:
    policy = maybe_get_policy(situation_id)
    if policy is None:
        raise KeyError(f"Unknown situation policy: {situation_id}")
    return policy


def list_policies() -> tuple[SituationPolicy, ...]:
    return tuple(SITUATION_POLICIES[key] for key in sorted(SITUATION_POLICIES))


def policies_by_family(family: str) -> tuple[SituationPolicy, ...]:
    family_value = family.value if isinstance(family, SituationFamily) else str(family)
    return tuple(policy for policy in list_policies() if policy.family.value == family_value)


def validate_policy_registry() -> list[str]:
    errors: list[str] = []
    for situation_id, policy in SITUATION_POLICIES.items():
        if situation_id != policy.situation_id:
            errors.append(f"{situation_id}: registry key mismatch")
        errors.extend(policy.validate())
    missing = {item.value for item in SituationId} - set(SITUATION_POLICIES)
    for situation_id in sorted(missing):
        errors.append(f"{situation_id}: missing policy")
    return errors


def _enum_or_value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def _snapshot_policy(policy: SituationPolicy) -> dict[str, Any]:
    data = asdict(policy)
    return _normalize_dict(data)


def _normalize_dict(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _normalize_dict(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_dict(item) for item in value]
    return value


def _allowed(value: ContextUse) -> bool:
    return value != ContextUse.FORBIDDEN


def build_decision_from_candidate(
    candidate: SituationCandidate,
    candidates: list[SituationCandidate] | tuple[SituationCandidate, ...] | None = None,
) -> SituationDecision:
    policy = get_policy(candidate.situation_id)
    all_candidates = tuple(candidates) if candidates is not None else (candidate,)
    provider = policy.provider_policy
    context = policy.context_policy
    evidence_required = policy.evidence_policy.requirement in {EvidenceRequirement.REQUIRED, EvidenceRequirement.REQUIRED_CANONICAL}
    metadata = {
        key: value
        for key, value in (candidate.metadata or {}).items()
        if key not in {"raw_message", "message", "user_text", "prompt", "raw_user_text"}
    }
    return SituationDecision(
        situation_id=policy.situation_id,
        family=policy.family.value,
        confidence=max(0.0, min(float(candidate.confidence), 1.0)),
        priority=int(candidate.priority or policy.priority),
        reason=candidate.reason,
        signals=tuple(candidate.signals),
        response_mode=policy.response_mode,
        provider_mode=provider.provider_mode,
        provider_allowed=provider.provider_allowed,
        planner_allowed=provider.planner_allowed,
        final_answer_allowed=provider.final_answer_allowed,
        verbalizer_allowed=provider.verbalizer_allowed,
        translator_allowed=provider.translator_allowed,
        selected_finding_allowed=_allowed(context.selected_finding),
        shown_list_allowed=_allowed(context.shown_list),
        count_scope_allowed=_allowed(context.count_scope),
        artifact_scope_allowed=_allowed(context.artifact_scope),
        previous_answer_allowed=_allowed(context.previous_answer),
        evidence_required=evidence_required,
        canonical_answer_required=policy.evidence_policy.canonical_answer_required,
        speed_budget=_normalize_dict(asdict(policy.speed_budget)),
        fallback_mode=policy.fallback_policy.fallback_mode.value,
        candidates=all_candidates,
        metadata=metadata,
    )


_ROUTE_ID_TO_SITUATION_ID: dict[str, str] = {
    "malformed_output_complaint": "language.malformed_output",
    "language_complaint": "language.complaint",
    "cancel_or_reset_topic": "artifact.cancel_topic",
    "artifact_full_link": "artifact.full_link_request",
    "artifact_download_help": "artifact.download_help",
    "previous_answer_condense": "context.previous_answer_condense",
    "previous_answer_rerender_or_condense": "context.previous_answer_translate",
    "count_conflict": "complaint.count_conflict",
    "count_conflict_or_why_previous_answer": "complaint.count_conflict",
    "wrong_route_complaint": "complaint.wrong_route",
    "aggregate_scope_remediation": "workflow.aggregate_remediation",
    "scan_delta": "workflow.scan_delta",
    "scan_delta_or_what_changed": "workflow.scan_delta",
    "fix_now_top_risks": "workflow.fix_now_top_risks",
}

_PROFESSIONAL_INTENT_TO_SITUATION_ID: dict[str, str] = {
    "riskiest_item": "context.shown_list_followup",
    "triage_priorities": "workflow.triage",
    "risk_type_breakdown": "dspm.breakdown.risk_type",
    "manager_summary": "workflow.manager_summary",
    "technical_remediation": "workflow.technical_remediation",
    "condense_previous": "context.previous_answer_condense",
}


def situation_from_route_id(route_id: str, metadata: Mapping[str, Any] | None = None) -> str | None:
    metadata = metadata or {}
    route_id = str(route_id or "")
    if route_id == "artifact_link_or_download_help":
        repair_intent = str(metadata.get("repair_intent") or metadata.get("answer_type") or "")
        if repair_intent == "artifact_create":
            return "artifact.create_report"
        if repair_intent == "artifact_link":
            return "artifact.full_link_request"
        if repair_intent == "artifact_download_help":
            return "artifact.download_help"
        return None
    if route_id == "previous_answer_rerender_or_condense":
        answer_type = str(metadata.get("answer_type") or "")
        professional_intent = str(metadata.get("professional_intent") or "")
        if answer_type == "condense_previous" or professional_intent == "condense_previous":
            return "context.previous_answer_condense"
        return "context.previous_answer_translate"
    if route_id == "count_conflict_or_why_previous_answer":
        if metadata.get("why_previous") and not metadata.get("count_conflict"):
            return "complaint.why_answered_this"
        return "complaint.count_conflict"
    if route_id == "wrong_route_complaint":
        return "complaint.ne_elaqe" if metadata.get("repair_why_misunderstood") else "complaint.wrong_route"
    if route_id == "professional_followup":
        return _PROFESSIONAL_INTENT_TO_SITUATION_ID.get(str(metadata.get("professional_intent") or ""))
    if route_id == "deterministic_contract_route":
        repair_intent = str(metadata.get("repair_intent") or "")
        if repair_intent == "severity_subset_count":
            return "dspm.count.severity_subset"
        if repair_intent == "general_scope_advice":
            return "general.unrelated_request"
        return None
    return _ROUTE_ID_TO_SITUATION_ID.get(route_id)


def decision_from_route_decision(route_decision: Any) -> SituationDecision | None:
    if route_decision is None:
        return None
    route_metadata = dict(getattr(route_decision, "metadata", {}) or {})
    answer_type = getattr(route_decision, "answer_type", None)
    if answer_type is not None and "answer_type" not in route_metadata:
        route_metadata["answer_type"] = answer_type
    situation_id = situation_from_route_id(str(getattr(route_decision, "route_id", "")), route_metadata)
    if situation_id is None or maybe_get_policy(situation_id) is None:
        return None
    candidate = SituationCandidate(
        situation_id=situation_id,
        confidence=float(getattr(route_decision, "confidence", 1.0) or 1.0),
        priority=int(getattr(route_decision, "priority", 1) or 1),
        matched=True,
        reason=str(getattr(route_decision, "reason", "") or "route decision bridge"),
        signals=tuple(str(item) for item in (getattr(route_decision, "signals", []) or [])),
        metadata=route_metadata,
    )
    decision = build_decision_from_candidate(candidate)
    provider_overrides = {
        "provider_allowed": bool(getattr(route_decision, "provider_allowed", decision.provider_allowed)),
        "translator_allowed": bool(getattr(route_decision, "translator_allowed", decision.translator_allowed)),
        "selected_finding_allowed": bool(getattr(route_decision, "selected_finding_used", decision.selected_finding_allowed)),
        "count_scope_allowed": bool(getattr(route_decision, "count_scope_used", decision.count_scope_allowed)),
        "artifact_scope_allowed": bool(getattr(route_decision, "artifact_scope_used", decision.artifact_scope_allowed)),
    }
    return SituationDecision(
        **{
            **decision.__dict__,
            **provider_overrides,
        }
    )


def route_situation_metadata(route_decision: Any) -> dict[str, Any]:
    decision = decision_from_route_decision(route_decision)
    return decision.to_route_metadata() if decision is not None else {}
