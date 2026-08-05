"""Single authoritative entry point for the Copilot Situation/Route decision.

The runtime has several routing-adjacent layers that historically re-detected
the same concepts independently inside ``service.handle_chat``:

- ``situation_classifier`` — deterministic situation classification;
- ``route_dispatcher`` — typed early-route dispatch (P0 guardrails,
  corrections, professional follow-ups, contract routes);
- ``intent_router`` — deterministic contract routes / heuristics;
- ``planner`` — structured AI planning for ambiguous/compound turns;
- ``situation_arbiter`` — LLM tie-breaker for genuinely ambiguous situations.

Authority order (highest first) — this is the contract, and the arbiter is a
tie-breaker only, never a primary fact source:

1. Route dispatcher early routes (P0 guardrail > malformed/language
   complaint > cancel/artifact/rerender > correction routes > professional
   follow-ups > contract routes), each fed by the *single-source* detectors
   in ``correction_detection`` / ``language_service`` / ``severity``.
2. Active TaskFrame resolution (only for task-frame-compatible routes).
3. Deterministic contract routes / intent_router heuristics.
4. Structured AI planner (validated, allowlisted tools only).
5. Situation arbiter — ambiguity tie-breaking only.
6. Evidence gate (``evidence_sensitivity``) in front of any provider-final.

This module owns the joint classification step: it runs the situation
classifier and the route dispatcher on identical inputs and merges the
classifier fields into the dispatch decision, so ``service.handle_chat``
consumes one :class:`RoutingOutcome` instead of assembling the layers
inline. Remaining legacy paths (intent_router contract routes and the
planner heuristics further down ``handle_chat``) are documented above and
still execute after these early routes, unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from backend.copilot import route_dispatcher, situation_classifier

# Route ids that may hand over to an active TaskFrame before their handler
# runs. Any other early route (corrections, complaints, artifact help …)
# must keep precedence over the task frame.
TASK_FRAME_COMPATIBLE_ROUTES: frozenset[str | None] = frozenset({
    None,
    "p0_situation_guardrail",
    "deterministic_contract_route",
    "structured_ai_planner_candidate",
    "legacy_provider_fallback",
})


@dataclass(frozen=True)
class RoutingOutcome:
    """Joint result of the deterministic routing layers for one turn."""

    situation_context: situation_classifier.SituationClassificationContext
    situation_decision: Any | None
    dispatch_decision: route_dispatcher.RouteDecision | None

    @property
    def route_id(self) -> str | None:
        return self.dispatch_decision.route_id if self.dispatch_decision is not None else None

    @property
    def task_frame_compatible(self) -> bool:
        return self.route_id in TASK_FRAME_COMPATIBLE_ROUTES

    def audit_metadata(self) -> dict[str, Any]:
        return route_dispatcher.decision_metadata(self.dispatch_decision)


def decide(
    *,
    message: str,
    normalized_message: str,
    target_language: str,
    session_state: Mapping[str, Any] | None,
    principal: Any | None = None,
    scan_id: str | None = None,
    selected_language: str | None = None,
    canonical_language: str | None = None,
) -> RoutingOutcome:
    """Run the deterministic routing layers once, on identical inputs.

    Zero provider calls. The situation-classifier fields are merged into the
    dispatch decision metadata so downstream audit sees one coherent
    decision instead of two divergent ones.
    """
    dispatch_context = route_dispatcher.RouteDispatchContext(
        message=message,
        normalized_message=normalized_message,
        target_language=target_language,
        legacy_context=session_state,
        principal=principal,
        scan_id=scan_id,
        selected_language=selected_language,
        canonical_metadata={"language": canonical_language},
    )
    situation_context = situation_classifier.SituationClassificationContext(
        message=message,
        normalized_message=normalized_message,
        target_language=target_language,
        legacy_context=session_state,
        selected_language=selected_language,
        scan_id=scan_id,
        last_answer_type=str((session_state or {}).get("last_answer_type") or "") or None,
    )
    situation_decision = situation_classifier.classify_situation(situation_context)
    dispatch_decision = route_dispatcher.dispatch(dispatch_context)
    if dispatch_decision is not None and situation_decision is not None:
        dispatch_decision = replace(
            dispatch_decision,
            metadata={
                **dispatch_decision.metadata,
                "_situation_classifier_fields": situation_decision.to_route_metadata(),
            },
        )
    return RoutingOutcome(
        situation_context=situation_context,
        situation_decision=situation_decision,
        dispatch_decision=dispatch_decision,
    )
