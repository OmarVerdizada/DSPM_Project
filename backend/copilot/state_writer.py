"""Canonical write path for Copilot conversational session state.

The session context is persisted as a backwards-compatible dict, and
:class:`backend.copilot.conversation_state.ConversationState` is the typed
read view over it. Historically *writes* were scattered: handlers mutated raw
legacy keys directly and only a few sites re-synced the typed
``conversation_state_v2`` payload, so the typed view and the raw dict could
drift between turns.

This module is the single sanctioned write API for the important
conversational state:

- last answer envelope (type / language / summary)
- selected finding / shown items / count scope
- rejected route + correction context
- language decision

Every writer mutates the legacy keys (serialization detail, kept for
backward compatibility with older sessions and existing readers) and then
re-syncs ``conversation_state_v2`` through the ConversationState round-trip,
so the typed view can never drift from what was written.

Raw-dict writes by legacy callers still work — ``ConversationState.
from_legacy_context`` reads the legacy keys — but new code should write
through this module.
"""
from __future__ import annotations

from typing import Any, Mapping

from backend.copilot.conversation_state import ConversationState

_MAX_ANSWER_SUMMARY = 500
_MAX_ANSWER_TEXT = 1200
_MAX_CORRECTION = 300


def sync(context: dict | None) -> dict:
    """Re-derive the typed state from the legacy keys and write it back as
    ``conversation_state_v2``. This is the one normalization point; the old
    ``service._normalize_conversation_state`` delegates here."""
    return ConversationState.from_legacy_context(context).to_legacy_context(context or {})


def record_answer_envelope(
    context: dict,
    *,
    task_type: str,
    answer_summary: str | None = None,
    answer_text: str | None = None,
    language: str | None = None,
    preserve_existing_answer_type: bool = True,
) -> dict:
    """Record the previous-answer envelope. ``answer_summary``/``answer_text``
    must already be masked/cleaned by the caller (this module never masks —
    it is a state writer, not a guardrail)."""
    if answer_summary is not None:
        context["last_answer_summary"] = str(answer_summary)[:_MAX_ANSWER_SUMMARY]
    if answer_text is not None:
        context["last_answer_text"] = str(answer_text)[:_MAX_ANSWER_TEXT]
    if language:
        context["last_answer_language"] = language
    context["last_task_type"] = task_type
    if preserve_existing_answer_type:
        context["last_answer_type"] = context.get("last_answer_type") or task_type
    else:
        context["last_answer_type"] = task_type
    return context


def record_failed_route(context: dict, route: str | None, correction: str | None = None) -> dict:
    """Record the rejected route + the user's correction text so next-turn
    routers can avoid repeating the rejected route."""
    if route:
        context["last_failed_route"] = str(route)[:120]
    if correction is not None:
        context["last_user_correction"] = str(correction)[:_MAX_CORRECTION]
    return context


def record_correction_effects(context: dict, effects: Mapping[str, Any] | None) -> dict:
    """Apply the state effects produced by
    :func:`backend.copilot.correction_controller.correction_state_effects`."""
    for key, value in (effects or {}).items():
        context[key] = value
    return context


def record_selected_finding(context: dict, item: Mapping[str, Any] | None) -> dict:
    if isinstance(item, Mapping):
        context["current_item"] = dict(item)
    return context


def clear_selected_finding(context: dict) -> dict:
    context.pop("current_item", None)
    return context


def record_shown_items(context: dict, items: list[dict] | None, *, scan_id: str | None = None) -> dict:
    context["last_shown_items"] = list(items or [])
    if scan_id:
        context["last_scan_id"] = scan_id
    return context


def record_count_scope(
    context: dict,
    *,
    severities: list[str] | None = None,
    scan_id: str | None = None,
    metric: str | None = None,
    answer_type: str | None = None,
) -> dict:
    if severities is not None:
        context["last_count_scope_severities"] = list(severities)
    if scan_id:
        context["last_count_scope_scan_id"] = scan_id
    if metric:
        context["last_count_scope_metric"] = metric
    if answer_type:
        context["last_answer_type"] = answer_type
    return context


def record_language_decision(context: dict, *, language: str | None = None, source: str | None = None) -> dict:
    if language:
        context["response_language"] = language
    if source:
        context["language_source"] = source
    return context
