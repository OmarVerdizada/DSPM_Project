"""Safe runtime metadata helpers for Situation Intelligence.

This module is deliberately small. It centralizes latency/length/provider-role
metadata without executing routes, calling providers, or reading scan data.
"""
from __future__ import annotations

import re
from typing import Any


def response_word_count(answer: str) -> int:
    return len([part for part in re.split(r"\s+", str(answer or "").strip()) if part])


def response_length_class(answer: str) -> str:
    count = response_word_count(answer)
    if count <= 25:
        return "short"
    if count <= 80:
        return "medium"
    return "long"


def response_length_metadata(answer: str | None) -> dict[str, Any]:
    if answer is None:
        return {}
    return {
        "response_word_count": response_word_count(answer),
        "response_length_class": response_length_class(answer),
    }


def speed_budget_metadata(decision: Any | None) -> dict[str, Any]:
    if decision is None:
        return {}
    budget = getattr(decision, "speed_budget", None) or {}
    if not isinstance(budget, dict):
        return {}
    provider_timeout = _int_or_none(budget.get("provider_timeout_ms"))
    total_timeout = _int_or_none(budget.get("total_timeout_ms"))
    deterministic = _int_or_none(budget.get("deterministic_ms"))
    max_words = _int_or_none(budget.get("max_answer_words"))
    max_tokens = _int_or_none(budget.get("max_output_tokens"))
    metadata = {
        "situation_speed_budget_ms": total_timeout or deterministic,
        "situation_provider_timeout_ms": provider_timeout,
        "situation_total_timeout_ms": total_timeout,
        "situation_max_answer_words": max_words,
        "situation_max_output_tokens": max_tokens,
    }
    provider_mode = str(getattr(getattr(decision, "provider_mode", None), "value", getattr(decision, "provider_mode", "")) or "")
    situation_id = str(getattr(decision, "situation_id", "") or "")
    if provider_mode == "TINY_NO_THINK_CLASSIFIER" or situation_id.startswith("unknown."):
        metadata["arbiter_timeout_ms"] = provider_timeout or 2000
    if provider_mode == "TINY_NO_THINK_VERBALIZER" or situation_id.startswith(("social.", "edu.", "general.")):
        metadata["verbalizer_timeout_ms"] = provider_timeout or 1500
    return {key: value for key, value in metadata.items() if value is not None}


def runtime_response_metadata(
    *,
    answer: str | None = None,
    decision: Any | None = None,
    fallback_used: bool | None = None,
    fallback_reason: str | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    metadata.update(speed_budget_metadata(decision))
    metadata.update(response_length_metadata(answer))
    if fallback_used is not None:
        metadata["fallback_used"] = bool(fallback_used)
    if fallback_reason:
        metadata["fallback_reason"] = str(fallback_reason)[:160]
    return metadata


def provider_role_budget_summary(
    *,
    verbalizer_call_count: int = 0,
    arbiter_call_count: int = 0,
    planner_call_count: int = 0,
    final_provider_call_count: int = 0,
    translator_call_count: int = 0,
    fast_verbalizer_used: bool = False,
    fast_verbalizer_fallback_used: bool = False,
) -> dict[str, Any]:
    roles = {
        "verbalizer_call_count": max(0, int(verbalizer_call_count or 0)),
        "arbiter_call_count": max(0, int(arbiter_call_count or 0)),
        "planner_call_count": max(0, int(planner_call_count or 0)),
        "final_provider_call_count": max(0, int(final_provider_call_count or 0)),
        "translator_call_count": max(0, int(translator_call_count or 0)),
    }
    total = sum(roles.values())
    return {
        **roles,
        "provider_call_count": total,
        "provider_budget_total": total,
        "provider_budget_roles": dict(roles),
        "provider_planning_called": bool(roles["planner_call_count"]),
        "provider_final_called": bool(roles["final_provider_call_count"]),
        "translator_called": bool(roles["translator_call_count"]),
        "fast_verbalizer_used": bool(fast_verbalizer_used),
        "fast_verbalizer_fallback_used": bool(fast_verbalizer_fallback_used),
    }


def role_budget_metadata(**kwargs: Any) -> dict[str, Any]:
    summary = provider_role_budget_summary(**kwargs)
    metadata = {
        key: summary[key]
        for key in (
            "verbalizer_call_count",
            "arbiter_call_count",
            "planner_call_count",
            "final_provider_call_count",
            "translator_call_count",
            "provider_budget_total",
            "provider_budget_roles",
        )
    }
    metadata["provider_role_budget_summary"] = summary
    return metadata


def enforce_short_answer(answer: str, max_words: int, fallback: str | None = None) -> str:
    text = str(answer or "").strip()
    if response_word_count(text) <= max_words:
        return text
    if fallback and response_word_count(fallback) <= max_words:
        return fallback.strip()
    words = [part for part in re.split(r"\s+", text) if part]
    return " ".join(words[: max(1, int(max_words))]).strip()


def _int_or_none(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None
