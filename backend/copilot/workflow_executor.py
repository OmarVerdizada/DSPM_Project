"""Workflow executor — runs multi-step skill workflows.

Chains skill outputs: step N can reference results from step N-1.
All deterministic skill steps produce 0 LLM calls.
At most 1 LLM finalization call for the entire compound workflow.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from backend.copilot.skill_registry import DSPM_SKILL_REGISTRY, DSPMSkill
from backend.copilot.workflow import WorkflowPlan, WorkflowStep

_log = logging.getLogger(__name__)


@dataclass
class StepResult:
    skill_id: str
    answer: str
    tool_results: list[Any] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    sources: list[Any] = field(default_factory=list)
    elapsed_ms: int = 0
    llm_called: bool = False
    error: str | None = None


@dataclass
class WorkflowResult:
    steps: list[StepResult]
    combined_answer: str
    total_elapsed_ms: int = 0
    total_llm_calls: int = 0
    is_compound: bool = True


def combine_step_answers(results: list[StepResult]) -> str:
    parts: list[str] = []
    for i, result in enumerate(results):
        if result.error:
            continue
        if result.answer.strip():
            parts.append(result.answer.strip())
    return "\n\n---\n\n".join(parts)


def merge_sources(results: list[StepResult]) -> list:
    seen: set[str] = set()
    merged: list = []
    for result in results:
        for source in result.sources:
            key = str(source)
            if key not in seen:
                seen.add(key)
                merged.append(source)
    return merged


def merge_tools_used(results: list[StepResult]) -> list[str]:
    seen: set[str] = set()
    merged: list[str] = []
    for result in results:
        for tool in result.tools_used:
            if tool not in seen:
                seen.add(tool)
                merged.append(tool)
    return merged


def resolve_step_dependency(step: WorkflowStep, previous_results: list[StepResult]) -> dict[str, Any]:
    """Extract context from a previous step's results to pass to the current step."""
    params = dict(step.params)
    if step.depends_on is None or step.depends_on >= len(previous_results):
        return params

    dep_result = previous_results[step.depends_on]
    if not dep_result.tool_results:
        return params

    target_index = params.get("target_index")
    if target_index is not None and dep_result.tool_results:
        items = _extract_shown_items(dep_result)
        if items:
            if target_index == -1:
                params["resolved_item"] = items[-1]
            elif 1 <= target_index <= len(items):
                params["resolved_item"] = items[target_index - 1]

    if step.consumes == "all_results":
        params["_all_previous_items"] = _extract_shown_items(dep_result)
        params["_previous_answer"] = dep_result.answer
        params["_previous_tool_results"] = dep_result.tool_results
    elif step.consumes == "single_item":
        params["_previous_answer"] = dep_result.answer
        params["_previous_tool_results"] = dep_result.tool_results
    else:
        params["_previous_answer"] = dep_result.answer
        params["_previous_tool_results"] = dep_result.tool_results
    return params


def _extract_shown_items(result: StepResult) -> list[dict]:
    items: list[dict] = []
    for tr in result.tool_results:
        try:
            content = tr.content if isinstance(tr.content, str) else str(tr.content)
            data = json.loads(content)
        except (json.JSONDecodeError, AttributeError, TypeError):
            continue
        if isinstance(data, dict):
            results_list = data.get("results") or []
            if isinstance(results_list, list):
                for item in results_list:
                    if isinstance(item, dict):
                        items.append(item)
    return items
