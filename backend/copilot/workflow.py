"""Multi-skill workflow planner and executor.

Decomposes compound user requests into ordered skill steps.
Deterministic decomposition — no LLM calls in the planner itself.
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

from backend.copilot.language import normalize_message
from backend.copilot.skill_registry import (
    DSPM_SKILL_REGISTRY,
    DSPMSkill,
    TASK_TO_SKILL,
    skill_for_task,
)

_log = logging.getLogger(__name__)

MAX_WORKFLOW_STEPS = 4


@dataclass(frozen=True)
class WorkflowStep:
    skill_id: str
    params: dict[str, Any] = field(default_factory=dict)
    depends_on: int | None = None
    consumes: str = "none"  # "none" | "single_item" | "all_results"


@dataclass(frozen=True)
class WorkflowPlan:
    steps: tuple[WorkflowStep, ...]
    is_compound: bool = False
    source_message: str = ""


_COMPOUND_CONNECTORS = re.compile(
    r"\b(?:and\s+(?:also\s+)?(?:then\s+)?|then\s+|after\s+that\s+|"
    r"also\s+|və\s+(?:həmçinin\s+)?|sonra\s+|həmçinin\s+|bundan\s+sonra\s+)"
    r"(?:show|list|explain|generate|create|compare|check|göstər|izah\s+et|yarat|müqayisə\s+et|yoxla)",
    re.IGNORECASE,
)

_EXPLAIN_FIRST_RE = re.compile(
    r"(?:explain|izah\s+et|describe|detail|açıqla)\s+(?:the\s+)?(?:first|1st|birinci|ilk)\s+(?:one|item|finding)?",
    re.IGNORECASE,
)

_EXPLAIN_LAST_RE = re.compile(
    r"(?:explain|izah\s+et|describe|detail|açıqla)\s+(?:the\s+)?(?:last|son|sonuncu)\s+(?:one|item|finding)?",
    re.IGNORECASE,
)

_EXPLAIN_NTH_RE = re.compile(
    r"(?:explain|izah\s+et|describe|detail|açıqla)\s+(?:the\s+)?(?:(\d+)(?:st|nd|rd|th)?|number\s+(\d+))\s*(?:one|item|finding)?",
    re.IGNORECASE,
)

_GENERATE_REPORT_RE = re.compile(
    r"\b(?:generate|create|export|yarat|ixrac)\s+(?:a\s+)?(?:pdf|report|hesabat)",
    re.IGNORECASE,
)

_LIST_CRITICAL_RE = re.compile(
    r"\b(?:show|list|göstər|siyahı)\s+(?:me\s+)?(?:the\s+)?(?:critical|high)\s+(?:findings?|alerts?|items?|tapıntılar?)",
    re.IGNORECASE,
)

_DASHBOARD_RE = re.compile(
    r"\b(?:dashboard|summary|xülasə|icmal|posture)\b",
    re.IGNORECASE,
)

_SEVERITY_DIST_RE = re.compile(
    r"\b(?:severity\s+(?:distribution|breakdown|count)|bölgü|paylan)",
    re.IGNORECASE,
)

_COMPARE_RE = re.compile(
    r"\b(?:compare|müqayisə|difference|fərq|diff)\b",
    re.IGNORECASE,
)

_CRITICAL_FILTER_RE = re.compile(
    r"\b(?:sadəcə|yalnız|only|cəmi)\s+(?:kritik|critical)\b|"
    r"\b(?:kritik|critical)\s+(?:olanları|olanlar|tapıntılar|alerts?)\b",
    re.IGNORECASE,
)

_SORT_BY_TIME_RE = re.compile(
    r"\b(?:vaxt|zaman|tarix|time|son|ən\s+yeni)\s+(?:olaraq\s+)?sırala|"
    r"sıralayıb|"
    r"(?:newest|oldest|by\s+time)\b",
    re.IGNORECASE,
)

_TEACH_RE = re.compile(
    r"\b(?:teach|teach\s+me|step\s+by\s+step|walk\s+me\s+through|how\s+to\s+fix|"
    r"what\s+does\s+this\s+mean|beginner|learn|oyret|oyredici|addim\s+addim|"
    r"basa\s+sal|sade\s+dille|ne\s+demekdir|nece\s+duzeltmek|nece\s+edim)\b",
    re.IGNORECASE,
)

_REMEDIATION_RE = re.compile(
    r"\b(?:recommend|recommendation|recommendations|remediation|remediate|fix|"
    r"what\s+should\s+i\s+do|what\s+can\s+i\s+do|ne\s+etmeliyem|neler\s+etmeliyem|"
    r"tovsiye|duzelis|hell)\b",
    re.IGNORECASE,
)

_RISK_RE = re.compile(
    r"\b(?:risk|risky|why|explain\s+why|niye|niyə|riskli|riskini|riskleri)\b",
    re.IGNORECASE,
)

_SON_SKAN_RE = re.compile(
    r"\b(?:son\s+skan|sonuncu\s+skan|ən\s+son\s+skan|keçən\s+skan|evvelki\s+skan|əvvəlki\s+skan)\b",
    re.IGNORECASE,
)


def _requested_limit(message: str) -> int | None:
    text = normalize_message(message)
    number_words = {
        "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
        "bir": 1, "iki": 2, "uc": 3, "üç": 3, "dord": 4, "bes": 5,
    }
    for word, value in number_words.items():
        if re.search(rf"\b{re.escape(word)}\b", text):
            return value
    m = re.search(r"\b(?:last|top|son)?\s*(\d{1,2})\s*(?:critical|kritik|alert|tapinti|finding)", text)
    if m:
        value = int(m.group(1))
        return max(1, min(value, 20))
    return None


def detect_compound_intents(message: str) -> list[str]:
    """Detect multiple skill IDs from a compound message. Returns list of skill_ids."""
    text = normalize_message(message)
    intents: list[str] = []
    seen: set[str] = set()

    def _add(sid: str) -> None:
        if sid not in seen:
            seen.add(sid)
            intents.append(sid)

    list_requested = bool(_LIST_CRITICAL_RE.search(message)) or (
        ("critical" in text or "kritik" in text)
        and any(term in text for term in ("alert", "alerti", "tapinti", "finding", "findings"))
        and any(term in text for term in ("show", "list", "give", "goster", "ver", "tap", "mene"))
    )
    if list_requested:
        _add("sk_critical_findings_list")

    if _DASHBOARD_RE.search(message):
        _add("sk_executive_dashboard")

    if _SEVERITY_DIST_RE.search(message):
        _add("sk_severity_distribution")

    if _COMPARE_RE.search(message) or (_SON_SKAN_RE.search(text) and "arasinda" in text):
        _add("sk_scan_comparison")

    if _EXPLAIN_FIRST_RE.search(message):
        _add("sk_finding_detail")
    elif _EXPLAIN_LAST_RE.search(message):
        _add("sk_finding_detail")
    elif _EXPLAIN_NTH_RE.search(message):
        _add("sk_finding_detail")

    if _GENERATE_REPORT_RE.search(message):
        _add("sk_report_generation")

    if _CRITICAL_FILTER_RE.search(message):
        _add("sk_critical_filter")

    if _SORT_BY_TIME_RE.search(message):
        _add("sk_sort_by_time")

    if _TEACH_RE.search(text) or (_REMEDIATION_RE.search(text) and _RISK_RE.search(text) and list_requested):
        _add("sk_teach_dspm")

    return intents


def _is_single_finding_teaching_request(message: str) -> bool:
    text = normalize_message(message)
    has_teaching = bool(_TEACH_RE.search(text)) or any(term in text for term in (
        "step by step", "pille pille", "pillə pillə", "addim addim", "basa sal", "başa sal",
    ))
    if not has_teaching:
        return False
    has_single_marker = (
        "random" in text
        or "tesadufi" in text
        or bool(re.search(r"\b(?:bir|1|one|single)\b.{0,40}\b(?:critical|kritik|alert|tapinti|finding)\b", text))
        or bool(re.search(r"\b(?:critical|kritik|alert|tapinti|finding)\b.{0,40}\b(?:bir|1|one|single)\b", text))
    )
    return has_single_marker and any(term in text for term in ("critical", "kritik", "alert", "tapinti", "finding"))


def _extract_explain_index(message: str) -> int | None:
    m = _EXPLAIN_FIRST_RE.search(message)
    if m:
        return 1
    m = _EXPLAIN_LAST_RE.search(message)
    if m:
        return -1
    m = _EXPLAIN_NTH_RE.search(message)
    if m:
        idx = m.group(1) or m.group(2)
        if idx:
            return int(idx)
    return None


def plan_workflow(message: str, task_type: str, session_context: dict | None = None) -> WorkflowPlan | None:
    """Try to decompose a message into a multi-step workflow.

    Returns None if the message is a single-skill request (caller falls back to existing path).
    """
    compound_skills = detect_compound_intents(message)
    if task_type == "list_plus_remediation" and _is_single_finding_teaching_request(message):
        return None
    if (
        task_type in {
        "critical_finding_details",
        "critical_finding_remediation",
        "critical_finding_risk_explanation",
        "finding_history",
        "remediation_status",
        "compliance_mapping",
        }
        and not {"sk_critical_findings_list", "sk_teach_dspm"}.issubset(set(compound_skills))
    ):
        return None

    if len(compound_skills) <= 1:
        return None

    if len(compound_skills) > MAX_WORKFLOW_STEPS:
        compound_skills = compound_skills[:MAX_WORKFLOW_STEPS]

    steps: list[WorkflowStep] = []
    list_step_index: int | None = None
    compare_step_index: int | None = None

    for i, skill_id in enumerate(compound_skills):
        params: dict[str, Any] = {}
        depends: int | None = None
        consumes: str = "none"

        if skill_id == "sk_finding_detail" and list_step_index is not None:
            depends = list_step_index
            consumes = "single_item"
            idx = _extract_explain_index(message)
            if idx is not None:
                params["target_index"] = idx

        if skill_id == "sk_report_generation" and steps:
            depends = len(steps) - 1

        if skill_id == "sk_critical_findings_list":
            list_step_index = i
            limit = _requested_limit(message)
            if limit is not None:
                params["requested_limit"] = limit

        if skill_id == "sk_scan_comparison":
            compare_step_index = i

        if skill_id == "sk_critical_filter" and compare_step_index is not None:
            depends = compare_step_index
            consumes = "all_results"

        if skill_id == "sk_sort_by_time" and steps:
            for step in reversed(steps):
                if step.skill_id in ("sk_critical_filter", "sk_critical_findings_list", "sk_scan_comparison"):
                    depends = steps.index(step)
                    consumes = "all_results"
                    break

        if skill_id == "sk_critical_findings_list":
            list_step_index = i

        if skill_id == "sk_teach_dspm":
            if list_step_index is not None:
                depends = list_step_index
                consumes = "all_results"
            elif steps:
                depends = len(steps) - 1
                consumes = "all_results"

        steps.append(WorkflowStep(skill_id=skill_id, params=params, depends_on=depends, consumes=consumes))

    if len(steps) <= 1:
        return None

    _log.info(
        "workflow_plan compound=%d steps=%s message=%r",
        len(steps),
        [s.skill_id for s in steps],
        message[:200],
    )

    return WorkflowPlan(
        steps=tuple(steps),
        is_compound=True,
        source_message=message[:500],
    )


def is_compound_request(message: str) -> bool:
    return len(detect_compound_intents(message)) > 1
