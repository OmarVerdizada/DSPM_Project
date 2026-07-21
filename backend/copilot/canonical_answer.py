from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath
from typing import Any

from backend.copilot.masking import mask_sensitive_text


SUPPORTED_METRICS = {
    "file_level_finding_count": {
        "object_type": "file",
        "source": "latest scan report",
        "definition": "Counts scanned files that match the requested finding filter. Raw detector hits are not included.",
    },
    "raw_detection_count": {
        "object_type": "detection",
        "source": "latest scan report",
        "definition": "Counts detector hits inside files. This is not the default finding/tapinti count.",
    },
    "severity_distribution_file_level": {
        "object_type": "file",
        "source": "latest scan report",
        "definition": "Counts scanned files grouped by severity.",
    },
    "risk_type_file_count": {
        "object_type": "file",
        "source": "latest scan report",
        "definition": "Counts files whose finding types map to the requested risk category.",
    },
    "shown_items_count": {
        "object_type": "display_item",
        "source": "rendered answer",
        "definition": "Counts the number of safe items shown in the answer.",
    },
    "artifact_generated": {
        "object_type": "artifact",
        "source": "local artifact store",
        "definition": "Records that a local report artifact was generated.",
    },
}


@dataclass(frozen=True)
class MetricSpec:
    name: str
    object_type: str
    scope: str | None
    source: str
    definition: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CanonicalFinding:
    id: str | None
    name: str
    severity: str | None
    risk_score: int | float | None
    risk_types: list[str] = field(default_factory=list)
    scan_id: str | None = None
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvidenceRef:
    source: str
    scan_id: str | None = None
    metric: str | None = None
    item_id: str | None = None
    item_name: str | None = None
    confidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CanonicalAnswer:
    answer_type: str
    display_text: str
    scan_id: str | None = None
    metric: MetricSpec | None = None
    items: list[CanonicalFinding] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    evidence: list[EvidenceRef] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    language: str | None = None

    def to_dict(self, max_items: int = 20, max_evidence: int = 10) -> dict[str, Any]:
        return {
            "answer_type": self.answer_type,
            "scan_id": self.scan_id,
            "metric": self.metric.to_dict() if self.metric else None,
            "items": [item.to_dict() for item in self.items[:max_items]],
            "counts": {str(key): int(value or 0) for key, value in self.counts.items()},
            "evidence": [item.to_dict() for item in self.evidence[:max_evidence]],
            "metadata": _safe_metadata(self.metadata),
            "language": self.language,
        }


def metric_spec(name: str, scope: str | None = None) -> MetricSpec:
    details = SUPPORTED_METRICS.get(name)
    if not details:
        details = {
            "object_type": "unknown",
            "source": "unknown",
            "definition": "Unspecified metric.",
        }
    return MetricSpec(
        name=name,
        object_type=str(details["object_type"]),
        scope=scope,
        source=str(details["source"]),
        definition=str(details["definition"]),
    )


def canonical_finding_from_dict(item: dict[str, Any], scan_id: str | None = None) -> CanonicalFinding:
    item_scan_id = _safe_text(item.get("scan_id") or scan_id, 120)
    name = _safe_name(item.get("name") or item.get("path") or item.get("file") or "unknown")
    item_id = _safe_text(item.get("id") or item.get("finding_id") or name, 160)
    return CanonicalFinding(
        id=item_id,
        name=name or "unknown",
        severity=_safe_severity(item.get("severity") or item.get("risk")),
        risk_score=_safe_score(item.get("risk_score")),
        risk_types=_safe_risk_types(item),
        scan_id=item_scan_id,
        source=_safe_text(item.get("source") or item.get("source_type") or "latest scan report", 120),
    )


def canonical_answer_for_count(payload: dict[str, Any], display_text: str, language: str | None = None) -> CanonicalAnswer:
    scan_id = _safe_text(payload.get("scan_id"), 120)
    severity = _safe_severity(payload.get("severity"))
    count = _safe_int(payload.get("count"))
    counts = {"total_count": count}
    if severity:
        counts[severity] = count
    answer_type = "severity_count" if severity else "finding_count"
    metric = metric_spec("file_level_finding_count", scope=severity or "all_findings")
    return CanonicalAnswer(
        answer_type=answer_type,
        display_text=display_text,
        scan_id=scan_id,
        metric=metric,
        items=[],
        counts=counts,
        evidence=[_evidence(scan_id, metric.name)],
        metadata={"severity": severity, "result_type": payload.get("result_type")},
        language=language,
    )


def canonical_answer_for_severity_distribution(
    payload: dict[str, Any],
    display_text: str,
    language: str | None = None,
    requested_severities: list[str] | None = None,
) -> CanonicalAnswer:
    scan_id = _safe_text(payload.get("scan_id"), 120)
    raw_counts = payload.get("severity_counts") if isinstance(payload.get("severity_counts"), dict) else payload.get("counts")
    raw_counts = raw_counts if isinstance(raw_counts, dict) else {}
    wanted = [_safe_severity(value) for value in (requested_severities or [])]
    wanted = [value for value in wanted if value]
    keys = wanted or ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    counts = {key: _safe_int(raw_counts.get(key)) for key in keys}
    metric = metric_spec("severity_distribution_file_level", scope=",".join(keys) if wanted else "all_severities")
    return CanonicalAnswer(
        answer_type="severity_distribution",
        display_text=display_text,
        scan_id=scan_id,
        metric=metric,
        counts=counts,
        evidence=[_evidence(scan_id, metric.name)],
        metadata={"requested_severities": keys, "result_type": payload.get("result_type")},
        language=language,
    )


def canonical_answer_for_finding_list(payload: dict[str, Any], display_text: str, language: str | None = None) -> CanonicalAnswer:
    scan_id = _safe_text(payload.get("scan_id"), 120)
    raw_items = payload.get("items") if isinstance(payload.get("items"), list) else payload.get("results")
    raw_items = raw_items if isinstance(raw_items, list) else []
    items = [canonical_finding_from_dict(item, scan_id) for item in raw_items if isinstance(item, dict)]
    severity = _safe_severity(payload.get("severity"))
    metric = metric_spec("file_level_finding_count", scope=severity or "all_findings")
    shown = _safe_int(payload.get("returned") if payload.get("returned") is not None else len(items))
    total = _safe_int(payload.get("count") if payload.get("count") is not None else len(items))
    return CanonicalAnswer(
        answer_type="finding_list",
        display_text=display_text,
        scan_id=scan_id,
        metric=metric,
        items=items,
        counts={"shown_count": shown, "total_matching_count": total},
        evidence=[_evidence(scan_id, metric.name, item) for item in items[:10]] or [_evidence(scan_id, metric.name)],
        metadata={"severity": severity, "selection_mode": payload.get("selection_mode")},
        language=language,
    )


def canonical_answer_for_selected_finding(
    item: dict[str, Any],
    display_text: str,
    scan_id: str | None = None,
    language: str | None = None,
) -> CanonicalAnswer:
    finding = canonical_finding_from_dict(item, scan_id)
    metric = metric_spec("shown_items_count", scope="selected_finding")
    return CanonicalAnswer(
        answer_type="selected_finding_detail",
        display_text=display_text,
        scan_id=finding.scan_id or _safe_text(scan_id, 120),
        metric=metric,
        items=[finding],
        counts={"shown_count": 1},
        evidence=[_evidence(finding.scan_id or scan_id, metric.name, finding)],
        language=language,
    )


def canonical_answer_for_risk_type_breakdown(
    findings: list[dict[str, Any]],
    display_text: str,
    scan_id: str | None = None,
    language: str | None = None,
    severity: str | None = None,
    queried_category: str | None = None,
) -> CanonicalAnswer:
    from backend.copilot.remediation_policy import categorize_risk_types

    sev = _safe_severity(severity)
    scoped = [item for item in findings if not sev or _safe_severity(item.get("severity")) == sev]
    category_counts: dict[str, int] = {}
    for item in scoped:
        risk_types = item.get("risk_types") or []
        if not isinstance(risk_types, list):
            risk_types = []
        for category in categorize_risk_types([str(value) for value in risk_types]):
            category_counts[category] = category_counts.get(category, 0) + 1
    metric = metric_spec("risk_type_file_count", scope=sev or "all_findings")
    counts = dict(category_counts)
    counts["total_matching_count"] = len(scoped)
    if queried_category:
        counts["queried_category_count"] = category_counts.get(str(queried_category), 0)
    return CanonicalAnswer(
        answer_type="risk_type_breakdown",
        display_text=display_text,
        scan_id=_safe_text(scan_id, 120),
        metric=metric,
        items=[canonical_finding_from_dict(item, scan_id) for item in scoped[:20] if isinstance(item, dict)],
        counts=counts,
        evidence=[_evidence(scan_id, metric.name)],
        metadata={"severity": sev, "queried_category": queried_category},
        language=language,
    )


def render_canonical_answer(answer: CanonicalAnswer, language: str | None = None) -> str:
    text = str(answer.display_text or "").strip()
    line = evidence_line(answer, language or answer.language)
    if line and line not in text:
        text = f"{text}\n{line}" if text else line
    return text


def evidence_line(answer: CanonicalAnswer, language: str | None = None) -> str:
    scan_id = answer.scan_id or (answer.evidence[0].scan_id if answer.evidence else None) or "latest"
    metric_name = answer.metric.name if answer.metric else None
    if not metric_name:
        return ""
    if language == "az":
        return f"Skan: {scan_id}  Metrik: {metric_name}"
    if language == "ru":
        return f"Evidence: scan={scan_id}, metric={metric_name}, source={answer.metric.source}"
    return f"Evidence: scan={scan_id}, metric={metric_name}, source={answer.metric.source}"


def _evidence(scan_id: str | None, metric_name: str, item: CanonicalFinding | None = None) -> EvidenceRef:
    return EvidenceRef(
        source="latest scan report",
        scan_id=_safe_text(scan_id, 120),
        metric=metric_name,
        item_id=item.id if item else None,
        item_name=item.name if item else None,
        confidence="high",
    )


def _safe_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in (metadata or {}).items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            safe[str(key)] = _safe_text(value, 200) if isinstance(value, str) else value
        elif isinstance(value, list):
            safe[str(key)] = [_safe_text(item, 120) for item in value[:20]]
    return safe


def _safe_text(value: Any, limit: int = 160) -> str | None:
    if value is None:
        return None
    text = mask_sensitive_text(str(value)).strip()
    return text[:limit] if text else None


def _safe_name(value: Any) -> str:
    text = _safe_text(value, 180) or "unknown"
    normalized = text.replace("\\", "/").rstrip("/")
    name = PurePosixPath(normalized).name
    return mask_sensitive_text(name or normalized or "unknown")[:180]


def _safe_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _safe_score(value: Any) -> int | float | None:
    if value is None:
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return int(score) if score.is_integer() else score


def _safe_severity(value: Any) -> str | None:
    text = str(value or "").upper().strip()
    return text if text in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else None


def _safe_risk_types(item: dict[str, Any]) -> list[str]:
    raw = item.get("risk_types")
    values: list[str] = []
    if isinstance(raw, list):
        for value in raw:
            text = _safe_text(value, 80)
            if text and text not in values:
                values.append(text)
    for finding in item.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        text = _safe_text(finding.get("type") or finding.get("name"), 80)
        if text and text not in values:
            values.append(text)
    return values[:12]
