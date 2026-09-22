"""Composer-aligned DSPM report data model for generated report artifacts.

The dashboard's **PDF Composer** (``frontend/app.js`` ``buildReportModel`` /
``buildExecutiveReportHtml``) renders a client-side "DSPM Assessment Report"
with a fixed set of sections: executive summary, risk posture, risk
distribution, detection signals, recommended remediation plan, scan
comparison, priority file queue, and the full evidence register.

There is no server-side Composer renderer (the dashboard prints the HTML from
the browser), so this module reproduces the **same underlying report model**
from the persisted scan report, so a generated PDF/HTML follows the
same structure and data model as the dashboard Composer instead of a separate
flat scan-summary text blob.

A report can be *scoped*:

* ``full``     — every file in the scan.
* ``severity`` — only files at the requested severity level(s) (e.g. MEDIUM,
                 or CRITICAL + HIGH).
* ``finding``  — a single selected file/finding.

The posture score is a whole-scan metric and is always computed from the full
scan; the distribution, detection signals, priority queue, evidence register,
and remediation plan reflect the requested scope.

This module is deterministic and evidence-based: it never calls the LLM and
never invents files, findings, or risk types.
"""
from __future__ import annotations

from typing import Any, Mapping

from backend.reporting.posture import compute_posture_score
from backend.reporting.remediation_policy import build_remediation_steps_for_types

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _risk_level(file_obj: Mapping[str, Any]) -> str:
    return str((file_obj.get("risk") or {}).get("level") or "LOW").upper()


def _risk_score(file_obj: Mapping[str, Any]) -> float:
    try:
        return float((file_obj.get("risk") or {}).get("score") or 0)
    except (TypeError, ValueError):
        return 0.0


def _display_name(file_obj: Mapping[str, Any]) -> str:
    raw = str(file_obj.get("name") or file_obj.get("path") or "").replace("\\", "/").rstrip("/")
    return raw.split("/")[-1] or raw or "unknown"


def _ref_key(value: Any) -> str:
    return str(value or "").replace("\\", "/").rstrip("/").split("/")[-1].strip().lower()


def _severity_counts(files: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for file_obj in files:
        level = _risk_level(file_obj).lower()
        if level in counts:
            counts[level] += 1
    return counts


def _file_risk_types(file_obj: Mapping[str, Any]) -> list[str]:
    """Every rule name the file's findings stand for.

    B7 merges a card found by three detectors into one finding that keeps the strongest
    one's type, so reading `type` alone would have lost `credit_card` - and with it the
    financial remediation steps this file needs.
    """
    from backend.finding_contracts import finding_detected_types

    types: list[str] = []
    for finding in file_obj.get("findings") or []:
        if isinstance(finding, dict):
            types.extend(finding_detected_types(finding))
    return types


def _detection_signals(files: list[dict]) -> list[dict]:
    tally: dict[str, int] = {}
    for file_obj in files:
        for finding in file_obj.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            ftype = str(finding.get("type") or "").strip()
            if not ftype:
                continue
            try:
                count = int(finding.get("count") or 1)
            except (TypeError, ValueError):
                count = 1
            tally[ftype] = tally.get(ftype, 0) + max(1, count)
    return [
        {"type": ftype, "count": count}
        for ftype, count in sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))
    ]


def _scope_risk_types(files: list[dict]) -> list[str]:
    seen: list[str] = []
    for file_obj in files:
        for risk_type in _file_risk_types(file_obj):
            if risk_type not in seen:
                seen.append(risk_type)
    return seen


def _file_row(file_obj: Mapping[str, Any]) -> dict:
    risk = file_obj.get("risk") or {}
    findings = [
        f"{finding.get('type')}: {finding.get('count', 1)}"
        for finding in (file_obj.get("findings") or [])
        if isinstance(finding, dict) and finding.get("type")
    ]
    actions = [str(a) for a in (risk.get("remediation") or {}).get("actions", []) if a]
    return {
        "name": _display_name(file_obj),
        "path": str(file_obj.get("path") or ""),
        "source": str(file_obj.get("source") or ""),
        "severity": _risk_level(file_obj),
        "risk_score": risk.get("score"),
        "findings": findings,
        "actions": actions[:3],
        "reasons": [str(r) for r in (risk.get("reasons") or [])][:3],
    }


def _normalize_limit(scope: Mapping[str, Any]) -> int | None:
    """Explicit top-N cap carried by the scope; None means no cap."""
    try:
        limit = int(scope.get("limit") or 0)
    except (TypeError, ValueError):
        return None
    return max(1, min(limit, 100)) if limit > 0 else None


def _normalize_extension(value: Any) -> str | None:
    token = str(value or "").strip().lower().lstrip(".")
    if not token or not token.replace("_", "").replace("-", "").replace("+", "").isalnum():
        return None
    return f".{token}"


def _normalize_scope(scope: Mapping[str, Any] | None) -> dict:
    scope = dict(scope or {})
    kind = str(scope.get("kind") or "full")
    limit = _normalize_limit(scope)
    if kind == "severity":
        severities = [str(s).upper() for s in (scope.get("severities") or []) if s]
        severities = [s for s in SEVERITY_ORDER if s in set(severities)]
        if not severities:
            return {"kind": "full", "label": "Full scan"}
        base = severities[0] if len(severities) == 1 else " + ".join(severities)
        normalized = {"kind": "severity", "severities": severities, "label": base}
        if limit:
            normalized["limit"] = limit
            normalized["label"] = f"Top {limit} {base}"
        return normalized
    if kind == "extension":
        extension = _normalize_extension(scope.get("extension"))
        if not extension:
            return {"kind": "full", "label": "Full scan"}
        severities = [str(s).upper() for s in (scope.get("severities") or []) if s]
        severities = [s for s in SEVERITY_ORDER if s in set(severities)]
        base = f"{' + '.join(severities)} {extension} files" if severities else f"{extension} files"
        normalized: dict = {"kind": "extension", "extension": extension, "label": base}
        if severities:
            normalized["severities"] = severities
        if limit:
            normalized["limit"] = limit
            normalized["label"] = f"Top {limit} {base}"
        return normalized
    if kind == "finding":
        ref = scope.get("finding_ref")
        if not ref:
            return {"kind": "full", "label": "Full scan"}
        return {"kind": "finding", "finding_ref": str(ref), "label": f"finding: {_ref_key(ref)}"}
    normalized = {"kind": "full", "label": "Full scan"}
    if limit:
        normalized["limit"] = limit
        normalized["label"] = f"Top {limit} files"
    return normalized


def _file_extension(file_obj: Mapping[str, Any]) -> str:
    raw = str(file_obj.get("extension") or "").strip().lower()
    if raw:
        return raw if raw.startswith(".") else f".{raw}"
    name = _display_name(file_obj)
    dot = name.rfind(".")
    return name[dot:].lower() if dot > 0 else ""


def _select_scoped_files(files: list[dict], scope: dict) -> list[dict]:
    kind = scope.get("kind")
    if kind == "severity":
        wanted = set(scope.get("severities") or [])
        return [f for f in files if _risk_level(f) in wanted]
    if kind == "extension":
        extension = str(scope.get("extension") or "").lower()
        selected = [f for f in files if _file_extension(f) == extension]
        severities = set(scope.get("severities") or [])
        if severities:
            selected = [f for f in selected if _risk_level(f) in severities]
        return selected
    if kind == "finding":
        ref = _ref_key(scope.get("finding_ref"))
        return [
            f
            for f in files
            if ref
            and (
                _ref_key(f.get("name")) == ref
                or _ref_key(f.get("path")) == ref
                or _ref_key(f.get("id")) == ref
                or _ref_key(f.get("finding_id")) == ref
            )
        ]
    return list(files)


def _comparison(full_counts: dict[str, int], total_files: int, previous_summary: Mapping[str, Any] | None) -> list[dict]:
    if not previous_summary:
        return []
    rows = []
    metrics = [
        ("Critical", full_counts.get("critical", 0), previous_summary.get("critical", 0)),
        ("High", full_counts.get("high", 0), previous_summary.get("high", 0)),
        ("Medium", full_counts.get("medium", 0), previous_summary.get("medium", 0)),
        ("Low", full_counts.get("low", 0), previous_summary.get("low", 0)),
        ("Total files", total_files, previous_summary.get("total_files", 0)),
    ]
    for label, current, prior in metrics:
        try:
            current_i = int(current or 0)
            prior_i = int(prior or 0)
        except (TypeError, ValueError):
            continue
        rows.append({"label": label, "current": current_i, "prior": prior_i, "delta": current_i - prior_i})
    return rows


def _status_text(score: int, critical_high: int) -> str:
    if score >= 80 and not critical_high:
        return "Healthy exposure profile."
    if score >= 55:
        return "Watch active risk concentration."
    return "Immediate remediation recommended."


REPORT_TITLE = "DSPM Assessment Report"


def report_title(scope: Mapping[str, Any] | None = None) -> str:
    """The document's name, composed once and used everywhere it appears.

    A scoped export is a different document from the full one - it was built to be
    sent to someone about that scope - so the scope belongs in the title, which is
    what a browser tab, a saved file and a PDF reader's properties pane all show.
    """
    label = str((scope or {}).get("label") or "").strip()
    if not label or label.lower() in {"full scan", "full"}:
        return REPORT_TITLE
    return f"{REPORT_TITLE} - {label}"


def build_report_model(
    report: Mapping[str, Any],
    scope: Mapping[str, Any] | None = None,
    previous_summary: Mapping[str, Any] | None = None,
    tenant_id: str | None = None,
) -> dict:
    """Build the Composer-aligned, optionally-scoped report data model."""
    norm_scope = _normalize_scope(scope)
    files = [f for f in (report.get("files") or []) if isinstance(f, dict)]

    scoped = _select_scoped_files(files, norm_scope)
    scoped_sorted = sorted(scoped, key=lambda f: -_risk_score(f))
    # An explicit top-N scope caps the report to the N highest-risk rows in
    # scope; every scoped section (summary, distribution, signals, remediation,
    # queue, register) reflects the capped set. Posture/full summary stay
    # whole-scan metrics.
    limit = norm_scope.get("limit")
    if isinstance(limit, int) and limit > 0:
        scoped_sorted = scoped_sorted[:limit]
    scoped = scoped_sorted

    full_counts = _severity_counts(files)
    scoped_counts = _severity_counts(scoped)
    critical_high = int(full_counts["critical"] + full_counts["high"])

    posture = compute_posture_score(
        full_counts,
        total_assets=len(files),
        exposed_assets=critical_high,
        remediated_count=0,
        total_actionable=int(sum(full_counts.values())),
    )

    risk_types = _scope_risk_types(scoped)
    remediation_steps = build_remediation_steps_for_types(risk_types, "en") if scoped else []

    return {
        "title": report_title(norm_scope),
        "scan_id": str(report.get("scan_id") or "latest"),
        "timestamp": str(report.get("timestamp") or ""),
        "source": str(report.get("source") or ""),
        "tenant": str(tenant_id or ""),
        "scope": norm_scope,
        "posture": {
            "score": posture.total_score,
            "grade": posture.grade,
            "trend": posture.trend_direction,
            "status_text": _status_text(posture.total_score, critical_high),
        },
        "full_summary": {
            "total_files": len(files),
            "critical": full_counts["critical"],
            "high": full_counts["high"],
            "medium": full_counts["medium"],
            "low": full_counts["low"],
            "critical_high": critical_high,
        },
        "scoped_summary": {
            "total_files": len(scoped),
            "critical": scoped_counts["critical"],
            "high": scoped_counts["high"],
            "medium": scoped_counts["medium"],
            "low": scoped_counts["low"],
        },
        "distribution": [
            {"level": level, "count": scoped_counts[level.lower()]}
            for level in SEVERITY_ORDER
        ],
        "detection_signals": _detection_signals(scoped),
        "remediation_steps": remediation_steps,
        "comparison": _comparison(full_counts, len(files), previous_summary),
        "priority_files": [_file_row(f) for f in scoped_sorted[:10]],
        "evidence_register": [_file_row(f) for f in scoped_sorted],
    }
