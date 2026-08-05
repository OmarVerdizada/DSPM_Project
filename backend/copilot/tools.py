from __future__ import annotations

import json
import random
from pathlib import PurePosixPath
from typing import Any

from backend.copilot.prompts import MAX_TOKENS_PER_TOOL_RESULT, estimate_tokens, to_json_text, truncate_text
from backend.copilot.schemas import SourceRef, ToolResult
from backend.copilot.skills.compliance import compliance_mapping
from backend.copilot.skills.scan_comparison import compare_recent_scans, finding_history, remediation_status
from backend.copilot.skills.scan_summary import severity_distribution
from backend.security import Principal
from backend.store import read_alerts, read_audit_log, read_scan_history, read_scan_report


DEFAULT_LIMIT = 10
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
VIEWER_MAX_SOURCES = 5


class ToolError(Exception):
    """Raised when a DSPM tool cannot complete safely."""


class NoEvidenceError(ToolError):
    """Raised when the tenant has no evidence for the requested DSPM operation."""


def tenant_has_scan_data(tenant_id: str) -> bool:
    return bool(read_scan_history(tenant_id, limit=1))


def _latest_report(principal: Principal) -> dict:
    report = read_scan_report(principal.tenant_id)
    if not report:
        raise NoEvidenceError("No DSPM scan report is available for this tenant.")
    return report


def _report_by_scan_id(principal: Principal, scan_id: str) -> dict:
    if not scan_id:
        raise ToolError("scan_id is required.")
    report = read_scan_report(principal.tenant_id, scan_id)
    if not report:
        raise NoEvidenceError("The requested DSPM scan report was not found for this tenant.")
    return report


def _risk_level(file_obj: dict) -> str:
    return str(file_obj.get("risk", {}).get("level") or "LOW").upper()


def _risk_score(file_obj: dict) -> float:
    try:
        return float(file_obj.get("risk", {}).get("score") or 0)
    except (TypeError, ValueError):
        return 0.0


def _safe_display_path(value: str | None) -> str | None:
    if not value:
        return None
    normalized = str(value).replace("\\", "/").rstrip("/")
    name = PurePosixPath(normalized).name
    return name or normalized


def _finding_identity(file_obj: dict) -> str:
    return (
        _safe_display_path(file_obj.get("id"))
        or _safe_display_path(file_obj.get("finding_id"))
        or _safe_display_path(file_obj.get("name") or file_obj.get("path"))
        or "unknown"
    )


def _exclude_key(value: Any) -> str:
    return str(value or "").replace("\\", "/").rstrip("/").split("/")[-1].strip().lower()


def _source(scan_id: str | None, file_obj: dict | None = None, source_type: str = "finding") -> SourceRef:
    file_obj = file_obj or {}
    return SourceRef(
        type=source_type,
        scan_id=scan_id,
        path=_safe_display_path(file_obj.get("path")),
        severity=_risk_level(file_obj) if file_obj else None,
        risk_score=_risk_score(file_obj) if file_obj else None,
    )


def _format_file(file_obj: dict, scan_id: str | None) -> dict:
    findings = file_obj.get("findings") or []
    risk = file_obj.get("risk") or {}
    return {
        "scan_id": scan_id,
        "path": _safe_display_path(file_obj.get("path")),
        "name": _safe_display_path(file_obj.get("name") or file_obj.get("path")),
        "extension": _file_extension(file_obj),
        "source": file_obj.get("source"),
        "share": file_obj.get("share"),
        "severity": risk.get("level"),
        "risk_score": risk.get("score"),
        "findings": [
            {
                "type": finding.get("type"),
                "risk": finding.get("risk"),
                "description": finding.get("description"),
                "count": finding.get("count"),
            }
            for finding in findings
        ],
        "permissions": file_obj.get("permissions", {}),
        "risk_reasons": risk.get("reasons", []),
        "remediation": risk.get("remediation", {}),
        "dlp_recommendations": risk.get("dlp_recommendations", []),
    }


def _file_extension(file_obj: dict) -> str:
    stored = str(file_obj.get("extension") or "").strip().lower()
    if stored:
        return stored if stored.startswith(".") else f".{stored}"
    name = str(file_obj.get("name") or file_obj.get("path") or "").replace("\\", "/").split("/")[-1]
    if name.startswith(".") and name.count(".") == 1:
        return name.lower()
    suffix = PurePosixPath(name).suffix.lower()
    return suffix


def _format_finding_brief(file_obj: dict, scan_id: str | None) -> dict:
    risk = file_obj.get("risk") or {}
    findings = []
    for finding in (file_obj.get("findings") or [])[:3]:
        if not isinstance(finding, dict):
            continue
        findings.append(
            {
                "type": finding.get("type"),
                "risk": finding.get("risk"),
                "count": finding.get("count"),
            }
        )
    return {
        "id": _finding_identity(file_obj),
        "scan_id": scan_id,
        "path": _safe_display_path(file_obj.get("path")),
        "name": _safe_display_path(file_obj.get("name") or file_obj.get("path")),
        "severity": risk.get("level"),
        "risk_score": risk.get("score"),
        "findings": findings,
    }


def _compact_file_query_item(file_obj: dict, scan_id: str | None) -> dict:
    """Bounded file metadata for deterministic chat rendering."""
    risk = file_obj.get("risk") if isinstance(file_obj.get("risk"), dict) else {}
    findings = []
    for finding in file_obj.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        findings.append({
            "type": str(finding.get("type") or "")[:80],
            "risk": str(finding.get("risk") or "")[:20],
            "count": finding.get("count"),
        })
        if len(findings) >= 4:
            break
    remediation = risk.get("remediation") if isinstance(risk.get("remediation"), dict) else {}
    if not remediation and isinstance(file_obj.get("remediation"), dict):
        remediation = file_obj.get("remediation")
    actions = [str(value)[:180] for value in (remediation.get("actions") or [])[:2]]
    recommendations = risk.get("dlp_recommendations") or file_obj.get("dlp_recommendations") or []
    return {
        "scan_id": scan_id,
        "path": _safe_display_path(file_obj.get("path")),
        "name": _safe_display_path(file_obj.get("name") or file_obj.get("path")),
        "extension": _file_extension(file_obj),
        "source": str(file_obj.get("source") or "")[:80] or None,
        "share": str(file_obj.get("share") or "")[:80] or None,
        "severity": risk.get("level"),
        "risk_score": risk.get("score"),
        "findings": findings,
        "risk_reasons": [str(value)[:180] for value in (risk.get("reasons") or [])[:2]],
        "remediation": {"actions": actions},
        "dlp_recommendations": [str(value)[:180] for value in recommendations[:1]],
    }


def _severity_counts(report: dict) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for file_obj in report.get("files") or []:
        if not isinstance(file_obj, dict):
            continue
        level = _risk_level(file_obj).lower()
        if level in counts:
            counts[level] += 1
    return counts


def _report_findings(report: dict) -> list[dict]:
    findings: list[dict] = []
    for file_obj in report.get("files") or []:
        if not isinstance(file_obj, dict):
            continue
        name = _safe_display_path(file_obj.get("name") or file_obj.get("path"))
        for finding in file_obj.get("findings") or []:
            if isinstance(finding, dict):
                findings.append({"file": name, **finding})
        permissions = file_obj.get("permissions") if isinstance(file_obj.get("permissions"), dict) else {}
        if permissions.get("issues"):
            findings.append({"file": name, "type": "permission_risk", "count": len(permissions.get("issues") or [])})
        share = str(file_obj.get("share") or "").lower()
        if any(term in share for term in ("public", "anonymous", "anyone")):
            findings.append({"file": name, "type": "public_exposure", "count": 1})
    return findings


def _exposed_asset_count(report: dict) -> int:
    count = 0
    for file_obj in report.get("files") or []:
        if not isinstance(file_obj, dict):
            continue
        permissions = file_obj.get("permissions") if isinstance(file_obj.get("permissions"), dict) else {}
        share = str(file_obj.get("share") or "").lower()
        if _risk_level(file_obj) in {"CRITICAL", "HIGH"} or permissions.get("issues") or any(term in share for term in ("public", "anonymous", "anyone")):
            count += 1
    return count


def _remediated_count(report: dict) -> int:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    for key in ("remediated_count", "resolved_findings", "fixed_findings"):
        if summary.get(key) is not None:
            try:
                return max(0, int(summary.get(key) or 0))
            except (TypeError, ValueError):
                return 0
    return 0


def _total_actionable(report: dict) -> int:
    severity = _severity_counts(report)
    return int(sum(severity.values()))


def _scan_metrics(report: dict, previous_score: int | None = None) -> dict:
    from backend.copilot.posture import compute_posture_score

    files = [item for item in report.get("files") or [] if isinstance(item, dict)]
    severity = _severity_counts(report)
    total_assets = len(files)
    exposed_assets = _exposed_asset_count(report)
    total_actionable = _total_actionable(report)
    posture = compute_posture_score(
        severity,
        total_assets=total_assets,
        exposed_assets=exposed_assets,
        remediated_count=_remediated_count(report),
        total_actionable=total_actionable,
        previous_score=previous_score,
    )
    return {
        "scan_id": report.get("scan_id"),
        "timestamp": report.get("timestamp"),
        "findings_by_severity": severity,
        "total_assets": total_assets,
        "exposed_assets": exposed_assets,
        "remediated_count": _remediated_count(report),
        "total_actionable": total_actionable,
        "posture_score": posture.total_score,
    }


def _result(tool_name: str, payload: Any, sources: list[SourceRef]) -> ToolResult:
    content = truncate_text(to_json_text(payload), MAX_TOKENS_PER_TOOL_RESULT, max(0, len(sources) - DEFAULT_LIMIT))
    return ToolResult(tool_name=tool_name, content=content, sources=sources, token_count=estimate_tokens(content))


def _keyword_score(text: str, terms: list[str], file_obj: dict) -> float:
    lowered = text.lower()
    matches = sum(lowered.count(term) for term in terms if term)
    return matches * 10 + _risk_score(file_obj)


def role_filter(tool_result: ToolResult, role: str) -> ToolResult:
    if role != "viewer":
        return tool_result
    try:
        content = json.loads(tool_result.content)
    except json.JSONDecodeError:
        content = {"summary": tool_result.content}
    if isinstance(content, dict):
        content["viewer_notice"] = "Detailed sensitive evidence is limited for viewer role."
        if tool_result.tool_name == "get_findings_by_severity":
            if isinstance(content.get("results"), list):
                content["results"] = [
                    {
                        "scan_id": item.get("scan_id"),
                        "path": _safe_display_path(item.get("path")),
                        "name": _safe_display_path(item.get("name") or item.get("path")),
                        "severity": item.get("severity"),
                        "risk_score": item.get("risk_score"),
                        "findings": [
                            {
                                "type": finding.get("type"),
                                "risk": finding.get("risk"),
                                "count": finding.get("count"),
                            }
                            for finding in (item.get("findings") or [])[:3]
                            if isinstance(finding, dict)
                        ],
                    }
                    for item in content["results"]
                    if isinstance(item, dict)
                ]
            return _result(tool_result.tool_name, content, tool_result.sources)
        for key in ("results", "top_assets", "top_risks", "remediation_summary", "alerts", "events"):
            if isinstance(content.get(key), list):
                content[key] = content[key][:VIEWER_MAX_SOURCES]
    return _result(tool_result.tool_name, content, tool_result.sources[:VIEWER_MAX_SOURCES])


async def get_executive_dashboard(principal: Principal) -> ToolResult:
    report = _latest_report(principal)
    files = report.get("files", [])
    top = sorted(files, key=_risk_score, reverse=True)[:5]
    payload = {
        "scan_id": report.get("scan_id"),
        "timestamp": report.get("timestamp"),
        "source": report.get("source"),
        "summary": report.get("summary", {}),
        "total_findings": sum(len(item.get("findings") or []) for item in files),
        "top_risks": [_format_file(item, report.get("scan_id")) for item in top],
    }
    return _result("get_executive_dashboard", payload, [_source(report.get("scan_id"), source_type="scan")])


async def get_scan_history(principal: Principal, limit: int = 5) -> ToolResult:
    history = read_scan_history(principal.tenant_id, limit=max(1, min(limit, 50)))
    if not history:
        raise NoEvidenceError("No DSPM scan history is available for this tenant.")
    payload = {"history": history[-limit:]}
    sources = [SourceRef(type="scan", scan_id=str(item.get("scan_id")), path=None, severity=None, risk_score=None) for item in history[-limit:]]
    return _result("get_scan_history", payload, sources)


async def get_scan_report(principal: Principal, scan_id: str | None = None) -> ToolResult:
    report = _report_by_scan_id(principal, scan_id) if scan_id else _latest_report(principal)
    files = report.get("files", [])
    top = sorted(files, key=_risk_score, reverse=True)[:10]
    payload = {
        "scan_id": report.get("scan_id"),
        "timestamp": report.get("timestamp"),
        "summary": report.get("summary", {}),
        "top_findings": [_format_file(item, report.get("scan_id")) for item in top],
    }
    return _result("get_scan_report", payload, [_source(report.get("scan_id"), item) for item in top])


async def search_findings(principal: Principal, query: str, severity: list[str] | None = None, scan_id: str | None = None, limit: int = 10) -> ToolResult:
    reports = [_report_by_scan_id(principal, scan_id)] if scan_id else [_latest_report(principal)]
    severity_filter = {item.upper() for item in severity or [] if item.upper() in SEVERITIES}
    terms = [term.lower() for term in query.split() if len(term) > 1 and term.lower() not in {"show", "find", "risk", "risks"}]
    matches: list[tuple[float, dict, str | None]] = []
    for report in reports:
        rid = report.get("scan_id")
        for file_obj in report.get("files", []):
            if severity_filter and _risk_level(file_obj) not in severity_filter:
                continue
            haystack = to_json_text(_format_file(file_obj, rid))
            score = _keyword_score(haystack, terms, file_obj)
            if score > _risk_score(file_obj) or not terms or severity_filter:
                matches.append((score, file_obj, rid))
    safe_limit = max(1, min(int(limit or DEFAULT_LIMIT), 25))
    top = sorted(matches, key=lambda item: item[0], reverse=True)[:safe_limit]
    if not top:
        raise NoEvidenceError("No matching DSPM findings were found.")
    payload = {"query": query, "result_type": "findings", "count": len(top), "results": [_format_file(file_obj, rid) for _, file_obj, rid in top]}
    return _result("search_findings", payload, [_source(rid, file_obj) for _, file_obj, rid in top])


async def get_findings_by_severity(
    principal: Principal,
    severity: str,
    limit: int = 25,
    selection_mode: str = "top",
    exclude_ids: list[str] | None = None,
    seed: str | None = None,
) -> ToolResult:
    target = severity.upper()
    if target not in SEVERITIES:
        raise ToolError("Invalid severity.")
    report = _latest_report(principal)
    matches = [item for item in report.get("files", []) if _risk_level(item) == target]
    if not matches:
        raise NoEvidenceError(f"No {target} DSPM findings were found.")
    safe_limit = max(1, min(int(limit or 25), 50))
    mode = str(selection_mode or "top").lower()
    if mode not in {"top", "random", "next_unshown", "representative", "explicit"}:
        mode = "top"
    excluded = {_exclude_key(value) for value in (exclude_ids or []) if _exclude_key(value)}
    ordered = sorted(matches, key=lambda item: (-_risk_score(item), _finding_identity(item)))
    remaining = [
        item for item in ordered
        if _exclude_key(_finding_identity(item)) not in excluded
        and _exclude_key(item.get("name")) not in excluded
        and _exclude_key(item.get("path")) not in excluded
    ]
    exhausted = False
    if mode == "random":
        pool = list(remaining)
        if pool:
            rng = random.Random(str(seed)) if seed is not None else random.SystemRandom()
            count = min(safe_limit, len(pool))
            selected = rng.sample(pool, count)
        else:
            selected = []
            exhausted = True
    elif mode == "next_unshown":
        selected = remaining[:safe_limit]
        exhausted = not bool(selected)
    else:
        selected = ordered[:safe_limit] if mode in {"top", "representative", "explicit"} else remaining[:safe_limit]
    payload = {
        "scan_id": report.get("scan_id"),
        "result_type": f"{target.lower()}_findings",
        "severity": target,
        "selection_mode": mode,
        "excluded_ids": sorted(excluded),
        "count": len(matches),
        "returned": len(selected),
        "results": [_format_finding_brief(item, report.get("scan_id")) for item in selected],
        "no_more_results": exhausted,
        "note_codes": ["findings_files_not_separate_alert_objects"],
    }
    return _result("get_findings_by_severity", payload, [_source(report.get("scan_id"), item) for item in selected])


async def get_high_risk_assets(principal: Principal, top_n: int = 10) -> ToolResult:
    report = _latest_report(principal)
    top = sorted(report.get("files", []), key=_risk_score, reverse=True)[: max(1, min(top_n, 25))]
    if not top:
        raise NoEvidenceError("No DSPM assets were found in the latest report.")
    payload = {"scan_id": report.get("scan_id"), "result_type": "high_risk_assets", "count": len(top), "top_assets": [_format_file(item, report.get("scan_id")) for item in top]}
    return _result("get_high_risk_assets", payload, [_source(report.get("scan_id"), item) for item in top])


async def query_files(
    principal: Principal,
    *,
    extension: str | None = None,
    severity: str | None = None,
    limit: int = 5,
) -> ToolResult:
    """Return sanitized file metadata from the tenant's latest scan.

    A zero-match filter is successful evidence, not a missing-evidence error.
    """
    report = _latest_report(principal)
    requested_extension = str(extension or "").strip().lower()
    if requested_extension and not requested_extension.startswith("."):
        requested_extension = f".{requested_extension}"
    requested_severity = str(severity or "").strip().upper()
    files = [item for item in report.get("files") or [] if isinstance(item, dict)]
    extension_counts: dict[str, int] = {}
    for item in files:
        item_extension = _file_extension(item) or "[no extension]"
        extension_counts[item_extension] = extension_counts.get(item_extension, 0) + 1
    matched = [
        item for item in files
        if (not requested_extension or _file_extension(item) == requested_extension)
        and (not requested_severity or _risk_level(item) == requested_severity)
    ]
    matched.sort(key=lambda item: (-_risk_score(item), str(item.get("name") or item.get("path") or "").lower()))
    safe_limit = max(1, min(int(limit or 5), 25))
    selected = matched[:safe_limit]
    scan_id = report.get("scan_id")
    payload = {
        "scan_id": scan_id,
        "result_type": "file_query",
        "evidence_available": True,
        "extension": requested_extension or None,
        "severity": requested_severity or None,
        "count": len(matched),
        "returned": len(selected),
        "items": [_compact_file_query_item(item, scan_id) for item in selected],
        "extension_counts": dict(sorted(extension_counts.items())),
    }
    sources = [_source(scan_id, item) for item in selected]
    if not sources:
        sources = [SourceRef(type="scan", scan_id=scan_id)]
    return _result("query_files", payload, sources)


async def explain_risk_for_asset(principal: Principal, asset_id: str) -> ToolResult:
    needle = asset_id.lower().strip()
    if not needle:
        raise ToolError("asset_id is required.")
    report = _latest_report(principal)
    candidates = []
    for file_obj in report.get("files", []):
        path = str(file_obj.get("path") or "").lower()
        name = str(file_obj.get("name") or "").lower()
        if needle in path or needle in name:
            candidates.append((_risk_score(file_obj), file_obj))
    if not candidates:
        raise NoEvidenceError("The requested asset was not found in available DSPM data.")
    _, file_obj = sorted(candidates, key=lambda item: item[0], reverse=True)[0]
    return _result("explain_risk_for_asset", {"asset": _format_file(file_obj, report.get("scan_id"))}, [_source(report.get("scan_id"), file_obj)])


async def get_finding_detail(principal: Principal, identifier: str, scan_id: str | None = None) -> ToolResult:
    needle = _safe_display_path(identifier) or str(identifier or "").strip()
    if not needle:
        raise ToolError("finding identifier is required.")
    report = _report_by_scan_id(principal, scan_id) if scan_id else _latest_report(principal)
    for file_obj in report.get("files", []):
        name = _safe_display_path(file_obj.get("name") or file_obj.get("path"))
        path = _safe_display_path(file_obj.get("path"))
        if needle in {name, path}:
            payload = {"result_type": "finding_detail", "scan_id": report.get("scan_id"), "item": _format_file(file_obj, report.get("scan_id"))}
            return _result("get_finding_detail", payload, [_source(report.get("scan_id"), file_obj)])
    raise NoEvidenceError("The referenced finding was not found in the selected scan.")


async def compare_scans(principal: Principal, limit: int = 2) -> ToolResult:
    try:
        payload = compare_recent_scans(principal, limit)
    except Exception as exc:
        raise NoEvidenceError(str(exc)) from exc
    sources = [
        SourceRef(type="scan", scan_id=payload.get("previous_scan_id")),
        SourceRef(type="scan", scan_id=payload.get("latest_scan_id")),
    ]
    return _result("compare_scans", payload, sources)


async def get_finding_history(principal: Principal, identifier: str | None = None) -> ToolResult:
    try:
        payload = finding_history(principal, identifier)
    except Exception as exc:
        raise NoEvidenceError(str(exc)) from exc
    item = payload.get("item") if isinstance(payload.get("item"), dict) else {}
    return _result(
        "get_finding_history",
        payload,
        [SourceRef(type="finding", scan_id=payload.get("latest_scan_id"), path=item.get("name"), severity=item.get("severity"), risk_score=item.get("risk_score"))],
    )


async def get_remediation_status(principal: Principal, identifier: str | None = None) -> ToolResult:
    try:
        payload = remediation_status(principal, identifier)
    except Exception as exc:
        raise NoEvidenceError(str(exc)) from exc
    item = payload.get("item") if isinstance(payload.get("item"), dict) else {}
    return _result(
        "get_remediation_status",
        payload,
        [SourceRef(type="finding", scan_id=payload.get("latest_scan_id"), path=item.get("name"), severity=item.get("severity"), risk_score=item.get("risk_score"))],
    )


async def get_severity_distribution(principal: Principal, scan_id: str | None = None) -> ToolResult:
    try:
        payload = severity_distribution(principal, scan_id)
    except Exception as exc:
        raise NoEvidenceError(str(exc)) from exc
    return _result("get_severity_distribution", payload, [SourceRef(type="scan", scan_id=payload.get("scan_id"))])


async def get_posture_score(principal: Principal, scan_id: str | None = None, previous_scan_id: str | None = None) -> ToolResult:
    from backend.copilot.posture import compute_posture_score

    report = _report_by_scan_id(principal, scan_id) if scan_id else _latest_report(principal)
    previous_score = None
    if previous_scan_id:
        previous_report = _report_by_scan_id(principal, previous_scan_id)
        previous_score = _scan_metrics(previous_report).get("posture_score")
    metrics = _scan_metrics(report)
    score = compute_posture_score(
        metrics["findings_by_severity"],
        total_assets=metrics["total_assets"],
        exposed_assets=metrics["exposed_assets"],
        remediated_count=metrics["remediated_count"],
        total_actionable=metrics["total_actionable"],
        previous_score=previous_score,
    )
    payload = {
        "result_type": "posture_score",
        "scan_id": report.get("scan_id"),
        "timestamp": report.get("timestamp"),
        "findings_by_severity": metrics["findings_by_severity"],
        "total_assets": metrics["total_assets"],
        "exposed_assets": metrics["exposed_assets"],
        **score.to_dict(),
    }
    return _result("get_posture_score", payload, [SourceRef(type="scan", scan_id=report.get("scan_id"))])


async def get_compliance_report(principal: Principal, scan_id: str | None = None, framework: str | None = None) -> ToolResult:
    from backend.copilot.compliance import get_compliance_summary, normalize_framework

    report = _report_by_scan_id(principal, scan_id) if scan_id else _latest_report(principal)
    findings = _report_findings(report)
    requested_framework = normalize_framework(framework)
    summary = get_compliance_summary(findings, requested_framework)
    payload = {
        "result_type": "compliance_report",
        "scan_id": report.get("scan_id"),
        "timestamp": report.get("timestamp"),
        "framework": requested_framework,
        "total_findings": len(findings),
        "summary": summary,
    }
    return _result("get_compliance_report", payload, [SourceRef(type="scan", scan_id=report.get("scan_id"))])


async def get_trend_analysis(principal: Principal, limit: int = 5) -> ToolResult:
    from backend.copilot.trends import compute_trend_analysis

    history = read_scan_history(principal.tenant_id, limit=max(1, min(int(limit or 5), 20)))
    if not history:
        raise NoEvidenceError("No DSPM scan history is available for this tenant.")
    scans: list[dict] = []
    previous_score = None
    for row in history:
        report = read_scan_report(principal.tenant_id, str(row.get("scan_id")))
        if not report:
            continue
        metrics = _scan_metrics(report, previous_score)
        previous_score = int(metrics.get("posture_score") or 0)
        scans.append(metrics)
    if not scans:
        raise NoEvidenceError("No DSPM scan reports are available for trend analysis.")
    analysis = compute_trend_analysis(scans)
    payload = {"result_type": "trend_analysis", **analysis.to_dict()}
    sources = [SourceRef(type="scan", scan_id=point.get("scan_id")) for point in payload.get("points", [])]
    return _result("get_trend_analysis", payload, sources)


async def get_compliance_mapping(principal: Principal, identifier: str | None = None) -> ToolResult:
    try:
        payload = compliance_mapping(principal, identifier)
    except Exception as exc:
        raise NoEvidenceError(str(exc)) from exc
    item = payload.get("item") if isinstance(payload.get("item"), dict) else {}
    return _result(
        "get_compliance_mapping",
        payload,
        [SourceRef(type="finding", scan_id=item.get("scan_id"), path=item.get("name"), severity=item.get("severity"), risk_score=item.get("risk_score"))],
    )


async def get_recent_alerts(principal: Principal, limit: int = 10) -> ToolResult:
    rows = read_alerts(principal.tenant_id, limit=max(1, min(limit, 50)))
    alerts: list[dict] = []
    sources: list[SourceRef] = []
    for row in reversed(rows):
        for alert in row.get("alerts", []):
            item = {"scan_id": row.get("scan_id"), "source_type": "alert", **alert}
            alerts.append(item)
            sources.append(SourceRef(type="alert", scan_id=row.get("scan_id"), severity=alert.get("severity")))
    if not alerts:
        raise NoEvidenceError("No DSPM alerts are available for this tenant.")
    return _result("get_recent_alerts", {"result_type": "alerts", "count": len(alerts[:limit]), "alerts": alerts[:limit]}, sources[:limit])


async def search_audit_events(principal: Principal, query: str) -> ToolResult:
    terms = [term.lower() for term in query.split() if len(term) > 1]
    events = read_audit_log(principal.tenant_id, 200)
    matches = []
    for event in events:
        text = to_json_text(event).lower()
        if not terms or any(term in text for term in terms):
            matches.append({"timestamp": event.get("timestamp"), "actor": event.get("actor"), "action": event.get("action"), "detail": event.get("detail", {})})
    results = matches[-10:]
    if not results:
        raise NoEvidenceError("No matching DSPM audit events were found.")
    return _result("search_audit_events", {"query": query, "events": results}, [SourceRef(type="audit") for _ in results])


async def generate_remediation_summary(principal: Principal, finding_id: str | None = None) -> ToolResult:
    if finding_id:
        return await explain_risk_for_asset(principal, finding_id)
    report = _latest_report(principal)
    candidates = [item for item in report.get("files", []) if _risk_level(item) in {"CRITICAL", "HIGH"}]
    top = sorted(candidates, key=_risk_score, reverse=True)[:10]
    if not top:
        raise NoEvidenceError("No high-priority DSPM remediation items are available.")
    payload = {
        "scan_id": report.get("scan_id"),
        "remediation_summary": [
            {
                "path": _safe_display_path(item.get("path")),
                "severity": _risk_level(item),
                "risk_score": _risk_score(item),
                "actions": item.get("risk", {}).get("remediation", {}).get("actions", []),
                "reasons": item.get("risk", {}).get("reasons", []),
            }
            for item in top
        ],
    }
    return _result("generate_remediation_summary", payload, [_source(report.get("scan_id"), item) for item in top])
