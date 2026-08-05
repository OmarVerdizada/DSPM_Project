from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from backend.copilot.report_model import build_report_model
from backend.copilot.report_pdf import REPORT_TEMPLATE_ID, render_visual_report_pdf
from backend.security import Principal, create_artifact_download_token
from backend.store import DATA_DIR, read_scan_history, read_scan_report


ARTIFACT_ID_RE = re.compile(r"^[a-f0-9]{32}$")
ARTIFACT_ROOT = DATA_DIR / "copilot"


class ArtifactError(Exception):
    """Raised when a Copilot artifact cannot be created or served safely."""


def _safe(value: str) -> str:
    return "".join(ch for ch in str(value or "") if ch.isalnum() or ch in {"-", "_"})[:80] or "default"


def _basename(value: str) -> str:
    """SC-13: reduce a scanned file path to its basename for the HTML report,
    matching the path-exposure policy chat and the PDF already apply. Full
    absolute/UNC paths must not be printed into the evidence register."""
    text = str(value or "").replace("\\", "/").rstrip("/")
    return text.rsplit("/", 1)[-1] if text else ""


def _artifact_dir(principal: Principal) -> Path:
    return ARTIFACT_ROOT / _safe(principal.tenant_id) / "artifacts" / _safe(principal.subject)


_SCOPE_DESCRIPTION = {
    "full": "Full scan (all severities).",
    "severity": "Scoped to severity: {label}.",
    "extension": "Scoped to file type: {label}.",
    "finding": "Scoped to a single finding: {label}.",
}


def _scope_line(scope: dict) -> str:
    kind = scope.get("kind", "full")
    template = _SCOPE_DESCRIPTION.get(kind, _SCOPE_DESCRIPTION["full"])
    return template.format(label=scope.get("label", ""))


def _render_report_html(model: dict) -> str:
    """Accessible HTML companion for the shared visual PDF report."""
    e = html.escape
    scope = model.get("scope") or {}
    posture = model.get("posture") or {}
    full = model.get("full_summary") or {}
    scoped = model.get("scoped_summary") or {}

    def _rows(items: list[dict], cells) -> str:
        if not items:
            return '<tr><td colspan="9">No rows in this report scope.</td></tr>'
        return "".join("<tr>" + "".join(f"<td>{c}</td>" for c in cells(row)) + "</tr>" for row in items)

    dist_rows = "".join(
        f'<tr><td><span class="risk {e(item.get("level",""))}">{e(str(item.get("level","")))}</span></td>'
        f"<td>{e(str(item.get('count', 0)))}</td></tr>"
        for item in model.get("distribution") or []
    )
    signal_rows = "".join(
        f"<tr><td>{e(str(item.get('type','')))}</td><td>{e(str(item.get('count',0)))}</td></tr>"
        for item in (model.get("detection_signals") or [])
    ) or '<tr><td colspan="2">No detection signals in scope.</td></tr>'
    remediation_items = "".join(
        f"<li>{e(str(step))}</li>" for step in (model.get("remediation_steps") or [])
    ) or "<li>No scoped findings require remediation in this report.</li>"
    comparison_rows = "".join(
        f"<tr><td>{e(str(row.get('label','')))}</td><td>{e(str(row.get('current',0)))}</td>"
        f"<td>{e(str(row.get('prior',0)))}</td>"
        f"<td>{'+' if row.get('delta',0) > 0 else ''}{e(str(row.get('delta',0)))}</td></tr>"
        for row in (model.get("comparison") or [])
    ) or '<tr><td colspan="4">Run and save at least two scans to populate comparison.</td></tr>'
    priority_rows = _rows(
        model.get("priority_files") or [],
        lambda row: [
            f"<strong>{e(str(row.get('name','')))}</strong>",
            e(str(row.get("source", ""))),
            f'<span class="risk {e(str(row.get("severity","")))}">{e(str(row.get("severity","")))} {e(str(row.get("risk_score","")))}</span>',
            e("; ".join(row.get("findings") or []) or "None"),
            e("; ".join(row.get("actions") or []) or "Review ownership and access"),
        ],
    )
    register_rows = _rows(
        model.get("evidence_register") or [],
        lambda row: [
            f"<strong>{e(str(row.get('name','')))}</strong>",
            e(_basename(row.get("path", ""))),
            e(str(row.get("source", ""))),
            f'<span class="risk {e(str(row.get("severity","")))}">{e(str(row.get("severity","")))} {e(str(row.get("risk_score","")))}</span>',
            e("; ".join(row.get("findings") or []) or "None"),
            e("; ".join(row.get("reasons") or []) or ""),
            e("; ".join(row.get("actions") or []) or "Review ownership and access"),
        ],
    )
    return f"""<!doctype html><html lang="en" data-report-template="{REPORT_TEMPLATE_ID}"><head><meta charset="utf-8">
<title>{e(str(model.get('title', 'DSPM Assessment Report')))}</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;margin:28px;color:#0f172a;line-height:1.45;background:#f8fafc}}
h1{{margin:0 0 4px;color:#0b1739}} h2{{margin:22px 0 6px;border-bottom:2px solid #4f46e5;padding-bottom:3px;color:#102a56}}
.muted{{color:#64748b}} table{{width:100%;border-collapse:collapse;margin-top:6px;font-size:13px}}
th,td{{border:1px solid #d8dee8;padding:5px 7px;text-align:left;vertical-align:top}}
th{{background:#f1f5f9;text-transform:uppercase;font-size:11px;letter-spacing:.04em}}
.risk{{display:inline-block;border-radius:999px;padding:2px 8px;color:#fff;font-weight:800;font-size:12px}}
.CRITICAL{{background:#9f1239}}.HIGH{{background:#c2410c}}.MEDIUM{{background:#b7791f}}.LOW{{background:#15803d}}
.kpis{{display:flex;gap:10px;flex-wrap:wrap;margin-top:8px}}
.kpi{{border:1px solid #c7d2fe;border-radius:12px;padding:8px 14px;min-width:96px;background:#fff}}
.kpi strong{{display:block;font-size:22px}} .scope{{background:#eef4ff;border:1px dashed #818cf8;border-radius:12px;padding:10px 12px;margin-top:8px}}
</style></head><body>
<h1>{e(str(model.get('title', 'DSPM Assessment Report')))}</h1>
<p class="muted">Scan {e(str(model.get('scan_id','')))} &middot; generated {e(str(model.get('timestamp','')))}
&middot; tenant {e(str(model.get('tenant','')))} &middot; {full.get('total_files', 0)} files analyzed</p>
<div class="scope"><strong>Report scope:</strong> {e(_scope_line(scope))}
&middot; {scoped.get('total_files', 0)} file(s) in this report</div>

<h2>Executive summary</h2>
<p>{e(str(posture.get('status_text','')))} This pack follows the dashboard PDF Composer structure:
decision summary first, then the evidence register.</p>
<div class="kpis">
<div class="kpi"><span>Posture</span><strong>{posture.get('score')}</strong><span>grade {e(str(posture.get('grade','')))}</span></div>
<div class="kpi"><span>Priority exposure</span><strong>{full.get('critical_high', 0)}</strong><span>critical + high</span></div>
<div class="kpi CRITICAL"><span>Critical</span><strong>{full.get('critical', 0)}</strong></div>
<div class="kpi HIGH"><span>High</span><strong>{full.get('high', 0)}</strong></div>
<div class="kpi MEDIUM"><span>Medium</span><strong>{full.get('medium', 0)}</strong></div>
<div class="kpi LOW"><span>Low</span><strong>{full.get('low', 0)}</strong></div>
</div>

<h2>Risk posture</h2>
<p>Score {posture.get('score')}/100 (grade {e(str(posture.get('grade','')))}, trend {e(str(posture.get('trend','')))}).</p>

<h2>Risk distribution</h2>
<table><thead><tr><th>Severity</th><th>Files in scope</th></tr></thead><tbody>{dist_rows}</tbody></table>

<h2>Detection signals</h2>
<table><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>{signal_rows}</tbody></table>

<h2>Recommended remediation plan</h2>
<ol>{remediation_items}</ol>

<h2>Scan comparison</h2>
<table><thead><tr><th>Metric</th><th>Latest</th><th>Previous</th><th>Delta</th></tr></thead><tbody>{comparison_rows}</tbody></table>

<h2>Priority file queue</h2>
<table><thead><tr><th>File</th><th>Source</th><th>Risk</th><th>Findings</th><th>Action</th></tr></thead><tbody>{priority_rows}</tbody></table>

<h2>Full evidence register</h2>
<table><thead><tr><th>File</th><th>Path</th><th>Source</th><th>Risk</th><th>Findings</th><th>Reasons</th><th>DLP / action</th></tr></thead><tbody>{register_rows}</tbody></table>
</body></html>"""


def _scope_filename_tag(scope: dict) -> str:
    kind = scope.get("kind", "full")
    try:
        limit = int(scope.get("limit") or 0)
    except (TypeError, ValueError):
        limit = 0
    prefix = f"top{limit}_" if limit > 0 else ""
    if kind == "severity":
        return prefix + "_".join(str(s).lower() for s in scope.get("severities") or [])
    if kind == "extension":
        extension = re.sub(r"[^a-z0-9]+", "", str(scope.get("extension") or "").lower())
        return f"{prefix}{extension}_files" if extension else prefix.rstrip("_")
    if kind == "finding":
        return "finding_" + re.sub(r"[^A-Za-z0-9]+", "-", str(scope.get("finding_ref") or "")).strip("-").lower()[:40]
    return prefix.rstrip("_")


def _resolve_scope(scope: dict | None, filter_severity: str | None) -> dict:
    if scope:
        return dict(scope)
    if filter_severity:
        return {"kind": "severity", "severities": [str(filter_severity).upper()]}
    return {"kind": "full"}


def _previous_scan_summary(tenant_id: str, current_scan_id: str) -> dict | None:
    history = read_scan_history(tenant_id, limit=5)
    # read_scan_history returns oldest-first; the entry before the current scan
    # is the previous scan used for the scan-comparison section.
    previous: dict | None = None
    for entry in history:
        if str(entry.get("scan_id")) == str(current_scan_id):
            break
        previous = entry
    if previous is None and len(history) >= 2 and str(history[-1].get("scan_id")) == str(current_scan_id):
        previous = history[-2]
    return previous.get("summary") if previous else None


def create_report_artifact(
    principal: Principal,
    session_context: dict | None,
    scan_id: str | None = None,
    filter_severity: str | None = None,
    *,
    scope: dict | None = None,
) -> dict:
    report = read_scan_report(principal.tenant_id, scan_id)
    if not report:
        raise ArtifactError("No DSPM scan report is available to export.")
    resolved_scope = _resolve_scope(scope, filter_severity)
    artifact_id = uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat()
    source_scan_id = str(report.get("scan_id") or scan_id or "latest")
    previous_summary = _previous_scan_summary(principal.tenant_id, source_scan_id)
    model = build_report_model(report, resolved_scope, previous_summary, tenant_id=principal.tenant_id)
    normalized_scope = model.get("scope") or {"kind": "full", "label": "Full scan"}

    tag = _scope_filename_tag(normalized_scope)
    filename = f"dspm_report_{source_scan_id}{('_' + tag) if tag else ''}.pdf"
    safe_filename = re.sub(r"[^A-Za-z0-9_.-]", "_", filename)
    root = _artifact_dir(principal)
    root.mkdir(parents=True, exist_ok=True)
    pdf_path = root / f"{artifact_id}.pdf"
    html_path = root / f"{artifact_id}.html"
    metadata_path = root / f"{artifact_id}.json"
    title = f"DSPM Assessment Report — {normalized_scope.get('label', 'Full scan')}"
    html_path.write_text(_render_report_html(model), encoding="utf-8")
    pdf_info = render_visual_report_pdf(pdf_path, model)
    if not pdf_path.exists():
        raise ArtifactError("Report generation failed. The file could not be written.")
    dl_token = create_artifact_download_token(artifact_id, principal.tenant_id, principal.subject, principal.role)
    filter_severity_meta = (
        normalized_scope.get("label") if normalized_scope.get("kind") == "severity" else None
    )
    metadata = {
        "artifact_id": artifact_id,
        "type": "pdf",
        "filename": safe_filename,
        "download_url": f"/api/v1/copilot/artifacts/{artifact_id}?dl_token={dl_token}",
        "preview_url": f"/api/v1/copilot/artifacts/{artifact_id}?dl_token={dl_token}&inline=1",
        "html_download_url": f"/api/v1/copilot/artifacts/{artifact_id}?format=html&dl_token={dl_token}",
        "created_at": created_at,
        "source_scan_id": source_scan_id,
        "filter_severity": filter_severity_meta,
        "scope": normalized_scope,
        "scope_label": normalized_scope.get("label", "Full scan"),
        "media_type": "application/pdf",
        "storage_filename": pdf_path.name,
        "html_storage_filename": html_path.name,
        "truncated": pdf_info["truncated"],
        "original_line_count": pdf_info["original_line_count"],
        "included_line_count": pdf_info["included_line_count"],
        "render_style": pdf_info["render_style"],
        "template_id": pdf_info["template_id"],
        "page_count": pdf_info["page_count"],
    }
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    return {key: value for key, value in metadata.items() if key not in {"storage_filename", "html_storage_filename", "media_type"}}


def load_artifact_metadata(principal: Principal, artifact_id: str) -> dict | None:
    if not ARTIFACT_ID_RE.fullmatch(artifact_id or ""):
        return None
    metadata_path = _artifact_dir(principal) / f"{artifact_id}.json"
    try:
        data = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if data.get("artifact_id") != artifact_id:
        return None
    return data


def artifact_file(principal: Principal, artifact_id: str, format: str = "pdf") -> tuple[Path, dict] | None:
    metadata = load_artifact_metadata(principal, artifact_id)
    if not metadata:
        return None
    storage_key = "html_storage_filename" if format == "html" else "storage_filename"
    filename = str(metadata.get(storage_key) or "")
    if not re.fullmatch(r"[a-f0-9]{32}\.(?:pdf|html)", filename):
        return None
    path = (_artifact_dir(principal) / filename).resolve()
    root = _artifact_dir(principal).resolve()
    if not path.is_file() or root not in path.parents:
        return None
    return path, metadata
