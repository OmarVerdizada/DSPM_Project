"""Routes for the reports the console composes: the filed PDF, and (C9) Word and Excel.

These were served under /api/v1/copilot while the report renderer lived inside
the Copilot package. Reporting is not an assistant feature, so it kept its own
neutral prefix when Copilot was removed.
"""
from __future__ import annotations

import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from backend.errors import client_message
from backend.reporting.artifacts import ArtifactError, artifact_file, create_report_artifact
from backend.reporting.office import DOCX_MEDIA_TYPE, XLSX_MEDIA_TYPE, render_docx, render_xlsx
from backend.security import Principal, require_artifact_download, require_permission
from backend.store import audit

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


class ReportArtifactRequest(BaseModel):
    scan_id: str | None = Field(default=None, max_length=160)
    # The Reports page lets an operator narrow a report to the severities that
    # matter. create_report_artifact has always been able to build a scoped
    # artifact; the route simply never offered it.
    severities: list[str] | None = Field(default=None, max_length=4)


def _on_heavy_budget(function, *args, **kwargs):
    """A report's reads run on the heavy-read pool and bounds, not the API's (W3.4)."""
    from backend import db

    with db.workload("heavy"):
        return function(*args, **kwargs)


@router.post("")
async def create_report(
    payload: ReportArtifactRequest,
    principal: Principal = Depends(require_permission("report.create")),
) -> dict:
    """Create the filed assessment PDF, for the whole scan or a severity slice."""
    wanted = [level for level in (payload.severities or []) if str(level).upper() in SEVERITY_LEVELS]
    scope = {"kind": "severity", "severities": [str(level).upper() for level in wanted]} if wanted else {"kind": "full"}
    try:
        # W3.3: rendering a PDF is seconds of work; it runs on a worker thread, not the loop
        # every other request is waiting on.
        artifact = await run_in_threadpool(_on_heavy_budget, create_report_artifact, principal, {},
                                           scan_id=payload.scan_id, scope=scope)
    except ArtifactError as exc:
        raise HTTPException(status_code=404, detail=client_message(exc, "The report could not be created")) from exc
    # C4: filing a report is an export of the scan's findings; recorded with its scope.
    audit(principal.tenant_id, principal.subject, "report.created", {
        "artifact_id": artifact.get("artifact_id"), "scan_id": artifact.get("scan_id") or payload.scan_id or "",
        "scope": scope.get("kind"), "severities": scope.get("severities", []),
    })
    return artifact


# ── Word and Excel (C9) ─────────────────────────────────────────────────────────────
# The Reports page composes the sections - it holds the findings in scope and the
# operator's choices of type, sections and depth - and the server builds the file from
# them: masked, formula-inert, typed, and recorded here. The bounds are the page's own
# (40 sections, 5,000 rows a report) with room to spare; the request body is capped at
# DSPM_MAX_BODY_BYTES before any of this runs.
OFFICE_MAX_CELLS = 400_000


class OfficeTable(BaseModel):
    headers: list[str] = Field(default_factory=list, max_length=40)
    rows: list[list[str | int | float | None]] = Field(default_factory=list, max_length=20_000)


class OfficeDetail(BaseModel):
    finding: str = Field(default="", max_length=500)
    severity: str = Field(default="", max_length=40)
    status: str = Field(default="", max_length=80)
    file: str = Field(default="", max_length=4000)
    data_class: str = Field(default="", max_length=200)
    owner: str = Field(default="", max_length=300)
    frameworks: str = Field(default="", max_length=500)
    score: str = Field(default="", max_length=20)
    occurrences: str = Field(default="", max_length=20)
    due: str = Field(default="", max_length=40)
    reason: str = Field(default="", max_length=8000)
    recommendation: str = Field(default="", max_length=8000)


class OfficeBlock(BaseModel):
    label: str = Field(default="", max_length=200)
    table: OfficeTable | None = None
    detail: list[OfficeDetail] = Field(default_factory=list, max_length=500)
    paragraphs: list[str] = Field(default_factory=list, max_length=200)
    notes: list[str] = Field(default_factory=list, max_length=20)


class OfficeNumberFormat(BaseModel):
    """The separators the page's locale formats numbers with, so "1.204" is read as the
    page meant it. Validated again, and defaulted to en-US, by the writer."""
    group: str = Field(default=",", max_length=1)
    decimal: str = Field(default=".", min_length=1, max_length=1)


class OfficeReportRequest(BaseModel):
    format: Literal["docx", "xlsx"]
    report_type: str = Field(default="", max_length=60)
    scan_id: str = Field(default="", max_length=160)
    title: str = Field(default="", max_length=300)
    lines: list[str] = Field(default_factory=list, max_length=8)
    blocks: list[OfficeBlock] = Field(default_factory=list, max_length=40)
    filename: str = Field(default="", max_length=120)
    number_format: OfficeNumberFormat | None = None


def _office_cells(payload: OfficeReportRequest) -> int:
    """Every cell the files will hold. The document pads each row out to its table's
    width, so an empty row costs as much as a full one; counting what was SENT let a
    160 KB request build a 242 MB document (review of C9)."""
    cells = 0
    for block in payload.blocks:
        if block.table:
            cells += len(block.table.rows) * max(1, len(block.table.headers))
        cells += len(block.detail) * 13 + len(block.paragraphs) + len(block.notes)
    return cells + len(payload.lines)


def _office_filename(stem: str, extension: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", stem or "").strip("._")[:100] or "sentro_report"
    return f"{safe}.{extension}"


@router.post("/office")
def export_office_report(
    payload: OfficeReportRequest,
    principal: Principal = Depends(require_permission("report.create")),
) -> Response:
    """C9: the Word or Excel report the Reports page composed, built on the server.

    A plain `def`, so FastAPI runs the build on its thread pool rather than on the
    event loop every other request shares."""
    cells = _office_cells(payload)
    if cells > OFFICE_MAX_CELLS:
        raise HTTPException(status_code=413, detail=(
            f"The report holds {cells:,} cells; one file carries at most {OFFICE_MAX_CELLS:,}. "
            "Narrow the scope or choose Brief detail."))
    render, media_type = (render_docx, DOCX_MEDIA_TYPE) if payload.format == "docx" else (render_xlsx, XLSX_MEDIA_TYPE)
    body, stats = render(payload.model_dump())
    # C3/C4: an export of the findings, recorded with its shape - never its content.
    audit(principal.tenant_id, principal.subject, "report.exported", {
        "format": payload.format, "report_type": payload.report_type, "scan_id": payload.scan_id,
        "sections": stats["sections"], "rows": stats["rows"], "masked_values": stats["masked_values"],
        "bytes": len(body),
    })
    filename = _office_filename(payload.filename, payload.format)
    return Response(content=body, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/artifacts/{artifact_id}")
async def download_artifact(
    artifact_id: str,
    format: str = "pdf",
    inline: bool = False,
    principal: Principal = Depends(require_artifact_download),
) -> FileResponse:
    if format not in ("pdf", "html"):
        raise HTTPException(status_code=400, detail="Invalid format. Use 'pdf' or 'html'.")
    artifact = artifact_file(principal, artifact_id, format)
    if artifact is None:
        raise HTTPException(status_code=404, detail="Report artifact was not found.")
    path, metadata = artifact
    media_type = (
        "text/html; charset=utf-8" if format == "html"
        else str(metadata.get("media_type") or "application/octet-stream")
    )
    filename = str(metadata.get("filename") or "sentro_report.pdf")
    if format == "html":
        filename = filename.replace(".pdf", ".html")
    audit(principal.tenant_id, principal.subject, "report.downloaded", {
        "artifact_id": artifact_id, "format": format, "inline": bool(inline),
        "via": "download_token" if principal.auth_type == "artifact_dl_token" else principal.auth_type or "session",
    })
    return FileResponse(
        path,
        media_type=media_type,
        filename=filename,
        content_disposition_type="inline" if inline and format == "pdf" else "attachment",
    )
