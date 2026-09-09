"""Routes for the unified scan PDF the console composes.

These were served under /api/v1/copilot while the report renderer lived inside
the Copilot package. Reporting is not an assistant feature, so it kept its own
neutral prefix when Copilot was removed.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend.reporting.artifacts import ArtifactError, artifact_file, create_report_artifact
from backend.security import Principal, require_artifact_principal, require_role

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


class ReportArtifactRequest(BaseModel):
    scan_id: str | None = Field(default=None, max_length=160)
    # The Reports page lets an operator narrow a report to the severities that
    # matter. create_report_artifact has always been able to build a scoped
    # artifact; the route simply never offered it.
    severities: list[str] | None = Field(default=None, max_length=4)


@router.post("")
async def create_report(
    payload: ReportArtifactRequest,
    principal: Principal = Depends(require_role("viewer")),
) -> dict:
    """Create the filed assessment PDF, for the whole scan or a severity slice."""
    wanted = [level for level in (payload.severities or []) if str(level).upper() in SEVERITY_LEVELS]
    scope = {"kind": "severity", "severities": [str(level).upper() for level in wanted]} if wanted else {"kind": "full"}
    try:
        return create_report_artifact(principal, {}, scan_id=payload.scan_id, scope=scope)
    except ArtifactError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/artifacts/{artifact_id}")
async def download_artifact(
    artifact_id: str,
    format: str = "pdf",
    inline: bool = False,
    principal: Principal = Depends(require_artifact_principal),
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
    return FileResponse(
        path,
        media_type=media_type,
        filename=filename,
        content_disposition_type="inline" if inline and format == "pdf" else "attachment",
    )
