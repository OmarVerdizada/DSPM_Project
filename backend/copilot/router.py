from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from backend.copilot.artifacts import ArtifactError, artifact_file, create_report_artifact
from backend.copilot.llm_client import OLLAMA_MODEL, check_ollama
from backend.copilot.memory import list_conversations, load_full_conversation, truncate_conversation
from backend.copilot.schemas import ChatRequest, ChatResponse, HealthResponse, ReportArtifactRequest
from backend.copilot.service import append_first_insight_note, handle_chat, stream_chat
from backend.copilot.session_context import clear_session_context
from backend.copilot.tools import search_findings
from backend.security import Principal, require_artifact_principal, require_role
from backend.store import db_path


COPILOT_VERSION = "0.1.0-mvp"

router = APIRouter(prefix="/api/v1/copilot", tags=["copilot"])


def _public_insight(row: dict[str, Any]) -> dict[str, Any]:
    action_query = str(row.get("action_query") or "")
    return {
        "id": row.get("insight_id"),
        "type": row.get("insight_type"),
        "severity": row.get("severity"),
        "title": {"en": row.get("title_en") or "", "az": row.get("title_az") or ""},
        "summary": {"en": row.get("body_en") or "", "az": row.get("body_az") or ""},
        "created_at": row.get("created_at"),
        "action_label": {"en": row.get("action_label_en") or "Review", "az": row.get("action_label_az") or "Bax"},
        "action_query": {"en": action_query, "az": action_query},
        "metadata": row.get("metadata") or {},
    }


@router.post("/chat", response_model=ChatResponse)
async def chat(payload: ChatRequest, principal: Principal = Depends(require_role("viewer"))) -> ChatResponse:
    response = await handle_chat(
        payload.message,
        principal,
        payload.conversation_id,
        payload.scan_id,
        payload.selected_language,
        selected_language_source=payload.selected_language_source,
    )
    return append_first_insight_note(response, principal, is_first_message=not bool(payload.conversation_id))


@router.post("/stream")
async def stream(payload: ChatRequest, principal: Principal = Depends(require_role("viewer"))) -> StreamingResponse:
    async def events() -> AsyncIterator[str]:
        async for event in stream_chat(
            payload.message,
            principal,
            payload.conversation_id,
            payload.scan_id,
            payload.selected_language,
            selected_language_source=payload.selected_language_source,
        ):
            event_name = str(event.pop("event", event.get("type", "message")))
            yield f"event: {event_name}\n"
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream")


@router.get("/health", response_model=HealthResponse)
async def health(_: Principal = Depends(require_role("viewer"))) -> HealthResponse:
    ollama_ok = await check_ollama()
    storage_ok = db_path().parent.exists()
    return HealthResponse(
        status="ok" if ollama_ok and storage_ok else "degraded" if storage_ok else "down",
        ollama="ok" if ollama_ok else "unreachable",
        storage="ok" if storage_ok else "error",
        model=OLLAMA_MODEL,
        version=COPILOT_VERSION,
    )


@router.get("/conversations")
async def conversations(principal: Principal = Depends(require_role("viewer"))) -> dict:
    return {"conversations": await list_conversations(principal)}


@router.get("/conversations/{conversation_id}")
async def conversation_detail(conversation_id: str, principal: Principal = Depends(require_role("viewer"))) -> dict:
    return {"conversation_id": conversation_id, "messages": await load_full_conversation(principal, conversation_id)}


@router.put("/conversations/{conversation_id}/messages/{turn_index}", response_model=ChatResponse)
async def replace_conversation_message(
    conversation_id: str,
    turn_index: int,
    payload: ChatRequest,
    principal: Principal = Depends(require_role("viewer")),
) -> ChatResponse:
    """Replace a user turn by truncating stale history and regenerating it."""
    if payload.conversation_id and payload.conversation_id != conversation_id:
        raise HTTPException(status_code=400, detail="Conversation ID does not match the edit target")
    try:
        await truncate_conversation(principal, conversation_id, turn_index)
    except IndexError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    await clear_session_context(principal, conversation_id)
    return await handle_chat(
        payload.message,
        principal,
        conversation_id,
        payload.scan_id,
        payload.selected_language,
        selected_language_source=payload.selected_language_source,
    )


@router.get("/insights")
async def get_insights(limit: int = 20, principal: Principal = Depends(require_role("viewer"))) -> dict:
    from backend.copilot.insight_store import get_active_insights

    insights = [_public_insight(item) for item in get_active_insights(limit, tenant_id=principal.tenant_id)]
    return {"insights": insights, "count": len(insights)}


@router.post("/insights/{insight_id}/dismiss")
async def dismiss_insight(insight_id: str, principal: Principal = Depends(require_role("viewer"))) -> dict:
    from backend.copilot.insight_store import dismiss_insight as do_dismiss

    if not do_dismiss(insight_id, tenant_id=principal.tenant_id):
        raise HTTPException(status_code=404, detail="Insight not found")
    return {"dismissed": True, "insight_id": insight_id}


@router.post("/insights/{insight_id}/action", response_model=ChatResponse)
async def execute_insight_action(insight_id: str, principal: Principal = Depends(require_role("viewer"))) -> ChatResponse:
    from backend.copilot.insight_store import dismiss_insight as do_dismiss
    from backend.copilot.insight_store import get_insight

    insight = get_insight(insight_id, tenant_id=principal.tenant_id)
    if not insight or not insight.get("action_query"):
        raise HTTPException(status_code=404, detail="Insight or action not found")
    response = await handle_chat(str(insight["action_query"]), principal, None, None)
    do_dismiss(insight_id, tenant_id=principal.tenant_id)
    return response


@router.post("/reports")
async def create_report(
    payload: ReportArtifactRequest,
    principal: Principal = Depends(require_role("viewer")),
) -> dict:
    """Create the shared full-scan PDF used by the dashboard composer."""
    try:
        return create_report_artifact(principal, {}, scan_id=payload.scan_id, scope={"kind": "full"})
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
        raise HTTPException(status_code=404, detail="Copilot artifact was not found.")
    path, metadata = artifact
    media_type = "text/html; charset=utf-8" if format == "html" else str(metadata.get("media_type") or "application/octet-stream")
    filename = str(metadata.get("filename") or "copilot_artifact.pdf")
    if format == "html":
        filename = filename.replace(".pdf", ".html")
    return FileResponse(
        path,
        media_type=media_type,
        filename=filename,
        content_disposition_type="inline" if inline and format == "pdf" else "attachment",
    )


@router.post("/tools/search-findings")
async def debug_search_findings(
    payload: ChatRequest,
    principal: Principal = Depends(require_role("analyst")),
) -> dict:
    """Debug endpoint for searching findings — gated behind COPILOT_ENABLE_DEBUG_TOOLS."""
    if not os.getenv("COPILOT_ENABLE_DEBUG_TOOLS", "").lower() in ("1", "true", "yes"):
        raise HTTPException(status_code=403, detail="Debug tools are disabled")

    try:
        result = await search_findings(principal, payload.message, scan_id=payload.scan_id)
        from backend.copilot.guardrails import clean_answer_text, LEAKED_INTERNAL_TEXT_RE, CREDENTIAL_RE, TENANT_RE
        content = str(result.content)
        content = clean_answer_text(content)
        tenant_id = principal.tenant_id
        def redact_other_tenants(match):
            val = match.group(0)
            return val if val == tenant_id else "[REDACTED]"
        content = TENANT_RE.sub(redact_other_tenants, content)
        content = CREDENTIAL_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", content)
        content = LEAKED_INTERNAL_TEXT_RE.sub("[internal text removed]", content)
        result.content = content
        return result.model_dump()
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=str(exc)) from exc
