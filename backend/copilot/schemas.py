from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    conversation_id: str | None = None
    scan_id: str | None = None
    selected_language: Literal["az", "en", "ru"] | None = None
    selected_language_source: Literal["explicit_user_selection", "absent", "legacy_default"] | None = None


class SourceRef(BaseModel):
    type: Literal["finding", "scan", "alert", "audit"]
    scan_id: str | None = None
    path: str | None = None
    severity: str | None = None
    risk_score: float | None = None


class ChatResponse(BaseModel):
    answer: str | None
    intent: str | None = None
    task_type: str | None = None
    language: Literal["en", "az", "ru", "unknown"] | None = None
    sources: list[SourceRef] = Field(default_factory=list)
    tools_used: list[str] = Field(default_factory=list)
    conversation_id: str
    message_id: str | None = None
    artifact: dict | None = None
    session_context_summary: str | None = None
    error: dict | None = None
    metadata: dict | None = None


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded", "down"]
    ollama: Literal["ok", "unreachable"]
    storage: Literal["ok", "error"]
    model: str
    version: str


class ReportArtifactRequest(BaseModel):
    scan_id: str | None = Field(default=None, max_length=160)


class ToolResult(BaseModel):
    tool_name: str
    content: str
    sources: list[SourceRef] = Field(default_factory=list)
    token_count: int


class IntentResult(BaseModel):
    intent: Literal[
        "executive_summary",
        "finding_search",
        "asset_risk",
        "remediation_advice",
        "audit_query",
        "alert_summary",
        "general",
    ]
    needs_scan_id: bool = False
