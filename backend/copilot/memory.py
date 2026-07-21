from __future__ import annotations

import asyncio
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from backend.store import DATA_DIR
from backend.copilot.masking import mask_sensitive_text

COPILOT_MEMORY_MAX_LINES = int(os.getenv("COPILOT_MEMORY_MAX_LINES", "500"))
COPILOT_MEMORY_MAX_BYTES = int(os.getenv("COPILOT_MEMORY_MAX_BYTES", "2097152"))


def _safe(value: str) -> str:
    return "".join(ch for ch in value if ch.isalnum() or ch in {"-", "_"})[:80] or "default"


def _conversation_path(tenant_id: str, conversation_id: str) -> Path:
    return DATA_DIR / "copilot" / _safe(tenant_id) / "conversations" / f"{_safe(conversation_id)}.jsonl"


def new_conversation_id() -> str:
    return "conv-" + uuid4().hex[:12]


def _needs_rotation(path: Path) -> bool:
    if not path.exists():
        return False
    if path.stat().st_size > COPILOT_MEMORY_MAX_BYTES:
        return True
    with path.open("r", encoding="utf-8") as f:
        line_count = sum(1 for _ in f)
    return line_count > COPILOT_MEMORY_MAX_LINES


def _rotate(path: Path) -> None:
    with path.open("r", encoding="utf-8") as f:
        lines = [line for line in f if line.strip()]
    if len(lines) <= COPILOT_MEMORY_MAX_LINES:
        return
    trimmed = lines[-COPILOT_MEMORY_MAX_LINES:]
    dirname = path.parent
    dirname.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=dirname, delete=False, suffix=".tmp") as tmp:
        tmp.writelines(trimmed)
        tmp_path = Path(tmp.name)
    try:
        tmp_path.replace(path)
    except OSError:
        tmp_path.unlink(missing_ok=True)


async def load_history(tenant_id: str, conversation_id: str, max_turns: int = 6) -> list[dict]:
    path = _conversation_path(tenant_id, conversation_id)

    def read() -> list[dict]:
        if not path.exists():
            return []
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        return [{"role": row.get("role"), "content": row.get("content", "")} for row in rows[-max_turns * 2 :]]

    try:
        return await asyncio.to_thread(read)
    except (OSError, json.JSONDecodeError):
        return []

async def save_turn(tenant_id: str, conversation_id: str, user_message: str, assistant_message: str, tools_used: list[str], sources: list[dict]) -> None:
    path = _conversation_path(tenant_id, conversation_id)
    now = datetime.now(timezone.utc).isoformat()
    # SC-10: mask the user message before it is persisted to the conversation
    # JSONL. This is the copy that is later replayed into LLM prompt history
    # (read_recent), so masking here covers both at-rest persistence and replay,
    # preventing a pasted secret/PII from lingering and propagating.
    rows = [
        {"role": "user", "content": mask_sensitive_text(user_message), "timestamp": now},
        {"role": "assistant", "content": assistant_message, "timestamp": now, "tools_used": tools_used, "sources": sources},
    ]

    def write() -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if _needs_rotation(path):
            _rotate(path)
        with path.open("a", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    await asyncio.to_thread(write)


async def list_conversations(tenant_id: str) -> list[dict]:
    root = DATA_DIR / "copilot" / _safe(tenant_id) / "conversations"

    def scan() -> list[dict]:
        if not root.exists():
            return []
        summaries = []
        for path in sorted(root.glob("*.jsonl"), key=lambda item: item.stat().st_mtime, reverse=True):
            lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            summaries.append({"conversation_id": path.stem, "message_count": len(lines)})
        return summaries

    try:
        return await asyncio.to_thread(scan)
    except OSError:
        return []


async def load_full_conversation(tenant_id: str, conversation_id: str) -> list[dict]:
    path = _conversation_path(tenant_id, conversation_id)

    def read() -> list[dict]:
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    try:
        return await asyncio.to_thread(read)
    except (OSError, json.JSONDecodeError):
        return []


async def truncate_conversation(tenant_id: str, conversation_id: str, turn_index: int) -> dict:
    """Remove the selected user turn and every message after it atomically."""
    path = _conversation_path(tenant_id, conversation_id)

    def truncate() -> dict:
        if turn_index < 0 or not path.exists():
            raise IndexError("Conversation turn was not found.")
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        user_positions = [index for index, row in enumerate(rows) if row.get("role") == "user"]
        if turn_index >= len(user_positions):
            raise IndexError("Conversation turn was not found.")
        cut_at = user_positions[turn_index]
        kept = rows[:cut_at]
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp") as tmp:
            for row in kept:
                tmp.write(json.dumps(row, ensure_ascii=False) + "\n")
            tmp_path = Path(tmp.name)
        try:
            tmp_path.replace(path)
        except OSError:
            tmp_path.unlink(missing_ok=True)
            raise
        return {"kept_messages": len(kept), "removed_messages": len(rows) - len(kept)}

    return await asyncio.to_thread(truncate)
