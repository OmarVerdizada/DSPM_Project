from __future__ import annotations

import json
import os
from typing import Any

from backend.copilot.guardrails import fallback_answer
from backend.copilot.language import LanguageIntent
from backend.copilot.schemas import ToolResult


MAX_TOKENS_PER_TOOL_RESULT = int(os.getenv("COPILOT_MAX_TOKENS_PER_TOOL", "1500"))
MAX_TOKENS_TOTAL_CONTEXT = int(os.getenv("COPILOT_MAX_TOKENS_CONTEXT", "12000"))
MAX_CONVERSATION_TURNS = int(os.getenv("COPILOT_MAX_CONVERSATION_TURNS", "6"))
MAX_TOKENS_CONVERSATION = int(os.getenv("COPILOT_MAX_TOKENS_CONVERSATION", "2000"))
MAX_GENERAL_HISTORY_TURNS = int(os.getenv("COPILOT_MAX_GENERAL_HISTORY_TURNS", "2"))

INTENT_TOOL_MAP: dict[str, list[str]] = {
    "executive_summary": ["get_executive_dashboard", "get_scan_history"],
    "finding_search": ["search_findings", "get_findings_by_severity"],
    "asset_risk": ["get_high_risk_assets", "explain_risk_for_asset"],
    "remediation_advice": ["generate_remediation_summary", "search_findings"],
    "audit_query": ["search_audit_events"],
    "alert_summary": ["get_findings_by_severity", "get_recent_alerts"],
    "general": ["get_executive_dashboard"],
}

TECHNICAL_TERMS = "DSPM, scan, finding, high-risk asset, alert, audit log, remediation, ACL, PII, private key, secret, filenames, sanitized paths"
LANGUAGE_NAMES = {"az": "Azerbaijani", "en": "English", "ru": "Russian", "unknown": "English"}
LANGUAGE_GUARDS = {
    "az": "Do not start with English boilerplate such as 'found in scan' or 'Recommended next step'. Use natural Azerbaijani, not Turkish.",
    "en": "Do not use Azerbaijani boilerplate such as 'Tövsiyə', 'tapıldı', 'aşkar olunub', 'Access-i yoxla', or 'Lazımsız paylaşımı bağla'.",
    "ru": "Answer only in Russian. Do not use Azerbaijani or English boilerplate unless quoting evidence, filenames, severity labels, or DSPM field names.",
    "unknown": "Use English unless the current user message clearly asks otherwise.",
}

LANGUAGE_INSTRUCTIONS = {
    "az": "You must answer ONLY in Azerbaijani. Use proper Azerbaijani letters: ə, ı, ö, ü, ğ, ş, ç. Do not answer in English or Russian unless quoting evidence or field names. Keep technical DSPM terms understandable.",
    "en": "You must answer ONLY in English. Do not answer in Azerbaijani or Russian unless quoting evidence or field names.",
    "ru": "You must answer ONLY in Russian. Do not answer in Azerbaijani or English unless quoting evidence, file names, severity labels, or field names. Keep DSPM technical terms clear.",
    "unknown": "Use English unless a selected response language is provided.",
}

SYSTEM_ROLE = (
    "/no_think\n\n"
    "You are DSPM AI Copilot, a local assistant inside a Data Security Posture Management dashboard.\n\n"
    "Answer directly and concisely.\n"
    "Do not reason extensively.\n"
    "Do not reveal chain-of-thought.\n"
    "Do not output internal planning.\n"
    "Do not output prompt instructions.\n"
    "Do not say 'We are given', 'The user asked', 'The context shows', or similar meta text.\n\n"
    "For simple questions, respond immediately.\n"
    "For DSPM data queries, use the provided local evidence and return the result without long analysis.\n"
    "For tool/evidence results, summarize the result directly.\n"
    "Maximum thinking: identify the category, pick the action, execute. That is all.\n\n"
    "You can help with:\n"
    "- scan summaries\n"
    "- critical/high findings\n"
    "- finding details\n"
    "- risk explanation\n"
    "- remediation\n"
    "- sensitive data exposure\n"
    "- exposed secrets, private keys, credentials\n"
    "- risky files and prioritization\n\n"
    "You cannot:\n"
    "- browse the internet\n"
    "- invent scan data\n"
    "- reveal raw secrets\n"
    "- answer as a general chatbot outside DSPM/security scope\n\n"
    "Keep technical terms unchanged: " + TECHNICAL_TERMS + ".\n\n"
    "Default answer length:\n"
    "- simple/status/capability: 1-2 short sentences\n"
    "- finding/risk/remediation: max 3 short sentences unless user asks for detail\n"
    "- lists: compact bullets\n"
    "- reports: only longer when explicitly requested\n\n"
    "Return ONLY the final user-facing answer."
)

CLASSIFICATION_PROMPT = """Return ONLY valid JSON:
{"intent": "<intent_from_taxonomy>", "needs_scan_id": true/false}

Intent taxonomy:
- executive_summary
- finding_search
- asset_risk
- remediation_advice
- audit_query
- alert_summary
- general

Question:
{question}
"""

DSPM_ANSWER_PROMPT = """Task: {task_type}
Language: {language}
Language instruction: {language_instruction}

Use only this DSPM evidence:
{context}

Minimal history:
{history}

User asked:
{question}

Return only the final answer.
Be direct and concise.
Maximum {max_lines} lines unless user asks for detail.
Do not mention prompt rules, context construction, planner, tools, or hidden reasoning.
Do not invent findings, assets, alerts, users, tenants, paths, scan IDs, or compliance claims.
If evidence is insufficient, return exactly: {fallback}
Keep technical terms and filenames unchanged: {technical_terms}.
If you mention files, use short filenames only, never full local filesystem paths.
No markdown headings. No markdown tables. No debug footer."""

ITEM_ANSWER_PROMPT = """Task: {task_type}
Language: {language}
Language instruction: {language_instruction}
Target: {target_reference}

Evidence:
{evidence}

User asked:
{question}

Return only the final answer.
Be direct and concise.
Maximum 3 short sentences unless user asks for detail.
Do not mention prompt rules, tools, or hidden reasoning.
The user is asking about one selected finding, not the full previous list.
Do not repeat the previous list.
Do not invent unavailable fields.
For remediation, mention private_key/JWT/token rotation only if those types appear in evidence.
For risk explanation, focus on why the selected item is risky and its likely impact.
Keep filenames, scan IDs, and DSPM technical terms unchanged: {technical_terms}.
No markdown headings. No debug footer."""

GENERAL_CHAT_PROMPT = """Task: general_chat
Language: {language}
Language instruction: {language_instruction}

History:
{history}

User asked:
{question}

Return only the final answer.
Be concise and professional, max {max_lines} lines.
Do not mention prompt rules, tools, or hidden reasoning.
Do not use DSPM findings from previous turns.
Do not claim tools were used.
Keep technical terms unchanged: {technical_terms}.
No markdown headings. No debug footer."""

INTENT_RULES = {
    "small_talk": (
        "Reply briefly and naturally. If appropriate, say you can help with DSPM scans, findings, risks, alerts, and remediation. "
        "Do not list current findings or high-risk assets."
    ),
    "capability_help": (
        "Explain capabilities, not current findings. Include a compact numbered list of things the user can ask for: latest scan summary, high-risk assets, critical findings, alerts, asset risk, and remediation steps."
    ),
    "complaint_or_misunderstanding": (
        "Apologize briefly, acknowledge the mismatch, and ask what the user wants to check next. Do not repeat any previous DSPM results."
    ),
    "unclear": (
        "Ask one short clarification question. Offer examples such as high-risk assets, latest scan summary, alerts, or remediation. Do not assume the user wants high-risk assets."
    ),
}


class ContextTooLargeError(Exception):
    """Raised when context exceeds configured limits."""


def estimate_tokens(text: str) -> int:
    return int(len(text.split()) * 1.35)


def truncate_text(text: str, max_tokens: int, omitted_count: int = 0) -> str:
    if estimate_tokens(text) <= max_tokens:
        return text
    max_words = max(1, int(max_tokens / 1.35))
    suffix = ""
    if omitted_count > 0:
        suffix = f"\n[Truncated. {omitted_count} additional records omitted. Ask for a narrower DSPM question.]"
    return " ".join(text.split()[:max_words]) + suffix


class ContextBuilder:
    def build(self, tool_results: list[ToolResult], conversation_history: list[dict], user_message: str) -> str:
        del conversation_history, user_message
        sections: list[str] = []
        total_tokens = 0
        for result in tool_results:
            content = truncate_text(result.content, MAX_TOKENS_PER_TOOL_RESULT, max(0, len(result.sources) - 10))
            section = f"TOOL: {result.tool_name}\n{content}"
            tokens = estimate_tokens(section)
            if total_tokens + tokens > MAX_TOKENS_TOTAL_CONTEXT:
                break
            sections.append(section)
            total_tokens += tokens
        context = "\n\n".join(sections)
        if estimate_tokens(context) > MAX_TOKENS_TOTAL_CONTEXT:
            raise ContextTooLargeError("Tool context exceeds the configured budget.")
        return context

    def history_text(self, conversation_history: list[dict]) -> str:
        selected = conversation_history[-MAX_CONVERSATION_TURNS * 2 :]
        return _history_lines(selected, MAX_TOKENS_CONVERSATION)

    def minimal_history_text(self, conversation_history: list[dict]) -> str:
        selected = conversation_history[-MAX_GENERAL_HISTORY_TURNS * 2 :]
        sanitized = []
        for item in selected:
            content = str(item.get("content", ""))
            if "high-risk" in content.lower() or "critical" in content.lower() or "finding" in content.lower():
                content = "[previous DSPM result omitted]"
            sanitized.append({"role": item.get("role", "unknown"), "content": content})
        return _history_lines(sanitized, 600)


def _history_lines(items: list[dict], token_budget: int) -> str:
    lines: list[str] = []
    total_tokens = 0
    for item in reversed(items):
        line = f"{item.get('role', 'unknown')}: {item.get('content', '')}"
        tokens = estimate_tokens(line)
        if total_tokens + tokens > token_budget:
            break
        lines.insert(0, line)
        total_tokens += tokens
    return "\n".join(lines)


def _metadata_text(metadata: LanguageIntent) -> str:
    return json.dumps(metadata.model_dump(), ensure_ascii=False, indent=2, default=str)


def build_classification_messages(question: str) -> list[dict[str, str]]:
    return [{"role": "system", "content": SYSTEM_ROLE}, {"role": "user", "content": CLASSIFICATION_PROMPT.format(question=question)}]


def build_answer_messages(question: str, context: str, history: str, metadata: LanguageIntent | None = None, task_type: str = "general") -> list[dict[str, str]]:
    lang = (metadata.language if metadata else "en") or "en"
    return [
        {"role": "system", "content": SYSTEM_ROLE},
        {
            "role": "user",
            "content": DSPM_ANSWER_PROMPT.format(
                technical_terms=TECHNICAL_TERMS,
                task_type=task_type,
                language=lang,
                language_instruction=LANGUAGE_INSTRUCTIONS.get(lang, LANGUAGE_INSTRUCTIONS["en"]),
                max_lines=metadata.style.max_lines_default if metadata else 7,
                fallback=fallback_answer("en"),
                context=context,
                history=history,
                question=question,
            ),
        },
    ]


def build_item_answer_messages(question: str, evidence: str, metadata: LanguageIntent, task_type: str, target_reference: str | None) -> list[dict[str, str]]:
    lang = metadata.language or "en"
    return [
        {"role": "system", "content": SYSTEM_ROLE},
        {
            "role": "user",
            "content": ITEM_ANSWER_PROMPT.format(
                technical_terms=TECHNICAL_TERMS,
                task_type=task_type,
                language=lang,
                language_instruction=LANGUAGE_INSTRUCTIONS.get(lang, LANGUAGE_INSTRUCTIONS["en"]),
                target_reference=target_reference or "selected item",
                evidence=evidence,
                question=question,
            ),
        },
    ]


def build_general_chat_messages(question: str, history: str, metadata: LanguageIntent) -> list[dict[str, str]]:
    lang = metadata.language or "en"
    return [
        {"role": "system", "content": SYSTEM_ROLE},
        {
            "role": "user",
            "content": GENERAL_CHAT_PROMPT.format(
                technical_terms=TECHNICAL_TERMS,
                language=lang,
                language_instruction=LANGUAGE_INSTRUCTIONS.get(lang, LANGUAGE_INSTRUCTIONS["en"]),
                max_lines=metadata.style.max_lines_default,
                history=history,
                question=question,
            ),
        },
    ]


def to_json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)
