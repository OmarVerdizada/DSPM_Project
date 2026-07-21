"""Fast local verbalizer for safe prepared Copilot drafts.

This layer is intentionally narrow: it can rewrite a prepared safe draft for
policy-approved non-factual situations, but it cannot plan, arbitrate, execute
tools, or become the source of DSPM facts.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import inspect
import os
import re
import time
from typing import Any, Awaitable, Callable

from backend.copilot import language_service
from backend.copilot.guardrails import clean_answer_text
from backend.copilot.llm_client import LLMError, call_ollama
from backend.copilot.masking import mask_sensitive_text
from backend.copilot import situation_runtime
from backend.copilot.situation_policy import ProviderMode, ResponseMode, SituationDecision


ProviderCall = Callable[["str", "VerbalizerRequest"], Awaitable[str] | str]


@dataclass(frozen=True)
class VerbalizerRequest:
    safe_draft: str
    situation_decision: SituationDecision
    target_language: str
    style_hint: str | None
    max_words: int | None
    max_tokens: int | None
    timeout_ms: int = 1500
    allow_emoji: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VerbalizerResult:
    used: bool
    enabled: bool
    eligible: bool
    timed_out: bool
    provider_error: str | None
    validation_failed: bool
    fallback_used: bool
    text: str
    fallback_text: str | None
    reason: str
    latency_ms: int | None
    metadata: dict[str, Any]


_ELIGIBLE_SOCIAL_IDS = {
    "social.praise",
    "social.thanks",
    "social.greeting",
    "social.greeting_status",
    "social.status_check",
    "social.casual_reaction",
    "social.farewell",
    "social.frustration_unclear",
}
_ELIGIBLE_GENERAL_IDS = {"general.casual_non_dspm"}
_ELIGIBLE_EDU_IDS = {
    "edu.dspm_concept",
    "edu.security_concept",
    "edu.compliance_concept",
    "edu.risk_score",
    "edu.severity",
    "edu.remediation_concept",
    "edu.beginner",
    "edu.metric_semantics",
}
_CLARIFICATION_IDS = {"unknown.needs_clarification"}

_RAW_CONTEXT_KEYS = {
    "raw_message",
    "message",
    "user_text",
    "raw_user_text",
    "prompt",
    "conversation_history",
    "history",
    "raw_finding",
    "finding",
    "findings",
    "scan_data",
    "scan_json",
    "artifact_url",
    "artifact_file_content",
    "artifact_id",
    "secret",
    "raw_secret",
    "previous_answer_text",
}
_SAFE_METADATA_KEYS = {
    "conversation_id",
    "situation_id",
    "response_family",
    "style",
    "allow_clarification_verbalizer",
}
_SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{12,}", re.IGNORECASE),
    re.compile(r"sk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"(?i)(api[_-]?key|password|secret|token)\s*[:=]\s*\S+"),
    re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._-]{12,}"),
)
_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_FILENAME_RE = re.compile(r"\b[A-Za-z0-9_.-]+\.(?:pdf|json|txt|xlsx|xls|csv|env|pem|key|yaml|yml|docx|zip)\b")
_NUMBER_RE = re.compile(r"(?<![A-Za-z0-9_])\d+(?:[.,]\d+)?(?![A-Za-z0-9_])")
_PREFIX_RE = re.compile(
    r"^\s*(?:az(?:ə|e)rbaycanca\s+cavab|azerbaijani\s+answer|answer|cavab)\s*[:：]",
    re.IGNORECASE,
)
_BOILERPLATE_PREFIX_RE = re.compile(
    r"^\s*(?:az(?:ə|e)rbaycanca\s+cavab|azerbaijani\s+answer|answer|cavab)\s*[:：]\s*",
    re.IGNORECASE,
)
_FORBIDDEN_FACT_TERMS = {
    "scan": ("scan", "skan"),
    "finding": ("finding", "findings", "tapıntı", "tapıntılar", "tapinti", "tapintilar"),
    "report": ("report", "hesabat", "pdf"),
    "file": ("file", "fayl"),
    "link": ("link", "url"),
    "count": ("count", "say", "ədəd", "eded", "rəqəm", "reqem", "metric", "metrik"),
    "tool": ("tool", "provider", "ollama", "planner", "arbiter"),
}
_ACTION_CLAIMS = (
    "created",
    "downloaded",
    "fixed",
    "rotated",
    "checked scan",
    "generated report",
    "yaratdım",
    "yaradıldı",
    "hazırdır",
    "yüklədim",
    "düzəltdim",
    "rotasiya etdim",
    "scan yoxladım",
    "skan yoxladım",
    "hesabat yaratdım",
)
# Harmless social/meta filler words that must never be treated as new "facts"
# or action claims. They carry no scan/count/finding/report/link/tool meaning,
# so they are always safe to add to a social paraphrase. This set documents the
# intent of the validator: reject factual/action additions, allow social tone.
_HARMLESS_SOCIAL_ADDITIONS = frozenset(
    {
        "qısa",
        "qisa",
        "dəqiq",
        "deqiq",
        "birlikdə",
        "birlikde",
        "hazır",
        "hazir",
        "davam",
        "buyurun",
        "buyur",
        "short",
        "useful",
        "ready",
        "quickly",
        "sure",
        "gladly",
    }
)
_EN_WORDS = {"the", "and", "answer", "thanks", "ready", "help", "with", "when", "you", "are", "appreciate"}
_AZ_CHAR_RE = re.compile(r"[əƏıİöÖüÜçÇşŞğĞ]")
_EMOJI_RE = re.compile(r"[\U0001F300-\U0001FAFF]")

_FALLBACKS: dict[tuple[str, str], tuple[str, ...]] = {
    ("az", "social.praise"): (
        "Çox sağ ol 🙂 DSPM riskləri ilə bağlı kömək etməyə hazıram.",
        "Təşəkkür edirəm 🙂 İstəsən, növbəti DSPM riskini birlikdə prioritetləşdirək.",
        "Sağ ol 🙂 DSPM mövzularında qısa və dəqiq kömək etməyə çalışıram.",
    ),
    ("az", "social.thanks"): (
        "Xahiş edirəm 🙂 DSPM riskləri ilə bağlı kömək etməyə hazıram.",
        "Sağ ol 🙂 Növbəti riskə baxmaq istəsən, hazıram.",
        "Məmnuniyyətlə. Cavabları qısa və faydalı saxlayacağam.",
    ),
    ("en", "social.praise"): (
        "Thanks. I'm ready to help with DSPM risks when you are.",
        "Appreciate it. I'll keep the answers short and useful.",
        "Thanks. I'm here to help you move through the risks quickly.",
    ),
    ("en", "social.thanks"): (
        "You're welcome. I'm ready to help with DSPM risks when you are.",
        "Anytime. I'll keep the answers short and useful.",
        "You're welcome. We can move through the risks quickly.",
    ),
    # Greeting pools keep the "Salam" / DSPM tokens the deterministic fast-path
    # regression tests rely on, while offering short deterministic variation.
    ("az", "social.greeting"): (
        "Salam! DSPM riskləri və tapıntıları üzrə kömək etməyə hazıram.",
        "Salam 🙂 DSPM riskləri ilə bağlı nə soruşmaq istəsən, buyur.",
        "Salam! Buyurun, DSPM tapıntıları və riskləri üzrə köməyə hazıram.",
    ),
    ("en", "social.greeting"): (
        "Hello! I'm ready to help with DSPM findings and risks.",
        "Hi 🙂 Ask me anything about your DSPM findings and risks.",
        "Hello! I can help you review DSPM findings and risks.",
    ),
    ("az", "social.status_check"): (
        "Yaxşıyam, sağ ol! DSPM riskləri üzrə kömək etməyə hazıram.",
        "Yaxşıyam, sağ ol 🙂 DSPM riskləri ilə bağlı istədiyini soruşa bilərsən.",
        "Yaxşıyam, sağ ol. Buyurun, DSPM sualınıza baxaq.",
    ),
    ("en", "social.status_check"): (
        "I'm doing well, thank you! Ready to help with your DSPM findings and risks.",
        "All good 🙂 Ask me about your DSPM findings and risks.",
        "I'm good. I can help you review DSPM findings and risks.",
    ),
    ("az", "social.greeting_status"): (
        "Salam! Yaxşıyam, sağ ol. DSPM riskləri üzrə köməyə hazıram.",
        "Salam! Yaxşıyam. DSPM riskləri ilə bağlı istədiyini soruş.",
        "Salam! Yaxşıyam, təşəkkür. Buyurun, DSPM sualınıza baxaq.",
    ),
    ("en", "social.greeting_status"): (
        "Hello! I'm doing well, thank you. Ready to help with DSPM findings and risks.",
        "Hi 🙂 I'm good. Ask me anything about your DSPM findings and risks.",
        "Hello! All good here. I can help you review DSPM findings and risks.",
    ),
    ("az", "social.casual_reaction"): (
        "Oldu 🙂 DSPM üzrə sualın olsa, buyur.",
        "Aydındır. Növbəti DSPM sualına baxa bilərik.",
        "Başa düşdüm. DSPM üzrə nə etmək istəyirsən?",
    ),
    ("en", "social.casual_reaction"): (
        "Got it 🙂 Ask me anything about your DSPM data.",
        "Alright. We can look at the next DSPM question.",
        "Understood. What would you like to check in DSPM?",
    ),
    ("az", "social.farewell"): (
        "Sağ ol, görüşərik 🙂",
        "Hələlik! Lazım olsa, DSPM üzrə buradayam.",
        "Görüşənədək! İstənilən vaxt DSPM sualınla qayıt.",
    ),
    ("en", "social.farewell"): (
        "Goodbye 🙂 Come back anytime with DSPM questions.",
        "See you! I'm here whenever you need DSPM help.",
        "Take care. Reach out anytime for DSPM support.",
    ),
    ("az", "social.frustration_unclear"): (
        "Üzr istəyirəm. Nəyi dəqiqləşdirim ki, DSPM üzrə kömək edə bilim?",
        "Anladım. Zəhmət olmasa sualı bir az dəqiqləşdir — DSPM üzrə kömək edim.",
        "Bağışlayın. Hansı DSPM mövzusunda kömək lazımdır?",
    ),
    ("en", "social.frustration_unclear"): (
        "I'm sorry. Could you clarify what you need so I can help with DSPM?",
        "Understood. Please refine the question a bit and I'll help with DSPM.",
        "Apologies. Which DSPM topic can I help you with?",
    ),
}


def is_verbalizer_enabled(request: VerbalizerRequest | None = None) -> bool:
    if request is not None:
        override = request.metadata.get("enable_fast_verbalizer")
        if isinstance(override, bool):
            return override
    value = os.getenv("COPILOT_FAST_VERBALIZER", "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def is_verbalizer_eligible(request: VerbalizerRequest) -> bool:
    decision = request.situation_decision
    if not str(request.safe_draft or "").strip():
        return False
    if decision.evidence_required or decision.canonical_answer_required:
        return False
    if decision.response_mode != ResponseMode.FAST_VERBALIZER:
        clarification_override = (
            decision.situation_id in _CLARIFICATION_IDS
            and decision.response_mode == ResponseMode.CLARIFICATION
            and bool(request.metadata.get("allow_clarification_verbalizer"))
        )
        if not clarification_override:
            return False
    if decision.provider_mode != ProviderMode.TINY_NO_THINK_VERBALIZER and decision.situation_id not in _CLARIFICATION_IDS:
        return False
    if not decision.verbalizer_allowed and decision.situation_id not in _CLARIFICATION_IDS:
        return False
    if decision.situation_id.startswith(("dspm.", "workflow.", "artifact.", "language.", "safety.")):
        return False
    if decision.situation_id.startswith("complaint."):
        return bool(request.metadata.get("allow_complaint_ack_verbalizer"))
    if decision.situation_id in _ELIGIBLE_SOCIAL_IDS:
        return _safe_draft_is_safe(request.safe_draft)
    if decision.situation_id in _ELIGIBLE_GENERAL_IDS:
        return _safe_draft_is_safe(request.safe_draft)
    if decision.situation_id in _ELIGIBLE_EDU_IDS:
        return _safe_draft_is_safe(request.safe_draft) and not _contains_scan_or_finding_fact(request.safe_draft)
    if decision.situation_id in _CLARIFICATION_IDS:
        return _safe_draft_is_safe(request.safe_draft)
    return False


def build_verbalizer_prompt(request: VerbalizerRequest) -> str:
    max_words = _max_words(request)
    safe_draft = _sanitize_safe_draft_for_prompt(request.safe_draft)
    style = _safe_style(request.style_hint)
    return (
        "/no_think\n\n"
        "You rewrite a safe prepared DSPM Copilot draft into a short natural final answer.\n\n"
        "Rules:\n"
        "- Return only the final user-visible answer.\n"
        "- Do not add facts.\n"
        "- Do not mention scans, counts, findings, files, reports, links, tools, providers, or actions unless they are already in the safe draft.\n"
        "- Do not claim anything was checked, created, downloaded, fixed, or changed unless the safe draft says it.\n"
        f"- Use exactly the target language: {request.target_language}.\n"
        "- Keep it short.\n"
        f"- Max words: {max_words}.\n"
        "- Do not explain your reasoning.\n"
        "- Do not include JSON.\n"
        "- Do not include prefixes like \"Azerbaijani answer:\" or \"Azərbaycanca cavab:\".\n\n"
        "Policy metadata:\n"
        f"- situation_id: {request.situation_decision.situation_id}\n"
        f"- response_mode: {request.situation_decision.response_mode.value}\n"
        f"- provider_mode: {request.situation_decision.provider_mode.value}\n"
        f"- style: {style}\n\n"
        "Safe draft:\n"
        f"{safe_draft}"
    )


def validate_verbalizer_output(output: str, request: VerbalizerRequest) -> tuple[bool, list[str]]:
    errors: list[str] = []
    raw = str(output or "").strip()
    if not raw:
        return False, ["empty"]
    if _PREFIX_RE.search(raw):
        errors.append("forbidden_prefix")
    text = clean_answer_text(raw)
    text = _BOILERPLATE_PREFIX_RE.sub("", text).strip()
    text = mask_sensitive_text(text)
    if not text:
        errors.append("empty_after_clean")
    if _word_count(text) > _max_words(request):
        errors.append("too_long")
    if _contains_secret_like(text):
        errors.append("sensitive_value")
    if _URL_RE.search(text) and not _URL_RE.search(request.safe_draft):
        errors.append("new_url")
    new_filenames = set(_FILENAME_RE.findall(text)) - set(_FILENAME_RE.findall(request.safe_draft))
    if new_filenames:
        errors.append("new_filename")
    new_numbers = set(_NUMBER_RE.findall(text)) - set(_NUMBER_RE.findall(request.safe_draft))
    if new_numbers:
        errors.append("new_number")
    errors.extend(_language_errors(text, request.target_language))
    errors.extend(_unsupported_fact_errors(text, request.safe_draft))
    errors.extend(_unsupported_action_errors(text, request.safe_draft))
    return not errors, errors


def fallback_verbalization(request: VerbalizerRequest) -> str:
    sid = request.situation_decision.situation_id
    if sid in _CLARIFICATION_IDS or request.situation_decision.response_mode == ResponseMode.CLARIFICATION:
        return _finalize_text(request.safe_draft, request)
    variants = _FALLBACKS.get((request.target_language, sid))
    if not variants:
        variants = _FALLBACKS.get(("en", sid))
    if not variants:
        return _finalize_text(request.safe_draft, request)
    basis = str(request.metadata.get("conversation_id") or f"{sid}:{request.safe_draft}")
    digest = hashlib.sha256(basis.encode("utf-8", errors="ignore")).hexdigest()
    index = int(digest[:8], 16) % len(variants)
    return _finalize_text(variants[index], request)


async def run_fast_verbalizer(
    request: VerbalizerRequest,
    provider_call: ProviderCall | None = None,
) -> VerbalizerResult:
    started = time.perf_counter()
    enabled = is_verbalizer_enabled(request)
    eligible = is_verbalizer_eligible(request)
    fallback = fallback_verbalization(request)
    base_metadata = _result_metadata(
        request,
        enabled=enabled,
        eligible=eligible,
        used=False,
        timed_out=False,
        validation_failed=False,
        fallback_used=True,
        latency_ms=0,
        reason="not_enabled" if not enabled else "not_eligible",
    )
    if not enabled or not eligible:
        return VerbalizerResult(
            used=False,
            enabled=enabled,
            eligible=eligible,
            timed_out=False,
            provider_error=None,
            validation_failed=False,
            fallback_used=True,
            text=fallback,
            fallback_text=fallback,
            reason="not_enabled" if not enabled else "not_eligible",
            latency_ms=_elapsed_ms(started),
            metadata={**base_metadata, "fast_verbalizer_latency_ms": _elapsed_ms(started)},
        )

    prompt = build_verbalizer_prompt(request)
    provider = provider_call or _default_provider_call
    try:
        raw = provider(prompt, request)
        if inspect.isawaitable(raw):
            raw = await asyncio.wait_for(raw, timeout=max(int(request.timeout_ms), 1) / 1000)
    except (asyncio.TimeoutError, TimeoutError):
        latency = _elapsed_ms(started)
        return _fallback_result(request, fallback, enabled, eligible, latency, "timeout", timed_out=True)
    except LLMError as exc:
        latency = _elapsed_ms(started)
        return _fallback_result(request, fallback, enabled, eligible, latency, exc.error_code, provider_error=exc.error_code)
    except Exception as exc:
        latency = _elapsed_ms(started)
        return _fallback_result(request, fallback, enabled, eligible, latency, type(exc).__name__, provider_error=type(exc).__name__)

    raw_text = str(raw)
    ok, errors = validate_verbalizer_output(raw_text, request)
    latency = _elapsed_ms(started)
    if not ok:
        return _fallback_result(
            request,
            fallback,
            enabled,
            eligible,
            latency,
            "validation_failed:" + ",".join(errors[:5]),
            validation_failed=True,
        )
    cleaned = _finalize_text(raw_text, request)
    ok, errors = validate_verbalizer_output(cleaned, request)
    if not ok:
        return _fallback_result(
            request,
            fallback,
            enabled,
            eligible,
            latency,
            "validation_failed:" + ",".join(errors[:5]),
            validation_failed=True,
        )
    metadata = _result_metadata(
        request,
        enabled=enabled,
        eligible=eligible,
        used=True,
        timed_out=False,
        validation_failed=False,
        fallback_used=False,
        latency_ms=latency,
        reason="provider_valid",
    )
    return VerbalizerResult(
        used=True,
        enabled=enabled,
        eligible=eligible,
        timed_out=False,
        provider_error=None,
        validation_failed=False,
        fallback_used=False,
        text=cleaned,
        fallback_text=None,
        reason="provider_valid",
        latency_ms=latency,
        metadata=metadata,
    )


async def _default_provider_call(prompt: str, request: VerbalizerRequest) -> str:
    max_tokens = int(request.max_tokens or _default_token_budget(request))
    messages = [
        {
            "role": "system",
            "content": "/no_think\nYou rewrite safe prepared DSPM Copilot drafts. Return only final wording.",
        },
        {"role": "user", "content": prompt},
    ]
    return await call_ollama(
        messages,
        json_mode=False,
        options={"temperature": 0.25, "top_p": 0.4, "num_predict": max_tokens},
        max_tokens=max_tokens,
        task_type="short_answer",
    )


def _fallback_result(
    request: VerbalizerRequest,
    fallback: str,
    enabled: bool,
    eligible: bool,
    latency_ms: int,
    reason: str,
    *,
    timed_out: bool = False,
    provider_error: str | None = None,
    validation_failed: bool = False,
) -> VerbalizerResult:
    metadata = _result_metadata(
        request,
        enabled=enabled,
        eligible=eligible,
        used=False,
        timed_out=timed_out,
        validation_failed=validation_failed,
        fallback_used=True,
        latency_ms=latency_ms,
        reason=reason,
    )
    return VerbalizerResult(
        used=False,
        enabled=enabled,
        eligible=eligible,
        timed_out=timed_out,
        provider_error=provider_error,
        validation_failed=validation_failed,
        fallback_used=True,
        text=fallback,
        fallback_text=fallback,
        reason=reason,
        latency_ms=latency_ms,
        metadata=metadata,
    )


def _result_metadata(
    request: VerbalizerRequest,
    *,
    enabled: bool,
    eligible: bool,
    used: bool,
    timed_out: bool,
    validation_failed: bool,
    fallback_used: bool,
    latency_ms: int | None,
    reason: str,
) -> dict[str, Any]:
    verbalizer_calls = 1 if enabled and eligible else 0
    role_budget = situation_runtime.provider_role_budget_summary(
        verbalizer_call_count=verbalizer_calls,
        fast_verbalizer_used=bool(used),
        fast_verbalizer_fallback_used=bool(fallback_used),
    )
    return {
        **request.situation_decision.to_route_metadata(),
        **situation_runtime.runtime_response_metadata(
            answer=None,
            decision=request.situation_decision,
            fallback_used=bool(fallback_used),
            fallback_reason=reason,
        ),
        "fast_verbalizer_enabled": bool(enabled),
        "fast_verbalizer_eligible": bool(eligible),
        "fast_verbalizer_used": bool(used),
        "fast_verbalizer_timed_out": bool(timed_out),
        "fast_verbalizer_validation_failed": bool(validation_failed),
        "fast_verbalizer_fallback_used": bool(fallback_used),
        "fast_verbalizer_latency_ms": latency_ms,
        "fast_verbalizer_situation_id": request.situation_decision.situation_id,
        "fast_verbalizer_provider_mode": request.situation_decision.provider_mode.value,
        "fast_verbalizer_reason": reason[:160],
        "verbalizer_call_count": verbalizer_calls,
        "arbiter_call_count": 0,
        "planner_call_count": 0,
        "final_provider_call_count": 0,
        "translator_call_count": 0,
        # Namespaced role flags (the top-level provider_*/translator_* audit
        # fields are supplied by the service; these mirror them without
        # colliding with the audit.log_interaction keyword arguments).
        "fast_verbalizer_provider_final_called": False,
        "fast_verbalizer_provider_planning_called": False,
        "fast_verbalizer_translator_called": False,
        "provider_budget_total": role_budget["provider_budget_total"],
        "provider_budget_roles": role_budget["provider_budget_roles"],
        "provider_role_budget_summary": role_budget,
    }


def provider_role_budget_summary(
    *,
    verbalizer_call_count: int = 0,
    arbiter_call_count: int = 0,
    planner_call_count: int = 0,
    final_provider_call_count: int = 0,
    translator_call_count: int = 0,
    fast_verbalizer_used: bool = False,
    fast_verbalizer_fallback_used: bool = False,
) -> dict[str, Any]:
    """Return a single-source-of-truth role budget snapshot.

    ``provider_call_count`` here is the *total* across every provider role, so
    it never falsely implies a final-answer provider call. Callers can inspect
    the role-specific counts to see exactly which provider budget was spent.
    """
    return situation_runtime.provider_role_budget_summary(
        verbalizer_call_count=verbalizer_call_count,
        arbiter_call_count=arbiter_call_count,
        planner_call_count=planner_call_count,
        final_provider_call_count=final_provider_call_count,
        translator_call_count=translator_call_count,
        fast_verbalizer_used=fast_verbalizer_used,
        fast_verbalizer_fallback_used=fast_verbalizer_fallback_used,
    )


def _safe_draft_is_safe(text: str) -> bool:
    value = str(text or "")
    if len(value) > 500:
        return False
    if _contains_secret_like(value):
        return False
    if _URL_RE.search(value):
        return False
    if _FILENAME_RE.search(value):
        return False
    return True


def _contains_scan_or_finding_fact(text: str) -> bool:
    lowered = str(text or "").lower()
    return bool(_NUMBER_RE.search(lowered) or _URL_RE.search(lowered) or _FILENAME_RE.search(lowered))


def _sanitize_safe_draft_for_prompt(text: str) -> str:
    value = str(text or "")
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    value = _URL_RE.sub("[REDACTED_URL]", value)
    value = _FILENAME_RE.sub("[REDACTED_FILE]", value)
    return value.strip()[:500]


def _safe_style(style: str | None) -> str:
    value = re.sub(r"[^A-Za-z0-9 ,._-]+", "", str(style or "short, natural, professional"))
    return value[:80] or "short, natural, professional"


def _finalize_text(text: str, request: VerbalizerRequest) -> str:
    value = clean_answer_text(str(text or ""))
    value = _BOILERPLATE_PREFIX_RE.sub("", value).strip()
    value = mask_sensitive_text(value)
    if request.target_language == "az":
        value = language_service.polish_azerbaijani(value)
    if not request.allow_emoji:
        value = _EMOJI_RE.sub("", value).strip()
    words = value.split()
    max_words = _max_words(request)
    if len(words) > max_words:
        value = " ".join(words[:max_words]).strip()
    return value


def _language_errors(text: str, target_language: str) -> list[str]:
    if target_language == "az":
        result = language_service.validate_mixed_language(text, "az")
        errors = [f"language:{item}" for item in result.violations]
        if not _AZ_CHAR_RE.search(text):
            words = {word.lower() for word in re.findall(r"[A-Za-z]+", text)}
            if len(words & _EN_WORDS) >= 2:
                errors.append("language:english_sentence")
        return errors
    if target_language == "en" and _AZ_CHAR_RE.search(text):
        return ["language:azerbaijani_in_english"]
    return []


def _unsupported_fact_errors(output: str, safe_draft: str) -> list[str]:
    out = output.lower()
    draft = safe_draft.lower()
    errors: list[str] = []
    for group, terms in _FORBIDDEN_FACT_TERMS.items():
        output_has = any(_contains_term(out, term) for term in terms)
        draft_has = any(_contains_term(draft, term) for term in terms)
        if output_has and not draft_has:
            errors.append(f"unsupported_fact:{group}")
    return errors


def _unsupported_action_errors(output: str, safe_draft: str) -> list[str]:
    out = output.lower()
    draft = safe_draft.lower()
    errors: list[str] = []
    for claim in _ACTION_CLAIMS:
        if claim in out and claim not in draft:
            errors.append("unsupported_action_claim")
            break
    return errors


def _contains_term(text: str, term: str) -> bool:
    if re.search(r"\W", term):
        return term in text
    return bool(re.search(rf"(?<![a-z0-9_]){re.escape(term)}(?![a-z0-9_])", text, flags=re.IGNORECASE))


def _contains_secret_like(value: str) -> bool:
    return any(pattern.search(value or "") for pattern in _SECRET_PATTERNS)


def _word_count(text: str) -> int:
    return len([part for part in re.split(r"\s+", str(text or "").strip()) if part])


def _max_words(request: VerbalizerRequest) -> int:
    if request.max_words is not None:
        return max(1, min(int(request.max_words), 80))
    budget = request.situation_decision.speed_budget.get("max_answer_words")
    if isinstance(budget, int) and budget > 0:
        return min(budget, 80)
    return 40


def _default_token_budget(request: VerbalizerRequest) -> int:
    sid = request.situation_decision.situation_id
    if sid.startswith(("social.", "complaint.")) or sid in _CLARIFICATION_IDS:
        return 80
    if sid.startswith(("edu.", "general.")):
        return 140
    return 80


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)
