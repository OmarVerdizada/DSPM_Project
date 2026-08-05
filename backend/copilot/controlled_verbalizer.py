"""P4B controlled natural verbalizer for ResponseBrainmap answers.

This module does not classify, retrieve evidence, or decide facts. It receives a
safe ResponseBrainmap plus a prepared/structured answer and either asks the
existing local provider to verbalize that brainmap or returns a local fallback
variant within the configured budget.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import inspect
import os
import re
import time
from typing import Any, Mapping

from backend.copilot import fast_situation_arbiter, language_service, provider_health, response_brainmap
from backend.copilot.guardrails import clean_answer_text
from backend.copilot.llm_client import LLMError, call_ollama
from backend.copilot.masking import mask_sensitive_text


PRODUCTION_TIMEOUT_MS = 3000
MAX_RECENT_FINGERPRINTS = 20
MAX_FAMILY_FINGERPRINTS = 8
MAX_RECENT_SNIPPETS = 6
CONTROLLED_VERBALIZER_DEFAULT_ENABLED = True

_ELIGIBLE_FAMILIES = {
    response_brainmap.BrainmapFamily.SOCIAL,
    response_brainmap.BrainmapFamily.CAPABILITY,
    response_brainmap.BrainmapFamily.ASSISTANT_BEHAVIOR_META,
    response_brainmap.BrainmapFamily.LANGUAGE_AND_OUTPUT_QUALITY,
    response_brainmap.BrainmapFamily.UNSUPPORTED_OR_OUT_OF_SCOPE,
    response_brainmap.BrainmapFamily.AMBIGUOUS_OR_UNKNOWN,
}

_STRUCTURED_FAMILIES = {
    response_brainmap.BrainmapFamily.DSPM_FACTUAL,
    response_brainmap.BrainmapFamily.TASK_FRAME,
    response_brainmap.BrainmapFamily.SCAN_OPERATION,
    response_brainmap.BrainmapFamily.MODEL_PROVIDER_STATUS,
    response_brainmap.BrainmapFamily.UTILITY,
    response_brainmap.BrainmapFamily.ARTIFACT,
    response_brainmap.BrainmapFamily.PROFESSIONAL_WORKFLOW,
}

_ARABIC_RE = re.compile(r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF]")
_PREFIX_RE = re.compile(r"^\s*(?:az(?:ə|e)rbaycanca\s+cavab|azerbaijani\s+answer|answer|cavab)\s*[:：]", re.IGNORECASE)
_NUMBER_RE = re.compile(r"(?<![A-Za-z0-9_])\d+(?:[.,]\d+)?(?![A-Za-z0-9_])")
_SECRET_RE = re.compile(
    r"AKIA[0-9A-Z]{12,}|sk-[A-Za-z0-9_-]{12,}|(?i:(api[_-]?key|password|secret|token)\s*[:=]\s*\S+)"
)
_INTERNAL_TERMS = (
    "brainmap",
    "hidden prompt",
    "system prompt",
    "chain-of-thought",
    "policy",
    "route_id",
    "provider",
    "ollama",
    "fallback",
    "validation",
)
_SELECTED_FINDING_FORBIDDEN = (
    "seçilmiş tapıntı",
    "secilmis tapinti",
    "selected finding",
    "seçilmiş tapıntı",
)
_COUNT_FALLBACK_FORBIDDEN = (
    "say, siyahı",
    "say, siyahi",
    "siyahı və ya müqayisə",
    "siyahi ve ya muqayise",
    "count/list/compare",
)
_MALFORMED_AZ_TERMS = (
    "bulunma",
    "özümü təsadüfən",
    "ozumu tesadufen",
    "ticaart",
    "söyüyünüz",
    "mӧjü",
    "çevri",
    "çeviri",
)


@dataclass(frozen=True)
class VerbalizerPolicy:
    enabled: bool
    allowed: bool
    timeout_ms: int
    reason: str
    default_enabled: bool = CONTROLLED_VERBALIZER_DEFAULT_ENABLED
    disabled_by_config: bool = False


@dataclass(frozen=True)
class VerbalizerPrompt:
    messages: list[dict[str, str]]
    safe_prompt: str
    max_tokens: int


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FallbackVariantResult:
    text: str
    variant_id: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class ControlledVerbalizerResult:
    text: str
    allowed: bool
    called: bool
    result: str
    fallback_used: bool
    fallback_reason: str | None
    validation_failed: bool
    timeout_ms: int
    latency_ms: int
    variant_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def configured_timeout_ms(timeout_ms: int | None = None) -> int:
    if timeout_ms is not None:
        return max(1, int(timeout_ms))
    raw = os.getenv("COPILOT_CONTROLLED_VERBALIZER_TIMEOUT_MS")
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            pass
    return PRODUCTION_TIMEOUT_MS


def _is_enabled(metadata: Mapping[str, Any] | None = None) -> bool:
    override = (metadata or {}).get("enable_controlled_verbalizer")
    if isinstance(override, bool):
        return override
    env_value = os.getenv("COPILOT_CONTROLLED_VERBALIZER", "").strip().lower()
    if env_value in {"1", "true", "yes", "on"}:
        return True
    if env_value in {"0", "false", "no", "off"}:
        return False
    return CONTROLLED_VERBALIZER_DEFAULT_ENABLED


def _disabled_by_config(metadata: Mapping[str, Any] | None = None) -> bool:
    override = (metadata or {}).get("enable_controlled_verbalizer")
    if isinstance(override, bool):
        return not override
    env_value = os.getenv("COPILOT_CONTROLLED_VERBALIZER", "").strip().lower()
    return env_value in {"0", "false", "no", "off"}


def _explicitly_enabled_by_config(metadata: Mapping[str, Any] | None = None) -> bool:
    override = (metadata or {}).get("enable_controlled_verbalizer")
    if isinstance(override, bool):
        return override
    env_value = os.getenv("COPILOT_CONTROLLED_VERBALIZER", "").strip().lower()
    return env_value in {"1", "true", "yes", "on"}


def _safe_language(language: str | None) -> str:
    return language if language in {"az", "en", "ru"} else "az"


def _word_count(text: str) -> int:
    return len([part for part in re.split(r"\s+", str(text or "").strip()) if part])


def _max_words(brainmap: response_brainmap.ResponseBrainmap) -> int:
    preferred = str(brainmap.style.style.get("preferred_verbosity") or "default")
    max_sentences = int(brainmap.policy.response_policy.get("max_sentences") or 2)
    if preferred == "short":
        return 8 if max_sentences <= 2 else 45
    if brainmap.situation.family == response_brainmap.BrainmapFamily.SOCIAL:
        return 14
    if brainmap.situation.family == response_brainmap.BrainmapFamily.ASSISTANT_BEHAVIOR_META:
        return 22
    if preferred == "detailed":
        return 55
    return 32


def should_use_controlled_verbalizer(
    brainmap: response_brainmap.ResponseBrainmap,
    provider_snapshot: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> VerbalizerPolicy:
    timeout_ms = configured_timeout_ms()
    response_policy = brainmap.policy.response_policy
    enabled = _is_enabled(metadata)
    disabled_by_config = _disabled_by_config(metadata)
    force_block_reason = str((metadata or {}).get("controlled_verbalizer_force_block_reason") or "").strip()
    if force_block_reason:
        return VerbalizerPolicy(enabled, False, timeout_ms, force_block_reason, disabled_by_config=disabled_by_config)
    if not bool(response_policy.get("ai_verbalizer_allowed")):
        return VerbalizerPolicy(enabled, False, timeout_ms, "brainmap_policy_denied", disabled_by_config=disabled_by_config)
    if brainmap.situation.family in _STRUCTURED_FAMILIES:
        return VerbalizerPolicy(enabled, False, timeout_ms, "structured_renderer_required", disabled_by_config=disabled_by_config)
    if brainmap.situation.family not in _ELIGIBLE_FAMILIES:
        return VerbalizerPolicy(enabled, False, timeout_ms, "family_not_eligible", disabled_by_config=disabled_by_config)
    if brainmap.evidence.evidence_required:
        return VerbalizerPolicy(enabled, False, timeout_ms, "evidence_required", disabled_by_config=disabled_by_config)
    if disabled_by_config:
        return VerbalizerPolicy(False, False, timeout_ms, "disabled_by_config", disabled_by_config=True)
    explicitly_enabled = _explicitly_enabled_by_config(metadata)
    health_snapshot = provider_snapshot if isinstance(provider_snapshot, Mapping) and provider_snapshot.get("provider_health_status") else provider_health.snapshot()
    health_status = str(health_snapshot.get("provider_health_status") or "unknown")
    if health_snapshot.get("provider_circuit_open") or health_status == "unhealthy":
        return VerbalizerPolicy(enabled, True, timeout_ms, "provider_unhealthy", disabled_by_config=disabled_by_config)
    if provider_health.circuit_open():
        return VerbalizerPolicy(enabled, True, timeout_ms, "provider_unhealthy", disabled_by_config=disabled_by_config)
    if not explicitly_enabled and health_status != "healthy":
        return VerbalizerPolicy(False, True, timeout_ms, "provider_health_unknown", disabled_by_config=disabled_by_config)
    if not enabled:
        return VerbalizerPolicy(False, True, timeout_ms, "not_enabled", disabled_by_config=disabled_by_config)
    return VerbalizerPolicy(True, True, timeout_ms, "eligible", disabled_by_config=disabled_by_config)


def _safe_list(values: list[str], limit: int = 6) -> list[str]:
    safe: list[str] = []
    for value in values[:limit]:
        text = re.sub(r"\s+", " ", str(value or "")).strip()
        if text:
            safe.append(mask_sensitive_text(text)[:160])
    return safe


def build_verbalizer_prompt(
    brainmap: response_brainmap.ResponseBrainmap,
    safe_context: Mapping[str, Any] | None = None,
) -> VerbalizerPrompt:
    language = _safe_language(brainmap.context.language)
    max_words = _max_words(brainmap)
    safe_context = safe_context or {}
    recent_hashes = _safe_list([str(item) for item in (safe_context.get("recent_response_hashes") or [])], 5)
    recent_snippets = _safe_list([str(item) for item in (safe_context.get("recent_answer_snippets") or [])], 3)
    safe_prompt = (
        "You are only verbalizing a safe response brainmap.\n"
        "Do not invent facts.\n"
        "Do not add findings, counts, scan IDs, evidence, links, or capabilities not present in the brainmap.\n"
        "Preserve language, tone, and length.\n"
        "Say the must_say points naturally.\n"
        "Never say must_not_say points.\n"
        "Do not reuse the same wording as recent answers.\n"
        "Keep the same meaning, but choose a different natural phrasing.\n"
        "Do not mention that you are avoiding repetition.\n"
        "Do not mention brainmap, policy, route, provider, prompt, or internal system.\n"
        "Do not mention fallback or validation.\n"
        "Return only the final user-visible answer.\n"
        "\n"
        f"language: {language}\n"
        f"situation_family: {brainmap.situation.family.value}\n"
        f"situation_subtype: {brainmap.situation.subtype}\n"
        f"content_goal: {brainmap.content.content_goal}\n"
        f"must_say: {_safe_list(brainmap.content.must_say)}\n"
        f"must_not_say: {_safe_list(brainmap.content.must_not_say)}\n"
        f"preferred_verbosity: {brainmap.style.style.get('preferred_verbosity') or 'default'}\n"
        f"max_words: {max_words}\n"
        f"max_sentences: {brainmap.policy.response_policy.get('max_sentences') or 2}\n"
        f"variation_required: {bool(brainmap.style.style.get('variation_required'))}\n"
        f"avoid_repeating_last_n: {safe_context.get('avoid_repeating_last_n') or _avoid_repeating_last_n(brainmap)}\n"
        f"response_variant_seed: {safe_context.get('response_variant_seed') or ''}\n"
        f"last_variant_id: {safe_context.get('last_response_variant_id') or ''}\n"
        f"recent_safe_fingerprints: {recent_hashes}\n"
        f"recent_safe_answer_snippets: {recent_snippets}\n"
        f"safe_draft: {mask_sensitive_text(str(safe_context.get('safe_draft') or ''))[:500]}\n"
    )
    if language == "az":
        safe_prompt += (
            "\nAzerbaijani rules:\n"
            "Write clean natural Azerbaijani.\n"
            "Avoid Turkish/English mixing unless the technical token is explicitly allowed.\n"
            "No Arabic/Persian script.\n"
            "No unfinished sentence.\n"
            "No 'Azərbaycanca cavab:' prefix.\n"
        )
    elif language == "en":
        safe_prompt += (
            "\nEnglish rules:\n"
            "Write clean natural English.\n"
            "Do not answer in Azerbaijani.\n"
            "Do not translate into Azerbaijani.\n"
            "Do not include Azerbaijani canned fragments (Salam, buradayam, hazıram, tapıntı).\n"
            "No unfinished sentence.\n"
        )
    elif language == "ru":
        safe_prompt += (
            "\nRussian rules:\n"
            "Write clean natural Russian.\n"
            "Do not answer in Azerbaijani or English prose.\n"
            "No unfinished sentence.\n"
        )
    messages = [
        {
            "role": "system",
            "content": "You rewrite safe DSPM Copilot response brainmaps. Return only final wording.",
        },
        {"role": "user", "content": safe_prompt},
    ]
    return VerbalizerPrompt(messages=messages, safe_prompt=safe_prompt, max_tokens=max(48, min(160, max_words * 4)))


def _normalize_for_fingerprint(text: str) -> str:
    value = language_service.normalize_for_intent(clean_answer_text(text or "")).lower()
    value = re.sub(r"[^a-z0-9əıöüçşğ]+", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def fingerprint_answer(text: str) -> str:
    normalized = _normalize_for_fingerprint(text)
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _family_key(brainmap: response_brainmap.ResponseBrainmap) -> str:
    return f"{brainmap.situation.family.value}.{brainmap.situation.subtype}"


def _avoid_repeating_last_n(brainmap: response_brainmap.ResponseBrainmap) -> int:
    configured = int(brainmap.style.style.get("avoid_repeating_last_n") or 0)
    family = brainmap.situation.family
    if family in {response_brainmap.BrainmapFamily.SOCIAL, response_brainmap.BrainmapFamily.ASSISTANT_BEHAVIOR_META}:
        return max(configured, 5)
    if family in {response_brainmap.BrainmapFamily.CAPABILITY, response_brainmap.BrainmapFamily.LANGUAGE_AND_OUTPUT_QUALITY}:
        return max(configured, 3)
    return max(configured, 1)


def _recent_global_fingerprints(
    brainmap: response_brainmap.ResponseBrainmap,
    conversation_state: Mapping[str, Any] | None,
) -> list[str]:
    limit = _avoid_repeating_last_n(brainmap)
    values = (conversation_state or {}).get("recent_response_fingerprints")
    if isinstance(values, list):
        return [str(value) for value in values[-limit:] if value]
    return []


def _recent_family_fingerprints(
    brainmap: response_brainmap.ResponseBrainmap,
    conversation_state: Mapping[str, Any] | None,
) -> list[str]:
    state = conversation_state or {}
    limit = _avoid_repeating_last_n(brainmap)
    grouped = state.get("recent_brainmap_response_fingerprints")
    if isinstance(grouped, Mapping):
        values = grouped.get(_family_key(brainmap))
        if isinstance(values, list):
            return [str(value) for value in values[-min(MAX_FAMILY_FINGERPRINTS, limit):] if value]
    return []


def _recent_family_snippets(
    brainmap: response_brainmap.ResponseBrainmap,
    conversation_state: Mapping[str, Any] | None,
) -> list[str]:
    state = conversation_state or {}
    grouped = state.get("recent_brainmap_response_snippets")
    if isinstance(grouped, Mapping):
        values = grouped.get(_family_key(brainmap))
        if isinstance(values, list):
            return [sanitize_response_snippet(value) for value in values[-MAX_RECENT_SNIPPETS:] if value]
    values = state.get("recent_response_snippets")
    if isinstance(values, list):
        return [sanitize_response_snippet(value) for value in values[-MAX_RECENT_SNIPPETS:] if value]
    return []


def sanitize_response_snippet(value: Any, limit: int = 120) -> str:
    text = clean_answer_text(mask_sensitive_text(str(value or ""))).strip()
    text = re.sub(r"\s+", " ", text)
    return text[:limit]


def _response_variant_seed(
    brainmap: response_brainmap.ResponseBrainmap,
    conversation_state: Mapping[str, Any] | None,
) -> str:
    existing = str((conversation_state or {}).get("response_variant_seed") or "").strip()
    if existing:
        return existing[:32]
    raw = f"{(conversation_state or {}).get('conversation_id') or ''}:{brainmap.context.language}:{brainmap.situation.family.value}"
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _recent_fingerprint_set(
    brainmap: response_brainmap.ResponseBrainmap,
    conversation_state: Mapping[str, Any] | None,
) -> set[str]:
    return set(_recent_global_fingerprints(brainmap, conversation_state)) | set(_recent_family_fingerprints(brainmap, conversation_state))


def _token_similarity(left: str, right: str) -> float:
    left_tokens = set(_normalize_for_fingerprint(left).split())
    right_tokens = set(_normalize_for_fingerprint(right).split())
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / max(1, len(left_tokens | right_tokens))


def _too_similar_to_recent(
    answer: str,
    brainmap: response_brainmap.ResponseBrainmap,
    conversation_state: Mapping[str, Any] | None,
) -> bool:
    fingerprint = fingerprint_answer(answer)
    if fingerprint in _recent_fingerprint_set(brainmap, conversation_state):
        return True
    normalized = _normalize_for_fingerprint(answer)
    for snippet in _recent_family_snippets(brainmap, conversation_state):
        if normalized and normalized == _normalize_for_fingerprint(snippet):
            return True
        if _token_similarity(answer, snippet) >= 0.86:
            return True
    return False


def _select_variant(
    brainmap: response_brainmap.ResponseBrainmap,
    conversation_state: Mapping[str, Any] | None,
    variants: tuple[str, ...],
    reason: str,
) -> tuple[str, str, str, bool]:
    if not variants:
        return "", f"{brainmap.situation.family.value.lower()}:{brainmap.situation.subtype}:0", _response_variant_seed(brainmap, conversation_state), False
    seed = _response_variant_seed(brainmap, conversation_state)
    family = brainmap.situation.family
    subtype = brainmap.situation.subtype
    recent_fingerprints = _recent_fingerprint_set(brainmap, conversation_state)
    last_variant_id = str((conversation_state or {}).get("last_response_variant_id") or "")
    base = int(hashlib.sha256(f"{seed}:{_family_key(brainmap)}:{reason}:{len(recent_fingerprints)}".encode("utf-8", errors="ignore")).hexdigest()[:8], 16)
    first_choice: tuple[str, str] | None = None
    for offset in range(len(variants)):
        index = (base + offset) % len(variants)
        text = _fit_budget(variants[index], brainmap)
        variant_id = f"{family.value.lower()}:{subtype}:{index + 1}"
        if first_choice is None:
            first_choice = (text, variant_id)
        if variant_id == last_variant_id:
            continue
        if fingerprint_answer(text) in recent_fingerprints:
            continue
        if _too_similar_to_recent(text, brainmap, conversation_state):
            continue
        return text, variant_id, seed, True
    text, variant_id = first_choice or (_fit_budget(variants[0], brainmap), f"{family.value.lower()}:{subtype}:1")
    return text, variant_id, seed, bool(recent_fingerprints or last_variant_id)


def render_brainmap_fallback_variant(
    brainmap: response_brainmap.ResponseBrainmap,
    conversation_state: Mapping[str, Any] | None,
    reason: str,
) -> FallbackVariantResult:
    language = _safe_language(brainmap.context.language)
    subtype = brainmap.situation.subtype
    family = brainmap.situation.family
    preferred = str(brainmap.style.style.get("preferred_verbosity") or "default")
    short = preferred == "short"
    variants: tuple[str, ...]

    if language == "az" and family == response_brainmap.BrainmapFamily.SOCIAL:
        if subtype in {"greeting", "repeated_greeting"}:
            variants = (
                "Salam, buradayam. Hansı riskə baxaq?",
                "Salam! İstəsən, son scan üzrə əsas risklərdən başlayaq.",
                "Buradayam. Tapıntı, scan və ya remediation üzrə sual verə bilərsən.",
            )
        elif subtype == "status_check":
            variants = (
                "Yaxşıyam, sağ ol. DSPM riskləri üzrə kömək etməyə hazıram.",
                "Yaxşıyam. İstəsən, son scan risklərinə baxaq.",
            )
        elif subtype == "praise":
            variants = (
                "Sağ ol. DSPM riskləri üzrə kömək etməyə hazıram.",
                "Təşəkkür edirəm. Növbəti riskə baxa bilərik.",
            )
        else:
            variants = ("Oldu. DSPM üzrə sualın varsa, buyur.",)
    elif language == "az" and family == response_brainmap.BrainmapFamily.ASSISTANT_BEHAVIOR_META:
        if subtype == "response_too_long_feedback":
            variants = (
                "Oldu, bundan sonra daha qısa və konkret cavab verəcəyəm.",
                "Başa düşdüm, daha qısa cavab verəcəyəm.",
                "Düz deyirsən, uzatmayacağam; daha qısa cavab verəcəyəm.",
            )
        elif subtype == "response_too_short_feedback":
            variants = (
                "Oldu, lazım olanda daha ətraflı izah verəcəyəm.",
                "Başa düşdüm. Növbəti cavablarda daha çox kontekst verəcəyəm.",
            )
        elif subtype == "repeated_answer_complaint":
            variants = (
                "Haqlısan, eyni cavab təkrarlanmamalıdır; növbəti sosial cavablarda variantlılığı qoruyacağam.",
                "Düz deyirsən. Bu təkrar olmamalı idi, cavab variantlarını dəyişəcəyəm.",
                "Razıyam, eyni salam cavabını dönə-dönə verməməliyəm.",
            )
        elif subtype in {"clarify_previous_response", "explain_previous_response"}:
            variants = (
                "Üzr istəyirəm, əvvəlki cavabım aydın deyildisə, onu daha sadə formada izah edəcəyəm.",
                "Başa düşdüm. Əvvəlki cavabı daha qısa və aydın formada yenidən deyim.",
            )
        elif subtype == "wrong_route_correction":
            variants = (
                "Haqlısınız — bu, istədiyiniz cavab deyildi və səhv kontekstdən istifadə etmişəm. İndi nəyi görmək istədiyinizi yazın, düz kontekstlə cavab verim.",
                "Düz deyirsiniz, əvvəlki cavab səhv kontekstdə idi. Həmin kontekstdən istifadə etmirəm — sualı bir də verin, düzgün cavablayım.",
            )
        elif subtype == "explain_previous_route":
            variants = (
                "Bu, əvvəlki cavabla bağlı meta sual idi — seçilmiş tapıntı kontekstini yox, əvvəlki cavabın özünü izah etməliyəm.",
                "Sualınız əvvəlki cavab haqqında idi; ona görə seçilmiş tapıntı detallarını təkrar etmirəm, əvvəlki cavabı izah edirəm.",
            )
        else:
            variants = (
                "Haqlısan, cavabı daha təmiz və qısa formada quracağam.",
                "Başa düşdüm. Növbəti cavabı daha aydın saxlayacağam.",
            )
    elif language == "az" and family == response_brainmap.BrainmapFamily.CAPABILITY:
        variants = (
            "DSPM scan, tapıntı, risk və remediation suallarında kömək edə bilərəm.",
            "Mən scan nəticələri, tapıntılar, risk prioriteti və remediation üzrə kömək edirəm.",
        )
    elif language == "az" and family == response_brainmap.BrainmapFamily.LANGUAGE_AND_OUTPUT_QUALITY:
        if subtype == "malformed_output_complaint":
            variants = (
                "\u00d6n\u00e7\u00fck Az\u0259rbaycan dilind\u0259 d\u00fczg\u00fcn s\u00f6z deyil; ehtimal olunan d\u00fczg\u00fcn forma \u00f6nc\u0259ki ola bil\u0259r. Sondak\u0131 t\u0259 is\u0259 yar\u0131m\u00e7\u0131q qalm\u0131\u015f cavab hiss\u0259sidir.",
                "Haql\u0131s\u0131n\u0131z, \u00d6n\u00e7\u00fck Az\u0259rbaycan dilind\u0259 d\u00fczg\u00fcn s\u00f6z deyil; \u00f6nc\u0259ki n\u0259z\u0259rd\u0259 tutulmu\u015f ola bil\u0259r. Sondak\u0131 t\u0259 is\u0259 yar\u0131m\u00e7\u0131q qalm\u0131\u015f cavab hiss\u0259sidir.",
            )
        else:
            variants = (
                "Haql\u0131s\u0131n\u0131z, cavab Az\u0259rbaycan dilind\u0259 ayd\u0131n v\u0259 t\u0259miz olmal\u0131 idi.",
                "Haql\u0131s\u0131n\u0131z, qar\u0131\u015f\u0131q dil istifad\u0259 etm\u0259m\u0259liydim; cavab\u0131 Az\u0259rbaycan dilind\u0259 saxlayaca\u011fam.",
            )
    elif language == "en" and family == response_brainmap.BrainmapFamily.SOCIAL:
        if subtype in {"greeting", "repeated_greeting"}:
            variants = (
                "Hi, I'm here. What risk should we look at?",
                "Hello again. We can start from the top risks in the latest scan.",
                "I'm here. You can ask about the latest scan, findings, or remediation.",
            )
        elif subtype == "status_check":
            variants = (
                "I'm good, thanks. I'm ready to help with DSPM risks.",
                "Doing well. Want to look at the latest scan risks?",
            )
        elif subtype == "praise":
            variants = (
                "Thanks. I'm ready to help with the next DSPM risk.",
                "Appreciate it. We can move on to the next finding.",
            )
        else:
            variants = ("Sure. If you have a DSPM question, go ahead.",)
    elif language == "en" and family == response_brainmap.BrainmapFamily.ASSISTANT_BEHAVIOR_META:
        if subtype == "response_too_long_feedback":
            variants = (
                "Got it, I'll keep the answers shorter and more concrete.",
                "Understood, I'll be more concise from here.",
            )
        elif subtype == "response_too_short_feedback":
            variants = (
                "Got it, I'll add more detail when it helps.",
                "Understood. I'll give more context in the next answers.",
            )
        elif subtype == "repeated_answer_complaint":
            variants = (
                "You're right, I shouldn't repeat the same answer; I'll vary the phrasing.",
                "Fair point. That repetition shouldn't happen; I'll change the wording.",
            )
        elif subtype in {"clarify_previous_response", "explain_previous_response"}:
            variants = (
                "Sorry if that wasn't clear; I'll explain it more simply.",
                "Understood. Let me restate the previous answer more clearly.",
            )
        elif subtype == "wrong_route_correction":
            variants = (
                "You're right — that wasn't what you asked for, and I used the wrong context. Tell me what you'd like to see and I'll answer with the right one.",
                "Fair point: my previous answer used the wrong context. I've dropped it — ask again and I'll answer the right thing.",
            )
        elif subtype == "explain_previous_route":
            variants = (
                "That was a question about my previous answer, so I'm explaining that answer instead of reusing the selected-finding context.",
                "Your question was about the earlier reply — I won't repeat the selected-finding details; let me explain the previous answer.",
            )
        else:
            variants = (
                "You're right, I'll keep the answer cleaner and shorter.",
                "Understood. I'll keep the next answer clearer.",
            )
    elif language == "en" and family == response_brainmap.BrainmapFamily.CAPABILITY:
        variants = (
            "I can help with DSPM scans, findings, risk, and remediation questions.",
            "I help with scan results, findings, risk priority, and remediation steps.",
        )
    elif language == "en" and family == response_brainmap.BrainmapFamily.LANGUAGE_AND_OUTPUT_QUALITY:
        variants = (
            "You're right, the answer should stay in clear English.",
            "You're right; I should keep the response in the requested language.",
        )
    elif language == "en":
        variants = (
            "Tell me which finding you want a step-by-step plan for: share the file name or ask me to pick one.",
        )
    elif language == "az":
        variants = (
            "Hansı tapıntı üçün addım-addım plan istədiyini dəqiqləşdir: fayl adını yaz və ya bir tapıntı seçməyimi istə.",
        )
    elif language == "ru":
        variants = ("Отвечу коротко и безопасно.",)
    else:
        variants = ("I will keep this short and controlled.",)

    variants = _expanded_fallback_variants(brainmap, language, variants)
    if short:
        variants = tuple(_first_sentence(value) for value in variants)
    variants = tuple(_preserve_fallback_public_markers(value, brainmap) for value in variants)
    text, variant_id, seed, anti_repetition = _select_variant(brainmap, conversation_state, variants, reason)
    return FallbackVariantResult(
        text=text,
        variant_id=variant_id,
        metadata={
            "controlled_verbalizer_fallback_variant_id": variant_id,
            "controlled_verbalizer_fallback_family": family.value,
            "response_variant_id": variant_id,
            "response_variant_seed": seed,
            "anti_repetition_applied": anti_repetition,
            "recent_fingerprint_count": len(_recent_fingerprint_set(brainmap, conversation_state)),
        },
    )


def _preserve_fallback_public_markers(text: str, brainmap: response_brainmap.ResponseBrainmap) -> str:
    language = _safe_language(brainmap.context.language)
    family = brainmap.situation.family
    subtype = brainmap.situation.subtype
    value = str(text or "").strip()
    if language == "az" and family == response_brainmap.BrainmapFamily.SOCIAL:
        if subtype == "status_check":
            if "Yax\u015f\u0131yam" not in value:
                value = f"Yax\u015f\u0131yam. {value}".strip()
            if "DSPM" not in value:
                value = f"{value} DSPM riskl\u0259ri \u00fczr\u0259 k\u00f6m\u0259k etm\u0259y\u0259 haz\u0131ram.".strip()
            return value
        if subtype in {"greeting", "repeated_greeting"}:
            prefix = ""
            if "Salam" not in value:
                prefix += "Salam. "
            if "Yax\u015f\u0131yam" not in value:
                prefix += ""
                value = f"{value} Yax\u015f\u0131yam.".strip()
            return f"{prefix}{value}".strip()
    if language == "az" and family == response_brainmap.BrainmapFamily.ASSISTANT_BEHAVIOR_META and subtype == "response_too_long_feedback":
        folded = language_service.normalize_for_intent(value).lower()
        if "qisa" not in folded and "q\u0131sa" not in value.lower():
            return f"Q\u0131sa cavab ver\u0259c\u0259y\u0259m. {value}".strip()
    if language == "az" and family == response_brainmap.BrainmapFamily.CAPABILITY and "DSPM" not in value:
        value = f"DSPM: {value}".strip()
    if language == "az" and family == response_brainmap.BrainmapFamily.CAPABILITY and "finding" not in value.lower():
        return f"{value} finding m\u00f6vzular\u0131n\u0131 da izah ed\u0259 bilir\u0259m.".strip()
    return value


def _expanded_fallback_variants(
    brainmap: response_brainmap.ResponseBrainmap,
    language: str,
    variants: tuple[str, ...],
) -> tuple[str, ...]:
    family = brainmap.situation.family
    subtype = brainmap.situation.subtype
    extra: tuple[str, ...] = ()
    if language == "az" and family == response_brainmap.BrainmapFamily.SOCIAL and subtype in {"greeting", "repeated_greeting"}:
        extra = (
            "Salam. Hansı scan, risk və ya remediation mövzusuna baxım?",
            "Salam! Buyur, bu gün hansı DSPM riskini açaq?",
            "Buradayam. Son scan nəticəsi, risk və ya tapıntı üzrə davam edə bilərik.",
            "Salam, hazıram. Konkret risk, tapıntı və ya remediation sualı verə bilərsən.",
        )
    elif language == "az" and family == response_brainmap.BrainmapFamily.SOCIAL and subtype == "status_check":
        extra = ("Hazıram. Hansı tapıntı və ya riskə baxmağımı istəyirsən?",)
    elif language == "az" and family == response_brainmap.BrainmapFamily.ASSISTANT_BEHAVIOR_META and subtype == "response_too_long_feedback":
        extra = (
            "Oldu, növbəti cavabları daha qısa və yığcam saxlayacağam.",
            "Başa düşdüm, bundan sonra qısa və birbaşa cavab verəcəyəm.",
        )
    elif language == "az" and family == response_brainmap.BrainmapFamily.ASSISTANT_BEHAVIOR_META and subtype == "response_too_short_feedback":
        extra = ("Oldu, ehtiyac olanda cavabı daha açıq izahla genişləndirəcəyəm.",)
    elif language == "az" and family == response_brainmap.BrainmapFamily.ASSISTANT_BEHAVIOR_META and subtype == "repeated_answer_complaint":
        extra = (
            "Haqlı iraddır. Eyni cavabı təkrarlamaq əvəzinə mənanı qoruyub ifadəni dəyişəcəyəm.",
            "Düz tutmusan, bu təkrar hissi yaratmamalıdır; cavabları daha variantlı saxlayacağam.",
            "Razıyam. Sosial cavablar eyni məzmunu saxlayıb fərqli sözlərlə gəlməlidir.",
        )
    elif language == "az" and family == response_brainmap.BrainmapFamily.CAPABILITY:
        extra = (
            "Scan xülasəsi, tapıntı izahı, risk prioriteti və remediation planında kömək edə bilərəm.",
            "Tapıntı sayı, risk siyahısı və addım-addım remediation üzrə cavab verə bilirəm.",
        )
    result = list(variants)
    for value in extra:
        if value not in result:
            result.append(value)
    return tuple(result)


def _first_sentence(text: str) -> str:
    parts = re.split(r"(?<=[.!?])\s+", str(text or "").strip())
    return parts[0].strip() if parts and parts[0].strip() else str(text or "").strip()


def _fit_budget(text: str, brainmap: response_brainmap.ResponseBrainmap) -> str:
    value = clean_answer_text(mask_sensitive_text(str(text or ""))).strip()
    if brainmap.context.language == "az":
        value = language_service.polish_azerbaijani(value)
    max_words = _max_words(brainmap)
    words = value.split()
    if len(words) > max_words:
        value = " ".join(words[:max_words]).rstrip(" ,;") + "."
    return value


def validate_verbalized_answer(
    answer: str,
    brainmap: response_brainmap.ResponseBrainmap,
    safe_context: Mapping[str, Any] | None = None,
) -> ValidationResult:
    errors: list[str] = []
    text = clean_answer_text(str(answer or "")).strip()
    if not text:
        return ValidationResult(False, ["empty"])
    lowered = text.lower()
    safe_context = safe_context or {}
    safe_draft = str(safe_context.get("safe_draft") or "")
    if _PREFIX_RE.search(text):
        errors.append("forbidden_prefix")
    if _SECRET_RE.search(text):
        errors.append("secret_like")
    if brainmap.context.language == "az":
        if _ARABIC_RE.search(text):
            errors.append("arabic_persian_script")
        mixed = language_service.validate_mixed_language(text, "az")
        errors.extend([f"language:{item}" for item in mixed.violations])
        if any(term in lowered for term in _MALFORMED_AZ_TERMS):
            errors.append("malformed_azerbaijani")
        if fast_situation_arbiter.is_truncated(text):
            errors.append("truncated")
    if any(term in lowered for term in _INTERNAL_TERMS):
        errors.append("internal_text")
    forbidden_strings = brainmap.safety.safety_policy.get("forbidden_strings") or []
    for forbidden in forbidden_strings:
        if forbidden and str(forbidden).lower() in lowered:
            errors.append("forbidden_string")
    for item in brainmap.content.must_not_say:
        item_lower = str(item or "").lower()
        if item_lower and item_lower in lowered:
            errors.append("must_not_say")
    if not brainmap.policy.context_policy.get("selected_finding_allowed"):
        if any(term in lowered for term in _SELECTED_FINDING_FORBIDDEN):
            errors.append("selected_finding_forbidden")
    if brainmap.situation.family == response_brainmap.BrainmapFamily.ASSISTANT_BEHAVIOR_META:
        if any(term in lowered for term in _COUNT_FALLBACK_FORBIDDEN):
            errors.append("generic_count_fallback_forbidden")
    if brainmap.situation.family != response_brainmap.BrainmapFamily.DSPM_FACTUAL:
        new_numbers = set(_NUMBER_RE.findall(text)) - set(_NUMBER_RE.findall(safe_draft))
        if new_numbers:
            errors.append("invented_number")
    if _word_count(text) > _max_words(brainmap):
        errors.append("too_long")
    return ValidationResult(not errors, errors)


async def run_controlled_verbalizer_with_timeout(
    brainmap: response_brainmap.ResponseBrainmap,
    safe_context: Mapping[str, Any] | None = None,
    *,
    timeout_ms: int | None = None,
) -> tuple[str | None, str | None]:
    prompt = build_verbalizer_prompt(brainmap, safe_context)
    raw = call_ollama(
        prompt.messages,
        json_mode=False,
        options={"temperature": 0.35, "top_p": 0.6, "num_predict": prompt.max_tokens},
        max_tokens=prompt.max_tokens,
        task_type="short_answer",
    )
    try:
        if inspect.isawaitable(raw):
            raw = await asyncio.wait_for(raw, timeout=configured_timeout_ms(timeout_ms) / 1000)
        return str(raw), None
    except (asyncio.TimeoutError, TimeoutError):
        return None, "timeout"


async def finalize_brainmap_answer(
    *,
    answer: str,
    brainmap: response_brainmap.ResponseBrainmap,
    metadata: Mapping[str, Any] | None,
    conversation_state: Mapping[str, Any] | None,
    timeout_ms: int | None = None,
) -> ControlledVerbalizerResult:
    started = time.perf_counter()
    provider_snapshot = provider_health.snapshot()
    policy = should_use_controlled_verbalizer(brainmap, provider_snapshot, metadata)
    fallback = render_brainmap_fallback_variant(brainmap, conversation_state, policy.reason)
    base_metadata = _base_metadata(brainmap, policy, fallback)

    if policy.reason == "disabled_by_config":
        return _fallback_result(started, brainmap, fallback, policy, "disabled_by_config")
    if not policy.allowed:
        return ControlledVerbalizerResult(
            text=answer,
            allowed=False,
            called=False,
            result="structured_renderer",
            fallback_used=False,
            fallback_reason=None,
            validation_failed=False,
            timeout_ms=policy.timeout_ms,
            latency_ms=_elapsed_ms(started),
            variant_id=None,
            metadata={**base_metadata, "controlled_verbalizer_result": "structured_renderer"},
        )
    if policy.reason == "provider_unhealthy":
        return _fallback_result(started, brainmap, fallback, policy, "provider_unhealthy")
    if not policy.enabled:
        latency = _elapsed_ms(started)
        return ControlledVerbalizerResult(
            text=answer,
            allowed=policy.allowed,
            called=False,
            result="not_enabled",
            fallback_used=False,
            fallback_reason=None,
            validation_failed=False,
            timeout_ms=policy.timeout_ms,
            latency_ms=latency,
            variant_id=None,
            metadata={
                **base_metadata,
                "controlled_verbalizer_result": policy.reason,
                "controlled_verbalizer_latency_ms": latency,
                "controlled_verbalizer_response_fingerprint": fingerprint_answer(answer),
                "provider_final_called": False,
            },
        )

    safe_context = {
        "safe_draft": answer,
        "recent_response_hashes": sorted(_recent_fingerprint_set(brainmap, conversation_state))[:8],
        "recent_answer_snippets": _recent_family_snippets(brainmap, conversation_state),
        "avoid_repeating_last_n": _avoid_repeating_last_n(brainmap),
        "response_variant_seed": _response_variant_seed(brainmap, conversation_state),
        "last_response_variant_id": (conversation_state or {}).get("last_response_variant_id"),
    }
    called = True
    try:
        raw_text, runtime_reason = await run_controlled_verbalizer_with_timeout(
            brainmap,
            safe_context,
            timeout_ms=policy.timeout_ms,
        )
    except LLMError as exc:
        provider_health.record_failure(exc.error_code, str(exc))
        return _fallback_result(started, brainmap, fallback, policy, "provider_error", called=called)
    except Exception as exc:
        provider_health.record_failure("CONTROLLED_VERBALIZER_ERROR", str(exc))
        return _fallback_result(started, brainmap, fallback, policy, "provider_error", called=called)

    if runtime_reason == "timeout":
        return _fallback_result(started, brainmap, fallback, policy, "timeout", called=called)
    cleaned = _fit_budget(str(raw_text or ""), brainmap)
    validation = validate_verbalized_answer(cleaned, brainmap, safe_context)
    if not validation.ok:
        meta = {**base_metadata, "controlled_verbalizer_validation_errors": ",".join(validation.errors[:6])}
        return _fallback_result(started, brainmap, fallback, policy, "validation_failed", called=called, extra_metadata=meta, validation_failed=True)

    fingerprint = fingerprint_answer(cleaned)
    similarity_retry_used = False
    similarity_blocked = False
    anti_repetition_applied = bool(_avoid_repeating_last_n(brainmap))
    if anti_repetition_applied and _too_similar_to_recent(cleaned, brainmap, conversation_state):
        similarity_retry_used = True
        retry_safe_context = dict(safe_context)
        retry_safe_context["similarity_retry"] = True
        try:
            raw_retry, retry_reason = await run_controlled_verbalizer_with_timeout(
                brainmap,
                retry_safe_context,
                timeout_ms=max(1, policy.timeout_ms - _elapsed_ms(started)),
            )
        except Exception:
            raw_retry, retry_reason = None, "provider_error"
        if not retry_reason and raw_retry:
            retry_cleaned = _fit_budget(str(raw_retry), brainmap)
            retry_validation = validate_verbalized_answer(retry_cleaned, brainmap, retry_safe_context)
            retry_fingerprint = fingerprint_answer(retry_cleaned)
            if retry_validation.ok and not _too_similar_to_recent(retry_cleaned, brainmap, conversation_state):
                cleaned = retry_cleaned
                fingerprint = retry_fingerprint
            else:
                similarity_blocked = True
                return _fallback_result(
                    started,
                    brainmap,
                    fallback,
                    policy,
                    "too_similar",
                    called=called,
                    extra_metadata={
                        "controlled_verbalizer_similarity_retry_used": similarity_retry_used,
                        "controlled_verbalizer_similarity_blocked": similarity_blocked,
                    },
                )
        else:
            similarity_blocked = True
            return _fallback_result(
                started,
                brainmap,
                fallback,
                policy,
                "too_similar",
                called=called,
                extra_metadata={
                    "controlled_verbalizer_similarity_retry_used": similarity_retry_used,
                    "controlled_verbalizer_similarity_blocked": similarity_blocked,
                },
            )

    latency = _elapsed_ms(started)
    return ControlledVerbalizerResult(
        text=cleaned,
        allowed=True,
        called=True,
        result="success",
        fallback_used=False,
        fallback_reason=None,
        validation_failed=False,
        timeout_ms=policy.timeout_ms,
        latency_ms=latency,
        variant_id=None,
        metadata={
            **base_metadata,
            "controlled_verbalizer_called": True,
            "controlled_verbalizer_result": "success",
            "controlled_verbalizer_fallback_used": False,
            "controlled_verbalizer_fallback_reason": None,
            "controlled_verbalizer_latency_ms": latency,
            "controlled_verbalizer_response_fingerprint": fingerprint,
            "controlled_verbalizer_similarity_retry_used": similarity_retry_used,
            "controlled_verbalizer_similarity_blocked": similarity_blocked,
            "response_variant_id": f"verbalizer:{_family_key(brainmap)}:{fingerprint[:8]}",
            "response_variant_seed": _response_variant_seed(brainmap, conversation_state),
            "anti_repetition_applied": anti_repetition_applied,
            "recent_fingerprint_count": len(_recent_fingerprint_set(brainmap, conversation_state)),
            "provider_final_called": False,
        },
    )


def _base_metadata(
    brainmap: response_brainmap.ResponseBrainmap,
    policy: VerbalizerPolicy,
    fallback: FallbackVariantResult,
) -> dict[str, Any]:
    return {
        "controlled_verbalizer_allowed": bool(policy.allowed),
        "controlled_verbalizer_enabled": bool(policy.enabled),
        "controlled_verbalizer_default_enabled": bool(policy.default_enabled),
        "controlled_verbalizer_disabled_by_config": bool(policy.disabled_by_config),
        "controlled_verbalizer_called": False,
        "controlled_verbalizer_timeout_ms": int(policy.timeout_ms),
        "controlled_verbalizer_result": policy.reason,
        "controlled_verbalizer_fallback_used": False,
        "controlled_verbalizer_fallback_reason": None,
        "controlled_verbalizer_validation_failed": False,
        "controlled_verbalizer_similarity_retry_used": False,
        "controlled_verbalizer_similarity_blocked": False,
        "controlled_verbalizer_latency_ms": 0,
        "controlled_verbalizer_preferred_verbosity": brainmap.style.style.get("preferred_verbosity") or "default",
        "anti_repetition_applied": bool(_avoid_repeating_last_n(brainmap)),
        "recent_fingerprint_count": len(_recent_fingerprint_set(brainmap, None)),
        "provider_final_called": False,
        **fallback.metadata,
    }


def _fallback_result(
    started: float,
    brainmap: response_brainmap.ResponseBrainmap,
    fallback: FallbackVariantResult,
    policy: VerbalizerPolicy,
    reason: str,
    *,
    called: bool = False,
    validation_failed: bool = False,
    extra_metadata: Mapping[str, Any] | None = None,
) -> ControlledVerbalizerResult:
    latency = _elapsed_ms(started)
    fingerprint = fingerprint_answer(fallback.text)
    metadata = {
        **_base_metadata(brainmap, policy, fallback),
        **dict(extra_metadata or {}),
        "controlled_verbalizer_called": bool(called),
        "controlled_verbalizer_result": "fallback",
        "controlled_verbalizer_fallback_used": True,
        "controlled_verbalizer_fallback_reason": reason,
        "controlled_verbalizer_validation_failed": bool(validation_failed),
        "controlled_verbalizer_latency_ms": latency,
        "controlled_verbalizer_response_fingerprint": fingerprint,
        "provider_final_called": False,
    }
    return ControlledVerbalizerResult(
        text=fallback.text,
        allowed=policy.allowed,
        called=called,
        result="fallback",
        fallback_used=True,
        fallback_reason=reason,
        validation_failed=validation_failed,
        timeout_ms=policy.timeout_ms,
        latency_ms=latency,
        variant_id=fallback.variant_id,
        metadata=metadata,
    )


def fingerprint_update_payload(
    brainmap: response_brainmap.ResponseBrainmap,
    answer: str,
    session_state: Mapping[str, Any] | None,
    *,
    variant_id: str | None = None,
    response_variant_seed: str | None = None,
) -> dict[str, Any]:
    next_state = dict(session_state or {})
    fingerprint = fingerprint_answer(answer)
    snippet = sanitize_response_snippet(answer)
    recent = [str(value) for value in (next_state.get("recent_response_fingerprints") or []) if value]
    recent.append(fingerprint)
    next_state["recent_response_fingerprints"] = recent[-MAX_RECENT_FINGERPRINTS:]
    grouped_raw = next_state.get("recent_brainmap_response_fingerprints")
    grouped: dict[str, list[str]] = {}
    if isinstance(grouped_raw, Mapping):
        for key, values in grouped_raw.items():
            if isinstance(values, list):
                grouped[str(key)] = [str(value) for value in values[-MAX_FAMILY_FINGERPRINTS:] if value]
    key = _family_key(brainmap)
    family_values = grouped.get(key, [])
    family_values.append(fingerprint)
    grouped[key] = family_values[-MAX_FAMILY_FINGERPRINTS:]
    next_state["recent_brainmap_response_fingerprints"] = grouped
    if brainmap.situation.family in _ELIGIBLE_FAMILIES and not brainmap.evidence.evidence_required and snippet:
        snippets = [sanitize_response_snippet(value) for value in (next_state.get("recent_response_snippets") or []) if value]
        snippets.append(snippet)
        next_state["recent_response_snippets"] = snippets[-MAX_RECENT_SNIPPETS:]
        grouped_snippets_raw = next_state.get("recent_brainmap_response_snippets")
        grouped_snippets: dict[str, list[str]] = {}
        if isinstance(grouped_snippets_raw, Mapping):
            for raw_key, values in grouped_snippets_raw.items():
                if isinstance(values, list):
                    grouped_snippets[str(raw_key)] = [sanitize_response_snippet(value) for value in values[-MAX_RECENT_SNIPPETS:] if value]
        family_snippets = grouped_snippets.get(key, [])
        family_snippets.append(snippet)
        grouped_snippets[key] = family_snippets[-MAX_RECENT_SNIPPETS:]
        next_state["recent_brainmap_response_snippets"] = grouped_snippets
    next_state["last_response_variant_id"] = variant_id or f"{key}:{fingerprint[:8]}"
    next_state["response_variant_seed"] = response_variant_seed or _response_variant_seed(brainmap, next_state)
    next_state["last_brainmap_response_key"] = key
    return next_state


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)
