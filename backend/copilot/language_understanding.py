from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from backend.copilot.language_detector import detect_language as base_detect_language
from backend.copilot.language_detector import normalize_for_language_detection
from backend.copilot.llm_client import LLMError, call_ollama


@dataclass(frozen=True)
class LanguageUnderstandingResult:
    original_text: str
    detected_language: str
    language_candidates: list[dict[str, Any]]
    normalized_text: str
    canonical_text_candidates: list[str]
    cleaned_text: str
    removed_fillers: list[str]
    typo_corrections: list[dict[str, str]]
    intent_candidates: list[dict[str, Any]]
    best_intent: str | None
    confidence: float
    needs_dspm_evidence: bool
    response_language: str
    language_preference_update: str | None
    notes: list[str] = field(default_factory=list)

    def model_dump(self) -> dict[str, Any]:
        return asdict(self)


FILLER_WORDS = {
    "qa",
    "qaa",
    "qaq",
    "qaqa",
    "qardas",
    "qardash",
    "brat",
    "aga",
    "dostum",
    "bro",
}

AZ_ASCII_TO_CANONICAL = {
    "sen": "s\u0259n",
    "men": "m\u0259n",
    "mene": "m\u0259n\u0259",
    "ne": "n\u0259",
    "niye": "niy\u0259",
    "nece": "nec\u0259",
    "isler": "i\u015fl\u0259r",
    "gore": "g\u00f6r\u0259",
    "bilirsen": "bilirs\u0259n",
    "tapinti": "tap\u0131nt\u0131",
    "tapintilar": "tap\u0131nt\u0131lar",
    "tapintilari": "tap\u0131nt\u0131lar\u0131",
    "goster": "g\u00f6st\u0259r",
    "duzeltmeliyem": "d\u00fcz\u0259ltm\u0259liy\u0259m",
    "duzelt": "d\u00fcz\u0259lt",
    "azerbaycan": "az\u0259rbaycan",
    "azerbaycanca": "az\u0259rbaycanca",
    "dilinde": "dilind\u0259",
    "dilind": "dilind\u0259",
    "netersen": "n\u0259t\u0259rs\u0259n",
    "necesen": "nec\u0259s\u0259n",
    "neleredebilirsen": "n\u0259l\u0259r ed\u0259 bilirs\u0259n",
    "neleredebilersen": "n\u0259l\u0259r ed\u0259 bil\u0259rs\u0259n",
    "muqayise": "m\u00fcqayis\u0259",
    "cixart": "\u00e7\u0131xart",
    "dene": "d\u0259n\u0259",
    "eded": "\u0259d\u0259d",
}

CONTROLLED_VOCAB = {
    "kritik",
    "critical",
    "alert",
    "alerti",
    "alertleri",
    "tapinti",
    "tapintilar",
    "tapintilari",
    "finding",
    "findings",
    "goster",
    "tapib",
    "gore",
    "isler",
    "bilirsen",
    "duzeltmeliyem",
    "etmeliyem",
    "azerbaycan",
    "azerbaycanca",
    "dilinde",
    "dilind",
    "cavab",
    "ver",
    "remediation",
    "report",
    "pdf",
    "scan",
    "compliance",
    "risk",
    "netersen",
    "necesen",
    "neler",
    "neleredebilirsen",
    "neleredebilersen",
    "gedir",
    "var",
    "yox",
    "medium",
    "muqayise",
    "cixart",
    "dene",
    "eded",
    "say",
}

INTENT_NEEDS_EVIDENCE = {
    "findings_list": True,
    "list_plus_remediation": True,
    "risk_explanation": True,
    "remediation": True,
    "report_generation": True,
    "scan_comparison": True,
    "compliance_mapping": True,
    "general_dspm_question": True,
}

_AI_HELPER_CACHE: dict[str, dict[str, Any] | None] = {}


def _tokens(text: str) -> list[str]:
    return normalize_for_language_detection(text).replace("-", " ").split()


def _token_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    previous = list(range(len(right) + 1))
    for i, lc in enumerate(left, start=1):
        current = [i]
        for j, rc in enumerate(right, start=1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (0 if lc == rc else 1),
                )
            )
        previous = current
    return previous[-1]


def _correct_tokens(tokens: list[str]) -> tuple[list[str], list[dict[str, str]]]:
    corrected: list[str] = []
    changes: list[dict[str, str]] = []
    for token in tokens:
        if token in CONTROLLED_VOCAB or token.isdigit():
            corrected.append(token)
            continue
        replacement = None
        for candidate in CONTROLLED_VOCAB:
            distance = _token_distance(token, candidate)
            if distance == 1 and len(token) >= 4:
                replacement = candidate
                break
            if len(token) >= 5 and candidate.startswith(token):
                replacement = candidate
                break
        if replacement:
            corrected.append(replacement)
            changes.append({"from": token, "to": replacement})
        else:
            corrected.append(token)
    return corrected, changes


def _remove_fillers(tokens: list[str]) -> tuple[list[str], list[str]]:
    cleaned: list[str] = []
    removed: list[str] = []
    for token in tokens:
        if token in FILLER_WORDS:
            removed.append(token)
        else:
            cleaned.append(token)
    return cleaned, removed


def _canonicalize(tokens: list[str]) -> str:
    return " ".join(AZ_ASCII_TO_CANONICAL.get(token, token) for token in tokens)


def _score_language(original: str, tokens: list[str], removed_fillers: list[str]) -> list[dict[str, Any]]:
    detected, confidence = base_detect_language(original)
    scores = {"az": 0.0, "en": 0.0, "ru": 0.0, "unknown": 0.0}
    scores[detected if detected in scores else "unknown"] += confidence
    token_set = set(tokens)
    az_terms = {
        "sen",
        "mene",
        "men",
        "ne",
        "niye",
        "nece",
        "isler",
        "gore",
        "bilirsen",
        "tapinti",
        "tapintilar",
        "goster",
        "duzeltmeliyem",
        "azerbaycan",
        "azerbaycanca",
        "dilinde",
        "dilind",
        "cavab",
        "ver",
        "kritik",
        "netersen",
        "necesen",
        "neleredebilirsen",
        "neleredebilersen",
        "medium",
        "muqayise",
        "cixart",
        "dene",
        "eded",
        "say",
        "gedir",
        "var",
        "yox",
    }
    en_terms = {
        "what",
        "can",
        "you",
        "do",
        "show",
        "give",
        "critical",
        "finding",
        "findings",
        "scan",
        "compliance",
        "report",
        "risk",
        "analyst",
        "senior",
    }
    scores["az"] += len(token_set & az_terms) * 0.18
    scores["en"] += len(token_set & en_terms) * 0.18
    scores["az"] += len(removed_fillers) * 0.12
    if re.search(r"[\u0400-\u04ff]", original or ""):
        scores["ru"] += 0.85
    if token_set <= {"senior", "risk", "analyst"}:
        scores["en"] += 0.8
        scores["az"] = 0.0
    if token_set <= {"scan", "compliance", "report"}:
        scores["en"] += 0.8
        scores["az"] = 0.0
    candidates = [
        {"language": language, "confidence": round(min(score, 0.99), 2)}
        for language, score in scores.items()
        if score > 0
    ]
    candidates.sort(key=lambda item: item["confidence"], reverse=True)
    return candidates or [{"language": "unknown", "confidence": 0.25}]


def _add_intent(scores: dict[str, float], intent: str, amount: float) -> None:
    scores[intent] = scores.get(intent, 0.0) + amount


def _score_intents(tokens: list[str], cleaned_text: str) -> list[dict[str, Any]]:
    token_set = set(tokens)
    scores: dict[str, float] = {}

    if {"what", "can", "you"} <= token_set or {"what", "can", "u"} <= token_set:
        _add_intent(scores, "capability", 0.95)
    if "help" in token_set and len(tokens) <= 5:
        _add_intent(scores, "capability", 0.75)
    if "bilirsen" in token_set and ({"isler", "gore"} <= token_set or {"ede"} & token_set or "neler" in token_set or "ne" in token_set):
        _add_intent(scores, "capability", 0.94)
    if token_set & {"neleredebilirsen", "neleredebilersen"}:
        _add_intent(scores, "capability", 1.0)
    if {"ne", "isler", "gore"} <= token_set:
        _add_intent(scores, "capability", 0.8)
    if "bilirsen" in token_set and "azerbaycan" in token_set and any(token.startswith("dilind") for token in token_set):
        _add_intent(scores, "capability", 1.0)

    if any(term in cleaned_text for term in ("azerbaycan dilind", "azerbaycanca", "az dilind")):
        if "bilirsen" in token_set:
            _add_intent(scores, "capability", 1.0)
        elif "niye" in token_set or "ingilis" in token_set:
            _add_intent(scores, "language_complaint", 1.05)
        else:
            _add_intent(scores, "language_preference", 0.98)
    if {"cavab", "ver"} <= token_set and ("azerbaycanca" in token_set or "azerbaycan" in token_set):
        _add_intent(scores, "language_preference", 1.0)

    if any(phrase in cleaned_text for phrase in ("bu ne demekdi", "bu nedi", "ne elaqe", "ne yazmisan", "basa dusmedim", "anlamadim", "bu nedi cixartdin")):
        _add_intent(scores, "previous_answer_clarification", 0.95)
    if any(phrase in cleaned_text for phrase in ("anlamirsan", "basa dusmursen", "wrong answer", "not understanding", "i didnt want", "didnt want", "did not ask", "why give information", "why did you give", "are u okay", "are you okay", "you are not okay", "this makes no sense", "unrelated")):
        _add_intent(scores, "language_complaint", 0.88)
    if "istem" in cleaned_text and ("tapinti" in token_set or "sey" in token_set or "bunu" in token_set):
        _add_intent(scores, "language_complaint", 0.95)

    if any(
        phrase in cleaned_text
        for phrase in (
            "necesen",
            "sen necesen",
            "ozun necesen",
            "netersen",
            "sen netersen",
            "ozun netersen",
            "ne var ne yox",
            "nece gedir",
        )
    ):
        _add_intent(scores, "small_talk", 0.96)

    has_dspm_item = bool(token_set & {"critical", "kritik", "high", "medium", "low", "alert", "alerti", "alertleri", "tapinti", "tapintilar", "finding", "findings"})
    has_list_action = bool(token_set & {"goster", "show", "give", "list", "ver", "tapib", "tap"})
    if token_set & {"cixart"}:
        has_list_action = True
    if has_dspm_item and ("muqayise" in token_set or "compare" in token_set):
        _add_intent(scores, "findings_list", 0.9)
    if has_dspm_item and ("nece" in token_set or "how" in token_set or "say" in token_set or "count" in token_set or "var" in token_set):
        _add_intent(scores, "findings_list", 0.86)
    has_remediation = bool(token_set & {"duzeltmeliyem", "etmeliyem", "remediation", "recommend", "fix"})
    if has_dspm_item and has_list_action:
        _add_intent(scores, "findings_list", 0.85)
    if has_dspm_item and has_list_action and has_remediation:
        _add_intent(scores, "list_plus_remediation", 1.05)
    if has_dspm_item and has_remediation:
        _add_intent(scores, "remediation", 0.78)
    if "compliance" in token_set and ("gdpr" in token_set or "finding" in token_set or "scan" in token_set):
        _add_intent(scores, "compliance_mapping", 0.8)
    if "report" in token_set or "pdf" in token_set:
        _add_intent(scores, "report_generation", 0.8)

    if not scores and re.search(r"[\u0400-\u04ff]", cleaned_text):
        _add_intent(scores, "unsupported_or_unclear", 0.55)

    candidates = [{"intent": intent, "confidence": round(min(score, 0.99), 2)} for intent, score in scores.items()]
    priority = {
        "list_plus_remediation": 4,
        "language_complaint": 3,
        "previous_answer_clarification": 3,
        "capability": 2,
    }
    candidates.sort(key=lambda item: (item["confidence"], priority.get(str(item["intent"]), 0)), reverse=True)
    return candidates or [{"intent": "unsupported_or_unclear", "confidence": 0.35}]


def _build_result(original: str, helper: dict[str, Any] | None = None, helper_used: bool = False) -> LanguageUnderstandingResult:
    tokens = _tokens(original)
    no_fillers, removed = _remove_fillers(tokens)
    corrected, corrections = _correct_tokens(no_fillers)
    cleaned_text = " ".join(corrected)
    language_candidates = _score_language(original, corrected, removed)
    intent_candidates = _score_intents(corrected, cleaned_text)

    detected_language = language_candidates[0]["language"]
    best_intent = intent_candidates[0]["intent"]
    confidence = float(intent_candidates[0]["confidence"])
    canonical_candidates = []
    canonical = _canonicalize(corrected)
    if canonical:
        canonical_candidates.append(canonical)
    if best_intent == "capability" and detected_language == "az":
        canonical_candidates.append("n\u0259 ed\u0259 bilirs\u0259n")
        canonical_candidates.append("capability_question")
    if best_intent in {"language_preference", "language_complaint"}:
        canonical_candidates.append("az\u0259rbaycan dilind\u0259 cavab ver")
        canonical_candidates.append("language_preference_or_complaint")
    if best_intent == "list_plus_remediation":
        canonical_candidates.append("critical findings list + remediation")

    notes: list[str] = []
    if helper:
        detected_language = str(helper.get("language") or detected_language)
        best_intent = str(helper.get("intent") or best_intent)
        confidence = float(helper.get("confidence") or confidence)
        cleaned_text = str(helper.get("canonical_text") or cleaned_text)
        canonical_candidates.insert(0, cleaned_text)
        intent_candidates.insert(0, {"intent": best_intent, "confidence": round(confidence, 2), "source": "ai_helper"})
    if helper_used:
        notes.append("ai_helper_used")

    needs_evidence = bool(helper.get("needs_dspm_evidence")) if helper else bool(INTENT_NEEDS_EVIDENCE.get(best_intent or "", False))
    response_language = str(helper.get("response_language")) if helper and helper.get("response_language") else ("az" if detected_language == "az" else "en")
    if detected_language == "ru":
        response_language = "en"
    preference_update = response_language if best_intent in {"language_preference", "language_complaint"} and response_language in {"az", "en"} else None

    deduped_candidates: list[str] = []
    for item in canonical_candidates:
        if item and item not in deduped_candidates:
            deduped_candidates.append(item)

    return LanguageUnderstandingResult(
        original_text=original,
        detected_language=detected_language,
        language_candidates=language_candidates,
        normalized_text=" ".join(tokens),
        canonical_text_candidates=deduped_candidates,
        cleaned_text=cleaned_text,
        removed_fillers=removed,
        typo_corrections=corrections,
        intent_candidates=intent_candidates[:5],
        best_intent=best_intent,
        confidence=round(min(confidence, 0.99), 2),
        needs_dspm_evidence=needs_evidence,
        response_language=response_language if response_language in {"az", "en"} else "en",
        language_preference_update=preference_update,
        notes=notes,
    )


def understand_message(message: str) -> LanguageUnderstandingResult:
    return _build_result(message or "")


def routing_normalized_text(message: str) -> str:
    result = understand_message(message)
    return result.cleaned_text or result.normalized_text


HELPER_SYSTEM = (
    "/no_think\n\n"
    "You classify noisy user text for a local DSPM Copilot. Return compact JSON only. "
    "Do not answer the user. Do not include reasoning."
)


def _helper_prompt(message: str) -> str:
    return (
        "Classify this short user message. Return JSON with keys: language, canonical_text, "
        "intent, needs_dspm_evidence, response_language, confidence. "
        "Allowed intents: capability, language_preference, language_complaint, "
        "previous_answer_clarification, findings_list, list_plus_remediation, remediation, "
        "report_generation, scan_comparison, compliance_mapping, general_dspm_question, unsupported_or_unclear.\n"
        f"Message: {message[:300]}"
    )


async def classify_with_ai_helper(message: str) -> dict[str, Any] | None:
    cache_key = hashlib.sha256((message or "").encode("utf-8", "ignore")).hexdigest()
    if cache_key in _AI_HELPER_CACHE:
        return _AI_HELPER_CACHE[cache_key]
    try:
        raw = await asyncio.wait_for(
            call_ollama(
                [{"role": "system", "content": HELPER_SYSTEM}, {"role": "user", "content": _helper_prompt(message)}],
                json_mode=True,
                options={"temperature": 0.0, "think": False},
                task_type="classification",
            ),
            timeout=1.5,
        )
        data = json.loads(raw)
        if not isinstance(data, dict):
            data = None
    except (LLMError, TimeoutError, ValueError, TypeError, json.JSONDecodeError):
        data = None
    _AI_HELPER_CACHE[cache_key] = data
    return data


async def understand_message_async(message: str) -> LanguageUnderstandingResult:
    deterministic = understand_message(message)
    if deterministic.confidence >= 0.65 and deterministic.best_intent != "unsupported_or_unclear":
        return deterministic
    helper = await classify_with_ai_helper(message or "")
    if not helper:
        return deterministic
    return _build_result(message or "", helper=helper, helper_used=True)


def audit_metadata(result: LanguageUnderstandingResult) -> dict[str, Any]:
    return {
        "language_understanding_mode": "ai_helper" if "ai_helper_used" in result.notes else "deterministic",
        "detected_language": result.detected_language,
        "language_candidates": result.language_candidates[:3],
        "canonical_text": result.canonical_text_candidates[0] if result.canonical_text_candidates else None,
        "canonical_candidates_count": len(result.canonical_text_candidates),
        "removed_fillers": result.removed_fillers[:10],
        "typo_corrections_count": len(result.typo_corrections),
        "intent_candidates": result.intent_candidates[:5],
        "best_intent": result.best_intent,
        "intent_confidence": result.confidence,
        "needs_dspm_evidence": result.needs_dspm_evidence,
        "response_language": result.response_language,
    }
