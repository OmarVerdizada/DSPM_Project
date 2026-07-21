from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from backend.copilot.intent_router import IntentRoute
from backend.copilot.masking import mask_sensitive_text


AZ_BOILERPLATE_IN_EN = ("Tövsiyə", "tapıldı", "aşkar olunub", "yoxla", "lazımsız paylaşımı")
EN_BOILERPLATE_IN_AZ = ("Recommended next step", "found in scan", "Based on the provided", "translation failed", "cannot answer in Azerbaijani")
WRONG_LANGUAGE_IN_RU = ("Recommended next step", "Based on the provided", "Tövsiyə", "tapıldı", "translation failed", "cannot answer in Azerbaijani")
SENSITIVE_MARKERS = ("BEGIN PRIVATE KEY", "password=", "api_key=", "apikey=", "token=", "@example.com")


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    answer: str
    errors: list[str] = field(default_factory=list)


def _payload_items(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    items = payload.get("items")
    return items if isinstance(items, list) else []


def _contains_wrong_language(route: IntentRoute, answer: str) -> bool:
    if route.language == "en":
        return any(term in answer for term in AZ_BOILERPLATE_IN_EN)
    if route.language == "ru":
        return any(term.lower() in answer.lower() for term in WRONG_LANGUAGE_IN_RU)
    return any(term.lower() in answer.lower() for term in EN_BOILERPLATE_IN_AZ)


def _contains_unmasked_sensitive(answer: str) -> bool:
    masked = mask_sensitive_text(answer)
    if masked != answer:
        return True
    return any(marker.lower() in answer.lower() for marker in SENSITIVE_MARKERS)


def validate_contract_answer(route: IntentRoute, answer: str, payload: Any = None) -> ValidationResult:
    errors: list[str] = []
    text = answer or ""
    if _contains_wrong_language(route, text):
        errors.append("wrong_language_boilerplate")
    if _contains_unmasked_sensitive(text):
        errors.append("unmasked_sensitive_value")
    if route.intent == "count_findings":
        items = _payload_items(payload)
        if items:
            errors.append("count_answer_contains_list_items")
        if isinstance(payload, dict) and str(payload.get("count")) not in text:
            errors.append("count_missing_payload_count")
        if re.search(r"\b[\w.-]+\.(?:env|yaml|yml|json|txt|pem|key)\b", text, re.IGNORECASE):
            errors.append("count_answer_contains_finding_name")
    if route.intent in {"complaint", "correction", "meta", "capability", "greeting", "small_talk_status", "greeting_status"}:
        if re.search(r"\b[\w.-]+\.(?:env|yaml|yml|json|txt|pem|key)\b", text, re.IGNORECASE):
            errors.append("non_dspm_answer_contains_finding_name")
        if any(term in text.lower() for term in ("critical finding", "high risk asset", "severity:", "risk score")):
            errors.append("non_dspm_answer_contains_finding_detail")
    if route.intent == "filter_findings" and isinstance(payload, dict):
        returned = payload.get("returned")
        if isinstance(returned, int):
            found_names = re.findall(r"\b[\w.-]+\.(?:env|yaml|yml|json|txt|pem|key)\b", text, re.IGNORECASE)
            if len(set(found_names)) > returned:
                errors.append("list_answer_exceeds_payload_returned")
    return ValidationResult(ok=not errors, answer=mask_sensitive_text(text), errors=errors)


def safe_fallback_for_route(route: IntentRoute, payload: Any = None) -> str:
    if route.language == "en":
        if route.intent == "count_findings" and isinstance(payload, dict):
            return f"Available DSPM data shows {int(payload.get('count') or 0)} matching findings."
        if route.intent in {"complaint", "correction"}:
            return "You are right to flag that. I will answer from the current question and available DSPM data only."
        if route.intent == "capability":
            from backend.copilot.capability_registry import render_capabilities

            return render_capabilities("en")
        return "I cannot answer this from available DSPM data."
    if route.language == "ru":
        if route.intent == "count_findings" and isinstance(payload, dict):
            return f"По данным последнего сканирования, найдено {int(payload.get('count') or 0)} findings."
        if route.intent in {"complaint", "correction"}:
            return "Вы правы — я неправильно понял запрос. В этом ответе я не буду использовать контекст выбранной находки."
        if route.intent == "capability":
            from backend.copilot.capability_registry import render_capabilities

            return render_capabilities("ru")
        if route.intent in {"greeting", "small_talk_status", "greeting_status"}:
            return "Здравствуйте. Я готов помочь с DSPM scans, findings, risk и remediation."
        return "Я не могу ответить на это по доступным DSPM данным."
    if route.intent == "count_findings" and isinstance(payload, dict):
        severity = payload.get("severity") or "uyğun"
        return f"Mövcud DSPM datasına əsasən {severity} üçün uyğun finding sayı: {int(payload.get('count') or 0)}."
    if route.intent in {"complaint", "correction"}:
        return "Haqlısan. Bu cavabda əvvəlki finding kontekstini istifadə etmirəm; sualınızı mövcud DSPM datasına əsasən yenidən cavablandıracağam."
    if route.intent == "capability":
        from backend.copilot.capability_registry import render_capabilities

        return render_capabilities("az")
    if route.intent == "greeting":
        return "Salam. Mən hazıram; DSPM scan, finding, risk və remediation suallarında kömək edə bilərəm."
    if route.intent == "small_talk_status":
        return "Yaxşıyam, sağ ol! DSPM tapıntıları və risklərlə bağlı kömək etməyə hazıram."
    if route.intent == "greeting_status":
        return "Salam! Yaxşıyam, sağ ol. DSPM tapıntıları və risklərlə bağlı kömək etməyə hazıram."
    return "Mövcud DSPM məlumatlarına əsasən buna cavab verə bilmirəm."
