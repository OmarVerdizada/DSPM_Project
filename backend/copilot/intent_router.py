from __future__ import annotations

import ast
import operator as _operator
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from backend.copilot import capability_registry, language_service
from backend.copilot.planner import parse_limit_with_negation
from backend.copilot.severity import (
    bare_severity_followup,
    is_severity_breakdown_request,
    mentioned_severities,
    severity_from_normalized_text,
    severity_from_text,
)


# ---------------------------------------------------------------------------
# Safe arithmetic evaluator (no eval(), no shell, ast-only)
# ---------------------------------------------------------------------------
_ARITH_OPS: dict = {
    ast.Add: _operator.add,
    ast.Sub: _operator.sub,
    ast.Mult: _operator.mul,
    ast.Div: _operator.truediv,
    ast.FloorDiv: _operator.floordiv,
    ast.Mod: _operator.mod,
    ast.Pow: _operator.pow,
    ast.USub: _operator.neg,
    ast.UAdd: _operator.pos,
}

_ARITH_EXPR_RE = re.compile(
    r"^-?\d+(?:\.\d+)?\s*(?:[+\-*/]\s*-?\d+(?:\.\d+)?)+$"
)

_AZ_ARITH_SUBS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\busteqel\b|\bustegel\b", re.IGNORECASE), "+"),
    (re.compile(r"\bcixmaq\b|\bcix\b", re.IGNORECASE), "-"),
    (re.compile(r"\bvurmaq\b|\bvur\b", re.IGNORECASE), "*"),
    (re.compile(r"\bbolmek\b|\bbol\b", re.IGNORECASE), "/"),
    (re.compile(r"\bplus\b", re.IGNORECASE), "+"),
    (re.compile(r"\bminus\b", re.IGNORECASE), "-"),
    (re.compile(r"\btimes\b", re.IGNORECASE), "*"),
    (re.compile(r"\bdivided\s+by\b", re.IGNORECASE), "/"),
]


def _safe_eval_arith(expr: str) -> float | None:
    try:
        tree = ast.parse(expr.strip(), mode="eval")
    except SyntaxError:
        return None

    def _eval(node: ast.expr) -> float:
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return float(node.value)
        if isinstance(node, ast.BinOp) and type(node.op) in _ARITH_OPS:
            left_val = _eval(node.left)
            right_val = _eval(node.right)
            if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)) and right_val == 0:
                raise ZeroDivisionError
            return _ARITH_OPS[type(node.op)](left_val, right_val)
        if isinstance(node, ast.UnaryOp) and type(node.op) in _ARITH_OPS:
            return _ARITH_OPS[type(node.op)](_eval(node.operand))
        raise ValueError("unsupported node type")

    try:
        result = _eval(tree.body)
        if not (-1e15 < result < 1e15):
            return None
        return result
    except (ZeroDivisionError, ValueError, OverflowError, RecursionError):
        return None


def _detect_arithmetic(normalized: str) -> float | None:
    """Return numeric result if normalized is a simple arithmetic expression, else None."""
    text = normalized.strip()
    for pattern, sym in _AZ_ARITH_SUBS:
        text = pattern.sub(sym, text)
    text = re.sub(r"\s+", "", text)
    if not _ARITH_EXPR_RE.match(text):
        return None
    return _safe_eval_arith(text)


@dataclass(frozen=True)
class IntentRoute:
    intent: str
    language: str = "az"
    entities: dict[str, Any] = field(default_factory=dict)
    needs_structured_query: bool = False
    retrieval_allowed: bool = False
    provider_allowed: bool = False
    reason: str = "deterministic"


_AZ_CHARS = set("əğıöşçüƏĞİÖŞÇÜ")
_AZ_SIGNAL_WORDS = {
    "salam", "necesen", "netersen", "ozun", "sen", "sən", "mene", "mene",
    "neler", "neleredebilirsen", "ede", "bilirsen", "isler", "gore",
    "tapinti", "tapintini", "kritik", "goster", "duzelt", "duzeltmeliyem",
    "deyirem", "dene", "muqayise", "ele", "eded", "gore", "yox", "yaz",
    "azerbaycan", "dilinde", "niye", "nedi", "cixartdin", "qaqa", "qaa", "qa",
}
def normalize_for_route(message: str) -> str:
    return language_service.normalize_for_intent(message)


def _response_language(message: str, normalized: str) -> str:
    if re.search(r"\b(answer|respond|reply|write|speak)\s+in\s+english\b", normalized):
        return "en"
    if "use english" in normalized or "english please" in normalized:
        return "en"
    if "ingilis dilinde" in normalized or "ingilisce cavab" in normalized:
        return "en"
    if re.search(r"\b(answer|respond|reply|write|speak)\s+in\s+azerbaijani\b", normalized):
        return "az"
    if any(ch in message for ch in _AZ_CHARS):
        return "az"
    words = set(re.findall(r"[a-z0-9_]+", normalized))
    if len(words & _AZ_SIGNAL_WORDS) >= 1 and not {"what", "how", "show", "give", "list", "compare", "english"} & words:
        return "az"
    if len(words & _AZ_SIGNAL_WORDS) >= 2:
        return "az"
    return "en"


def _limit(normalized: str) -> int | None:
    parsed = parse_limit_with_negation(normalized, cap=50)
    if parsed.limit is None:
        return None
    return max(1, min(parsed.limit, 50))


def _severity(normalized: str) -> str | None:
    return severity_from_normalized_text(normalized)


def _severity_from_route_context(context: Mapping[str, Any] | None) -> str | None:
    if not context:
        return None
    result_type = str(context.get("last_result_type") or "").upper()
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if result_type.startswith(f"{severity}_"):
            return severity
    for item in context.get("last_shown_items") or []:
        if isinstance(item, Mapping):
            severity = str(item.get("severity") or "").upper()
            if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                return severity
    return None


def _has_count_context(context: Mapping[str, Any] | None) -> bool:
    if not context:
        return False
    if context.get("last_count_scope_severities"):
        return True
    result_type = str(context.get("last_result_type") or "").lower()
    answer_type = str(context.get("last_answer_type") or "").lower()
    return "count" in result_type or "distribution" in result_type or "count" in answer_type or "distribution" in answer_type


def _mentioned_severities(normalized: str) -> set[str]:
    return mentioned_severities(normalized)


def _is_severity_distribution_question(normalized: str) -> bool:
    if is_severity_breakdown_request(normalized):
        return True
    if any(term in normalized for term in ("severity distribution", "risk summary", "high vs critical", "critical vs high")):
        return True
    mentioned = _mentioned_severities(normalized)
    if len(mentioned) < 2:
        return False
    has_count_language = any(term in normalized for term in ("how many", "count", "say", "nece", "sayi"))
    has_comparison_language = bool(re.search(r"\b(vs|versus)\b", normalized)) or any(term in normalized for term in (" muqayise", " ferq"))
    return has_count_language or has_comparison_language


def _route(intent: str, language: str, *, entities: dict[str, Any] | None = None,
           structured: bool = False, retrieval: bool = False, provider: bool = False,
           reason: str = "deterministic") -> IntentRoute:
    return IntentRoute(
        intent=intent,
        language=language,
        entities=entities or {},
        needs_structured_query=structured,
        retrieval_allowed=retrieval,
        provider_allowed=provider,
        reason=reason,
    )


def route_message(message: str, context: Mapping[str, Any] | None = None) -> IntentRoute:
    normalized = normalize_for_route(message)
    language = _response_language(message, normalized)
    locked_language = (context or {}).get("language_preference_locked")
    if locked_language in {"az", "en"} and not (
        re.search(r"\b(answer|respond|reply|write|speak)\s+in\s+(english|azerbaijani)\b", normalized)
        or "use english" in normalized
        or "english please" in normalized
        or "ingilis dilinde" in normalized
        or "ingilisce cavab" in normalized
        or "azerbaycanca cavab ver" in normalized
        or "azerbaycan dilinde danis" in normalized
    ):
        language = locked_language
    entities: dict[str, Any] = {}
    severity = _severity(normalized)
    context_severity = _severity_from_route_context(context)
    is_random_selection = any(term in normalized for term in ("random", "tesadufi"))
    is_single_selection = bool(
        is_random_selection
        or re.search(r"\b(?:one|single|bir)\s+(?:eded|dene|tane|alert|finding|tapinti)\b", normalized)
    )
    needs_step_by_step = any(term in normalized for term in (
        "step by step", "pille pille", "addim addim", "basa sal", "pillə pillə",
    ))
    wants_remediation_guidance = any(term in normalized for term in (
        "what should i do", "what can i do", "neler etmeliyem", "ne etmeliyem",
        "ne etmeli", "neler etməliyəm", "nə etməliyəm", "remediation",
        "recommendation", "recommendations", "duzeltmeliyem", "fix",
    )) or needs_step_by_step
    if not severity and (is_random_selection or is_single_selection):
        severity = context_severity
    if severity:
        entities["severity"] = severity
    limit = _limit(normalized)
    if limit is None and is_random_selection:
        limit = 1
    if limit:
        entities["limit"] = limit
    if is_random_selection:
        entities["selection_mode"] = "random"
    if wants_remediation_guidance:
        entities["include_remediation"] = True
    if needs_step_by_step:
        entities["needs_step_by_step"] = True

    if "ollama" in normalized and any(term in normalized for term in ("running", "is running", "service", "daemon", "works", "isleyir")):
        return _route("ollama_status_meta", language, reason="model_status_meta")

    greeting_patterns = ("salam", "hi", "hello", "hey")
    status_patterns = (
        "necesen", "netersen", "ozun necesen", "sen necesen",
        "ne var ne yox", "ne xeber", "nece gedir",
        "how are you", "how are u", "are you okay",
    )
    mixed_greeting_status_patterns = (
        "salam necesen", "salam netersen", "salam ne var ne yox",
        "hello how are you", "hi how are you",
    )
    if normalized in mixed_greeting_status_patterns:
        return _route("greeting_status", language)
    if normalized in greeting_patterns:
        return _route("greeting", language)
    if normalized in status_patterns:
        return _route("small_talk_status", language)

    capability_patterns = (
        "what can you do", "what can u do", "help", "sen ne ede bilirsen",
        "ne isler gore bilirsen", "sən nə edə bilirsən", "nə işlər görə bilirsən",
        "neler edebilirsen", "neler edebilersen",
    )
    if (
        normalized in capability_patterns
        or "ne ede bilirsen" in normalized
        or "neler ede" in normalized
        or "neler edebilir" in normalized
        or re.search(r"\bwhat can (you|u)\b", normalized)
        or capability_registry.asks_about_limitations(message)
    ):
        return _route("capability", language)

    complaint_terms = (
        "meni basa dusmursen", "yaxsi anlayabilmirsen", "you are not understanding me",
        "wrong answer", "you are broken", "this is wrong", "not correct",
        "that is incorrect", "thats incorrect", "is incorrect", "that is wrong", "thats wrong",
    )
    correction_terms = (
        "eded yox", "gore yox", "tapinti yox", "azerbaycan herfleri", "duz yaz",
        "bele yazma", "düz yaz", "belə yazma", "proper azerbaijani",
    )
    if any(term in normalized for term in correction_terms) or any(term in normalized for term in ("verebilmiyesen", "verebilmirsen", "vere bilmirsen")):
        return _route("correction", language)
    if any(term in normalized for term in complaint_terms):
        if any(term in normalized for term in ("wrong answer", "this is wrong", "not correct", "incorrect", "that is wrong", "thats wrong")):
            return _route("correction", language)
        return _route("complaint", language)

    # Contextual severity follow-up: "low?", "and high?", "what about medium" after
    # a count/distribution answer inherits the count intent for that severity.
    bare_followup_severity = bare_severity_followup(normalized)
    if bare_followup_severity and _has_count_context(context):
        followup_entities = dict(entities)
        followup_entities["severity"] = bare_followup_severity
        return _route("count_findings", language, entities=followup_entities, structured=True, reason="context_severity_followup")

    if any(term in normalized for term in ("pdf", "export", "report hazirla", "make this a report", "bunu pdf et")):
        return _route("report_export", language, entities=entities)

    proactive_terms = (
        "proaktiv xeberdarliq",
        "proaktiv xeberdarli",
        "proactive alert",
        "send proactive risk alert",
        "notify me about new risks",
        "new risks",
        "yeni risk",
        "riskler barede",
        "risklər barədə",
        "predipredi o novyh riskah",
    )
    if any(term in normalized for term in proactive_terms) and any(term in normalized for term in ("gonder", "gönder", "send", "notify", "alert", "xeberdar", "xəbərdar", "risk")):
        return _route("proactive_alert_request", language, entities=entities, structured=True, retrieval=True, provider=False, reason="proactive_dspm_workflow")

    if ("compare" in normalized or "muqayise" in normalized or "ferq" in normalized) and severity and limit:
        return _route("legacy", language, entities=entities, retrieval=True, provider=True)

    if "compare" in normalized or "muqayise" in normalized or "ferq" in normalized:
        return _route("compare_findings", language, entities=entities, structured=True)

    if any(term in normalized for term in ("posture score", "security posture", "security health", "health score", "risk score", "overall score")):
        return _route("posture_score", language, entities=entities, structured=True)

    if any(term in normalized for term in ("compliance", "gdpr", "hipaa", "pci", "nist")):
        return _route("compliance", language, entities=entities, structured=True, provider=True)

    if "remediation" in normalized:
        return _route("remediation", language, entities=entities, structured=True)

    remediation_followup = any(term in normalized for term in ("what should i do", "what next", "what can i do", "indi ne etmeliyem", "ne etmeli", "neler etmeliyem"))
    has_list_context = any(term in normalized for term in ("alert", "alerts", "finding", "findings", "tapinti", "kritik", "critical"))
    if remediation_followup and has_list_context:
        entities["include_remediation"] = True
        return _route("filter_findings", language, entities=entities, structured=True)

    if remediation_followup:
        if context and (context.get("last_shown_items") or context.get("last_tool_result_summary")):
            return _route("remediation", language, entities=entities, structured=True, reason="follow_up_context")
        return _route("clarification_followup", language, entities=entities)

    if (
        "recommendation" in normalized
        or "recommendations" in normalized
        or "and recommendation" in normalized
        or "duzeltmeliyem" in normalized
        or "duzeltmeli" in normalized
    ):
        return _route("legacy", language, entities=entities, retrieval=True, provider=True)

    count_terms = ("how many", "count", "sayin", "sayi", "nece dene", "nece eded", "nece")
    item_action_terms = ("show", "give me", "list", "goster", "ver", "cixart", "çıxart", "pick")
    dspm_terms = ("finding", "alert", "asset", "file", "scan", "risk", "tapilan", "tapinti", "tapintilar", "goster", "show", "give me", "random")
    explicit_count_question = any(term in normalized for term in count_terms) or bool(
        re.search(r"\beded\b.{0,20}\bvar\b", normalized) or re.search(r"\bvar\b.{0,20}\beded\b", normalized)
    )
    has_item_action = any(term in normalized for term in item_action_terms) or is_random_selection
    if _is_severity_distribution_question(normalized):
        return _route("severity_distribution", language, entities=entities, structured=True)
    if explicit_count_question and not is_random_selection and (
        any(term in normalized for term in dspm_terms) or severity or context_severity
    ):
        return _route("count_findings", language, entities=entities, structured=True)

    detail_terms = (
        "information about", "details", "detail", "why", "recommend", "last critical",
        "number ", "risk for", "about last", "haqqinda", "melumat",
    )
    if any(term in normalized for term in detail_terms):
        return _route("legacy", language, entities=entities, retrieval=True, provider=True)

    list_terms = ("show", "give me", "list", "goster", "ver", "top", "assetleri", "fayllari", "alerts", "alert", "random", "cixart")
    if not severity and "file" in normalized and not any(term in normalized for term in ("alert", "finding", "risk", "critical", "high", "medium", "low")):
        return _route("legacy", language, entities=entities, retrieval=True, provider=True)
    if any(term in normalized for term in list_terms) and any(term in normalized for term in dspm_terms):
        return _route("filter_findings", language, entities=entities, structured=True)

    if any(term in normalized for term in ("explain this", "bunu izah et", "izah et")):
        if "assistant" in normalized:
            return _route("legacy", language, entities=entities, retrieval=True, provider=True)
        if context and (context.get("last_shown_items") or context.get("current_item")):
            return _route("remediation", language, entities=entities, structured=True, reason="follow_up_context")
        return _route("clarification_followup", language, entities=entities)

    if any(term in normalized for term in ("are you ai", "who are you", "what are you", "model are you")):
        return _route("meta", language, entities=entities)

    # Simple arithmetic fast path — no retrieval, no provider, no dashboard context
    arith_result = _detect_arithmetic(normalized)
    if arith_result is not None:
        arith_entities = dict(entities)
        arith_entities["arithmetic_result"] = arith_result
        return _route("simple_arithmetic", language, entities=arith_entities, reason="arithmetic_fast_path")

    # General non-DSPM question — provider allowed but no dashboard retrieval
    _GENERAL_SIGNALS = (
        "what is", "what are", "who is", "how does", "how do", "explain",
        "define", "meaning of", "what does", "capital of", "history of",
        "tell me about", "2fa", "mfa", "two factor", "dns", "http", "https",
        "paytaxti", "paytaxt", "nedir", "ne demekdir", "izah et",
    )
    _DSPM_GUARD = (
        "finding", "alert", "scan", "tapinti", "severity", "risk", "posture",
        "dashboard", "dspm", "remediation", "compliance", "critical", "high", "medium", "low",
    )
    is_general_signal = any(term in normalized for term in _GENERAL_SIGNALS)
    is_dspm_topic = any(term in normalized for term in _DSPM_GUARD)
    if is_general_signal and not is_dspm_topic and not severity and not limit:
        return _route("general_non_dspm_question", language, entities=entities, provider=True, reason="general_knowledge_no_retrieval")

    return _route("legacy", language, entities=entities, retrieval=True, provider=True)
