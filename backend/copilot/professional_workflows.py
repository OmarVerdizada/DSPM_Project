"""Deterministic, evidence-based professional DSPM follow-up workflows.

This module adds analyst-grade follow-up behaviour on top of the existing
deterministic routes. Every function here is:

* zero-provider (no LLM / no translator calls),
* evidence-based (answers are computed from session context or the scan
  report that was already retrieved), and
* safe (only sanitized metadata already present in session memory is used;
  no raw secrets, no arbitrary tools).

Covered follow-ups (all built from ``last_shown_items`` / scan evidence):

* riskiest item             -> "onlardan ən risklisi hansıdır?"
* triage / fix-first        -> "mən nə etməliyəm indi?", "what should I fix first?"
* condense previous answer  -> "əvvəlki cavabı qısa de", "make it shorter"
* risk-type breakdown       -> "bu 72 kritikdən neçəsi secret-dir?",
                               "which findings are credentials?"
* manager summary           -> "bu tapıntı üçün manager summary ver"
* technical remediation     -> "technical remediation ver"

Supported languages: ``az`` (primary), ``en``, ``ru``.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

from backend.copilot.remediation_policy import (
    CATEGORY_ORDER,
    categorize_risk_types,
)
from backend.copilot.skill_renderers import render_step_by_step_remediation

# Intent identifiers emitted by :func:`detect_professional_followup`.
RISKIEST = "riskiest_item"
TRIAGE = "triage_priorities"
CONDENSE = "condense_previous"
RISK_TYPE_BREAKDOWN = "risk_type_breakdown"
MANAGER_SUMMARY = "manager_summary"
TECHNICAL_REMEDIATION = "technical_remediation"
SCAN_DELTA = "scan_delta"
FIX_NOW_TOP_RISKS = "fix_now_top_risks"


# ---------------------------------------------------------------------------
# Category display labels
# ---------------------------------------------------------------------------
_CATEGORY_LABELS: dict[str, dict[str, str]] = {
    "credential": {"az": "credential/secret", "en": "credential/secret", "ru": "credential/secret"},
    "financial": {"az": "maliyyə/ödəniş", "en": "financial/payment", "ru": "финансовые/платёжные"},
    "personal": {"az": "şəxsi/PII", "en": "personal/PII", "ru": "персональные/PII"},
    "confidential": {"az": "məxfi/məhdud", "en": "confidential/restricted", "ru": "конфиденциальные"},
    "context": {"az": "kontekstual risk", "en": "contextual risk", "ru": "контекстный риск"},
    "unknown": {"az": "təsnif olunmamış", "en": "unclassified", "ru": "не классифицировано"},
}

# Category keywords used to detect which category the user asked about.
_CATEGORY_QUERY_TERMS: dict[str, tuple[str, ...]] = {
    "credential": (
        "secret", "credential", "credentials", "password", "parol", "token",
        "api key", "apikey", "api-key", "private key", "acar", "sirr", "jwt",
    ),
    "financial": (
        "financial", "finance", "maliyye", "credit card", "kredit kart", "kart",
        "iban", "bank", "payment", "odenis", "pci",
    ),
    "personal": (
        "personal", "pii", "sexsi", "email", "e-mail", "phone", "telefon",
        "contact", "elaqe",
    ),
    "confidential": (
        "confidential", "mexfi", "restricted", "mehdud", "classified", "gizli",
    ),
    "context": (
        "hr context", "payroll", "finance context", "contextual", "kontekst",
    ),
}


def _norm(message: str) -> str:
    """ASCII-fold Azerbaijani for keyword matching (mirrors intent_router)."""
    text = str(message or "").lower()
    for src, dst in (
        ("ə", "e"), ("ı", "i"), ("ğ", "g"), ("ö", "o"),
        ("ş", "s"), ("ç", "c"), ("ü", "u"), ("İ", "i"),
    ):
        text = text.replace(src, dst)
    return text


def _has_list_context(items: list[dict[str, Any]] | None) -> bool:
    return bool(items)


_PREVIOUS_SET_TERMS = (
    "onlardan", "bunlardan", "onlarin", "bunlarin", "onlar arasinda",
    "from those", "from them", "from these", "of these", "of those",
    "from the list", "siyahidan", "yuxaridakilardan",
)


def refers_to_previous_set(message: str) -> bool:
    """True when the user explicitly points back at the previously shown items."""
    return any(t in _norm(message) for t in _PREVIOUS_SET_TERMS)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
_STEP_MARKERS = ("step by step", "pille pille", "addim addim", "basa sal")
_LIST_VERBS = ("goster", "show", "list", "ver ", "cixart", "give me", "gətir", "getir")


def detect_professional_followup(
    message: str, session_state: Mapping[str, Any] | None
) -> str | None:
    """Classify a professional follow-up, or return ``None`` to defer.

    Detection is intentionally conservative: it only fires when the required
    context (previous list / previous answer) exists, so it never hijacks a
    fresh request that the normal deterministic routes should handle.
    """
    norm = _norm(message)
    raw = str(message or "").lower()
    joined = f"{norm} {raw}"
    context = session_state or {}
    items = [i for i in (context.get("last_shown_items") or []) if isinstance(i, dict)]

    if _is_scan_delta_request(joined):
        return SCAN_DELTA

    # Manager summary — business-facing summary of the selected/last finding.
    if ("manager" in norm or "executive" in norm or "menecer" in norm or "rehber" in norm) and any(
        t in norm for t in ("summary", "xulase", "icmal", "ozet", "hesabat")
    ):
        if items:
            return MANAGER_SUMMARY

    # Technical remediation — detailed technical fix plan for the finding.
    if ("technical" in norm or "texniki" in norm) and any(
        t in norm for t in ("remediation", "remediasiya", "fix", "duzelt", "plan", "hell")
    ):
        if items:
            return TECHNICAL_REMEDIATION

    # Risk-type breakdown — "which findings are credentials", "neçəsi secret-dir".
    # Excluded: compliance questions and questions about a specific named file
    # (those have their own established routes).
    excluded_for_breakdown = _is_compliance_question(norm) or _references_filename(norm)
    if not excluded_for_breakdown:
        asked_category = _queried_category(norm)
        strong_breakdown = any(
            t in norm for t in ("risk type breakdown", "risk-type breakdown", "risk tipi", "hansi tiplerde")
        )
        category_query = asked_category is not None and any(
            t in norm for t in ("nece", "how many", "which", "hansi", "count", "breakdown")
        )
        if strong_breakdown or category_query:
            return RISK_TYPE_BREAKDOWN

    # Riskiest item — reasons over the shown list. Fires when a list exists, or
    # when the user explicitly points back at the previous set (so a "onlardan
    # ən risklisi" with no list yields a smart clarification, not a provider call).
    riskiest_terms = (
        "en risklisi", "en riskli", "most risky", "riskiest", "highest risk",
        "en tehlukelisi", "en tehlukeli", "biggest risk", "en boyuk risk",
        "hansi daha riskli", "which is the riskiest", "hansimiz riskli",
    )
    if any(t in norm for t in riskiest_terms) and (
        _has_list_context(items) or refers_to_previous_set(message)
    ):
        return RISKIEST

    # Condense previous answer — needs a previous answer to shorten.
    condense_terms = (
        "qisa de", "qisaca", "qisa yaz", "daha qisa", "shorten", "make it shorter",
        "briefly", "tldr", "tl;dr", "in short", "bir cumle", "one sentence",
        "qisa cavab", "qisaldib",
    )
    has_prev_answer = bool((context.get("last_answer_text") or context.get("last_answer_summary")))
    if any(t in norm for t in condense_terms) and has_prev_answer:
        return CONDENSE

    # Triage / fix-first — standalone prioritization ask (not a list+step request).
    has_step = any(t in norm for t in _STEP_MARKERS)
    has_list_verb = any(t in norm for t in _LIST_VERBS)
    # Only unambiguous prioritization asks. Bare "indi nə etməliyəm" keeps its
    # established selected-finding remediation route and is intentionally excluded.
    triage_terms = (
        "fix first", "what should i fix", "neden baslamaliyam", "nereden baslamaliyam",
        "prioritet", "prioritize", "prioritise", "triage", "en vacib", "en once",
        "hansindan baslamaliyam", "top priorities", "top priority",
        "ilk neyi duzeldim", "ilk nəyi düzəldim", "first fix", "fix-now", "fix now",
        "top 5 risk", "top five risk", "ən vacib 5", "en vacib 5",
    )
    if any(t in norm for t in triage_terms) and not has_step and not has_list_verb:
        return TRIAGE if refers_to_previous_set(message) else FIX_NOW_TOP_RISKS
    if any(t in joined for t in triage_terms) and not has_step:
        return TRIAGE if refers_to_previous_set(message) else FIX_NOW_TOP_RISKS

    return None


def _is_scan_delta_request(joined: str) -> bool:
    if any(term in joined for term in ("pdf", "artifact", "export", "download", "full link")):
        return False
    if any(term in joined for term in ("how many", "nece", "neçə", "count", "say")) and "changed" not in joined:
        return False
    terms = (
        "ne deyisib", "nə dəyişib", "what changed", "changed since last scan",
        "since last scan", "compare latest scan", "latest scan previous",
        "latest scan with previous", "previous scan", "evvelki scan", "əvvəlki scan",
        "son scan evvel", "son scan əvvəl", "scan muqayise", "scan müqayisə",
        "worse", "better", "pisdir", "yaxsidir", "yaxşıdır",
    )
    has_scan_context = any(term in joined for term in ("scan", "skan", "son scan", "latest scan", "previous scan", "əvvəlki"))
    return any(term in joined for term in terms) and (has_scan_context or "what changed" in joined or "nə dəyişib" in joined)


_COMPLIANCE_TERMS = (
    "compliance", "gdpr", "hipaa", "pci", "nist", "iso 27001", "iso27001",
    "soc 2", "soc2", "framework", "standart", "cerceve",
)

_FILENAME_RE = re.compile(r"[\w-]+\.(yaml|yml|json|txt|csv|xlsx|docx|pdf|env|pem|key|log|xml|ini|conf)\b")


def _is_compliance_question(norm: str) -> bool:
    return any(t in norm for t in _COMPLIANCE_TERMS)


def _references_filename(norm: str) -> bool:
    return bool(_FILENAME_RE.search(norm))


def _queried_category(norm: str) -> str | None:
    for category in CATEGORY_ORDER:
        for term in _CATEGORY_QUERY_TERMS.get(category, ()):  # priority order
            if re.search(r"\b" + re.escape(term) + r"\b", norm):
                return category
    return None


# ---------------------------------------------------------------------------
# Evidence helpers
# ---------------------------------------------------------------------------
def _risk_score(item: Mapping[str, Any]) -> float:
    try:
        return float(item.get("risk_score") or 0)
    except (TypeError, ValueError):
        return 0.0


_SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "UNKNOWN": -1}
_FIX_NOW_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def _sort_key(item: Mapping[str, Any]) -> tuple[int, float, str]:
    severity = str(item.get("severity") or "").upper()
    return (_SEVERITY_RANK.get(severity, -1), _risk_score(item), str(item.get("name") or ""))


def rank_items_by_risk(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(items, key=_sort_key, reverse=True)


def _primary_category(item: Mapping[str, Any]) -> str:
    categories = categorize_risk_types(_item_types(item))
    return categories[0] if categories else "unknown"


def _credential_bucket(item: Mapping[str, Any]) -> int:
    return 0 if _primary_category(item) == "credential" else 1


def _fix_now_key(item: Mapping[str, Any]) -> tuple[int, float, int, str, str]:
    severity = str(item.get("severity") or "UNKNOWN").upper()
    name = str(item.get("name") or "")
    item_id = str(item.get("id") or item.get("safe_identifier") or name)
    return (
        _FIX_NOW_SEVERITY_RANK.get(severity, 4),
        -_risk_score(item),
        _credential_bucket(item),
        name.lower(),
        item_id.lower(),
    )


def rank_fix_now_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(items, key=_fix_now_key)


def _item_types(item: Mapping[str, Any]) -> list[str]:
    return [str(t) for t in (item.get("risk_types") or []) if str(t).strip()]


def _evidence_line(item: Mapping[str, Any], language: str) -> str:
    name = str(item.get("name") or "—")
    severity = str(item.get("severity") or "UNKNOWN").upper()
    score = _risk_score(item)
    score_text = f"{score:g}" if score else "n/a"
    types = ", ".join(_item_types(item)) or ("məlum deyil" if language == "az" else "unknown")
    if language == "en":
        return f"{name} — severity {severity}, risk score {score_text}, types: {types}"
    if language == "ru":
        return f"{name} — severity {severity}, risk score {score_text}, типы: {types}"
    return f"{name} — severity {severity}, risk score {score_text}, tiplər: {types}"


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------
def render_riskiest(items: list[dict[str, Any]], language: str) -> str:
    ranked = rank_items_by_risk(items)
    if not ranked:
        return _no_context(language)
    top = ranked[0]
    category = (categorize_risk_types(_item_types(top)) or ["unknown"])[0]
    action = _first_action(category, language)
    ev = _evidence_line(top, language)
    if language == "en":
        return (
            f"The riskiest of the shown findings is **{top.get('name')}**.\n"
            f"Why it is first: {ev}.\n"
            f"Next best action: {action}\n"
            "Ask me next: \"remediation for this\", \"another one\", or \"what should I fix first?\""
        )
    if language == "ru":
        return (
            f"Самая рискованная из показанных находок — **{top.get('name')}**.\n"
            f"Почему первая: {ev}.\n"
            f"Следующее действие: {action}\n"
            "Спросите далее: «remediation по этой», «другую», «что чинить первым?»"
        )
    return (
        f"Göstərilən tapıntılar arasında ən risklisi **{top.get('name')}**.\n"
        f"Niyə birincidir: {ev}.\n"
        f"Növbəti ən yaxşı addım: {action}\n"
        "Sonra soruşa bilərsiniz: «bunun üçün remediation», «başqa biri», «əvvəlcə nəyi düzəltməliyəm?»"
    )


def render_triage(items: list[dict[str, Any]], language: str, top_n: int = 3) -> str:
    ranked = rank_items_by_risk(items)
    if not ranked:
        return _no_context(language)
    ranked = ranked[:top_n]
    lines: list[str] = []
    for idx, item in enumerate(ranked, 1):
        category = (categorize_risk_types(_item_types(item)) or ["unknown"])[0]
        action = _first_action(category, language)
        name = item.get("name")
        severity = str(item.get("severity") or "UNKNOWN").upper()
        score = _risk_score(item)
        score_text = f"{score:g}" if score else "n/a"
        lines.append(f"{idx}. {name} ({severity}, risk {score_text}) — {action}")
    body = "\n".join(lines)
    if language == "en":
        header = "Fix these first, ordered by risk (highest first):"
        footer = "Ask me next: \"remediation for #1\", \"manager summary\", or \"technical remediation\"."
    elif language == "ru":
        header = "Чините в этом порядке, по убыванию риска:"
        footer = "Спросите далее: «remediation для #1», «manager summary» или «technical remediation»."
    else:
        header = "Riskə görə (ən yüksəkdən) əvvəlcə bunları düzəldin:"
        footer = "Sonra soruşun: «#1 üçün remediation», «manager summary» və ya «technical remediation»."
    return f"{header}\n{body}\n{footer}"


def render_fix_now_top_risks(
    items: list[dict[str, Any]],
    language: str,
    scan_id: str | None = None,
    top_n: int = 5,
) -> str:
    ranked = rank_fix_now_items(items)[:top_n]
    if not ranked:
        if language == "en":
            return "No findings were found in the latest scan.\nScan: latest\nMetric: file_level_finding_count"
        return "Son scan üzrə tapıntı tapılmadı.\nSkan: son scan\nMetrik: file_level_finding_count"
    if language == "en":
        lines = [f"Fix these {len(ranked)} risks first:"]
    else:
        lines = [f"İlk düzəltməli olduğunuz {len(ranked)} risk:"]
    for index, item in enumerate(ranked, 1):
        name = str(item.get("name") or "unknown")
        severity = str(item.get("severity") or "UNKNOWN").upper()
        score = _risk_score(item)
        score_text = f"{score:g}" if score else "n/a"
        types = ", ".join(_item_types(item)) or ("unknown" if language == "en" else "bilinmir")
        category = _primary_category(item)
        action = _first_action(category, language)
        if language == "en":
            reason = "credential/secret risk takes priority at the same severity and score." if category == "credential" else "ranked by severity, risk score, type, and stable name."
            lines.extend([
                f"{index}. {name} — {severity}, risk score {score_text}, type: {types}",
                f"   Why here: {reason}",
                f"   First action: {action}",
            ])
        else:
            reason = "eyni ciddilik və risk skorunda credential/secret tipi öndədir." if category == "credential" else "ciddilik, risk skoru, tip və sabit ada görə sıralanıb."
            lines.extend([
                f"{index}. {name} — {severity}, risk score {score_text}, tip: {types}",
                f"   Niyə prioritetdir: {reason}",
                f"   İlk addım: {action}",
            ])
    sid = scan_id or (ranked[0].get("scan_id") if ranked else None) or "latest"
    if language == "en":
        lines.append(f"Scan: {sid}  Metric: file_level_finding_count")
    else:
        lines.append(f"Skan: {sid}  Metrik: file_level_finding_count")
    return "\n".join(lines)


def render_scan_delta(payload: dict[str, Any], language: str) -> str:
    latest = payload.get("latest_scan_id") or "latest"
    previous = payload.get("previous_scan_id")
    metric = payload.get("metric") or "file_level_finding_count"
    if not payload.get("has_latest_scan"):
        if language == "en":
            return "No scan data was found. I need at least one scan before I can compare scan changes.\nMetric: file_level_finding_count"
        return "Scan məlumatı tapılmadı. Müqayisə üçün ən azı bir scan lazımdır.\nMetrik: file_level_finding_count"
    if not payload.get("has_previous_scan"):
        if language == "en":
            return (
                "No previous scan was found for comparison. I can only summarize the latest scan right now.\n"
                f"Scan: {latest}\nMetric: {metric}"
            )
        return (
            "Müqayisə üçün əvvəlki scan tapılmadı. Hazırda yalnız son scan üzrə xülasə verə bilərəm.\n"
            f"Skan: {latest}\nMetrik: {metric}"
        )

    severity_delta = payload.get("severity_delta") or {}
    verdict = str(payload.get("verdict") or "unchanged")
    if language == "en":
        lines = [
            f"Latest scan compared with previous scan looks {verdict}.",
            "",
            f"- CRITICAL: {_delta_text(severity_delta.get('CRITICAL', 0))}",
            f"- HIGH: {_delta_text(severity_delta.get('HIGH', 0))}",
            f"- MEDIUM: {_delta_text(severity_delta.get('MEDIUM', 0))}",
            f"- LOW: {_delta_text(severity_delta.get('LOW', 0))}",
            f"- Total finding count delta: {int(payload.get('total_finding_count_delta') or 0):+d}",
            f"- New findings: {int(payload.get('new_findings_count') or 0)}",
            f"- Resolved findings: {int(payload.get('resolved_findings_count') or 0)}",
            f"- Still open/common findings: {int(payload.get('common_findings_count') or 0)}",
        ]
        if payload.get("risk_score_delta") is not None:
            lines.append(f"- Average risk score delta: {payload.get('risk_score_delta'):+g}")
        if payload.get("posture_delta") is not None:
            lines.append(f"- Posture score delta: {payload.get('posture_delta'):+g}")
        lines.extend(["", "Top changes:"])
        lines.extend(_top_change_lines(payload, "en"))
        lines.extend([
            "",
            f"Verdict: {verdict}.",
            f"Next best action: {_delta_next_action(payload, 'en')}",
            f"Scans: previous={previous}, latest={latest}  Metric: {metric}",
        ])
        return "\n".join(lines)

    az_verdict = {
        "improved": "yaxşılaşıb",
        "worsened": "pisləşib",
        "mixed": "qarışıqdır",
        "unchanged": "dəyişməyib",
    }.get(verdict, "qarışıqdır")
    lines = [
        f"Son scan əvvəlki scan ilə müqayisədə {az_verdict}.",
        "",
        f"- CRITICAL: {_delta_text(severity_delta.get('CRITICAL', 0))}",
        f"- HIGH: {_delta_text(severity_delta.get('HIGH', 0))}",
        f"- MEDIUM: {_delta_text(severity_delta.get('MEDIUM', 0))}",
        f"- LOW: {_delta_text(severity_delta.get('LOW', 0))}",
        f"- Ümumi tapıntı sayı fərqi: {int(payload.get('total_finding_count_delta') or 0):+d}",
        f"- Yeni tapıntılar: {int(payload.get('new_findings_count') or 0)}",
        f"- Bağlanmış tapıntılar: {int(payload.get('resolved_findings_count') or 0)}",
        f"- Açıq qalan tapıntılar: {int(payload.get('common_findings_count') or 0)}",
    ]
    if payload.get("risk_score_delta") is not None:
        lines.append(f"- Orta risk score fərqi: {payload.get('risk_score_delta'):+g}")
    if payload.get("posture_delta") is not None:
        lines.append(f"- Posture score fərqi: {payload.get('posture_delta'):+g}")
    lines.extend(["", "Əsas dəyişikliklər:"])
    lines.extend(_top_change_lines(payload, "az"))
    lines.extend([
        "",
        f"Nəticə: {az_verdict}.",
        f"Növbəti ən yaxşı addım: {_delta_next_action(payload, 'az')}",
        f"Skanlar: previous={previous}, latest={latest}  Metrik: {metric}",
    ])
    return "\n".join(lines)


def _delta_text(value: Any) -> str:
    try:
        number = int(value or 0)
    except (TypeError, ValueError):
        number = 0
    return "0" if number == 0 else f"{number:+d}"


def _top_change_lines(payload: dict[str, Any], language: str) -> list[str]:
    lines: list[str] = []
    for item in (payload.get("new_findings") or [])[:3]:
        label = "New" if language == "en" else "Yeni"
        lines.append(f"- {label}: {item.get('name')} ({item.get('severity')}, risk score {item.get('risk_score')})")
    for item in (payload.get("resolved_findings") or [])[:2]:
        label = "Resolved" if language == "en" else "Bağlanıb"
        lines.append(f"- {label}: {item.get('name')} ({item.get('severity')})")
    for item in (payload.get("severity_changes") or [])[:2]:
        if language == "en":
            lines.append(f"- Severity changed: {item.get('name')} {item.get('previous_severity')} -> {item.get('latest_severity')}")
        else:
            lines.append(f"- Ciddilik dəyişib: {item.get('name')} {item.get('previous_severity')} -> {item.get('latest_severity')}")
    if not lines:
        return ["- No material file-level finding changes." if language == "en" else "- Fayl səviyyəsində ciddi dəyişiklik görünmür."]
    return lines


def _delta_next_action(payload: dict[str, Any], language: str) -> str:
    severity_delta = payload.get("severity_delta") or {}
    if int(severity_delta.get("CRITICAL", 0) or 0) > 0:
        return "review the new CRITICAL findings first." if language == "en" else "əvvəlcə yeni CRITICAL tapıntılara baxın."
    if int(severity_delta.get("HIGH", 0) or 0) > 0:
        return "review the new HIGH findings next." if language == "en" else "növbəti olaraq yeni HIGH tapıntılara baxın."
    if int(payload.get("resolved_findings_count") or 0) > int(payload.get("new_findings_count") or 0):
        return "validate the resolved findings and re-scan after remediation." if language == "en" else "bağlanmış tapıntıları təsdiqləyin və remediation-dan sonra yenidən scan edin."
    return "start with the highest-severity new findings." if language == "en" else "ən yüksək ciddilikli yeni tapıntılardan başlayın."


def render_risk_type_breakdown(
    findings: list[dict[str, Any]],
    language: str,
    severity: str | None = None,
    queried_category: str | None = None,
    scan_id: str | None = None,
) -> str:
    scoped = findings
    if severity:
        scoped = [f for f in findings if str(f.get("severity") or "").upper() == severity.upper()]
    counts: dict[str, int] = {c: 0 for c in CATEGORY_ORDER + ["unknown"]}
    for finding in scoped:
        types = [str(t) for t in (finding.get("risk_types") or []) if str(t).strip()]
        cats = categorize_risk_types(types)
        for cat in cats:
            counts[cat] = counts.get(cat, 0) + 1
    total = len(scoped)
    scope_label = _severity_label(severity, language) if severity else _all_label(language)
    evidence = _breakdown_evidence(scan_id, language)

    if queried_category:
        matched = counts.get(queried_category, 0)
        cat_label = _CATEGORY_LABELS.get(queried_category, {}).get(language, queried_category)
        if language == "en":
            return f"Of {total} {scope_label} finding(s), {matched} are {cat_label}.\n{evidence}"
        if language == "ru":
            return f"Из {total} находок ({scope_label}) {matched} — {cat_label}.\n{evidence}"
        return f"{total} {scope_label} tapıntıdan {matched} ədədi {cat_label} tipindədir.\n{evidence}"

    # Full breakdown across categories present.
    present = [(c, counts[c]) for c in CATEGORY_ORDER + ["unknown"] if counts.get(c)]
    lines = [
        f"- {_CATEGORY_LABELS.get(c, {}).get(language, c)}: {n}"
        for c, n in present
    ]
    body = "\n".join(lines) if lines else ("—")
    # A finding may carry more than one risk type, so category counts can overlap.
    overlap = sum(n for _c, n in present) > total
    if language == "en":
        note = " A finding can match more than one type." if overlap else ""
        return f"Risk-type breakdown for {total} {scope_label} finding(s):\n{body}\n{evidence}{note}"
    if language == "ru":
        note = " Находка может относиться к нескольким типам." if overlap else ""
        return f"Разбивка по типам риска для {total} находок ({scope_label}):\n{body}\n{evidence}{note}"
    note = " Bir tapıntı birdən çox tipə aid ola bilər." if overlap else ""
    return f"{total} {scope_label} tapıntı üçün risk tipi bölgüsü:\n{body}\n{evidence}{note}"


def _breakdown_evidence(scan_id: str | None, language: str) -> str:
    sid = str(scan_id).strip() if scan_id else ""
    if language == "en":
        where = f"scan {sid}" if sid else "the latest scan"
        return f"Evidence: counted at file level from {where}."
    if language == "ru":
        where = f"scan {sid}" if sid else "последнего scan"
        return f"Основание: подсчёт на уровне файлов из {where}."
    where = f"{sid} skanı" if sid else "son scan"
    return f"Sübut: {where} üzrə fayl səviyyəsində sayılıb."


def render_manager_summary(item: dict[str, Any], language: str) -> str:
    category = (categorize_risk_types(_item_types(item)) or ["unknown"])[0]
    cat_label = _CATEGORY_LABELS.get(category, {}).get(language, category)
    name = item.get("name")
    severity = str(item.get("severity") or "UNKNOWN").upper()
    score = _risk_score(item)
    score_text = f"{score:g}" if score else "n/a"
    impact = _business_impact(category, language)
    if language == "en":
        return (
            f"Manager summary — {name}\n"
            f"- Severity: {severity} (risk score {score_text})\n"
            f"- Data type: {cat_label}\n"
            f"- Business impact: {impact}\n"
            f"- Recommended: prioritize this finding for remediation and confirm the owner."
        )
    if language == "ru":
        return (
            f"Manager summary — {name}\n"
            f"- Severity: {severity} (risk score {score_text})\n"
            f"- Тип данных: {cat_label}\n"
            f"- Влияние на бизнес: {impact}\n"
            f"- Рекомендация: приоритизировать устранение и подтвердить владельца."
        )
    return (
        f"Manager üçün icmal — {name}\n"
        f"- Ciddilik: {severity} (risk score {score_text})\n"
        f"- Məlumat tipi: {cat_label}\n"
        f"- Biznes təsiri: {impact}\n"
        f"- Tövsiyə: bu tapıntını remediation üçün prioritetləşdirin və sahibini təsdiqləyin."
    )


def render_technical_remediation(item: dict[str, Any], language: str, scan_id: str | None = None) -> str:
    # Reuse the type-aware step-by-step remediation renderer for evidence-based steps.
    answer = render_step_by_step_remediation(item, language=language, scan_id=scan_id)
    resolved_scan_id = scan_id or item.get("scan_id") or "latest"
    if language == "en":
        footer = f"Scan: {resolved_scan_id}  Metric: file_level_finding_count"
    elif language == "ru":
        footer = f"Scan: {resolved_scan_id}  Metric: file_level_finding_count"
    else:
        footer = f"Skan: {resolved_scan_id}  Metrik: file_level_finding_count"
    return answer if footer in answer else f"{answer}\n\n{footer}"


def condense_answer(previous_text: str, language: str) -> str:
    text = " ".join(str(previous_text or "").split())
    if not text:
        return _no_context(language)
    # Keep the first informative sentence / clause, capped.
    for sep in (". ", "\n", "; "):
        if sep in text:
            text = text.split(sep, 1)[0].strip()
            break
    short = text[:200].rstrip()
    if language == "en":
        return f"In short: {short}"
    if language == "ru":
        return f"Коротко: {short}"
    return f"Qısaca: {short}"


# ---------------------------------------------------------------------------
# Small localized helpers
# ---------------------------------------------------------------------------
def _first_action(category: str, language: str) -> str:
    actions = {
        "credential": {
            "az": "credential/secret-i dərhal ləğv edin və ya rotasiya edin, sonra yenidən skan edin.",
            "en": "immediately revoke or rotate the credential/secret, then re-scan.",
            "ru": "немедленно отзовите или ротируйте credential/secret, затем повторите scan.",
        },
        "financial": {
            "az": "kart/hesab məlumatını maskalayın və ya tokenize edin, PCI təsirini yoxlayın.",
            "en": "mask or tokenize the card/account data and review PCI impact.",
            "ru": "замаскируйте или токенизируйте данные карты/счёта, оцените влияние PCI.",
        },
        "personal": {
            "az": "şəxsi məlumatı maskalayın, girişi yoxlayın və saxlanma müddətini nəzərdən keçirin.",
            "en": "mask the personal data, review access, and check retention.",
            "ru": "замаскируйте персональные данные, проверьте доступ и срок хранения.",
        },
        "confidential": {
            "az": "təsnifatı təsdiqləyin, label/DLP tətbiq edin və girişi məhdudlaşdırın.",
            "en": "confirm classification, apply labels/DLP, and restrict access.",
            "ru": "подтвердите классификацию, примените метки/DLP, ограничьте доступ.",
        },
        "context": {
            "az": "biznes sahibi ilə giriş nəzərdən keçirin və least-privilege tətbiq edin.",
            "en": "review access with the business owner and apply least privilege.",
            "ru": "пересмотрите доступ с владельцем и примените least privilege.",
        },
        "unknown": {
            "az": "əvvəlcə məlumat tipini dəqiqləşdirin, sonra girişi məhdudlaşdırın.",
            "en": "first verify the data type, then restrict access.",
            "ru": "сначала уточните тип данных, затем ограничьте доступ.",
        },
    }
    return actions.get(category, actions["unknown"]).get(language, actions.get(category, actions["unknown"])["az"])


def _business_impact(category: str, language: str) -> str:
    impacts = {
        "credential": {
            "az": "ifşa olunmuş credential hesab ələ keçirilməsi və sistemə icazəsiz girişə səbəb ola bilər.",
            "en": "an exposed credential can lead to account takeover and unauthorized system access.",
            "ru": "раскрытый credential может привести к захвату аккаунта и несанкционированному доступу.",
        },
        "financial": {
            "az": "ödəniş məlumatının ifşası PCI/bank uyğunluğu və maliyyə itkisi riski yaradır.",
            "en": "exposed payment data creates PCI/banking-compliance and financial-loss risk.",
            "ru": "раскрытие платёжных данных создаёт риск PCI/банковского соответствия и убытков.",
        },
        "personal": {
            "az": "şəxsi məlumatın ifşası məxfilik və tənzimləyici uyğunluq riski yaradır.",
            "en": "exposed personal data creates privacy and regulatory-compliance risk.",
            "ru": "раскрытие персональных данных создаёт риск приватности и соответствия.",
        },
        "confidential": {
            "az": "məxfi sənədin ifşası biznes və reputasiya riski yaradır.",
            "en": "exposed confidential documents create business and reputational risk.",
            "ru": "раскрытие конфиденциальных документов создаёт бизнес- и репутационный риск.",
        },
        "context": {
            "az": "həssas biznes kontekstinin geniş girişi məlumatın sui-istifadə riskini artırır.",
            "en": "broad access to sensitive business context increases misuse risk.",
            "ru": "широкий доступ к чувствительному контексту повышает риск злоупотреблений.",
        },
        "unknown": {
            "az": "təsnif olunmamış həssas məlumat qiymətləndirilməmiş risk daşıyır.",
            "en": "unclassified sensitive data carries unassessed risk.",
            "ru": "неклассифицированные данные несут неоценённый риск.",
        },
    }
    return impacts.get(category, impacts["unknown"]).get(language, impacts.get(category, impacts["unknown"])["az"])


def _severity_label(severity: str | None, language: str) -> str:
    sev = str(severity or "").upper()
    labels = {
        "CRITICAL": {"az": "kritik", "en": "critical", "ru": "критических"},
        "HIGH": {"az": "yüksək", "en": "high", "ru": "высоких"},
        "MEDIUM": {"az": "orta", "en": "medium", "ru": "средних"},
        "LOW": {"az": "aşağı", "en": "low", "ru": "низких"},
    }
    return labels.get(sev, {}).get(language, sev.lower())


def _all_label(language: str) -> str:
    return {"az": "bütün", "en": "total", "ru": "всех"}.get(language, "total")


def _no_context(language: str) -> str:
    if language == "en":
        return "I don't have a previous finding list in this conversation yet. Ask me to show findings first (e.g. \"show critical findings\")."
    if language == "ru":
        return "В этом разговоре ещё нет списка находок. Сначала попросите показать находки (например, «show critical findings»)."
    return "Bu söhbətdə hələ tapıntı siyahısı yoxdur. Əvvəlcə tapıntıları göstərməyimi istəyin (məsələn «kritik tapıntıları göstər»)."
