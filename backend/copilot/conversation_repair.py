"""Deterministic conversation-repair routes for the DSPM Copilot.

These handlers fix the real broken-conversation failures observed in production
transcripts: artifact/PDF download UX, "cancel this topic", partial severity
counts, aggregate (category/severity-scope) remediation instead of selected-finding
hijack, "why didn't you understand me", and malformed-output complaints.

Everything here is deterministic and zero-provider: answers are built from
sanitized session memory and the latest scan report only. Native Azerbaijani is
primary (EN/RU also); no LLM translation is used, so no mixed-language or
fabricated-word output can leak from this layer.
"""
from __future__ import annotations

import os
import re
from typing import Any, Mapping

from backend.copilot import language_service
from backend.copilot.remediation_policy import categorize_risk_types
from backend.copilot.severity import normalize_for_severity

# Intent identifiers emitted by the detectors below.
ARTIFACT_CREATE = "artifact_create"
ARTIFACT_LINK = "artifact_link"
CANCEL_TOPIC = "cancel_current_topic"
SEVERITY_SUBSET_COUNT = "severity_subset_count"
AGGREGATE_REMEDIATION = "aggregate_scope_remediation"
WHY_MISUNDERSTOOD = "why_misunderstood_previous_request"
MALFORMED_OUTPUT = "malformed_output_complaint"


def _norm(message: str) -> str:
    return language_service.normalize_for_intent(message)


# ---------------------------------------------------------------------------
# Artifact / PDF download UX
# ---------------------------------------------------------------------------
def artifact_base_url() -> str:
    """Base URL prefix for artifact links.

    Default is empty: artifact links are emitted as same-origin **relative**
    URLs (``/api/v1/copilot/artifacts/<id>``), which the authenticated
    frontend downloads with its auth headers. A raw absolute
    ``http://127.0.0.1:8000/...`` link opened in a new tab has no
    Authorization header and returns ``{"detail":"Authentication required"}``
    — that broken UX is exactly what the relative default avoids. Set
    ``COPILOT_ARTIFACT_BASE_URL`` only for non-UI clients that need an
    absolute prefix.
    """
    return os.getenv("COPILOT_ARTIFACT_BASE_URL", "").rstrip("/")


def absolute_artifact_url(download_url: str | None) -> str:
    url = str(download_url or "")
    if url.startswith("http://") or url.startswith("https://"):
        return url
    if not url.startswith("/"):
        url = "/" + url
    return f"{artifact_base_url()}{url}"


_CREATE_TERMS = ("pdf", "report", "hesabat", "export", "eksport")
_LINK_TERMS = (
    "link", "linki", "linkini", "full link", "tam link", "url",
    "yukle", "yukleyim", "yuklu", "yuklem", "yuklen", "download",
    "klik", "kliklen", "ust", "bas", "basanda", "acilsin", "aciland",
    # Location / lookup queries about an already-created artifact.
    "where", "harada", "hara", "hardadir", "haradadir", "hardadi",
)
_NEW_ARTIFACT_TERMS = ("yeni", "teze", "yenilen", "yeniden yarat", "new", "regenerate", "yenisini")


_SEVERITY_ALIASES = {
    "CRITICAL": ("critical", "kritik"),
    "HIGH": ("high", "yuksek"),
    "MEDIUM": ("medium", "orta"),
    "LOW": ("low", "asagi"),
}
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _requested_filter_severity(norm: str) -> str | None:
    for severity, terms in _SEVERITY_ALIASES.items():
        if any(re.search(rf"\b{t}\w*\b", norm) for t in terms):
            return severity
    return None


def _requested_severities(norm: str) -> list[str]:
    """All severity levels named in the message, in canonical order."""
    found = []
    for severity in _SEVERITY_ORDER:
        terms = _SEVERITY_ALIASES[severity]
        if any(re.search(rf"\b{t}\w*\b", norm) for t in terms):
            found.append(severity)
    return found


# Single-finding scope: "this finding / this alert / one alert / for this
# finding / bu tapıntı / bu alert" — a report about the currently selected item.
_SINGLE_FINDING_TERMS = (
    "this finding", "this alert", "that finding", "that alert", "one alert",
    "one finding", "single finding", "single alert", "for this finding",
    "for this alert", "this file", "selected finding", "selected alert",
    "bu tapinti", "bu alert", "bu finding", "bu fayl", "secilmis tapinti",
    "secilmis finding", "bir alert", "bir tapinti",
)

# Correction turns that mean "you sent me the same PDF" — treat as a report
# regeneration request that keeps the previously requested scope.
_SAME_PDF_TERMS = (
    "same pdf", "same link", "same file", "same report", "same one",
    "eyni pdf", "eyni link", "eyni fayl", "eyni hesabat", "eyni report",
    "eyni seyi", "yene eyni", "yene o", "again same", "same as",
)

# Bare report-scope corrections ("i need only medium alerts pdf", "its about
# scan summary") that clarify scope without re-stating it fully.
_REPORT_CORRECTION_TERMS = (
    "i need only", "only", "just", "sadece", "yalniz", "its about", "it is about",
    "not this", "wrong", "yanlis", "duz deyil", "different", "ferqli",
)


def detect_same_pdf_complaint(message: str) -> bool:
    norm = _norm(message)
    return any(t in norm for t in _SAME_PDF_TERMS)


def _has_selected_finding(session_state: Mapping[str, Any] | None) -> dict | None:
    context = session_state or {}
    item = context.get("current_item") or context.get("last_item")
    if isinstance(item, dict) and (item.get("name") or item.get("path")):
        return item
    return None


_TOP_N_RE = re.compile(r"\btop\s+(\d{1,3})\b")
_SCOPE_EXTENSION_RE = re.compile(r"(?<![\w.])\.([a-z0-9][a-z0-9_+-]{0,15})\b", re.IGNORECASE)
_BARE_EXTENSION_FILE_RE = re.compile(r"\b([a-z0-9]{1,15})\s+(?:files?|extension\s+files?)\b", re.IGNORECASE)


def _requested_limit(norm: str) -> int | None:
    """Explicit top-N request in the message ("top 5 ..."), or None."""
    match = _TOP_N_RE.search(norm)
    if not match:
        return None
    value = int(match.group(1))
    return max(1, min(value, 100)) if value > 0 else None


def _requested_extension(message: str) -> str | None:
    """Explicit extension named in the message, normalized, or None.

    A dotted extension (".pdf") always counts. A bare token counts only when it
    is a known extension immediately followed by a file noun ("csv files"), so
    severity words and ordinary nouns never become extension filters.
    """
    raw = str(message or "")
    match = _SCOPE_EXTENSION_RE.search(raw)
    if match:
        return f".{match.group(1).lower()}"
    from backend.copilot.file_queries import _KNOWN_EXTENSIONS

    for bare in _BARE_EXTENSION_FILE_RE.finditer(raw):
        token = bare.group(1).lower()
        if token in _KNOWN_EXTENSIONS:
            return f".{token}"
    return None


def requested_report_scope(message: str, session_state: Mapping[str, Any] | None) -> dict:
    """Parse the report scope explicitly named in the message.

    Returns a normalized scope dict:
    ``{"kind": "full"|"severity"|"extension"|"finding", ...}`` optionally
    carrying an explicit top-N ``limit``. A single-finding scope requires both
    single-finding wording *and* a currently selected finding in session, so we
    never invent a target.
    """
    norm = _norm(message)
    limit = _requested_limit(norm)
    if any(t in norm for t in _SINGLE_FINDING_TERMS):
        item = _has_selected_finding(session_state)
        if item is not None:
            ref = str(item.get("name") or item.get("path"))
            return {"kind": "finding", "finding_ref": ref, "label": f"finding: {ref}"}
    severities = _requested_severities(norm)
    severities = severities if len(severities) < 4 else []
    extension = _requested_extension(message)
    if extension:
        base = f"{' + '.join(severities)} {extension} files" if severities else f"{extension} files"
        scope: dict[str, Any] = {"kind": "extension", "extension": extension, "label": base}
        if severities:
            scope["severities"] = severities
        if limit:
            scope["limit"] = limit
            scope["label"] = f"Top {limit} {base}"
        return scope
    if severities:
        base = severities[0] if len(severities) == 1 else " + ".join(severities)
        scope = {"kind": "severity", "severities": severities, "label": base}
        if limit:
            scope["limit"] = limit
            scope["label"] = f"Top {limit} {base}"
        return scope
    if limit:
        return {"kind": "full", "limit": limit, "label": f"Top {limit} files"}
    return {"kind": "full", "label": "Full scan"}


def _cached_report_scope(session_state: Mapping[str, Any] | None) -> dict | None:
    context = session_state or {}
    scope = context.get("last_artifact_scope")
    if isinstance(scope, dict) and scope.get("kind"):
        return scope
    # Backward compatibility with the older single-severity field.
    legacy = context.get("last_artifact_filter")
    if legacy:
        legacy_up = str(legacy).upper()
        first = legacy_up.split()[0] if legacy_up else ""
        if first in _SEVERITY_ORDER:
            return {"kind": "severity", "severities": [first], "label": first}
    return None


# Anaphoric / bare report requests ("give me that as a pdf report", "give as a
# pdf", "pdf", "make it a report", "export this") name no fresh scope; they mean
# "turn the result I just showed you into a report". These inherit the scope of
# the previous reportable evidence result instead of silently falling back to a
# full unscoped scan.
_ANAPHORIC_REPORT_TERMS = (
    " that ", " this ", " it ", " those ", " these ", " o ", " onu ", " bunu ", " same ",
)


def _inherited_reportable_scope(session_state: Mapping[str, Any] | None) -> dict | None:
    """Rebuild the previous reportable scope from prior evidence state.

    Consulted only for bare/anaphoric report requests. Reads, in order:
    an explicit ``last_reportable_scope`` frame, the severity carried by the
    last file query, and any stored last count-scope severities.
    """
    context = session_state or {}
    explicit = context.get("last_reportable_scope")
    if isinstance(explicit, dict) and explicit.get("kind"):
        return dict(explicit)

    lfq = context.get("last_file_query")
    if isinstance(lfq, Mapping):
        severity = str(lfq.get("severity") or "").upper()
        severity = severity if severity in _SEVERITY_ORDER else ""
        extension = str(lfq.get("extension") or "").strip().lower()
        try:
            limit = int(lfq.get("limit") or 0)
        except (TypeError, ValueError):
            limit = 0
        if extension:
            base = f"{severity} {extension} files".strip() if severity else f"{extension} files"
            scope: dict[str, Any] = {"kind": "extension", "extension": extension, "label": base}
            if severity:
                scope["severities"] = [severity]
            if limit > 0:
                scope["limit"] = limit
                scope["label"] = f"Top {limit} {base}"
            return scope
        if severity:
            scope = {"kind": "severity", "severities": [severity], "label": severity}
            if limit > 0:
                scope["limit"] = limit
                scope["label"] = f"Top {limit} {severity}"
            return scope

    stored = context.get("last_count_scope_severities")
    if isinstance(stored, (list, tuple)):
        severities = [str(s).upper() for s in stored if str(s).upper() in _SEVERITY_ORDER]
        severities = [s for s in _SEVERITY_ORDER if s in set(severities)]
        if severities:
            label = severities[0] if len(severities) == 1 else " + ".join(severities)
            return {"kind": "severity", "severities": severities, "label": label}
    return None


def _is_bare_or_anaphoric_report(norm: str) -> bool:
    padded = f" {norm} "
    if any(term in padded for term in _ANAPHORIC_REPORT_TERMS):
        return True
    # A short request that only names an output format ("pdf", "give as a pdf",
    # "make it a report") with no explicit new scope inherits the last scope.
    if len(norm.split()) <= 6 and re.search(r"\b(?:pdf|report|export|hesabat)\b", norm):
        return True
    return False


def scopes_equal(a: Mapping[str, Any] | None, b: Mapping[str, Any] | None) -> bool:
    a = a or {"kind": "full"}
    b = b or {"kind": "full"}
    if a.get("kind") != b.get("kind"):
        return False

    def _limit(scope: Mapping[str, Any]) -> int:
        try:
            return max(0, int(scope.get("limit") or 0))
        except (TypeError, ValueError):
            return 0

    if _limit(a) != _limit(b):
        return False
    kind = a.get("kind")
    if kind == "severity":
        return set(a.get("severities") or []) == set(b.get("severities") or [])
    if kind == "extension":
        return (
            str(a.get("extension") or "").lower() == str(b.get("extension") or "").lower()
            and set(a.get("severities") or []) == set(b.get("severities") or [])
        )
    if kind == "finding":
        return str(a.get("finding_ref") or "").lower() == str(b.get("finding_ref") or "").lower()
    return True


def resolve_report_scope(message: str, session_state: Mapping[str, Any] | None) -> dict:
    """Final scope for a report request, applying correction memory.

    An explicit scope in the message always wins. A bare correction
    ("its same pdf", "i need only ... pdf") with no fresh scope keeps the
    previously requested scope so we regenerate the *right* report instead of
    silently falling back to a full unfiltered summary.
    """
    requested = requested_report_scope(message, session_state)
    if requested.get("kind") != "full" or requested.get("limit"):
        return requested
    norm = _norm(message)
    is_correction = detect_same_pdf_complaint(message) or any(t in norm for t in _REPORT_CORRECTION_TERMS)
    if is_correction or _is_bare_or_anaphoric_report(norm):
        inherited = _inherited_reportable_scope(session_state)
        if inherited:
            return inherited
        cached = _cached_report_scope(session_state)
        if cached:
            return cached
    return requested


def detect_artifact_intent(message: str, session_state: Mapping[str, Any] | None) -> str | None:
    """Return artifact create/link intent, or None.

    Reuse (link) wins whenever an artifact already exists and the user is asking
    about the link/download, so we never regenerate a PDF for "full link ver" —
    *unless* the user is asking for a different scope (severity/finding) or is
    complaining that we sent the same PDF, both of which force a fresh,
    correctly-scoped report.
    """
    norm = _norm(message)
    has_artifact = bool((session_state or {}).get("latest_artifact"))
    wants_link = any(t in norm for t in _LINK_TERMS)
    wants_strong_link = bool(re.search(
        r"\b(?:full link|tam link|link|url|download|yukle\w*|yuklu\w*|yuklem\w*|yuklen\w*)\b",
        norm,
    ))
    wants_create = any(t in norm for t in _CREATE_TERMS)
    wants_new = any(t in norm for t in _NEW_ARTIFACT_TERMS)
    same_pdf_complaint = detect_same_pdf_complaint(message)

    # A newly requested scope that differs from the cached artifact's scope must
    # never be silently served the stale (differently-scoped) artifact — that is
    # what produced "same PDF for a different severity/finding ask".
    requested_scope = requested_report_scope(message, session_state)
    cached_scope = _cached_report_scope(session_state)
    scope_changed = (
        has_artifact
        and requested_scope.get("kind") != "full"
        and not scopes_equal(requested_scope, cached_scope)
    )

    # "You sent me the same PDF" on an existing artifact is a regeneration
    # request (keeps the last scope, mints a new artifact).
    if has_artifact and same_pdf_complaint:
        return ARTIFACT_CREATE
    # Explicit "new/regenerate" always creates.
    if wants_new and wants_create:
        return ARTIFACT_CREATE
    # A newly requested scope with create/link wording creates a fresh artifact.
    if scope_changed and (wants_create or wants_link):
        return ARTIFACT_CREATE
    # A pure link/download follow-up on an existing artifact reuses it (no dup),
    # as long as the request isn't actually asking for a different scope.
    if has_artifact and wants_link and not wants_new and not scope_changed:
        return ARTIFACT_LINK
    # An explicit create request (pdf/report/export) creates.
    if wants_create:
        return ARTIFACT_CREATE
    # A pure link/download lookup is still deterministic even if no artifact is active.
    if wants_strong_link and not wants_new and not scope_changed:
        return ARTIFACT_LINK
    # Link/download question with an existing artifact.
    if has_artifact and wants_link and not scope_changed:
        return ARTIFACT_LINK
    return None


def _artifact_scope(artifact: Mapping[str, Any], scope: Mapping[str, Any] | None) -> dict:
    if scope and scope.get("kind"):
        return dict(scope)
    art_scope = artifact.get("scope")
    if isinstance(art_scope, dict) and art_scope.get("kind"):
        return dict(art_scope)
    return {"kind": "full", "label": "Full scan"}


def _scope_display_label(scope: Mapping[str, Any]) -> str | None:
    kind = scope.get("kind")
    if kind in {"severity", "extension"}:
        return str(scope.get("label") or "")
    if kind == "finding":
        ref = str(scope.get("finding_ref") or scope.get("label") or "")
        ref = ref.split(":", 1)[-1].strip() if ref.startswith("finding:") else ref
        return f"finding {ref}" if ref else "single finding"
    if kind == "full" and scope.get("limit"):
        return str(scope.get("label") or "")
    return None


def artifact_session_fields(artifact: Mapping[str, Any], scope: Mapping[str, Any] | None = None) -> dict[str, Any]:
    url = absolute_artifact_url(artifact.get("download_url"))
    art_scope = _artifact_scope(artifact, scope)
    severity_label = art_scope.get("label") if art_scope.get("kind") == "severity" else None
    return {
        "last_artifact_id": artifact.get("artifact_id"),
        "last_artifact_name": artifact.get("filename"),
        "last_artifact_url": url,
        "last_artifact_type": artifact.get("type") or "pdf",
        "last_artifact_scan_id": artifact.get("source_scan_id"),
        "last_artifact_filter": severity_label,
        "last_artifact_scope": art_scope,
    }


def render_artifact_answer(
    artifact: Mapping[str, Any], language: str, scope: Mapping[str, Any] | None = None
) -> str:
    name = str(artifact.get("filename") or "report.pdf")
    url = absolute_artifact_url(artifact.get("download_url"))
    scan_id = str(artifact.get("source_scan_id") or "latest")
    label = _scope_display_label(_artifact_scope(artifact, scope))
    link = f"[{name}]({url})"
    if language == "az":
        lines = [
            f"PDF hazırdır: {link}", "",
            f"Skan: {scan_id}",
        ]
        if label:
            lines.append(f"Filtr: {label}")
    elif language == "ru":
        lines = [
            f"PDF готов: {link}", "",
            f"Scan: {scan_id}",
        ]
        if label:
            lines.append(f"Фильтр: {label}")
    else:
        # English is the default for any non-AZ/RU (or unknown) language so an
        # English conversation can never leak Azerbaijani report labels.
        lines = [
            f"Your PDF is ready: {link}", "",
            f"Scan: {scan_id}",
        ]
        if label:
            lines.append(f"Filter: {label}")
    return "\n".join(lines)


# The dashboard's Reports tab already offers these export features (see
# frontend/index.html): Export Excel Workbook, Export Word Pack, Open PDF
# Composer. When the user asks for one of them, route to the real feature
# instead of generating the Copilot's simple PDF.
_REPORTS_FEATURES = {
    "excel": ("excel", "xlsx", "workbook", "spreadsheet"),
    "word": ("word pack", "word document", "docx", " word "),
    "pdf_composer": ("composer", "pdf composer"),
}


def detect_reports_feature_request(message: str) -> str | None:
    norm = f" {_norm(message)} "
    for kind, terms in _REPORTS_FEATURES.items():
        if any(term in norm for term in terms):
            return kind
    return None


_REPORTS_FEATURE_LABELS = {
    "excel": "Export Excel Workbook",
    "word": "Export Word Pack",
    "pdf_composer": "Open PDF Composer",
}


def render_reports_feature_answer(kind: str, language: str) -> str:
    label = _REPORTS_FEATURE_LABELS.get(kind, "Export")
    if language == "az":
        return (
            f"Bunun üçün Reports səhifəsindəki hazır funksiyadan istifadə edin: sol paneldə Reports bölməsini açın "
            f"və “{label}” düyməsinə klikləyin. İstəsəniz, mən burada sadə PDF hesabat da yarada bilərəm — sadəcə “pdf report” yazın."
        )
    if language == "ru":
        return (
            f"Для этого используйте готовую функцию на странице Reports: откройте раздел Reports в левой панели "
            f"и нажмите «{label}». Если нужно, я могу создать здесь простой PDF-отчёт — просто напишите “pdf report”."
        )
    return (
        f"Use the built-in Reports feature for that: open the Reports section in the left sidebar and click "
        f"\"{label}\". If you prefer, I can also generate a simple PDF report right here — just ask for a \"pdf report\"."
    )


def render_artifact_error(language: str) -> str:
    """Honest message when a PDF cannot be created (e.g. no scan report)."""
    if language == "az":
        return "PDF yarada bilmədim: hələ heç bir DSPM skan hesabatı yoxdur."
    if language == "ru":
        return "Не удалось создать PDF: пока нет доступного DSPM scan отчёта."
    return "I could not create a PDF: no DSPM scan report is available yet."


def render_missing_artifact_link(language: str) -> str:
    """Honest answer for link/download requests with no active artifact."""
    if language == "az":
        return "Hazırda link veriləcək aktiv hesabat faylı yoxdur. Əvvəlcə hesabat yaratmağımı istəyin."
    if language == "ru":
        return "Сейчас нет активного report artifact для ссылки. Сначала попросите меня создать report."
    return "There is no active report artifact to link right now. Ask me to generate the report first."


# ---------------------------------------------------------------------------
# Cancel / reset current topic
# ---------------------------------------------------------------------------
_CANCEL_TERMS = (
    "bos verek", "bosver", "bos ver", "bunu bos", "kenara qoy", "kenara qoyaq",
    "unut", "unudaq", "unut bunu", "lazim deyil", "ehtiyac yoxdu bunu bos",
    "cancel", "nevermind", "never mind", "forget it", "forget this", "leave it",
    "bunu burax", "burax bunu", "keçək başqa", "kecek basqa", "bunu saxlayaq",
)


def detect_cancel_topic(message: str) -> bool:
    norm = _norm(message)
    for term in _CANCEL_TERMS:
        if term not in norm:
            continue
        residual = norm.replace(term, " ", 1)
        residual = re.sub(r"\b(?:just|but|then|please|now)\b", " ", residual)
        residual = re.sub(r"[^a-z0-9]+", " ", residual).strip()
        if not residual:
            return True
    return False


_GENERAL_TOPIC_SWITCH_TERMS = (
    "umumiyyetle", "umumi", "general", "generally", "basqa movzu", "another topic",
    "konkret tapinti istemirem", "tapinti goster demedim", "tapinti istemirem",
)


def detect_general_topic_switch(message: str) -> bool:
    norm = _norm(message)
    wants_advice = any(t in norm for t in _AGG_ADVICE_TERMS) or "meslehet" in norm
    return wants_advice and any(t in norm for t in _GENERAL_TOPIC_SWITCH_TERMS)


def render_cancel(language: str) -> str:
    if language == "en":
        return "Alright, I'll set that aside. You can ask a new question."
    if language == "ru":
        return "Хорошо, отложу это. Можете задать новый вопрос."
    return "Oldu, bunu kənara qoyuram. Başqa sual verə bilərsiniz."


# ---------------------------------------------------------------------------
# Partial / subset severity count
# ---------------------------------------------------------------------------
_COUNT_UNIT_RE = re.compile(r"\b(?:e+d+e*d|eded|adad|dene|dane|tane|say|count)\b")


def _mentioned_severities_ordered(norm: str) -> list[str]:
    aliases = [
        ("CRITICAL", ("critical", "kritik")),
        ("HIGH", ("high", "yuksek")),
        ("MEDIUM", ("medium", "orta")),
        ("LOW", ("low", "asagi")),
    ]
    positions: list[tuple[int, str]] = []
    for severity, terms in aliases:
        for term in terms:
            m = re.search(rf"\b{term}\w*\b", norm)
            if m:
                positions.append((m.start(), severity))
                break
    positions.sort()
    seen: list[str] = []
    for _pos, sev in positions:
        if sev not in seen:
            seen.append(sev)
    return seen


def detect_severity_subset_count(message: str) -> list[str] | None:
    """Return the requested severity subset for a count question, or None.

    Fires only when the user names a *proper subset* (1-3 severities, not all 4)
    together with count language, so the full severity-distribution route is left
    intact for genuine "distribution/summary" questions.
    """
    norm = _norm(message)
    severities = _mentioned_severities_ordered(norm)
    if not (1 <= len(severities) <= 3):
        return None
    # Distribution/summary/comparison intent stays on the distribution route
    # ("high vs critical", "severity summary", ...).
    if any(t in norm for t in (
        "distribution", "summary", "xulase", "bolgu", "breakdown", "hamisi", "butun",
        " vs ", "versus", "muqayise", "ferq", "compare",
    )):
        return None
    has_count_language = (
        bool(_COUNT_UNIT_RE.search(norm))
        or any(t in norm for t in ("nece", "how many", "var", "sayi", "sayin"))
    )
    if not has_count_language:
        return None
    # Need at least two severities, OR a single severity that the plain count
    # route already handles — defer single-severity to the existing count route.
    if len(severities) < 2:
        return None
    return severities


def detect_severity_subset_correction(
    message: str, session_state: Mapping[str, Any] | None
) -> list[str] | None:
    """Correction like "yox, sadəcə medium və low soruşdum" after a count answer.

    Re-answers the named subset when a prior count/subset scope exists.
    """
    context = session_state or {}
    had_count = bool(context.get("last_count_scope_severities")) or str(
        context.get("last_answer_type") or ""
    ).startswith("severity_count") or str(context.get("last_task_type") or "") in {
        "severity_count", "severity_distribution", "severity_subset_count",
    }
    if not had_count:
        return None
    norm = _norm(message)
    is_correction = any(t in norm for t in (
        "yox", "sadece", "yalniz", "only", "just", "sorusdum", "demek istedim", "demistim",
    )) or bool(re.search(r"\bno+o\b|\bnoo+\b|\bxeyr\b", norm))
    if not is_correction:
        return None
    severities = _mentioned_severities_ordered(norm)
    if 1 <= len(severities) <= 3:
        return severities
    return None


_SEVERITY_LABELS = {
    "CRITICAL": {"az": "CRITICAL", "en": "CRITICAL", "ru": "CRITICAL"},
    "HIGH": {"az": "HIGH", "en": "HIGH", "ru": "HIGH"},
    "MEDIUM": {"az": "MEDIUM", "en": "MEDIUM", "ru": "MEDIUM"},
    "LOW": {"az": "LOW", "en": "LOW", "ru": "LOW"},
}


def render_severity_subset_count(
    counts: Mapping[str, int], severities: list[str], scan_id: str | None, language: str
) -> str:
    rows = [f"- {sev}: {int(counts.get(sev, 0))}" for sev in severities]
    body = "\n".join(rows)
    sid = str(scan_id or "latest")
    if language == "en":
        return (
            "From the latest scan:\n" + body + f"\n\nScan: {sid}\n"
            "Here \"finding\" is counted at file level."
        )
    if language == "ru":
        return (
            "По последнему scan:\n" + body + f"\n\nScan: {sid}\n"
            "Здесь «находка» считается на уровне файлов."
        )
    return (
        "Son skana görə:\n" + body + f"\n\nSkan: {sid}\n"
        "Burada \"tapıntı\" fayl səviyyəsində sayılır."
    )


# ---------------------------------------------------------------------------
# Aggregate (severity-scope) remediation instead of selected-finding hijack
# ---------------------------------------------------------------------------
_AGG_REFERENCE_TERMS = ("bunlar", "onlar", "these", "those", "bu tapintilar", "hamisi ucun", "umumiyyetle", "ne meslehet")
_AGG_ADVICE_TERMS = (
    "ne edebilerem", "neler edebilerem", "ne etmeliyem", "neler etmeliyem",
    "ne meslehet", "meslehet gorursen", "what should i do", "what can i do",
    "recommend", "remediation", "step by step", "addim addim", "pille pille", "basa sal",
)


def detect_aggregate_remediation(message: str, session_state: Mapping[str, Any] | None) -> list[str] | None:
    """When the previous answer was a severity-subset count and the user asks for
    general advice about "these", return the scope severities for an aggregate plan.
    """
    context = session_state or {}
    scope = [s for s in (context.get("last_count_scope_severities") or []) if s]
    if not scope:
        return None
    norm = _norm(message)
    wants_advice = any(t in norm for t in _AGG_ADVICE_TERMS)
    if not wants_advice:
        return None
    # Must not be an explicit selected-finding reference.
    if any(t in norm for t in ("bu tapinti", "secilmis", "bu finding", "this finding", "selected")):
        return None
    return list(scope)


def detect_aggregate_remediation_complaint(message: str, session_state: Mapping[str, Any] | None) -> list[str] | None:
    """User protests that they did NOT ask for a specific finding, they wanted
    general advice. Re-answer the aggregate plan for the stored scope.
    """
    context = session_state or {}
    scope = [s for s in (context.get("last_count_scope_severities") or []) if s]
    if not scope:
        return None
    norm = _norm(message)
    protests_finding = (
        ("tapinti" in norm and any(n in norm for n in ("demedim", "istemedim", "demirem")))
        or "gostor demedim" in norm
        or "goster demedim" in norm
        or ("umumiyyetle" in norm and "meslehet" in norm)
        or ("general" in norm and "advice" in norm)
    )
    if protests_finding:
        return list(scope)
    return None


def render_aggregate_remediation(
    severities: list[str],
    language: str,
    risk_type_categories: list[str] | None = None,
    acknowledge_mistake: bool = False,
) -> str:
    sev_text = " və ".join(severities) if language == "az" else (
        " and ".join(severities) if language == "en" else " и ".join(severities)
    )
    cats = risk_type_categories or []
    if language == "en":
        head = ""
        if acknowledge_mistake:
            head = (
                "You're right — you did not ask for a specific finding. You asked for a "
                f"general step-by-step plan for the {sev_text} findings.\n\n"
            )
        steps = [
            f"Step-by-step plan for {sev_text} findings:",
            f"1. Prioritize {severities[0]} findings first, then work down.",
            "2. Group the findings by risk type.",
            "3. For email/phone data: mask and minimize, review access.",
            "4. For confidential_keyword: confirm classification and run access review.",
            "5. Put LOW findings into the backlog.",
            "6. Re-scan after the changes to confirm.",
        ]
        return head + "\n".join(steps)
    if language == "ru":
        head = ""
        if acknowledge_mistake:
            head = (
                "Вы правы — вы не просили конкретную находку. Вы просили общий пошаговый план "
                f"для находок {sev_text}.\n\n"
            )
        steps = [
            f"Пошаговый план для находок {sev_text}:",
            f"1. Сначала приоритизируйте {severities[0]}, затем остальные.",
            "2. Сгруппируйте находки по типу риска.",
            "3. Email/phone: маскирование и минимизация, проверка доступа.",
            "4. confidential_keyword: подтвердите классификацию и проведите access review.",
            "5. LOW — в бэклог.",
            "6. После изменений повторите scan.",
        ]
        return head + "\n".join(steps)
    head = ""
    if acknowledge_mistake:
        head = (
            "Haqlısınız, siz konkret tapıntı istəmirdiniz. Siz "
            f"{sev_text} tapıntılar üzrə ümumi addım-addım plan istəyirdiniz.\n\n"
        )
    steps = [
        f"{sev_text} tapıntılar üçün addım-addım plan:",
        f"1. Əvvəl {severities[0]} tapıntıları prioritetləşdirin, sonra aşağıya doğru davam edin.",
        "2. Tapıntıları risk növlərinə görə qruplaşdırın.",
        "3. Email/phone məlumatı varsa: maskalama və minimizasiya, giriş nəzərdən keçirin.",
        "4. confidential_keyword varsa: təsnifatı təsdiqləyin və access review aparın.",
        "5. LOW tapıntıları backlog-a salın.",
        "6. Dəyişiklikdən sonra yenidən scan edin.",
    ]
    return head + "\n".join(steps)


# ---------------------------------------------------------------------------
# "Why didn't you understand me the first time?"
# ---------------------------------------------------------------------------
_WHY_MISUNDERSTOOD_TERMS = (
    "niye ilk", "ilk defe", "ilk de basa", "niye basa dusmursen", "niye ilk defe",
    "why dont you understand", "why didnt you understand", "first time",
    "duzgun yerine yetirmirsen", "niye deyende", "niye birinci",
)


def detect_why_misunderstood(message: str, session_state: Mapping[str, Any] | None) -> bool:
    norm = _norm(message)
    return any(t in norm for t in _WHY_MISUNDERSTOOD_TERMS)


def render_why_misunderstood(session_state: Mapping[str, Any] | None, language: str) -> str:
    context = session_state or {}
    scope = [s for s in (context.get("last_count_scope_severities") or []) if s]
    sev_text = " və ".join(scope) if scope else ""
    if scope:
        if language == "en":
            en_sev = " and ".join(scope)
            return (
                "You're right. The mistake was that I read your earlier \"these\" as a selected finding "
                f"instead of the {en_sev} group. The correct behavior: the previous answer's scope was "
                f"{en_sev}, so the step-by-step plan should also cover just those two severities in aggregate."
            )
        if language == "ru":
            ru_sev = " и ".join(scope)
            return (
                "Вы правы. Ошибка в том, что «эти» я воспринял как выбранную находку, а не как группу "
                f"{ru_sev}. Правильно: scope предыдущего ответа был {ru_sev}, поэтому пошаговый план "
                "тоже должен покрывать только эти severity в совокупности."
            )
        return (
            "Haqlısınız. Səhv ondan yarandı ki, əvvəlki “bunlar” ifadəsini "
            f"{sev_text} qrupu kimi yox, seçilmiş tapıntı kimi şərh etdim. Düzgün davranış belə olmalı idi: "
            f"əvvəlki cavabın scope-u {sev_text} idi, ona görə addım-addım plan da həmin severity-lər üçün "
            "ümumi verilməli idi."
        )
    if language == "en":
        return (
            "You're right. I misread the scope of your previous request. I should track the previous "
            "answer's scope and keep to it instead of switching context."
        )
    if language == "ru":
        return (
            "Вы правы. Я неверно понял scope вашего предыдущего запроса. Мне следует держаться scope "
            "предыдущего ответа, а не менять контекст."
        )
    return (
        "Haqlısınız. Əvvəlki sualınızın scope-unu səhv başa düşdüm. Konteksti dəyişmək əvəzinə əvvəlki "
        "cavabın scope-una sadiq qalmalıyam."
    )


# ---------------------------------------------------------------------------
# Malformed-output / invalid-word complaint
# ---------------------------------------------------------------------------
# Known fabricated / malformed tokens that have leaked from AZ translation.
FABRICATED_WORDS = {"önçük", "oncuk", "öncük", "oncuk"}


def detect_malformed_output_complaint(message: str) -> bool:
    return language_service.detect_malformed_output_complaint(message)


def render_malformed_output(message: str, language: str) -> str:
    return language_service.malformed_output_answer(language)


def scope_risk_categories(findings: list[dict[str, Any]], severities: list[str]) -> list[str]:
    """Distinct remediation categories present in the given severities' findings."""
    wanted = {s.upper() for s in severities}
    present: list[str] = []
    for finding in findings or []:
        if str(finding.get("severity") or "").upper() not in wanted:
            continue
        for cat in categorize_risk_types([str(t) for t in (finding.get("risk_types") or [])]):
            if cat not in present:
                present.append(cat)
    return present
