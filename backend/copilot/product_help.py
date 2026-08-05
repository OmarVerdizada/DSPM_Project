"""Deterministic product-help answers for the DSPM Copilot.

Real-chat regression class: product-level questions ("what is our product's
main idea", "what are our features", "how do you filter the data"), UI
navigation requests ("go to findings page", including typos), and
alert-type taxonomy questions ("how many alert types do we have") were
falling into the generic provider-final path or being misread as total-count
questions.

This module answers them deterministically from **verified product facts**:

- the actual dashboard tabs in ``frontend/index.html`` (labels below mirror
  the ``data-tab`` nav buttons);
- the actual Findings/inventory filters (search box, severity buttons,
  source and finding-type dropdowns);
- the actual Reports tab actions (Export Excel Workbook, Export Word Pack,
  Open PDF Composer) plus the Copilot's own report/PDF capability;
- the Copilot capability registry.

It never invents features, never calls a provider, and never asserts scan
facts — the alert-type breakdown renderer receives the distinct detected
types from the caller, which computes them from the real scan report.
Navigation answers are truthful: the Copilot cannot drive the UI, so it
tells the user where the page is instead of pretending to navigate.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from backend.copilot import language_service

PRODUCT_OVERVIEW = "product_overview"
PRODUCT_FEATURES = "product_features"
FILTER_HOWTO = "filter_howto"
NAVIGATION = "navigation_help"
ALERT_TYPES = "alert_types_breakdown"
RISK_SUMMARY_DELTA = "risk_summary_delta_explanation"


@dataclass(frozen=True)
class ProductHelpDecision:
    kind: str
    nav_target_key: str | None = None
    nav_target_label: str | None = None


# Verified dashboard tabs: (key, sidebar label, match tokens).
UI_TABS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("overview", "Dashboard", ("dashboard", "overview", "home", "main")),
    ("risk", "Remediation Center", ("remediation", "remediation center")),
    ("file-servers", "File Server Scan", ("file server", "file servers", "fileserver", "file server scan")),
    ("endpoint", "Endpoint Scan", ("endpoint", "endpoints", "endpoint scan")),
    ("findings", "Findings", ("findings", "finding", "tapinti", "tapintilar")),
    ("exposure", "Exposure", ("exposure",)),
    ("reports", "Reports", ("reports", "report page", "hesabat")),
    ("history", "History", ("history", "scan history", "tarixce")),
    ("security", "Security Ops", ("security", "security ops")),
    ("admin", "MSSP Admin", ("admin", "mssp", "mssp admin")),
    ("settings", "Asset Rules", ("asset rules", "settings", "parametrler")),
    ("integrations", "Integrations", ("integrations", "integration")),
    ("logic", "Risk Logic", ("risk logic", "logic")),
)

_NAV_VERB_RE = re.compile(r"\b(go to|goto|navigate to|navigate|take me to|take me|kec|ac|acin)\b")
_OPEN_SHOW_RE = re.compile(r"\b(open|show|display|goster)\b")
_PAGE_TOKEN_RE = re.compile(r"\b(page|tab|section|screen|sehife|sehifesine|sehifeye|bolme|ekran)\b")

_NAV_STOPWORDS = {
    "go", "to", "goto", "navigate", "take", "me", "open", "show", "display", "the",
    "page", "tab", "section", "screen", "please", "now", "kec", "ac", "acin",
    "goster", "sehife", "sehifesine", "sehifeye", "bolme", "ekran",
}

_TAB_VOCAB: dict[str, str] = {}
for _key, _label, _tokens in UI_TABS:
    for _token in _tokens:
        for _word in _token.split():
            _TAB_VOCAB.setdefault(_word, _key)


def _norm(message: str) -> str:
    return language_service.normalize_for_intent(message)


def _resolve_nav_target(norm: str) -> tuple[str, str] | None:
    """Resolve a navigation target from the message, tolerating typos like
    ``findigs`` via fuzzy matching against the verified tab vocabulary."""
    words = [w for w in re.findall(r"[a-z\-]+", norm) if w not in _NAV_STOPWORDS]
    vocab = list(_TAB_VOCAB)
    for word in words:
        if word in _TAB_VOCAB:
            key = _TAB_VOCAB[word]
        else:
            close = difflib.get_close_matches(word, vocab, n=1, cutoff=0.78)
            if not close:
                continue
            key = _TAB_VOCAB[close[0]]
        for tab_key, label, _tokens in UI_TABS:
            if tab_key == key:
                return tab_key, label
    return None


_PRODUCT_SUBJECT_RE = re.compile(
    r"\b(product|products|app|application|platform|tool|website|site|mehsul|mehsulun|proyekt|proqram)\b"
)
_IDEA_RE = re.compile(r"\b(main idea|idea|purpose|goal|about|used for|what is|what does|meqsed|ideya|ne ucun)\b")
# Bare "dspm" (or "system") as the subject is often a definitional/teaching
# question ("what is DSPM", "write a paragraph about DSPM") — those must stay
# on their normal routes. Only a strong product-idea phrasing qualifies.
_WEAK_SUBJECT_RE = re.compile(r"\b(dspm|system)\b")
_STRONG_IDEA_RE = re.compile(r"\b(main idea|purpose|goal|meqsed|ideya)\b")
_FEATURES_RE = re.compile(r"\b(features?|functionality|functions?|capabilities|modules?|imkanlar|funksiyalar?)\b")
_FILTER_RE = re.compile(r"\b(filter\w*|filtr\w*)\b")
_HOWTO_RE = re.compile(r"\b(how|nece|can i|can we|do you|do i|kimi|necur)\b")
_TYPE_WORD_RE = re.compile(r"\b(types?|kinds?|categor\w+|nov\w*|növ\w*)\b")
_ALERT_NOUN_RE = re.compile(r"\b(alerts?|findings?|tapinti\w*|risk types?)\b")
_TYPE_QUESTION_RE = re.compile(r"\b(how many|what|which|list|exist|we have|do we|are there|nece|hansi|var)\b")
# DSPM-evidence phrasing that must stay on the normal evidence routes.
_EVIDENCE_GUARD_RE = re.compile(r"\b(critical|high|medium|low|kritik|yuksek|orta|asagi|count of|posture|risk score)\b")
# Explanation cues: a "why does X show Y" question is never a request to
# navigate to a page, even when it names one.
_WHY_RE = re.compile(r"\b(why|explain|meaning|means|niye|niye ki|nece yeni|izah|what does .* mean)\b")
# A question about negative / minus values in the risk summary (dashboard
# severity deltas), e.g. "why do some alerts show minus, Critical: -1".
_MINUS_RE = re.compile(r"(minus|negative|-\s*\d|azalma|why .*\bminus\b)")
_RISK_SUMMARY_CONTEXT_RE = re.compile(
    r"\b(risk summary|risk-summary|summary|dashboard|alerts?|delta|change|critical|high|medium|low)\b"
)


def detect_product_help(message: str) -> ProductHelpDecision | None:
    """Classify a product-help message, or None to defer to normal routing.

    Deterministic and zero-provider. Order matters: navigation and
    filter-how-to are the most specific; overview is the loosest and runs
    last with a DSPM-evidence guard so real data questions never land here.
    """
    norm = _norm(message)
    if not norm:
        return None

    has_why = bool(_WHY_RE.search(norm))

    # A "why does the risk summary show minus / Critical: -1" question is a
    # data/UI explanation about severity deltas, not navigation.
    if _MINUS_RE.search(norm) and _RISK_SUMMARY_CONTEXT_RE.search(norm) and (has_why or "summary" in norm or "dashboard" in norm):
        return ProductHelpDecision(RISK_SUMMARY_DELTA)

    has_nav_verb = bool(_NAV_VERB_RE.search(norm))
    has_open_show = bool(_OPEN_SHOW_RE.search(norm))
    # Navigation is only a genuine "take me to page X" intent. A why/explanation
    # question or one carrying real severity/evidence data ("Critical: -1") must
    # never be answered with navigation instructions.
    if (has_nav_verb or (has_open_show and _PAGE_TOKEN_RE.search(norm))) and not has_why and not _EVIDENCE_GUARD_RE.search(norm):
        target = _resolve_nav_target(norm)
        if target is not None:
            return ProductHelpDecision(NAVIGATION, nav_target_key=target[0], nav_target_label=target[1])

    if _FILTER_RE.search(norm) and _HOWTO_RE.search(norm):
        return ProductHelpDecision(FILTER_HOWTO)

    if (
        _TYPE_WORD_RE.search(norm)
        and _ALERT_NOUN_RE.search(norm)
        and _TYPE_QUESTION_RE.search(norm)
        and not _EVIDENCE_GUARD_RE.search(norm)
    ):
        return ProductHelpDecision(ALERT_TYPES)

    if _FEATURES_RE.search(norm) and not _EVIDENCE_GUARD_RE.search(norm):
        if _PRODUCT_SUBJECT_RE.search(norm) or re.search(r"\b(what|which|our|your|list|hansi|ne)\b", norm):
            return ProductHelpDecision(PRODUCT_FEATURES)

    if not _EVIDENCE_GUARD_RE.search(norm):
        if _PRODUCT_SUBJECT_RE.search(norm) and _IDEA_RE.search(norm):
            return ProductHelpDecision(PRODUCT_OVERVIEW)
        if _WEAK_SUBJECT_RE.search(norm) and _STRONG_IDEA_RE.search(norm):
            return ProductHelpDecision(PRODUCT_OVERVIEW)

    return None


# ---------------------------------------------------------------------------
# Renderers — verified product facts only, no provider, no invented features.
# ---------------------------------------------------------------------------
def render_product_overview(language: str) -> str:
    if language == "az":
        return (
            "Bu, DSPM (Data Security Posture Management) platformasıdır. Əsas məqsədi: "
            "fayl serverlərini və Windows endpointləri skan etmək, həssas məlumatları "
            "(secrets, şəxsi, maliyyə məlumatları) aşkarlamaq, tapıntıları təsnif edib risk balı ilə "
            "qiymətləndirmək və nəticələri dashboard-da göstərməkdir. Mən — AI Copilot — scan nəticələrini, "
            "tapıntıları, riskləri və remediation addımlarını izah etməyə kömək edirəm."
        )
    if language == "ru":
        return (
            "Это платформа DSPM (Data Security Posture Management). Основная идея: сканировать файловые "
            "серверы и Windows endpoints, находить чувствительные данные (secrets, персональные и финансовые "
            "данные), классифицировать findings, оценивать их risk score и показывать результаты на dashboard. "
            "Я — AI Copilot — помогаю разбирать scan results, findings, риски и шаги remediation."
        )
    return (
        "This is a DSPM (Data Security Posture Management) platform. Its main idea: scan file servers "
        "and Windows endpoints, detect sensitive data (secrets, personal and financial data), classify "
        "the findings, score their risk, and show the results on the dashboard. I am the AI Copilot — "
        "I help you understand scan results, findings, risks, and remediation steps."
    )


def render_product_features(language: str) -> str:
    tabs = "Dashboard, Remediation Center, File Server Scan, Endpoint Scan, Findings, Exposure, Reports, History, Security Ops, Integrations, Risk Logic"
    if language == "az":
        return (
            "Əsas imkanlar: fayl serverlərinin və endpointlərin skan edilməsi, həssas məlumatların aşkarlanması, "
            "tapıntıların severity və risk balı ilə təsnifatı, dashboard və hesabatlar. "
            f"Əsas bölmələr: {tabs}. Reports bölməsində Excel Workbook, Word Pack export və PDF Composer var. "
            "Mən isə tapıntıları saymağa, siyahılamağa, müqayisə etməyə və remediation addımları təklif etməyə kömək edirəm."
        )
    if language == "ru":
        return (
            "Основные возможности: сканирование файловых серверов и endpoints, обнаружение чувствительных данных, "
            "классификация findings по severity и risk score, dashboard и отчёты. "
            f"Основные разделы: {tabs}. В разделе Reports есть Export Excel Workbook, Export Word Pack и PDF Composer. "
            "Я помогаю считать, фильтровать и сравнивать findings и предлагать шаги remediation."
        )
    return (
        "Core features: scanning file servers and Windows endpoints, detecting sensitive data, classifying "
        "findings with severity and risk scores, plus dashboards and reporting. "
        f"Main sections: {tabs}. The Reports tab offers Export Excel Workbook, Export Word Pack, and a PDF Composer. "
        "As the Copilot, I can count, list, filter, and compare findings and suggest remediation steps."
    )


def render_filter_howto(language: str) -> str:
    if language == "az":
        return (
            "Tapıntıları bir neçə yolla filtrləyə bilərsiniz: Findings səhifəsində axtarış xanası "
            "(fayl, path, finding, source və risk üzrə axtarır), severity düymələri (All / Critical / High / "
            "Medium / Low / Protected), həmçinin Source və Finding type açılan siyahıları. "
            "History səhifəsində skan tarixçəsini vaxt aralığına görə filtrləmək olur. "
            "Məndən də birbaşa istəyə bilərsiniz — məsələn: “show high findings” və ya “top 5 critical”."
        )
    if language == "ru":
        return (
            "Фильтровать findings можно несколькими способами: на странице Findings есть строка поиска "
            "(по файлу, пути, finding, source и risk), кнопки severity (All / Critical / High / Medium / Low / "
            "Protected), а также выпадающие списки Source и Finding type. На странице History историю сканов "
            "можно фильтровать по периоду. Можно просто попросить меня — например: «show high findings» или «top 5 critical»."
        )
    return (
        "You can filter findings in a few ways: on the Findings page there is a search box (matches file, "
        "path, finding, source, and risk), severity buttons (All / Critical / High / Medium / Low / Protected), "
        "and Source / Finding type dropdowns. The History page filters scan history by time range. "
        "You can also just ask me directly — for example: \"show high findings\" or \"top 5 critical\"."
    )


def render_risk_summary_delta(language: str) -> str:
    """Explain the negative values in the dashboard risk summary.

    Those values are per-severity *deltas* between the latest saved scan and the
    previous one (``delta = latest_count - previous_count``). A negative value
    means the latest scan has fewer files at that severity than the previous
    scan (posture improved); a leading ``+`` means more (posture worsened).
    """
    if language == "az":
        return (
            "Risk summary-dəki mənfi rəqəmlər say deyil — onlar dəyişmə (delta) göstəriciləridir: "
            "son skan ilə əvvəlki skan arasındakı fərq (delta = son skan − əvvəlki skan). "
            "Məsələn “Critical: -1” son skanda əvvəlki skana nisbətən 1 az kritik fayl olduğunu bildirir "
            "(yəni vəziyyət yaxşılaşıb). Müsbət “+” dəyər isə artım deməkdir. "
            "İstəsəniz iki skanı müqayisə edib dəqiq fərqi göstərə bilərəm."
        )
    if language == "ru":
        return (
            "Отрицательные числа в risk summary — это не количество, а дельта: разница между последним "
            "и предыдущим сканом (delta = последний − предыдущий). Например «Critical: -1» означает, что в "
            "последнем скане на 1 критический файл меньше, чем в предыдущем (то есть стало лучше). Значение "
            "с «+» означает рост. При желании я могу сравнить два скана и показать точную разницу."
        )
    return (
        "Those minus values in the risk summary are not counts — they are per-severity deltas comparing the "
        "latest scan with the previous one (delta = latest count - previous count). So \"Critical: -1\" means "
        "the latest scan has 1 fewer critical-severity file than the previous scan (posture improved); a "
        "leading \"+\" means more than last time (posture worsened), and 0 means no change. They need at least "
        "two saved scans. I can compare the last two scans and show you the exact per-severity difference if you want."
    )


def render_navigation_help(language: str, target_label: str) -> str:
    if language == "az":
        return (
            f"Mən interfeysdə naviqasiya edə bilmirəm, amma {target_label} səhifəsini sol paneldəki "
            f"“{target_label}” bölməsinə klikləyərək aça bilərsiniz. Məzmunla bağlı sualları isə mənə verə bilərsiniz."
        )
    if language == "ru":
        return (
            f"Я не могу переключать страницы интерфейса, но вы можете открыть {target_label}, нажав "
            f"«{target_label}» в левой боковой панели. По содержимому страницы можете спросить меня."
        )
    return (
        f"I can't navigate the UI for you, but you can open the {target_label} page from the "
        f"\"{target_label}\" item in the left sidebar. If you want, ask me about the data instead — "
        "I can summarize or filter it here."
    )


def render_alert_types(language: str, type_counts: list[tuple[str, int]], scan_id: str | None) -> str:
    """Alert-type taxonomy answer. ``type_counts`` are the distinct detected
    finding types computed by the caller from the real scan report."""
    scan_label = scan_id or "latest"
    if not type_counts:
        if language == "az":
            return (
                "DSPM datasında ayrıca “alert type” obyekti yoxdur — alertlər fayl səviyyəli tapıntılar kimi saxlanılır. "
                "Hazırda skan datası yoxdur; skan tamamlandıqdan sonra tapıntıları severity və ya aşkarlanmış tipə görə bölə bilərəm."
            )
        if language == "ru":
            return (
                "В данных DSPM нет отдельного объекта «alert type» — алерты хранятся как файловые findings. "
                "Сейчас нет данных сканирования; после скана я могу разбить findings по severity или по типу."
            )
        return (
            "There is no separate alert-type object in the DSPM data — alerts are represented as file-level "
            "findings. No scan data is available yet; after a scan I can break findings down by severity or "
            "by detected type."
        )
    lines_en = [
        "There is no separate alert-type object — alerts are represented as findings. "
        f"By detected type, the latest scan ({scan_label}) has {len(type_counts)} distinct types:",
    ]
    lines_az = [
        "Ayrıca “alert type” obyekti yoxdur — alertlər tapıntılar kimi təmsil olunur. "
        f"Aşkarlanmış tipə görə son skanda ({scan_label}) {len(type_counts)} fərqli tip var:",
    ]
    lines_ru = [
        "Отдельного объекта «alert type» нет — алерты представлены как findings. "
        f"По типу обнаружения в последнем скане ({scan_label}) {len(type_counts)} разных типов:",
    ]
    breakdown = [f"- {name}: {count}" for name, count in type_counts]
    tail_en = "I can also break these down by severity if you prefer."
    tail_az = "İstəsəniz, severity üzrə bölgü də verə bilərəm."
    tail_ru = "Могу также разбить их по severity."
    if language == "az":
        return "\n".join(lines_az + breakdown + [tail_az])
    if language == "ru":
        return "\n".join(lines_ru + breakdown + [tail_ru])
    return "\n".join(lines_en + breakdown + [tail_en])


def distinct_finding_types(findings: list[dict]) -> list[tuple[str, int]]:
    """Distinct detected finding types with counts, from real scan findings.

    Accepts both the normalized shape (``risk_types: [str, ...]``) and the
    raw report shape (``findings: [{"type": ..., "count": ...}, ...]``).
    """
    counts: dict[str, int] = {}
    for item in findings or []:
        if not isinstance(item, dict):
            continue
        risk_types = item.get("risk_types")
        if isinstance(risk_types, list) and risk_types:
            for name in risk_types:
                if str(name or "").strip():
                    key = str(name)
                    counts[key] = counts.get(key, 0) + 1
            continue
        for entry in item.get("findings") or []:
            if isinstance(entry, dict) and entry.get("type"):
                name = str(entry["type"])
                counts[name] = counts.get(name, 0) + int(entry.get("count") or 1)
    return sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))
