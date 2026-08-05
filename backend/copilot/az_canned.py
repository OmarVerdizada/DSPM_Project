from __future__ import annotations

"""
Predefined safe responses for short small-talk and capability questions.

These are intentionally deterministic because the local 3B model can produce
broken Azerbaijani for open-ended small-talk.

Variant rotation ensures the same message does not return identical text
every time in a session. Rotation is deterministic (not random) based on
session hit count, so tests are stable and no hidden state is stored.

Important:
- Only use for short conversational messages.
- Never use for real DSPM/security tasks.
"""

import re
import unicodedata
from dataclasses import dataclass

from backend.copilot.language import normalize_message
from backend.copilot.language_detector import is_cyrillic_or_mojibake_russian

_VARIANT_CACHE: dict[str, int] = {}


def _normalize_for_matching(text: str) -> str:
    """Normalize short conversational text for deterministic matching."""
    value = (text or "").strip().lower()
    value = value.translate(str.maketrans({"ə": "e", "ı": "i", "ö": "o", "ü": "u", "ç": "c", "ş": "s", "ğ": "g"}))
    nfkd = unicodedata.normalize("NFKD", value)
    ascii_text = "".join(char for char in nfkd if not unicodedata.combining(char))
    ascii_text = ascii_text.translate(str.maketrans({"ə": "e", "ı": "i", "ö": "o", "ü": "u", "ç": "c", "ş": "s", "ğ": "g"}))
    ascii_text = re.sub(r"[^\w\s]", " ", ascii_text, flags=re.UNICODE)
    return re.sub(r"\s+", " ", ascii_text).strip()


_SMALL_TALK_NORMALIZED = {
    "salam",
    "salam aleykum",
    "salamlar",
    "salam necesen",
    "necesen",
    "ne tersen",
    "netersen",
    "ozun necesen",
    "ozun ne tersen",
    "sen necesen",
    "nece deyilsen",
    "nece gedir",
    "ne var ne yox",
    "noldu",
    "ne oldu",
    "ne xeber",
    "saol",
    "sagol",
    "sag ol",
    "cox sagol",
    "helelik",
    "gorusherik",
    "gorusek",
    "bye",
    "hello",
    "hi",
    "hey",
    "how are you",
    "how are u",
    "whats up",
    "good morning",
    "good evening",
    "tesekkurler",
    "tesekkur",
    "thanks",
    "thank you",
    "minnetdaram",
}


def _detect_unsupported_script(text: str) -> str | None:
    """Return the dominant unsupported script name, if any."""
    clean = (text or "").strip()
    if not clean:
        return None
    cyrillic_count = sum(1 for char in clean if "\u0400" <= char <= "\u04ff")
    arabic_count = sum(1 for char in clean if "\u0600" <= char <= "\u06ff")
    cjk_count = sum(1 for char in clean if "\u4e00" <= char <= "\u9fff")
    kana_count = sum(1 for char in clean if "\u3040" <= char <= "\u30ff")
    alpha_count = sum(1 for char in clean if char.isalpha())
    if alpha_count == 0:
        return None
    if cyrillic_count / alpha_count > 0.5:
        return "cyrillic"
    if arabic_count / alpha_count > 0.5:
        return "arabic"
    if (cjk_count + kana_count) / alpha_count > 0.3:
        return "cjk"
    return None


def _is_cyrillic_or_mojibake_russian(message: str) -> bool:
    # Single source in language_detector so the language runtime and the canned
    # layer cannot drift apart on what counts as unsupported Russian input.
    return is_cyrillic_or_mojibake_russian(message)


def is_unsupported_language_message(message: str) -> bool:
    return _is_cyrillic_or_mojibake_russian(message) or _detect_unsupported_script(message) is not None


UNSUPPORTED_LANGUAGE_AZ = (
    "Hal-hazırda əsas dəstək Azərbaycan və İngilis dilləri üçündür. "
    "İstəsəniz, sualınızı Azərbaycan və ya İngilis dilində göndərin, mən kömək edim."
)
UNSUPPORTED_LANGUAGE_EN = (
    "Currently I mainly support Azerbaijani and English. Please send your question in Azerbaijani or English and I will help."
)


@dataclass
class CannedFamily:
    id: str
    patterns: list[str]
    en: list[str]
    az: list[str]


CANNED_FAMILIES: list[CannedFamily] = [
    CannedFamily(
        id="greeting",
        patterns=[r"^salam\b", r"^hello\b", r"^hi\b", r"^hey\b", r"^salam necesen\b"],
        en=[
            "Hello! I'm the DSPM Security Copilot. How can I help you with your security findings today?",
            "Hi! I can help with DSPM findings, risks, and remediation steps.",
            "Hello! I'm ready to help analyze your DSPM security data.",
        ],
        az=[
            "Salam! Mən DSPM Copilot-am. Tapıntılar, risklər, remediation və dashboard məlumatları ilə bağlı kömək edə bilərəm.",
            "Salam! DSPM tapıntıları, riskləri və remediation işlərini araşdırmağa kömək edə bilərəm.",
        ],
    ),
    CannedFamily(
        id="status",
        patterns=[
            r"necesen",
            r"necesin",
            r"sen necesen",
            r"ozun necesen",
            r"netersen",
            r"sen netersen",
            r"ozun netersen",
            r"ne var ne yox",
            r"ne xeber",
            r"nece gedir",
            r"yaxsisan",
            r"yaxshisan",
            r"how are you",
            r"how r u",
            r"how are u",
        ],
        en=[
            "I'm doing well, thank you! Ready to help with your DSPM data. What would you like to know?",
            "I'm good. I can help you review findings, risks, and remediation steps.",
            "All good. Tell me what DSPM issue you want to inspect.",
        ],
        az=[
            "Yaxşıyam, sağ ol! DSPM tapıntıları və risklərlə bağlı kömək etməyə hazıram.",
            "Yaxşıyam. DSPM tapıntıları və risklər üzrə kömək etməyə hazıram.",
        ],
    ),
    CannedFamily(
        id="language_capability",
        patterns=[
            r"azerbaycan dilinde danisa bilirsen",
            r"azerbaycan dilinde danisirsan",
            r"azerbaycanca danisa bilirsen",
            r"azerbaycanca cavab vere bilirsen",
        ],
        en=[
            "Yes, I can answer in Azerbaijani or English. Which DSPM data would you like to review?",
        ],
        az=[
            "B\u0259li, Az\u0259rbaycan dilind\u0259 cavab ver\u0259 bil\u0259r\u0259m. Hans\u0131 DSPM m\u0259lumat\u0131n\u0131 yoxlamaq ist\u0259yirsiniz?",
        ],
    ),
    CannedFamily(
        id="capability",
        patterns=[
            r"neler ede bilir", r"neler edebiler", r"neler edebilir", r"neleredebilir", r"neleredebiler",
            r"ne ede biler", r"ne ede bilersen", r"ne ede bilirsen", r"sen ne ede bilirsen", r"ne edebilersen", r"ne edebilirsen",
            r"ne bacarir", r"imkanlarin", r"ne isler gore bilir", r"sen ne isler gore bilir",
            r"azerbaycan dilinde danisa bilirsen", r"azerbaycan dilinde danisirsan",
            r"what can you do", r"what can u do", r"capabilities", r"what do you do", r"help me with",
        ],
        en=[
            "I can list findings, explain risks, suggest remediation, compare scans, and summarize dashboard posture.",
            "I can help with critical findings, high-risk assets, recent alerts, scan comparison, and remediation guidance.",
            "I can answer DSPM questions using local scan evidence and deterministic tools where possible.",
        ],
        az=[
            "Mən DSPM üzrə kömək edə bilərəm: kritik tapıntıları göstərə, riskləri izah edə, tövsiyə verə və skanları müqayisə edə bilərəm.",
            "Mən DSPM üzrə tapıntı siyahısı, risk izahı, remediation tövsiyəsi, skan müqayisəsi və hesabatlarda kömək edə bilərəm.",
            "Sizə kritik/high tapıntıları tapmaq, hər biri üçün tövsiyə vermək, scan nəticələrini müqayisə etmək və dashboard xülasəsi çıxarmaqda kömək edə bilərəm.",
        ],
    ),
    CannedFamily(
        id="language_preference",
        patterns=[
            r"azerbaycan dilinde cavab",
            r"azerbaycanca cavab ver",
            r"azerbaycanca yaz",
            r"niye ingilis",
            r"niye azerbaycan dilind",
        ],
        en=[
            "Sorry, I will answer in Azerbaijani from now on. Send your question and I will explain it clearly in Azerbaijani.",
        ],
        az=[
            "\u00dczr ist\u0259yir\u0259m, bundan sonra Az\u0259rbaycan dilind\u0259 cavab ver\u0259c\u0259y\u0259m. Sual\u0131n\u0131z\u0131 g\u00f6nd\u0259rin, m\u0259n onu Az\u0259rbaycan dilind\u0259 v\u0259 ayd\u0131n \u015f\u0259kild\u0259 izah edim.",
        ],
    ),
    CannedFamily(
        id="unsupported_language",
        patterns=[r"[\u0400-\u04ff]", r"ğ¿ñ", r"ñ‡ñ", r"ğ¾ñ"],
        en=[UNSUPPORTED_LANGUAGE_EN],
        az=[UNSUPPORTED_LANGUAGE_AZ],
    ),
    CannedFamily(
        id="identity",
        patterns=[r"kimisen", r"kimisin", r"sen kimsen", r"who are you", r"what are you"],
        en=["I'm the DSPM AI Security Copilot, an assistant built into your dashboard to help analyze security findings from your data scans."],
        az=["Mən DSPM AI Təhlükəsizlik Köməkçisiyəm. Data skanlarınızdan gələn təhlükəsizlik tapıntılarını təhlil etmək üçün idarə panelinizdə işləyirəm."],
    ),
    CannedFamily(
        id="thanks",
        patterns=[r"^(cox )?sag ol", r"^(cox )?tesekkur", r"^thank", r"^thanks", r"^thx"],
        en=["You're welcome! Let me know if you need anything else."],
        az=["Xahiş edirəm! Başqa bir şey lazım olsa, bildirin."],
    ),
    CannedFamily(
        id="praise",
        patterns=[
            r"^cox agillisan$", r"^agillisan$", r"^elasan$", r"^super$",
            r"^zorsan$", r"^supersen$", r"^bravo$", r"^bomba kimisen$",
            r"^mohtesemsen$", r"^mukemmelsen$", r"^mukemmel$", r"^cox yaxsisan$",
            r"^great$", r"^good job$", r"^nice$", r"^bomba$",
        ],
        en=["Thank you. I am here to help with DSPM findings and remediation."],
        az=["Təşəkkür edirəm. DSPM tapıntıları və remediation ilə bağlı kömək etməyə hazıram."],
    ),
    CannedFamily(
        id="ack",
        patterns=[r"^tamam$", r"^ok\b", r"^okay\b", r"^anladim", r"^basa dusdum", r"^got it", r"^understood", r"^clear"],
        en=["Got it. What would you like to do next?"],
        az=["Başa düşdüm. Növbəti nə etmək istəyirsiniz?"],
    ),
    CannedFamily(
        id="complaint",
        patterns=[
            r"bu ne demekdi",
            r"bu nedi",
            r"bu nedi cixartdin",
            r"ne elaqe",
            r"ne yazmisan",
            r"anlamirsan",
            r"basa dusmursen",
            r"dediklerimi anlamirsan",
            r"meni basa dusmursen",
            r"men bunu istemedim",
            r"bele bir sey istemedim",
            r"niye bunu verdin",
            r"wrong answer",
            r"why give information",
            r"why did you give",
            r"i did not ask",
            r"i didnt want",
            r"that is unrelated",
            r"are u okay",
            r"are you okay",
            r"you are not okay",
            r"this makes no sense",
            r"you are not understanding",
            r"you do not understand",
        ],
        en=["You are right to question that answer. I likely reused the wrong selected finding context. Please ask the count, list, or compare question again, and I will answer from the dashboard scan data."],
        az=["Üzr istəyirəm, sizi düzgün başa düşmədim. Konkret finding, fayl və ya scan sualını yazın, daha dəqiq cavab verim."],
    ),
    CannedFamily(
        id="active",
        patterns=[
            r"isleyirsan", r"isleyirsen", r"isleyir", r"calisir", r"calisirsan",
            r"aktivsen", r"aktivsən", r"burdasan", r"burda san", r"ordasan",
            r"are you working", r"are you active", r"are you there",
            r"is it working", r"do you work", r"can you work", r"is the copilot", r"is the assistant",
        ],
        en=["Yes, I'm working. I can help with DSPM scan summaries, findings, risk explanations, and remediation steps."],
        az=["Bəli, işləyirəm. DSPM scan, finding, risk və remediation suallarında kömək edə bilərəm."],
    ),
    CannedFamily(
        id="ping",
        patterns=[r"^test$", r"^he$", r"^hə$", r"^yox$", r"^no$", r"^yes$", r"^hmm$"],
        en=["Ready to help. What would you like to check in your DSPM data?"],
        az=["Kömək etməyə hazıram. DSPM məlumatlarınızda nə yoxlamaq istəyirsiniz?"],
    ),
]

CAPABILITY_HELP_EN = (
    "I can list findings and help you with DSPM work:\n"
    "• List and filter critical findings by severity\n"
    "• Explain what a finding means and why it's risky\n"
    "• Provide step-by-step remediation guidance\n"
    "• Calculate your security posture score\n"
    "• Map findings to compliance frameworks (GDPR, NIST, PCI-DSS, HIPAA)\n"
    "• Compare scans and show trends over time\n"
    "• Generate security reports\n"
    "• Teach you about data security concepts\n"
    "• Show proactive alerts about new risks"
)

CAPABILITY_HELP_AZ = (
    "DSPM üzrə sizə bunlarda kömək edə bilərəm:\n"
    "• Kritik tapıntıları təhlükə səviyyəsinə görə sıralamaq və süzmək\n"
    "• Tapıntının nə demək olduğunu və niyə riskli olduğunu izah etmək\n"
    "• Addım-addım düzəliş təlimatları vermək\n"
    "• Təhlükəsizlik balınızı hesablamaq\n"
    "• Tapıntıları uyğunluq standartlarına uyğunlaşdırmaq (GDPR, NIST, PCI-DSS, HIPAA)\n"
    "• Skanları müqayisə etmək və dinamikanı göstərmək\n"
    "• Təhlükəsizlik hesabatları yaratmaq\n"
    "• Məlumat təhlükəsizliyi konseptlərini öyrətmək\n"
    "• Yeni risklər barədə proaktiv xəbərdarlıqlar göstərmək"
)

for _family in CANNED_FAMILIES:
    if _family.id == "capability":
        _family.en = [CAPABILITY_HELP_EN, CAPABILITY_HELP_EN]
        _family.az = [CAPABILITY_HELP_AZ, CAPABILITY_HELP_AZ]
        break


SECURITY_TERMS = {
    "critical",
    "alert",
    "alerts",
    "finding",
    "findings",
    "scan",
    "history",
    "histories",
    "compare",
    "comparison",
    "timestamp",
    "report",
    "export",
    "risk",
    "remediation",
    "compliance",
    "gdpr",
    "pci",
    "iso",
    "private_key",
    "jwt",
    "api_key",
    "kritik",
    "tapinti",
    "tapintilar",
    "xeberdarliq",
    "skan",
    "tarixce",
    "muqayise",
    "hesabat",
    "duzelis",
}


def get_canned_response(message: str, lang: str, session_id: str | None = None) -> str | None:
    """Return a canned response for simple small-talk/capability messages.

    Variant rotation is deterministic based on session hit count, ensuring
    the same message does not return the exact same text every time within
    a session.

    Args:
        message: The user's input message.
        lang: Target language ("az" or "en").
        session_id: Optional session identifier for hit-count tracking and rotation.

    Returns:
        A canned response string, or None if the message does not match
        any canned pattern or is too long/security-relevant.
    """
    if is_unsupported_language_message(message):
        return UNSUPPORTED_LANGUAGE_AZ if lang == "az" else UNSUPPORTED_LANGUAGE_EN
    normalized = normalize_message(message)
    if not normalized:
        return None
    if len(normalized) > 80:
        return None
    words = set(normalized.replace("-", " ").split())
    if words & SECURITY_TERMS:
        return None
    target_lang = "az" if lang == "az" else "en"
    normalized_for_matching = _normalize_for_matching(message)
    if normalized_for_matching in _SMALL_TALK_NORMALIZED:
        entry = next(item for item in CANNED_FAMILIES if item.id == "status")
        if normalized_for_matching in {"salam necesen", "salam netersen", "salam ne var ne yox"}:
            return "Salam! Yaxşıyam, sağ ol. DSPM tapıntıları və risklərlə bağlı kömək etməyə hazıram." if target_lang == "az" else "Hello. I'm doing well, thank you. I am ready to help with DSPM findings and risks."
        if normalized_for_matching.startswith(("salam", "hello", "hi", "hey")):
            entry = next(item for item in CANNED_FAMILIES if item.id == "greeting")
        if normalized_for_matching in {"thanks", "thank you", "tesekkur", "tesekkurler", "sagol", "sag ol", "cox sagol", "saol"}:
            entry = next(item for item in CANNED_FAMILIES if item.id == "thanks")
        variants = entry.az if target_lang == "az" else entry.en
        cache_key = f"{session_id or 'anon'}:{entry.id}"
        hit_count = _VARIANT_CACHE.get(cache_key, 0)
        variant_index = hit_count % len(variants)
        _VARIANT_CACHE[cache_key] = hit_count + 1
        return variants[variant_index]
    for entry in CANNED_FAMILIES:
        for pattern in entry.patterns:
            if re.search(pattern, normalized) or re.search(pattern, normalized_for_matching):
                variants = entry.az if target_lang == "az" else entry.en
                if len(variants) == 1:
                    return variants[0]
                cache_key = f"{session_id or 'anon'}:{entry.id}"
                hit_count = _VARIANT_CACHE.get(cache_key, 0)
                variant_index = hit_count % len(variants)
                _VARIANT_CACHE[cache_key] = hit_count + 1
                return variants[variant_index]
    return None


def get_canned_response_metadata(message: str, lang: str, session_id: str | None = None) -> dict | None:
    """Return route metadata for a canned response without the response text.

    This allows the service layer to record audit information (provider call
    count = 0, final_answer_mode = canned_variant, etc.) without exposing
    hidden reasoning.

    Returns a dict with keys:
        intent, route, response_family, provider_call_count,
        provider_planning_called, provider_final_called, translator_called,
        final_answer_mode, cache_hit, variant_id, variant_count, hit_count

    Returns None if message does not match any canned pattern.
    """
    if is_unsupported_language_message(message):
        return {
            "intent": "unsupported_language",
            "route": "canned_fast_path",
            "response_family": "unsupported_language",
            "provider_call_count": 0,
            "provider_planning_called": False,
            "provider_final_called": False,
            "translator_called": False,
            "final_answer_mode": "canned_variant",
            "cache_hit": False,
            "variant_id": "unsupported_language_1",
            "variant_count": 1,
            "hit_count": 1,
        }
    normalized = normalize_message(message)
    if not normalized:
        return None
    if len(normalized) > 80:
        return None
    words = set(normalized.replace("-", " ").split())
    if words & SECURITY_TERMS:
        return None
    normalized_for_matching = _normalize_for_matching(message)
    if normalized_for_matching in _SMALL_TALK_NORMALIZED:
        entry = next(item for item in CANNED_FAMILIES if item.id == "status")
        if normalized_for_matching in {"salam necesen", "salam netersen", "salam ne var ne yox"}:
            return {
                "intent": "small_talk_greeting_status",
                "route": "canned_fast_path",
                "response_family": "greeting_status",
                "provider_call_count": 0,
                "provider_planning_called": False,
                "provider_final_called": False,
                "translator_called": False,
                "final_answer_mode": "canned_variant",
                "cache_hit": False,
                "variant_id": "greeting_status_1",
                "variant_count": 1,
                "hit_count": 1,
            }
        if normalized_for_matching.startswith(("salam", "hello", "hi", "hey")):
            entry = next(item for item in CANNED_FAMILIES if item.id == "greeting")
        if normalized_for_matching in {"thanks", "thank you", "tesekkur", "tesekkurler", "sagol", "sag ol", "cox sagol", "saol"}:
            entry = next(item for item in CANNED_FAMILIES if item.id == "thanks")
        variants = entry.az if lang == "az" else entry.en
        cache_key = f"{session_id or 'anon'}:{entry.id}"
        hit_count = _VARIANT_CACHE.get(cache_key, 0)
        variant_index = hit_count % len(variants)
        _VARIANT_CACHE[cache_key] = hit_count + 1
        return {
            "intent": "small_talk_" + entry.id,
            "route": "canned_fast_path",
            "response_family": entry.id,
            "provider_call_count": 0,
            "provider_planning_called": False,
            "provider_final_called": False,
            "translator_called": False,
            "final_answer_mode": "canned_variant",
            "cache_hit": hit_count > 0,
            "variant_id": f"{entry.id}_{variant_index + 1}",
            "variant_count": len(variants),
            "hit_count": hit_count + 1,
        }
    target_lang = "az" if lang == "az" else "en"
    for entry in CANNED_FAMILIES:
        for pattern in entry.patterns:
            if re.search(pattern, normalized) or re.search(pattern, normalized_for_matching):
                variants = entry.az if target_lang == "az" else entry.en
                cache_key = f"{session_id or 'anon'}:{entry.id}"
                hit_count = _VARIANT_CACHE.get(cache_key, 0)
                variant_index = hit_count % len(variants)
                _VARIANT_CACHE[cache_key] = hit_count + 1
                return {
                    "intent": "small_talk_" + entry.id,
                    "route": "canned_fast_path",
                    "response_family": entry.id,
                    "provider_call_count": 0,
                    "provider_planning_called": False,
                    "provider_final_called": False,
                    "translator_called": False,
                    "final_answer_mode": "canned_variant",
                    "cache_hit": hit_count > 0,
                    "variant_id": f"{entry.id}_{variant_index + 1}",
                    "variant_count": len(variants),
                    "hit_count": hit_count + 1,
                }
    return None


CANNED = [
    {
        "patterns": [
            r"^salam\b",
            r"^hello\b",
            r"^hi\b",
            r"^hey\b",
            r"^salam necesen\b",
        ],
        "en": "Hello! I'm the DSPM Security Copilot. How can I help you with your security findings today?",
        "az": "Salam! Mən DSPM Copilot-am. Tapıntılar, risklər, remediation və dashboard məlumatları ilə bağlı kömək edə bilərəm.",
    },
    {
        "patterns": [
            r"necesen",
            r"necesin",
            r"yaxsisan",
            r"yaxshisan",
            r"how are you",
            r"how r u",
            r"how are u",
        ],
        "en": "I'm doing well, thank you! Ready to help with your DSPM data. What would you like to know?",
        "az": "Yaxşıyam, sağ ol! DSPM tapıntıları və risklərlə bağlı kömək etməyə hazıram.",
    },
    {
        "patterns": [
            r"azerbaycan dilinde danisa bilirsen",
            r"azerbaycan dilinde danisirsan",
            r"azerbaycanca danisa bilirsen",
            r"azerbaycanca cavab vere bilirsen",
        ],
        "en": "Yes, I can answer in Azerbaijani or English. Which DSPM data would you like to review?",
        "az": "Bəli, Azərbaycan dilində cavab verə bilərəm. Hansı DSPM məlumatını yoxlamaq istəyirsiniz?",
    },
    {
        "patterns": [
            r"neler ede bilir",
            r"neler edebiler",
            r"neler edebilir",
            r"ne ede biler",
            r"ne ede bilersen",
            r"ne edebilersen",
            r"ne edebilirsen",
            r"ne bacarir",
            r"imkanlarin",
            r"what can you do",
            r"what can u do",
            r"capabilities",
            r"what do you do",
            r"help me with",
        ],
        "en": (
            "I can help you with:\n"
            "- List critical or high findings from the latest scan\n"
            "- Show details for a specific finding or file\n"
            "- Recommend remediation steps\n"
            "- Explain why a finding is risky\n"
            "- Compare scan histories\n"
            "- Generate a security report or export if available\n"
            "- Check compliance implications such as GDPR, PCI-DSS, and ISO 27001\n\n"
            "You can ask in English or Azerbaijani."
        ),
        "az": (
            "Mən sizə aşağıdakılarla kömək edə bilərəm:\n"
            "- Son skandan kritik və ya yüksək tapıntıları siyahılamaq\n"
            "- Müəyyən tapıntı və ya fayl üzrə təfərrüatları göstərmək\n"
            "- Düzəliş addımlarını tövsiyə etmək\n"
            "- Tapıntının niyə riskli olduğunu izah etmək\n"
            "- Skan tarixçələrini müqayisə etmək\n"
            "- Mövcuddursa təhlükəsizlik hesabatı və ya export yaratmaq\n"
            "- GDPR, PCI-DSS və ISO 27001 kimi uyğunluq təsirlərini yoxlamaq\n\n"
            "İngilis və ya Azərbaycan dilində soruşa bilərsiniz."
        ),
    },
    {
        "patterns": [
            r"kimisen",
            r"kimisin",
            r"sen kimsen",
            r"who are you",
            r"what are you",
        ],
        "en": "I'm the DSPM AI Security Copilot, an assistant built into your dashboard to help analyze security findings from your data scans.",
        "az": "Mən DSPM AI Təhlükəsizlik Köməkçisiyəm. Data skanlarınızdan gələn təhlükəsizlik tapıntılarını təhlil etmək üçün idarə panelinizdə işləyirəm.",
    },
    {
        "patterns": [
            r"^(cox )?sag ol",
            r"^(cox )?tesekkur",
            r"^thank",
            r"^thanks",
            r"^thx",
        ],
        "en": "You're welcome! Let me know if you need anything else.",
        "az": "Xahiş edirəm! Başqa bir şey lazım olsa, bildirin.",
    },
    {
        "patterns": [
            r"^tamam$",
            r"^ok\b",
            r"^okay\b",
            r"^anladim",
            r"^basa dusdum",
            r"^got it",
            r"^understood",
            r"^clear",
        ],
        "en": "Got it. What would you like to do next?",
        "az": "Başa düşdüm. Növbəti nə etmək istəyirsiniz?",
    },
    {
        "patterns": [
            r"isleyirsan",
            r"isleyirsen",
            r"isleyir",
            r"calisir",
            r"calisirsan",
            r"aktivsen",
            r"aktivsən",
            r"burdasan",
            r"burda san",
            r"ordasan",
            r"are you working",
            r"are you active",
            r"are you there",
            r"is it working",
            r"do you work",
            r"can you work",
            r"is the copilot",
            r"is the assistant",
        ],
        "en": "Yes, I'm working. I can help with DSPM scan summaries, findings, risk explanations, and remediation steps.",
        "az": "Bəli, işləyirəm. DSPM scan, finding, risk və remediation suallarında kömək edə bilərəm.",
    },
    {
        "patterns": [
            r"^test$",
            r"^he$",
            r"^hə$",
            r"^yox$",
            r"^no$",
            r"^yes$",
            r"^hmm$",
        ],
        "en": "Ready to help. What would you like to check in your DSPM data?",
        "az": "Kömək etməyə hazıram. DSPM məlumatlarınızda nə yoxlamaq istəyirsiniz?",
    },
    {
        "patterns": [
            r"bu ne demekdi",
            r"bu ne toyreyir",
            r"ne yazmisan onu anlamadim",
            r"neyi yazmisan",
            r"ne dedin",
            r"sen ne dedin",
            r"ne demek istedin",
            r"basa dusmedim",
            r"anlamadim",
            r"dediklerini anlamadim",
        ],
        "en": "I apologize if my previous answer was unclear. I can show findings and recommendations together when you ask for them.",
        "az": "Üzr istəyirəm, əvvəlki cavabım aydın olmamışdı. İstədiyiniz zaman tapıntıları və tövsiyələri birlikdə göstərə bilərəm.",
    },
    {
        "patterns": [
            r"dediklerimi anlamirsan",
            r"anlamirsan",
            r"anlayabilmirsen",
            r"basa dusmursen",
            r"sen dediklerimi yaxsi anlayabilmirsen",
            r"mence sen dediklerimi yaxsi anlayabilmirsen",
            r"eyni anda birden artiq is",
            r"beraber isleye bilmirsen",
            r"birlikde ede bilmirsen",
        ],
        "en": "I apologize for the confusion. I can handle multiple DSPM tasks in one message. For example, I can show 3 critical findings and provide a recommendation for each one together.",
        "az": "Üzr istəyirəm, sizi düzgün başa düşmədim. Bir mesajda bir neçə DSPM tapşırığını birlikdə yerinə yetirə bilərəm. Məsələn, 3 kritik tapıntını göstərib hər biri üçün tövsiyəni birlikdə verə bilərəm.",
    },
    {
        "patterns": [
            r"uzr istiyirem",
            r"ozur dilerim",
            r"bagislayin",
            r"dogru deyil",
            r"yanlish cavab",
            r"duzgun cavab deyil",
        ],
        "en": "I apologize. Let me provide the correct information.",
        "az": "Üzr istəyirəm. Düzgün məlumat verirəm.",
    },
    {
        "patterns": [
            r"yeniden cehd edirəm",
            r"yeniden sinayiram",
            r"tekrar deneyelim",
        ],
        "en": "Let me try again with the correct information.",
        "az": "Düzgün məlumatla yenidən cəhd edirəm.",
    },
]
