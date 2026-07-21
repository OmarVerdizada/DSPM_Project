from __future__ import annotations

import logging
import re
from collections.abc import Awaitable, Callable

from backend.copilot.az_vocabulary import apply_az_corrections, apply_az_security_vocabulary, az_quality_failed, az_translation_quality_failed
from backend.copilot.guardrails import FALLBACK_ANSWER, FALLBACK_ANSWER_AZ, clean_answer_text, provider_unavailable_answer
from backend.copilot.llm_client import LLMError, call_ollama

_log = logging.getLogger(__name__)


AZ_QUALITY_FALLBACK_NOTE = (
    "Azerbaijani output quality is currently unreliable with the local model, "
    "so I am showing the answer in English to avoid incorrect wording."
)

LANGUAGE_CAPABILITY_EN = (
    "Yes, I can answer in Azerbaijani. I automatically detect your messages and translate my answers into Azerbaijani. "
    "File names, scan IDs, CRITICAL/HIGH severity values, and technical terms like private_key and jwt may stay unchanged."
)

LANGUAGE_CAPABILITY_AZ = (
    "Bəli, Azərbaycan dilində cavab verə bilərəm. Mesajlarınızı avtomatik tanıyıram və cavablarımı Azərbaycan dilinə tərcümə edirəm. "
    "Fayl adları, scan ID-lər, CRITICAL/HIGH kimi ciddilik dərəcələri və private_key, jwt kimi texniki terminlər dəyişmədən saxlanıla bilər."
)

Provider = Callable[..., Awaitable[str]]


TRANSLATION_SYSTEM = (
    "/no_think\n\n"
    "You are a professional Azerbaijani translator for cybersecurity and DSPM content. "
    "Translate English into correct, natural Azerbaijani. Output only the Azerbaijani translation."
)

TRANSLATION_PROMPT = """Translate the English text into correct, natural Azerbaijani.

Rules:
- Output only Azerbaijani translation.
- Preserve file names, scan IDs, JSON/YAML names, severity values, risk scores, and technical identifiers.
- Keep CRITICAL, HIGH, MEDIUM, LOW unchanged unless the surrounding sentence naturally uses Azerbaijani.
- Keep private_key, jwt, api_key, password unchanged.
- Use correct Azerbaijani grammar.
- Do not mix Russian.
- Do not mix Turkish.
- Do not leave normal English words inside Azerbaijani sentences.
- Keep numbered lists and bullet formatting.

English text:
{english_text}
"""

STRICT_TRANSLATION_PROMPT = TRANSLATION_PROMPT + (
    "\nThe previous translation attempt was rejected for broken Azerbaijani. "
    "Use natural Azerbaijani only and avoid words like tilində, xox, previous, röportlarda, cevaplayarak.\n"
)

STRICT_TRANSLATION_PROMPT += (
    "Output ONLY Azerbaijani. "
    "Do not use English words except technical identifiers. "
    "Do not use Russian or Turkish words. "
    "Preserve file names, scan IDs, CRITICAL/HIGH, private_key, jwt.\n"
)


def deterministic_az_translation(english_text: str) -> str | None:
    text = clean_answer_text(english_text)
    if not text:
        return None
    exact_phrases = {
        "critical findings found": "Kritik tapıntılar tapıldı",
        "no critical findings found": "Kritik tapıntı tapılmadı",
        "no issues detected": "Problem aşkar edilmədi",
        "remediation steps": "Remediation addımları",
        "recommended actions": "Tövsiyə olunan addımlar",
        "scan completed": "Skan tamamlandı",
        "latest scan": "Son skan",
        "risk score": "Risk balı",
        "detected types": "Aşkar edilmiş növlər",
        "source": "Mənbə",
        "evidence": "Sübut",
        "severity": "Ciddilik",
        "critical": "Kritik",
        "high": "Yüksək",
        "medium": "Orta",
        "low": "Aşağı",
        "dashboard summary": "Dashboard xülasəsi",
        "executive summary": "İcraçı xülasə",
        "report generated": "Hesabat yaradıldı",
        "report generation is not available": "Hesabat yaratmaq hazırda mümkün deyil",
        "i can help with your dspm findings": "DSPM tapıntılarınızla bağlı kömək edə bilərəm",
        "i can list findings, explain risks, suggest remediation, compare scans, and summarize dashboard posture": (
            "Tapıntıları göstərə, riskləri izah edə, remediation tövsiyələri verə, "
            "skanları müqayisə edə və dashboard xülasəsi hazırlaya bilərəm"
        ),
        "i could not find enough evidence for that request": "Bu sorğu üçün kifayət qədər sübut tapa bilmədim",
        "please clarify which finding you mean": "Zəhmət olmasa hansı tapıntını nəzərdə tutduğunuzu dəqiqləşdirin",
    }
    phrasebook_additions = {
        "critical findings found": "kritik tapıntılar aşkarlandı",
        "no critical findings": "kritik tapıntı yoxdur",
        "high severity": "yüksək təhlükə",
        "medium severity": "orta təhlükə",
        "low severity": "aşağı təhlükə",
        "no issues detected": "problem aşkarlanmadı",
        "findings sorted by severity": "tapıntılar təhlükə səviyyəsinə görə sıralanıb",
        "remediation steps": "düzəliş addımları",
        "recommended actions": "tövsiyə olunan tədbirlər",
        "rotate the key immediately": "açarı dərhal dəyişdirin",
        "revoke the token": "tokeni ləğv edin",
        "update the password": "şifrəni yeniləyin",
        "restrict access permissions": "giriş icazələrini məhdudlaşdırın",
        "remove public access": "ictimai girişi silin",
        "encrypt sensitive data": "həssas məlumatları şifrələyin",
        "scan completed successfully": "skan uğurla tamamlandı",
        "scan in progress": "skan davam edir",
        "last scan": "son skan",
        "no changes detected": "dəyişiklik aşkarlanmadı",
        "new findings since last scan": "son skandan bəri yeni tapıntılar",
        "compared to previous scan": "əvvəlki skanla müqayisədə",
        "high risk assets": "yüksək riskli aktivlər",
        "exposed assets": "açıq qalan aktivlər",
        "total assets scanned": "skan edilmiş ümumi aktivlər",
        "here are the results": "nəticələr budur",
        "i found the following": "aşağıdakıları tapdım",
        "no results found": "nəticə tapılmadı",
        "would you like more details": "daha ətraflı məlumat istəyirsiniz",
        "is there anything else": "başqa sualınız var",
        "i can help you with": "sizə bunlarda kömək edə bilərəm",
    }
    for source, target in phrasebook_additions.items():
        exact_phrases.setdefault(source, target)
    exact = exact_phrases.get(text.lower().strip(" ."))
    if exact:
        return exact
    if text == FALLBACK_ANSWER:
        return FALLBACK_ANSWER_AZ
    if text == LANGUAGE_CAPABILITY_EN:
        return LANGUAGE_CAPABILITY_AZ
    if text == "I will answer in Azerbaijani.":
        return "Azərbaycanca cavab verəcəyəm."
    if text == "I will answer in English.":
        return "İngiliscə cavab verəcəyəm."
    if text.startswith("Mən bacarıram:") or text.startswith("M\u0259n bacarıram:"):
        return text
    if text.startswith("Mən DSPM Köməkçisiyəm"):
        return text
    if text.startswith("Bəli, işləyirəm"):
        return text

    lines = text.splitlines()
    translated: list[str] = []
    handled = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            translated.append("")
            continue
        if stripped == "The current data stores these as critical findings/files, not separate alert objects.":
            translated.append("Mövcud datada bunlar ayrıca xəbərdarlıq obyekti kimi yox, kritik tapıntı/fayl kimi saxlanılır.")
            handled = True
            continue
        if stripped == "Latest scan severity distribution:":
            translated.append("Son skan severity bölgüsü:")
            handled = True
            continue
        if stripped.startswith("Scan: "):
            translated.append(stripped.replace("Scan:", "Skan:", 1))
            handled = True
            continue
        if stripped == "Top risk types:":
            translated.append("Əsas risk tipləri:")
            handled = True
            continue
        if re.match(r"- (?:CRITICAL|HIGH|MEDIUM|LOW): \d+", stripped):
            translated.append(stripped)
            handled = True
            continue
        if stripped.startswith("- ") and ":" in stripped:
            translated.append(stripped)
            handled = True
            continue
        match = re.match(r"There are (\d+) alert summary rows, but the latest scan contains (\d+) critical findings/files\.", stripped)
        if match:
            translated.append(
                f"{match.group(1)} xəbərdarlıq xülasəsi sətri var, amma son skanda {match.group(2)} kritik tapıntı/fayl saxlanılır."
            )
            handled = True
            continue
        match = re.match(r"Scan checked: (.+?)\. Total critical findings/files: (\d+)\. Showing (\d+)\.", stripped)
        if match:
            translated.append(f"Yoxlanılan skan: {match.group(1)}. Ümumi kritik tapıntı/fayl: {match.group(2)}. Göstərilən: {match.group(3)}.")
            handled = True
            continue
        match = re.match(r"(\d+)\. (.+?) - severity ([A-Z]+), risk score ([^,]+)(?:, type (.+))?", stripped)
        if match:
            suffix = f", tip {match.group(5)}" if match.group(5) else ""
            translated.append(
                f"{match.group(1)}. {match.group(2)} - ciddilik dərəcəsi {match.group(3)}, risk skoru {match.group(4)}{suffix}"
            )
            handled = True
            continue
        if stripped == "Recommended next step: restrict access, rotate confirmed exposed keys/tokens, and re-scan after remediation.":
            translated.append("Tövsiyə olunan növbəti addım: girişi məhdudlaşdır, təsdiqlənmiş ifşa olunmuş key/token-ləri rotate et və düzəlişdən sonra yenidən skan et.")
            handled = True
            continue
        replacements = {
            "Selected finding:": "Seçilmiş tapıntı:",
            "File:": "Fayl:",
            "Severity:": "Ciddilik dərəcəsi:",
            "Risk score:": "Risk skoru:",
            "Detected sensitive types:": "Aşkarlanan həssas məlumat tipləri:",
            "Recommended next step:": "Tövsiyə olunan növbəti addım:",
            "Why it matters:": "Niyə vacibdir:",
            "Impact:": "Təsir:",
            "Next steps:": "Növbəti addımlar:",
            "Unavailable fields are not inferred beyond the provided evidence.": "Mövcud sübutda olmayan sahələr uydurulmur.",
            "Detected sensitive values may expose credentials or regulated data.": "Aşkarlanan həssas dəyərlər credential-ları və ya tənzimlənən məlumatları ifşa edə bilər.",
            "Unauthorized access, token misuse, or credential reuse may be possible.": "İcazəsiz giriş, token sui-istifadəsi və ya credential təkrar istifadəsi mümkün ola bilər.",
            "Restrict access, rotate confirmed exposed secrets or tokens, and re-scan after remediation.": "Girişi məhdudlaşdır, təsdiqlənmiş ifşa olunmuş secret və ya token-ləri rotate et və düzəlişdən sonra yenidən skan et.",
        }
        phrase_replacements = {
            "detected sensitive values may expose credentials or regulated data.": "aşkarlanan həssas dəyərlər credential-ları və ya tənzimlənən məlumatları ifşa edə bilər.",
            "unauthorized access, token misuse, or credential reuse may be possible.": "icazəsiz giriş, token sui-istifadəsi və ya credential təkrar istifadəsi mümkün ola bilər.",
            "restrict access, rotate confirmed exposed secrets or tokens, and re-scan after remediation.": "girişi məhdudlaşdır, təsdiqlənmiş ifşa olunmuş secret və ya token-ləri rotate et və düzəlişdən sonra yenidən skan et.",
        }
        replaced = stripped
        for source, target in replacements.items():
            if replaced.startswith(source):
                replaced = replaced.replace(source, target, 1)
                handled = True
                break
        for source, target in phrase_replacements.items():
            replaced_next = re.sub(re.escape(source), target, replaced, flags=re.IGNORECASE)
            if replaced_next != replaced:
                replaced = replaced_next
                handled = True
        translated.append(apply_az_security_vocabulary(replaced))
    if not handled:
        return None
    value = "\n".join(translated).strip()
    return value


async def _call_translation_provider(provider: Provider, messages: list[dict[str, str]], temperature: float = 0.1) -> str:
    try:
        result = await provider(messages, options={"temperature": temperature}, task_type="translation")
    except TypeError:
        result = await provider(messages, options={"temperature": temperature})
    if not isinstance(result, str):
        raise LLMError("Translation provider returned a non-text response.", "TRANSLATION_INVALID_RESPONSE")
    return result


def _safe_az_translation_fallback(canonical: str) -> str:
    identifiers = re.findall(r"\b[A-Za-z0-9_.-]+\.(?:ya?ml|json|env|txt|csv|xml|pem|key|py|js|ts|md)\b", canonical)
    terms = [term for term in ("private_key", "jwt", "api_key", "password") if term in canonical]
    preserved = ", ".join(dict.fromkeys(identifiers + terms))
    _log.warning("AZ translation failed quality checks twice; returning evidence-preserving Azerbaijani fallback.")
    if (
        "local ai model is temporarily unavailable" in canonical.lower()
        or "local model is not responding" in canonical.lower()
        or "ollama" in canonical.lower()
    ):
        return provider_unavailable_answer("az")
    lines = ["Azərbaycanca cavab:"]
    if preserved:
        lines.append(f"Əsas texniki detallar: {preserved}.")
    compact = canonical.strip()
    if compact:
        lines.append(compact[:1200])
    return "\n".join(lines)

async def translate_to_azerbaijani(english_text: str, provider: Provider = call_ollama) -> str:
    canonical = clean_answer_text(english_text)
    deterministic = deterministic_az_translation(canonical)
    if deterministic:
        return deterministic

    messages = [
        {"role": "system", "content": TRANSLATION_SYSTEM},
        {"role": "user", "content": TRANSLATION_PROMPT.format(english_text=canonical)},
    ]
    try:
        first = apply_az_corrections(clean_answer_text(await _call_translation_provider(provider, messages, temperature=0.1)))
        failed, _reason = az_quality_failed(first, canonical)
        if not failed:
            return first

        retry_messages = [
            {"role": "system", "content": TRANSLATION_SYSTEM},
            {"role": "user", "content": STRICT_TRANSLATION_PROMPT.format(english_text=canonical)},
        ]
        retry = apply_az_corrections(clean_answer_text(await _call_translation_provider(provider, retry_messages, temperature=0.05)))
        failed, _reason = az_quality_failed(retry, canonical)
        if not failed:
            return retry
    except LLMError:
        pass

    return _safe_az_translation_fallback(canonical)
