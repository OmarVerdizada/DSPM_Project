"""Deterministic, type-aware remediation policy for DSPM findings.

This module maps detected risk types (e.g. ``private_key``, ``email``,
``credit_card``, ``ml_finance_context``) to category-appropriate remediation
actions. It is intentionally deterministic and evidence-based: it never calls
the LLM, never invents risk types, and never recommends secret rotation unless
a credential/secret type is actually present.

Supported languages: ``az`` (primary), ``en``, ``ru``.
"""
from __future__ import annotations

import re


# --- Risk-type category membership -----------------------------------------
# Credential / secret material — the only category where rotate/revoke applies.
CREDENTIAL_TYPES = {
    "private_key",
    "private_key_exposure",
    "api_key",
    "api_key_exposure",
    "jwt",
    "jwt_token",
    "jwt_token_exposure",
    "password",
    "password_exposure",
    "connection_string",
    "connection_string_exposure",
    "token",
    "token_exposure",
    "secret",
    "secret_exposure",
    "access_key",
    "secret_key",
    "client_secret",
    "bearer_token",
    "aws_access_key",
    "azure_access_token",
    "gcp_key",
    "ssh_key",
    "credential",
}

# Personal / contact data — masking, minimization, access review (never rotate).
PERSONAL_TYPES = {
    "email",
    "email_exposure",
    "phone_number",
    "phone",
    "pii",
    "pii_exposure",
    "personal_data",
    "national_id",
    "passport",
    "ssn",
    "address",
    "date_of_birth",
}

# Financial / payment data — masking, tokenization, PCI/banking compliance.
FINANCIAL_TYPES = {
    "credit_card",
    "credit_card_exposure",
    "iban",
    "bank_account",
    "payment_card",
    "financial_data",
    "card_number",
    "swift",
    "bic",
    "cvv",
}

# Confidential / business classification — labels, DLP, access control.
CONFIDENTIAL_TYPES = {
    "confidential_keyword",
    "restricted",
    "internal_only",
    "sensitive_keyword",
    "confidential",
    "classified",
    "proprietary",
}

# ML / contextual risk — governance, access review, retention (never rotate).
CONTEXT_TYPES = {
    "ml_finance_context",
    "ml_hr_context",
    "payroll_context",
    "ml_sensitive_context",
    "hr_context",
    "finance_context",
    "ml_context",
}

# Category priority order. Credential first so rotation, when valid, leads.
CATEGORY_ORDER = ["credential", "financial", "personal", "confidential", "context"]

_CATEGORY_MEMBERS: dict[str, set[str]] = {
    "credential": CREDENTIAL_TYPES,
    "financial": FINANCIAL_TYPES,
    "personal": PERSONAL_TYPES,
    "confidential": CONFIDENTIAL_TYPES,
    "context": CONTEXT_TYPES,
}


def normalize_type(value: object) -> str:
    """Normalize a raw risk-type token to a comparable snake_case string."""
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def category_for_type(risk_type: object) -> str:
    normalized = normalize_type(risk_type)
    for category in CATEGORY_ORDER:
        if normalized in _CATEGORY_MEMBERS[category]:
            return category
    return "unknown"


def categorize_risk_types(risk_types: list[str] | None) -> list[str]:
    """Return the distinct categories present, in priority order.

    An empty/None input, or types that match no known category, yields
    ``["unknown"]`` so callers fall back to cautious guidance.
    """
    present: set[str] = set()
    for risk_type in risk_types or []:
        present.add(category_for_type(risk_type))
    ordered = [category for category in CATEGORY_ORDER if category in present]
    if not ordered:
        return ["unknown"]
    # Preserve "unknown" only when it is the sole signal.
    return ordered


def has_credential_type(risk_types: list[str] | None) -> bool:
    return "credential" in categorize_risk_types(risk_types)


# --- Localized step text ----------------------------------------------------
# Each step has a stable key (used for deduplication) plus per-language text.
_STEPS: dict[str, dict[str, str]] = {
    "verify": {
        "az": "Təsdiqlə: faylda həqiqətən hansı həssas məlumatın olduğunu yoxla.",
        "en": "Confirm what sensitive data the file actually contains.",
        "ru": "Подтвердите, какие именно чувствительные данные содержит файл.",
    },
    "restrict_access": {
        "az": "Girişi məhdudlaşdır: fayla yalnız ehtiyacı olan rollar çıxış etsin (least privilege).",
        "en": "Restrict access so only roles that truly need the file keep it (least privilege).",
        "ru": "Ограничьте доступ: оставьте его только для ролей, которым он действительно нужен (least privilege).",
    },
    # credential
    "cred_revoke": {
        "az": "İfşa olunmuş credential/secret/token/açarı dərhal revoke və ya rotate et.",
        "en": "Immediately revoke or rotate the exposed credential, secret, token, or key.",
        "ru": "Немедленно отзовите или ротируйте раскрытый credential, secret, token или ключ.",
    },
    "cred_remove": {
        "az": "Həssas dəyəri fayldan çıxar və onu secret manager-də saxla.",
        "en": "Remove the sensitive value from the file and store it in a secret manager.",
        "ru": "Удалите чувствительное значение из файла и храните его в secret manager.",
    },
    "cred_update_services": {
        "az": "Bu credential-dan istifadə edən servisləri təhlükəsiz şəkildə yenilə.",
        "en": "Securely update the services that use this credential.",
        "ru": "Безопасно обновите сервисы, которые используют этот credential.",
    },
    # financial
    "fin_mask": {
        "az": "Kart və ya hesab nömrələrini maskala və ya tokenize et.",
        "en": "Mask or tokenize the card or account numbers.",
        "ru": "Замаскируйте или токенизируйте номера карт или счетов.",
    },
    "fin_compliance": {
        "az": "PCI DSS / bank tənzimləmə təsirini compliance komandası ilə nəzərdən keçir.",
        "en": "Review the PCI DSS / banking-regulation impact with the compliance team.",
        "ru": "Оцените влияние на соответствие PCI DSS / банковским нормам с командой compliance.",
    },
    "fin_remove_copies": {
        "az": "Lazımsız maliyyə məlumatı surətlərini sil və saxlanma müddətini yoxla.",
        "en": "Remove unnecessary copies of the financial data and check retention.",
        "ru": "Удалите лишние копии финансовых данных и проверьте срок хранения.",
    },
    # personal
    "pii_minimize": {
        "az": "Məlumatı minimuma endir: yalnız həqiqətən lazım olan sahələri saxla.",
        "en": "Minimize the data: keep only the fields that are truly required.",
        "ru": "Минимизируйте данные: оставьте только действительно необходимые поля.",
    },
    "pii_mask": {
        "az": "Şəxsi məlumatı maskala və ya anonimləşdir.",
        "en": "Mask or anonymize the personal data.",
        "ru": "Замаскируйте или анонимизируйте персональные данные.",
    },
    "pii_sharing": {
        "az": "Paylaşımı və saxlanma (retention) müddətini nəzərdən keçir.",
        "en": "Review sharing and retention of the data.",
        "ru": "Пересмотрите совместный доступ и срок хранения данных.",
    },
    # confidential
    "conf_classify": {
        "az": "Təsnifatı təsdiqlə: sənədin həqiqətən məxfi/məhdud olduğunu yoxla.",
        "en": "Confirm the classification: verify the document is genuinely confidential or restricted.",
        "ru": "Подтвердите классификацию: убедитесь, что документ действительно конфиденциальный или ограниченный.",
    },
    "conf_labels": {
        "az": "Uyğun label/DLP qaydasını tətbiq et.",
        "en": "Apply the appropriate label and DLP rule.",
        "ru": "Примените соответствующую метку и правило DLP.",
    },
    "conf_public": {
        "az": "Faylı açıq və ya geniş paylaşılan yerlərdən çıxar.",
        "en": "Remove the file from public or broadly shared locations.",
        "ru": "Уберите файл из публичных или широко доступных мест.",
    },
    # context (ml / hr / finance / payroll)
    "ctx_owner": {
        "az": "Biznes sahibi (data owner) ilə giriş və istifadəni nəzərdən keçir.",
        "en": "Review access and usage with the business owner (data owner).",
        "ru": "Пересмотрите доступ и использование вместе с владельцем данных (data owner).",
    },
    "ctx_least_priv": {
        "az": "Least-privilege tətbiq et və paylaşımı audit et.",
        "en": "Apply least privilege and audit sharing.",
        "ru": "Примените least privilege и проведите аудит совместного доступа.",
    },
    "ctx_retention": {
        "az": "Saxlanma (retention) siyasətini nəzərdən keçir və lazımsız məlumatı minimuma endir.",
        "en": "Review the retention policy and minimize unnecessary data.",
        "ru": "Пересмотрите политику хранения и минимизируйте лишние данные.",
    },
    # unknown / cautious
    "unknown_verify": {
        "az": "Əvvəlcə məlumatın tipini dəqiqləşdir: bu faylda hansı həssas məlumatın olduğunu təsdiqlə.",
        "en": "First verify the data type: confirm what sensitive data this file holds.",
        "ru": "Сначала определите тип данных: подтвердите, что за чувствительные данные в файле.",
    },
    "unknown_minimize": {
        "az": "Girişi məhdudlaşdır, məlumatı minimuma endir və ya maskala.",
        "en": "Restrict access and minimize or mask the data.",
        "ru": "Ограничьте доступ и минимизируйте или замаскируйте данные.",
    },
    # trailing (always)
    "clean_or_mask": {
        "az": "Faylı təmizlə və ya həssas dəyəri maskala.",
        "en": "Clean the file or mask the sensitive value.",
        "ru": "Очистите файл или замаскируйте чувствительное значение.",
    },
    "rescan": {
        "az": "Yenidən scan et və tapıntının aradan qalxdığını təsdiqlə.",
        "en": "Re-scan and confirm the finding is gone.",
        "ru": "Запустите повторный scan и убедитесь, что finding исчез.",
    },
    "prevention": {
        "az": "Qarşısını almaq üçün DLP / secret scanning / classification qaydası əlavə et.",
        "en": "Add a DLP / secret-scanning / classification rule to prevent recurrence.",
        "ru": "Добавьте правило DLP / secret scanning / classification, чтобы предотвратить повтор.",
    },
}

_CATEGORY_STEP_KEYS: dict[str, list[str]] = {
    "credential": ["cred_revoke", "cred_remove", "cred_update_services"],
    "financial": ["fin_mask", "fin_compliance", "fin_remove_copies"],
    "personal": ["pii_minimize", "pii_mask", "pii_sharing"],
    "confidential": ["conf_classify", "conf_labels", "conf_public"],
    "context": ["ctx_owner", "ctx_least_priv", "ctx_retention"],
    "unknown": ["unknown_verify", "unknown_minimize"],
}


def _lang(language: str) -> str:
    return language if language in {"az", "en", "ru"} else "en"


def _step_keys_for_types(risk_types: list[str] | None) -> list[str]:
    """Ordered, deduplicated remediation step keys for the given risk types."""
    categories = categorize_risk_types(risk_types)
    keys: list[str] = ["verify", "restrict_access"]

    if categories == ["unknown"]:
        keys = ["unknown_verify", "restrict_access", "unknown_minimize"]
    else:
        for category in CATEGORY_ORDER:
            if category in categories:
                keys.extend(_CATEGORY_STEP_KEYS[category])

    keys.extend(["clean_or_mask", "rescan", "prevention"])

    seen: set[str] = set()
    ordered: list[str] = []
    for key in keys:
        if key not in seen:
            seen.add(key)
            ordered.append(key)
    return ordered


def build_remediation_steps_for_types(risk_types: list[str] | None, language: str = "az") -> list[str]:
    """Return ordered, deduplicated, localized remediation step sentences."""
    lang = _lang(language)
    return [_STEPS[key][lang] for key in _step_keys_for_types(risk_types)]


def remediation_checklist(risk_types: list[str] | None, language: str = "az") -> list[str]:
    """Return a localized verification checklist tuned to the risk categories."""
    lang = _lang(language)
    categories = categorize_risk_types(risk_types)
    items_by_lang = {
        "az": {
            "access": "Access review edildi",
            "sharing": "Lazımsız paylaşım bağlandı",
            "mask": "Məlumat maskalandı/təmizləndi",
            "credential": "Credential rotate/revoke edildi",
            "compliance": "Maliyyə compliance (PCI/bank) təsiri yoxlanıldı",
            "rescan": "Yenidən scan edildi",
        },
        "en": {
            "access": "Access review completed",
            "sharing": "Unnecessary sharing closed",
            "mask": "Data masked/cleaned",
            "credential": "Credential rotated/revoked",
            "compliance": "Financial compliance (PCI/banking) impact reviewed",
            "rescan": "Re-scanned",
        },
        "ru": {
            "access": "Проведён access review",
            "sharing": "Закрыт лишний совместный доступ",
            "mask": "Данные замаскированы/очищены",
            "credential": "Credential ротирован/отозван",
            "compliance": "Оценено влияние на финансовый compliance (PCI/банк)",
            "rescan": "Выполнен повторный scan",
        },
    }
    labels = items_by_lang[lang]
    checklist = [labels["access"], labels["sharing"], labels["mask"]]
    if "credential" in categories:
        checklist.append(labels["credential"])
    if "financial" in categories:
        checklist.append(labels["compliance"])
    checklist.append(labels["rescan"])
    return [f"- [ ] {item}" for item in checklist]


# --- Explanations -----------------------------------------------------------
_WHAT_IT_MEANS: dict[str, dict[str, str]] = {
    "credential": {
        "az": "Faylda credential, secret, token və ya açar aşkarlanıb — bunlar birbaşa giriş verə bilər.",
        "en": "The file exposes a credential, secret, token, or key that can grant direct access.",
        "ru": "В файле раскрыт credential, secret, token или ключ, дающий прямой доступ.",
    },
    "financial": {
        "az": "Faylda ödəniş/maliyyə məlumatı (kart, IBAN, hesab) var və tənzimləməyə tabedir.",
        "en": "The file contains payment/financial data (card, IBAN, account) that is regulated.",
        "ru": "Файл содержит платёжные/финансовые данные (карта, IBAN, счёт), подпадающие под регулирование.",
    },
    "personal": {
        "az": "Faylda şəxsi məlumat (PII) var — məxfilik və tənzimləmə riski yaradır.",
        "en": "The file contains personal data (PII), creating privacy and regulatory risk.",
        "ru": "Файл содержит персональные данные (PII), создавая риск приватности и регулирования.",
    },
    "confidential": {
        "az": "Fayl məxfi/məhdud biznes məlumatı kimi işarələnib və nəzarətə ehtiyacı var.",
        "en": "The file is flagged as confidential/restricted business content that needs controls.",
        "ru": "Файл помечен как конфиденциальный/ограниченный бизнес-контент и требует контроля.",
    },
    "context": {
        "az": "Fayl həssas biznes kontekstidir (maliyyə/HR/payroll) — idarəetmə və giriş nəzarəti tələb edir.",
        "en": "The file is a sensitive business context (finance/HR/payroll) needing governance and access control.",
        "ru": "Файл — чувствительный бизнес-контекст (финансы/HR/payroll), требующий governance и контроля доступа.",
    },
    "unknown": {
        "az": "Aşkarlanan risk tipi qeydə alınmayıb, ona görə əvvəlcə məlumatın tipini təsdiqləmək lazımdır.",
        "en": "The detected risk type is not recorded, so the data type must be verified first.",
        "ru": "Тип риска не зафиксирован, поэтому сначала нужно подтвердить тип данных.",
    },
}

_WHY_IT_MATTERS: dict[str, dict[str, str]] = {
    "credential": {
        "az": "Sızarsa, icazəsiz giriş, token sui-istifadəsi və ya credential təkrar istifadəsi mümkün olur.",
        "en": "If leaked, it can enable unauthorized access, token misuse, or credential reuse.",
        "ru": "При утечке возможен несанкционированный доступ, злоупотребление token или повторное использование credential.",
    },
    "financial": {
        "az": "Ödəniş məlumatının ifşası fırıldaqçılıq və PCI/bank compliance pozuntusu riski yaradır.",
        "en": "Exposed payment data risks fraud and PCI/banking compliance violations.",
        "ru": "Раскрытие платёжных данных грозит мошенничеством и нарушением PCI/банковского compliance.",
    },
    "personal": {
        "az": "İcazəsiz paylaşım GDPR/məxfilik pozuntusu, hüquqi iddia və reputasiya zərəri yarada bilər.",
        "en": "Unauthorized sharing can cause GDPR/privacy violations, legal claims, and reputational damage.",
        "ru": "Несанкционированный доступ грозит нарушением GDPR/приватности, исками и репутационным ущербом.",
    },
    "confidential": {
        "az": "Məxfi məzmunun sızması rəqabət, hüquqi və reputasiya zərəri yarada bilər.",
        "en": "Leaking confidential content can cause competitive, legal, and reputational harm.",
        "ru": "Утечка конфиденциального контента грозит конкурентным, юридическим и репутационным ущербом.",
    },
    "context": {
        "az": "Zəif giriş nəzarəti həssas biznes məlumatına icazəsiz baxış və sui-istifadə riski yaradır.",
        "en": "Weak access control risks unauthorized viewing and misuse of sensitive business data.",
        "ru": "Слабый контроль доступа грозит несанкционированным просмотром и злоупотреблением бизнес-данными.",
    },
    "unknown": {
        "az": "Tip təsdiqlənməyincə yanlış remediation tətbiq etmək riski var, ona görə ehtiyatlı olmaq lazımdır.",
        "en": "Until the type is verified there is a risk of applying the wrong remediation, so caution is needed.",
        "ru": "Пока тип не подтверждён, есть риск применить неверную remediation, поэтому нужна осторожность.",
    },
}


def _primary_category(risk_types: list[str] | None) -> str:
    return categorize_risk_types(risk_types)[0]


def what_it_means(risk_types: list[str] | None, language: str = "az") -> str:
    lang = _lang(language)
    categories = categorize_risk_types(risk_types)
    parts = [_WHAT_IT_MEANS[category][lang] for category in categories]
    return " ".join(parts)


def why_it_matters(risk_types: list[str] | None, language: str = "az") -> str:
    lang = _lang(language)
    categories = categorize_risk_types(risk_types)
    parts = [_WHY_IT_MATTERS[category][lang] for category in categories]
    return " ".join(parts)


def risk_explanation_for_types(risk_types: list[str] | None, language: str = "az") -> str:
    """Backwards-compatible single-line risk explanation (keeps 'Risklidir')."""
    lang = _lang(language)
    if lang == "az":
        return f"Risklidir: {why_it_matters(risk_types, 'az')}"
    if lang == "ru":
        return f"Это рискованно: {why_it_matters(risk_types, 'ru')}"
    return f"It is risky: {why_it_matters(risk_types, 'en')}"


# --- Short one-line recommendation (for list routes) ------------------------
_SHORT_RECS: dict[str, dict[str, str]] = {
    "credential": {
        "az": "credential/secret/token/açarı revoke və ya rotate et, fayldan çıxar və girişi məhdudlaşdır",
        "en": "revoke or rotate the credential/secret/token/key, remove it from the file, and restrict access",
        "ru": "отзовите или ротируйте credential/secret/token/ключ, удалите из файла и ограничьте доступ",
    },
    "financial": {
        "az": "maliyyə məlumatını maskala/tokenize et, girişi məhdudlaşdır və PCI/bank compliance təsirini yoxla",
        "en": "mask/tokenize the financial data, restrict access, and review PCI/banking compliance impact",
        "ru": "замаскируйте/токенизируйте финансовые данные, ограничьте доступ и оцените PCI/банковский compliance",
    },
    "personal": {
        "az": "şəxsi məlumatı minimuma endir, maskala və paylaşımı/girişi nəzərdən keçir",
        "en": "minimize the personal data, mask it, and review sharing/access",
        "ru": "минимизируйте персональные данные, замаскируйте и пересмотрите доступ",
    },
    "confidential": {
        "az": "təsnifatı təsdiqlə, label/DLP tətbiq et və faylı açıq yerlərdən çıxar",
        "en": "confirm the classification, apply labels/DLP, and remove the file from public locations",
        "ru": "подтвердите классификацию, примените метки/DLP и уберите файл из публичных мест",
    },
    "context": {
        "az": "giriş və istifadəni data owner ilə nəzərdən keçir, least-privilege tətbiq et və retention-u yoxla",
        "en": "review access and usage with the data owner, apply least privilege, and check retention",
        "ru": "пересмотрите доступ и использование с data owner, примените least privilege и проверьте retention",
    },
    "unknown": {
        "az": "əvvəlcə məlumat tipini təsdiqlə, girişi məhdudlaşdır, minimuma endir/maskala",
        "en": "first verify the data type, restrict access, and minimize/mask the data",
        "ru": "сначала подтвердите тип данных, ограничьте доступ и минимизируйте/замаскируйте данные",
    },
}


def short_recommendation_for_types(risk_types: list[str] | None, language: str = "az") -> str:
    """One-line, type-aware recommendation used by concise list renderers."""
    lang = _lang(language)
    categories = categorize_risk_types(risk_types)
    parts = [_SHORT_RECS[category][lang] for category in categories]
    rescan = {"az": "sonra yenidən scan et", "en": "then re-scan", "ru": "затем выполните повторный scan"}[lang]
    joined = "; ".join(parts)
    return f"{joined}; {rescan}"
