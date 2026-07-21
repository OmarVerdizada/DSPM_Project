from __future__ import annotations


SUPPORTED_CAPABILITIES = (
    "scan_summary",
    "count_findings",
    "filter_findings",
    "top_risks",
    "scan_comparison",
    "remediation_guidance",
    "compliance_mapping",
    "audit_log_questions",
    "report_export_status",
)

UNSUPPORTED_CAPABILITIES = (
    "invent_missing_scan_data",
    "remote_model_calls_by_default",
    "write_remediation_without_evidence",
    "create_pdf_when_export_backend_is_unavailable",
)


# Concise, positive one-line capability answers. This is the default: it only
# says what the Copilot can do, without "supported/unsupported" sections or
# internal backend limitations. Limitations are shown only when the user
# explicitly asks about them (include_limitations=True).
_CONCISE_CAPABILITIES = {
    "en": (
        "I can help you understand DSPM scan results, explain findings, "
        "prioritize risky files, compare scans, and suggest remediation steps."
    ),
    "az": (
        "DSPM scan nəticələrini izah edə, tapıntıları prioritetləşdirə, "
        "riskli faylları göstərə və remediation addımları təklif edə bilərəm."
    ),
    "ru": (
        "Я могу объяснять результаты DSPM-сканирования, разбирать findings, "
        "приоритизировать рискованные файлы, сравнивать сканы и предлагать "
        "шаги remediation."
    ),
}


def asks_about_limitations(message: str) -> bool:
    """True when the user is asking what the Copilot cannot do / its limits."""
    text = (message or "").lower()
    return any(
        term in text
        for term in (
            "can't you", "cannot you", "can not you", "cant you", "what can't", "what cant",
            "can you not", "what can you not", "cannot do", "can't do", "cant do",
            "limitation", "limits", "unsupported", "not support", "what you can't",
            "bacarmirsan", "bacarmadigin", "məhdudiyyət", "mehdudiyyet", "dəstəklənmir", "desteklenmir",
            "не можешь", "ограничен",
        )
    )


def render_capabilities(language: str = "az", include_limitations: bool = False) -> str:
    """Render the capability answer.

    By default this is a concise, positive statement of what the Copilot can do.
    The verbose "supported/unsupported" breakdown is returned only when the user
    explicitly asks about limitations (``include_limitations=True``).
    """
    if not include_limitations:
        return _CONCISE_CAPABILITIES.get(language, _CONCISE_CAPABILITIES["en"])
    if language == "en":
        supported = [
            "I can list findings, count findings, and apply severity filters",
            "scan summaries and latest-scan evidence checks",
            "top-risk files/assets from available DSPM data",
            "scan comparison and remediation guidance",
            "compliance mapping and audit-log questions",
            "report/export status when the backend supports it",
        ]
        unsupported = [
            "inventing scan IDs, counts, findings, assets, or evidence",
            "using remote models by default",
            "creating a PDF file when export is not implemented",
        ]
        return (
            "Supported:\n- " + "\n- ".join(supported) +
            "\n\nUnsupported:\n- " + "\n- ".join(unsupported)
        )
    if language == "ru":
        supported_ru = [
            "считать findings и фильтровать их по severity",
            "показывать top-risk файлы и assets из доступных DSPM данных",
            "сравнивать scans и объяснять remediation steps",
            "показывать posture score, compliance mapping и audit-log вопросы",
            "показывать статус report/export, когда backend это поддерживает",
        ]
        unsupported_ru = [
            "придумывать scan IDs, counts, findings, assets или evidence",
            "использовать remote models по умолчанию",
            "утверждать, что PDF создан, если backend его не создал",
        ]
        return (
            "Я могу:\n- " + "\n- ".join(supported_ru) +
            "\n\nНе поддерживается:\n- " + "\n- ".join(unsupported_ru)
        )
    supported_az = [
        "scan xülasələri, finding sayları və severity filtrləri",
        "mövcud DSPM datasına əsasən ən riskli fayl və assetlər",
        "scan müqayisəsi və remediation tövsiyələri",
        "compliance mapping və audit log sualları",
        "backend dəstəklədikdə report/export statusu",
    ]
    unsupported_az = [
        "olmayan scan ID, say, finding, asset və evidence uydurmaq",
        "default olaraq remote model istifadə etmək",
        "export backend-i hazır deyilsə PDF faylı yaratdığını iddia etmək",
    ]
    return (
        "Dəstəklənir:\n- " + "\n- ".join(supported_az) +
        "\n\nDəstəklənmir:\n- " + "\n- ".join(unsupported_az)
    )
