"""Fact-free meta/correction/language answer renderers.

Extracted from ``service.py`` (P7 split): these are the deterministic
template answers for correction, meta-why, language-complaint, and
previous-answer situations. They contain no DSPM facts by construction —
the only renderer that mentions numbers (``render_count_conflict_text``)
receives them pre-computed from real evidence by the caller.

These drafts are the safe fallback (B-plan). Fact-free ones are eligible
for the controlled verbalizer (see ``task_types.FACT_FREE_META_TASKS``),
which may reword them without inventing facts.
"""
from __future__ import annotations


def render_count_conflict_text(mentioned: str, severity: str, canonical: str, language: str) -> str:
    if language == "en":
        return (
            f"The earlier number ({mentioned}) should not be treated as the canonical finding count. "
            f"The canonical metric for finding-count questions is file_level_finding_count: {severity} = {canonical}. "
            "I am not using selected-finding context for this reply."
        )
    if language == "ru":
        return (
            f"Предыдущее число ({mentioned}) не должно считаться каноническим count. "
            f"Канонический источник для count вопросов — severity count последнего scan: {severity} = {canonical}. "
            "В этом ответе я не использую контекст выбранной находки."
        )
    return (
        f"Əvvəlki rəqəm ({mentioned}) kanonik tapıntı sayı kimi qəbul edilməməlidir. "
        f"Tapıntı sayı suallarında kanonik mənbə son scan üzrə severity sayıdır: {severity} = {canonical}. "
        "Bu cavabda seçilmiş tapıntı kontekstindən istifadə etmirəm."
    )


def render_why_previous_answer(message: str, language: str) -> str:
    del message  # kept for signature compatibility with the service wrapper
    if language == "en":
        return (
            "That was a previous-answer/meta question, not a selected-finding question. "
            "I should explain the prior answer or correct the count route instead of reusing selected-finding context."
        )
    if language == "ru":
        return (
            "Это был meta вопрос о предыдущем ответе, а не вопрос о выбранной находке. "
            "Я должен объяснить предыдущий ответ или исправить count route, а не использовать контекст выбранной находки."
        )
    return (
        "Bu, seçilmiş tapıntı sualı yox, əvvəlki cavabla bağlı meta sual idi. "
        "Seçilmiş tapıntını yenidən izah etmək əvəzinə əvvəlki cavabı və ya count marşrutunu izah etməli idim."
    )


def render_wrong_route_complaint(language: str) -> str:
    if language == "en":
        return (
            "You are right: that was the wrong context. I should not have answered with selected-finding details. "
            "This reply does not use selected-finding context."
        )
    if language == "ru":
        return (
            "Вы правы: это был неправильный контекст. Я не должен был отвечать деталями выбранной находки. "
            "В этом ответе контекст выбранной находки не используется."
        )
    return (
        "Haqlısınız: bu, səhv kontekst idi. Seçilmiş tapıntının detallarını cavab kimi verməməli idim. "
        "Bu cavabda seçilmiş tapıntı kontekstindən istifadə etmirəm."
    )


def evidence_guard_clarification(language: str) -> str:
    if language == "az":
        return (
            "Alert, tapıntı və severity suallarına yalnız real scan məlumatı əsasında cavab verirəm. "
            "Severity bölgüsü, konkret severity üzrə say, yoxsa tapıntı siyahısı istəyirsiniz?"
        )
    if language == "ru":
        return (
            "На вопросы об alert, находках и severity я отвечаю только по реальным данным scan. "
            "Вам нужна разбивка по severity, count по одному severity или список находок?"
        )
    return (
        "I answer questions about alerts, findings, and severity from the actual scan data only. "
        "Do you want the severity breakdown, a count for one severity, or a list of findings?"
    )


LANGUAGE_COMPLAINT_ANSWERS: dict[str, str] = {
    "az": (
        "Haqlısınız, cavab Azərbaycan dilində olmalı idi. Bundan sonra seçilmiş dilə uyğun "
        "Azərbaycan dilində cavab verəcəyəm. İstəsəniz, əvvəlki cavabı da Azərbaycan dilində yenidən verə bilərəm."
    ),
    "en": (
        "You're right, the answer should match the selected language. I'll continue in English. "
        "If you'd like, I can also re-render the previous answer."
    ),
    "ru": (
        "Вы правы, ответ должен быть на выбранном языке. Дальше буду отвечать по-русски. "
        "При желании могу заново отобразить предыдущий ответ."
    ),
}

PREV_ANSWER_CANNOT_RECREATE: dict[str, str] = {
    "az": (
        "Əvvəlki cavabı tam yenidən yarada bilmirəm, çünki əvvəlki cavabın strukturlaşdırılmış məzmunu "
        "saxlanmayıb. Zəhmət olmasa həmin cavabı və ya sualı yenidən göndərin."
    ),
    "en": (
        "I cannot fully recreate the previous answer because its structured content was not stored. "
        "Please resend that answer or the question."
    ),
    "ru": (
        "Я не могу полностью воссоздать предыдущий ответ, так как его структурированное содержимое не сохранено. "
        "Пожалуйста, пришлите тот ответ или вопрос ещё раз."
    ),
}

NO_PREV_ANSWER: dict[str, str] = {
    "az": (
        "Yenidən vermək üçün əvvəlki cavab tapılmadı. Zəhmət olmasa tərcümə etmək istədiyiniz mətni "
        "və ya sualı göndərin."
    ),
    "en": "I could not find a previous answer to re-render. Please send the text or question you want translated.",
    "ru": "Не нашёл предыдущего ответа для повторного показа. Пришлите текст или вопрос для перевода.",
}
