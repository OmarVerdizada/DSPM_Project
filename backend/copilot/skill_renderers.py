"""Deterministic renderers for DSPM skills.

Each renderer converts structured tool/skill output into a user-facing
text answer without calling the LLM. All renderers support EN + AZ.
"""
from __future__ import annotations

import json
import re
from typing import Any

from backend.copilot.masking import mask_sensitive_text
from backend.copilot.remediation_policy import (
    build_remediation_steps_for_types,
    categorize_risk_types,
    remediation_checklist,
    short_recommendation_for_types,
    what_it_means,
    why_it_matters,
)


FINDING_EXPLANATIONS: dict[str, dict[str, dict[str, str]]] = {
    "private_key_exposure": {
        "en": {
            "what": "A private cryptographic key was found exposed in {location}.",
            "risk": "Private keys are used to decrypt data, authenticate servers, and sign code. An exposed private key allows an attacker to impersonate your systems, decrypt protected communications, and forge digital signatures.",
            "impact": "If exploited, an attacker could decrypt data encrypted with this key, perform man-in-the-middle attacks, sign malicious code as your organization, and access systems that trust this key.",
            "severity_justification": "This is rated critical because private key exposure enables immediate, direct compromise with no additional exploitation steps required.",
        },
        "az": {
            "what": "{location}-da açıq qalmış gizli kriptoqrafik açar aşkarlanıb.",
            "risk": "Gizli açarlar məlumatların şifrəsini açmaq, serverləri autentifikasiya etmək və kodu imzalamaq üçün istifadə olunur. Açıq qalan gizli açar hücumçuya sistemlərinizi təqlid etmək, qorunan kommunikasiyaları deşifrə etmək və rəqəmsal imzaları saxtalaşdırmaq imkanı verə bilər.",
            "impact": "İstismar edilərsə, hücumçu bu açarla şifrələnmiş məlumatları deşifrə edə, ortadakı adam hücumları həyata keçirə, zərərli kodu təşkilatınız adından imzalaya və bu açara etibar edən sistemlərə daxil ola bilər.",
            "severity_justification": "Bu kritik səviyyəli qiymətləndirilir, çünki gizli açar ifşası əlavə istismar addımları olmadan dərhal birbaşa kompromisə imkan verir.",
        },
    },
    "jwt_token_exposure": {
        "en": {
            "what": "A JSON Web Token (JWT) was found exposed in {location}.",
            "risk": "JWTs are authentication tokens that grant access to APIs and services. An exposed JWT allows an attacker to impersonate the token holder without needing a username or password.",
            "impact": "The attacker can access APIs, read or modify data, and perform actions as the authenticated user until the token expires or is revoked.",
            "severity_justification": "This is critical when the token has not expired and grants access to sensitive resources.",
        },
        "az": {
            "what": "{location}-da açıq qalmış JWT (JSON Web Token) aşkarlanıb.",
            "risk": "JWT-lər API-lərə və xidmətlərə giriş icazəsi verən autentifikasiya tokenləridir. Açıq qalmış JWT hücumçuya istifadəçi adı və ya şifrə olmadan token sahibini təqlid etmək imkanı verə bilər.",
            "impact": "Hücumçu token bitənə və ya ləğv edilənə qədər API-lərə daxil ola, məlumatları oxuya və ya dəyişdirə, autentifikasiya olunmuş istifadəçi kimi hərəkət edə bilər.",
            "severity_justification": "Tokenin vaxtı bitməyibsə və həssas resurslara giriş icazəsi verirsə, bu kritik səviyyəli sayılır.",
        },
    },
    "api_key_exposure": {
        "en": {
            "what": "An API key was found exposed in {location}.",
            "risk": "API keys authenticate programmatic access to services. An exposed API key can be used to access cloud services, incur costs, exfiltrate data, or modify infrastructure.",
            "impact": "Possible impact includes unauthorized service access, data exfiltration, unexpected billing charges, and infrastructure manipulation.",
            "severity_justification": "Severity depends on the key's permissions; keys with write or admin access to production services are critical.",
        },
        "az": {
            "what": "{location}-da açıq qalmış API açarı aşkarlanıb.",
            "risk": "API açarları xidmətlərə proqramatik girişi autentifikasiya edir. Açıq qalmış API açarı ilə bulud xidmətlərinə daxil olmaq, xərc yaratmaq, məlumatları oğurlamaq və ya infrastrukturu dəyişdirmək mümkündür.",
            "impact": "Mümkün təsirə xidmətlərə icazəsiz giriş, məlumat oğurluğu, gözlənilməz faktura xərcləri və infrastruktur manipulyasiyası daxildir.",
            "severity_justification": "Təhlükə səviyyəsi açarın icazələrindən asılıdır; production xidmətlərinə yazma və ya admin girişi olan açarlar kritik sayılır.",
        },
    },
    "password_exposure": {
        "en": {
            "what": "A plaintext password was found in {location}.",
            "risk": "Plaintext passwords provide direct authentication credentials. If the password is reused across systems, one exposure can compromise multiple accounts and services.",
            "impact": "Possible impact includes direct account takeover, lateral movement through reused credentials, and access to sensitive data or administrative functions.",
            "severity_justification": "This is high to critical depending on the account's privilege level and whether the password is reused.",
        },
        "az": {
            "what": "{location}-da açıq mətn şifrəsi aşkarlanıb.",
            "risk": "Açıq mətn şifrələri birbaşa autentifikasiya kredensiallarıdır. Şifrə sistemlər arasında təkrar istifadə olunursa, tək bir ifşa birdən çox hesabı və xidməti kompromis edə bilər.",
            "impact": "Mümkün təsirə hesabın ələ keçirilməsi, təkrar istifadə olunan kredensiallarla yan hərəkət və həssas məlumatlara və ya inzibati funksiyalara giriş daxildir.",
            "severity_justification": "Bu, hesabın imtiyaz səviyyəsindən və şifrənin təkrar istifadə edilib-edilməməsindən asılı olaraq yüksəkdən kritikə qədər qiymətləndirilir.",
        },
    },
    "pii_exposure": {
        "en": {
            "what": "Personally Identifiable Information (PII) was found exposed in {location}.",
            "risk": "PII exposure creates legal and privacy risk under data protection regulations such as GDPR and CCPA, and can lead to identity theft, fraud, and reputational damage.",
            "impact": "Possible impact includes regulatory fines, mandatory breach notification, identity theft risk, legal claims, and reputational damage.",
            "severity_justification": "Severity depends on the type and volume of PII; large datasets of financial or health information are critical.",
        },
        "az": {
            "what": "{location}-da açıq qalmış Şəxsi Müəyyənləşdirmə Məlumatları (PII) aşkarlanıb.",
            "risk": "PII ifşası GDPR və CCPA kimi məlumat qoruma qaydaları altında hüquqi və məxfilik riski yaradır, həmçinin şəxsiyyət oğurluğu, fırıldaqçılıq və reputasiya zərərinə səbəb ola bilər.",
            "impact": "Mümkün təsirə tənzimləyici cərimələr, məcburi pozuntu bildirişi, şəxsiyyət oğurluğu riski, hüquqi iddialar və reputasiya zərəri daxildir.",
            "severity_justification": "Təhlükə səviyyəsi PII-nin növündən və həcmindən asılıdır; maliyyə və ya sağlamlıq məlumatlarının böyük dataset-ləri kritik sayılır.",
        },
    },
}


FINDING_REMEDIATIONS: dict[str, dict[str, list[str]]] = {
    "private_key_exposure": {
        "en": [
            "1. Immediately revoke or rotate the exposed private key.",
            "2. Generate a new key pair using a secure key generation process.",
            "3. Update all systems, services, and certificates that use the old key.",
            "4. Audit access logs to check whether the exposed key was used by unauthorized parties.",
            "5. Store the new key in a dedicated secrets manager.",
            "6. Add pre-commit hooks or CI/CD secret scanning to prevent future key commits.",
            "7. Implement key rotation policies to limit the impact of future exposures.",
        ],
        "az": [
            "1. Açıq qalan gizli açarı dərhal ləğv edin və ya dəyişdirin.",
            "2. Təhlükəsiz açar yaratma prosesi ilə yeni açar cütü yaradın.",
            "3. Köhnə açardan istifadə edən bütün sistemləri, xidmətləri və sertifikatları yeniləyin.",
            "4. Açıq qalan açarın icazəsiz istifadə olunub-olunmadığını yoxlamaq üçün giriş qeydlərini audit edin.",
            "5. Yeni açarı xüsusi secrets manager-də saxlayın.",
            "6. Gələcək açar commit-lərinin qarşısını almaq üçün pre-commit hook və ya CI/CD secret scanning əlavə edin.",
            "7. Gələcək ifşaların təsirini azaltmaq üçün açar rotasiya siyasətləri tətbiq edin.",
        ],
    },
    "jwt_token_exposure": {
        "en": [
            "1. Immediately revoke or invalidate the exposed JWT token.",
            "2. Force re-authentication for sessions associated with the compromised token.",
            "3. Rotate the JWT signing secret or key if token signing may be affected.",
            "4. Review the token scope and reduce permissions to least privilege.",
            "5. Use short-lived access tokens with refresh-token controls.",
            "6. Never store tokens in source code, logs, or URL parameters.",
            "7. Add audience restrictions or token binding where possible.",
        ],
        "az": [
            "1. Açıq qalan JWT tokeni dərhal ləğv edin və ya etibarsız edin.",
            "2. Kompromis olunmuş tokenlə bağlı sessiyalar üçün yenidən autentifikasiya tələb edin.",
            "3. Token imzalanması təsirlənə bilərsə, JWT imzalama sirrini və ya açarını dəyişdirin.",
            "4. Tokenin scope-larını nəzərdən keçirin və icazələri least privilege səviyyəsinə endirin.",
            "5. Refresh-token nəzarəti ilə qısaömürlü access token-lərdən istifadə edin.",
            "6. Tokenləri heç vaxt mənbə kodunda, log-larda və ya URL parametrlərində saxlamayın.",
            "7. Mümkün olduqda audience restriction və ya token binding əlavə edin.",
        ],
    },
    "api_key_exposure": {
        "en": [
            "1. Immediately rotate or regenerate the exposed API key.",
            "2. Audit API access logs for unauthorized usage since the key was exposed.",
            "3. Restrict the new key's permissions to least privilege.",
            "4. Add IP allowlisting or network restrictions where supported.",
            "5. Move API keys to environment variables or a secrets manager; never hardcode them.",
            "6. Add secret scanning to CI/CD to detect key leaks before deployment.",
            "7. Set usage alerts and rate limits on the key to detect abuse.",
        ],
        "az": [
            "1. Açıq qalan API açarını dərhal dəyişdirin və ya yenidən yaradın.",
            "2. Açar ifşa olunduğundan bəri icazəsiz istifadə üçün API giriş log-larını audit edin.",
            "3. Yeni açarın icazələrini least privilege səviyyəsinə məhdudlaşdırın.",
            "4. Dəstəklənirsə, IP allowlist və ya şəbəkə məhdudiyyətləri əlavə edin.",
            "5. API açarlarını environment variable-lara və ya secrets manager-ə köçürün; heç vaxt kodda saxlamayın.",
            "6. Deployment-dən əvvəl açar sızmasını aşkar etmək üçün CI/CD secret scanning əlavə edin.",
            "7. Sui-istifadəni aşkar etmək üçün açar üzrə istifadə xəbərdarlıqları və rate limit-lər qurun.",
        ],
    },
    "password_exposure": {
        "en": [
            "1. Immediately change the exposed password everywhere it is used.",
            "2. Check for password reuse across other accounts and services.",
            "3. Force a password reset for affected accounts.",
            "4. Remove the plaintext password from the location where it was found.",
            "5. Store passwords using strong hashing such as bcrypt or Argon2; never plaintext.",
            "6. Implement a password manager policy for the organization.",
            "7. Enable multi-factor authentication on affected accounts.",
        ],
        "az": [
            "1. Açıq qalan şifrəni istifadə olunduğu bütün sistemlərdə dərhal dəyişdirin.",
            "2. Digər hesablar və xidmətlər arasında şifrənin təkrar istifadəsini yoxlayın.",
            "3. Təsirlənmiş hesablar üçün məcburi şifrə sıfırlaması tələb edin.",
            "4. Açıq mətn şifrəsini tapıldığı yerdən silin.",
            "5. Şifrələri bcrypt və ya Argon2 kimi güclü hash alqoritmləri ilə saxlayın; heç vaxt açıq mətn saxlamayın.",
            "6. Təşkilat üçün password manager siyasəti tətbiq edin.",
            "7. Təsirlənmiş hesablarda multi-factor authentication aktiv edin.",
        ],
    },
    "pii_exposure": {
        "en": [
            "1. Immediately restrict access to the location containing exposed PII.",
            "2. Assess the scope: PII types, record volume, and who may have accessed it.",
            "3. Determine whether regulatory breach notification is required.",
            "4. Remove, mask, or encrypt the PII at the source.",
            "5. Implement data classification and DLP policies to prevent recurrence.",
            "6. Review retention rules and delete PII that is no longer needed.",
            "7. Document the incident for compliance records and lessons learned.",
        ],
        "az": [
            "1. Açıq qalan PII olan yerə girişi dərhal məhdudlaşdırın.",
            "2. Əhatə dairəsini qiymətləndirin: PII növləri, qeyd sayı və kimlərin daxil ola biləcəyi.",
            "3. Tənzimləyici pozuntu bildirişinin tələb olunub-olunmadığını müəyyən edin.",
            "4. Mənbədəki PII-ni silin, maskalayın və ya şifrələyin.",
            "5. Təkrar halın qarşısını almaq üçün data classification və DLP siyasətləri tətbiq edin.",
            "6. Retention qaydalarını nəzərdən keçirin və artıq lazım olmayan PII-ni silin.",
            "7. Uyğunluq qeydləri və dərs çıxarma üçün hadisəni sənədləşdirin.",
        ],
    },
}


_FINDING_TYPE_ALIASES = {
    "private_key_exposure": "private_key_exposure",
    "jwt_token_exposure": "jwt_token_exposure",
    "api_key_exposure": "api_key_exposure",
    "password_exposure": "password_exposure",
    "pii_exposure": "pii_exposure",
}


def render_executive_dashboard(payload: dict, language: str = "en") -> str:
    scan_id = payload.get("scan_id") or "latest scan"
    total = payload.get("total_findings") or payload.get("total_files") or 0
    critical = payload.get("critical_count") or 0
    high = payload.get("high_count") or 0
    medium = payload.get("medium_count") or 0
    low = payload.get("low_count") or 0

    summary = payload.get("summary")
    if isinstance(summary, str):
        try:
            inner = json.loads(summary)
            if isinstance(inner, dict):
                total = inner.get("total_findings") or inner.get("total_files") or total
                critical = inner.get("critical_count") or critical
                high = inner.get("high_count") or high
                medium = inner.get("medium_count") or medium
                low = inner.get("low_count") or low
        except json.JSONDecodeError:
            pass

    if language == "az":
        lines = [
            f"İcmal panel ({scan_id}):",
            "",
            f"Ümumi tapıntılar: {total}",
            f"- CRITICAL: {critical}",
            f"- HIGH: {high}",
            f"- MEDIUM: {medium}",
            f"- LOW: {low}",
        ]
    else:
        lines = [
            f"Executive dashboard ({scan_id}):",
            "",
            f"Total findings: {total}",
            f"- CRITICAL: {critical}",
            f"- HIGH: {high}",
            f"- MEDIUM: {medium}",
            f"- LOW: {low}",
        ]
    return "\n".join(lines)


def render_scan_history(payload: dict, language: str = "en") -> str:
    scans = payload.get("scans") or payload.get("results") or []
    if not scans:
        if language == "az":
            return "Heç bir scan tarixçəsi tapılmadı."
        return "No scan history is available."

    if language == "az":
        lines = [f"Son {len(scans)} scan:"]
    else:
        lines = [f"Recent {len(scans)} scans:"]
    lines.append("")
    for i, scan in enumerate(scans, 1):
        scan_id = scan.get("scan_id") or f"scan-{i}"
        ts = scan.get("timestamp") or scan.get("date") or "unknown"
        total = scan.get("total_findings") or scan.get("file_count") or "?"
        lines.append(f"{i}. {scan_id} — {ts} ({total} findings)")
    return "\n".join(lines)


def render_high_risk_assets(payload: dict, language: str = "en") -> str:
    assets = payload.get("results") or payload.get("assets") or []
    if not assets:
        if language == "az":
            return "Yüksək riskli aktiv tapılmadı."
        return "No high-risk assets found."

    if language == "az":
        lines = [f"Yüksək riskli aktivlər ({len(assets)} tapıldı):"]
    else:
        lines = [f"High-risk assets ({len(assets)} found):"]
    lines.append("")
    for i, asset in enumerate(assets[:10], 1):
        name = asset.get("name") or asset.get("path") or "unknown"
        severity = asset.get("severity") or "unknown"
        score = asset.get("risk_score") if asset.get("risk_score") is not None else "?"
        lines.append(f"{i}. {name} — severity {severity}, risk score {score}")
    return "\n".join(lines)


def render_recent_alerts(payload: dict, language: str = "en") -> str:
    alerts = payload.get("alerts") or payload.get("results") or []
    if not alerts:
        if language == "az":
            return "Son alertlər tapılmadı."
        return "No recent alerts found."

    if language == "az":
        lines = [f"Son alertlər ({len(alerts)} tapıldı):"]
    else:
        lines = [f"Recent alerts ({len(alerts)} found):"]
    lines.append("")
    for i, alert in enumerate(alerts[:10], 1):
        title = alert.get("title") or alert.get("name") or alert.get("message") or "unknown"
        severity = alert.get("severity") or ""
        ts = alert.get("timestamp") or ""
        parts = [f"{i}. {title}"]
        if severity:
            parts.append(f"severity {severity}")
        if ts:
            parts.append(str(ts))
        lines.append(" — ".join(parts))
    return "\n".join(lines)


def render_audit_events(payload: dict, language: str = "en") -> str:
    events = payload.get("events") or payload.get("results") or []
    if not events:
        if language == "az":
            return "Audit hadisəsi tapılmadı."
        return "No audit events found."

    if language == "az":
        lines = [f"Audit hadisələri ({len(events)} tapıldı):"]
    else:
        lines = [f"Audit events ({len(events)} found):"]
    lines.append("")
    for i, event in enumerate(events[:10], 1):
        action = event.get("action") or event.get("event_type") or "unknown"
        user = event.get("user") or event.get("actor") or ""
        ts = event.get("timestamp") or ""
        parts = [f"{i}. {action}"]
        if user:
            parts.append(f"by {user}")
        if ts:
            parts.append(str(ts))
        lines.append(" — ".join(parts))
    return "\n".join(lines)


def render_finding_detail(payload: dict, language: str = "en") -> str:
    item = payload.get("item") if isinstance(payload.get("item"), dict) else payload
    name = item.get("name") or item.get("path") or "unknown item"
    severity = item.get("severity") or "unknown"
    score = item.get("risk_score") if item.get("risk_score") is not None else "unknown"
    risk_types = _extract_risk_types(item)

    if language == "az":
        lines = [
            f"Seçilmiş tapıntı: {name}",
            f"Təhlükə səviyyəsi: {severity}",
            f"Risk balı: {score}",
        ]
        if risk_types:
            lines.append(f"Aşkarlanan həssas məlumat tipləri: {', '.join(risk_types)}")
        lines.append("Əlavə sahələr mövcud sübut daxilində yoxdursa, onları uydurmuram.")
    else:
        lines = [
            f"Selected finding: {name}",
            f"Severity: {severity}",
            f"Risk score: {score}",
        ]
        if risk_types:
            lines.append(f"Detected sensitive types: {', '.join(risk_types)}")
        lines.append("Unavailable fields are not inferred beyond the provided evidence.")

    scan_id = payload.get("scan_id") or item.get("scan_id")
    if scan_id:
        source_label = "Mənbə: scan" if language == "az" else "Source: scan"
        lines.extend(["", f"{source_label} {scan_id}"])
    return "\n".join(lines)


def render_finding_risk_explanation(payload: dict, language: str = "en") -> str:
    known = render_known_finding_explanation(payload, language)
    if known:
        return known
    item = payload.get("item") if isinstance(payload.get("item"), dict) else payload
    name = item.get("name") or item.get("path") or "unknown item"
    severity = item.get("severity") or "unknown"
    score = item.get("risk_score") if item.get("risk_score") is not None else "unknown"
    risk_types = _extract_risk_types(item)
    types_str = ", ".join(risk_types) if risk_types else "none recorded"

    if language == "az":
        return (
            f"Seçilmiş tapıntı: {name}\n"
            f"Fayl: {name}\n"
            f"Ciddilik dərəcəsi: {severity}\n"
            f"Risk skoru: {score}\n"
            f"Aşkarlanan həssas məlumat tipləri: {types_str}\n\n"
            f"Risklidir, çünki {why_it_matters(risk_types, 'az')}\n"
            f"Tövsiyə: {short_recommendation_for_types(risk_types, 'az')}."
        )
    return (
        f"Selected finding: {name}\n"
        f"File: {name}\n"
        f"Severity: {severity}\n"
        f"Risk score: {score}\n"
        f"Detected sensitive types: {types_str}\n\n"
        f"Why it matters: {why_it_matters(risk_types, 'en')}\n"
        f"Recommendation: {short_recommendation_for_types(risk_types, 'en')}."
    )


def render_finding_remediation(payload: dict, language: str = "en") -> str:
    known = render_known_finding_remediation(payload, language)
    if known:
        return known
    item = payload.get("item") if isinstance(payload.get("item"), dict) else payload
    name = item.get("name") or item.get("path") or "unknown item"
    severity = item.get("severity") or "unknown"
    score = item.get("risk_score") if item.get("risk_score") is not None else "unknown"
    risk_types = _extract_risk_types(item)

    if language == "az":
        lines = [
            f"Seçilmiş tapıntı: {name}",
            f"Təhlükə səviyyəsi: {severity}",
            f"Risk balı: {score}",
        ]
        if risk_types:
            lines.append(f"Aşkarlanan həssas məlumat tipləri: {', '.join(risk_types)}")
        lines.append(f"Tövsiyə: {short_recommendation_for_types(risk_types, 'az')}.")
    else:
        lines = [
            f"Selected finding: {name}",
            f"Severity: {severity}",
            f"Risk score: {score}",
        ]
        if risk_types:
            lines.append(f"Detected sensitive types: {', '.join(risk_types)}")
        lines.append(f"Recommended next step: {short_recommendation_for_types(risk_types, 'en')}.")
    scan_id = payload.get("scan_id") or item.get("scan_id")
    if scan_id:
        source_label = "Mənbə: scan" if language == "az" else "Evidence: scan"
        lines.extend(["", f"{source_label} {scan_id}"])
    return "\n".join(lines)


def _extract_risk_types(item: dict) -> list[str]:
    risk_types = item.get("risk_types")
    if isinstance(risk_types, list):
        return [str(t) for t in risk_types if t]
    findings = item.get("findings")
    if isinstance(findings, list):
        return [
            str(f.get("type"))
            for f in findings
            if isinstance(f, dict) and f.get("type")
        ]
    return []


def _canonical_finding_type(item: dict) -> str | None:
    candidates: list[str] = []
    for value in _extract_risk_types(item):
        candidates.append(value)
    for value in item.get("risk_reasons") or []:
        candidates.append(str(value))
    for value in candidates:
        normalized = re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")
        text_value = str(value).strip().lower()
        if normalized in _FINDING_TYPE_ALIASES:
            return _FINDING_TYPE_ALIASES[normalized]
        if text_value in _FINDING_TYPE_ALIASES:
            return _FINDING_TYPE_ALIASES[text_value]
    return None


def _selected_item(payload: dict) -> dict:
    return payload.get("item") if isinstance(payload.get("item"), dict) else payload


def _item_location(item: dict) -> str:
    return str(item.get("name") or item.get("path") or "the selected finding")


def render_known_finding_explanation(payload: dict, language: str = "en") -> str | None:
    item = _selected_item(payload)
    finding_type = _canonical_finding_type(item)
    if not finding_type or finding_type not in FINDING_EXPLANATIONS:
        return None
    lang = "az" if language == "az" else "en"
    template = FINDING_EXPLANATIONS[finding_type][lang]
    location = _item_location(item)
    lines = [
        template["what"].format(location=location),
        "",
        f"Why it matters: {finding_type}" if lang == "en" else f"Niyə vacibdir: {finding_type}",
        f"Risk: {template['risk']}" if lang == "en" else f"Risk: {template['risk']}",
        f"Impact: {template['impact']}" if lang == "en" else f"Təsir: {template['impact']}",
        f"Severity justification: {template['severity_justification']}" if lang == "en" else f"Qiymətləndirmə səbəbi: {template['severity_justification']}",
    ]
    remediation_steps = FINDING_REMEDIATIONS.get(finding_type, {}).get(lang) or []
    if remediation_steps:
        label = "Recommended next steps" if lang == "en" else "Növbəti addımlar"
        lines.append(f"{label}: {remediation_steps[0]}")
    scan_id = payload.get("scan_id") or item.get("scan_id")
    if scan_id:
        source_label = "Mənbə: scan" if lang == "az" else "Evidence: scan"
        lines.extend(["", f"{source_label} {scan_id}"])
    return "\n".join(lines)


def render_known_finding_remediation(payload: dict, language: str = "en") -> str | None:
    item = _selected_item(payload)
    finding_type = _canonical_finding_type(item)
    if not finding_type or finding_type not in FINDING_REMEDIATIONS:
        return None
    lang = "az" if language == "az" else "en"
    location = _item_location(item)
    if lang == "az":
        lines = [f"Seçilmiş tapıntı: {location}", "", "Düzəliş addımları:"]
    else:
        lines = [f"Selected finding: {location}", "", "Recommended next step:", "Remediation steps:"]
    lines.extend(FINDING_REMEDIATIONS[finding_type][lang])
    scan_id = payload.get("scan_id") or item.get("scan_id")
    if scan_id:
        source_label = "Mənbə: scan" if lang == "az" else "Evidence: scan"
        lines.extend(["", f"{source_label} {scan_id}"])
    return "\n".join(lines)


def render_critical_filter(items: list[dict], language: str = "en") -> str:
    if not items:
        if language == "az":
            return "Tapıntı yoxdur."
        return "No items to filter."

    critical_items = []
    for item in items:
        severity = item.get("severity") or ""
        if isinstance(severity, str) and severity.upper() == "CRITICAL":
            critical_items.append(item)
        else:
            nested_item = item.get("item") or item.get("finding") or {}
            nested_severity = nested_item.get("severity") or ""
            if isinstance(nested_severity, str) and nested_severity.upper() == "CRITICAL":
                critical_items.append(item)

    if not critical_items:
        if language == "az":
            return "Kritik tapıntı tapılmadı."
        return "No critical items found."

    if language == "az":
        return f"{len(critical_items)} kritik tapıntı tapıldı."
    return f"Found {len(critical_items)} critical items."


def render_sort_by_time(items: list[dict], language: str = "en", ascending: bool = False) -> str:
    if not items:
        if language == "az":
            return "Tapıntı yoxdur."
        return "No items to sort."

    time_fields = ("last_seen", "created_at", "updated_at", "detected_at", "timestamp", "time", "scan_time")

    def get_timestamp(item: dict) -> float:
        for field in time_fields:
            val = item.get(field) or item.get("item", {}).get(field) or item.get("finding", {}).get(field)
            if val:
                if isinstance(val, (int, float)):
                    return val
                try:
                    from datetime import datetime
                    parsed = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
                    return parsed.timestamp()
                except (ValueError, AttributeError):
                    pass
        return 0

    sorted_items = sorted(items, key=get_timestamp, reverse=not ascending)

    if language == "az":
        order = "ən yenidən ən köhnəyə" if not ascending else "ən köhnədən ən yeniyə"
        return f"Tapıntılar {order} sıralandı ({len(sorted_items)} ədəd)."
    order = "newest first" if not ascending else "oldest first"
    return f"Items sorted by time ({order}): {len(sorted_items)} items."


SKILL_RENDERERS: dict[str, Any] = {
    "render_executive_dashboard": render_executive_dashboard,
    "render_scan_history": render_scan_history,
    "render_high_risk_assets": render_high_risk_assets,
    "render_recent_alerts": render_recent_alerts,
    "render_audit_events": render_audit_events,
    "render_finding_detail": render_finding_detail,
    "render_finding_risk_explanation": render_finding_risk_explanation,
    "render_finding_remediation": render_finding_remediation,
    "render_critical_filter": render_critical_filter,
    "render_sort_by_time": render_sort_by_time,
}


def _recommendation_for_types(risk_types: list[str], language: str) -> str:
    """Concise, type-aware recommendation.

    Delegates to the deterministic remediation policy so that rotation is only
    recommended when a credential/secret type is actually present.
    """
    return short_recommendation_for_types(risk_types, "az" if language == "az" else language)


def render_step_by_step_remediation(finding: dict, language: str = "az", scan_id: str | None = None) -> str:
    """Render a type-aware, teaching-style step-by-step remediation for one finding.

    Only safe metadata (name, severity, risk score, risk types, scan id) is used.
    Raw sensitive values are never rendered; the output is additionally passed
    through ``mask_sensitive_text`` as defense-in-depth.
    """
    item = finding.get("item") if isinstance(finding.get("item"), dict) else finding
    lang = "az" if language == "az" else ("ru" if language == "ru" else "en")
    name = str(item.get("name") or item.get("path") or ("naməlum fayl" if lang == "az" else "unknown file"))
    severity = str(item.get("severity") or ("naməlum" if lang == "az" else "unknown")).upper()
    score = item.get("risk_score") if item.get("risk_score") is not None else ("naməlum" if lang == "az" else "unknown")
    risk_types = _extract_risk_types(item)
    resolved_scan_id = scan_id or finding.get("scan_id") or item.get("scan_id")

    steps = build_remediation_steps_for_types(risk_types, lang)
    if lang == "az":
        steps = [
            step.replace(
                "dərhal revoke və ya rotate et",
                "dərhal dəyişdirin (rotate/revoke edin)",
            )
            for step in steps
        ]
    checklist = remediation_checklist(risk_types, lang)
    meaning = what_it_means(risk_types, lang)
    matters = why_it_matters(risk_types, lang)

    if lang == "az":
        types_label = ", ".join(risk_types) if risk_types else "qeydə alınmayıb"
        lines = [
            f"Seçilmiş {severity} tapıntı:",
            f"{name} — {severity} — risk score {score}",
            f"Risk növləri: {types_label}",
            "",
            "Bu tapıntı nə deməkdir?",
            meaning,
            "",
            "Niyə vacibdir?",
            matters,
            "",
            "Nə etməlisən? Addım-addım:",
        ]
        lines.extend(f"{idx}. {step}" for idx, step in enumerate(steps, 1))
        lines.extend(["", "Yoxlama siyahısı:"])
        lines.extend(checklist)
    elif lang == "ru":
        types_label = ", ".join(risk_types) if risk_types else "не зафиксировано"
        lines = [
            f"Выбранная находка {severity}:",
            f"{name} — {severity} — risk score {score}",
            f"Типы риска: {types_label}",
            "",
            "Что означает эта находка?",
            meaning,
            "",
            "Почему это важно?",
            matters,
            "",
            "Что делать? Шаг за шагом:",
        ]
        lines.extend(f"{idx}. {step}" for idx, step in enumerate(steps, 1))
        lines.extend(["", "Контрольный список:"])
        lines.extend(checklist)
    else:
        types_label = ", ".join(risk_types) if risk_types else "none recorded"
        lines = [
            f"Selected {severity} finding:",
            f"{name} — {severity} — risk score {score}",
            f"Risk types: {types_label}",
            "",
            "What does this finding mean?",
            meaning,
            "",
            "Why it matters?",
            matters,
            "",
            "What should you do? Step by step:",
        ]
        lines.extend(f"{idx}. {step}" for idx, step in enumerate(steps, 1))
        lines.extend(["", "Checklist:"])
        lines.extend(checklist)

    if resolved_scan_id:
        source_label = "Mənbə: scan" if lang == "az" else ("Источник: scan" if lang == "ru" else "Evidence: scan")
        lines.extend(["", f"{source_label} {resolved_scan_id}"])

    return mask_sensitive_text("\n".join(lines))


def render_finding_teaching_response(finding: dict, language: str = "az", scan_id: str | None = None) -> str:
    """Alias for the step-by-step teaching renderer for a single finding."""
    return render_step_by_step_remediation(finding, language, scan_id)


def render_list_plus_remediation(items: list[dict], scan_id: str | None, language: str = "en") -> str:
    if not items:
        if language == "az":
            return "Bu tapıntı yoxdur."
        return "No findings available."
    lines: list[str] = []
    if language == "az":
        lines.append(f"Son skanda {len(items)} kritik tapıntı və hər biri üçün tövsiyə:")
        lines.append("")
        for idx, item in enumerate(items, 1):
            name = item.get("name") or item.get("path") or "unknown"
            severity = item.get("severity") or "CRITICAL"
            score = item.get("risk_score" if "risk_score" in item else "risk_score") or item.get("risk_score") or "n/a"
            risk_types = _extract_risk_types(item)
            recommendation = _recommendation_for_types(risk_types, "az")
            lines.append(f"{idx}. {name}")
            lines.append(f"   Təhlükə səviyyəsi: {severity}")
            lines.append(f"   Risk balı: {score}")
            if risk_types:
                lines.append(f"   Aşkarlanan tiplər: {', '.join(risk_types)}")
            lines.append(f"   Tövsiyə: {recommendation}")
            lines.append("")
        lines.append(f"Mənbə: scan {scan_id or 'son skan'}")
    else:
        lines.append(f"Here are {len(items)} critical findings from the latest scan with recommendations:")
        lines.append("")
        for idx, item in enumerate(items, 1):
            name = item.get("name") or item.get("path") or "unknown"
            severity = item.get("severity") or "CRITICAL"
            score = item.get("risk_score" if "risk_score" in item else "risk_score") or item.get("risk_score") or "n/a"
            risk_types = _extract_risk_types(item)
            recommendation = _recommendation_for_types(risk_types, "en")
            lines.append(f"{idx}. {name}")
            lines.append(f"   Severity: {severity}")
            lines.append(f"   Risk score: {score}")
            if risk_types:
                lines.append(f"   Detected types: {', '.join(risk_types)}")
            lines.append(f"   Recommendation: {recommendation}")
            lines.append("")
        lines.append(f"Evidence: Scan ID: {scan_id or 'latest scan'}")
    return "\n".join(lines)


def _risk_explanation_for_types(risk_types: list[str], language: str) -> str:
    normalized = {str(rt).lower() for rt in risk_types}
    if language == "az":
        if "private_key" in normalized:
            return "private_key tapıntısı çox risklidir, çünki açar sızarsa sistemlərə icazəsiz giriş mümkün ola bilər."
        if "jwt" in normalized:
            return "JWT tapıntısı risklidir, çünki aktiv token ələ keçirilərsə istifadəçi və ya servis sessiyası sui-istifadə oluna bilər."
        if {"password", "secret", "api_key", "aws_access_key", "azure_access_token"} & normalized:
            return "Sirr və credential tapıntıları risklidir, çünki onlar hesab, servis və data girişini açıq qoya bilər."
        if {"pii", "personal_data", "email", "phone_number"} & normalized:
            return "PII tapıntısı risklidir, çünki şəxsi məlumatların icazəsiz paylaşımı hüquqi və məxfilik problemi yarada bilər."
        return "Bu tapıntı yüksək risk yarada bilər, çünki həssas data və ya zəif access nəzarəti ilə bağlıdır."
    if "private_key" in normalized:
        return "A private_key finding is critical because a leaked key can allow unauthorized access to systems or data."
    if "jwt" in normalized:
        return "A JWT finding is risky because an active token can be abused as a user or service session."
    if {"password", "secret", "api_key", "aws_access_key", "azure_access_token"} & normalized:
        return "Secret or credential findings are risky because they can expose account, service, or data access."
    if {"pii", "personal_data", "email", "phone_number"} & normalized:
        return "PII findings are risky because unauthorized sharing can create privacy and compliance exposure."
    return "This finding can create material risk because it involves sensitive data or weak access control."


def render_teach_dspm(items: list[dict] | None = None, language: str = "en", topic: str | None = None) -> str:
    items = items or []
    first = items[0] if items else {}
    risk_types = _extract_risk_types(first) if first else ([topic] if topic else [])
    example_name = first.get("name") or first.get("path") or "the selected finding"
    recommendation = _recommendation_for_types(risk_types, language)
    risk_text = _risk_explanation_for_types(risk_types, language)

    if language == "az":
        lines = [
            "Qısa izah:",
            risk_text,
            "",
            "Niyə vacibdir:",
            "Bu tip tapıntılar data sızması, icazəsiz giriş və compliance riski yarada bilər. Copilot yalnız mövcud DSPM sübutuna əsaslanır və remediation-un tamamlandığını iddia etmir.",
            "",
            "Addım-addım nə etməli:",
            "1. Tapıntının faylını və risk tipini yoxlayın.",
            "2. Açıq sirr, token və ya açarı dərhal rotate/revoke edin.",
            "3. Həssas dəyəri fayldan çıxarın və secret manager istifadə edin.",
            "4. Fayl paylaşımını və access-i least-privilege prinsipinə endirin.",
            "5. Növbəti skanda tapıntının artıq görünmədiyini yoxlayın.",
            "",
            "Məsələn bu tapıntıda:",
            f"{example_name}: {recommendation}.",
            "",
            "Yoxlama siyahısı:",
            "- Secret/token rotate edilib",
            "- Fayldan həssas dəyər silinib",
            "- Access məhdudlaşdırılıb",
            "- Növbəti skanla təsdiqlənib",
            "",
            "Kiçik test:",
            "Əgər private key repoda tapılıbsa, ilk addım onu sadəcə silmək yox, əvvəlcə rotate/revoke etməkdir.",
        ]
    else:
        lines = [
            "Quick explanation:",
            risk_text,
            "",
            "Why it matters:",
            "These findings can create data exposure, unauthorized access, and compliance risk. Copilot uses available DSPM evidence only and does not claim remediation is complete.",
            "",
            "Step-by-step:",
            "1. Confirm the file and risk type.",
            "2. Rotate or revoke the exposed secret, token, or key immediately.",
            "3. Remove the sensitive value from the file and move it to a secret manager.",
            "4. Reduce sharing and access to least privilege.",
            "5. Verify the finding is gone in the next scan.",
            "",
            "In this finding:",
            f"{example_name}: {recommendation}.",
            "",
            "Checklist:",
            "- Secret/token rotated",
            "- Sensitive value removed from the file",
            "- Access restricted",
            "- Next scan confirms the fix",
            "",
            "Quick check:",
            "If a private key is found in a repository, the first step is not only deleting it; rotate or revoke it first.",
        ]
    if len(items) > 1:
        if language == "az":
            lines.insert(0, f"Bu izah göstərilən {len(items)} tapıntıya tətbiq olunur.")
        else:
            lines.insert(0, f"This guidance applies to the {len(items)} findings shown.")
    return "\n".join(lines)


SKILL_RENDERERS["render_teach_dspm"] = render_teach_dspm
SKILL_RENDERERS["render_step_by_step_remediation"] = render_step_by_step_remediation
SKILL_RENDERERS["render_finding_teaching_response"] = render_finding_teaching_response


def render_posture_score(payload: dict, language: str = "en") -> str:
    score = payload.get("total_score", 0)
    grade = payload.get("grade") or "unknown"
    breakdown = payload.get("breakdown") if isinstance(payload.get("breakdown"), dict) else {}
    trend = payload.get("trend_direction") or "unknown"
    if language == "az":
        lines = [
            f"DSPM təhlükəsizlik balı: {score}/100 (dərəcə {grade})",
            payload.get("summary_az") or "",
            "",
            "Bal bölgüsü:",
            f"- Tapıntı riski: {breakdown.get('finding_score', 0)}/40",
            f"- Remediation irəliləyişi: {breakdown.get('remediation_score', 0)}/25",
            f"- Ekspozisiya: {breakdown.get('exposure_score', 0)}/20",
            f"- Trend: {breakdown.get('trend_score', 0)}/15",
            f"Trend istiqaməti: {trend}",
        ]
    elif language == "ru":
        lines = [
            f"По данным dashboard, DSPM posture score составляет {score}/100 (grade {grade})",
            payload.get("summary_ru") or payload.get("summary_en") or "",
            "",
            "Разбивка score:",
            f"- Finding risk: {breakdown.get('finding_score', 0)}/40",
            f"- Remediation progress: {breakdown.get('remediation_score', 0)}/25",
            f"- Exposure: {breakdown.get('exposure_score', 0)}/20",
            f"- Trend: {breakdown.get('trend_score', 0)}/15",
            f"Trend direction: {trend}",
        ]
    else:
        lines = [
            f"DSPM posture score: {score}/100 (grade {grade})",
            payload.get("summary_en") or "",
            "",
            "Score breakdown:",
            f"- Finding risk: {breakdown.get('finding_score', 0)}/40",
            f"- Remediation progress: {breakdown.get('remediation_score', 0)}/25",
            f"- Exposure: {breakdown.get('exposure_score', 0)}/20",
            f"- Trend: {breakdown.get('trend_score', 0)}/15",
            f"Trend direction: {trend}",
        ]
    return "\n".join(line for line in lines if line != "")


def render_compliance_report(payload: dict, language: str = "en") -> str:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    frameworks = summary.get("frameworks") if isinstance(summary.get("frameworks"), dict) else {}
    scan_id = payload.get("scan_id") or "latest scan"
    requested_framework = payload.get("framework")
    if language == "az":
        title = f"Uyğunluq xəritəsi ({scan_id})"
        lines = [
            title,
            "Bu, DSPM tapıntılarına əsaslanan texniki xəritədir; hüquqi pozuntu qərarı deyil.",
        ]
        if requested_framework:
            lines.append(f"Framework: {requested_framework}")
        if not frameworks:
            lines.append("Mövcud tapıntılar üçün uyğun framework xəritəsi tapılmadı.")
            return "\n".join(lines)
        for name, data in frameworks.items():
            lines.append("")
            lines.append(f"{name}: {data.get('finding_count', 0)} əlaqəli tapıntı")
            controls = data.get("controls") if isinstance(data.get("controls"), dict) else {}
            for control, reason in controls.items():
                lines.append(f"- {control}: {reason}")
        return "\n".join(lines)

    lines = [
        f"Compliance mapping ({scan_id})",
        "This is a technical mapping from DSPM findings, not a legal violation decision.",
    ]
    if requested_framework:
        lines.append(f"Framework: {requested_framework}")
    if not frameworks:
        lines.append("No framework mapping was found for the available findings.")
        return "\n".join(lines)
    for name, data in frameworks.items():
        lines.append("")
        lines.append(f"{name}: {data.get('finding_count', 0)} related findings")
        controls = data.get("controls") if isinstance(data.get("controls"), dict) else {}
        for control, reason in controls.items():
            lines.append(f"- {control}: {reason}")
    return "\n".join(lines)


def render_trend_analysis(payload: dict, language: str = "en") -> str:
    points = payload.get("points") if isinstance(payload.get("points"), list) else []
    recommendations = payload.get("recommendations") if isinstance(payload.get("recommendations"), list) else []
    if language == "az":
        lines = [
            "Trend analizi",
            payload.get("summary_az") or "",
            f"İstiqamət: {payload.get('direction') or 'unknown'}",
            f"Bal dəyişikliyi: {payload.get('score_delta', 0)}",
            f"Kritik tapıntı dəyişikliyi: {payload.get('critical_delta', 0)}",
        ]
        if points:
            lines.extend(["", "Scan nöqtələri:"])
            for point in points[-5:]:
                lines.append(
                    f"- {point.get('scan_id')}: score {point.get('posture_score')}, "
                    f"CRITICAL {point.get('critical_count')}, HIGH {point.get('high_count')}"
                )
        if recommendations:
            lines.extend(["", "Növbəti addımlar:"])
            for item in recommendations[:3]:
                lines.append(f"- {item}")
        return "\n".join(line for line in lines if line != "")

    lines = [
        "Trend analysis",
        payload.get("summary_en") or "",
        f"Direction: {payload.get('direction') or 'unknown'}",
        f"Score delta: {payload.get('score_delta', 0)}",
        f"Critical finding delta: {payload.get('critical_delta', 0)}",
    ]
    if points:
        lines.extend(["", "Scan points:"])
        for point in points[-5:]:
            lines.append(
                f"- {point.get('scan_id')}: score {point.get('posture_score')}, "
                f"CRITICAL {point.get('critical_count')}, HIGH {point.get('high_count')}"
            )
    if recommendations:
        lines.extend(["", "Next steps:"])
        for item in recommendations[:3]:
            lines.append(f"- {item}")
    return "\n".join(line for line in lines if line != "")


SKILL_RENDERERS["render_posture_score"] = render_posture_score
SKILL_RENDERERS["render_compliance_report"] = render_compliance_report
SKILL_RENDERERS["render_trend_analysis"] = render_trend_analysis


def get_renderer(renderer_name: str | None):
    if not renderer_name:
        return None
    return SKILL_RENDERERS.get(renderer_name)
