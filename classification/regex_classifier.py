from __future__ import annotations

import re
from dataclasses import dataclass

from classification.ml_classifier import classify_with_ml


@dataclass(frozen=True, slots=True)
class DetectionRule:
    name: str
    pattern: re.Pattern[str]
    risk: str
    description: str
    redact: bool = True


RULES = [
    DetectionRule(
        name="private_key",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{0,2000}?-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
            re.IGNORECASE,
        ),
        risk="CRITICAL",
        description="Private cryptographic key detected",
    ),
    DetectionRule(
        name="aws_access_key",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        risk="CRITICAL",
        description="AWS access key identifier detected",
    ),
    DetectionRule(
        name="jwt",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        risk="HIGH",
        description="JSON Web Token detected",
    ),
    DetectionRule(
        name="connection_string",
        pattern=re.compile(
            r"\b(?:server|host|data source)\s*=\s*[^;\n]{2,};(?:[^;\n=]+\s*=\s*[^;\n]+;?){2,}",
            re.IGNORECASE,
        ),
        risk="HIGH",
        description="Database or service connection string detected",
    ),
    DetectionRule(
        name="azure_storage_key",
        pattern=re.compile(r"\b(?:DefaultEndpointsProtocol|AccountName|AccountKey|BlobEndpoint)\s*=\s*[^;\n]{4,}", re.IGNORECASE),
        risk="CRITICAL",
        description="Azure storage connection secret detected",
    ),
    DetectionRule(
        name="google_api_key",
        pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        risk="CRITICAL",
        description="Google API key detected",
    ),
    DetectionRule(
        name="slack_token",
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        risk="CRITICAL",
        description="Slack token detected",
    ),
    DetectionRule(
        name="github_token",
        pattern=re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b"),
        risk="CRITICAL",
        description="GitHub access token detected",
    ),
    DetectionRule(
        name="email",
        pattern=re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"),
        risk="MEDIUM",
        description="Email address detected",
    ),
    DetectionRule(
        name="password",
        pattern=re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*[^\s'\"]+", re.IGNORECASE),
        risk="HIGH",
        description="Password-like secret detected",
    ),
    DetectionRule(
        name="api_key",
        pattern=re.compile(r"\b(?:api[_-]?key|token|secret)\s*[:=]\s*[A-Za-z0-9_\-]{12,}", re.IGNORECASE),
        risk="HIGH",
        description="Token or API key pattern detected",
    ),
    DetectionRule(
        name="credit_card",
        pattern=re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        risk="HIGH",
        description="Possible payment card number detected",
    ),
    DetectionRule(
        name="swift_bic",
        pattern=re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),
        risk="HIGH",
        description="Possible SWIFT/BIC bank identifier detected",
    ),
    DetectionRule(
        name="iban",
        pattern=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
        risk="HIGH",
        description="Possible IBAN bank account identifier detected",
    ),
    DetectionRule(
        name="passport_number",
        pattern=re.compile(r"\b(?:passport|pass\.?|pasport)\s*(?:no\.?|number|#)?\s*[:=]?\s*[A-Z0-9]{6,12}\b", re.IGNORECASE),
        risk="HIGH",
        description="Passport identifier context detected",
    ),
    DetectionRule(
        name="national_id",
        pattern=re.compile(r"\b(?:national id|tax id|tin|ssn|social security)\s*[:=]?\s*[A-Z0-9\-]{6,18}\b", re.IGNORECASE),
        risk="HIGH",
        description="Government identifier context detected",
    ),
    DetectionRule(
        name="phone_number",
        pattern=re.compile(r"(?:\+994|0)(?:\s|-)?(?:50|51|55|70|77|99|10|12)(?:\s|-)?\d{3}(?:\s|-)?\d{2}(?:\s|-)?\d{2}\b"),
        risk="MEDIUM",
        description="Azerbaijan phone number detected",
    ),
    DetectionRule(
        name="azerbaijan_fin",
        pattern=re.compile(r"\b[A-Z0-9]{7}\b"),
        risk="MEDIUM",
        description="Possible Azerbaijan FIN-like identifier detected",
    ),
    DetectionRule(
        name="confidential_keyword",
        pattern=re.compile(r"\b(confidential|restricted|internal use only|secret|nda|non-disclosure|board only|privileged)\b", re.IGNORECASE),
        risk="MEDIUM",
        description="Confidentiality keyword detected",
        redact=False,
    ),
    DetectionRule(
        name="source_code_secret_context",
        pattern=re.compile(r"\b(?:client_secret|private_token|auth_token|db_password|encryption_key)\b\s*[:=]", re.IGNORECASE),
        risk="HIGH",
        description="Source-code secret assignment detected",
    ),
    DetectionRule(
        name="legal_contract_context",
        pattern=re.compile(r"\b(?:contract|statement of work|master service agreement|msa|nda|legal hold)\b", re.IGNORECASE),
        risk="MEDIUM",
        description="Legal or contract context detected",
        redact=False,
    ),
]


def _redact(value: str) -> str:
    if len(value) <= 6:
        return "***"
    return f"{value[:3]}***{value[-2:]}"


def classify_content(content: str) -> list[dict]:
    if not content:
        return []

    findings: list[dict] = []
    for rule in RULES:
        matches = []
        for match in rule.pattern.finditer(content):
            value = match.group(0)
            matches.append(_redact(value) if rule.redact else value)
            if len(matches) >= 10:
                break

        if not matches:
            continue

        findings.append(
            {
                "type": rule.name,
                "risk": rule.risk,
                "description": rule.description,
                "count": len(matches),
                "samples": matches,
            }
        )

    existing = {finding["type"] for finding in findings}
    for finding in classify_with_ml(content):
        if finding["type"] not in existing:
            findings.append(finding)

    return findings
