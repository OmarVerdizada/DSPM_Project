from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DetectionRule:
    name: str
    pattern: re.Pattern[str]
    risk: str
    description: str
    redact: bool = True


RULES = [
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
        name="azerbaijan_fin",
        pattern=re.compile(r"\b[A-Z0-9]{7}\b"),
        risk="MEDIUM",
        description="Possible Azerbaijan FIN-like identifier detected",
    ),
    DetectionRule(
        name="confidential_keyword",
        pattern=re.compile(r"\b(confidential|restricted|internal use only|secret)\b", re.IGNORECASE),
        risk="MEDIUM",
        description="Confidentiality keyword detected",
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

    return findings
