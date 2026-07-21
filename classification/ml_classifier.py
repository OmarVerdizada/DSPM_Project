from __future__ import annotations

import re


SENSITIVE_ENTITY_LABELS = {"PERSON", "ORG", "GPE", "LOC", "NORP", "MONEY", "DATE", "CARDINAL"}


def classify_with_ml(content: str) -> list[dict]:
    if not content:
        return []

    spacy_findings = _spacy_ner(content)
    if spacy_findings:
        return spacy_findings
    return _heuristic_findings(content)


def _spacy_ner(content: str) -> list[dict]:
    try:
        import spacy
    except ModuleNotFoundError:
        return []

    try:
        nlp = spacy.load("en_core_web_sm")
    except Exception:
        return []

    counts: dict[str, int] = {}
    for entity in nlp(content[:60_000]).ents:
        if entity.label_ in SENSITIVE_ENTITY_LABELS:
            counts[entity.label_] = counts.get(entity.label_, 0) + 1

    return [
        {
            "type": f"ml_ner_{label.lower()}",
            "risk": "MEDIUM",
            "description": f"ML NER detected {label} entities",
            "count": count,
            "samples": [],
        }
        for label, count in sorted(counts.items())
    ]


def _heuristic_findings(content: str) -> list[dict]:
    findings: list[dict] = []
    if re.search(r"\b(source code|repository|git clone|commit hash|pull request|deployment key)\b", content, re.IGNORECASE):
        findings.append(
            {
                "type": "ml_source_code_context",
                "risk": "HIGH",
                "description": "Source code context classifier detected engineering asset language",
                "count": 1,
                "samples": [],
            }
        )
    if re.search(r"\b(patient|diagnosis|treatment|medical record|mrn)\b", content, re.IGNORECASE):
        findings.append(
            {
                "type": "ml_phi_context",
                "risk": "HIGH",
                "description": "PHI context classifier detected medical language",
                "count": 1,
                "samples": [],
            }
        )
    if re.search(r"\b(invoice|salary|payroll|iban|swift|bank|payment|wire transfer|tax)\b", content, re.IGNORECASE):
        findings.append(
            {
                "type": "ml_finance_context",
                "risk": "MEDIUM",
                "description": "Finance context classifier detected regulated business language",
                "count": 1,
                "samples": [],
            }
        )
    if re.search(r"\b(employee|termination|performance review|bonus|compensation|hr case)\b", content, re.IGNORECASE):
        findings.append(
            {
                "type": "ml_hr_context",
                "risk": "MEDIUM",
                "description": "HR context classifier detected employee-sensitive language",
                "count": 1,
                "samples": [],
            }
        )
    if re.search(r"\b(customer list|customer export|account owner|crm|lead list|prospect)\b", content, re.IGNORECASE):
        findings.append(
            {
                "type": "ml_customer_data_context",
                "risk": "MEDIUM",
                "description": "Customer data context classifier detected commercial data language",
                "count": 1,
                "samples": [],
            }
        )
    return findings
