from __future__ import annotations

import re

from scripts.logger import get_logger

logger = get_logger(__name__)

SENSITIVE_ENTITY_LABELS = {"PERSON", "ORG", "GPE", "LOC", "NORP", "MONEY", "DATE", "CARDINAL"}

# GAP-2: the spaCy/NER path used to fail silently (return []), so on any install
# without spacy + en_core_web_sm the ML detection layer was disabled with no
# signal. Probe availability once, emit a one-time warning, and expose the state
# so the degradation is observable rather than silent.
_ML_STATUS: dict | None = None


def ml_classifier_status() -> dict:
    """Return {'available': bool, 'reason': str} for the ML/NER detector.

    Probed once and cached. Emits a single WARNING when unavailable so operators
    know classification is running in the heuristic-only fallback mode.
    """
    global _ML_STATUS
    if _ML_STATUS is not None:
        return _ML_STATUS
    try:
        import spacy
    except ModuleNotFoundError:
        _ML_STATUS = {"available": False, "reason": "spacy_not_installed"}
        logger.warning(
            "ML/NER classification is DISABLED (spacy not installed); using "
            "heuristic context detection only. Install requirements-ml.txt and run "
            "'python -m spacy download en_core_web_sm' to enable it."
        )
        return _ML_STATUS
    try:
        spacy.load("en_core_web_sm")
    except Exception:
        _ML_STATUS = {"available": False, "reason": "model_not_downloaded"}
        logger.warning(
            "ML/NER classification is DISABLED ('en_core_web_sm' model missing); "
            "using heuristic context detection only. Run "
            "'python -m spacy download en_core_web_sm' to enable it."
        )
        return _ML_STATUS
    _ML_STATUS = {"available": True, "reason": ""}
    return _ML_STATUS


def classify_with_ml(content: str) -> list[dict]:
    if not content:
        return []

    spacy_findings = _spacy_ner(content)
    if spacy_findings:
        return spacy_findings
    return _heuristic_findings(content)


def _spacy_ner(content: str) -> list[dict]:
    if not ml_classifier_status()["available"]:
        return []

    import spacy

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
