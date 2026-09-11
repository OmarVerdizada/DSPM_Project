from __future__ import annotations

import os

from scripts.logger import get_logger

logger = get_logger(__name__)

SENSITIVE_ENTITY_LABELS = {"PERSON", "ORG", "GPE", "LOC", "NORP", "MONEY", "DATE", "CARDINAL"}

# A3: the heuristic fallback that used to live here is GONE. It was five
# re.search calls - one occurrence of `tax`, `bank`, `employee`, `patient` or
# `repository` anywhere in a file produced a MEDIUM or HIGH finding described as
# a "classifier". Three of the five duplicated rules that already exist in
# `regex_classifier.RULES` (`phi_context`, `payroll_context`,
# `customer_context`), so one sentence could produce the same claim twice.
# Context detection belongs in the GDPR and NIST detectors, which have keyword
# catalogs, thresholds and confidence tiers; a regex with no threshold is not a
# classifier and should not have been named like one.
#
# What remains is the real spaCy NER path, and it is opt-in twice over: the
# optional dependency has to be installed AND DSPM_ML_NER_ENABLED has to be set.
# GAP-2 (why the status probe exists): the NER path used to fail silently, so an
# install without spacy ran without it and said nothing.
_ML_STATUS: dict | None = None


def _ner_enabled() -> bool:
    """Whether the operator asked for entity recognition at all.

    Off by default. `SENSITIVE_ENTITY_LABELS` includes DATE and CARDINAL, which
    every business document contains, so this is a tuning surface an operator
    opts into deliberately - not something that should arrive with an install.
    """

    return os.getenv("DSPM_ML_NER_ENABLED", "0").strip().lower() not in {"", "0", "false", "no", "off"}


def ml_classifier_status() -> dict:
    """Return {'available': bool, 'reason': str} for the ML/NER detector.

    Probed once and cached. Emits a single WARNING when the operator asked for
    NER and it cannot run, so a requested control that does not apply is
    visible rather than silent. Being switched off is not a warning.
    """
    global _ML_STATUS
    if _ML_STATUS is not None:
        return _ML_STATUS
    if not _ner_enabled():
        _ML_STATUS = {"available": False, "reason": "ml_ner_disabled"}
        return _ML_STATUS
    try:
        import spacy
    except ModuleNotFoundError:
        _ML_STATUS = {"available": False, "reason": "spacy_not_installed"}
        logger.warning(
            "DSPM_ML_NER_ENABLED is set but spacy is not installed, so entity "
            "recognition is off. Install requirements-ml.txt and run "
            "'python -m spacy download en_core_web_sm'."
        )
        return _ML_STATUS
    try:
        spacy.load("en_core_web_sm")
    except Exception:
        _ML_STATUS = {"available": False, "reason": "model_not_downloaded"}
        logger.warning(
            "DSPM_ML_NER_ENABLED is set but the 'en_core_web_sm' model is missing, "
            "so entity recognition is off. Run "
            "'python -m spacy download en_core_web_sm'."
        )
        return _ML_STATUS
    _ML_STATUS = {"available": True, "reason": ""}
    return _ML_STATUS


def classify_with_ml(content: str) -> list[dict]:
    if not content:
        return []
    return _spacy_ner(content)


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

    # An entity count is a hint about a document, not evidence about a value:
    # LOW severity and an explicit LOW confidence, so it can neither drive a
    # severity band nor inflate `_detection_confidence_label`, which otherwise
    # reads a finding carrying no confidence at all as MEDIUM.
    return [
        {
            "type": f"ml_ner_{label.lower()}",
            "risk": "LOW",
            "detection_confidence": "LOW",
            "description": f"ML NER detected {label} entities",
            "count": count,
            "samples": [],
        }
        for label, count in sorted(counts.items())
    ]
