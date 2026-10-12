"""One reading of a finding's confidence, for every place that needs it (D2).

The canonical model, the compliance service and the risk engine each parsed confidence
themselves, with the fields in different orders and three different answers for a
finding that stated none - 50, 70 and "MEDIUM" - so the same finding was confident in
one place and not in another. They all read it here now.

A finding states its confidence as a number (0-100) or a label. One that states none
reads as ``UNSCORED`` (70, "MEDIUM"), the value two of the three readers already used;
GDPR findings state their own since D2 (``gdpr_confidence``), and the PCI and NIST
classifiers already did.
"""

from __future__ import annotations

UNSCORED = 70
_LABELS = {
    "high": 90, "confirmed": 90, "verified": 90,
    "medium": 70, "review": 70, "needs_review": 70, "probable": 70,
    "low": 40, "context": 40, "context_only": 40, "possible": 40,
}
_FIELDS = ("detection_confidence", "confidence")


def stated_confidence(finding: dict, *, fields: tuple[str, ...] = _FIELDS) -> int | None:
    """The confidence a finding states, 0-100 - or None when it states none (or a label
    this does not know)."""
    for field in fields:
        value = finding.get(field)
        if value is None or value == "":
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return max(0, min(100, int(value)))
        label = str(value).strip().lower()
        if label in _LABELS:
            return _LABELS[label]
        try:
            return max(0, min(100, int(float(label))))
        except ValueError:
            continue
    return None


def confidence_score(finding: dict, *, fields: tuple[str, ...] = _FIELDS) -> int:
    """The confidence a finding states, or ``UNSCORED``."""
    stated = stated_confidence(finding, fields=fields)
    return UNSCORED if stated is None else stated


def confidence_label(score: int) -> str:
    """HIGH from 85, MEDIUM from 60, LOW below - the risk engine's thresholds."""
    if score >= 85:
        return "HIGH"
    if score >= 60:
        return "MEDIUM"
    return "LOW"
