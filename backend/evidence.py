"""What a role without `evidence.view` may not see (C3).

A scan reads content, and some of what it read travels with its results as *evidence*:
the preview of the lines around a match, the matched values themselves (masked, but
still derived from the document - a masked card number keeps its first six and last four
digits, a medical record number in a preview line may not be masked at all), and each
occurrence's redacted sample. That is what an analyst needs to confirm a finding, and
exactly what a scan operator, a viewer or an auditor does not: they need to know THAT a
file holds cardholder data and where, not what the card numbers are.

Evidence is a small, named set of fields, and it is the same set wherever a record goes -
the asset detail, a finding, its occurrences, a saved report, a scan job's result - so it
is removed here, in one place, on the way out:

* `preview` - lines of file content (replaced by an unavailable, `redacted` preview so a
  console can say why there is none);
* `samples`, `sample`, `redacted_sample`, `masked_preview` and the NIST contract's
  "Masked preview" - matched values;
* `iin_bin` - the PCI classifier's copy of a card's first eight digits, which the
  test that pins this module found surviving everything above;
* `keywords` where it sits beside `samples` - the compliance evidence entries repeat the
  matched values there;
* `context` when it is text - the PCI classifier's copy of the row a value was found in.

Everything else - types, counts, risk, fingerprints (one-way), locations, frameworks - is
the finding itself and stays.
"""

from __future__ import annotations

from typing import Any

_VALUE_KEYS = frozenset({"samples", "sample", "redacted_sample", "masked_preview", "Masked preview", "iin_bin"})

REDACTED_PREVIEW = {"available": False, "lines": [], "truncated": False, "redacted": True}


def redact_evidence(value: Any) -> tuple[Any, int]:
    """A copy of `value` without evidence, and how many evidence fields were removed.
    The original is not modified - callers may be holding a cached object."""

    if isinstance(value, dict):
        removed = 0
        result: dict = {}
        beside_samples = "samples" in value
        for key, item in value.items():
            if key in _VALUE_KEYS:
                removed += 1
                continue
            if key == "preview" and isinstance(item, (dict, str)):
                result[key] = dict(REDACTED_PREVIEW)
                removed += 1
                continue
            if key == "keywords" and beside_samples:
                removed += 1
                continue
            if key == "context" and isinstance(item, str):
                removed += 1
                continue
            result[key], inner = redact_evidence(item)
            removed += inner
        return result, removed
    if isinstance(value, list):
        removed = 0
        items = []
        for item in value:
            copied, inner = redact_evidence(item)
            items.append(copied)
            removed += inner
        return items, removed
    return value, 0


def without_evidence(payload: Any) -> Any:
    """`payload` with evidence removed, marked so a console can say why it is missing."""
    if not isinstance(payload, (dict, list)):
        return payload
    redacted, _ = redact_evidence(payload)
    if isinstance(redacted, dict):
        redacted["evidence_hidden"] = True
    return redacted
