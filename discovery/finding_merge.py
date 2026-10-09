"""One finding per value, whatever found it (B7).

Three detectors read the same file, and a card number in it produced three findings: the
generic rule's `credit_card`, GDPR's `gdpr_payment_card_data` and PCI's `pci_chd_pan`.
An analyst saw one card three times, in three severities, and dismissing one left the
other two. The same email produced two.

They are merged here, at the end of the detector stage, where every detector's output is
in one list and nothing downstream has looked at it yet:

- **what merges**: findings about the same **value** - the same canonical entity type
  (B7a's one vocabulary) and at least one canonical value fingerprint in common. An API
  key and a JWT in one file are both credentials and are NOT one finding: they are two
  values, and an analyst rotates them separately. A finding no vocabulary can name - a
  keyword match, a context observation - merges with nothing, and neither does one that
  carries no value fingerprint, because "unnamed" is not an identity;
- **what does not**: the same value in two protection states. A readable PAN and a
  tokenized one are two different facts about a file, and PCI cares about the difference.
  A finding whose protection state is unknown joins the strongest known one, because the
  detectors that report no state are the ones that read the value in the clear;
- **what survives**: the strongest severity, the union of the framework tags, the highest
  count - never the sum, since the detectors counted the same values - and `detected_by`,
  the list of rules that found it, so nothing downstream keyed on a rule name loses its
  key. What a person is *shown* stays the primary's: two detectors mask one email two
  ways, and a union would show one value twice.

The merged finding keeps the **primary** contributor's type and display name (the
strongest, then a stable tie-break), which is what lets the maps keyed on a rule name -
compliance categories, remediation policy, the inventory's labels - keep resolving.
"""

from __future__ import annotations

from classification.compliance.canonical_entities import canonical_entity_type_for_finding

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "": 0}

# How readable the value is, strongest first. A state absent from this map is
# treated as unknown, which joins the strongest known state in its group.
PROTECTION_RANK = {
    "READABLE_FULL": 6,
    "READABLE_PARTIAL": 5,
    "MASKED": 4,
    "HASHED_UNKEYED_OR_UNKNOWN": 3,
    "ENCRYPTED": 2,
    "TOKENIZED": 1,
}
UNKNOWN_PROTECTION = {"", "UNKNOWN", "NOT_ASSESSED", "NONE", "NOT_APPLICABLE"}

# Fields whose values are unions across the findings that merged.
UNION_FIELDS = (
    "canonical_entity_fingerprints",
    "correlated_elements",
    "framework_mappings",
    "frameworks",
    "evidence_ids",
)
# What a person is shown stays the PRIMARY's. Two detectors mask the same email two
# ways - "o***@example.com" and "oma***om" - so a union would show one value twice and
# make the evidence disagree with the count. The fingerprints go with it, because a
# suppression rule written for one value (B6) has to keep covering that finding.
PRIMARY_EVIDENCE_FIELDS = ("samples", "secure_value_fingerprints", "secure_fingerprints")
# Fields whose value is the largest any contributor reported.
MAX_FIELDS = ("count", "occurrence_count", "unique_value_count", "confidence", "risk_score",
              "operational_risk_score", "sample_count")
SAMPLE_CAP = 10
OCCURRENCE_CAP = 100


def severity_of(finding: dict) -> str:
    return str(finding.get("impact_severity") or finding.get("risk") or "").strip().upper()


def protection_of(finding: dict) -> str:
    state = str(finding.get("protection_state") or finding.get("encryption_state") or "").strip().upper()
    return "" if state in UNKNOWN_PROTECTION else state


def is_context_only(finding: dict) -> bool:
    """A keyword or routing observation: evidence about a file, not a value in it.

    The canonical registry excludes exactly these from becoming entities, and the merge
    excludes them for the same reason - two context observations that mention a card are
    not one card.
    """
    return (
        finding.get("scope_candidate") is False
        or str(finding.get("custom_rule_mode") or "").upper() == "CONTEXT_ONLY"
        or str(finding.get("protection_state") or "").upper() == "CONTEXT_ONLY"
        or str(finding.get("finding_role") or "").lower() == "custom_context_observation"
    )


def merge_key(finding: dict) -> str:
    """What this finding is about, or "" when nothing can name it."""
    if is_context_only(finding):
        return ""
    return canonical_entity_type_for_finding(finding)


def merge_findings(findings: list[dict]) -> list[dict]:
    """One finding per (value kind, protection state) in this file; the rest untouched."""
    if len(findings) < 2:
        return findings

    groups: dict[str, list[int]] = {}
    for index, finding in enumerate(findings):
        key = merge_key(finding)
        if key:
            groups.setdefault(key, []).append(index)

    merged_at: dict[int, dict] = {}
    absorbed: set[int] = set()
    for indexes in groups.values():
        for bucket in _buckets([findings[index] for index in indexes], indexes):
            for same_value in _by_shared_value(findings, bucket):
                if len(same_value) < 2:
                    continue
                first = min(same_value)
                merged_at[first] = _merge([findings[index] for index in same_value])
                absorbed.update(set(same_value) - {first})

    if not merged_at:
        return findings
    return [
        merged_at.get(index, finding)
        for index, finding in enumerate(findings)
        if index not in absorbed
    ]


def _buckets(group: list[dict], indexes: list[int]) -> list[list[int]]:
    """Split one entity's findings by protection state, unknown joining the strongest known."""
    by_state: dict[str, list[int]] = {}
    unknown: list[int] = []
    for finding, index in zip(group, indexes):
        state = protection_of(finding)
        if state:
            by_state.setdefault(state, []).append(index)
        else:
            unknown.append(index)
    if not by_state:
        return [unknown]
    strongest = max(by_state, key=lambda state: (PROTECTION_RANK.get(state, 0), state))
    by_state[strongest].extend(unknown)
    return list(by_state.values())


def _by_shared_value(findings: list[dict], bucket: list[int]) -> list[list[int]]:
    """Split one bucket into the sets that share a value.

    Two findings are about the same value when their canonical fingerprints overlap -
    the fingerprint every detector now computes the same way (B7a). A finding with no
    fingerprint is its own set: a detector that reports a kind without a value has not
    told us which value, and merging on the kind alone would put an API key and a JWT in
    one finding.
    """
    groups: list[tuple[set[str], list[int]]] = []
    for index in bucket:
        prints = {str(item) for item in (findings[index].get("canonical_entity_fingerprints") or []) if item}
        if not prints:
            groups.append((set(), [index]))
            continue
        for known, members in groups:
            if known & prints:
                known |= prints
                members.append(index)
                break
        else:
            groups.append((prints, [index]))
    return [members for _prints, members in groups]


def _primary(findings: list[dict]) -> dict:
    """The finding the merged one is built from: strongest, then a stable tie-break.

    Severity decides, because the merged finding has to carry the worst thing that is
    true about the value. Everything after it is only there so two runs of the same scan
    produce the same primary.
    """
    return sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_RANK.get(severity_of(finding), 0),
            -PROTECTION_RANK.get(protection_of(finding), 0),
            -len(finding.get("secure_value_fingerprints") or finding.get("secure_fingerprints") or []),
            str(finding.get("type") or ""),
        ),
    )[0]


def _merge(findings: list[dict]) -> dict:
    primary = _primary(findings)
    others = [finding for finding in findings if finding is not primary]
    merged = dict(primary)

    # Anything the primary does not carry, the others may - a field is only ever
    # filled in, never overwritten, so the primary stays the one being described.
    for finding in others:
        for key, value in finding.items():
            if key not in merged or merged[key] in (None, "", [], {}):
                merged[key] = value

    for field in UNION_FIELDS:
        values: list = []
        for finding in findings:
            for item in finding.get(field) or []:
                if item not in values:
                    values.append(item)
        if values:
            merged[field] = values[:SAMPLE_CAP if field == "canonical_entity_fingerprints" else OCCURRENCE_CAP]

    for field in PRIMARY_EVIDENCE_FIELDS:
        evidence = primary.get(field) or next((finding.get(field) for finding in others if finding.get(field)), None)
        if evidence is not None:
            merged[field] = list(evidence)[:SAMPLE_CAP]

    merged["occurrences"] = _merged_occurrences(findings)
    if not merged["occurrences"]:
        merged.pop("occurrences", None)

    for field in MAX_FIELDS:
        numbers = [_as_int(finding.get(field)) for finding in findings if finding.get(field) is not None]
        if numbers:
            # The largest, not the sum: the detectors counted the same values, so adding
            # them up would report one card as two.
            merged[field] = max(numbers)

    severity = max((severity_of(finding) for finding in findings),
                   key=lambda value: SEVERITY_RANK.get(value, 0))
    if severity:
        merged["impact_severity"] = severity
        if merged.get("risk"):
            merged["risk"] = severity
    state = max((protection_of(finding) for finding in findings),
                key=lambda value: PROTECTION_RANK.get(value, 0))
    if state:
        merged["protection_state"] = state

    if merged.get("samples") is not None:
        merged["sample_count"] = len(merged["samples"])
    merged["detected_by"] = sorted({str(finding.get("type") or "") for finding in findings if finding.get("type")})
    merged["merged_finding_count"] = len(findings)
    return merged


def _merged_occurrences(findings: list[dict]) -> list[dict]:
    """Every detector's evidence, with the same value in the same place counted once.

    Two detectors that matched the same span found one occurrence, however differently
    they masked it; a detector that reports no offsets is deduplicated by what it shows.
    """
    merged: list[dict] = []
    seen: set = set()
    for finding in findings:
        for occurrence in finding.get("occurrences") or []:
            if not isinstance(occurrence, dict):
                continue
            start = _as_int(occurrence.get("offset_start"))
            end = _as_int(occurrence.get("offset_end"))
            key = (
                (start, end)
                if start or end
                else (str(occurrence.get("secure_fingerprint") or ""), str(occurrence.get("redacted_sample") or occurrence.get("sample") or ""))
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(occurrence)
            if len(merged) >= OCCURRENCE_CAP:
                return merged
    return merged


def _as_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
