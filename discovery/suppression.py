"""Suppression rules: what a scan has been told not to report again (B6).

A rule is an analyst's decision, not a change to the detectors. The detectors still
run, the findings cache still holds everything they found, and the rule decides what
the scan *emits*. Deleting a rule brings the finding back on the next scan without
re-reading or re-classifying a single file.

A rule matches a finding on four things, any of which may be left empty to mean "any":

``finding_type``
    the detector's own name for what it found (``credit_card``, ``email``);
``source``
    ``local``, ``smb``, ``endpoint-winrm``, ``endpoint-local``;
``path_pattern``
    the path exactly as the finding shows it, or a prefix ending in ``*``. Separators
    and case are normalized, because the same file is written ``C:\\Data\\x.csv`` by one
    collector and ``C:/Data/x.csv`` by another;
``fingerprint``
    one secure value fingerprint, so a rule can be "this number here, not this
    detector everywhere". Fingerprints are salted per tenant, never the value.

A rule with all four empty would suppress the whole estate, and is refused where rules
are created (``store.create_suppression_rule``) rather than here.

**A finding is not a value.** One finding carries every match its detector made in that
file, so a value rule may only suppress a finding when *every* value it carries is
covered - by that rule or another - and when the finding is not truncated, because a
truncated finding carries fewer fingerprints than it found. Dismissing one card number
must never hide the other nine in the same file.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

# What one tenant may hold. The matcher is a linear scan per finding, so the cap is
# what keeps it a rounding error rather than a scan-time cost.
MAX_SUPPRESSION_RULES = 500


def normalized_path(value: str) -> str:
    """One spelling for a path: forward slashes, no trailing separator, casefolded."""
    text = str(value or "").replace("\\", "/").strip().casefold()
    while len(text) > 1 and text.endswith("/"):
        text = text[:-1]
    return text


@dataclass(frozen=True)
class CompiledRule:
    rule_id: str
    finding_type: str
    source: str
    path: str
    prefix: str
    fingerprint: str

    def covers(self, finding_type: str, source: str, path: str) -> bool:
        """Whether the rule's type, source and path all admit this finding."""
        if self.finding_type and self.finding_type != finding_type:
            return False
        if self.source and self.source != source:
            return False
        if self.prefix:
            return path.startswith(self.prefix)
        if self.path:
            return path == self.path
        return True


class SuppressionMatcher:
    """The rules of one scan, compiled once and asked per finding."""

    __slots__ = ("_broad", "_by_value", "digest")

    def __init__(self, rules: list[CompiledRule], digest: str) -> None:
        # A rule naming no value covers a finding on its own; a rule naming one can
        # only ever cover a finding together with the rules covering its other values.
        self._broad = [rule for rule in rules if not rule.fingerprint]
        self._by_value = [rule for rule in rules if rule.fingerprint]
        self.digest = digest

    def __bool__(self) -> bool:
        return bool(self._broad or self._by_value)

    def __len__(self) -> int:
        return len(self._broad) + len(self._by_value)

    def match(self, *, finding_type: str, source: str, path: str, fingerprints=(), truncated: bool = False) -> str:
        """The id of a rule that covers this whole finding, or an empty string."""
        if not (self._broad or self._by_value):
            return ""
        finding_type = str(finding_type or "").strip().casefold()
        source = str(source or "").strip().casefold()
        path = normalized_path(path)
        for rule in self._broad:
            if rule.covers(finding_type, source, path):
                return rule.rule_id
        if truncated or not self._by_value:
            # More values than fingerprints: what the rules cover is not what the
            # finding found, so the finding stands.
            return ""
        prints = {str(item).strip() for item in (fingerprints or ()) if str(item).strip()}
        if not prints:
            return ""
        matched = ""
        for value in prints:
            covering = next(
                (
                    rule.rule_id
                    for rule in self._by_value
                    if rule.fingerprint == value and rule.covers(finding_type, source, path)
                ),
                "",
            )
            if not covering:
                return ""
            matched = matched or covering
        return matched


def _expired(rule: dict, now: datetime) -> bool:
    expires_at = str(rule.get("expires_at") or "").strip()
    if not expires_at:
        return False
    try:
        moment = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        # An unparseable expiry is treated as expired: a rule nobody can date is a
        # rule that stops hiding findings, never one that hides them forever.
        return True
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment <= now


def compile_rules(rules, now: datetime | None = None) -> SuppressionMatcher:
    """Compile stored rules into a matcher, dropping the inactive and the expired.

    Expiry is resolved once, when the scan starts: a rule that runs out during a long
    scan keeps applying to that scan, and stops at the next one. A scan whose findings
    changed halfway through would be harder to explain than one that is a day late.
    """
    moment = now or datetime.now(timezone.utc)
    compiled: list[CompiledRule] = []
    for rule in rules or []:
        if not isinstance(rule, dict):
            continue
        if not bool(rule.get("active", True)) or _expired(rule, moment):
            continue
        pattern = normalized_path(rule.get("path_pattern"))
        prefix = ""
        if pattern.endswith("*"):
            prefix, pattern = pattern[:-1], ""
        compiled.append(
            CompiledRule(
                rule_id=str(rule.get("rule_id") or ""),
                finding_type=str(rule.get("finding_type") or "").strip().casefold(),
                source=str(rule.get("source") or "").strip().casefold(),
                path=pattern,
                prefix=prefix,
                fingerprint=str(rule.get("fingerprint") or "").strip(),
            )
        )
    return SuppressionMatcher(compiled, rules_digest(compiled))


def rules_digest(compiled) -> str:
    """A stable token for a set of compiled rules.

    It joins the reuse version signature, so adding or removing a rule invalidates
    cached analysis rather than letting an unchanged file replay findings the rule now
    covers - or keep hiding findings a deleted rule no longer covers.
    """
    if not compiled:
        return ""
    payload = sorted(
        [rule.rule_id, rule.finding_type, rule.source, rule.path, rule.prefix, rule.fingerprint]
        for rule in compiled
    )
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
