"""B7: one card is one finding, whatever found it - and it says what found it.

The gate, in the roadmap's words: **"Email" appears once; PAN once with two framework
tags.** Before this, three detectors reading one file reported one card three times - the
generic `credit_card`, GDPR's `gdpr_payment_card_data` and PCI's `pci_chd_pan` - in three
severities, and dismissing one left the other two standing.

The merge runs at the end of the detector stage, and the rules it follows are the
interesting part:

- it merges findings about the same **value** - one vocabulary can name it, and their
  canonical fingerprints agree. Two credentials in one file are two findings, because an
  analyst rotates them separately; a keyword match merges with nothing at all, being
  evidence about a file rather than a value in it;
- it keeps a readable PAN and a tokenized PAN apart, because PCI cares about exactly that
  difference, while a finding that reports no protection state joins the strongest known
  one - the detectors that report nothing are the ones that read the value in the clear;
- it keeps the strongest severity, the union of the framework tags and the highest count -
  never the sum, because the detectors counted the same values;
- what a person is shown stays one detector's: two detectors mask one email two ways, and
  a union would show the same value twice.

`detected_by` is what keeps the merge honest downstream: every map keyed on a rule name -
compliance categories, the remediation policy's type sets - reads it, so merging cannot
quietly drop a key that used to resolve.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from backend.compliance_rules import categories_for_finding
from backend.finding_contracts import finding_detected_types
from backend.reporting.report_model import _file_risk_types
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.finding_merge import merge_findings

CARD = "4111 1111 1111 1111"
CONTENT = f"name: Ana Mammadova\nemail: ana.mammadova@example.com\ncard number: {CARD}\n"


def _finding(finding_type: str, value: str = "value-1", **overrides) -> dict:
    """A detector's output. `value` is the identity: two findings of one value share it."""
    finding = {"type": finding_type, "risk": "MEDIUM", "count": 1, "samples": ["x"],
               "secure_value_fingerprints": [f"fp-{finding_type}"],
               "canonical_entity_fingerprints": [f"cv-{value}"]}
    finding.update(overrides)
    return finding


class TheMergeRulesTest(unittest.TestCase):

    def test_two_detectors_that_found_one_card_produce_one_finding(self) -> None:
        merged = merge_findings([
            _finding("credit_card", data_class="pan", risk="HIGH", count=1),
            _finding("pci_chd_pan", risk="CRITICAL", count=2, protection_state="READABLE_FULL",
                     framework_mappings=["PCI DSS"]),
        ])
        self.assertEqual(len(merged), 1)
        card = merged[0]
        self.assertEqual(card["type"], "pci_chd_pan", "the worst thing true about the value describes it")
        self.assertEqual(card["impact_severity"], "CRITICAL")
        self.assertEqual(card["detected_by"], ["credit_card", "pci_chd_pan"])
        self.assertEqual(card["count"], 2, "the detectors counted the same card; two is not three")

    def test_a_readable_card_and_a_tokenized_one_are_two_facts(self) -> None:
        merged = merge_findings([
            _finding("pci_chd_pan", risk="CRITICAL", protection_state="READABLE_FULL"),
            _finding("pci_tokenized_pan", risk="LOW", protection_state="TOKENIZED"),
        ])
        self.assertEqual(sorted(item["type"] for item in merged), ["pci_chd_pan", "pci_tokenized_pan"])

    def test_a_finding_that_reports_no_protection_joins_the_strongest_known(self) -> None:
        merged = merge_findings([
            _finding("credit_card", data_class="pan", risk="HIGH"),
            _finding("pci_chd_pan", risk="CRITICAL", protection_state="READABLE_FULL"),
            _finding("pci_tokenized_pan", risk="LOW", protection_state="TOKENIZED"),
        ])
        self.assertEqual(len(merged), 2)
        readable = next(item for item in merged if item["type"] == "pci_chd_pan")
        self.assertIn("credit_card", readable["detected_by"], "a value read in the clear is not the tokenized one")

    def test_two_values_of_the_same_kind_are_two_findings(self) -> None:
        """An API key and a JWT are both credentials, and an analyst rotates them separately."""
        merged = merge_findings([
            _finding("api_key", value="key-1", data_class="secret", risk="HIGH"),
            _finding("jwt", value="token-1", data_class="secret", risk="HIGH"),
        ])
        self.assertEqual(sorted(item["type"] for item in merged), ["api_key", "jwt"])

    def test_a_finding_with_no_value_fingerprint_merges_with_nothing(self) -> None:
        merged = merge_findings([
            _finding("credit_card", data_class="pan", canonical_entity_fingerprints=[]),
            _finding("pci_chd_pan", risk="CRITICAL", canonical_entity_fingerprints=[]),
        ])
        self.assertEqual(len(merged), 2, "a detector that named no value did not say which value")

    def test_a_keyword_observation_merges_with_nothing(self) -> None:
        findings = [
            _finding("credit_card", data_class="pan", risk="HIGH"),
            _finding("pci_scope_context", scope_candidate=False, canonical_entity_type="PAN"),
        ]
        merged = merge_findings(findings)
        self.assertEqual(len(merged), 2, "context about a card is not a card")

    def test_findings_nothing_can_name_are_left_where_they_are(self) -> None:
        findings = [_finding("confidential_keyword", data_class="generic"), _finding("api_key", data_class="secret")]
        self.assertEqual(merge_findings(findings), findings)

    def test_the_merged_finding_takes_the_place_of_the_first_it_absorbed(self) -> None:
        findings = [
            _finding("email", data_class="email"),
            _finding("api_key", data_class="secret"),
            _finding("gdpr_email_address", risk="HIGH"),
        ]
        merged = merge_findings(findings)
        self.assertEqual([item["type"] for item in merged], ["gdpr_email_address", "api_key"],
                         "the merged finding stays where the scan first reported it")

    def test_what_a_person_is_shown_comes_from_one_detector(self) -> None:
        merged = merge_findings([
            _finding("email", data_class="email", samples=["o***@example.com"],
                     secure_value_fingerprints=["[redacted:aa]"]),
            _finding("gdpr_email_address", samples=["oma***om"], secure_value_fingerprints=["deadbeef"]),
        ])[0]
        self.assertEqual(merged["samples"], ["o***@example.com"], "one value was shown twice, masked two ways")
        self.assertEqual(merged["secure_value_fingerprints"], ["[redacted:aa]"])
        self.assertEqual(merged["sample_count"], 1)

    def test_the_same_value_in_the_same_place_is_one_occurrence(self) -> None:
        merged = merge_findings([
            _finding("email", data_class="email",
                     occurrences=[{"offset_start": 16, "offset_end": 32, "redacted_sample": "o***@example.com"}]),
            _finding("gdpr_email_address",
                     occurrences=[{"offset_start": 16, "offset_end": 32, "redacted_sample": "oma***om"}]),
        ])[0]
        self.assertEqual(len(merged["occurrences"]), 1, "two detectors matched one span and reported it twice")

    def test_a_single_finding_is_returned_untouched(self) -> None:
        findings = [_finding("credit_card", data_class="pan")]
        self.assertEqual(merge_findings(findings), findings)
        self.assertNotIn("detected_by", findings[0], "nothing was merged, so nothing has provenance to add")


class TheGateTest(unittest.TestCase):
    """One file, one email, one card, both frameworks on."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {"DSPM_SCAN_CACHE_DIR": str(Path(self._dir.name) / "cache")})
        self._env.start()
        self.analyzed = DSPMDiscoveryEngine(
            ScanConfig(
                tenant_id="tenant-b7",
                use_sample_when_empty=False,
                incremental_enabled=False,
                persistent_cache_enabled=False,
                cache_dir=str(Path(self._dir.name) / "cache"),
                compliance_enabled=True,
                compliance_frameworks=["pci_dss", "gdpr"],
            )
        )._analyze_record({
            "source": "local", "share": "local", "path": r"C:\Data\customers.csv", "name": "customers.csv",
            "size": len(CONTENT), "extension": ".csv", "modified_at": "2026-09-01T00:00:00Z",
            "tenant_id": "tenant-b7", "content": CONTENT,
        })

    def tearDown(self) -> None:
        self._env.stop()
        self._dir.cleanup()

    def test_the_email_appears_once(self) -> None:
        emails = [finding for finding in self.analyzed["findings"]
                  if finding.get("canonical_entity_type") == "EMAIL_ADDRESS"]
        self.assertEqual(len(emails), 1, "the same email was reported by more than one detector")
        self.assertEqual(sorted(emails[0]["detected_by"]), ["email", "gdpr_email_address"])

    def test_the_card_appears_once_with_two_framework_tags(self) -> None:
        cards = [finding for finding in self.analyzed["findings"]
                 if finding.get("canonical_entity_type") == "PAN"]
        self.assertEqual(len(cards), 1, "one card, reported more than once")
        card = cards[0]
        self.assertEqual(card["impact_severity"], "CRITICAL", "the merged finding lost the worst severity")
        self.assertEqual(sorted(card["detected_by"]),
                         ["credit_card", "gdpr_payment_card_data", "pci_chd_pan"])
        self.assertEqual(sorted(card["framework_mappings"]), ["GDPR", "PCI DSS"])

    def test_the_whole_file_is_two_findings(self) -> None:
        self.assertEqual(len(self.analyzed["findings"]), 2,
                         [finding["type"] for finding in self.analyzed["findings"]])


class NothingKeyedOnARuleNameLostItsKeyTest(unittest.TestCase):
    """The merge keeps one type; everything that read a type reads `detected_by` too."""

    def setUp(self) -> None:
        self.card = merge_findings([
            _finding("credit_card", data_class="pan", risk="HIGH"),
            _finding("gdpr_payment_card_data", risk="HIGH"),
            _finding("pci_chd_pan", risk="CRITICAL", protection_state="READABLE_FULL"),
        ])[0]

    def test_every_rule_that_found_it_is_still_readable(self) -> None:
        self.assertEqual(
            finding_detected_types(self.card),
            ["pci_chd_pan", "credit_card", "gdpr_payment_card_data"],
        )

    def test_the_compliance_categories_are_the_union_the_detectors_used_to_contribute(self) -> None:
        categories = categories_for_finding(self.card)
        self.assertIn("financial_records", categories, "the generic rule's category went with the merge")
        self.assertIn("pci_cardholder_data", categories)

    def test_a_files_remediation_still_knows_it_holds_a_card(self) -> None:
        from backend.reporting.remediation_policy import categorize_risk_types

        types = _file_risk_types({"findings": [self.card]})
        self.assertIn("credit_card", types)
        self.assertIn("financial", categorize_risk_types(types),
                      "the file would have been given the cautious fallback steps instead of the financial ones")


if __name__ == "__main__":
    unittest.main()
