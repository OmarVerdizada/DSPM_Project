"""B7a: one value is one entity, whichever detector found it.

"Detected once, mapped many" is the contract the canonical registry exists for, and it
was only half true. The generic detector named what it found with a masking `data_class`
("email", "pan"); the compliance detectors named the same thing with an `entity_type`
("EMAIL_ADDRESS", "PAN"); and the fingerprints the registry falls back to were a masked
token on one side and a digest of the raw value on the other. One email in one file
therefore registered as two entities, and one card as two - a CREDIT_CARD and a PAN.

One vocabulary, and every detector fingerprinting a value the same way, is what lets the
merge in B7b know that two findings are about the same thing.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from classification.compliance.canonical_entities import (
    canonical_entity_fingerprint,
    canonical_entity_type_for_finding,
    normalize_entity_type,
)
from classification.regex_classifier import classify_content
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

CARD = "4111 1111 1111 1111"
EMAIL = "ana.mammadova@example.com"
CONTENT = f"name: Ana Mammadova\nemail: {EMAIL}\ncard number: {CARD}\n"


class TheOneVocabularyTest(unittest.TestCase):

    def test_a_generic_rule_is_named_the_same_as_the_compliance_rule_for_it(self) -> None:
        self.assertEqual(canonical_entity_type_for_finding({"type": "credit_card", "data_class": "pan"}), "PAN")
        self.assertEqual(canonical_entity_type_for_finding({"type": "gdpr_payment_card_data"}), "PAN")
        self.assertEqual(canonical_entity_type_for_finding({"type": "pci_chd_pan"}), "PAN")
        self.assertEqual(canonical_entity_type_for_finding({"type": "email", "data_class": "email"}), "EMAIL_ADDRESS")
        self.assertEqual(canonical_entity_type_for_finding({"type": "gdpr_email_address"}), "EMAIL_ADDRESS")

    def test_a_value_nobody_can_name_is_not_an_entity(self) -> None:
        self.assertEqual(canonical_entity_type_for_finding({"type": "confidential_keyword", "data_class": "generic"}), "")
        self.assertEqual(canonical_entity_type_for_finding({}), "")

    def test_two_names_for_one_thing_resolve_to_one(self) -> None:
        self.assertEqual(normalize_entity_type("CREDIT_CARD"), "PAN")
        self.assertEqual(normalize_entity_type("payment card"), "PAN")
        self.assertEqual(normalize_entity_type("email"), "EMAIL_ADDRESS")
        self.assertEqual(canonical_entity_type_for_finding({"canonical_entity_type": "credit_card"}), "PAN")
        self.assertEqual(normalize_entity_type("PAN"), "PAN", "a name that is already canonical stays put")

    def test_what_a_finding_says_about_itself_wins(self) -> None:
        finding = {"canonical_entity_type": "PIN", "type": "email", "data_class": "email"}
        self.assertEqual(canonical_entity_type_for_finding(finding), "PIN")


class TheGenericDetectorFingerprintsLikeTheOthersTest(unittest.TestCase):

    def _finding(self, findings: list[dict], finding_type: str) -> dict:
        return next(item for item in findings if item.get("type") == finding_type)

    def test_it_fingerprints_the_value_the_way_the_registry_does(self) -> None:
        findings = classify_content(CONTENT, tenant_id="tenant-b7")
        card = self._finding(findings, "credit_card")
        self.assertEqual(card["canonical_entity_type"], "PAN")
        self.assertEqual(
            card["canonical_entity_fingerprints"],
            [canonical_entity_fingerprint("PAN", CARD, "tenant-b7")],
            "a card found by the generic detector must fingerprint as the same value the compliance one found",
        )

    def test_one_tenants_values_do_not_fingerprint_as_another_tenants(self) -> None:
        mine = self._finding(classify_content(CONTENT, tenant_id="tenant-a"), "email")
        theirs = self._finding(classify_content(CONTENT, tenant_id="tenant-b"), "email")
        self.assertTrue(mine["canonical_entity_fingerprints"])
        self.assertNotEqual(mine["canonical_entity_fingerprints"], theirs["canonical_entity_fingerprints"])

    def test_a_keyword_rule_has_no_value_and_so_no_fingerprint(self) -> None:
        findings = classify_content("This document is strictly confidential.", tenant_id="t")
        for finding in findings:
            with self.subTest(finding=finding.get("type")):
                self.assertEqual(finding.get("canonical_entity_fingerprints"), [],
                                 "a rule that matches a keyword has no value to fingerprint")


class OneValueIsOneEntityTest(unittest.TestCase):
    """The end of the story, on the real engine with both frameworks on."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.engine = DSPMDiscoveryEngine(
            ScanConfig(
                tenant_id="tenant-b7",
                walk_local_path=False,
                incremental_enabled=False,
                persistent_cache_enabled=False,
                cache_dir=str(Path(self._dir.name) / "cache"),
                compliance_enabled=True,
                compliance_frameworks=["pci_dss", "gdpr"],
            )
        )

    def tearDown(self) -> None:
        self._dir.cleanup()

    def _analyzed(self) -> dict:
        return self.engine._analyze_record({
            "source": "local",
            "share": "local",
            "path": r"C:\Data\customers.csv",
            "name": "customers.csv",
            "size": len(CONTENT),
            "extension": ".csv",
            "modified_at": "2026-09-01T00:00:00Z",
            "tenant_id": "tenant-b7",
            "content": CONTENT,
        })

    def test_one_card_and_one_email_are_two_entities_not_four(self) -> None:
        analyzed = self._analyzed()
        entities = analyzed["canonical_entities"]
        self.assertEqual(
            sorted(entity["entity_type"] for entity in entities),
            ["EMAIL_ADDRESS", "PAN"],
            "the same value registered twice under two names",
        )

    def test_the_detectors_that_found_the_same_value_point_at_the_same_entity(self) -> None:
        """Asked of the detectors' own output, because B7b then merges them into one finding."""
        from classification.compliance import classify_gdpr_content, classify_pci_content
        from classification.compliance.canonical_entities import apply_canonical_entity_registry
        from classification.regex_classifier import classify_content

        file_obj = {"path": r"C:\Data\customers.csv", "name": "customers.csv",
                    "source": "local", "tenant_id": "tenant-b7"}
        findings = [
            *classify_content(CONTENT, tenant_id="tenant-b7"),
            *classify_gdpr_content(CONTENT, file_obj, []),
            *classify_pci_content(CONTENT, file_obj, []),
        ]
        apply_canonical_entity_registry(findings, file_obj)
        by_type = {finding["type"]: finding for finding in findings}

        self.assertEqual(
            by_type["email"]["canonical_entity_id"],
            by_type["gdpr_email_address"]["canonical_entity_id"],
            "one email, two entity ids",
        )
        self.assertEqual(
            by_type["credit_card"]["canonical_entity_id"],
            by_type["pci_chd_pan"]["canonical_entity_id"],
            "one card, two entity ids",
        )

    def test_the_card_entity_carries_both_frameworks(self) -> None:
        entities = {entity["entity_type"]: entity for entity in self._analyzed()["canonical_entities"]}
        self.assertEqual(sorted(entities["PAN"]["framework_mappings"]), ["GDPR", "PCI DSS"])

    def test_the_finding_and_the_entity_agree_on_what_the_value_is(self) -> None:
        for finding in self._analyzed()["findings"]:
            canonical = finding.get("canonical_entity_type")
            if not canonical:
                continue
            with self.subTest(finding=finding.get("type")):
                self.assertEqual(finding["entity_type"], canonical,
                                 "the id a finding gets says one thing and the entity it points at says another")


if __name__ == "__main__":
    unittest.main()
