"""The payment-card detector, measured rather than asserted.

The exit gate for A2 in docs/SENTRO_PRODUCT_GAP_ANALYSIS_AND_ROADMAP_2026-09.md:
precision and recall at or above 0.95, and nothing that is not a card reported
as CRITICAL.

Measured on this corpus with the rule that shipped - a Luhn checksum and nothing
else - recall was 0.993 and **precision was 0.525**: 135 of the 350 documents
that contain no card at all were reported as containing one. That is the number
behind "it considers all 16-digit texts as credit cards", and it is why a
checksum is a necessary condition and never a sufficient one.

The corpus is built by tests/pan_corpus.py from a fixed seed. Its negatives are
the shapes that actually occur in an enterprise estate - IMEIs, order and
tracking ids, loyalty and meter numbers - all Luhn-valid, none of them issued by
a card scheme.
"""

from __future__ import annotations

import unittest

from discovery.detector_stage import run_detector_stage
from tests.pan_corpus import build_corpus

# Every finding type that claims "this is a payment card number".
PAN_FINDING_TYPES = frozenset({
    "credit_card",
    "gdpr_payment_card_data",
    "pci_chd_pan",
    "pci_chd_truncated_pan",
    "pci_tokenized_pan",
    "pci_hashed_pan",
    "pci_encrypted_pan",
    "pci_chd_masked_pan",
})

ACTIONABLE = frozenset({"HIGH", "MEDIUM"})
RECALL_FLOOR = 0.95
PRECISION_FLOOR = 0.95


def _scan(document) -> list[dict]:
    record = {
        "name": document.name,
        "path": "\\\\fs01\\corpus\\" + document.name,
        "extension": ".txt",
    }
    result = run_detector_stage({
        "content": document.text,
        "record": record,
        "framework_ids": ["pci_dss", "gdpr"],
        "compliance_enabled": True,
        "timeout_seconds": 0,
        "custom_keywords": {},
    })
    return [f for f in result["findings"] if f.get("type") in PAN_FINDING_TYPES]


class PanCorpusGateTests(unittest.TestCase):
    """One scan of the corpus, several claims about it."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.documents = build_corpus()
        cls.findings = {document.name: _scan(document) for document in cls.documents}

    def _tiers(self, name: str) -> set[str]:
        return {
            str(f.get("pan_confidence") or "").upper()
            for f in self.findings[name]
            if f.get("pan_confidence")
        }

    def _claims_a_card(self, name: str) -> bool:
        """A detector said "payment card" at a tier worth acting on.

        A finding carrying no tier at all still counts: the GDPR detector reports
        a card without a confidence field, and it must not escape the measurement
        by staying silent about how sure it is.
        """
        found = self.findings[name]
        if not found:
            return False
        tiers = self._tiers(name)
        return not tiers or bool(tiers & ACTIONABLE)

    def _split(self) -> tuple[list, list]:
        cards = [d for d in self.documents if d.label == "positive"]
        not_cards = [d for d in self.documents if d.label != "positive"]
        return cards, not_cards

    def test_the_corpus_is_the_shape_it_claims_to_be(self) -> None:
        labels = [document.label for document in self.documents]
        self.assertEqual(labels.count("positive"), 150)
        self.assertEqual(labels.count("negative"), 150)
        self.assertEqual(labels.count("clean"), 200)

    def test_recall_holds(self) -> None:
        cards, _ = self._split()
        found = [d for d in cards if self._claims_a_card(d.name)]
        recall = len(found) / len(cards)
        self.assertGreaterEqual(
            recall, RECALL_FLOOR,
            f"recall {recall:.3f}; missed {[d.name for d in cards if not self._claims_a_card(d.name)][:10]}",
        )

    def test_precision_holds(self) -> None:
        """The measurement that failed before: 135 false positives, 0.525."""
        cards, not_cards = self._split()
        true_positive = sum(1 for d in cards if self._claims_a_card(d.name))
        false_positive = [d.name for d in not_cards if self._claims_a_card(d.name)]
        precision = true_positive / max(1, true_positive + len(false_positive))
        self.assertGreaterEqual(
            precision, PRECISION_FLOOR,
            f"precision {precision:.3f}; false positives {false_positive[:10]}",
        )

    def test_nothing_that_is_not_a_card_is_ever_critical(self) -> None:
        """A guess is allowed to be wrong. It is not allowed to be urgent."""
        _, not_cards = self._split()
        offenders = [
            (document.name, finding.get("type"), finding.get("risk"), finding.get("pan_confidence"))
            for document in not_cards
            for finding in self.findings[document.name]
            if "CRITICAL" in {
                str(finding.get("risk") or "").upper(),
                str(finding.get("impact_severity") or "").upper(),
            }
        ]
        self.assertEqual(offenders, [], f"non-card documents reported at CRITICAL: {offenders[:10]}")

    def test_a_luhn_valid_operational_identifier_is_not_a_card(self) -> None:
        """The specific complaint. IMEIs, order ids and meter numbers all carry
        a mod-10 check digit; none of them is issued by a card scheme."""
        negatives = [d for d in self.documents if d.label == "negative"]
        claimed = [d.name for d in negatives if self.findings[d.name]]
        self.assertEqual(claimed, [], f"operational identifiers reported as cards: {claimed[:10]}")

    def test_a_bare_export_is_confirmed_by_density_not_by_prose(self) -> None:
        """A payments export is a column of numbers with no words near them.

        Nothing a context window can see makes those cards, so several distinct
        issuer-valid numbers in one file is what confirms them.
        """
        dense = [d for d in self.documents if d.label == "positive" and len(d.pans) > 1]
        self.assertTrue(dense, "the corpus should contain bare multi-card exports")
        for document in dense:
            with self.subTest(document=document.name):
                self.assertIn("HIGH", self._tiers(document.name))

    def test_a_confirmed_card_still_reaches_critical(self) -> None:
        """Tightening the gate must not cost the finding that matters."""
        labelled = [
            d for d in self.documents
            if d.label == "positive" and len(d.pans) == 1 and "card" in d.text.lower()
        ]
        self.assertTrue(labelled)
        critical = [
            d.name for d in labelled
            if any(str(f.get("risk") or "").upper() == "CRITICAL" for f in self.findings[d.name])
        ]
        self.assertGreaterEqual(len(critical), len(labelled) * 0.9)


if __name__ == "__main__":
    unittest.main()
