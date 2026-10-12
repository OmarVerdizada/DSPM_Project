"""The four gates, one at a time.

The corpus gate in tests/test_pan_corpus_gate.py measures the result. This pins
each rule that produces it, so a regression says WHICH rule moved.
"""

from __future__ import annotations

import unittest

from classification.pan_validator import (
    cap_severity,
    card_issuer,
    is_luhn_valid,
    normalize_candidate,
    pan_hits,
    structural_exclusion,
    validate_pan,
)

CARD_CONTEXT = "Card number on file, expiry 12/28"


class ShapeGateTests(unittest.TestCase):
    def test_one_separator_style_only(self) -> None:
        self.assertEqual(normalize_candidate("4111 1111 1111 1111"), "4111111111111111")
        self.assertEqual(normalize_candidate("4111-1111-1111-1111"), "4111111111111111")
        # Two styles in one run is two numbers stuck together far more often
        # than it is a card.
        self.assertEqual(normalize_candidate("4111 1111-1111 1111"), "")

    def test_card_like_grouping_only(self) -> None:
        # A phone number and a date are not cards, however many digits they have.
        self.assertEqual(normalize_candidate("994 50 123 45 67 89"), "")
        self.assertEqual(normalize_candidate("4111 1111 1111 1111"), "4111111111111111")

    def test_letters_and_masks_are_not_candidates(self) -> None:
        self.assertEqual(normalize_candidate("4111 XXXX XXXX 1111"), "")
        self.assertEqual(normalize_candidate("4111abcd11111111"), "")

    def test_a_card_inside_a_longer_token_is_not_a_card(self) -> None:
        self.assertEqual(pan_hits("sha=a4111111111111119f2c3d4e5f60718293a4b5c6d"), [])


class ChecksumGateTests(unittest.TestCase):
    def test_luhn_is_required(self) -> None:
        self.assertTrue(is_luhn_valid("4111111111111111"))
        self.assertFalse(is_luhn_valid("4111111111111112"))
        self.assertIsNone(validate_pan("4111111111111112", context=CARD_CONTEXT))


class IssuerGateTests(unittest.TestCase):
    def test_every_brand_and_its_lengths(self) -> None:
        for digits, brand, valid in (
            ("4111111111111111", "visa", True),
            ("4222222222222", "visa", True),
            ("5555555555554444", "mastercard", True),
            ("2223003122003222", "mastercard", True),
            ("378282246310005", "amex", True),
            ("6011111111111117", "discover", True),
            ("3530111333300000", "jcb", True),
            ("6200000000000005", "unionpay", True),
            ("30569309025904", "diners", True),
            # Right prefix, a length that issuer does not use.
            ("41111111111111111", "visa", False),
            ("37828224631000", "amex", False),
        ):
            with self.subTest(digits=digits):
                self.assertEqual(card_issuer(digits), (brand, valid))

    def test_a_number_no_scheme_issues_is_not_a_card(self) -> None:
        self.assertEqual(card_issuer("9701234567890122")[0], "unknown")
        self.assertIsNone(validate_pan("9701234567890122"))

    def test_an_unknown_issuer_with_payment_context_is_a_possible_card(self) -> None:
        """Reported, so a real card on an unusual range is not lost - but LOW,
        and LOW can never be CRITICAL."""
        verdict = validate_pan("9701234567890122", context=CARD_CONTEXT)
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.confidence, "LOW")
        self.assertEqual(verdict.issuer, "unknown")
        self.assertEqual(cap_severity("CRITICAL", verdict.confidence), "MEDIUM")


class ExclusionGateTests(unittest.TestCase):
    def test_repeated_digits_are_a_serial_not_a_card(self) -> None:
        self.assertTrue(structural_exclusion("4444444444444448"))
        self.assertIsNone(validate_pan("4444444444444448", context=CARD_CONTEXT))

    def test_a_repeated_block_is_a_placeholder_not_a_card(self) -> None:
        """1234567812345670 satisfies Luhn. It is a placeholder."""
        self.assertTrue(structural_exclusion("1234567812345670"))
        self.assertTrue(structural_exclusion("4321432143214320"))

    def test_an_imei_is_not_a_card(self) -> None:
        self.assertTrue(structural_exclusion("490154203237518"))
        self.assertIsNone(validate_pan("490154203237518", context="Device IMEI"))

    def test_structure_beats_context(self) -> None:
        """A spreadsheet can say "card number" above a column of serials."""
        self.assertIsNone(validate_pan("4444444444444448", context="card number cvv expiry cardholder"))

    def test_a_published_test_card_is_reported_not_dropped(self) -> None:
        """Payment fixtures in production data are a finding about the estate."""
        verdict = validate_pan("4111111111111111", context=CARD_CONTEXT)
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.test_card, "visa_test")


class ConfidenceTests(unittest.TestCase):
    def test_context_confirms(self) -> None:
        self.assertEqual(validate_pan("4539578763621486", context=CARD_CONTEXT).confidence, "HIGH")

    def test_a_bare_card_is_worth_reviewing_not_confirming(self) -> None:
        self.assertEqual(validate_pan("4539578763621486", context="Reference recorded.").confidence, "MEDIUM")

    def test_a_negative_word_alone_drops_it(self) -> None:
        self.assertIsNone(validate_pan("4539578763621486", context="Order number recorded."))

    def test_density_confirms_a_file_with_no_words_in_it(self) -> None:
        export = "4539578763621486\n5555555555554444\n4012888888881881\n"
        self.assertTrue(all(hit.verdict.confidence == "HIGH" for hit in pan_hits(export)))

    def test_context_terms_match_as_words_not_substrings(self) -> None:
        # `card_number:` is the same word as "card number"...
        self.assertEqual(validate_pan("4539578763621486", context="card_number: x").confidence, "HIGH")
        self.assertEqual(validate_pan("4539578763621486", context='{"cardNumber":"x"}').confidence, "HIGH")
        # ...and "discard" is not.
        self.assertEqual(validate_pan("4539578763621486", context="Please discard this.").confidence, "MEDIUM")

    def test_confidence_caps_severity(self) -> None:
        self.assertEqual(cap_severity("CRITICAL", "HIGH"), "CRITICAL")
        self.assertEqual(cap_severity("CRITICAL", "MEDIUM"), "HIGH")
        self.assertEqual(cap_severity("CRITICAL", "LOW"), "MEDIUM")
        self.assertEqual(cap_severity("LOW", "HIGH"), "LOW")


class OneValidatorTests(unittest.TestCase):
    """Three detectors used to disagree about the same number."""

    def test_every_card_detector_gives_the_same_answer(self) -> None:
        from classification.compliance.gdpr_rules import detect_payment_card_data
        from classification.compliance.pci_classifier import classify_pci_content
        from classification.regex_classifier import classify_content

        metadata = {"path": r"D:\Ops\notes.txt", "name": "notes.txt", "extension": ".txt", "tenant_id": "t"}
        for text, expected in (
            ("Device IMEI: 490154203237518 registered to the fleet.", False),
            ("Order number 1234567812345670 shipped Tuesday.", False),
            ("Serial 4444444444444448 on the asset tag.", False),
            ("Cardholder: Jane Doe\nCard number: 4111 1111 1111 1111\nExp 12/28 CVV 123", True),
        ):
            with self.subTest(text=text[:40]):
                generic = any(f["type"] == "credit_card" for f in classify_content(text))
                pci = any("pan" in str(f.get("type")) for f in classify_pci_content(text, dict(metadata)))
                gdpr = bool(detect_payment_card_data(text, metadata))
                self.assertEqual(generic, expected)
                self.assertEqual(pci, expected)
                if expected:
                    self.assertTrue(gdpr)
                else:
                    self.assertFalse(gdpr)


if __name__ == "__main__":
    unittest.main()
