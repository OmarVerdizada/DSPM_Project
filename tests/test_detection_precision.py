"""Detection precision: structural validators stop 'looks-like' false positives.

Covers the user-reported class of bug - e.g. any 16 digits flagged as a card -
across the generic detectors that previously matched on shape alone.
"""

from __future__ import annotations

import unittest

from classification.regex_classifier import classify_content


def _types(text: str) -> set[str]:
    return {finding["type"] for finding in classify_content(text)}


class FalsePositiveTests(unittest.TestCase):
    def test_arbitrary_16_digits_is_not_a_card(self) -> None:
        # 16 digits, not Luhn-valid -> not a card
        self.assertNotIn("credit_card", _types("order id 1234567890123456 shipped"))
        self.assertNotIn("credit_card", _types("ref 9999999999999999"))

    def test_ordinary_words_are_not_swift_or_fin(self) -> None:
        self.assertNotIn("swift_bic", _types("Our CUSTOMER and PROVIDER records"))
        self.assertNotIn("azerbaijan_fin", _types("PROJECT COMPANY EXAMPLE SERVICE PRODUCT"))

    def test_invalid_iban_checksum_is_rejected(self) -> None:
        self.assertNotIn("iban", _types("AZ00NABZ00000000137010001944"))
        self.assertNotIn("iban", _types("DE00370400440532013000"))


class TruePositiveTests(unittest.TestCase):
    def test_luhn_valid_cards_still_detected(self) -> None:
        self.assertIn("credit_card", _types("card 4111 1111 1111 1111"))  # Visa test
        self.assertIn("credit_card", _types("5555555555554444"))  # Mastercard test

    def test_labeled_swift_still_detected(self) -> None:
        self.assertIn("swift_bic", _types("SWIFT: DEUTDEFF500"))
        self.assertIn("swift_bic", _types("BIC DEUTDEFF"))

    def test_real_fin_still_detected(self) -> None:
        self.assertIn("azerbaijan_fin", _types("FIN 5RW8F42"))

    def test_valid_iban_still_detected(self) -> None:
        self.assertIn("iban", _types("IBAN DE89370400440532013000"))


if __name__ == "__main__":
    unittest.main()
