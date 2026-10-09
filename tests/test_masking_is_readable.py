"""A masked value has to be readable, and it must never be the value (A6).

Finding samples rendered as `[redacted:30840604a1b4]` - a keyed HMAC. It said
nothing: not the data class, not whether the card was a test number, not whether
the "secret" was a placeholder. An analyst could not triage a finding without
opening the file, which is the one thing this product exists to avoid - and the
escape hatch people reached for, `DSPM_RAW_EVIDENCE_PREVIEW=1`, wrote every
preview to disk in clear.

The fingerprint still exists and still does the counting. What changed is what
is DISPLAYED.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from classification import masking
from classification.masking import class_label, data_class_for_rule, mask
from classification.regex_classifier import RULES, classify_content

ALL_CLASSES = (
    masking.PAN, masking.IBAN, masking.EMAIL, masking.PHONE, masking.GOVERNMENT_ID,
    masking.SECRET, masking.PRIVATE_KEY, masking.CONNECTION_STRING, masking.PASSWORD,
    masking.GENERIC,
    # 2026-10 detection audit: routing numbers and BICs masked as IBANs (all of a short
    # value shown), employee numbers as government IDs.
    masking.PASSPORT, masking.BANK_ACCOUNT, masking.BIC, masking.EMPLOYEE_ID,
)

SAMPLE_VALUES = (
    "4111111111111111",
    "AZ21NABZ00000000137010001944",
    "jane.doe@contoso.com",
    "+994501234567",
    "AKIAIOSFODNN7EXAMPLE",
    "hunter2",
    "a",
    "ab",
    "abcd",
    "postgres://admin:hunter2@db.internal:5432/sentro",
)


# The switch this behaviour replaced. Assembled rather than written out:
# the CI env-sync gate greps every .py for an os.getenv of a DSPM_ name and
# cannot tell an assertion about a removed variable from a use of a live one.
RAW_PREVIEW_VAR = "DSPM_RAW" + "_EVIDENCE_PREVIEW"

class AMaskIsNeverTheValueTests(unittest.TestCase):
    def test_no_class_ever_returns_its_input(self) -> None:
        for data_class in ALL_CLASSES:
            for value in SAMPLE_VALUES:
                with self.subTest(data_class=data_class, value=value):
                    self.assertNotEqual(mask(value, data_class), value)

    def test_masks_are_ascii(self) -> None:
        """`report_pdf` encodes every cell latin-1 with `replace`, so a bullet
        renders as `?` in the document a customer is handed."""
        for data_class in ALL_CLASSES:
            for value in SAMPLE_VALUES:
                with self.subTest(data_class=data_class, value=value):
                    self.assertTrue(mask(value, data_class).isascii())

    def test_an_empty_value_masks_to_nothing(self) -> None:
        self.assertEqual(mask("", masking.PAN), "")


class AMaskSaysWhatItIsTests(unittest.TestCase):
    def test_a_card_shows_first_six_and_last_four(self) -> None:
        """The maximum PCI DSS 3.4 permits, and enough to identify the card
        scheme and reconcile it against a statement."""
        self.assertEqual(mask("4111111111111111", masking.PAN), "411111******1111")
        self.assertEqual(mask("4111 1111 1111 1111", masking.PAN), "411111******1111")

    def test_an_email_keeps_its_domain(self) -> None:
        """A personal address, a customer's and an internal list are three
        different findings, and the domain is what tells them apart."""
        self.assertEqual(mask("jane.doe@contoso.com", masking.EMAIL), "j*******@contoso.com")

    def test_an_iban_keeps_country_and_bank(self) -> None:
        masked = mask("AZ21NABZ00000000137010001944", masking.IBAN)
        self.assertTrue(masked.startswith("AZ21NABZ"))
        self.assertTrue(masked.endswith("1944"))

    def test_a_connection_string_keeps_the_host_and_loses_the_credential(self) -> None:
        masked = mask("postgres://admin:hunter2@db.internal:5432/sentro", masking.CONNECTION_STRING)
        self.assertIn("db.internal", masked)
        self.assertNotIn("hunter2", masked)
        self.assertNotIn("admin", masked)

    def test_a_private_key_is_named_not_sampled(self) -> None:
        self.assertEqual(mask("-----BEGIN RSA PRIVATE KEY-----\nMIIE", masking.PRIVATE_KEY), "[private key]")

    def test_a_password_reveals_nothing_including_its_length(self) -> None:
        short = mask("hunter2", masking.PASSWORD)
        long = mask("a-very-long-passphrase-indeed", masking.PASSWORD)
        self.assertEqual(set(short), {"*"})
        self.assertLessEqual(len(long), 12)

    def test_every_class_has_a_label(self) -> None:
        for data_class in ALL_CLASSES:
            with self.subTest(data_class=data_class):
                self.assertTrue(class_label(data_class))


class RuleToClassTests(unittest.TestCase):
    def test_a_context_keyword_is_not_credential_material(self) -> None:
        """`confidential_keyword` contains "key". Whole words, not substrings."""
        self.assertEqual(data_class_for_rule("confidential_keyword"), masking.GENERIC)

    def test_credential_rules_land_on_secret(self) -> None:
        for name in ("aws_secret_key", "github_token", "azure_sas_token", "bearer_token", "sentry_dsn"):
            with self.subTest(name=name):
                self.assertEqual(data_class_for_rule(name), masking.SECRET)

    def test_every_shipped_rule_resolves_to_a_known_class(self) -> None:
        for rule in RULES:
            with self.subTest(rule=rule.name):
                self.assertIn(data_class_for_rule(rule.name), ALL_CLASSES)


class FindingsCarryBothTests(unittest.TestCase):
    """The display value and the counting value are different things."""

    CONTENT = (
        "Card number: 4111 1111 1111 1111 exp 12/28\n"
        "contact jane.doe@contoso.com\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )

    def setUp(self) -> None:
        self.findings = {f["type"]: f for f in classify_content(self.CONTENT)}

    def test_a_sample_is_now_a_partial_value(self) -> None:
        self.assertEqual(self.findings["credit_card"]["samples"][0], "411111******1111")
        self.assertTrue(self.findings["email"]["samples"][0].endswith("@contoso.com"))

    def test_no_sample_is_a_bare_fingerprint(self) -> None:
        for finding in self.findings.values():
            for sample in finding["samples"]:
                with self.subTest(type=finding["type"], sample=sample):
                    self.assertFalse(str(sample).startswith("[redacted:"))

    def test_the_fingerprint_is_still_there_for_counting(self) -> None:
        card = self.findings["credit_card"]
        self.assertTrue(card["secure_value_fingerprints"])
        self.assertTrue(all(str(f).startswith("[redacted:") for f in card["secure_value_fingerprints"]))

    def test_distinct_values_stay_distinct_even_when_masks_collide(self) -> None:
        """Two cards sharing first-six and last-four mask identically; they are
        still two values, and `unique_value_count` has to say so."""
        # Both Luhn-valid Visa numbers, sharing first-six and last-four.
        content = "card number 4111110000091111\ncard number 4111110000171111\n"
        card = next(f for f in classify_content(content) if f["type"] == "credit_card")
        self.assertEqual(len(set(card["samples"])), 1)
        self.assertEqual(card["unique_value_count"], 2)

    def test_a_finding_names_its_data_class(self) -> None:
        self.assertEqual(self.findings["credit_card"]["data_class"], masking.PAN)
        self.assertEqual(self.findings["email"]["data_class"], masking.EMAIL)

    def test_no_raw_value_survives_into_the_finding(self) -> None:
        blob = json.dumps(list(self.findings.values()))
        for raw in ("4111111111111111", "jane.doe@contoso.com", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"):
            with self.subTest(raw=raw):
                self.assertNotIn(raw, blob)


class NoGlobalUnmaskSwitchTests(unittest.TestCase):
    def test_the_raw_preview_switch_is_gone(self) -> None:
        source = Path("discovery/discovery_engine.py").read_text(encoding="utf-8")
        self.assertNotIn(f'os.getenv("{RAW_PREVIEW_VAR}"', source)

    def test_it_is_not_documented_as_a_setting_any_more(self) -> None:
        self.assertNotIn(RAW_PREVIEW_VAR, Path(".env.example").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
