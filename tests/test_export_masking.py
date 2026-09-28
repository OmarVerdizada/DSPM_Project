"""C9: the one masking pass every export applies - PDF, its HTML twin, Word and Excel.

A finding's samples are masked where they are made. This is the second line, for a value
that reaches a report by another road: a file named after a card number, an IBAN in a
share name, a key pasted into a field. It must catch those, and it must leave alone the
digit runs a report is full of - dates, counts, IMEIs, order numbers - and every name in
another script.
"""

from __future__ import annotations

import unittest

from classification.masking import mask_in_text


class WhatIsMaskedTest(unittest.TestCase):

    def test_a_card_number_in_any_of_its_written_forms(self) -> None:
        cases = {
            "refund_4111111111111111.csv": "refund_411111******1111.csv",
            "card 4111 1111 1111 1111 exp": "card 411111******1111 exp",
            "5500-0000-0000-0004": "550000******0004",
            "amex 378282246310005": "amex 378282*****0005",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(mask_in_text(raw), (expected, 1))

    def test_an_iban_that_passes_its_check(self) -> None:
        self.assertEqual(mask_in_text("salary AZ21NABZ00000000137010001944 June"),
                         ("salary AZ21NABZ****************1944 June", 1))
        self.assertEqual(mask_in_text("GB82 WEST 1234 5698 7654 32"), ("GB82WEST**********5432", 1))

    def test_a_private_key_block_whole(self) -> None:
        text = "owner -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY----- end"
        self.assertEqual(mask_in_text(text), ("owner [private key] end", 1))
        self.assertEqual(mask_in_text("-----BEGIN PRIVATE KEY-----\nMIIE truncated"), ("[private key]", 1))

    def test_several_in_one_string_are_all_counted(self) -> None:
        masked, count = mask_in_text("4111111111111111 and 5500000000000004 and GB82WEST12345698765432")
        self.assertEqual(count, 3)
        self.assertNotRegex(masked, r"\d{12}")


class WhatIsLeftAloneTest(unittest.TestCase):

    def test_numbers_that_are_not_cards_or_accounts(self) -> None:
        for text in ("IMEI 490154203237518",           # Luhn-valid, IMEI allocation prefix
                     "order 1234567812345670",         # a repeated block
                     "4444444444444448",               # one digit repeated
                     "4111111111111112",               # fails Luhn
                     "GB82WEST12345698765433",         # fails mod 97
                     "2026-09-28 1,204 files 45%",
                     "ticket 9876543210987"):          # no issuer prefix
            with self.subTest(text=text):
                self.assertEqual(mask_in_text(text), (text, 0))

    def test_names_in_other_scripts_pass_through_unchanged(self) -> None:
        for text in ("müştəri_siyahısı.csv", "отчет_2026.csv", "Ελληνικά.docx", "CORP\\ə.məmmədov"):
            with self.subTest(text=text):
                self.assertEqual(mask_in_text(text), (text, 0))

    def test_masking_twice_changes_nothing(self) -> None:
        once, _ = mask_in_text("refund_4111111111111111.csv AZ21NABZ00000000137010001944")
        self.assertEqual(mask_in_text(once), (once, 0))

    def test_empty_and_non_text_values(self) -> None:
        self.assertEqual(mask_in_text(None), ("", 0))
        self.assertEqual(mask_in_text(""), ("", 0))
        self.assertEqual(mask_in_text(94), ("94", 0))


if __name__ == "__main__":
    unittest.main()
