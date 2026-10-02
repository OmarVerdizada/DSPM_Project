"""Backend audit, 2026-10: detection and scoring. Each test pins the behaviour a reviewer
measured on this tree - a card that was never found, a column of codes that was found as
ten cards, a password shown as "Hun***2!", a private key that scored HIGH - so the fix
cannot quietly come undone.
"""
from __future__ import annotations

import re
import time
import unittest

from backend.reporting.posture import PostureInputs, compute_posture
from backend.reporting.remediation_policy import categorize_risk_types, has_credential_type
from backend.reporting.report_model import build_report_model
from classification import masking
from classification.compliance.canonical_model import apply_canonical_finding_model
from classification.compliance.gdpr_classifier import classify_gdpr_content
from classification.compliance.gdpr_rules import detect_payment_card_data
from classification.compliance.nist_classifier import _masked_preview, classify_nist_content
from classification.compliance.pci_classifier import classify_pci_content
from classification.compliance.validators import DATABASE_URI_RE, DB_KV_CONNECTION_RE
from classification.pan_validator import pan_hits
from classification.regex_classifier import RULES, classify_content
from discovery.finding_merge import merge_findings
from risk.risk_engine import RISK_RULE_DESCRIPTIONS, calculate_risk, get_level

FILE = {"name": "notes.txt", "path": r"C:\Data\notes.txt", "extension": ".txt", "size": 4096}


def _types(findings: list[dict]) -> dict[str, dict]:
    return {finding["type"]: finding for finding in findings}


def _cards(text: str) -> list[str]:
    return [hit.verdict.digits for hit in pan_hits(text)]


class ACardFollowedByAnotherNumberIsStillACardTest(unittest.TestCase):
    """The candidate pattern took the longest run of digits and separators. A card with
    its expiry or CVV after it on the line arrived as one 18- or 19-digit run, failed the
    card-shape check whole, and the card inside it was never tried - in all three
    detectors, which share the candidate."""

    LINES = (
        "Card: 4111 1111 1111 1111 05/27",
        "Card number 4111111111111111 123",
        "John\t4111111111111111\t123\t12/25",
        "Card number:\n4111111111111111\n123\n",
    )

    def test_the_card_inside_the_run_is_found(self) -> None:
        for text in self.LINES:
            with self.subTest(text=text):
                self.assertEqual(_cards(text), ["4111111111111111"])

    def test_every_detector_reports_it(self) -> None:
        # GDPR asks for a payment phrase ("card number"), not the bare word "card".
        text = "Card number: 4111 1111 1111 1111 05/27"
        self.assertIn("credit_card", _types(classify_content(text)))
        self.assertIn("pci_chd_pan", _types(classify_pci_content(text, {"name": "pay.txt", "extension": ".txt"})))
        self.assertIn("4111 1111 1111 1111", detect_payment_card_data(text, {}))

    def test_a_run_that_is_a_card_as_it_stands_is_read_as_before(self) -> None:
        hits = pan_hits("visa 4111111111111111")
        self.assertEqual([(hit.raw, hit.start, hit.end) for hit in hits], [("4111111111111111", 5, 21)])

    def test_the_window_is_reported_where_it_is(self) -> None:
        text = "Card: 4111 1111 1111 1111 05/27"
        hit = pan_hits(text)[0]
        self.assertEqual(text[hit.start:hit.end], hit.raw)
        self.assertEqual(hit.raw, "4111 1111 1111 1111")


class LinesDoNotJoinIntoACardTest(unittest.TestCase):
    """The separator class included a newline, so a column of four-digit values - codes,
    years, PINs on separate lines - joined into card-shaped runs: 4000..4159 gave ten
    issuer-valid "cards", a HIGH generic finding and a CRITICAL PCI one."""

    CODES = "\n".join(str(number) for number in range(4000, 4160))

    def test_a_column_of_codes_is_no_card(self) -> None:
        self.assertEqual(pan_hits(self.CODES), [])
        self.assertNotIn("credit_card", _types(classify_content(self.CODES)))
        self.assertNotIn("pci_chd_pan", _types(classify_pci_content(self.CODES, {"name": "codes.txt", "extension": ".txt"})))

    def test_windows_line_endings_do_not_join_either(self) -> None:
        self.assertEqual(pan_hits(self.CODES.replace("\n", "\r\n")), [])

    def test_the_separators_a_card_is_written_with_still_join(self) -> None:
        for text in ("card 4111 1111 1111 1111", "card 4111-1111-1111-1111", "card 4111\t1111\t1111\t1111",
                     "card 4111\u00a01111\u00a01111\u00a01111"):
            with self.subTest(text=text):
                self.assertEqual(_cards(text), ["4111111111111111"])


class ComplianceMasksHideTheValueTest(unittest.TestCase):
    """GDPR and NIST masked every value as its first three and last two characters, so a
    seven-character FIN showed five of them and a password read "Hun***2!"; the report-time
    mask only knows cards, IBANs and keys, so these went into reports as they were."""

    def setUp(self) -> None:
        content = ("password: Hunter2!x\nFIN: 5ABCD12\nPassport number: C12345678\n"
                   "Customer email: omar@example.com\n")
        self.findings = _types(classify_gdpr_content(content, {"name": "kyc.txt", "extension": ".txt"}))

    def test_a_password_shows_nothing(self) -> None:
        samples = self.findings["gdpr_password_secret"]["samples"]
        self.assertTrue(samples)
        for sample in samples:
            self.assertEqual(set(sample), {"*"})

    def test_a_password_found_by_the_connection_rule_shows_nothing(self) -> None:
        findings = _types(classify_gdpr_content("Server=db01;Database=hr;User Id=sa;Password=P@ssw0rd1;", {"name": "app.config"}))
        samples = findings["gdpr_database_connection_string"]["samples"]
        self.assertTrue(samples)
        for sample in samples:
            self.assertNotIn("P@ss", sample)

    def test_an_identifier_shows_its_last_two_characters_only(self) -> None:
        self.assertEqual(self.findings["gdpr_fin_pin"]["samples"], ["*****12"])
        self.assertEqual(self.findings["gdpr_passport_number"]["samples"], ["*******78"])

    def test_an_email_is_masked_the_way_every_detector_masks_one(self) -> None:
        self.assertEqual(self.findings["gdpr_email_address"]["samples"], ["o***@example.com"])
        self.assertEqual(self.findings["gdpr_email_address"]["occurrences"][0]["sample"], "o***@example.com")

    def test_a_short_value_is_never_mostly_shown(self) -> None:
        for value in ("jdoe1", "AZ1000", "abcdefg"):
            with self.subTest(value=value):
                masked = masking.mask(value, masking.GENERIC)
                shown = sum(1 for char in masked if char != "*")
                self.assertLessEqual(shown, len(value) // 2)

    def test_a_long_free_text_value_does_not_print_as_a_wall_of_stars(self) -> None:
        masked = masking.mask("diagnosis " * 15, masking.GENERIC)
        self.assertLessEqual(len(masked), 20)

    def test_a_nist_value_keeps_no_prefix(self) -> None:
        self.assertEqual(_masked_preview("123-45-6789", masking.GOVERNMENT_ID), "*********89")
        findings = classify_nist_content("Our password policy: the api key must rotate. token ABCD1234EFGH",
                                         {"name": "a.txt", "path": "C:/x/a.txt", "extension": ".txt"})
        self.assertTrue(findings)
        for finding in findings:
            for sample in finding["samples"]:
                self.assertNotIn("ABCD1234", sample)


class ProseIsNotAnIdentifierTest(unittest.TestCase):
    """The generic ID rules matched case-insensitively with any following word as the
    value, GDPR's national ID needed no keyword (so "or 10020031" was one), its passport
    took any nine-character word near "passport", and an SSN was reported twice."""

    def _generic(self, text: str) -> dict[str, dict]:
        return {name: finding for name, finding in _types(classify_content(text)).items()
                if name in {"passport_number", "national_id", "ssn"}}

    def _gdpr(self, text: str) -> dict[str, dict]:
        return {name: finding for name, finding in _types(classify_gdpr_content(text, {"name": "a.txt"})).items()
                if name in {"gdpr_national_id", "gdpr_passport_number"}}

    def test_prose_is_no_finding(self) -> None:
        for text in ("Please bring your passport photos", "passthrough mode",
                     "Social security benefits are paid monthly. National ID required",
                     # a word in capitals has no digit; a file name with one is not in capitals
                     "PASSPORT OFFICE HOURS", "Upload the passport scan001.pdf", "Attach the national id scan001.pdf",
                     # "pass" alone is not the abbreviation "pass."
                     "Your boarding pass AB12345 is attached"):
            with self.subTest(text=text):
                self.assertEqual(self._generic(text), {})
        for text in ("Ship order 10020030 or 10020031", "bring your passport and identity documents to reception",
                     "SHIP ORDER 10020030 OR 10020031"):
            with self.subTest(text=text):
                self.assertEqual(self._gdpr(text), {})

    def test_an_ssn_is_one_finding(self) -> None:
        self.assertEqual(set(self._generic("SSN: 123-45-6789")), {"ssn"})

    def test_real_identifiers_are_still_found(self) -> None:
        self.assertIn("passport_number", self._generic("Passport No: C12345678"))
        self.assertIn("national_id", self._generic("National ID: AZE12345678"))
        self.assertIn("national_id", self._generic("SSN 123456789"))
        self.assertIn("national_id", self._generic("TIN: 1234567890"))
        self.assertIn("gdpr_national_id", self._gdpr("National ID: AZE 12345678"))
        self.assertIn("gdpr_passport_number", self._gdpr("Passport number: C12345678"))

    def test_the_value_is_what_is_masked_and_counted(self) -> None:
        passport = self._generic("Passport No: C12345678")["passport_number"]
        self.assertEqual(passport["samples"], ["*******78"])


class ConnectionStringsAreFoundInLinearTimeTest(unittest.TestCase):
    """The generic connection-string pattern's pairs had an optional separator, so one
    failing line could be split every possible way: 8 KB took a second, 16 KB four."""

    RULE = next(rule for rule in RULES if rule.name == "connection_string")

    def test_a_long_failing_line_is_fast(self) -> None:
        for text in ("server=ab;x=" + "y" * 65_536, "server=ab " * 6_554, "server=ab;" + "k=v" * 21_845,
                     "Server=a;" + ";" * 65_536, "server=ab;" + "x=y;" + " " * 65_536):
            with self.subTest(text=text[:16]):
                started = time.perf_counter()
                list(self.RULE.pattern.finditer(text))
                self.assertLess(time.perf_counter() - started, 0.5)

    def test_real_connection_strings_still_match(self) -> None:
        for text in ("Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;",
                     "Data Source=SQL01;Initial Catalog=x;User Id=sa;Password=Secr3t!",
                     "host = db01 ; database = hr ; password = P@ss"):
            with self.subTest(text=text):
                match = self.RULE.pattern.search(text)
                self.assertIsNotNone(match)
                self.assertIn("Pass", match.group(0).title())


class DatabaseConnectionPatternsReadTheirEscapesTest(unittest.TestCase):
    """Written as raw strings with doubled backslashes, the GDPR patterns forbade the
    letters r and n in a value, needed a literal backslash after each ";" and a literal
    backslash before "+srv"."""

    def test_key_value_connection_strings(self) -> None:
        for text in ("Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;",
                     "Server=db01;Database=hr;User Id=sa;Password=P@ss",
                     "Data Source=SQL01;Initial Catalog=x;Password=Secr3t!"):
            with self.subTest(text=text):
                self.assertIsNotNone(DB_KV_CONNECTION_RE.search(text))

    def test_a_mongodb_srv_uri(self) -> None:
        match = DATABASE_URI_RE.search("mongodb+srv://admin:S3cret@cluster0.example.net/db")
        self.assertIsNotNone(match)
        self.assertTrue(match.group(0).startswith("mongodb+srv://"))

    def test_gdpr_reports_the_connection_string(self) -> None:
        findings = _types(classify_gdpr_content("Server=db01;Database=hr;User Id=sa;Password=P@ss", {"name": "app.config"}))
        self.assertIn("gdpr_database_connection_string", findings)


class BankAndIdentityValuesHaveTheirOwnClassTest(unittest.TestCase):
    """Routing numbers and BICs masked as IBANs - first eight and last four, which for a
    nine- to twelve-character value is all of it - and registered as IBAN entities; an
    employee number was a government ID; the generic and GDPR passports were two
    entities because one fingerprinted the label with the number."""

    def test_a_short_value_in_the_iban_mask_shows_only_its_end(self) -> None:
        self.assertEqual(masking.mask("DEUTDEFF500", masking.IBAN), "*******F500")
        self.assertEqual(masking.mask("021000021", masking.IBAN), "*****0021")

    def test_routing_and_bic_samples_hide_the_value(self) -> None:
        findings = _types(classify_content("ABA 021000021\nSWIFT: DEUTDEFF500"))
        self.assertEqual(findings["routing_account"]["samples"], ["*****0021"])
        self.assertNotIn("F500", findings["swift_bic"]["samples"][0])
        self.assertNotIn("IBAN", {findings["routing_account"]["canonical_entity_type"],
                                  findings["swift_bic"]["canonical_entity_type"]})

    def test_an_employee_number_is_not_a_government_id(self) -> None:
        finding = _types(classify_content("Employee ID: EMP-20931"))["employee_id"]
        self.assertNotEqual(finding["canonical_entity_type"], "GOVERNMENT_ID")

    def test_one_passport_is_one_entity(self) -> None:
        text = "Passport number: C12345678"
        generic = _types(classify_content(text))["passport_number"]
        gdpr = _types(classify_gdpr_content(text, {"name": "a.txt"}))["gdpr_passport_number"]
        self.assertEqual(generic["canonical_entity_type"], gdpr["canonical_entity_type"])
        self.assertTrue(set(generic["canonical_entity_fingerprints"]) & set(gdpr["canonical_entity_fingerprints"]))
        merged = [finding for finding in merge_findings([generic, gdpr]) if "passport" in finding["type"]]
        self.assertEqual(len(merged), 1)


class NoChangedPatternIsQuadraticTest(unittest.TestCase):
    """Every pattern this audit changed, on 64 KB single lines of what it reads."""

    def test_changed_patterns(self) -> None:
        from classification.compliance.validators import NATIONAL_ID_RE, PASSPORT_RE
        from classification.pan_validator import PAN_CANDIDATE_RE

        patterns = [PAN_CANDIDATE_RE, NATIONAL_ID_RE, PASSPORT_RE, DB_KV_CONNECTION_RE, DATABASE_URI_RE]
        patterns += [rule.pattern for rule in RULES if rule.name in {"passport_number", "national_id", "ssn",
                                                                     "routing_account", "employee_id", "connection_string"}]
        texts = ["1 " * 32_768, "1\t" * 32_768, "4111 " * 13_107, "AA" + "1" * 65_536, "a" * 65_536,
                 "passport " * 7_281, "SSN: " + "1-" * 32_768, "server=" + "a" * 65_536,
                 "Server=a;" + "Database=b;" * 5_957, "postgres://" + "a" * 65_536]
        for pattern in patterns:
            for text in texts:
                with self.subTest(pattern=pattern.pattern[:40], text=text[:12]):
                    started = time.perf_counter()
                    for _ in pattern.finditer(text):
                        pass
                    self.assertLess(time.perf_counter() - started, 1.0)
        self.assertTrue(all(isinstance(pattern, re.Pattern) for pattern in patterns))

if __name__ == "__main__":
    unittest.main()
