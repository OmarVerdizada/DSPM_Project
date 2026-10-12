"""What a scan of an ordinary machine is allowed to claim.

The console reported "2 low findings, posture 77" for a freshly installed
Windows workstation, and 1,099 tests did not notice - because nothing asserted
what a file with NOTHING IN IT should score. Every scan-time defect behind that
number is pinned here:

  A1  a file is a finding only when a detector saw something, the content was
      sealed against inspection, or the customer named the asset;
  A3  the five keyword regexes that shipped as an "ML classifier" are gone;
  A4  a path keyword has to be a word, and a document extension is not a risk.

The measured "before" for each case is in the test that covers it.
"""

from __future__ import annotations

import unittest

from classification.regex_classifier import classify_content
from discovery.discovery_engine import ScanSummary, DSPMDiscoveryEngine
from risk.risk_engine import (
    EXTENSION_RISK,
    LEVEL_NONE,
    PROTECTION_FLOOR_SEALED,
    PROTECTION_FLOOR_UNINSPECTABLE,
    _path_keyword_hit,
    calculate_risk,
)


def risk(path, *, extension="", findings=None, acl=None, **record):
    record.update({"path": path, "name": path.rsplit("\\", 1)[-1], "extension": extension})
    return calculate_risk(record, findings or [], acl or {})


class NoSignalNoFindingTests(unittest.TestCase):
    """A1. Measured before this landed: every one of these scored 15-70."""

    def test_a_desktop_shortcut_is_not_a_finding(self) -> None:
        # The report that started this: "Microsoft Edge.lnk" scored 20 because
        # its path contains "administrator" - the account running the scan.
        assessment = risk(
            r"C:\Users\Administrator\Desktop\Microsoft Edge.lnk",
            extension=".lnk",
            source="endpoint",
            content_status="metadata_only",
        )
        self.assertEqual(assessment.level, LEVEL_NONE)
        self.assertEqual(assessment.score, 0)

    def test_an_empty_text_file_is_not_a_high_finding(self) -> None:
        """This one scored 70. HIGH.

        `content_status` is "empty_or_unreadable" for any content-extension file
        that read empty, and the protection check matched on the substring
        "unreadable" - so every zero-byte .txt and .log on a machine was a file
        someone had sealed against inspection.
        """
        assessment = risk(
            r"C:\Users\bob\Documents\notes.txt",
            extension=".txt",
            size=0,
            source="endpoint",
            content_status="empty_or_unreadable",
        )
        self.assertEqual(assessment.level, LEVEL_NONE)

    def test_an_ordinary_document_on_a_share_is_not_a_finding(self) -> None:
        assessment = risk(
            r"\\fs01\Marketing\brochure.docx",
            extension=".docx",
            size=40000,
            source="smb",
            content_status="scanned",
        )
        self.assertEqual(assessment.level, LEVEL_NONE)

    def test_a_detector_signal_still_scores(self) -> None:
        assessment = risk(
            r"\\fs01\Finance\cards.csv",
            extension=".csv",
            source="smb",
            content_status="scanned",
            findings=[{"type": "credit_card", "risk": "HIGH", "occurrence_count": 3, "framework": "pci"}],
        )
        self.assertIn(assessment.level, {"HIGH", "CRITICAL"})
        self.assertGreaterEqual(assessment.score, 70)

    def test_a_sealed_container_is_a_finding_even_with_no_detector_hit(self) -> None:
        """Nobody read it, and somebody locked it. Both facts are the point."""
        assessment = risk(
            r"\\fs01\IT\Backups\Secure\production_credential_vault.kdbx",
            extension=".kdbx",
            source="smb",
            content_status="protected",
        )
        self.assertNotEqual(assessment.level, LEVEL_NONE)
        self.assertGreaterEqual(assessment.exposure_score, PROTECTION_FLOOR_SEALED)

    def test_a_format_we_cannot_read_ranks_below_one_somebody_locked(self) -> None:
        """A downloaded .rar is a coverage gap, not a concealment.

        Both used to floor at 70, so every archive in a Downloads folder was a
        HIGH finding indistinguishable from an encrypted credential vault.
        """
        archive = risk(
            r"C:\Users\bob\Downloads\pics.rar",
            extension=".rar",
            source="endpoint",
            content_status="protected_or_uninspectable_archive",
            protected=True,
        )
        self.assertEqual(archive.exposure_score, PROTECTION_FLOOR_UNINSPECTABLE)
        self.assertLess(PROTECTION_FLOOR_UNINSPECTABLE, PROTECTION_FLOOR_SEALED)

    def test_an_analysis_that_crashed_is_never_reported_as_clean(self) -> None:
        """"We could not look" is the opposite of "there is nothing here".

        The first cut of the gate scored a crashed record NONE, which removed it
        from every severity count, the summary and the posture - a scan could
        fail on half an estate and report a perfect score.
        """
        assessment = risk(
            r"\\fs01\Finance\ledger.xlsx",
            extension=".xlsx",
            source="smb",
            scan_error="record analysis failed",
        )
        self.assertNotEqual(assessment.level, LEVEL_NONE)
        self.assertIn("not inspected", " ".join(assessment.reasons))

    def test_broad_permissions_alone_are_governance_not_a_data_finding(self) -> None:
        """The ACL score and its issues survive; they just do not invent a
        severity for a file with nothing sensitive in it."""
        assessment = risk(
            r"\\fs01\Public\readme.md",
            extension=".md",
            source="smb",
            content_status="scanned",
            acl={"score": 90, "issues": ["Everyone has write access"]},
        )
        self.assertEqual(assessment.level, LEVEL_NONE)
        self.assertEqual(assessment.access_risk_score, 90)
        self.assertIn("Everyone has write access", assessment.reasons)

    def test_a_customer_override_still_forces_its_level(self) -> None:
        assessment = risk(
            r"\\fs01\Legal\crown_jewels\deal.docx",
            extension=".docx",
            source="smb",
            content_status="scanned",
            asset_overrides=[{"pattern": "crown_jewels", "level": "CRITICAL", "reason": "board material"}],
        )
        self.assertEqual(assessment.level, "CRITICAL")


class SummaryAddsUpTests(unittest.TestCase):
    """A1. total_files == critical + high + medium + low + clear."""

    def test_a_clean_estate_reports_no_severities_and_counts_the_files(self) -> None:
        files = [
            {"risk": {"level": LEVEL_NONE, "score": 0}},
            {"risk": {"level": LEVEL_NONE, "score": 0}},
            {"risk": {"level": "HIGH", "score": 80}, "findings": [{"type": "credit_card"}]},
        ]
        summary = DSPMDiscoveryEngine._build_summary(files)
        self.assertEqual(summary.total_files, 3)
        self.assertEqual(summary.clear, 2)
        self.assertEqual(summary.high, 1)
        self.assertEqual(
            summary.total_files,
            summary.critical + summary.high + summary.medium + summary.low + summary.clear,
        )

    def test_an_unscored_record_counts_as_clear_not_low(self) -> None:
        summary = DSPMDiscoveryEngine._build_summary([{"path": "x"}])
        self.assertEqual(summary.low, 0)
        self.assertEqual(summary.clear, 1)

    def test_the_summary_publishes_the_clear_count(self) -> None:
        self.assertIn("clear", ScanSummary(0, 0, 0, 0, 0, 0).to_dict())


class HeuristicClassifierIsGoneTests(unittest.TestCase):
    """A3. Five re.search calls that shipped as a "context classifier"."""

    def test_a_runbook_sentence_is_not_a_high_finding(self) -> None:
        # Measured before: one HIGH finding, ml_source_code_context.
        text = "Restart the service after each deployment. See the repository for the commit hash."
        self.assertEqual(classify_content(text), [])

    def test_a_vendor_form_is_not_a_finding(self) -> None:
        # Measured before: MEDIUM, ml_finance_context, on the word "payment".
        self.assertEqual(classify_content("Please provide your bank details so we can process the payment."), [])

    def test_a_sales_note_is_not_a_finding(self) -> None:
        self.assertEqual(classify_content("Pull the lead list from the CRM before the call."), [])

    def test_one_sentence_no_longer_produces_the_same_claim_twice(self) -> None:
        """`phi_context` and `ml_phi_context` both fired on the same words."""
        types = [finding["type"] for finding in classify_content("The patient waiting area is closed for cleaning.")]
        self.assertEqual(len(types), len(set(types)))
        self.assertFalse([name for name in types if name.startswith("ml_")])

    def test_no_finding_type_starts_with_ml_by_default(self) -> None:
        corpus = (
            "employee tax invoice payroll bank payment wire transfer termination bonus "
            "patient diagnosis treatment medical record mrn crm lead list prospect "
            "source code repository git clone commit hash deployment key"
        )
        self.assertFalse([f for f in classify_content(corpus) if str(f["type"]).startswith("ml_")])

    def test_a_real_secret_is_still_found(self) -> None:
        found = {f["type"] for f in classify_content("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")}
        self.assertIn("aws_secret_key", found)


class PathKeywordsAreWordsTests(unittest.TestCase):
    """A4. `hr` matched "chrome"; `administrator` matched every scanned profile."""

    def test_words_inside_other_words_no_longer_match(self) -> None:
        for path in (
            r"C:\Users\bob\AppData\Local\Google\Chrome\history.dat",   # hr
            r"D:\dev\docs\syntax.md",                                  # tax
            r"D:\assets\keyboard.png",                                 # board
            r"D:\Products\catalogue.xlsx",                             # prod
            r"C:\Windows\System32\accessibility.dll",                  # access
            r"D:\sandbox\notes.txt",                                   # db
        ):
            with self.subTest(path=path):
                self.assertEqual(_path_keyword_hit(path), "")

    def test_the_account_running_the_scan_is_not_a_keyword(self) -> None:
        self.assertEqual(_path_keyword_hit(r"C:\Users\Administrator\Desktop\shortcut.lnk"), "")

    def test_a_real_keyword_still_matches_as_a_word(self) -> None:
        for path, expected in (
            (r"\\fs01\Finance\Payroll\2026\review.xlsx", {"finance", "payroll"}),
            (r"\\fs01\IT\Backups\vault.kdbx", {"backup", "vault"}),
            (r"D:\svc\config\api_key.txt", {"api_key"}),
            (r"D:\svc\config\api-key.txt", {"api_key"}),
            (r"D:\legal\due diligence\merger.docx", {"legal", "due diligence", "merger"}),
        ):
            with self.subTest(path=path):
                self.assertIn(_path_keyword_hit(path), expected)

    def test_a_keyword_still_matches_under_a_user_profile(self) -> None:
        """Only the account NAME is skipped, not everything beneath it."""
        self.assertEqual(_path_keyword_hit(r"C:\Users\Administrator\Documents\payroll_2026.xlsx"), "payroll")

    def test_ordinary_document_extensions_carry_no_risk_of_their_own(self) -> None:
        for extension in (".txt", ".csv", ".tsv", ".xlsx", ".xls", ".docx", ".doc", ".pdf", ".json", ".xml", ".yaml", ".yml", ".log"):
            with self.subTest(extension=extension):
                self.assertEqual(EXTENSION_RISK.get(extension, 0), 0)

    def test_credential_extensions_still_carry_risk(self) -> None:
        for extension in (".env", ".pem", ".key", ".kdbx", ".p12", ".pfx", ".sql", ".bak"):
            with self.subTest(extension=extension):
                self.assertGreater(EXTENSION_RISK.get(extension, 0), 0)


class CredentialMaterialIsReadTests(unittest.TestCase):
    """A1's precondition: dropping the extension score is only safe if the file
    is actually opened and classified."""

    def test_key_material_is_content_scanned(self) -> None:
        from collectors.file_scanner import CONTENT_EXTENSIONS

        for extension in (".pem", ".key", ".crt", ".cer", ".ppk", ".kubeconfig"):
            with self.subTest(extension=extension):
                self.assertIn(extension, CONTENT_EXTENSIONS)

    def test_a_private_key_in_a_pem_file_is_found(self) -> None:
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEAx7Vv0m3ZQ2b8kK1mVQvJd3nQpQ0J8mS1u6oGqNzXy2A9wLmR\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        self.assertIn("private_key", {f["type"] for f in classify_content(pem)})


if __name__ == "__main__":
    unittest.main()
