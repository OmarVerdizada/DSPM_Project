import unittest

from classification.compliance.nist_classifier import classify_nist_content


class NISTClassifierTests(unittest.TestCase):
    def test_exact_marking_and_context_becomes_high_or_confirmed(self):
        findings = classify_nist_content(
            "CUI NIST SP 800-60 FIPS 199 Identity Management Type 1 user id restricted record",
            {"path": "secure/identity.csv", "extension": ".csv"},
        )

        self.assertTrue(findings)
        self.assertTrue(any(item["confidence"] in {"high", "confirmed"} for item in findings))

    def test_public_training_template_reduces_or_rejects_confidence(self):
        positive = classify_nist_content("NIST SP 800-60 Financial Records Type 1 bank account payment", {"path": "finance/export.txt"})
        negative = classify_nist_content("public training template example for Financial Records Type 1 bank account payment", {"path": "public/training/template.txt"})

        self.assertTrue(positive)
        self.assertLessEqual(len(negative), len(positive))
        if negative:
            self.assertTrue(all(item["confidence_score"] < 70 for item in negative))

    def test_keyword_only_match_is_not_confirmed(self):
        findings = classify_nist_content("Identity Management Type 1", {"path": "notes.txt"})

        self.assertTrue(findings)
        self.assertTrue(all(item["confidence"] != "confirmed" for item in findings))

    def test_raw_secret_like_value_is_masked(self):
        findings = classify_nist_content(
            "password token-ABCD1234 NIST SP 800-60 Credentials and Secrets Type 1 private key",
            {"path": "prod/secrets.env", "extension": ".env"},
        )

        self.assertTrue(findings)
        rendered = str(findings)
        self.assertNotIn("token-ABCD1234", rendered)
        self.assertTrue(any(item.get("secure_value_fingerprints") for item in findings))


if __name__ == "__main__":
    unittest.main()

