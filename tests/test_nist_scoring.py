import unittest

from classification.compliance.nist_classifier import classify_nist_content


class NISTScoringTests(unittest.TestCase):
    def test_cia_high_water_mark_in_output(self):
        finding = classify_nist_content(
            "CUI NIST SP 800-60 Security Operations Type 1 incident vulnerability siem",
            {"path": "security/incidents.json", "extension": ".json"},
        )[0]
        order = {"LOW": 0, "MODERATE": 1, "HIGH": 2}

        self.assertEqual(
            finding["overall_impact"],
            max([finding["confidentiality_impact"], finding["integrity_impact"], finding["availability_impact"]], key=order.get),
        )

    def test_risk_factor_breakdown_is_clamped(self):
        finding = classify_nist_content("CUI FIPS 199 Financial Records Type 1 financial payment bank account", {"path": "finance.csv"})[0]

        self.assertGreaterEqual(finding["final_risk_score"], 0)
        self.assertLessEqual(finding["final_risk_score"], 100)
        self.assertIn("risk_factor_breakdown", finding)


if __name__ == "__main__":
    unittest.main()

