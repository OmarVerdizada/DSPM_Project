import unittest

from risk.risk_engine import calculate_risk


class CustomGdprRiskEngineTests(unittest.TestCase):
    def test_custom_gdpr_finding_drives_reasons_and_recommendations(self):
        findings = [
            {
                "type": "custom_contract_marker",
                "framework": "gdpr",
                "category": "legal",
                "label": "Custom contract marker",
                "risk": "HIGH",
                "count": 2,
                "matched_keywords": ["restricted vendor agreement"],
            }
        ]

        risk = calculate_risk(
            {"name": "vendor-contract.txt", "path": r"C:\Legal\vendor-contract.txt", "extension": ".txt"},
            findings,
            {"score": 0, "issues": []},
        ).to_dict()

        self.assertIn("Custom contract marker", " ".join(risk["reasons"]))
        self.assertIn("legal", " ".join(risk["reasons"]).lower())
        self.assertIn("restricted vendor agreement", " ".join(risk["reasons"]))
        self.assertIn("legal operations", " ".join(risk["dlp_recommendations"]))
        self.assertIn("Block external movement", " ".join(risk["dlp_recommendations"]))
        self.assertIn("Apply custom GDPR/category label", risk["remediation"]["actions"])

    def test_custom_secret_category_adds_secret_remediation(self):
        risk = calculate_risk(
            {"name": "runtime.env", "path": r"C:\Apps\runtime.env", "extension": ".env"},
            [
                {
                    "type": "custom_runtime_secret",
                    "framework": "gdpr",
                    "category": "credentials_secrets",
                    "label": "Runtime secret",
                    "risk": "CRITICAL",
                    "count": 1,
                }
            ],
            {"score": 0, "issues": []},
        ).to_dict()

        self.assertIn("Runtime secret", " ".join(risk["reasons"]))
        self.assertIn("Rotate exposed secret", risk["remediation"]["actions"])


if __name__ == "__main__":
    unittest.main()
