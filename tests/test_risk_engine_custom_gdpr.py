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
        # SC-11: the matched keyword must NOT be echoed into risk reasons (it
        # would flow into copilot context, chat answers and the HTML register).
        self.assertNotIn("restricted vendor agreement", " ".join(risk["reasons"]))
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

    def test_risk_engine_returns_separate_compliance_and_operational_scores(self):
        risk = calculate_risk(
            {
                "name": "patient-export.xlsx",
                "path": r"C:\Desktop\patient-export.xlsx",
                "extension": ".xlsx",
                "size": 4096,
            },
            [
                {
                    "type": "gdpr_health_record",
                    "framework": "gdpr",
                    "category": "health_data",
                    "risk": "HIGH",
                    "count": 20,
                    "special_category": True,
                    "detection_confidence": 72,
                    "gdpr_article_mappings": [{"article": "9", "mapping_type": "classification"}],
                }
            ],
            {"score": 35, "issues": ["Everyone access"]},
        ).to_dict()

        self.assertEqual(risk["score"], risk["operational_priority_score"])
        self.assertEqual(risk["level"], risk["operational_priority"])
        self.assertGreaterEqual(risk["data_sensitivity_score"], 70)
        self.assertGreaterEqual(risk["compliance_impact_score"], 80)
        self.assertGreaterEqual(risk["access_risk_score"], 35)
        self.assertGreaterEqual(risk["exposure_score"], 10)
        self.assertEqual(risk["compliance_severity"], "HIGH")
        self.assertEqual(risk["detection_confidence"], "MEDIUM")
        self.assertEqual(
            risk["final_display"],
            {
                "compliance_severity": "High",
                "operational_priority": risk["operational_priority"].title(),
                "detection_confidence": "Medium",
            },
        )

    def test_access_risk_no_longer_inflates_compliance_severity(self):
        risk = calculate_risk(
            {"name": "public-readme.txt", "path": r"C:\Share\public-readme.txt", "extension": ".txt"},
            [{"type": "email", "framework": "gdpr", "category": "personal_data", "risk": "LOW", "confidence": "medium"}],
            {"score": 90, "issues": ["Everyone has write access"]},
        ).to_dict()

        self.assertEqual(risk["access_risk_score"], 90)
        self.assertEqual(risk["operational_priority"], "CRITICAL")
        self.assertEqual(risk["compliance_severity"], "LOW")


if __name__ == "__main__":
    unittest.main()
