import unittest

from backend.compliance_service import build_nist_sp800_60_report, enrich_report_with_compliance


class NISTRiskMappingTests(unittest.TestCase):
    def test_nist_compliance_report_is_added(self):
        report = {
            "files": [
                {
                    "name": "identity.csv",
                    "path": "identity.csv",
                    "risk": {"score": 60},
                    "permissions": {"wide_access": True},
                    "findings": [
                        {
                            "framework": "nist_sp800_60_enterprise",
                            "type": "nist_privacy_pii_type_01",
                            "rule_id": "NIST-PII-PRIVACY-001",
                            "category_id": "nist_privacy_pii",
                            "category": "Privacy PII",
                            "risk": "HIGH",
                            "product_severity": "HIGH",
                            "overall_impact": "HIGH",
                            "handling_tier": "RESTRICTED",
                            "confidence": "high",
                            "final_risk_score": 82,
                            "needs_review": True,
                        }
                    ],
                }
            ]
        }

        enriched = enrich_report_with_compliance(report, True, ["nist_sp800_60_enterprise"])

        self.assertIn("nist_sp800_60_enterprise_report", enriched)
        self.assertEqual(enriched["compliance_summary"]["total_compliance_findings"], 1)

    def test_nist_report_counts_distributions(self):
        data = build_nist_sp800_60_report(
            [
                {
                    "name": "a.txt",
                    "permissions": {"public": True},
                    "findings": [
                        {
                            "framework": "nist_sp800_60_enterprise",
                            "rule_id": "NIST-CUI-TEST-001",
                            "category_id": "nist_security_operations",
                            "source_kind": "CUI",
                            "handling_tier": "RESTRICTED",
                            "product_severity": "HIGH",
                            "overall_impact": "HIGH",
                            "confidence": "high",
                            "needs_review": True,
                            "final_risk_score": 80,
                        }
                    ],
                }
            ]
        )

        self.assertEqual(data["total_nist_findings"], 1)
        self.assertEqual(data["source_kind_distribution"]["CUI"], 1)
        self.assertTrue(data["publicly_exposed_findings"])


if __name__ == "__main__":
    unittest.main()

