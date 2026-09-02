import unittest

from backend.compliance_service import build_compliance_summary, enrich_report_with_compliance, evaluate_file, normalize_framework_ids, selected_profiles


class ComplianceScoringTests(unittest.TestCase):
    def test_framework_validation_rejects_unknown_ids(self):
        with self.assertRaises(ValueError):
            normalize_framework_ids(["gdpr", "made_up"])

    def test_gdpr_maps_personal_data(self):
        file_obj = {
            "name": "customers.csv",
            "path": r"C:\Exports\customers.csv",
            "extension": ".csv",
            "findings": [{"type": "email", "risk": "MEDIUM", "count": 5}],
            "permissions": {"wide_access": True, "writable": False, "score": 20},
            "risk": {"score": 55, "level": "MEDIUM"},
        }
        compliance = evaluate_file(file_obj, selected_profiles(["gdpr"]))
        self.assertIn("gdpr", compliance["matched_frameworks"])
        self.assertIn("pii", compliance["data_categories"])
        self.assertGreaterEqual(compliance["compliance_score"], 70)

    def test_pci_maps_payment_card_data(self):
        file_obj = {
            "name": "cardholder-data.xlsx",
            "path": r"C:\Finance\cardholder-data.xlsx",
            "extension": ".xlsx",
            "findings": [{"type": "pci_chd_pan", "framework": "pci_dss", "risk": "HIGH", "count": 2, "category": "pci_cardholder_data"}],
            "permissions": {"wide_access": False, "writable": False, "score": 0},
            "risk": {"score": 70, "level": "HIGH"},
        }
        compliance = evaluate_file(file_obj, selected_profiles(["pci_dss"]))
        self.assertIn("pci_dss", compliance["matched_frameworks"])
        self.assertIn("pci_cardholder_data", compliance["data_categories"])
        self.assertNotIn("pci_payment", compliance["data_categories"])
        self.assertLessEqual(compliance["compliance_score"], 100)

    def test_hipaa_maps_phi_context(self):
        file_obj = {
            "name": "patient-notes.docx",
            "path": r"C:\Health\patient-notes.docx",
            "extension": ".docx",
            "findings": [{"type": "phi_context", "risk": "HIGH", "count": 1}],
            "permissions": {"wide_access": True, "writable": True, "score": 35},
            "risk": {"score": 75, "level": "HIGH"},
        }
        compliance = evaluate_file(file_obj, selected_profiles(["hipaa"]))
        self.assertIn("hipaa", compliance["matched_frameworks"])
        self.assertEqual(compliance["compliance_severity"], "CRITICAL")

    def test_disabled_compliance_keeps_summary_empty(self):
        report = {"files": [{"name": "a.txt", "findings": [{"type": "email"}], "risk": {"score": 50}}]}
        enriched = enrich_report_with_compliance(report, False, ["gdpr"])
        self.assertFalse(enriched["compliance_summary"]["enabled"])
        self.assertNotIn("compliance", enriched["files"][0])

    def test_disabled_compliance_strips_framework_only_results_but_keeps_generic_findings(self):
        report = {
            "files": [{
                "name": "mixed.txt",
                "compliance": {"matched_frameworks": ["gdpr"]},
                "findings": [
                    {"type": "email", "risk": "MEDIUM", "framework": "generic", "framework_mappings": ["GDPR"]},
                    {"type": "gdpr_full_name", "framework": "gdpr"},
                    {"type": "pci_chd_pan", "framework": "pci_dss"},
                    {"type": "nist_privacy_pii_type_01", "framework": "nist_sp800_60_enterprise"},
                ],
            }],
            "gdpr_report": {"stale": True},
            "pci_scope_summary": {"stale": True},
            "nist_sp800_60_enterprise_report": {"stale": True},
        }

        enriched = enrich_report_with_compliance(report, False, ["gdpr", "pci_dss", "nist_sp800_60_enterprise"])

        self.assertEqual([finding["type"] for finding in enriched["files"][0]["findings"]], ["email"])
        self.assertEqual(enriched["files"][0]["findings"][0]["framework_mappings"], [])
        self.assertNotIn("compliance", enriched["files"][0])
        self.assertNotIn("gdpr_report", enriched)
        self.assertNotIn("pci_scope_summary", enriched)
        self.assertNotIn("nist_sp800_60_enterprise_report", enriched)

    def test_gdpr_scoring_varies_by_evidence_and_exposure(self):
        profiles = selected_profiles(["gdpr"])
        low_signal = {
            "name": "names.txt",
            "path": r"C:\HR\names.txt",
            "extension": ".txt",
            "findings": [{"type": "gdpr_full_name", "risk": "LOW", "count": 1, "category": "pii", "samples": ["Jo***th"]}],
            "permissions": {"wide_access": False, "writable": False, "score": 0},
            "risk": {"score": 20, "level": "LOW"},
        }
        exposed_health = {
            "name": "medical.xlsx",
            "path": r"C:\Desktop\medical.xlsx",
            "extension": ".xlsx",
            "findings": [{"type": "gdpr_health_medical_record", "risk": "HIGH", "count": 4, "category": "health_data", "samples": ["di***is"]}],
            "permissions": {"wide_access": True, "writable": True, "score": 35},
            "risk": {"score": 90, "level": "CRITICAL"},
        }

        low_compliance = evaluate_file(low_signal, profiles)
        high_compliance = evaluate_file(exposed_health, profiles)

        self.assertLess(low_compliance["compliance_score"], 60)
        self.assertGreater(high_compliance["compliance_score"], low_compliance["compliance_score"])
        self.assertTrue(high_compliance["reason_details"])
        self.assertTrue(high_compliance["evidence"])

    def test_compliance_summary_separates_file_finding_occurrence_and_unique_counts(self):
        profiles = selected_profiles(["gdpr"])
        files = [
            {
                "name": "customers.csv",
                "path": r"C:\Exports\customers.csv",
                "asset_id": "asset-1",
                "findings": [
                    {
                        "type": "email",
                        "framework": "gdpr",
                        "risk": "MEDIUM",
                        "count": 20,
                        "occurrence_count": 20,
                        "unique_value_count": 20,
                        "category": "personal_data",
                    },
                    {
                        "type": "gdpr_health_medical_record",
                        "framework": "gdpr",
                        "risk": "HIGH",
                        "count": 2,
                        "unique_value_count": 1,
                        "category": "health_data",
                    },
                ],
                "compliance": {
                    "matched_frameworks": ["gdpr"],
                    "matched_framework_names": ["GDPR"],
                    "data_categories": ["personal_data", "health_data"],
                    "compliance_score": 90,
                    "compliance_severity": "CRITICAL",
                    "relevant_controls": ["GDPR personal data"],
                },
            }
        ]

        summary = build_compliance_summary(files, profiles)

        self.assertEqual(summary["affected_asset_count"], 1)
        self.assertEqual(summary["affected_file_count"], 1)
        self.assertEqual(summary["finding_group_count"], 2)
        self.assertEqual(summary["total_compliance_findings"], 2)
        self.assertEqual(summary["occurrence_count"], 22)
        self.assertEqual(summary["unique_sensitive_value_count"], 21)
        self.assertEqual(summary["critical"], 0)
        self.assertEqual(summary["high"], 1)
        self.assertEqual(summary["medium"], 1)


if __name__ == "__main__":
    unittest.main()
