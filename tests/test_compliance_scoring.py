import unittest

from backend.compliance_service import enrich_report_with_compliance, evaluate_file, normalize_framework_ids, selected_profiles


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
            "findings": [{"type": "credit_card", "risk": "HIGH", "count": 2}],
            "permissions": {"wide_access": False, "writable": False, "score": 0},
            "risk": {"score": 70, "level": "HIGH"},
        }
        compliance = evaluate_file(file_obj, selected_profiles(["pci_dss"]))
        self.assertIn("pci_dss", compliance["matched_frameworks"])
        self.assertIn("pci_payment", compliance["data_categories"])
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
            "findings": [{"type": "gdpr_health_medical_record", "risk": "HIGH", "count": 4, "category": "phi", "samples": ["di***is"]}],
            "permissions": {"wide_access": True, "writable": True, "score": 35},
            "risk": {"score": 90, "level": "CRITICAL"},
        }

        low_compliance = evaluate_file(low_signal, profiles)
        high_compliance = evaluate_file(exposed_health, profiles)

        self.assertLess(low_compliance["compliance_score"], 60)
        self.assertGreater(high_compliance["compliance_score"], low_compliance["compliance_score"])
        self.assertTrue(high_compliance["reason_details"])
        self.assertTrue(high_compliance["evidence"])


if __name__ == "__main__":
    unittest.main()
