import unittest

from backend.compliance_service import build_pci_scope_summary, enrich_report_with_compliance, evaluate_file, selected_profiles


class PCIComplianceMappingTests(unittest.TestCase):
    def test_pci_pan_maps_to_pci_dss_cardholder_data(self):
        file_obj = {
            "name": "cardholder-data.csv",
            "path": r"C:\Exports\cardholder-data.csv",
            "extension": ".csv",
            "findings": [
                {
                    "type": "pci_chd_pan",
                    "framework": "pci_dss",
                    "risk": "CRITICAL",
                    "count": 1,
                    "category": "pci_cardholder_data",
                    "samples": ["411111******1111"],
                    "protection_state": "READABLE_FULL",
                }
            ],
            "permissions": {"wide_access": False, "writable": False, "score": 0},
            "risk": {"score": 90, "level": "CRITICAL"},
        }

        compliance = evaluate_file(file_obj, selected_profiles(["pci_dss"]))

        self.assertIn("pci_dss", compliance["matched_frameworks"])
        self.assertIn("pci_cardholder_data", compliance["data_categories"])
        self.assertNotIn("pci_payment", compliance["data_categories"])
        self.assertEqual(compliance["compliance_severity"], "CRITICAL")

    def test_pci_cardholder_name_maps_when_linked_to_pan(self):
        file_obj = {
            "name": "cardholder-data.csv",
            "path": r"C:\Exports\cardholder-data.csv",
            "extension": ".csv",
            "findings": [
                {
                    "type": "pci_chd_cardholder_name",
                    "framework": "pci_dss",
                    "risk": "HIGH",
                    "count": 1,
                    "category": "pci_cardholder_data",
                    "samples": ["O***r V***a"],
                    "correlated_elements": ["pan"],
                }
            ],
            "permissions": {"wide_access": False, "writable": False, "score": 0},
            "risk": {"score": 70, "level": "HIGH"},
        }

        compliance = evaluate_file(file_obj, selected_profiles(["pci_dss"]))

        self.assertIn("pci_dss", compliance["matched_frameworks"])
        self.assertIn("pci_cardholder_data", compliance["data_categories"])

    def test_pci_expiration_date_maps_when_linked_to_pan(self):
        file_obj = {
            "name": "cardholder-data.csv",
            "path": r"C:\Exports\cardholder-data.csv",
            "extension": ".csv",
            "findings": [
                {
                    "type": "pci_chd_expiration_date",
                    "framework": "pci_dss",
                    "risk": "HIGH",
                    "count": 1,
                    "category": "pci_cardholder_data",
                    "samples": ["12/2029"],
                    "correlated_elements": ["pan"],
                }
            ],
            "permissions": {"wide_access": False, "writable": False, "score": 0},
            "risk": {"score": 70, "level": "HIGH"},
        }

        compliance = evaluate_file(file_obj, selected_profiles(["pci_dss"]))

        self.assertIn("pci_dss", compliance["matched_frameworks"])
        self.assertIn("pci_cardholder_data", compliance["data_categories"])

    def test_pci_service_code_maps_when_linked_to_pan(self):
        file_obj = {
            "name": "cardholder-data.csv",
            "path": r"C:\Exports\cardholder-data.csv",
            "extension": ".csv",
            "findings": [
                {
                    "type": "pci_chd_service_code",
                    "framework": "pci_dss",
                    "risk": "HIGH",
                    "count": 1,
                    "category": "pci_cardholder_data",
                    "samples": ["201"],
                    "correlated_elements": ["pan"],
                }
            ],
            "permissions": {"wide_access": False, "writable": False, "score": 0},
            "risk": {"score": 70, "level": "HIGH"},
        }

        compliance = evaluate_file(file_obj, selected_profiles(["pci_dss"]))

        self.assertIn("pci_dss", compliance["matched_frameworks"])
        self.assertIn("pci_cardholder_data", compliance["data_categories"])

    def test_pci_track_data_maps_to_sensitive_authentication_data(self):
        file_obj = {
            "name": "swipe.log",
            "path": r"C:\Exports\swipe.log",
            "extension": ".log",
            "findings": [
                {
                    "type": "pci_sad_track_data",
                    "framework": "pci_dss",
                    "risk": "CRITICAL",
                    "count": 1,
                    "category": "pci_sensitive_authentication_data",
                    "samples": ["track_2 PAN=411111******1111 EXP=12/2029 SVC=201 DISC_LEN=11"],
                    "correlated_elements": ["pan", "expiration_date", "service_code", "discretionary_data"],
                }
            ],
            "permissions": {"wide_access": False, "writable": False, "score": 0},
            "risk": {"score": 95, "level": "CRITICAL"},
        }

        compliance = evaluate_file(file_obj, selected_profiles(["pci_dss"]))

        self.assertIn("pci_dss", compliance["matched_frameworks"])
        self.assertIn("pci_sensitive_authentication_data", compliance["data_categories"])
        self.assertEqual(compliance["compliance_severity"], "CRITICAL")

    def test_pci_cvv_maps_to_sensitive_authentication_data(self):
        file_obj = {
            "name": "payment-request.log",
            "path": r"C:\Exports\payment-request.log",
            "extension": ".log",
            "findings": [
                {
                    "type": "pci_sad_cvv",
                    "framework": "pci_dss",
                    "risk": "CRITICAL",
                    "count": 1,
                    "category": "pci_sensitive_authentication_data",
                    "samples": ["CVV_LEN=3"],
                    "correlated_elements": ["pan"],
                }
            ],
            "permissions": {"wide_access": False, "writable": False, "score": 0},
            "risk": {"score": 95, "level": "CRITICAL"},
        }

        compliance = evaluate_file(file_obj, selected_profiles(["pci_dss"]))

        self.assertIn("pci_dss", compliance["matched_frameworks"])
        self.assertIn("pci_sensitive_authentication_data", compliance["data_categories"])
        self.assertEqual(compliance["compliance_severity"], "CRITICAL")

    def test_pci_pin_maps_to_sensitive_authentication_data(self):
        file_obj = {
            "name": "atm-request.log",
            "path": r"C:\Exports\atm-request.log",
            "extension": ".log",
            "findings": [
                {
                    "type": "pci_sad_pin",
                    "framework": "pci_dss",
                    "risk": "CRITICAL",
                    "count": 1,
                    "category": "pci_sensitive_authentication_data",
                    "samples": ["PIN_LEN=4"],
                    "correlated_elements": ["pan"],
                }
            ],
            "permissions": {"wide_access": False, "writable": False, "score": 0},
            "risk": {"score": 95, "level": "CRITICAL"},
        }

        compliance = evaluate_file(file_obj, selected_profiles(["pci_dss"]))

        self.assertIn("pci_dss", compliance["matched_frameworks"])
        self.assertIn("pci_sensitive_authentication_data", compliance["data_categories"])

    def test_composite_pci_findings_map_to_expected_categories(self):
        file_obj = {
            "name": "payment-request.log",
            "path": r"C:\Prod\payment-request.log",
            "extension": ".log",
            "findings": [
                {
                    "type": "pci_composite_sad",
                    "framework": "pci_dss",
                    "risk": "CRITICAL",
                    "count": 1,
                    "category": "pci_sensitive_authentication_data",
                    "pci_category": "SAD",
                    "samples": ["PAN+SAD_COMPOSITE"],
                    "exception_required": True,
                }
            ],
            "permissions": {"wide_access": True, "writable": True, "score": 40},
            "risk": {"score": 98, "level": "CRITICAL"},
        }

        compliance = evaluate_file(file_obj, selected_profiles(["pci_dss"]))

        self.assertIn("pci_dss", compliance["matched_frameworks"])
        self.assertIn("pci_sensitive_authentication_data", compliance["data_categories"])
        self.assertEqual(compliance["compliance_severity"], "CRITICAL")

    def test_builds_pci_scope_summary_and_exception_queue(self):
        files = [
            {
                "name": "payment-request.log",
                "path": r"C:\Prod\payment-request.log",
                "extension": ".log",
                "findings": [
                    {
                        "type": "pci_sad_cvv",
                        "framework": "pci_dss",
                        "risk": "CRITICAL",
                        "count": 1,
                        "category": "pci_sensitive_authentication_data",
                        "pci_category": "SAD",
                        "samples": ["CVV_LEN=3"],
                        "storage_state": "log_or_diagnostic",
                        "environment": "production",
                        "entity_role": "merchant",
                        "authorization_state": "post_authorization",
                        "exception_required": True,
                    },
                    {
                        "type": "pci_chd_pan",
                        "framework": "pci_dss",
                        "risk": "CRITICAL",
                        "count": 1,
                        "category": "pci_cardholder_data",
                        "pci_category": "CHD",
                        "samples": ["411111******1111"],
                        "storage_state": "log_or_diagnostic",
                        "environment": "production",
                    },
                ],
                "risk": {"score": 96, "level": "CRITICAL"},
            }
        ]

        summary = build_pci_scope_summary(files)

        self.assertEqual(summary["cde_candidate_count"], 1)
        self.assertEqual(summary["sad_retention_candidate_count"], 1)
        self.assertEqual(summary["exception_required_count"], 1)
        self.assertEqual(summary["environment_counts"]["production"], 2)
        self.assertEqual(summary["category_finding_group_counts"]["SAD"], 1)
        self.assertEqual(summary["category_finding_group_counts"]["CHD"], 1)
        self.assertEqual(summary["category_occurrence_counts"]["SAD"], 1)
        self.assertEqual(summary["scope_candidates"][0]["storage_state"], "log_or_diagnostic")

    def test_pci_scope_summary_filters_context_child_and_low_confidence_evidence(self):
        files = [
            {
                "name": "payment-context.txt",
                "path": r"C:\Payments\payment-context.txt",
                "findings": [
                    {
                        "type": "pci_payment_context",
                        "framework": "pci_dss",
                        "risk": "MEDIUM",
                        "category": "pci_scope_context",
                        "pci_category": "CONTEXT",
                        "scope_candidate": True,
                        "confidence": "high",
                    },
                    {
                        "type": "pci_chd_pan_child",
                        "framework": "pci_dss",
                        "risk": "HIGH",
                        "category": "pci_cardholder_data",
                        "pci_category": "CHD",
                        "display_state": "child_evidence",
                        "confidence": "high",
                    },
                    {
                        "type": "pci_chd_pan_low_confidence",
                        "framework": "pci_dss",
                        "risk": "HIGH",
                        "category": "pci_cardholder_data",
                        "pci_category": "CHD",
                        "confidence": "low",
                    },
                    {
                        "type": "pci_chd_pan_context_only",
                        "framework": "pci_dss",
                        "risk": "HIGH",
                        "category": "pci_cardholder_data",
                        "pci_category": "CHD",
                        "scope_candidate": False,
                        "confidence": "high",
                    },
                    {
                        "type": "pci_chd_pan",
                        "framework": "pci_dss",
                        "risk": "CRITICAL",
                        "category": "pci_cardholder_data",
                        "pci_category": "CHD",
                        "count": 3,
                        "scope_candidate": True,
                        "confidence": "medium",
                        "protection_state": "READABLE_FULL",
                    },
                ],
            }
        ]

        summary = build_pci_scope_summary(files)

        self.assertEqual(summary["cde_candidate_count"], 1)
        self.assertEqual(summary["category_finding_group_counts"], {"CHD": 1})
        self.assertEqual(summary["category_occurrence_counts"], {"CHD": 3})
        self.assertEqual(summary["scope_candidates"][0]["finding_types"], ["pci_chd_pan"])

    def test_enriched_report_redacts_raw_pci_values_before_persistence(self):
        report = {
            "files": [
                {
                    "name": "raw-payment.log",
                    "path": "raw-payment.log",
                    "extension": ".log",
                    "preview": {"available": True, "lines": ["card_number: 4111 1111 1111 1111", "cvv: 123"]},
                    "findings": [
                        {
                            "type": "pci_chd_pan",
                            "framework": "pci_dss",
                            "risk": "CRITICAL",
                            "count": 1,
                            "category": "pci_cardholder_data",
                            "pci_category": "CHD",
                            "samples": ["4111 1111 1111 1111"],
                            "protection_state": "READABLE_FULL",
                        }
                    ],
                    "permissions": {},
                    "risk": {"score": 90, "level": "CRITICAL"},
                }
            ]
        }

        enriched = enrich_report_with_compliance(report, True, ["pci_dss"])

        serialized = str(enriched)
        self.assertIn("pci_scope_summary", enriched)
        self.assertIn("411111******1111", serialized)
        self.assertNotIn("4111 1111 1111 1111", serialized)
        self.assertNotIn("cvv: 123", serialized)


if __name__ == "__main__":
    unittest.main()
