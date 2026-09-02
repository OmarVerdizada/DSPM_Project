import unittest
import tempfile
from pathlib import Path

from classification.compliance import keyword_library
from classification.compliance.gdpr_classifier import classify_gdpr_content
from classification.compliance.keyword_index import compiled_keyword_index
from classification.compliance.pci_classifier import classify_pci_content


class ComplianceKeywordLibraryTests(unittest.TestCase):
    def test_aho_keyword_index_is_cached_by_catalog_metadata(self):
        groups = [{"framework": "gdpr", "language": "en", "type": "gdpr_email_address", "terms": ["email address"]}]
        first = compiled_keyword_index(framework="gdpr", catalog_version="test-v1", language="en", groups=groups)
        second = compiled_keyword_index(framework="gdpr", catalog_version="test-v1", language="en", groups=groups)

        self.assertIs(first, second)
        self.assertEqual(first.framework, "gdpr")
        self.assertEqual(first.catalog_version, "test-v1")
        self.assertEqual(first.language, "en")
        self.assertIn("gdpr_email_address", first.search("Email address: user@example.com"))

    def test_custom_keyword_import_enriches_confirmed_gdpr_finding(self):
        original_dir = keyword_library.CUSTOM_KEYWORD_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            keyword_library.CUSTOM_KEYWORD_DIR = Path(temp_dir)
            try:
                payload = {
                    "framework": "gdpr",
                    "language": "ru",
                    "mode": "merge",
                    "keywords": [
                        {
                            "type": "gdpr_full_name",
                            "category": "pii",
                            "terms": ["test russian full name marker"],
                        }
                    ],
                }
                result = keyword_library.import_keyword_groups("tenant_test", payload)
                self.assertTrue(result["imported"])
                self.assertEqual(result["new_terms"], 1)

                custom_groups = keyword_library.custom_keyword_groups_for_scan("tenant_test", "gdpr")
                findings = classify_gdpr_content("Full name: Omar Verdizada\ncontains test russian full name marker", {}, custom_groups)

                self.assertIn("gdpr_full_name", {finding["type"] for finding in findings})
                self.assertIn("test russian full name marker", findings[0].get("matched_keywords", []))
            finally:
                keyword_library.CUSTOM_KEYWORD_DIR = original_dir

    def test_text_terms_are_split_across_common_enterprise_delimiters(self):
        payload = {
            "framework": "gdpr",
            "language": "custom",
            "mode": "merge",
            "keywords": [
                {
                    "type": "gdpr_full_name",
                    "terms": "employee legal name, customer full name; beneficiary name|data subject name\tpayroll full name",
                }
            ],
        }

        groups = keyword_library.normalize_import_groups(payload)

        self.assertEqual(groups[0]["terms"], [
            "employee legal name",
            "customer full name",
            "beneficiary name",
            "data subject name",
            "payroll full name",
        ])

    def test_replace_type_replaces_only_matching_custom_finding_type(self):
        original_dir = keyword_library.CUSTOM_KEYWORD_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            keyword_library.CUSTOM_KEYWORD_DIR = Path(temp_dir)
            try:
                keyword_library.import_keyword_groups(
                    "tenant_modes",
                    {
                        "framework": "gdpr",
                        "mode": "merge",
                        "keywords": [
                            {"type": "gdpr_full_name", "terms": ["legacy subject name"]},
                            {"type": "gdpr_health_medical_record", "terms": ["legacy clinical marker"]},
                        ],
                    },
                )

                result = keyword_library.import_keyword_groups(
                    "tenant_modes",
                    {
                        "framework": "gdpr",
                        "mode": "replace_type",
                        "keywords": [{"type": "gdpr_full_name", "terms": ["approved legal name marker"]}],
                    },
                )
                groups = keyword_library.custom_keyword_groups_for_scan("tenant_modes", "gdpr")
                terms_by_type = {group["type"]: group["terms"] for group in groups}

                self.assertTrue(result["imported"])
                self.assertEqual(terms_by_type["gdpr_full_name"], ["approved legal name marker"])
                self.assertEqual(terms_by_type["gdpr_health_medical_record"], ["legacy clinical marker"])
            finally:
                keyword_library.CUSTOM_KEYWORD_DIR = original_dir

    def test_custom_keyword_matching_uses_word_boundaries(self):
        group = {"type": "gdpr_health_medical_record", "terms": ["clinical diagnosis"]}

        positive = classify_gdpr_content("medical record: MRN-1234567 diagnosis I10\nPatient file contains clinical diagnosis details.", {}, [group])
        negative = classify_gdpr_content("The term nonclinical diagnosislike content should not match.", {}, [group])

        self.assertIn("gdpr_health_medical_record", {finding["type"] for finding in positive})
        self.assertNotIn("gdpr_health_medical_record", {finding["type"] for finding in negative})

    def test_custom_finding_type_does_not_create_keyword_only_gdpr_finding(self):
        original_dir = keyword_library.CUSTOM_KEYWORD_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            keyword_library.CUSTOM_KEYWORD_DIR = Path(temp_dir)
            try:
                payload = {
                    "framework": "gdpr",
                    "language": "custom",
                    "mode": "merge",
                    "keywords": [
                        {
                            "type": "custom_contract_marker",
                            "category": "legal",
                            "label": "Custom contract marker",
                            "risk": "HIGH",
                            "terms": ["restricted contract phrase"],
                        }
                    ],
                }

                preview = keyword_library.validate_keyword_import("tenant_custom", payload)
                result = keyword_library.import_keyword_groups("tenant_custom", payload)
                custom_groups = keyword_library.custom_keyword_groups_for_scan("tenant_custom", "gdpr")
                findings = classify_gdpr_content("This file has a restricted contract phrase.", {}, custom_groups)
                custom = next(item for item in findings if item["type"] == "custom_contract_marker")

                self.assertTrue(preview["valid"])
                self.assertEqual(preview["unknown_types"], [])
                self.assertTrue(result["imported"])
                self.assertFalse(custom["data_presence"])
                self.assertFalse(custom["scope_candidate"])
                self.assertTrue(custom["needs_review"])
                self.assertEqual(custom["custom_rule_mode"], "CONTEXT_ONLY")
            finally:
                keyword_library.CUSTOM_KEYWORD_DIR = original_dir

    def test_pci_dss_keyword_library_supports_builtin_and_custom_context(self):
        original_dir = keyword_library.CUSTOM_KEYWORD_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            keyword_library.CUSTOM_KEYWORD_DIR = Path(temp_dir)
            try:
                builtins = keyword_library.list_keyword_groups("tenant_pci", "pci_dss")
                self.assertIn("pci_chd_pan", {group["type"] for group in builtins["groups"]})

                payload = {
                    "framework": "pci_dss",
                    "language": "custom",
                    "mode": "merge",
                    "keywords": [
                        {
                            "type": "pci_processor_context",
                            "category": "pci_scope_context",
                            "label": "Processor context",
                            "risk": "MEDIUM",
                            "terms": ["alpha-payment-switch"],
                        }
                    ],
                }
                result = keyword_library.import_keyword_groups("tenant_pci", payload)
                custom_groups = keyword_library.custom_keyword_groups_for_scan("tenant_pci", "pci_dss")
                findings = classify_pci_content("alpha-payment-switch route notes", {}, custom_groups)
                custom = next(item for item in findings if item["type"] == "pci_processor_context")

                self.assertTrue(result["imported"])
                self.assertEqual(custom["pci_category"], "CONTEXT")
                self.assertFalse(custom["scope_candidate"])
            finally:
                keyword_library.CUSTOM_KEYWORD_DIR = original_dir

    def test_corrupt_keyword_catalog_uses_last_known_good_and_reports_error(self):
        original_dir = keyword_library.CUSTOM_KEYWORD_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            keyword_library.CUSTOM_KEYWORD_DIR = Path(temp_dir)
            try:
                keyword_library.import_keyword_groups(
                    "tenant_corrupt",
                    {
                        "framework": "gdpr",
                        "keywords": [{"type": "gdpr_full_name", "terms": ["approved subject marker"]}],
                    },
                )
                path = keyword_library._custom_path("tenant_corrupt", "gdpr")
                path.write_text("{ broken json", encoding="utf-8")

                status = keyword_library.keyword_catalog_status("tenant_corrupt", "gdpr")
                groups = keyword_library.custom_keyword_groups_for_scan("tenant_corrupt", "gdpr")

                self.assertEqual(status["catalog_status"], "ERROR")
                self.assertTrue(status["degraded_mode"])
                self.assertEqual(groups[0]["terms"], ["approved subject marker"])
                self.assertTrue(groups[0]["degraded_mode"])
                self.assertTrue(keyword_library._catalog_alert_path("tenant_corrupt", "gdpr").exists())
                self.assertTrue(keyword_library._catalog_audit_path("tenant_corrupt", "gdpr").exists())
            finally:
                keyword_library.CUSTOM_KEYWORD_DIR = original_dir

    def test_keyword_import_limits_reject_excessive_request(self):
        payload = {
            "framework": "gdpr",
            "keywords": [
                {
                    "type": "gdpr_full_name",
                    "terms": [f"term {index}" for index in range(keyword_library.MAX_TERMS_PER_GROUP + 1)],
                }
            ],
        }

        preview = keyword_library.validate_keyword_import("tenant_limits", payload)

        self.assertFalse(preview["valid"])
        self.assertTrue(preview["approval_required"])
        self.assertTrue(preview["limit_errors"])

    def test_enterprise_rule_metadata_is_preserved_for_custom_rules(self):
        payload = {
            "framework": "gdpr",
            "keywords": [
                {
                    "type": "custom_employee_identifier",
                    "category": "personal_data",
                    "label": "Employee identifier",
                    "risk": "HIGH",
                    "terms": ["employee registry id"],
                    "negative_keywords": ["sample employee registry id"],
                    "regex": [r"EMP-[0-9]{6}"],
                    "validator": "employee_id",
                    "normalizer": "uppercase",
                    "checksum": "mod11",
                    "minimum_context_score": 70,
                    "proximity": 80,
                    "structured_field_names": ["employee_id"],
                    "allowed_file_types": ["csv"],
                    "excluded_paths": ["test-fixtures"],
                    "confidence": "high",
                    "framework_mapping": [{"framework": "GDPR", "requirement_id": "Article 5"}],
                    "version": "2.1.0",
                    "owner": "Privacy",
                    "status": "pending_approval",
                    "effective_date": "2026-01-01",
                    "expiration_date": "2027-01-01",
                    "test_cases": [{"name": "positive", "input": "EMP-123456", "expected_match": True}],
                }
            ],
        }

        group = keyword_library.normalize_import_groups(payload)[0]

        self.assertEqual(group["positive_keywords"], ["employee registry id"])
        self.assertEqual(group["negative_keywords"], ["sample employee registry id"])
        self.assertEqual(group["regex"], [r"EMP-[0-9]{6}"])
        self.assertEqual(group["validator"], "employee_id")
        self.assertEqual(group["allowed_file_types"], [".csv"])
        self.assertEqual(group["status"], "pending_approval")
        self.assertEqual(group["test_cases"][0]["name"], "positive")

    def test_tenant_isolation_and_multi_update_keyword_merges(self):
        original_dir = keyword_library.CUSTOM_KEYWORD_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            keyword_library.CUSTOM_KEYWORD_DIR = Path(temp_dir)
            try:
                keyword_library.import_keyword_groups("tenant_a", {"framework": "gdpr", "keywords": [{"type": "gdpr_full_name", "terms": ["tenant a marker"]}]})
                keyword_library.import_keyword_groups("tenant_b", {"framework": "gdpr", "keywords": [{"type": "gdpr_full_name", "terms": ["tenant b marker"]}]})
                keyword_library.import_keyword_groups("tenant_a", {"framework": "gdpr", "keywords": [{"type": "gdpr_full_name", "terms": ["tenant a second marker"]}]})

                tenant_a_terms = keyword_library.custom_keyword_groups_for_scan("tenant_a", "gdpr")[0]["terms"]
                tenant_b_terms = keyword_library.custom_keyword_groups_for_scan("tenant_b", "gdpr")[0]["terms"]

                self.assertEqual(tenant_a_terms, ["tenant a marker", "tenant a second marker"])
                self.assertEqual(tenant_b_terms, ["tenant b marker"])
            finally:
                keyword_library.CUSTOM_KEYWORD_DIR = original_dir

    def test_rule_version_metadata_survives_import_migration(self):
        payload = {
            "framework": "gdpr",
            "keywords": [
                {
                    "type": "custom_versioned_rule",
                    "category": "personal_data",
                    "label": "Versioned rule",
                    "risk": "MEDIUM",
                    "terms": ["version marker"],
                    "version": "2026.07.03",
                }
            ],
        }

        group = keyword_library.normalize_import_groups(payload)[0]

        self.assertEqual(group["version"], "2026.07.03")

    def test_pci_pan_keywords_are_split_from_protection_keywords(self):
        groups = {group["type"]: group for group in keyword_library.built_in_keyword_groups("pci_dss")}

        self.assertIn("pci_chd_pan", groups)
        self.assertIn("pci_pan_protection_claim", groups)
        self.assertIn("pci_pan_encryption_control", groups)
        self.assertIn("pci_pan_tokenization", groups)
        self.assertIn("pci_pan_truncation", groups)
        self.assertNotIn("encrypted pan", {term.lower() for term in groups["pci_chd_pan"]["terms"]})
        self.assertIn("encrypted pan", {term.lower() for term in groups["pci_pan_encryption_control"]["terms"]})


if __name__ == "__main__":
    unittest.main()
