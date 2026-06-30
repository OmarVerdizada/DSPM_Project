import tempfile
import unittest
import tempfile
from pathlib import Path

from classification.compliance import keyword_library
from classification.compliance.gdpr_classifier import classify_gdpr_content


class ComplianceKeywordLibraryTests(unittest.TestCase):
    def test_custom_keyword_import_extends_gdpr_classifier(self):
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
                findings = classify_gdpr_content("contains test russian full name marker", {}, custom_groups)

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

        positive = classify_gdpr_content("Patient file contains clinical diagnosis details.", {}, [group])
        negative = classify_gdpr_content("The term nonclinical diagnosislike content should not match.", {}, [group])

        self.assertIn("gdpr_health_medical_record", {finding["type"] for finding in positive})
        self.assertNotIn("gdpr_health_medical_record", {finding["type"] for finding in negative})


if __name__ == "__main__":
    unittest.main()
