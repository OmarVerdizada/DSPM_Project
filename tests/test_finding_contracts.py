import unittest

from backend.finding_contracts import (
    build_nist_finding_detail,
    get_finding_display_name,
    normalize_framework_id,
)
from classification.compliance.nist_catalog import list_nist_rules
from classification.compliance.nist_classifier import classify_nist_content
from classification.compliance.keyword_library import list_keyword_groups


class FindingContractTests(unittest.TestCase):
    def test_nist_display_name_prefers_human_label_over_generated_type(self):
        finding = {
            "framework": "nist",
            "category": "nist_export_control",
            "label": "Export Control Type 1",
            "type": "nist_export_control_type_1",
            "rule_id": "NIST-EXPORT-001",
        }

        self.assertEqual(get_finding_display_name(finding), "Controlled Technical Information")
        self.assertEqual(get_finding_display_name(finding, "az"), "Nəzarət olunan texniki məlumat")

    def test_display_name_fallback_cleans_generated_type_suffix(self):
        finding = {"framework": "standard_scan", "label": "Financial Records Type 1", "type": "finance_type_1"}

        self.assertEqual(get_finding_display_name(finding), "Financial Records")

    def test_framework_normalization_keeps_nist_distinct_from_standard_scan(self):
        self.assertEqual(normalize_framework_id("NIST SP 800-60 Enterprise"), "nist_sp800_60_enterprise")
        self.assertEqual(normalize_framework_id("nist_sp800_60"), "nist_sp800_60_enterprise")
        self.assertEqual(normalize_framework_id("standard_scan"), "generic")

    def test_nist_rule_list_uses_real_display_names_without_type_numbers(self):
        education = list_nist_rules(category="nist_education", limit=20)["rules"]
        privacy = list_nist_rules(category="nist_privacy_pii", limit=20)["rules"]

        self.assertTrue(any(rule["display_name"] == "Student Records" for rule in education))
        self.assertTrue(any(rule["display_name"] == "Sensitive Personally Identifiable Information" for rule in privacy))
        self.assertFalse(any("Type " in rule["display_name"] for rule in education + privacy))

    def test_nist_keyword_library_legal_options_are_distinct_rule_names(self):
        library = list_keyword_groups("default", "nist_sp800_60_enterprise")
        legal = [group for group in library["groups"] if group.get("category") == "nist_legal"]
        labels = [group["label"] for group in legal]

        self.assertIn("Legal Matter Records", labels)
        self.assertIn("Law Enforcement Records", labels)
        self.assertEqual(len(labels), len(set(labels)))
        self.assertFalse(any(label == "Legal and Law Enforcement" for label in labels))

    def test_nist_detail_payload_is_framework_aware(self):
        finding = {
            "framework": "nist",
            "category": "nist_credentials_secrets",
            "rule_id": "NIST-CRED-001",
            "type": "nist_credentials_secrets_type_1",
            "product_severity": "CRITICAL",
            "matched_signal_groups": ["credential"],
            "framework_mappings": [{"framework": "NIST SP 800-60"}],
        }

        detail = build_nist_finding_detail(finding)

        self.assertEqual(detail["summary"]["display_name"], "API Keys, Access Tokens and OAuth Secrets")
        self.assertNotIn("Assur" + "ance", str(detail))
        self.assertIn("identity", detail)
        self.assertIn("classification", detail)
        self.assertIn("mappings", detail)

    def test_classifier_preserves_nist_metadata_and_redacts_sensitive_evidence(self):
        findings = classify_nist_content(
            "password token-ABCD1234 NIST SP 800-60 Credentials and Secrets Type 1 private key",
            {"path": "prod/secrets.env", "extension": ".env"},
        )

        self.assertTrue(findings)
        finding = findings[0]
        self.assertEqual(finding["framework"], "nist_sp800_60_enterprise")
        self.assertIn("framework_metadata", finding)
        self.assertIn("nist", finding["framework_metadata"])
        self.assertIn("display_name", finding)
        self.assertIn("technical_type", finding)
        removed_field = "protection_" + "".join(["a", "s", "s", "u", "r", "a", "n", "c", "e"])
        self.assertNotIn(removed_field, finding)
        self.assertNotIn("token-ABCD1234", str(finding))
        self.assertTrue(finding.get("secure_value_fingerprints"))


if __name__ == "__main__":
    unittest.main()
