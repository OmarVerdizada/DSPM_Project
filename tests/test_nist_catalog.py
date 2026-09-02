import copy
import unittest

from classification.compliance.nist_catalog import built_in_nist_keyword_groups, load_nist_catalog, nist_catalog_status
from classification.compliance.nist_validators import validate_nist_catalog_payload


class NISTCatalogTests(unittest.TestCase):
    def test_built_in_catalog_loads_expected_counts(self):
        catalog = load_nist_catalog()
        status = nist_catalog_status()

        self.assertEqual(catalog["framework"], "nist_sp800_60_enterprise")
        self.assertEqual(len(catalog["categories"]), 22)
        self.assertEqual(len(catalog["rules"]), 154)
        self.assertEqual(status["rule_count"], 154)
        self.assertEqual(status["category_count"], 22)
        self.assertEqual(len(status["catalog_hash"]), 64)

    def test_built_in_catalog_preserves_nested_keyword_groups(self):
        rule = load_nist_catalog()["rules"][0]

        self.assertIn("classification", rule)
        self.assertIn("detection", rule)
        self.assertIn("keyword_groups", rule["detection"])
        self.assertIn("primary_and_aliases", rule["detection"]["keyword_groups"])

    def test_keyword_groups_are_available_for_overlay_ui(self):
        groups = built_in_nist_keyword_groups()

        self.assertEqual(len(groups), 154)
        self.assertTrue(all(group["framework"] == "nist_sp800_60_enterprise" for group in groups))

    def test_wrong_framework_is_rejected(self):
        catalog = copy.deepcopy(load_nist_catalog())
        catalog["framework"] = "gdpr"

        result = validate_nist_catalog_payload(catalog)

        self.assertFalse(result.valid)
        self.assertTrue(any("framework" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()

