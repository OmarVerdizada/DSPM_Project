import copy
import unittest

from classification.compliance.nist_catalog import load_nist_catalog
from classification.compliance.nist_validators import validate_nist_catalog_payload


class NISTSchemaValidationTests(unittest.TestCase):
    def test_catalog_passes_validation(self):
        result = validate_nist_catalog_payload(load_nist_catalog())

        self.assertTrue(result.valid, result.errors)
        self.assertEqual(result.rule_count, 154)
        self.assertEqual(result.category_count, 22)

    def test_duplicate_rule_id_rejected(self):
        catalog = copy.deepcopy(load_nist_catalog())
        catalog["rules"][1]["rule_id"] = catalog["rules"][0]["rule_id"]

        result = validate_nist_catalog_payload(catalog)

        self.assertFalse(result.valid)
        self.assertIn(catalog["rules"][0]["rule_id"], result.duplicate_rule_ids)

    def test_duplicate_type_rejected(self):
        catalog = copy.deepcopy(load_nist_catalog())
        catalog["rules"][1]["type"] = catalog["rules"][0]["type"]

        result = validate_nist_catalog_payload(catalog)

        self.assertFalse(result.valid)
        self.assertIn(catalog["rules"][0]["type"], result.duplicate_types)

    def test_unknown_category_rejected(self):
        catalog = copy.deepcopy(load_nist_catalog())
        catalog["rules"][0]["category_id"] = "nist_missing_category"

        result = validate_nist_catalog_payload(catalog)

        self.assertFalse(result.valid)
        self.assertTrue(any("unknown category_id" in error for error in result.errors))

    def test_invalid_cia_impact_rejected(self):
        catalog = copy.deepcopy(load_nist_catalog())
        catalog["rules"][0]["classification"]["confidentiality_impact"] = "CRITICAL"

        result = validate_nist_catalog_payload(catalog)

        self.assertFalse(result.valid)

    def test_invalid_detection_mode_rejected(self):
        catalog = copy.deepcopy(load_nist_catalog())
        catalog["rules"][0]["detection"]["mode"] = "KEYWORD_ONLY"

        result = validate_nist_catalog_payload(catalog)

        self.assertFalse(result.valid)

    def test_invalid_regex_rejected(self):
        catalog = copy.deepcopy(load_nist_catalog())
        catalog["rules"][0]["detection"]["regex_patterns"] = [{"id": "bad", "pattern": "(", "flags": "", "validator": "", "confidence": "", "notes": ""}]

        result = validate_nist_catalog_payload(catalog)

        self.assertFalse(result.valid)
        self.assertTrue(result.invalid_regex)


if __name__ == "__main__":
    unittest.main()

