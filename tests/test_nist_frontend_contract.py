import unittest
import json
from pathlib import Path

from classification.compliance.keyword_library import export_keyword_groups, validate_keyword_import
from classification.compliance.nist_catalog import export_nist_catalog


class NISTFrontendContractTests(unittest.TestCase):
    def test_frontend_lists_nist_framework_and_reads_top_level_rules(self):
        app_js = Path("frontend/app.js").read_text(encoding="utf-8")
        index_html = Path("frontend/index.html").read_text(encoding="utf-8")
        styles_css = Path("frontend/styles.css").read_text(encoding="utf-8")

        self.assertIn("nist_sp800_60_enterprise", app_js)
        self.assertIn("Array.isArray(parsed.rules)", app_js)
        self.assertIn('name: "NIST"', app_js)
        self.assertIn("findingDisplayName(finding", app_js)
        self.assertIn("renderGenericFindingDetails", app_js)
        self.assertNotIn("function renderNistFindingDetails", app_js)
        self.assertNotIn('return renderNistFindingDetails(file, finding)', app_js)
        self.assertNotIn("nist-finding-detail", styles_css)
        self.assertIn("NIST_RULE_NAME_TAXONOMY", app_js)
        self.assertIn("keywordFindingTypeLabel", app_js)
        self.assertIn("selectedFrameworkScope", app_js)
        self.assertIn("findingVisualFramework", app_js)
        self.assertIn("complianceFindingDetailsForFile", app_js)
        self.assertIn("return [];", app_js)
        self.assertNotIn("NIST Compliance Mapping", app_js)
        self.assertNotIn('nist_compliance_mapping: "Compliance mapping"', app_js)
        self.assertIn("frameworks.map(frameworkLabel)", app_js)
        self.assertIn("findingFrameworkBadges(finding)", app_js)
        self.assertNotIn("includeSeverity", app_js)
        self.assertNotIn("complianceVisualFramework", app_js)
        self.assertNotIn("complianceChip", app_js)
        self.assertIn("smoothProgress", app_js)
        self.assertIn("visibleFindingChips", app_js)
        self.assertIn("inventoryFrameworkSelect", app_js)
        self.assertIn("getFileFrameworks", app_js)
        self.assertIn("inventory-framework-select", index_html)
        self.assertIn("Legal Matter Records", app_js)
        self.assertIn("Law Enforcement Records", app_js)
        self.assertIn("framework-nist", styles_css)
        self.assertIn("data-keyword-option-label", app_js)
        removed_word = "".join(["a", "s", "s", "u", "r", "a", "n", "c", "e"])
        self.assertNotIn("inventory-" + removed_word + "-filter", index_html)
        self.assertNotIn("normalize" + "Assur" + "anceStatus", app_js)
        self.assertNotIn("render" + "Assur" + "anceDashboard", app_js)
        self.assertNotIn("protection_" + removed_word, app_js)

    def test_nist_exports_use_display_name(self):
        filename, _media_type, content = export_keyword_groups("default", "nist_sp800_60_enterprise", fmt="json")
        payload = json.loads(content)

        self.assertEqual(filename, "NIST_keywords_all.json")
        self.assertEqual(payload["framework"], "NIST")
        self.assertEqual(payload["catalog_status"]["framework"], "NIST")
        self.assertTrue(all(group["framework"] == "NIST" for group in payload["groups"]))
        self.assertEqual(validate_keyword_import("default", {"framework": "NIST", "keywords": []})["framework"], "nist_sp800_60_enterprise")

        catalog_filename, _catalog_media_type, catalog_content = export_nist_catalog()
        self.assertTrue(catalog_filename.startswith("NIST_"))
        self.assertNotIn("800_60", catalog_filename)
        self.assertEqual(json.loads(catalog_content)["framework"], "NIST")


if __name__ == "__main__":
    unittest.main()
