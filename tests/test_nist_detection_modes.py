import unittest

from classification.compliance.nist_catalog import load_nist_catalog
from classification.compliance.nist_classifier import classify_nist_content


class NISTDetectionModeTests(unittest.TestCase):
    def test_all_declared_detection_modes_are_present(self):
        modes = {rule["detection"]["mode"] for rule in load_nist_catalog()["rules"]}

        self.assertEqual(
            modes,
            {
                "DOCUMENT_MARKING_AND_CONTEXT",
                "ENTITY_CONTEXT_COMPOSITE",
                "VALUE_PATTERN_PLUS_CONTEXT",
                "SECRET_PATTERN_COMPOSITE",
                "TECHNICAL_ARTIFACT_COMPOSITE",
            },
        )

    def test_technical_artifact_context_matches_source_file(self):
        findings = classify_nist_content(
            "NIST SP 800-60 Source Code and Build Type 1 repository build pipeline",
            {"path": "repo/build/pipeline.py", "extension": ".py"},
        )

        self.assertTrue(any(item["category_id"] == "nist_source_code" for item in findings))


if __name__ == "__main__":
    unittest.main()

