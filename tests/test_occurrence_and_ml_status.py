"""SCAN-003 and GAP-2 regressions: accurate occurrence counts + observable ML status."""

from __future__ import annotations

import unittest

from classification import ml_classifier
from classification.regex_classifier import classify_content


class OccurrenceCountTests(unittest.TestCase):
    def test_count_is_not_capped_at_the_sample_limit(self) -> None:
        content = "\n".join(f"password: Secret{i:03d}xyz" for i in range(25))
        finding = next(f for f in classify_content(content) if f["type"] == "password")
        self.assertEqual(finding["count"], 25)
        self.assertEqual(finding["occurrence_count"], 25)
        self.assertEqual(finding["sample_count"], 10)
        self.assertTrue(finding["occurrence_truncated"])
        self.assertFalse(finding["count_capped"])

    def test_small_counts_are_exact_and_not_flagged_truncated(self) -> None:
        content = "password: OnlyOne11\npassword: OnlyTwo22"
        finding = next(f for f in classify_content(content) if f["type"] == "password")
        self.assertEqual(finding["count"], 2)
        self.assertEqual(finding["sample_count"], 2)
        self.assertFalse(finding["occurrence_truncated"])


class MlStatusTests(unittest.TestCase):
    def test_status_is_reported_and_cached(self) -> None:
        status = ml_classifier.ml_classifier_status()
        self.assertIn("available", status)
        self.assertIn("reason", status)
        self.assertIsInstance(status["available"], bool)
        # cached: same object on repeat calls (probe runs once)
        self.assertIs(ml_classifier.ml_classifier_status(), status)

    def test_unavailable_status_carries_a_reason(self) -> None:
        status = ml_classifier.ml_classifier_status()
        if not status["available"]:
            self.assertIn(status["reason"], {"spacy_not_installed", "model_not_downloaded"})


if __name__ == "__main__":
    unittest.main()
