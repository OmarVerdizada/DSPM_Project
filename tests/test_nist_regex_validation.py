"""Phase 0.5 / H4: the regex complexity heuristic was removed as security theater.
These tests lock in the acceptance criterion - catalog/keyword regex validation
still rejects oversized and uncompilable patterns via the retained length +
compile-validity checks, and the backtracking-cost scorer is gone for good.
"""

from __future__ import annotations

import unittest

from classification.compliance import keyword_library as kl
from classification.compliance import nist_validators as nv


class RegexValidationRetainedTests(unittest.TestCase):
    def test_valid_pattern_accepted(self) -> None:
        self.assertEqual(nv._regex_issue({"pattern": r"\bpan\b"}), "")

    def test_uncompilable_pattern_rejected(self) -> None:
        self.assertNotEqual(nv._regex_issue({"pattern": "(unbalanced"}), "")

    def test_oversized_pattern_rejected(self) -> None:
        self.assertEqual(
            nv._regex_issue({"pattern": "a" * (nv.MAX_REGEX_LENGTH + 1)}),
            "regex length exceeds limit",
        )

    def test_complexity_scorer_is_gone(self) -> None:
        # The heuristic must not come back - it is not a boundary. Any future
        # customer-facing regex feature belongs on a non-backtracking engine.
        self.assertFalse(hasattr(nv, "_regex_complexity_score"))
        self.assertFalse(hasattr(kl, "_regex_complexity_score"))

    def test_keyword_normalize_keeps_valid_drops_invalid_and_oversized(self) -> None:
        result = kl._normalize_regex_patterns([r"\d{3}", "(bad", "x" * (kl.MAX_REGEX_LENGTH + 1)])
        self.assertEqual(result, [r"\d{3}"])


if __name__ == "__main__":
    unittest.main()
