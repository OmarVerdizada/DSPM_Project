"""H4 (roadmap 1.2): a catastrophic catalog regex is proven bad by running it
under a HARD PROCESS timeout and rejected at import - the real boundary that
replaces the deleted complexity heuristic (0.5). A thread timeout cannot do this
(a backtracking regex holds the GIL in one C call), which is why it runs in a
separate, killable process."""

from __future__ import annotations

import time
import unittest
from unittest import mock

from classification.compliance import preemptible
from classification.compliance.nist_validators import validate_nist_catalog_payload


class HardTimeoutTests(unittest.TestCase):
    def test_hard_timeout_kills_catastrophic_regex(self) -> None:
        start = time.perf_counter()
        with self.assertRaises(TimeoutError):
            preemptible.run_with_hard_timeout(preemptible._run_patterns, [(r"(a+)+$", 0)], timeout=1.0)
        # Control returned near the budget (not hung forever); allow slack for spawn.
        self.assertLess(time.perf_counter() - start, 15.0)

    def test_catastrophic_regexes_flags_only_the_bad_pattern(self) -> None:
        # Budgets sit above the ~1s spawn cost so the safe pattern completes.
        bad = preemptible.catastrophic_regexes(
            [(r"(a+)+$", 0), (r"\bpayroll\b", 0)], batch_timeout=2.5, per_pattern_timeout=2.5
        )
        self.assertIn(r"(a+)+$", bad)
        self.assertNotIn(r"\bpayroll\b", bad)

    def test_safe_patterns_pass(self) -> None:
        self.assertEqual(
            preemptible.catastrophic_regexes([(r"\d{3}-\d{4}", 0), (r"CVE-\d{4}-\d+", 0)]),
            [],
        )


class ValidatorWiringTests(unittest.TestCase):
    def test_validator_rejects_a_probed_catastrophic_pattern(self) -> None:
        # Mock the (subprocess-backed) probe so the wiring is tested fast: the
        # validator must surface the flagged pattern as an invalid regex.
        catalog = {
            "framework": "nist_sp800_60_enterprise",
            "rules": [
                {"rule_id": "R1", "detection": {"regex_patterns": [{"id": "evil", "pattern": r"(a+)+$"}]}}
            ],
        }
        with mock.patch("classification.compliance.preemptible.catastrophic_regexes", return_value=[r"(a+)+$"]):
            result = validate_nist_catalog_payload(catalog, probe_regexes=True)
        self.assertTrue(any(item.get("pattern_id") == "evil" for item in result.invalid_regex))
        self.assertFalse(result.valid)
        # And the /validate preview (probe off) does NOT spawn the probe.
        with mock.patch("classification.compliance.preemptible.catastrophic_regexes") as probe:
            validate_nist_catalog_payload(catalog)
            probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
