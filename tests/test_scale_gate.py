"""B8: the Phase B envelopes are measured on every run, not remembered.

`scripts/scale_gate.py` is the nightly tool; this runs its quick corpus in the normal test
job, so a pull request that breaks one of Phase B's properties fails here rather than in
somebody's estate three months later:

- the estate write costs a fixed number of statements (B0);
- a partitioned scan reports what one scan reports (B2.2);
- a partition redelivered after a crash runs nothing twice (B3);
- an endpoint scan's memory follows its batch budget (B4);
- one value found by three detectors is one finding with both framework tags (B7).

The memory ratio (B1/B2) is reported here and **gated nightly**, because a hundred-odd
files cannot tell a partitioned scan from a single one - the engine's fixed cost is most
of the peak at that size. A bound that cannot discriminate is worse than no bound.
"""

from __future__ import annotations

import os
import unittest

from backend import store
from scripts.scale_gate import _check, run_gate


class TheScaleGateHoldsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._db_path = store.DB_PATH
        cls._environment = dict(os.environ)
        cls.metrics = run_gate(quick=True)
        cls._environment_after = dict(os.environ)

    @classmethod
    def tearDownClass(cls) -> None:
        store.DB_PATH = cls._db_path

    def _named(self, fragment: str) -> dict:
        return next(check for check in self.metrics["checks"] if fragment in check["name"])

    def test_it_leaves_the_environment_as_it_found_it(self) -> None:
        # It used to leave DSPM_ARTIFACT_DIR pointing at its deleted temp directory, and
        # every later test wrote its artifacts there - re-creating it under tmp/.
        changed = sorted(key for key in set(self._environment) | set(self._environment_after)
                         if self._environment.get(key) != self._environment_after.get(key))
        self.assertEqual(changed, [], "the gate left its settings behind for whatever runs next")

    def test_every_envelope_holds(self) -> None:
        self.assertEqual(self.metrics["failures"], [], f"a Phase B envelope regressed: {self.metrics['failures']}")

    def test_the_corpus_was_scanned_so_nothing_passed_vacuously(self) -> None:
        corpus = self._named("corpus was actually scanned")
        self.assertTrue(corpus["ok"])
        self.assertEqual(corpus["measured"], self.metrics["files"])

    def test_the_write_path_is_still_flat(self) -> None:
        self.assertLess(self._named("statements per extra file")["measured"], 0.02)

    def test_a_partitioned_scan_still_agrees_with_a_single_one(self) -> None:
        parity = self._named("reports what one scan reports")
        self.assertEqual(parity["measured"], {"files": True, "findings": True, "summary": True})

    def test_a_redelivered_partition_still_runs_nothing_twice(self) -> None:
        kill = self._named("runs nothing twice")
        self.assertEqual(kill["measured"]["first"], "written")
        self.assertEqual(kill["measured"]["redelivery"], "finished")
        self.assertTrue(kill["measured"]["estate_unchanged"])

    def test_an_endpoint_scan_still_holds_its_batch_and_not_the_profile(self) -> None:
        paging = self._named("follows the batch budget")
        self.assertTrue(paging["ok"])
        self.assertLess(paging["measured"]["ratio"], 0.5)

    def test_one_value_is_still_one_finding(self) -> None:
        model = self._named("one card is one finding")
        self.assertEqual(model["measured"]["pan_findings"], 1)
        self.assertEqual(model["measured"]["email_findings"], 1)
        self.assertEqual(model["measured"]["frameworks"], ["GDPR", "PCI DSS"])

    def test_the_memory_ratio_is_reported_here_and_gated_nightly(self) -> None:
        memory = self._named("holds less than a single scan")
        self.assertIsInstance(memory["measured"], float)
        self.assertIn("reported only", memory["bound"],
                      "a bound that cannot discriminate at this size must not read as evidence")


class TheGateReportsFailureTest(unittest.TestCase):
    """The gate has to be able to fail, or it is decoration."""

    def test_a_check_that_misses_its_bound_is_a_failure(self) -> None:
        passing = _check("something", "B0", True, 0.001, "< 0.02")
        failing = _check("something", "B0", False, 9.0, "< 0.02")
        self.assertTrue(passing["ok"])
        self.assertFalse(failing["ok"])
        self.assertEqual(failing["measured"], 9.0)


if __name__ == "__main__":
    unittest.main()
