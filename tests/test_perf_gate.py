"""Track P-F: the performance gate runs in the normal test job, so every PR is
defended against a parity or reuse regression.

What this job gates is what a loaded machine cannot change: an unchanged re-scan
finds exactly what the full scan found, the detector prefilter finds exactly what
the whole catalogue finds, and an unchanged re-scan re-reads almost nothing. Those
are counted, not timed.

The gate's two speedups are wall-clock ratios of two runs of the same work, and a
machine running the rest of a test suite does not slow both halves equally - this
test failed at 1.31x against a 1.5x bound under load while the same corpus passed at
8.95s vs 8.97s when run alone (roadmap M0/Q3, fixed in the M0 polish). They are
measured here and reported, and they are GATED in the nightly job
(`scripts/perf_gate.py`, `.github/workflows/perf-nightly.yml`), which owns its
runner. A per-PR red that a re-run clears teaches people to re-run reds.
"""

from __future__ import annotations

import unittest

from backend import store
from scripts.perf_gate import run_gate


class PerfGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # run_gate points store.DB_PATH at a throwaway DB it deletes; snapshot and
        # restore so it can't leak a dead path into other tests. One run serves both
        # tests - it builds a corpus and scans it three times.
        db_path = store.DB_PATH
        try:
            cls.metrics = run_gate(enforce_timing=False)
        finally:
            store.DB_PATH = db_path

    def test_perf_gate_holds(self) -> None:
        metrics = self.metrics
        self.assertEqual(metrics["failures"], [], f"perf gate regressed: {metrics['failures']}")
        self.assertEqual(metrics["correctness_failures"], [])
        # Spot-check the invariants directly so a fixture that stopped scanning
        # (0 files) can't pass vacuously.
        self.assertGreater(metrics["scan"]["files"], 0)
        self.assertGreater(metrics["scan"]["sensitive_files"], 0)
        self.assertTrue(metrics["scan"]["_incremental_parity"])
        self.assertTrue(metrics["detector"]["_prefilter_parity"])
        self.assertEqual(metrics["scan"]["delta_ratio"], 0.0)

    def test_the_timed_ratios_are_still_measured_here(self) -> None:
        """Not gated in this job, but a measurement that stopped happening would make
        the nightly gate pass vacuously, so this job still checks it produced one."""
        self.assertGreater(self.metrics["scan"]["incremental_speedup"], 0.0)
        self.assertGreater(self.metrics["detector"]["prefilter_speedup"], 0.0)
        self.assertIsInstance(self.metrics["timing_failures"], list)
        if self.metrics["timing_failures"]:  # visible in the run log, not a failure
            print("perf gate timing (gated nightly, not here):", self.metrics["timing_failures"])


if __name__ == "__main__":
    unittest.main()
