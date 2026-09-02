"""Track P-F: the performance gate runs in the normal test job, so every PR is
defended against a performance OR parity regression. The gate's failure
conditions are host-independent ratios (parity, delta-ratio, relative speedups),
so this is stable on any CI runner. `scripts/perf_gate.py` is the richer
nightly tool (absolute throughput + per-host baseline)."""

from __future__ import annotations

import unittest

from backend import store
from scripts.perf_gate import run_gate


class PerfGateTests(unittest.TestCase):
    def setUp(self) -> None:
        # run_gate points store.DB_PATH at a throwaway DB it deletes; snapshot and
        # restore so it can't leak a dead path into other tests.
        self._db_path = store.DB_PATH

    def tearDown(self) -> None:
        store.DB_PATH = self._db_path

    def test_perf_gate_holds(self) -> None:
        metrics = run_gate()
        self.assertEqual(metrics["failures"], [], f"perf gate regressed: {metrics['failures']}")
        # Spot-check the invariants directly so a fixture that stopped scanning
        # (0 files) can't pass vacuously.
        self.assertGreater(metrics["scan"]["files"], 0)
        self.assertGreater(metrics["scan"]["sensitive_files"], 0)
        self.assertTrue(metrics["scan"]["_incremental_parity"])
        self.assertTrue(metrics["detector"]["_prefilter_parity"])
        self.assertEqual(metrics["scan"]["delta_ratio"], 0.0)


if __name__ == "__main__":
    unittest.main()
