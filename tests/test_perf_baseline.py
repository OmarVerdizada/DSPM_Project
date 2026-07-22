"""Smoke test for the perf-baseline harness (Phase 0 item 12).

Validates the harness returns well-formed metrics; it does not assert timings
(those are environment-dependent). Uses the tiny committed test_data fixture.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from scripts.perf_baseline import run_baseline

_FIXTURE = Path(__file__).resolve().parent.parent / "test_data"


class PerfBaselineHarnessTests(unittest.TestCase):
    def test_run_baseline_returns_wellformed_metrics(self) -> None:
        if not _FIXTURE.exists():
            self.skipTest("test_data fixture missing")
        result = run_baseline(str(_FIXTURE), frameworks=[], use_cache=False)
        for key in ("cache", "files", "total_mb", "elapsed_s", "files_per_s", "mb_per_s", "peak_python_mem_mb"):
            self.assertIn(key, result)
        self.assertEqual(result["cache"], "cold")
        self.assertGreaterEqual(result["files"], 1)
        self.assertGreaterEqual(result["elapsed_s"], 0.0)


if __name__ == "__main__":
    unittest.main()
