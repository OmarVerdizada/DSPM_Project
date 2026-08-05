"""Frontend source-contract tests for the stabilization pass.

This frontend has no browser test runner, so these assert the fixed behavior at
the source-contract level (the same approach as the existing Copilot UI
contract tests). They guard:

* the scan poller tolerating transient poll errors instead of abandoning a
  live scan (the stuck-progress class of bug);
* the dashboard risk-summary delta having a human-readable tooltip/label so the
  negative values are self-explanatory.
"""
from __future__ import annotations

import unittest
from pathlib import Path


class ScanAndDashboardUiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app_js = Path("frontend/app.js").read_text(encoding="utf-8")

    def test_pollscan_tolerates_transient_errors(self) -> None:
        # A single poll error must not abandon monitoring; the poller retries a
        # bounded number of times before surfacing a failure.
        self.assertIn("MAX_POLL_ERRORS", self.app_js)
        self.assertIn("consecutiveErrors", self.app_js)
        # The api() poll call is wrapped so a transient error is caught.
        poll_start = self.app_js.index("async function pollScan(")
        poll_body = self.app_js[poll_start:poll_start + 1400]
        self.assertIn("try {", poll_body)
        self.assertIn("catch (err)", poll_body)

    def test_scan_comparison_delta_has_explanatory_tooltip(self) -> None:
        self.assertIn("scan-comparison-hint", self.app_js)
        self.assertIn("Change vs previous scan", self.app_js)
        # Each delta value carries a title/aria-label explaining the sign.
        self.assertIn("deltaTitle", self.app_js)
        self.assertIn("fewer", self.app_js)
        self.assertIn("previous scan", self.app_js)

    def test_scan_progress_is_driven_by_backend_progress_and_message(self) -> None:
        # The async poll loop must render the backend's authoritative progress
        # and stage message (which now moves past the old collection ceiling),
        # not a fixed client-side value.
        poll_start = self.app_js.index("async function pollScan(")
        poll_body = self.app_js[poll_start:poll_start + 1600]
        self.assertIn("job.progress", poll_body)
        self.assertIn("job.message", poll_body)
        # Completion pins 100 and failure/cancel surfaces an error (no stale bar).
        self.assertIn('setScanProgress(true, 100', poll_body)
        self.assertIn('job.status === "failed"', poll_body)


if __name__ == "__main__":
    unittest.main()
