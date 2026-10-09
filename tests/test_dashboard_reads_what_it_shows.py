"""M0/Q5: the executive dashboard reads the scan history it actually plots.

It asked for 200 runs, used the newest 14 for the trend and the newest one for
`latest`, and built a `summary` variable nothing referenced. On a busy install that
is 186 report rows decoded per call, on the endpoint the console requests most
often and on every page load.

The window is one constant now, so the read and the trend cannot drift apart again.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from backend import app as backend_app
from backend import store
from backend.security import Principal

TENANT = "tenant-dashboard"


def _report(index: int) -> dict:
    return {
        "scan_id": f"scan-{index:03d}",
        "timestamp": f"2026-09-{(index % 28) + 1:02d}T00:00:00+00:00",
        "source": "local",
        "summary": {"total_files": index, "critical": index % 3, "high": 1},
        "files": [],
    }


class TheTrendWindowTest(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "dashboard.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        store.create_tenant(TENANT, "Dashboard")
        self.principal = Principal("viewer-1", "viewer", TENANT)

    def test_it_asks_for_exactly_the_rows_it_plots(self) -> None:
        with mock.patch.object(backend_app, "read_scan_history", return_value=[]) as history:
            backend_app.executive_dashboard(self.principal)
        history.assert_called_once_with(TENANT, limit=backend_app.DASHBOARD_TREND_POINTS)

    def test_the_window_is_the_one_the_trend_uses(self) -> None:
        for index in range(20):
            store.save_scan_history(TENANT, _report(index))
        response = backend_app.executive_dashboard(self.principal)
        self.assertEqual(len(response["trend"]), backend_app.DASHBOARD_TREND_POINTS)

    def test_the_newest_scan_is_still_the_latest(self) -> None:
        # The read is ordered newest-first and reversed, so trimming it must not
        # turn the trend around or make an older run look like the current one.
        for index in range(18):
            store.save_scan_history(TENANT, _report(index))
        response = backend_app.executive_dashboard(self.principal)
        self.assertEqual(response["latest"]["scan_id"], "scan-017")
        self.assertEqual(response["trend"][-1]["scan_id"], "scan-017")
        self.assertEqual(response["trend"][0]["scan_id"], "scan-004")

    def test_a_tenant_with_no_scans_still_answers(self) -> None:
        response = backend_app.executive_dashboard(self.principal)
        self.assertEqual(response["trend"], [])
        self.assertEqual(response["latest"], {"summary": {}})
        self.assertIn("risk_posture_score", response)


if __name__ == "__main__":
    unittest.main()
