import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app import FRONTEND_DIR, ConnectionRequest, _persist_scan, _prepare_local_scan_data, app
from backend.security import Principal


class RootRouteTests(unittest.TestCase):
    """The product starts at login: no marketing landing page ships on-prem.

    "/" and "/login" both serve the operator login page directly; the console
    lives at "/dashboard". (The former frontend-landing React build was removed
    in redesign P1.)
    """

    def setUp(self):
        self.client = TestClient(app)

    def test_root_and_login_serve_the_login_page(self):
        for route in ("/", "/login"):
            response = self.client.get(route)

            self.assertEqual(response.status_code, 200, route)
            self.assertIn("SENTRO", response.text, route)
            self.assertIn("Sign in to your account", response.text, route)
            # L2 regression lock: no stale default-credential hint may ship.
            self.assertNotIn("admin123", response.text, route)

    def test_dashboard_serves_the_console(self):
        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertIn("inventory-workspace", response.text)
        # Copilot was removed: no launcher, popup, or bundle may return.
        self.assertNotIn("copilot", response.text.lower())

    def test_toasts_clear_the_bottom_right_action_stack(self):
        styles = (FRONTEND_DIR / "styles.css").read_text(encoding="utf-8")

        toast_rule = styles[styles.index(".toast-host {"):styles.index(".toast {", styles.index(".toast-host {"))]
        self.assertIn("bottom: 96px", toast_rule)
        self.assertIn("z-index: 10001", toast_rule)

    @patch("backend.app.generate_enterprise_test_data")
    @patch("backend.app.Path.exists", return_value=False)
    def test_missing_default_synthetic_dataset_is_generated_automatically(self, _exists, generate):
        _prepare_local_scan_data(ConnectionRequest())

        generate.assert_called_once()

    @patch("backend.app.Path.exists", return_value=False)
    def test_missing_custom_local_path_is_reported(self, _exists):
        with self.assertRaisesRegex(FileNotFoundError, "Local scan path does not exist"):
            _prepare_local_scan_data(ConnectionRequest(local_path="missing-custom-scan-folder"))

    @patch("backend.app.audit")
    @patch("backend.app.generate_report", side_effect=OSError("disk full"))
    @patch("backend.app.evaluate_alerts", side_effect=RuntimeError("alert sink unavailable"))
    @patch("backend.app.save_scan_history", return_value="scan-1")
    def test_secondary_post_scan_failures_do_not_fail_the_scan(self, _save, _alerts, _report, _audit):
        data = {"files": [], "summary": {"total_files": 0}}
        payload = SimpleNamespace(save_report=True)
        principal = Principal("admin", "admin", "default")

        _persist_scan(data, payload, principal)

        self.assertEqual(data["scan_id"], "scan-1")
        self.assertEqual(data["alerts"], [])
        stages = {warning["stage"] for warning in data["scan_warnings"]}
        self.assertIn("alerts", stages)
        self.assertIn("report_export", stages)


if __name__ == "__main__":
    unittest.main()
