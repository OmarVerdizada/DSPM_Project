"""M4 (roadmap 1.6): an aggregate per-IP login-failure cap alongside the
per-(IP,username) cap - so one IP spraying a password across many usernames is
throttled even though no single (IP,username) counter trips."""

from __future__ import annotations

import types
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from backend.app import _login_ip_rate_key, app
from backend.store import clear_login_failures


class LoginIpThrottleTests(unittest.TestCase):
    def setUp(self) -> None:
        # No shared test DB isolation exists; scrub the exact keys we touch so the
        # test is deterministic regardless of prior state, and again on teardown.
        self._keys = (
            ["ip:testclient", "testclient:samuser"]
            + [f"testclient:spray{i}" for i in range(8)]
        )
        for key in self._keys:
            clear_login_failures(key)
        self.client = TestClient(app)

    def tearDown(self) -> None:
        for key in self._keys:
            clear_login_failures(key)

    def test_ip_rate_key_uses_a_distinct_namespace(self) -> None:
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="203.0.113.7"))
        self.assertEqual(_login_ip_rate_key(request), "ip:203.0.113.7")

    def test_ip_spray_across_usernames_trips_the_aggregate_limit(self) -> None:
        # Cap the per-IP aggregate at 3 and keep the per-user cap high, so the trip
        # can ONLY come from the aggregate counter.
        with mock.patch("backend.app.LOGIN_IP_MAX_ATTEMPTS", 3), \
             mock.patch("backend.app.LOGIN_MAX_ATTEMPTS", 50):
            for i in range(3):  # 3 DIFFERENT usernames, one failure each
                response = self.client.post(
                    "/api/auth/login", json={"username": f"spray{i}", "password": "wrongpass"}
                )
                self.assertEqual(response.status_code, 401, response.text)
            # A 4th, never-before-seen username from the same IP is now refused.
            blocked = self.client.post(
                "/api/auth/login", json={"username": "spray7", "password": "wrongpass"}
            )
            self.assertEqual(blocked.status_code, 429)

    def test_per_username_cap_still_trips(self) -> None:
        # Aggregate cap high so the trip can ONLY come from the per-user counter.
        with mock.patch("backend.app.LOGIN_MAX_ATTEMPTS", 3), \
             mock.patch("backend.app.LOGIN_IP_MAX_ATTEMPTS", 999):
            for _ in range(3):
                response = self.client.post(
                    "/api/auth/login", json={"username": "samuser", "password": "wrongpass"}
                )
                self.assertEqual(response.status_code, 401, response.text)
            blocked = self.client.post(
                "/api/auth/login", json={"username": "samuser", "password": "wrongpass"}
            )
            self.assertEqual(blocked.status_code, 429)


if __name__ == "__main__":
    unittest.main()
