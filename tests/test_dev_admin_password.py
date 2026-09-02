"""SC-5 regression: no hardcoded 'admin123' default; dev password is env-driven or random."""

from __future__ import annotations

import os
import unittest

from backend.security import (
    _dev_admin_password,
    _generate_dev_admin_password,
    validate_password_strength,
)


class DevAdminPasswordTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = os.environ.get("DSPM_DEV_ADMIN_PASSWORD")

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop("DSPM_DEV_ADMIN_PASSWORD", None)
        else:
            os.environ["DSPM_DEV_ADMIN_PASSWORD"] = self._saved

    def test_generated_password_satisfies_policy(self) -> None:
        for _ in range(50):
            pw = _generate_dev_admin_password()
            validate_password_strength(pw)  # raises on weak passwords
            self.assertGreaterEqual(len(pw), 12)

    def test_env_password_is_honored(self) -> None:
        os.environ["DSPM_DEV_ADMIN_PASSWORD"] = "DevOperator123"
        self.assertEqual(_dev_admin_password(), "DevOperator123")

    def test_no_static_admin123_default(self) -> None:
        os.environ.pop("DSPM_DEV_ADMIN_PASSWORD", None)
        # With nothing configured a fresh random password is generated every
        # call; it must never be the old hardcoded default.
        self.assertNotEqual(_dev_admin_password(), "admin123")
        self.assertNotEqual(_dev_admin_password(), _dev_admin_password())


if __name__ == "__main__":
    unittest.main()
