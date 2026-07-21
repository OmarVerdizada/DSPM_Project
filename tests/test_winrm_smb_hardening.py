"""SC-6/SC-7 regression: WinRM SSL/activation posture and SMB credential handling."""

from __future__ import annotations

import base64
import os
import unittest
from unittest import mock

from collectors import winrm_endpoint_scanner as winrm
from collectors.smb_scanner import SMBConfig, SMBScanner


class WinrmPostureTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = {k: os.environ.get(k) for k in ("DSPM_ENV", "DSPM_REQUIRE_WINRM_SSL", "DSPM_ALLOW_WINRM_ACTIVATION")}
        for k in self._saved:
            os.environ.pop(k, None)

    def tearDown(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_ssl_required_in_production_by_default(self) -> None:
        os.environ["DSPM_ENV"] = "production"
        self.assertTrue(winrm._winrm_ssl_required())

    def test_ssl_not_required_in_local_by_default(self) -> None:
        os.environ["DSPM_ENV"] = "local"
        self.assertFalse(winrm._winrm_ssl_required())

    def test_ssl_override_wins_both_ways(self) -> None:
        os.environ["DSPM_ENV"] = "production"
        os.environ["DSPM_REQUIRE_WINRM_SSL"] = "0"
        self.assertFalse(winrm._winrm_ssl_required())
        os.environ["DSPM_ENV"] = "local"
        os.environ["DSPM_REQUIRE_WINRM_SSL"] = "1"
        self.assertTrue(winrm._winrm_ssl_required())

    def test_activation_blocked_in_production_without_optin(self) -> None:
        os.environ["DSPM_ENV"] = "production"
        self.assertFalse(winrm._winrm_activation_allowed())

    def test_activation_allowed_in_production_with_optin(self) -> None:
        os.environ["DSPM_ENV"] = "production"
        os.environ["DSPM_ALLOW_WINRM_ACTIVATION"] = "1"
        self.assertTrue(winrm._winrm_activation_allowed())

    def test_activation_allowed_in_local(self) -> None:
        os.environ["DSPM_ENV"] = "local"
        self.assertTrue(winrm._winrm_activation_allowed())


class SmbAclCredentialTests(unittest.TestCase):
    def test_password_off_the_command_line_and_passed_via_env(self) -> None:
        scanner = SMBScanner(SMBConfig(server="fs", username="admin", password="Sup3rSecretPW", domain="CORP"))
        captured: dict = {}

        def fake_run(args, **kwargs):
            captured["args"] = args
            captured["env"] = kwargs.get("env")
            return mock.Mock(returncode=0, stdout='{"owner":"x","principals":[],"permissions":[]}', stderr="")

        with mock.patch("collectors.smb_scanner.subprocess.run", side_effect=fake_run):
            scanner._acl_for_path("share", "file.txt")

        encoded_script = captured["args"][-1]
        decoded = base64.b64decode(encoded_script).decode("utf-16le")
        self.assertNotIn("Sup3rSecretPW", decoded, "password must not be embedded in the PowerShell script/argv")
        self.assertNotIn("Sup3rSecretPW", " ".join(str(a) for a in captured["args"]))
        self.assertEqual(captured["env"].get("DSPM_SMB_ACL_PW"), "Sup3rSecretPW")


if __name__ == "__main__":
    unittest.main()
