"""SC-6/SC-7 regression: WinRM SSL/activation posture and SMB credential handling."""

from __future__ import annotations

import base64
import os
import unittest
from unittest import mock

from collectors import winrm_endpoint_scanner as winrm
from collectors.winrm_endpoint_scanner import WinRMEndpointConfig, WinRMEndpointScanner
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


class WinrmActivationCredentialTests(unittest.TestCase):
    """H1 / completes FINDING 5: the remote WinRM-activation admin password must
    travel via the child environment block, never on the powershell.exe command
    line (the -EncodedCommand blob is visible to 4688/Sysmon)."""

    SECRET = "Sup3rSecretActivationPW"

    def _secret_encodings(self) -> list[str]:
        return [
            self.SECRET,
            base64.b64encode(self.SECRET.encode("utf-8")).decode("ascii"),
            base64.b64encode(self.SECRET.encode("utf-16le")).decode("ascii"),
        ]

    def test_activation_password_off_argv_and_in_env(self) -> None:
        scanner = WinRMEndpointScanner(
            WinRMEndpointConfig(host="10.0.0.5", username="svc_scan", password=self.SECRET, domain="CORP")
        )
        captured: dict = {}

        def fake_run(args, **kwargs):
            captured["args"] = args
            captured["env"] = kwargs.get("env")
            return mock.Mock(returncode=0, stdout='{"activated": true}', stderr="")

        with mock.patch("collectors.winrm_endpoint_scanner.platform.system", return_value="Windows"), \
             mock.patch("collectors.winrm_endpoint_scanner._winrm_activation_allowed", return_value=True), \
             mock.patch.object(scanner, "test_connection", return_value={"connected": False}), \
             mock.patch("collectors.winrm_endpoint_scanner.subprocess.run", side_effect=fake_run):
            scanner.activate_winrm()

        argv = " ".join(str(a) for a in captured["args"])
        decoded_script = base64.b64decode(captured["args"][-1]).decode("utf-16le")
        for enc in self._secret_encodings():
            self.assertNotIn(enc, argv, "credential must not appear on the command line")
            self.assertNotIn(enc, decoded_script, "credential must not be embedded in the script")
        self.assertEqual(captured["env"].get("DSPM_ACTIVATION_PW"), self.SECRET)

    def test_activation_script_strips_password_even_if_passed(self) -> None:
        # Defensive: a caller that regresses and puts the password back in the
        # payload must still not leak it - _activation_script drops it and the
        # script reads $env:DSPM_ACTIVATION_PW instead.
        script = winrm._activation_script(
            {"host": "h", "username": "u", "domain": "D", "password": self.SECRET}
        )
        self.assertNotIn(self.SECRET, script)
        self.assertIn("$env:DSPM_ACTIVATION_PW", script)


if __name__ == "__main__":
    unittest.main()
