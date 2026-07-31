"""SC-6/SC-7 regression: WinRM SSL/activation posture and SMB credential handling."""

from __future__ import annotations

import base64
import os
import re
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


class WinrmActivationPostureTests(unittest.TestCase):
    """M10/M11 (roadmap 0.3): activation must not weaken the onboarded endpoint -
    no Pass-the-Hash enabler, no any-profile firewall, scoped to the collector."""

    def _local_and_remote_scripts(self) -> tuple[str, str]:
        local = winrm._local_activation_script(False)
        outer = winrm._activation_script(
            {"host": "10.0.0.5", "username": "svc", "domain": "CORP"}, "192.168.1.50"
        )
        encoded = re.search(r"-EncodedCommand ([A-Za-z0-9+/=]+)", outer).group(1)
        remote = base64.b64decode(encoded).decode("utf-16le")
        return local, remote

    def test_activation_does_not_enable_pass_the_hash(self) -> None:
        for script in self._local_and_remote_scripts():
            self.assertNotIn("LocalAccountTokenFilterPolicy", script)

    def test_activation_firewall_is_scoped_not_any_profile(self) -> None:
        for script in self._local_and_remote_scripts():
            self.assertNotIn("profile=any", script)
            self.assertNotIn("-Profile Any", script)
            self.assertIn("-Profile Domain,Private", script)

    def test_remote_activation_scopes_source_to_the_collector(self) -> None:
        _, remote = self._local_and_remote_scripts()
        self.assertIn("-RemoteAddress 192.168.1.50", remote)
        self.assertIn('IPv4Filter="192.168.1.50"', remote)

    def test_deactivation_reverts_rule_listener_and_source_filter(self) -> None:
        script = winrm._deactivation_script()
        self.assertIn("Remove-NetFirewallRule", script)
        self.assertIn("winrm delete", script)
        self.assertIn('IPv4Filter=""', script)

    def test_https_mode_provisions_cert_and_removes_http_listener(self) -> None:
        # 0.3 Part B: DSPM_WINRM_ACTIVATION_HTTPS=1 → HTTPS(5986) listener with a
        # cert, HTTP listener removed, still no Pass-the-Hash enabler.
        with mock.patch.dict(os.environ, {"DSPM_WINRM_ACTIVATION_HTTPS": "1"}):
            for script in self._local_and_remote_scripts():
                self.assertIn("New-SelfSignedCertificate", script)
                self.assertIn("Transport HTTPS", script)
                self.assertIn("winrm delete", script)  # removes the HTTP listener
                self.assertIn("LocalPort 5986", script)
                self.assertNotIn("LocalAccountTokenFilterPolicy", script)

    def test_remote_deactivation_passes_password_via_env_not_payload(self) -> None:
        # 0.3 Part C: remote deactivation runs via WMI with the H1-safe env
        # password (never in the payload / on a command line).
        script = winrm._remote_deactivation_script({"host": "h", "username": "u", "domain": "D"})
        self.assertIn("$env:DSPM_ACTIVATION_PW", script)
        self.assertNotIn('"password"', script)
        self.assertIn("Invoke-WmiMethod", script)


class WinrmTransportTests(unittest.TestCase):
    """0.3 Part A (M11): Kerberos-preferred transport and cert-validation control."""

    def _scanner(self, use_ssl: bool = False) -> WinRMEndpointScanner:
        return WinRMEndpointScanner(WinRMEndpointConfig(host="h", username="u", password="p", domain="D", use_ssl=use_ssl))

    def test_kerberos_preferred_with_ntlm_fallback_when_enabled(self) -> None:
        scanner = self._scanner()
        with mock.patch.dict(os.environ, {"DSPM_WINRM_KERBEROS": "1"}):
            self.assertEqual(scanner._winrm_transports(), ["kerberos", "ntlm"])
        with mock.patch.dict(os.environ, {"DSPM_WINRM_KERBEROS": "0"}):
            self.assertEqual(scanner._winrm_transports(), ["ntlm"])

    def test_cert_validation_defaults_validate_opts_into_ignore(self) -> None:
        scanner = self._scanner(use_ssl=True)
        with mock.patch.dict(os.environ, {"DSPM_WINRM_SSL_SKIP_CA_CHECK": "0"}):
            self.assertEqual(scanner._winrm_cert_validation(), "validate")
        with mock.patch.dict(os.environ, {"DSPM_WINRM_SSL_SKIP_CA_CHECK": "1"}):
            self.assertEqual(scanner._winrm_cert_validation(), "ignore")


class SmbSigningTests(unittest.TestCase):
    def test_smb_session_requests_signing_when_supported(self) -> None:
        # M11 (0.3): the SMB session opts into signing whenever the server
        # supports it, rather than the pysmb default (sign only when required).
        from smb.SMBConnection import SMBConnection as RealSMB

        sign_supported = RealSMB.SIGN_WHEN_SUPPORTED
        captured: dict = {}

        class FakeConn:
            SIGN_WHEN_SUPPORTED = sign_supported

            def __init__(self, *args, **kwargs):
                captured.update(kwargs)

            def connect(self, *args, **kwargs):
                return True

        import socket as _socket

        # M12: connect() now resolves + pins the target, so give "fs" a resolvable,
        # allowed address instead of hitting real DNS.
        gai = [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        with mock.patch("smb.SMBConnection.SMBConnection", FakeConn), \
             mock.patch("collectors.net_guard.socket.getaddrinfo", return_value=gai):
            scanner = SMBScanner(SMBConfig(server="fs", username="u1", password="Pw123456", domain="CORP"))
            scanner.connect()

        self.assertEqual(captured.get("sign_options"), sign_supported)


if __name__ == "__main__":
    unittest.main()
