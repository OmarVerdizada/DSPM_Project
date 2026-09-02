"""SMB connection fixes: clear auth-vs-unreachable errors, no IP-octet as a name/domain."""

from __future__ import annotations

import unittest

from collectors.smb_scanner import SMBConfig, SMBScanner


class SmbConnectionErrorTests(unittest.TestCase):
    def test_scan_reports_authentication_rejected_clearly(self) -> None:
        scanner = SMBScanner(SMBConfig(server="10.10.33.200", username="svc_scan", domain="WORKGROUP"))

        def fake_connect() -> bool:
            scanner._auth_rejected = True  # TCP ok, creds rejected
            return False

        scanner.connect = fake_connect  # type: ignore[assignment]
        with self.assertRaises(ConnectionError) as ctx:
            scanner.scan()
        message = str(ctx.exception).lower()
        self.assertIn("authentication was rejected", message)
        self.assertIn("domain", message)  # points the user at the real cause

    def test_scan_reports_unreachable_distinctly(self) -> None:
        scanner = SMBScanner(SMBConfig(server="10.10.33.200", username="svc_scan"))

        def fake_connect() -> bool:
            scanner._auth_rejected = False  # never established a session
            return False

        scanner.connect = fake_connect  # type: ignore[assignment]
        with self.assertRaises(ConnectionError) as ctx:
            scanner.scan()
        self.assertIn("could not reach", str(ctx.exception).lower())


class SmbNamingTests(unittest.TestCase):
    def test_remote_name_does_not_split_an_ip(self) -> None:
        scanner = SMBScanner(SMBConfig(server="10.10.33.200"))
        self.assertEqual(scanner._remote_name_for("10.10.33.200"), "10.10.33.200")  # not "10"
        self.assertEqual(scanner._remote_name_for("dc01.corp.local"), "dc01")

    def test_short_name_empty_for_ip(self) -> None:
        self.assertEqual(SMBScanner(SMBConfig(server="10.10.33.200"))._server_short_name(), "")
        self.assertEqual(SMBScanner(SMBConfig(server="DC01.corp.local"))._server_short_name(), "DC01")

    def test_credential_candidates_never_use_an_ip_octet_as_domain(self) -> None:
        scanner = SMBScanner(SMBConfig(server="10.10.33.200", username="svc_scan", domain="WORKGROUP"))
        domains = {dom for _, dom, _ in scanner._credential_candidates()}
        self.assertNotIn("10", domains)

    def test_windows_credential_no_ip_octet_prefix(self) -> None:
        user, _ = SMBScanner(SMBConfig(server="10.10.33.200", username="svc_scan", domain="WORKGROUP"))._windows_credential()
        self.assertNotIn("10\\", user)  # was "10\\svc_scan"


if __name__ == "__main__":
    unittest.main()
