"""M12 (roadmap 1.4): DNS-rebind-safe target connection.

resolve_and_pin resolves a target ONCE and refuses if any resolved address is
disallowed, and the collectors connect to that pinned address - so a TTL-0 name
that flips public->loopback between validation and connect is refused."""

from __future__ import annotations

import ipaddress
import socket
import unittest
from unittest import mock

from collectors.net_guard import (
    TargetNotAllowed,
    ip_disallowed_reason,
    resolve_and_pin,
)


def _gai(*ips: str):
    """Build a socket.getaddrinfo-shaped result for the given IPs."""
    out = []
    for ip in ips:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        out.append((family, socket.SOCK_STREAM, 6, "", (ip, 0)))
    return out


class ResolveAndPinTests(unittest.TestCase):
    def test_public_ip_literal_pins_itself(self) -> None:
        self.assertEqual(resolve_and_pin("93.184.216.34"), "93.184.216.34")

    def test_loopback_literal_refused(self) -> None:
        with self.assertRaises(TargetNotAllowed):
            resolve_and_pin("127.0.0.1")

    def test_metadata_ip_refused(self) -> None:
        with self.assertRaises(TargetNotAllowed):
            resolve_and_pin("169.254.169.254")

    def test_hostname_rebind_to_loopback_is_refused(self) -> None:
        # THE acceptance case: at connect time the name answers with loopback.
        with mock.patch("collectors.net_guard.socket.getaddrinfo", return_value=_gai("127.0.0.1")):
            with self.assertRaises(TargetNotAllowed):
                resolve_and_pin("evil.example.com", allow_private=True)

    def test_hostname_public_pins_the_resolved_ip(self) -> None:
        with mock.patch("collectors.net_guard.socket.getaddrinfo", return_value=_gai("93.184.216.34")):
            self.assertEqual(resolve_and_pin("good.example.com"), "93.184.216.34")

    def test_any_disallowed_address_refuses_the_whole_name(self) -> None:
        # A rebind name often answers with several IPs; one bad one refuses all.
        with mock.patch(
            "collectors.net_guard.socket.getaddrinfo",
            return_value=_gai("93.184.216.34", "127.0.0.1"),
        ):
            with self.assertRaises(TargetNotAllowed):
                resolve_and_pin("mixed.example.com", allow_private=True)

    def test_unresolvable_refused(self) -> None:
        with mock.patch("collectors.net_guard.socket.getaddrinfo", side_effect=socket.gaierror):
            with self.assertRaises(TargetNotAllowed):
                resolve_and_pin("nope.invalid")

    def test_ipv4_preferred_when_pinning_dual_stack(self) -> None:
        with mock.patch(
            "collectors.net_guard.socket.getaddrinfo",
            return_value=_gai("2606:2800:220:1:248:1893:25c8:1946", "93.184.216.34"),
        ):
            self.assertEqual(resolve_and_pin("dual.example.com"), "93.184.216.34")

    def test_private_gated_by_allow_private(self) -> None:
        ten = ipaddress.ip_address("10.0.0.5")
        self.assertIsNone(ip_disallowed_reason(ten, allow_private=True))
        self.assertIsNotNone(ip_disallowed_reason(ten, allow_private=False))
        # loopback is refused even when private targets are allowed
        self.assertIsNotNone(ip_disallowed_reason(ipaddress.ip_address("127.0.0.1"), allow_private=True))


class SmbRebindTests(unittest.TestCase):
    def test_scan_refuses_a_rebound_target(self) -> None:
        from collectors.smb_scanner import SMBConfig, SMBScanner

        scanner = SMBScanner(SMBConfig(server="evil.example.com", username="u", password="p", domain="CORP"))
        with mock.patch("collectors.net_guard.socket.getaddrinfo", return_value=_gai("127.0.0.1")):
            with self.assertRaises(ConnectionError) as ctx:
                scanner.scan()
        self.assertIn("refused", str(ctx.exception).lower())


class WinRMRebindTests(unittest.TestCase):
    def _scanner(self, use_ssl: bool = False):
        from collectors.winrm_endpoint_scanner import WinRMEndpointConfig, WinRMEndpointScanner

        return WinRMEndpointScanner(
            WinRMEndpointConfig(host="host.example.com", username="u", password="p", use_ssl=use_ssl)
        )

    def test_http_endpoint_dials_the_pinned_ip(self) -> None:
        scanner = self._scanner(use_ssl=False)
        with mock.patch("collectors.net_guard.socket.getaddrinfo", return_value=_gai("93.184.216.34")):
            url = scanner._endpoint_url("host.example.com")
        self.assertIn("93.184.216.34", url)          # dials the validated IP...
        self.assertNotIn("host.example.com", url)     # ...not the re-resolvable name

    def test_endpoint_refuses_loopback_rebind(self) -> None:
        scanner = self._scanner(use_ssl=False)
        with mock.patch("collectors.net_guard.socket.getaddrinfo", return_value=_gai("127.0.0.1")):
            with self.assertRaises(TargetNotAllowed):
                scanner._endpoint_url("host.example.com")

    def test_https_keeps_hostname_for_cert_but_still_validates(self) -> None:
        scanner = self._scanner(use_ssl=True)
        with mock.patch("collectors.net_guard.socket.getaddrinfo", return_value=_gai("93.184.216.34")):
            url = scanner._endpoint_url("host.example.com")
        self.assertIn("host.example.com", url)  # hostname kept so TLS cert validation works
        with mock.patch("collectors.net_guard.socket.getaddrinfo", return_value=_gai("127.0.0.1")):
            with self.assertRaises(TargetNotAllowed):
                scanner._endpoint_url("host.example.com")  # still refuses a rebind


if __name__ == "__main__":
    unittest.main()
