"""C0.1: the console can ask for WinRM over TLS, and say how the certificate is trusted.

The collector has been able to speak TLS since it was written - `WinRMEndpointConfig`
has carried `use_ssl` and `port` all along - but `EndpointScanRequest` had neither, and
`_to_endpoint_config` never set them. Every scan and every preflight the console started
was therefore cleartext HTTP on 5985, and an install that requires TLS
(`DSPM_REQUIRE_WINRM_SSL=1`, or any production install) could only fail, mid-scan, with a
RuntimeError from inside the collector.

These tests hold the API-to-collector contract the pilot depends on: what the operator
chooses is what reaches the wire, a combination that cannot work is refused before
anything connects and says which choice to change, and the transport a scan used is
recorded rather than assumed.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pydantic import ValidationError

from backend import app as backend_app
from backend.app import EndpointScanRequest, _to_endpoint_config
from collectors import winrm_endpoint_scanner as winrm
from collectors.winrm_endpoint_scanner import (
    WinRMEndpointConfig,
    WinRMEndpointScanner,
    WinRMTransportRefused,
    normalize_certificate_thumbprint,
)


def _url(config: WinRMEndpointConfig, host: str) -> str:
    """The URL the scanner would dial, with DNS stubbed the way test_net_guard does:
    _endpoint_url resolves and pins the target before composing anything."""
    import socket

    resolved = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    with mock.patch("collectors.net_guard.socket.getaddrinfo", return_value=resolved):
        return WinRMEndpointScanner(config)._endpoint_url(host)


SHA1 = "AA" * 20
SHA256 = "BB" * 32
TENANT = "tenant-transport"


def _request(**kwargs) -> EndpointScanRequest:
    return EndpointScanRequest(host="10.10.10.25", username="svc_scan", password="x", **kwargs)


class WhatTheOperatorChoseReachesTheWireTest(unittest.TestCase):
    """The gate: the API reaches WinRMEndpointConfig(use_ssl=True, port=5986)."""

    def test_tls_without_a_port_is_5986(self) -> None:
        config = _to_endpoint_config(_request(use_ssl=True), TENANT)
        self.assertIsInstance(config, WinRMEndpointConfig)
        self.assertTrue(config.use_ssl)
        self.assertEqual(config.port, 5986)
        url = _url(config, "endpoint.corp.local")
        self.assertTrue(url.startswith("https://"), url)
        self.assertTrue(url.endswith(":5986/wsman"), url)
        # Over TLS the NAME stays in the URL, or certificate validation has nothing
        # to match; net_guard still refused a disallowed resolved address above.
        self.assertIn("endpoint.corp.local", url)

    def test_plain_http_stays_5985(self) -> None:
        config = _to_endpoint_config(_request(), TENANT)
        self.assertFalse(config.use_ssl)
        self.assertIsNone(config.port)
        url = _url(config, "endpoint.corp.local")
        self.assertTrue(url.startswith("http://"), url)
        self.assertIn(":5985/wsman", url)

    def test_an_explicit_port_wins_over_the_default(self) -> None:
        config = _to_endpoint_config(_request(use_ssl=True, port=15986), TENANT)
        self.assertEqual(config.port, 15986)

    def test_a_pinned_thumbprint_reaches_the_collector_normalised(self) -> None:
        pasted = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd"
        config = _to_endpoint_config(
            _request(use_ssl=True, cert_trust="thumbprint", cert_thumbprint=pasted), TENANT)
        self.assertEqual(config.cert_thumbprint, "AABBCCDDEEFF00112233445566778899AABBCCDD")
        self.assertEqual(config.ca_bundle, "")

    def test_a_ca_bundle_reaches_the_collector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "internal-root.pem"
            bundle.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
            config = _to_endpoint_config(
                _request(use_ssl=True, cert_trust="ca_bundle", ca_bundle=str(bundle)), TENANT)
        self.assertEqual(config.ca_bundle, str(bundle))
        self.assertEqual(config.cert_thumbprint, "")

    def test_the_authentication_policy_reaches_the_collector(self) -> None:
        config = _to_endpoint_config(_request(kerberos="require"), TENANT)
        self.assertEqual(config.kerberos_mode, "require")

    def test_the_transport_fields_do_not_disturb_the_rest_of_the_scan(self) -> None:
        plain = _to_endpoint_config(_request(), TENANT)
        secured = _to_endpoint_config(_request(use_ssl=True), TENANT)
        for field in ("paths", "max_depth", "read_content", "read_acl", "include_hidden"):
            with self.subTest(field):
                self.assertEqual(getattr(plain, field), getattr(secured, field))


class ACombinationThatCannotWorkIsRefusedEarlyTest(unittest.TestCase):
    """Before C0.1 these surfaced mid-scan, or not at all."""

    def assertRefused(self, contains: str, **kwargs) -> None:
        with self.assertRaises(ValidationError) as refused:
            _request(**kwargs)
        self.assertIn(contains, str(refused.exception))

    def test_a_trust_choice_without_tls(self) -> None:
        self.assertRefused("only applies when the scan uses TLS", cert_trust="thumbprint", cert_thumbprint=SHA1)

    def test_a_trust_choice_with_nothing_to_trust(self) -> None:
        self.assertRefused("Choose the CA bundle file", use_ssl=True, cert_trust="ca_bundle")
        self.assertRefused("Paste the endpoint certificate", use_ssl=True, cert_trust="thumbprint")

    def test_a_value_the_trust_choice_will_not_use(self) -> None:
        # Silently ignoring it is how an operator ends up believing a scan is pinned.
        self.assertRefused("the trust choice is not 'thumbprint'", use_ssl=True, cert_thumbprint=SHA1)
        self.assertRefused("the trust choice is not 'ca_bundle'", use_ssl=True, ca_bundle="README.md")

    def test_a_thumbprint_that_is_not_one(self) -> None:
        for bad in ("123", "ZZ" * 20, "AA" * 21, "not-a-thumbprint"):
            with self.subTest(bad=bad):
                self.assertRefused("40 hex characters", use_ssl=True, cert_trust="thumbprint", cert_thumbprint=bad)

    def test_both_thumbprint_lengths_are_accepted(self) -> None:
        for good in (SHA1, SHA256):
            with self.subTest(length=len(good)):
                self.assertEqual(
                    _request(use_ssl=True, cert_trust="thumbprint", cert_thumbprint=good).cert_thumbprint,
                    good.upper(),
                )

    def test_a_ca_bundle_that_is_not_on_this_machine(self) -> None:
        self.assertRefused("must be a file on the machine running Sentro",
                           use_ssl=True, cert_trust="ca_bundle", ca_bundle="C:\\nope\\missing.pem")

    def test_a_port_outside_the_range(self) -> None:
        for bad in (0, 70000, -1):
            with self.subTest(port=bad), self.assertRaises(ValidationError):
                _request(use_ssl=True, port=bad)

    def test_an_authentication_policy_that_does_not_exist(self) -> None:
        with self.assertRaises(ValidationError):
            _request(kerberos="whatever")


class WhatProductionWillNotAllowTest(unittest.TestCase):

    def test_cleartext_is_refused_when_the_install_requires_tls(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_REQUIRE_WINRM_SSL": "1"}):
            with self.assertRaises(ValidationError) as refused:
                _request()
            self.assertIn("requires WinRM over TLS", str(refused.exception))
            # ... and the same request with TLS is accepted.
            self.assertTrue(_request(use_ssl=True).use_ssl)

    def test_a_local_scan_is_not_a_winrm_connection(self) -> None:
        # The local-host path never opens WinRM, so requiring TLS must not block it.
        with mock.patch.dict(os.environ, {"DSPM_REQUIRE_WINRM_SSL": "1"}):
            self.assertEqual(EndpointScanRequest(host="localhost").host, "localhost")

    def test_not_checking_the_certificate_is_refused_in_production(self) -> None:
        with mock.patch.object(backend_app, "IS_PRODUCTION", True):
            with self.assertRaises(ValidationError) as refused:
                _request(use_ssl=True, cert_trust="insecure")
            self.assertIn("refused in production", str(refused.exception))

    def test_it_is_allowed_outside_production_and_says_so(self) -> None:
        with mock.patch.object(backend_app, "IS_PRODUCTION", False):
            config = _to_endpoint_config(_request(use_ssl=True, cert_trust="insecure"), TENANT)
        self.assertTrue(config.insecure_tls)
        summary = WinRMEndpointScanner(config).transport_summary()
        self.assertEqual(summary["certificate_trust"], "insecure")
        self.assertEqual(summary["certificate_validation"], "none")

    def test_the_environment_bypass_is_also_refused_in_production(self) -> None:
        # The same door, opened from the other side: an operator who exports
        # DSPM_WINRM_SSL_SKIP_CA_CHECK=1 on a production install.
        scanner = WinRMEndpointScanner(
            WinRMEndpointConfig(host="h", username="u", password="p", use_ssl=True))
        with mock.patch.dict(os.environ, {"DSPM_ENV": "production", "DSPM_WINRM_SSL_SKIP_CA_CHECK": "1"}):
            with self.assertRaises(WinRMTransportRefused) as refused:
                scanner._winrm_cert_validation()
            self.assertIn("refused", str(refused.exception))
            self.assertIn("thumbprint", str(refused.exception), "the message must say what to do instead")

    def test_cleartext_is_refused_at_the_collector_too(self) -> None:
        # The API is not the only caller: a queued scan and a resumed one rebuild the
        # config, so the refusal lives in both places.
        scanner = WinRMEndpointScanner(WinRMEndpointConfig(host="h", username="u", password="p"))
        with (
            mock.patch.dict(os.environ, {"DSPM_REQUIRE_WINRM_SSL": "1"}),
            self.assertRaises(WinRMTransportRefused) as refused,
        ):
            scanner._run_ps("dir")
        self.assertIn("5986", str(refused.exception), "the message must name the port to use")


class HowTheCertificateIsTrustedTest(unittest.TestCase):

    def _scanner(self, **kwargs) -> WinRMEndpointScanner:
        return WinRMEndpointScanner(WinRMEndpointConfig(
            host="endpoint.corp.local", username="u", password="p", **kwargs))

    def test_the_system_trust_store_validates(self) -> None:
        scanner = self._scanner(use_ssl=True)
        with mock.patch.dict(os.environ, {"DSPM_WINRM_SSL_SKIP_CA_CHECK": "0"}):
            self.assertEqual(scanner._winrm_cert_validation(), "validate")
            self.assertEqual(scanner._winrm_ca_trust_path(), "")

    def test_a_ca_bundle_is_handed_to_the_transport(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "root.pem"
            bundle.write_text("x", encoding="utf-8")
            scanner = self._scanner(use_ssl=True, ca_bundle=str(bundle))
            self.assertEqual(scanner._winrm_cert_validation(), "validate")
            self.assertEqual(scanner._winrm_ca_trust_path(), str(bundle))

    def test_a_ca_bundle_that_vanished_is_a_refusal_not_a_silent_fallback(self) -> None:
        # Falling back to the system store would quietly scan with different trust
        # than the operator configured.
        scanner = self._scanner(use_ssl=True, ca_bundle="C:\\gone\\root.pem")
        with self.assertRaises(WinRMTransportRefused) as refused:
            scanner._winrm_ca_trust_path()
        self.assertIn("does not exist", str(refused.exception))

    def test_a_pin_carries_the_fingerprint_into_the_connection(self) -> None:
        adapter = winrm._pinned_adapter(SHA1)
        pool_kwargs = adapter.poolmanager.connection_pool_kw
        self.assertEqual(pool_kwargs["assert_fingerprint"], SHA1.lower())
        self.assertEqual(pool_kwargs["cert_reqs"], "CERT_NONE",
                         "the pin replaces chain validation; urllib3 will not do both")

    def test_a_pin_is_reported_as_validation_not_as_ignoring(self) -> None:
        # pywinrm's own word for "no chain validation" is 'ignore', and a reader of a
        # saved scan must not see that and conclude nothing was checked.
        summary = self._scanner(use_ssl=True, cert_thumbprint=SHA1).transport_summary()
        self.assertEqual(summary["certificate_trust"], "thumbprint")
        self.assertEqual(summary["certificate_validation"], "pinned")
        self.assertEqual(summary["certificate_thumbprint"], SHA1)

    def test_trust_choices_never_share_a_session(self) -> None:
        # A reused session would carry the previous scan's trust into this one.
        base = {"host": "h", "username": "u", "password": "p", "use_ssl": True}
        identities = {
            WinRMEndpointScanner(WinRMEndpointConfig(**base))._session_identity(),
            WinRMEndpointScanner(WinRMEndpointConfig(**base, cert_thumbprint=SHA1))._session_identity(),
            WinRMEndpointScanner(WinRMEndpointConfig(**base, insecure_tls=True))._session_identity(),
            WinRMEndpointScanner(WinRMEndpointConfig(host="h", username="u", password="p"))._session_identity(),
        }
        self.assertEqual(len(identities), 4, "two different transports shared one session identity")

    def test_normalisation_accepts_what_windows_prints(self) -> None:
        for pasted in (SHA1, SHA1.lower(), " ".join(SHA1[i:i + 2] for i in range(0, 40, 2)),
                       ":".join(SHA1[i:i + 2] for i in range(0, 40, 2))):
            with self.subTest(pasted=pasted[:20]):
                self.assertEqual(normalize_certificate_thumbprint(pasted), SHA1)
        self.assertEqual(normalize_certificate_thumbprint(""), "")


class TheTransportIsRecordedTest(unittest.TestCase):

    def test_a_scan_records_how_it_was_carried(self) -> None:
        scanner = WinRMEndpointScanner(_to_endpoint_config(
            _request(use_ssl=True, cert_trust="thumbprint", cert_thumbprint=SHA1, kerberos="require"), TENANT))
        transport = scanner._session_diagnostics()["transport"]
        self.assertEqual(
            {transport["scheme"], transport["port"], transport["certificate_trust"], transport["authentication"]},
            {"https", 5986, "thumbprint", "kerberos_only"} if winrm._kerberos_transport_available()
            else {"https", 5986, "thumbprint", transport["authentication"]},
        )
        self.assertTrue(transport["ssl"])

    def test_the_record_names_the_authentication_policy(self) -> None:
        for mode, expected in (("off", "ntlm"), ("", "ntlm")):
            with self.subTest(mode=mode):
                scanner = WinRMEndpointScanner(_to_endpoint_config(_request(kerberos=mode), TENANT))
                self.assertEqual(scanner.transport_summary()["authentication"], expected)

    def test_kerberos_only_is_not_quietly_downgraded(self) -> None:
        scanner = WinRMEndpointScanner(_to_endpoint_config(_request(kerberos="require"), TENANT))
        policy = scanner.transport_summary()["authentication"]
        if winrm._kerberos_transport_available():
            self.assertEqual(policy, "kerberos_only")
        else:
            # Refusing to run is the design (a silent NTLM fallback is the bug this
            # names), and the record says why rather than claiming Kerberos.
            self.assertTrue(policy.startswith("unavailable:"), policy)
            self.assertIn("requests-kerberos", policy)

    def test_no_credential_appears_in_the_record(self) -> None:
        config = _to_endpoint_config(
            EndpointScanRequest(host="10.10.10.25", username="svc_scan", password="hunter2-secret",
                                domain="CORP", use_ssl=True), TENANT)
        rendered = repr(WinRMEndpointScanner(config)._session_diagnostics())
        self.assertNotIn("hunter2-secret", rendered)
        self.assertNotIn("svc_scan", rendered)


if __name__ == "__main__":
    unittest.main()
