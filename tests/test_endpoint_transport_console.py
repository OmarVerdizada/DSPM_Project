"""C0.1: what the endpoint wizard sends is what the API accepts.

The API half of C0.1 is covered by tests/test_endpoint_transport_contract.py. This is the
other half, and the one nothing else can catch: the console builds its payload by reading
element ids out of frontend/index.html, and a renamed or mistyped id is invisible to
`node --check`. It does not throw either - `document.querySelector("#typo")?.value || ""`
quietly yields the default, which for a transport control means the scan runs in cleartext
while the operator believes they chose TLS.

So the real frontend/app.js runs in Node against a DOM that resolves **only the ids
index.html actually defines**, and the payload it produces is fed to the real
EndpointScanRequest. Skips where Node is absent; CI's runners have it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from backend.app import EndpointScanRequest, _to_endpoint_config

ROOT = Path(__file__).resolve().parent.parent
SMOKE = ROOT / "tests" / "js" / "endpoint_transport_smoke.js"
NODE = shutil.which("node")
TENANT = "tenant-console"


@unittest.skipUnless(NODE, "Node is not installed; the console smoke needs it")
class TheWizardSendsWhatTheApiAcceptsTest(unittest.TestCase):

    def _transport(self, **fields) -> dict:
        """Run the console's readEndpointTransport() with these form values."""
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "fields.json"
            fixture.write_text(json.dumps(fields), encoding="utf-8")
            result = subprocess.run(
                [NODE, str(SMOKE), str(fixture)],
                cwd=ROOT, capture_output=True, text=True, timeout=180, check=False,
            )
        self.assertTrue(result.stdout.strip(), f"the smoke printed nothing: {result.stderr[-400:]}")
        report = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertIsNone(report.get("error"), report.get("error"))
        self.assertEqual(report["unknown_ids"], [],
                         "the console reads an endpoint id that frontend/index.html does not define")
        return report

    def test_the_default_is_the_transport_the_product_has_always_used(self) -> None:
        report = self._transport()
        self.assertEqual(report["payload"]["use_ssl"], False)
        self.assertEqual(report["payload"]["cert_trust"], "system")
        self.assertIsNone(report["payload"]["port"])
        self.assertTrue(report["trust_disabled"], "a trust choice is meaningless without TLS")

    def test_choosing_tls_sends_tls(self) -> None:
        report = self._transport(**{"endpoint-transport": "https"})
        self.assertEqual(report["payload"]["use_ssl"], True)
        self.assertFalse(report["trust_disabled"])

    def test_a_pinned_thumbprint_reaches_the_payload(self) -> None:
        report = self._transport(**{
            "endpoint-transport": "https",
            "endpoint-cert-trust": "thumbprint",
            "endpoint-cert-thumbprint": "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
        })
        payload = report["payload"]
        self.assertEqual(payload["cert_trust"], "thumbprint")
        self.assertTrue(payload["cert_thumbprint"])
        self.assertEqual(payload["ca_bundle"], "")
        self.assertFalse(report["hidden"]["endpoint-thumbprint-field"], "the field must be visible to be filled")
        self.assertTrue(report["hidden"]["endpoint-ca-bundle-field"], "the bundle field belongs to the other choice")

    def test_a_ca_bundle_reaches_the_payload(self) -> None:
        report = self._transport(**{
            "endpoint-transport": "https",
            "endpoint-cert-trust": "ca_bundle",
            "endpoint-ca-bundle": "C:\\Sentro\\trust\\root.pem",
        })
        self.assertEqual(report["payload"]["ca_bundle"], "C:\\Sentro\\trust\\root.pem")
        self.assertEqual(report["payload"]["cert_thumbprint"], "")
        self.assertFalse(report["hidden"]["endpoint-ca-bundle-field"])

    def test_a_port_override_reaches_the_payload(self) -> None:
        report = self._transport(**{"endpoint-transport": "https", "endpoint-port": "15986"})
        self.assertEqual(report["payload"]["port"], 15986)

    def test_the_authentication_policy_reaches_the_payload(self) -> None:
        report = self._transport(**{"endpoint-kerberos": "require"})
        self.assertEqual(report["payload"]["kerberos"], "require")

    def test_the_payload_is_one_the_api_accepts_and_carries_to_the_collector(self) -> None:
        """The two halves meet: the console's own output, validated by the real model."""
        report = self._transport(**{
            "endpoint-transport": "https",
            "endpoint-cert-trust": "thumbprint",
            "endpoint-cert-thumbprint": "aabbccddeeff00112233445566778899aabbccdd",
            "endpoint-kerberos": "require",
        })
        request = EndpointScanRequest(host="10.10.10.25", username="svc_scan", password="x",
                                      **report["payload"])
        config = _to_endpoint_config(request, TENANT)
        self.assertTrue(config.use_ssl)
        self.assertEqual(config.port, 5986)
        self.assertEqual(config.cert_thumbprint, "AABBCCDDEEFF00112233445566778899AABBCCDD")
        self.assertEqual(config.kerberos_mode, "require")

    def test_a_saved_scan_restores_its_transport(self) -> None:
        """Re-running a saved endpoint scan must not quietly drop to cleartext."""
        saved = {
            "use_ssl": True,
            "port": 15986,
            "cert_trust": "thumbprint",
            "cert_thumbprint": "AABBCCDDEEFF00112233445566778899AABBCCDD",
            "kerberos": "require",
        }
        report = self._transport(__profile=saved)
        self.assertEqual(report["payload"], {**saved, "ca_bundle": ""})
        request = EndpointScanRequest(host="10.10.10.25", **report["payload"])
        self.assertEqual(_to_endpoint_config(request, TENANT).port, 15986)

    def test_a_saved_http_scan_stays_http(self) -> None:
        report = self._transport(__profile={"use_ssl": False, "cert_trust": "system"})
        self.assertFalse(report["payload"]["use_ssl"])
        self.assertTrue(report["trust_disabled"])

    def test_a_trust_choice_the_form_cannot_reach_is_never_sent(self) -> None:
        # The form disables the trust control without TLS; the payload builder repeats
        # that rather than trusting the disabled state, so a stale selection cannot be
        # sent and come back as a validation error the operator cannot explain.
        report = self._transport(**{"endpoint-transport": "http", "endpoint-cert-trust": "insecure"})
        self.assertEqual(report["payload"]["cert_trust"], "system")
        EndpointScanRequest(host="10.10.10.25", **report["payload"])  # accepted


class TheWizardHasTheControlsTest(unittest.TestCase):
    """Runs without Node: the markup itself."""

    def test_index_html_defines_every_transport_control(self) -> None:
        html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        for element_id in ("endpoint-transport", "endpoint-port", "endpoint-cert-trust",
                           "endpoint-ca-bundle", "endpoint-cert-thumbprint", "endpoint-kerberos",
                           "endpoint-ca-bundle-field", "endpoint-thumbprint-field"):
            with self.subTest(element_id):
                self.assertIn(f'id="{element_id}"', html)

    def test_both_payload_builders_carry_the_transport(self) -> None:
        # The preflight payload and the scan payload must agree, or "test connection"
        # proves a transport the scan will not use.
        app_js = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
        self.assertEqual(app_js.count("...readEndpointTransport()"), 2)
        self.assertIn("function readEndpointTransport()", app_js)
        self.assertIn("syncEndpointTransportFields", app_js)


if __name__ == "__main__":
    unittest.main()
