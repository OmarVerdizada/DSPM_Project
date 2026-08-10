"""Track P-C: cheap-signal triage. The recall contract is the point of these
tests - triage may only skip content that is unambiguously binary (a NUL byte),
never text in any encoding, and must never drop a finding that a full scan would
have produced."""

from __future__ import annotations

import gzip
import os
import unittest
from unittest import mock

from classification.regex_classifier import classify_content
from discovery import triage
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig, _detector_version


def _route(name: str, content: str) -> str:
    return triage.triage_content({"name": name}, content)["route"]


class TriageRoutingTests(unittest.TestCase):
    def test_plain_text_is_fully_scanned(self) -> None:
        self.assertEqual(_route("a.txt", "ssn 123-45-6789 email a@b.com password hunter2"), triage.ROUTE_FULL)

    def test_non_utf8_text_is_never_skipped(self) -> None:
        # A windows-1252 / ISO-8859-9 file (Azerbaijani, Turkish, German, ...) read
        # as UTF-8-with-replace becomes many U+FFFD but has NO NUL. It MUST be fully
        # scanned - skipping it would silently drop non-English PII. This is the
        # reason the skip gate is NUL-based, not replacement-char/text-ratio-based.
        az = "Salam dünya. Əməkdaş şifrəsi ali@şirkət.az".encode("iso-8859-9", "replace").decode("utf-8", "replace")
        self.assertIn("�", az)  # it really did fail to decode cleanly
        self.assertEqual(_route("az.txt", az), triage.ROUTE_FULL)

    def test_base64_and_minified_are_fully_scanned(self) -> None:
        import base64
        self.assertEqual(_route("a.b64", base64.b64encode(os.urandom(4000)).decode()), triage.ROUTE_FULL)
        self.assertEqual(_route("min.json", '{"a":1,"b":[2,3]}' * 500), triage.ROUTE_FULL)

    def test_empty_content_is_left_to_the_detector_empty_check(self) -> None:
        self.assertEqual(_route("a.txt", ""), triage.ROUTE_FULL)

    def test_binary_with_nul_is_skipped(self) -> None:
        blob = os.urandom(8000).decode("utf-8", "replace")
        self.assertIn("\x00", blob)  # random 8 KB almost surely contains a NUL
        self.assertEqual(_route("fake.log", blob), triage.ROUTE_SKIP_NON_TEXT)

    def test_disabled_never_skips(self) -> None:
        blob = ("\x00" * 100) + "data"
        with mock.patch.dict(os.environ, {"DSPM_TRIAGE_ENABLED": "0"}):
            self.assertEqual(_route("x.bin", blob), triage.ROUTE_FULL)
        with mock.patch.dict(os.environ, {"DSPM_TRIAGE_BINARY_SKIP": "0"}):
            self.assertEqual(_route("x.bin", blob), triage.ROUTE_FULL)


class TriageRecallSafetyTests(unittest.TestCase):
    """For every blob triage skips, a FULL scan of that blob must find nothing -
    otherwise the skip lost a finding."""

    def test_skipped_binary_has_no_findings_under_full_scan(self) -> None:
        blobs = [
            os.urandom(9000).decode("utf-8", "replace"),
            gzip.compress(b"secret ssn 111-22-3333 email x@y.com " * 400).decode("utf-8", "replace"),
            (b"\x00\x01\x02\x03" * 3000).decode("utf-8", "replace"),
        ]
        for blob in blobs:
            self.assertEqual(_route("f.txt", blob), triage.ROUTE_SKIP_NON_TEXT)
            self.assertEqual(classify_content(blob), [], "a skipped blob would have produced findings — recall loss")


class TriageSignatureTests(unittest.TestCase):
    def test_signature_is_folded_into_detector_version(self) -> None:
        self.assertIn(triage.triage_signature(), _detector_version(set()))

    def test_signature_changes_with_policy(self) -> None:
        base = triage.triage_signature()
        with mock.patch.dict(os.environ, {"DSPM_TRIAGE_ENABLED": "0"}):
            self.assertNotEqual(base, triage.triage_signature())
        with mock.patch.dict(os.environ, {"DSPM_TRIAGE_BINARY_SKIP": "0"}):
            self.assertNotEqual(base, triage.triage_signature())


class TriageDetectorIntegrationTests(unittest.TestCase):
    def _engine(self) -> DSPMDiscoveryEngine:
        return DSPMDiscoveryEngine(ScanConfig(tenant_id="triage-test", use_sample_when_empty=False))

    def test_run_detectors_skips_binary_and_reports_triage(self) -> None:
        engine = self._engine()
        blob = os.urandom(8000).decode("utf-8", "replace")
        findings, metrics = engine._run_detectors(blob, {"name": "f.log"}, set())
        self.assertEqual(findings, [])
        self.assertEqual(metrics["triage_route"], triage.ROUTE_SKIP_NON_TEXT)
        self.assertEqual(metrics["detectors"], [])
        # text still runs the catalog and finds the planted secrets
        text_findings, text_metrics = engine._run_detectors("email a@b.com ssn 123-45-6789", {"name": "n.txt"}, set())
        self.assertTrue(text_findings)
        self.assertEqual(text_metrics["triage_route"], triage.ROUTE_FULL)

        diag = engine._triage_diagnostics()
        self.assertEqual(diag["records_skipped_non_text"], 1)
        self.assertEqual(diag["records_full"], 1)
        self.assertTrue(diag["enabled"])


if __name__ == "__main__":
    unittest.main()
