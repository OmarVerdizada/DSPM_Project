"""Track P-C: cheap-signal triage. The recall contract is the point of these
tests - triage may only skip content that is unambiguously binary (a NUL byte),
never text in any encoding, and must never drop a finding that a full scan would
have produced."""

from __future__ import annotations

import gzip
import os
import random
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
        # Seeded, not os.urandom: lucky random bytes occasionally decode into
        # enough finance-ish token soup to trip the heuristic context classifier,
        # which fails the [] assertion below on a blob no real scan would see.
        rng = random.Random(1787)
        blobs = [
            bytes(rng.randrange(256) for _ in range(9000)).decode("utf-8", "replace"),
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
        return DSPMDiscoveryEngine(ScanConfig(tenant_id="triage-test", walk_local_path=False))

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

    def test_run_detectors_surfaces_triage_score_on_the_record(self) -> None:
        engine = self._engine()
        record = {"name": "passwords.txt"}
        engine._run_detectors("email a@b.com", record, set())
        self.assertIn("triage_score", record)
        self.assertGreater(record["triage_score"], 0)


class TriageSamplingTests(unittest.TestCase):
    """Opt-in head/tail sampling of very large text (DSPM_TRIAGE_SAMPLE_BYTES).
    Off by default -> byte-for-byte unchanged; on -> scans head+tail and marks the
    record PARTIAL/truncated so findings inherit the truncation contract."""

    def _engine(self) -> DSPMDiscoveryEngine:
        return DSPMDiscoveryEngine(ScanConfig(tenant_id="triage-sample", walk_local_path=False))

    def test_disabled_by_default_scans_full_content(self) -> None:
        big = "a@b.com " + ("x " * 6000) + " c@d.com"
        self.assertEqual(triage.triage_content({"name": "big.txt"}, big)["route"], triage.ROUTE_FULL)

    def test_sampling_scans_head_and_tail_and_marks_partial(self) -> None:
        engine = self._engine()
        # Findings planted in the head and tail; a lot of filler in the middle.
        big = "head a@b.com " + ("filler " * 8000) + " tail c@d.com"
        record = {"name": "big.txt", "scan_completeness": "FULL", "total_bytes": len(big)}
        with mock.patch.dict(os.environ, {"DSPM_TRIAGE_SAMPLE_BYTES": "400"}):
            findings, metrics = engine._run_detectors(big, record, set())
        self.assertEqual(metrics["triage_route"], triage.ROUTE_SAMPLE)
        # head and tail emails are still found
        emails = {f.get("type") for f in findings}
        self.assertIn("email", emails)
        # the record is marked partial so findings inherit truncation
        self.assertEqual(record["scan_completeness"], "PARTIAL")
        self.assertTrue(record["truncated"])
        self.assertLessEqual(record["bytes_scanned"], 400)
        self.assertEqual(engine._triage_diagnostics()["records_sampled"], 1)


class TriageOrderingTests(unittest.TestCase):
    """Score-ordered analysis: dispatch likeliest-sensitive first so a
    deadline-truncated scan keeps recall. Never changes a completed scan's output
    order (results are stored by original index)."""

    def _engine(self) -> DSPMDiscoveryEngine:
        return DSPMDiscoveryEngine(ScanConfig(tenant_id="triage-order", walk_local_path=False))

    def test_order_puts_high_score_first(self) -> None:
        engine = self._engine()
        records = [
            {"name": "readme.txt", "content": "hello world"},          # low score
            {"name": "secrets.env", "content": "API_KEY=x password=y"},  # high score (name + text)
            {"name": "notes.md", "content": "meeting notes"},           # low score
        ]
        order = engine._analysis_order(records)
        self.assertEqual(order[0], 1)  # the secrets file is analyzed first
        self.assertEqual(sorted(order), [0, 1, 2])  # every record still dispatched

    def test_ordering_can_be_disabled(self) -> None:
        engine = self._engine()
        records = [{"name": "a.txt", "content": "x"}, {"name": "secret.env", "content": "password=y"}]
        with mock.patch.dict(os.environ, {"DSPM_TRIAGE_ORDER": "0"}):
            self.assertEqual(engine._analysis_order(records), [0, 1])  # natural order


if __name__ == "__main__":
    unittest.main()
