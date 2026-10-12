from __future__ import annotations

import base64
import gzip
import json
import os
import unittest
from types import SimpleNamespace
from unittest import mock

from collectors.winrm_endpoint_scanner import (
    WINRM_GZIP_RESPONSE_PREFIX,
    WinRMEndpointConfig,
    WinRMEndpointScanner,
    _decode_scan_response,
    _read_json,
    _scan_script,
)


def _frame(raw: bytes) -> bytes:
    return WINRM_GZIP_RESPONSE_PREFIX + base64.b64encode(gzip.compress(raw, mtime=0))


class WinRMResponseCompressionTests(unittest.TestCase):
    def test_gzip_frame_round_trips_unicode_json_and_reports_ratio(self) -> None:
        payload = {
            "records": [
                {
                    "path": r"C:\Data\résumé.txt",
                    "content": "confidential-value-12345\n" * 500,
                }
            ],
            "diagnostics": {"visited_files": 1},
        }
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        framed = _frame(raw)

        decoded, diagnostics = _decode_scan_response(framed)

        self.assertEqual(decoded, raw)
        self.assertEqual(_read_json(framed), payload)
        self.assertEqual(diagnostics["response_encoding"], "gzip+base64")
        self.assertEqual(diagnostics["response_json_bytes"], len(raw))
        self.assertEqual(diagnostics["response_wire_bytes"], len(framed))
        self.assertGreater(diagnostics["response_compression_ratio"], 10)
        self.assertLess(len(framed), len(raw) // 5)

    def test_plain_json_remains_compatible(self) -> None:
        raw = b'{"records":[],"diagnostics":{"visited_files":0}}'

        decoded, diagnostics = _decode_scan_response(raw)

        self.assertEqual(decoded, raw)
        self.assertEqual(_read_json(raw), {"records": [], "diagnostics": {"visited_files": 0}})
        self.assertEqual(diagnostics["response_encoding"], "json")
        self.assertEqual(diagnostics["response_compression_ratio"], 1.0)

    def test_corrupt_frame_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "Invalid compressed"):
            _decode_scan_response(WINRM_GZIP_RESPONSE_PREFIX + b"not-valid-base64!")

    def test_decompressed_response_limit_is_enforced_before_json_parse(self) -> None:
        framed = _frame(b"x" * 2048)
        with mock.patch.dict(os.environ, {"DSPM_WINRM_RESPONSE_MAX_BYTES": "1024"}):
            with self.assertRaisesRegex(ValueError, "Decompressed.*size limit"):
                _decode_scan_response(framed)

    def test_scanner_records_are_identical_for_plain_and_compressed_responses(self) -> None:
        payload = {
            "records": [
                {
                    "path": r"C:\Data\account.txt",
                    "name": "account.txt",
                    "size": 17,
                    "extension": ".txt",
                    "content": "account=customer",
                    "modified_at": "2026-08-28T00:00:00Z",
                    "sha256": "a" * 64,
                }
            ],
            "diagnostics": {"visited_files": 1, "matched_files": 1},
        }
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        def run(output: bytes) -> tuple[list[dict], dict]:
            scanner = WinRMEndpointScanner(
                WinRMEndpointConfig(host="endpoint-01", username="scan", password="secret")
            )
            response = SimpleNamespace(status_code=0, std_out=output, std_err=b"")
            with mock.patch.object(scanner, "_run_ps_file", return_value=response), \
                 mock.patch.object(scanner, "_connection_hosts", return_value=["endpoint-01"]), \
                 mock.patch.object(scanner, "_connection_host", return_value="endpoint-01"):
                return scanner.scan(), dict(scanner.last_scan_diagnostics)

        plain_records, plain_diagnostics = run(raw)
        compressed_records, compressed_diagnostics = run(_frame(raw))

        self.assertEqual(compressed_records, plain_records)
        self.assertEqual(plain_diagnostics["response_encoding"], "json")
        self.assertEqual(compressed_diagnostics["response_encoding"], "gzip+base64")
        for key in ("visited_files", "matched_files"):
            self.assertEqual(compressed_diagnostics[key], plain_diagnostics[key])

    def test_generated_scan_script_emits_versioned_gzip_frame_with_json_fallback(self) -> None:
        script = _scan_script(
            [r"C:\Data"],
            max_depth=1,
            read_content=True,
            max_read_bytes=1024,
            allowed_extensions=[".txt"],
            extension_filter_enabled=True,
            include_hidden=True,
            include_system=False,
            hidden_filter_enabled=False,
            system_filter_enabled=False,
            read_acl=False,
            inspect_archives=False,
        )

        self.assertIn("DSPM-GZIP-BASE64-V1:", script)
        self.assertIn("IO.Compression.GZipStream", script)
        self.assertIn("IO.Compression.CompressionMode]::Compress", script)
        self.assertIn("$dspmResponse = $dspmJson", script)
        self.assertIn("[Console]::Out.Write($dspmResponse)", script)


if __name__ == "__main__":
    unittest.main()
