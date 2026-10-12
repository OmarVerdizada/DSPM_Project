"""Extension-policy normalization is tolerant, canonical, and identical across
every scan type (local / SMB file-server / WinRM endpoint).

Regression for the "file-server scan errored, endpoint scan silently accepted
garbage" inconsistency: inputs like ``*.pdf`` / ``pdf docx`` / ``.pdf,.docx``
used to 422 the file-server scan (raising validator) while the endpoint scan
(no validator) produced match-nothing filters like ``.*.pdf``. Now one canonical
normalizer serves both: split multi-token items, strip globs/quotes, validate,
drop invalid tokens - never raise, never leak garbage.
"""

from __future__ import annotations

import unittest

from collectors.file_scanner import (
    MAX_EXTENSION_FILTER,
    matches_scan_filters,
    normalize_extension_filter,
    normalize_one_extension,
)


class NormalizeOneExtensionTests(unittest.TestCase):
    def test_canonicalizes(self) -> None:
        self.assertEqual(normalize_one_extension("PDF"), ".pdf")
        self.assertEqual(normalize_one_extension(".pdf"), ".pdf")
        self.assertEqual(normalize_one_extension("  .PDF  "), ".pdf")
        self.assertEqual(normalize_one_extension("*.pdf"), ".pdf")   # leading glob
        self.assertEqual(normalize_one_extension("'.pdf'"), ".pdf")  # quotes
        self.assertEqual(normalize_one_extension(".tar.gz"), ".tar.gz")
        self.assertEqual(normalize_one_extension("123"), ".123")     # numeric ok

    def test_drops_invalid(self) -> None:
        for bad in ("", ".", "..", ".c#", ".p df", ".<x>", None, "." + "a" * 60):
            self.assertEqual(normalize_one_extension(bad), "", repr(bad))


class NormalizeFilterTests(unittest.TestCase):
    def test_splits_multi_token_items(self) -> None:
        self.assertEqual(normalize_extension_filter(["pdf docx"]), {".pdf", ".docx"})
        self.assertEqual(normalize_extension_filter([".pdf,.docx"]), {".pdf", ".docx"})
        self.assertEqual(
            normalize_extension_filter(["pdf, docx; xls | txt"]),
            {".pdf", ".docx", ".xls", ".txt"},
        )

    def test_strips_globs_and_dedups(self) -> None:
        self.assertEqual(normalize_extension_filter(["*.pdf", ".pdf", "PDF"]), {".pdf"})

    def test_drops_invalid_without_raising(self) -> None:
        self.assertEqual(normalize_extension_filter([".c#", "!!!", ".ok"]), {".ok"})

    def test_defensive_against_non_strings(self) -> None:
        # A None/other item must not raise (the old naive normalizer did item.strip()).
        self.assertEqual(normalize_extension_filter([None, ".pdf"]), {".pdf"})

    def test_output_is_bounded(self) -> None:
        big = [f"ext{i}" for i in range(MAX_EXTENSION_FILTER * 4)]
        self.assertLessEqual(len(normalize_extension_filter(big)), MAX_EXTENSION_FILTER)

    def test_empty(self) -> None:
        self.assertEqual(normalize_extension_filter(None), set())
        self.assertEqual(normalize_extension_filter([]), set())


class RequestModelConsistencyTests(unittest.TestCase):
    """The file-server (ScanRequest) and WinRM (EndpointScanRequest) models must
    normalize identically and never raise on a messy policy."""

    def _models(self):
        from backend.app import EndpointScanRequest, ScanRequest
        return ScanRequest, EndpointScanRequest

    def test_both_scan_types_agree(self) -> None:
        ScanRequest, EndpointScanRequest = self._models()
        for raw in (["*.pdf"], ["pdf docx"], [".pdf,.docx"], [".c#"], ["PDF", " .docx "], []):
            fs = ScanRequest(server="", allowed_extensions=raw).allowed_extensions
            ep = EndpointScanRequest(host="h", allowed_extensions=raw).allowed_extensions
            self.assertEqual(fs, ep, raw)

    def test_messy_policy_does_not_error(self) -> None:
        ScanRequest, _ = self._models()
        r = ScanRequest(server="", allowed_extensions=["*.pdf", "pdf docx", ".c#"],
                        extension_filter_enabled=True)
        self.assertEqual(r.allowed_extensions, [".docx", ".pdf"])  # sorted, .c# dropped


class FilterApplicationTests(unittest.TestCase):
    def test_normalized_filter_matches_intended_files(self) -> None:
        flt = normalize_extension_filter(["*.pdf", "docx"])  # -> {.pdf, .docx}
        keep = matches_scan_filters(".pdf", False, False, flt, True, True, False, False, False)
        drop = matches_scan_filters(".exe", False, False, flt, True, True, False, False, False)
        self.assertTrue(keep)
        self.assertFalse(drop)


if __name__ == "__main__":
    unittest.main()
