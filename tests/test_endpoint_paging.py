"""B4: an endpoint scan reads a bounded amount per file, and asks for a bounded amount per command.

Everything an endpoint scan reads crosses WinRM as one response, base64 and gzip, and is
held whole on the endpoint and again here. Two bounds keep that from following the size
of somebody's profile:

- **per file**: the collector's own default is the local one, a hundred megabytes, which
  one file can spend on its own. An endpoint scan reads five, and the record says it was
  truncated rather than pretending the file was read whole;
- **per command**: a fetch is cut into batches bounded by bytes as well as by count -
  two hundred and fifty-six files of a megabyte each is a quarter-gigabyte response.
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

from backend.app import (
    EndpointScanRequest,
    _endpoint_fetch_batches,
    _run_endpoint_scan_payload,
    _to_endpoint_config,
    endpoint_fetch_batch_bytes,
    endpoint_max_file_text_bytes,
)
from backend.security import Principal
from collectors.winrm_endpoint_scanner import WinRMEndpointConfig
from tests.test_endpoint_p2_single_delivery import _Report, _record

MB = 1024 * 1024


class TheBoundsTest(unittest.TestCase):

    def test_what_one_file_may_spend(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_ENDPOINT_MAX_FILE_TEXT_BYTES", None)
            self.assertEqual(endpoint_max_file_text_bytes(), 5 * MB)
        for value, expected in (("1048576", MB), ("1", 64 * 1024), ("999999999", 100 * MB), ("plenty", 5 * MB)):
            with self.subTest(value=value), mock.patch.dict(os.environ, {"DSPM_ENDPOINT_MAX_FILE_TEXT_BYTES": value}):
                self.assertEqual(endpoint_max_file_text_bytes(), expected)

    def test_what_one_command_may_ask_for(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_ENDPOINT_FETCH_BATCH_BYTES", None)
            # W5: 16 MiB, not 32 - a page fetches its next batch while it analyzes this one, so
            # two batches are held where one was, and the page's bound stays 32 MiB.
            self.assertEqual(endpoint_fetch_batch_bytes(), 16 * MB)
        for value, expected in (("8388608", 8 * MB), ("1", MB), ("999999999", 512 * MB), ("lots", 16 * MB)):
            with self.subTest(value=value), mock.patch.dict(os.environ, {"DSPM_ENDPOINT_FETCH_BATCH_BYTES": value}):
                self.assertEqual(endpoint_fetch_batch_bytes(), expected)

    def test_the_cap_reaches_the_collector(self) -> None:
        payload = EndpointScanRequest(host="endpoint-01", username="scan", password="secret", paths=["documents"])
        with mock.patch.dict(os.environ, {"DSPM_ENDPOINT_MAX_FILE_TEXT_BYTES": str(2 * MB)}):
            config = _to_endpoint_config(payload, "tenant-b4")
        self.assertEqual(config.max_read_bytes, 2 * MB)
        self.assertLess(config.max_read_bytes, WinRMEndpointConfig(host="h", username="u", password="p").max_read_bytes,
                        "an endpoint scan still reads as much per file as a local one")


class TheBatchesTest(unittest.TestCase):

    def _paths(self, count: int) -> list[str]:
        return [fr"C:\Users\ana\Documents\file-{index}.txt" for index in range(count)]

    def _sizes(self, paths: list[str], each: int) -> dict[str, int]:
        return {path.casefold(): each for path in paths}

    def test_bytes_end_a_batch_before_the_count_does(self) -> None:
        paths = self._paths(10)
        with mock.patch.dict(os.environ, {"DSPM_ENDPOINT_FETCH_BATCH_BYTES": str(16 * MB),
                                          "DSPM_ENDPOINT_MAX_FILE_TEXT_BYTES": str(5 * MB)}):
            batches = _endpoint_fetch_batches(paths, self._sizes(paths, 5 * MB))
        self.assertEqual([len(batch) for batch in batches], [3, 3, 3, 1])
        self.assertEqual([path for batch in batches for path in batch], paths, "a path was lost or reordered")

    def test_a_file_is_only_ever_counted_at_what_will_be_read(self) -> None:
        paths = self._paths(4)
        with mock.patch.dict(os.environ, {"DSPM_ENDPOINT_FETCH_BATCH_BYTES": str(32 * MB),
                                          "DSPM_ENDPOINT_MAX_FILE_TEXT_BYTES": str(5 * MB)}):
            # Four files of 400 MB each are four reads of 5 MB, not 1.6 GB.
            batches = _endpoint_fetch_batches(paths, self._sizes(paths, 400 * MB))
        self.assertEqual([len(batch) for batch in batches], [4])

    def test_a_file_that_fills_the_budget_alone_is_its_own_batch(self) -> None:
        paths = self._paths(3)
        with mock.patch.dict(os.environ, {"DSPM_ENDPOINT_FETCH_BATCH_BYTES": str(MB),
                                          "DSPM_ENDPOINT_MAX_FILE_TEXT_BYTES": str(5 * MB)}):
            batches = _endpoint_fetch_batches(paths, self._sizes(paths, 5 * MB))
        self.assertEqual([len(batch) for batch in batches], [1, 1, 1])

    def test_the_count_still_ends_a_batch_when_the_files_are_small(self) -> None:
        paths = self._paths(600)
        batches = _endpoint_fetch_batches(paths, self._sizes(paths, 1024))
        self.assertEqual([len(batch) for batch in batches], [256, 256, 88])

    def test_nothing_to_fetch_is_no_command_at_all(self) -> None:
        self.assertEqual(_endpoint_fetch_batches([], {}), [])
        self.assertEqual(_endpoint_fetch_batches(["", "  "], {}), [["  "]])


class AWarmScanFetchesInBoundedCommandsTest(unittest.TestCase):
    """The end of the story: a profile of large changed files is read in several commands."""

    def setUp(self) -> None:
        # The single path's B4 batching, which a partitioned endpoint scan (W1.3) reuses per page.
        single = mock.patch("backend.app.partitioned_scans_enabled", return_value=False)
        single.start()
        self.addCleanup(single.stop)
        self.config = WinRMEndpointConfig(
            host="endpoint-01", username="scan", password="secret", paths=["documents"], read_content=True,
        )
        self.payload = EndpointScanRequest(
            host="endpoint-01", username="scan", password="secret", paths=["documents"],
            incremental_enabled=True, save_report=False,
        )
        self.principal = Principal(subject="analyst", role="analyst", tenant_id="tenant-b4")

    def test_ten_large_changed_files_are_read_in_several_bounded_commands(self) -> None:
        paths = [fr"C:\Users\ana\Documents\file-{index}.txt" for index in range(10)]
        metadata = [dict(_record(path, content=""), size=5 * MB) for path in paths]
        fetches: list[list[str]] = []

        class Scanner:
            def __init__(self, config):
                self.config = config
                self.last_scan_diagnostics: dict = {}
                self.last_connection_host = "endpoint-01"

            def scan(self):
                if not self.config.read_content:
                    return metadata
                fetches.append(list(self.config.paths))
                return [_record(path) for path in self.config.paths]

        report = _Report()
        with mock.patch.dict(os.environ, {"DSPM_ENDPOINT_FETCH_BATCH_BYTES": str(16 * MB),
                                          "DSPM_ENDPOINT_MAX_FILE_TEXT_BYTES": str(5 * MB)}), \
                mock.patch("backend.app.incremental_baseline_exists", return_value=True), \
                mock.patch("backend.app._endpoint_analysis_engine", return_value=report), \
                mock.patch("backend.app.WinRMEndpointScanner", side_effect=Scanner), \
                mock.patch("backend.app._analyze_endpoint_records",
                           side_effect=lambda _report, records, _job=None, **_bounds: records), \
                mock.patch("backend.app._apply_compliance"), \
                mock.patch("backend.app._persist_scan"):
            result = _run_endpoint_scan_payload(self.config, self.payload, self.principal)

        self.assertEqual([len(batch) for batch in fetches], [3, 3, 3, 1],
                         "the whole profile was asked for in one response")
        diagnostics = result["scan_diagnostics"]
        self.assertEqual(diagnostics["incremental_content_fetch_commands"], 4)
        self.assertEqual(diagnostics["incremental_fetch_batch_bytes"], 16 * MB)
        self.assertEqual(diagnostics["endpoint_max_file_text_bytes"], 5 * MB)
        self.assertEqual(len(result["files"]), 10, "a file was lost between the batches")
        self.assertEqual([item["path"] for item in result["files"]], paths, "the batches changed the order")


class AFullScanIsReadInBoundedCommandsTest(unittest.TestCase):
    """B4b: a first scan pages too, and a batch's text is released when the batch is analyzed.

    Paging the transfer alone would only move the peak: ten batches of text still
    add up to the whole profile if the scan waits until the end to analyze them.
    Analysis is what turns text into findings and drops the text, so it runs per
    batch, and what the scan holds follows the batch instead of the profile.
    """

    def setUp(self) -> None:
        # The single path's B4 batching, which a partitioned endpoint scan (W1.3) reuses per page.
        single = mock.patch("backend.app.partitioned_scans_enabled", return_value=False)
        single.start()
        self.addCleanup(single.stop)
        self.config = WinRMEndpointConfig(
            host="endpoint-01", username="scan", password="secret", paths=["documents"], read_content=True,
        )
        self.payload = EndpointScanRequest(
            host="endpoint-01", username="scan", password="secret", paths=["documents"],
            incremental_enabled=False, save_report=False,
        )
        self.principal = Principal(subject="analyst", role="analyst", tenant_id="tenant-b4")

    def _run(self, metadata: list[dict], fetched_for, fetches: list, analyzed_with_text: list) -> dict:
        class Scanner:
            def __init__(self, config):
                self.config = config
                self.last_scan_diagnostics: dict = {}
                self.last_connection_host = "endpoint-01"

            def scan(self):
                if not self.config.read_content:
                    return metadata
                fetches.append(list(self.config.paths))
                return fetched_for(list(self.config.paths))

        def analyze(_report, records, _job=None, **_bounds):
            analyzed_with_text.append(sum(1 for record in records if record.get("content")))
            return [{key: value for key, value in record.items() if key != "content"} for record in records]

        with mock.patch.dict(os.environ, {"DSPM_ENDPOINT_FETCH_BATCH_BYTES": str(16 * MB),
                                          "DSPM_ENDPOINT_MAX_FILE_TEXT_BYTES": str(5 * MB)}), \
                mock.patch("backend.app._endpoint_analysis_engine", return_value=_Report()), \
                mock.patch("backend.app.WinRMEndpointScanner", side_effect=Scanner), \
                mock.patch("backend.app._analyze_endpoint_records", side_effect=analyze), \
                mock.patch("backend.app._apply_compliance"), \
                mock.patch("backend.app._persist_scan"):
            return _run_endpoint_scan_payload(self.config, self.payload, self.principal)

    def test_a_first_scan_never_holds_more_than_one_batch_of_text(self) -> None:
        paths = [fr"C:\Users\ana\Documents\file-{index}.txt" for index in range(10)]
        metadata = [dict(_record(path, content=""), size=5 * MB) for path in paths]
        fetches: list[list[str]] = []
        analyzed_with_text: list[int] = []

        result = self._run(metadata, lambda chunk: [_record(path) for path in chunk], fetches, analyzed_with_text)

        self.assertEqual([len(batch) for batch in fetches], [3, 3, 3, 1],
                         "the whole scope was asked for in one response")
        self.assertEqual(analyzed_with_text, [3, 3, 3, 1],
                         "a batch was still held as text when the next one arrived")
        diagnostics = result["scan_diagnostics"]
        self.assertTrue(diagnostics["incremental_metadata_pass"], "a first scan enumerates before it reads")
        self.assertEqual(diagnostics["incremental_content_fetch_commands"], 4)
        self.assertFalse(diagnostics["incremental_first_scan_single_pass"])
        self.assertEqual([item["path"] for item in result["files"]], paths, "the batches changed walk order")

    def test_a_file_the_batch_could_not_read_is_reported_and_the_scan_is_incomplete(self) -> None:
        paths = [fr"C:\Users\ana\Documents\file-{index}.txt" for index in range(2)]
        metadata = [dict(_record(path, content=""), size=1024) for path in paths]
        fetches: list[list[str]] = []
        analyzed_with_text: list[int] = []

        result = self._run(
            metadata,
            lambda chunk: [_record(path) for path in chunk if path != paths[1]],
            fetches,
            analyzed_with_text,
        )

        diagnostics = result["scan_diagnostics"]
        self.assertIn("MissingRecords", diagnostics["incremental_fetch_errors"])
        self.assertEqual(diagnostics["incremental_missing_changed_paths"], [paths[1]])
        self.assertFalse(diagnostics["incremental"]["complete"],
                         "a scope that was not fully read must not look complete to the pruner")
        unread = next(item for item in result["files"] if item["path"] == paths[1])
        self.assertIn("could not be read", unread["scan_error"])
        self.assertEqual(len(result["files"]), 2, "the file that could not be read still belongs to the estate")


if __name__ == "__main__":
    unittest.main()
