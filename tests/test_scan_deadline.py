"""1.2 (M14 + M9): the scan wall-clock deadline is ENFORCED - the engine stops and
returns a partial/truncated report (releasing its worker), and the advertised
archive timeout is real, not cosmetic."""

from __future__ import annotations

import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import collectors.file_scanner as fs
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig


class ScanDeadlineTests(unittest.TestCase):
    def test_cancelled_reflects_deadline_and_cancel_check(self) -> None:
        engine = DSPMDiscoveryEngine(ScanConfig())
        self.assertFalse(engine._cancelled())  # no deadline armed, no cancel
        engine._deadline = time.monotonic() - 1
        self.assertTrue(engine._cancelled())  # M14: deadline passed
        cancelled = DSPMDiscoveryEngine(ScanConfig(cancel_check=lambda: True))
        self.assertTrue(cancelled._cancelled())  # caller cancelled (job heartbeat)

    def test_analysis_stops_at_the_deadline_and_marks_truncated(self) -> None:
        engine = DSPMDiscoveryEngine(ScanConfig(max_workers=1))
        engine._deadline = time.monotonic() - 1  # already exceeded
        out = engine._analyze_records([{"name": f"f{i}.txt"} for i in range(4)])
        self.assertEqual(out, [])  # stopped before analyzing any record
        self.assertTrue(engine.last_scan_diagnostics.get("scan_truncated"))
        self.assertEqual(engine.last_scan_diagnostics.get("scan_truncated_total"), 4)


class ArchiveTimeoutTests(unittest.TestCase):
    def test_metadata_advertises_the_enforced_timeout(self) -> None:
        meta = fs._archive_safety_metadata(".zip")
        self.assertEqual(meta["archive_timeout_seconds"], fs.ARCHIVE_TOTAL_TIMEOUT_SECONDS)
        self.assertTrue(meta["timeout_enforced"])
        self.assertNotIn("per_entry_timeout_seconds", meta)  # the cosmetic key is gone

    def test_archive_processing_stops_at_the_budget(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = str(Path(d).resolve())
            with zipfile.ZipFile(Path(root) / "a.zip", "w") as archive:
                for i in range(5):
                    archive.writestr(f"e{i}.txt", "sensitive data " * 10)
            diagnostics: dict = {}
            # Budget already spent (-1) -> the first entry check trips. The
            # skip-path patch is only because the OS temp dir is scan-excluded.
            with mock.patch.object(fs, "ARCHIVE_TOTAL_TIMEOUT_SECONDS", -1), \
                 mock.patch.object(fs, "is_skipped_scan_path", return_value=False):
                fs.scan_directory(root, inspect_archives=True, diagnostics=diagnostics)
            self.assertTrue(diagnostics.get("archive_timed_out"))


if __name__ == "__main__":
    unittest.main()
