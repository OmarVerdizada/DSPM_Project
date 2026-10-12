"""W4.6: a unit's memory follows the file being analysed, not the bytes the unit holds.

The walk kept every record it handed to the analysis - content included - until the unit's
walk ended, so a unit of 120 MiB of text peaked 1.6x above one of 30 MiB (MEASURED,
2026-10-08: 226 against 142 MiB). The record handed on carries the content; the one the walk
keeps no longer does, and says what was read. A walk with nobody to hand records to (the
single path, a test's oracle) keeps them whole.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from collectors import file_scanner
from collectors.file_scanner import scan_directory

_BODY = "contact owner{n}@example.com about the invoice\nquarterly budget notes {n}\n"


class TheWalkKeepsNoContentItHandedOnTest(unittest.TestCase):

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        # %TEMP% is skipped by the collector on purpose.
        skip = patch.object(file_scanner, "is_skipped_scan_path", return_value=False)
        skip.start()
        self.addCleanup(skip.stop)
        for index in range(3):
            (self.folder / f"doc_{index}.txt").write_text(_BODY.format(n=index) * 20, encoding="utf-8")

    def test_handed_whole_kept_without_content(self) -> None:
        handed: list[dict] = []
        kept = scan_directory(self.folder, record_callback=handed.append)
        self.assertEqual(len(handed), 3)
        self.assertEqual(len(kept), 3)
        for record in handed:
            self.assertIn("@example.com", record.get("content") or "", "the analysis lost the content")
        by_name = {record["name"]: record for record in handed}
        for record in kept:
            self.assertFalse(record.get("content"), f"the walk still holds {record['name']}'s content")
            self.assertEqual(record.get("content_status"), by_name[record["name"]].get("content_status"))
            self.assertEqual(record.get("content_hash"), by_name[record["name"]].get("content_hash"))

    def test_with_nobody_to_hand_them_to_records_stay_whole(self) -> None:
        records = scan_directory(self.folder)
        self.assertEqual(len(records), 3)
        for record in records:
            self.assertIn("@example.com", record.get("content") or "")


if __name__ == "__main__":
    unittest.main()
