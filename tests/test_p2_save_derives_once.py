"""M2/P2: a save stops re-deriving what it has just built - and stores the same bytes.

Profiling a save of the quality audit's 3,083-file scan: 15% of it re-normalised the
whole report to build the packed inventory rows the normalized write had just built,
serialising every record a second time, and 10% parsed each asset's detail_json back
out of the JSON the save had just written, to count two lists. The rows now come from
the normalized write and the counts from the record dict. What is stored must not
change by a byte: the row column and the counts are compared with what the old
derivation gives for the same report.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from backend import store
from backend.domain import models

TENANT = "tenant-p2"


def _report(scan_id: str = "scan-p2") -> dict:
    files = []
    for index in range(40):
        risk = {"score": index, "level": "HIGH" if index % 3 else "LOW",
                "reasons": [f"reason {n}" for n in range(index % 4)],
                "dlp_recommendations": [{"action": f"act {n}"} for n in range(index % 3)]}
        if index % 7 == 0:
            risk = {"score": 1}                 # no lists at all
        files.append({
            "path": f"C:/share/dept{index % 5}/file_{index:03d}.txt", "name": f"file_{index:03d}.txt",
            "extension": ".txt", "size": 100 + index, "owner": "HR\\owner", "modified_at": "2026-09-01T00:00:00Z",
            "risk": risk,
            "findings": [{"type": "email", "count": 1 + index % 2, "samples": [f"u{index}@example.com"],
                          "framework": "gdpr"}] if index % 2 else [],
        })
    return {"scan_id": scan_id, "timestamp": "2026-09-24T00:00:00Z", "source": "local", "scan_label": "HR share",
            "files": files, "summary": {"total_files": len(files)}}


class _Case(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "p2.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        store.create_tenant(TENANT, "P2")

    def _stored_rows(self, scan_id: str) -> str:
        with store._connect() as conn:
            row = conn.execute("SELECT rows_json FROM scan_reports WHERE tenant_id = ? AND scan_id = ?",
                               (TENANT, scan_id)).fetchone()
        return store.unpack_json_text(row["rows_json"])


class TheSameBytesTest(_Case):

    def test_the_packed_rows_are_the_old_projection_byte_for_byte(self) -> None:
        report = _report()
        store.save_scan_history(TENANT, json.loads(json.dumps(report)))
        # What _scan_report_inventory_rows built before P2, verbatim - independent of
        # the helper both paths now share, or this would compare the code with itself.
        rows = []
        for asset in models.iter_normalized_assets(TENANT, report):
            row = {column: getattr(asset, column) for column in store._INVENTORY_COLS}
            row["search_text"] = asset.search_text
            row["scan_id"] = "scan-p2"
            row["reason_count"], row["dlp_count"] = store._detail_counts(asset.detail_json)
            rows.append(row)
        expected = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
        self.assertEqual(self._stored_rows("scan-p2"), expected)
        self.assertEqual(len(rows), 40)

    def test_the_counts_are_the_ones_the_detail_json_gives(self) -> None:
        store.save_scan_history(TENANT, _report())
        with store._connect() as conn:
            rows = conn.execute("SELECT detail_json, reason_count, dlp_count FROM assets WHERE tenant_id = ?",
                                (TENANT,)).fetchall()
        self.assertEqual(len(rows), 40)
        counted = [(row["reason_count"], row["dlp_count"]) for row in rows]
        self.assertEqual(counted, [store._detail_counts(row["detail_json"]) for row in rows])
        self.assertIn((3, 2), counted, "the fixture should exercise non-zero counts")

    def test_the_record_counts_agree_with_the_json_counts_for_odd_shapes(self) -> None:
        for record in ({}, {"risk": None}, {"risk": "high"}, {"risk": {"reasons": None}},
                       {"risk": {"reasons": ["a", "b"], "dlp_recommendations": [{}]}}):
            with self.subTest(record=record):
                self.assertEqual(models.record_detail_counts(record),
                                 store._detail_counts(json.dumps(record)))


class TheSaveDerivesOnceTest(_Case):

    def test_a_first_save_does_not_normalise_the_report_twice(self) -> None:
        calls = []
        real = models.iter_normalized_chunks

        def counting(*args, **kwargs):
            calls.append(1)
            return real(*args, **kwargs)

        with mock.patch("backend.domain.iter_normalized_chunks", counting), \
                mock.patch.object(models, "iter_normalized_chunks", counting):
            store.save_scan_history(TENANT, _report())
        self.assertEqual(len(calls), 1, "the packed rows come from the normalized write")

    def test_nor_parse_the_detail_json_it_just_wrote(self) -> None:
        with mock.patch.object(store, "_detail_counts", side_effect=AssertionError("parsed back")):
            store.save_scan_history(TENANT, _report())

    def test_a_re_save_still_stores_the_rows(self) -> None:
        # A lifecycle re-save writes no estate rows, so the rows come the old way.
        store.save_scan_history(TENANT, _report())
        first = self._stored_rows("scan-p2")
        store.save_scan_history(TENANT, _report())
        self.assertEqual(self._stored_rows("scan-p2"), first)


if __name__ == "__main__":
    unittest.main()
