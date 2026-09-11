"""The estate write must not hold the whole estate in memory to do its work.

B0 stopped this path asking the database one row at a time. It still asked
Python for everything at once: `normalize_scan_report` returned four lists
covering every file in the scan, and one of the things it put in them was a
re-serialised copy of every record. Measured at 6,000 files that projection cost
6.17 KB per file and was alive at the same time as the report it was built from.

These tests pin the structure rather than the megabytes. A memory assertion
would measure the machine that happens to run it; what matters is that no code
path builds a list proportional to the estate, and that walking the scan in
batches produces exactly what walking it in one pass did.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
import uuid

from backend import store
from backend.domain import (
    iter_normalized_assets,
    iter_normalized_chunks,
    normalize_scan_report,
    scan_run_from_report,
)


def _report(scan_id: str, files: int, *, findings_per_file: int = 2) -> dict:
    rows = []
    for index in range(files):
        rows.append({
            "path": f"//fs01/share/dir{index % 20}/f{index}.txt",
            "name": f"f{index}.txt", "extension": ".txt", "size": 1000 + index,
            "source": "smb", "share": "share", "owner": "CORP/svc",
            "content_status": "scanned", "sha256": f"{index:064x}",
            "modified_at": "2026-01-01T00:00:00Z",
            "risk": {"level": ("HIGH", "MEDIUM", "LOW", "CRITICAL")[index % 4],
                     "score": 40 + index % 50, "reasons": ["r"], "dlp_recommendations": ["a"]},
            "findings": [
                {"type": ("credit_card", "email", "password")[which % 3],
                 "finding_id": f"s-f{index}-{which}", "risk": "HIGH",
                 "count": 1 + which, "occurrence_count": 1 + which,
                 "description": "d", "samples": ["x"], "category": "pii",
                 "framework": "gdpr"}
                for which in range(findings_per_file)
            ],
        })
    return {
        "scan_id": scan_id, "timestamp": "2026-09-11T00:00:00Z", "source": "smb",
        "scan_label": "streamed",
        "summary": {"total_files": files, "critical": 0, "high": files,
                    "medium": 0, "low": 0, "sensitive_files": files},
        "files": rows,
    }


class ProjectionComesOutInBatchesTest(unittest.TestCase):

    def test_the_batches_reassemble_into_the_single_pass(self):
        report = _report("s1", 250)
        whole = normalize_scan_report("t", report).to_dict()

        parts = {"assets": [], "asset_versions": [], "findings": [], "occurrences": []}
        for _records, piece in iter_normalized_chunks("t", report, chunk_files=40):
            for key in parts:
                parts[key].extend(item.to_dict() for item in getattr(piece, key))

        for key, value in parts.items():
            self.assertEqual(value, whole[key], f"{key} differed once the walk was batched")

    def test_no_batch_is_larger_than_asked_for(self):
        report = _report("s1", 250)
        sizes = [len(records) for records, _piece in iter_normalized_chunks("t", report, chunk_files=40)]
        self.assertEqual(sum(sizes), 250)
        self.assertTrue(all(size <= 40 for size in sizes), sizes)
        self.assertGreater(len(sizes), 1, "a 250-file report should not fit in one batch of 40")

    def test_a_repeated_path_behaves_the_same_at_every_batch_size(self):
        """Identity state has to survive a batch boundary.

        A report that lists the same path twice yields one asset and one
        finding. If the sets tracking that were rebuilt per batch, splitting the
        copies apart would silently produce two of each.
        """

        report = _report("s1", 3)
        report["files"].append(json.loads(json.dumps(report["files"][0])))
        whole = normalize_scan_report("t", report).to_dict()

        for size in (1, 2, 3, 4, 50):
            parts = {"assets": [], "findings": [], "occurrences": []}
            for _records, piece in iter_normalized_chunks("t", report, chunk_files=size):
                for key in parts:
                    parts[key].extend(item.to_dict() for item in getattr(piece, key))
            for key, value in parts.items():
                self.assertEqual(value, whole[key], f"{key} differed at chunk_files={size}")

    def test_an_empty_report_yields_nothing_but_still_has_a_run(self):
        self.assertEqual(list(iter_normalized_chunks("t", {"scan_id": "s"})), [])
        self.assertEqual(scan_run_from_report("t", {"scan_id": "s"}).id, "s")
        # The run is readable without walking a single file, which is what lets
        # the write start before the estate has been seen.
        run = scan_run_from_report("t", _report("s1", 10))
        self.assertEqual(run.total_files, 10)
        self.assertEqual(run.id, "s1")

    def test_the_asset_iterator_matches_the_projection(self):
        report = _report("s1", 120)
        expected = [asset.to_dict() for asset in normalize_scan_report("t", report).assets]
        streamed = [asset.to_dict() for asset in iter_normalized_assets("t", report, chunk_files=25)]
        self.assertEqual(streamed, expected)


class TheWriteDoesNotBuildTheWholeEstateTest(unittest.TestCase):
    """A structural guard, not a memory measurement.

    If `_write_normalized_rows` ever goes back to asking for the whole estate at
    once, this fails - because the whole-estate entry point is made to explode.
    """

    def setUp(self):
        self._previous = os.environ.get("DSPM_DB_PATH")
        self._dir = tempfile.TemporaryDirectory()
        os.environ["DSPM_DB_PATH"] = os.path.join(self._dir.name, "streamed.sqlite")
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.init_db()

    def tearDown(self):
        if self._previous is None:
            os.environ.pop("DSPM_DB_PATH", None)
        else:
            os.environ["DSPM_DB_PATH"] = self._previous
        self._dir.cleanup()

    def test_saving_a_scan_never_calls_the_whole_estate_projection(self):
        import backend.domain as domain
        import backend.domain.models as models

        def _refuse(*_args, **_kwargs):
            raise AssertionError(
                "the estate write built the whole projection at once; "
                "it must consume iter_normalized_chunks"
            )

        originals = (domain.normalize_scan_report, models.normalize_scan_report)
        domain.normalize_scan_report = _refuse
        models.normalize_scan_report = _refuse
        try:
            store.save_scan_history(self.tenant, _report("s1", 120))
        finally:
            domain.normalize_scan_report, models.normalize_scan_report = originals

        with store._connect() as conn:
            assets = conn.execute(
                "SELECT COUNT(*) AS n FROM assets WHERE tenant_id = ?", (self.tenant,)
            ).fetchone()["n"]
            findings = conn.execute(
                "SELECT COUNT(*) AS n FROM findings WHERE tenant_id = ?", (self.tenant,)
            ).fetchone()["n"]
        self.assertEqual(assets, 120)
        self.assertEqual(findings, 240)

    def test_the_rows_are_the_same_whatever_the_batch_size(self):
        """Batch size is a memory knob and must not be a correctness knob."""

        import backend.domain.models as models

        tables = ("assets", "findings", "asset_versions",
                  "finding_occurrences", "finding_index")
        # `scan_reports` has to go too: its presence is what tells the save it
        # is re-saving an existing scan rather than recording a new one, and a
        # re-save deliberately leaves the estate alone.
        cleared = tables + ("scan_reports", "scan_runs")
        # One tenant throughout: an asset's identity is derived from it, so a
        # different tenant would change every id and the comparison would only
        # be measuring that.
        fingerprints = []
        for size in (7, 50, 10_000):
            with store._connect() as conn:
                for table in cleared:
                    conn.execute(f"DELETE FROM {table} WHERE tenant_id = ?", (self.tenant,))
            original = models.PROJECTION_CHUNK
            models.PROJECTION_CHUNK = size
            try:
                store.save_scan_history(self.tenant, _report("s1", 120))
            finally:
                models.PROJECTION_CHUNK = original
            with store._connect() as conn:
                rows = []
                for table in tables:
                    table_rows = conn.execute(
                        f"SELECT * FROM {table} WHERE tenant_id = ?", (self.tenant,)
                    ).fetchall()
                    rows.append(sorted(
                        json.dumps([str(value) for value in tuple(row)]) for row in table_rows
                    ))
            fingerprints.append(rows)
        self.assertTrue(all(any(part) for part in fingerprints[0]), "nothing was written")

        self.assertEqual(fingerprints[0], fingerprints[1], "batch size 7 and 50 disagreed")
        self.assertEqual(fingerprints[1], fingerprints[2], "batching disagreed with one pass")


if __name__ == "__main__":
    unittest.main()
