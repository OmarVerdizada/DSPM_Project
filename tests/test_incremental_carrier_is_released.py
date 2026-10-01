"""A re-scan must not carry a second copy of every file it reuses.

On an unchanged incremental re-scan - the production default - each collector
record arrived with the full prior analysis attached (`baseline_result`), the
engine deep-copied it to produce the result, and the rehydrate that refreshes the
L1 cache deep-copied the canonical findings into an in-memory cache for the rest
of the scan. Measured on 2,000 files, counting every object once: 67.5 KB per
file of prior records kept alive until the scan ended, 29.7 KB of duplicated
containers in the result, and 18.3 KB in the findings cache.

The prior analysis is now taken off the record and adopted as the result, and
the rehydrate writes to disk without keeping a copy. These tests pin that - and,
because this is the reuse path itself, that what a re-scan reuses is exactly what
it reused before.
"""

from __future__ import annotations

import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend import store
from collectors import file_scanner
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.incremental import apply_reuse_snapshot, incremental_scope_key
from discovery.parity import accuracy_projection


FILES = 8


def _make_tree(root: Path) -> None:
    for index in range(FILES):
        folder = root / f"sub{index % 2}"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"f{index}.txt").write_text(
            f"contact user{index}@example.com\ncard 4111 1111 1111 1111\npassword=secret{index}\n",
            encoding="utf-8",
        )


class _ReScanTest(unittest.TestCase):
    def setUp(self) -> None:
        self._previous_db = os.environ.get("DSPM_DB_PATH")
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.estate = self.root / "estate"
        self.cache = self.root / "cache"
        _make_tree(self.estate)
        os.environ["DSPM_DB_PATH"] = str(self.root / "carrier.sqlite")
        store.init_db()
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "carrier")
        self.scope = incremental_scope_key("local", str(self.estate), {"max_depth": 4})
        # Temp directories sit under %TEMP%, which the scanner skips on purpose.
        self.skip_patch = patch.object(file_scanner, "is_skipped_scan_path", return_value=False)
        self.owner_patch = patch.object(file_scanner, "file_owner", MagicMock(return_value="tester"))
        self.skip_patch.start()
        self.owner_patch.start()

    def tearDown(self) -> None:
        self.owner_patch.stop()
        self.skip_patch.stop()
        if self._previous_db is None:
            os.environ.pop("DSPM_DB_PATH", None)
        else:
            os.environ["DSPM_DB_PATH"] = self._previous_db
        self.temp.cleanup()

    def _config(self, **overrides) -> ScanConfig:
        probe = lambda key, size, mtime, version: store.probe_incremental_object(  # noqa: E731
            self.tenant, self.scope, key, size, mtime, version,
        )
        settings = dict(
            tenant_id=self.tenant,
            local_path=str(self.estate),
            max_depth=4,
            walk_local_path=True,
            persistent_cache_enabled=True,
            cache_dir=str(self.cache),
            incremental_scope=self.scope,
            incremental_enabled=True,
            baseline_probe=probe,
            max_workers=1,
        )
        settings.update(overrides)
        return ScanConfig(**settings)

    def _scan(self, **overrides):
        """Run a scan and also hand back the list the collector returned."""
        engine = DSPMDiscoveryEngine(self._config(**overrides))
        captured: dict = {}
        original = engine._collect_records

        def collect(record_callback=None):
            records = original(record_callback=record_callback)
            captured["records"] = records
            return records

        engine._collect_records = collect
        report = engine.run().to_dict()
        return engine, report, captured.get("records") or []

    def _full_then_saved(self) -> dict:
        _engine, first, _records = self._scan(incremental_enabled=False)
        store.save_scan_history(self.tenant, first)
        return first

    def _clear_l1(self) -> None:
        for item in self.cache.rglob("*"):
            if item.is_file():
                item.unlink()


class ReuseIsStillVerbatimTest(_ReScanTest):

    def test_a_rescan_answered_by_the_l1_index_matches_the_full_scan(self) -> None:
        first = self._full_then_saved()
        _engine, second, _records = self._scan()
        self.assertEqual(second["scan_diagnostics"]["incremental"]["sidecar_hits"], FILES)
        self.assertEqual(accuracy_projection(first), accuracy_projection(second))

    def test_a_rescan_answered_by_the_durable_baseline_matches_the_full_scan(self) -> None:
        first = self._full_then_saved()
        self._clear_l1()
        _engine, second, _records = self._scan()
        incremental = second["scan_diagnostics"]["incremental"]
        self.assertEqual(incremental["durable_baseline_hits"], FILES)
        self.assertEqual(incremental["content_reads"], 0)
        self.assertEqual(accuracy_projection(first), accuracy_projection(second))

    def test_the_generation_after_that_still_matches(self) -> None:
        """Adopting the prior record in place must not leak into the next one."""
        first = self._full_then_saved()
        _engine, second, _records = self._scan()
        store.save_scan_history(self.tenant, second)
        _engine, third, _records = self._scan()
        self.assertEqual(accuracy_projection(first), accuracy_projection(third))


class ThePriorAnalysisIsTakenNotCopiedTest(_ReScanTest):

    def test_the_reused_result_is_the_prior_record_itself(self) -> None:
        first = self._full_then_saved()
        item = first["files"][0]
        probed = store.probe_incremental_object(
            self.tenant, self.scope, item["reuse_key"], item["size"], item["modified_at"],
            first["scan_diagnostics"]["incremental"]["version_signature"],
        )
        self.assertEqual(probed["state"], "unchanged")
        record = apply_reuse_snapshot(dict(item), probed["snapshot"], item["reuse_key"])
        prior = record["baseline_result"]

        engine = DSPMDiscoveryEngine(self._config())
        try:
            result = engine._analyze_record(record)
        finally:
            engine.close_meta_index()

        self.assertIs(result, prior, "the prior analysis was copied instead of adopted")
        self.assertNotIn("baseline_result", record, "the collector record still holds the prior analysis")
        self.assertNotIn("baseline_result", result)
        self.assertEqual(result.get("findings"), item.get("findings"))

    def test_no_collected_record_still_holds_a_prior_analysis_after_a_rescan(self) -> None:
        self._full_then_saved()
        for pipeline in (True, False):
            with self.subTest(pipeline_enabled=pipeline):
                _engine, report, records = self._scan(pipeline_enabled=pipeline)
                self.assertEqual(report["scan_diagnostics"]["cache_reused_files"], FILES)
                self.assertEqual(len(records), FILES)
                holding = [
                    record.get("path") for record in records
                    if isinstance(record, dict) and record.get("baseline_result") is not None
                ]
                self.assertEqual(holding, [], "collected records kept a full prior copy alive")
                self.assertFalse(any("baseline_result" in item for item in report["files"]))


class TheRehydrateKeepsNoCopyTest(_ReScanTest):

    def test_a_durable_rescan_rewrites_the_cache_to_disk_and_keeps_none_in_memory(self) -> None:
        self._full_then_saved()
        self._clear_l1()
        engine, report, _records = self._scan()
        self.assertEqual(report["scan_diagnostics"]["incremental"]["durable_baseline_hits"], FILES)
        self.assertEqual(engine._finding_cache, {},
                         "reused findings were kept in memory for the rest of the scan")
        self.assertGreaterEqual(len(list(self.cache.glob("*.json"))), FILES,
                                "the rehydrate no longer wrote the findings cache")
        # What the rehydrate wrote is what answers the next scan.
        _engine, third, _records = self._scan()
        self.assertEqual(third["scan_diagnostics"]["incremental"]["sidecar_hits"], FILES)

    def test_an_ordinary_scan_still_uses_the_in_memory_cache(self) -> None:
        engine, _report, _records = self._scan(incremental_enabled=False)
        self.assertEqual(len(engine._finding_cache), FILES)


class AFailedReuseDoesNotStoreThePriorRecordTest(_ReScanTest):

    def test_the_error_record_does_not_carry_the_prior_analysis(self) -> None:
        """Before this change the error record kept `baseline_result`, nested,
        and the save wrote it into the asset row and the report body."""
        self._full_then_saved()
        with patch.object(DSPMDiscoveryEngine, "_reuse_analyzed_record",
                          side_effect=RuntimeError("reuse failed")):
            _engine, report, _records = self._scan()
        self.assertEqual(len(report["files"]), FILES)
        for item in report["files"]:
            self.assertNotIn("baseline_result", item)
            self.assertTrue(item.get("scan_error"))


if __name__ == "__main__":
    unittest.main()
