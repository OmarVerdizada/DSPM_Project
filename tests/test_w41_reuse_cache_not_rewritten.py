"""W4.1 step 4: the reuse cache (L1) is not written on a hit.

Every unchanged file replayed from the node's reuse index wrote its entry back - serialised,
compressed and sealed again, then inserted: 6,000 inserts for an unchanged rescan of 6,000
files (amplification probe, 2026-10-08), each entry the record it had just read. The write
back exists to rehydrate the index after a failover or an evicted cache, when the replay came
from the durable baseline; a replay that came from the index leaves its entry as it is.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend import db, store
from collectors import file_scanner
from discovery import discovery_engine
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

FILES = 5
TENANT = "w41-reuse-cache"
SCOPE = "w41-reuse-cache-scope"


class TheReuseCacheIsNotRewrittenOnAHitTest(unittest.TestCase):

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.estate = self.root / "estate"
        self.estate.mkdir()
        for index in range(FILES):
            (self.estate / f"f{index}.txt").write_text(f"contact person{index}@example.com about the invoice\n",
                                                       encoding="utf-8")
        # Temp directories sit under %TEMP%, which the scanner skips on purpose.
        for patcher in (patch.object(file_scanner, "is_skipped_scan_path", return_value=False),
                        patch.object(file_scanner, "file_owner", MagicMock(return_value="tester"))):
            patcher.start()
            self.addCleanup(patcher.stop)
        if not db.is_postgres():
            original = store.DB_PATH
            store.DB_PATH = self.root / "reuse.sqlite"
            self.addCleanup(setattr, store, "DB_PATH", original)
        store.init_db()
        try:
            store.create_tenant(TENANT, TENANT)
        except Exception:  # noqa: BLE001 - already there on a shared database
            pass

    def _scan(self) -> tuple[dict, int]:
        """One scan, saved; and how many reuse-cache entries it wrote."""
        config = ScanConfig(
            tenant_id=TENANT, local_path=str(self.estate), walk_local_path=True, max_workers=1,
            persistent_cache_enabled=True, cache_dir=str(self.root / "cache"),
            incremental_enabled=True, incremental_scope=SCOPE,
            baseline_probe=lambda key, size, mtime, version: store.probe_incremental_object(
                TENANT, SCOPE, key, size, mtime, version))
        original = DSPMDiscoveryEngine._write_meta_sidecar
        written = []

        def counting(engine, record, cache_key=None):
            written.append(str(record.get("path") or ""))
            return original(engine, record, cache_key)

        with patch.object(DSPMDiscoveryEngine, "_write_meta_sidecar", counting):
            report = DSPMDiscoveryEngine(config).run().to_dict()
        store.save_scan_history(TENANT, report)
        return report["scan_diagnostics"]["incremental"], len(written)

    def _evict_the_index(self) -> None:
        for path in (self.root / "cache").rglob(f"{discovery_engine.META_INDEX_FILENAME}*"):
            path.unlink()

    def test_a_hit_writes_nothing_and_a_durable_replay_rehydrates(self) -> None:
        first, written = self._scan()
        # A read file's entry is written at collection and replaced by its analysed result.
        self.assertEqual(first["content_reads"], FILES)
        self.assertGreaterEqual(written, FILES)

        hits, written = self._scan()
        self.assertEqual((hits["sidecar_hits"], hits["content_reads"]), (FILES, 0))
        self.assertEqual(written, 0, "an entry the scan had just replayed was written back")

        self._evict_the_index()
        durable, written = self._scan()
        self.assertEqual((durable["durable_baseline_hits"], durable["content_reads"]), (FILES, 0))
        self.assertEqual(written, FILES, "a replay from the durable baseline did not rehydrate the index")

        again, written = self._scan()
        self.assertEqual((again["sidecar_hits"], again["content_reads"], written), (FILES, 0, 0))


if __name__ == "__main__":
    unittest.main()
