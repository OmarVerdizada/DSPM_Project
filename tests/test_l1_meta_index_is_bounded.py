"""The L1 reuse index must not be held, or rewritten, whole.

It used to be one JSON document, `index.json`, with an entry per file. Measured
on a production-default scan of 2,000 files: the engine held a 26.9 KB snapshot
per file for the entire scan, then merged it into the loaded prior index and
serialised the lot as one string - a traced peak of 106.8 KB per file, double
the analysis before it, and the peak of the whole scan. On disk an entry is
27.6 KB, which is about 26 GB for a million files, rewritten in full at the end
of every scan and loaded in full at the start of every incremental one.

It is a SQLite file now. These tests pin the properties that make that matter -
entries leave memory in bounded batches, a scan touches only the rows it
writes, the handle never outlives the scan - and the one that makes it safe:
what an unchanged re-scan reuses is exactly what it reused before.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import MagicMock, patch

from collectors import file_scanner
from discovery import discovery_engine as engine_module
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.parity import accuracy_projection


FILES = 9


def _make_tree(root: Path, count: int = FILES) -> None:
    for index in range(count):
        folder = root / f"sub{index % 3}"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"f{index}.txt").write_text(
            f"contact user{index}@example.com\ncard 4111 1111 1111 1111\npassword=secret{index}\n",
            encoding="utf-8",
        )


class _EstateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.local = self.root / "estate"
        self.cache = self.root / "cache"
        _make_tree(self.local)
        # Temp directories sit under %TEMP%, which the scanner skips on purpose.
        self.skip_patch = patch.object(file_scanner, "is_skipped_scan_path", return_value=False)
        self.owner_patch = patch.object(file_scanner, "file_owner", MagicMock(return_value="tester"))
        self.skip_patch.start()
        self.owner_patch.start()

    def tearDown(self) -> None:
        self.owner_patch.stop()
        self.skip_patch.stop()
        self.temp.cleanup()

    def _config(self, **overrides) -> ScanConfig:
        settings = dict(
            tenant_id="l1-index",
            local_path=str(self.local),
            use_sample_when_empty=True,
            persistent_cache_enabled=True,
            cache_dir=str(self.cache),
            max_workers=1,
        )
        settings.update(overrides)
        return ScanConfig(**settings)

    def _run(self, **overrides) -> dict:
        return DSPMDiscoveryEngine(self._config(**overrides)).run().to_dict()

    def _index_rows(self) -> dict[str, tuple[int, bytes]]:
        path = self.cache / engine_module.META_INDEX_FILENAME
        conn = sqlite3.connect(str(path))
        try:
            return {digest: (rowid, payload) for rowid, digest, payload in
                    conn.execute("SELECT rowid, digest, payload FROM entries")}
        finally:
            conn.close()

    def _assert_cache_dir_is_deletable(self) -> None:
        """Windows refuses to delete a file that is still open."""
        for item in sorted(self.cache.rglob("*"), reverse=True):
            if item.is_file():
                item.unlink()
        self.assertEqual([p for p in self.cache.rglob("*") if p.is_file()], [])


class TheIndexIsASQLiteFileTest(_EstateTest):

    def test_a_scan_writes_one_row_per_file_and_no_json_document(self) -> None:
        self._run()
        self.assertTrue((self.cache / engine_module.META_INDEX_FILENAME).exists())
        self.assertFalse((self.cache / "index.json").exists(), "the whole-document index came back")
        self.assertEqual(len(self._index_rows()), FILES)

    def test_a_stored_entry_is_the_same_payload_the_json_index_held(self) -> None:
        """Only the storage changed: every entry still carries its snapshot."""
        self._run()
        payload = json.loads(zlib.decompress(next(iter(self._index_rows().values()))[1]))
        self.assertEqual(payload.get("meta_version"), 2)
        self.assertIn("snapshot", payload)
        self.assertIn("baseline_result", payload["snapshot"],
                      "verbatim reuse depends on the prior analyzed record being in the entry")


class ReuseIsUnchangedTest(_EstateTest):

    def test_an_unchanged_rescan_reuses_every_file_from_the_index(self) -> None:
        first = self._run()
        second = self._run()
        incremental = second["scan_diagnostics"]["incremental"]
        self.assertEqual(incremental["sidecar_hits"], FILES, "the L1 index was not what answered the probe")
        self.assertEqual(second["scan_diagnostics"]["cache_reused_files"], FILES)
        self.assertEqual(accuracy_projection(first), accuracy_projection(second),
                         "reuse from the SQLite index is not verbatim")

    def test_a_changed_file_is_not_reused(self) -> None:
        self._run()
        target = sorted(self.local.rglob("*.txt"))[0]
        target.write_text("nothing sensitive here now\n", encoding="utf-8")
        second = self._run()
        changed = next(f for f in second["files"] if Path(f["path"]).name == target.name)
        self.assertFalse(changed.get("cache_reused"))
        self.assertEqual(second["scan_diagnostics"]["incremental"]["sidecar_hits"], FILES - 1)


class MemoryAndWritesAreBoundedTest(_EstateTest):

    def test_pending_entries_never_reach_the_batch_size(self) -> None:
        seen: list[int] = []
        original = DSPMDiscoveryEngine._write_meta_sidecar

        def watching(engine, record, cache_key=None):
            original(engine, record, cache_key)
            seen.append(len(engine._meta_pending))

        with patch.object(engine_module, "META_INDEX_FLUSH_BATCH", 4), \
                patch.object(DSPMDiscoveryEngine, "_write_meta_sidecar", watching):
            self._run()
        self.assertTrue(seen, "no reuse entries were produced")
        self.assertLess(max(seen), 4, f"pending grew to {max(seen)} with a batch of 4")
        self.assertEqual(len(self._index_rows()), FILES, "an entry was lost across a batch boundary")

    def test_a_scan_rewrites_only_the_rows_it_produced(self) -> None:
        """The old index merged every prior entry and wrote the lot back.

        `INSERT OR REPLACE` gives a replaced row a new rowid, so an unrelated
        entry that keeps its rowid and its bytes was provably not rewritten.
        """
        self.cache.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.cache / engine_module.META_INDEX_FILENAME))
        conn.execute("CREATE TABLE IF NOT EXISTS entries (digest TEXT PRIMARY KEY, payload BLOB NOT NULL)")
        conn.executemany(
            "INSERT INTO entries (digest, payload) VALUES (?, ?)",
            [(f"unrelated-{index:04d}", zlib.compress(b'{"meta_version": 2}')) for index in range(500)],
        )
        conn.commit()
        conn.close()
        before = {digest: row for digest, row in self._index_rows().items() if digest.startswith("unrelated-")}

        self._run()

        after = self._index_rows()
        untouched = {digest: row for digest, row in after.items() if digest.startswith("unrelated-")}
        self.assertEqual(untouched, before, "a scan rewrote index entries it did not produce")
        self.assertEqual(len(after), 500 + FILES)


class TheHandleNeverOutlivesTheScanTest(_EstateTest):

    def test_the_cache_directory_can_be_cleared_right_after_a_scan(self) -> None:
        self._run()
        self._assert_cache_dir_is_deletable()

    def test_a_failed_scan_still_releases_the_index(self) -> None:
        calls = {"n": 0}
        original = DSPMDiscoveryEngine._analyze_record_safe

        def fail_after_some(engine, record):
            calls["n"] += 1
            if calls["n"] > 3:
                raise RuntimeError("the scan died here")
            return original(engine, record)

        with patch.object(DSPMDiscoveryEngine, "_analyze_record_safe", fail_after_some):
            with self.assertRaises(RuntimeError):
                self._run(pipeline_enabled=False)
        self._assert_cache_dir_is_deletable()

    def test_a_failure_after_analysis_still_releases_the_index(self) -> None:
        """The summary runs after analysis, outside the loop that used to close."""
        with patch.object(DSPMDiscoveryEngine, "_build_summary",
                          side_effect=RuntimeError("the summary died here")):
            with self.assertRaises(RuntimeError):
                self._run()
        self.assertEqual(len(self._index_rows()), FILES,
                         "entries analysed before the failure were not written")
        self._assert_cache_dir_is_deletable()

    def test_endpoint_analysis_writes_its_entries_and_releases_the_index(self) -> None:
        """Endpoint scans drive the engine without run().

        Before this change their reuse entries accumulated in memory and were
        never written at all.
        """
        from backend.app import _analyze_endpoint_records

        records = file_scanner.normalize_records(
            file_scanner.scan_directory(str(self.local), max_depth=4)
        )
        self.assertEqual(len(records), FILES)
        engine = DSPMDiscoveryEngine(self._config())
        analyzed = _analyze_endpoint_records(engine, records)
        self.assertEqual(len(analyzed), FILES)
        self.assertEqual(len(self._index_rows()), FILES, "endpoint reuse entries were not persisted")
        self._assert_cache_dir_is_deletable()


class ReadsRunInParallelTest(_EstateTest):
    """The SMB collector probes from one thread per share being walked.

    That is min(io_workers, shares), capped at 64 - so a server with many shares
    probes from many threads at once, and a read that queues behind the write
    lock is a throughput limit that grows with the server.
    """

    def _populated_engine(self):
        self._run()
        digest = next(iter(self._index_rows()))
        engine = DSPMDiscoveryEngine(self._config())
        self.assertIsNotNone(engine._meta_index_get(digest), "the index did not answer at all")
        return engine, digest

    def test_a_read_completes_while_the_write_lock_is_held(self) -> None:
        import threading

        engine, digest = self._populated_engine()
        result = {}
        # A thread that has never read before: its first read must not queue
        # behind a write that is holding the lock.
        reader = threading.Thread(target=lambda: result.update(value=engine._meta_index_get(digest)))
        try:
            engine._meta_index_lock.acquire()
            try:
                reader.start()
                reader.join(timeout=10)
                waited = reader.is_alive()
            finally:
                engine._meta_index_lock.release()
            reader.join(timeout=10)
            self.assertFalse(waited, "a new thread's first read waited for the write lock")
            self.assertIsInstance(result.get("value"), dict)
        finally:
            engine.close_meta_index()

    def test_every_reader_connection_is_released(self) -> None:
        import threading

        engine, digest = self._populated_engine()
        answers = []
        threads = [threading.Thread(target=lambda: answers.append(engine._meta_index_get(digest)))
                   for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(len(answers), 16)
        self.assertTrue(all(isinstance(answer, dict) for answer in answers))
        self.assertGreaterEqual(len(engine._meta_index_reader_conns), 16)
        engine.close_meta_index()
        self.assertEqual(engine._meta_index_reader_conns, [])
        self._assert_cache_dir_is_deletable()


class ABrokenCacheIsNeverAFailedScanTest(_EstateTest):

    def test_a_corrupt_index_file_is_rebuilt(self) -> None:
        self.cache.mkdir(parents=True, exist_ok=True)
        (self.cache / engine_module.META_INDEX_FILENAME).write_bytes(b"this is not a database" * 50)
        report = self._run()
        self.assertEqual(len(report["files"]), FILES)
        self.assertEqual(len(self._index_rows()), FILES)

    def test_an_unusable_cache_location_degrades_to_a_miss(self) -> None:
        blocker = self.root / "not-a-directory"
        blocker.write_text("occupied", encoding="utf-8")
        report = self._run(cache_dir=str(blocker / "cache"))
        self.assertEqual(len(report["files"]), FILES)
        self.assertTrue(all(f.get("findings") for f in report["files"]))


class TheOldIndexIsRetiredCarefullyTest(_EstateTest):

    def test_a_legacy_whole_document_index_is_removed(self) -> None:
        self.cache.mkdir(parents=True, exist_ok=True)
        legacy = self.cache / "index.json"
        legacy.write_text(json.dumps({"index_version": 1, "entries": {"x": {}}}, ensure_ascii=False),
                          encoding="utf-8")
        self._run()
        self.assertFalse(legacy.exists(), "the obsolete index was left behind")

    def test_an_unrelated_file_named_index_json_is_left_alone(self) -> None:
        self.cache.mkdir(parents=True, exist_ok=True)
        foreign = self.cache / "index.json"
        foreign.write_text('{"owner": "someone else", "entries": []}', encoding="utf-8")
        self._run()
        self.assertTrue(foreign.exists(), "a file that is not the old index was deleted")


if __name__ == "__main__":
    unittest.main()
