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
            walk_local_path=True,
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


class AStoppedCacheIsNeverSilentTest(_EstateTest):
    """A cache that stops working must not stop quietly (B1 review, 2026-09-14).

    Damage used to be noticed only while the file was being opened. Pages damaged
    after that turned lookups into misses and batch writes into no-ops - for every
    scan, with nothing in any report to say so.
    """

    def _index_path(self) -> Path:
        return self.cache / engine_module.META_INDEX_FILENAME

    def _marker(self) -> Path:
        return Path(f"{self._index_path()}{engine_module.META_INDEX_REBUILD_MARKER_SUFFIX}")

    def _damage_every_page_after_the_schema(self) -> None:
        path = self._index_path()
        conn = sqlite3.connect(str(path))
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
        data = bytearray(path.read_bytes())
        page_size = int.from_bytes(data[16:18], "big")
        page_size = 65536 if page_size == 1 else page_size
        self.assertGreater(len(data), page_size, "the index is one page; there is nothing to damage")
        data[page_size:] = bytes(len(data) - page_size)
        path.write_bytes(bytes(data))

    def test_damage_found_during_a_scan_is_reported_and_the_next_scan_rebuilds(self) -> None:
        first = self._run()
        self.assertNotIn("reuse_index", first["scan_diagnostics"], "a healthy scan reports nothing")
        self._damage_every_page_after_the_schema()

        damaged = self._run()
        self.assertEqual(len(damaged["files"]), FILES, "a damaged cache failed the scan")
        health = damaged["scan_diagnostics"].get("reuse_index") or {}
        self.assertEqual(health.get("state"), "rebuild_scheduled", damaged["scan_diagnostics"])
        self.assertGreater(health.get("read_errors", 0), 0)
        self.assertTrue(self._marker().exists(), "nothing tells the next engine to rebuild")

        rebuilt = self._run()
        self.assertNotIn("reuse_index", rebuilt["scan_diagnostics"])
        self.assertFalse(self._marker().exists())
        self.assertEqual(len(self._index_rows()), FILES, "the index was not rebuilt")

    def test_a_read_only_index_stops_writing_and_counts_what_it_dropped(self) -> None:
        self._run()
        engine = DSPMDiscoveryEngine(self._config())
        with engine._meta_index_lock:
            writer = engine._meta_index_connection()
        self.assertIsNotNone(writer)
        # What SQLite hands back on Windows when another process holds the file
        # exclusively at open: a connection that cannot write, and does not say so.
        engine._meta_index_db = sqlite3.connect(
            f"file:{self._index_path().as_posix()}?mode=ro", uri=True,
            check_same_thread=False, isolation_level=None,
        )
        writer.close()
        try:
            engine._meta_pending = {"ro-1": zlib.compress(b"{}"), "ro-2": zlib.compress(b"{}")}
            engine.flush_meta_index()
            engine._meta_pending = {"ro-3": zlib.compress(b"{}")}
            engine.flush_meta_index()
        finally:
            engine.close_meta_index()
        health = engine._meta_index_health
        self.assertEqual(health["state"], "read_only")
        self.assertEqual(health["write_failures"], 1, "it kept writing to a file that cannot be written")
        self.assertEqual(health["dropped_entries"], 3)
        self.assertFalse({"ro-1", "ro-2", "ro-3"} & set(self._index_rows()))
        self.assertFalse(self._marker().exists(), "a read-only file is not a damaged one")

    def test_a_busy_index_drops_one_batch_and_the_next_one_lands(self) -> None:
        import time

        self._run()
        with patch.object(engine_module, "META_INDEX_BUSY_TIMEOUT_SECONDS", 0.2):
            engine = DSPMDiscoveryEngine(self._config())
            blocker = sqlite3.connect(str(self._index_path()), isolation_level=None)
            blocker.execute("BEGIN IMMEDIATE")
            try:
                engine._meta_pending = {"busy-1": zlib.compress(b"{}")}
                started = time.monotonic()
                engine.flush_meta_index()
                waited = time.monotonic() - started
            finally:
                blocker.execute("ROLLBACK")
                blocker.close()
            engine._meta_pending = {"busy-2": zlib.compress(b"{}")}
            engine.flush_meta_index()
            engine.close_meta_index()
        self.assertLess(waited, 3.0)
        health = engine._meta_index_health
        self.assertEqual((health["state"], health["write_failures"], health["dropped_entries"]), ("ok", 1, 1))
        rows = set(self._index_rows())
        self.assertIn("busy-2", rows)
        self.assertNotIn("busy-1", rows)

    def test_queuing_an_entry_never_waits_for_a_batch_write(self) -> None:
        """Analysis threads queue under the entries lock; the disk is not theirs to wait for."""
        import threading

        engine = DSPMDiscoveryEngine(self._config())
        entered = threading.Event()
        release = threading.Event()
        real = engine._write_meta_batch_holding_write_lock

        def slow_write(batch):
            entered.set()
            release.wait(10)
            real(batch)

        engine._write_meta_batch_holding_write_lock = slow_write
        try:
            engine._meta_pending = {"slow": zlib.compress(b"{}")}
            flusher = threading.Thread(target=engine.flush_meta_index)
            flusher.start()
            self.assertTrue(entered.wait(10))
            acquired = engine._meta_index_lock.acquire(timeout=2)
            if acquired:
                engine._meta_index_lock.release()
            release.set()
            flusher.join(10)
            self.assertTrue(acquired, "a batch write held the lock analysis threads queue entries under")
        finally:
            release.set()
            engine.close_meta_index()

    def test_a_cancelled_endpoint_scan_releases_the_index(self) -> None:
        """Collection probes the index before analysis, and a cancel can land in between."""
        import platform

        if platform.system().lower() != "windows":
            self.skipTest("local endpoint scans run only on Windows")
        from backend import app as app_module

        for runner, body in (
            (app_module._run_local_endpoint_scan_payload, "_collect_and_persist_local_endpoint"),
            (app_module._run_endpoint_scan_payload, "_collect_and_persist_remote_endpoint"),
        ):
            with self.subTest(body=body):
                engine = DSPMDiscoveryEngine(self._config())
                opened = {}

                def probe_then_cancel(*_args, **_kwargs):
                    engine._meta_index_get("any-digest")
                    opened["db"] = engine._meta_index_db is not None
                    raise RuntimeError("Scan cancelled")

                with patch.object(app_module, "_endpoint_analysis_engine", return_value=engine), \
                        patch.object(app_module, body, side_effect=probe_then_cancel), \
                        patch.object(app_module, "_is_local_endpoint_host", return_value=False):
                    with self.assertRaises(RuntimeError):
                        runner(MagicMock(host="endpoint-host"), MagicMock(incremental_enabled=False), MagicMock())
                self.assertTrue(opened.get("db"), "the probe never opened the index, so this proves nothing")
                self.assertIsNone(engine._meta_index_db, f"{body}: the index outlived a cancelled scan")
                self.assertEqual(engine._meta_index_reader_conns, [])
                self._assert_cache_dir_is_deletable()


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
