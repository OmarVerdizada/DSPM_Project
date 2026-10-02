"""Backend audit, 2026-10, the scan pipeline: each defect the review found, pinned by the
behaviour that was wrong.

Local scans here walk a folder of the system temp directory, never one under the
checkout: the worktree path holds a dot-folder, and the walker treats everything under
one as hidden. The temp directory is under AppData, which the collector skips, so every
test that walks patches `is_skipped_scan_path`.
"""
from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

from backend import store
from collectors import file_scanner
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig


def _estate(root: Path, files: int, text: str = "nothing to see here\n") -> Path:
    estate = root / "estate"
    estate.mkdir()
    for index in range(files):
        (estate / f"file-{index:03d}.txt").write_text(f"{index} {text}", encoding="utf-8")
    return estate


class _LocalScanTest(unittest.TestCase):
    """A temp folder outside the checkout, walked with the collector's skip rules off."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="audit-pipeline-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.cache = self.root / "cache"
        for patcher in (patch.object(file_scanner, "is_skipped_scan_path", return_value=False),
                        patch.object(file_scanner, "file_owner", MagicMock(return_value="tester"))):
            patcher.start()
            self.addCleanup(patcher.stop)


# ---- 1: a stopped scan is never a complete one ----------------------------------------------------


class AStoppedScanIsNeverCompleteTest(_LocalScanTest):
    """A cancelled or over-budget scan returned a partial report that said
    `incremental.complete=True` whenever everything already submitted had finished: the
    pipelined path marked truncation only when it caught a future still running, and the
    local walk had no cancel hook. Saved, that report pruned every file it never analyzed."""

    def test_a_walk_asked_to_stop_stops_and_says_so(self) -> None:
        estate = _estate(self.root, 40)
        asked = {"n": 0}

        def stop_after_ten() -> bool:
            asked["n"] += 1
            return asked["n"] > 10

        diagnostics: dict = {}
        records = file_scanner.scan_directory(estate, diagnostics=diagnostics, cancel_check=stop_after_ten)
        self.assertEqual(len(records), 10, "the walk went on reading files after it was told to stop")
        self.assertTrue(diagnostics.get("walk_cancelled"))

    def test_a_scan_cancelled_while_it_walks_is_truncated_and_incomplete(self) -> None:
        estate = _estate(self.root, 80)
        cancelled = threading.Event()

        def progress(stage: str, completed: int, _total: int) -> None:
            if stage == "pipelining" and completed >= 10:
                cancelled.set()

        config = ScanConfig(
            tenant_id="audit-stop", local_path=str(estate), walk_local_path=True, max_workers=2,
            persistent_cache_enabled=False, incremental_scope="scope-stop",
            cancel_check=cancelled.is_set, progress_callback=progress,
        )
        report = DSPMDiscoveryEngine(config).run().to_dict()
        diagnostics = report["scan_diagnostics"]
        self.assertLess(len(report["files"]), 80, "the cancel never reached the scan")
        self.assertTrue(diagnostics.get("scan_truncated"), "a cancelled scan was not marked truncated")
        self.assertFalse(diagnostics["incremental"]["complete"], "a cancelled scan called itself complete")

    def test_records_the_pipeline_never_submitted_mark_the_scan_truncated(self) -> None:
        # A collector without a cancel hook - the SMB one hands over what it has - with
        # everything that was submitted already finished when the results are read.
        cancelled = threading.Event()
        finished = {"n": 0}

        def progress(stage: str, completed: int, _total: int) -> None:
            if stage == "pipelining":
                finished["n"] = completed

        config = ScanConfig(tenant_id="audit-stop", walk_local_path=False, max_workers=2,
                            persistent_cache_enabled=False, incremental_scope="scope-stop",
                            cancel_check=cancelled.is_set, progress_callback=progress)
        engine = DSPMDiscoveryEngine(config)

        def collect(record_callback=None) -> list[dict]:
            records = [
                {"source": "local", "path": str(self.root / f"r{index}.txt"), "name": f"r{index}.txt",
                 "extension": ".txt", "size": 5, "content": "hello", "modified_at": "2026-10-01T00:00:00+00:00"}
                for index in range(80)
            ]
            for index, record in enumerate(records):
                if index == 10:
                    cancelled.set()
                    # Everything submitted finishes before the results are read.
                    deadline = time.monotonic() + 30
                    while finished["n"] < 10 and time.monotonic() < deadline:
                        time.sleep(0.01)
                if record_callback is not None:
                    record_callback(record)
            engine.last_scan_diagnostics = {"mode": "test", "records": len(records)}
            return records

        engine._collect_records = collect
        report = engine.run().to_dict()
        diagnostics = report["scan_diagnostics"]
        self.assertEqual(len(report["files"]), 10)
        self.assertTrue(diagnostics.get("scan_truncated"), "70 records were never analyzed and nothing said so")
        self.assertEqual((diagnostics.get("scan_truncated_analyzed"), diagnostics.get("scan_truncated_total")), (10, 80))
        self.assertFalse(diagnostics["incremental"]["complete"])


# ---- 3: a failed analysis is read again, not replayed ---------------------------------------------


class AFailedAnalysisIsReadAgainTest(_LocalScanTest):
    """A record whose analysis raised (scan_error, detector_metrics.record_failed, no
    findings) went into the durable baseline like any other, and the next scan reused it
    as unchanged: the file stayed blind - "nothing found" - until someone modified it."""

    def setUp(self) -> None:
        super().setUp()
        self.tenant = f"audit-failed-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "audit failed analysis")
        self.estate = self.root / "estate"
        self.estate.mkdir()
        (self.estate / "contacts.txt").write_text("alice.wonder@example.com\nbob.builder@example.com\n", encoding="utf-8")
        (self.estate / "plain.txt").write_text("nothing to see here\n", encoding="utf-8")
        self.scope = f"scope-{uuid4().hex[:8]}"

    def _scan(self) -> dict:
        config = ScanConfig(
            tenant_id=self.tenant, local_path=str(self.estate), walk_local_path=True, max_workers=1,
            persistent_cache_enabled=False, incremental_enabled=True, incremental_scope=self.scope,
            baseline_probe=lambda key, size, mtime, version: store.probe_incremental_object(
                self.tenant, self.scope, key, size, mtime, version),
        )
        report = DSPMDiscoveryEngine(config).run().to_dict()
        store.save_scan_history(self.tenant, report)
        return report

    @staticmethod
    def _file(report: dict, name: str) -> dict:
        return next(item for item in report["files"] if item["name"] == name)

    def test_the_next_scan_reads_a_file_whose_analysis_failed(self) -> None:
        real = DSPMDiscoveryEngine._run_detectors

        def fails_on_contacts(engine, content, record, framework_ids):
            if record.get("name") == "contacts.txt":
                raise RuntimeError("detector crashed")
            return real(engine, content, record, framework_ids)

        with patch.object(DSPMDiscoveryEngine, "_run_detectors", fails_on_contacts):
            first = self._scan()
        failed = self._file(first, "contacts.txt")
        self.assertTrue(failed["detector_metrics"].get("record_failed"))
        self.assertEqual(failed["findings"], [])
        with store._connect() as conn:
            versions = {
                str(row["object_key"]).rsplit("\\", 1)[-1]: str(row["version_signature"])
                for row in conn.execute(
                    "SELECT object_key, version_signature FROM scan_object_baselines WHERE tenant_id = ? AND scope_key = ?",
                    (self.tenant, self.scope),
                ).fetchall()
            }
        self.assertEqual(set(versions), {"contacts.txt", "plain.txt"}, "the failed file left the scope's objects")
        self.assertEqual(versions["contacts.txt"], "", "the failed analysis was stored as reusable")
        self.assertTrue(versions["plain.txt"])

        second = self._file(self._scan(), "contacts.txt")
        self.assertNotEqual(second.get("incremental_scan_reason"), "durable_baseline_unchanged_file",
                            "the failed analysis was replayed as the file's result")
        self.assertTrue(second["findings"], "the file whose analysis failed stayed blind")

    def test_a_failed_row_an_older_build_wrote_is_not_offered_for_reuse(self) -> None:
        config = ScanConfig(tenant_id=self.tenant, local_path=str(self.estate), incremental_scope=self.scope)
        version = DSPMDiscoveryEngine(config).version_signature()
        record = {
            "source": "local", "path": str(self.estate / "contacts.txt"), "name": "contacts.txt",
            "extension": ".txt", "size": 52, "modified_at": "2026-10-01T00:00:00+00:00",
            "content_hash": "c" * 64, "findings": [], "risk": {"score": 0, "level": "NONE"},
            "scan_error": "RuntimeError", "detector_metrics": {"record_failed": True},
        }
        with store._lock, store._connect() as conn:
            conn.execute(
                "INSERT INTO scan_object_baselines (tenant_id, scope_key, object_key, asset_id, size, mtime, "
                "content_hash, version_signature, last_scan_id, last_seen_at, updated_at, snapshot_json) "
                "VALUES (?, ?, ?, 'a1', 52, ?, ?, ?, 's1', 'now', 'now', ?)",
                (self.tenant, self.scope, record["path"], record["modified_at"], record["content_hash"], version,
                 store.json.dumps(record)),
            )
        probed = store.probe_incremental_object(self.tenant, self.scope, record["path"], 52, record["modified_at"], version)
        self.assertEqual(probed["state"], "changed")

    def test_a_failed_analysis_in_the_reuse_index_is_read_again(self) -> None:
        # The L1 index was rehydrated from such a durable row by the scan that replayed it.
        config = ScanConfig(tenant_id=self.tenant, local_path=str(self.estate), persistent_cache_enabled=True,
                            cache_dir=str(self.cache), incremental_enabled=True)
        stamp = "2026-10-01T00:00:00+00:00"

        def record(name: str, **extra) -> dict:
            return {"source": "local", "path": str(self.estate / name), "name": name, "extension": ".txt",
                    "size": 52, "modified_at": stamp, "content_hash": "c" * 64, "findings": [],
                    "risk": {"score": 0, "level": "NONE"}, **extra}

        writer = DSPMDiscoveryEngine(config)
        writer._write_meta_sidecar(record("plain.txt"))
        writer._write_meta_sidecar(record("contacts.txt", scan_error="RuntimeError",
                                          detector_metrics={"record_failed": True}))
        writer.close_meta_index()
        reader = DSPMDiscoveryEngine(config)
        self.addCleanup(reader.close_meta_index)
        self.assertIsInstance(reader._reuse_probe(str(self.estate / "plain.txt"), 52, stamp), dict,
                              "the index entry was never written, so the next assertion proves nothing")
        self.assertIsNone(reader._reuse_probe(str(self.estate / "contacts.txt"), 52, stamp))


if __name__ == "__main__":
    unittest.main()
