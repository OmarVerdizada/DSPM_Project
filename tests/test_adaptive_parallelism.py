from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

from collectors import ocr
from collectors.file_scanner import scan_directory
from collectors.smb_scanner import SMBConfig, SMBScanner, _SmbConnectionLost
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.parallelism import (
    MAX_ANALYSIS_WORKERS,
    resolve_parallelism,
)


class ParallelismPolicyTests(unittest.TestCase):
    def test_auto_policy_uses_cpu_count_and_is_bounded(self) -> None:
        env = {
            "DSPM_ANALYSIS_WORKERS": "",
            "DSPM_IO_WORKERS": "",
            "DSPM_PIPELINE_BUFFER": "",
            "DSPM_PIPELINE_ENABLED": "1",
        }
        with mock.patch.dict(os.environ, env, clear=False), \
             mock.patch("discovery.parallelism.os.cpu_count", return_value=6):
            plan = resolve_parallelism()

        self.assertEqual(plan.analysis_workers, 6)
        self.assertEqual(plan.analysis_source, "auto_cpu")
        # I/O workers are latency-bound (an SMB file is ~3 network round trips),
        # so the auto policy budgets 6x CPU rather than 2x: at 2x the link sat
        # idle and collection was the wall-clock floor of every remote scan.
        self.assertEqual(plan.io_workers, 36)
        self.assertEqual(plan.ocr_workers, 1)
        self.assertGreaterEqual(plan.pipeline_buffer, plan.analysis_workers * 2)
        self.assertTrue(plan.pipeline_enabled)

    def test_explicit_and_environment_values_are_clamped(self) -> None:
        env = {
            "DSPM_ANALYSIS_WORKERS": "3",
            "DSPM_PIPELINE_BUFFER": "999999",
            "DSPM_PIPELINE_ENABLED": "0",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            from_env = resolve_parallelism()
            explicit = resolve_parallelism(analysis_workers=999)

        self.assertEqual(from_env.analysis_workers, 3)
        self.assertEqual(from_env.analysis_source, "environment")
        self.assertFalse(from_env.pipeline_enabled)
        self.assertEqual(explicit.analysis_workers, MAX_ANALYSIS_WORKERS)
        self.assertEqual(explicit.analysis_source, "scan_config")


class CollectorPipelineTests(unittest.TestCase):
    @staticmethod
    def _record(name: str) -> dict:
        return {
            "source": "local",
            "path": name,
            "name": name,
            "extension": ".txt",
            "size": 1,
            "content": name,
            "acl": {},
        }

    def test_local_collector_emits_every_returned_record(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            root = Path(temp_dir)
            (root / "a.txt").write_text("a", encoding="utf-8")
            (root / "b.txt").write_text("b", encoding="utf-8")
            emitted: list[dict] = []

            records = scan_directory(
                root,
                allowed_extensions=[".txt"],
                extension_filter_enabled=True,
                record_callback=emitted.append,
            )

        self.assertEqual(
            {record["path"] for record in emitted},
            {record["path"] for record in records},
        )
        self.assertEqual(len(emitted), len(records))

    def test_pipeline_overlaps_collection_is_bounded_and_preserves_order(self) -> None:
        records = [self._record(name) for name in ("a.txt", "b.txt", "c.txt", "d.txt")]
        engine = DSPMDiscoveryEngine(
            ScanConfig(
                walk_local_path=False,
                max_workers=2,
                pipeline_buffer=2,
                persistent_cache_enabled=False,
            )
        )

        def analyze(record: dict) -> dict:
            if record["name"] == "a.txt":
                time.sleep(0.06)
            else:
                time.sleep(0.005)
            return {"name": record["name"], "risk": {"level": "LOW"}}

        def collect(record_callback=None) -> list[dict]:
            self.assertIsNotNone(record_callback)
            for record in records:
                record_callback(record)
            # Give at least one analysis task time to finish before collection
            # returns, proving the two stages overlap.
            time.sleep(0.03)
            return records

        with mock.patch.object(engine, "_collect_records", side_effect=collect), \
             mock.patch.object(engine, "_analyze_record_safe", side_effect=analyze):
            report = engine.run()

        self.assertEqual([item["name"] for item in report.files], [item["name"] for item in records])
        pipeline = report.scan_diagnostics["pipeline"]
        self.assertTrue(pipeline["collection_analysis_overlap"])
        self.assertLessEqual(pipeline["peak_in_flight"], 2)
        self.assertEqual(pipeline["records_selected"], len(records))
        self.assertEqual(report.scan_diagnostics["worker_pool"]["max_workers"], 2)

    def test_pipeline_never_submits_its_nested_cache_sidecars(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            root = Path(temp_dir)
            cache = root / "cache"
            (root / "a.txt").write_text("alpha", encoding="utf-8")
            (root / "b.txt").write_text("beta", encoding="utf-8")
            config = ScanConfig(
                local_path=str(root),
                cache_dir=str(cache),
                max_workers=2,
                pipeline_buffer=2,
            )

            DSPMDiscoveryEngine(config).run()
            second = DSPMDiscoveryEngine(config).run()

        self.assertEqual(second.summary.total_files, 2)
        self.assertEqual(second.scan_diagnostics["pipeline"]["records_submitted"], 2)


class OcrConcurrencyTests(unittest.TestCase):
    def test_inference_is_serialized_across_callers(self) -> None:
        active = 0
        peak = 0
        lock = threading.Lock()

        def fake_engine(_image):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            return []

        with mock.patch.object(ocr, "_timeout_seconds", return_value=1.0):
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda _: ocr._run_ocr_with_budget(fake_engine, object()), range(2)))

        self.assertEqual(results, [[], []])
        self.assertEqual(peak, 1)
        self.assertEqual(ocr.ocr_status()["inference_workers"], 1)


class SmbPipelineCallbackTests(unittest.TestCase):
    def test_failed_share_attempt_emits_only_the_successful_retry(self) -> None:
        emitted: list[dict] = []
        record = {
            "source": "smb",
            "share": "Docs",
            "path": "/ok.txt",
            "name": "ok.txt",
            "size": 2,
            "sha256": "abc",
        }
        scanner = SMBScanner(
            SMBConfig(server="fs", record_callback=emitted.append)
        )

        class Share:
            name = "Docs"

        class Connection:
            def listShares(self):
                return [Share()]

            def close(self):
                return None

        connection = Connection()

        def connect() -> bool:
            scanner.connection = connection
            scanner.server_used = "fs"
            return True

        attempts = iter([_SmbConnectionLost("Docs", "reset"), [record]])

        def walk_share(*_args, **_kwargs):
            result = next(attempts)
            if isinstance(result, Exception):
                raise result
            return result

        scanner.connect = connect  # type: ignore[assignment]
        scanner._reconnect = lambda: True  # type: ignore[assignment]
        scanner._walk_share = walk_share  # type: ignore[assignment]

        result = scanner.scan()

        self.assertEqual(result, [record])
        self.assertEqual(emitted, [record])


if __name__ == "__main__":
    unittest.main()
