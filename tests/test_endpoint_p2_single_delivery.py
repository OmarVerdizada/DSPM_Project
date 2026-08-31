from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest import mock

from backend.app import EndpointScanRequest, _run_endpoint_scan_payload
from backend.security import Principal
from collectors.winrm_endpoint_scanner import WinRMEndpointConfig


def _record(path: str, *, content: str = "payload") -> dict:
    return {
        "source": "endpoint-winrm",
        "share": "endpoint-01",
        "path": path,
        "name": path.rsplit("\\", 1)[-1],
        "size": len(content),
        "extension": ".txt",
        "modified_at": "2026-08-28T00:00:00Z",
        "content": content,
        "sha256": "a" * 64,
    }


class _Summary:
    def __init__(self, total: int) -> None:
        self.total = total

    def to_dict(self) -> dict:
        return {
            "total_files": self.total,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": self.total,
            "sensitive_files": 0,
        }


class _Report:
    def __init__(self, snapshots: dict[str, dict] | None = None) -> None:
        self.snapshots = snapshots or {}
        self.last_scan_diagnostics: dict = {}
        self.probes: list[str] = []

    def _reuse_probe(self, object_key: str, _size: int, _mtime: str):
        self.probes.append(object_key)
        return self.snapshots.get(object_key)

    def _finalize_incremental_diagnostics(self, analyzed: list[dict]) -> None:
        errors = list(self.last_scan_diagnostics.get("incremental_fetch_errors") or [])
        reused = sum(bool(item.get("incremental_reused")) for item in analyzed)
        self.last_scan_diagnostics["incremental"] = {
            "enabled": True,
            "complete": not errors,
            "total_objects": len(analyzed),
            "new_objects": 0,
            "changed_objects": len(analyzed) - reused,
            "unclassified_fresh_objects": len(analyzed) - reused,
            "unchanged_objects": reused,
            "content_reads": len(analyzed) - reused,
            "delta_ratio": 1.0 if analyzed and not reused else 0.0,
        }

    def _build_summary(self, analyzed: list[dict]) -> _Summary:
        return _Summary(len(analyzed))


class EndpointP2SingleDeliveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = WinRMEndpointConfig(
            host="endpoint-01",
            username="scan",
            password="secret",
            paths=["documents"],
            read_content=True,
        )
        self.payload = EndpointScanRequest(
            host="endpoint-01",
            username="scan",
            password="secret",
            paths=["documents"],
            incremental_enabled=True,
            save_report=False,
        )
        self.principal = Principal(subject="analyst", role="analyst", tenant_id="tenant-p2")

    def _run(self, *, baseline: bool, scanner_factory, report: _Report | None = None) -> dict:
        report = report or _Report()
        with mock.patch("backend.app.incremental_baseline_exists", return_value=baseline) as baseline_check, \
             mock.patch("backend.app._endpoint_analysis_engine", return_value=report) as engine_factory, \
             mock.patch("backend.app.WinRMEndpointScanner", side_effect=scanner_factory), \
             mock.patch("backend.app._analyze_endpoint_records", side_effect=lambda _report, records, _job=None: records), \
             mock.patch("backend.app._apply_compliance"), \
             mock.patch("backend.app._persist_scan"):
            result = _run_endpoint_scan_payload(self.config, self.payload, self.principal)
        baseline_check.assert_called_once()
        self.assertIs(engine_factory.call_args.kwargs["baseline_available"], baseline)
        return result

    def test_cold_incremental_scan_skips_metadata_and_reads_everything_once(self) -> None:
        scan_configs: list[WinRMEndpointConfig] = []

        class Scanner:
            def __init__(self, config):
                self.config = config
                self.last_scan_diagnostics = {"visited_files": 2}
                self.last_connection_host = "endpoint-01"

            def scan(self):
                scan_configs.append(self.config)
                return [_record(r"C:\Data\one.txt"), _record(r"C:\Data\two.txt")]

        result = self._run(baseline=False, scanner_factory=Scanner)

        self.assertEqual(len(scan_configs), 1)
        self.assertTrue(scan_configs[0].read_content)
        self.assertTrue(scan_configs[0].hash_files)
        diagnostics = result["scan_diagnostics"]
        self.assertFalse(diagnostics["incremental_metadata_pass"])
        self.assertTrue(diagnostics["incremental_first_scan_single_pass"])
        self.assertEqual(diagnostics["incremental_content_fetch_commands"], 1)
        self.assertEqual(diagnostics["incremental"]["new_objects"], 2)
        self.assertEqual(diagnostics["incremental"]["unclassified_fresh_objects"], 0)

    def test_seventy_changed_paths_use_one_content_fetch_instead_of_three(self) -> None:
        metadata = [_record(fr"C:\Data\file-{index}.txt", content="") for index in range(70)]
        scan_configs: list[WinRMEndpointConfig] = []

        class Scanner:
            def __init__(self, config):
                self.config = config
                self.last_scan_diagnostics = {}
                self.last_connection_host = "endpoint-01"

            def scan(self):
                scan_configs.append(self.config)
                if not self.config.read_content:
                    return metadata
                return [_record(path) for path in self.config.paths]

        result = self._run(baseline=True, scanner_factory=Scanner)

        self.assertEqual(len(scan_configs), 2)
        self.assertFalse(scan_configs[0].read_content)
        self.assertEqual(len(scan_configs[1].paths), 70)
        self.assertEqual(result["scan_diagnostics"]["incremental_content_fetch_commands"], 1)
        self.assertEqual(len(result["files"]), 70)

    def test_changed_path_fetch_stays_bounded_at_256(self) -> None:
        metadata = [_record(fr"C:\Data\file-{index}.txt", content="") for index in range(300)]
        fetched_batches: list[list[str]] = []

        class Scanner:
            def __init__(self, config):
                self.config = config
                self.last_scan_diagnostics = {}
                self.last_connection_host = "endpoint-01"

            def scan(self):
                if not self.config.read_content:
                    return metadata
                fetched_batches.append(list(self.config.paths))
                return [_record(path) for path in self.config.paths]

        result = self._run(baseline=True, scanner_factory=Scanner)

        self.assertEqual([len(batch) for batch in fetched_batches], [256, 44])
        self.assertEqual(result["scan_diagnostics"]["incremental_content_fetch_commands"], 2)

    def test_missing_changed_record_marks_incremental_scan_incomplete(self) -> None:
        metadata = [_record(r"C:\Data\one.txt", content=""), _record(r"C:\Data\two.txt", content="")]

        class Scanner:
            def __init__(self, config):
                self.config = config
                self.last_scan_diagnostics = {}
                self.last_connection_host = "endpoint-01"

            def scan(self):
                return metadata if not self.config.read_content else [_record(r"C:\Data\one.txt")]

        result = self._run(baseline=True, scanner_factory=Scanner)

        diagnostics = result["scan_diagnostics"]
        self.assertIn("MissingChangedRecords", diagnostics["incremental_fetch_errors"])
        self.assertEqual(diagnostics["incremental_missing_changed_paths"], [r"C:\Data\two.txt"])
        self.assertFalse(diagnostics["incremental"]["complete"])
        missing = next(item for item in result["files"] if item["path"].endswith("two.txt"))
        self.assertIn("could not be fetched", missing["scan_error"])

    def test_changed_archive_children_survive_metadata_merge(self) -> None:
        archive_path = r"C:\Data\bundle.zip"
        metadata = [{**_record(archive_path, content=""), "extension": ".zip"}]
        archive_child = _record(archive_path + "::inside.txt")

        class Scanner:
            def __init__(self, config):
                self.config = config
                self.last_scan_diagnostics = {}
                self.last_connection_host = "endpoint-01"

            def scan(self):
                if not self.config.read_content:
                    return metadata
                return [archive_child, {**_record(archive_path), "extension": ".zip"}]

        result = self._run(baseline=True, scanner_factory=Scanner)

        self.assertEqual({item["path"] for item in result["files"]}, {archive_path, archive_child["path"]})
        child = next(item for item in result["files"] if "::" in item["path"])
        self.assertTrue(child["reuse_key"].endswith("C:/Data/bundle.zip::inside.txt"))


if __name__ == "__main__":
    unittest.main()
