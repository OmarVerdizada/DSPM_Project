"""Track P-E: a partitioned + merged scan MUST be semantically identical to a
single-engine scan of the whole target — same findings/risk/permissions/preview
per file, same file set. Validated both for the in-process partition+merge (the
semantic core) and for the real multi-process runner.

The local scanner skips %TEMP% (it is under \\AppData\\), so the corpus lives at a
drive-root path. Windows only for the hidden-dir attribute; the parity logic is OS
-agnostic.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from backend import store
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.partition import merge_reports, plan_partitions, run_partitioned

_VOLATILE = {
    "first_seen", "last_seen", "seen_at", "timestamp", "updated_at", "last_scanned_at",
    "detector_elapsed_ms", "detector_metrics", "incremental_scan_reason", "cache_reused",
    "incremental_reused", "sla_due", "triage_score",
}


def _semantic(value):
    if isinstance(value, dict):
        return {k: _semantic(v) for k, v in value.items() if k not in _VOLATILE}
    if isinstance(value, list):
        return [_semantic(v) for v in value]
    return value


def _accuracy(report: dict) -> dict:
    return {
        str(item.get("path") or ""): {
            "findings": _semantic(item.get("findings") or []),
            "risk": _semantic(item.get("risk") or {}),
            "permissions": _semantic(item.get("permissions") or {}),
            "preview": _semantic(item.get("preview") or {}),
        }
        for item in report.get("files") or []
    }


class PartitionParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = os.path.join("C:\\" if os.name == "nt" else tempfile.gettempdir(), f"dspm_partition_{os.getpid()}")
        shutil.rmtree(cls.root, ignore_errors=True)
        files = {
            "root_secret.txt": "root contact alice@example.com\n",           # depth 0 (root loose file)
            "dept_a/a1.txt": "ssn: 123-45-6789 for review\n",
            "dept_a/nested/a2.txt": "nested email bob@example.com\n",         # depth 2 (checks max_depth offset)
            "dept_b/b1.txt": "password: hunter2value here\n",
            "dept_c/c1.txt": "card 4111 1111 1111 1111 on file\n",
        }
        for rel, content in files.items():
            p = os.path.join(cls.root, rel.replace("/", os.sep))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(content)
        # A hidden top-level dir: the single walk skips it, so the planner must too.
        hidden = os.path.join(cls.root, "hidden_dir")
        os.makedirs(hidden, exist_ok=True)
        with open(os.path.join(hidden, "h.txt"), "w", encoding="utf-8") as fh:
            fh.write("hidden email zoe@example.com\n")
        if os.name == "nt":
            ctypes.windll.kernel32.SetFileAttributesW(hidden, 0x2)  # FILE_ATTRIBUTE_HIDDEN

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.root, ignore_errors=True)

    def setUp(self) -> None:
        self._tmpdb = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        self._tmpdb.close()
        os.environ["DSPM_DB_PATH"] = self._tmpdb.name
        store.DB_PATH = Path(self._tmpdb.name)
        store.init_db()
        store.create_tenant("partition-test", "partition-test")

    def tearDown(self) -> None:
        try:
            os.unlink(self._tmpdb.name)
        except OSError:
            pass

    def _config(self) -> ScanConfig:
        # use_sample_when_empty=True is the "scan the local filesystem" flag (a
        # misnomer - there is no fake-sample injection). Cache/incremental off so
        # the comparison isolates partitioning, not reuse behavior.
        return ScanConfig(
            tenant_id="partition-test", local_path=self.root, max_depth=4,
            use_sample_when_empty=True, persistent_cache_enabled=False, incremental_enabled=False,
        )

    def _single(self) -> dict:
        return DSPMDiscoveryEngine(self._config()).run().to_dict()

    def test_planner_units_and_hidden_skip(self) -> None:
        parts = plan_partitions(self._config())
        self.assertIsNotNone(parts)
        paths = {Path(p.local_path).name for p in parts}
        # 3 real subtrees + the root-files unit; hidden_dir is NOT a unit.
        self.assertEqual(paths, {"dept_a", "dept_b", "dept_c", Path(self.root).name})
        self.assertNotIn("hidden_dir", paths)
        # subtree units get parent_depth - 1; the root-files unit is depth 0.
        depths = {Path(p.local_path).name: p.max_depth for p in parts}
        self.assertEqual(depths["dept_a"], 3)
        self.assertEqual(depths[Path(self.root).name], 0)

    def test_partitioned_serial_equals_single(self) -> None:
        single = self._single()
        # Guard against a vacuous (0-file) pass: 5 real files, hidden h.txt excluded.
        self.assertEqual(single["summary"]["total_files"], 5)
        self.assertGreater(single["summary"]["sensitive_files"], 0)
        partitioned = run_partitioned(self._config(), workers=1)  # in-process partitions + merge
        self.assertEqual(_accuracy(single), _accuracy(partitioned), "partition+merge changed findings")
        self.assertEqual(single["summary"]["total_files"], partitioned["summary"]["total_files"])
        self.assertEqual(single["summary"], partitioned["summary"])

    def test_partitioned_multiprocess_equals_single(self) -> None:
        single = self._single()
        partitioned = run_partitioned(self._config(), workers=3)  # real ProcessPoolExecutor
        self.assertTrue(partitioned["scan_diagnostics"]["partitioned"]["enabled"])
        self.assertEqual(partitioned["scan_diagnostics"]["partitioned"]["worker_processes"], 3)
        self.assertEqual(_accuracy(single), _accuracy(partitioned), "multiprocess partition scan changed findings")
        self.assertEqual(single["summary"], partitioned["summary"])

    def test_merge_recomputes_summary_and_dedups(self) -> None:
        # Two reports that both carry the same file must not double-count it.
        f = {"path": "/x/a.txt", "source": "local", "reuse_key": "local:///x/a.txt",
             "findings": [{"type": "email"}], "risk": {"level": "MEDIUM"}}
        merged = merge_reports([{"files": [f]}, {"files": [f]}], source="local")
        self.assertEqual(len(merged["files"]), 1)
        self.assertEqual(merged["summary"]["total_files"], 1)
        self.assertEqual(merged["summary"]["sensitive_files"], 1)


if __name__ == "__main__":
    unittest.main()
