"""Tests for metadata-first scan cache reuse and real collection progress.

These verify the scan-pipeline stabilization: a repeat scan over unchanged
files reuses the cache and skips the expensive per-file owner lookup, content
read, full-file hash, and reclassification; a changed file is re-read; a missing
findings cache safely triggers a re-read; and collection emits real progress so
the job no longer freezes at the collection heartbeat ceiling.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from collectors import file_scanner
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from backend import jobs


def _make_tree(root: Path, n: int) -> None:
    for i in range(n):
        folder = root / f"sub{i % 3}"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"f{i}.txt").write_text(
            f"contact user{i}@example.com\npassword=secret{i}\n", encoding="utf-8"
        )


class ScanCacheReuseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.local = self.root / "data"
        self.cache = self.root / "cache"
        _make_tree(self.local, 6)
        # Temp directories are on the scanner's skip-list; disable skipping for
        # the test and stub the per-file owner subprocess so scans stay fast.
        self.skip_patch = patch.object(file_scanner, "is_skipped_scan_path", return_value=False)
        self.owner = MagicMock(return_value="tester")
        self.owner_patch = patch.object(file_scanner, "file_owner", self.owner)
        self.skip_patch.start()
        self.owner_patch.start()

    def tearDown(self) -> None:
        self.owner_patch.stop()
        self.skip_patch.stop()
        self.temp.cleanup()

    def _config(self, progress=None) -> ScanConfig:
        cfg = ScanConfig(
            tenant_id="reuse-tenant",
            local_path=str(self.local),
            walk_local_path=True,
            persistent_cache_enabled=True,
            cache_dir=str(self.cache),
            max_workers=1,
        )
        cfg.progress_callback = progress
        return cfg

    def _run(self, progress=None) -> dict:
        return DSPMDiscoveryEngine(self._config(progress)).run().to_dict()

    def test_second_scan_reuses_unchanged_files(self) -> None:
        d1 = self._run()
        self.assertEqual(d1["scan_diagnostics"]["cache_reused_files"], 0)
        self.assertTrue(d1["files"])
        d2 = self._run()
        self.assertEqual(d2["scan_diagnostics"]["cache_reused_files"], len(d2["files"]))
        self.assertTrue(all(f.get("cache_reused") for f in d2["files"]))

    def test_reuse_avoids_content_read_and_owner_calls(self) -> None:
        self._run()  # cold scan warms the cache + sidecars
        self.owner.reset_mock()
        real_reader = file_scanner.read_text_preview_and_sha256
        reader = MagicMock(side_effect=real_reader)
        with patch.object(file_scanner, "read_text_preview_and_sha256", reader):
            self._run()
        # A fully-cached scan reads no file content and makes no per-file owner
        # (ACL) subprocess calls.
        reader.assert_not_called()
        self.owner.assert_not_called()

    def test_reuse_preserves_findings_risk_and_preview(self) -> None:
        d1 = self._run()
        d2 = self._run()
        summary1 = {f["path"]: (len(f.get("findings") or []), f.get("risk", {}).get("level")) for f in d1["files"]}
        summary2 = {f["path"]: (len(f.get("findings") or []), f.get("risk", {}).get("level")) for f in d2["files"]}
        self.assertEqual(summary1, summary2)
        self.assertTrue(all((f.get("preview") or {}).get("available") for f in d2["files"]))

    def test_changed_file_is_not_reused(self) -> None:
        self._run()
        target = sorted(self.local.rglob("*.txt"))[0]
        target.write_text("nothing sensitive here now\n", encoding="utf-8")
        d = self._run()
        changed = next(f for f in d["files"] if Path(f["path"]).name == target.name)
        self.assertFalse(changed.get("cache_reused"))
        reused = sum(1 for f in d["files"] if f.get("cache_reused"))
        self.assertGreaterEqual(reused, len(d["files"]) - 1)

    def test_missing_findings_cache_triggers_safe_reread(self) -> None:
        self._run()
        # Remove findings cache files but keep the .meta.json reuse sidecars, so
        # the reuse path hits and must fall back to a re-read for correctness.
        for cache_file in self.cache.glob("*.json"):
            if not cache_file.name.endswith(".meta.json"):
                cache_file.unlink()
        d = self._run()
        self.assertTrue(any(f.get("findings") for f in d["files"]))

    def test_collection_emits_progress_and_reused_counters(self) -> None:
        self._run()
        stages: list[tuple] = []
        d = self._run(progress=lambda stage, done, total: stages.append((stage, done, total)))
        collecting = [s for s in stages if s[0] == "collecting"]
        self.assertTrue(collecting, "collection must emit progress stages")
        # reused count is carried as the 'total' field of the collecting stage
        self.assertGreater(max(t for _s, _c, t in collecting), 0)
        diag = d["scan_diagnostics"]
        self.assertIn("files_discovered", diag)
        self.assertIn("cache_reused_files", diag)
        self.assertEqual(diag["cache_reused_files"], len(d["files"]))

    def test_progress_moves_past_14_across_stages(self) -> None:
        stages: list[tuple] = []
        self._run(progress=lambda stage, done, total: stages.append((stage, done, total)))
        job = jobs.ScanJob(id="prog", tenant_id="reuse-tenant")
        peak = 0
        for stage, done, total in stages:
            jobs._update_scan_job_progress(job, stage, done, total)
            peak = max(peak, job.progress)
        self.assertGreater(peak, 14)


if __name__ == "__main__":
    unittest.main()
