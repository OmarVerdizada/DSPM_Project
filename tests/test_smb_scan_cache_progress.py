"""SMB collection progress + metadata-first cache reuse tests.

Runs the real SMB walk (`SMBScanner._walk_share`) against a fake in-memory SMB
connection, so no pysmb dependency or live server is needed. Verifies:

* collection emits real progress with discovered/reused counters (past the old
  heartbeat-only ceiling);
* an unchanged second scan reuses the metadata sidecars and skips the remote
  content read, full-file hash, and per-file ACL lookup;
* a changed file (different mtime) is fully re-read and reclassified;
* reuse is fail-closed: a sidecar without its findings-cache entry misses, so
  the file is re-read while the connection is still open (SMB has no
  post-collection re-read fallback).
"""
from __future__ import annotations

import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from collectors.smb_scanner import SMBScanner
from discovery import scan_cache
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from backend import jobs

FILE_COUNT = 60
_MTIME = 1751500000.0


class _Entry:
    def __init__(self, filename: str, size: int = 0, is_dir: bool = False, mtime: float = _MTIME):
        self.filename = filename
        self.isDirectory = is_dir
        self.isHidden = False
        self.isSystem = False
        self.file_size = size
        self.create_time = _MTIME - 1000
        self.last_write_time = mtime


class _FakeShare:
    name = "data"


class _FakeConnection:
    """Minimal stand-in for pysmb's SMBConnection used by the walker."""

    def __init__(self, contents: dict[str, bytes], mtimes: dict[str, float]):
        self.contents = contents
        self.mtimes = mtimes
        self.retrieve_calls = 0

    def listShares(self):
        return [_FakeShare()]

    def listPath(self, share_name: str, folder: str):
        entries = [_Entry(".", is_dir=True), _Entry("..", is_dir=True)]
        for path, data in sorted(self.contents.items()):
            name = path.rsplit("/", 1)[-1]
            entries.append(_Entry(name, size=len(data), mtime=self.mtimes.get(path, _MTIME)))
        return entries

    def retrieveFileFromOffset(self, share_name: str, path: str, buffer, offset: int = 0, max_length: int = 0):
        self.retrieve_calls += 1
        data = self.contents.get(path, b"")
        chunk = data[offset:offset + max_length] if max_length else data[offset:]
        buffer.write(chunk)

    def close(self):
        return None


class SmbScanCacheProgressTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.cache = Path(self.temp.name) / "cache"
        self.contents = {
            f"/file{i:02d}.txt": f"user{i}@example.com\npassword=secret{i}\n".encode("utf-8")
            for i in range(FILE_COUNT)
        }
        self.mtimes = {path: _MTIME for path in self.contents}
        self.fake = _FakeConnection(self.contents, self.mtimes)

        fake = self.fake

        def _connect(scanner_self) -> bool:
            scanner_self.connection = fake
            scanner_self.server_used = "testserver"
            return True

        self.acl = MagicMock(return_value={"owner": "tester", "principals": [], "permissions": []})
        self.batch_acl = MagicMock(
            side_effect=lambda _share, paths: {
                path: {"owner": "tester", "principals": [], "permissions": []}
                for path in paths
            }
        )
        self.connect_patch = patch.object(SMBScanner, "connect", _connect)
        self.acl_patch = patch.object(SMBScanner, "_acl_for_path", self.acl)
        self.batch_acl_patch = patch.object(SMBScanner, "_acl_batch_for_paths", self.batch_acl)
        self.connect_patch.start()
        self.acl_patch.start()
        self.batch_acl_patch.start()

    def tearDown(self) -> None:
        self.batch_acl_patch.stop()
        self.acl_patch.stop()
        self.connect_patch.stop()
        self.temp.cleanup()

    def _run(self, progress=None) -> dict:
        cfg = ScanConfig(
            tenant_id="smb-tenant",
            server="testserver",
            persistent_cache_enabled=True,
            cache_dir=str(self.cache),
            max_workers=1,
        )
        cfg.progress_callback = progress
        return DSPMDiscoveryEngine(cfg).run().to_dict()

    def test_smb_collection_emits_progress_with_counters_past_heartbeat(self) -> None:
        stages: list[tuple] = []
        data = self._run(progress=lambda stage, done, total: stages.append((stage, done, total)))
        collecting = [s for s in stages if s[0] == "collecting"]
        self.assertTrue(collecting, "SMB collection must emit real progress stages")
        self.assertEqual(max(c for _s, c, _t in collecting), FILE_COUNT)
        job = jobs.ScanJob(id="smb-prog", tenant_id="smb-tenant")
        for stage, done, total in stages:
            jobs._update_scan_job_progress(job, stage, done, total)
        self.assertGreater(job.progress, 14)
        diag = data["scan_diagnostics"]
        self.assertEqual(diag["files_discovered"], FILE_COUNT)
        self.assertEqual(diag["cache_reused_files"], 0)

    def test_second_smb_scan_reuses_unchanged_files_and_skips_heavy_work(self) -> None:
        d1 = self._run()
        self.assertEqual(len(d1["files"]), FILE_COUNT)
        retrieve_after_cold = self.fake.retrieve_calls
        self.assertGreater(retrieve_after_cold, 0)
        self.acl.reset_mock()
        self.batch_acl.reset_mock()

        d2 = self._run()
        # No remote content read / hash chunk fetch or ACL acquisition happened
        # for unchanged files.
        self.assertEqual(self.fake.retrieve_calls, retrieve_after_cold)
        self.acl.assert_not_called()
        self.assertTrue(all(f.get("cache_reused") for f in d2["files"]))
        self.batch_acl.assert_not_called()
        self.assertEqual(d2["scan_diagnostics"]["cache_reused_files"], FILE_COUNT)
        # Findings, risk, owner, and preview survive reuse unchanged.
        s1 = {f["path"]: (len(f.get("findings") or []), f.get("risk", {}).get("level"), f.get("owner")) for f in d1["files"]}
        s2 = {f["path"]: (len(f.get("findings") or []), f.get("risk", {}).get("level"), f.get("owner")) for f in d2["files"]}
        self.assertEqual(s1, s2)
        self.assertTrue(all((f.get("preview") or {}).get("available") for f in d2["files"]))

    def test_changed_smb_file_is_reread_and_reclassified(self) -> None:
        self._run()
        target = "/file00.txt"
        self.contents[target] = b"nothing sensitive anymore\n"
        self.mtimes[target] = _MTIME + 999
        d = self._run()
        changed = next(f for f in d["files"] if f["path"] == target)
        self.assertFalse(changed.get("cache_reused"))
        self.assertEqual(d["scan_diagnostics"]["cache_reused_files"], FILE_COUNT - 1)
        self.assertEqual(len(changed.get("findings") or []), 0)

    def test_missing_findings_cache_fails_closed_and_rereads(self) -> None:
        self._run()
        # Remove the findings cache but keep the reuse sidecars: the probe must
        # miss (fail-closed) so SMB files are fully re-read, never silently
        # emitted with empty findings.
        entries = list(scan_cache.tenant_cache_dir(self.cache, "smb-tenant").glob(f"*{scan_cache.FINDINGS_SUFFIX}"))
        self.assertTrue(entries, "the first scan wrote no findings entries, so this proves nothing")
        for cache_file in entries:
            cache_file.unlink()
        retrieve_before = self.fake.retrieve_calls
        d = self._run()
        self.assertGreater(self.fake.retrieve_calls, retrieve_before)
        self.assertFalse(any(f.get("cache_reused") for f in d["files"]))
        self.assertTrue(all(f.get("findings") for f in d["files"]))


if __name__ == "__main__":
    unittest.main()
