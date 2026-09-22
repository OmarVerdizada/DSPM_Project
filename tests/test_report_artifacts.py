"""Encrypted content-addressed artifact tier (roadmap Phase 5, DB-07).

Report bodies were the largest thing in the database: 24 rows holding 251.6 MB,
the biggest 45 MB. They now live in an object store and the database keeps a
reference. These tests pin the properties that make that safe to do:

- a body survives the round trip and is verified by content hash on read,
- writing the same body twice stores one object (re-saves are free),
- ciphertext on disk does not contain the plaintext,
- a tenant id that is not an identifier cannot escape the store's directory,
- **erasure reaches the bodies**, and
- **backup and restore reach the bodies** - the property whose absence would
  make this whole change a recoverability regression.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from uuid import uuid4

from backend import artifacts, backup, db, store


def _report(scan_id: str, marker: str) -> dict:
    return {
        "scan_id": scan_id,
        "source": "smb",
        "scan_label": "Artifact check",
        "summary": {"total_files": 1, "high": 1},
        "files": [{
            "path": f"/share/{marker}.txt",
            "name": f"{marker}.txt",
            "risk": {"level": "HIGH", "score": 80, "reasons": ["r"], "dlp_recommendations": ["d"]},
            "findings": [{"type": "email", "risk": "HIGH", "count": 1}],
        }],
    }


class _ArtifactSandbox(unittest.TestCase):
    """Isolate the artifact root and the key so tests never touch real data."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self._env = mock.patch.dict(os.environ, {
            "DSPM_ARTIFACT_DIR": str(root / "artifacts"),
            "DSPM_LOCAL_ARTIFACT_KEY_PATH": str(root / "artifact_key"),
            "DSPM_BACKUP_DIR": str(root / "backups"),
            "DSPM_LOCAL_BACKUP_KEY_PATH": str(root / "backup_key"),
        })
        self._env.start()
        self.addCleanup(self._env.stop)
        self.tenant = f"art{uuid4().hex[:8]}"


class ObjectStore(_ArtifactSandbox):
    def test_round_trip_and_content_addressing(self) -> None:
        payload = json.dumps({"hello": "world", "n": list(range(500))})
        ref = artifacts.put_text(self.tenant, payload)
        self.assertEqual(len(ref.content_id), 64)
        self.assertEqual(artifacts.get_text(self.tenant, ref.content_id), payload)

        again = artifacts.put_text(self.tenant, payload)
        self.assertEqual(again.content_id, ref.content_id)
        self.assertEqual(artifacts.store_stats()["objects"], 1,
                         "identical content must be stored once")

    def test_ciphertext_does_not_contain_the_plaintext(self) -> None:
        secret = "TOTALLY-DISTINCTIVE-SECRET-STRING"
        ref = artifacts.put_text(self.tenant, json.dumps({"finding": secret}))
        raw = artifacts.object_path(self.tenant, ref.content_id).read_bytes()
        self.assertNotIn(secret.encode(), raw)

    def test_corrupted_object_is_detected_not_served(self) -> None:
        ref = artifacts.put_text(self.tenant, '{"a": 1}')
        other = artifacts.put_text(self.tenant, '{"b": 2}')
        path = artifacts.object_path(self.tenant, ref.content_id)
        # Swap the two objects' bytes: each file is individually valid
        # ciphertext, so only the content-id check can catch the substitution.
        path.write_bytes(artifacts.object_path(self.tenant, other.content_id).read_bytes())
        with self.assertRaises(artifacts.ArtifactCorrupted):
            artifacts.get_text(self.tenant, ref.content_id)

    def test_missing_object_is_an_explicit_error(self) -> None:
        with self.assertRaises(artifacts.ArtifactMissing):
            artifacts.get_text(self.tenant, "0" * 64)

    def test_tenant_id_cannot_escape_the_store(self) -> None:
        for hostile in ("../../etc", "a/b", "..", "", "tenant;rm -rf /"):
            with self.assertRaises(ValueError):
                artifacts.put_text(hostile, "x")

    def test_prune_removes_only_unreferenced_and_aged_objects(self) -> None:
        keep = artifacts.put_text(self.tenant, "keep me")
        drop = artifacts.put_text(self.tenant, "drop me")
        # Nothing is removed inside the grace window, even when unreferenced:
        # a body is written before the row that references it.
        self.assertEqual(artifacts.prune({(self.tenant, keep.content_id)}), 0)
        self.assertEqual(
            artifacts.prune({(self.tenant, keep.content_id)}, grace_seconds=0), 1
        )
        self.assertTrue(artifacts.exists(self.tenant, keep.content_id))
        self.assertFalse(artifacts.exists(self.tenant, drop.content_id))


class StoreIntegration(_ArtifactSandbox):
    def setUp(self) -> None:
        super().setUp()
        if db.is_postgres():
            store.create_tenant(self.tenant, "Artifact tenant")
            self.addCleanup(store.delete_tenant_with_data, self.tenant)
            return
        self._orig = store.DB_PATH
        store.DB_PATH = Path(self._tmp.name) / "artifacts.sqlite"

        def _restore() -> None:
            store.DB_PATH = self._orig

        self.addCleanup(_restore)
        from backend import migrations

        migrations.upgrade()
        store.create_tenant(self.tenant, "Artifact tenant")

    def _row(self, scan_id: str):
        with store._connect() as conn:
            return conn.execute(
                "SELECT report_json, report_ref, report_bytes FROM scan_reports "
                "WHERE tenant_id = ? AND scan_id = ?",
                (self.tenant, scan_id),
            ).fetchone()

    def test_a_saved_report_leaves_no_body_in_the_database(self) -> None:
        store.save_scan_history(self.tenant, _report("s1", "alpha"))
        row = self._row("s1")
        self.assertEqual(row["report_json"], "", "the body must not stay in the row")
        self.assertEqual(len(row["report_ref"]), 64)
        self.assertGreater(row["report_bytes"], 0)

        # And it reads back identically through the normal API.
        report = store.read_scan_report(self.tenant, "s1")
        self.assertEqual(report["scan_id"], "s1")
        self.assertEqual(report["files"][0]["name"], "alpha.txt")

    def test_reads_still_serve_rows_whose_body_is_inline(self) -> None:
        """An install mid-backfill has both shapes and must serve both."""
        with mock.patch.dict(os.environ, {"DSPM_REPORT_ARTIFACTS": "0"}):
            store.save_scan_history(self.tenant, _report("legacy", "beta"))
        row = self._row("legacy")
        self.assertEqual(row["report_ref"], "")
        self.assertNotEqual(row["report_json"], "")
        self.assertEqual(store.read_scan_report(self.tenant, "legacy")["files"][0]["name"], "beta.txt")

    def test_label_lookup_reads_through_the_reference(self) -> None:
        store.save_scan_history(self.tenant, _report("s2", "gamma"))
        found = store.read_latest_scan_report_by_label(self.tenant, "Artifact check")
        self.assertEqual(found["files"][0]["name"], "gamma.txt")

    def test_tenant_erasure_removes_the_bodies(self) -> None:
        """Erasure is only whole if it reaches the object store."""
        store.save_scan_history(self.tenant, _report("s3", "delta"))
        ref = self._row("s3")["report_ref"]
        self.assertTrue(artifacts.exists(self.tenant, ref))

        usage = store.delete_tenant_with_data(self.tenant)

        self.assertFalse(artifacts.exists(self.tenant, ref))
        self.assertEqual(usage.get("artifacts_removed"), 1)
        self.assertEqual(artifacts.store_stats()["objects"], 0)


class BackupCoversTheArtifactTier(_ArtifactSandbox):
    def test_backup_captures_and_restore_returns_every_object(self) -> None:
        bodies = [json.dumps({"report": i, "pad": "x" * 2000}) for i in range(4)]
        refs = [artifacts.put_text(self.tenant, b) for b in bodies]

        captured = backup.capture_artifacts(Path(self._tmp.name) / "set.artifacts.tar")
        self.assertEqual(captured["objects"], 4)
        self.assertTrue(captured["file"])

        with tempfile.TemporaryDirectory() as scratch:
            restored = backup.restore_artifacts(
                Path(self._tmp.name) / str(captured["file"]), Path(scratch)
            )
        self.assertEqual(restored["objects"], 4)
        self.assertEqual(restored["inventory_sha256"], captured["inventory_sha256"],
                         "the restored object set must match the captured one exactly")
        self.assertEqual(len({r.content_id for r in refs}), 4)

    def test_an_empty_store_captures_cleanly(self) -> None:
        captured = backup.capture_artifacts(Path(self._tmp.name) / "empty.artifacts.tar")
        self.assertEqual(captured["objects"], 0)
        self.assertIsNone(captured["file"])


class RestoreRefusesAnArchiveItDidNotWrite(_ArtifactSandbox):
    """M0/Q5: capture_artifacts writes regular files and nothing else.

    A member of any other kind means the archive was built by something else, and
    restore runs as the service account into the artifact directory. The check used
    to `continue` past such a member - keeping it out of the inventory while
    extraction still wrote it - and on Python 3.10/3.11 the `filter="data"` fallback
    was not there to catch it either. It is now refused outright, before anything is
    unpacked. (The floor is 3.12, so the filter is always available as well.)
    """

    def _archive(self, build) -> Path:
        import tarfile

        plain = Path(self._tmp.name) / "crafted.tar"
        with tarfile.open(plain, "w") as tar:
            build(tar, tarfile)
        encrypted = Path(self._tmp.name) / "crafted.tar.enc"
        backup.encrypt_file(plain, encrypted)
        plain.unlink()
        return encrypted

    def _refused(self, build, expected: str) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            destination = Path(scratch)
            with self.assertRaises(ValueError) as refused:
                backup.restore_artifacts(self._archive(build), destination)
            self.assertIn(expected, str(refused.exception))
            leftovers = [p.name for p in destination.iterdir() if p.suffix != ".tmp"]
            self.assertEqual(leftovers, [], "nothing may be unpacked from a refused archive")

    def test_a_symlink_member_is_refused(self) -> None:
        def build(tar, tarfile):
            link = tarfile.TarInfo("tenant/escape.enc")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../../../etc/passwd"
            tar.addfile(link)
        self._refused(build, "non-file archive member")

    def test_a_hard_link_member_is_refused(self) -> None:
        def build(tar, tarfile):
            link = tarfile.TarInfo("tenant/hard.enc")
            link.type = tarfile.LNKTYPE
            link.linkname = "tenant/real.enc"
            tar.addfile(link)
        self._refused(build, "non-file archive member")

    def test_a_device_member_is_refused(self) -> None:
        def build(tar, tarfile):
            node = tarfile.TarInfo("tenant/null.enc")
            node.type = tarfile.CHRTYPE
            node.devmajor, node.devminor = 1, 3
            tar.addfile(node)
        self._refused(build, "non-file archive member")

    def test_a_traversing_path_is_still_refused(self) -> None:
        def build(tar, tarfile):
            payload = b"x" * 16
            member = tarfile.TarInfo("../../outside.enc")
            member.size = len(payload)
            tar.addfile(member, io.BytesIO(payload))
        self._refused(build, "unsafe archive member")

    def test_one_bad_member_refuses_the_whole_archive(self) -> None:
        # A mixed archive must not be half-restored: the refusal comes before
        # extraction, so the good member is not written either.
        def build(tar, tarfile):
            payload = b"y" * 16
            good = tarfile.TarInfo("tenant/good.enc")
            good.size = len(payload)
            tar.addfile(good, io.BytesIO(payload))
            directory = tarfile.TarInfo("tenant/subdir")
            directory.type = tarfile.DIRTYPE
            tar.addfile(directory)
        self._refused(build, "non-file archive member")


if __name__ == "__main__":
    unittest.main()
