"""Phase 1 of the enterprise database roadmap (DB-02): recovery machinery.

The encrypted-backup format must round-trip byte-exactly, refuse truncation,
track manifests/age, and prune deterministically. The full pg_dump/pg_restore
drill runs against a real cluster (scripts/db_restore_drill.py) and leaves
evidence in docs/database/evidence/.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from backend import backup


class BackupCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.key_patch = mock.patch.dict(
            os.environ, {"DSPM_BACKUP_KEY": __import__("cryptography.fernet", fromlist=["Fernet"]).Fernet.generate_key().decode()}
        )
        self.key_patch.start()
        self.addCleanup(self.key_patch.stop)

    def test_encrypt_decrypt_round_trips_multi_chunk_payloads(self) -> None:
        source = self.dir / "payload.bin"
        # Three chunks + a ragged tail, incompressible-ish content.
        source.write_bytes(os.urandom(backup.CHUNK_BYTES * 2 + 12345))
        encrypted = self.dir / "payload.enc"
        restored = self.dir / "payload.out"

        plain_sha, cipher_sha = backup.encrypt_file(source, encrypted)
        self.assertNotEqual(source.read_bytes()[:64], encrypted.read_bytes()[:64])
        restored_sha = backup.decrypt_file(encrypted, restored)

        self.assertEqual(restored.read_bytes(), source.read_bytes())
        self.assertEqual(plain_sha, restored_sha)
        self.assertTrue(cipher_sha)

    def test_truncated_backup_is_refused_not_silently_shortened(self) -> None:
        source = self.dir / "p.bin"
        source.write_bytes(os.urandom(100_000))
        encrypted = self.dir / "p.enc"
        backup.encrypt_file(source, encrypted)
        clipped = self.dir / "p.enc.cut"
        clipped.write_bytes(encrypted.read_bytes()[:-20])

        with self.assertRaisesRegex(ValueError, "Truncated backup"):
            backup.decrypt_file(clipped, self.dir / "p.out")

    def test_manifest_age_and_prune(self) -> None:
        def manifest(name: str, age_minutes: int) -> None:
            created = datetime.now(timezone.utc) - timedelta(minutes=age_minutes)
            payload = self.dir / f"{name}.dump.enc"
            payload.write_bytes(b"x")
            (self.dir / f"{name}{backup.MANIFEST_SUFFIX}").write_text(json.dumps({
                "created_at": created.isoformat(), "file": payload.name, "table_counts": {},
            }))

        manifest("sentro_a", 300)
        manifest("sentro_b", 200)
        manifest("sentro_c", 5)

        age = backup.latest_backup_age_seconds(self.dir)
        self.assertIsNotNone(age)
        self.assertLess(abs(age - 300), 30, "age must track the NEWEST manifest")

        removed = backup.prune_backups(keep=1, directory=self.dir)
        self.assertEqual(removed, 2)
        self.assertEqual(len(backup.list_manifests(self.dir)), 1)
        self.assertFalse((self.dir / "sentro_a.dump.enc").exists())

    def test_production_requires_an_explicit_key(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_BACKUP_KEY": ""}):
            with mock.patch.object(backup, "_IS_PRODUCTION", True):
                with self.assertRaisesRegex(RuntimeError, "DSPM_BACKUP_KEY"):
                    backup.backup_key()


if __name__ == "__main__":
    unittest.main()
