"""M1 (Phase 1.1): the dev JWT-signing key and evidence-HMAC key must live
OUTSIDE the data/ (DB/backup) directory, so a data/ backup carries no key
material. The JWT secret rotates (it was cross-tree duplicated); the evidence key
migrates (preserved, for fingerprint consistency)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from backend import security, store
from classification.compliance import evidence_keys

DATA_DIR = store.DB_PATH.parent.resolve()


class KeyRelocationTests(unittest.TestCase):
    def test_jwt_dev_key_resolves_outside_the_data_dir(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            keyfile = Path(d) / "sub" / "jwt_secret"
            with mock.patch.dict(os.environ, {"DSPM_LOCAL_JWT_SECRET_PATH": str(keyfile), "DSPM_ENV": "local"}):
                os.environ.pop("DSPM_SECRET_KEY", None)
                key = security._load_secret_key()
            self.assertTrue(keyfile.exists())
            self.assertEqual(key, keyfile.read_text(encoding="utf-8").strip())
            self.assertNotIn(DATA_DIR, keyfile.resolve().parents)

    def test_evidence_dev_key_resolves_outside_the_data_dir(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            keyfile = Path(d) / "evidence_hmac_key"
            with mock.patch.dict(os.environ, {"DSPM_LOCAL_EVIDENCE_KEY_PATH": str(keyfile), "DSPM_ENV": "local"}):
                os.environ.pop("DSPM_EVIDENCE_HMAC_KEY", None)
                key = evidence_keys._load_or_generate_dev_key()
            self.assertTrue(keyfile.exists())
            self.assertEqual(key, keyfile.read_text(encoding="utf-8").strip())
            self.assertNotIn(DATA_DIR, keyfile.resolve().parents)

    def test_jwt_secret_is_rotated_and_legacy_removed(self) -> None:
        with tempfile.TemporaryDirectory() as base, tempfile.TemporaryDirectory() as newdir:
            legacy = Path(base) / "data" / ".jwt_secret"
            legacy.parent.mkdir(parents=True)
            legacy.write_text("old-duplicated-secret", encoding="utf-8")
            newpath = Path(newdir) / "jwt_secret"
            with mock.patch.object(security, "BASE_DIR", Path(base)), \
                 mock.patch.dict(os.environ, {"DSPM_LOCAL_JWT_SECRET_PATH": str(newpath), "DSPM_ENV": "local"}):
                os.environ.pop("DSPM_SECRET_KEY", None)
                key = security._load_secret_key()
            self.assertNotEqual(key, "old-duplicated-secret")  # rotated, not migrated
            self.assertTrue(newpath.exists())
            self.assertFalse(legacy.exists())  # old copy removed from data/

    def test_evidence_key_is_migrated_and_legacy_removed(self) -> None:
        with tempfile.TemporaryDirectory() as base, tempfile.TemporaryDirectory() as newdir:
            legacy = Path(base) / "data" / evidence_keys._KEY_FILENAME
            legacy.parent.mkdir(parents=True)
            legacy.write_text("legacy-evidence-key-value", encoding="utf-8")
            newpath = Path(newdir) / "evidence_hmac_key"
            with mock.patch.object(evidence_keys, "_BASE_DIR", Path(base)), \
                 mock.patch.dict(os.environ, {"DSPM_LOCAL_EVIDENCE_KEY_PATH": str(newpath), "DSPM_ENV": "local"}):
                os.environ.pop("DSPM_EVIDENCE_HMAC_KEY", None)
                key = evidence_keys._load_or_generate_dev_key()
            self.assertEqual(key, "legacy-evidence-key-value")  # preserved
            self.assertTrue(newpath.exists())
            self.assertFalse(legacy.exists())  # migrated out of data/


if __name__ == "__main__":
    unittest.main()
