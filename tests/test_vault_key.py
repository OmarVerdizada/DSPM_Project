"""M3 (roadmap 1.8): the credential vault requires a REAL urlsafe-base64 Fernet
key - no passphrase/PBKDF2/salt - and fails CLOSED at startup on a bad key."""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from cryptography.fernet import Fernet

import backend.vault as vault
from backend import store


class VaultKeyFormatTests(unittest.TestCase):
    def test_valid_fernet_key_passes_startup_check(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_VAULT_KEY": Fernet.generate_key().decode()}):
            vault.validate_vault_key()  # must not raise

    def test_short_or_garbage_key_fails_closed(self) -> None:
        for bad in ("short", "x" * 20, "not-valid-base64!!" * 3):
            with mock.patch.dict(os.environ, {"DSPM_VAULT_KEY": bad}):
                with self.assertRaises(RuntimeError):
                    vault.validate_vault_key()

    def test_production_requires_the_key(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_ENV": "production"}):
            os.environ.pop("DSPM_VAULT_KEY", None)  # restored on context exit
            with self.assertRaises(RuntimeError):
                vault.validate_vault_key()

    def test_salt_and_kdf_env_have_no_effect(self) -> None:
        # Proves the KDF/salt are gone: the SAME key decrypts regardless of the
        # (now-ignored) salt/rounds env vars.
        key = Fernet.generate_key().decode()
        with mock.patch.dict(os.environ, {"DSPM_VAULT_KEY": key, "DSPM_VAULT_SALT": "aaa", "DSPM_VAULT_KDF_ROUNDS": "111"}):
            token = vault._fernet().encrypt(b"secret")
        with mock.patch.dict(os.environ, {"DSPM_VAULT_KEY": key, "DSPM_VAULT_SALT": "zzz", "DSPM_VAULT_KDF_ROUNDS": "999"}):
            self.assertEqual(vault._fernet().decrypt(token), b"secret")


class VaultLocalKeyTests(unittest.TestCase):
    def test_local_generates_a_real_fernet_key_file(self) -> None:
        with TemporaryDirectory() as d:
            keyfile = Path(d) / "vault.key"
            with mock.patch.dict(os.environ, {"DSPM_LOCAL_VAULT_KEY_PATH": str(keyfile), "DSPM_ENV": "local"}):
                os.environ.pop("DSPM_VAULT_KEY", None)
                vault._fernet()  # generates + persists
                self.assertTrue(vault._is_valid_fernet_key(keyfile.read_text().strip().encode()))

    def test_legacy_passphrase_file_is_replaced_with_a_fernet_key(self) -> None:
        with TemporaryDirectory() as d:
            keyfile = Path(d) / "vault.key"
            keyfile.write_text("reg_an_old_pbkdf2_passphrase", encoding="utf-8")  # not a Fernet key
            with mock.patch.dict(os.environ, {"DSPM_LOCAL_VAULT_KEY_PATH": str(keyfile), "DSPM_ENV": "local"}):
                os.environ.pop("DSPM_VAULT_KEY", None)
                fernet = vault._fernet()
                self.assertTrue(fernet.encrypt(b"x"))  # usable
                self.assertTrue(vault._is_valid_fernet_key(keyfile.read_text().strip().encode()))


class VaultRoundTripTests(unittest.TestCase):
    def test_store_resolve_delete_round_trip(self) -> None:
        if not store.tenant_exists("t_vault_key_test"):
            store.create_tenant("t_vault_key_test", "t_vault_key_test")
        cv = vault.CredentialVault()
        ref = cv.store("t_vault_key_test", "u", "p", "CORP")
        try:
            self.assertEqual(cv.resolve("t_vault_key_test", ref), {"username": "u", "password": "p", "domain": "CORP"})
        finally:
            cv.delete("t_vault_key_test", ref)


if __name__ == "__main__":
    unittest.main()
