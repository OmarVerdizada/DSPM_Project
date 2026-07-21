"""SC-2 regression tests: evidence-HMAC key is fail-closed and never a shared fallback."""

from __future__ import annotations

import os
import unittest


class EvidenceHmacKeyTests(unittest.TestCase):
    def setUp(self) -> None:
        import classification.compliance.evidence_keys as ek

        self.ek = ek
        self._saved = {
            var: os.environ.get(var)
            for var in ("DSPM_EVIDENCE_HMAC_KEY", "DSPM_ENV")
        }
        ek._dev_key_cache = None

    def tearDown(self) -> None:
        for var, val in self._saved.items():
            if val is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = val
        self.ek._dev_key_cache = None

    def test_env_key_is_honored(self) -> None:
        os.environ["DSPM_EVIDENCE_HMAC_KEY"] = "explicit-operator-key-1234567890"
        self.assertEqual(self.ek.evidence_hmac_key(), "explicit-operator-key-1234567890")

    def test_production_without_key_fails_closed(self) -> None:
        os.environ.pop("DSPM_EVIDENCE_HMAC_KEY", None)
        os.environ["DSPM_ENV"] = "production"
        with self.assertRaises(RuntimeError):
            self.ek.evidence_hmac_key()

    def test_dev_generates_non_default_stable_key(self) -> None:
        os.environ.pop("DSPM_EVIDENCE_HMAC_KEY", None)
        os.environ["DSPM_ENV"] = "local"
        key = self.ek.evidence_hmac_key()
        self.assertTrue(key)
        self.assertNotEqual(key, "dspm-local-evidence-key")
        self.assertEqual(key, self.ek.evidence_hmac_key())

    def test_key_actually_keys_the_fingerprint(self) -> None:
        # Proves the HMAC key feeds the fingerprint (no hardcoded constant):
        # different keys must yield different fingerprints for the same value.
        from classification.compliance.canonical_entities import canonical_entity_fingerprint

        os.environ["DSPM_EVIDENCE_HMAC_KEY"] = "key-A-abcdefghijklmnop"
        fp_a = canonical_entity_fingerprint("EMAIL_ADDRESS", "a@b.com", "default")
        os.environ["DSPM_EVIDENCE_HMAC_KEY"] = "key-B-abcdefghijklmnop"
        fp_b = canonical_entity_fingerprint("EMAIL_ADDRESS", "a@b.com", "default")
        self.assertNotEqual(fp_a, fp_b)
        self.assertEqual(len(fp_a), 64)  # sha256 hex


if __name__ == "__main__":
    unittest.main()
