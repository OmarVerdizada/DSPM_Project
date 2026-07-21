"""SC-1/SC-3 regression: the universal evidence sanitizer masks every sensitive
class in previews and generic samples, not just PCI card data."""

from __future__ import annotations

import json
import os
import unittest

from classification.regex_classifier import classify_content
from discovery.discovery_engine import _safe_preview, sanitize_evidence_text

# Raw secret/PII values that must never survive into any evidence surface.
RAW_SECRETS = [
    "SuperSecretP@ss99",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",  # JWT header segment
    "AKIAIOSFODNN7EXAMPLE",
    "MIIBOgIBAAJBAKj34GkxFhD",  # inside a private key block
    "alice.smith@example.com",
    "123-45-6789",  # SSN
]

CONTENT = "\n".join(
    [
        "password: SuperSecretP@ss99",
        "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "AKIAIOSFODNN7EXAMPLE",
        "-----BEGIN RSA PRIVATE KEY-----",
        "MIIBOgIBAAJBAKj34GkxFhD",
        "-----END RSA PRIVATE KEY-----",
        "contact: alice.smith@example.com",
        "SSN: 123-45-6789",
    ]
)


class EvidenceSanitizerTests(unittest.TestCase):
    def test_preview_masks_all_secret_classes(self) -> None:
        preview = _safe_preview(CONTENT)
        self.assertTrue(preview["available"])
        blob = "\n".join(preview["lines"])
        for raw in RAW_SECRETS:
            self.assertNotIn(raw, blob, f"raw secret leaked into preview: {raw!r}")

    def test_generic_samples_never_contain_raw_values(self) -> None:
        serialized = json.dumps(classify_content(CONTENT))
        for raw in ["SuperSecretP@ss99", "AKIAIOSFODNN7EXAMPLE", "alice.smith@example.com", "123-45-6789"]:
            self.assertNotIn(raw, serialized, f"raw secret leaked into samples: {raw!r}")

    def test_preview_shape_is_stable(self) -> None:
        preview = _safe_preview(CONTENT)
        self.assertEqual(set(preview.keys()), {"available", "lines", "truncated"})
        self.assertIsInstance(preview["lines"], list)
        self.assertEqual(_safe_preview(""), {"available": False, "lines": [], "truncated": False})

    def test_raw_passthrough_is_opt_in_and_off_by_default(self) -> None:
        # Default: masked.
        self.assertNotIn("SuperSecretP@ss99", sanitize_evidence_text("password: SuperSecretP@ss99"))
        # Explicit opt-in restores raw (for controlled/local debugging only).
        os.environ["DSPM_RAW_EVIDENCE_PREVIEW"] = "1"
        try:
            self.assertIn("SuperSecretP@ss99", sanitize_evidence_text("password: SuperSecretP@ss99"))
        finally:
            os.environ.pop("DSPM_RAW_EVIDENCE_PREVIEW", None)


if __name__ == "__main__":
    unittest.main()
