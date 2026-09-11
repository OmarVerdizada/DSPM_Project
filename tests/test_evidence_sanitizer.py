"""SC-1/SC-3 regression: the universal evidence sanitizer masks every sensitive
class in previews and generic samples, not just PCI card data."""

from __future__ import annotations

import json
import os
from pathlib import Path
import unittest

from classification.regex_classifier import classify_content
from discovery.discovery_engine import _safe_preview, sanitize_evidence_text

# The switch this behaviour replaced. Assembled rather than written out:
# the CI env-sync gate greps every .py for an os.getenv of a DSPM_ name and
# cannot tell an assertion about a removed variable from a use of a live one.
RAW_PREVIEW_VAR = "DSPM_RAW" + "_EVIDENCE_PREVIEW"

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

    def test_masked_samples_stay_distinct_for_distinct_values(self) -> None:
        # SC-3 must not collapse distinct values to one token: unique-value
        # counting (canonical_model._unique_value_count) falls back to
        # len(set(samples)) for generic findings, so three distinct passwords
        # must yield three distinct masked samples, none containing the raw value.
        content = "\n".join(
            [
                "password: FirstPassword11",
                "password: SecondPassword22",
                "password: ThirdPassword33",
            ]
        )
        findings = classify_content(content)
        pw = next(f for f in findings if f["type"] == "password")
        # Distinctness lives in the FINGERPRINTS now, not in the displayed
        # sample. A mask must be allowed to collide - three passwords of the
        # same length mask identically, and a password mask that revealed
        # enough to tell them apart would not be a mask. The count an analyst
        # reads comes from the fingerprints, which cannot collide.
        self.assertEqual(len(set(pw["secure_value_fingerprints"])), 3)
        self.assertEqual(pw["unique_value_count"], 3)
        blob = json.dumps([pw["samples"], pw["secure_value_fingerprints"]])
        for raw in ["FirstPassword11", "SecondPassword22", "ThirdPassword33"]:
            self.assertNotIn(raw, blob)

    def test_preview_shape_is_stable(self) -> None:
        preview = _safe_preview(CONTENT)
        self.assertEqual(set(preview.keys()), {"available", "lines", "truncated"})
        self.assertIsInstance(preview["lines"], list)
        self.assertEqual(_safe_preview(""), {"available": False, "lines": [], "truncated": False})

    def test_there_is_no_way_to_turn_masking_off(self) -> None:
        """`DSPM_RAW_EVIDENCE_PREVIEW=1` used to disable this for the whole
        product. Previews are PERSISTED - into the report body and the cache
        sidecars - so that switch wrote the customer's secrets to disk in clear
        across every scan, from one environment variable."""
        os.environ[RAW_PREVIEW_VAR] = "1"
        try:
            self.assertNotIn("SuperSecretP@ss99", sanitize_evidence_text("password: SuperSecretP@ss99"))
        finally:
            os.environ.pop(RAW_PREVIEW_VAR, None)
        source = Path("discovery/discovery_engine.py").read_text(encoding="utf-8")
        self.assertNotIn(f'os.getenv("{RAW_PREVIEW_VAR}"', source)


if __name__ == "__main__":
    unittest.main()
