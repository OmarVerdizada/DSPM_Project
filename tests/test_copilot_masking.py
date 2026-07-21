"""SC-10/11/13/14 regression: the copilot boundary masks evidence it persists,
replays, reasons over, and renders."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import backend.copilot.memory as memory
from backend.copilot.artifacts import _basename
from backend.copilot.audit import AuditBuilder
from risk.risk_engine import _dynamic_finding_reason


class CopilotMaskingTests(unittest.TestCase):
    def test_sc11_reasons_do_not_echo_matched_evidence(self) -> None:
        finding = {
            "type": "gdpr_full_name",
            "category": "pii",
            "label": "Full name",
            "samples": ["secret-token-abc123", "hunter2pass"],
            "keywords": ["salary", "confidential"],
        }
        reason = _dynamic_finding_reason(finding, "fallback")
        self.assertNotIn("Matched evidence", reason)
        self.assertNotIn("secret-token-abc123", reason)
        self.assertNotIn("salary", reason)

    def test_sc13_basename_strips_directories(self) -> None:
        self.assertEqual(_basename(r"C:\Users\admin\secret\prod_passwords.txt"), "prod_passwords.txt")
        self.assertEqual(_basename("/mnt/share/hr/salaries.xlsx"), "salaries.xlsx")
        self.assertEqual(_basename(r"\\server\share\vpn_credentials.env"), "vpn_credentials.env")
        self.assertEqual(_basename(""), "")

    def test_sc14_audit_message_preview_is_masked(self) -> None:
        builder = AuditBuilder(
            "my password: SuperSecret99 and token=eyJhbGci.abcdefgh.ijklmnop",
            "operator@corp.com",
            "conv1",
        )
        preview = builder._data["message_preview"]
        self.assertNotIn("SuperSecret99", preview)
        # audit attribution (user id) is intentionally NOT masked
        self.assertEqual(builder._data["user_id"], "operator@corp.com")

    def test_sc10_save_turn_masks_persisted_user_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(memory, "DATA_DIR", Path(tmp)):
                asyncio.run(
                    memory.save_turn(
                        "t1", "c1",
                        "here is my key AKIAIOSFODNN7EXAMPLE please store it",
                        "acknowledged", [], [],
                    )
                )
                path = Path(tmp) / "copilot" / "t1" / "conversations" / "c1.jsonl"
                content = path.read_text(encoding="utf-8")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", content)
        self.assertIn("[KEY_MASKED]", content)


if __name__ == "__main__":
    unittest.main()
