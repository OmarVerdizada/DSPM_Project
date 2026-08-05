"""Phase 1 read-switch: normalized list_findings is byte-for-byte identical to
the blob path (DATA-001). The flag is off by default; parity is the safety gate."""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

from backend import store


def _report(scan_id: str, findings: list[dict]) -> dict:
    return {
        "scan_id": scan_id,
        "source": "local",
        "timestamp": "2026-07-22T00:00:00Z",
        "summary": {"total_files": 1},
        "files": [{"name": "f.txt", "path": "/f.txt", "size": 10, "findings": findings}],
    }


class ReadSwitchParityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = os.environ.get("DSPM_READ_FROM_NORMALIZED")
        os.environ.pop("DSPM_READ_FROM_NORMALIZED", None)

        self.tenant = f"rs-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "Read Switch")
        # older scan: f1 OPEN, f2 RESOLVED
        store.save_scan_history(self.tenant, _report(f"{self.tenant}-s1", [
            {"finding_id": "f1", "type": "password", "risk": "HIGH", "status": "OPEN", "occurrence_count": 3},
            {"finding_id": "f2", "type": "email", "risk": "LOW", "status": "RESOLVED"},
        ]))
        # newer scan: f1 re-detected, now CONFIRMED (newest wins on dedup)
        store.save_scan_history(self.tenant, _report(f"{self.tenant}-s2", [
            {"finding_id": "f1", "type": "password", "risk": "CRITICAL", "status": "CONFIRMED", "occurrence_count": 5},
        ]))

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop("DSPM_READ_FROM_NORMALIZED", None)
        else:
            os.environ["DSPM_READ_FROM_NORMALIZED"] = self._saved

    def _both(self, status: str = "") -> tuple[list[dict], list[dict]]:
        os.environ.pop("DSPM_READ_FROM_NORMALIZED", None)
        blob = store.list_findings(self.tenant, status=status)
        os.environ["DSPM_READ_FROM_NORMALIZED"] = "1"
        norm = store.list_findings(self.tenant, status=status)
        os.environ.pop("DSPM_READ_FROM_NORMALIZED", None)
        return blob, norm

    def test_parity_no_filter(self) -> None:
        blob, norm = self._both()
        self.assertEqual(norm, blob)
        by_id = {f["finding_id"]: f for f in norm}
        self.assertEqual(set(by_id), {"f1", "f2"})
        self.assertEqual(by_id["f1"]["risk"], "CRITICAL")  # newest scan won
        self.assertEqual(by_id["f1"]["status"], "CONFIRMED")

    def test_parity_status_resolved(self) -> None:
        blob, norm = self._both(status="RESOLVED")
        self.assertEqual(norm, blob)
        self.assertEqual([f["finding_id"] for f in norm], ["f2"])

    def test_parity_status_confirmed(self) -> None:
        blob, norm = self._both(status="CONFIRMED")
        self.assertEqual(norm, blob)
        self.assertEqual([f["finding_id"] for f in norm], ["f1"])

    def test_default_flag_off_uses_blob(self) -> None:
        # With the flag unset, behaviour is exactly the legacy blob path.
        self.assertIsNone(os.environ.get("DSPM_READ_FROM_NORMALIZED"))
        result = store.list_findings(self.tenant)
        self.assertEqual({f["finding_id"] for f in result}, {"f1", "f2"})


if __name__ == "__main__":
    unittest.main()
