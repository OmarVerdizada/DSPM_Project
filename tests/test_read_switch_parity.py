"""Phase 1 read-switch: list_findings answers from the findings rows (DATA-001).

The switch (DSPM_READ_FROM_NORMALIZED) compared two paths; the list has had one since
W3.3 and the switch had no reader left. W4.1 retired it. What the parity tests held - the
newest scan wins on dedup, the row owns the lifecycle, the status filter - still holds."""

from __future__ import annotations

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
        self.tenant = f"rs-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "Read Switch")
        # older scan: f1 OPEN, f2 RESOLVED
        store.save_scan_history(self.tenant, _report(f"{self.tenant}-s1", [
            {"finding_id": "f1", "type": "password", "risk": "HIGH", "status": "OPEN", "occurrence_count": 3},
            {"finding_id": "f2", "type": "email", "risk": "LOW", "status": "RESOLVED"},
        ]))
        # newer scan: f1 re-detected, and worse than before (newest wins on dedup)
        store.save_scan_history(self.tenant, _report(f"{self.tenant}-s2", [
            {"finding_id": "f1", "type": "password", "risk": "CRITICAL", "occurrence_count": 5},
        ]))
        # ...and then an analyst confirms it. The status arrives this way and no
        # other: a scan reports what it found, never what someone decided about
        # it, and a scan that claimed a status would now be ignored anyway - the
        # row owns the lifecycle, so that nightly re-detection cannot undo triage.
        store.update_finding_lifecycle(
            self.tenant, "f1", "status", {"status": "CONFIRMED"}, "analyst@example.com",
        )

    def test_parity_no_filter(self) -> None:
        norm = store.list_findings(self.tenant)
        by_id = {f["finding_id"]: f for f in norm}
        self.assertEqual(set(by_id), {"f1", "f2"})
        self.assertEqual(by_id["f1"]["risk"], "CRITICAL")  # newest scan won
        self.assertEqual(by_id["f1"]["status"], "CONFIRMED")

    def test_parity_status_resolved(self) -> None:
        norm = store.list_findings(self.tenant, status="RESOLVED")
        self.assertEqual([f["finding_id"] for f in norm], ["f2"])

    def test_parity_status_confirmed(self) -> None:
        norm = store.list_findings(self.tenant, status="CONFIRMED")
        self.assertEqual([f["finding_id"] for f in norm], ["f1"])


if __name__ == "__main__":
    unittest.main()
