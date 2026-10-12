"""Phase 1 read-switch completion: get_finding / _history / _occurrences answer for a finding.

The switch (DSPM_READ_FROM_NORMALIZED) compared the blob path with the normalized index.
The blob path went with W3.3 and the switch had no reader left; W4.1 retired it, and an
estate finding answers from its row and its asset's record. What the parity tests held
still holds: the finding, its history and its occurrences as the scan reported them.
"""

from __future__ import annotations

import unittest
from uuid import uuid4

from backend import store


def _report(scan_id: str) -> dict:
    return {
        "scan_id": scan_id,
        "source": "local",
        "timestamp": "2026-07-23T00:00:00Z",
        "summary": {"total_files": 1},
        "files": [
            {
                "name": "f.txt",
                "path": "/f.txt",
                "size": 10,
                "findings": [
                    {
                        "finding_id": "f1",
                        "type": "password",
                        "risk": "HIGH",
                        "status": "OPEN",
                        "occurrences": [{"scan_id": scan_id, "locator": "/f.txt"}],
                        "status_history": [{"status": "OPEN", "at": "2026-07-23T00:00:00Z"}],
                    }
                ],
            }
        ],
    }


class GetFindingParityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant = f"gf-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "Get Finding")
        store.save_scan_history(self.tenant, _report(f"{self.tenant}-s1"))

    def test_get_finding(self) -> None:
        finding = store.get_finding(self.tenant, "f1")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["finding_id"], "f1")

    def test_get_finding_history(self) -> None:
        self.assertEqual(len(store.get_finding_history(self.tenant, "f1")), 1)

    def test_get_finding_occurrences(self) -> None:
        self.assertEqual(store.get_finding_occurrences(self.tenant, "f1"),
                         [{"scan_id": f"{self.tenant}-s1", "locator": "/f.txt"}])

    def test_missing_finding_is_none(self) -> None:
        self.assertIsNone(store.get_finding(self.tenant, "does-not-exist"))
        self.assertIsNone(store.get_finding_history(self.tenant, "does-not-exist"))


if __name__ == "__main__":
    unittest.main()
