"""Phase 1 read-switch completion: get_finding / _history / _occurrences serve
from the normalized index with byte-for-byte parity against the blob path."""

from __future__ import annotations

import os
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
        self._saved = os.environ.get("DSPM_READ_FROM_NORMALIZED")
        os.environ.pop("DSPM_READ_FROM_NORMALIZED", None)
        self.tenant = f"gf-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "Get Finding")
        store.save_scan_history(self.tenant, _report(f"{self.tenant}-s1"))

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop("DSPM_READ_FROM_NORMALIZED", None)
        else:
            os.environ["DSPM_READ_FROM_NORMALIZED"] = self._saved

    def _both(self, fn, finding_id: str = "f1"):
        os.environ.pop("DSPM_READ_FROM_NORMALIZED", None)
        blob = fn(self.tenant, finding_id)
        os.environ["DSPM_READ_FROM_NORMALIZED"] = "1"
        norm = fn(self.tenant, finding_id)
        os.environ.pop("DSPM_READ_FROM_NORMALIZED", None)
        return blob, norm

    def test_get_finding_parity(self) -> None:
        blob, norm = self._both(store.get_finding)
        self.assertEqual(norm, blob)
        self.assertIsNotNone(norm)
        self.assertEqual(norm["finding_id"], "f1")

    def test_get_finding_history_parity(self) -> None:
        blob, norm = self._both(store.get_finding_history)
        self.assertEqual(norm, blob)
        self.assertEqual(len(norm), 1)

    def test_get_finding_occurrences_parity(self) -> None:
        blob, norm = self._both(store.get_finding_occurrences)
        self.assertEqual(norm, blob)
        self.assertEqual(len(norm), 1)

    def test_missing_finding_is_none_with_flag_on(self) -> None:
        os.environ["DSPM_READ_FROM_NORMALIZED"] = "1"
        try:
            self.assertIsNone(store.get_finding(self.tenant, "does-not-exist"))
            self.assertIsNone(store.get_finding_history(self.tenant, "does-not-exist"))
        finally:
            os.environ.pop("DSPM_READ_FROM_NORMALIZED", None)


if __name__ == "__main__":
    unittest.main()
