"""SMB scan coverage visibility: the scan must record which shares were
discovered, scanned, skipped, and access-denied - so a share that is not
exported or is unreadable by the scan account is visible, not silently absent
(the 'cc.png cannot be found' class of confusion)."""

from __future__ import annotations

import unittest
from unittest import mock

from collectors.smb_scanner import SMBConfig, SMBScanner


class _Share:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeConn:
    """listShares -> a fixed set; listPath denies some shares, allows others."""

    def __init__(self, denied: set[str]) -> None:
        self._denied = denied

    def listShares(self):
        return [_Share("Executive"), _Share("Finance"), _Share("Shared"), _Share("IPC$")]

    def listPath(self, share, folder):
        if share in self._denied:
            raise Exception(f"Failed to list  on {share}: Unable to open directory")
        return []  # readable but empty

    def close(self):
        pass


class SmbShareCoverageTests(unittest.TestCase):
    def test_scan_records_share_coverage(self) -> None:
        scanner = SMBScanner(SMBConfig(server="fs", username="u", password="p", domain="CORP"))
        scanner.connection = _FakeConn(denied={"Executive", "Finance"})
        scanner.last_scan_diagnostics = {}
        with mock.patch.object(scanner, "connect", return_value=True), \
             mock.patch.object(scanner, "close"), \
             mock.patch.object(scanner, "_emit_collection_progress"):
            scanner.scan()
        diag = scanner.last_scan_diagnostics
        self.assertEqual(diag["shares_discovered"], ["Executive", "Finance", "Shared", "IPC$"])
        self.assertIn("Shared", diag["shares_scanned"])       # readable share was scanned
        self.assertIn("IPC$", diag["shares_skipped"])          # system share skipped
        self.assertEqual(diag["shares_access_denied"], ["Executive", "Finance"])

    def test_missing_share_is_simply_absent_from_discovered(self) -> None:
        # If the folder holding the file is not exported over SMB, its share name
        # never appears in shares_discovered - which is the actionable signal.
        scanner = SMBScanner(SMBConfig(server="fs"))
        scanner.connection = _FakeConn(denied=set())
        scanner.last_scan_diagnostics = {}
        with mock.patch.object(scanner, "connect", return_value=True), \
             mock.patch.object(scanner, "close"), \
             mock.patch.object(scanner, "_emit_collection_progress"):
            scanner.scan()
        self.assertNotIn("Marketing", scanner.last_scan_diagnostics["shares_discovered"])


if __name__ == "__main__":
    unittest.main()
