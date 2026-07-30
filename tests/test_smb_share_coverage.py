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


class _ResettingConn:
    """listPath raises a connection reset for named shares, succeeds otherwise."""

    def __init__(self, reset: set[str]) -> None:
        self._reset = reset

    def listShares(self):
        return [_Share("Executive"), _Share("Public"), _Share("IPC$")]

    def listPath(self, share, folder):
        if share in self._reset:
            raise ConnectionResetError("[WinError 10054] An existing connection was forcibly closed")
        return []

    def close(self):
        pass


class SmbConnectionResetTests(unittest.TestCase):
    def test_reset_reconnects_continues_and_is_categorized(self) -> None:
        scanner = SMBScanner(SMBConfig(server="dc"))
        scanner.last_scan_diagnostics = {}
        calls = {"connect": 0}

        def fake_connect():
            calls["connect"] += 1
            # First connection resets on Executive; the reconnected one is clean.
            scanner.connection = _ResettingConn({"Executive"} if calls["connect"] == 1 else set())
            scanner.server_used = "dc"
            return True

        with mock.patch.object(scanner, "connect", side_effect=fake_connect), \
             mock.patch.object(scanner, "_skip_path", return_value=False), \
             mock.patch.object(scanner, "_emit_collection_progress"):
            scanner.scan()

        diag = scanner.last_scan_diagnostics
        # The reset is categorized as connection-reset, NOT access-denied...
        self.assertEqual(diag["shares_connection_reset"], ["Executive"])
        self.assertNotIn("Executive", diag.get("shares_access_denied", []))
        # ...the scan reconnected and still reached the next share...
        self.assertGreaterEqual(calls["connect"], 2)
        self.assertIn("Public", diag["shares_scanned"])
        # ...and did not abort (it recovered).
        self.assertNotIn("scan_aborted_reason", diag)

    def test_persistent_reset_aborts_with_reason(self) -> None:
        # The real "server resets every share" case: after 5 consecutive resets
        # the scan stops with a clear reason instead of thrashing every share.
        class _AllReset:
            def listShares(self):
                return [_Share(f"Dept{i}") for i in range(8)]

            def listPath(self, share, folder):
                raise ConnectionResetError("[WinError 10054] An existing connection was forcibly closed")

            def close(self):
                pass

        scanner = SMBScanner(SMBConfig(server="dc"))
        scanner.last_scan_diagnostics = {}

        def fake_connect():
            scanner.connection = _AllReset()
            scanner.server_used = "dc"
            return True

        with mock.patch.object(scanner, "connect", side_effect=fake_connect), \
             mock.patch.object(scanner, "_skip_path", return_value=False), \
             mock.patch.object(scanner, "_emit_collection_progress"):
            scanner.scan()

        diag = scanner.last_scan_diagnostics
        self.assertEqual(diag.get("scan_aborted_reason"), "smb_connection_reset")
        # It stopped early (did not attempt all 8 shares after hitting the cap).
        self.assertLessEqual(len(diag["shares_connection_reset"]), 6)


if __name__ == "__main__":
    unittest.main()
