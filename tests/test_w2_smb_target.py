"""W2.3: what an SMB scan may ask of the file server it reads.

Nothing kept a scan from opening a session per worker (up to 64) to one server, reading as
fast as the wire allowed, retrying a struggling server at once, recalling tiered files
from tape by reading them, or holding a file so nobody could delete or rename it.
"""
from __future__ import annotations

import io
import os
import threading
import time
import unittest
from unittest import mock

from collectors import content_policy, pysmb_compat, smb_target
from tests.test_backend_audit_collectors import (
    _FakeSmbServer,
    _smb_records,
    _smb_scanner,
    _SmbEntry,
)


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


class TheBandwidthCapTest(unittest.TestCase):

    def test_a_reader_is_held_to_the_rate_after_its_burst(self) -> None:
        clock = _Clock()
        bucket = smb_target.TokenBucket(4 * 1024 * 1024, clock=clock, sleep=clock.sleep)  # 4 MiB/s, 1 MiB burst
        waited = sum(bucket.take(1024 * 1024) for _ in range(5))
        # 5 MiB at 4 MiB/s with 1 MiB of burst: 1 s of waiting.
        self.assertAlmostEqual(waited, 1.0, places=3)
        self.assertAlmostEqual(clock.now, 1.0, places=3)

    def test_no_cap_never_waits(self) -> None:
        clock = _Clock()
        bucket = smb_target.TokenBucket(0, clock=clock, sleep=clock.sleep)
        self.assertEqual(sum(bucket.take(100 * 1024 * 1024) for _ in range(3)), 0.0)
        self.assertEqual(clock.slept, [])


class TheSessionCapTest(unittest.TestCase):

    def test_no_more_sessions_than_the_cap_are_open_at_once(self) -> None:
        gate = smb_target.TargetGate("fs01", sessions=3, bytes_per_second=0)
        open_now, peak, lock = [0], [0], threading.Lock()

        def worker() -> None:
            with gate.session():
                with lock:
                    open_now[0] += 1
                    peak[0] = max(peak[0], open_now[0])
                time.sleep(0.02)
                with lock:
                    open_now[0] -= 1

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        self.assertEqual(peak[0], 3)
        self.assertEqual(gate.snapshot()["sessions_peak"], 3)

    def test_the_cap_comes_from_the_environment_per_server(self) -> None:
        smb_target.reset_target_gates()
        self.addCleanup(smb_target.reset_target_gates)
        with mock.patch.dict(os.environ, {"DSPM_SMB_MAX_SESSIONS_PER_TARGET": "2", "DSPM_SMB_MAX_MBPS": "10"}):
            gate = smb_target.target_gate("FS01")
        self.assertIs(gate, smb_target.target_gate("fs01"), "one gate per server, whatever the case")
        self.assertEqual((gate.sessions, gate.snapshot()["max_bytes_per_second"]), (2, 10 * 1024 * 1024))


class TheBackoffTest(unittest.TestCase):

    def test_a_lost_session_doubles_the_pause_and_completed_ones_halve_it(self) -> None:
        clock = _Clock()
        gate = smb_target.TargetGate("fs01", sessions=2, bytes_per_second=0, clock=clock, sleep=clock.sleep)
        for _ in range(3):
            gate.lost()
        self.assertEqual(gate.backoff_seconds, 4.0)
        with gate.session():
            pass
        self.assertEqual(clock.slept, [4.0], "the next session waited out the backoff")
        gate.completed()
        gate.completed()
        self.assertEqual(gate.backoff_seconds, 1.0)
        gate.completed()
        self.assertEqual(gate.backoff_seconds, 0.0)
        for _ in range(10):
            gate.lost()
        self.assertEqual(gate.backoff_seconds, smb_target.BACKOFF_MAX_SECONDS)
        self.assertEqual(gate.snapshot()["sessions_lost"], 13)


class ReadsAreCountedAgainstTheServerTest(unittest.TestCase):

    def test_every_read_through_a_session_is_counted(self) -> None:
        from collectors.smb_scanner import _GatedConnection

        gate = smb_target.TargetGate("fs01", sessions=1, bytes_per_second=0)
        server = _FakeSmbServer({"Docs": {"/a.txt": b"x" * 5000}})
        connection = _GatedConnection(server, gate)
        buffer = io.BytesIO()
        connection.retrieveFileFromOffset("Docs", "/a.txt", buffer, offset=0, max_length=3000)
        connection.retrieveFileFromOffset("Docs", "/a.txt", buffer, offset=3000, max_length=3000)
        self.assertEqual((gate.snapshot()["bytes_read"], gate.snapshot()["reads"]), (5000, 2))
        self.assertEqual(connection.listShares()[0].name, "Docs", "everything else is the session's own")


class _OfflineEntry(_SmbEntry):
    def __init__(self, name: str, size: int = 0, directory: bool = False) -> None:
        super().__init__(name, size, directory)
        self.file_attributes = smb_target.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS if name.startswith("archived") else 0x20


class _TieredServer(_FakeSmbServer):
    def __init__(self, shares) -> None:
        super().__init__(shares)
        self.read_paths: list[str] = []

    def listPath(self, share: str, folder: str):
        return [_OfflineEntry(entry.filename, entry.file_size, entry.isDirectory)
                for entry in super().listPath(share, folder)]

    def retrieveFileFromOffset(self, share, path, buffer, offset=0, max_length=-1):
        self.read_paths.append(path)
        return super().retrieveFileFromOffset(share, path, buffer, offset, max_length)


class AnOfflineFileIsNotRecalledTest(unittest.TestCase):

    def setUp(self) -> None:
        smb_target.reset_target_gates()
        self.addCleanup(smb_target.reset_target_gates)

    def test_a_tiered_file_is_not_read_and_says_so(self) -> None:
        server = _TieredServer({"Docs": {"/archived_payroll.csv": b"ssn 123-45-6789\n" * 10,
                                         "/live.csv": b"contact alice@example.com\n"}})
        records = _smb_records(_smb_scanner(server))
        offline = records["Docs:/archived_payroll.csv"]
        self.assertEqual((offline["content"], offline["content_status"]), ("", "offline_not_recalled"))
        self.assertEqual(content_policy.coverage_state(offline), content_policy.SKIPPED_POLICY)
        self.assertTrue(offline["sha256"].startswith("meta:"))
        self.assertIn("DSPM_SMB_READ_OFFLINE", offline["skip_reason"])
        self.assertNotIn("/archived_payroll.csv", server.read_paths, "the tiered file was read - and recalled")
        self.assertIn("alice@example.com", records["Docs:/live.csv"]["content"])

    def test_it_is_read_when_asked_for(self) -> None:
        server = _TieredServer({"Docs": {"/archived_payroll.csv": b"ssn 123-45-6789\n"}})
        with mock.patch.dict(os.environ, {"DSPM_SMB_READ_OFFLINE": "1"}):
            records = _smb_records(_smb_scanner(server))
        self.assertIn("123-45-6789", records["Docs:/archived_payroll.csv"]["content"])


class AReadLetsTheFileBeDeletedTest(unittest.TestCase):

    def test_a_read_only_open_shares_delete_and_a_write_does_not(self) -> None:
        read_mask, write_mask, file_open = 0x01 | 0x80 | 0x20000 | 0x100000, 0x02, 0x01
        both = 0x01 | 0x02
        self.assertEqual(pysmb_compat.read_only_share_access(read_mask, both, file_open), both | 0x04)
        self.assertEqual(pysmb_compat.read_only_share_access(read_mask | write_mask, both, file_open), both)
        self.assertEqual(pysmb_compat.read_only_share_access(read_mask, both, 0x05), both, "not an open")

    def test_pysmb_is_patched_when_the_collector_loads(self) -> None:
        import smb.base

        import collectors.smb_scanner  # noqa: F401 - loading it applies the patch

        request = smb.base.SMB2CreateRequest("x.txt", access_mask=0x01, share_access=0x03, create_disp=0x01)
        self.assertEqual(request.share_access, 0x07)


class TheWorkingCredentialIsTriedFirstTest(unittest.TestCase):

    def test_the_credential_that_worked_leads_next_time(self) -> None:
        from collectors.smb_scanner import SMBConfig, SMBScanner

        scanner = SMBScanner(SMBConfig(server="fs-cred", username="svc_scan", domain="WORKGROUP"))
        first = [label for _user, _domain, label in scanner._credential_candidates()]
        scanner._remember_credential("fs-cred", first[-1])
        again = [label for _user, _domain, label in scanner._credential_candidates()]
        self.assertEqual(again[0], first[-1])
        self.assertEqual(sorted(again), sorted(first))


if __name__ == "__main__":
    unittest.main()
