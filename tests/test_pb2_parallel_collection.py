"""Track P-B.2 - process-wide collector-I/O admission budget and parallel
collector acquisition.

The admission budget caps concurrently connected collector workers across ALL
scan jobs, so a burst of concurrent DSPM_JOB_WORKERS scans (each using
io_workers threads) cannot oversubscribe one target host. These tests are
deterministic and need no SMB/WinRM server; the parallel SMB path is exercised
with mock connections, the same way the rest of the SMB suite is.
"""

from __future__ import annotations

import json
import os
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from collectors.smb_scanner import SMBConfig, SMBScanner, _SmbConnectionLost
from collectors.winrm_endpoint_scanner import WinRMEndpointConfig, WinRMEndpointScanner
from discovery.parallelism import (
    MAX_HOST_IO_BUDGET,
    HostAdmissionBudget,
    host_admission_budget,
    reset_host_admission_budget,
)


class HostAdmissionBudgetTests(unittest.TestCase):
    def tearDown(self) -> None:
        reset_host_admission_budget()  # don't leak a test-sized budget into other tests

    def test_caps_concurrency_across_threads(self) -> None:
        budget = HostAdmissionBudget(3)
        active = 0
        peak = 0
        lock = threading.Lock()

        def work(_i: int) -> None:
            nonlocal active, peak
            with budget.slot():
                with lock:
                    active += 1
                    peak = max(peak, active)
                time.sleep(0.02)
                with lock:
                    active -= 1

        with ThreadPoolExecutor(max_workers=12) as ex:
            list(ex.map(work, range(24)))

        self.assertLessEqual(peak, 3)  # never more than the budget concurrently
        stats = budget.stats()
        self.assertEqual(stats["limit"], 3)
        self.assertEqual(stats["in_use"], 0)
        self.assertLessEqual(stats["peak_in_use"], 3)
        self.assertEqual(stats["grants"], 24)
        self.assertGreater(stats["waits"], 0)  # 24 tasks / 3 slots -> real contention

    def test_slot_releases_on_exception(self) -> None:
        budget = HostAdmissionBudget(1)
        with self.assertRaises(ValueError):
            with budget.slot():
                raise ValueError("boom")
        # The slot must be freed even though the body raised.
        with budget.slot():
            pass
        self.assertEqual(budget.stats()["in_use"], 0)

    def test_timeout_when_exhausted(self) -> None:
        budget = HostAdmissionBudget(1)
        with budget.slot():
            with self.assertRaises(TimeoutError):
                with budget.slot(timeout=0.05):
                    pass

    def test_singleton_and_env_sizing_and_bound(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_HOST_IO_BUDGET": "7"}):
            b = reset_host_admission_budget()
            self.assertEqual(b.limit, 7)
            self.assertIs(host_admission_budget(), b)
        with mock.patch.dict(os.environ, {"DSPM_HOST_IO_BUDGET": "99999"}):
            self.assertEqual(reset_host_admission_budget().limit, MAX_HOST_IO_BUDGET)


def _record_for(share_name: str, conn_tag: int) -> dict:
    return {
        "source": "smb",
        "share": share_name,
        "path": f"/{share_name}.txt",
        "name": f"{share_name}.txt",
        "size": 1,
        "sha256": share_name,
        "reuse_key": f"smb://fs/{share_name}/{share_name}.txt",
        # the connection tag that walked this share - used to assert isolation.
        "conn_tag": conn_tag,
    }


def _build_scanner(shares, walk, *, io_workers=4, record_callback=None):
    """An SMBScanner whose connect/close/_walk_share are mocked (no server), so
    scan()'s real serial/parallel orchestration runs against fake connections.
    ``walk(share_name, conn_tag)`` returns that share's records. Each connect()
    hands out a fresh, monotonically-tagged connection so a walk can prove which
    connection it ran on."""
    scanner = SMBScanner(SMBConfig(server="fs", io_workers=io_workers, record_callback=record_callback))
    connects: list[int] = []
    lock = threading.Lock()
    counter = {"n": 0}

    class Share:
        def __init__(self, name: str) -> None:
            self.name = name

    class Connection:
        def __init__(self, tag: int) -> None:
            self.tag = tag

        def listShares(self):
            return [Share(name) for name in shares]

        def close(self):
            return None

    def connect() -> bool:
        with lock:
            counter["n"] += 1
            tag = counter["n"]
            connects.append(tag)
        scanner.connection = Connection(tag)
        scanner.server_used = "fs"
        return True

    def close() -> None:
        scanner.connection = None

    def walk_share(share_name: str, folder: str, depth: int):
        conn = scanner.connection
        assert conn is not None, "walk ran without a connection"
        return walk(share_name, conn.tag)

    scanner.connect = connect  # type: ignore[assignment]
    scanner.close = close  # type: ignore[assignment]
    scanner._walk_share = walk_share  # type: ignore[assignment]
    return scanner, connects


class ParallelSmbShareTests(unittest.TestCase):
    """The default-on parallel per-share SMB path, exercised with mock
    connections (mirroring the rest of the SMB suite). Parallel acquisition must
    give each worker its OWN isolated connection, preserve the exact record set
    in deterministic share order, stream every record once via the pipeline
    callback, and fall back to serial when disabled."""

    def tearDown(self) -> None:
        reset_host_admission_budget()

    def test_parallel_isolates_connections_and_preserves_order(self) -> None:
        shares = ["Docs", "HR", "Finance"]
        emitted: list[dict] = []
        scanner, connects = _build_scanner(
            shares,
            lambda name, tag: [_record_for(name, tag)],
            io_workers=4,
            record_callback=emitted.append,
        )

        result = scanner.scan()

        # Exact record set, in the original share (discovery) order.
        self.assertEqual([r["share"] for r in result], shares)
        # Every record streamed to the pipeline exactly once (order-independent).
        self.assertEqual(
            sorted(r["share"] for r in emitted), sorted(shares)
        )
        diag = scanner.last_scan_diagnostics
        self.assertTrue(diag["io_parallel_active"])
        self.assertEqual(diag["io_workers"], 4)
        self.assertEqual(diag["shares_scanned"], shares)
        # One listing connection (tag 1) + one fresh, isolated connection per
        # share worker; no walk ran on the listing connection.
        self.assertEqual(len(connects), 1 + len(shares))
        walk_tags = [r["conn_tag"] for r in result]
        self.assertNotIn(1, walk_tags)
        self.assertEqual(len(set(walk_tags)), len(shares))  # each worker its own

    def test_disabled_env_forces_serial_single_connection(self) -> None:
        shares = ["Docs", "HR", "Finance"]
        emitted: list[dict] = []
        scanner, connects = _build_scanner(
            shares,
            lambda name, tag: [_record_for(name, tag)],
            io_workers=4,
            record_callback=emitted.append,
        )
        with mock.patch.dict(os.environ, {"DSPM_SMB_PARALLEL": "0"}):
            result = scanner.scan()

        self.assertEqual([r["share"] for r in result], shares)
        self.assertEqual([r["share"] for r in emitted], shares)  # serial: in order
        diag = scanner.last_scan_diagnostics
        self.assertFalse(diag["io_parallel_active"])
        # Serial reuses the single listing connection for every share.
        self.assertEqual(connects, [1])
        self.assertEqual(set(r["conn_tag"] for r in result), {1})

    def test_parallel_output_order_is_independent_of_finish_order(self) -> None:
        shares = ["A", "B", "C", "D"]
        # Earlier shares sleep longer so they finish LAST; output must still be
        # A, B, C, D (collector order), not completion order.
        delays = {"A": 0.06, "B": 0.04, "C": 0.02, "D": 0.0}

        def walk(name: str, tag: int):
            time.sleep(delays[name])
            return [_record_for(name, tag)]

        scanner, _connects = _build_scanner(shares, walk, io_workers=4)
        result = scanner.scan()
        self.assertEqual([r["share"] for r in result], shares)

    def test_parallel_reset_share_is_reported_without_partial_records(self) -> None:
        shares = ["Docs", "HR", "Finance"]
        attempts: dict[str, int] = {}
        attempts_lock = threading.Lock()
        emitted: list[dict] = []

        def walk(name: str, tag: int):
            if name == "HR":
                with attempts_lock:
                    attempts[name] = attempts.get(name, 0) + 1
                raise _SmbConnectionLost("HR", "reset")  # fails on BOTH attempts
            return [_record_for(name, tag)]

        scanner, _connects = _build_scanner(
            shares, walk, io_workers=4, record_callback=emitted.append
        )
        result = scanner.scan()

        self.assertEqual([r["share"] for r in result], ["Docs", "Finance"])
        # HR never streamed a record despite two failed attempts.
        self.assertEqual(sorted(r["share"] for r in emitted), ["Docs", "Finance"])
        self.assertEqual(attempts["HR"], 2)  # walked twice (retry-once), then given up
        diag = scanner.last_scan_diagnostics
        self.assertEqual(diag["shares_connection_reset"], ["HR"])
        self.assertNotIn("scan_aborted_reason", diag)  # 2 resets < breaker threshold

    def test_parallel_persistent_reset_aborts_and_bounds_attempts(self) -> None:
        # A server that resets EVERY share: the breaker must still fire (with a
        # reason) and must NOT thrash all shares. Under parallelism the abort is
        # bounded by the worker pool (in-flight shares can't be un-dispatched),
        # not one-at-a-time like the serial path - so with a small pool, shares
        # the breaker never reached are skipped, not attempted.
        shares = [f"Dept{i}" for i in range(8)]

        def walk(name: str, tag: int):
            raise _SmbConnectionLost(name, "reset")  # every share resets on every attempt

        scanner, _connects = _build_scanner(shares, walk, io_workers=2)
        result = scanner.scan()

        self.assertEqual(result, [])  # nothing scanned
        diag = scanner.last_scan_diagnostics
        self.assertEqual(diag.get("scan_aborted_reason"), "smb_connection_reset")
        reset = diag["shares_connection_reset"]
        self.assertGreater(len(reset), 0)
        self.assertLess(len(reset), len(shares))  # bounded: not every share was hammered


class WinRmAdmissionBudgetTests(unittest.TestCase):
    """The WinRM collector runs one remote PowerShell session (no client-side
    per-file split to parallelize), but it still holds a connection-equivalent
    for the scan, so it must take a process-wide admission slot alongside the
    SMB share workers - and report the admission posture in its diagnostics."""

    def tearDown(self) -> None:
        reset_host_admission_budget()

    def test_scan_holds_admission_slot_and_reports_stats(self) -> None:
        scanner = WinRMEndpointScanner(
            WinRMEndpointConfig(host="endpoint-01", username="admin", password="secret", use_ssl=True)
        )
        seen = {"in_use_during_call": -1}

        class _Result:
            status_code = 0
            std_err = b""
            std_out = json.dumps(
                {
                    "records": [
                        {
                            "path": "C:/Users/x/Documents/a.txt",
                            "name": "a.txt",
                            "size": 3,
                            "extension": ".txt",
                            "content": "abc",
                        }
                    ],
                    "diagnostics": {"walked": 1},
                }
            ).encode()

        def fake_run(_script: str):
            # The admission slot must be held WHILE the remote session runs.
            seen["in_use_during_call"] = host_admission_budget().stats()["in_use"]
            return _Result()

        with mock.patch.object(scanner, "_run_ps_file", side_effect=fake_run):
            records = scanner.scan()

        self.assertEqual(len(records), 1)
        self.assertEqual(seen["in_use_during_call"], 1)  # slot held during the call
        diag = scanner.last_scan_diagnostics
        self.assertFalse(diag["io_parallel_active"])
        self.assertEqual(diag["host_admission"]["in_use"], 0)  # released after
        self.assertGreaterEqual(diag["host_admission"]["grants"], 1)


if __name__ == "__main__":
    unittest.main()
