"""W2 parallelism: the detector pool outlives the engine that started it.

A partitioned scan builds an engine per partition, and each engine built its own pool:
it spawned five workers here, warmed them (about 2.5 s of CPU each), classified its first
files in-process while they warmed, and shut them down at the partition's end - so every
partition paid the warm-up again. Engines now lease one pool the process keeps.
"""
from __future__ import annotations

import os
import time
import unittest
from unittest import mock

from discovery import detector_pool


class _Sharing(unittest.TestCase):
    def setUp(self) -> None:
        detector_pool.shutdown_shared_pool()
        self.addCleanup(detector_pool.shutdown_shared_pool)
        patcher = mock.patch.object(detector_pool, "_configured_workers", return_value=2)
        patcher.start()
        self.addCleanup(patcher.stop)
        # No worker process is spawned here: the lease bookkeeping is what is under test.
        started = mock.patch.object(detector_pool.DetectorPool, "start", lambda self: None)
        started.start()
        self.addCleanup(started.stop)


class EnginesShareOnePoolTest(_Sharing):

    def test_two_engines_lease_the_same_pool_and_it_outlives_both(self) -> None:
        first = detector_pool.build_pool(compliance_enabled=True)
        second = detector_pool.build_pool(compliance_enabled=True)
        self.assertIs(first._pool, second._pool)
        pool = first._pool
        with mock.patch.dict(os.environ, {"DSPM_DETECTOR_POOL_IDLE_SECONDS": "60"}):
            first.shutdown()
            second.shutdown()
        third = detector_pool.build_pool(compliance_enabled=True)
        self.assertIs(third._pool, pool, "the next partition found the pool gone")
        third.shutdown()

    def test_an_idle_pool_is_shut_down(self) -> None:
        lease = detector_pool.build_pool(compliance_enabled=True)
        pool = lease._pool
        with mock.patch.object(pool, "shutdown") as closed, \
                mock.patch.dict(os.environ, {"DSPM_DETECTOR_POOL_IDLE_SECONDS": "0.05"}):
            lease.shutdown()
            lease.shutdown()  # giving a lease back twice is giving it back once
            deadline = time.monotonic() + 5
            while not closed.called and time.monotonic() < deadline:
                time.sleep(0.01)
        self.assertTrue(closed.called)
        self.assertIsNone(detector_pool._shared_pool)

    def test_a_lease_left_on_a_closed_pool_does_not_hold_the_next_one(self) -> None:
        leftover = detector_pool.build_pool(compliance_enabled=True)
        detector_pool.shutdown_shared_pool()  # closed with a lease still out
        lease = detector_pool.build_pool(compliance_enabled=True)
        pool = lease._pool
        self.assertIsNot(pool, leftover._pool)
        with mock.patch.object(pool, "shutdown") as closed, \
                mock.patch.dict(os.environ, {"DSPM_DETECTOR_POOL_IDLE_SECONDS": "0.05"}):
            lease.shutdown()
            deadline = time.monotonic() + 5
            while not closed.called and time.monotonic() < deadline:
                time.sleep(0.01)
        self.assertTrue(closed.called, "the closed pool's lease was counted against this one")
        again = detector_pool.build_pool(compliance_enabled=True)
        with mock.patch.dict(os.environ, {"DSPM_DETECTOR_POOL_IDLE_SECONDS": "0.05"}):
            leftover.shutdown()  # given back late: not one of the live pool's leases
            passing = detector_pool.build_pool(compliance_enabled=True)
            passing.shutdown()  # `again` still holds the pool, so it must not be reaped
            time.sleep(0.2)
        self.assertIs(detector_pool._shared_pool, again._pool, "a late lease from a closed pool released the live one")
        again.shutdown()

    def test_a_lease_taken_before_the_idle_time_keeps_it(self) -> None:
        lease = detector_pool.build_pool(compliance_enabled=True)
        pool = lease._pool
        with mock.patch.object(pool, "shutdown") as closed, \
                mock.patch.dict(os.environ, {"DSPM_DETECTOR_POOL_IDLE_SECONDS": "0.3"}):
            lease.shutdown()
            again = detector_pool.build_pool(compliance_enabled=True)
            time.sleep(0.5)
            self.assertFalse(closed.called, "a leased pool was shut down")
            self.assertIs(again._pool, pool)
            again.shutdown()

    def test_a_broken_pool_is_replaced(self) -> None:
        lease = detector_pool.build_pool(compliance_enabled=True)
        broken = lease._pool
        broken._record_failure("worker died")
        lease.shutdown()
        fresh = detector_pool.build_pool(compliance_enabled=True)
        self.assertIsNot(fresh._pool, broken)
        self.assertTrue(fresh.enabled)
        fresh.shutdown()

    def test_each_engine_counts_its_own_files(self) -> None:
        first = detector_pool.build_pool(compliance_enabled=True)
        second = detector_pool.build_pool(compliance_enabled=True)
        with mock.patch.object(first._pool, "run", side_effect=[{"ok": 1}, None, {"ok": 2}]):
            first.run({})
            first.run({})
            second.run({})
        self.assertEqual((first.diagnostics()["files_in_workers"], first.diagnostics()["files_in_process"]), (1, 1))
        self.assertEqual(second.diagnostics()["files_in_workers"], 1)
        self.assertTrue(second.diagnostics()["shared"])
        first.shutdown()
        second.shutdown()


class SharingCanBeTurnedOffTest(_Sharing):

    def test_off_gives_every_engine_its_own_pool(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_DETECTOR_POOL_SHARED": "0"}):
            one = detector_pool.build_pool(compliance_enabled=True)
            two = detector_pool.build_pool(compliance_enabled=True)
        self.assertIsInstance(one, detector_pool.DetectorPool)
        self.assertIsNot(one, two)

    def test_without_compliance_there_is_no_pool_to_share(self) -> None:
        pool = detector_pool.build_pool(compliance_enabled=False)
        self.assertIsInstance(pool, detector_pool.DetectorPool)
        self.assertFalse(pool.enabled)


if __name__ == "__main__":
    unittest.main()
