"""M0/Q2: a detector worker dying must not leave a process that cannot exit.

The pool warms its workers in the background and disables itself if one fails. That
disabling ran from the warm-up callback - and when a worker *dies*, CPython runs those
callbacks on the executor's own manager thread, inside `terminate_broken`, which holds the
executor's non-reentrant `_shutdown_lock` while it fails each pending future
(`concurrent/futures/process.py`). Asking the executor to shut down from there takes that
lock on the thread already holding it. The scan still finished in-process, so the symptom
was a backend, worker or `main.py scan` process that did all its work and then hung at
exit: a Windows service that never stops.

The callback now only records the failure. Closing the pool stays with the threads that
own neither the manager loop nor its lock - `run`, and the scan's own `finally`.

The first test is the gate: a real pool, a worker that really dies, and a process that has
to exit. The rest pin the reasoning in-process, where a fake executor can say whether it
was touched at all.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from concurrent.futures import Future
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path

from discovery import detector_pool

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "tests" / "detector_pool_crash_helper.py"
# Generous: spawning and breaking two workers is seconds, and a hang is the failure.
EXIT_TIMEOUT_SECONDS = 180


class _FakeExecutor:
    """Records whether the pool touched the executor, and from where."""

    def __init__(self) -> None:
        self.shutdown_calls: list[dict] = []

    def shutdown(self, wait=True, *, cancel_futures=False) -> None:
        self.shutdown_calls.append({"wait": wait, "cancel_futures": cancel_futures})

    def submit(self, *_args, **_kwargs):  # pragma: no cover - a disabled pool never submits
        raise AssertionError("a disabled pool submitted work")


def _failed_future() -> Future:
    future: Future = Future()
    future.set_exception(BrokenProcessPool("a process in the process pool was terminated abruptly"))
    return future


class AWorkerThatDiesWarmingUpTest(unittest.TestCase):

    def test_the_process_still_exits(self) -> None:
        try:
            run = subprocess.run([sys.executable, str(HELPER)], capture_output=True, text=True,
                                 timeout=EXIT_TIMEOUT_SECONDS, cwd=str(ROOT))
        except subprocess.TimeoutExpired:
            self.fail(
                "the process could not exit after a worker died warming up: the warm-up callback "
                "closed the executor from the executor's own manager thread, which holds its lock"
            )
        self.assertEqual(run.returncode, 0, f"stdout={run.stdout}\nstderr={run.stderr}")
        result = json.loads([line for line in run.stdout.splitlines() if line.startswith("{")][-1])
        self.assertIn("BrokenProcessPool", result["disabled_reason"])
        self.assertFalse(result["enabled"], "a pool whose workers died stayed enabled")
        self.assertTrue(result["fell_back_in_process"], "the caller did not fall back to in-process work")
        self.assertEqual(result["files_in_process"], 1)


class TheWarmUpCallbackTest(unittest.TestCase):
    """What the callback may do, given it can run on the executor's own thread."""

    def setUp(self) -> None:
        self.pool = detector_pool.DetectorPool(workers=2)
        self.executor = _FakeExecutor()
        self.pool._executor = self.executor

    def test_it_records_the_failure_and_leaves_the_executor_alone(self) -> None:
        self.pool._warmed(_failed_future())

        self.assertFalse(self.pool.enabled, "the pool stayed enabled after a worker died")
        self.assertIn("BrokenProcessPool", self.pool.diagnostics()["disabled_reason"])
        self.assertEqual(self.executor.shutdown_calls, [],
                         "the callback closed the executor - that is the deadlock")
        self.assertIs(self.pool._executor, self.executor,
                      "the callback detached the executor the scan still has to close")

    def test_a_warm_worker_still_counts(self) -> None:
        warm: Future = Future()
        warm.set_result(True)
        self.pool._warmed(warm)
        self.assertEqual(self.pool.diagnostics()["warm_workers"], 1)
        self.assertTrue(self.pool.enabled)

    def test_the_scan_closes_the_broken_pool_afterwards_exactly_once(self) -> None:
        self.pool._warmed(_failed_future())
        self.pool.shutdown()
        self.pool.shutdown()
        self.assertEqual(self.executor.shutdown_calls, [{"wait": False, "cancel_futures": True}])
        self.assertIsNone(self.pool._executor)

    def test_every_worker_failing_disables_once_and_keeps_the_first_reason(self) -> None:
        for _ in range(4):
            self.pool._warmed(_failed_future())
        self.pool._record_failure("something later")
        self.assertEqual(self.pool.diagnostics()["disabled_reason"], "worker failed to warm: BrokenProcessPool")
        self.assertEqual(self.executor.shutdown_calls, [])

    def test_a_failure_on_a_safe_thread_does_close_the_pool(self) -> None:
        # `run` and `start` own neither the manager loop nor its lock, so they close it.
        self.pool._disable("submit failed: BrokenProcessPool")
        self.assertEqual(self.executor.shutdown_calls, [{"wait": False, "cancel_futures": True}])
        self.assertIsNone(self.pool._executor)

    def test_a_disabled_pool_hands_the_work_back_to_the_caller(self) -> None:
        self.pool._warmed(_failed_future())
        self.assertIsNone(self.pool.run({"anything": True}), "a disabled pool must return None, not raise")
        diagnostics = self.pool.diagnostics()
        self.assertEqual((diagnostics["files_seen"], diagnostics["files_in_process"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
