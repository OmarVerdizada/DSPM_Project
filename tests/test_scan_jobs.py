"""Regression tests for the async scan job lifecycle.

These guard the "scan progress stuck at 7%" class of failures: progress must
advance during collection, a completed scan must reach 100/completed, and a
failed scan must transition to failed (with an error) instead of silently
staying at a stale running progress.
"""
from __future__ import annotations

import threading
import time
import types
import unittest
from unittest.mock import patch

from backend import jobs


class _FakeReport:
    def __init__(self, data: dict) -> None:
        self._data = data

    def to_dict(self) -> dict:
        return self._data


class _FakeEngine:
    """Stands in for DSPMDiscoveryEngine. Emits collection/analysis progress
    through the config callback, optionally blocking to simulate a slow
    collection phase."""

    block_event: threading.Event | None = None
    emit_collected: bool = True
    raise_error: bool = False

    def __init__(self, config) -> None:
        self.config = config

    def run(self) -> _FakeReport:
        if self.__class__.block_event is not None:
            # Simulate a slow collection phase (no progress callbacks yet).
            self.__class__.block_event.wait(2.0)
        if self.__class__.raise_error:
            raise RuntimeError("winrm connection timed out")
        if self.__class__.emit_collected and self.config.progress_callback:
            self.config.progress_callback("collected", 3, 3)
            self.config.progress_callback("analyzing", 3, 3)
        return _FakeReport({"files": [{"name": "a.txt"}], "summary": {}})


def _config() -> types.SimpleNamespace:
    return types.SimpleNamespace(cancel_check=None, progress_callback=None)


class ScanJobLifecycleTests(unittest.TestCase):
    def test_completed_custom_job_reaches_100(self) -> None:
        job = jobs.ScanJob(id="j1", tenant_id="t1")
        jobs._run_custom_job(job, lambda _job: {"files": []})
        self.assertEqual(job.status, "completed")
        self.assertEqual(job.progress, 100)
        self.assertEqual(job.message, "Completed")
        self.assertIsNone(job.error)

    def test_failed_job_reports_failure_not_stale_running(self) -> None:
        def _boom(_job):
            raise RuntimeError("winrm connection timed out")

        job = jobs.ScanJob(id="j2", tenant_id="t1")
        job.progress = 7  # the value it would otherwise be stuck at
        jobs._run_custom_job(job, _boom)
        self.assertEqual(job.status, "failed")
        self.assertEqual(job.message, "Failed")
        self.assertTrue(job.error)
        self.assertNotEqual(job.status, "running")

    def test_scan_job_completes_and_leaves_running_progress_behind(self) -> None:
        _FakeEngine.block_event = None
        _FakeEngine.emit_collected = True
        _FakeEngine.raise_error = False
        job = jobs.ScanJob(id="j3", tenant_id="t1")
        saved: list[dict] = []
        with patch.object(jobs, "DSPMDiscoveryEngine", _FakeEngine):
            jobs._run_custom_job(job, lambda j: jobs._run_scan_job(j, _config(), saved.append))
        self.assertEqual(job.status, "completed")
        self.assertEqual(job.progress, 100)
        self.assertTrue(saved, "on_complete must be called with the scan data")

    def test_progress_advances_past_7_during_slow_collection(self) -> None:
        _FakeEngine.block_event = threading.Event()
        _FakeEngine.emit_collected = False
        _FakeEngine.raise_error = False
        job = jobs.ScanJob(id="j4", tenant_id="t1")
        saved: list[dict] = []
        try:
            with patch.object(jobs, "DSPMDiscoveryEngine", _FakeEngine), \
                    patch.object(jobs, "COLLECT_HEARTBEAT_SECONDS", 0.05):
                worker = threading.Thread(
                    target=lambda: jobs._run_scan_job(job, _config(), saved.append)
                )
                worker.start()
                # Give the heartbeat a few ticks while collection is "running".
                time.sleep(0.4)
                progress_during_collection = job.progress
                _FakeEngine.block_event.set()
                worker.join(timeout=3.0)
        finally:
            _FakeEngine.block_event = None
        self.assertGreater(
            progress_during_collection, 7,
            "progress must move during collection instead of freezing at 7",
        )
        self.assertLessEqual(progress_during_collection, jobs.COLLECT_HEARTBEAT_CEILING)
        self.assertGreaterEqual(job.progress, 96)

    def test_collecting_stage_moves_progress_past_14(self) -> None:
        job = jobs.ScanJob(id="c1", tenant_id="t1")
        jobs._update_scan_job_progress(job, "collecting", 100, 0)
        self.assertGreater(job.progress, 14)
        self.assertIn("Discovering", job.message)

    def test_collecting_stage_reports_reused_count(self) -> None:
        job = jobs.ScanJob(id="c2", tenant_id="t1")
        jobs._update_scan_job_progress(job, "collecting", 80, 55)
        self.assertIn("55 reused from cache", job.message)

    def test_progress_stages_are_monotonic_through_analysis(self) -> None:
        job = jobs.ScanJob(id="c3", tenant_id="t1")
        sequence = [
            ("collecting", 20, 0),
            ("collecting", 120, 10),
            ("collected", 120, 120),
            ("analyzing", 60, 120),
            ("analyzing", 120, 120),
        ]
        last = 0
        for stage, done, total in sequence:
            jobs._update_scan_job_progress(job, stage, done, total)
            self.assertGreaterEqual(job.progress, last)
            last = job.progress
        self.assertGreater(job.progress, 14)
        self.assertLessEqual(job.progress, 95)

    def test_status_api_dict_reports_progress_message_status(self) -> None:
        job = jobs.ScanJob(id="c4", tenant_id="t1")
        jobs._update_scan_job_progress(job, "analyzing", 60, 120)
        payload = job.to_dict()
        self.assertEqual(payload["status"], "queued")
        self.assertEqual(payload["progress"], job.progress)
        self.assertIn("Analyzing", payload["message"])
        self.assertIn("elapsed_seconds", payload)

    def test_collection_heartbeat_guard_advances_and_respects_ceiling(self) -> None:
        # The public guard is what keeps the remote (WinRM/SMB) blocking phase
        # visibly alive within a bounded band.
        job = jobs.ScanJob(id="hb1", tenant_id="t1")
        job.status = "running"
        job.progress = 8
        with patch.object(jobs, "COLLECT_HEARTBEAT_SECONDS", 0.05):
            with jobs.collection_heartbeat(job, ceiling=60):
                time.sleep(0.4)
                during = job.progress
        self.assertGreater(during, 8)
        self.assertLessEqual(during, 60)

    def test_collection_heartbeat_guard_deadline_fails_hung_remote_scan(self) -> None:
        job = jobs.ScanJob(id="hb2", tenant_id="t1")
        job.status = "running"
        with patch.object(jobs, "COLLECT_HEARTBEAT_SECONDS", 0.05), \
                patch.object(jobs, "SCAN_MAX_SECONDS", 1):
            with jobs.collection_heartbeat(job, ceiling=60):
                time.sleep(1.4)
        self.assertEqual(job.status, "failed")
        self.assertTrue(job.error)
        self.assertTrue(job.cancel_requested)

    def test_endpoint_analysis_reports_per_record_progress(self) -> None:
        from backend.app import _analyze_endpoint_records

        report = types.SimpleNamespace(_analyze_record=lambda record: record)
        job = jobs.ScanJob(id="ep1", tenant_id="t1")
        job.status = "running"
        job.progress = 70
        records = [{"path": f"C:/f{i}.txt"} for i in range(30)]
        analyzed = _analyze_endpoint_records(report, records, job, floor=70)
        self.assertEqual(len(analyzed), 30)
        self.assertEqual(job.progress, 90)
        self.assertIn("30/30", job.message)

    def test_endpoint_analysis_honors_cancellation(self) -> None:
        from backend.app import _analyze_endpoint_records

        report = types.SimpleNamespace(_analyze_record=lambda record: record)
        job = jobs.ScanJob(id="ep2", tenant_id="t1")
        job.status = "running"
        job.cancel_requested = True
        with self.assertRaises(RuntimeError):
            _analyze_endpoint_records(report, [{"path": "C:/f.txt"}], job)

    def test_scan_deadline_marks_hung_job_failed(self) -> None:
        _FakeEngine.block_event = threading.Event()
        _FakeEngine.emit_collected = False
        _FakeEngine.raise_error = False
        job = jobs.ScanJob(id="j5", tenant_id="t1")
        try:
            with patch.object(jobs, "DSPMDiscoveryEngine", _FakeEngine), \
                    patch.object(jobs, "COLLECT_HEARTBEAT_SECONDS", 0.05), \
                    patch.object(jobs, "SCAN_MAX_SECONDS", 1):
                worker = threading.Thread(
                    target=lambda: jobs._run_custom_job(
                        job, lambda j: jobs._run_scan_job(j, _config(), lambda _d: None)
                    )
                )
                worker.start()
                time.sleep(1.4)
                status_after_deadline = job.status
                self.assertEqual(status_after_deadline, "failed")
                self.assertTrue(job.error)
                _FakeEngine.block_event.set()
                worker.join(timeout=3.0)
        finally:
            _FakeEngine.block_event = None


if __name__ == "__main__":
    unittest.main()
