"""Classification runs on more than one core, and never at the scan's expense.

Classification is pure-Python CPU work, so on a GIL build the engine's analysis
threads run one detector at a time between them: six cores ran one. The
detectors moved into `discovery.detector_stage` - content and metadata in,
findings out, no engine state touched - which is what lets a worker process run
them.

Measured on a 2,160-file estate with GDPR, PCI DSS and NIST enabled:
75.1s in one process, 30.1s across five.

The pool is the risky half of that, so most of what follows is about the three
rules it obeys rather than about speed: never block on it, never fail because
of it, never start it when it cannot pay. The last one is not theoretical - a
44-file scan measured 75% SLOWER against an earlier version that started the
pool unconditionally, because warming five workers costs ~12s of CPU taken
from the cores the scan itself is using.
"""
from __future__ import annotations

import os
import pickle
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from discovery import detector_pool  # noqa: E402
from discovery.detector_stage import run_detector_stage, warm_up  # noqa: E402

ENGINE = Path("discovery/discovery_engine.py").read_text(encoding="utf-8")

RECORD = {"name": "hr.csv", "path": "/Shares/HR/hr.csv", "extension": ".csv", "tenant_id": "23"}
CONTENT = (
    "Full name: Aysel Mammadova\nEmail: aysel@prosol.az\n"
    "Payment card: 4111 1111 1111 1111 exp 09/28 cvv 123\n"
    "API key: sk_live_51H8zQ2eZvKYlo2C0abcdefghijklmnop\n"
)


def payload(**overrides) -> dict:
    base = {
        "content": CONTENT,
        "record": dict(RECORD),
        "framework_ids": ["gdpr", "pci_dss", "nist_sp800_60_enterprise"],
        "compliance_enabled": True,
        "timeout_seconds": 8.0,
        "custom_keywords": {},
    }
    base.update(overrides)
    return base


class StageIsPureTests(unittest.TestCase):
    """A worker has no engine, no database and no shared memory. Everything the
    detectors read has to travel with the file, and everything they produce has
    to travel back."""

    def test_the_payload_and_its_result_survive_a_process_boundary(self) -> None:
        sent = pickle.loads(pickle.dumps(payload()))
        result = run_detector_stage(sent)
        returned = pickle.loads(pickle.dumps(result))
        self.assertEqual(returned, result)
        self.assertTrue(returned["findings"])
        self.assertEqual(
            [row["name"] for row in returned["detector_rows"]],
            ["generic", "gdpr", "pci_dss", "nist_sp800_60_enterprise"],
        )

    def test_the_record_comes_back_with_its_annotations(self) -> None:
        """The detectors write onto the record they are given. In a worker that
        is a copy, so it is returned rather than lost at the boundary."""
        self.assertIn('returned = result.get("record")', ENGINE)
        self.assertIn("record.update(returned)", ENGINE)
        self.assertIn("record", run_detector_stage(payload()))

    def test_only_the_selected_frameworks_run(self) -> None:
        rows = run_detector_stage(payload(framework_ids=["gdpr"]))["detector_rows"]
        self.assertEqual([row["name"] for row in rows], ["generic", "gdpr"])
        rows = run_detector_stage(payload(compliance_enabled=False))["detector_rows"]
        self.assertEqual([row["name"] for row in rows], ["generic"])

    def test_a_detector_that_raises_degrades_only_itself(self) -> None:
        with mock.patch("discovery.detector_stage.classify_pci_content", side_effect=ValueError("boom")):
            result = run_detector_stage(payload())
        rows = {row["name"]: row for row in result["detector_rows"]}
        self.assertTrue(rows["pci_dss"]["degraded_mode"])
        self.assertIn("boom", rows["pci_dss"]["error"])
        self.assertFalse(rows["gdpr"]["degraded_mode"])
        self.assertTrue(result["findings"], "the other detectors still reported")

    def test_warm_up_builds_the_catalogs(self) -> None:
        """~2.5s of a worker's first file: importing the detectors, compiling
        the 46,000-term GDPR catalog and reading the NIST one. Paid before the
        worker is given anything real."""
        self.assertTrue(warm_up())


class PoolNeverCostsMoreThanItSavesTests(unittest.TestCase):
    def test_it_does_not_start_for_a_small_scan(self) -> None:
        pool = detector_pool.DetectorPool(workers=4)
        with mock.patch.object(pool, "start", side_effect=AssertionError("must not start")):
            pool.consider_start(detector_pool._START_AFTER_FILES - 1)

    def test_it_starts_once_the_collector_has_found_enough(self) -> None:
        pool = detector_pool.DetectorPool(workers=4)
        with mock.patch.object(pool, "start") as start:
            pool.consider_start(detector_pool._START_AFTER_FILES)
        start.assert_called_once()

    def test_the_collector_is_what_triggers_it_not_the_analyzer(self) -> None:
        """Warming has to overlap collection, which is I/O. Started once
        analysis is already running, the warm-ups compete with the scan for the
        same cores - a 360-file scan measured slower than no pool at all."""
        self.assertIn("self._detector_pool.consider_start(submitted)", ENGINE)
        self.assertIn("self._detector_pool.consider_start(len(records))", ENGINE)

    def test_compliance_off_means_no_pool(self) -> None:
        """The generic detector alone is 8ms a file; there is nothing to win."""
        self.assertFalse(detector_pool.build_pool(compliance_enabled=False).enabled)

    def test_the_operator_can_turn_it_off(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_DETECTOR_PROCESSES": "0"}):
            self.assertEqual(detector_pool._configured_workers(), 0)
        with mock.patch.dict(os.environ, {"DSPM_DETECTOR_PROCESSES": "3"}):
            self.assertEqual(detector_pool._configured_workers(), 3)
        with mock.patch.dict(os.environ, {"DSPM_DETECTOR_PROCESSES": "not a number"}):
            self.assertGreaterEqual(detector_pool._configured_workers(), 0)

    def test_a_machine_too_small_to_share_gets_no_pool(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_DETECTOR_PROCESSES", None)
            with mock.patch("os.cpu_count", return_value=2):
                self.assertEqual(detector_pool._configured_workers(), 0)
            with mock.patch("os.cpu_count", return_value=6):
                # One core is left for the parent, which is still collecting,
                # extracting and writing while the workers classify.
                self.assertEqual(detector_pool._configured_workers(), 5)


class PoolFailsSafeTests(unittest.TestCase):
    def test_a_pool_that_will_not_start_is_simply_not_used(self) -> None:
        pool = detector_pool.DetectorPool(workers=4)
        with mock.patch("discovery.detector_pool.ProcessPoolExecutor", side_effect=OSError("no")):
            pool.start()
        self.assertFalse(pool.enabled)
        self.assertIn("pool did not start", pool.diagnostics()["disabled_reason"])
        self.assertIsNone(pool.run(payload()), "the caller runs the stage itself")

    def test_a_worker_that_dies_disables_the_pool_once(self) -> None:
        """A broken pool stays broken, so this is decided once and not per
        file - otherwise every remaining file pays a failed round trip."""
        pool = detector_pool.DetectorPool(workers=1)

        class Boom:
            def submit(self, *_args, **_kwargs):
                raise RuntimeError("worker gone")

            def shutdown(self, **_kwargs):
                return None

        pool._executor = Boom()
        pool._warm = 1
        self.assertTrue(pool.ready)
        self.assertIsNone(pool.run(payload()))
        self.assertFalse(pool.enabled)
        self.assertIn("RuntimeError", pool.diagnostics()["disabled_reason"])

    def test_a_cold_pool_is_not_used(self) -> None:
        pool = detector_pool.DetectorPool(workers=4)
        pool._executor = object()
        pool._warm = 3  # one still building its catalogs
        self.assertFalse(pool.ready)
        self.assertIsNone(pool.run(payload()))
        self.assertEqual(pool.diagnostics()["files_in_process"], 1)

    def test_the_scan_reports_what_the_pool_did(self) -> None:
        self.assertIn('diagnostics["detector_pool"] = self._detector_pool.diagnostics()', ENGINE)
        keys = set(detector_pool.DetectorPool(workers=2).diagnostics())
        self.assertLessEqual(
            {"workers", "enabled", "warm_workers", "files_in_workers", "files_in_process", "disabled_reason"},
            keys,
        )

    def test_the_pool_is_closed_even_when_a_scan_raises(self) -> None:
        run = ENGINE[ENGINE.index("    def run(self) -> ScanReport:"):]
        run = run[:run.index(chr(10) + "    def ", 10)]
        self.assertIn("finally:", run)
        self.assertIn("self._detector_pool.shutdown()", run)


class EngineUsesTheStageTests(unittest.TestCase):
    def test_the_engine_calls_the_stage_not_the_detectors(self) -> None:
        """The detectors have one call site now, so a worker process and this
        process cannot drift apart."""
        for gone in ("classify_gdpr_content", "classify_pci_content", "classify_nist_content", "classify_content"):
            with self.subTest(symbol=gone):
                self.assertNotIn(f"{gone}(content", ENGINE)
        self.assertIn("result = self._detector_pool.run(payload) if self._detector_pool.enabled else None", ENGINE)
        self.assertIn("result = run_detector_stage(payload)", ENGINE)

    def test_custom_keywords_travel_with_the_file(self) -> None:
        """A worker has no database. The groups are resolved once per scan in
        the parent and sent with each payload."""
        self.assertIn("def _custom_keywords_payload(self, framework_ids: set[str])", ENGINE)
        self.assertIn('"custom_keywords": self._custom_keywords_payload(framework_ids)', ENGINE)


if __name__ == "__main__":
    unittest.main()
