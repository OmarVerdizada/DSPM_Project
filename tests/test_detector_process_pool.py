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
    "Full name: Aysel Mammadova\nEmail: aysel@example.az\n"
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
        # W4.3 (section 25): through _consider_pool, which also decides by text size when
        # compliance is off - still called with the collector's count.
        self.assertIn("self._consider_pool(submitted, [normalized])", ENGINE)
        self.assertIn("self._consider_pool(len(records), records)", ENGINE)

    def test_compliance_off_still_uses_the_pool(self) -> None:
        """Restated for W4.3 (scaling roadmap section 25, W4.3: "the process pool serves every
        scan level"). The generic detector alone is 8 ms on a small file, but on a large text
        it is the file's whole cost: a scan without compliance read 1.4 MiB/s on one core.
        The start threshold, not the scan level, keeps a small scan from paying for workers."""
        with mock.patch.dict(os.environ, {"DSPM_DETECTOR_PROCESSES": "2", "DSPM_DETECTOR_POOL_SHARED": "0"}):
            pool = detector_pool.build_pool(compliance_enabled=False)
        try:
            self.assertTrue(pool.enabled)
        finally:
            pool.shutdown()
        with mock.patch.dict(os.environ, {"DSPM_DETECTOR_PROCESSES": "0"}):
            self.assertFalse(detector_pool.build_pool(compliance_enabled=False).enabled)

    def test_a_worker_is_not_sent_the_text_in_the_record_nor_returns_it(self) -> None:
        """W4.3: the record a worker gets leaves the content out; returned, it replaced the
        engine's text with an unpickled copy of it."""
        from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

        engine = DSPMDiscoveryEngine(ScanConfig(walk_local_path=False, persistent_cache_enabled=False))
        text = "contact a@example.com " * 4000  # 88 KB: large enough to go to a worker
        record = {"name": "a.txt", "path": "a.txt", "extension": ".txt", "content": text}
        sent: list[dict] = []

        class _Pool:
            enabled = True

            def run(self, payload_: dict) -> dict:
                sent.append(payload_)
                return run_detector_stage(pickle.loads(pickle.dumps(payload_)))

        engine._detector_pool = _Pool()
        findings, _metrics = engine._run_detectors(text, record, set())
        self.assertEqual(len(sent), 1)
        self.assertNotIn("content", sent[0]["record"])
        self.assertIs(sent[0]["content"], text)
        self.assertIs(record["content"], text, "the engine's text was replaced by the worker's copy")
        self.assertTrue(findings)

    @staticmethod
    def _engine_with_recording_pool(compliance: bool):
        from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

        engine = DSPMDiscoveryEngine(ScanConfig(walk_local_path=False, persistent_cache_enabled=False,
                                                compliance_enabled=compliance,
                                                compliance_frameworks=["gdpr"] if compliance else []))
        calls = {"run": 0, "start": 0, "consider": []}

        class _Pool:
            enabled = True

            def run(self, payload_: dict) -> None:
                calls["run"] += 1
                return None  # as a cold pool: the file runs in-process

            def start(self) -> None:
                calls["start"] += 1

            def consider_start(self, files: int) -> None:
                calls["consider"].append(files)

        engine._detector_pool = _Pool()
        return engine, calls

    def test_without_compliance_only_a_large_text_goes_to_a_worker(self) -> None:
        """W4.3: a 10 KiB file cost more to hand over than to classify - 3,000 of them ran 8%
        slower with five workers (MEASURED). Small texts stay here; large ones go."""
        engine, calls = self._engine_with_recording_pool(compliance=False)
        small, large = "a@example.com notes " * 400, "a@example.com notes " * 4000
        engine._run_detectors(small, {"name": "s.txt", "path": "s.txt", "content": small}, set())
        self.assertEqual(calls["run"], 0, "a small text was handed to a worker")
        engine._run_detectors(large, {"name": "l.txt", "path": "l.txt", "content": large}, set())
        self.assertEqual(calls["run"], 1)
        engine, calls = self._engine_with_recording_pool(compliance=True)
        engine._run_detectors(small, {"name": "s.txt", "path": "s.txt", "content": small}, set())
        self.assertEqual(calls["run"], 1, "a compliance scan keeps every file on the pool")

    def test_without_compliance_only_large_texts_start_the_pool(self) -> None:
        engine, calls = self._engine_with_recording_pool(compliance=False)
        small = [{"content": "x" * 1000}] * 500
        engine._consider_pool(500, small)
        self.assertEqual(calls["start"], 0, "small files started workers they cannot use")
        large = {"content": "x" * (65 * 1024)}
        for _ in range(3):
            engine._consider_pool(501, [large])
        self.assertEqual(calls["start"], 0)
        engine._consider_pool(502, [large])
        self.assertEqual(calls["start"], 1)
        engine, calls = self._engine_with_recording_pool(compliance=True)
        engine._consider_pool(500, small)
        self.assertEqual(calls["consider"], [500])
        with mock.patch.dict(os.environ, {"DSPM_DETECTOR_POOL_MIN_KIB": "8"}):
            self.assertEqual(detector_pool.min_routed_chars(), 8 * 1024)

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
        # W4.3 (section 25): the pool is sent the payload with the record's copy of the text left out.
        self.assertIn("result = (self._detector_pool.run({**payload, \"record\":", ENGINE)
        self.assertIn("result = run_detector_stage(payload)", ENGINE)

    def test_custom_keywords_travel_with_the_file(self) -> None:
        """A worker has no database. The groups are resolved once per scan in
        the parent and sent with each payload."""
        self.assertIn("def _custom_keywords_payload(self, framework_ids: set[str])", ENGINE)
        self.assertIn('"custom_keywords": self._custom_keywords_payload(framework_ids)', ENGINE)


if __name__ == "__main__":
    unittest.main()
