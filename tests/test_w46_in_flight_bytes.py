"""W4.6: one in-flight bytes budget, charged at working size.

The pipeline bounded the records between collection and the end of their analysis by count
(72 on a six-core host): right for small files, and up to 72 texts of 16 MiB. The content
those records hold is now also charged, at working size, against one budget for the
process (``DSPM_IN_FLIGHT_MB``). A record waits, in order, while the records ahead of it
would leave too little; one larger than the whole budget runs alone; one without content
costs nothing. What the scan answers does not change.
"""
from __future__ import annotations

import os
import threading
import time
import unittest
from unittest import mock

from discovery import parallelism
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.parallelism import InFlightBytes, in_flight_bytes, reset_in_flight_bytes, working_size

MIB = 1024 * 1024


class TheBudgetTest(unittest.TestCase):

    def test_what_fits_is_charged_and_released(self) -> None:
        budget = InFlightBytes(10)
        self.assertTrue(budget.acquire(4))
        self.assertTrue(budget.acquire(6))
        self.assertEqual(budget.used, 10)
        budget.release(4)
        budget.release(6)
        self.assertEqual(budget.used, 0)
        self.assertEqual(budget.stats()["peak_in_use"], 10)

    def test_what_does_not_fit_waits_for_a_release(self) -> None:
        budget = InFlightBytes(10)
        budget.acquire(8)
        got = threading.Event()
        threading.Thread(target=lambda: (budget.acquire(5), got.set()), daemon=True).start()
        self.assertFalse(got.wait(0.3), "admitted past the budget")
        budget.release(8)
        self.assertTrue(got.wait(2))
        self.assertEqual(budget.used, 5)

    def test_one_larger_than_the_budget_runs_alone(self) -> None:
        budget = InFlightBytes(10)
        budget.acquire(3)
        got = threading.Event()
        threading.Thread(target=lambda: (budget.acquire(50), got.set()), daemon=True).start()
        self.assertFalse(got.wait(0.3))
        budget.release(3)
        self.assertTrue(got.wait(2), "a record over the whole budget was never admitted")
        self.assertEqual(budget.used, 50)

    def test_in_order_so_a_large_one_is_not_starved(self) -> None:
        budget = InFlightBytes(10)
        budget.acquire(6)
        order: list[str] = []
        big = threading.Thread(target=lambda: (budget.acquire(9), order.append("big")), daemon=True)
        big.start()
        time.sleep(0.2)
        small = threading.Thread(target=lambda: (budget.acquire(2), order.append("small")), daemon=True)
        small.start()
        time.sleep(0.3)
        self.assertEqual(order, [], "a later small record went ahead of the waiting large one")
        budget.release(6)
        big.join(2)
        self.assertEqual(order, ["big"])
        budget.release(9)
        small.join(2)
        self.assertEqual(order, ["big", "small"])

    def test_a_cancelled_scan_stops_waiting_and_leaves_the_queue(self) -> None:
        budget = InFlightBytes(10)
        budget.acquire(10)
        stop = threading.Event()
        result: list[bool] = []
        waiter = threading.Thread(target=lambda: result.append(budget.acquire(5, stop.is_set)), daemon=True)
        waiter.start()
        time.sleep(0.2)
        stop.set()
        waiter.join(3)
        self.assertEqual(result, [False])
        budget.release(10)
        self.assertTrue(budget.acquire(10), "the cancelled waiter still holds the head of the queue")

    def test_no_content_costs_nothing(self) -> None:
        budget = InFlightBytes(1)
        budget.acquire(1)
        self.assertTrue(budget.acquire(0))
        self.assertEqual(working_size({"content": ""}), 0)
        self.assertEqual(working_size({}), 0)
        self.assertEqual(working_size({"content": "abcd"}), 4 * parallelism.WORKING_SIZE_FACTOR)

    def test_the_setting(self) -> None:
        for value, expected in (("", 512), ("64", 64), ("1", 16), ("x", 512)):
            with self.subTest(value=value), mock.patch.dict(os.environ, {"DSPM_IN_FLIGHT_MB": value}):
                self.assertEqual(parallelism._resolve_in_flight_bytes(), expected * MIB)


class APipelineHoldsNoMoreThanTheBudgetTest(unittest.TestCase):

    def setUp(self) -> None:
        self.addCleanup(reset_in_flight_bytes)

    @staticmethod
    def _record(index: int, chars: int) -> dict:
        return {"source": "local", "path": f"doc_{index}.txt", "name": f"doc_{index}.txt", "extension": ".txt",
                "size": chars, "content": "x" * chars, "acl": {}}

    def _run(self, records: list[dict]) -> tuple[dict, list[str], int]:
        engine = DSPMDiscoveryEngine(ScanConfig(walk_local_path=False, max_workers=4, pipeline_buffer=64,
                                                persistent_cache_enabled=False))
        lock = threading.Lock()
        holding = {"now": 0, "peak": 0}
        charges = {record["path"]: working_size(record) for record in records}

        def analyze(record: dict) -> dict:
            with lock:
                holding["now"] += charges[record["path"]]
                holding["peak"] = max(holding["peak"], holding["now"])
            time.sleep(0.05)
            with lock:
                holding["now"] -= charges[record["path"]]
            return {"name": record["name"], "risk": {"level": "LOW"}}

        def collect(record_callback=None) -> list[dict]:
            for record in records:
                record_callback(dict(record))
            return records

        with mock.patch.object(engine, "_collect_records", side_effect=collect), \
                mock.patch.object(engine, "_analyze_record_safe", side_effect=analyze):
            report = engine.run()
        return report.scan_diagnostics["pipeline"], [item["name"] for item in report.files], holding["peak"]

    def test_records_wait_for_room_and_the_answer_is_the_same(self) -> None:
        records = [self._record(index, MIB) for index in range(8)]
        one = working_size(records[0])
        reset_in_flight_bytes(int(one * 2.5))
        pipeline, names, peak = self._run(records)
        self.assertEqual(names, [record["name"] for record in records])
        self.assertLessEqual(pipeline["peak_in_flight_bytes"], int(one * 2.5))
        self.assertLessEqual(peak, int(one * 2.5))
        self.assertGreater(pipeline["in_flight_byte_waits"], 0)
        self.assertEqual(in_flight_bytes().used, 0, "a finished scan left bytes charged")

    def test_a_record_over_the_whole_budget_still_runs(self) -> None:
        records = [self._record(0, 4 * MIB), self._record(1, 10)]
        reset_in_flight_bytes(MIB)
        pipeline, names, _peak = self._run(records)
        self.assertEqual(names, ["doc_0.txt", "doc_1.txt"])
        self.assertEqual(in_flight_bytes().used, 0)


if __name__ == "__main__":
    unittest.main()
