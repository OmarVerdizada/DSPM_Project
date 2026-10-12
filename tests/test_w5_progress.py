"""W5: a partitioned scan's progress is the work it has done, not the first unit's.

The real endpoint scan behind this sat at "Analyzing endpoint files 25/26 (94%)" for forty
minutes. Its first page - two files under the profile's roots, the plan's only unit when the
scan began - finished, and the bar went to 8 + 86 * 1/1 = 94%: the units that page found
were never counted, and every page reported its own progress in a whole scan's bands
(46-90%) straight onto the job. Now the total is re-read after each unit, a unit's own
progress is mapped into its slice of the bar, and one unit's room is held back while the
plan can still grow.
"""
from __future__ import annotations

import os
import re
import unittest
from types import SimpleNamespace
from unittest import mock

from backend import app as app_module
from backend import partitioned_scan, store
from backend.jobs import ScanJob
from backend.security import Principal
from tests.test_w13_endpoint_frontier import _Endpoint, _EndpointTest, _tree


class _RecordingJob(ScanJob):
    def __setattr__(self, name, value):
        if name in ("progress", "message") and "history" in self.__dict__:
            self.history.append((name, value))
        super().__setattr__(name, value)


class AUnitsProgressIsItsSliceTest(unittest.TestCase):

    def test_a_unit_moves_the_bar_only_within_its_slice(self) -> None:
        job = SimpleNamespace(progress=20, message="", cancel_requested=False)
        unit = partitioned_scan._UnitProgress(job, base=20, span=10, where="partition 3 of 8")
        unit.progress = 90           # a page's analysis band, as a whole scan reports it
        self.assertEqual(job.progress, 29)
        self.assertEqual(unit.progress, 90, "the unit reads back its own progress")
        unit.progress = 50           # never backwards
        self.assertEqual(job.progress, 29)
        unit.progress = 100
        self.assertEqual(job.progress, 30)
        unit.message = "Reading endpoint files 120/1198"
        self.assertEqual(job.message, "Reading endpoint files 120/1198 - partition 3 of 8")
        unit.cancel_requested = True
        self.assertTrue(job.cancel_requested)

    def test_the_bar_keeps_room_while_the_plan_can_grow(self) -> None:
        self.assertEqual(partitioned_scan._scan_progress(1, 1, growing=False), 94)
        self.assertEqual(partitioned_scan._scan_progress(1, 1, growing=True), 51)
        self.assertLess(partitioned_scan._scan_progress(3, 4, growing=True), 94)


class AFrontierScanIsNotNearlyDoneAfterItsFirstPageTest(_EndpointTest):

    def test_the_bar_follows_the_units_the_frontier_finds(self) -> None:
        endpoint = _Endpoint(_tree(files_per_folder=12, folders=4))
        payload = self._payload()
        principal = Principal(subject="tester", role="admin", tenant_id=self.tenant, auth_type="session")
        config = app_module._to_endpoint_config(payload, self.tenant)
        job = _RecordingJob(id="w5-progress", tenant_id=self.tenant, status="running")
        object.__setattr__(job, "history", [])
        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_FILES": "10", "DSPM_ENDPOINT_PAGE_FOLDERS": "2"}), \
                self._serve(endpoint):
            compact = app_module._run_endpoint_scan_payload(config, payload, principal, job=job)
        units = store.list_scan_partitions(self.tenant, compact["scan_id"])
        self.assertGreater(len(units), 4)
        progress = [value for name, value in job.history if name == "progress"]
        messages = [str(value) for name, value in job.history if name == "message"]
        self.assertEqual(progress, sorted(progress), "the bar went backwards")
        # Until the last unit has started, the bar is not near the end.
        last = max(int(match.group(1)) for message in messages
                   for match in [re.search(r"partition (\d+) of", message)] if match)
        self.assertEqual(last, len(units))
        before_last = []
        for name, value in job.history:
            if name == "message" and f"partition {len(units)} of" in str(value):
                break
            if name == "progress":
                before_last.append(value)
        self.assertTrue(before_last)
        self.assertLess(max(before_last), 90, f"the bar reached {max(before_last)}% with units still to run")
        # The total a message gives counts the units the frontier found, and no unit is past it.
        shown = [(int(match.group(1)), int(match.group(2))) for message in messages
                 for match in [re.search(r"partitions? (\d+)(?:-\d+)? of (\d+)", message)] if match]
        self.assertTrue(all(index <= total for index, total in shown), f"a unit past the total: {shown}")
        self.assertEqual(max(total for _index, total in shown), len(units),
                         "the total never counted the units the pages found")
        # A page's own messages say which partition they are.
        self.assertTrue(any(re.search(r"Reading endpoint files \d+/\d+ - partition \d+ of", m) for m in messages),
                        messages[:20])


if __name__ == "__main__":
    unittest.main()
