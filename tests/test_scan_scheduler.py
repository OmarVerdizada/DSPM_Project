"""B3: a backend runs scheduled scans unattended, and a week alone changes nothing.

The gate is a week: a daily schedule, ticked hour by hour through seven days, runs seven
times - not six, not eight - and a run that cannot be started is a failed run, not the
end of the schedule. Two more rules matter as much:

- a backend that was off for a week owes one scan, not a week of them, because the next
  run is counted from now rather than from the due time that passed;
- two backends sharing a database start a due schedule once between them, because the
  claim is a compare-and-set on that due time.

A schedule that needed a typed password could not run unattended anyway, and the store
never keeps one.
"""

from __future__ import annotations

import os
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock

from backend import scan_scheduler, store

DAY = 24 * 3600


class _ScheduleTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self._previous_path = store.DB_PATH
        store.DB_PATH = Path(self._dir.name) / "schedules.sqlite"
        self._env = mock.patch.dict(os.environ, {"DSPM_ARTIFACT_DIR": str(Path(self._dir.name) / "artifacts")})
        self._env.start()
        store.init_db()
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "schedules")
        self.week_start = datetime(2026, 9, 14, 2, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self._env.stop()
        store.DB_PATH = self._previous_path
        self._dir.cleanup()

    def _schedule(self, **overrides) -> dict:
        settings = dict(
            name="nightly", request={"local_path": "enterprise_test_data"}, interval_seconds=DAY,
            first_run_at=self.week_start, created_by="analyst@corp",
        )
        settings.update(overrides)
        return store.create_scan_schedule(self.tenant, **settings)


class TheWeekAloneTest(_ScheduleTest):

    def test_a_daily_schedule_runs_once_a_day_for_a_week_whatever_one_run_does(self) -> None:
        schedule = self._schedule()
        tick = {"now": self.week_start}
        started: list[datetime] = []
        refused = {"once": True}

        def start(claimed: dict) -> None:
            self.assertEqual(claimed["schedule_id"], schedule["schedule_id"])
            if refused["once"] and tick["now"] >= self.week_start + timedelta(days=3):
                refused["once"] = False
                raise RuntimeError("Async scan queue is full")
            started.append(tick["now"])

        for hour in range(7 * 24):
            tick["now"] = self.week_start + timedelta(hours=hour)
            scan_scheduler.run_due_schedules(start, now=tick["now"])

        stored = store.read_scan_schedule(self.tenant, schedule["schedule_id"])
        self.assertEqual(stored["runs"], 7, "a day was missed, or one ran twice")
        self.assertEqual(len(started), 6, "the refused run was counted as started")
        self.assertEqual([moment.hour for moment in started], [2] * 6, "the schedule drifted through the day")
        gaps = [int((b - a).total_seconds()) for a, b in zip(started, started[1:])]
        self.assertEqual(gaps, [DAY, DAY, 2 * DAY, DAY, DAY], "the day after a refused run was not the next day")
        self.assertFalse(refused["once"], "the failing run never happened")
        due = datetime.fromisoformat(stored["next_run_at"])
        self.assertEqual(int((due - self.week_start).total_seconds()), 7 * DAY)

    def test_a_backend_that_was_off_owes_one_scan_not_a_weeks_worth(self) -> None:
        schedule = self._schedule(first_run_at=self.week_start - timedelta(days=7))
        started: list[dict] = []
        self.assertEqual(scan_scheduler.run_due_schedules(started.append, now=self.week_start),
                         [schedule["schedule_id"]])
        self.assertEqual(scan_scheduler.run_due_schedules(started.append, now=self.week_start + timedelta(minutes=1)),
                         [])
        self.assertEqual(len(started), 1)
        stored = store.read_scan_schedule(self.tenant, schedule["schedule_id"])
        self.assertEqual(stored["runs"], 1)
        self.assertEqual(int((datetime.fromisoformat(stored["next_run_at"]) - self.week_start).total_seconds()), DAY)

    def test_two_backends_start_a_due_schedule_once_between_them(self) -> None:
        self._schedule()
        first = store.claim_due_schedules(now=self.week_start)
        second = store.claim_due_schedules(now=self.week_start)
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [], "both backends started the same scheduled scan")

    def test_a_disabled_schedule_waits_until_it_is_enabled_again(self) -> None:
        schedule = self._schedule(enabled=False)
        self.assertEqual(scan_scheduler.run_due_schedules(MagicMock(), now=self.week_start), [])
        store.update_scan_schedule(self.tenant, schedule["schedule_id"], enabled=True)
        self.assertEqual(scan_scheduler.run_due_schedules(MagicMock(), now=self.week_start),
                         [schedule["schedule_id"]])

    def test_a_run_that_could_not_be_started_says_so_on_the_schedule(self) -> None:
        schedule = self._schedule()

        def refuse(_claimed: dict) -> None:
            raise RuntimeError("Too many active scans for this tenant")

        self.assertEqual(scan_scheduler.run_due_schedules(refuse, now=self.week_start), [])
        stored = store.read_scan_schedule(self.tenant, schedule["schedule_id"])
        self.assertEqual(stored["last_status"], "failed")
        self.assertIn("RuntimeError", stored["last_error"])
        self.assertEqual(stored["runs"], 1, "a refused run still counts as the run for that day")


class TheStoredScheduleTest(_ScheduleTest):

    def test_a_typed_password_is_never_stored(self) -> None:
        schedule = self._schedule(request={"server": "fs01", "username": "svc", "password": "hunter2-not-for-disk"})
        self.assertNotIn("password", schedule["request"])
        self.assertEqual(schedule["request"]["server"], "fs01")
        with store._connect() as conn:
            raw = conn.execute(
                "SELECT request_json FROM scan_schedules WHERE tenant_id = ?", (self.tenant,),
            ).fetchone()["request_json"]
        self.assertNotIn("hunter2-not-for-disk", raw)

    def test_the_interval_has_a_floor_and_a_ceiling(self) -> None:
        for wanted, expected in ((30, 300), (0, 300), ("not-a-number", 86_400), (3600, 3600), (10 ** 9, 366 * DAY)):
            with self.subTest(wanted=wanted):
                schedule = self._schedule(interval_seconds=wanted)
                self.assertEqual(schedule["interval_seconds"], expected)

    def test_a_schedule_can_be_renamed_repointed_and_deleted(self) -> None:
        schedule = self._schedule()
        changed = store.update_scan_schedule(
            self.tenant, schedule["schedule_id"], name="weekly", interval_seconds=7 * DAY,
            request={"local_path": "enterprise_test_data", "compliance_enabled": True},
        )
        self.assertEqual((changed["name"], changed["interval_seconds"]), ("weekly", 7 * DAY))
        self.assertTrue(changed["request"]["compliance_enabled"])
        self.assertEqual([s["schedule_id"] for s in store.list_scan_schedules(self.tenant)], [schedule["schedule_id"]])
        self.assertTrue(store.delete_scan_schedule(self.tenant, schedule["schedule_id"]))
        self.assertIsNone(store.read_scan_schedule(self.tenant, schedule["schedule_id"]))
        self.assertFalse(store.delete_scan_schedule(self.tenant, schedule["schedule_id"]))

    def test_another_tenant_cannot_see_it(self) -> None:
        other = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(other, "other")
        schedule = self._schedule()
        self.assertIsNone(store.read_scan_schedule(other, schedule["schedule_id"]))
        self.assertEqual(store.list_scan_schedules(other), [])

    def test_erasing_a_tenant_erases_its_schedules(self) -> None:
        self._schedule()
        store.delete_tenant_with_data(self.tenant)
        with store._connect() as conn:
            left = conn.execute(
                "SELECT COUNT(*) AS n FROM scan_schedules WHERE tenant_id = ?", (self.tenant,),
            ).fetchone()["n"]
        self.assertEqual(left, 0)

    def test_the_sweep_can_be_turned_off(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_SCAN_SCHEDULER_INTERVAL_SECONDS", None)
            self.assertEqual(scan_scheduler.scheduler_interval_seconds(), 30)
        with mock.patch.dict(os.environ, {"DSPM_SCAN_SCHEDULER_INTERVAL_SECONDS": "not-a-number"}):
            self.assertEqual(scan_scheduler.scheduler_interval_seconds(), 30)
        with mock.patch.dict(os.environ, {"DSPM_SCAN_SCHEDULER_INTERVAL_SECONDS": "0"}):
            self.assertFalse(scan_scheduler.start_scan_scheduler(MagicMock()))


if __name__ == "__main__":
    unittest.main()
