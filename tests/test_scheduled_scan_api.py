"""B3: the console side of scheduled scans - the endpoints, and the job a schedule starts.

A schedule is a scan nobody will be there to start, so the console refuses one it could
not run alone: a typed password is never stored, and a schedule that needed one would
fail every night at the same point. Everything else is the ordinary shape - a tenant's
schedules are its own, a viewer can read them and an analyst can change them.

The job a due schedule starts is an ordinary asynchronous scan, and what became of it is
written back to the schedule, so a week of unattended nights can be read afterwards.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from unittest import mock
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from backend import app as app_module, scan_scheduler, store
from backend.app import app
from backend.security import create_token, hash_password

LATER = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()


def _headers(tenant: str = "default", role: str = "admin", subject: str = "admin") -> dict:
    return {"Authorization": f"Bearer {create_token(subject, role, tenant)}"}


class ScanScheduleApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def setUp(self) -> None:
        self.made: list[tuple[str, str]] = []

    def tearDown(self) -> None:
        # Nothing may be left due: another test's app startup would run it.
        for tenant, schedule_id in self.made:
            store.delete_scan_schedule(tenant, schedule_id)

    def _create(self, tenant: str = "default", subject: str = "admin", **overrides) -> dict:
        payload = {
            "name": "nightly",
            "interval_seconds": 86400,
            "first_run_at": LATER,
            "scan": {"local_path": "enterprise_test_data", "scan_label": "nightly"},
        }
        payload.update(overrides)
        response = self.client.post("/api/scan-schedules", json=payload,
                                    headers=_headers(tenant, subject=subject))
        self.assertEqual(response.status_code, 200, response.text)
        schedule = response.json()
        self.made.append((tenant, schedule["schedule_id"]))
        return schedule

    def test_a_schedule_is_created_listed_changed_and_deleted(self) -> None:
        schedule = self._create()
        self.assertEqual((schedule["name"], schedule["interval_seconds"], schedule["enabled"]),
                         ("nightly", 86400, True))
        self.assertEqual(schedule["request"]["local_path"], "enterprise_test_data")
        self.assertEqual(schedule["created_by"], "admin")

        listed = self.client.get("/api/scan-schedules", headers=_headers()).json()["schedules"]
        self.assertIn(schedule["schedule_id"], [item["schedule_id"] for item in listed])

        changed = self.client.patch(
            f"/api/scan-schedules/{schedule['schedule_id']}",
            json={"name": "weekly", "interval_seconds": 7 * 86400, "enabled": False},
            headers=_headers(),
        )
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertEqual((changed.json()["name"], changed.json()["interval_seconds"], changed.json()["enabled"]),
                         ("weekly", 7 * 86400, False))

        deleted = self.client.delete(f"/api/scan-schedules/{schedule['schedule_id']}", headers=_headers())
        self.assertEqual(deleted.json(), {"deleted": True})
        self.assertIsNone(store.read_scan_schedule("default", schedule["schedule_id"]))

    def test_a_typed_password_is_refused_rather_than_half_stored(self) -> None:
        response = self.client.post(
            "/api/scan-schedules",
            json={"name": "fileserver", "first_run_at": LATER,
                  "scan": {"server": "fs01", "username": "svc", "password": "hunter2-not-for-disk"}},
            headers=_headers(),
        )
        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("typed password", response.text)
        self.assertEqual(store.list_scan_schedules("default"), [])

    def test_a_vaulted_credential_is_what_a_schedule_runs_with(self) -> None:
        schedule = self._create(scan={"server": "fs01", "username": "svc", "credential_ref": "ref-nightly"})
        self.assertEqual(schedule["request"]["credential_ref"], "ref-nightly")
        self.assertNotIn("password", schedule["request"])

    def test_run_now_makes_a_schedule_due(self) -> None:
        schedule = self._create()
        self.assertGreater(schedule["next_run_at"], datetime.now(timezone.utc).isoformat())
        response = self.client.post(f"/api/scan-schedules/{schedule['schedule_id']}/run", headers=_headers())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertLessEqual(response.json()["next_run_at"], datetime.now(timezone.utc).isoformat())

    def test_a_missing_schedule_is_a_404(self) -> None:
        self.assertEqual(self.client.patch("/api/scan-schedules/sch_nothing", json={"name": "x"},
                                           headers=_headers()).status_code, 404)
        self.assertEqual(self.client.post("/api/scan-schedules/sch_nothing/run", headers=_headers()).status_code, 404)
        self.assertEqual(self.client.delete("/api/scan-schedules/sch_nothing", headers=_headers()).json(),
                         {"deleted": False})

    def test_one_tenant_cannot_see_or_change_anothers(self) -> None:
        tenant = f"sched-{uuid4().hex[:8]}"
        store.create_tenant(tenant, "other tenant")
        # The principal's tenant comes from the user record, not the token claim, so
        # isolation needs a real admin over there.
        other_admin = f"sadmin-{uuid4().hex[:6]}"
        store.create_user(other_admin, hash_password("x9!Schedule"), "admin", tenant)
        self.addCleanup(store.delete_user, other_admin)
        mine = self._create(tenant, subject=other_admin)
        listed = self.client.get("/api/scan-schedules", headers=_headers()).json()["schedules"]
        self.assertNotIn(mine["schedule_id"], [item["schedule_id"] for item in listed])
        self.assertEqual(self.client.patch(f"/api/scan-schedules/{mine['schedule_id']}", json={"name": "theirs"},
                                           headers=_headers()).status_code, 404)
        self.assertEqual(self.client.delete(f"/api/scan-schedules/{mine['schedule_id']}",
                                            headers=_headers()).json(), {"deleted": False})
        self.assertIsNotNone(store.read_scan_schedule(tenant, mine["schedule_id"]))

    def test_a_viewer_reads_and_an_analyst_changes(self) -> None:
        schedule = self._create()
        watcher = f"swatch-{uuid4().hex[:6]}"
        store.create_user(watcher, hash_password("x9!Watcher"), "viewer", "default")
        self.addCleanup(store.delete_user, watcher)
        viewer = _headers(role="viewer", subject=watcher)
        self.assertEqual(self.client.get("/api/scan-schedules", headers=viewer).status_code, 200)
        refused = self.client.post(
            "/api/scan-schedules",
            json={"name": "no", "first_run_at": LATER, "scan": {"local_path": "enterprise_test_data"}},
            headers=viewer,
        )
        self.assertEqual(refused.status_code, 403, refused.text)
        self.assertEqual(self.client.delete(f"/api/scan-schedules/{schedule['schedule_id']}",
                                            headers=viewer).status_code, 403)


class TheJobASchedulStartsTest(unittest.TestCase):

    def setUp(self) -> None:
        self.tenant = "default"
        self.schedule = store.create_scan_schedule(
            self.tenant, name="nightly", request={"local_path": "enterprise_test_data"},
            interval_seconds=86400, first_run_at=datetime.now(timezone.utc) + timedelta(days=30),
            created_by="admin",
        )

    def tearDown(self) -> None:
        store.delete_scan_schedule(self.tenant, self.schedule["schedule_id"])

    def test_it_starts_an_asynchronous_scan_rebuilt_from_the_stored_request(self) -> None:
        with mock.patch.object(app_module, "create_job", return_value=MagicMock(id="job-sched")) as create_job:
            app_module._start_scheduled_scan(self.schedule)
        tenant_id, runner = create_job.call_args[0]
        self.assertEqual(tenant_id, self.tenant)

        with mock.patch.object(app_module, "partitioned_scans_enabled", return_value=True), \
                mock.patch.object(app_module, "_run_partitioned_scan_payload",
                                  return_value={"scan_id": "20260917010203"}) as ran:
            self.assertEqual(runner(MagicMock(progress=0, cancel_requested=False))["scan_id"], "20260917010203")
        config, payload, principal = ran.call_args[0][0], ran.call_args[0][1], ran.call_args[0][2]
        self.assertEqual(config.local_path, "enterprise_test_data")
        self.assertTrue(payload.async_scan, "a scheduled scan must not block the sweep")
        self.assertIn(self.schedule["schedule_id"], principal.subject)

        stored = store.read_scan_schedule(self.tenant, self.schedule["schedule_id"])
        self.assertEqual((stored["last_status"], stored["last_scan_id"]), ("completed", "20260917010203"))

    def test_a_schedule_whose_folder_is_gone_fails_that_run_and_no_more(self) -> None:
        gone = store.create_scan_schedule(
            self.tenant, name="gone", request={"local_path": "no-such-folder-here"},
            interval_seconds=86400, first_run_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        self.addCleanup(store.delete_scan_schedule, self.tenant, gone["schedule_id"])
        self.assertEqual(scan_scheduler.run_due_schedules(app_module._start_scheduled_scan), [])
        stored = store.read_scan_schedule(self.tenant, gone["schedule_id"])
        self.assertEqual(stored["last_status"], "failed")
        self.assertIn("FileNotFoundError", stored["last_error"])
        self.assertGreater(stored["next_run_at"], datetime.now(timezone.utc).isoformat(),
                           "the schedule lost its place because one run could not start")

    def test_a_scan_that_fails_is_written_back_to_the_schedule(self) -> None:
        with mock.patch.object(app_module, "create_job", return_value=MagicMock(id="job-sched")) as create_job:
            app_module._start_scheduled_scan(self.schedule)
        runner = create_job.call_args[0][1]
        with mock.patch.object(app_module, "partitioned_scans_enabled", return_value=True), \
                mock.patch.object(app_module, "_run_partitioned_scan_payload",
                                  side_effect=RuntimeError("Scan cancelled")):
            with self.assertRaises(RuntimeError):
                runner(MagicMock(progress=0, cancel_requested=False))
        stored = store.read_scan_schedule(self.tenant, self.schedule["schedule_id"])
        self.assertEqual((stored["last_status"], stored["last_error"]), ("failed", "RuntimeError"))


if __name__ == "__main__":
    unittest.main()
