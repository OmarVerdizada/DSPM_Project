"""B2.4: an interrupted partitioned scan continues into the report it would have written.

B2.2b made a local scan persist one partition at a time, and in doing so made an
interruption worse than before: a scan killed part way through left its finished
partitions in the estate and no report. Revision 0014 records what continuing such a
scan needs. This holds the runner and the resume sweep to what that record promises -
above all, that a scan whose process is killed in the middle of a partition resumes
into the same report and the same estate as a scan that was never interrupted.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

from backend import jobs, partitioned_scan, scan_resumer, store
from discovery.discovery_engine import ScanConfig
from discovery.parity import accuracy_projection
from tests.test_partitioned_local_scan import ALL_FRAMEWORKS, TENANT, _LocalTest

REPO = Path(__file__).resolve().parents[1]
REQUEST = {"local_path": "estate", "max_depth": 4}
SECTIONS = ("compliance_summary", "pci_scope_summary", "gdpr_report", "nist_sp800_60_enterprise_report")

# The scan the parent kills: the same engine, estate rules and plan as the parent's
# uninterrupted scan, with a two-second lease and an engine that stalls - forever, as
# far as the parent is concerned - on the third partition it is given.
_CHILD = r'''
import json, sys, time
from pathlib import Path
from unittest.mock import MagicMock, patch

settings = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
sys.path.insert(0, settings["repo"])

from backend import partitioned_scan, store
from collectors import file_scanner
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

store.DB_PATH = Path(settings["db"])
store.init_db()
runs = {"n": 0}


class StallsOnTheThirdPartition(DSPMDiscoveryEngine):
    def run(self):
        runs["n"] += 1
        if runs["n"] == 3:
            Path(settings["marker"]).write_text("stalled", encoding="utf-8")
            time.sleep(600)
        return super().run()


with patch.object(file_scanner, "is_skipped_scan_path", side_effect=lambda path: "node_modules" in str(path).lower()), \
        patch.object(file_scanner, "file_owner", MagicMock(return_value="CORP\\owner")), \
        patch.object(partitioned_scan, "DSPMDiscoveryEngine", StallsOnTheThirdPartition):
    partitioned_scan.run_partitioned_scan(
        settings["tenant"], ScanConfig(**settings["config"]), request=settings["request"],
        scan_label="estate", compliance_enabled=True, compliance_frameworks=settings["frameworks"], max_files=3,
    )
Path(settings["marker"]).write_text("finished", encoding="utf-8")
'''


class AKilledScanResumesTest(_LocalTest):

    def _settings(self, name: str) -> dict:
        return dict(
            tenant_id=TENANT, local_path=str(self.estate), max_depth=4, use_sample_when_empty=True,
            persistent_cache_enabled=False, incremental_enabled=False, max_workers=2,
            cache_dir=str(self.base / f"{name}-cache"),
        )

    def _kill_in_the_third_partition(self) -> None:
        marker = self.base / "child.marker"
        script = self.base / "child.py"
        script.write_text(_CHILD, encoding="utf-8")
        settings = self.base / "child.json"
        settings.write_text(json.dumps({
            "repo": str(REPO), "db": str(store.DB_PATH), "marker": str(marker), "tenant": TENANT,
            "config": self._settings("killed"), "request": REQUEST, "frameworks": ALL_FRAMEWORKS,
        }), encoding="utf-8")
        env = {
            **os.environ,
            "DSPM_DB_PATH": str(store.DB_PATH),
            "DSPM_ARTIFACT_DIR": os.environ["DSPM_ARTIFACT_DIR"],
            "DSPM_PARTITION_LEASE_SECONDS": "2",
        }
        log_path = self.base / "child.log"
        with open(log_path, "wb") as log:
            child = subprocess.Popen([sys.executable, str(script), str(settings)], cwd=str(REPO), env=env,
                                     stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 240
                while not marker.exists():
                    if child.poll() is not None:
                        break
                    if time.monotonic() > deadline:
                        break
                    time.sleep(0.1)
            finally:
                # TerminateProcess on Windows, SIGKILL elsewhere: no handler, no cleanup.
                child.kill()
                child.wait(timeout=60)
        if not marker.exists() or marker.read_text(encoding="utf-8") != "stalled":
            self.fail("the scan process never reached its third partition:\n"
                      + log_path.read_text(encoding="utf-8", errors="replace")[-4000:])

    def test_a_scan_killed_inside_a_partition_resumes_into_the_uninterrupted_scans_report(self) -> None:
        self._use_database("whole")
        whole_compact = partitioned_scan.run_partitioned_scan(
            TENANT, ScanConfig(**self._settings("whole")), request=REQUEST, scan_label="estate",
            compliance_enabled=True, compliance_frameworks=ALL_FRAMEWORKS, max_files=3,
        )
        whole = store.read_scan_report(TENANT, whole_compact["scan_id"])
        whole_rows = self._rows()

        self._use_database("killed")
        self._kill_in_the_third_partition()
        (killed,) = store.list_unfinished_partitioned_scans()
        scan_id = killed["scan_id"]
        units = store.list_scan_partitions(TENANT, scan_id)
        self.assertGreater(len(units), 4, "the scan was not really partitioned")
        self.assertEqual([unit["status"] for unit in units[:3]], ["done", "done", "running"])
        self.assertEqual({unit["status"] for unit in units[3:]}, {"queued"})
        self.assertTrue(killed["resumable"])
        with store._connect() as conn:
            reports = conn.execute("SELECT COUNT(*) FROM scan_reports WHERE tenant_id = ?", (TENANT,)).fetchone()[0]
        self.assertEqual(reports, 0)

        # The dead process's lease and its scan's last touch both run out.
        time.sleep(2.5)
        resumed: list[dict] = []

        def resume(record: dict) -> None:
            resumed.append(record)
            partitioned_scan.continue_partitioned_scan(record["tenant_id"], record["scan_id"],
                                                       ScanConfig(**self._settings("killed")))

        self.assertEqual(scan_resumer.resume_stale_scans(resume, stale_after_seconds=2), [scan_id])
        self.assertEqual(len(resumed), 1)
        self.assertEqual(store.read_partitioned_scan(TENANT, scan_id)["status"], "done")
        attempts = [unit["attempt"] for unit in store.list_scan_partitions(TENANT, scan_id)]
        self.assertEqual(attempts[2], 2, "the interrupted partition was not run again")
        self.assertEqual(set(attempts[:2] + attempts[3:]), {1}, "a partition that had finished ran again")

        report = store.read_scan_report(TENANT, scan_id)
        self.assertEqual([f["path"] for f in report["files"]], [f["path"] for f in whole["files"]])
        self.assertEqual(accuracy_projection(report), accuracy_projection(whole))
        self.assertEqual(report["summary"], whole["summary"])
        for key in SECTIONS:
            self.assertEqual(report[key], whole[key], f"{key} differs")
        for key in ("records", "skipped_dirs", "files_discovered", "unreadable_dirs", "local_path", "max_depth"):
            self.assertEqual(report["scan_diagnostics"].get(key), whole["scan_diagnostics"].get(key), key)
        self.assertEqual(report["scan_label"], "estate")
        self.assertEqual(self._rows(), whole_rows, "the resumed scan's estate differs")


class RetriesAndStopsTest(_LocalTest):

    def _scan_rows(self) -> list:
        with store._connect() as conn:
            return conn.execute(
                "SELECT scan_id, status, error FROM partitioned_scans WHERE tenant_id = ?", (TENANT,),
            ).fetchall()

    def test_a_partition_that_fails_once_is_tried_again_and_the_scan_completes(self) -> None:
        self._use_database("retry")
        real_run = partitioned_scan.DSPMDiscoveryEngine.run
        calls = {"n": 0}

        def blinks_once(engine):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("the share blinked")
            return real_run(engine)

        with patch.object(partitioned_scan.DSPMDiscoveryEngine, "run", blinks_once):
            compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("retry"), request=REQUEST, max_files=3)
        units = store.list_scan_partitions(TENANT, compact["scan_id"])
        self.assertEqual({unit["status"] for unit in units}, {"done"})
        self.assertEqual(units[1]["attempt"], 2)
        self.assertEqual(store.read_partitioned_scan(TENANT, compact["scan_id"])["status"], "done")
        walked, _ = self._single_walk(self._config("retry"))
        self.assertEqual([f["path"] for f in store.read_scan_report(TENANT, compact["scan_id"])["files"]], walked,
                         "the retried partition's files are missing or out of order")

    def test_a_partition_that_keeps_failing_stops_the_scan_after_its_attempts(self) -> None:
        self._use_database("exhausted")
        real_run = partitioned_scan.DSPMDiscoveryEngine.run
        seen: dict = {}

        def always_fails_on_the_first(engine):
            key = (engine.config.local_path, engine.config.local_entry_names)
            seen.setdefault("key", key)
            if key == seen["key"]:
                raise OSError("locked")
            return real_run(engine)

        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_ATTEMPTS": "2"}), \
                patch.object(partitioned_scan.DSPMDiscoveryEngine, "run", always_fails_on_the_first):
            with self.assertRaisesRegex(partitioned_scan.ScanStopped, "failed 2 times"):
                partitioned_scan.run_partitioned_scan(TENANT, self._config("exhausted"), request=REQUEST, max_files=3)
        (row,) = self._scan_rows()
        self.assertEqual(row["status"], "failed")
        self.assertIn("OSError", row["error"])
        with store._connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_reports WHERE tenant_id = ?", (TENANT,)).fetchone()[0], 0)
        resume = MagicMock()
        self.assertEqual(scan_resumer.resume_stale_scans(resume, stale_after_seconds=0), [])
        resume.assert_not_called()

    def test_a_cancelled_scan_is_over_and_never_resumed(self) -> None:
        self._use_database("cancelled")
        job = MagicMock(id="job-cancelled", cancel_requested=False, progress=0, message="")
        real_persist = store.persist_partition

        def persist_then_cancel(*args, **kwargs):
            result = real_persist(*args, **kwargs)
            job.cancel_requested = True
            return result

        with patch.object(store, "persist_partition", side_effect=persist_then_cancel):
            with self.assertRaisesRegex(partitioned_scan.ScanStopped, "cancelled"):
                partitioned_scan.run_partitioned_scan(TENANT, self._config("cancelled"), request=REQUEST,
                                                            job=job, max_files=3)
        (row,) = self._scan_rows()
        self.assertEqual((row["status"], row["error"]), ("failed", "Scan cancelled"))
        resume = MagicMock()
        self.assertEqual(scan_resumer.resume_stale_scans(resume, stale_after_seconds=0), [])
        resume.assert_not_called()

    def test_a_scan_started_without_a_request_is_failed_by_the_sweep_and_says_why(self) -> None:
        self._use_database("norequest")
        record = partitioned_scan.start_partitioned_scan(TENANT, self._config("norequest"), max_files=3)
        self.assertFalse(record["resumable"])
        resume = MagicMock()
        self.assertEqual(scan_resumer.resume_stale_scans(resume, stale_after_seconds=0), [record["scan_id"]])
        resume.assert_not_called()
        stored = store.read_partitioned_scan(TENANT, record["scan_id"])
        self.assertEqual((stored["status"], stored["error"]), ("failed", scan_resumer.NO_REQUEST_ERROR))


class AFinalizeThatCommittedHasSucceededTest(_LocalTest):

    def test_a_done_mark_that_fails_after_the_finalize_committed_does_not_fail_the_scan(self) -> None:
        self._use_database("mark-fails")
        real_mark = store.mark_partitioned_scan

        def done_refused(tenant_id, scan_id, status, **kwargs):
            if status == "done":
                raise RuntimeError("database is locked")
            return real_mark(tenant_id, scan_id, status, **kwargs)

        with patch.object(store, "mark_partitioned_scan", side_effect=done_refused):
            compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("mark-fails"), request=REQUEST,
                                                            max_files=3)
        stored = store.read_partitioned_scan(TENANT, compact["scan_id"])
        self.assertEqual(stored["status"], "finalizing", "a scan whose report was written was marked failed")
        self.assertEqual(len(store.read_scan_report(TENANT, compact["scan_id"])["files"]), compact["file_count"])


class OneFinalizeWinsTest(_LocalTest):

    def test_a_finalize_after_the_first_committed_is_refused_and_the_report_stays_whole(self) -> None:
        self._use_database("second-finalize")
        compact = partitioned_scan.run_partitioned_scan(TENANT, self._config("second-finalize"),
                                                              request=REQUEST, max_files=3)
        before = store.read_scan_report(TENANT, compact["scan_id"])
        late = {"timestamp": "late", "source": "local", "summary": {}, "scan_diagnostics": {},
                "files": store.StreamedFiles(lambda: iter(()))}
        with self.assertRaises(store.ScanAlreadyFinalized):
            store.finalize_partitioned_scan(TENANT, compact["scan_id"], late, write_estate=True,
                                            file_count=0, sample_count=0)
        self.assertEqual(store.read_scan_report(TENANT, compact["scan_id"]), before)

    def test_a_finalize_that_read_the_records_before_another_committed_returns_that_report(self) -> None:
        self._use_database("raced-finalize")
        record = partitioned_scan.start_partitioned_scan(TENANT, self._config("raced-finalize"),
                                                               request=REQUEST, max_files=3)
        scan_id = record["scan_id"]
        with patch.object(partitioned_scan, "_finalize_when_claimed", return_value={}):
            partitioned_scan.continue_partitioned_scan(TENANT, scan_id, self._config("raced-finalize"))
        read_before_the_winner = store.list_scan_partitions(TENANT, scan_id)
        self.assertTrue(all(unit["has_records"] for unit in read_before_the_winner))
        winner = partitioned_scan.finalize_scan(TENANT, scan_id, timestamp="t", source="local")
        with patch.object(store, "list_scan_partitions", return_value=read_before_the_winner):
            loser = partitioned_scan.finalize_scan(TENANT, scan_id, timestamp="t", source="local")
        self.assertEqual(loser["file_count"], winner["file_count"])
        self.assertEqual(len(store.read_scan_report(TENANT, scan_id)["files"]), winner["file_count"])


class _FreshDatabase(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self._previous_path = store.DB_PATH
        store.DB_PATH = Path(self._dir.name) / "sweep.sqlite"
        self._env = mock.patch.dict(os.environ, {"DSPM_ARTIFACT_DIR": str(Path(self._dir.name) / "artifacts")})
        self._env.start()
        store.init_db()
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "sweep")

    def tearDown(self) -> None:
        self._env.stop()
        store.DB_PATH = self._previous_path
        self._dir.cleanup()

    def _record(self, scan_id: str = "scan-s", *, request: dict | None = None, job_id: str = "job-s",
                quiet_for: int = 0) -> None:
        store.register_partitioned_scan(self.tenant, scan_id, job_id=job_id,
                                        request=REQUEST if request is None else request, header={"timestamp": "t"})
        if quiet_for:
            self._age(scan_id, quiet_for)

    def _age(self, scan_id: str, seconds: int) -> None:
        with store._connect() as conn:
            conn.execute(
                "UPDATE partitioned_scans SET updated_at = ? WHERE tenant_id = ? AND scan_id = ?",
                ((datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat(), self.tenant, scan_id),
            )


class TheSweepTest(_FreshDatabase):

    def test_by_default_a_finalize_is_given_far_longer_than_a_lease(self) -> None:
        self._record("scan-running", quiet_for=400)
        self._record("scan-finalizing")
        self.assertTrue(store.claim_scan_finalize(self.tenant, "scan-finalizing"))
        self._age("scan-finalizing", 400)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_PARTITION_LEASE_SECONDS", None)
            self.assertEqual(scan_resumer.resume_stale_scans(MagicMock()), ["scan-running"],
                             "a finalize still writing its body was taken over after one lease")

    def test_a_scan_touched_within_a_lease_is_left_alone(self) -> None:
        self._record(quiet_for=10)
        resume = MagicMock()
        self.assertEqual(scan_resumer.resume_stale_scans(resume, stale_after_seconds=300), [])
        resume.assert_not_called()

    def test_a_quiet_scan_is_taken_over_once_under_its_old_job(self) -> None:
        self._record(quiet_for=400)
        resume = MagicMock()
        self.assertEqual(scan_resumer.resume_stale_scans(resume, stale_after_seconds=300), ["scan-s"])
        (handed,), _ = resume.call_args
        self.assertEqual((handed["scan_id"], handed["job_id"], handed["request"]["local_path"]), ("scan-s", "job-s", "estate"))
        self.assertEqual(scan_resumer.resume_stale_scans(resume, stale_after_seconds=300), [],
                         "the take-over did not count as a sign of life, so a second sweep took the scan again")
        self.assertEqual(resume.call_count, 1)

    def test_a_scan_without_a_job_is_given_one(self) -> None:
        self._record(job_id="", quiet_for=400)
        resume = MagicMock()
        scan_resumer.resume_stale_scans(resume, stale_after_seconds=300)
        (handed,), _ = resume.call_args
        self.assertTrue(handed["job_id"])
        self.assertEqual(store.read_partitioned_scan(self.tenant, "scan-s")["job_id"], handed["job_id"])

    def test_a_scan_left_finalizing_is_handed_back_as_running(self) -> None:
        self._record()
        self.assertTrue(store.claim_scan_finalize(self.tenant, "scan-s"))
        self._age("scan-s", 400)
        scan_resumer.resume_stale_scans(MagicMock(), stale_after_seconds=300)
        self.assertEqual(store.read_partitioned_scan(self.tenant, "scan-s")["status"], "running")
        self.assertTrue(store.claim_scan_finalize(self.tenant, "scan-s"), "the new runner could not claim the finalize")

    def test_a_live_runner_keeps_its_scan(self) -> None:
        self._record(quiet_for=400)
        self.assertTrue(store.touch_partitioned_scan(self.tenant, "scan-s"))
        self.assertEqual(scan_resumer.resume_stale_scans(MagicMock(), stale_after_seconds=300), [])

    def test_a_scan_running_in_this_process_is_never_taken(self) -> None:
        self._record(quiet_for=400)
        with patch.object(partitioned_scan, "_running_here", {(self.tenant, "scan-s")}):
            self.assertEqual(scan_resumer.resume_stale_scans(MagicMock(), stale_after_seconds=0), [])

    def test_a_typed_password_scan_is_failed_and_says_why_without_the_password(self) -> None:
        self._record(request={"server": "fs01", "password": "typed-secret-never-stored"}, quiet_for=400)
        resume = MagicMock()
        scan_resumer.resume_stale_scans(resume, stale_after_seconds=300)
        resume.assert_not_called()
        stored = store.read_partitioned_scan(self.tenant, "scan-s")
        self.assertEqual((stored["status"], stored["error"]), ("failed", scan_resumer.TYPED_PASSWORD_ERROR))
        self.assertNotIn("typed-secret-never-stored", json.dumps(stored))

    def test_a_full_queue_leaves_the_scan_for_later_and_any_other_error_fails_it(self) -> None:
        self._record("scan-later", quiet_for=400)
        self._record("scan-broken", quiet_for=400)

        def resume(record: dict) -> None:
            if record["scan_id"] == "scan-later":
                raise scan_resumer.ResumeLater("Async scan queue is full")
            raise ValueError("cannot rebuild")

        self.assertEqual(sorted(scan_resumer.resume_stale_scans(resume, stale_after_seconds=300)),
                         ["scan-broken", "scan-later"])
        self.assertEqual(store.read_partitioned_scan(self.tenant, "scan-later")["status"], "running")
        broken = store.read_partitioned_scan(self.tenant, "scan-broken")
        self.assertEqual(broken["status"], "failed")
        self.assertIn("ValueError", broken["error"])

    def test_a_scan_that_finished_is_never_marked_failed_afterwards(self) -> None:
        self._record()
        store.mark_partitioned_scan(self.tenant, "scan-s", "done")
        self.assertFalse(store.mark_partitioned_scan(self.tenant, "scan-s", "failed", error="late loser"))
        self.assertEqual(store.read_partitioned_scan(self.tenant, "scan-s")["status"], "done")

    def test_the_sweep_interval(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DSPM_SCAN_RESUME_INTERVAL_SECONDS", None)
            self.assertEqual(scan_resumer.resume_interval_seconds(), 60)
        with mock.patch.dict(os.environ, {"DSPM_SCAN_RESUME_INTERVAL_SECONDS": "not-a-number"}):
            self.assertEqual(scan_resumer.resume_interval_seconds(), 60)
        with mock.patch.dict(os.environ, {"DSPM_SCAN_RESUME_INTERVAL_SECONDS": "0"}):
            self.assertFalse(scan_resumer.start_scan_resumer(MagicMock()))


class JobsTest(_FreshDatabase):

    def test_a_restart_tells_a_resumable_partitioned_scans_job_that_it_continues(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        for job_id in ("job-resumable", "job-typed", "job-plain"):
            store.record_job({"id": job_id, "tenant_id": self.tenant, "status": "running", "progress": 40,
                              "message": "Running", "created_at": now})
        self._record("scan-resumable", job_id="job-resumable")
        self._record("scan-typed", job_id="job-typed", request={"server": "fs01", "password": "typed"})
        store.recover_interrupted_jobs()
        errors = {job_id: store.read_job(self.tenant, job_id)["error"] for job_id in ("job-resumable", "job-typed", "job-plain")}
        self.assertIn("continues automatically", errors["job-resumable"])
        self.assertIn("Re-run the scan", errors["job-typed"])
        self.assertIn("Re-run the scan", errors["job-plain"])

    def test_a_job_can_be_created_under_an_id_it_had_but_not_one_that_is_active(self) -> None:
        release = threading.Event()
        first = jobs.create_job(self.tenant, lambda job: release.wait(10) and {}, job_id=f"job-{uuid.uuid4().hex[:6]}")
        try:
            with self.assertRaises(ValueError):
                jobs.create_job(self.tenant, lambda job: {}, job_id=first.id)
        finally:
            release.set()
        deadline = time.monotonic() + 10
        while first.status in {"queued", "running"} and time.monotonic() < deadline:
            time.sleep(0.05)
        again = jobs.create_job(self.tenant, lambda job: {}, job_id=first.id)
        self.assertEqual(again.id, first.id)
        # The job records its state from a worker thread: let it finish before the test's
        # database is deleted, or Windows refuses to remove a file still open.
        deadline = time.monotonic() + 10
        while again.status in {"queued", "running"} and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(0.2)
        self.assertEqual(again.status, "completed")


class TheAppRebuildsTheScanTest(_FreshDatabase):

    def test_it_rebuilds_the_engine_from_the_request_and_continues_under_the_old_job(self) -> None:
        from backend import app as app_module

        record = {"tenant_id": self.tenant, "scan_id": "scan-s", "job_id": "job-old", "resumable": True,
                  "request": {"local_path": "enterprise_test_data", "max_depth": 3, "scan_label": "nightly"},
                  "header": {"requested_by": "analyst@corp"}}
        self._record(job_id="job-old")
        created = MagicMock(id="job-old")
        with patch.object(app_module, "create_job", return_value=created) as create_job:
            app_module._resume_partitioned_scan(record)
        args, kwargs = create_job.call_args
        self.assertEqual((args[0], kwargs["job_id"]), (self.tenant, "job-old"))
        runner = args[1]
        with patch.object(app_module, "continue_partitioned_scan", return_value={"scan_id": "scan-s"}) as continued, \
                patch.object(app_module, "evaluate_alerts", return_value=[]):
            runner(MagicMock(progress=0, cancel_requested=False))
        (tenant_id, scan_id, config), _ = continued.call_args
        self.assertEqual((tenant_id, scan_id, config.local_path, config.max_depth, config.server),
                         (self.tenant, "scan-s", "enterprise_test_data", 3, ""))

    def test_an_smb_scan_is_rebuilt_for_its_server_and_a_full_queue_is_left_for_later(self) -> None:
        from backend import app as app_module

        remote = {"tenant_id": self.tenant, "scan_id": "scan-r", "job_id": "job-r", "resumable": True,
                  "request": {"server": "fileserver01", "username": "svc-scan", "domain": "CORP"}, "header": {}}
        with patch.object(app_module, "create_job", return_value=MagicMock(id="job-r")) as create_job:
            app_module._resume_partitioned_scan(remote)
        runner = create_job.call_args[0][1]
        with patch.object(app_module, "continue_partitioned_scan", return_value={"scan_id": "scan-r"}) as continued, \
                patch.object(app_module, "evaluate_alerts", return_value=[]):
            runner(MagicMock(progress=0, cancel_requested=False))
        config = continued.call_args[0][2]
        self.assertEqual((config.server, config.username, config.domain, config.password),
                         ("fileserver01", "svc-scan", "CORP", ""))
        local = {"tenant_id": self.tenant, "scan_id": "scan-l", "job_id": "job-l", "resumable": True,
                 "request": {"local_path": "enterprise_test_data"}, "header": {}}
        with patch.object(app_module, "create_job", side_effect=RuntimeError("Async scan queue is full")):
            with self.assertRaises(scan_resumer.ResumeLater):
                app_module._resume_partitioned_scan(local)


if __name__ == "__main__":
    unittest.main()
