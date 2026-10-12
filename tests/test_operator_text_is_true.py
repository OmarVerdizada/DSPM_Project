"""What the API and the console tell an operator about a scan is true (Waves 1-2 re-verified).

Found on 2026-10-08, re-reading every operator-facing line about job states, pauses and
coverage against the code that produces the state:

- an incomplete scan was announced with a green "Scan completed" (pollScan warned, then
  its caller overwrote it), and a scan run in the request could not say it was incomplete;
- a cancelled scan was reported as "Scan failed";
- a scan run in the request that paused answered 400 "Scan failed ... retry", though the
  resume sweep continues it and a retry starts a second scan;
- a queued scan that paused kept saying "A worker is scanning partition N of M", and the
  job that stopped following it said "Scan failed. Check backend logs";
- a full local disk was classed as the file server being unreachable;
- the coverage chip said "full" of a scan with gaps, the coverage card called files it
  never read "Clear", and the report said "no coverage exceptions" past quarantined units,
  unreadable folders and folders a depth limit kept it out of;
- a direct scan's progress bar was driven by the clock, and an endpoint fetch's heartbeat
  pushed the bar above the band its real progress moves in;
- the scan-level hints described what the levels do not do.
"""
from __future__ import annotations

import errno
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from uuid import uuid4

from backend import db, failures, jobs, partitioned_scan, store

ROOT = Path(__file__).resolve().parent.parent
APP = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
NODE = shutil.which("node")
_INCOMPLETE = {"scan_diagnostics": {"incremental": {"complete": False}, "unreadable_dirs": ["C:/a", "C:/b"]}}


def _statement(start: str) -> str:
    """A top-level statement of app.js, to its closing brace at the start of a line."""
    begin = APP.index(start)
    assert APP.rfind("\n", 0, begin) + 1 == begin, f"{start!r} is not top-level"
    if start.startswith("const "):
        return APP[begin:APP.index(";\n", begin) + 1]
    closing = "\n});\n" if "addEventListener(" in start else "\n}\n"
    return APP[begin:APP.index(closing, begin) + len(closing)]


def _js(statements: list[str], expression: str):
    script = "\n".join(_statement(start) for start in statements)
    script += f"\nprocess.stdout.write(JSON.stringify({expression}));"
    run = subprocess.run([NODE, "-e", script], capture_output=True, text=True, timeout=60, check=False)
    if run.returncode != 0:
        raise AssertionError(run.stderr[:800])
    return json.loads(run.stdout)


class _Store(unittest.TestCase):
    def setUp(self) -> None:
        if not db.is_postgres():
            temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
            self.addCleanup(temp.cleanup)
            original = store.DB_PATH
            store.DB_PATH = Path(temp.name) / "text.sqlite"
            self.addCleanup(setattr, store, "DB_PATH", original)
        store.init_db()
        self.tenant = f"text-{uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "Operator text")


class AScanSaysHowItFinishedTest(unittest.TestCase):

    def test_a_scan_run_in_the_request_answers_with_its_completion(self) -> None:
        from backend import app as app_module

        answer = app_module._scan_answer({**_INCOMPLETE, "files": [], "summary": {}},
                                         SimpleNamespace(compact_result=True))
        self.assertEqual(answer["completion"]["status"], "incomplete")
        self.assertIn("2 folder(s) could not be listed", answer["completion"]["message"])
        whole = app_module._scan_answer({"files": [], "summary": {}}, SimpleNamespace(compact_result=False))
        self.assertEqual(whole["completion"]["status"], "completed")

    def test_a_pause_is_answered_as_a_pause_not_as_a_failure_to_retry(self) -> None:
        from backend import app as app_module

        paused = partitioned_scan.ScanPaused("Scan paused: free disk on the data volume (C:\\) is 10 MB, "
                                             "below the 2048 MB floor (DSPM_MIN_FREE_DISK_MB); it continues automatically")
        with mock.patch.dict(os.environ, {"DSPM_SCAN_RESUME_INTERVAL_SECONDS": "60"}):
            error = app_module._safe_operation_error("Scan failed", paused)
        self.assertEqual((error.status_code, error.detail["code"]), (409, "scan_paused"))
        self.assertNotIn("retry", error.detail["hint"].lower())
        self.assertIn("data volume", error.detail["hint"])
        # Nothing will continue it: a failure, and it says why.
        with mock.patch.dict(os.environ, {"DSPM_SCAN_RESUME_INTERVAL_SECONDS": "0"}):
            error = app_module._safe_operation_error("Scan failed", paused)
        self.assertEqual((error.status_code, error.detail["code"]), (400, "scan_stopped"))
        self.assertIn("free disk space ran low", error.detail["hint"])

    def test_the_507_does_not_advise_lowering_the_floor(self) -> None:
        from fastapi import HTTPException

        from backend import app as app_module
        from backend import disk_guard

        with mock.patch.object(disk_guard, "low_space_reason", return_value="free disk on the data volume (C:\\) is 1 MB"), \
                self.assertRaises(HTTPException) as refused:
            app_module._require_scan_licence()
        self.assertNotIn("lower DSPM_MIN_FREE_DISK_MB", str(refused.exception.detail))


class APauseSaysWhyTest(unittest.TestCase):

    def test_a_low_disk_pause_names_the_volume(self) -> None:
        text = jobs._safe_job_error(Exception("Scan paused: free disk on the wal archive volume (E:\\) is 12 MB, "
                                              "below the 2048 MB floor (DSPM_MIN_FREE_DISK_MB)"))
        self.assertIn("the wal archive volume, E:\\", text)

    def test_a_pause_nothing_continues_says_its_real_reason(self) -> None:
        for raw, reason in (("Scan paused: its target cannot be reached", "could not be reached"),
                            ("Scan paused: OperationalError (infrastructure)", "database or the network"),
                            ("Scan paused: free disk on the data volume", "free disk"),
                            ("Scan paused: no partition of scan s finished in 600 s", "stopped making progress")):
            with self.subTest(raw=raw):
                self.assertIn(reason, jobs._stopped_for_good(partitioned_scan.ScanPaused(raw)))

    def test_a_job_that_stops_following_a_queued_scan_does_not_call_it_failed(self) -> None:
        text = jobs._safe_job_error(partitioned_scan.ScanStopped("no worker finished scan s1 within the queue wait"))
        self.assertIn("stopped following", text)
        self.assertNotIn("Scan failed", text)


class AFullDiskIsNotAnUnreachableTargetTest(unittest.TestCase):

    def test_out_of_space_is_infrastructure_but_not_the_target(self) -> None:
        full = OSError(errno.ENOSPC, "No space left on device")
        self.assertTrue(failures.is_infrastructure(full))
        self.assertFalse(failures.is_target_unreachable(full), "a full local disk tripped the target's breaker")
        self.assertIn("free disk", failures.describe(full))
        wrapped = RuntimeError("artifact write")
        wrapped.__cause__ = full
        self.assertFalse(failures.is_target_unreachable(wrapped))
        self.assertTrue(failures.is_target_unreachable(ConnectionRefusedError()))


class AQueuedScanThatPausedSaysSoTest(_Store):

    def test_the_following_job_says_paused_and_stops_without_calling_it_failed(self) -> None:
        scan_id = f"q-{uuid4().hex[:6]}"
        store.register_partitioned_scan(self.tenant, scan_id, job_id="j1", request={}, header={})
        store.create_scan_partitions(self.tenant, scan_id, "j1", [{"part": 0}, {"part": 1}])
        store.pause_partitioned_scan(self.tenant, scan_id, "its target cannot be reached", seconds=600)
        job = SimpleNamespace(progress=5, message="", cancel_requested=False, id="j1", tenant_id=self.tenant)
        with mock.patch.object(partitioned_scan, "_share_progress"), \
                self.assertRaises(partitioned_scan.ScanStopped) as stopped:
            partitioned_scan.follow_partitioned_scan(self.tenant, scan_id, job=job, poll_seconds=0.05, wait_seconds=1)
        self.assertIn("Scan paused", job.message)
        self.assertIn("cannot be reached", job.message)
        self.assertNotIn("A worker is scanning", job.message)
        self.assertIn("stopped following", jobs._safe_job_error(stopped.exception))


class AnUnreadableReportIsNotCalledCompleteTest(_Store):

    def test_a_reconciled_job_whose_report_cannot_be_read_ends_incomplete(self) -> None:
        scan_id, job_id = f"r-{uuid4().hex[:6]}", f"job-{uuid4().hex[:6]}"
        store.record_job({"id": job_id, "tenant_id": self.tenant, "status": "paused",
                          "created_at": "2026-10-08T00:00:00Z"})
        store.register_partitioned_scan(self.tenant, scan_id, job_id=job_id, request={}, header={})
        store.mark_partitioned_scan(self.tenant, scan_id, "done")
        with mock.patch.object(store, "read_scan_report_compact", return_value=None):
            self.assertEqual(store.reconcile_paused_jobs(jobs.completion_of), 1)
        row = store.read_job(self.tenant, job_id)
        self.assertEqual(row["status"], "incomplete", "a job was called completed on a report nobody could read")
        self.assertIn("not known", row["message"])


class TheEndpointFetchBarStaysInItsBandTest(unittest.TestCase):

    def test_the_heartbeat_never_lifts_the_bar_past_the_fetch_band(self) -> None:
        from backend import app as app_module

        ceilings: list[int] = []

        class _Heartbeat:
            def __init__(self, job, *, ceiling, **_kwargs) -> None:
                ceilings.append(ceiling)

            def __enter__(self):
                return None

            def __exit__(self, *_exc):
                return False

        from collectors.winrm_endpoint_scanner import WinRMEndpointConfig

        scanner = SimpleNamespace(config=None, last_scan_diagnostics={}, scan=lambda: [])
        job = SimpleNamespace(progress=0, message="", cancel_requested=False)
        paths = [f"C:/f{i}.txt" for i in range(40)]
        config = WinRMEndpointConfig(host="ep1", username="u", password="")
        with mock.patch.object(app_module, "collection_heartbeat", _Heartbeat), \
                mock.patch.object(app_module, "_endpoint_fetch_batches", lambda wanted, _sizes: [wanted[:20], wanted[20:]]):
            try:
                app_module._fetch_endpoint_content_in_batches(
                    scanner, config, SimpleNamespace(), job, "host", paths, {}, message="Reading")
            except Exception:  # noqa: BLE001 - the stub scanner stands in for the fetch only
                pass
        self.assertTrue(ceilings, "no batch ran")
        self.assertLessEqual(max(ceilings), 60, "the heartbeat could lift the bar above the 46-60 fetch band")
        self.assertEqual(ceilings, sorted(ceilings))


@unittest.skipUnless(NODE, "the console's helpers run in Node")
class TheConsoleSaysHowAScanEndedTest(unittest.TestCase):

    def test_completion_is_read_from_the_backend_and_gaps_are_named(self) -> None:
        result = _js(["function scanCompletion("], json.dumps([
            {"completion": {"status": "incomplete", "message": "Completed with gaps: 2 folder(s) could not be listed. "
                                                                "Nothing it missed was treated as deleted."}},
            {"completion": {"status": "completed", "message": "Completed"}},
            {},
        ]) + ".map(scanCompletion)")
        self.assertEqual(result[0]["incomplete"], True)
        self.assertTrue(result[0]["detail"].startswith("2 folder(s) could not be listed"))
        self.assertEqual([item["incomplete"] for item in result[1:]], [False, False])

    def test_a_pause_answer_is_told_apart_from_a_failure(self) -> None:
        result = _js(["function scanPausedDetail("],
                     '[new Error("409: Scan paused — free disk space is low"), new Error("400: Scan failed — x"), '
                     'new Error("409: Conflict")].map(scanPausedDetail)')
        self.assertEqual(result, ["free disk space is low", "", ""])

    def test_folders_entered_is_never_all_for_a_scan_with_gaps(self) -> None:
        result = _js(["const LIMITED_BY_LABELS", "function foldersEnteredFact("], json.dumps([
            [{"coverage": "full"}, "completed"], [{"coverage": "full"}, "incomplete"],
            [{"coverage": "limited", "limited_by": ["depth", "system_paths"]}, "completed"], [{}, "completed"],
        ]) + ".map(([scope, status]) => foldersEnteredFact(scope, status))")
        self.assertEqual(result, [["folders entered", "all in scope"], None,
                                  ["folders entered", "limited by depth limit, system folders"], None])

    def test_the_callers_announce_gaps_cancels_pauses_and_lost_contact_as_such(self) -> None:
        poll = _statement("async function pollScan(")
        self.assertIn("cancelled.cancelled = true", poll)
        self.assertNotIn('job.status === "failed" || job.status === "cancelled"', poll)
        self.assertIn("lost.lostContact = true", poll)
        for start, toast in (('form.addEventListener("submit"', 'showToast("Scan completed"'),
                             ('endpointScanBtn.addEventListener("click"', 'showToast("Endpoint scan completed"')):
            with self.subTest(handler=start):
                body = _statement(start)
                gaps = body.index("if (completion.incomplete)")
                self.assertLess(gaps, body.index(toast), "the completion toast is not behind the gaps check")
                # ... and in its else branch: shown only when the scan did not finish with gaps.
                self.assertIn("} else {", body[gaps:body.index(toast)], "the completion toast is shown whatever the gaps")
                failed = body.index("failed: ${error.message}")
                for branch in ("error.cancelled", "error.lostContact", "scanPausedDetail(error)"):
                    self.assertLess(body.index(branch), failed, branch)

    def test_no_progress_figure_is_made_up_from_the_clock(self) -> None:
        self.assertNotIn("function estimatedProgress(", APP)
        self.assertNotIn("function nextLiveProgress(", APP)
        for start in ("function setScanProgress(", "function setEndpointScanProgress("):
            self.assertIn("if (progress === null)", _statement(start))

    def test_a_refused_cancel_is_not_shown_as_requested(self) -> None:
        for start in ('scanCancelBtn.addEventListener("click"', 'endpointCancelBtn.addEventListener("click"'):
            body = APP[APP.index(start):APP.index("\n});\n", APP.index(start))]
            self.assertIn("answer?.cancelled === false", body)

    def test_the_report_names_every_gap_before_saying_there_were_none(self) -> None:
        start = APP.index('case "assurance": {')
        body = APP[start:APP.index("This scan recorded no coverage exceptions.", start)]
        for gap in ("quarantined_units", "unreadable_dirs", "shares_connection_reset", "incomplete_unit_count",
                    "notEntered.depth_limit", "notEntered.system_path"):
            self.assertIn(gap, body)

    def test_no_findings_is_not_called_clear_and_identities_are_named(self) -> None:
        self.assertIn('["clear", clear, "No findings", "Clear"]', _statement("function renderCoverageCard("))
        self.assertIn('label: fileIdentityKind(hash) ? "Identity" : "SHA-256"', APP)
        meta = _statement("function buildScanMetaText(")
        self.assertNotIn("full scan", meta)
        self.assertNotIn(chr(0xC2) + chr(0xB7), APP, "a middle dot encoded twice")

    def test_the_scan_level_hints_say_what_the_levels_do(self) -> None:
        hints = (ROOT / "frontend" / "scan-summary.js").read_text(encoding="utf-8")
        self.assertNotIn("every compliance framework applied", hints)
        self.assertIn("every framework if you choose none", hints)
        self.assertIn("read up to its cap and marked partly inspected", hints)
        index = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        self.assertNotIn("<small>Every framework, archives opened. Slowest.</small>", index)


if __name__ == "__main__":
    unittest.main()
