"""W3.3 (scaling roadmap, section 24): no interactive path reads a whole scan.

The console's hash comparison read the two newest scans' whole report bodies on every load;
a filed report read the body and sorted every file on the event loop; the finding drawer
and triage fell back to bodies - up to 1,000 of them for a finding that did not exist; the
inventory's compatibility path read up to 1,000 bodies a page; the history report endpoints
returned whole scans of any size.

Now every one of them answers from rows, and a guard refuses any console request that would
reach the body reader. The last test drives every registered route with the guard on.
"""
from __future__ import annotations

import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from backend import security, store
from backend.app import app
from backend.reporting import router as report_router

TENANT = "tenant-w33"
PASSWORD = "a-w33-harbour-pass-9"


def _file(path: str, digest: str, kind: str = "email", level: str = "HIGH", score: int = 70) -> dict:
    return {
        "path": path, "name": path.rsplit("/", 1)[-1], "source": "smb", "share": "fs01", "extension": ".txt",
        "sha256": digest, "size": 10, "risk": {"level": level, "score": score, "reasons": ["contains " + kind]},
        "findings": [{"type": kind, "count": 2, "severity": level, "secure_fingerprints": [f"fp-{path}"]}],
    }


def _report(scan_id: str, files: list[dict], *, timestamp: str, label: str = "fileserver") -> dict:
    return {"scan_id": scan_id, "timestamp": timestamp, "source": "smb", "scan_label": label, "mode": "full",
            "summary": {"total_files": len(files), "critical": 0, "high": len(files), "medium": 0, "low": 0},
            "scan_diagnostics": {"incremental": {"complete": True}}, "files": files}


class _Case(unittest.TestCase):

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        previous = store.DB_PATH
        store.DB_PATH = Path(self.temp.name) / "w33.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", previous))
        env = mock.patch.dict(os.environ, {"DSPM_ARTIFACT_DIR": str(Path(self.temp.name) / "artifacts"),
                                           "DSPM_REPORT_DIR": str(Path(self.temp.name) / "reports")})
        env.start()
        self.addCleanup(env.stop)
        store.init_db()
        for tenant in ("default", TENANT):
            try:
                store.create_tenant(tenant, tenant)
            except Exception:
                pass
        # Every body read is a failure here, whether or not a request made it. W3.5: a scan
        # is stored as a manifest by default, so reading its records through the manifest
        # is the same whole-scan read and counts the same.
        self.body_reads = 0
        real_body, real_records = store._report_body, store.iter_scan_records

        def counting(*args, **kwargs):
            self.body_reads += 1
            return real_body(*args, **kwargs)

        def counting_records(*args, **kwargs):
            self.body_reads += 1
            return real_records(*args, **kwargs)

        for name, replacement in (("_report_body", counting), ("iter_scan_records", counting_records)):
            patcher = mock.patch.object(store, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _two_scans(self) -> None:
        store.save_scan_history(TENANT, _report("20990101000001000000", [
            _file("/hr/a.txt", "h-a1"), _file("/hr/b.txt", "h-b"), _file("/hr/gone.txt", "h-gone"),
        ], timestamp="2099-01-01T00:00:01+00:00"))
        store.save_scan_history(TENANT, _report("20990101000002000000", [
            _file("/hr/a.txt", "h-a2"), _file("/hr/b.txt", "h-b"), _file("/hr/new.txt", "h-b"),
        ], timestamp="2099-01-01T00:00:02+00:00"))


class HashChangesAreRowsTest(_Case):

    def test_changes_additions_removals_and_duplicates_come_from_rows(self) -> None:
        self._two_scans()
        result = store.read_hash_changes(TENANT)
        self.assertTrue(result["available"])
        self.assertEqual((result["latest_scan_id"], result["previous_scan_id"]),
                         ("20990101000002000000", "20990101000001000000"))
        self.assertEqual([(item["path"], item["previous_hash"], item["current_hash"]) for item in result["changed"]],
                         [("/hr/a.txt", "h-a1", "h-a2")])
        self.assertEqual(result["changed"][0]["key"], "smb|fs01|/hr/a.txt", "the console's key for the file")
        self.assertEqual((result["changed_count"], result["added_count"], result["removed_count"]), (1, 1, 1))
        (group,) = result["duplicate_hash_paths"]
        self.assertEqual((group["hash"], group["count"], group["keys"]),
                         ("h-b", 2, ["smb|fs01|/hr/b.txt", "smb|fs01|/hr/new.txt"]))
        self.assertEqual(self.body_reads, 0, "the hash changes read a report body")

    def test_a_scan_saved_before_revision_0046_says_it_has_no_answer(self) -> None:
        self._two_scans()
        with store._connect() as conn:
            conn.execute("UPDATE scan_reports SET hash_changes_json = '' WHERE tenant_id = ?", (TENANT,))
        result = store.read_hash_changes(TENANT)
        self.assertFalse(result["available"])
        self.assertEqual(result["changed"], [])
        self.assertEqual(self.body_reads, 0)

    def test_an_asset_written_before_revision_0046_gets_its_hash_when_next_seen_unchanged(self) -> None:
        self._two_scans()
        with store._connect() as conn:
            conn.execute("UPDATE assets SET content_hash = '' WHERE tenant_id = ?", (TENANT,))
        store.save_scan_history(TENANT, _report("20990101000003000000", [
            _file("/hr/a.txt", "h-a2"), _file("/hr/b.txt", "h-b"), _file("/hr/new.txt", "h-b"),
        ], timestamp="2099-01-01T00:00:03+00:00"))
        with store._connect() as conn:
            hashes = {row["path"]: row["content_hash"] for row in conn.execute(
                "SELECT path, content_hash FROM assets WHERE tenant_id = ?", (TENANT,)).fetchall()}
        self.assertEqual(hashes, {"/hr/a.txt": "h-a2", "/hr/b.txt": "h-b", "/hr/new.txt": "h-b"})
        self.assertEqual(store.read_hash_changes(TENANT)["changed_count"], 0, "a filled-in hash is not a change")


class TheDrawerAndTriageReadRowsTest(_Case):

    def _finding_id(self, path: str) -> str:
        with store._connect() as conn:
            return str(conn.execute("SELECT id FROM findings WHERE tenant_id = ? AND file_path = ?",
                                    (TENANT, path)).fetchone()["id"])

    def test_a_finding_outside_the_index_window_is_answered_from_its_row(self) -> None:
        self._two_scans()
        finding_id = self._finding_id("/hr/a.txt")
        with store._connect() as conn:
            conn.execute("UPDATE finding_index SET response_json = '' WHERE tenant_id = ?", (TENANT,))
        finding = store.get_finding(TENANT, finding_id)
        self.assertEqual((finding["type"], finding["file"]["path"]), ("email", "/hr/a.txt"))
        self.assertEqual(store.get_finding_occurrences(TENANT, finding_id), finding.get("occurrences") or [])
        self.assertIsNotNone(store.update_finding_lifecycle(TENANT, finding_id, "comment", {"comment": "seen"}, "an"))
        self.assertEqual(self.body_reads, 0)

    def test_a_finding_that_does_not_exist_reads_no_report(self) -> None:
        self._two_scans()
        self.assertIsNone(store.get_finding(TENANT, "f" * 24))
        self.assertIsNone(store.get_finding_occurrences(TENANT, "f" * 24))
        self.assertIsNone(store.update_finding_lifecycle(TENANT, "f" * 24, "resolve", {}, "an"))
        self.assertEqual(self.body_reads, 0, "a missing finding walked the saved reports")

    def test_the_workflow_route_finds_its_finding_in_rows(self) -> None:
        self._two_scans()
        changed = store.update_finding_workflow(TENANT, "20990101000002000000",
                                                {"path": "/hr/b.txt", "type": "email", "fingerprint": "fp-/hr/b.txt"},
                                                {"review_status": "confirmed"}, "an")
        self.assertIsNotNone(changed)
        self.assertIsNone(store.update_finding_workflow(TENANT, "20990101000002000000",
                                                        {"path": "/hr/b.txt", "fingerprint": "no-such"},
                                                        {"review_status": "confirmed"}, "an"))
        self.assertEqual(self.body_reads, 0)


class ReportsAreRowsTest(_Case):

    def test_a_report_lists_at_most_its_ceiling_and_counts_the_whole_scan(self) -> None:
        files = [_file(f"/r/f{index:02d}.txt", f"h{index}", score=index) for index in range(12)]
        store.save_scan_history(TENANT, _report("20990101000005000000", files, timestamp="2099-01-01T00:00:05+00:00"))
        source = store.read_report_source(TENANT, "20990101000005000000", limit=5)
        self.assertEqual(len(source["report"]["files"]), 5)
        self.assertEqual([f["path"] for f in source["report"]["files"]], [f"/r/f{i:02d}.txt" for i in (11, 10, 9, 8, 7)])
        self.assertEqual((source["totals"]["total_files"], source["totals"]["scoped_total"]), (12, 12))
        self.assertEqual(source["totals"]["signals"], [{"type": "email", "count": 24}])
        from backend.reporting.report_model import build_report_model

        model = build_report_model(source["report"], {"kind": "full"}, None, tenant_id=TENANT,
                                   totals=source["totals"])
        self.assertEqual((model["full_summary"]["total_files"], len(model["evidence_register"])), (12, 5))
        self.assertTrue(model["evidence_register_truncated"])
        self.assertEqual(model["evidence_register_total"], 12)
        self.assertEqual(self.body_reads, 0)

    def test_the_report_route_renders_off_the_event_loop(self) -> None:
        self._two_scans()
        store.create_user("w33-boss", security.hash_password(PASSWORD), "admin", TENANT)
        client = TestClient(app)
        self.addCleanup(client.close)
        calls = []
        real = report_router.run_in_threadpool

        async def recording(function, *args, **kwargs):
            # W3.4 wraps the call to run it on the heavy-read budget.
            called = args[0] if getattr(function, "__name__", "") == "_on_heavy_budget" else function
            calls.append(getattr(called, "__name__", ""))
            return await real(function, *args, **kwargs)

        headers = {"Authorization": f"Bearer {security.create_token('w33-boss', 'admin', TENANT)}"}
        with mock.patch.object(report_router, "run_in_threadpool", recording):
            response = client.post("/api/v1/reports", headers=headers, json={})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(calls, ["create_report_artifact"])
        self.assertEqual(self.body_reads, 0)


class TheGuardTest(_Case):

    def test_a_console_request_that_reaches_the_body_reader_is_refused(self) -> None:
        self._two_scans()
        token = store.mark_interactive_request("GET /api/test")
        try:
            with self.assertRaises(store.WholeScanRead):
                store.read_scan_report(TENANT, "20990101000002000000")
            with store.whole_scan_read("a bounded download"):
                self.assertIsNotNone(store.read_scan_report(TENANT, "20990101000002000000"))
        finally:
            store.unmark_interactive_request(token)
        self.assertIsNotNone(store.read_scan_report(TENANT, "20990101000002000000"), "a scan job reads bodies")

    def test_the_full_report_above_its_size_is_refused_and_below_it_is_served(self) -> None:
        # A verbatim body (opt-in since W3.5) is refused above its size; a scan stored as a
        # manifest is streamed instead (tests/test_w35_storage_stops_growing.py).
        with mock.patch.dict(os.environ, {"DSPM_STORE_REPORT_BODY": "1"}):
            self._two_scans()
        store.create_user("w33-boss", security.hash_password(PASSWORD), "admin", TENANT)
        client = TestClient(app)
        self.addCleanup(client.close)
        headers = {"Authorization": f"Bearer {security.create_token('w33-boss', 'admin', TENANT)}"}
        with mock.patch.dict(os.environ, {"DSPM_REPORT_BODY_MAX_BYTES": "10"}):
            refused = client.get("/api/history/20990101000002000000/report?include_files=true", headers=headers)
        self.assertEqual(refused.status_code, 413, refused.text)
        self.assertIn("/api/inventory/export", refused.json()["detail"])
        served = client.get("/api/history/20990101000002000000/report?include_files=true", headers=headers)
        self.assertEqual(served.status_code, 200, served.text)
        self.assertEqual(len(served.json()["report"]["files"]), 3)
        self.assertEqual(self.body_reads, 1, "only the bounded download read the body")


class TheInventoryReadsRowsTest(_Case):

    def test_an_incomplete_mirror_is_served_from_rows_and_says_so(self) -> None:
        self._two_scans()
        with store._connect() as conn:
            conn.execute("DELETE FROM scan_runs WHERE tenant_id = ? AND id = '20990101000001000000'", (TENANT,))
        store._invalidate_inventory_query_cache(TENANT)
        page = store.list_inventory(TENANT)
        self.assertTrue(page["inventory_incomplete"])
        self.assertEqual(page["source"], "normalized")
        self.assertEqual(store.inventory_facets(TENANT)["source"], "normalized")
        self.assertEqual(self.body_reads, 0)

    def test_a_superseded_runs_file_above_the_size_limit_is_described_by_its_row(self) -> None:
        store.save_scan_history(TENANT, _report("20990101000001000000", [_file("/hr/a.txt", "h-a1", level="HIGH")],
                                                timestamp="2099-01-01T00:00:01+00:00", label="named"))
        store.save_scan_history(TENANT, _report("20990101000002000000", [_file("/hr/a.txt", "h-a2", level="LOW",
                                                                               score=5)],
                                                timestamp="2099-01-01T00:00:02+00:00", label=""))
        scan_id, rows = store.scan_report_inventory_rows_by_label(TENANT, "named")
        with mock.patch.dict(os.environ, {"DSPM_REPORT_BODY_MAX_BYTES": "10"}):
            described = store.get_inventory_asset(TENANT, rows[0]["id"], scan_id)
        self.assertEqual((described["risk"]["level"], described["detail_available"]), ("HIGH", False))
        self.assertEqual(self.body_reads, 0)
        read = store.get_inventory_asset(TENANT, rows[0]["id"], scan_id)
        self.assertEqual((read["risk"]["level"], read["detail_scan_id"]), ("HIGH", scan_id))
        self.assertEqual(self.body_reads, 1, "below the limit the run's own record is read, once")

    def test_a_run_without_stored_rows_is_viewed_from_its_assets(self) -> None:
        self._two_scans()
        with store._connect() as conn:
            conn.execute("UPDATE scan_reports SET rows_json = NULL WHERE tenant_id = ?", (TENANT,))
        store._forget_scan_report_rows(TENANT)
        scan_id, rows = store.scan_report_inventory_rows_by_label(TENANT, "fileserver")
        self.assertEqual((scan_id, sorted(row["path"] for row in rows)),
                         ("20990101000002000000", ["/hr/a.txt", "/hr/b.txt", "/hr/new.txt"]))
        asset = store.get_inventory_asset(TENANT, rows[0]["id"], scan_id)
        self.assertEqual((asset["scan_id"], asset["detail_scan_id"]), (scan_id, scan_id))
        self.assertEqual(self.body_reads, 0)


# Routes the sweep does not call: they change the host or reach the network, or end the
# sweep's own session or workspace. Every other registered route is called.
_NOT_CALLED = {
    ("POST", "/api/endpoint/activate-local-winrm"), ("POST", "/api/endpoint/activate-winrm"),
    ("POST", "/api/endpoint/repair-winrm"), ("POST", "/api/demo-data/generate"),
    ("POST", "/api/logout"), ("POST", "/api/auth/logout"), ("DELETE", "/api/tenants/{tenant_id}"),
    ("POST", "/api/users/{username}/delete"), ("DELETE", "/api/users/{username}"),
    ("POST", "/api/auth/change-password"),
    # these reach out to a host, a directory, a receiver or a vault
    ("POST", "/api/test-connection"), ("POST", "/api/endpoint/test-connection"),
    ("POST", "/api/endpoint/check-access"), ("POST", "/api/settings/directory/test"),
    ("POST", "/api/scan-targets/check"), ("POST", "/api/credentials/{secret_ref}/preflight"),
    ("POST", "/api/integrations/{channel}/test"), ("POST", "/api/settings/siem/test"),
}


class EveryRouteTest(_Case):
    """Section 24, exit 4: no interactive route can reach the report-body reader, tested by
    a guard that fails the request - every registered route, called as a signed-in admin
    of a workspace with saved scans, findings and assets."""

    def test_no_route_reads_a_whole_scan(self) -> None:
        self._two_scans()
        store.create_user("w33-boss", security.hash_password(PASSWORD), "admin", TENANT)
        with store._connect() as conn:
            finding_id = str(conn.execute("SELECT id FROM findings WHERE tenant_id = ? LIMIT 1",
                                          (TENANT,)).fetchone()["id"])
            asset_id = str(conn.execute("SELECT id FROM assets WHERE tenant_id = ? LIMIT 1",
                                        (TENANT,)).fetchone()["id"])
        values = {"scan_id": "20990101000002000000", "finding_id": finding_id, "asset_id": asset_id,
                  "tenant_id": TENANT, "username": "w33-boss", "artifact_id": "a" * 32, "job_id": "missing-job",
                  "channel": "email", "unmatched_path": "nowhere"}
        queries = {"/api/inventory": "?source=fileserver", "/api/inventory/facets": "?source=fileserver",
                   "/api/inventory/{asset_id}": "?scan_id=20990101000002000000",
                   "/api/history/{scan_id}/report": "?include_files=false",
                   "/api/history/latest/report": "?include_files=false"}
        bodies = {"/api/findings/{finding_id}/comment": {"comment": "x"},
                  "/api/findings/{finding_id}/status": {"status": "CONFIRMED"},
                  "/api/history/{scan_id}/findings/workflow": {
                      "selector": {"path": "/hr/a.txt", "type": "email"}, "update": {"review_status": "confirmed"}}}
        client = TestClient(app, raise_server_exceptions=False)
        self.addCleanup(client.close)
        headers = {"Authorization": f"Bearer {security.create_token('w33-boss', 'admin', TENANT)}"}
        routes = sorted(
            ((method, route.path) for route in app.routes if isinstance(route, APIRoute)
             for method in sorted(route.methods or ()) if method not in {"HEAD", "OPTIONS"}),
            key=lambda pair: (pair[0] != "GET", pair[1]),
        )
        self.assertGreater(len(routes), 150)
        refused, called = [], 0
        interactive_before = store.whole_scan_reads()["interactive"]
        for method, path in routes:
            if (method, path) in _NOT_CALLED:
                continue
            url = path
            for name, value in values.items():
                url = url.replace("{" + name + ":path}", value).replace("{" + name + "}", value)
            url = re.sub(r"\{([a-z_]+)(?::path)?\}", lambda match: "missing-" + match.group(1), url)
            url += queries.get(path, "")
            response = client.request(method, url, headers=headers,
                                      json=bodies.get(path, {}) if method != "GET" else None)
            called += 1
            if response.status_code == 500 and "whole_scan_read" in response.text:
                refused.append(f"{method} {path}")
        self.assertEqual(refused, [], "routes that would read a whole scan")
        self.assertEqual(store.whole_scan_reads()["interactive"], interactive_before)
        self.assertEqual(self.body_reads, 0, "a route read a report body")
        self.assertGreater(called, 140)


if __name__ == "__main__":
    unittest.main()
