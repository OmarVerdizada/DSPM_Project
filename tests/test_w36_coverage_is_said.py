"""W3.6 (scaling roadmap, section 24, decision D4): coverage is said.

Local, SMB and endpoint scans stopped at a depth of 4 (12 on an endpoint) unless told
otherwise, and said nothing about it: a scan reported complete that never entered most of a
deep share, and a named scan then took everything it had not entered out of the estate.
Now:

- with no depth setting a scan enters every folder; an explicit limit stays optional;
- a limit is part of the scan's scope block, the folders it did not enter are counted -
  as are the system folders every scan skips - and its coverage says ``limited``, in the
  results, the job's message and the history; never ``full``;
- a named scan limited by depth or scope rules prunes nothing it did not see;
- saved profiles and schedules that carry the old default's 4 keep it, visibly;
- a reused file's ACL is read again when its folder's ACL moved, when it has explicit
  entries, or when it was last read too long ago (E14) - measured on the fake SMB server.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from unittest.mock import patch

from backend import db, jobs, store
from collectors import acl_refresh, file_scanner, scan_scope
from collectors.smb_scanner import SMBConfig, SMBScanner
from collectors.winrm_endpoint_scanner import WinRMEndpointConfig, _scan_script
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from discovery.partition import plan_bounded_partitions
from tests.test_partitioned_local_scan import _LocalTest
from tests.test_w12_smb_range_units import _RangeTest

ROOT = Path(__file__).resolve().parents[1]


def _not_entered(diagnostics: dict) -> dict:
    return dict((diagnostics.get("scope") or {}).get("not_entered_by") or {})


# ── no default limit ─────────────────────────────────────────────────────────────────────
class NoDefaultDepthLimitTest(unittest.TestCase):

    def test_no_request_or_collector_defaults_to_a_limit(self) -> None:
        from backend.app import EndpointScanRequest, ScanRequest

        self.assertIsNone(ScanRequest().max_depth)
        self.assertIsNone(EndpointScanRequest(host="pc01").max_depth)
        self.assertIsNone(ScanConfig().max_depth)
        self.assertIsNone(SMBConfig(server="fs").max_depth)
        self.assertIsNone(WinRMEndpointConfig(host="pc01", username="u", password="p").max_depth)
        self.assertEqual(ScanRequest(max_depth=3).max_depth, 3, "an explicit limit stays")

    def test_the_endpoint_script_has_no_limit_unless_one_is_set(self) -> None:
        unlimited = _scan_script(["C:\\Users"], None, True, 1024, [], False, True, False, False, False, True, False)
        self.assertIn("if (-1 -ge 0 -and $depth -gt -1)", unlimited)
        self.assertIn("if (-1 -lt 0 -or ($depth + 1) -le -1)", unlimited)
        limited = _scan_script(["C:\\Users"], 3, True, 1024, [], False, True, False, False, False, True, False)
        self.assertIn("if (3 -ge 0 -and $depth -gt 3)", limited)
        # The whole walk, a page's own folder and a page's subfolders past the limit: each counts.
        self.assertEqual(limited.count("$diagnostics.not_entered_depth += 1"), 3)
        self.assertEqual(limited.count("$diagnostics.not_entered_system += 1"), 4)

    def test_the_console_sends_no_limit_by_default(self) -> None:
        html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        depth = html[html.index('id="max_depth"'):].split(">", 1)[0]
        self.assertNotIn("value=", depth, "the file-server form still fills in a depth")
        endpoint = html[html.index('id="endpoint-max-depth"'):].split(">", 1)[0]
        self.assertNotIn("value=", endpoint)
        script = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
        self.assertIn('max_depth: String(data.get("max_depth") || "").trim() ? Number(data.get("max_depth")) : null', script)
        self.assertNotIn("depth: 5, label", script, "an endpoint scope still sets a depth of its own")


class AWalkWithoutALimitEntersEveryFolderTest(unittest.TestCase):

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="w36-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        for depth in range(1, 10):
            folder = self.root.joinpath(*[f"l{level}" for level in range(depth)])
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f"file{depth}.txt").write_text("hello", encoding="utf-8")
        (self.root / "Windows" / "System32").mkdir(parents=True)
        (self.root / "Windows" / "System32" / "kernel.txt").write_text("system", encoding="utf-8")
        # %TEMP% is itself a system path: only the Windows folder is one here.
        self.skip = patch.object(file_scanner, "is_skipped_scan_path",
                                 side_effect=lambda path: "\\windows" in str(path).lower() + "\\"
                                 and str(path).lower().rstrip("\\").endswith("windows"))
        self.skip.start()
        self.addCleanup(self.skip.stop)

    def test_every_level_is_read_and_coverage_says_only_the_system_folder(self) -> None:
        diagnostics: dict = {}
        records = file_scanner.scan_directory(self.root, diagnostics=diagnostics)
        self.assertEqual(len(records), 9, "a folder deeper than the old default of 4 was not entered")
        block = diagnostics["scope"]
        self.assertIsNone(block["depth_limit"])
        self.assertEqual(_not_entered(diagnostics), {scan_scope.NOT_ENTERED_SYSTEM: 1})
        self.assertEqual((block["coverage"], block["limited_by"]), ("limited", [scan_scope.LIMITED_BY_SYSTEM]))
        self.assertTrue(scan_scope.prune_allowed(diagnostics), "system folders alone do not stop the prune")

    def test_a_system_folder_named_as_the_target_is_not_entered_and_said(self) -> None:
        diagnostics: dict = {}
        records = file_scanner.scan_directory(self.root / "Windows", diagnostics=diagnostics)
        self.assertEqual(records, [])
        self.assertEqual(_not_entered(diagnostics), {scan_scope.NOT_ENTERED_SYSTEM: 1})
        self.assertEqual(diagnostics["scope"]["coverage"], "limited")

    def test_a_limit_counts_what_it_did_not_enter(self) -> None:
        diagnostics: dict = {}
        records = file_scanner.scan_directory(self.root, max_depth=3, diagnostics=diagnostics)
        self.assertEqual(len(records), 3, "the files of the folders at depths 1 to 3")
        block = diagnostics["scope"]
        self.assertEqual(block["depth_limit"], 3)
        self.assertEqual(_not_entered(diagnostics)[scan_scope.NOT_ENTERED_DEPTH], 1)
        self.assertIn(scan_scope.LIMITED_BY_DEPTH, block["limited_by"])
        self.assertFalse(scan_scope.prune_allowed(diagnostics))
        summary = scan_scope.summary_fields(diagnostics)
        self.assertEqual((summary["coverage"], summary["depth_limit"], summary["folders_not_entered_by_depth"]),
                         ("limited", 3, 1))

    def test_the_job_says_the_coverage_was_limited(self) -> None:
        diagnostics: dict = {"incremental": {"complete": True}}
        file_scanner.scan_directory(self.root, max_depth=3, diagnostics=diagnostics)
        status, message = jobs.completion_of({"scan_diagnostics": diagnostics})
        self.assertEqual(status, "completed")
        self.assertIn("coverage limited: depth limit 3: 1 folder(s) not entered", message)
        self.assertIn("1 system folder(s) not entered", message)
        unlimited: dict = {"incremental": {"complete": True}, "scope": scan_scope.ScopeTally().to_dict(None)}
        self.assertEqual(jobs.completion_of({"scan_diagnostics": unlimited}), ("completed", "Completed"))


# ── partitions say what the whole walk says ──────────────────────────────────────────────
class PartitionsCountWhatTheWalkCountsTest(_LocalTest):

    def test_every_depth_limit_counts_the_same_pieced_and_whole(self) -> None:
        for depth in (None, 1, 2, 3, 4):
            with self.subTest(max_depth=depth):
                config = self._config(max_depth=depth)
                engine = DSPMDiscoveryEngine(config)
                single = [record["path"] for record in engine._collect_records()]
                whole = _not_entered(engine.last_scan_diagnostics)
                plan = plan_bounded_partitions(config, max_files=2)
                self.assertIsNotNone(plan)
                pieced: list[str] = []
                counted: dict = {}
                from backend import partitioned_scan

                for unit in plan["units"]:
                    unit_engine = DSPMDiscoveryEngine(partitioned_scan._unit_config(config, unit, self._root(config)))
                    pieced.extend(record["path"] for record in unit_engine._collect_records())
                    for reason, count in _not_entered(unit_engine.last_scan_diagnostics).items():
                        counted[reason] = counted.get(reason, 0) + count
                self.assertEqual(pieced, single)
                self.assertEqual(counted, whole, "a partition missed or doubled a folder it did not enter")
                if depth is None:
                    self.assertNotIn(scan_scope.NOT_ENTERED_DEPTH, whole)
                if depth == 2:
                    self.assertGreater(whole.get(scan_scope.NOT_ENTERED_DEPTH, 0), 0)

    def test_a_partitioned_scan_reports_the_scans_limit_not_a_units(self) -> None:
        from backend import partitioned_scan

        self._use_database("limited")
        compact = partitioned_scan.run_partitioned_scan(
            "partitioned-local", self._config("limited", max_depth=2), request={"local_path": "estate", "max_depth": 2},
            max_files=2)
        report = store.read_scan_report_compact("partitioned-local", compact["scan_id"])
        block = report["scan_diagnostics"]["scope"]
        self.assertEqual(block["depth_limit"], 2, "a unit's relative limit was reported as the scan's")
        self.assertEqual(block["coverage"], "limited")
        self.assertEqual(report["summary"]["coverage"], "limited")
        self.assertEqual(report["summary"]["depth_limit"], 2)
        self.assertGreater(report["summary"]["folders_not_entered_by_depth"], 0)


class SmbRangesCountWhatTheWalkCountsTest(_RangeTest):

    def test_a_limited_share_counts_the_same_in_ranges_and_whole(self) -> None:
        from discovery.partition import plan_share_partitions

        config = self._config(max_depth=2)
        whole = DSPMDiscoveryEngine(self._config("whole", max_depth=2)).run().to_dict()
        whole_counts = _not_entered(whole["scan_diagnostics"])
        self.assertEqual(whole_counts.get(scan_scope.NOT_ENTERED_DEPTH), 1, "deep/a/b is past a limit of 2")
        plan = plan_share_partitions(config, max_files=10, max_bytes=1 << 30)
        from backend import partitioned_scan

        counted: dict = {}
        for unit in plan["units"]:
            unit_config = partitioned_scan._share_unit_config(self._config("unit", max_depth=2), unit)
            report = DSPMDiscoveryEngine(unit_config).run().to_dict()
            for reason, count in _not_entered(report["scan_diagnostics"]).items():
                counted[reason] = counted.get(reason, 0) + count
        self.assertEqual(counted, whole_counts)

    def test_an_unlimited_share_enters_every_folder(self) -> None:
        whole = DSPMDiscoveryEngine(self._config("whole", max_depth=None)).run().to_dict()
        self.assertIn("/deep/a/b/n0.txt", {record["path"] for record in whole["files"]})
        block = whole["scan_diagnostics"]["scope"]
        self.assertEqual((block["depth_limit"], block["coverage"]), (None, "full"))


class FinalizeSaysTheScansOwnLimitTest(unittest.TestCase):

    def test_the_first_units_relative_limit_is_not_reported_as_the_scans(self) -> None:
        from backend import partitioned_scan

        first = scan_scope.ScopeTally()
        first.not_entered(scan_scope.NOT_ENTERED_DEPTH, 2)
        second = scan_scope.ScopeTally()
        merged = scan_scope.merge_diagnostics([first.to_dict(None, depth_limit=1),
                                               second.to_dict(None, depth_limit=3)])
        self.assertEqual(merged["depth_limit"], 1, "the merge keeps the first unit's - finalize must not")
        units = [{"partition_id": f"p{index}", "status": "done", "has_records": True, "summary": {},
                  "diagnostics": {"scope": block, "incremental": {"complete": True}}}
                 for index, block in enumerate((first.to_dict(None, depth_limit=1), second.to_dict(None, depth_limit=3)))]
        folded = {"finalize_state": {"folded": True, "file_count": 0, "sample_count": 0, "sections": {}}}
        with mock.patch.object(store, "list_scan_partitions", return_value=units), \
                mock.patch.object(store, "read_partitioned_scan", return_value=folded), \
                mock.patch.object(store, "preview_finalize_decisions"), \
                mock.patch.object(store, "finalize_partitioned_scan") as finalize:
            partitioned_scan.finalize_scan("t", "s", timestamp="2026-10-07T00:00:00Z", source="local",
                                           depth_limit=4)
        report = finalize.call_args.args[2]
        self.assertEqual(report["scan_diagnostics"]["scope"]["depth_limit"], 4)
        self.assertEqual(report["summary"]["depth_limit"], 4)
        self.assertEqual(report["summary"]["folders_not_entered_by_depth"], 2)


# ── a limited scan prunes nothing it did not see ─────────────────────────────────────────
class ALimitedScanDoesNotPruneTest(unittest.TestCase):

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._dir.cleanup)
        environment = mock.patch.dict(os.environ, {"DSPM_ARTIFACT_DIR": str(Path(self._dir.name) / "artifacts")})
        environment.start()
        self.addCleanup(environment.stop)
        self.tenant = f"w36{uuid.uuid4().hex[:8]}"
        if db.is_postgres():
            store.create_tenant(self.tenant, "W3.6")
            self.addCleanup(store.delete_tenant_with_data, self.tenant)
            return
        previous = store.DB_PATH
        store.DB_PATH = Path(self._dir.name) / "w36.sqlite"
        self.addCleanup(setattr, store, "DB_PATH", previous)
        store.init_db()
        store.create_tenant(self.tenant, "W3.6")

    def _save(self, scan_id: str, paths: list[str], block: dict) -> None:
        files = [{"path": path, "name": path.rsplit("/", 1)[-1], "source": "local", "size": 1,
                  "risk": {"level": "LOW", "score": 1}, "findings": []} for path in paths]
        store.save_scan_history(self.tenant, {
            "scan_id": scan_id, "source": "local", "timestamp": "2026-10-07T00:00:00Z", "summary": {},
            "scan_label": "estate", "files": files,
            "scan_diagnostics": {"incremental": {"complete": True}, "scope": block}})

    def _paths(self) -> set[str]:
        with db.tenant_scope(self.tenant):
            with store._connect() as conn:
                return {row["path"] for row in conn.execute(
                    "SELECT path FROM assets WHERE tenant_id = ?", (self.tenant,)).fetchall()}

    def test_depth_and_scope_limits_keep_what_they_did_not_see(self) -> None:
        full = scan_scope.ScopeTally().to_dict(None)
        self._save("s1", ["/a.txt", "/deep/x/y.txt", "/deep/x/z.txt"], full)
        depth = scan_scope.ScopeTally()
        depth.not_entered(scan_scope.NOT_ENTERED_DEPTH)
        self._save("s2", ["/a.txt"], depth.to_dict(None, depth_limit=1))
        self.assertEqual(self._paths(), {"/a.txt", "/deep/x/y.txt", "/deep/x/z.txt"},
                         "a depth-limited scan pruned the folders it never entered")
        scoped = scan_scope.ScopeTally()
        scoped.folder(scan_scope.EXCLUDED_FOLDER)
        self._save("s3", ["/a.txt"], scoped.to_dict({"exclude_paths": ["deep"], "absolute": False}))
        self.assertEqual(len(self._paths()), 3, "a scope-limited scan pruned what it left out")
        system = scan_scope.ScopeTally()
        system.not_entered(scan_scope.NOT_ENTERED_SYSTEM)
        self._save("s4", ["/a.txt"], system.to_dict(None))
        self.assertEqual(self._paths(), {"/a.txt"}, "a scan that entered everything but system folders prunes")


# ── saved scans with the old default ─────────────────────────────────────────────────────
class SavedScansKeepTheirLimitVisiblyTest(ALimitedScanDoesNotPruneTest):

    def test_they_are_counted_kept_and_said(self) -> None:
        for name, depth in (("Old default", 4), ("Chosen", 7), ("Unlimited", None)):
            store.save_scan_profile(self.tenant, profile_id=None, kind="file-server", name=name,
                                    config={"local_path": "x", "max_depth": depth})
        counts = store.saved_depth_limits(self.tenant)
        self.assertEqual((counts["profiles"], counts["profiles_at_old_default"]), (2, 1))
        kept = [profile["config"].get("max_depth") for profile in store.list_scan_profiles(self.tenant)]
        self.assertEqual(sorted(kept, key=str), sorted([4, 7, None], key=str), "a saved limit was changed silently")
        from backend import app as app_module

        logged = []
        with mock.patch.object(store, "tenant_ids", return_value=[self.tenant]), \
                mock.patch("scripts.logger.get_logger") as get_logger:
            get_logger.return_value.warning.side_effect = lambda message, *args: logged.append(message % args)
            app_module._log_saved_depth_limits()
        self.assertEqual(len(logged), 1)
        # Said at every start of the server, not only when asked.
        from fastapi.testclient import TestClient

        with mock.patch.object(app_module, "_log_saved_depth_limits") as said, \
                mock.patch.dict(os.environ, {"DSPM_RETENTION_INTERVAL_SECONDS": "0", "DSPM_BACKUP_SCHEDULE_HOURS": "0"}):
            with TestClient(app_module.app):
                pass
        said.assert_called_once_with()
        self.assertIn("1 saved scan profile(s) and 0 schedule(s) keep a depth limit of 4", logged[0])
        script = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
        self.assertIn("return maxDepth ? `Depth limit ${maxDepth}` : \"Every folder\";", script)


# ── E14: the ACL refresh policy ──────────────────────────────────────────────────────────
def _inherited_acl(owner: str = "CORP\\owner", group: str = "CORP\\staff") -> dict:
    return {"owner": owner, "principals": [group], "permissions": ["Read"],
            "entries": [{"principal": group, "rights": "Read", "inherited": True}]}


class TheAclPolicyDecidesTest(unittest.TestCase):

    def test_each_reason(self) -> None:
        now = datetime(2026, 10, 7, tzinfo=timezone.utc)
        recent = (now - timedelta(hours=1)).isoformat()
        folder = acl_refresh.acl_digest(_inherited_acl())
        replay = {"acl": _inherited_acl(), "acl_checked_at": recent, "acl_parent_digest": folder}
        self.assertEqual(acl_refresh.refresh_reason(replay, path="/a.txt", parent_digest=folder, now=now), "")
        self.assertEqual(acl_refresh.refresh_reason({**replay, "acl_checked_at": ""}, path="/a.txt",
                                                    parent_digest=folder, now=now), acl_refresh.NEVER_CHECKED)
        # An ACL that cannot say which entries are inherited - the PowerShell paths - or none at
        # all is not explicit: re-reading every such file every scan is what the policy avoids.
        self.assertFalse(acl_refresh.has_explicit_entries({"owner": "o", "principals": ["p"], "permissions": ["r"]}))
        self.assertFalse(acl_refresh.has_explicit_entries({}))
        explicit = {**replay, "acl": {**_inherited_acl(), "entries": [{"principal": "x", "inherited": False}]}}
        self.assertEqual(acl_refresh.refresh_reason(explicit, path="/a.txt", parent_digest=folder, now=now),
                         acl_refresh.EXPLICIT_ENTRIES)
        self.assertEqual(acl_refresh.refresh_reason(replay, path="/a.txt", parent_digest="moved", now=now),
                         acl_refresh.FOLDER_CHANGED)
        old = {**replay, "acl_checked_at": (now - timedelta(days=8)).isoformat()}
        self.assertEqual(acl_refresh.refresh_reason(old, path="/a.txt", parent_digest=folder, now=now),
                         acl_refresh.FULL_REFRESH)
        with mock.patch.dict(os.environ, {"DSPM_ACL_FULL_REFRESH_DAYS": "0"}):
            self.assertEqual(acl_refresh.refresh_reason(replay, path="/a.txt", parent_digest=folder, now=now),
                             acl_refresh.FULL_REFRESH)

    def test_the_full_refresh_is_spread_over_its_period(self) -> None:
        now = datetime(2026, 10, 7, tzinfo=timezone.utc)
        folder = acl_refresh.acl_digest(_inherited_acl())
        checked = (now - timedelta(days=5)).isoformat()
        due = sum(1 for index in range(400) if acl_refresh.refresh_reason(
            {"acl": _inherited_acl(), "acl_checked_at": checked, "acl_parent_digest": folder},
            path=f"/f{index}.txt", parent_digest=folder, now=now))
        self.assertGreater(due, 50, "nothing is refreshed before the period ends")
        self.assertLess(due, 350, "the whole estate is refreshed on one night")


class _AclCountingRangeTest(_RangeTest):
    """The fake SMB server of the W1.2 tests, with ACL reads counted and folder ACLs settable."""

    def setUp(self) -> None:
        super().setUp()
        self.reads: list[str] = []
        self.folder_acls: dict[str, dict] = {}
        self.file_acls: dict[str, dict] = {}

        def acl_for_path(scanner, share, path):
            # The real method's per-scan cache, so a read is counted once, as the server sees it.
            unc = scanner._unc_path(share, path)
            with scanner._acl_lock:
                cached = scanner._acl_cache.get(unc)
            if cached is not None:
                return cached
            self.reads.append(str(path))
            value = self.folder_acls.get(path) or self.file_acls.get(path) or _inherited_acl()
            with scanner._acl_lock:
                scanner._acl_cache[unc] = value
            return value

        self._acl_patches = [
            patch.object(SMBScanner, "_acl_for_path", acl_for_path),
            patch.object(SMBScanner, "_acl_batch_for_paths", lambda _self, _share, _paths: None),
            patch("collectors.smb_scanner.win_security.available", return_value=False),
            mock.patch.dict(os.environ, {"DSPM_SMB_ACL_BATCH": "0"}),
        ]
        for started in self._acl_patches:
            started.start()
        self._use_database("acl")

    def tearDown(self) -> None:
        # Stopped before the fixture's own patches of the same methods, in reverse order: a
        # patch stopped out of order restores the one beneath it for every later test.
        for started in reversed(self._acl_patches):
            started.stop()
        super().tearDown()

    def _scan(self) -> dict:
        config = self._config("acl", incremental_enabled=True, persistent_cache_enabled=True, max_depth=None,
                              smb_shares=["Big"])
        self.reads.clear()
        return DSPMDiscoveryEngine(config).run().to_dict()

    def _files(self, report: dict) -> list[str]:
        return [record["path"] for record in report["files"] if "::" not in record["path"]]

    def _folders(self, report: dict) -> set[str]:
        return {str(Path(path).parent).replace("\\", "/") for path in self._files(report)}


class TheAclPolicyOnTheFakeSmbServerTest(_AclCountingRangeTest):
    """E14 measured: what each scan reads, on the fake SMB server (fake transport, said)."""

    def test_its_cost_and_its_catches(self) -> None:
        first = self._scan()
        files, folders = self._files(first), self._folders(first)
        self.assertEqual(len(files), 31)
        cold = list(self.reads)
        self.assertEqual(len([path for path in cold if path in files]), len(files))
        self.assertEqual(first["scan_diagnostics"]["acl_refresh"]["folders_read"], len(folders))

        second = self._scan()
        self.assertTrue(all(record.get("cache_reused") for record in second["files"]))
        warm = [path for path in self.reads if path in files]
        self.assertEqual(warm, [], "an unchanged file's inherited ACL was read again")
        self.assertEqual(second["scan_diagnostics"]["acl_refresh"]["files_replayed"], len(files))

        # A folder's ACL changes: the files under it are read again, nothing else.
        self.folder_acls["/deep/a/b"] = _inherited_acl(group="CORP\\everyone")
        changed = {path for path in files if path.startswith("/deep/a/b/")}
        for path in changed:
            self.file_acls[path] = _inherited_acl(group="CORP\\everyone")
        third = self._scan()
        reread = {path for path in self.reads if path in files}
        self.assertEqual(reread, changed)
        after = {record["path"]: record for record in third["files"]}
        self.assertEqual(after["/deep/a/b/n0.txt"]["acl"]["principals"], ["CORP\\everyone"],
                         "the changed ACL was not taken")
        self.assertEqual(third["scan_diagnostics"]["acl_refresh"]["files_reread"],
                         {acl_refresh.FOLDER_CHANGED: len(changed)})

        # A file with an explicit entry is read every scan.
        self.file_acls["/readme.txt"] = {**_inherited_acl(), "entries": [{"principal": "x", "inherited": False}]}
        with mock.patch.dict(os.environ, {"DSPM_ACL_FULL_REFRESH_DAYS": "0"}):
            self._scan()  # stamps the explicit ACL into the snapshot
        self._scan()
        self.assertEqual({path for path in self.reads if path in files}, {"/readme.txt"})

        # The full refresh: every file again once its period has passed.
        with mock.patch.dict(os.environ, {"DSPM_ACL_FULL_REFRESH_DAYS": "0"}):
            self._scan()
        self.assertEqual({path for path in self.reads if path in files}, set(files))

    def test_a_file_read_on_this_scan_is_stamped_for_the_next(self) -> None:
        first = self._scan()
        for record in first["files"]:
            if "::" in record["path"]:
                continue
            self.assertTrue(record.get("acl_checked_at"), record["path"])
            self.assertEqual(record.get("acl_parent_digest"), acl_refresh.acl_digest(_inherited_acl()))


class ARefreshedAclMovesTheRiskTest(_LocalTest):
    """A local file whose ACL changed is re-assessed without reading its content again."""

    def test_the_exposure_follows_the_acl(self) -> None:
        from discovery import discovery_engine

        self._use_database("acl-local")
        config = self._config("acl-local", incremental_enabled=True, persistent_cache_enabled=True, max_depth=None)
        state = {"acl": _inherited_acl()}

        def local_acl(path):
            return state["acl"]

        with patch.object(file_scanner, "local_acl", side_effect=local_acl):
            DSPMDiscoveryEngine(config).run()
            state["acl"] = {"owner": "CORP\\owner", "principals": ["Everyone"], "permissions": ["FullControl"],
                            "entries": [{"principal": "Everyone", "rights": "FullControl", "inherited": True}]}
            with mock.patch.dict(os.environ, {"DSPM_ACL_FULL_REFRESH_DAYS": "0"}), \
                    patch.object(discovery_engine.DSPMDiscoveryEngine, "_read_full_content",
                                 side_effect=AssertionError("content read again")):
                second = DSPMDiscoveryEngine(config).run().to_dict()
        record = next(record for record in second["files"] if record["path"].endswith("a_root.txt"))
        self.assertTrue(record.get("incremental_reused") or record.get("cache_reused"))
        self.assertEqual(record["acl"]["principals"], ["Everyone"])
        self.assertTrue(record["permissions"].get("public") or record["permissions"].get("wide_access"),
                        record["permissions"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
