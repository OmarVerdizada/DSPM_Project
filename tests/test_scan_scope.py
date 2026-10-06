"""Advanced scan scope: what a scan leaves out, it never reads.

The operator says which folders, file types, sizes and dates a scan is for. Every rule is
applied where the facts it needs first exist - a folder before it is listed, a file by its
name before any stat, by its size and date before it is opened - so a file out of scope
costs no read, hash, extraction, classification or database row, and a folder out of
scope is not even enumerated. These tests watch the work itself, not only the result.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from pydantic import ValidationError

from backend import partitioned_scan, store
from collectors import file_scanner, scan_scope
from collectors.scan_scope import ScopeRules
from discovery.discovery_engine import DSPMDiscoveryEngine
from discovery.incremental import incremental_scope_key
from discovery.partition import plan_bounded_partitions, plan_share_partitions
from tests.test_partitioned_local_scan import TENANT, _LocalTest
from tests.test_w12_smb_range_units import _Connection, _RangeTest

CARD = "card 4111 1111 1111 1111 exp 09/29\n"
OLD = datetime(2019, 6, 1, tzinfo=timezone.utc).timestamp()


def _rules(**scope) -> ScopeRules:
    return ScopeRules.from_dict(scan_scope.canonical(scope, absolute=False))


class TheRulesTest(unittest.TestCase):

    def test_an_exclusion_wins_over_an_inclusion(self) -> None:
        rules = _rules(include_paths=["Finance"], exclude_paths=["Finance/Archive"])
        self.assertEqual(rules.folder_reason("finance"), "")
        self.assertEqual(rules.folder_reason("finance/archive"), scan_scope.EXCLUDED_FOLDER)
        self.assertEqual(rules.file_reason("finance/archive/q1.pdf", ".pdf"), scan_scope.EXCLUDED_FOLDER)
        self.assertEqual(rules.file_reason("finance/q1.pdf", ".pdf"), "")
        self.assertEqual(rules.folder_reason("hr"), scan_scope.OUTSIDE_INCLUDED)
        self.assertEqual(rules.file_reason("readme.txt", ".txt"), scan_scope.OUTSIDE_INCLUDED,
                         "a file beside the included folder is outside it")
        self.assertEqual(rules.folder_reason(""), "", "the root holds the included folder")

    def test_paths_compare_without_case_or_separator(self) -> None:
        rules = _rules(exclude_paths=["Finance\\ARCHIVE\\"])
        self.assertEqual(rules.folder_reason(rules.path_of("finance/archive")), scan_scope.EXCLUDED_FOLDER)
        self.assertEqual(rules.folder_reason(rules.path_of("Finance/Archive2")), "",
                         "a prefix of a name is not the folder")
        endpoint = ScopeRules.from_dict(scan_scope.canonical(
            {"exclude_paths": ["C:\\Users\\Ana\\Downloads\\ISOs", "\\\\nas\\share\\VMs"]}, absolute=True))
        self.assertTrue(endpoint.file_reason(endpoint.path_of("c:/users/ana/downloads/isos/x.iso"), ".iso"))
        self.assertTrue(endpoint.folder_reason(endpoint.path_of("\\\\NAS\\Share\\vms")))
        self.assertFalse(endpoint.folder_reason(endpoint.path_of("\\\\nas\\share")))

    def test_size_limits_are_inclusive_and_dates_are_utc_days(self) -> None:
        rules = _rules(min_size_bytes=10, max_size_bytes=100, modified_after="2024-01-01")
        self.assertEqual(rules.file_meta_reason(9, None), scan_scope.TOO_SMALL)
        self.assertEqual(rules.file_meta_reason(10, None), "")
        self.assertEqual(rules.file_meta_reason(100, None), "")
        self.assertEqual(rules.file_meta_reason(101, None), scan_scope.TOO_LARGE)
        midnight = datetime(2024, 1, 1, tzinfo=timezone.utc).timestamp()
        self.assertEqual(rules.file_meta_reason(50, midnight - 1), scan_scope.MODIFIED_BEFORE)
        self.assertEqual(rules.file_meta_reason(50, midnight), "")
        self.assertEqual(rules.file_meta_reason(50, "2023-12-31T23:59:59+00:00"), scan_scope.MODIFIED_BEFORE)

    def test_an_unknown_size_or_time_never_excludes(self) -> None:
        rules = _rules(min_size_bytes=10, modified_after="2024-01-01")
        self.assertEqual(rules.file_meta_reason(None, None), "")
        self.assertEqual(rules.file_meta_reason(None, "not a time"), "")

    def test_there_is_no_folder_name_rule(self) -> None:
        # The console offers none: a scan reads every folder of its target, narrowed by
        # path, type, size and date. A folder-name rule is not part of a scope.
        self.assertIsNone(scan_scope.canonical({"exclude_folder_patterns": ["backup*"]}, absolute=False))
        self.assertFalse(scan_scope.rules_for({"exclude_folder_patterns": ["backup*"]}).active)
        for name in ("FOLDER_PATTERN", "clean_patterns"):
            self.assertFalse(hasattr(scan_scope, name), name)

    def test_extensions_compare_without_case(self) -> None:
        rules = _rules(exclude_extensions=[".ISO", ".vhdx"])
        self.assertEqual(rules.file_reason("a/disk.ISO", ".ISO"), scan_scope.EXTENSION)
        self.assertEqual(rules.file_reason("a/disk.vhd", ".vhd"), "")

    def test_no_rule_is_the_scan_as_before(self) -> None:
        for empty in (None, {}, {"exclude_extensions": [], "include_paths": [], "min_size_bytes": None}):
            self.assertIsNone(scan_scope.canonical(empty, absolute=False))
        self.assertFalse(scan_scope.rules_for(None).active)
        self.assertEqual(scan_scope.digest(None), "")
        self.assertEqual(scan_scope.summary_fields({"scope": None}), {})

    def test_one_scope_has_one_name_however_it_is_spelled(self) -> None:
        first = scan_scope.canonical({"exclude_extensions": [".iso", ".VHD"], "exclude_paths": ["A\\B", "c/d/"]},
                                     absolute=False)
        second = scan_scope.canonical({"exclude_extensions": [".vhd", ".ISO"], "exclude_paths": ["/c/d", "a/b"]},
                                      absolute=False)
        self.assertEqual(scan_scope.digest(first), scan_scope.digest(second))
        self.assertEqual(scan_scope.rule_count(first), 4)


class TheRequestTest(unittest.TestCase):
    """What the API accepts: a rule that would silently match nothing is refused."""

    def _scan(self, **scope):
        from backend.app import ScanRequest

        return ScanRequest.model_validate({"local_path": "enterprise_test_data", "scope": scope})

    def _smb(self, **scope):
        from backend.app import ScanRequest

        return ScanRequest.model_validate({"server": "fs01.corp.local", "scope": scope})

    def _endpoint(self, **scope):
        from backend.app import EndpointScanRequest

        return EndpointScanRequest.model_validate({"host": "ws-17", "scope": scope})

    def test_input_is_normalized(self) -> None:
        scope = self._scan(exclude_extensions=["ISO", "*.vhdx", ".Mp4, mkv"], exclude_paths=["Finance\\Archive\\"]).scope
        self.assertEqual(scope.exclude_extensions, [".iso", ".mkv", ".mp4", ".vhdx"])
        self.assertEqual(scope.exclude_paths, ["Finance\\Archive\\"])
        self.assertEqual(self._smb(include_paths=["\\\\FS01.corp.local\\Finance\\Reports"]).scope.include_paths,
                         ["Finance/Reports"], "a UNC path naming this server is share-relative")

    def test_invalid_rules_are_refused(self) -> None:
        refused = [
            lambda: self._scan(exclude_extensions=["iso$"]),
            lambda: self._scan(min_size_bytes=100, max_size_bytes=10),
            lambda: self._scan(min_size_bytes=-1),
            lambda: self._scan(modified_after=(datetime.now(timezone.utc).date() + timedelta(days=2)).isoformat()),
            lambda: self._scan(exclude_paths=["Finance/*/Archive"]),
            lambda: self._scan(exclude_paths=["../outside"]),
            lambda: self._scan(exclude_paths=["C:\\Shares\\Finance"]),
            lambda: self._scan(exclude_paths=["\\\\fs01\\share\\x"]),
            lambda: self._smb(include_paths=["\\\\another-server\\Finance"]),
            # A rule the console does not offer is refused, never silently ignored.
            lambda: self._scan(exclude_folder_patterns=["backup*"]),
            lambda: self._scan(skip_hidden=True),
            lambda: self._endpoint(include_paths=["C:\\Users\\ana"]),
            lambda: self._endpoint(exclude_paths=["Downloads"]),
        ]
        for index, attempt in enumerate(refused):
            with self.subTest(index=index), self.assertRaises(ValidationError):
                attempt()

    def test_an_endpoint_excludes_by_absolute_path(self) -> None:
        scope = self._endpoint(exclude_paths=["C:\\Users\\ana\\Downloads\\ISOs", "\\\\nas\\vms"]).scope
        self.assertEqual(scope.canonical(absolute=True)["exclude_paths"],
                         ["//nas/vms", "c:/users/ana/downloads/isos"])

    def test_a_scan_without_scope_keeps_its_incremental_baseline(self) -> None:
        from backend import app as app_module

        payload = self._scan()
        key = app_module._file_scan_scope(payload, "", [], False)
        target = str((app_module.BASE_DIR / "enterprise_test_data").resolve())
        expected = incremental_scope_key("local", target, {
            "max_depth": 4, "allowed_extensions": [], "extension_filter_enabled": False, "include_hidden": True,
            "include_system": False, "hidden_filter_enabled": False, "system_filter_enabled": False,
            "include_admin_shares": False, "inspect_archives": False})
        self.assertEqual(key, expected, "an unscoped scan's baseline key moved: every incremental scan would start over")
        scoped = app_module._file_scan_scope(self._scan(exclude_extensions=[".iso"]), "", [], False)
        self.assertNotEqual(scoped, key, "a scoped scan must keep its own baseline")
        same = app_module._file_scan_scope(self._scan(exclude_extensions=["ISO"]), "", [], False)
        self.assertEqual(scoped, same)


def _corpus(root: Path) -> dict[str, Path]:
    files = {
        "in_pdf": root / "Finance" / "Reports" / "q1.pdf",
        "in_txt": root / "HR" / "staff.txt",
        "iso": root / "Finance" / "Reports" / "disk.iso",
        "large": root / "Finance" / "Reports" / "export.txt",
        "archived": root / "Finance" / "Archive" / "old.txt",
        "backup": root / "HR" / "Backup_2020" / "dump.txt",
        "stale": root / "HR" / "ancient.txt",
    }
    for key, path in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(CARD * (400 if key == "large" else 1), encoding="utf-8")
    os.utime(files["stale"], (OLD, OLD))
    return files


SCOPE = {"exclude_extensions": [".iso"], "max_size_bytes": 4096, "exclude_paths": ["Finance/Archive", "HR/Backup_2020"],
         "modified_after": "2020-01-01"}
OUT_OF_SCOPE = ("iso", "large", "archived", "backup", "stale")


class TheLocalWalkDoesNoWorkOutOfScopeTest(_LocalTest):

    def setUp(self) -> None:
        super().setUp()
        self.root = self.base / "scoped"
        self.files = _corpus(self.root)
        self.rules = scan_scope.canonical(SCOPE, absolute=False)

    def _spy(self, name: str, calls: list[str]):
        original = getattr(file_scanner, name)

        def spy(path, *args, **kwargs):
            calls.append(str(Path(path).resolve()))
            return original(path, *args, **kwargs)

        return mock.patch.object(file_scanner, name, side_effect=spy)

    def test_a_file_out_of_scope_is_never_read_hashed_or_asked_for_its_owner(self) -> None:
        touched: list[str] = []
        probed: list[str] = []
        listed: list[str] = []
        original_iterdir = Path.iterdir

        def iterdir(folder):
            listed.append(str(folder.resolve()))
            return original_iterdir(folder)

        diagnostics: dict = {}
        with self._spy("read_text_preview_and_sha256", touched), self._spy("identity_without_content", touched), \
                self._spy("local_acl", touched), \
                mock.patch.object(Path, "iterdir", iterdir):
            records = file_scanner.scan_directory(
                self.root, diagnostics=diagnostics, scope=self.rules,
                reuse_probe=lambda key, size, modified: probed.append(key))
        kept = {Path(record["path"]).name for record in records}
        self.assertEqual(kept, {"q1.pdf", "staff.txt"})
        for key in OUT_OF_SCOPE:
            path = str(self.files[key].resolve())
            self.assertNotIn(path, touched, f"{key} was read, hashed or asked for its ACL")
            self.assertFalse([item for item in probed if item.endswith(self.files[key].name)], f"{key} was probed")
        for folder in ("Finance/Archive", "HR/Backup_2020"):
            self.assertNotIn(str((self.root / folder).resolve()), listed, f"{folder} was listed")
        self.assertIn(str(self.files["in_pdf"].resolve()), touched, "an in-scope file was not read")
        scope = diagnostics["scope"]
        self.assertEqual(scope["excluded_by"], {"extension": 1, "larger_than_maximum": 1, "modified_before_date": 1})
        self.assertEqual(scope["skipped_folders_by"], {"excluded_folder": 2})
        self.assertEqual(diagnostics["visited_files"], 5, "the excluded files were discovered, not hidden")

    def test_an_included_folder_is_all_that_is_listed(self) -> None:
        listed: list[str] = []
        original_iterdir = Path.iterdir

        def iterdir(folder):
            listed.append(str(folder.resolve()))
            return original_iterdir(folder)

        with mock.patch.object(Path, "iterdir", iterdir):
            records = file_scanner.scan_directory(
                self.root, scope=scan_scope.canonical({"include_paths": ["Finance/Reports"]}, absolute=False))
        self.assertEqual({Path(record["path"]).name for record in records}, {"q1.pdf", "disk.iso", "export.txt"})
        for folder in ("HR", "Finance/Archive"):
            self.assertNotIn(str((self.root / folder).resolve()), listed)

    def test_without_rules_the_walk_is_unchanged(self) -> None:
        plain = file_scanner.scan_directory(self.root)
        scoped = file_scanner.scan_directory(self.root, scope=None)
        self.assertEqual([record["path"] for record in plain], [record["path"] for record in scoped])
        self.assertEqual(len(plain), len(self.files))


class TheScanAndTheEstateTest(_LocalTest):
    """End to end: the report, the findings and the database hold only what is in scope."""

    def setUp(self) -> None:
        super().setUp()
        self.root = self.base / "scoped"
        self.files = _corpus(self.root)
        # Enough files that the planner cuts the scan into several partitions.
        for index in range(9):
            (self.root / "HR" / f"note{index}.txt").write_text(f"note {index}\n", encoding="utf-8")
        self.rules = scan_scope.canonical(SCOPE, absolute=False)

    def _paths(self, records) -> set[str]:
        return {str(Path(record["path"]).resolve()) for record in records}

    def test_a_scoped_scan_reports_finds_and_stores_only_what_is_in_scope(self) -> None:
        self._use_database("scoped")
        report = DSPMDiscoveryEngine(self._config("scoped", local_path=str(self.root), scope=self.rules)).run().to_dict()
        out = {str(self.files[key].resolve()) for key in OUT_OF_SCOPE}
        self.assertFalse(self._paths(report["files"]) & out)
        finding_paths = {str(Path(record["path"]).resolve()) for record in report["files"] if record.get("findings")}
        self.assertTrue(finding_paths, "the in-scope card numbers were not found")
        self.assertFalse(finding_paths & out)
        self.assertEqual(report["summary"]["excluded_by_scope"], 3)
        self.assertEqual(report["summary"]["folders_skipped_by_scope"], 2)
        self.assertEqual(report["summary"]["scope"]["rule_count"], 5)
        store.save_scan_history(TENANT, report)
        with store._connect() as conn:
            stored = {str(Path(row["path"]).resolve()) for row in conn.execute(
                "SELECT path FROM assets WHERE tenant_id = ?", (TENANT,)).fetchall()}
        self.assertTrue(stored)
        self.assertFalse(stored & out, "an out-of-scope file reached the database")
        history = store.read_scan_history(TENANT, limit=5)[0]
        self.assertEqual(history["summary"]["excluded_by_scope"], 3, "the history row does not say the scan was scoped")

    def test_a_partitioned_scan_leaves_out_exactly_what_a_whole_one_does(self) -> None:
        self._use_database("whole")
        whole = DSPMDiscoveryEngine(self._config("whole", local_path=str(self.root), scope=self.rules)).run().to_dict()
        self._use_database("parts")
        planned_listing: list[str] = []
        original_iterdir = Path.iterdir

        def iterdir(folder):
            planned_listing.append(str(folder.resolve()))
            return original_iterdir(folder)

        with mock.patch.object(Path, "iterdir", iterdir):
            plan = plan_bounded_partitions(self._config("plan", local_path=str(self.root), scope=self.rules), max_files=3)
        self.assertIsNotNone(plan)
        self.assertGreater(len(plan["units"]), 1)
        self.assertNotIn(str((self.root / "Finance" / "Archive").resolve()), planned_listing,
                         "the planner listed an excluded folder")
        compact = partitioned_scan.run_partitioned_scan(
            TENANT, self._config("parts", local_path=str(self.root), scope=self.rules), max_files=3)
        self.assertIsNotNone(compact, "the scan was not partitioned")
        stored = store.read_scan_report(TENANT, compact["scan_id"])
        self.assertEqual(self._paths(stored["files"]), self._paths(whole["files"]))
        self.assertEqual(stored["summary"]["excluded_by_scope"], whole["summary"]["excluded_by_scope"])
        self.assertEqual(stored["summary"]["scope"]["rule_count"], 5, "partitions' rule counts were added up")
        merged = stored["scan_diagnostics"]["scope"]
        self.assertEqual(merged["excluded_by"], whole["scan_diagnostics"]["scope"]["excluded_by"])
        self.assertEqual(merged["skipped_folders"], whole["scan_diagnostics"]["scope"]["skipped_folders"])
        self.assertEqual(merged["rule_count"], 5)


class TheSmbCollectorDoesNoWorkOutOfScopeTest(_RangeTest):

    def _retrieved(self):
        calls: list[tuple[str, str]] = []
        original = _Connection.retrieveFileFromOffset

        def spy(connection, share, path, buffer, offset=0, max_length=0):
            calls.append((share, path))
            return original(connection, share, path, buffer, offset, max_length)

        return calls, mock.patch.object(_Connection, "retrieveFileFromOffset", spy)

    def test_an_excluded_share_or_folder_is_never_listed_and_an_excluded_file_never_read(self) -> None:
        rules = scan_scope.canonical({"include_paths": ["Big/deep"], "exclude_paths": ["Big/deep/a/b/n3.txt"]},
                                     absolute=False)
        calls, spy = self._retrieved()
        with spy:
            report = DSPMDiscoveryEngine(self._config("scoped", scope=rules)).run().to_dict()
        walked = {(record["share"], record["path"]) for record in report["files"]}
        self.assertEqual({path for _share, path in walked},
                         {"/deep/top.txt", *[f"/deep/a/b/n{index}.txt" for index in range(6) if index != 3]})
        listed = set(self.server.listed)
        self.assertNotIn(("Small", "/"), listed, "a share outside the included folders was listed")
        self.assertNotIn("Small", report["scan_diagnostics"]["shares_scanned"],
                         "a share left out by the scope is reported as scanned")
        self.assertNotIn(("Big", "/flat"), listed, "a folder outside the included folders was listed")
        self.assertNotIn(("Big", "/deep/a/b/n3.txt"), set(calls), "an excluded file was read")
        self.assertFalse([call for call in calls if call[1].startswith("/flat")])
        scope = report["scan_diagnostics"]["scope"]
        self.assertEqual(scope["skipped_folders_by"], {"outside_included_folders": 2})
        self.assertEqual(scope["excluded_by"], {"excluded_folder": 1, "outside_included_folders": 1})

    def test_size_and_date_are_decided_on_the_listing(self) -> None:
        rules = scan_scope.canonical({"max_size_bytes": 10}, absolute=False)
        calls, spy = self._retrieved()
        with spy:
            report = DSPMDiscoveryEngine(self._config("small-only", scope=rules)).run().to_dict()
        self.assertEqual({record["path"] for record in report["files"]}, {"/readme.txt"})
        self.assertTrue(all(path == "/readme.txt" for _share, path in calls), f"files over the limit were read: {calls}")
        later = scan_scope.canonical({"modified_after": "2026-01-01"}, absolute=False)
        calls, spy = self._retrieved()
        with spy:
            report = DSPMDiscoveryEngine(self._config("recent-only", scope=later)).run().to_dict()
        self.assertEqual(report["files"], [], "the fixture's files are from 2025")
        self.assertEqual(calls, [])

    def test_the_range_planner_does_not_list_an_excluded_folder(self) -> None:
        rules = scan_scope.canonical({"exclude_paths": ["Big/flat"]}, absolute=False)
        plan = plan_share_partitions(self._config(scope=rules), max_files=4, max_bytes=1 << 30)
        self.assertNotIn(("Big", "/flat"), set(self.server.listed))
        self.assertTrue(plan is None or all(unit.get("folder") != "/flat" for unit in plan["units"]))


_POWERSHELL = shutil.which("powershell.exe")


@unittest.skipUnless(os.name == "nt" and _POWERSHELL, "needs Windows and powershell.exe to run the endpoint script")
class TheEndpointScriptDoesNoWorkOutOfScopeTest(unittest.TestCase):
    """The collector script, run by this host's PowerShell against a real folder."""

    def setUp(self) -> None:
        # %TEMP% is under AppData, which the script always skips; a drive-root folder is not.
        self.root = Path(tempfile.mkdtemp(dir="C:\\"))
        self.addCleanup(shutil.rmtree, self.root, True)
        # "[old]1" holds brackets, which PowerShell's -like and wildcard paths would read
        # as a set: a literal path must still be walked.
        for relative, body in (("keep.txt", CARD), ("image.iso", "x"), ("big.log", "y" * 4000),
                               ("Backups/dump.txt", CARD), ("VMs/disk.txt", CARD), ("sub/ok.txt", CARD),
                               ("sub/[old]1/z.txt", CARD)):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        stale = self.root / "sub" / "stale.txt"
        stale.write_text(CARD, encoding="utf-8")
        os.utime(stale, (OLD, OLD))
        self.scope = scan_scope.canonical(
            {"exclude_extensions": [".iso"], "max_size_bytes": 1000,
             "exclude_paths": [str(self.root / "VMs"), str(self.root / "Backups")],
             "modified_after": "2020-01-01"}, absolute=True)

    def _run(self, script: str) -> dict:
        from tests.test_winrm_parallel_parity import _run

        return _run(script)

    def _script(self, **kwargs) -> str:
        from collectors.winrm_endpoint_scanner import _scan_script

        options = dict(max_depth=6, read_content=True, max_read_bytes=1 << 20, allowed_extensions=[],
                       extension_filter_enabled=False, include_hidden=True, include_system=False,
                       hidden_filter_enabled=False, system_filter_enabled=False, read_acl=False,
                       inspect_archives=False, hash_files=True, read_owner=False, scope=self.scope)
        options.update(kwargs)
        return _scan_script(**options)

    def test_the_whole_walk_leaves_out_what_is_out_of_scope(self) -> None:
        result = self._run(self._script(paths=[str(self.root)]))
        names = sorted(Path(record["path"]).name for record in result.get("records") or [])
        self.assertEqual(names, ["keep.txt", "ok.txt", "z.txt"])
        diagnostics = result["diagnostics"]
        self.assertEqual(diagnostics["scope_excluded_by"],
                         {"extension": 1, "larger_than_maximum": 1, "modified_before_date": 1})
        self.assertEqual(diagnostics["scope_skipped_folders_by"], {"excluded_folder": 2})

    def test_a_page_hands_on_no_excluded_folder(self) -> None:
        page = {"folders": [{"path": str(self.root), "depth": 0, "after": "", "root": True}],
                "page_size": 100, "max_folders": 1}
        result = self._run(self._script(paths=[], page=page))
        handed_on = {Path(str(folder["path"])).name for folder in result.get("folders") or []}
        self.assertEqual(handed_on, {"sub"}, "an excluded folder was handed on to be listed")
        self.assertEqual(sorted(Path(record["path"]).name for record in result.get("records") or []), ["keep.txt"])

    def test_without_scope_the_script_is_unchanged(self) -> None:
        self.scope = None
        names = sorted(Path(record["path"]).name for record in self._run(self._script(paths=[str(self.root)]))["records"])
        self.assertEqual(names, ["big.log", "disk.txt", "dump.txt", "image.iso", "keep.txt", "ok.txt", "stale.txt", "z.txt"])


class AScanKeepsItsScopeWhereverItRunsTest(unittest.TestCase):
    """Resumed, retried, queued and scheduled runs rebuild the scan from its stored request."""

    def test_a_resumed_or_queued_scan_rebuilds_the_same_scope(self) -> None:
        from backend import app as app_module

        payload = app_module.ScanRequest.model_validate(
            {"local_path": "enterprise_test_data", "scope": SCOPE, "incremental_enabled": True})
        original = app_module._to_config(payload, "default")
        stored = store._sanitize_scan_profile_config(payload.model_dump(mode="json"))
        rebuilt = app_module.rebuild_scan_config({"tenant_id": "default", "request": stored, "header": {"source": "local"}})
        self.assertEqual(rebuilt.scope, original.scope)
        self.assertEqual(rebuilt.scope, scan_scope.canonical(SCOPE, absolute=False))
        self.assertEqual(rebuilt.incremental_scope, original.incremental_scope)

    def test_a_schedule_runs_with_the_scope_it_was_saved_with(self) -> None:
        from backend import app as app_module

        payload = app_module.ScanRequest.model_validate({"local_path": "enterprise_test_data", "scope": SCOPE})
        schedule = store.create_scan_schedule(
            "default", name="scoped nightly", request=payload.model_dump(mode="json"), interval_seconds=86400,
            first_run_at=datetime.now(timezone.utc) + timedelta(days=30), created_by="admin")
        self.addCleanup(store.delete_scan_schedule, "default", schedule["schedule_id"])
        schedule = store.read_scan_schedule("default", schedule["schedule_id"])
        self.assertEqual(schedule["request"]["scope"]["exclude_paths"], ["Finance/Archive", "HR/Backup_2020"])
        with mock.patch.object(app_module, "create_job", return_value=mock.MagicMock(id="job-scoped")) as create_job:
            app_module._start_scheduled_scan(schedule)
        runner = create_job.call_args[0][1]
        with mock.patch.object(app_module, "partitioned_scans_enabled", return_value=True), \
                mock.patch.object(app_module, "_run_partitioned_scan_payload", return_value={"scan_id": "s"}) as ran:
            runner(mock.MagicMock(progress=0, cancel_requested=False))
        self.assertEqual(ran.call_args[0][0].scope, scan_scope.canonical(SCOPE, absolute=False))


class TheApiTest(unittest.TestCase):

    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        from backend.app import BASE_DIR, app
        from backend.security import create_token

        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.headers = {"Authorization": f"Bearer {create_token('admin', 'admin', 'default')}"}
        self.relative = f"tmp/scope-api-{os.getpid()}-{id(self) % 10_000}"
        self.root = BASE_DIR / self.relative
        self.addCleanup(shutil.rmtree, self.root, True)
        _corpus(self.root)

    def test_an_invalid_scope_is_refused_and_says_where(self) -> None:
        response = self.client.post("/api/scan", headers=self.headers, json={
            "local_path": self.relative, "scope": {"exclude_extensions": ["not an extension!"]}})
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("scope", " ".join(item["field"] for item in response.json()["fields"]))

    def test_a_scoped_scan_reports_what_it_left_out(self) -> None:
        response = self.client.post("/api/scan", headers=self.headers, json={
            "local_path": self.relative, "scope": SCOPE, "incremental_enabled": False, "scan_label": "scope-api"})
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        names = {Path(record["path"]).name for record in data["files"]}
        self.assertEqual(names, {"q1.pdf", "staff.txt"})
        self.assertEqual(data["summary"]["excluded_by_scope"], 3)
        self.assertEqual(data["scan_diagnostics"]["scope"]["rules"]["exclude_paths"],
                         ["finance/archive", "hr/backup_2020"])


if __name__ == "__main__":
    unittest.main()
