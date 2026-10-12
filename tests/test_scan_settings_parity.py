"""The file-server scan's Configuration step, end to end: what it shows is what the scan does.

Every setting on the step is followed from the console's request through the API's
validation, into a saved scan, a schedule and a resumed (or retried, or queued) run, and
into a real scan of a real folder tree - where each one must change what the scan reads,
and leave out what it leaves out before any work is spent on it.

The API accepts exactly the settings the step shows: a scope rule it does not offer is
refused, not ignored, and compliance mapping is on exactly when a framework is chosen.
"""
from __future__ import annotations

import ctypes
import os
import re
import shutil
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar
from unittest import mock

from pydantic import ValidationError

from backend import store
from collectors import file_scanner

ROOT = Path(__file__).resolve().parent.parent
INDEX = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
APP_JS = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
SETUP_JS = (ROOT / "frontend" / "console" / "scan-setup.js").read_text(encoding="utf-8")
STEP_2 = INDEX[INDEX.index('<div class="wizard-step hidden" data-wizard-step="2">'):
               INDEX.index('<div class="wizard-step hidden" data-wizard-step="3">')]

CARD = "card 4111 1111 1111 1111 exp 09/29\n"
OLD = datetime(2019, 6, 1, tzinfo=timezone.utc).timestamp()
HIDDEN, SYSTEM = 0x2, 0x4
ON_WINDOWS = os.name == "nt"

# The request the console sends for a scan with every setting changed from its default
# (frontend/app.js readPayload, console/scan-setup.js readSpecialFiles).
CONSOLE = {
    "server": "", "domain": "WORKGROUP", "username": "", "password": "", "credential_ref": "",
    "local_path": "enterprise_test_data", "max_depth": 6,
    "allowed_extensions": [".txt", ".zip"], "extension_filter_enabled": True,
    "include_hidden": False, "hidden_filter_enabled": False, "include_system": True, "system_filter_enabled": False,
    "scope": {"include_paths": ["Finance", "HR"], "exclude_paths": ["Finance/Archive"], "exclude_extensions": [".iso"],
              "min_size_bytes": 10, "max_size_bytes": 4096, "modified_after": "2020-01-01"},
    "include_admin_shares": False, "inspect_archives": True, "scan_level": "standard",
    "smb_encryption": False, "smb_shares": [], "async_scan": True, "incremental_enabled": False,
    "asset_overrides": [], "compliance_enabled": True, "compliance_frameworks": ["pci_dss"], "scan_label": "",
}
# What a scan's engine configuration carries of the step's settings.
SETTINGS = ("local_path", "max_depth", "allowed_extensions", "extension_filter_enabled", "include_hidden",
            "include_system", "hidden_filter_enabled", "system_filter_enabled", "include_admin_shares",
            "inspect_archives", "read_content", "compliance_enabled", "compliance_frameworks",
            "incremental_enabled", "incremental_scope", "scope", "smb_shares", "smb_require_encryption")


def _request(**overrides):
    from backend.app import ScanRequest

    return ScanRequest.model_validate({**CONSOLE, **overrides})


def _settings(config) -> dict:
    return {name: getattr(config, name) for name in SETTINGS}


def _keys(source: str, function: str) -> set[str]:
    start = source.index(f"function {function}(")
    body = source[start:source.index("\n}\n", start)]
    return set(re.findall(r"^\s{4}(\w+):", body[body.index("return {"):], re.MULTILINE))


class TheConsoleAndTheApiAgreeTest(unittest.TestCase):

    def test_the_console_sends_exactly_what_the_api_defines(self) -> None:
        from backend.app import ScanRequest

        sent = _keys(APP_JS, "readPayload") | _keys(SETUP_JS, "readSpecialFiles")
        defined = set(ScanRequest.model_fields)
        self.assertFalse(sent - defined, "the console sends a setting the API does not know")
        # The two the scan runner adds itself (runQueuedScan, the form's submit).
        self.assertEqual(defined - sent, {"compact_result", "save_report"})
        self.assertEqual(set(CONSOLE) - {"scope"}, sent - {"scope"}, "CONSOLE no longer mirrors readPayload")

    def test_every_scope_rule_on_the_step_is_one_the_api_accepts_and_no_other(self) -> None:
        from backend.app import ScanScope

        on_screen = set(re.findall(r'data-scope-field="(\w+)"', STEP_2))
        sent = {"min_size": "min_size_bytes", "max_size": "max_size_bytes"}
        self.assertEqual({sent.get(name, name) for name in on_screen}, set(ScanScope.model_fields))

    def test_a_rule_the_step_does_not_offer_is_refused_not_ignored(self) -> None:
        for retired in ({"exclude_folder_patterns": ["backup*"]}, {"skip_hidden": True}, {"include_names": ["x"]}):
            with self.subTest(rule=retired), self.assertRaises(ValidationError):
                _request(scope=retired)

    def test_each_setting_is_checked_where_the_step_checks_it(self) -> None:
        refused = [{"max_depth": 0}, {"max_depth": 13}, {"scan_level": "deep"},
                   {"compliance_frameworks": ["no_such_framework"]},
                   {"scope": {"min_size_bytes": 100, "max_size_bytes": 10}},
                   {"scope": {"modified_after": "2999-01-01"}},
                   {"scope": {"exclude_paths": ["../outside"]}},
                   {"scope": {"exclude_extensions": ["not a type!"]}}]
        for overrides in refused:
            with self.subTest(overrides=overrides), self.assertRaises(ValidationError):
                _request(**overrides)

    def test_compliance_mapping_follows_the_frameworks_chosen(self) -> None:
        self.assertFalse(_request(compliance_enabled=True, compliance_frameworks=[]).compliance_enabled,
                         "a switch on with no framework mapped nothing")
        self.assertTrue(_request(compliance_enabled=False, compliance_frameworks=["gdpr"]).compliance_enabled,
                        "a framework chosen was dropped")

    def test_the_three_hidden_and_system_choices_reach_the_scan(self) -> None:
        from backend import app as app_module

        choices = {"include": (True, False), "skip": (False, False), "only": (True, True)}
        for hidden, (include_hidden, hidden_only) in choices.items():
            for system, (include_system, system_only) in choices.items():
                with self.subTest(hidden=hidden, system=system):
                    config = app_module._to_config(_request(
                        include_hidden=include_hidden, hidden_filter_enabled=hidden_only,
                        include_system=include_system, system_filter_enabled=system_only), "default")
                    self.assertEqual((config.include_hidden, config.hidden_filter_enabled,
                                      config.include_system, config.system_filter_enabled),
                                     (include_hidden, hidden_only, include_system, system_only))

    def test_all_file_types_is_no_filter_and_a_type_set_is_one(self) -> None:
        from backend import app as app_module

        everything = app_module._to_config(_request(allowed_extensions=[], extension_filter_enabled=False), "default")
        self.assertEqual((everything.allowed_extensions, everything.extension_filter_enabled), ([], False))
        chosen = app_module._to_config(_request(allowed_extensions=[".TXT", "pdf"]), "default")
        self.assertEqual((chosen.allowed_extensions, chosen.extension_filter_enabled), ([".pdf", ".txt"], True))

    def test_smb_encryption_needs_the_shares_named(self) -> None:
        from fastapi import HTTPException

        from backend import app as app_module

        with self.assertRaises(HTTPException) as refused:
            app_module._to_config(_request(server="fs01.corp.local", smb_encryption=True), "default")
        self.assertEqual(refused.exception.status_code, 400)
        config = app_module._to_config(_request(server="fs01.corp.local", smb_encryption=True,
                                                smb_shares=["Finance"], include_admin_shares=True), "default")
        self.assertEqual((config.smb_shares, config.smb_require_encryption, config.include_admin_shares),
                         (("Finance",), True, True))


class EverySettingSurvivesEveryWayAScanRunsTest(unittest.TestCase):
    """Saved and edited, scheduled, resumed, retried and queued: the same scan each time."""

    def test_a_saved_scan_comes_back_as_it_was_saved(self) -> None:
        from fastapi.testclient import TestClient

        from backend.app import app
        from backend.security import create_token

        client = TestClient(app)
        self.addCleanup(client.close)
        headers = {"Authorization": f"Bearer {create_token('admin', 'admin', 'default')}"}
        config = {key: value for key, value in CONSOLE.items() if key not in ("password", "asset_overrides", "scan_label")}
        config["ui"] = {"ext_preset": "", "ext_mode": "selected", "extensions": [".txt", ".zip"]}
        saved = client.post("/api/scan-profiles", headers=headers,
                             json={"kind": "file-server", "name": f"parity {os.getpid()}", "config": config})
        self.assertEqual(saved.status_code, 200, saved.text)
        profile_id = saved.json()["profile_id"]
        self.addCleanup(client.delete, f"/api/scan-profiles/{profile_id}", headers=headers)
        listed = client.get("/api/scan-profiles", headers=headers).json()["profiles"]
        stored = next(item for item in listed if item["profile_id"] == profile_id)["config"]
        self.assertEqual(stored, config, "a setting was lost or changed on save")
        # Edited and run again, the stored settings are the scan they were.
        from backend import app as app_module

        self.assertEqual(_settings(app_module._to_config(app_module.ScanRequest.model_validate(stored), "default")),
                         _settings(app_module._to_config(_request(), "default")))

    def test_a_resumed_retried_or_queued_scan_is_rebuilt_with_every_setting(self) -> None:
        from backend import app as app_module

        for level in ("inventory", "standard", "full"):
            with self.subTest(level=level):
                payload = _request(scan_level=level)
                original = app_module._to_config(payload, "default")
                stored = store._sanitize_scan_profile_config(payload.model_dump(mode="json"))
                rebuilt = app_module.rebuild_scan_config(
                    {"tenant_id": "default", "request": stored, "header": {"source": "local"}})
                self.assertEqual(_settings(rebuilt), _settings(original))
                self.assertEqual(rebuilt.read_content, level != "inventory")
                self.assertEqual(rebuilt.inspect_archives, level != "inventory")
                if level == "full":
                    self.assertEqual(rebuilt.compliance_frameworks, ["pci_dss"], "full keeps the frameworks chosen")

    def test_a_schedule_runs_with_every_setting_it_was_saved_with(self) -> None:
        from datetime import timedelta

        from backend import app as app_module

        payload = _request()
        schedule = store.create_scan_schedule(
            "default", name="parity nightly", request=payload.model_dump(mode="json"), interval_seconds=86400,
            first_run_at=datetime.now(timezone.utc) + timedelta(days=30), created_by="admin")
        self.addCleanup(store.delete_scan_schedule, "default", schedule["schedule_id"])
        schedule = store.read_scan_schedule("default", schedule["schedule_id"])
        with mock.patch.object(app_module, "create_job", return_value=mock.MagicMock(id="job-parity")) as create_job:
            app_module._start_scheduled_scan(schedule)
        runner = create_job.call_args[0][1]
        with mock.patch.object(app_module, "partitioned_scans_enabled", return_value=True), \
                mock.patch.object(app_module, "_run_partitioned_scan_payload", return_value={"scan_id": "s"}) as ran:
            runner(mock.MagicMock(progress=0, cancel_requested=False))
        self.assertEqual(_settings(ran.call_args[0][0]), _settings(app_module._to_config(payload, "default")))


def _set_attribute(path: Path, flag: int) -> None:
    current = ctypes.windll.kernel32.GetFileAttributesW(str(path))
    if not ctypes.windll.kernel32.SetFileAttributesW(str(path), current | flag):
        raise OSError(f"could not set attributes on {path}")


class EverySettingChangesWhatTheScanReadsTest(unittest.TestCase):
    """One real folder tree, scanned through the request the console sends, setting by setting."""

    FILES: ClassVar[dict[str, str]] = {
        "Finance/Reports/q1.txt": CARD, "Finance/Archive/old.txt": CARD, "HR/staff.txt": CARD,
        "HR/big.txt": CARD * 400, "HR/tiny.txt": "x", "HR/stale.txt": CARD, "HR/photo.jpg": CARD, "HR/disk.iso": CARD,
        "plain.txt": CARD, "hidden.txt": CARD, "Hid/inside.txt": CARD, "sys.txt": CARD,
    }

    @classmethod
    def setUpClass(cls) -> None:
        from backend.app import BASE_DIR

        cls.relative = f"tmp/settings-parity-{os.getpid()}"
        cls.root = BASE_DIR / cls.relative
        shutil.rmtree(cls.root, True)
        for relative, body in cls.FILES.items():
            path = cls.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        os.utime(cls.root / "HR" / "stale.txt", (OLD, OLD))
        with zipfile.ZipFile(cls.root / "HR" / "pack.zip", "w") as archive:
            archive.writestr("inner.txt", CARD)
        if ON_WINDOWS:
            _set_attribute(cls.root / "hidden.txt", HIDDEN)
            _set_attribute(cls.root / "Hid", HIDDEN)
            _set_attribute(cls.root / "sys.txt", SYSTEM)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.root, True)

    def setUp(self) -> None:
        owner = mock.patch.object(file_scanner, "file_owner", mock.MagicMock(return_value="CORP\\owner"))
        owner.start()
        self.addCleanup(owner.stop)

    def _scan(self, **overrides) -> tuple[set[str], dict, dict]:
        """The relative paths a scan reports, the files it read, and its report."""
        from backend import app as app_module
        from discovery.discovery_engine import DSPMDiscoveryEngine

        settings = {**CONSOLE, "local_path": self.relative, "max_depth": 6, "allowed_extensions": [],
                    "extension_filter_enabled": False, "include_hidden": True, "include_system": False,
                    "scope": {}, "inspect_archives": False, "compliance_frameworks": [], **overrides}
        config = app_module._to_config(app_module.ScanRequest.model_validate(settings), "default")
        config.persistent_cache_enabled = False
        config.cache_dir = str(self.root.parent / f"settings-parity-cache-{os.getpid()}")
        self.addCleanup(shutil.rmtree, config.cache_dir, True)
        read: dict[str, int] = {}
        original = file_scanner.read_text_preview_and_sha256

        def spy(path, *args, **kwargs):
            key = Path(path).resolve().relative_to(self.root.resolve()).as_posix()
            read[key] = read.get(key, 0) + 1
            return original(path, *args, **kwargs)

        with mock.patch.object(file_scanner, "read_text_preview_and_sha256", side_effect=spy):
            report = DSPMDiscoveryEngine(config).run().to_dict()
        base = str(self.root.resolve())
        paths = {str(Path(record["path"].split("::")[0]).resolve())[len(base) + 1:].replace("\\", "/")
                 + (f"::{record['path'].split('::', 1)[1]}" if "::" in record["path"] else "")
                 for record in report["files"]}
        return paths, read, report

    def _plain(self) -> set[str]:
        return {"Finance/Reports/q1.txt", "Finance/Archive/old.txt", "HR/staff.txt", "HR/big.txt", "HR/tiny.txt",
                "HR/stale.txt", "HR/photo.jpg", "HR/disk.iso", "HR/pack.zip", "plain.txt"}

    def test_each_folder_size_date_and_type_rule_leaves_out_its_files_unread(self) -> None:
        everything, _read, _report = self._scan()
        self.assertTrue(self._plain() <= everything, everything)
        cases = {
            "Only these folders": ({"include_paths": ["Finance"]}, everything - {"Finance/Reports/q1.txt",
                                                                                  "Finance/Archive/old.txt"}),
            "Skip these folders": ({"exclude_paths": ["Finance/Archive"]}, {"Finance/Archive/old.txt"}),
            "Minimum file size": ({"min_size_bytes": 10}, {"HR/tiny.txt"}),
            "Maximum file size": ({"max_size_bytes": 4096}, {"HR/big.txt"}),
            "Modified on or after": ({"modified_after": "2020-01-01"}, {"HR/stale.txt"}),
            "Skip these types": ({"exclude_extensions": [".iso"]}, {"HR/disk.iso"}),
        }
        for name, (scope, left_out) in cases.items():
            with self.subTest(setting=name):
                paths, read, report = self._scan(scope=scope)
                self.assertEqual(paths, everything - left_out)
                for path in left_out:
                    self.assertNotIn(path, read, f"{path} was read although out of scope")
                self.assertTrue(report["summary"].get("excluded_by_scope") or report["summary"].get(
                    "folders_skipped_by_scope"), "the scan does not say it left anything out")

    def test_the_file_type_policy_is_decided_before_any_stat(self) -> None:
        stats: list[str] = []
        original = Path.stat

        def stat(path, *args, **kwargs):
            stats.append(path.name)
            return original(path, *args, **kwargs)

        with mock.patch.object(Path, "stat", stat):
            paths, _read, _report = self._scan(allowed_extensions=[".txt"], extension_filter_enabled=True)
        self.assertFalse({path for path in paths if not path.endswith(".txt")}, paths)
        for name in ("photo.jpg", "disk.iso", "pack.zip"):
            self.assertNotIn(name, stats, f"{name} was stat()ed although its type is not scanned")
        everything, _read, _report = self._scan(allowed_extensions=[], extension_filter_enabled=False)
        self.assertTrue({"HR/photo.jpg", "HR/disk.iso", "HR/pack.zip"} <= everything, "All file types left a type out")

    @unittest.skipUnless(ON_WINDOWS, "hidden and system are Windows file attributes")
    def test_hidden_files_include_skip_or_only(self) -> None:
        listed: list[str] = []
        original = Path.iterdir

        def iterdir(folder):
            listed.append(folder.name)
            return original(folder)

        include, _read, _report = self._scan(include_hidden=True, hidden_filter_enabled=False)
        self.assertTrue({"hidden.txt", "Hid/inside.txt", "plain.txt"} <= include)
        with mock.patch.object(Path, "iterdir", iterdir):
            skip, read, _report = self._scan(include_hidden=False, hidden_filter_enabled=False)
        self.assertFalse({"hidden.txt", "Hid/inside.txt"} & skip)
        self.assertIn("plain.txt", skip)
        self.assertNotIn("Hid", listed, "Skip, with hidden folders: a hidden folder was listed")
        self.assertNotIn("hidden.txt", read)
        only, _read, _report = self._scan(include_hidden=True, hidden_filter_enabled=True)
        self.assertEqual(only, {"hidden.txt"}, "a file inside a hidden folder is not itself hidden")

    @unittest.skipUnless(ON_WINDOWS, "hidden and system are Windows file attributes")
    def test_system_files_skip_include_or_only(self) -> None:
        skip, read, _report = self._scan(include_system=False, system_filter_enabled=False)
        self.assertNotIn("sys.txt", skip)
        self.assertNotIn("sys.txt", read)
        include, _read, _report = self._scan(include_system=True, system_filter_enabled=False)
        self.assertTrue({"sys.txt", "plain.txt"} <= include)
        only, _read, _report = self._scan(include_system=True, system_filter_enabled=True)
        self.assertEqual(only, {"sys.txt"})

    def test_open_zip_archives_reads_the_files_inside(self) -> None:
        closed, _read, _report = self._scan(inspect_archives=False)
        opened, _read, _report = self._scan(inspect_archives=True)
        self.assertNotIn("HR/pack.zip::inner.txt", closed)
        self.assertIn("HR/pack.zip::inner.txt", opened)

    def test_the_scan_level_decides_what_is_read(self) -> None:
        def findings(report: dict) -> int:
            return sum(len(record.get("findings") or []) for record in report["files"])

        inventory, read, report = self._scan(scan_level="inventory", inspect_archives=True,
                                             compliance_frameworks=["pci_dss"])
        self.assertEqual(read, {}, "an inventory scan read file content")
        self.assertEqual(findings(report), 0)
        self.assertNotIn("HR/pack.zip::inner.txt", inventory, "inventory opens no archive")
        _paths, read, report = self._scan(scan_level="standard")
        self.assertIn("plain.txt", read)
        self.assertGreater(findings(report), 0)
        full, _read, report = self._scan(scan_level="full")
        self.assertIn("HR/pack.zip::inner.txt", full, "full compliance opens archives")
        frameworks = {framework for record in report["files"] for finding in record.get("findings") or []
                      for framework in finding.get("frameworks") or []}
        self.assertIn("pci_dss", frameworks, "full compliance maps every framework")

    def test_compliance_maps_to_the_frameworks_chosen_and_no_other(self) -> None:
        def frameworks(report: dict) -> set[str]:
            return {framework for record in report["files"] for finding in record.get("findings") or []
                    for framework in finding.get("frameworks") or []}

        _paths, _read, none = self._scan(compliance_frameworks=[])
        self.assertEqual(frameworks(none), set())
        _paths, _read, pci = self._scan(compliance_frameworks=["pci_dss"])
        self.assertEqual(frameworks(pci), {"pci_dss"})

    def test_incremental_and_background_reach_the_scan(self) -> None:
        from backend import app as app_module

        on = app_module._to_config(_request(incremental_enabled=True), "default")
        off = app_module._to_config(_request(incremental_enabled=False), "default")
        self.assertTrue(on.incremental_enabled)
        self.assertFalse(off.incremental_enabled)
        self.assertTrue(on.incremental_scope, "an incremental scan has no baseline to reuse")
        self.assertTrue(_request(async_scan=True).async_scan)


if __name__ == "__main__":
    unittest.main()
