"""W1.3 (scaling roadmap, 2026-10): an endpoint scan of any size, paged by a folder frontier.

The endpoint walk was one command: it listed everything, kept the first 5,000 files and
dropped the rest without failing, and the backend held every record until one save. Now
each page lists at most a partition's worth of files and a bounded number of folders, is
written as a unit of the ledger as it finishes, and hands on the subfolders it met and
where it stopped. Every command runs in one WinRS shell per scan and has a wall clock.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock
from unittest.mock import patch

from backend import app as app_module
from backend import partitioned_scan, scan_resumer, store
from backend.security import Principal
from collectors import winrm_endpoint_scanner as winrm
from collectors.winrm_endpoint_scanner import WinRMEndpointScanner

TENANT = "w13-endpoint"
_PAGE = re.compile(r'ConvertFrom-Json \(\[Text\.Encoding\]::UTF8\.GetString\(\[Convert\]::FromBase64String\("([A-Za-z0-9+/=]*)"\)\)\)')
_PATHS = re.compile(r'\$pathsJson = \[Text\.Encoding\]::UTF8\.GetString\(\[Convert\]::FromBase64String\("([A-Za-z0-9+/=]*)"\)\)')


class _Response:
    def __init__(self, body: str) -> None:
        self.status_code = 0
        self.std_out = body.encode("utf-8")
        self.std_err = b""


class _Endpoint:
    """An endpoint's files - Windows paths to text - answering the collector's commands the way
    its script would: a page lists one level of the page's folders, a batch reads named files."""

    def __init__(self, files: dict[str, str]) -> None:
        self.files = files
        self.folders: dict[str, list[tuple[str, bool]]] = {}
        for path in files:
            parts = path.split("\\")
            for depth in range(1, len(parts)):
                parent, name = "\\".join(parts[:depth]), parts[depth]
                entry = (name, depth < len(parts) - 1)
                entries = self.folders.setdefault(parent, [])
                if entry not in entries:
                    entries.append(entry)
        self.commands = 0
        self.pages = 0

    @staticmethod
    def _record(path: str, text: str, *, content: bool) -> dict:
        name = path.rsplit("\\", 1)[-1]
        data = text.encode("utf-8")
        return {
            "path": path, "name": name, "size": len(data), "extension": "." + name.rsplit(".", 1)[-1].lower(),
            "is_hidden": False, "is_system": False, "created_at": "2026-09-01T00:00:00.0000000Z",
            "modified_at": "2026-09-01T00:00:00.0000000Z", "accessed_at": "2026-09-01T00:00:00.0000000Z",
            "attributes": "Archive", "sha256": hashlib.sha256(data).hexdigest() if content else "",
            "protected": False, "content_status": "", "content_scannable": None, "protection_type": "",
            "scan_error": "", "owner": "CORP\\owner" if content else "", "principals": [], "permissions": [],
            "types": [], "inherited": [], "sids": [], "content": text if content else "",
            "scan_completeness": "FULL" if content else "NONE", "bytes_scanned": len(data) if content else 0,
            "total_bytes": len(data), "truncated": False,
        }

    def run(self, script: str) -> _Response:
        self.commands += 1
        page_match = _PAGE.search(script)
        page = json.loads(base64.b64decode(page_match.group(1))) if page_match else {}
        diagnostics = {"visited_files": 0, "matched_files": 0, "missing_roots": [], "unreadable_dirs": []}
        if page:
            self.pages += 1
            records, found, rest = self._page(page, diagnostics)
            body = {"records": records, "diagnostics": diagnostics, "folders": found, "continuation": rest}
        else:
            paths = json.loads(base64.b64decode(_PATHS.search(script).group(1)))
            content = "if ($true -and ($textExtensions" in script
            records = []
            for path in paths:
                # A folder is walked whole, as the single path's command does, to its cap.
                for found in ([path] if path in self.files else self._walk(path)):
                    if len(records) < 5000:
                        records.append(self._record(found, self.files[found], content=content))
            body = {"records": records, "diagnostics": diagnostics, "folders": [], "continuation": []}
        return _Response(json.dumps(body))

    def _walk(self, folder: str) -> list[str]:
        found: list[str] = []
        for name, is_dir in sorted(self.folders.get(folder, []), key=lambda item: item[0].upper()):
            child = folder + "\\" + name
            found.extend(self._walk(child) if is_dir else [child])
        return found

    def _page(self, page: dict, diagnostics: dict):
        size, max_folders = int(page["page_size"]), int(page["max_folders"])
        records: list[dict] = []
        found: list[dict] = []
        rest: list[dict] = []
        listed = 0
        stopped = False
        for spec in page["folders"]:
            if stopped or listed >= max_folders:
                rest.append(spec)
                continue
            path = spec["path"]
            if spec.get("root") and path not in self.folders:
                if path in self.files:
                    records.append(self._record(path, self.files[path], content=False))
                else:
                    diagnostics["missing_roots"].append(path)
                continue
            listed += 1
            after = str(spec.get("after") or "")
            for name, is_dir in sorted(self.folders.get(path, []), key=lambda item: item[0].upper()):
                if after and name.upper() <= after.upper():
                    continue
                child = path + "\\" + name
                if is_dir:
                    if int(spec["depth"]) + 1 <= 12:
                        found.append({"path": child, "depth": int(spec["depth"]) + 1, "after": "", "root": False})
                    continue
                diagnostics["visited_files"] += 1
                diagnostics["matched_files"] += 1
                records.append(self._record(child, self.files[child], content=False))
                if len(records) >= size:
                    rest.append({"path": path, "depth": int(spec["depth"]), "after": name, "root": False})
                    stopped = True
                    break
        return records, found, rest


def _tree(files_per_folder: int, folders: int) -> dict[str, str]:
    files = {}
    for folder in range(folders):
        for index in range(files_per_folder):
            text = f"contact user{folder}x{index}@example.com about it" if index % 3 == 0 else f"plain notes {index}"
            files[f"C:\\Data\\dept{folder:02d}\\file{index:04d}.txt"] = text
    files["C:\\Data\\top.txt"] = "card 4111 1111 1111 1111 exp 09/29"
    return files


class _EndpointTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant = f"{TENANT}-{uuid.uuid4().hex[:6]}"
        store.create_tenant(self.tenant, "Endpoint")
        self.env = mock.patch.dict(os.environ, {"DSPM_PARTITION_RETRY_SECONDS": "0", "DSPM_PARTITIONED_SCANS": "1"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def _serve(self, endpoint: _Endpoint):
        def run_ps_file(scanner, script):
            scanner.last_connection_host = "fs-endpoint"
            return endpoint.run(script)

        return patch.object(WinRMEndpointScanner, "_run_ps_file", run_ps_file)

    def _payload(self, **overrides):
        settings = dict(host="fs-endpoint", username="svc", credential_ref="", paths=["C:\\Data"], max_depth=12,
                        read_content=True, read_acl=False, incremental_enabled=False, scan_label="laptop")
        settings.update(overrides)
        return app_module.EndpointScanRequest(**settings)

    def _scan(self, endpoint: _Endpoint, **overrides) -> dict:
        payload = self._payload(**overrides)
        principal = Principal(subject="tester", role="admin", tenant_id=self.tenant, auth_type="session")
        config = app_module._to_endpoint_config(payload, self.tenant)
        with self._serve(endpoint):
            return app_module._run_endpoint_scan_payload(config, payload, principal)

    def _estate(self) -> list[tuple[str, int]]:
        with store._connect() as conn:
            return sorted((row["path"], int(row["finding_count"] or 0)) for row in conn.execute(
                "SELECT path, finding_count FROM assets WHERE tenant_id = ?", (self.tenant,)).fetchall())


class NoRecordCapTest(_EndpointTest):

    def test_an_endpoint_of_twelve_thousand_files_is_scanned_whole(self) -> None:
        files = _tree(files_per_folder=400, folders=30)
        endpoint = _Endpoint(files)
        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_FILES": "2000"}):
            compact = self._scan(endpoint, read_content=False)
        self.assertEqual(compact["file_count"], len(files), "the 5,000-file cap is still there")
        self.assertEqual(len(self._estate()), len(files))
        units = store.list_scan_partitions(self.tenant, compact["scan_id"])
        self.assertGreater(len(units), 6)
        self.assertEqual({unit["status"] for unit in units}, {"done"})
        self.assertTrue(all(int(unit["files"] or 0) <= 2000 for unit in units), "a page held more than a partition")
        report = store.read_scan_report(self.tenant, compact["scan_id"])
        self.assertEqual(report["source"], "endpoint-winrm")
        self.assertEqual(report["endpoint"]["host"], "fs-endpoint")
        self.assertTrue(report["endpoint"]["frontier"])


class APageReadsAndAnalyzesWhatChangedTest(_EndpointTest):

    def test_content_is_read_in_batches_and_findings_land(self) -> None:
        endpoint = _Endpoint(_tree(files_per_folder=12, folders=3))
        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_FILES": "10", "DSPM_ENDPOINT_PAGE_FOLDERS": "2"}):
            compact = self._scan(endpoint)
        report = store.read_scan_report(self.tenant, compact["scan_id"])
        self.assertEqual(compact["file_count"], 37)
        with_findings = {f["path"] for f in report["files"] if f.get("findings")}
        self.assertIn("C:\\Data\\top.txt", with_findings)
        self.assertGreater(len(with_findings), 10)
        self.assertGreater(endpoint.commands, endpoint.pages, "no content batch was read")

    def test_the_same_files_the_single_path_reports(self) -> None:
        files = _tree(files_per_folder=12, folders=3)
        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_FILES": "10", "DSPM_ENDPOINT_PAGE_FOLDERS": "2"}):
            paged = self._scan(_Endpoint(files))
            paged_estate = self._estate()
        store.delete_tenant_with_data(self.tenant)
        store.create_tenant(self.tenant, "Endpoint")
        with mock.patch.dict(os.environ, {"DSPM_PARTITIONED_SCANS": "0"}):
            single = self._scan(_Endpoint(files))
        self.assertEqual(sorted(f["path"] for f in single["files"]), sorted(path for path, _count in paged_estate))
        self.assertEqual(paged["file_count"], len(single["files"]))
        self.assertEqual(self._estate(), paged_estate, "the frontier found different files or findings")


class APageRetriedGivesTheSameEstateTest(_EndpointTest):

    def test_a_page_whose_write_fails_twice_is_retried_without_doubling_anything(self) -> None:
        files = _tree(files_per_folder=12, folders=3)
        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_FILES": "10", "DSPM_ENDPOINT_PAGE_FOLDERS": "2"}):
            self._scan(_Endpoint(files))
            clean = self._estate()
            store.delete_tenant_with_data(self.tenant)
            store.create_tenant(self.tenant, "Endpoint")
            real = store.persist_partition
            failures = {"left": 2}

            def flaky(*args, **kwargs):
                if args[2] == "p00002" and failures["left"]:
                    failures["left"] -= 1
                    raise OSError("the write failed")
                return real(*args, **kwargs)

            with patch.object(store, "persist_partition", side_effect=flaky):
                compact = self._scan(_Endpoint(files))
        units = store.list_scan_partitions(self.tenant, compact["scan_id"])
        self.assertEqual(next(unit for unit in units if unit["partition_id"] == "p00002")["attempt"], 3)
        self.assertEqual(len({unit["partition_id"] for unit in units}), len(units))
        self.assertEqual(self._estate(), clean)


class ACrashResumesFromTheFrontierTest(_EndpointTest):

    def test_a_scan_that_dies_mid_frontier_is_continued_into_the_same_estate(self) -> None:
        files = _tree(files_per_folder=12, folders=3)
        with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_FILES": "10", "DSPM_ENDPOINT_PAGE_FOLDERS": "2"}):
            self._scan(_Endpoint(files))
            clean = self._estate()
            store.delete_tenant_with_data(self.tenant)
            store.create_tenant(self.tenant, "Endpoint")
            endpoint = _Endpoint(files)
            real_page = app_module._run_endpoint_page
            calls = {"n": 0}

            def dies_on_the_fourth(*args, **kwargs):
                calls["n"] += 1
                if calls["n"] == 4:
                    raise KeyboardInterrupt("the process died")
                return real_page(*args, **kwargs)

            with patch.dict(partitioned_scan._UNIT_RUNNERS, {"endpoint-winrm": dies_on_the_fourth}):
                with self.assertRaises(KeyboardInterrupt):
                    self._scan(endpoint)
            (record,) = [r for r in store.list_unfinished_partitioned_scans() if r["tenant_id"] == self.tenant]
            self.assertEqual(record["status"], "running")
            self.assertTrue(record["resumable"])
            app_module._ENDPOINT_RUNS.clear()
            resumed: list[str] = []

            def resume(found: dict) -> None:
                resumed.append(found["scan_id"])
                payload = app_module.EndpointScanRequest.model_validate(found["request"])
                principal = Principal(subject="tester", role="admin", tenant_id=self.tenant, auth_type="session")
                app_module._continue_endpoint_scan(found["scan_id"], payload, principal, None)

            with self._serve(endpoint):
                taken = scan_resumer.resume_stale_scans(resume, stale_after_seconds=0)
        self.assertEqual(taken, [record["scan_id"]])
        self.assertEqual(store.read_partitioned_scan(self.tenant, record["scan_id"])["status"], "done")
        self.assertEqual(self._estate(), clean, "the resumed scan's estate differs")


class TheResumerKnowsAnEndpointScanTest(unittest.TestCase):

    def test_an_endpoint_record_is_resumed_as_an_endpoint_scan(self) -> None:
        record = {"tenant_id": "t", "scan_id": "s", "header": {"source": "endpoint-winrm"}, "request": {}}
        with patch.object(app_module, "_resume_endpoint_scan") as resume:
            app_module._resume_partitioned_scan(record)
        resume.assert_called_once_with(record)
        self.assertEqual(app_module.rebuild_scan_config(record).tenant_id, "t")


class _Protocol:
    """A WS-Man protocol that records what it was asked to do."""

    def __init__(self, *, hang: bool = False) -> None:
        self.hang = hang
        self.opened: list[str] = []
        self.closed: list[str] = []
        self.cleaned: list[str] = []
        self.commands = 0

    def open_shell(self, codepage=None):
        shell = f"shell-{len(self.opened)}"
        self.opened.append(shell)
        return shell

    def run_command(self, shell_id, command, arguments):
        self.commands += 1
        return f"cmd-{self.commands}"

    def send_command_input(self, shell_id, command_id, data, end=False):
        return None

    def get_command_output_raw(self, shell_id, command_id):
        if self.hang:
            from winrm.exceptions import WinRMOperationTimeoutError

            raise WinRMOperationTimeoutError()
        return b"{}", b"", 0, True

    def cleanup_command(self, shell_id, command_id):
        self.cleaned.append(command_id)

    def close_shell(self, shell_id):
        self.closed.append(shell_id)


class _Session:
    def __init__(self, protocol) -> None:
        self.protocol = protocol


def _scanner() -> WinRMEndpointScanner:
    return WinRMEndpointScanner(winrm.WinRMEndpointConfig(host="fs-endpoint", username="svc", password="x"))


class OneShellPerScanTest(unittest.TestCase):

    def test_commands_in_a_block_share_one_shell_and_it_closes_at_the_end(self) -> None:
        protocol = _Protocol()
        scanner = _scanner()
        with scanner.reusing_shell():
            for _ in range(3):
                scanner._run_ps_file_over_stdin(_Session(protocol), "Write-Output 1")
            self.assertEqual(protocol.opened, ["shell-0"])
            self.assertEqual(protocol.closed, [])
        self.assertEqual(protocol.closed, ["shell-0"])
        self.assertEqual(len(protocol.cleaned), 3, "each command is still cleaned up")

    def test_outside_a_block_each_command_has_its_own_shell(self) -> None:
        protocol = _Protocol()
        scanner = _scanner()
        for _ in range(2):
            scanner._run_ps_file_over_stdin(_Session(protocol), "Write-Output 1")
        self.assertEqual(protocol.opened, ["shell-0", "shell-1"])
        self.assertEqual(protocol.closed, ["shell-0", "shell-1"])


class ACommandHasAWallClockTest(unittest.TestCase):

    def test_a_command_that_never_finishes_is_stopped_and_its_shell_closed(self) -> None:
        protocol = _Protocol(hang=True)
        scanner = _scanner()
        with mock.patch.dict(os.environ, {"DSPM_WINRM_COMMAND_TIMEOUT_SECONDS": "1"}):
            with scanner.reusing_shell():
                with self.assertRaises(winrm.WinRMCommandTimedOut):
                    scanner._run_ps_file_over_stdin(_Session(protocol), "Start-Sleep 999")
                self.assertEqual(protocol.closed, ["shell-0"], "a shell a command timed out in was kept")
        self.assertEqual(protocol.cleaned, ["cmd-1"])

    def test_a_timeout_is_not_tried_again_on_another_transport(self) -> None:
        scanner = _scanner()
        sessions: list[str] = []

        def session(host, transport):
            sessions.append(transport)
            return _Session(_Protocol(hang=True))

        with mock.patch.dict(os.environ, {"DSPM_WINRM_COMMAND_TIMEOUT_SECONDS": "1"}), \
                patch.object(scanner, "_winrm_session", side_effect=session), \
                patch.object(scanner, "_winrm_transports", return_value=["ntlm", "kerberos"]), \
                patch.object(scanner, "_connection_hosts", return_value=["fs-endpoint"]):
            with self.assertRaises(winrm.WinRMCommandTimedOut):
                scanner._run_with_session(lambda s: scanner._run_ps_file_over_stdin(s, "Start-Sleep 999"))
        self.assertEqual(sessions, ["ntlm"])


@unittest.skipUnless(os.name == "nt" and shutil.which("powershell.exe"), "runs the collector script with PowerShell")
class TheRealPageScriptTest(_EndpointTest):
    """The page and batch scripts themselves, run by PowerShell on a folder of this host."""

    def test_a_partitioned_endpoint_scan_of_a_real_folder(self) -> None:
        root = Path(f"C:/dspm-w13-{uuid.uuid4().hex[:6]}")
        try:
            (root / "sub" / "deeper").mkdir(parents=True)
            expected = set()
            for index in range(7):
                path = root / f"note{index}.txt"
                path.write_text(f"mail hr{index}@example.com" if index % 2 else "plain", encoding="utf-8")
                expected.add(str(path).replace("/", "\\"))
            for name in ("inner.txt", "deeper/last.txt"):
                path = root / "sub" / name
                path.write_text("card 4111 1111 1111 1111 exp 09/29", encoding="utf-8")
                expected.add(str(path).replace("/", "\\"))

            def run_ps_file(scanner, script):
                scanner.last_connection_host = "fs-endpoint"
                file = Path(tempfile.gettempdir()) / f"w13-{uuid.uuid4().hex[:6]}.ps1"
                file.write_text(script, encoding="utf-8-sig")
                try:
                    done = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(file)],
                                          capture_output=True, timeout=180)
                finally:
                    file.unlink()
                return type("R", (), {"status_code": done.returncode, "std_out": done.stdout, "std_err": done.stderr})()

            payload = self._payload(paths=[str(root).replace("/", "\\")])
            principal = Principal(subject="tester", role="admin", tenant_id=self.tenant, auth_type="session")
            config = app_module._to_endpoint_config(payload, self.tenant)
            with mock.patch.dict(os.environ, {"DSPM_PARTITION_MAX_FILES": "3", "DSPM_ENDPOINT_PAGE_FOLDERS": "1"}), \
                    patch.object(WinRMEndpointScanner, "_run_ps_file", run_ps_file):
                compact = app_module._run_endpoint_scan_payload(config, payload, principal)
            report = store.read_scan_report(self.tenant, compact["scan_id"])
            self.assertEqual({f["path"] for f in report["files"]}, expected)
            self.assertGreater(len(store.list_scan_partitions(self.tenant, compact["scan_id"])), 3)
            self.assertTrue(any(f.get("findings") for f in report["files"] if f["path"].endswith("last.txt")))
        finally:
            shutil.rmtree(root, ignore_errors=True)
