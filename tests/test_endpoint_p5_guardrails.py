from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from backend.app import EndpointScanRequest, _apply_local_endpoint_acl
from collectors import win_security
from collectors.winrm_endpoint_scanner import (
    WINRM_GZIP_RESPONSE_PREFIX,
    WinRMEndpointConfig,
    WinRMEndpointScanner,
    _decode_scan_response,
    _scan_script,
)


_POWERSHELL = shutil.which("powershell.exe")
_CORPUS_BASE = "C:\\" if os.name == "nt" else None
_LOOPBACK_BUDGET_SECONDS = 20.0


class EndpointP5DefaultContractTests(unittest.TestCase):
    def test_endpoint_acl_collection_defaults_on_at_api_and_collector_boundaries(self) -> None:
        self.assertTrue(EndpointScanRequest(host="endpoint-01").read_acl)
        self.assertTrue(
            WinRMEndpointConfig(
                host="endpoint-01",
                username="scan",
                password="secret",
            ).read_acl
        )

    def test_local_endpoint_uses_full_acl_and_preserves_reused_snapshot(self) -> None:
        fresh = {"path": r"C:\Data\fresh.txt", "owner": "old", "acl": {}}
        resolved = {
            "owner": "CORP\\owner",
            "principals": ["CORP\\analyst"],
            "permissions": ["ReadAndExecute, Synchronize"],
        }
        with mock.patch("backend.app.read_security", return_value=resolved) as read:
            _apply_local_endpoint_acl(fresh, read_acl=True)
        read.assert_called_once_with(r"C:\Data\fresh.txt", with_dacl=True)
        self.assertEqual(fresh["owner"], resolved["owner"])
        self.assertEqual(fresh["acl"], resolved)

        reused = {
            "path": r"C:\Data\reused.txt",
            "owner": resolved["owner"],
            "acl": dict(resolved),
            "incremental_reused": True,
        }
        with mock.patch(
            "backend.app.read_security",
            side_effect=AssertionError("reused ACL should come from the durable snapshot"),
        ):
            _apply_local_endpoint_acl(reused, read_acl=True)
        self.assertEqual(reused["acl"], resolved)


class _FastCaptureProtocol:
    def __init__(self) -> None:
        self.arguments: list[str] = []
        self.payload = b""

    def open_shell(self, **_kwargs):
        return "shell"

    def run_command(self, _shell_id, _command, arguments):
        self.arguments = list(arguments)
        return "command"

    def send_command_input(self, _shell_id, _command_id, payload, end=False):
        self.payload += payload

    def get_command_output(self, _shell_id, _command_id):
        return b"{}", b"", 0

    def cleanup_command(self, _shell_id, _command_id):
        pass

    def close_shell(self, _shell_id):
        pass


class _LegacyCaptureSession:
    def __init__(self) -> None:
        # Deliberately lacks the complete low-level Protocol contract so the
        # scanner uses this deterministic run_cmd target emulator.
        self.protocol = SimpleNamespace()
        self.calls: list[tuple[str, list[str]]] = []
        self.powershell_calls = 0

    def run_cmd(self, command, arguments):
        args = list(arguments)
        self.calls.append((command, args))
        if command == "powershell.exe":
            self.powershell_calls += 1
            if self.powershell_calls == 1:
                remote_path = r"C:\Windows\Temp\dspm_p5_capture.b64"
                return SimpleNamespace(
                    status_code=0,
                    std_out=base64.b64encode(remote_path.encode("utf-8")),
                    std_err=b"",
                )
        return SimpleNamespace(status_code=0, std_out=b"{}", std_err=b"")

    def reconstructed_script(self) -> str:
        chunks = []
        for command, args in self.calls:
            if command != "cmd.exe" or "echo(" not in args[-1]:
                continue
            match = re.search(r'echo\((.*?)>>"', args[-1])
            if match:
                chunks.append(match.group(1))
        return base64.b64decode("".join(chunks), validate=True).decode("utf-8")


def _run_script_file(script: str) -> subprocess.CompletedProcess:
    with tempfile.NamedTemporaryFile(
        "w",
        suffix=".ps1",
        delete=False,
        encoding="utf-8-sig",
    ) as handle:
        handle.write(script)
        path = handle.name
    try:
        return subprocess.run(
            [_POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path],
            capture_output=True,
            timeout=120,
            check=False,
        )
    finally:
        os.unlink(path)


@unittest.skipUnless(
    os.name == "nt" and _POWERSHELL,
    "needs Windows + powershell.exe for the P5 local-loopback gate",
)
class EndpointP5LoopbackParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(_CORPUS_BASE) / f"dspm_endpoint_p5_{os.getpid()}"
        shutil.rmtree(cls.root, ignore_errors=True)
        cls.root.mkdir(parents=True)
        cls.secret_path = cls.root / "secret.txt"
        cls.secret_path.write_text(
            "ssn 123-45-6789\napi_key=AKIAIOSFODNN7EXAMPLE\n",
            encoding="utf-8",
        )
        (cls.root / "notes.txt").write_text("ordinary notes\n", encoding="utf-8")
        cls.paths = [cls.secret_path, cls.root / "notes.txt"]
        cls.fixed_timestamp = 1_700_000_000
        cls._reset_file_times()

        cls.script = _scan_script(
            [str(cls.root)],
            max_depth=2,
            read_content=True,
            max_read_bytes=1_000_000,
            allowed_extensions=[],
            extension_filter_enabled=False,
            include_hidden=True,
            include_system=True,
            hidden_filter_enabled=False,
            system_filter_enabled=False,
            read_acl=True,
            inspect_archives=False,
            hash_files=True,
            read_owner=True,
            parallel_workers=2,
        )

        # Capture the shipped stdin bootstrap and payload exactly as WS-Man sees
        # them, then execute that command against the local PowerShell process.
        fast_protocol = _FastCaptureProtocol()
        fast_scanner = WinRMEndpointScanner(
            WinRMEndpointConfig(host="loopback", username="scan", password="secret")
        )
        fast_scanner._run_ps_file_over_stdin(
            SimpleNamespace(protocol=fast_protocol, run_cmd=mock.Mock()),
            cls.script,
        )
        cls._reset_file_times()
        started = time.perf_counter()
        cls.fast = subprocess.run(
            [
                _POWERSHELL,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                fast_protocol.arguments[-1],
            ],
            input=fast_protocol.payload,
            capture_output=True,
            timeout=120,
            check=False,
        )
        cls.fast_elapsed = time.perf_counter() - started

        # Exercise the actual compatible disk/chunk builder, reconstruct what
        # landed on the target, and execute that exact reconstructed script.
        legacy_session = _LegacyCaptureSession()
        legacy_scanner = WinRMEndpointScanner(
            WinRMEndpointConfig(host="loopback", username="scan", password="secret")
        )
        legacy_scanner._run_ps_file_legacy(legacy_session, cls.script)
        cls.legacy_script = legacy_session.reconstructed_script()
        cls._reset_file_times()
        cls.legacy = _run_script_file(cls.legacy_script)

        if cls.fast.returncode != 0:
            raise AssertionError(
                "fast bootstrap failed: "
                + cls.fast.stderr.decode("utf-8", "replace")[:500]
            )
        if cls.legacy.returncode != 0:
            raise AssertionError(
                "legacy script failed: "
                + cls.legacy.stderr.decode("utf-8", "replace")[:500]
            )

        cls.fast_json, _ = _decode_scan_response(cls.fast.stdout)
        cls.legacy_json, _ = _decode_scan_response(cls.legacy.stdout)

    @classmethod
    def _reset_file_times(cls) -> None:
        for path in cls.paths:
            os.utime(path, (cls.fixed_timestamp, cls.fixed_timestamp))

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_stdin_and_legacy_delivery_return_byte_identical_records(self) -> None:
        self.assertEqual(self.legacy_script.encode("utf-8"), self.script.encode("utf-8"))
        self.assertTrue(self.fast.stdout.strip().startswith(WINRM_GZIP_RESPONSE_PREFIX))
        self.assertTrue(self.legacy.stdout.strip().startswith(WINRM_GZIP_RESPONSE_PREFIX))
        self.assertEqual(self.fast_json, self.legacy_json)

    def test_fast_local_loopback_scan_stays_inside_wall_clock_budget(self) -> None:
        self.assertLess(
            self.fast_elapsed,
            _LOOPBACK_BUDGET_SECONDS,
            f"fast endpoint loopback took {self.fast_elapsed:.2f}s; "
            "the old multi-command delivery path may have returned",
        )

    def test_endpoint_acl_is_byte_compatible_with_smb_security_descriptor_shape(self) -> None:
        import json

        from collectors.winrm_endpoint_scanner import _endpoint_acl

        payload = json.loads(self.fast_json)
        by_name = {str(item.get("name")): item for item in payload.get("records") or []}
        # Revision 0055: the script sends the ACL as collectors.acl_powershell does - masks,
        # not rights sentences - and the console renders it; the parsed ACL is what is compared.
        actual = _endpoint_acl(by_name["secret.txt"])
        expected = win_security.security_for_path(str(self.secret_path), with_dacl=True)

        self.assertTrue(expected.get("owner"), "reference ACL owner should resolve")
        self.assertEqual((actual.get("owner"), actual.get("owner_sid"), actual.get("protected")),
                         (expected.get("owner"), expected.get("owner_sid"), expected.get("protected")))
        actual_entries = list(zip(actual.get("principals") or [], actual.get("permissions") or []))
        expected_entries = list(zip(expected.get("principals") or [], expected.get("permissions") or []))
        self.assertEqual(actual_entries, expected_entries)
        compared = ("principal", "sid", "mask", "type", "inherited", "flags")
        self.assertEqual([tuple(entry.get(key) for key in compared) for entry in actual.get("entries") or []],
                         [tuple(entry.get(key) for key in compared) for entry in expected.get("entries") or []])


if __name__ == "__main__":
    unittest.main()
