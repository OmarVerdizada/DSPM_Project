from __future__ import annotations

import base64
import gzip
import math
import os
import re
import shutil
import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

from collectors.winrm_endpoint_scanner import (
    WINRM_FAST_DELIVERY_COMMAND_BUDGET,
    WinRMEndpointConfig,
    WinRMEndpointScanner,
)


class _StreamingProtocol:
    def __init__(self, output: tuple[bytes, bytes, int] = (b"scan-output", b"", 0)) -> None:
        self.output = output
        self.open_calls: list[dict] = []
        self.command_calls: list[tuple] = []
        self.input_calls: list[tuple] = []
        self.cleanup_calls: list[tuple] = []
        self.close_calls: list[str] = []

    def open_shell(self, **kwargs):
        self.open_calls.append(kwargs)
        return "shell-1"

    def run_command(self, shell_id, command, arguments):
        self.command_calls.append((shell_id, command, list(arguments)))
        return "command-1"

    def send_command_input(self, shell_id, command_id, payload, end=False):
        self.input_calls.append((shell_id, command_id, payload, end))

    def get_command_output(self, shell_id, command_id):
        return self.output

    def cleanup_command(self, shell_id, command_id):
        self.cleanup_calls.append((shell_id, command_id))

    def close_shell(self, shell_id):
        self.close_calls.append(shell_id)


class WinRMScriptDeliveryTests(unittest.TestCase):
    def _scanner(self) -> WinRMEndpointScanner:
        return WinRMEndpointScanner(
            WinRMEndpointConfig(host="endpoint-01", username="scan", password="secret")
        )

    def test_stdin_delivery_runs_one_command_and_preserves_script_bytes(self) -> None:
        script = "Write-Output 'Grüße from endpoint'\n" + ("# compressible scan source\n" * 400)
        protocol = _StreamingProtocol()
        session = SimpleNamespace(protocol=protocol, run_cmd=mock.Mock())

        result = self._scanner()._run_ps_file_with_session(session, script)

        self.assertEqual(result.status_code, 0)
        self.assertEqual(result.std_out, b"scan-output")
        self.assertEqual(len(protocol.command_calls), 1)
        self.assertEqual(protocol.command_calls[0][1], "powershell.exe")
        self.assertEqual(protocol.open_calls, [{"codepage": 65001}])
        self.assertEqual(protocol.cleanup_calls, [("shell-1", "command-1")])
        self.assertEqual(protocol.close_calls, ["shell-1"])
        session.run_cmd.assert_not_called()

        _, _, payload, end = protocol.input_calls[0]
        self.assertTrue(end)
        self.assertEqual(gzip.decompress(base64.b64decode(payload)), script.encode("utf-8"))

        encoded_bootstrap = protocol.command_calls[0][2][-1]
        bootstrap = base64.b64decode(encoded_bootstrap).decode("utf-16le")
        self.assertIn("[Console]::In.ReadToEnd()", bootstrap)
        self.assertIn("IO.Compression.GZipStream", bootstrap)
        self.assertIn("[ScriptBlock]::Create", bootstrap)

    def test_script_failure_is_returned_without_reexecuting_legacy_path(self) -> None:
        protocol = _StreamingProtocol(output=(b"", b"script failed", 1))
        session = SimpleNamespace(protocol=protocol, run_cmd=mock.Mock())

        result = self._scanner()._run_ps_file_with_session(session, "throw 'failed'")

        self.assertEqual(result.status_code, 1)
        self.assertEqual(result.std_err, b"script failed")
        session.run_cmd.assert_not_called()

    def test_transport_failure_uses_cmd_chunks_and_reassembles_exact_script(self) -> None:
        script = "Write-Output 'fallback'\n" + ("0123456789abcdef" * 500)
        remote_path = r"C:\Windows\Temp\dspm_test.b64"
        calls: list[tuple[str, list[str]]] = []
        powershell_calls = 0

        class FailingProtocol:
            def open_shell(self, **_kwargs):
                raise RuntimeError("stdin is unavailable")

        def run_cmd(command, arguments):
            nonlocal powershell_calls
            args = list(arguments)
            calls.append((command, args))
            if command == "powershell.exe":
                powershell_calls += 1
                if powershell_calls == 1:
                    return SimpleNamespace(
                        status_code=0,
                        std_out=base64.b64encode(remote_path.encode("utf-8")),
                        std_err=b"",
                    )
                return SimpleNamespace(status_code=0, std_out=b"fallback-output", std_err=b"")
            return SimpleNamespace(status_code=0, std_out=b"", std_err=b"")

        session = SimpleNamespace(protocol=FailingProtocol(), run_cmd=mock.Mock(side_effect=run_cmd))
        result = self._scanner()._run_ps_file_with_session(session, script)

        self.assertEqual(result.std_out, b"fallback-output")
        self.assertEqual(powershell_calls, 2, "fallback should only spawn PowerShell for init and execution")
        chunk_calls = [
            args for command, args in calls if command == "cmd.exe" and "echo(" in args[-1]
        ]
        expected_chunks = math.ceil(len(base64.b64encode(script.encode("utf-8"))) / 1800)
        self.assertEqual(len(chunk_calls), expected_chunks)
        reconstructed = "".join(
            re.search(r"echo\((.*?)>>\"", args[-1]).group(1) for args in chunk_calls
        )
        self.assertEqual(base64.b64decode(reconstructed), script.encode("utf-8"))


class WinRMDeliveryFallbackScopeTests(unittest.TestCase):
    """A dead socket must not be dialed twice.

    The legacy path reuses the SAME session, so a connection/auth failure fails
    there identically. Falling back on those doubled the wall clock of every
    unreachable-endpoint failure (measured live: 16.0s vs 8.0s for one connect
    timeout, and the connect loop repeats that per host/transport candidate).
    """

    def _scanner(self) -> WinRMEndpointScanner:
        return WinRMEndpointScanner(
            WinRMEndpointConfig(host="endpoint-01", username="scan", password="secret")
        )

    def _session_failing_with(self, error: BaseException):
        class FailingProtocol:
            def open_shell(self, **_kwargs):
                raise error

        return SimpleNamespace(protocol=FailingProtocol(), run_cmd=mock.Mock())

    def test_connection_errors_do_not_retry_the_legacy_path(self) -> None:
        import requests.exceptions as request_errors

        for error in (
            request_errors.ConnectTimeout("timed out"),
            request_errors.ConnectionError("refused"),
            request_errors.ReadTimeout("read timed out"),
            OSError("socket is gone"),
        ):
            with self.subTest(error=type(error).__name__):
                scanner = self._scanner()
                session = self._session_failing_with(error)

                with self.assertRaises(type(error)):
                    scanner._run_ps_file_with_session(session, "Write-Output ok")

                session.run_cmd.assert_not_called()
                self.assertEqual(scanner.last_delivery_diagnostics["delivery_mode"], "failed")

    def test_rejected_credentials_do_not_retry_the_legacy_path(self) -> None:
        from winrm.exceptions import InvalidCredentialsError

        scanner = self._scanner()
        session = self._session_failing_with(InvalidCredentialsError("bad password"))

        with self.assertRaises(InvalidCredentialsError):
            scanner._run_ps_file_with_session(session, "Write-Output ok")

        session.run_cmd.assert_not_called()

    def test_wsman_capability_refusal_still_falls_back(self) -> None:
        remote_path = r"C:\Windows\Temp\dspm_test.b64"
        powershell_calls = 0

        def run_cmd(command, arguments):
            nonlocal powershell_calls
            if command == "powershell.exe":
                powershell_calls += 1
                if powershell_calls == 1:
                    return SimpleNamespace(
                        status_code=0,
                        std_out=base64.b64encode(remote_path.encode("utf-8")),
                        std_err=b"",
                    )
            return SimpleNamespace(status_code=0, std_out=b"legacy-output", std_err=b"")

        scanner = self._scanner()
        session = self._session_failing_with(RuntimeError("target refuses command input"))
        session.run_cmd = mock.Mock(side_effect=run_cmd)

        result = scanner._run_ps_file_with_session(session, "Write-Output ok")

        self.assertEqual(result.std_out, b"legacy-output")
        diagnostics = scanner.last_delivery_diagnostics
        self.assertEqual(diagnostics["delivery_mode"], "legacy_disk_chunks")
        self.assertEqual(diagnostics["delivery_fallback_reason"], "RuntimeError")
        self.assertGreater(diagnostics["delivery_remote_commands"], 1)

    def test_fast_path_records_a_single_remote_command(self) -> None:
        scanner = self._scanner()
        protocol = _StreamingProtocol()
        session = SimpleNamespace(protocol=protocol, run_cmd=mock.Mock())

        scanner._run_ps_file_with_session(session, "Write-Output ok")

        diagnostics = scanner.last_delivery_diagnostics
        self.assertEqual(diagnostics["delivery_mode"], "stdin_gzip")
        self.assertEqual(diagnostics["delivery_remote_commands"], 1)
        self.assertLessEqual(
            diagnostics["delivery_remote_commands"],
            WINRM_FAST_DELIVERY_COMMAND_BUDGET,
            "primary delivery exceeded the P5 command budget",
        )
        self.assertEqual(diagnostics["remote_commands"], 1)
        self.assertEqual(diagnostics["response_envelopes"], 1)
        self.assertEqual(diagnostics["delivery_invocations"], 1)
        self.assertEqual(diagnostics["delivery_fallback_reason"], "")
        self.assertGreaterEqual(diagnostics["delivery_ms"], 0)

    def test_receive_envelopes_are_counted_from_raw_wsman_pages(self) -> None:
        from winrm.exceptions import WinRMOperationTimeoutError

        class PagedProtocol(_StreamingProtocol):
            def __init__(self):
                super().__init__()
                self.timeout_pending = True
                self.pages = [
                    (b"page-1", b"", -1, False),
                    (b"-page-2", b"warning", -1, False),
                    (b"-page-3", b"", 0, True),
                ]

            def get_command_output(self, shell_id, command_id):
                raise AssertionError("raw WS-Man receive pages should be used")

            def get_command_output_raw(self, shell_id, command_id):
                if self.timeout_pending:
                    self.timeout_pending = False
                    raise WinRMOperationTimeoutError()
                return self.pages.pop(0)

        scanner = self._scanner()
        protocol = PagedProtocol()
        session = SimpleNamespace(protocol=protocol, run_cmd=mock.Mock())

        result = scanner._run_ps_file_with_session(session, "Write-Output ok")

        self.assertEqual(result.std_out, b"page-1-page-2-page-3")
        self.assertEqual(result.std_err, b"warning")
        self.assertEqual(scanner.last_delivery_diagnostics["response_envelopes"], 4)
        self.assertEqual(scanner.last_delivery_diagnostics["delivery_response_envelopes"], 4)


class WinRMStdinChunkingTests(unittest.TestCase):
    """A large script must not be pushed as one oversized WS-Man envelope.

    P2 batches up to 256 changed paths into a single script; one envelope over
    the target's MaxEnvelopeSize would be refused and silently demote the scan
    to the slow legacy path.
    """

    def test_large_payload_is_sent_in_bounded_slices_ending_once(self) -> None:
        from collectors.winrm_endpoint_scanner import _WINRM_STDIN_CHUNK_BYTES

        # Random-ish content so gzip cannot collapse it below the chunk size.
        script = "".join(f"Write-Output '{index:08d}-{index * 7919:012d}'\n" for index in range(20000))
        protocol = _StreamingProtocol()
        session = SimpleNamespace(protocol=protocol, run_cmd=mock.Mock())
        scanner = WinRMEndpointScanner(
            WinRMEndpointConfig(host="endpoint-01", username="scan", password="secret")
        )

        scanner._run_ps_file_with_session(session, script)

        self.assertGreater(len(protocol.input_calls), 1, "payload should have been split")
        for _, _, slice_, _ in protocol.input_calls:
            self.assertLessEqual(len(slice_), _WINRM_STDIN_CHUNK_BYTES)
        ends = [end for _, _, _, end in protocol.input_calls]
        self.assertEqual(ends[-1], True, "the final slice must close stdin")
        self.assertEqual(ends.count(True), 1, "stdin must be closed exactly once")

        payload = b"".join(slice_ for _, _, slice_, _ in protocol.input_calls)
        self.assertEqual(gzip.decompress(base64.b64decode(payload)), script.encode("utf-8"))
        self.assertEqual(len(protocol.command_calls), 1, "still one remote command")


_POWERSHELL = shutil.which("powershell.exe")
# The scan script skips noise roots including %TEMP% (it lives under \AppData\),
# so a real corpus must sit at a non-excluded path. A drive-root dir is safe.
_CORPUS_BASE = "C:\\" if os.name == "nt" else None


@unittest.skipUnless(
    os.name == "nt" and _POWERSHELL,
    "needs Windows + powershell.exe to execute the delivered bootstrap",
)
class WinRMStdinBootstrapExecutionTests(unittest.TestCase):
    """Execute the SHIPPED bootstrap with a real PowerShell.

    Every other delivery test drives a fake WS-Man protocol, so the bootstrap
    PowerShell string itself is never run - a syntax error in it would break
    every fast-path delivery while the suite stayed green. This feeds the real
    gzip payload of a real scan script through the real bootstrap over stdin,
    exactly as the endpoint receives it.
    """

    def test_bootstrap_expands_and_runs_the_delivered_script(self) -> None:
        from collectors.winrm_endpoint_scanner import (
            WINRM_GZIP_RESPONSE_PREFIX,
            _read_json,
            _scan_script,
        )

        captured: dict = {}

        class CapturingProtocol:
            def open_shell(self, **_kwargs):
                return "shell"

            def run_command(self, shell_id, command, arguments):
                captured["arguments"] = list(arguments)
                return "cmd"

            def send_command_input(self, shell_id, command_id, payload, end=False):
                captured["payload"] = captured.get("payload", b"") + payload

            def get_command_output(self, shell_id, command_id):
                return (b"", b"", 0)

            def cleanup_command(self, shell_id, command_id):
                pass

            def close_shell(self, shell_id):
                pass

        corpus = os.path.join(_CORPUS_BASE, f"dspm_bootstrap_{os.getpid()}")
        shutil.rmtree(corpus, ignore_errors=True)
        os.makedirs(corpus, exist_ok=True)
        try:
            with open(os.path.join(corpus, "secret.txt"), "w", encoding="utf-8") as handle:
                handle.write("ssn 123-45-6789\napi_key=AKIAIOSFODNN7EXAMPLE\n")
            with open(os.path.join(corpus, "notes.txt"), "w", encoding="utf-8") as handle:
                handle.write("nothing sensitive here\n")

            script = _scan_script(
                [corpus], max_depth=2, read_content=True, max_read_bytes=1048576,
                allowed_extensions=[], extension_filter_enabled=False,
                include_hidden=True, include_system=False,
                hidden_filter_enabled=False, system_filter_enabled=False,
                read_acl=False, inspect_archives=False, hash_files=True,
                read_owner=True, parallel_workers=2,
            )

            scanner = WinRMEndpointScanner(
                WinRMEndpointConfig(host="endpoint-01", username="scan", password="secret")
            )
            session = SimpleNamespace(protocol=CapturingProtocol(), run_cmd=mock.Mock())
            scanner._run_ps_file_over_stdin(session, script)

            completed = subprocess.run(
                [_POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-EncodedCommand", captured["arguments"][-1]],
                input=captured["payload"], capture_output=True, timeout=300,
            )
            self.assertEqual(
                completed.returncode, 0,
                f"bootstrap failed: {completed.stderr.decode('utf-8', 'replace')[:400]}",
            )
            self.assertTrue(
                completed.stdout.strip().startswith(WINRM_GZIP_RESPONSE_PREFIX),
                "the delivered script must still emit the compressed response frame",
            )
            parsed = _read_json(completed.stdout) or {}
            records = parsed.get("records") or []
            by_name = {str(record.get("name")): record for record in records}
            self.assertEqual(sorted(by_name), ["notes.txt", "secret.txt"])
            self.assertIn("123-45-6789", by_name["secret.txt"].get("content") or "")
            self.assertTrue(by_name["secret.txt"].get("sha256"))
        finally:
            shutil.rmtree(corpus, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
