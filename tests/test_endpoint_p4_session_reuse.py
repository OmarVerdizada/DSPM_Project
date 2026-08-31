from __future__ import annotations

import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest import mock

from collectors.winrm_endpoint_scanner import WinRMEndpointConfig, WinRMEndpointScanner


def _result(output: bytes = b"ok") -> SimpleNamespace:
    return SimpleNamespace(status_code=0, std_out=output, std_err=b"")


class WinRMSessionReuseTests(unittest.TestCase):
    def _scanner(self) -> WinRMEndpointScanner:
        return WinRMEndpointScanner(
            WinRMEndpointConfig(
                host="endpoint-01",
                username="scan",
                password="secret",
                domain="CORP",
                use_ssl=True,
            )
        )

    def test_scan_option_changes_reuse_one_session_and_candidate_resolution(self) -> None:
        scanner = self._scanner()
        session = object()

        with mock.patch.object(scanner, "_connection_hosts", return_value=["endpoint-01"]) as hosts, \
             mock.patch.object(scanner, "_winrm_session", return_value=session) as create, \
             mock.patch.object(scanner, "_run_ps_file_with_session", return_value=_result()) as run:
            scanner._run_ps_file("metadata")
            scanner.config = replace(
                scanner.config,
                paths=[r"C:\Data\changed.txt"],
                read_content=True,
                hash_files=True,
            )
            scanner._run_ps_file("content")

        hosts.assert_called_once()
        create.assert_called_once_with("endpoint-01", "ntlm")
        self.assertEqual([call.args[0] for call in run.call_args_list], [session, session])
        self.assertEqual(scanner._session_diagnostics()["session_creations"], 1)
        self.assertEqual(scanner._session_diagnostics()["session_negotiations"], 1)
        self.assertEqual(scanner._session_diagnostics()["session_reuse_count"], 1)
        self.assertTrue(scanner._session_diagnostics()["session_reused"])

    def test_connection_probe_and_scan_share_the_negotiated_session(self) -> None:
        scanner = self._scanner()
        session = SimpleNamespace(
            run_ps=mock.Mock(
                return_value=_result(
                    b'{"computer":"ENDPOINT-01","user":"CORP\\\\scan"}'
                )
            )
        )

        with mock.patch.object(scanner, "_connection_hosts", return_value=["endpoint-01"]), \
             mock.patch.object(scanner, "_winrm_session", return_value=session) as create, \
             mock.patch.object(scanner, "_run_ps_file_with_session", return_value=_result()) as run:
            connection = scanner.test_connection()
            scanner._run_ps_file("scan")

        self.assertTrue(connection["connected"])
        create.assert_called_once_with("endpoint-01", "ntlm")
        run.assert_called_once_with(session, "scan")
        self.assertEqual(scanner._session_diagnostics()["session_reuse_count"], 1)

    def test_connection_candidates_are_resolved_once_per_job_and_host(self) -> None:
        scanner = self._scanner()

        with mock.patch(
            "collectors.winrm_endpoint_scanner.endpoint_connection_hosts",
            return_value=["endpoint-01", "192.0.2.10"],
        ) as resolve:
            self.assertEqual(scanner._connection_hosts(), ["endpoint-01", "192.0.2.10"])
            scanner.config = replace(scanner.config, paths=["documents"])
            self.assertEqual(scanner._connection_hosts(), ["endpoint-01", "192.0.2.10"])

        resolve.assert_called_once_with("endpoint-01")

    def test_security_relevant_config_change_forces_a_fresh_session(self) -> None:
        scanner = self._scanner()
        first_session = object()
        second_session = object()

        with mock.patch.object(scanner, "_connection_hosts", return_value=["endpoint-01"]), \
             mock.patch.object(scanner, "_winrm_session", side_effect=[first_session, second_session]) as create, \
             mock.patch.object(scanner, "_run_ps_file_with_session", return_value=_result()):
            scanner._run_ps_file("first")
            scanner.config = replace(scanner.config, password="rotated-secret")
            scanner._run_ps_file("second")

        self.assertEqual(create.call_count, 2)
        self.assertEqual(scanner._session_diagnostics()["session_creations"], 2)
        self.assertEqual(scanner._session_diagnostics()["session_negotiations"], 2)
        self.assertEqual(scanner._session_diagnostics()["session_reuse_count"], 0)
        self.assertFalse(scanner._session_diagnostics()["session_reused"])

    def test_failed_cached_session_is_invalidated_and_renegotiated(self) -> None:
        scanner = self._scanner()
        stale_session = object()
        replacement_session = object()

        def run(session, script):
            if session is stale_session and script == "second":
                raise ConnectionError("connection expired")
            return _result()

        with mock.patch.object(scanner, "_connection_hosts", return_value=["endpoint-01"]), \
             mock.patch.object(scanner, "_winrm_session", side_effect=[stale_session, replacement_session]) as create, \
             mock.patch.object(scanner, "_run_ps_file_with_session", side_effect=run):
            scanner._run_ps_file("first")
            scanner._run_ps_file("second")

        self.assertEqual(create.call_count, 2)
        diagnostics = scanner._session_diagnostics()
        self.assertEqual(diagnostics["session_failovers"], 1)
        self.assertEqual(diagnostics["session_negotiations"], 2)
        self.assertFalse(diagnostics["session_reused"])

    def test_working_fallback_transport_is_reused_without_retrying_preferred_transport(self) -> None:
        scanner = self._scanner()
        kerberos_session = object()
        ntlm_session = object()

        def run(session, _script):
            if session is kerberos_session:
                raise ConnectionError("no Kerberos ticket")
            return _result()

        with mock.patch.object(scanner, "_connection_hosts", return_value=["endpoint-01"]), \
             mock.patch.object(scanner, "_winrm_transports", return_value=["kerberos", "ntlm"]), \
             mock.patch.object(
                 scanner,
                 "_winrm_session",
                 side_effect=[kerberos_session, ntlm_session],
             ) as create, \
             mock.patch.object(scanner, "_run_ps_file_with_session", side_effect=run):
            scanner._run_ps_file("metadata")
            scanner._run_ps_file("content")

        self.assertEqual(
            [call.args for call in create.call_args_list],
            [("endpoint-01", "kerberos"), ("endpoint-01", "ntlm")],
        )
        diagnostics = scanner._session_diagnostics()
        self.assertEqual(diagnostics["session_creations"], 2)
        self.assertEqual(diagnostics["session_negotiations"], 1)
        self.assertEqual(diagnostics["session_reuse_count"], 1)
        self.assertEqual(diagnostics["connection_transport"], "ntlm")


if __name__ == "__main__":
    unittest.main()
