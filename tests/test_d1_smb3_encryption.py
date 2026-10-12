"""D1: SMB 3.1.1 with encryption, behind the SMB collector.

Gate line: "Encryption-required share scan completes with file, ACL, error and resume
parity." Here: the collector's own walker, over an encrypted SMB 3.1.1 session, against the
Windows SMB server on this host (a share read-only, through the service's identity - no
password), compared with the same folder read from disk; errors and resume planning are
the collector's own code, exercised through the adapter. A share that REQUIRES encryption
on the server (EncryptData) is the pilot's to configure: HELD - the session here is
encrypted because the client requires it, which is what reading such a share needs.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import socket
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from collectors import smb3_transport
from collectors.smb_scanner import (
    SMBConfig,
    SMBScanner,
    _is_access_denied,
    _is_connection_error,
)

SHARE = os.getenv("DSPM_D1_SHARE", "Public")


def _share_path(name: str) -> Path | None:
    # The name goes into a PowerShell command: a share name's characters only.
    if os.name != "nt" or not re.fullmatch(r"[A-Za-z0-9 _.$-]{1,80}", name):
        return None
    out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                          f"(Get-SmbShare -Name '{name}' -ErrorAction SilentlyContinue).Path"],
                         capture_output=True, text=True, timeout=60, check=False)
    text = out.stdout.strip()
    return Path(text) if text else None


def _live() -> tuple[str, Path] | None:
    """This host's SMB server, reachable with the service identity, and the share's folder."""
    path = _share_path(SHARE)
    if path is None or not path.is_dir():
        return None
    host = socket.gethostname()
    try:
        address = socket.gethostbyname(host)
        with mock.patch.dict(os.environ, {"DSPM_SMB_ALLOW_SERVICE_IDENTITY": "1"}):
            conn = smb3_transport.Smb3Connection("", "", "sentro", host, shares=[SHARE])
            ok = conn.connect(address, 445, timeout=10)
            conn.close()
        return (host, path) if ok else None
    except Exception:  # noqa: BLE001 - any failure to reach it means the live half does not run here
        return None


LIVE = _live()


class TheAdapterTest(unittest.TestCase):

    def test_an_encrypted_scan_goes_through_the_adapter_and_never_pysmb(self) -> None:
        made = []

        class Fake(smb3_transport.Smb3Connection):
            def connect(self, ip, port=445, timeout=30):
                made.append((self.shares, ip))
                raise smb3_transport.EncryptionUnavailable("fileserver does not offer SMB 3 encryption; it is not read in the clear.")

        scanner = SMBScanner(SMBConfig(server="fileserver.corp.test", username="svc", password="x", require_encryption=True,
                                       allowed_shares=("Finance",)))
        with (mock.patch("collectors.smb_scanner.resolve_and_pin", return_value="10.1.2.3"),
              mock.patch.object(smb3_transport, "Smb3Connection", Fake),
              mock.patch("smb.SMBConnection.SMBConnection") as pysmb,
              self.assertRaisesRegex(ConnectionError, "SMB 3 encryption required: .*not read in the clear")):
            scanner.scan()
        self.assertEqual(made, [(["Finance"], "10.1.2.3")], "one attempt, at the pinned address, with the named share")
        pysmb.assert_not_called()

    def test_the_service_identity_needs_its_setting(self) -> None:
        with (mock.patch.dict(os.environ, {"DSPM_SMB_ALLOW_SERVICE_IDENTITY": "0"}),
              self.assertRaisesRegex(PermissionError, "DSPM_SMB_ALLOW_SERVICE_IDENTITY")):
            smb3_transport.Smb3Connection("", "", "sentro", "fs").connect("10.1.2.3")

    def test_shares_are_named_not_listed(self) -> None:
        with self.assertRaisesRegex(PermissionError, "name their shares"):
            smb3_transport.Smb3Connection("u", "p", "sentro", "fs").listShares()
        self.assertEqual([share.name for share in smb3_transport.Smb3Connection("u", "p", "s", "fs", shares=["A", " B "]).listShares()],
                         ["A", "B"])

    def test_errors_read_as_the_collector_reads_pysmbs(self) -> None:
        denied = smb3_transport._translate(mock.Mock(status=0xC0000022), "Finance", "Payroll")
        missing = smb3_transport._translate(mock.Mock(status=0xC0000034), "Finance", "Gone")
        self.assertTrue(_is_access_denied(denied))
        self.assertTrue(str(denied).startswith("Access denied"), "said in words, as pysmb's refusal reads")
        self.assertFalse(_is_access_denied(missing))
        self.assertFalse(_is_connection_error(missing))

    def test_attributes_are_pysmbs(self) -> None:
        entry = smb3_transport.SharedFile("x", 1, 0.0, 0.0, 0.0, 0x10 | 0x2 | 0x4)
        self.assertEqual((entry.isDirectory, entry.isHidden, entry.isSystem, entry.isReadOnly), (True, True, True, False))

    def test_resume_planning_runs_through_the_adapter(self) -> None:
        # B2.3's share groups: A's root holds a folder named B, so A and B stay together.
        roots = {"A": ["B", "Reports"], "B": ["Payroll"], "C": ["Misc"]}

        class Named(smb3_transport.Smb3Connection):
            def connect(self, ip, port=445, timeout=30):
                return True

            def listPath(self, service_name, path, search=0, pattern="*", timeout=30):
                return [smb3_transport.SharedFile(name, 0, 0.0, 0.0, 0.0, 0x10) for name in roots[service_name]]

        scanner = SMBScanner(SMBConfig(server="fs.corp.test", username="svc", password="x", require_encryption=True,
                                       allowed_shares=("A", "B", "C")))
        with (mock.patch("collectors.smb_scanner.resolve_and_pin", return_value="10.1.2.3"),
              mock.patch.object(smb3_transport, "Smb3Connection", Named)):
            groups = scanner.plan_share_groups()
        self.assertEqual(groups, [["A", "B"], ["C"]])


class TheNegotiationTest(unittest.TestCase):
    """What the adapter does with each answer the server can give (smbprotocol mocked)."""

    def connect(self, *, supports_encryption=True, encrypt_data=True, auth_fails=False, session_error=None,
                negotiate_error=None):
        from smbprotocol.exceptions import SMBAuthenticationError

        connection = mock.Mock(supports_encryption=supports_encryption, dialect=0x0311)
        session = mock.Mock(encrypt_data=encrypt_data)
        if auth_fails:
            session.connect.side_effect = SMBAuthenticationError("refused")
        if session_error is not None:
            session.connect.side_effect = session_error
        if negotiate_error is not None:
            connection.connect.side_effect = negotiate_error
        with (mock.patch("smbprotocol.connection.Connection", return_value=connection) as made_connection,
              mock.patch("smbprotocol.session.Session", return_value=session) as made_session):
            adapter = smb3_transport.Smb3Connection("svc", "pw", "sentro", "fs", domain="CORP", shares=["Finance"])
            try:
                result = adapter.connect("10.1.2.3", 445, timeout=5)
            finally:
                self.made = (made_connection, made_session, connection)
        return result, adapter

    def test_signing_encryption_and_smb_3_1_1_are_asked_for(self) -> None:
        from smbprotocol.connection import Dialects

        ok, adapter = self.connect()
        made_connection, made_session, connection = self.made
        self.assertTrue(ok and adapter.encrypted)
        self.assertTrue(made_connection.call_args.kwargs["require_signing"])
        connection.connect.assert_called_once_with(Dialects.SMB_3_1_1, timeout=5)
        self.assertTrue(made_session.call_args.kwargs["require_encryption"])
        self.assertEqual(made_session.call_args.kwargs["username"], "CORP\\svc")

    def test_a_server_that_cannot_encrypt_is_refused_before_signing_in(self) -> None:
        with self.assertRaisesRegex(smb3_transport.EncryptionUnavailable, "not read in the clear"):
            self.connect(supports_encryption=False)
        made_connection, made_session, connection = self.made
        made_session.assert_not_called()
        connection.disconnect.assert_called_once_with(True)

    def test_a_session_that_is_not_encrypted_reads_nothing(self) -> None:
        with self.assertRaisesRegex(smb3_transport.EncryptionUnavailable, "not encrypted"):
            self.connect(encrypt_data=False)
        self.made[2].disconnect.assert_called_once_with(True)

    def test_refused_credentials_answer_false_as_pysmb_does(self) -> None:
        ok, adapter = self.connect(auth_fails=True)
        self.assertFalse(ok)
        self.assertFalse(adapter.encrypted)
        self.made[2].disconnect.assert_called_once_with(True)

    def test_a_wrong_password_is_a_refused_login_and_the_connection_is_closed(self) -> None:
        # M4 exit review: a wrong password is STATUS_LOGON_FAILURE, which smbprotocol raises
        # as LogonFailure - not SMBAuthenticationError. It escaped, leaked the connection
        # (socket and worker thread) and the operator was told the server was unreachable.
        from smbprotocol.exceptions import LogonFailure, PasswordExpired, SMBResponseException, WrongPassword
        from smbprotocol.header import SMB2HeaderResponse

        locked = SMB2HeaderResponse()
        locked["status"] = 0xC0000234  # STATUS_ACCOUNT_LOCKED_OUT, which smbprotocol has no class for
        for refusal in (LogonFailure(), WrongPassword(), PasswordExpired(), SMBResponseException(locked)):
            with self.subTest(refusal=type(refusal).__name__, status=hex(refusal.status)):
                ok, adapter = self.connect(session_error=refusal)
                self.assertFalse(ok, "a refused login answers False, as pysmb does")
                self.assertFalse(adapter.encrypted)
                self.made[2].disconnect.assert_called_once_with(True)

    def test_any_other_failure_still_closes_the_connection(self) -> None:
        for where, error in (("session", RuntimeError("worker died")), ("negotiate", TimeoutError("no answer"))):
            with self.subTest(where=where), self.assertRaises(type(error)):
                if where == "session":
                    self.connect(session_error=error)
                else:
                    self.connect(negotiate_error=error)
            self.made[2].disconnect.assert_called_once_with(True)

    def test_the_scan_says_the_login_was_rejected_and_leaks_nothing(self) -> None:
        from smbprotocol.exceptions import LogonFailure

        made = []

        def new_connection(*_args, **_kwargs):
            made.append(mock.Mock(supports_encryption=True, dialect=0x0311))
            return made[-1]

        session = mock.Mock(encrypt_data=True)
        session.connect.side_effect = LogonFailure()
        scanner = SMBScanner(SMBConfig(server="fs.corp.test", username="svc", password="wrong", domain="CORP",
                                       require_encryption=True, allowed_shares=("Finance",)))
        with (mock.patch("collectors.smb_scanner.resolve_and_pin", return_value="10.1.2.3"),
              mock.patch("smbprotocol.connection.Connection", side_effect=new_connection),
              mock.patch("smbprotocol.session.Session", return_value=session),
              self.assertRaisesRegex(ConnectionError, "SMB authentication was rejected")):
            scanner.scan()
        self.assertTrue(made, "a credential was tried")
        for connection in made:
            connection.disconnect.assert_called_once_with(True)


class TheScanWiringTest(unittest.TestCase):
    """The scan's collector, its partition planner and its connection test all get it."""

    def config(self):
        from discovery.discovery_engine import ScanConfig

        return ScanConfig(server="fs.corp.test", username="svc", password="pw", smb_shares=("Finance",),
                          smb_require_encryption=True)

    def capture(self):
        made = []

        class Scanner:
            def __init__(self, config):
                made.append(config)
                self.last_scan_diagnostics = {}

            def scan(self):
                return []

            def plan_share_groups(self, stop_check=None):
                return None

            def plan_share_layout(self, stop_check=None):
                # W3.1: the planner asks for the shares and their root folders.
                return {"shares": [], "folders": {}}

            def test_connection(self):
                return {"ok": True}

        return made, Scanner

    def test_collection_partition_planning_and_connection_test(self) -> None:
        from discovery import discovery_engine, partition

        made, Scanner = self.capture()
        with mock.patch.object(discovery_engine, "SMBScanner", Scanner):
            engine = discovery_engine.DSPMDiscoveryEngine(self.config())
            engine._collect_records()
            engine.test_connection()
        with mock.patch("collectors.smb_scanner.SMBScanner", Scanner):
            partition.plan_share_partitions(self.config())
        self.assertEqual([(config.require_encryption, config.allowed_shares) for config in made],
                         [(True, ("Finance",))] * 3)


class TheRequestTest(unittest.TestCase):
    """The API asks for it, the installation can require it, and a reveal reads the same way."""

    def test_an_encrypted_scan_must_name_its_shares_and_is_told_so(self) -> None:
        from fastapi.testclient import TestClient

        from backend import security
        from backend.app import ScanRequest, app

        headers = {"Authorization": f"Bearer {security.create_token('admin', 'admin', 'default')}"}
        # A guard: were the refusal missing, nothing may actually connect.
        with mock.patch("discovery.discovery_engine.DSPMDiscoveryEngine.test_connection",
                        side_effect=AssertionError("connected")) as reached:
            response = TestClient(app).post("/api/test-connection", headers=headers,
                                            json={"server": "fs.corp.test", "smb_encryption": True})
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("Name the shares to scan", response.json()["detail"])
        reached.assert_not_called()
        request = ScanRequest(server="fs.corp.test", smb_encryption=True,
                              smb_shares=[" Fin\\ance/ ", "\x00HR", "", "  "])
        self.assertEqual(request.smb_shares, ["Finance", "HR"], "control characters and separators removed")
        self.assertEqual(ScanRequest(server="", smb_encryption=True).smb_shares, [], "a local scan names none")

    def test_the_scan_config_carries_it_and_the_installation_can_require_it(self) -> None:
        from backend import app as app_module

        with mock.patch.dict(os.environ, {"DSPM_SMB_REQUIRE_ENCRYPTION": "0"}):
            asked = app_module._to_config(app_module.ScanRequest(server="fs.corp.test", smb_encryption=True,
                                                                 smb_shares=["Finance"]), "t-d1")
            plain = app_module._to_config(app_module.ScanRequest(server="fs.corp.test"), "t-d1")
        with mock.patch.dict(os.environ, {"DSPM_SMB_REQUIRE_ENCRYPTION": "1"}):
            required = app_module._to_config(app_module.ScanRequest(server="fs.corp.test"), "t-d1")
        self.assertEqual((asked.smb_require_encryption, asked.smb_shares), (True, ("Finance",)))
        self.assertEqual((plain.smb_require_encryption, plain.smb_shares), (False, None))
        self.assertTrue(required.smb_require_encryption, "DSPM_SMB_REQUIRE_ENCRYPTION holds for every SMB scan")

    def test_named_shares_ignore_case(self) -> None:
        scanner = SMBScanner(SMBConfig(server="fs", allowed_shares=("finance",)))
        self.assertTrue(scanner._share_selected("Finance"))
        self.assertFalse(scanner._share_selected("HR"))
        self.assertTrue(SMBScanner(SMBConfig(server="fs"))._share_selected("anything"), "no names: every share")

    def test_the_scan_records_smb3_and_a_reveal_reads_it_encrypted(self) -> None:
        from backend import app as app_module
        from backend import evidence_reveal

        recorded = []
        with mock.patch.object(app_module.store_module, "record_scan_source",
                               side_effect=lambda *args: recorded.append(args)):
            app_module._record_scan_source("t-d1", "scan-d1", app_module.ScanRequest(
                server="fs.corp.test", smb_encryption=True, smb_shares=["Finance"], credential_ref="ref-d1"))
            app_module._record_scan_source("t-d1", "scan-d1b", app_module.ScanRequest(server="fs.corp.test"))
        self.assertEqual([row[2] for row in recorded], ["smb3", "smb"])

        made = []

        class Scanner:
            def __init__(self, config):
                made.append(config)
                self.connection = None

            def connect(self):
                return False

        asset = {"share": "Finance", "path": "Payroll/2026.xlsx", "reuse_key": "smb://fs.corp.test/Finance/Payroll/2026.xlsx"}
        for kind in ("smb3", "smb"):
            source = {"source_kind": kind, "server": "fs.corp.test", "credential_ref": "ref-d1", "credential_kind": "saved"}
            with (mock.patch("collectors.smb_scanner.SMBScanner", Scanner),
                  mock.patch("backend.vault.CredentialVault") as vault):
                vault.return_value.resolve.return_value = {"username": "svc", "password": "pw", "domain": "CORP"}
                with self.assertRaises(evidence_reveal.RevealRefused):
                    evidence_reveal._read_smb("t-d1", asset, source)
        self.assertEqual([(config.require_encryption, config.allowed_shares) for config in made],
                         [(True, ("Finance",)), (False, None)], "encrypted again, never in the clear")

    def test_an_installation_that_requires_encryption_re_reads_every_smb_finding_encrypted(self) -> None:
        # M4 exit review: a finding an older "smb" scan recorded was re-read over pysmb, in
        # the clear, on an installation whose DSPM_SMB_REQUIRE_ENCRYPTION forbids exactly that.
        from backend import app as app_module
        from backend import evidence_reveal

        made = []

        class Scanner:
            def __init__(self, config):
                made.append(config)
                self.connection = None

            def connect(self):
                return False

        asset = {"share": "Finance", "path": "Payroll/2026.xlsx", "reuse_key": "smb://fs.corp.test/Finance/Payroll/2026.xlsx"}
        source = {"source_kind": "smb", "server": "fs.corp.test", "credential_ref": "ref-d1", "credential_kind": "saved"}
        with (mock.patch.dict(os.environ, {"DSPM_SMB_REQUIRE_ENCRYPTION": "1"}),
              mock.patch("collectors.smb_scanner.SMBScanner", Scanner),
              mock.patch("backend.vault.CredentialVault") as vault):
            vault.return_value.resolve.return_value = {"username": "svc", "password": "pw", "domain": "CORP"}
            self.assertTrue(app_module._smb_encryption_required(None), "the scan side reads the same setting")
            with self.assertRaises(evidence_reveal.RevealRefused):
                evidence_reveal._read_smb("t-d1", asset, source)
        self.assertEqual([(config.require_encryption, config.allowed_shares) for config in made],
                         [(True, ("Finance",))], "the installation's requirement holds for the re-read")

    def test_an_encrypted_scan_says_its_acls_came_through_windows(self) -> None:
        # The file bytes come over the encrypted session; owners and ACLs through Windows'
        # own SMB client. The scan's diagnostics say so (README: SMB 3 encryption).
        class Empty(smb3_transport.Smb3Connection):
            def connect(self, ip, port=445, timeout=30):
                return True

            def listPath(self, service_name, path, search=0, pattern="*", timeout=30):
                return []

        scanner = SMBScanner(SMBConfig(server="fs.corp.test", username="svc", password="x", require_encryption=True,
                                       allowed_shares=("Finance",)))
        with (mock.patch("collectors.smb_scanner.resolve_and_pin", return_value="10.1.2.3"),
              mock.patch.object(smb3_transport, "Smb3Connection", Empty)):
            scanner.scan()
        diagnostics = scanner.last_scan_diagnostics
        self.assertEqual(diagnostics.get("shares_scanned"), ["Finance"])
        self.assertEqual(diagnostics.get("acl_transport"), "windows-smb-client")
        self.assertIn("not the encrypted SMB 3 session", diagnostics.get("acl_transport_note", ""))


@unittest.skipUnless(LIVE, "needs this host's SMB server and a readable share (Windows)")
class TheEncryptedScanTest(unittest.TestCase):
    """The collector over encrypted SMB 3.1.1, against the same folder read from disk."""

    def scan(self) -> tuple[list[dict], SMBScanner]:
        host, _ = LIVE
        scanner = SMBScanner(SMBConfig(server=host, username="", require_encryption=True, allowed_shares=(SHARE,),
                                       max_depth=6, include_hidden=True, include_system=True))
        with (mock.patch.dict(os.environ, {"DSPM_SMB_ALLOW_SERVICE_IDENTITY": "1"}),
              mock.patch("collectors.smb_scanner.resolve_and_pin", return_value=socket.gethostbyname(host))):
            records = scanner.scan()
        return records, scanner

    def test_the_session_is_smb_3_1_1_and_encrypted(self) -> None:
        host, _ = LIVE
        with mock.patch.dict(os.environ, {"DSPM_SMB_ALLOW_SERVICE_IDENTITY": "1"}):
            conn = smb3_transport.Smb3Connection("", "", "sentro", host, shares=[SHARE])
            self.assertTrue(conn.connect(socket.gethostbyname(host), 445, timeout=15))
            try:
                self.assertEqual((conn.dialect, conn.encrypted), (0x0311, True))
            finally:
                conn.close()

    def test_files_sizes_content_and_acls_match_the_folder_on_disk(self) -> None:
        from collectors import win_security

        _, folder = LIVE
        records, _scanner = self.scan()
        smb_files = {}
        for record in records:
            if record.get("is_dir"):
                continue
            relative = str(record["path"]).replace("\\", "/").split(f"/{SHARE}/", 1)[-1].lstrip("/")
            smb_files[relative.lower()] = record
        disk_files = {}
        for path in folder.rglob("*"):
            if path.is_file() and len(path.relative_to(folder).parts) <= 6:
                disk_files[path.relative_to(folder).as_posix().lower()] = path
        self.assertTrue(disk_files, "the share has files to compare")
        self.assertEqual(sorted(smb_files), sorted(disk_files), "the same files")
        for relative, path in disk_files.items():
            with self.subTest(file=relative):
                record = smb_files[relative]
                self.assertEqual(int(record["size"]), path.stat().st_size)
                if record.get("sha256"):
                    self.assertEqual(record["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                local = win_security.security_for_path(str(path)) or {}
                remote = record.get("acl") or {}
                self.assertEqual(sorted(entry.get("sid") for entry in local.get("entries") or []),
                                 sorted(entry.get("sid") for entry in remote.get("entries") or []), "the same ACL")

    def test_errors_bounded_reads_and_attributes(self) -> None:
        host, folder = LIVE
        # A file somewhere in the share (its root may hold only folders), largest first so
        # the bounded read has more than 10 bytes to refuse.
        files = sorted((path for path in folder.rglob("*") if path.is_file()), key=lambda path: -path.stat().st_size)
        self.assertTrue(files, "the share has a file to read")
        local = files[0]
        remote = "/" + local.relative_to(folder).as_posix()
        with mock.patch.dict(os.environ, {"DSPM_SMB_ALLOW_SERVICE_IDENTITY": "1"}):
            conn = smb3_transport.Smb3Connection("", "", "sentro", host, shares=[SHARE])
            self.assertTrue(conn.connect(socket.gethostbyname(host), 445, timeout=15))
            try:
                with self.assertRaises(smb3_transport.OperationFailure) as refused:
                    conn.listPath(SHARE, "no-such-folder-d1")
                self.assertFalse(_is_connection_error(refused.exception), "a missing folder is not a dropped connection")
                buffer = io.BytesIO()
                conn.retrieveFileFromOffset(SHARE, remote, buffer, 0, 10)
                self.assertEqual(buffer.getvalue(), local.read_bytes()[:10], "a bounded read reads that much, exactly")
                # The evidence re-read asks the size as it is now.
                attributes = conn.getAttributes(SHARE, remote)
                self.assertEqual((attributes.filename, attributes.file_size, attributes.isDirectory),
                                 (local.name, local.stat().st_size, False))
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
