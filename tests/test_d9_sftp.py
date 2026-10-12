"""D9: Linux/macOS hosts over SSH/SFTP, with an ordinary account.

Gate line: "Linux home-directory fixture scans and resumes without elevated credentials."
The fixture is an SFTP server in this process (paramiko's server side) serving a home
directory tree with Unix modes: the account's own files, a world-readable key, a file only
root may read, a symbolic link out of the tree. A pilot's Linux host is the live half: HELD.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import paramiko
from fastapi.testclient import TestClient

from backend import security, store
from backend.app import app
from collectors import sftp_scanner

PASSWORD = "Kestrel-lantern-4471"
ALICE_PASSWORD = "alice-sftp-test-only-5"
CARD = "4111 1111 1111 1111"


class _Server(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        ok = (username, password) == ("alice", ALICE_PASSWORD)
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class _Sftp(paramiko.SFTPServerInterface):
    """The tree under `root`, with the modes, owners and refusals the test sets."""

    def __init__(self, server, *args, fixture=None, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.fixture = fixture

    def _attributes(self, path: str, name: str) -> paramiko.SFTPAttributes:
        real = self.fixture.real(path)
        attributes = paramiko.SFTPAttributes.from_stat(os.stat(real), filename=name)
        mode, uid = self.fixture.modes.get(path, (0o40755 if os.path.isdir(real) else 0o100640, 1000))
        attributes.st_mode, attributes.st_uid, attributes.st_gid = mode, uid, 1000
        return attributes

    def list_folder(self, path):
        real = self.fixture.real(path)
        if path in self.fixture.hang:
            self.fixture.release.wait(HANG_SECONDS)   # a hung NFS mount: no answer
        if path in self.fixture.denied:
            return paramiko.SFTP_PERMISSION_DENIED
        return [self._attributes(f"{path.rstrip('/')}/{name}", name) for name in os.listdir(real)]

    def stat(self, path):
        return self._attributes(path, os.path.basename(path))

    lstat = stat

    def open(self, path, flags, attr):
        if path in self.fixture.denied or flags & (os.O_WRONLY | os.O_RDWR):
            return paramiko.SFTP_PERMISSION_DENIED
        self.fixture.opened.append(path)
        handle = _HangingHandle(flags, self.fixture) if path in self.fixture.hang else paramiko.SFTPHandle(flags)
        handle.readfile = open(self.fixture.real(path), "rb")  # noqa: SIM115 - the handle closes it
        handle.filename = self.fixture.real(path)
        return handle


HANG_SECONDS = 15


class _HangingHandle(paramiko.SFTPHandle):
    """A file whose read is never answered (until the fixture stops)."""

    def __init__(self, flags, fixture):
        super().__init__(flags)
        self.fixture = fixture

    def read(self, offset, length):
        self.fixture.release.wait(HANG_SECONDS)
        return super().read(offset, length)


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.modes: dict[str, tuple[int, int]] = {}
        self.denied: set[str] = set()
        self.hang: set[str] = set()          # paths the server stops answering for
        self.release = threading.Event()
        self.opened: list[str] = []
        self.sessions: list[paramiko.Transport] = []
        self.host_key = paramiko.Ed25519Key.generate() if hasattr(paramiko.Ed25519Key, "generate") else None
        if self.host_key is None:
            self.host_key = paramiko.RSAKey.generate(2048)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(20)
        self.port = self.sock.getsockname()[1]
        self.running = True
        threading.Thread(target=self._serve, daemon=True).start()

    def real(self, path: str) -> str:
        return str(self.root / path.lstrip("/"))

    def _serve(self) -> None:
        while self.running:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            transport = paramiko.Transport(client)
            transport.add_server_key(self.host_key)
            transport.set_subsystem_handler("sftp", paramiko.SFTPServer, _Sftp, fixture=self)
            self.sessions.append(transport)  # held until stop(), never left to the collector
            try:
                # With an event, start_server returns at once and negotiates on the session's own
                # thread; without one it blocks this accept loop until the last client is done.
                transport.start_server(event=threading.Event(), server=_Server())
            except paramiko.SSHException:
                continue

    def stop(self) -> None:
        self.running = False
        self.release.set()
        self.sock.close()
        for transport in self.sessions:
            transport.close()


class D9Case(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        home = self.tmp / "tree" / "home" / "alice"
        (home / "docs").mkdir(parents=True)
        (home / ".ssh").mkdir()
        (home / "docs" / "payments.txt").write_text(f"Customer card {CARD} exp 12/29\n", encoding="utf-8")
        (home / "docs" / "readme.txt").write_text("Nothing here.\n", encoding="utf-8")
        (home / ".ssh" / "id_backup").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n",
                                                  encoding="utf-8")
        (home / "shadow-copy").write_text("root:$6$salt$hash:19000:0:99999:7:::\n", encoding="utf-8")
        (home / "escape").write_text("not followed\n", encoding="utf-8")
        self.fixture = Fixture(self.tmp / "tree")
        self.addCleanup(self.fixture.stop)
        self.fixture.modes["/home/alice/.ssh/id_backup"] = (0o100644, 1000)      # world-readable: the finding
        self.fixture.modes["/home/alice/shadow-copy"] = (0o100600, 0)             # root's, and alice may not read it
        self.fixture.denied.add("/home/alice/shadow-copy")
        self.fixture.modes["/home/alice/escape"] = (0o120777, 1000)               # a symbolic link
        self.source = sftp_scanner.SftpSource(host="linux01.corp.test", username="alice", password=ALICE_PASSWORD,
                                              host_key_fingerprint=sftp_scanner.fingerprint(self.fixture.host_key),
                                              port=self.fixture.port, paths=["/home/alice"], address="127.0.0.1")
        # The fixture is not on port 22, so its locations name the port.
        self.at = f"sftp://linux01.corp.test:{self.fixture.port}"


class TheCollectorTest(D9Case):

    def test_the_home_directory_is_read_as_an_ordinary_account(self) -> None:
        records, facts = sftp_scanner.scan(self.source)
        by_path = {record["path"]: record for record in records}
        self.assertEqual(sorted(by_path), [f"{self.at}/home/alice/.ssh/id_backup",
                                           f"{self.at}/home/alice/docs/payments.txt",
                                           f"{self.at}/home/alice/docs/readme.txt",
                                           f"{self.at}/home/alice/shadow-copy"])
        self.assertIn(CARD, by_path[f"{self.at}/home/alice/docs/payments.txt"]["content"])
        refused = by_path[f"{self.at}/home/alice/shadow-copy"]
        self.assertEqual(refused["content_status"], "unreadable", "reported, not escalated around")
        self.assertEqual(facts["unreadable"], [{"path": "/home/alice/shadow-copy", "error": "PermissionError"}])
        self.assertEqual(facts["symlinks_skipped"], 1)
        self.assertNotIn("/home/alice/escape", self.fixture.opened)

    def test_a_world_readable_file_is_readable_by_everyone(self) -> None:
        records, _ = sftp_scanner.scan(self.source)
        key = next(record for record in records if record["path"].endswith("id_backup"))
        everyone = [entry for entry in key["acl"]["entries"] if entry["sid"] == sftp_scanner.EVERYONE_SID]
        self.assertEqual(everyone[0]["rights"], ["read"])
        private = next(record for record in records if record["path"].endswith("payments.txt"))
        self.assertFalse([entry for entry in private["acl"]["entries"] if entry["sid"] == sftp_scanner.EVERYONE_SID])

    def test_an_unknown_host_key_is_refused(self) -> None:
        self.source.host_key_fingerprint = "SHA256:" + "A" * 43
        with self.assertRaisesRegex(sftp_scanner.SftpScanError, "not the one this source names"):
            sftp_scanner.scan(self.source)
        self.source.host_key_fingerprint = ""
        with self.assertRaisesRegex(sftp_scanner.SftpScanError, "not the one this source names"):
            sftp_scanner.scan(self.source)

    def test_a_session_dropped_during_the_handshake_is_said_plainly(self) -> None:
        dropped = paramiko.SSHException("No existing session")
        with (mock.patch.object(paramiko.Transport, "get_remote_server_key", side_effect=dropped),
              self.assertRaisesRegex(sftp_scanner.SftpScanError, "closed the session")):
            sftp_scanner.scan(self.source)

    def test_a_wrong_password_is_refused(self) -> None:
        self.source.password = "not-the-password"
        with self.assertRaisesRegex(sftp_scanner.SftpScanError, "refused the account"):
            sftp_scanner.scan(self.source)

    def test_a_cancelled_scan_says_so(self) -> None:
        _, facts = sftp_scanner.scan(self.source, cancel_check=lambda: True)
        self.assertEqual((facts["scan_aborted_reason"], facts["files"]), ("cancelled", 0))

    def test_the_limits_hold(self) -> None:
        self.source.max_files = 2
        records, facts = sftp_scanner.scan(self.source)
        self.assertEqual((len(records), facts["record_limit_reached"]), (2, True))
        self.source.max_files, self.source.max_read_bytes = 100, 10
        records, _ = sftp_scanner.scan(self.source)
        payments = next(record for record in records if record["path"].endswith("payments.txt"))
        self.assertEqual((payments["scan_completeness"], payments["bytes_scanned"]), ("PARTIAL", 10))

    def test_a_location_names_the_port_unless_it_is_22(self) -> None:
        self.assertEqual(sftp_scanner.authority(sftp_scanner.SftpSource(host="h1", username="u", host_key_fingerprint="",
                                                                         port=22)), "h1")
        self.assertEqual(sftp_scanner.authority(self.source), f"linux01.corp.test:{self.fixture.port}")

    def test_cancel_and_the_deadline_are_asked_per_file(self) -> None:
        # One folder can hold the rest of the scan: the engine's cancel (or its deadline)
        # is asked before each file, not only on entering a folder.
        records, facts = sftp_scanner.scan(
            self.source, cancel_check=lambda: "/home/alice/docs/payments.txt" in self.fixture.opened)
        self.assertEqual(facts["scan_aborted_reason"], "cancelled")
        self.assertNotIn("/home/alice/docs/readme.txt", self.fixture.opened)

    def test_a_folder_the_host_stops_answering_for_ends_the_scan_within_its_timeout(self) -> None:
        self.fixture.hang.add("/home/alice/docs")
        self.source.timeout = 1.0
        started = time.monotonic()
        records, facts = sftp_scanner.scan(self.source)
        self.assertLess(time.monotonic() - started, HANG_SECONDS / 2, "not held until the server answers")
        self.assertEqual(facts["scan_aborted_reason"], "sftp_session_lost")
        self.assertEqual(facts["unreadable_dirs"], [{"path": "/home/alice/docs", "error": "TimeoutError"}])
        self.assertNotIn(f"{self.at}/home/alice/shadow-copy", {record["path"] for record in records},
                         "nothing after it is waited for")

    def test_a_file_the_host_stops_answering_for_ends_the_scan_within_its_timeout(self) -> None:
        self.fixture.hang.add("/home/alice/docs/payments.txt")
        self.source.timeout = 1.0
        started = time.monotonic()
        records, facts = sftp_scanner.scan(self.source)
        self.assertLess(time.monotonic() - started, HANG_SECONDS / 2)
        self.assertEqual(facts["scan_aborted_reason"], "sftp_session_lost")
        payments = next(record for record in records if record["path"].endswith("payments.txt"))
        self.assertEqual(payments["content_status"], "unreadable")
        self.assertNotIn("/home/alice/docs/readme.txt", self.fixture.opened)


class TheScanTest(D9Case):
    """Through the API and the engine: findings, who can read them, and resuming."""

    def setUp(self) -> None:
        super().setUp()
        original = store.DB_PATH
        store.DB_PATH = self.tmp / "d9.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        store.create_tenant("t-d9", "t-d9")
        store.create_user("d9-admin", security.hash_password(PASSWORD), "admin", "t-d9")
        for patcher in (mock.patch("backend.app._validate_scan_target"),
                        mock.patch("collectors.net_guard.resolve_and_pin", return_value="127.0.0.1"),
                        mock.patch.dict(os.environ, {"DSPM_SCAN_CACHE_DIR": str(self.tmp / "cache")})):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = TestClient(app)
        self.headers = {"Authorization": f"Bearer {security.create_token('d9-admin', 'admin', 't-d9')}"}
        credential = self.client.post("/api/credentials", headers=self.headers,
                                      json={"username": "alice", "password": ALICE_PASSWORD, "domain": ""})
        self.assertEqual(credential.status_code, 200, credential.text)
        self.ref = credential.json()["credential_ref"]

    def scan(self, **extra) -> dict:
        response = self.client.post("/api/sftp/scan", headers=self.headers, json={
            "host": "linux01.corp.test", "port": self.fixture.port, "credential_ref": self.ref,
            "host_key_fingerprint": self.source.host_key_fingerprint, "paths": ["/home/alice"],
            "compact_result": False, "scan_label": "linux01 homes", **extra})
        self.assertEqual(response.status_code, 200, response.text[:400])
        return response.json()

    def test_findings_are_masked_and_the_world_readable_key_is_broad(self) -> None:
        report = self.scan()
        text = json.dumps(report)
        self.assertNotIn(CARD.replace(" ", ""), text.replace(" ", ""))
        self.assertNotIn(ALICE_PASSWORD, text)
        payments = next(entry for entry in report["files"] if entry["path"].endswith("payments.txt"))
        self.assertTrue(payments["findings"])
        broad = self.client.get("/api/access/files?kind=broad", headers=self.headers).json()
        self.assertIn(f"{self.at}/home/alice/.ssh/id_backup", json.dumps(broad))

    def test_a_scan_that_stopped_part_way_resumes_where_it_stopped(self) -> None:
        with mock.patch.object(sftp_scanner.SftpSource, "__init__", _capped(sftp_scanner.SftpSource.__init__, 2)):
            self.scan()
        self.fixture.opened.clear()
        report = self.scan()
        facts = report["scan_diagnostics"]
        self.assertEqual(facts["reused"], 2, "what the stopped run read is not read again")
        self.assertEqual(facts["incremental"]["sidecar_hits"], 2, "from the local cache")
        self.assertEqual(len(self.fixture.opened), facts["read"])
        self.assertEqual(len(report["files"]), 4)
        self.fixture.opened.clear()
        (self.tmp / "tree" / "home" / "alice" / "docs" / "readme.txt").write_text("Changed, and longer now.\n", encoding="utf-8")
        self.scan()
        self.assertEqual(self.fixture.opened, ["/home/alice/docs/readme.txt"], "only the changed file is read")

    def test_a_folder_it_may_not_list_is_not_taken_for_empty(self) -> None:
        self.scan()
        self.fixture.denied.add("/home/alice/docs")
        report = self.scan()
        facts = report["scan_diagnostics"]
        self.assertEqual(facts["unreadable_dirs"], [{"path": "/home/alice/docs", "error": "PermissionError"}])
        self.assertFalse(facts["incremental"]["complete"], "what is under it was not seen")
        self.assertIn(f"{self.at}/home/alice/docs/payments.txt", self.inventory_paths(),
                      "a folder that could not be listed is not pruned as if it were gone")

    def inventory_paths(self) -> set[str]:
        return {item["path"] for item in self.client.get("/api/inventory?limit=200", headers=self.headers).json()["items"]}

    def test_a_file_it_could_not_read_is_read_again_once_it_may(self) -> None:
        # Granting read changes neither the size nor the modified time: the refusal is not
        # replayed from the cache for as long as the file stays unchanged.
        self.scan()
        self.fixture.denied.discard("/home/alice/shadow-copy")
        self.fixture.opened.clear()
        report = self.scan()
        self.assertIn("/home/alice/shadow-copy", self.fixture.opened)
        shadow = next(entry for entry in report["files"] if entry["path"].endswith("shadow-copy"))
        self.assertNotEqual(shadow["content_status"], "unreadable")

    def test_a_scan_of_other_paths_does_not_prune_these(self) -> None:
        self.scan(scan_label="", paths=["/home/alice/docs"])
        self.scan(scan_label="", paths=["/home/alice/.ssh"])
        paths = self.inventory_paths()
        self.assertIn(f"{self.at}/home/alice/docs/payments.txt", paths)
        self.assertIn(f"{self.at}/home/alice/.ssh/id_backup", paths)

    def test_two_ssh_servers_on_one_host_are_two_sources(self) -> None:
        other_root = self.tmp / "other"
        (other_root / "home" / "alice").mkdir(parents=True)
        (other_root / "home" / "alice" / "payroll.txt").write_text(f"Card {CARD}\n", encoding="utf-8")
        other = Fixture(other_root)
        self.addCleanup(other.stop)
        self.scan(scan_label="")
        response = self.client.post("/api/sftp/scan", headers=self.headers, json={
            "host": "linux01.corp.test", "port": other.port, "credential_ref": self.ref,
            "host_key_fingerprint": sftp_scanner.fingerprint(other.host_key), "paths": ["/home/alice"]})
        self.assertEqual(response.status_code, 200, response.text[:400])
        paths = self.inventory_paths()
        self.assertIn(f"sftp://linux01.corp.test:{other.port}/home/alice/payroll.txt", paths)
        self.assertIn(f"{self.at}/home/alice/docs/payments.txt", paths, "the other port's scan did not prune these")

    def test_reuse_survives_a_lost_scan_cache(self) -> None:
        # The durable baseline in the database answers when the local cache is gone.
        self.scan()
        self.fixture.opened.clear()
        shutil.rmtree(self.tmp / "cache", ignore_errors=True)
        report = self.scan()
        self.assertEqual(self.fixture.opened, [], "nothing unchanged is read again")
        self.assertEqual(report["scan_diagnostics"]["reused"], 3)

    def test_the_host_must_be_in_scope_and_a_required_licence_held(self) -> None:
        from fastapi import HTTPException

        body = {"host": "linux01.corp.test", "port": self.fixture.port, "credential_ref": self.ref,
                "host_key_fingerprint": self.source.host_key_fingerprint}
        with mock.patch("backend.app._validate_scan_target", side_effect=HTTPException(status_code=403, detail="scope")):
            self.assertEqual(self.client.post("/api/sftp/scan", headers=self.headers, json=body).status_code, 403)
        with mock.patch.dict(os.environ, {"DSPM_LICENCE_REQUIRED": "1"}):
            self.assertEqual(self.client.post("/api/sftp/scan", headers=self.headers, json=body).status_code, 402)
        self.assertEqual(self.fixture.opened, [], "nothing was read")


def _capped(original, limit):
    def init(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.max_files = limit
    return init


if __name__ == "__main__":
    unittest.main()
