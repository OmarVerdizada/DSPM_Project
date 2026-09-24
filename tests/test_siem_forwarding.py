"""M2/C4: audit events reach the SIEM, and an outage costs a delay, not events.

The gate's words are "pilot SIEM receives event and retry works after outage". The pilot's
SIEM is the customer's; this is the same exchange against a real syslog receiver on a
local port - one that goes away in the middle and comes back - so the code path is proven
here and the pilot only has to confirm its own receiver.
"""

from __future__ import annotations

import json
import os
import socket
import socketserver
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from backend import siem, store


class _Receiver:
    """A syslog receiver: newline-framed over TCP, a datagram per event over UDP."""

    def __init__(self, scheme: str = "tcp", port: int = 0) -> None:
        self.lines: list[str] = []
        lines = self.lines

        class TcpHandler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                for raw in self.rfile:
                    lines.append(raw.decode("utf-8").rstrip("\n"))

        class UdpHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                lines.append(self.request[0].decode("utf-8"))

        socketserver.TCPServer.allow_reuse_address = True
        server_class = socketserver.ThreadingTCPServer if scheme == "tcp" else socketserver.ThreadingUDPServer
        self.server = server_class(("127.0.0.1", port), TcpHandler if scheme == "tcp" else UdpHandler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def wait_for(self, count: int, timeout: float = 5.0) -> list[str]:
        deadline = time.time() + timeout
        while len(self.lines) < count and time.time() < deadline:
            time.sleep(0.02)
        return list(self.lines)

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class _Case(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "siem.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        store.create_tenant("tenant-siem", "Siem")

    def _forward_to(self, url: str) -> None:
        patcher = mock.patch.dict(os.environ, {"DSPM_SIEM_URL": url, "DSPM_SIEM_FORMAT": "cef"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _db_hashes(self) -> dict[int, str]:
        with store._connect() as conn:
            return {int(r["seq"]): r["row_hash"] for r in conn.execute(
                "SELECT seq, row_hash FROM audit_events WHERE tenant_id = 'tenant-siem'")}


class TheSiemReceivesTest(_Case):

    def test_every_event_arrives_with_its_place_in_the_chain(self) -> None:
        receiver = _Receiver()
        self.addCleanup(receiver.stop)
        self._forward_to(f"tcp://127.0.0.1:{receiver.port}")
        for index in range(3):
            store.audit("tenant-siem", "alice", "user.role_updated", {"username": f"u{index}", "client_ip": "203.0.113.9"})
        self.assertEqual(store.audit_outbox_status()["pending"], 3, "queued with the audit rows")
        self.assertEqual(siem.drain()["sent"], 3)
        lines = receiver.wait_for(3)
        self.assertEqual(len(lines), 3)
        hashes = self._db_hashes()
        for seq, line in enumerate(lines, start=1):
            self.assertIn("CEF:0|Sentro|DSPM|", line)
            self.assertIn("|user.role_updated|", line)
            self.assertIn(f"cs2={seq}", line)
            self.assertIn(f"cs3={hashes[seq]}", line, "the SIEM holds its own copy of the chain")
            self.assertIn("src=203.0.113.9", line)
        self.assertEqual(store.audit_outbox_status()["pending"], 0, "delivered events leave the outbox")

    def test_an_outage_delays_events_and_loses_none(self) -> None:
        receiver = _Receiver()
        port = receiver.port
        self._forward_to(f"tcp://127.0.0.1:{port}")
        store.audit("tenant-siem", "alice", "auth.login", {})
        self.assertEqual(siem.drain()["sent"], 1)
        receiver.wait_for(1)
        receiver.stop()                                   # the SIEM goes down
        for index in range(4):
            store.audit("tenant-siem", "alice", "auth.login_failed", {"n": index})
        now = time.time()
        failed = siem.drain(now=now)
        self.assertEqual((failed["sent"], failed["failed"], failed["pending"]), (0, 4, 4))
        with store._connect() as conn:
            waiting = [dict(r) for r in conn.execute("SELECT attempts, next_attempt_at, last_error FROM audit_outbox")]
        self.assertTrue(all(row["attempts"] == 1 and row["next_attempt_at"] > now and row["last_error"] for row in waiting))
        self.assertEqual(siem.drain(now=now)["sent"], 0, "nothing is retried before its back-off")
        back = _Receiver(port=port)                       # it comes back on the same address
        self.addCleanup(back.stop)
        recovered = siem.drain(now=now + 10)
        self.assertEqual((recovered["sent"], recovered["pending"]), (4, 0))
        lines = back.wait_for(4)
        self.assertEqual([line.split("cs2=")[1].split(" ")[0] for line in lines], ["2", "3", "4", "5"],
                         "in order, none lost, none duplicated")

    def test_a_connection_lost_mid_batch_puts_the_rest_back(self) -> None:
        receiver = _Receiver()
        self.addCleanup(receiver.stop)
        self._forward_to(f"tcp://127.0.0.1:{receiver.port}")
        for index in range(4):
            store.audit("tenant-siem", "alice", "auth.login", {"n": index})
        real_send = siem._Sender.send
        calls = {"n": 0}

        def flaky_send(sender, line):
            calls["n"] += 1
            if calls["n"] == 2:
                raise ConnectionResetError("the SIEM dropped the connection")
            real_send(sender, line)

        now = time.time()
        with mock.patch.object(siem._Sender, "send", flaky_send):
            first = siem.drain(now=now)
        self.assertEqual((first["sent"], first["failed"]), (1, 3))
        # Every event after the break is waiting for its back-off - none is stranded
        # under the lease the pass took.
        second = siem.drain(now=now + 10)
        self.assertEqual((second["sent"], second["pending"]), (3, 0))
        lines = receiver.wait_for(4)
        self.assertEqual([line.split("cs2=")[1].split(" ")[0] for line in lines], ["1", "2", "3", "4"])

    def test_the_back_off_grows_and_stops_growing(self) -> None:
        self._forward_to("tcp://127.0.0.1:9")            # nothing listens on the discard port here
        store.audit("tenant-siem", "alice", "auth.login", {})
        now = time.time()
        delays = []
        for _ in range(12):
            siem.drain(now=now)
            with store._connect() as conn:
                next_at = conn.execute("SELECT next_attempt_at FROM audit_outbox").fetchone()[0]
            delays.append(round(next_at - now))
            now = next_at
        self.assertEqual(delays[:4], [2, 4, 8, 16])
        self.assertEqual(max(delays), 300)

    def test_two_backends_draining_one_outbox_do_not_both_send(self) -> None:
        self._forward_to("tcp://127.0.0.1:9")
        for index in range(3):
            store.audit("tenant-siem", "alice", "auth.login", {"n": index})
        now = time.time()
        first = store.claim_audit_outbox(limit=10, now=now, lease_seconds=60, owner="backend-a")
        second = store.claim_audit_outbox(limit=10, now=now, lease_seconds=60, owner="backend-b")
        self.assertEqual((len(first), len(second)), (3, 0), "a leased event is not handed out again")
        after_lease = store.claim_audit_outbox(limit=10, now=now + 61, lease_seconds=60, owner="backend-b")
        self.assertEqual(len(after_lease), 3, "a lease left by a dead backend expires")

    def test_udp_too(self) -> None:
        receiver = _Receiver("udp")
        self.addCleanup(receiver.stop)
        self._forward_to(f"udp://127.0.0.1:{receiver.port}")
        store.audit("tenant-siem", "alice", "auth.login", {})
        self.assertEqual(siem.drain()["sent"], 1)
        self.assertIn("|auth.login|", receiver.wait_for(1)[0])

    def test_without_a_siem_nothing_is_queued(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_SIEM_URL": ""}):
            store.audit("tenant-siem", "alice", "auth.login", {})
            self.assertEqual(store.audit_outbox_status()["pending"], 0)
            self.assertEqual(siem.drain(), {"sent": 0, "failed": 0, "pending": 0})

    def test_health_shows_the_backlog_and_nothing_else(self) -> None:
        from fastapi.testclient import TestClient

        from backend.app import app

        client = TestClient(app)
        self.addCleanup(client.close)
        with mock.patch.dict(os.environ, {"DSPM_SIEM_URL": ""}):
            self.assertEqual(client.get("/api/health").json()["siem"], {"enabled": False})
        self._forward_to("tcp://127.0.0.1:9")
        store.audit("tenant-siem", "alice", "auth.login", {"username": "alice"})
        siem_status = client.get("/api/health").json()["siem"]
        self.assertEqual((siem_status["enabled"], siem_status["pending"]), (True, 1))
        self.assertNotIn("alice", json.dumps(siem_status), "a public probe says how much, never what")

    def test_erasing_a_tenant_takes_its_undelivered_events(self) -> None:
        self._forward_to("tcp://127.0.0.1:9")
        store.audit("tenant-siem", "alice", "auth.login", {})
        store.delete_tenant_with_data("tenant-siem")
        self.assertEqual(store.audit_outbox_status()["pending"], 0)


class TheLineFormatTest(unittest.TestCase):

    EVENT = {"tenant_id": "t|1", "seq": 7, "row_hash": "ab" * 32, "timestamp": "2026-09-24T10:00:00+00:00",
             "actor": "eve=admin", "action": "auth.login_blocked",
             "detail": {"username": "x", "note": "line\nbreak", "client_ip": "not-an-ip", "user_agent": "curl/8"}}

    def test_cef_escapes_what_would_split_a_field(self) -> None:
        line = siem.format_event(self.EVENT, "cef")
        self.assertTrue(line.startswith("<108>1 2026-09-24T10:00:00+00:00 "), "warning priority for a blocked sign-in")
        body = line.split(" - - - ", 1)[1]
        self.assertEqual(body.split("|")[:7], ["CEF:0", "Sentro", "DSPM", siem.PRODUCT_VERSION, "auth.login_blocked",
                                                "auth login_blocked", "7"])
        self.assertIn(r"suser=eve\=admin", body)
        self.assertIn(r"cs1=t|1", body)
        self.assertNotIn("\n", line)
        self.assertNotIn("src=", body, "an address that is not one is not sent as one")
        self.assertIn("requestClientApplication=curl/8", body)

    def test_json_is_one_line_too(self) -> None:
        line = siem.format_event(self.EVENT, "json")
        payload = json.loads(line.split(" - - - ", 1)[1])
        self.assertEqual((payload["seq"], payload["row_hash"], payload["action"]), (7, "ab" * 32, "auth.login_blocked"))
        self.assertNotIn("\n", line)

    def test_a_bad_url_turns_forwarding_off_rather_than_guessing(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_SIEM_URL": "http://siem.example:514"}):
            self.assertIsNone(siem.siem_target())
        with mock.patch.dict(os.environ, {"DSPM_SIEM_URL": "tls://siem.example"}):
            self.assertEqual(siem.siem_target()["port"], 6514)


if __name__ == "__main__":
    unittest.main()
