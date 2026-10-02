"""D3: alerts a person sees, delivered where the workspace says - a signed webhook, e-mail,
the SIEM - and tickets that go to Jira or ServiceNow and come back closed.

Gate line: "Delivery retries survive outage; ticket closes round-trip; every outbound
action is permissioned and audited."

Every receiver here is real and local: an HTTPS server behind a private CA (the webhook,
Jira and ServiceNow), and an SMTP relay that offers STARTTLS with the same CA. The pilot's
own Jira or ServiceNow is the live half of the gate line, and is held until there is one.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import socketserver
import ssl
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, unquote, urlsplit

from fastapi.testclient import TestClient

from backend import alert_delivery, alerts, integrations, outbound, security, store
from backend.app import app
from tests.test_siem_forwarding import _private_ca

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "Kestrel-lantern-4471"


class _Services:
    """One HTTPS server playing a webhook receiver, Jira and ServiceNow."""

    def __init__(self, certfile: Path, keyfile: Path) -> None:
        self.requests: list[dict] = []
        self.webhook_status = 200
        self.down = False
        self.jira: dict[str, dict] = {}
        self.incidents: dict[str, dict] = {}
        services = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:
                pass

            def _answer(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                request = {"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body}
                services.requests.append(request)
                status, payload = services.route(request)
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _answer

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def url(self, path: str) -> str:
        return f"https://localhost:{self.port}{path}"

    def route(self, request: dict) -> tuple[int, dict]:
        if self.down:
            return 503, {"error": "down"}
        parts = urlsplit(request["path"])
        path, query = parts.path, parse_qs(parts.query)
        if path == "/hook":
            return self.webhook_status, {}
        if path.startswith("/rest/api/2/"):
            if request["headers"].get("Authorization") != "Basic " + base64.b64encode(b"bot@example.com:jira-token-1").decode():
                return 401, {}
            if path == "/rest/api/2/myself":
                return 200, {"displayName": "Sentro Bot"}
            if path == "/rest/api/2/project/SEC":
                return 200, {"key": "SEC"}
            if path == "/rest/api/2/search":
                label = unquote(query["jql"][0]).split('"')[1]
                issues = [{"key": key} for key, issue in self.jira.items() if label in issue["labels"]]
                return 200, {"issues": issues[:1]}
            if path == "/rest/api/2/issue" and request["method"] == "POST":
                fields = json.loads(request["body"])["fields"]
                key = f"SEC-{len(self.jira) + 1}"
                self.jira[key] = {"labels": fields["labels"], "summary": fields["summary"],
                                  "description": fields["description"], "category": "new", "name": "To Do"}
                return 201, {"key": key, "id": str(len(self.jira))}
            if path.startswith("/rest/api/2/issue/"):
                issue = self.jira.get(path.rsplit("/", 1)[1])
                if issue is None:
                    return 404, {}
                return 200, {"fields": {"status": {"name": issue["name"], "statusCategory": {"key": issue["category"]}}}}
        if path.startswith("/api/now/table/incident"):
            if request["headers"].get("Authorization") != "Basic " + base64.b64encode(b"sn.bot:sn-pass-1").decode():
                return 401, {}
            if path == "/api/now/table/incident" and request["method"] == "POST":
                row = json.loads(request["body"])
                sys_id = f"sys{len(self.incidents) + 1}"
                self.incidents[sys_id] = {**row, "number": f"INC00{len(self.incidents) + 1}", "state": "1"}
                return 201, {"result": {"sys_id": sys_id, "number": self.incidents[sys_id]["number"]}}
            if path == "/api/now/table/incident":
                wanted = unquote(query.get("sysparm_query", [""])[0]).partition("=")[2]
                rows = [{"sys_id": key, "number": row["number"]} for key, row in self.incidents.items()
                        if wanted and row.get("correlation_id") == wanted]
                return 200, {"result": rows if wanted else []}
            row = self.incidents.get(path.rsplit("/", 1)[1])
            return (404, {}) if row is None else (200, {"result": {"state": row["state"], "number": row["number"]}})
        return 404, {}

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class _Relay:
    """An SMTP relay offering STARTTLS with the private CA's certificate. An address in
    `refused` is answered 550 at RCPT, as a relay answers a mailbox that is gone."""

    def __init__(self, certfile: Path, keyfile: Path) -> None:
        self.messages: list[dict] = []
        self.logins: list[str] = []
        self.refused: set[str] = set()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        relay = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                conn = self.connection
                reader = conn.makefile("rb")
                tls = False
                mail: dict = {}

                def send(text: str) -> None:
                    conn.sendall((text + "\r\n").encode())

                send("220 localhost ESMTP test relay")
                while True:
                    raw = reader.readline()
                    if not raw:
                        return
                    line = raw.decode().rstrip("\r\n")
                    verb = line.split(" ", 1)[0].upper()
                    if verb in ("EHLO", "HELO"):
                        send("250-localhost")
                        if not tls:
                            send("250-STARTTLS")
                        else:
                            send("250-AUTH PLAIN")
                        send("250 OK")
                    elif verb == "STARTTLS":
                        send("220 Go ahead")
                        conn = context.wrap_socket(conn, server_side=True)
                        reader = conn.makefile("rb")
                        tls = True
                    elif verb == "AUTH":
                        relay.logins.append(base64.b64decode(line.split(" ")[2]).decode())
                        send("235 Authenticated")
                    elif verb == "MAIL":
                        mail = {"from": line, "rcpt": [], "tls": tls}
                        send("250 OK")
                    elif verb == "RCPT":
                        address = line.partition("<")[2].partition(">")[0].lower()
                        if address in relay.refused:
                            send("550 5.1.1 No such user here")
                        else:
                            mail["rcpt"].append(line)
                            send("250 OK")
                    elif verb == "DATA":
                        send("354 End with <CRLF>.<CRLF>")
                        lines = []
                        while True:
                            part = reader.readline()
                            if part in (b".\r\n", b""):
                                break
                            lines.append(part)
                        mail["data"] = b"".join(lines).decode("utf-8", "replace")
                        relay.messages.append(mail)
                        send("250 Queued")
                    elif verb == "QUIT":
                        send("221 Bye")
                        return
                    else:
                        send("250 OK")

        socketserver.TCPServer.allow_reuse_address = True
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class D3Case(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.certs = Path(tempfile.mkdtemp())
        cls.ca, cls.cert, cls.key = _private_ca(cls.certs)
        cls.services = _Services(cls.cert, cls.key)
        cls.relay = _Relay(cls.cert, cls.key)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.services.stop()
        cls.relay.stop()
        shutil.rmtree(cls.certs, ignore_errors=True)

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        original = store.DB_PATH
        store.DB_PATH = self.tmp / "d3.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        for tenant in ("t-d3", "t-other"):
            store.create_tenant(tenant, tenant)
        for user, role, tenant in (("d3-admin", "admin", "t-d3"), ("d3-analyst", "analyst", "t-d3"),
                                   ("d3-viewer", "viewer", "t-d3"), ("other-admin", "admin", "t-other")):
            store.create_user(user, security.hash_password(PASSWORD), role, tenant)
        loopback = mock.patch.object(outbound, "_allow_loopback", return_value=True)
        loopback.start()
        self.addCleanup(loopback.stop)
        self.services.requests.clear()
        self.services.webhook_status = 200
        self.services.down = False
        self.services.jira.clear()
        self.services.incidents.clear()
        self.relay.messages.clear()
        self.relay.logins.clear()
        self.relay.refused.clear()
        self.client = TestClient(app)

    def as_(self, user: str = "d3-admin", role: str = "admin", tenant: str = "t-d3", *, mfa: bool = True) -> dict:
        return {"Authorization": f"Bearer {security.create_token(user, role, tenant, mfa_verified=mfa)}"}

    def configure(self, channel: str, body: dict, *, headers: dict | None = None):
        return self.client.put(f"/api/integrations/{channel}", headers=headers or self.as_(),
                               json={"ca_pem": self.ca.read_text(), "ca_name": "ca.pem", **body})

    def webhook(self, **extra) -> str:
        response = self.configure("webhook", {"url": self.services.url("/hook"), "enabled": True,
                                              "min_severity": "HIGH", **extra})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["signing_secret"]

    def raise_alert(self, tenant: str = "t-d3", critical: int = 2) -> dict:
        raised = alerts.evaluate_alerts(tenant, {"summary": {"critical": critical}, "scan_id": "scan-d3"})
        self.assertTrue(raised)
        return raised[0]

    def later(self) -> float:
        return time.time() + 3600

    def audit_rows(self, tenant: str = "t-d3") -> list[dict]:
        with store._connect() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT actor, action, detail_json FROM audit_events WHERE tenant_id = ? ORDER BY id", (tenant,))]

    def actions(self, tenant: str = "t-d3") -> list[str]:
        return [row["action"] for row in self.audit_rows(tenant)]


class TheAlertsPageTest(D3Case):

    def test_a_raised_alert_is_listed_open_and_can_be_acknowledged(self) -> None:
        alert = self.raise_alert()
        listed = self.client.get("/api/alerts", headers=self.as_("d3-viewer", "viewer")).json()
        self.assertEqual(listed["open"], 1)
        self.assertEqual([(item["alert_id"], item["severity"], item["status"]) for item in listed["alerts"]],
                         [(alert["alert_id"], "CRITICAL", "open")])
        self.assertEqual(self.client.post(f"/api/alerts/{alert['alert_id']}/acknowledge",
                                          headers=self.as_("d3-viewer", "viewer")).status_code, 403)
        done = self.client.post(f"/api/alerts/{alert['alert_id']}/acknowledge", headers=self.as_("d3-analyst", "analyst"))
        self.assertEqual(done.status_code, 200)
        again = self.client.get("/api/alerts", headers=self.as_()).json()
        self.assertEqual((again["open"], again["alerts"][0]["acknowledged_by"]), (0, "d3-analyst"))
        self.assertIn("alert.acknowledged", self.actions())

    def test_an_alert_is_in_the_audit_trail_which_carries_it_to_the_siem(self) -> None:
        alert = self.raise_alert()
        raised = [row for row in self.audit_rows() if row["action"] == "alert.raised"]
        self.assertEqual(len(raised), 1)
        self.assertEqual(json.loads(raised[0]["detail_json"])["alert_id"], alert["alert_id"])
        from backend import siem

        self.assertGreaterEqual(siem._severity("alert.raised"), 7, "a SOC is paged on an alert")

    def test_another_workspace_neither_sees_nor_acknowledges_it(self) -> None:
        alert = self.raise_alert()
        other = self.as_("other-admin", tenant="t-other")
        self.assertEqual(self.client.get("/api/alerts", headers=other).json()["alerts"], [])
        self.assertEqual(self.client.post(f"/api/alerts/{alert['alert_id']}/acknowledge", headers=other).status_code, 404)


class TheSignedWebhookTest(D3Case):

    def test_a_delivery_is_signed_and_verifiable_with_the_secret_shown_once(self) -> None:
        secret = self.webhook()
        self.assertTrue(secret.startswith("whsec_"))
        read = self.client.get("/api/integrations", headers=self.as_()).text
        self.assertNotIn(secret, read, "the signing secret is shown once, never read back")
        self.assertIn('"signing_secret_configured": true', read.replace(":true", ": true"))
        alert = self.raise_alert()
        self.assertEqual(alert_delivery.drain()["delivered"], 1)
        [request] = [item for item in self.services.requests if item["path"] == "/hook"]
        # What the README tells a receiver to compute, computed here without Sentro's code.
        parts = dict(item.split("=", 1) for item in request["headers"]["X-Sentro-Signature"].split(","))
        expected = hmac.new(secret.encode(), f"{parts['t']}.".encode() + request["body"], hashlib.sha256).hexdigest()
        self.assertEqual(parts["v1"], expected)
        self.assertLess(abs(time.time() - int(parts["t"])), 60)
        self.assertTrue(alert_delivery.verify_signature(secret, request["headers"]["X-Sentro-Signature"], request["body"]))
        self.assertFalse(alert_delivery.verify_signature("whsec_other", request["headers"]["X-Sentro-Signature"], request["body"]))
        self.assertFalse(alert_delivery.verify_signature(secret, request["headers"]["X-Sentro-Signature"],
                                                         request["body"] + b" "), "the body is what is signed")
        self.assertFalse(alert_delivery.verify_signature(secret, request["headers"]["X-Sentro-Signature"],
                                                         request["body"], now=time.time() + 3600), "an old signature")
        body = json.loads(request["body"])
        self.assertEqual((body["event"], body["alert"]["id"], body["workspace"]), ("alert.raised", alert["alert_id"], "t-d3"))
        listed = self.client.get("/api/alerts", headers=self.as_()).json()["alerts"][0]["deliveries"]
        self.assertEqual([(item["channel"], item["status"]) for item in listed], [("webhook", "delivered")])
        self.assertIn("alert.delivered", self.actions())

    def test_an_outage_delays_delivery_and_loses_nothing(self) -> None:
        self.webhook()
        self.services.webhook_status = 500
        self.raise_alert()
        self.raise_alert()
        self.assertEqual(alert_delivery.drain()["retry"], 2)
        view = self.client.get("/api/integrations", headers=self.as_()).json()["integrations"][0]
        self.assertEqual((view["state"], view["queue"]["pending"], view["queue"]["failing"]), ("degraded", 2, 2))
        self.assertIn("HTTP 500", view["status"]["last_error"])
        self.assertEqual(alert_delivery.drain()["delivered"], 0, "not before its back-off")
        self.assertEqual(alert_delivery.drain(now=self.later())["retry"], 2, "still down after the back-off")
        self.services.webhook_status = 200
        self.assertEqual(alert_delivery.drain(now=self.later() + 3600)["delivered"], 2)
        deliveries = [d for a in self.client.get("/api/alerts", headers=self.as_()).json()["alerts"] for d in a["deliveries"]]
        self.assertEqual({(d["status"], d["attempts"]) for d in deliveries}, {("delivered", 3)})
        self.assertEqual(self.actions().count("alert.delivery_failed"), 2, "each failure audited once, not per retry")
        view = self.client.get("/api/integrations", headers=self.as_()).json()["integrations"][0]
        self.assertEqual(view["state"], "connected")

    def test_a_receiver_whose_certificate_is_not_trusted_is_not_sent_to(self) -> None:
        self.webhook(remove_ca=True)  # the system trust store does not know the private CA
        self.raise_alert()
        self.assertEqual(alert_delivery.drain()["retry"], 1)
        self.assertFalse([item for item in self.services.requests if item["path"] == "/hook"])
        error = self.client.get("/api/integrations", headers=self.as_()).json()["integrations"][0]["status"]["last_error"]
        self.assertIn("not trusted", error)

    def test_plain_http_and_credentials_in_the_address_are_refused(self) -> None:
        for url in ("http://localhost/hook", f"https://user:pass@localhost:{self.services.port}/hook", "file:///etc/passwd"):
            with self.subTest(url=url):
                refused = self.configure("webhook", {"url": url})
                self.assertEqual(refused.status_code, 400)
                self.assertNotIn("reference", refused.json()["detail"], "the reason itself, not a fallback")

    def test_loopback_link_local_and_metadata_addresses_are_never_called(self) -> None:
        with mock.patch.object(outbound, "_allow_loopback", return_value=False):
            for host in ("127.0.0.1", "localhost", "169.254.169.254", "[::1]"):
                with self.subTest(host=host), self.assertRaisesRegex(outbound.OutboundRefused, "does not call"):
                    outbound.https_request("POST", f"https://{host}/hook", body=b"{}")

    def test_only_https_is_called(self) -> None:
        with self.assertRaisesRegex(outbound.OutboundRefused, "Only https"):
            outbound.https_request("POST", f"http://localhost:{self.services.port}/hook", body=b"{}")
        self.assertFalse([item for item in self.services.requests if item["path"] == "/hook"])

    def test_rotating_the_secret_changes_what_verifies(self) -> None:
        first = self.webhook()
        second = self.configure("webhook", {"rotate_secret": True}).json()["signing_secret"]
        self.assertNotEqual(first, second)
        self.raise_alert()
        alert_delivery.drain()
        [request] = [item for item in self.services.requests if item["path"] == "/hook"]
        self.assertTrue(alert_delivery.verify_signature(second, request["headers"]["X-Sentro-Signature"], request["body"]))
        self.assertFalse(alert_delivery.verify_signature(first, request["headers"]["X-Sentro-Signature"], request["body"]))

    def test_below_the_channels_severity_nothing_is_queued(self) -> None:
        self.webhook(min_severity="CRITICAL")
        with store._connect() as conn:
            store.save_alerts("t-d3", "scan-x", [{"severity": "HIGH", "title": "High"}])
            self.assertEqual(conn.execute("SELECT COUNT(*) AS n FROM alert_deliveries").fetchone()["n"], 0)


class TheMailRelayTest(D3Case):

    def relay_config(self, **extra):
        return self.configure("email", {"host": "localhost", "port": self.relay.port, "security": "starttls",
                                        "sender": "sentro@example.com", "recipients": ["soc@example.com"],
                                        "username": "relay-user", "password": "relay-pass-1", "enabled": True, **extra})

    def test_an_alert_is_mailed_over_starttls_with_nothing_sensitive(self) -> None:
        self.assertEqual(self.relay_config().status_code, 200)
        self.raise_alert()
        self.assertEqual(alert_delivery.drain()["delivered"], 1)
        [message] = self.relay.messages
        self.assertTrue(message["tls"], "the message went after STARTTLS")
        self.assertEqual(self.relay.logins, ["\x00relay-user\x00relay-pass-1"])
        self.assertIn("Subject: [Sentro] CRITICAL: Critical sensitive exposure detected", message["data"])
        self.assertIn("soc@example.com", message["rcpt"][0])

    def test_a_password_only_travels_over_tls(self) -> None:
        refused = self.relay_config(security="none")
        self.assertEqual(refused.status_code, 400)
        self.assertIn("TLS", refused.json()["detail"])
        self.assertIsNone(store.get_alert_channel("t-d3", "email"), "nothing was saved")
        with self.assertRaisesRegex(outbound.OutboundRefused, "only sent over TLS"):
            outbound.send_mail(host="localhost", port=self.relay.port, security="none", sender="a@example.com",
                               recipients=["b@example.com"], subject="s", text="t", username="u", password="p")
        self.assertEqual((self.relay.messages, self.relay.logins), ([], []))
        plain = self.relay_config(security="none", username="", password=None)
        self.assertEqual(plain.status_code, 200, "no password, no TLS needed")

    def test_the_password_is_kept_replaced_and_removed_as_asked_and_never_returned(self) -> None:
        self.relay_config()
        first = store.get_alert_channel("t-d3", "email")["secret_ref"]
        kept = self.configure("email", {"min_severity": "MEDIUM"})
        self.assertTrue(kept.json()["config"]["password_configured"])
        self.assertEqual(store.get_alert_channel("t-d3", "email")["secret_ref"], first, "omitted: kept")
        self.assertEqual(self.configure("email", {"password": "•" * 12}).status_code, 400, "a mask is not a password")
        self.configure("email", {"password": "relay-pass-2"})
        second = store.get_alert_channel("t-d3", "email")["secret_ref"]
        self.assertNotEqual(second, first)
        self.assertIsNone(store.read_secret_record("t-d3", first), "the replaced secret is deleted")
        self.assertEqual(integrations.load("t-d3", "email")[1], "relay-pass-2")
        removed = self.configure("email", {"remove_secret": True, "username": ""})
        self.assertFalse(removed.json()["config"]["password_configured"])
        self.assertIsNone(store.read_secret_record("t-d3", second))
        texts = [self.client.get("/api/integrations", headers=self.as_()).text, json.dumps(self.audit_rows())]
        for text in texts:
            for secret in ("relay-pass-1", "relay-pass-2"):
                self.assertNotIn(secret, text)

    def mail_view(self) -> dict:
        return next(item for item in self.client.get("/api/integrations", headers=self.as_()).json()["integrations"]
                    if item["channel"] == "email")

    def test_one_refused_recipient_does_not_resend_the_alert_to_the_rest(self) -> None:
        """M4 exit review: a relay that refused one address while it took the others failed
        the delivery, and every retry mailed the others again - every few minutes, for good,
        because one mailbox was gone. They were sent it: it is delivered, once, and the
        channel names the address to fix."""
        self.relay.refused.add("gone@example.com")
        recipients = ["soc@example.com", "gone@example.com", "ciso@example.com"]
        self.assertEqual(self.relay_config(recipients=recipients).status_code, 200)
        alert = self.raise_alert()
        passes = [alert_delivery.drain(now=time.time() + later) for later in (0, 600, 3600, 86400)]
        self.assertEqual([(item["delivered"], item["retry"]) for item in passes], [(1, 0), (0, 0), (0, 0), (0, 0)])
        [message] = self.relay.messages
        accepted = " ".join(message["rcpt"])
        self.assertIn("soc@example.com", accepted)
        self.assertIn("ciso@example.com", accepted)
        self.assertNotIn("gone@example.com", accepted)
        [delivery] = self.client.get("/api/alerts", headers=self.as_()).json()["alerts"][0]["deliveries"]
        self.assertEqual((delivery["status"], delivery["attempts"]), ("delivered", 1))
        self.assertIn("gone@example.com", self.mail_view()["status"]["last_error"], "the address to fix is shown")
        [delivered] = [json.loads(row["detail_json"]) for row in self.audit_rows() if row["action"] == "alert.delivered"]
        self.assertEqual((delivered["alert_id"], delivered["refused_recipients"]), (alert["alert_id"], ["gone@example.com"]))

    def test_every_recipient_refused_is_still_a_failure(self) -> None:
        self.relay.refused.update({"soc@example.com", "gone@example.com"})
        self.assertEqual(self.relay_config(recipients=["soc@example.com", "gone@example.com"]).status_code, 200)
        self.raise_alert()
        self.assertEqual(alert_delivery.drain()["retry"], 1)
        self.assertEqual(self.relay.messages, [])
        [delivery] = self.client.get("/api/alerts", headers=self.as_()).json()["alerts"][0]["deliveries"]
        self.assertEqual(delivery["status"], "pending", "retried, not given up and not called delivered")
        self.assertIn("refused every recipient", self.mail_view()["status"]["last_error"])
        self.assertNotIn("alert.delivered", self.actions())

    def test_a_test_message_with_a_refused_recipient_is_not_a_pass(self) -> None:
        self.relay.refused.add("gone@example.com")
        self.relay_config(recipients=["soc@example.com", "gone@example.com"])
        result = self.client.post("/api/integrations/email/test", headers=self.as_()).json()["test"]
        self.assertFalse(result["ok"])
        self.assertIn("gone@example.com", result["message"])
        self.assertEqual(len(self.relay.messages), 1, "the others were sent the test")

    def test_the_relay_names_the_recipients_it_refused(self) -> None:
        self.relay.refused.add("gone@example.com")
        common = {"host": "localhost", "port": self.relay.port, "security": "starttls", "sender": "sentro@example.com",
                  "subject": "s", "text": "t", "ca_pem": self.ca.read_text()}
        self.assertEqual(outbound.send_mail(recipients=["soc@example.com"], **common), [])
        self.assertEqual(outbound.send_mail(recipients=["soc@example.com", "gone@example.com"], **common),
                         ["gone@example.com"])
        with self.assertRaisesRegex(outbound.OutboundRefused, "refused every recipient"):
            outbound.send_mail(recipients=["gone@example.com"], **common)
        self.assertEqual(len(self.relay.messages), 2)


class ASavedSecretStaysWithItsDestinationTest(D3Case):
    """M4 exit review: a save that pointed a channel somewhere else - another host or port,
    another URL, another CA trusted for it - with the secret left out sent the saved
    password or token there. An administrator who never saw it could collect it on a host
    of their own."""

    REFUSED = "enter the password or token again"

    def mail(self, **extra):
        return self.configure("email", {"host": "localhost", "port": self.relay.port, "security": "starttls",
                                        "sender": "sentro@example.com", "recipients": ["soc@example.com"],
                                        "username": "relay-user", "enabled": True, **extra})

    def assert_refused_and_unchanged(self, channel: str, change: dict) -> None:
        before = store.get_alert_channel("t-d3", channel)
        refused = self.configure(channel, change)
        self.assertEqual(refused.status_code, 400, refused.text)
        self.assertIn(self.REFUSED, refused.json()["detail"])
        after = store.get_alert_channel("t-d3", channel)
        self.assertEqual((after["config"], after["secret_ref"]), (before["config"], before["secret_ref"]),
                         "a refused save changed the channel")

    def test_a_mail_relay_moved_without_its_password_is_refused(self) -> None:
        self.assertEqual(self.mail(password="relay-pass-1").status_code, 200)
        other_ca, _cert, _key = _private_ca(self.tmp)
        for change in ({"host": "127.0.0.1"}, {"port": self.relay.port + 1}, {"remove_ca": True},
                       {"ca_pem": other_ca.read_text()}):
            with self.subTest(change=sorted(change)):
                self.assert_refused_and_unchanged("email", change)
        self.assertEqual(integrations.load("t-d3", "email")[1], "relay-pass-1")

    def test_entering_the_password_with_the_new_relay_saves_both(self) -> None:
        self.mail(password="relay-pass-1")
        first = store.get_alert_channel("t-d3", "email")["secret_ref"]
        moved = self.configure("email", {"host": "127.0.0.1", "password": "relay-pass-2"})
        self.assertEqual(moved.status_code, 200, moved.text)
        self.assertEqual(store.get_alert_channel("t-d3", "email")["config"]["host"], "127.0.0.1")
        self.assertEqual(integrations.load("t-d3", "email")[1], "relay-pass-2")
        self.assertIsNone(store.read_secret_record("t-d3", first), "the secret for the old relay is gone")

    def test_changing_what_is_not_a_destination_keeps_the_secret(self) -> None:
        self.mail(password="relay-pass-1")
        ref = store.get_alert_channel("t-d3", "email")["secret_ref"]
        for change in ({"recipients": ["soc@example.com", "ciso@example.com"]}, {"min_severity": "MEDIUM"},
                       {"sender": "alerts@example.com"}):
            with self.subTest(change=sorted(change)):
                self.assertEqual(self.configure("email", change).status_code, 200)
                self.assertEqual(store.get_alert_channel("t-d3", "email")["secret_ref"], ref)
        self.assertEqual(integrations.load("t-d3", "email")[1], "relay-pass-1")

    def test_a_relay_with_no_saved_password_may_move(self) -> None:
        self.assertEqual(self.mail().status_code, 200)
        self.assertEqual(self.configure("email", {"host": "127.0.0.1"}).status_code, 200)

    def test_a_ticket_system_moved_without_its_token_is_refused(self) -> None:
        self.assertEqual(self.configure("jira", {"base_url": self.services.url(""), "project_key": "SEC",
                                                 "username": "bot@example.com", "token": "jira-token-1"}).status_code, 200)
        self.assert_refused_and_unchanged("jira", {"base_url": "https://jira.example.test"})
        self.assert_refused_and_unchanged("jira", {"remove_ca": True})
        ref = store.get_alert_channel("t-d3", "jira")["secret_ref"]
        self.assertEqual(self.configure("jira", {"project_key": "OPS"}).status_code, 200, "not a destination")
        self.assertEqual(store.get_alert_channel("t-d3", "jira")["secret_ref"], ref)
        self.assertEqual(self.configure("jira", {"base_url": "https://jira.example.test", "token": "jira-token-2"})
                         .status_code, 200)
        self.assertEqual(integrations.load("t-d3", "jira")[1], "jira-token-2")

        self.assertEqual(self.configure("servicenow", {"instance_url": self.services.url(""), "username": "sn.bot",
                                                       "password": "sn-pass-1"}).status_code, 200)
        self.assert_refused_and_unchanged("servicenow", {"instance_url": "https://sn.example.test"})
        self.assertEqual(self.configure("servicenow", {"assignment_group": "SOC"}).status_code, 200)
        self.assertEqual(integrations.load("t-d3", "servicenow")[1], "sn-pass-1")


class TheDeliveryLeaseTest(D3Case):
    """M4 exit review: a pass of slow sends can outlast the lease its deliveries were claimed
    under. Another backend then claims them and sends them too, and whichever finished last
    wrote its outcome over the other's. The lease is renewed before each send, a worker that
    lost it does not send, and only the lease's holder writes an outcome."""

    def claim(self, owner: str, now: float, limit: int = 10) -> list[dict]:
        return store.claim_alert_deliveries(limit=limit, now=now, lease_seconds=alert_delivery.LEASE_SECONDS,
                                            owner=owner)

    def delivery(self, delivery_id: int) -> dict:
        with store._connect() as conn:
            return dict(conn.execute("SELECT status, attempts, lease_owner, lease_until FROM alert_deliveries "
                                     "WHERE id = ?", (delivery_id,)).fetchone())

    def hooks(self) -> list[dict]:
        return [item for item in self.services.requests if item["path"] == "/hook"]

    def test_a_renewed_lease_is_not_claimed_by_another_worker(self) -> None:
        self.webhook()
        self.raise_alert()
        start = time.time()
        [row] = self.claim("worker-a", start)
        self.assertTrue(store.renew_alert_delivery_lease("t-d3", row["id"], owner="worker-a", until=start + 600))
        self.assertEqual(self.claim("worker-b", start + alert_delivery.LEASE_SECONDS + 1), [],
                         "the renewed lease was claimed as if it had run out")
        self.assertFalse(store.renew_alert_delivery_lease("t-d3", row["id"], owner="worker-b", until=start + 900),
                         "a worker renewed a lease it does not hold")
        self.assertEqual(self.delivery(row["id"])["lease_owner"], "worker-a")
        self.assertEqual([item["id"] for item in self.claim("worker-b", start + 601)], [row["id"]])

    def test_a_worker_that_lost_its_lease_does_not_send(self) -> None:
        self.webhook()
        self.raise_alert()
        start = time.time()
        [stale] = self.claim("worker-a", start)
        [taken] = self.claim("worker-b", start + alert_delivery.LEASE_SECONDS + 1)
        with mock.patch.object(alert_delivery, "_owner", return_value="worker-a"):
            self.assertEqual(alert_delivery.deliver(stale), "skipped")
        self.assertEqual(self.hooks(), [], "sent by a worker that no longer held the delivery")
        self.assertEqual((self.delivery(taken["id"])["status"], self.delivery(taken["id"])["lease_owner"]),
                         ("pending", "worker-b"))
        with mock.patch.object(alert_delivery, "_owner", return_value="worker-b"):
            self.assertEqual(alert_delivery.deliver(taken), "delivered")
        self.assertEqual(len(self.hooks()), 1)
        self.assertEqual(self.delivery(taken["id"])["status"], "delivered")

    def test_an_outcome_from_a_worker_whose_lease_was_taken_over_is_not_written(self) -> None:
        self.webhook()
        self.raise_alert()
        start = time.time()
        [row] = self.claim("worker-a", start)
        taken: list[dict] = []
        real_send = alert_delivery.send_webhook

        def slow_send(*args, **kwargs):
            # The send outlasts the lease, and another worker claims the delivery meanwhile.
            taken.extend(self.claim("worker-b", time.time() + alert_delivery.LEASE_SECONDS + 1))
            return real_send(*args, **kwargs)

        with mock.patch.object(alert_delivery, "_owner", return_value="worker-a"), \
                mock.patch.object(alert_delivery, "send_webhook", side_effect=slow_send):
            alert_delivery.deliver(row)
        self.assertEqual([item["id"] for item in taken], [row["id"]])
        held = self.delivery(row["id"])
        self.assertEqual((held["status"], held["lease_owner"]), ("pending", "worker-b"),
                         "the worker that lost the lease wrote its outcome over the new holder's")
        self.assertFalse(store.finish_alert_delivery("t-d3", row["id"], status="pending", attempts=1, error="late",
                                                     next_attempt_at=start + 3600, owner="worker-a"))
        self.assertEqual(self.delivery(row["id"])["lease_owner"], "worker-b")
        self.assertTrue(store.finish_alert_delivery("t-d3", row["id"], status="delivered", attempts=1,
                                                    owner="worker-b"))
        self.assertEqual(self.delivery(row["id"])["status"], "delivered")

    def test_claims_take_turns_between_workspaces(self) -> None:
        for tenant in ("t-d3", "t-other"):
            store.save_alert_channel(tenant, "webhook", enabled=True, config={"url": self.services.url("/hook"),
                                     "min_severity": "LOW"}, secret_ref="", actor="tester")
        store.save_alerts("t-d3", "scan-a", [{"severity": "CRITICAL", "title": f"a{index}"} for index in range(5)])
        store.save_alerts("t-other", "scan-b", [{"severity": "CRITICAL", "title": "b0"}])
        claimed = self.claim("worker-a", time.time(), limit=2)
        self.assertEqual(sorted(row["tenant_id"] for row in claimed), ["t-d3", "t-other"],
                         "one workspace's backlog held another's alert behind it")
        rest = self.claim("worker-a", time.time(), limit=10)
        self.assertEqual([row["tenant_id"] for row in rest], ["t-d3"] * 4)


class OnOffAndRemoveTest(D3Case):

    def test_turning_a_channel_off_keeps_its_settings_and_cancels_what_waited(self) -> None:
        self.webhook()
        self.services.webhook_status = 500
        self.raise_alert()
        alert_delivery.drain()
        off = self.client.put("/api/integrations/webhook/enabled", headers=self.as_(), json={"enabled": False})
        self.assertEqual((off.json()["state"], off.json()["config"]["url"]), ("disabled", self.services.url("/hook")))
        self.raise_alert()
        self.assertEqual(alert_delivery.drain(now=self.later()), {"delivered": 0, "retry": 0, "cancelled": 0})
        statuses = [d["status"] for a in self.client.get("/api/alerts", headers=self.as_()).json()["alerts"] for d in a["deliveries"]]
        self.assertEqual(statuses, ["cancelled"], "the waiting one cancelled; the new one never queued")
        on = self.client.put("/api/integrations/webhook/enabled", headers=self.as_(), json={"enabled": True})
        self.assertTrue(on.json()["config"]["signing_secret_configured"])
        self.assertEqual(self.actions().count("integration.disabled"), 1)
        self.assertEqual(self.actions().count("integration.enabled"), 2)

    def test_removing_a_channel_deletes_its_settings_and_secret(self) -> None:
        self.webhook()
        ref = store.get_alert_channel("t-d3", "webhook")["secret_ref"]
        self.assertEqual(self.client.delete("/api/integrations/webhook", headers=self.as_()).status_code, 200)
        self.assertIsNone(store.get_alert_channel("t-d3", "webhook"))
        self.assertIsNone(store.read_secret_record("t-d3", ref))
        self.assertIn("integration.removed", self.actions())

    def test_testing_a_channel_is_audited_and_sets_its_state(self) -> None:
        self.webhook()
        self.assertEqual(self.client.get("/api/integrations", headers=self.as_()).json()["integrations"][0]["state"],
                         "not_connected", "enabled is not connected")
        passed = self.client.post("/api/integrations/webhook/test", headers=self.as_()).json()
        self.assertEqual((passed["test"]["ok"], passed["state"]), (True, "connected"))
        self.services.webhook_status = 404
        failed = self.client.post("/api/integrations/webhook/test", headers=self.as_()).json()
        self.assertFalse(failed["test"]["ok"])
        self.assertEqual([a for a in self.actions() if a.startswith("integration.test")],
                         ["integration.test_succeeded", "integration.test_failed"])


class ThePermissionsTest(D3Case):

    def test_only_a_verified_administrator_configures_and_only_triage_tickets(self) -> None:
        body = {"url": self.services.url("/hook")}
        self.assertEqual(self.configure("webhook", body, headers=self.as_("d3-viewer", "viewer")).status_code, 403)
        self.assertEqual(self.configure("webhook", body, headers=self.as_("d3-analyst", "analyst")).status_code, 403)
        self.assertEqual(self.configure("webhook", body, headers=self.as_(mfa=False)).status_code, 403)
        self.assertEqual(self.client.get("/api/integrations", headers=self.as_("d3-viewer", "viewer")).status_code, 403)
        self.assertEqual(self.client.post("/api/findings/x/ticket", headers=self.as_("d3-viewer", "viewer"),
                                          json={}).status_code, 403)

    def test_another_workspaces_channels_are_its_own(self) -> None:
        self.webhook()
        other = self.client.get("/api/integrations", headers=self.as_("other-admin", tenant="t-other")).json()
        self.assertFalse(any(item["configured"] for item in other["integrations"]))
        self.raise_alert(tenant="t-other")
        self.assertEqual(store.read_alerts("t-other")[0]["deliveries"], [], "nothing is queued in t-other")
        self.assertEqual(alert_delivery.drain()["delivered"], 0, "t-other has no webhook; t-d3's is not used")


class TheLegacyWebhookTest(D3Case):

    def test_the_environment_webhook_is_imported_once_as_a_signed_channel(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_ALERT_WEBHOOK_URL": self.services.url("/hook")}):
            self.assertTrue(integrations.import_environment())
            self.assertFalse(integrations.import_environment(), "once")
        record = store.get_alert_channel("default", "webhook")
        self.assertEqual((record["enabled"], record["config"]["url"]), (True, self.services.url("/hook")))
        self.assertTrue(record["secret_ref"])

    def test_an_http_environment_webhook_is_not_imported(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_ALERT_WEBHOOK_URL": "http://hooks.example.test/x"}):
            self.assertFalse(integrations.import_environment())
        self.assertIsNone(store.get_alert_channel("default", "webhook"))


class TicketCase(D3Case):

    def setUp(self) -> None:
        super().setUp()
        self.relative = Path("tmp") / f"d3-estate-{os.getpid()}-{id(self)}"
        folder = ROOT / self.relative
        folder.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, folder, True)
        (folder / "cards.txt").write_text("Customer card 4111 1111 1111 1111 exp 12/29\n", encoding="utf-8")
        with mock.patch("backend.app.partitioned_scans_enabled", return_value=False):
            response = self.client.post("/api/scan", headers=self.as_(), json={
                "local_path": self.relative.as_posix(), "async_scan": False, "save_report": True,
                "compact_result": False, "incremental_enabled": False})
        self.assertEqual(response.status_code, 200, response.text[:300])
        with store._connect() as conn:
            self.finding_id = conn.execute("SELECT id FROM findings WHERE tenant_id = 't-d3' LIMIT 1").fetchone()["id"]

    def jira(self, **extra):
        response = self.configure("jira", {"base_url": self.services.url(""), "project_key": "SEC",
                                           "username": "bot@example.com", "token": "jira-token-1", "enabled": True, **extra})
        self.assertEqual(response.status_code, 200, response.text)

    def servicenow(self):
        response = self.configure("servicenow", {"instance_url": self.services.url(""), "username": "sn.bot",
                                                 "password": "sn-pass-1", "enabled": True})
        self.assertEqual(response.status_code, 200, response.text)

    def request_ticket(self, system: str = "", user: str = "d3-analyst", role: str = "analyst"):
        return self.client.post(f"/api/findings/{self.finding_id}/ticket", headers=self.as_(user, role),
                                json={"system": system} if system else {})

    def finding_status(self) -> str:
        return str(store.get_finding("t-d3", self.finding_id).get("status") or "").upper()

    def sync_now(self) -> dict:
        # Every open ticket is due: the sync window ends an hour from now.
        with mock.patch.object(alert_delivery, "sync_seconds", return_value=-3600.0):
            return alert_delivery.drain_tickets(now=self.later())


class TheJiraRoundTripTest(TicketCase):

    def test_a_ticket_is_created_and_closing_it_resolves_the_finding(self) -> None:
        self.jira()
        requested = self.request_ticket()
        self.assertEqual(requested.status_code, 200, requested.text)
        ticket = requested.json()["ticket"]
        self.assertEqual((ticket["status"], ticket["system"]), ("pending", "jira"))
        self.assertEqual(alert_delivery.drain_tickets()["created"], 1)
        [issue] = self.services.jira.values()
        self.assertIn(f"sentro-{ticket['ticket_id']}", issue["labels"])
        self.assertNotIn("4111", issue["summary"] + issue["description"], "no value leaves in a ticket")
        listed = self.client.get(f"/api/tickets?finding_id={self.finding_id}", headers=self.as_()).json()["tickets"]
        self.assertEqual((listed[0]["status"], listed[0]["external_key"]), ("open", "SEC-1"))
        self.assertEqual(self.request_ticket().status_code, 409, "one open ticket per finding and system")
        self.assertEqual(self.sync_now()["open"], 1)
        self.assertNotEqual(self.finding_status(), "RESOLVED")
        self.services.jira["SEC-1"].update(category="done", name="Done")
        self.assertEqual(self.sync_now()["closed"], 1)
        self.assertEqual(self.finding_status(), "RESOLVED")
        history = store.get_finding_history("t-d3", self.finding_id)
        self.assertEqual(history[-1]["actor"], "jira:SEC-1")
        self.assertEqual([a for a in self.actions() if a.startswith("ticket.")],
                         ["ticket.requested", "ticket.created", "ticket.closed"])

    def test_a_ticket_system_outage_delays_the_ticket_and_makes_no_duplicate(self) -> None:
        self.jira()
        self.request_ticket()
        self.services.down = True
        self.assertEqual(alert_delivery.drain_tickets()["retry"], 1)
        self.assertEqual(self.services.jira, {})
        self.services.down = False
        # The ticket was made, and the process died before it was recorded: the next pass finds it.
        ticket_id = store.list_finding_tickets("t-d3")[0]["ticket_id"]
        self.services.jira["SEC-9"] = {"labels": ["sentro", f"sentro-{ticket_id}"], "summary": "", "description": "",
                                       "category": "new", "name": "To Do"}
        self.assertEqual(alert_delivery.drain_tickets(now=self.later())["created"], 1)
        self.assertEqual(list(self.services.jira), ["SEC-9"], "found, not created again")
        self.assertEqual(store.list_finding_tickets("t-d3")[0]["external_key"], "SEC-9")
        self.assertEqual(self.actions().count("ticket.create_failed"), 1)

    def test_a_refused_token_is_reported_without_the_token(self) -> None:
        self.jira(token="wrong-token")
        result = self.client.post("/api/integrations/jira/test", headers=self.as_()).json()
        self.assertFalse(result["test"]["ok"])
        self.assertIn("credentials were refused", result["test"]["message"])
        self.assertNotIn("wrong-token", json.dumps(result) + json.dumps(self.audit_rows()))


class TheServiceNowRoundTripTest(TicketCase):

    def test_an_incident_is_created_and_resolving_it_resolves_the_finding(self) -> None:
        self.servicenow()
        self.assertEqual(self.request_ticket().status_code, 200)
        self.assertEqual(alert_delivery.drain_tickets()["created"], 1)
        [(sys_id, incident)] = self.services.incidents.items()
        self.assertTrue(incident["correlation_id"].startswith("sentro-"))
        self.assertEqual(self.client.post("/api/tickets/sync", headers=self.as_("d3-analyst", "analyst")).json()["sync"]["open"], 1)
        incident["state"] = "6"
        self.assertEqual(self.client.post("/api/tickets/sync", headers=self.as_("d3-analyst", "analyst")).json()["sync"]["closed"], 1)
        self.assertEqual(self.finding_status(), "RESOLVED")
        self.assertEqual(store.list_finding_tickets("t-d3")[0]["external_status"], "Resolved")

    def test_with_two_systems_on_the_request_names_one(self) -> None:
        self.jira()
        self.servicenow()
        self.assertEqual(self.request_ticket().status_code, 400)
        self.assertEqual(self.request_ticket("servicenow").status_code, 200)


if __name__ == "__main__":
    unittest.main()
