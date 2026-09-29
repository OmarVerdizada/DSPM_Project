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
    """An SMTP relay offering STARTTLS with the private CA's certificate."""

    def __init__(self, certfile: Path, keyfile: Path) -> None:
        self.messages: list[dict] = []
        self.logins: list[str] = []
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
                self.assertEqual(self.configure("webhook", {"url": url}).status_code, 400)

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
