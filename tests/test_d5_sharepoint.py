"""D5: SharePoint Online / OneDrive through Microsoft Graph, with delta checkpoints.

Gate line: "Site collection initial and incremental scans complete with masking, scoped
auth and delete parity." Against a local Graph over HTTPS (a private CA): the client-
credentials token, the site and its libraries, delta pages with a next link and a delta
link, deleted items, and pre-signed downloads honouring Range. A pilot's tenant is the
live half: HELD.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient

from backend import outbound, security, store
from backend.app import app
from collectors import graph_scanner
from tests.test_siem_forwarding import _private_ca

PASSWORD = "Kestrel-lantern-4471"
SECRET = "graph-app-secret-test-only-91"
CARD = "4111 1111 1111 1111"


class FakeGraph:
    """Token endpoint, Graph and a download host, all one HTTPS server on localhost."""

    def __init__(self, certfile: Path, keyfile: Path) -> None:
        self.files: dict[str, dict] = {}
        self.deleted: set[str] = set()
        self.changed_since: dict[str, set[str]] = {}
        self.cursor = 0
        self.token_requests: list[dict] = []
        self.downloads: list[str] = []
        self.ranges: list[str] = []
        self.forbidden = False
        self.redirect_download = ""
        self.ignore_range = False          # a download host that sends the whole file anyway
        self.gone: set[str] = set()        # items whose download answers 404
        self.next_link_host = ""           # a next link pointing at another host
        self.drop_delta_link = False       # a change list that ends without a delta link
        self.garbage_drives = False        # an answer that is not JSON
        graph = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:
                pass

            def reply(self, status: int, payload=None, raw: bytes | None = None) -> None:
                data = raw if raw is not None else json.dumps(payload or {}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json" if raw is None else "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                graph.token_requests.append({key: values[0] for key, values in parse_qs(body).items()})
                form = graph.token_requests[-1]
                if form.get("client_secret") != SECRET or form.get("grant_type") != "client_credentials":
                    return self.reply(401, {"error": "invalid_client"})
                self.reply(200, {"access_token": "graph-token-1", "expires_in": 3600})

            def do_GET(self) -> None:
                parts = urlsplit(self.path)
                if parts.path.startswith("/download/"):
                    item_id = parts.path.rsplit("/", 1)[1]
                    if item_id in graph.gone:
                        return self.reply(404)
                    item = graph.files[item_id]
                    graph.downloads.append(item["name"])
                    graph.ranges.append(self.headers.get("Range", ""))
                    start, end = 0, len(item["content"]) - 1
                    if self.headers.get("Range", "").startswith("bytes=") and not graph.ignore_range:
                        start, end = (int(value) for value in self.headers["Range"][6:].split("-"))
                    chunk = item["content"][start:end + 1]
                    return self.reply(206 if len(chunk) < len(item["content"]) else 200, raw=chunk)
                if self.headers.get("Authorization") != "Bearer graph-token-1":
                    return self.reply(401)
                if graph.forbidden:
                    return self.reply(403)
                if parts.path == "/v1.0/sites/contoso.test:/sites/Finance":
                    return self.reply(200, {"id": "site-1"})
                if parts.path == "/v1.0/sites/site-1/drives":
                    if graph.garbage_drives:
                        return self.reply(200, raw=b"<html>maintenance</html>")
                    return self.reply(200, {"value": [{"id": "drive-1", "name": "Documents"}]})
                if parts.path == "/v1.0/drives/drive-1/root/delta":
                    token = parse_qs(parts.query).get("token", [""])[0]
                    return self.reply(200, graph.delta(token))
                if parts.path.startswith("/v1.0/drives/drive-1/items/"):
                    item_id = parts.path.rsplit("/", 1)[1]
                    return self.reply(200, graph.item(item_id))
                self.reply(404)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.base = f"https://localhost:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def put(self, item_id: str, name: str, content: bytes, folder: str = "") -> None:
        self.cursor += 1
        self.files[item_id] = {"name": name, "content": content, "folder": folder, "version": self.cursor}

    def item(self, item_id: str) -> dict:
        item = self.files[item_id]
        return {"id": item_id, "name": item["name"], "size": len(item["content"]), "file": {},
                "lastModifiedDateTime": f"2026-09-29T00:00:{item['version']:02d}Z",
                "parentReference": {"path": f"/drive/root:{item['folder']}"},
                "@microsoft.graph.downloadUrl": self.redirect_download or f"{self.base}/download/{item_id}"}

    def delta(self, token: str) -> dict:
        since = int(token or 0)
        changed = [self.item(item_id) for item_id, item in self.files.items() if item["version"] > since]
        gone = [{"id": item_id, "deleted": {"state": "deleted"}} for item_id in self.deleted if since]
        values = changed + gone
        # One page per two items, to exercise the next link.
        if len(values) > 2 and not getattr(self, "_second_page", False):
            self._second_page = True
            self._rest = values[2:]
            host = self.next_link_host or self.base
            return {"value": values[:2], "@odata.nextLink": f"{host}/v1.0/drives/drive-1/root/delta?token={since}&page=2"}
        if getattr(self, "_second_page", False):
            self._second_page = False
            values = self._rest
        if self.drop_delta_link:
            return {"value": values}
        return {"value": values, "@odata.deltaLink": f"{self.base}/v1.0/drives/drive-1/root/delta?token={self.cursor}"}

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class D5Case(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.certs = Path(tempfile.mkdtemp())
        cls.ca, cls.cert, cls.key = _private_ca(cls.certs)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.certs, ignore_errors=True)

    def setUp(self) -> None:
        self.graph = FakeGraph(self.cert, self.key)
        self.addCleanup(self.graph.stop)
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        original = store.DB_PATH
        store.DB_PATH = self.tmp / "d5.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        store.create_tenant("t-d5", "t-d5")
        store.create_user("d5-admin", security.hash_password(PASSWORD), "admin", "t-d5")
        store.create_user("d5-viewer", security.hash_password(PASSWORD), "viewer", "t-d5")
        for patcher in (
                mock.patch.object(outbound, "_allow_loopback", return_value=True),
                mock.patch("backend.app._validate_scan_target"),
                mock.patch.dict(os.environ, {"DSPM_GRAPH_AUTHORITY": self.graph.base, "DSPM_GRAPH_ENDPOINT": self.graph.base,
                                             "DSPM_GRAPH_CA_FILE": str(self.ca), "DSPM_GRAPH_DOWNLOAD_HOSTS": "localhost",
                                             "DSPM_SCAN_CACHE_DIR": str(self.tmp / "cache")})):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = TestClient(app)
        self.headers = {"Authorization": f"Bearer {security.create_token('d5-admin', 'admin', 't-d5', mfa_verified=True)}"}
        credential = self.client.post("/api/credentials", headers=self.headers,
                                      json={"username": "11111111-app", "password": SECRET, "domain": "contoso-tenant"})
        self.assertEqual(credential.status_code, 200, credential.text)
        self.ref = credential.json()["credential_ref"]
        self.graph.put("a", "customers.txt", f"Customer card {CARD} exp 12/29\n".encode())
        self.graph.put("b", "contacts.txt", b"Email: ana.mammadova@example.com\n", folder="/HR")
        self.graph.put("c", "notes.txt", b"Nothing sensitive here.\n")

    def scan(self, **extra) -> dict:
        response = self.client.post("/api/sharepoint/scan", headers=self.headers, json={
            "site": "contoso.test:/sites/Finance", "credential_ref": self.ref, "compact_result": False,
            "scan_label": "Finance site", **extra})
        self.assertEqual(response.status_code, 200, response.text[:400])
        return response.json()

    def inventory_paths(self) -> set[str]:
        items = self.client.get("/api/inventory?limit=200", headers=self.headers).json()["items"]
        return {item["path"] for item in items}


class TheInitialScanTest(D5Case):

    def test_every_file_is_read_with_masked_findings_and_scoped_auth(self) -> None:
        report = self.scan()
        paths = {entry["path"]: entry for entry in report["files"]}
        self.assertEqual(sorted(paths), ["sharepoint://contoso.test/Documents/HR/contacts.txt",
                                         "sharepoint://contoso.test/Documents/customers.txt",
                                         "sharepoint://contoso.test/Documents/notes.txt"])
        self.assertTrue(paths["sharepoint://contoso.test/Documents/customers.txt"]["findings"])
        self.assertEqual(paths["sharepoint://contoso.test/Documents/notes.txt"]["findings"], [])
        self.assertEqual(self.graph.token_requests[0]["scope"], "https://graph.microsoft.com/.default")
        self.assertEqual(self.graph.token_requests[0]["grant_type"], "client_credentials")
        text = json.dumps(report) + json.dumps(store.read_audit_log("t-d5", 50))
        self.assertNotIn(CARD.replace(" ", ""), text.replace(" ", ""))
        self.assertNotIn(SECRET, text)
        self.assertIsNotNone(store.get_source_checkpoint("t-d5", "sharepoint:contoso.test:/sites/finance"))

    def test_a_site_the_application_may_not_read_says_what_to_grant(self) -> None:
        self.graph.forbidden = True
        response = self.client.post("/api/sharepoint/scan", headers=self.headers,
                                    json={"site": "contoso.test:/sites/Finance", "credential_ref": self.ref})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Sites.Selected", response.json()["detail"])

    def test_a_download_link_to_another_host_is_not_followed(self) -> None:
        self.graph.redirect_download = "https://attacker.test/steal"
        response = self.client.post("/api/sharepoint/scan", headers=self.headers,
                                    json={"site": "contoso.test:/sites/Finance", "credential_ref": self.ref})
        self.assertEqual(response.status_code, 400)
        self.assertIn("outside the tenant", response.json()["detail"])

    def test_a_long_file_is_read_with_a_range_and_marked_partial(self) -> None:
        self.graph.put("big", "export.txt", b"x" * 200_000 + f" {CARD}".encode())
        with mock.patch.object(graph_scanner.GraphSource, "__init__", _small_reads(graph_scanner.GraphSource.__init__)):
            report = self.scan()
        entry = next(item for item in report["files"] if item["path"].endswith("export.txt"))
        self.assertEqual((entry["scan_completeness"], entry["bytes_scanned"]), ("PARTIAL", 65536))
        self.assertIn("bytes=0-65535", self.graph.ranges)

    def test_a_file_larger_than_one_answer_is_read_whole(self) -> None:
        # Past the 64 KB an outbound call reads by default: read to the scan's text limit,
        # COMPLETE, and hashed over every byte - not cut at 64 KB and called complete.
        content = b"y" * 300_000 + f" {CARD}\n".encode()
        self.graph.put("large", "ledger.txt", content)
        entry = next(item for item in self.scan()["files"] if item["path"].endswith("ledger.txt"))
        self.assertEqual((entry["scan_completeness"], entry["bytes_scanned"]), ("COMPLETE", len(content)))
        self.assertEqual(entry["sha256"], hashlib.sha256(content).hexdigest())
        self.assertTrue(entry["findings"], "the card after the first 64 KB is found")

    def test_a_host_that_ignores_the_range_is_cut_at_the_limit(self) -> None:
        self.graph.ignore_range = True
        self.graph.put("big", "export.txt", b"x" * 200_000)
        with mock.patch.object(graph_scanner.GraphSource, "__init__", _small_reads(graph_scanner.GraphSource.__init__)):
            report = self.scan()
        entry = next(item for item in report["files"] if item["path"].endswith("export.txt"))
        self.assertEqual((entry["scan_completeness"], entry["bytes_scanned"]), ("PARTIAL", 65536))

    def test_a_file_that_cannot_be_read_is_reported_and_the_scan_goes_on(self) -> None:
        self.graph.gone.add("c")
        report = self.scan()
        entries = {item["path"].rsplit("/", 1)[1]: item for item in report["files"]}
        self.assertEqual(sorted(entries), ["contacts.txt", "customers.txt", "notes.txt"])
        self.assertEqual(entries["notes.txt"]["content_status"], "unreadable")
        self.assertTrue(entries["customers.txt"]["findings"])
        self.assertEqual(report["scan_diagnostics"]["unreadable"], [{"path": "/Documents/notes.txt", "error": "HTTP 404"}])

    def test_the_file_cap_leaves_the_scan_incomplete_so_nothing_is_pruned(self) -> None:
        self.scan()
        with mock.patch.object(graph_scanner.GraphSource, "__init__", _capped(graph_scanner.GraphSource.__init__, 1)):
            report = self.scan(full=True)
        self.assertTrue(report["scan_diagnostics"]["record_limit_reached"])
        self.assertFalse(report["scan_diagnostics"]["incremental"]["complete"])
        self.assertEqual(len(self.inventory_paths()), 3, "the two files past the cap are still in the inventory")

    def test_only_a_scanner_may_start_it(self) -> None:
        viewer = {"Authorization": f"Bearer {security.create_token('d5-viewer', 'viewer', 't-d5')}"}
        self.assertEqual(self.client.post("/api/sharepoint/scan", headers=viewer,
                                          json={"site": "contoso.test:/sites/Finance", "credential_ref": self.ref}).status_code, 403)


def _small_reads(original):
    def init(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.max_read_bytes = 65536
    return init


def _capped(original, files):
    def init(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.max_files = files
    return init


class TheIncrementalScanTest(D5Case):

    def test_only_changes_are_read_and_a_deleted_file_leaves_the_inventory(self) -> None:
        self.scan()
        self.assertEqual(sorted(self.graph.downloads), ["contacts.txt", "customers.txt", "notes.txt"])
        self.graph.downloads.clear()
        self.graph.put("b", "contacts.txt", b"Email: leyla.aliyeva@example.org\nEmail: ana@example.com\n", folder="/HR")
        self.graph.put("d", "new-hire.txt", f"Card {CARD}\n".encode())
        del self.graph.files["c"]
        self.graph.deleted.add("c")
        report = self.scan()
        self.assertEqual(sorted(self.graph.downloads), ["contacts.txt", "new-hire.txt"], "unchanged customers.txt reused")
        facts = report["scan_diagnostics"]
        self.assertEqual((facts["changed"], facts["deleted"], facts["reused"]), (2, 1, 1))
        self.assertEqual(facts["incremental"]["sidecar_hits"], 1, "the unchanged file came from the local cache")
        self.assertEqual(sorted(entry["path"].rsplit("/", 1)[1] for entry in report["files"]),
                         ["contacts.txt", "customers.txt", "new-hire.txt"])
        paths = self.inventory_paths()
        self.assertNotIn("sharepoint://contoso.test/Documents/notes.txt", paths, "the deleted file is gone, as a full scan would leave it")
        self.assertIn("sharepoint://contoso.test/Documents/new-hire.txt", paths)

    def test_a_full_scan_ignores_the_checkpoint(self) -> None:
        self.scan()
        self.graph.downloads.clear()
        self.scan(full=True)
        self.assertEqual(sorted(self.graph.downloads), ["contacts.txt", "customers.txt", "notes.txt"])

    def test_a_failed_scan_does_not_move_the_checkpoint(self) -> None:
        self.scan()
        before = store.get_source_checkpoint("t-d5", "sharepoint:contoso.test:/sites/finance")
        self.graph.put("e", "later.txt", b"later\n")
        self.graph.forbidden = True
        self.client.post("/api/sharepoint/scan", headers=self.headers,
                         json={"site": "contoso.test:/sites/Finance", "credential_ref": self.ref})
        self.assertEqual(store.get_source_checkpoint("t-d5", "sharepoint:contoso.test:/sites/finance"), before)


class TheGuardsTest(D5Case):
    """What is refused before the tenant is asked anything, and what Graph may not steer."""

    def post(self):
        return self.client.post("/api/sharepoint/scan", headers=self.headers,
                                json={"site": "contoso.test:/sites/Finance", "credential_ref": self.ref})

    def test_the_site_must_be_in_scope_and_a_required_licence_held(self) -> None:
        from fastapi import HTTPException

        with mock.patch("backend.app._validate_scan_target", side_effect=HTTPException(status_code=403, detail="scope")):
            self.assertEqual(self.post().status_code, 403)
        with mock.patch.dict(os.environ, {"DSPM_LICENCE_REQUIRED": "1"}):
            self.assertEqual(self.post().status_code, 402)
        self.assertEqual(self.graph.token_requests, [], "nothing was asked of the tenant")

    def test_a_next_link_to_another_host_is_not_followed(self) -> None:
        self.graph.next_link_host = "https://attacker.test"
        response = self.post()
        self.assertEqual(response.status_code, 400)
        self.assertIn("another host", response.json()["detail"])

    def test_a_change_list_without_a_delta_link_is_an_error_and_keeps_no_checkpoint(self) -> None:
        self.graph.drop_delta_link = True
        response = self.post()
        self.assertEqual(response.status_code, 400)
        self.assertIn("without a delta link", response.json()["detail"])
        self.assertIsNone(store.get_source_checkpoint("t-d5", "sharepoint:contoso.test:/sites/finance"))

    def test_an_answer_that_is_not_json_is_an_error_not_an_empty_site(self) -> None:
        self.graph.garbage_drives = True
        response = self.post()
        self.assertEqual(response.status_code, 400)
        self.assertIn("not complete JSON", response.json()["detail"])


class TheDurableReuseTest(D5Case):

    def test_reuse_survives_a_lost_scan_cache(self) -> None:
        # The local cache is a fast first look; the durable baseline in the database is
        # what an unchanged file is reused from when it is gone (a new worker, eviction).
        self.scan()
        self.graph.downloads.clear()
        shutil.rmtree(self.tmp / "cache", ignore_errors=True)
        report = self.scan()
        self.assertEqual(self.graph.downloads, [])
        self.assertEqual(report["scan_diagnostics"]["reused"], 3)


if __name__ == "__main__":
    unittest.main()
