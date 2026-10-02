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
import re
import shutil
import ssl
import tempfile
import threading
import time
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
    """Token endpoint, Graph and a download host, all one HTTPS server on localhost.

    The change list answers as real Graph does: an item names its parent folder by id
    (parentReference.id) and never by path, the root and the folders are items of their
    own, and a renamed folder comes back alone, without what is in it."""

    def __init__(self, certfile: Path, keyfile: Path) -> None:
        self.files: dict[str, dict] = {}
        self.folders: dict[str, dict] = {}
        self.drives = [{"id": "drive-1", "name": "Documents"}]
        self.deleted: set[str] = set()
        self.cursor = 0
        self.token_requests: list[dict] = []
        self.downloads: list[str] = []
        self.ranges: list[str] = []
        self.refusals: list[tuple[str, int]] = []   # the queued answers sent, in order
        self.forbidden = False
        self.redirect_download = ""
        self.ignore_range = False          # a download host that sends the whole file anyway
        self.gone: set[str] = set()        # items whose download answers 404
        self.vanished: set[str] = set()    # items Graph answers 404 for: deleted after the change list was read
        self.refused: set[str] = set()     # items whose download answers 403
        self.expire_listed_links = False   # download links taken from the change list have expired
        self.expired_tokens: set[str] = set()  # delta links Graph no longer honours (410)
        self.answers: dict[str, list[tuple[int, dict]]] = {}  # path: answers sent before the real one
        self.page_drives = False           # the site's library list, one library per page
        self.next_link_host = ""           # a next link pointing at another host
        self.drop_delta_link = False       # a change list that ends without a delta link
        self.garbage_drives = False        # an answer that is not JSON
        graph = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:
                pass

            def reply(self, status: int, payload=None, raw: bytes | None = None, headers: dict | None = None) -> None:
                data = raw if raw is not None else json.dumps(payload or {}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json" if raw is None else "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
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
                queued = graph.answers.get(parts.path)
                if queued:
                    status, headers = queued.pop(0)
                    graph.refusals.append((parts.path, status))
                    return self.reply(status, {"error": {"code": "activityLimitReached"}}, headers=headers)
                if parts.path.startswith("/download/"):
                    item_id = parts.path.rsplit("/", 1)[1]
                    if item_id in graph.gone or item_id not in graph.files:
                        return self.reply(404)
                    if item_id in graph.refused:
                        return self.reply(403)
                    if graph.expire_listed_links and "issued=delta" in parts.query:
                        return self.reply(401)
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
                if parts.path.startswith("/v1.0/sites/contoso.test:/sites/"):
                    return self.reply(200, {"id": "site-1"})
                if parts.path == "/v1.0/sites/site-1/drives":
                    if graph.garbage_drives:
                        return self.reply(200, raw=b"<html>maintenance</html>")
                    if not graph.page_drives:
                        return self.reply(200, {"value": graph.drives})
                    page = int(parse_qs(parts.query).get("page", ["0"])[0])
                    more = {"@odata.nextLink": f"{graph.base}/v1.0/sites/site-1/drives?page={page + 1}"}
                    return self.reply(200, {"value": graph.drives[page:page + 1],
                                            **(more if page + 1 < len(graph.drives) else {})})
                found = re.fullmatch(r"/v1\.0/drives/([^/]+)/root/delta", parts.path)
                if found:
                    token = parse_qs(parts.query).get("token", [""])[0]
                    if token in graph.expired_tokens:
                        return self.reply(410, {"error": {"code": "resyncRequired"}})
                    return self.reply(200, graph.delta(found.group(1), token))
                found = re.fullmatch(r"/v1\.0/drives/([^/]+)/items/([^/]+)", parts.path)
                if found:
                    item_id = found.group(2)
                    if item_id in graph.vanished or item_id not in graph.files:
                        return self.reply(404)
                    return self.reply(200, graph.entry(item_id, issued="now"))
                self.reply(404)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.base = f"https://localhost:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def folder(self, path: str, drive: str = "drive-1") -> str:
        """The id of the folder at `path` in `drive`, made (with its parents) when new."""
        parent = f"{drive}-root"
        if parent not in self.folders:
            self.folders[parent] = {"name": "root", "parent": "", "drive": drive, "version": 0, "root": True}
        for name in (part for part in path.split("/") if part):
            found = next((key for key, value in self.folders.items()
                          if value["parent"] == parent and value["name"] == name), None)
            if found is None:
                self.cursor += 1
                found = f"folder-{len(self.folders)}"
                self.folders[found] = {"name": name, "parent": parent, "drive": drive, "version": self.cursor}
            parent = found
        return parent

    def rename_folder(self, folder_id: str, name: str) -> None:
        self.cursor += 1
        self.folders[folder_id].update(name=name, version=self.cursor)

    def put(self, item_id: str, name: str, content: bytes, folder: str = "", drive: str = "drive-1") -> None:
        parent = self.folder(folder, drive)
        self.cursor += 1
        self.files[item_id] = {"name": name, "content": content, "parent": parent, "drive": drive,
                               "version": self.cursor}

    def entry(self, item_id: str, issued: str = "delta") -> dict:
        item = self.files[item_id]
        version = item["version"]
        return {"id": item_id, "name": item["name"], "size": len(item["content"]), "file": {},
                "lastModifiedDateTime": f"2026-09-29T00:{version // 60:02d}:{version % 60:02d}Z",
                "parentReference": {"driveId": item["drive"], "id": item["parent"]},
                "@microsoft.graph.downloadUrl": self.redirect_download or f"{self.base}/download/{item_id}?issued={issued}"}

    def folder_entry(self, folder_id: str) -> dict:
        folder = self.folders[folder_id]
        if folder.get("root"):
            return {"id": folder_id, "name": "root", "root": {}, "folder": {"childCount": 0},
                    "parentReference": {"driveId": folder["drive"]}}
        return {"id": folder_id, "name": folder["name"], "folder": {"childCount": 0},
                "parentReference": {"driveId": folder["drive"], "id": folder["parent"]}}

    def delta(self, drive: str, token: str) -> dict:
        since = int(token or 0)
        files = [self.entry(key) for key, value in self.files.items()
                 if value["drive"] == drive and (not since or value["version"] > since)]
        folders = [self.folder_entry(key) for key, value in self.folders.items()
                   if value["drive"] == drive and (not since or value["version"] > since)]
        gone = [{"id": item_id, "deleted": {"state": "deleted"}} for item_id in self.deleted if since]
        # Files before their folders: Graph does not promise a parent comes first.
        values = files + folders + gone
        # One page per two items, to exercise the next link.
        if len(values) > 2 and not getattr(self, "_second_page", False):
            self._second_page = True
            self._rest = values[2:]
            host = self.next_link_host or self.base
            return {"value": values[:2], "@odata.nextLink": f"{host}/v1.0/drives/{drive}/root/delta?token={since}&page=2"}
        if getattr(self, "_second_page", False):
            self._second_page = False
            values = self._rest
        if self.drop_delta_link:
            return {"value": values}
        return {"value": values, "@odata.deltaLink": f"{self.base}/v1.0/drives/{drive}/root/delta?token={self.cursor}"}

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

    def inventory(self) -> list[dict]:
        return self.client.get("/api/inventory?limit=200", headers=self.headers).json()["items"]

    def inventory_paths(self) -> set[str]:
        return {item["path"] for item in self.inventory()}

    def source(self, **extra) -> graph_scanner.GraphSource:
        """The site as the collector is given it, for a call without the API."""
        return graph_scanner.GraphSource(
            tenant="contoso-tenant", client_id="11111111-app", client_secret=SECRET, site="contoso.test:/sites/Finance",
            authority=self.graph.base, graph=self.graph.base, ca_pem=self.ca.read_text(encoding="utf-8"),
            download_hosts=("localhost",), **extra)

    @staticmethod
    def by_name(report: dict) -> dict[str, dict]:
        return {entry["path"].rsplit("/", 1)[1]: entry for entry in report["files"]}


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
        self.graph.refused.add("c")
        report = self.scan()
        entries = self.by_name(report)
        self.assertEqual(sorted(entries), ["contacts.txt", "customers.txt", "notes.txt"])
        self.assertEqual(entries["notes.txt"]["content_status"], "unreadable")
        self.assertTrue(entries["customers.txt"]["findings"])
        self.assertEqual(report["scan_diagnostics"]["unreadable"], [{"path": "/Documents/notes.txt", "error": "HTTP 403"}])
        self.assertTrue(report["scan_diagnostics"]["incremental"]["complete"], "a refusal is an answer about the file")

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

    def test_a_file_that_could_not_be_read_is_read_again_next_time(self) -> None:
        # Read access granted since changes neither the size nor the modified time: the
        # failure is not replayed from the cache for as long as the file stays unchanged.
        self.graph.refused.add("a")
        self.assertEqual(self.by_name(self.scan())["customers.txt"]["content_status"], "unreadable")
        self.graph.refused.clear()
        self.graph.downloads.clear()
        entry = self.by_name(self.scan())["customers.txt"]
        self.assertEqual(self.graph.downloads, ["customers.txt"])
        self.assertTrue(entry["findings"])

    def test_each_file_is_downloaded_by_a_link_asked_for_just_before(self) -> None:
        # A download link lasts about an hour; one taken from the change list has expired
        # by the time a long scan reaches the file.
        self.graph.expire_listed_links = True
        report = self.scan()
        self.assertEqual(report["scan_diagnostics"]["unreadable"], [])
        self.assertEqual(sorted(self.graph.downloads), ["contacts.txt", "customers.txt", "notes.txt"])
        self.assertTrue(self.by_name(report)["customers.txt"]["findings"])


class ThePathsTest(D5Case):
    """Graph's change list names a file's folder by id, never by path."""

    def test_two_files_of_one_name_in_two_folders_are_two_assets(self) -> None:
        self.graph.put("f1", "budget.txt", f"Card {CARD}\n".encode(), folder="/Finance/2026")
        self.graph.put("f2", "budget.txt", b"Nothing sensitive here.\n", folder="/HR")
        report = self.scan()
        budgets = sorted(entry["path"] for entry in report["files"] if entry["path"].endswith("/budget.txt"))
        self.assertEqual(budgets, ["sharepoint://contoso.test/Documents/Finance/2026/budget.txt",
                                   "sharepoint://contoso.test/Documents/HR/budget.txt"])
        paths = [item["path"] for item in self.inventory()]
        self.assertEqual(len(paths), 5)
        self.assertIn("sharepoint://contoso.test/Documents/Finance/2026/budget.txt", paths)
        self.assertIn("sharepoint://contoso.test/Documents/HR/budget.txt", paths)

    def test_a_renamed_folder_moves_its_files_on_the_next_scan(self) -> None:
        self.graph.put("d", "plan.txt", b"Plan.\n", folder="/HR/2026")
        self.scan()
        before = {item["name"]: item["id"] for item in self.inventory()}
        self.graph.downloads.clear()
        self.graph.rename_folder(self.graph.folder("/HR"), "People")
        report = self.scan()
        self.assertEqual(sorted(entry["path"] for entry in report["files"]), [
            "sharepoint://contoso.test/Documents/People/2026/plan.txt",
            "sharepoint://contoso.test/Documents/People/contacts.txt",
            "sharepoint://contoso.test/Documents/customers.txt",
            "sharepoint://contoso.test/Documents/notes.txt"])
        self.assertEqual(self.graph.downloads, [], "the files did not change: reused, under their new paths")
        paths = self.inventory_paths()
        self.assertIn("sharepoint://contoso.test/Documents/People/contacts.txt", paths)
        self.assertNotIn("sharepoint://contoso.test/Documents/HR/contacts.txt", paths)
        self.assertEqual({item["name"]: item["id"] for item in self.inventory()}, before,
                         "the same assets, moved - not new ones in place of the old")

    def test_a_checkpoint_of_the_old_shape_is_read_again_in_full(self) -> None:
        # Version 1 kept a path per file, from a parentReference.path real Graph never sent.
        self.scan()
        key = "sharepoint:contoso.test:/sites/finance"
        old = store.get_source_checkpoint("t-d5", key)
        old.pop("version")
        for drive in old["drives"].values():
            drive.pop("folders")
            drive["items"] = {item_id: {"path": f"/Documents/{facts['name']}", "size": facts["size"],
                                        "modified": facts["modified"]} for item_id, facts in drive["items"].items()}
        store.save_source_checkpoint("t-d5", key, old)
        self.graph.downloads.clear()
        report = self.scan()
        self.assertIn("sharepoint://contoso.test/Documents/HR/contacts.txt", {entry["path"] for entry in report["files"]})
        self.assertEqual(self.graph.downloads, [], "every file is still offered to reuse")
        self.assertEqual(store.get_source_checkpoint("t-d5", key)["version"], graph_scanner.CHECKPOINT_VERSION)


class TheThrottlingTest(D5Case):
    """A file Graph throttles, cannot serve for a moment, or that was deleted mid-scan."""

    def test_a_throttled_download_waits_as_told_and_is_read(self) -> None:
        self.graph.answers["/download/a"] = [(429, {"Retry-After": "2"})]
        with mock.patch.object(graph_scanner, "_sleep", side_effect=time.sleep) as slept:
            report = self.scan()
        self.assertEqual(self.graph.refusals, [("/download/a", 429)])
        self.assertGreaterEqual(sum(call.args[0] for call in slept.call_args_list), 1.9, "Retry-After honoured")
        self.assertTrue(self.by_name(report)["customers.txt"]["findings"])
        self.assertTrue(report["scan_diagnostics"]["incremental"]["complete"])

    def test_a_moment_of_unavailability_is_asked_again(self) -> None:
        self.graph.answers["/v1.0/drives/drive-1/items/b"] = [(503, {})]
        report = self.scan()
        self.assertEqual(self.graph.refusals, [("/v1.0/drives/drive-1/items/b", 503)])
        self.assertTrue(self.by_name(report)["contacts.txt"]["findings"])
        self.assertEqual(report["scan_diagnostics"]["unreadable"], [])

    def test_a_file_still_throttled_after_the_retries_leaves_the_scan_incomplete(self) -> None:
        self.graph.answers["/download/a"] = [(429, {"Retry-After": "0"})] * 10
        report = self.scan()
        facts = report["scan_diagnostics"]
        self.assertEqual(len(self.graph.refusals), graph_scanner.MAX_RETRIES + 1, "asked again a bounded number of times")
        self.assertEqual(self.by_name(report)["customers.txt"]["content_status"], "unreadable")
        self.assertEqual(facts["scan_errors"], [{"path": "/Documents/customers.txt", "error": "HTTP 429"}])
        self.assertFalse(facts["incremental"]["complete"], "so nothing is pruned for it")
        self.assertEqual(self.by_name(report)["notes.txt"]["scan_completeness"], "COMPLETE", "the rest was read")
        self.assertIsNotNone(store.get_source_checkpoint("t-d5", "sharepoint:contoso.test:/sites/finance"))

    def test_a_file_deleted_after_the_change_list_was_read_is_not_in_the_scan(self) -> None:
        self.graph.vanished.add("b")   # Graph no longer knows the item
        self.graph.gone.add("c")       # its download link answers 404
        report = self.scan()
        facts = report["scan_diagnostics"]
        self.assertEqual(sorted(self.by_name(report)), ["customers.txt"])
        self.assertEqual((facts["gone"], facts["unreadable"]), (2, []))
        self.assertTrue(facts["incremental"]["complete"])

    def test_a_cancelled_scan_does_not_wait_out_a_retry_after(self) -> None:
        self.graph.answers["/download/a"] = [(429, {"Retry-After": "15"})] * 5
        started = time.monotonic()
        records, _, facts = graph_scanner.scan(self.source(), None, cancel_check=lambda: bool(self.graph.refusals))
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(facts["scan_aborted_reason"], "cancelled")
        self.assertEqual([record["content_status"] for record in records], ["unreadable"])

    def test_retry_after_is_read_in_seconds_or_as_a_date_and_capped(self) -> None:
        self.assertEqual(graph_scanner._retry_after("2", 0), 2.0)
        self.assertEqual(graph_scanner._retry_after("86400", 0), graph_scanner.RETRY_WAIT_CAP_SECONDS)
        self.assertEqual(graph_scanner._retry_after("Wed, 21 Oct 2015 07:28:00 GMT", 0), 0.0)
        self.assertEqual(graph_scanner._retry_after("", 2), 4.0)
        self.assertEqual(graph_scanner._retry_after("nan", 0), graph_scanner.RETRY_WAIT_CAP_SECONDS)


class TheLibrariesTest(D5Case):

    def test_an_expired_delta_link_reads_the_library_again_in_the_same_scan(self) -> None:
        self.scan()
        self.graph.expired_tokens.add(str(self.graph.cursor))
        self.graph.downloads.clear()
        self.graph.put("b", "contacts.txt", b"Email: leyla.aliyeva@example.org\n", folder="/HR")
        del self.graph.files["c"]   # deleted while the link was stale: absent from the full list
        report = self.scan()
        facts = report["scan_diagnostics"]
        self.assertEqual(facts["resynced"], 1)
        self.assertEqual(self.graph.downloads, ["contacts.txt"], "what did not change is still reused")
        self.assertNotIn("sharepoint://contoso.test/Documents/notes.txt", self.inventory_paths())
        self.graph.downloads.clear()
        again = self.scan()
        self.assertEqual((again["scan_diagnostics"]["resynced"], self.graph.downloads), (0, []),
                         "the next scan goes on from the new link")

    def test_every_library_of_a_paged_list_is_read(self) -> None:
        self.graph.drives.append({"id": "drive-2", "name": "Archive"})
        self.graph.page_drives = True
        self.graph.put("z", "old-cards.txt", f"Card {CARD}\n".encode(), drive="drive-2")
        report = self.scan()
        self.assertEqual(report["scan_diagnostics"]["drives"], 2)
        self.assertIn("sharepoint://contoso.test/Archive/old-cards.txt", {entry["path"] for entry in report["files"]})


class TheScopeTest(D5Case):
    """A scan given no name is named for what it sees, and prunes only that."""

    def test_a_scan_with_an_extension_filter_does_not_prune_other_types(self) -> None:
        self.graph.put("e", "ledger.csv", b"id,amount\n1,10\n")
        self.scan(scan_label="")
        self.scan(scan_label="", allowed_extensions=["txt"], extension_filter_enabled=True)
        self.assertIn("sharepoint://contoso.test/Documents/ledger.csv", self.inventory_paths())

    def test_two_long_site_addresses_are_two_scopes(self) -> None:
        site = "contoso.test:/sites/" + "finance-department-records-" * 4
        for name in ("east", "west"):
            response = self.client.post("/api/sharepoint/scan", headers=self.headers,
                                        json={"site": site + name, "credential_ref": self.ref})
            self.assertEqual(response.status_code, 200, response.text[:400])
        self.assertEqual(len(self.inventory()), 6, "the second site's scan did not prune the first's files")


if __name__ == "__main__":
    unittest.main()
