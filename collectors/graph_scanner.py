"""SharePoint Online and OneDrive through Microsoft Graph (D5).

A site's document libraries are read with Graph's delta query, so the first scan lists
every file and each later one asks only what changed since the last - files added,
changed or deleted - from the checkpoint the previous scan kept:

- **scoped auth**: an Entra application with the client-credentials grant, the secret
  sealed in the vault (a saved credential: application id as the user name, the secret as
  the password, the Entra tenant as the domain). Grant it `Sites.Selected` and give it
  read on the sites it may scan - nothing wider is needed or asked for;
- **the bounded record contract**: a file is read up to the scan's text limit with an
  HTTP range request, never more whatever the server sends, and one longer than that is
  PARTIAL like any other truncated file; only files the extension policy admits are
  downloaded at all. A file that cannot be read is reported as such, and the rest of the
  scan goes on;
- **delta checkpoints and delete parity**: the checkpoint holds the delta link and what
  each file was (path, size, modified time). An incremental scan rebuilds the library
  from it plus the changes: an unchanged file is offered to the engine's reuse (no
  download), a changed or new one is read, and a deleted one is simply absent - so the
  inventory ends where a full scan would have left it. A scan that stopped at its file
  cap says so, and is then not complete: nothing it did not reach is pruned.

Every call goes through backend.outbound: https only, the name resolved once and pinned,
TLS verified, no redirect followed. The file content comes from the item's pre-signed
download URL on the tenant's SharePoint host.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import PurePosixPath
from urllib.parse import quote, urlencode, urlsplit

from backend.outbound import OutboundRefused, https_request

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
MAX_DELTA_PAGES = 10_000
# A delta page holds up to a few hundred items; this is far above one and still bounded.
GRAPH_PAGE_MAX_BYTES = 16 * 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 60.0


class GraphScanError(RuntimeError):
    """A Graph source that cannot be scanned. `str()` is safe to show."""

    client_safe = True


@dataclass
class GraphSource:
    tenant: str            # the Entra tenant (id or domain)
    client_id: str
    client_secret: str = field(repr=False)
    site: str              # "contoso.sharepoint.com:/sites/Finance" or a site id
    authority: str = "https://login.microsoftonline.com"
    graph: str = "https://graph.microsoft.com"
    max_read_bytes: int = 5 * 1024 * 1024
    max_files: int = 100_000
    allowed_extensions: list[str] | None = None
    ca_pem: str = ""
    # The hosts a file's pre-signed download URL may be on (the tenant's SharePoint).
    download_hosts: tuple[str, ...] = ("sharepoint.com", "sharepoint.us", "sharepoint.de", "sharepoint.cn")


class GraphClient:
    def __init__(self, source: GraphSource) -> None:
        self.source = source
        self._token = ""
        self._expires = 0.0

    def token(self) -> str:
        if self._token and time.time() < self._expires - 60:
            return self._token
        form = urlencode({"client_id": self.source.client_id, "client_secret": self.source.client_secret,
                          "scope": GRAPH_SCOPE, "grant_type": "client_credentials"}).encode("ascii")
        url = f"{self.source.authority.rstrip('/')}/{quote(self.source.tenant)}/oauth2/v2.0/token"
        status, body = https_request("POST", url, body=form, ca_pem=self.source.ca_pem,
                                     headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
        try:
            document = json.loads(body.decode("utf-8") or "{}")
        except (UnicodeDecodeError, ValueError):
            document = {}
        if status != 200 or not isinstance(document, dict) or not document.get("access_token"):
            raise GraphScanError(f"The Entra tenant refused the application's sign-in (HTTP {status}): check the "
                                 "application id, its secret, and the tenant.")
        self._token = str(document["access_token"])
        self._expires = time.time() + int(document.get("expires_in") or 3600)
        return self._token

    def get(self, url_or_path: str) -> dict:
        url = url_or_path if url_or_path.startswith("https:") else f"{self.source.graph.rstrip('/')}/v1.0{url_or_path}"
        allowed = urlsplit(self.source.graph).hostname
        if urlsplit(url).hostname != allowed:
            raise GraphScanError("Graph answered with a link to another host; it is not followed.")
        status, body = https_request("GET", url, ca_pem=self.source.ca_pem, max_bytes=GRAPH_PAGE_MAX_BYTES,
                                     headers={"Authorization": f"Bearer {self.token()}", "Accept": "application/json"})
        if status == 403:
            raise GraphScanError("The application may not read this site. Grant it Sites.Selected and read on the site.")
        if status == 404:
            raise GraphScanError("The site or library was not found.")
        if status != 200:
            raise GraphScanError(f"Graph answered HTTP {status}.")
        # Parsed here, not through https_json: an answer that is not whole JSON is an error,
        # never an empty page that would read as "nothing changed".
        try:
            document = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise GraphScanError("Graph sent an answer that is not complete JSON.") from exc
        if not isinstance(document, dict):
            raise GraphScanError("Graph sent an answer that is not complete JSON.")
        return document

    def site_id(self) -> str:
        site = self.source.site.strip()
        if ":" in site and "/" in site:
            host, _, path = site.partition(":")
            return str(self.get(f"/sites/{quote(host)}:{quote(path)}").get("id") or "")
        return str(self.get(f"/sites/{quote(site)}").get("id") or site)

    def drives(self, site_id: str) -> list[dict]:
        return list(self.get(f"/sites/{quote(site_id)}/drives").get("value") or [])

    def delta(self, drive_id: str, link: str = "") -> tuple[list[dict], str]:
        """Every change since `link` (or everything), and the next delta link."""
        url = link or f"/drives/{quote(drive_id)}/root/delta"
        items: list[dict] = []
        for _ in range(MAX_DELTA_PAGES):
            page = self.get(url)
            items.extend(page.get("value") or [])
            if page.get("@odata.nextLink"):
                url = str(page["@odata.nextLink"])
                continue
            if not page.get("@odata.deltaLink"):
                raise GraphScanError("The library's change list ended without a delta link.")
            return items, str(page["@odata.deltaLink"])
        raise GraphScanError("The library's change list did not end.")

    def download_url(self, drive_id: str, item_id: str) -> str:
        item = self.get(f"/drives/{quote(drive_id)}/items/{quote(item_id)}")
        return str(item.get("@microsoft.graph.downloadUrl") or "")

    def download(self, url: str, limit: int) -> bytes:
        """At most `limit` bytes of a file from its pre-signed URL: asked for with a range,
        and read no further whatever the server sends."""
        host = (urlsplit(url).hostname or "").lower()
        if not any(host == allowed or host.endswith("." + allowed) for allowed in self.source.download_hosts):
            raise GraphScanError("A file's download link points outside the tenant's SharePoint; it is not followed.")
        limit = max(1, int(limit))
        status, body = https_request("GET", url, headers={"Range": f"bytes=0-{limit - 1}"}, ca_pem=self.source.ca_pem,
                                     max_bytes=limit, timeout=DOWNLOAD_TIMEOUT_SECONDS)
        if status not in (200, 206):
            raise _Unreadable(f"HTTP {status}")
        return body


class _Unreadable(Exception):
    """One file could not be read; the scan reports it and goes on."""


def _path(item: dict, drive_name: str) -> str:
    parent = str((item.get("parentReference") or {}).get("path") or "")
    folder = parent.split("root:", 1)[1] if "root:" in parent else ""
    return str(PurePosixPath("/") / drive_name / folder.strip("/") / str(item.get("name") or "")).replace("\\", "/")


def _stamp(value) -> str:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).isoformat()
    except ValueError:
        return ""


def scan(source: GraphSource, checkpoint: dict | None, *, reuse_probe=None, read_text=None) -> tuple[list[dict], dict, dict]:
    """(records, the checkpoint to keep, diagnostics). `checkpoint` is the previous scan's
    ({drive id: {"link", "items": {id: {path, size, modified}}}}), or None for a full scan."""
    client = GraphClient(source)
    try:
        site_id = client.site_id()
        drives = client.drives(site_id)
    except OutboundRefused as exc:
        raise GraphScanError(str(exc)) from exc
    previous = (checkpoint or {}).get("drives") or {}
    kept: dict = {"site": source.site, "drives": {}}
    records: list[dict] = []
    diagnostics = {"mode": "sharepoint", "site": source.site, "drives": len(drives), "incremental": bool(previous),
                   "changed": 0, "deleted": 0, "downloaded": 0, "reused": 0, "skipped_extension": 0,
                   "unreadable": [], "record_limit_reached": False}
    allowed = {item.lower().lstrip(".") for item in source.allowed_extensions or []}
    host = source.site.split(":", 1)[0]
    for drive in drives:
        drive_id, drive_name = str(drive.get("id")), str(drive.get("name") or "Documents")
        state = previous.get(drive_id) or {}
        try:
            changes, link = client.delta(drive_id, str(state.get("link") or ""))
        except OutboundRefused as exc:
            raise GraphScanError(str(exc)) from exc
        items = dict(state.get("items") or {})
        downloads: dict[str, str] = {}
        for item in changes:
            item_id = str(item.get("id") or "")
            if not item_id:
                continue
            if item.get("deleted") is not None:
                if items.pop(item_id, None) is not None:
                    diagnostics["deleted"] += 1
                continue
            if item.get("file") is None:
                continue
            diagnostics["changed"] += 1
            items[item_id] = {"path": _path(item, drive_name), "size": int(item.get("size") or 0),
                              "modified": _stamp(item.get("lastModifiedDateTime"))}
            if item.get("@microsoft.graph.downloadUrl"):
                downloads[item_id] = str(item["@microsoft.graph.downloadUrl"])
        kept["drives"][drive_id] = {"link": link, "items": items}
        for item_id, facts in items.items():
            if len(records) >= source.max_files:
                # What it did not reach is still in the checkpoint, so the next scan reads it;
                # this one is not complete, so nothing is pruned for it.
                diagnostics["record_limit_reached"] = True
                break
            path = f"sharepoint://{host}{facts['path']}"
            extension = PurePosixPath(facts["path"]).suffix.lower()
            record = {"source": "sharepoint", "path": path, "name": PurePosixPath(facts["path"]).name,
                      "extension": extension, "size": facts["size"], "modified_at": facts["modified"],
                      "is_dir": False, "content": "", "reuse_key": f"sharepoint|{drive_id}|{item_id}"}
            if allowed and extension.lstrip(".") not in allowed:
                diagnostics["skipped_extension"] += 1
                continue
            # Probed by the record's reuse key, the identity the engine keeps its snapshot under.
            snapshot = (reuse_probe(record["reuse_key"], facts["size"], facts["modified"])
                        if reuse_probe and item_id not in downloads else None)
            if isinstance(snapshot, dict):
                # The engine's reuse contract, as the file collectors meet it.
                record.update({
                    "cache_reused": True, "incremental_reused": bool(snapshot.get("baseline_result")),
                    "baseline_result": snapshot.get("baseline_result") if isinstance(snapshot.get("baseline_result"), dict) else None,
                    "content_status": str(snapshot.get("content_status") or "reused_from_cache"),
                    "sha256": str(snapshot.get("sha256") or ""), "content_hash": str(snapshot.get("content_hash") or ""),
                    "scan_completeness": str(snapshot.get("scan_completeness") or "UNKNOWN"),
                    "bytes_scanned": int(snapshot.get("bytes_scanned") or 0),
                    "total_bytes": int(snapshot.get("total_bytes") or facts["size"]),
                    "truncated": bool(snapshot.get("truncated", False)),
                    "reused_preview": snapshot.get("preview") if isinstance(snapshot.get("preview"), dict) else None})
                diagnostics["reused"] += 1
                records.append(record)
                continue
            # Changed, new - or unchanged with nothing to reuse: read it.
            try:
                url = downloads.get(item_id) or client.download_url(drive_id, item_id)
                if not url:
                    raise _Unreadable("no download link")
                data = client.download(url, source.max_read_bytes)
            except (_Unreadable, OutboundRefused) as exc:
                reason = str(exc) if isinstance(exc, _Unreadable) else type(exc).__name__
                record.update({"scan_error": f"not readable ({reason})", "content_status": "unreadable",
                               "content_scannable": False})
                diagnostics["unreadable"].append({"path": facts["path"], "error": reason})
                records.append(record)
                continue
            diagnostics["downloaded"] += 1
            complete = len(data) >= facts["size"]
            record.update({"content": read_text(data, extension) if read_text else data.decode("utf-8", "replace"),
                           "bytes_scanned": len(data), "total_bytes": facts["size"],
                           "sha256": hashlib.sha256(data).hexdigest() if complete else "",
                           "scan_completeness": "COMPLETE" if complete else "PARTIAL", "truncated": not complete})
            records.append(record)
    diagnostics["records"] = len(records)
    return records, kept, diagnostics
