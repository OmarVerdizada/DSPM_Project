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
  scan goes on. One deleted after the change list was read is simply not in the scan;
  one Graph throttles (429) or cannot serve (5xx) is asked for again a few times, as
  long as Graph says to wait, and if it still cannot be read the scan is not complete;
- **delta checkpoints and delete parity**: the checkpoint holds the delta link, the
  library's folders (name and parent) and what each file was (name, parent folder, size,
  modified time). Graph's change list names an item's parent by id, never by path, and a
  renamed folder comes back without its contents - so a file's path is built from its
  parent folders each scan, and a rename moves everything under it. An incremental scan
  rebuilds the library from the checkpoint plus the changes: an unchanged file is offered
  to the engine's reuse (no download), a changed or new one is read, and a deleted one
  is simply absent - so the inventory ends where a full scan would have left it. A scan
  that stopped at its file cap says so, and is then not complete: nothing it did not
  reach is pruned. A delta link Graph no longer honours (410) is dropped and the library
  read again from the start in the same scan.

Every call goes through backend.outbound: https only, the name resolved once and pinned,
TLS verified, no redirect followed. The file content comes from the item's pre-signed
download URL on the tenant's SharePoint host, asked for just before the download: such a
link is valid for about an hour, and a long scan outlives one taken from the change list.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import PurePosixPath
from urllib.parse import quote, urlencode, urlsplit

from backend.outbound import OutboundRefused, https_request
from discovery.incremental import snapshot_is_failed_read

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
MAX_DELTA_PAGES = 10_000
# A delta page holds up to a few hundred items; this is far above one and still bounded.
GRAPH_PAGE_MAX_BYTES = 16 * 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 60.0
# Throttling (429) and a service briefly unavailable (5xx) are asked again this many
# times, waiting what Graph's Retry-After says - never longer than the cap, so one file
# cannot hold the scan for as long as the server likes.
MAX_RETRIES = 3
RETRY_WAIT_CAP_SECONDS = 30.0
# The checkpoint's shape. Version 1 kept a path per file, taken from a parentReference.path
# real delta answers never carry; such a checkpoint is read again in full (see scan()).
CHECKPOINT_VERSION = 2

# Read at call time, so a test can watch the waits without making them.
_sleep = time.sleep


class GraphScanError(RuntimeError):
    """A Graph source that cannot be scanned. `str()` is safe to show."""

    client_safe = True


class _ResyncRequired(GraphScanError):
    """Graph no longer honours the delta link (410): the library must be read from the start."""


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


def _retry_after(value, attempt: int) -> float:
    """Seconds to wait before asking again: what the server said (Retry-After, in seconds
    or as a date), else 1, 2, 4 s - never more than the cap."""
    seconds = float(2 ** attempt)
    text = str(value or "").strip()
    if text:
        try:
            seconds = float(text)
        except ValueError:
            try:
                seconds = (parsedate_to_datetime(text) - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError, IndexError):
                pass
    if not math.isfinite(seconds):
        seconds = RETRY_WAIT_CAP_SECONDS
    return min(max(seconds, 0.0), RETRY_WAIT_CAP_SECONDS)


class GraphClient:
    def __init__(self, source: GraphSource, cancel_check=None) -> None:
        self.source = source
        self.cancel_check = cancel_check
        self._token = ""
        self._expires = 0.0

    def _wait(self, seconds: float) -> bool:
        """Wait `seconds`, or less if the scan is cancelled or runs out of time meanwhile
        (then False)."""
        end = time.monotonic() + seconds
        while True:
            if self.cancel_check and self.cancel_check():
                return False
            left = end - time.monotonic()
            if left <= 0:
                return True
            _sleep(min(left, 0.5))

    def _send(self, method: str, url: str, **kwargs) -> tuple[int, bytes]:
        """One call, asked again while the answer is 429 or 5xx, a bounded number of times.
        The last answer is returned whatever it was; the caller decides what it means."""
        for attempt in range(MAX_RETRIES + 1):
            answer: dict = {}
            status, body = https_request(method, url, response_headers=answer, **kwargs)
            if (status != 429 and status < 500) or attempt == MAX_RETRIES:
                break
            if not self._wait(_retry_after(answer.get("retry-after"), attempt)):
                break
        return status, body

    def token(self) -> str:
        if self._token and time.time() < self._expires - 60:
            return self._token
        form = urlencode({"client_id": self.source.client_id, "client_secret": self.source.client_secret,
                          "scope": GRAPH_SCOPE, "grant_type": "client_credentials"}).encode("ascii")
        url = f"{self.source.authority.rstrip('/')}/{quote(self.source.tenant)}/oauth2/v2.0/token"
        status, body = self._send("POST", url, body=form, ca_pem=self.source.ca_pem,
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

    def _get(self, url_or_path: str) -> tuple[int, bytes]:
        url = url_or_path if url_or_path.startswith("https:") else f"{self.source.graph.rstrip('/')}/v1.0{url_or_path}"
        allowed = urlsplit(self.source.graph).hostname
        if urlsplit(url).hostname != allowed:
            raise GraphScanError("Graph answered with a link to another host; it is not followed.")
        return self._send("GET", url, ca_pem=self.source.ca_pem, max_bytes=GRAPH_PAGE_MAX_BYTES,
                          headers={"Authorization": f"Bearer {self.token()}", "Accept": "application/json"})

    def get(self, url_or_path: str) -> dict:
        status, body = self._get(url_or_path)
        if status == 403:
            raise GraphScanError("The application may not read this site. Grant it Sites.Selected and read on the site.")
        if status == 404:
            raise GraphScanError("The site or library was not found.")
        if status == 410:
            raise _ResyncRequired("Graph no longer honours the library's change link; it must be read again in full.")
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
        """Every document library of the site. The list is paged like any other answer: a
        library on a later page that was not asked for would read as one with no files,
        and a complete scan would prune it."""
        url = f"/sites/{quote(site_id)}/drives"
        drives: list[dict] = []
        for _ in range(MAX_DELTA_PAGES):
            page = self.get(url)
            drives.extend(page.get("value") or [])
            if not page.get("@odata.nextLink"):
                return drives
            url = str(page["@odata.nextLink"])
        raise GraphScanError("The site's list of libraries did not end.")

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
        """The item's pre-signed download link, asked for now, just before it is used."""
        try:
            status, body = self._get(f"/drives/{quote(drive_id)}/items/{quote(item_id)}")
        except GraphScanError as exc:
            # The address is Graph's own, so what failed is the sign-in, part-way through
            # the scan: nothing about this file, and the scan is not complete.
            raise _Interrupted("sign-in failed") from exc
        if status == 404:
            raise _Gone()
        if status == 429 or status >= 500:
            raise _Interrupted(f"HTTP {status}")
        if status != 200:
            raise _Unreadable(f"HTTP {status}")
        try:
            item = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise _Interrupted("an answer that is not complete JSON") from exc
        return str(item.get("@microsoft.graph.downloadUrl") or "") if isinstance(item, dict) else ""

    def download(self, url: str, limit: int) -> bytes:
        """At most `limit` bytes of a file from its pre-signed URL: asked for with a range,
        and read no further whatever the server sends."""
        host = (urlsplit(url).hostname or "").lower()
        if not any(host == allowed or host.endswith("." + allowed) for allowed in self.source.download_hosts):
            raise GraphScanError("A file's download link points outside the tenant's SharePoint; it is not followed.")
        limit = max(1, int(limit))
        status, body = self._send("GET", url, headers={"Range": f"bytes=0-{limit - 1}"}, ca_pem=self.source.ca_pem,
                                  max_bytes=limit, timeout=DOWNLOAD_TIMEOUT_SECONDS)
        if status == 404:
            raise _Gone()
        if status == 429 or status >= 500:
            raise _Interrupted(f"HTTP {status}")
        if status not in (200, 206):
            raise _Unreadable(f"HTTP {status}")
        return body


class _Unreadable(Exception):
    """One file could not be read; the scan reports it and goes on."""


class _Interrupted(_Unreadable):
    """One file was not read because the service did not serve it - throttled past the
    retries, unavailable, the connection or the sign-in lost - not because of anything
    about the file. Reported like any unreadable file, and the scan is not complete."""


class _Gone(Exception):
    """The item was deleted after the change list was read: it is not in the library."""


def _path(drive_name: str, folders: dict, parent: str, name: str) -> str:
    """A file's path in the site, from its parent folders' names in the checkpoint."""
    parts = [name]
    seen: set[str] = set()
    while parent and parent in folders and parent not in seen:
        seen.add(parent)
        folder = folders[parent]
        parts.append(str(folder.get("name") or ""))
        parent = str(folder.get("parent") or "")
    return str(PurePosixPath("/", drive_name, *[part for part in reversed(parts) if part])).replace("\\", "/")


def _stamp(value) -> str:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).isoformat()
    except ValueError:
        return ""


def scan(source: GraphSource, checkpoint: dict | None, *, reuse_probe=None, read_text=None,
         cancel_check=None) -> tuple[list[dict], dict, dict]:
    """(records, the checkpoint to keep, diagnostics). `checkpoint` is the previous scan's
    ({"version", "drives": {drive id: {"link", "folders": {id: {name, parent}},
    "items": {id: {name, parent, size, modified}}}}}), or None for a full scan."""
    client = GraphClient(source, cancel_check)
    try:
        site_id = client.site_id()
        drives = client.drives(site_id)
    except OutboundRefused as exc:
        raise GraphScanError(str(exc)) from exc
    saved = checkpoint or {}
    # A checkpoint of another shape is read again in full - and, like a resync, every file
    # of that enumeration is still offered to reuse, so only what changed is downloaded.
    outdated = bool(saved) and saved.get("version") != CHECKPOINT_VERSION
    previous = {} if outdated else (saved.get("drives") or {})
    kept: dict = {"version": CHECKPOINT_VERSION, "site": source.site, "drives": {}}
    records: list[dict] = []
    diagnostics = {"mode": "sharepoint", "site": source.site, "drives": len(drives), "incremental": bool(previous),
                   "changed": 0, "deleted": 0, "downloaded": 0, "reused": 0, "skipped_extension": 0,
                   "gone": 0, "resynced": 0, "unreadable": [], "scan_errors": [], "record_limit_reached": False}
    allowed = {item.lower().lstrip(".") for item in source.allowed_extensions or []}
    host = source.site.split(":", 1)[0]

    def stopped() -> bool:
        if diagnostics.get("scan_aborted_reason"):
            return True
        if cancel_check and cancel_check():
            diagnostics["scan_aborted_reason"] = "cancelled"
            return True
        return False

    for position, drive in enumerate(drives):
        drive_id, drive_name = str(drive.get("id")), str(drive.get("name") or "Documents")
        state = previous.get(drive_id) or {}
        reenumerated = outdated
        try:
            try:
                changes, link = client.delta(drive_id, str(state.get("link") or ""))
            except _ResyncRequired:
                if not state.get("link"):
                    raise
                # Graph keeps a delta link only so long. Past that it answers 410, and the
                # library is read again from the start here - not left failing every
                # incremental scan until someone asks for a full one.
                diagnostics["resynced"] += 1
                state, reenumerated = {}, True
                changes, link = client.delta(drive_id, "")
        except OutboundRefused as exc:
            raise GraphScanError(str(exc)) from exc
        folders = dict(state.get("folders") or {})
        items = dict(state.get("items") or {})
        changed: set[str] = set()
        for item in changes:
            item_id = str(item.get("id") or "")
            if not item_id:
                continue
            if item.get("deleted") is not None:
                folders.pop(item_id, None)
                if items.pop(item_id, None) is not None:
                    diagnostics["deleted"] += 1
                continue
            parent = str((item.get("parentReference") or {}).get("id") or "")
            if item.get("root") is not None:
                folders[item_id] = {"name": "", "parent": ""}
                continue
            if item.get("folder") is not None or item.get("package") is not None:
                folders[item_id] = {"name": str(item.get("name") or ""), "parent": parent}
                continue
            if item.get("file") is None:
                continue
            diagnostics["changed"] += 1
            changed.add(item_id)
            items[item_id] = {"name": str(item.get("name") or ""), "parent": parent, "size": int(item.get("size") or 0),
                              "modified": _stamp(item.get("lastModifiedDateTime"))}
        kept["drives"][drive_id] = {"link": link, "folders": folders, "items": items}
        for item_id, facts in items.items():
            if stopped():
                # What it did not reach is still in the checkpoint, so the next scan reads it.
                break
            if len(records) >= source.max_files:
                # What it did not reach is still in the checkpoint, so the next scan reads it;
                # this one is not complete, so nothing is pruned for it.
                diagnostics["record_limit_reached"] = True
                break
            site_path = _path(drive_name, folders, str(facts.get("parent") or ""), str(facts.get("name") or ""))
            path = f"sharepoint://{host}{site_path}"
            extension = PurePosixPath(site_path).suffix.lower()
            # The asset is the item, not its path: two files of one name in two folders are
            # two assets, and a file whose folder is renamed is the same asset, moved.
            record = {"source": "sharepoint", "path": path, "name": PurePosixPath(site_path).name,
                      "extension": extension, "size": facts["size"], "modified_at": facts["modified"],
                      "is_dir": False, "content": "", "reuse_key": f"sharepoint|{drive_id}|{item_id}",
                      "stable_object_id": f"{drive_id}|{item_id}"}
            if allowed and extension.lstrip(".") not in allowed:
                diagnostics["skipped_extension"] += 1
                continue
            # Probed by the record's reuse key, the identity the engine keeps its snapshot under.
            snapshot = (reuse_probe(record["reuse_key"], facts["size"], facts["modified"])
                        if reuse_probe and (reenumerated or item_id not in changed) else None)
            if isinstance(snapshot, dict) and not snapshot_is_failed_read(snapshot):
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
                url = client.download_url(drive_id, item_id)
                if not url:
                    raise _Unreadable("no download link")
                data = client.download(url, source.max_read_bytes)
            except _Gone:
                diagnostics["gone"] += 1
                continue
            except (_Unreadable, OutboundRefused) as exc:
                reason = str(exc) if isinstance(exc, _Unreadable) else type(exc).__name__
                record.update({"scan_error": f"not readable ({reason})", "content_status": "unreadable",
                               "content_scannable": False})
                diagnostics["unreadable"].append({"path": site_path, "error": reason})
                if not isinstance(exc, _Unreadable) or isinstance(exc, _Interrupted):
                    diagnostics["scan_errors"].append({"path": site_path, "error": reason})
                records.append(record)
                continue
            diagnostics["downloaded"] += 1
            complete = len(data) >= facts["size"]
            record.update({"content": read_text(data, extension) if read_text else data.decode("utf-8", "replace"),
                           "bytes_scanned": len(data), "total_bytes": facts["size"],
                           "sha256": hashlib.sha256(data).hexdigest() if complete else "",
                           "scan_completeness": "COMPLETE" if complete else "PARTIAL", "truncated": not complete})
            records.append(record)
        if diagnostics.get("scan_aborted_reason"):
            # The libraries not reached keep their checkpoint, so the next scan resumes them.
            for rest in drives[position + 1:]:
                rest_id = str(rest.get("id"))
                if rest_id in previous:
                    kept["drives"][rest_id] = previous[rest_id]
            break
    diagnostics["records"] = len(records)
    return records, kept, diagnostics
