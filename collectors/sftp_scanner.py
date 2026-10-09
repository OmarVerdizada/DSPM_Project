"""Linux and macOS hosts over SSH/SFTP (D9).

Reads a host's files - typically home directories - through SFTP with an ordinary account:
no root, no sudo, no agent installed. What the account may not read is reported, not
escalated around. Each file becomes a record like any other collector's:

    sftp://build01.corp.local/home/alice/notes.txt
    sftp://build01.corp.local:2222/home/alice/notes.txt    (a port other than 22)

- **The host is who it says**: the server's host key must match the SHA-256 fingerprint the
  source names (as `ssh-keygen -lf` prints it). An unknown or changed key is refused -
  there is no trust-on-first-use.
- **Least privilege**: password or private key (sealed in the vault), read-only calls
  (list, stat, open for reading); symbolic links are not followed, so a link cannot walk
  the scan out of the paths it was given.
- **Bounded**: depth, a file count and the text limit a file is read to (a longer one is
  PARTIAL; a document - Office, OpenDocument, PDF - is read whole up to a larger cap of its
  own, since its text is parsed from the whole file), and the extension policy decides
  what is opened. Every answer is waited for
  at most the source's timeout, and the scan's cancel and deadline are asked per file: a
  host that stops answering ends the scan, not complete, instead of holding it.
- **Who can read it**: the mode bits become access entries the D7 analysis reads - the
  owner, the group and, for world-readable files, Everyone (S-1-1-0) - so a world-readable
  key or export is flagged like a share Everyone can read. The group and Everyone count
  only when every folder above the file lets them through (x): a 0644 file in a 0700 home
  folder is not world-readable.
- **Resume**: a scan interrupted part-way is simply run again; the engine's reuse skips
  every file the last run analysed unchanged (path, size, modification time), so only what
  is left, or what changed, is read.

The connection is made to the address the workspace's scan targets allow (resolved once
and pinned, collectors.net_guard).
"""

from __future__ import annotations

import base64
import hashlib
import io
import posixpath
import socket
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone

from collectors.binary_extractor import BINARY_TEXT_EXTENSIONS
from collectors.file_scanner import MAX_ARCHIVE_TOTAL_BYTES
from collectors.text_decode import decode_text
from discovery.incremental import snapshot_is_failed_read

EVERYONE_SID = "S-1-1-0"
_READ, _WRITE = 0o4, 0o2


class SftpScanError(RuntimeError):
    """The host could not be scanned. `str()` is safe to show."""

    client_safe = True


@dataclass
class SftpSource:
    host: str
    username: str
    host_key_fingerprint: str        # "SHA256:..." as ssh-keygen -lf prints it
    password: str = field(default="", repr=False)
    private_key: str = field(default="", repr=False)   # PEM / OpenSSH text
    port: int = 22
    paths: list[str] = field(default_factory=lambda: ["/home"])
    address: str = ""                # the pinned address to dial
    max_depth: int = 8
    max_files: int = 100_000
    max_read_bytes: int = 5 * 1024 * 1024
    # Office, OpenDocument and PDF files are read whole up to this: see scan().
    max_document_bytes: int = MAX_ARCHIVE_TOTAL_BYTES
    allowed_extensions: list[str] | None = None
    include_hidden: bool = True
    timeout: float = 15.0


def fingerprint(key) -> str:
    """A paramiko key's fingerprint, as OpenSSH prints it."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _load_key(text: str):
    import paramiko

    for kind in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return kind.from_private_key(io.StringIO(text))
        except (paramiko.SSHException, ValueError):
            continue
    raise SftpScanError("The private key could not be read (Ed25519, ECDSA or RSA, unencrypted).")


def connect(source: SftpSource):
    """(transport, sftp) after the host key matched and the account signed in."""
    import paramiko

    try:
        # Dialled with a timeout: paramiko's own connect from a (host, port) pair has none.
        sock = socket.create_connection((source.address or source.host, int(source.port)), timeout=source.timeout)
    except OSError as exc:
        raise SftpScanError(f"Could not reach SSH on {source.host}:{source.port} ({type(exc).__name__}).") from exc
    try:
        transport = paramiko.Transport(sock)
        transport.banner_timeout = transport.auth_timeout = source.timeout
        transport.start_client(timeout=source.timeout)
    except (paramiko.SSHException, OSError) as exc:
        sock.close()
        raise SftpScanError(f"Could not reach SSH on {source.host}:{source.port} ({type(exc).__name__}).") from exc
    try:
        offered = fingerprint(transport.get_remote_server_key())
        expected = source.host_key_fingerprint.strip()
        if not expected or offered != expected:
            raise SftpScanError(f"{source.host} presented host key {offered}, not the one this source names; it is "
                                "not signed in to. If the key changed on purpose, update the fingerprint.")
        if source.private_key:
            transport.auth_publickey(source.username, _load_key(source.private_key))
        else:
            transport.auth_password(source.username, source.password)
        if not transport.is_authenticated():
            raise SftpScanError(f"{source.host} refused the account {source.username}.")
        # Keepalives find a connection dropped without a word, and keep a firewall from
        # forgetting a quiet one while a large file is read.
        transport.set_keepalive(max(1, int(source.timeout)))
        sftp = paramiko.SFTPClient.from_transport(transport)
        if sftp is None:
            raise SftpScanError(f"SSH on {source.host}:{source.port} did not open an SFTP session.")
        # Every answer is waited for at most the source's timeout. paramiko waits forever by
        # default, so a hung NFS mount or a silently dropped connection held the scan - and
        # the server worker running it - for as long as it lasted.
        sftp.get_channel().settimeout(source.timeout)
        return transport, sftp
    except paramiko.AuthenticationException as exc:
        transport.close()
        raise SftpScanError(f"{source.host} refused the account {source.username}.") from exc
    except (paramiko.SSHException, OSError) as exc:
        # The server dropped the session during the key exchange or the sign-in.
        transport.close()
        raise SftpScanError(f"SSH on {source.host}:{source.port} closed the session ({type(exc).__name__}).") from exc
    except BaseException:
        transport.close()
        raise


def can_enter(folders: tuple[tuple[int, int | None], ...], gid=None) -> bool:
    """Whether every folder on the way to a file - (mode, gid), from "/" down to its own
    folder - lets others (``gid`` None) or the members of group ``gid`` pass through it
    (the x bit). A file's own bits do not open a folder that is closed: a 0644 file in a
    0700 home folder is read by no one but its owner."""
    for mode, folder_gid in folders:
        if mode & 0o001:
            continue
        if gid is not None and folder_gid == gid and mode & 0o010:
            continue
        return False
    return True


def access(attributes, folders: tuple[tuple[int, int | None], ...] = ()) -> dict:
    """The mode bits as the access entries D7 reads (owner, group, everyone) - the group and
    Everyone only when the folders above the file (see ``can_enter``) let them reach it."""
    mode = int(getattr(attributes, "st_mode", 0) or 0)
    uid, gid = getattr(attributes, "st_uid", None), getattr(attributes, "st_gid", None)
    reaches = {6: True, 3: can_enter(folders, gid), 0: can_enter(folders)}
    entries = []
    for who, sid, shift in ((f"uid:{uid}", f"unix-uid-{uid}", 6), (f"gid:{gid}", f"unix-gid-{gid}", 3),
                            ("Everyone", EVERYONE_SID, 0)):
        if not reaches[shift]:
            continue
        bits = (mode >> shift) & 0o7
        rights = [name for name, flag in (("read", _READ), ("write", _WRITE)) if bits & flag]
        if rights:
            entries.append({"principal": who, "sid": sid, "rights": rights, "type": "allow", "inherited": False,
                            "mask": (0x120089 if "read" in rights else 0) | (0x116 if "write" in rights else 0)})
    return {"owner": f"uid:{uid}", "principals": [entry["principal"] for entry in entries],
            "permissions": [entry["rights"] for entry in entries], "entries": entries, "source": "unix-mode"}


def _stamp(seconds) -> str:
    try:
        return datetime.fromtimestamp(float(seconds), timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return ""


def root_path(path: str) -> str:
    """A path the source names, as the walk starts from it."""
    return posixpath.normpath("/" + str(path).strip().lstrip("/"))


def authority(source: SftpSource) -> str:
    """The host as a location names it: with the port when it is not 22, so two SSH
    servers on one host are two sources, not one."""
    host = f"[{source.host}]" if ":" in source.host else source.host
    return host if int(source.port) == 22 else f"{host}:{int(source.port)}"


def scan(source: SftpSource, *, reuse_probe=None, read_text=None, cancel_check=None, sftp=None) -> tuple[list[dict], dict]:
    """(records, diagnostics) for the source's paths."""
    import paramiko

    transport = None
    if sftp is None:
        transport, sftp = connect(source)
    records: list[dict] = []
    diagnostics = {"mode": "sftp", "host": source.host, "paths": list(source.paths), "directories": 0,
                   "files": 0, "reused": 0, "read": 0, "unreadable": [], "unreadable_dirs": [],
                   "symlinks_skipped": 0, "record_limit_reached": False, "scan_errors": []}
    allowed = {item.lower().lstrip(".") for item in source.allowed_extensions or []}
    prefix = f"sftp://{authority(source)}"
    # The session stopped answering (the channel timeout) or is gone. TimeoutError is an
    # OSError, so these are caught before the OSError that means "may not read this".
    lost = (TimeoutError, EOFError, paramiko.SSHException)

    def stopped() -> bool:
        if diagnostics.get("scan_aborted_reason"):
            return True
        if cancel_check and cancel_check():
            diagnostics["scan_aborted_reason"] = "cancelled"
            return True
        return False

    def stop(path: str, exc: BaseException) -> None:
        # An SFTP server answers one request at a time, so what hung this one (an NFS
        # mount, a dropped connection) holds every later one too: the scan stops here, not
        # complete, rather than wait out the timeout once per file left.
        diagnostics["scan_aborted_reason"] = "sftp_session_lost"
        diagnostics["scan_errors"].append({"path": path, "error": type(exc).__name__})

    def folders_above(root: str) -> tuple[tuple[int, int | None], ...]:
        # The root's own folder and those above it, from "/". One that cannot be asked
        # about is taken to let everyone through: access is reported, not hidden.
        chain = []
        parts = [part for part in root.split("/") if part]
        for index in range(len(parts) + 1):
            try:
                attributes = sftp.stat("/" + "/".join(parts[:index]))
            except lost:
                # The session stopped answering: the walk finds that out and stops.
                chain.extend([(0o777, None)] * (len(parts) + 1 - index))
                break
            except OSError:
                chain.append((0o777, None))
                continue
            chain.append((int(attributes.st_mode or 0), getattr(attributes, "st_gid", None)))
        return tuple(chain)

    def walk(folder: str, depth: int, folders: tuple[tuple[int, int | None], ...] = ()) -> None:
        if stopped():
            return
        try:
            entries = sftp.listdir_attr(folder)
        except lost as exc:
            diagnostics["unreadable_dirs"].append({"path": folder, "error": type(exc).__name__})
            stop(folder, exc)
            return
        except OSError as exc:
            # What is under it was not seen: the scan is not complete, so a named scan
            # does not prune it (the engine reads unreadable_dirs as incomplete).
            diagnostics["unreadable_dirs"].append({"path": folder, "error": type(exc).__name__})
            return
        diagnostics["directories"] += 1
        for entry in sorted(entries, key=lambda item: item.filename):
            # Asked per file, not only per folder: one folder can hold the rest of the scan.
            if stopped():
                return
            if len(records) >= source.max_files:
                diagnostics["record_limit_reached"] = True
                return
            name = entry.filename
            if name in (".", "..") or (name.startswith(".") and not source.include_hidden):
                continue
            path = posixpath.join(folder, name)
            mode = int(entry.st_mode or 0)
            if stat.S_ISLNK(mode):
                diagnostics["symlinks_skipped"] += 1
                continue
            if stat.S_ISDIR(mode):
                if depth < source.max_depth:
                    walk(path, depth + 1, (*folders, (mode, getattr(entry, "st_gid", None))))
                continue
            if not stat.S_ISREG(mode):
                continue
            extension = posixpath.splitext(name)[1].lower()
            if allowed and extension.lstrip(".") not in allowed:
                continue
            diagnostics["files"] += 1
            size, modified = int(entry.st_size or 0), _stamp(entry.st_mtime)
            location = f"{prefix}{path}"
            record = {"source": "sftp", "path": location, "name": name, "extension": extension, "size": size,
                      "modified_at": modified, "is_dir": False, "is_hidden": name.startswith("."),
                      "owner": f"uid:{entry.st_uid}", "acl": access(entry, folders), "content": "", "reuse_key": location}
            snapshot = reuse_probe(location, size, modified) if reuse_probe else None
            if isinstance(snapshot, dict) and not snapshot_is_failed_read(snapshot):
                record.update({
                    "cache_reused": True, "incremental_reused": bool(snapshot.get("baseline_result")),
                    "baseline_result": snapshot.get("baseline_result") if isinstance(snapshot.get("baseline_result"), dict) else None,
                    "content_status": str(snapshot.get("content_status") or "reused_from_cache"),
                    "sha256": str(snapshot.get("sha256") or ""), "content_hash": str(snapshot.get("content_hash") or ""),
                    "scan_completeness": str(snapshot.get("scan_completeness") or "UNKNOWN"),
                    "bytes_scanned": int(snapshot.get("bytes_scanned") or 0), "total_bytes": size,
                    "truncated": bool(snapshot.get("truncated", False)),
                    "reused_preview": snapshot.get("preview") if isinstance(snapshot.get("preview"), dict) else None})
                diagnostics["reused"] += 1
                records.append(record)
                continue
            # A document is read whole, up to its own cap: its text is parsed from the whole
            # file, and the first 5 MB of a larger .docx/.xlsx/.pptx gave none.
            limit = (max(source.max_read_bytes, source.max_document_bytes)
                     if extension in BINARY_TEXT_EXTENSIONS else source.max_read_bytes)
            try:
                with sftp.open(path, "rb") as handle:
                    data = handle.read(limit)
            except (*lost, OSError) as exc:
                reason = (f"not read: the host stopped answering ({type(exc).__name__})" if isinstance(exc, lost)
                          else f"not readable by {source.username} ({type(exc).__name__})")
                record.update({"scan_error": reason, "content_status": "unreadable", "content_scannable": False})
                diagnostics["unreadable"].append({"path": path, "error": type(exc).__name__})
                records.append(record)
                if isinstance(exc, lost):
                    stop(path, exc)
                    return
                continue
            complete = len(data) >= size
            diagnostics["read"] += 1
            content = read_text(data, extension) if read_text else decode_text(data)
            record.update({"content": content,
                           "bytes_scanned": len(data), "total_bytes": size,
                           "sha256": hashlib.sha256(data).hexdigest() if complete else "",
                           "scan_completeness": "COMPLETE" if complete else "PARTIAL", "truncated": not complete})
            if extension in BINARY_TEXT_EXTENSIONS and not content:
                # No text came out of the document, so none of it was read - and one cut
                # short (its zip directory, or a PDF's cross-reference table, is at the end)
                # was not extracted at all, not read in part.
                record.update({"bytes_scanned": 0, "scan_completeness": "NONE"})
                if not complete:
                    record["content_status"] = "not_extracted"
            records.append(record)

    try:
        for root in source.paths:
            walk(root_path(root), 0, folders_above(root_path(root)))
    finally:
        if transport is not None:
            transport.close()
    diagnostics["records"] = len(records)
    return records, diagnostics
