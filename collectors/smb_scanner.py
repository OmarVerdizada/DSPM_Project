from __future__ import annotations

import hashlib
import io
import base64
import ipaddress
import json
import os
import socket
import subprocess
import tempfile
import threading
import zipfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
import re
from typing import Callable

from discovery.parallelism import host_admission_budget, resolve_parallelism

from collectors import content_policy, pysmb_compat, smb_target
from collectors.binary_extractor import BINARY_TEXT_EXTENSIONS, extract_binary_bytes_detail
from collectors.net_guard import TargetNotAllowed, resolve_and_pin
from collectors.text_decode import decode_text
from collectors import win_security
from collectors.smb3_transport import ACL_TRANSPORT, ACL_TRANSPORT_NOTE
from collectors.ocr import extract_text_from_image, is_ocr_scannable, max_image_bytes
from discovery.incremental import apply_reuse_snapshot, reuse_snapshot_from_result
from collectors.scan_scope import ScopeTally, rules_for
from collectors.file_scanner import (
    ARCHIVE_EXTENSIONS,
    CONTENT_EXTENSIONS,
    DEFAULT_TEXT_SCAN_MAX_BYTES,
    MAX_ARCHIVE_ENTRIES,
    MAX_ARCHIVE_ENTRY_BYTES,
    MAX_ARCHIVE_TOTAL_BYTES,
    PROTECTED_CONTENT_EXTENSIONS,
    TEXT_EXTENSIONS,
    archive_protection_metadata,
    content_status_for_extension,
    detect_extension,
    matches_scan_filters,
    normalize_extension_filter,
    scan_mode_for_extension,
)
from scripts.logger import get_logger

# W2.3: a read-only open lets the file be deleted or renamed meanwhile, as the SMB 3
# transport already does.
pysmb_compat.allow_delete_while_reading()

# W2.3: the credential that worked for a server is tried first next time, instead of
# failing through the others on every session a scan opens.
_working_credentials: dict[tuple[str, str], str] = {}
_working_credentials_lock = threading.Lock()

logger = get_logger(__name__)

SYSTEM_SHARES = {"print$", "IPC$", "ADMIN$"}


def _format_smb_timestamp(value) -> str:
    if not value:
        return ""
    try:
        if isinstance(value, datetime):
            parsed = value
        else:
            parsed = datetime.fromtimestamp(float(value), timezone.utc)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


# Windows caps a command line at 32,767 characters; the rest of the PowerShell
# invocation and a margin leave this much for the ACL batch's encoded command (E6).
ACL_BATCH_COMMAND_LIMIT = 30_000


def _in_range(key: str, low: str, high: str) -> bool:
    """Whether a case-folded name falls in [low, high); an empty bound is open."""
    return key >= low and (not high or key < high)


class _SmbConnectionLost(Exception):
    """Raised when an SMB operation fails because the CONNECTION died (reset by
    the peer / broken pipe / WinError 10054) rather than a per-object
    ACCESS_DENIED. Lets the scan reconnect and continue to the next share instead
    of hammering a dead socket and emitting one misleading error per remaining
    share."""

    def __init__(self, share: str, detail: str) -> None:
        super().__init__(detail)
        self.share = share
        self.detail = detail


def _connection_lost_types() -> tuple[type[BaseException], ...]:
    """The exception types that mean the session is gone, whatever their message says.

    The message test below knew only pysmb's reset strings. smbprotocol's
    SMBConnectionClosed ("SMB socket was closed..." / "Connection timed out...") and
    pysmb's SMBTimeout (no message at all) read as one file's failure: the files left in
    the chunk went to fallback readers that failed silently on the dead socket, and a
    listing read as access denied - no reconnect, no retry, the scan complete."""
    types: list[type[BaseException]] = [ConnectionError, TimeoutError]
    try:
        from smb.base import NotConnectedError, NotReadyError, SMBTimeout
        types += [NotConnectedError, NotReadyError, SMBTimeout]
    except ImportError:  # pysmb is not installed where only SMB 3 is used
        pass
    try:
        from smbprotocol.exceptions import SMBConnectionClosed
        types.append(SMBConnectionClosed)
    except ImportError:  # smbprotocol is an optional connector dependency
        pass
    return tuple(types)


_CONNECTION_LOST_TYPES = _connection_lost_types()


def _brief(exc: BaseException) -> str:
    """An error's first line, short - or its type when it says nothing (pysmb's SMBTimeout
    has no message). pysmb's OperationFailure embeds the whole SMB message history."""
    text = str(exc).strip()
    return text.splitlines()[0][:200] if text else exc.__class__.__name__


def _is_connection_error(exc: Exception) -> bool:
    """True for socket-level failures (connection reset/aborted/broken, the session closed
    or timed out) as opposed to a clean protocol error like ACCESS_DENIED that leaves the
    session usable."""
    if isinstance(exc, _CONNECTION_LOST_TYPES):
        return True
    text = str(exc).lower()
    return any(
        token in text
        for token in (
            "10054", "10053", "10058",  # WSAECONNRESET / ECONNABORTED / ESHUTDOWN
            "forcibly closed",
            "connection reset",
            "connection was aborted",
            "broken pipe",
            "not connected",
            "server disconnected",
        )
    )


def _is_access_denied(exc: Exception) -> bool:
    """True for a clean refusal to list a folder - the account may not read it - which
    refuses the scan the same way; False for a dropped connection, a timeout, or anything
    that might list fine a moment later."""
    if _is_connection_error(exc):
        return False
    text = str(exc).lower()
    return any(token in text for token in ("access denied", "access_denied", "0xc0000022", "unable to open directory"))


# How much a ranged archive read asks for at a time.
_RANGE_READ_BUFFER = 64 * 1024


class _GatedConnection:
    """A session whose reads are counted against, and held to, its server's gate (W2.3).
    Everything else is the session's own."""

    def __init__(self, connection, gate) -> None:
        self._connection = connection
        self._gate = gate

    def retrieveFileFromOffset(self, share, path, buffer, offset=0, max_length=-1, **kwargs):
        try:
            before = buffer.tell()
        except (AttributeError, OSError, ValueError):
            before = None
        result = self._connection.retrieveFileFromOffset(share, path, buffer, offset=offset, max_length=max_length,
                                                         **kwargs)
        try:
            read = buffer.tell() - before if before is not None else 0
        except (AttributeError, OSError, ValueError):
            read = 0
        self._gate.read(max(0, int(read)))
        return result

    def __getattr__(self, name):
        return getattr(self._connection, name)


class _ArchiveTooLarge(Exception):
    """Reading an archive through _SmbRangeFile would pass its byte budget."""


class _SmbRangeFile(io.RawIOBase):
    """A remote file as the seekable stream zipfile reads, each read one ranged SMB read.

    A ZIP's directory is at its END. A scan keeps at most MAX_ARCHIVE_TOTAL_BYTES of a
    file, so every zip larger than that was opened from a prefix with no directory and
    reported protected, "bad_archive", "could not be opened". Opened through this, only
    the directory and the entries asked for are fetched - at most ``budget`` bytes."""

    def __init__(self, connection, share: str, path: str, size: int, budget: int) -> None:
        super().__init__()
        self._connection, self._share, self._path = connection, share, path
        self._size, self._position = max(0, int(size)), 0
        self.transferred, self.budget = 0, max(0, int(budget))

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._position

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self._position, io.SEEK_END: self._size}[whence]
        self._position = max(0, base + int(offset))
        return self._position

    def readinto(self, buffer) -> int:
        wanted = min(len(buffer), self._size - self._position)
        if wanted <= 0:
            return 0
        if self.transferred + wanted > self.budget:
            raise _ArchiveTooLarge(f"reading {self._path} would pass {self.budget} bytes")
        sink = io.BytesIO()
        self._connection.retrieveFileFromOffset(self._share, self._path, sink, offset=self._position,
                                                max_length=wanted)
        data = sink.getvalue()[:wanted]
        buffer[:len(data)] = data
        self._position += len(data)
        self.transferred += len(data)
        return len(data)


@dataclass(slots=True)
class _SMBFileWork:
    """Metadata-only placeholder filled during P1's acquisition phase.

    No live pysmb objects cross the phase/thread boundary. That keeps the
    stateful connection thread-local while preserving deterministic order.
    """

    share_name: str
    remote_path: str
    name: str
    file_size: int
    extension: str
    is_hidden: bool
    is_system: bool
    created_at: str
    modified_at: str
    attributes: str
    reuse_key: str
    include_top: bool
    inspect_archive_entries: bool
    # The share's id for the file, when the server lists one: part of a meta identity.
    file_id: str = ""
    # W2.3: reading it would recall it from tiered storage; it is not read.
    offline: bool = False


@dataclass(slots=True)
class _SMBSharePlan:
    share_name: str
    # Each slot becomes one or more output records. Cached records are already
    # materialized; fresh records carry a metadata-only work placeholder.
    slots: list[list[dict] | _SMBFileWork]


@dataclass(slots=True)
class _SMBFileData:
    """One coherent remote-file acquisition used by P2.

    ``archive_bytes`` is bounded to ``MAX_ARCHIVE_TOTAL_BYTES``; the digest is
    still calculated over the complete file. Keeping these results together
    prevents the preview, archive inspector, and hasher from reopening byte 0.
    """

    content: str
    sha256: str
    archive_bytes: bytes | None = None
    # Why there is no text when there is none: the document extractor's reason
    # ("no_text_layer", "password_protected", "not_extracted"), or - read_error - the
    # type of the error that kept the file from being read at all.
    extraction_reason: str = ""
    read_error: str = ""
    # The document extractor stopped with document left or skipped a part (W2.2, E5).
    truncated: bool = False
    # A content type not read by policy (over its size cap): said, not an error.
    skip_reason: str = ""


# Bytes every SMB reader of this process holds in memory at once for content (W2.2).
# Each read takes its share before it starts and gives it back once its text is out,
# so io_workers x the document cap is not the bound - this is.
_DEFAULT_CAPTURE_BUDGET_MB = 256


class _ByteBudget:
    def __init__(self, total: int) -> None:
        self.total = max(1, int(total))
        self._free = self.total
        self._cond = threading.Condition()

    @contextmanager
    def take(self, amount: int):
        amount = min(max(0, int(amount)), self.total)
        with self._cond:
            while self._free < amount:
                self._cond.wait()
            self._free -= amount
        try:
            yield
        finally:
            with self._cond:
                self._free += amount
                self._cond.notify_all()


_capture_budget: _ByteBudget | None = None
_capture_budget_lock = threading.Lock()


def capture_budget() -> _ByteBudget:
    """``DSPM_SMB_CAPTURE_BUDGET_MB`` (256): read once per process."""
    global _capture_budget
    with _capture_budget_lock:
        if _capture_budget is None:
            try:
                megabytes = int(os.getenv("DSPM_SMB_CAPTURE_BUDGET_MB") or _DEFAULT_CAPTURE_BUDGET_MB)
            except ValueError:
                megabytes = _DEFAULT_CAPTURE_BUDGET_MB
            _capture_budget = _ByteBudget(max(16, megabytes) * 1024 * 1024)
        return _capture_budget


@dataclass(slots=True)
class SMBConfig:
    server: str
    # C5: the workspace whose scan targets decide whether `server` may be connected to.
    tenant_id: str = ""
    username: str = ""
    password: str = ""
    domain: str = "WORKGROUP"
    port: int = 445
    client_name: str = "dspm-client"
    max_depth: int = 4
    read_content: bool = True
    include_hidden: bool = True
    include_system: bool = False
    hidden_filter_enabled: bool = False
    system_filter_enabled: bool = False
    max_read_bytes: int = DEFAULT_TEXT_SCAN_MAX_BYTES
    allowed_extensions: list[str] | None = None
    extension_filter_enabled: bool = False
    include_admin_shares: bool = False
    inspect_archives: bool = False
    timeout: int = 10
    cancel_check: Callable[[], bool] | None = None
    # Metadata-first cache reuse: probe(qualified_path, size, mtime) returns a
    # stored snapshot for an unchanged file, letting the walker skip the remote
    # content read, full hash, and per-file ACL lookup.
    reuse_probe: Callable[[str, int, str], dict | None] | None = None
    # Collection progress: callback(visited, matched, reused_from_cache).
    progress_callback: Callable[[int, int, int], None] | None = None
    # P-B.1: emit a successfully collected share batch before walking the next
    # share so analysis overlaps later network I/O. Failed/retried share attempts
    # never emit partial records.
    record_callback: Callable[[dict], None] | None = None
    # P-B.2: bound for parallel per-share acquisition (0 = resolve from the
    # process parallelism policy / io_workers). Each parallel worker owns an
    # isolated connection and a process-wide admission slot.
    io_workers: int = 0
    # B2.3: the shares this scan walks, by name; None walks every share. A partitioned
    # SMB scan gives each partition a group of shares that cannot overlap any share
    # outside the group, so the overlapping-share collapse stays inside one partition.
    allowed_shares: tuple[str, ...] | None = None
    # D1: SMB 3.1.1 with the session encrypted, and required (collectors.smb3_transport).
    # pysmb cannot encrypt; a server or share that requires encryption resets it.
    require_encryption: bool = False
    # W1.2: one unit of a partitioned scan inside a share - {"share", "folder", "depth",
    # "name_from", "name_to"}. The folder's entries whose case-folded names fall in
    # [name_from, name_to) are walked, each subfolder among them whole; "" is unbounded.
    share_range: dict | None = None
    # Advanced scan scope (collectors.scan_scope): the scan's canonical rules, share-relative
    # paths. A share, folder or file out of scope is never listed, opened or read.
    scope: dict | None = None



def normalize_acl(owner, principals, permissions, types=None, *, entries=None) -> dict:
    """One shape for every ACL path (in-process, batched and per-file PowerShell): the
    owner, the parallel principal/permission lists reports have always carried, and -
    D7 - whether each entry allows or denies (``types``), or the full entries when the
    in-process read has them. A pair with an empty principal is dropped as a pair, so
    the lists stay aligned."""
    def listed(value) -> list:
        if value is None:
            return []
        return [value] if isinstance(value, str) else list(value)

    principals, permissions, types = listed(principals), listed(permissions), listed(types)
    kept_principals: list[str] = []
    kept_permissions: list[str] = []
    kept_types: list[str] = []
    for index, principal in enumerate(principals):
        if not str(principal or "").strip():
            continue
        kept_principals.append(str(principal))
        kept_permissions.append(str(permissions[index]) if index < len(permissions) else "")
        kept_types.append(str(types[index]).lower() if index < len(types) else "allow")
    acl = {"owner": str(owner or ""), "principals": kept_principals, "permissions": kept_permissions}
    if types:
        acl["types"] = kept_types
    if entries:
        acl["entries"] = [dict(entry) for entry in entries if isinstance(entry, dict)]
    return acl

class SMBScanner:
    def __init__(self, config: SMBConfig):
        self.config = config
        # P-B.2: the pysmb session is stateful and NOT thread-safe, so the live
        # connection is thread-local - each parallel share worker owns its own,
        # and the serial path (single thread) sees exactly one, unchanged.
        self._local = threading.local()
        self.extension_filter = normalize_extension_filter(config.allowed_extensions)
        self._scope = rules_for(config.scope)
        self._scope_tally = ScopeTally() if self._scope.active else None
        self.credential_used = ""
        self.server_used = ""
        self._owner_cache: dict[str, str] = {}
        self._acl_cache: dict[str, dict] = {}
        self._acl_lock = threading.RLock()
        self.last_scan_diagnostics: dict = {}
        self._progress_counters = {"visited": 0, "matched": 0, "reused": 0}
        # P-B.2 share-parallelism coordination (shared across workers).
        self._reset_lock = threading.Lock()
        self._consecutive_resets = 0
        self._abort_event = threading.Event()
        self._io_parallel_active = False
        # Serializes updates to the counters/diagnostics that parallel share
        # workers share: a bare ``+=`` on a dict value is a lost-update race, so
        # the progress counts and diagnostic tallies would drift under threads.
        # Uncontended (and therefore ~free) on the serial single-thread path.
        self._walk_lock = threading.Lock()

    @property
    def connection(self):
        """The live pysmb connection for the CURRENT thread (thread-local)."""
        return getattr(self._local, "connection", None)

    @connection.setter
    def connection(self, value) -> None:
        self._local.connection = value

    def _cancelled(self) -> bool:
        return bool(self.config.cancel_check and self.config.cancel_check())

    def _emit_collection_progress(self, force: bool = False) -> None:
        if self.config.progress_callback is None:
            return
        with self._walk_lock:  # a torn read across the three counters would misreport progress
            visited = self._progress_counters["visited"]
            matched = self._progress_counters["matched"]
            reused = self._progress_counters["reused"]
        # Throttle so the callback stays cheap during large share walks.
        if not force and visited % 25 != 0:
            return
        try:
            self.config.progress_callback(visited, matched, reused)
        except Exception:
            return

    def _bump_diag(self, key: str, amount: int = 1) -> None:
        """Atomically increment a running diagnostic tally. Parallel share
        workers touch the same ``last_scan_diagnostics`` counters, so the
        read-modify-write must hold ``_walk_lock`` or increments are lost."""
        with self._walk_lock:
            self.last_scan_diagnostics[key] = int(self.last_scan_diagnostics.get(key) or 0) + amount

    def _reuse_key(self, share_name: str, remote_path: str) -> str:
        server = self.server_used or self.config.server
        return f"smb://{server}/{share_name}{remote_path}"

    def connect(self) -> bool:
        encrypted = bool(self.config.require_encryption)
        try:
            if encrypted:
                from collectors.smb3_transport import EncryptionUnavailable, Smb3Connection
            else:
                from smb.SMBConnection import SMBConnection
        except ModuleNotFoundError as exc:
            package, needs = ("smbprotocol", "requirements-connectors.txt") if encrypted else ("pysmb", "requirements.txt")
            raise RuntimeError(f"Missing dependency '{package}'. Install {needs} before SMB scans.") from exc
        self._encryption_refused = ""

        reached_server = False
        self._target_refused = ""
        for server in self._server_candidates():
            remote_name = self._remote_name_for(server)
            # M12: resolve + validate the target ONCE and connect to the PINNED IP,
            # so a DNS-rebind flip (public -> loopback/private) between validation
            # and connect cannot turn the scanner into an SSRF primitive. The
            # NetBIOS remote_name (for auth) stays the hostname.
            try:
                pinned_ip = resolve_and_pin(server, tenant_id=self.config.tenant_id)
            except TargetNotAllowed as exc:
                logger.warning("Refusing SMB target %s: %s", server, exc)
                self._target_refused = str(exc)
                continue
            for username, domain, label in self._credential_candidates():
                if encrypted:
                    conn = Smb3Connection(username, self.config.password, self.config.client_name, remote_name,
                                          domain=domain, shares=list(self.config.allowed_shares or ()))
                    try:
                        if conn.connect(pinned_ip, self.config.port, timeout=self.config.timeout):
                            self.connection = _GatedConnection(conn, self._target_gate())
                            self.credential_used = label
                            self.server_used = server
                            self._remember_credential(server, label)
                            return True
                        reached_server = True
                    except (EncryptionUnavailable, PermissionError) as exc:
                        # Said, not retried with the next credential: no account makes the
                        # server encrypt, and the service identity was not allowed.
                        self._encryption_refused = str(exc)
                        conn.close()
                        return False
                    except Exception as exc:  # noqa: BLE001 - as the pysmb path: try the next credential
                        logger.warning("SMB 3 connection to %s failed: %s", server, type(exc).__name__)
                        conn.close()
                    continue
                conn = SMBConnection(
                    username,
                    self.config.password,
                    self.config.client_name,
                    remote_name,
                    domain=domain,
                    use_ntlm_v2=True,
                    # M11 (0.3): sign the SMB session whenever the server supports
                    # it (the default SIGN_WHEN_REQUIRED only signs if the server
                    # forces it). Protects NTLMv2 material and file bytes in transit
                    # against tampering. No-op if the server does not support signing.
                    sign_options=SMBConnection.SIGN_WHEN_SUPPORTED,
                    is_direct_tcp=True,
                )
                try:
                    if conn.connect(pinned_ip, self.config.port, timeout=self.config.timeout):
                        self.connection = _GatedConnection(conn, self._target_gate())
                        self.credential_used = label
                        self.server_used = server
                        self._remember_credential(server, label)
                        return True
                    # TCP + SMB negotiation succeeded but authentication was
                    # rejected (pysmb returns False rather than raising here).
                    reached_server = True
                except Exception:
                    conn.close()
                    continue
                conn.close()

        self._auth_rejected = reached_server
        return False

    def _remote_name_for(self, server: str) -> str:
        server = server.strip()
        try:
            ipaddress.ip_address(server)
            return server  # an IP has no NetBIOS name; do not split it into "10"
        except ValueError:
            return server.split(".")[0].strip() or server

    def _server_short_name(self) -> str:
        server = self.config.server.strip()
        try:
            ipaddress.ip_address(server)
            return ""  # an IP octet is not a valid NetBIOS domain or machine name
        except ValueError:
            return server.split(".")[0].strip()

    def close(self) -> None:
        if self.connection is not None:
            try:
                self.connection.close()
            except Exception:
                pass
            self.connection = None

    def _reconnect(self) -> bool:
        """Tear down a dead session and establish a fresh one. Used to recover
        from a mid-scan connection reset so the remaining shares still get a live
        connection."""
        self.close()
        try:
            return self.connect()
        except Exception:
            return False

    def test_connection(self) -> dict:
        try:
            connected = self.connect()
            shares = self._safe_list_shares() if connected else []
            return {
                "connected": connected,
                "server": self.config.server,
                "server_used": self.server_used,
                "domain": self.config.domain,
                "credential_used": self.credential_used,
                "shares": shares,
                "message": "Connected successfully" if connected else "Connection failed",
            }
        except Exception as exc:
            logger.exception("SMB connection test failed")
            return {
                "connected": False,
                "server": self.config.server,
                "server_used": self.server_used,
                "domain": self.config.domain,
                "credential_used": self.credential_used,
                "shares": [],
                "message": "SMB connection test failed",
            }
        finally:
            self.close()

    def scan(self) -> list[dict]:
        self.last_scan_diagnostics = {}
        self._progress_counters = {"visited": 0, "matched": 0, "reused": 0}
        self._scope_tally = ScopeTally() if self._scope.active else None
        self._consecutive_resets = 0
        self._abort_event.clear()
        self._io_parallel_active = False
        if not self.connect():
            if getattr(self, "_target_refused", ""):
                raise ConnectionError(f"SMB target refused (network guard): {self._target_refused}")
            if getattr(self, "_encryption_refused", ""):
                raise ConnectionError(f"SMB 3 encryption required: {self._encryption_refused}")
            if getattr(self, "_auth_rejected", False):
                raise ConnectionError(
                    f"SMB authentication was rejected by {self.config.server} for user "
                    f"'{self.config.username or '(anonymous)'}'. Verify the password and the "
                    f"domain - a domain/AD service account must authenticate with its AD "
                    f"domain (the NetBIOS domain name), not WORKGROUP."
                )
            raise ConnectionError(
                f"Could not reach SMB server {self.config.server}:{self.config.port}. "
                f"Check the host, port, and network path/firewall."
            )

        try:
            discovered_shares: list[str] = []
            scanned_shares: list[str] = []
            skipped_shares: list[str] = []
            for share in list(self.connection.listShares()):  # materialised once
                if self._cancelled():
                    raise RuntimeError("Scan cancelled")
                share_name = share.name
                discovered_shares.append(share_name)
                if self._skip_share(share_name):
                    skipped_shares.append(share_name)
                    continue
                if not self._share_selected(share_name):
                    # Another partition of the same scan walks it (B2.3): not skipped.
                    continue
                if self._scope_skips_folder(share_name, "/"):
                    # Out of scope - an excluded share, or one no included folder is in:
                    # not even listed.
                    continue
                scanned_shares.append(share_name)

            # P1: the real collector uses a metadata-first, globally bounded
            # per-file pipeline. Instance-overridden walkers (the compatibility
            # seam used by integrations/tests) retain the proven P-B.2 path.
            budget = host_admission_budget()
            if self.config.share_range and not self._should_use_file_pipeline():
                raise RuntimeError("an SMB range unit needs the metadata-first collector (DSPM_SMB_PARALLEL)")
            if self._should_use_file_pipeline():
                self.close()  # the listing connection is no longer needed
                records, reset_shares, aborted_reason = self._scan_shares_two_phase(scanned_shares, budget)
            elif self._should_parallelize(len(scanned_shares)):
                self._io_parallel_active = True
                records, reset_shares, aborted_reason = self._scan_shares_parallel(scanned_shares, budget)
            else:
                records, reset_shares, aborted_reason = self._scan_shares_serial(scanned_shares, budget)

            # Collapse the same physical file surfaced via overlapping shares
            # (e.g. a nested `HR` share also reachable under a parent `Shares`
            # share) so it is not scanned/reported twice.
            records = self._dedupe_overlapping_shares(records)

            self._emit_collection_progress(force=True)
            owner_missing = sum(1 for record in records if not str(record.get("owner") or "").strip())
            denied_shares = sorted({
                str(e.get("share"))
                for e in self.last_scan_diagnostics.get("list_errors", [])
                if isinstance(e, dict) and e.get("path") in ("/", "")
            })
            reset_unique = sorted(set(reset_shares))
            # Coverage visibility: an operator must be able to see WHICH shares were
            # found vs scanned vs access-denied vs connection-reset. Without this, a
            # share that is not exported, is unreadable, or whose session was reset
            # silently yields no findings and looks like "nothing sensitive here".
            logger.info(
                "SMB scan of %s: %d share(s) found [%s]; scanned %d; access-denied [%s]; connection-reset [%s]",
                self.server_used or self.config.server,
                len(discovered_shares),
                ", ".join(discovered_shares) or "-",
                len(scanned_shares),
                ", ".join(denied_shares) or "-",
                ", ".join(reset_unique) or "-",
            )
            self.last_scan_diagnostics = {
                **self.last_scan_diagnostics,
                "server_used": self.server_used or self.config.server,
                "records": len(records),
                "owner_missing": owner_missing,
                "owner_resolved": max(0, len(records) - owner_missing),
                "cache_reused_files": self._progress_counters["reused"],
                "files_discovered": self._progress_counters["matched"],
                "shares_discovered": discovered_shares,
                "shares_scanned": scanned_shares,
                "shares_skipped": skipped_shares,
                "shares_access_denied": denied_shares,
                "shares_connection_reset": reset_unique,
                "io_parallel_active": self._io_parallel_active,
                "io_workers": self._io_worker_count(),
                "host_admission": budget.stats(),
                # W2.3: what this server was asked for, by every scan of it in this process.
                "smb_target": self._target_gate().snapshot(),
                **({"scan_aborted_reason": aborted_reason} if aborted_reason else {}),
                # D1: the file bytes came over the encrypted session; the owners and ACLs
                # did not (collectors.smb3_transport says why). Said with the scan.
                **({"acl_transport": ACL_TRANSPORT, "acl_transport_note": ACL_TRANSPORT_NOTE}
                   if self.config.require_encryption else {}),
                **({"scope": self._scope_tally.to_dict(self.config.scope)} if self._scope_tally is not None else {}),
            }
            return records
        finally:
            self.close()

    # ------------------------------------------------------------------
    # P-B.2: per-share acquisition strategy (serial vs parallel).
    # ------------------------------------------------------------------

    @staticmethod
    def _env_enabled(name: str, default: bool = True) -> bool:
        fallback = "1" if default else "0"
        return os.getenv(name, fallback).strip().lower() not in {"0", "false", "no", "off"}

    def _file_parallel_enabled(self) -> bool:
        return (
            self._env_enabled("DSPM_SMB_PARALLEL", True)
            and self._env_enabled("DSPM_SMB_FILE_PARALLEL", True)
            and self._io_worker_count() > 1
        )

    def _acl_batch_enabled(self) -> bool:
        return self._env_enabled("DSPM_SMB_ACL_BATCH", True)

    def _single_pass_enabled(self) -> bool:
        return self._env_enabled("DSPM_SMB_SINGLE_PASS", True)

    @staticmethod
    def _acl_batch_size() -> int:
        configured = os.getenv("DSPM_SMB_ACL_BATCH_SIZE", "32").strip()
        try:
            return max(1, min(int(configured), 512))
        except ValueError:
            return 32

    def _should_use_file_pipeline(self) -> bool:
        """Use P1 for the real walker while retaining the instance override seam.

        DSPM_SMB_PARALLEL=0 is deliberately the full legacy escape hatch: it
        restores one connection, the original recursive walk and per-file ACLs.
        """
        if "_walk_share" in self.__dict__:
            return False
        if not self._env_enabled("DSPM_SMB_PARALLEL", True):
            return False
        return self._file_parallel_enabled() or self._acl_batch_enabled()

    def _scan_shares_two_phase(self, shares: list[str], budget) -> tuple[list[dict], list[str], str]:
        """Enumerate metadata first, then acquire expensive file data globally.

        Enumeration workers release their host-admission slots before acquisition
        workers start. This avoids nested-semaphore deadlocks across concurrent
        jobs and makes the budget an exact cap on live target connections.
        """
        enum_started = time.perf_counter()
        enum_workers = max(1, min(self._io_worker_count(), len(shares) or 1))
        plans_by_share: dict[str, _SMBSharePlan] = {}
        reset_shares: list[str] = []

        if enum_workers <= 1:
            for share_name in shares:
                plan, status = self._enumerate_one_share(share_name, budget)
                if status == "done" and plan is not None:
                    plans_by_share[share_name] = plan
                elif status == "reset":
                    reset_shares.append(share_name)
                if self._abort_event.is_set():
                    break
        else:
            with ThreadPoolExecutor(max_workers=enum_workers, thread_name_prefix="dspm-smb-enum") as executor:
                futures = {
                    executor.submit(self._enumerate_one_share, share_name, budget): share_name
                    for share_name in shares
                }
                for future in as_completed(futures):
                    share_name = futures[future]
                    plan, status = future.result()
                    if status == "done" and plan is not None:
                        plans_by_share[share_name] = plan
                    elif status == "reset":
                        reset_shares.append(share_name)

        ordered_plans = [plans_by_share[name] for name in shares if name in plans_by_share]
        enum_elapsed_ms = round((time.perf_counter() - enum_started) * 1000, 3)
        acquire_started = time.perf_counter()
        records, acquired_resets, file_workers, chunk_count = self._acquire_share_plans(ordered_plans, budget)
        acquire_elapsed_ms = round((time.perf_counter() - acquire_started) * 1000, 3)
        reset_shares.extend(acquired_resets)

        self._io_parallel_active = enum_workers > 1 or file_workers > 1
        with self._walk_lock:
            self.last_scan_diagnostics["smb_phases"] = {
                "mode": "metadata_then_acquire",
                "enumeration_workers": enum_workers,
                "enumeration_elapsed_ms": enum_elapsed_ms,
                "share_plans": len(ordered_plans),
                "file_work_items": sum(
                    1 for plan in ordered_plans for slot in plan.slots if isinstance(slot, _SMBFileWork)
                ),
                "file_workers": file_workers,
                "file_parallel_active": file_workers > 1,
                "acquisition_chunks": chunk_count,
                "acl_batch_size": self._acl_batch_size() if self._acl_batch_enabled() else 1,
                "acquisition_elapsed_ms": acquire_elapsed_ms,
                "acl_strategy": "batched_powershell_with_per_file_fallback" if self._acl_batch_enabled() else "per_file",
                "content_hash_strategy": "single_pass_with_exact_fallback" if self._single_pass_enabled() else "separate_preview_and_hash",
            }
        aborted_reason = "smb_connection_reset" if self._abort_event.is_set() else ""
        return records, reset_shares, aborted_reason

    def _note_connection_reset(self, share_name: str, detail: str, attempt: int) -> bool:
        with self._reset_lock:
            self._consecutive_resets += 1
            tripped = self._consecutive_resets >= 5
        logger.warning(
            "Connection reset scanning share %s (%s); %s",
            share_name,
            detail,
            "aborting remaining work" if tripped else "retrying" if attempt == 0 else "retry exhausted",
        )
        if tripped:
            self._abort_event.set()
        return tripped

    def _enumerate_one_share(self, share_name: str, budget) -> tuple[_SMBSharePlan | None, str]:
        for attempt in range(2):
            if self._abort_event.is_set() or self._cancelled():
                return None, "skipped"
            detail = ""
            gate = self._target_gate()
            with budget.slot(), gate.session():
                if self._abort_event.is_set() or self._cancelled():
                    return None, "skipped"
                if not self.connect():
                    detail = "could not establish an SMB enumeration connection"
                else:
                    try:
                        unit = self.config.share_range
                        if unit and str(unit.get("share") or "").casefold() == share_name.casefold():
                            plan = self._enumerate_share_plan(
                                share_name, str(unit.get("folder") or "/"), depth=int(unit.get("depth") or 0),
                                name_range=(str(unit.get("name_from") or ""), str(unit.get("name_to") or "")),
                            )
                        else:
                            plan = self._enumerate_share_plan(share_name, "/", depth=0)
                    except _SmbConnectionLost as lost:
                        detail = lost.detail
                        gate.lost()
                    else:
                        with self._reset_lock:
                            self._consecutive_resets = 0
                        gate.completed()
                        return plan, "done"
                    finally:
                        self.close()
            if self._note_connection_reset(share_name, detail or "connection lost", attempt):
                return None, "reset"
        return None, "reset"

    def _enumerate_share_plan(
        self,
        share_name: str,
        folder: str,
        depth: int,
        plan: _SMBSharePlan | None = None,
        name_range: tuple[str, str] | None = None,
    ) -> _SMBSharePlan:
        if plan is None:
            plan = _SMBSharePlan(share_name=share_name, slots=[])
        if self._cancelled():
            raise RuntimeError("Scan cancelled")
        if self.connection is None or depth > self.config.max_depth or self._skip_path(folder):
            return plan
        if self._scope_skips_folder(share_name, folder):
            return plan

        try:
            entries = self.connection.listPath(share_name, folder)
        except Exception as exc:
            brief = str(exc).splitlines()[0][:200] if str(exc) else exc.__class__.__name__
            if _is_connection_error(exc):
                raise _SmbConnectionLost(share_name, brief) from exc
            logger.warning("Could not list %s:%s: %s", share_name, folder, brief)
            with self._walk_lock:
                errors = self.last_scan_diagnostics.setdefault("list_errors", [])
                if isinstance(errors, list) and len(errors) < 20:
                    errors.append({"share": share_name, "path": folder, "error": brief})
            return plan

        # A folder's entries are walked in case-folded name order (W1.2): the order a
        # partitioned scan cuts its ranges in, so its units in sequence are this walk. A
        # range is applied before the sort, so a unit of a huge folder sorts only its own.
        keyed = ((str(entry.filename).casefold(), entry) for entry in entries)
        if name_range is not None:
            keyed = ((key, entry) for key, entry in keyed if _in_range(key, *name_range))
        for _key, entry in sorted(keyed, key=lambda pair: pair[0]):
            if self._cancelled():
                raise RuntimeError("Scan cancelled")
            if entry.filename in {".", ".."}:
                continue

            remote_path = str(PurePosixPath(folder) / entry.filename)
            if self._skip_path(remote_path):
                continue
            is_dir = bool(entry.isDirectory)
            is_hidden = bool(getattr(entry, "isHidden", False))
            is_system = bool(getattr(entry, "isSystem", False))
            if is_dir:
                if is_hidden and not (self.config.include_hidden or self.config.hidden_filter_enabled):
                    continue
                if self._scope_skips_folder(share_name, remote_path):
                    continue
                self._enumerate_share_plan(share_name, remote_path, depth + 1, plan)
                continue

            extension = detect_extension(remote_path)
            with self._walk_lock:
                self._progress_counters["visited"] += 1
            self._emit_collection_progress()
            if self._scope_skips_file(share_name, remote_path, extension, entry):
                # Decided on the listing: never opened, read, hashed or stored.
                continue
            include_top = matches_scan_filters(
                extension,
                is_hidden,
                is_system,
                self.extension_filter,
                self.config.extension_filter_enabled,
                self.config.include_hidden,
                self.config.include_system,
                self.config.hidden_filter_enabled,
                self.config.system_filter_enabled,
            )
            inspect_entries = self.config.inspect_archives and self._should_scan_archive_entries(extension)
            if not include_top and not inspect_entries:
                continue

            file_size = int(getattr(entry, "file_size", 0) or 0)
            modified_at = _format_smb_timestamp(getattr(entry, "last_write_time", None))
            created_at = _format_smb_timestamp(getattr(entry, "create_time", None))
            attributes = ", ".join(
                [item for item in ["H" if is_hidden else "", "S" if is_system else ""] if item]
            ) or "Normal"
            reuse_key = self._reuse_key(share_name, remote_path)

            snapshot = None
            if include_top and self.config.reuse_probe is not None and modified_at:
                try:
                    snapshot = self.config.reuse_probe(reuse_key, file_size, modified_at)
                except Exception:
                    snapshot = None
                if inspect_entries and not bool((snapshot or {}).get("archive_bundle_complete")):
                    snapshot = None
            if isinstance(snapshot, dict):
                slot_records = [
                    {
                        "source": "smb",
                        "share": share_name,
                        "path": remote_path,
                        "name": entry.filename,
                        "size": file_size,
                        "extension": extension,
                        "is_dir": False,
                        "is_hidden": is_hidden,
                        "is_system": is_system,
                        "content": "",
                        "acl": snapshot.get("acl") or {},
                        "scan_mode": scan_mode_for_extension(extension),
                        "content_status": str(snapshot.get("content_status") or "reused_from_cache"),
                        "content_scannable": bool(
                            snapshot.get(
                                "content_scannable",
                                extension in CONTENT_EXTENSIONS or is_ocr_scannable(extension),
                            )
                        ),
                        "protected": bool(snapshot.get("protected", False)),
                        "protection_type": str(snapshot.get("protection_type") or ""),
                        "scan_error": str(snapshot.get("scan_error") or ""),
                        "owner": str(snapshot.get("owner") or ""),
                        "created_at": created_at,
                        "modified_at": modified_at,
                        "attributes": attributes,
                        "sha256": str(snapshot.get("sha256") or ""),
                        "file_hash": str(snapshot.get("sha256") or ""),
                        "content_hash": str(snapshot.get("content_hash") or ""),
                        "scan_completeness": str(snapshot.get("scan_completeness") or "UNKNOWN"),
                        "bytes_scanned": int(snapshot.get("bytes_scanned") or 0),
                        "total_bytes": int(snapshot.get("total_bytes") or file_size),
                        "truncated": bool(snapshot.get("truncated", False)),
                        "cache_reused": True,
                        "incremental_reused": bool(snapshot.get("baseline_result")),
                        "reused_preview": snapshot.get("preview") if isinstance(snapshot.get("preview"), dict) else None,
                        "baseline_result": snapshot.get("baseline_result") if isinstance(snapshot.get("baseline_result"), dict) else None,
                        "reuse_key": reuse_key,
                    }
                ]
                archive_records = snapshot.get("archive_records") if isinstance(snapshot.get("archive_records"), list) else []
                for prior in archive_records:
                    if isinstance(prior, dict):
                        child_key = str(prior.get("reuse_key") or prior.get("path") or "")
                        slot_records.append(apply_reuse_snapshot(prior, reuse_snapshot_from_result(prior), child_key))
                plan.slots.append(slot_records)
                with self._walk_lock:
                    self._progress_counters["matched"] += len(slot_records)
                    self._progress_counters["reused"] += len(slot_records)
                self._emit_collection_progress()
                continue

            plan.slots.append(
                _SMBFileWork(
                    share_name=share_name,
                    remote_path=remote_path,
                    name=entry.filename,
                    file_size=file_size,
                    extension=extension,
                    is_hidden=is_hidden,
                    is_system=is_system,
                    created_at=created_at,
                    modified_at=modified_at,
                    attributes=attributes,
                    reuse_key=reuse_key,
                    include_top=include_top,
                    inspect_archive_entries=inspect_entries,
                    file_id=str(getattr(entry, "file_id", "") or ""),
                    offline=self._offline(entry),
                )
            )
        return plan

    def _acquire_share_plans(
        self,
        plans: list[_SMBSharePlan],
        budget,
    ) -> tuple[list[dict], list[str], int, int]:
        refs_by_plan: list[list[tuple[int, int, _SMBFileWork]]] = []
        total_work = 0
        for plan_index, plan in enumerate(plans):
            refs = [
                (plan_index, slot_index, slot)
                for slot_index, slot in enumerate(plan.slots)
                if isinstance(slot, _SMBFileWork)
            ]
            refs_by_plan.append(refs)
            total_work += len(refs)

        if total_work == 0:
            records: list[dict] = []
            for plan in plans:
                share_records = [row for slot in plan.slots if isinstance(slot, list) for row in slot]
                if self.config.record_callback is not None:
                    for record in share_records:
                        self.config.record_callback(record)
                records.extend(share_records)
            return records, [], 1, 0

        requested_workers = 1
        if self._file_parallel_enabled():
            requested_workers = max(1, min(self._io_worker_count(), int(budget.limit), total_work))
        target_chunk = max(1, (total_work + requested_workers - 1) // requested_workers)
        if self._acl_batch_enabled():
            # Keep PowerShell process creation decisively sub-linear. File work
            # stays parallel, but no task is smaller than one ACL batch.
            target_chunk = max(target_chunk, self._acl_batch_size())
        task_specs: list[tuple[int, list[tuple[int, int, _SMBFileWork]]]] = []
        tasks_by_plan: dict[int, list[int]] = {}
        for plan_index, refs in enumerate(refs_by_plan):
            for offset in range(0, len(refs), target_chunk):
                task_index = len(task_specs)
                task_specs.append((plan_index, refs[offset:offset + target_chunk]))
                tasks_by_plan.setdefault(plan_index, []).append(task_index)

        slot_results: dict[tuple[int, int], list[dict]] = {}

        file_workers = max(1, min(requested_workers, len(task_specs)))
        failed_plans: set[int] = set()
        reset_shares: list[str] = []
        futures: dict[int, object] = {}
        executor = None
        try:
            if file_workers > 1:
                executor = ThreadPoolExecutor(max_workers=file_workers, thread_name_prefix="dspm-smb-file")
                futures = {
                    task_index: executor.submit(self._acquire_work_chunk, refs, budget)
                    for task_index, (_plan_index, refs) in enumerate(task_specs)
                }

            records: list[dict] = []
            for plan_index, plan in enumerate(plans):
                for task_index in tasks_by_plan.get(plan_index, []):
                    try:
                        rows = (
                            futures[task_index].result()
                            if executor is not None
                            else self._acquire_work_chunk(task_specs[task_index][1], budget)
                        )
                    except _SmbConnectionLost as lost:
                        failed_plans.add(plan_index)
                        if plan.share_name not in reset_shares:
                            reset_shares.append(plan.share_name)
                        self._note_connection_reset(plan.share_name, lost.detail, 1)
                        continue
                    for result_plan, slot_index, result_rows in rows:
                        slot_results[(result_plan, slot_index)] = result_rows

                if plan_index in failed_plans:
                    continue
                share_records: list[dict] = []
                missing = False
                for slot_index, slot in enumerate(plan.slots):
                    if isinstance(slot, list):
                        result_rows = slot
                    else:
                        result_rows = slot_results.get((plan_index, slot_index))
                        if result_rows is None:
                            missing = True
                            break
                        if slot.include_top:
                            with self._walk_lock:
                                self._progress_counters["matched"] += 1
                    share_records.extend(result_rows)
                if missing:
                    reset_shares.append(plan.share_name)
                    continue
                if self.config.record_callback is not None:
                    for record in share_records:
                        self.config.record_callback(record)
                records.extend(share_records)
                self._emit_collection_progress()
            return records, reset_shares, file_workers, len(task_specs)
        finally:
            if executor is not None:
                executor.shutdown(wait=True, cancel_futures=self._abort_event.is_set())

    def _acquire_work_chunk(
        self,
        refs: list[tuple[int, int, _SMBFileWork]],
        budget,
    ) -> list[tuple[int, int, list[dict]]]:
        if not refs:
            return []
        share_name = refs[0][2].share_name
        gate = self._target_gate()
        with budget.slot(), gate.session():
            if self._cancelled():
                raise RuntimeError("Scan cancelled")
            self._prefetch_acl_paths(share_name, [ref[2].remote_path for ref in refs])
            last_detail = "could not establish an SMB acquisition connection"
            for _attempt in range(2):
                if not self.connect():
                    continue
                try:
                    built = [
                        (plan_index, slot_index, self._build_work_records(work))
                        for plan_index, slot_index, work in refs
                    ]
                    gate.completed()
                    return built
                except _SmbConnectionLost as lost:
                    last_detail = lost.detail
                    gate.lost()
                finally:
                    self.close()
            raise _SmbConnectionLost(share_name, last_detail)

    def _acquire_file_data(
        self,
        share_name: str,
        path: str,
        extension: str,
        size: int,
        *,
        inspect_archive_entries: bool = False,
        chunk_size: int = 1024 * 1024,
        modified_at: str = "",
        file_id: str = "",
    ) -> _SMBFileData:
        """Read what the scan inspects of a remote file - once - and name it (W2.2).

        One forward read gives the text, the archive head and the identity. Before W2.2 it
        read every file to its last byte for a whole-file hash; now it reads:

        - a text file up to its cap (``max_read_bytes``): whole within it, identity the
          whole-file SHA-256; past it, the first ``cap`` bytes, identity ``head:``;
        - a document or image within its cap: whole; over it, nothing (SKIPPED_POLICY);
        - a zip whose entries are inspected: up to MAX_ARCHIVE_TOTAL_BYTES, as before;
        - anything else: nothing, identity by DSPM_HASH_POLICY (meta by default; a zip's
          protection is read from its directory by range, not from a capture).

        Under DSPM_HASH_POLICY=full every byte is read, as before. A transport or
        short-read failure falls back to the independent readers.
        """
        file_size = max(0, int(size or 0))
        preview_requested = self._preview_requested(extension)
        document = extension in BINARY_TEXT_EXTENSIONS or is_ocr_scannable(extension)
        if preview_requested and document:
            cap = max_image_bytes() if extension not in BINARY_TEXT_EXTENSIONS else content_policy.document_cap_bytes()
            if file_size > cap:
                cap_name = "DSPM_DOCUMENT_SCAN_MAX_BYTES" if extension in BINARY_TEXT_EXTENSIONS else "DSPM_OCR_MAX_FILE_BYTES"
                self._bump_diag("content_skipped_over_cap")
                return _SMBFileData(
                    content="", extraction_reason="over_size_cap",
                    sha256=self._identity_without_content(share_name, path, file_size, modified_at, file_id),
                    skip_reason=f"Larger than {cap_name} ({cap // (1024 * 1024)} MiB); its content was not read")
        if not self._single_pass_enabled() or self.connection is None:
            return self._read_separately(share_name, path, extension, size, modified_at=modified_at, file_id=file_id,
                                         inspect_archive_entries=inspect_archive_entries)

        started = time.perf_counter()
        whole_hash = content_policy.hash_policy() == "full"
        text_cap = max(0, int(self.config.max_read_bytes or 0))
        if preview_requested and document:
            preview_limit = read_limit = file_size
        elif preview_requested:
            preview_limit = text_cap
            read_limit = file_size if whole_hash else min(file_size, text_cap)
        else:
            preview_limit = 0
            read_limit = file_size if whole_hash else 0
        capture_archive = extension == ".zip" and inspect_archive_entries
        archive_limit = MAX_ARCHIVE_TOTAL_BYTES if capture_archive else 0
        if capture_archive and file_size <= archive_limit:
            # Its entries are read from this capture: the whole archive, as before.
            read_limit = file_size
        capture_limit = min(read_limit, max(preview_limit, archive_limit))
        if read_limit == 0:
            return _SMBFileData(
                content="", sha256=self._identity_without_content(share_name, path, file_size, modified_at, file_id))
        with capture_budget().take(capture_limit):
            acquired = self._single_pass(share_name, path, extension, file_size, read_limit, capture_limit,
                                         preview_requested, preview_limit, capture_archive, archive_limit,
                                         inspect_archive_entries, chunk_size, started, modified_at, file_id)
        if acquired is None:
            # Outside the budget: the fallback takes its own share, never one on top of this.
            self._bump_diag("single_pass_fallbacks")
            return self._read_separately(share_name, path, extension, file_size, modified_at=modified_at,
                                         file_id=file_id, inspect_archive_entries=inspect_archive_entries)
        return acquired

    def _single_pass(self, share_name: str, path: str, extension: str, file_size: int, read_limit: int,
                     capture_limit: int, preview_requested: bool, preview_limit: int, capture_archive: bool,
                     archive_limit: int, inspect_archive_entries: bool, chunk_size: int, started: float,
                     modified_at: str, file_id: str) -> _SMBFileData | None:
        """The one forward read; None when it failed short and the independent readers
        should try."""
        captured = bytearray()
        digest = hashlib.sha256()
        offset = 0
        requests = 0
        failed = False

        try:
            while offset < read_limit:
                request_size = min(max(1, int(chunk_size)), read_limit - offset)
                buffer = io.BytesIO()
                self.connection.retrieveFileFromOffset(
                    share_name,
                    path,
                    buffer,
                    offset=offset,
                    max_length=request_size,
                )
                requests += 1
                chunk = buffer.getvalue()
                if not chunk:
                    failed = True
                    break
                # A defensive cap keeps a misbehaving transport from hashing or
                # retaining bytes beyond what this read asked for.
                chunk = chunk[: read_limit - offset]
                digest.update(chunk)
                if len(captured) < capture_limit:
                    remaining = capture_limit - len(captured)
                    captured.extend(chunk[:remaining])
                offset += len(chunk)
        except Exception as exc:
            if _is_connection_error(exc):
                # A reset kills the stateful pysmb session. Let the existing
                # share/chunk retry establish a fresh connection instead of
                # attempting legacy fallbacks on a known-dead socket.
                raise _SmbConnectionLost(share_name, _brief(exc)) from exc
            failed = True
            logger.debug("Could not single-pass acquire %s:%s: %s", share_name, path, _brief(exc))
        finally:
            self._bump_diag("single_pass_requests", requests)
            self._bump_diag("single_pass_transferred_bytes", offset)
            self._add_diag_ms("single_pass_elapsed_ms", (time.perf_counter() - started) * 1000)

        if failed or offset != read_limit:
            return None

        preview_bytes = bytes(captured[:preview_limit]) if preview_requested else b""
        truncated = False
        try:
            content, reason, truncated = (self._extract_from_bytes(preview_bytes, extension)
                                          if preview_requested else ("", "", False))
        except Exception as exc:
            # Extraction failure historically produced empty content while the
            # separate hash remained valid. Preserve that exact behavior.
            logger.debug("Could not extract preview for %s:%s: %s", share_name, path, exc)
            content, reason = "", "not_extracted"
        if offset == file_size:
            identity = digest.hexdigest()
        elif preview_requested and offset == preview_limit:
            identity = content_policy.head_identity(preview_limit, digest.hexdigest())
        else:
            identity = self._identity_without_content(share_name, path, file_size, modified_at, file_id)

        archive_bytes = bytes(captured[:archive_limit]) if capture_archive else None
        avoided_fetches = int(preview_requested)
        avoided_bytes = len(preview_bytes)
        if capture_archive:
            # Every top-level ZIP is inspected for protection; entry inspection
            # previously performed one additional fetch of the same prefix.
            avoided_fetches += 1 + int(inspect_archive_entries)
            avoided_bytes += len(archive_bytes or b"") * (1 + int(inspect_archive_entries))
        self._bump_diag("single_pass_files")
        self._bump_diag("single_pass_avoided_fetches", avoided_fetches)
        self._bump_diag("single_pass_avoided_transfer_bytes", avoided_bytes)
        return _SMBFileData(
            content=content,
            sha256=identity,
            archive_bytes=archive_bytes,
            extraction_reason=reason,
            truncated=truncated,
        )

    def _identity_without_content(self, share_name: str, path: str, size: int, modified_at: str = "",
                                  file_id: str = "") -> str:
        """A file not read whole for content, by DSPM_HASH_POLICY: meta (nothing read),
        sampled (first and last MiB), full (every byte)."""
        policy = content_policy.hash_policy()
        if policy == "full" or (policy == "sampled" and not content_policy.needs_sample(size)):
            return self._hash_file(share_name, path, size)
        if policy == "sampled" and self.connection is not None:
            sample = content_policy.SAMPLE_BYTES
            try:
                head, tail = io.BytesIO(), io.BytesIO()
                self.connection.retrieveFileFromOffset(share_name, path, head, offset=0, max_length=sample)
                self.connection.retrieveFileFromOffset(share_name, path, tail, offset=max(0, size - sample),
                                                       max_length=sample)
                self._bump_diag("single_pass_transferred_bytes", len(head.getvalue()) + len(tail.getvalue()))
                return content_policy.sampled_identity(size, head.getvalue(), tail.getvalue())
            except Exception as exc:
                if _is_connection_error(exc):
                    raise _SmbConnectionLost(share_name, _brief(exc)) from exc
                return ""
        self._bump_diag("identity_without_read")
        return content_policy.meta_identity(size, modified_at, file_id)

    def _read_separately(self, share_name: str, path: str, extension: str, size: int, *, modified_at: str = "",
                         file_id: str = "", inspect_archive_entries: bool = False) -> _SMBFileData:
        """The preview and the identity, each read on its own - with single pass off, or
        after it failed. A dropped connection is the chunk's to retry on a fresh one. A read
        this file alone refused is said on its record: it used to come back as content ''
        and sha '', a file with nothing in it, and the scan counted as complete."""
        content, reason, read_error, truncated = "", "", "", False
        preview = self.connection is not None and self._preview_requested(extension)
        if preview:
            try:
                content, reason, truncated = self._fetch_preview(share_name, path, extension, size)
            except Exception as exc:
                if _is_connection_error(exc):
                    raise _SmbConnectionLost(share_name, _brief(exc)) from exc
                logger.debug("Could not read preview for %s:%s: %s", share_name, path, _brief(exc))
                read_error = type(exc).__name__
        text_cap = max(0, int(self.config.max_read_bytes or 0))
        document = extension in BINARY_TEXT_EXTENSIONS or is_ocr_scannable(extension)
        # A zip whose entries are read is read whole within the archive cap: named as the
        # single pass names it.
        whole_zip = extension == ".zip" and inspect_archive_entries and size <= MAX_ARCHIVE_TOTAL_BYTES
        if content_policy.hash_policy() == "full" or whole_zip or (preview and (document or size <= text_cap)):
            sha256 = self._hash_file(share_name, path, size)
        elif preview:
            prefix = self._hash_file(share_name, path, text_cap)
            sha256 = content_policy.head_identity(text_cap, prefix)
        else:
            sha256 = self._identity_without_content(share_name, path, size, modified_at, file_id)
        if not sha256 and self.connection is not None:
            read_error = read_error or "IncompleteRead"
        return _SMBFileData(content=content, sha256=sha256, extraction_reason=reason, read_error=read_error,
                            truncated=truncated)

    def _preview_requested(self, extension: str) -> bool:
        return bool(self.config.read_content and (
            extension in TEXT_EXTENSIONS or extension in BINARY_TEXT_EXTENSIONS or is_ocr_scannable(extension)))

    def _content_fields(self, extension: str, file_size: int, acquired: _SMBFileData, protected_metadata: dict) -> dict:
        """What a file record says about its content: its status, whether it is protected,
        why it was not read, and how much of it was. A document is read whole within its
        cap, so it is partial only when the extractor cut its text short (W2.2, E5)."""
        content = acquired.content
        document = extension in BINARY_TEXT_EXTENSIONS or is_ocr_scannable(extension)
        max_read = file_size if document else self.config.max_read_bytes
        cut = bool(content) and (file_size > max_read or acquired.truncated)
        fields = {
            "content": "" if protected_metadata else content,
            "content_status": protected_metadata.get("content_status")
            or content_status_for_extension(extension, content, self.config.read_content),
            "content_scannable": bool(protected_metadata.get(
                "content_scannable", extension in CONTENT_EXTENSIONS or is_ocr_scannable(extension))),
            "protected": bool(protected_metadata.get("protected", False)),
            "protection_type": protected_metadata.get("protection_type", ""),
            "scan_error": protected_metadata.get("scan_error", ""),
            "scan_completeness": "PARTIAL" if cut
            else "FULL" if content or file_size == 0 else "NONE",
            "bytes_scanned": min(file_size, max_read) if content else 0,
            "truncated": cut,
            "skip_reason": "",
        }
        if protected_metadata or content:
            return fields
        if acquired.skip_reason:
            fields.update({"content_status": acquired.extraction_reason or "over_size_cap",
                           "scan_completeness": "NONE", "skip_reason": acquired.skip_reason})
            return fields
        if acquired.read_error:
            fields.update({"content_status": "unreadable", "scan_completeness": "NONE", "bytes_scanned": 0,
                           "scan_error": f"The file could not be read ({acquired.read_error})"})
        elif acquired.extraction_reason == "password_protected":
            fields.update({"content_status": "password_protected", "protected": True,
                           "protection_type": "document_password", "scan_completeness": "NONE",
                           "scan_error": "The document is encrypted and needs a password"})
        elif acquired.extraction_reason:
            fields.update({"content_status": acquired.extraction_reason, "scan_completeness": "NONE"})
        return fields

    def _note_unreadable(self, share_name: str, path: str, acquired: _SMBFileData) -> None:
        # A file that could not be read leaves the scan incomplete, like a folder that could
        # not be listed: what it holds was not looked at.
        if not acquired.read_error:
            return
        with self._walk_lock:
            errors = self.last_scan_diagnostics.setdefault("scan_errors", [])
            if isinstance(errors, list) and len(errors) < 100:
                errors.append({"share": share_name, "path": path, "error": acquired.read_error})

    def _build_work_records(self, work: _SMBFileWork) -> list[dict]:
        records: list[dict] = []
        if not work.include_top:
            if work.inspect_archive_entries:
                records.extend(
                    self._read_zip_entries(
                        work.share_name,
                        work.remote_path,
                        work.is_hidden,
                        work.is_system,
                        size=work.file_size,
                    )
                )
            return records

        if work.offline:
            acquired = self._offline_data(work.share_name, work.remote_path, work.file_size, work.modified_at,
                                          work.file_id)
        else:
            acquired = self._acquire_file_data(
                work.share_name,
                work.remote_path,
                work.extension,
                work.file_size,
                inspect_archive_entries=work.inspect_archive_entries,
                modified_at=work.modified_at,
                file_id=work.file_id,
            )
        if work.inspect_archive_entries and not work.offline:
            records.extend(
                self._read_zip_entries(
                    work.share_name,
                    work.remote_path,
                    work.is_hidden,
                    work.is_system,
                    archive_data=acquired.archive_bytes,
                    size=work.file_size,
                )
            )
        archive_metadata = archive_protection_metadata(work.extension)
        zip_metadata = (
            self._inspect_zip_protection(
                work.share_name,
                work.remote_path,
                archive_data=acquired.archive_bytes,
                size=work.file_size,
                directory_only=not work.inspect_archive_entries,
            )
            if work.extension == ".zip" and not work.offline
            else {}
        )
        protected_metadata = zip_metadata or archive_metadata
        sha256 = acquired.sha256
        self._note_unreadable(work.share_name, work.remote_path, acquired)
        acl = self._acl_for_path(work.share_name, work.remote_path)
        owner = str(acl.get("owner") or "")
        fields = self._content_fields(work.extension, work.file_size, acquired, protected_metadata)
        records.append(
            {
                "source": "smb",
                "share": work.share_name,
                "path": work.remote_path,
                "name": work.name,
                "size": work.file_size,
                "extension": work.extension,
                "is_dir": False,
                "is_hidden": work.is_hidden,
                "is_system": work.is_system,
                "content": fields["content"],
                "acl": acl,
                "scan_mode": scan_mode_for_extension(work.extension),
                "content_status": fields["content_status"],
                "content_scannable": fields["content_scannable"],
                "protected": fields["protected"],
                "protection_type": fields["protection_type"],
                "scan_error": fields["scan_error"],
                "owner": owner,
                "created_at": work.created_at,
                "modified_at": work.modified_at,
                "attributes": work.attributes,
                "sha256": sha256,
                "file_hash": sha256,
                "scan_completeness": fields["scan_completeness"],
                "bytes_scanned": fields["bytes_scanned"],
                "total_bytes": work.file_size,
                "truncated": fields["truncated"],
                "skip_reason": fields["skip_reason"],
                "reuse_key": work.reuse_key,
            }
        )
        return records

    def _io_worker_count(self) -> int:
        """Bounded parallel-share worker count. Falls back to the process
        parallelism policy's ``io_workers`` when the scan config doesn't pin
        one explicitly."""
        configured = self.config.io_workers if self.config.io_workers and self.config.io_workers > 0 else 0
        workers = configured or resolve_parallelism().io_workers
        return max(1, int(workers))

    def _should_parallelize(self, share_count: int) -> bool:
        """Parallel per-share acquisition is ON by default (Track P-B.2). It
        only engages with real fan-out - more than one scannable share AND more
        than one worker - so a single-share target keeps the simpler serial
        path. ``DSPM_SMB_PARALLEL=0`` forces serial as an operational escape
        hatch for a server that mishandles concurrent sessions."""
        if os.getenv("DSPM_SMB_PARALLEL", "1").strip().lower() in {"0", "false", "no", "off"}:
            return False
        return share_count > 1 and self._io_worker_count() > 1

    def _scan_one_share(self, share_name: str) -> tuple[list[dict], bool]:
        """Walk ONE share on the CURRENT thread's connection, retrying once on a
        connection reset. Returns ``(records, completed)``; a share that never
        completes returns ``([], False)``. Records stream to the pipeline
        ``record_callback`` only after the share's walk fully succeeds, so a
        failed/retried attempt never emits partial or duplicate records (a
        mid-walk reset raises ``_SmbConnectionLost`` and discards that attempt's
        records). The reset circuit-breaker is process-shared: repeated resets
        set ``_abort_event`` to stop the remaining shares rather than hammer a
        failing server."""
        for attempt in range(2):
            if self._abort_event.is_set():
                return [], False
            try:
                share_records = self._walk_share(share_name, "/", depth=0)
            except _SmbConnectionLost as lost:
                with self._reset_lock:
                    self._consecutive_resets += 1
                    tripped = self._consecutive_resets >= 5
                logger.warning(
                    "Connection reset scanning share %s (%s); reconnecting%s",
                    share_name, lost.detail,
                    " and retrying the share" if attempt == 0 else " for the remaining shares",
                )
                if tripped or not self._reconnect():
                    self._abort_event.set()
                    logger.error(
                        "The SMB server keeps resetting the connection; aborting the "
                        "remaining shares. This is a connection-level failure (network, "
                        "SMB signing/encryption mismatch, or server-side policy) - not a "
                        "per-share permission issue."
                    )
                    return [], False
                continue
            with self._reset_lock:
                self._consecutive_resets = 0
            callback = self.config.record_callback
            if callback is not None:
                for record in share_records:
                    callback(record)
            return share_records, True
        return [], False

    def _scan_shares_serial(self, shares: list[str], budget) -> tuple[list[dict], list[str], str]:
        """Walk the shares one at a time on the single already-open connection,
        holding one process-wide admission slot for the scan's duration."""
        records: list[dict] = []
        reset_shares: list[str] = []
        with budget.slot(), self._target_gate().session():
            for share_name in shares:
                if self._cancelled():
                    raise RuntimeError("Scan cancelled")
                if self._abort_event.is_set():
                    break
                share_records, completed = self._scan_one_share(share_name)
                if completed:
                    records.extend(share_records)
                else:
                    reset_shares.append(share_name)
        aborted_reason = "smb_connection_reset" if self._abort_event.is_set() else ""
        return records, reset_shares, aborted_reason

    def _scan_shares_parallel(self, shares: list[str], budget) -> tuple[list[dict], list[str], str]:
        """Walk the shares concurrently, each worker on its OWN isolated
        (thread-local) connection and its own process-wide admission slot. The
        record list is re-assembled in the ORIGINAL share order so output is
        deterministic regardless of finish order (semantic parity with the
        serial path).

        Each share resolves to one of three states:

        * ``done``    - walked successfully; its records are kept.
        * ``reset``   - actually attempted and lost the connection (retry
          exhausted, or the reset circuit-breaker tripped during ITS walk).
        * ``skipped`` - the circuit-breaker had already tripped, so this share
          was never attempted. Like the serial path's post-abort shares, a
          skipped share is neither scanned nor counted as reset - it just was
          not reached. This bounds how many shares a broken server is hammered
          with to roughly the worker pool, instead of every share."""
        worker_count = max(1, min(self._io_worker_count(), len(shares)))

        def run(share_name: str) -> tuple[str, list[dict], str]:
            if self._abort_event.is_set() or self._cancelled():
                return share_name, [], "skipped"
            with budget.slot(), self._target_gate().session():
                if self._abort_event.is_set() or self._cancelled():
                    return share_name, [], "skipped"
                if not self.connect():  # this worker's OWN thread-local connection
                    return share_name, [], "reset"
                try:
                    share_records, completed = self._scan_one_share(share_name)
                finally:
                    self.close()  # close THIS thread's connection (thread-local: isolated)
            return share_name, share_records, ("done" if completed else "reset")

        results: dict[str, tuple[list[dict], str]] = {}
        with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="dspm-smb-io") as executor:
            futures = [executor.submit(run, share_name) for share_name in shares]
            for future in as_completed(futures):
                try:
                    share_name, share_records, status = future.result()
                except BaseException:
                    # A cancel (RuntimeError) or unexpected failure in one worker
                    # aborts the whole scan (matching the serial path); signal the
                    # rest to stop promptly, then propagate.
                    self._abort_event.set()
                    raise
                results[share_name] = (share_records, status)

        records: list[dict] = []
        reset_shares: list[str] = []
        for share_name in shares:  # deterministic: original discovery order
            share_records, status = results.get(share_name, ([], "skipped"))
            if status == "done":
                records.extend(share_records)
            elif status == "reset":
                reset_shares.append(share_name)
        aborted_reason = "smb_connection_reset" if self._abort_event.is_set() else ""
        return records, reset_shares, aborted_reason

    @staticmethod
    def _norm_share_path(value: str) -> str:
        return "/" + str(value or "").replace("\\", "/").strip("/")

    def _share_selected(self, share_name: str) -> bool:
        """Whether this scan walks a share: every share, unless ``allowed_shares`` names some
        (B2.3). A person names them too (D1), and Windows share names ignore case."""
        if self.config.allowed_shares is None:
            return True
        return share_name.casefold() in {name.casefold() for name in self.config.allowed_shares}

    def plan_share_groups(self, stop_check: Callable[[], str | None] | None = None) -> list[list[str]] | None:
        """The shares a scan walks, in its order, cut into groups no overlap crosses (B2.3).

        The overlapping-share collapse only ever matches a file in one share with the
        same file seen through a share whose root holds a folder named like the first.
        So two shares can overlap only if one's root lists a folder with the other's
        name. Groups that keep every such pair together - contiguous in the server's
        listing order, so the groups in sequence are one scan's order - collapse
        exactly what a scan of every share at once collapses.

        This costs one root listing per share. A share whose root cannot be read yields
        nothing through it in the scan either, so it overlaps nothing. Returns ``None``
        when the plan cannot be trusted: the server cannot be reached, or a connection
        dropped while a root was being listed.
        """
        if not self.connect():
            return None
        try:
            shares = [
                share.name
                for share in list(self.connection.listShares())
                if not self._skip_share(share.name) and self._share_selected(share.name)
            ]
            folders: dict[str, set[str]] = {}
            for share_name in shares:
                reason = stop_check() if stop_check is not None else None
                if reason:
                    raise RuntimeError(reason)
                try:
                    entries = self.connection.listPath(share_name, "/")
                except Exception as exc:
                    # Only a root this account may not read is known to yield nothing in
                    # the scan as well. A dropped connection or a timeout might list fine a
                    # moment later, and hide an overlap between groups (B2.3 review).
                    if not _is_access_denied(exc):
                        return None
                    folders[share_name] = set()
                    continue
                folders[share_name] = {
                    str(entry.filename).casefold()
                    for entry in entries
                    if entry.isDirectory and entry.filename not in {".", ".."}
                }
        finally:
            self.close()
        spans = sorted(
            sorted((broad_index, narrow_index))
            for broad_index, broad in enumerate(shares)
            for narrow_index, narrow in enumerate(shares)
            if narrow_index != broad_index and narrow.casefold() in folders[broad]
        )
        merged: list[list[int]] = []
        for low, high in spans:
            if merged and low <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], high)
            else:
                merged.append([low, high])
        groups: list[list[str]] = []
        position = 0
        for low, high in merged:
            groups.extend([name] for name in shares[position:low])
            groups.append(shares[low:high + 1])
            position = high + 1
        groups.extend([name] for name in shares[position:])
        return groups

    def plan_share_ranges(
        self,
        share_name: str,
        *,
        max_files: int,
        max_bytes: int,
        stop_check: Callable[[], str | None] | None = None,
    ) -> list[dict] | None:
        """Cut one share into units of at most ``max_files`` files and ``max_bytes`` of reads (W1.2).

        A share used to be the smallest unit an SMB scan had, so its memory and its time
        followed its largest share. This walks the share's folders - names and sizes,
        nothing read - and cuts it the way :func:`discovery.partition.plan_bounded_partitions`
        cuts a local tree: a folder that fits stays inside its parent's unit, a larger
        one is cut into runs of its own entries, and a subfolder too large for one run is
        cut in place. A unit is a half-open range of case-folded names in one folder,
        ``[name_from, name_to)``, and the ranges of a folder are contiguous, so every
        entry it held when planned is in exactly one - and one that appears later is in
        one too. Bytes are what the scan reads: each file's size, up to the read cap.

        Returns ``None`` when the whole share fits one unit. Raises ``_SmbConnectionLost``
        when the plan cannot be trusted: the connection dropped while a folder was listed.
        """
        if not self.connect():
            raise _SmbConnectionLost(share_name, "could not establish an SMB planning connection")
        read_cap = max(1, int(self.config.max_read_bytes or 1))
        include_hidden_dirs = bool(self.config.include_hidden or self.config.hidden_filter_enabled)
        files_budget = max(1, int(max_files))
        bytes_budget = max(1, int(max_bytes))

        def visit(folder: str, depth: int) -> tuple[int, int, list[dict] | None]:
            if stop_check is not None:
                reason = stop_check()
                if reason:
                    raise RuntimeError(reason)
            if depth > self.config.max_depth or self._skip_path(folder):
                return 0, 0, None
            try:
                entries = self.connection.listPath(share_name, folder)
            except Exception as exc:
                if _is_connection_error(exc):
                    raise _SmbConnectionLost(share_name, _brief(exc)) from exc
                # Unreadable: whichever unit holds it lists it and reports the error.
                return 0, 0, None
            children: list[tuple[str, int, int, list[dict] | None]] = []
            files = size = 0
            for entry in sorted(entries, key=lambda item: str(item.filename).casefold()):
                if entry.filename in {".", ".."}:
                    continue
                remote_path = str(PurePosixPath(folder) / entry.filename)
                if self._skip_path(remote_path):
                    continue
                key = str(entry.filename).casefold()
                if entry.isDirectory:
                    if bool(getattr(entry, "isHidden", False)) and not include_hidden_dirs:
                        continue
                    if self._scope.active and self._scope.folder_reason(self._scope_path(share_name, remote_path)):
                        # The walk skips it, and counts it: it weighs nothing here.
                        continue
                    child_files, child_bytes, child_units = visit(remote_path, depth + 1)
                    files += child_files
                    size += child_bytes
                    children.append((key, child_files, child_bytes, child_units))
                    continue
                if self._scope.active and self._scope.file_reason(
                        self._scope_path(share_name, remote_path), detect_extension(remote_path),
                        int(getattr(entry, "file_size", 0) or 0), getattr(entry, "last_write_time", None)):
                    continue  # out of scope: the walk lists it and leaves it, so it weighs nothing
                weight = min(int(getattr(entry, "file_size", 0) or 0), read_cap)
                files += 1
                size += weight
                children.append((key, 1, weight, None))
            if files <= files_budget and size <= bytes_budget:
                return files, size, None
            units: list[dict] = []
            low = ""
            run_files = run_bytes = 0

            def flush(high: str) -> None:
                nonlocal run_files, run_bytes
                units.append({"kind": "smb_range", "share": share_name, "folder": folder, "depth": depth,
                              "name_from": low, "name_to": high})
                run_files = run_bytes = 0

            for key, child_files, child_bytes, child_units in children:
                if child_units is not None:
                    flush(key)
                    units.extend(child_units)
                    low = key + "\x00"
                    continue
                if (run_files or run_bytes) and (run_files + child_files > files_budget
                                                  or run_bytes + child_bytes > bytes_budget):
                    flush(key)
                    low = key
                run_files += child_files
                run_bytes += child_bytes
            flush("")
            return files, size, units

        try:
            _files, _bytes, units = visit("/", 0)
        finally:
            self.close()
        return units

    def _dedupe_overlapping_shares(self, records: list[dict]) -> list[dict]:
        """Collapse the SAME physical file surfaced through overlapping SMB shares.

        When a server exports both a nested share (e.g. ``HR`` -> D:\\Shares\\HR)
        and a parent share (e.g. ``Shares`` -> D:\\Shares), one physical file is
        walked twice: ``HR:/Benefits/f.docx`` and ``Shares:/HR/Benefits/f.docx``.
        Those are the same bytes at the same location, so reporting both double-
        counts findings and risk.

        Collapse ONLY when it is provably the same physical file: identical content
        hash AND the broader share's path equals ``/<narrow-share-name><narrow-
        path>``. We deliberately do NOT collapse mere content duplicates (two
        different files that share the same bytes) - for a DLP tool that is real
        data proliferation and must stay visible. The kept record notes the
        redundant location in ``also_accessible_via``.

        Every pair in a hash group is checked, narrowest location first, and a copy
        found through a copy is credited to the narrowest (B2.3). Before, only the
        single shortest path was compared: a third file with the same bytes elsewhere
        hid a real overlap, and a share nested two deep collapsed one level. Two
        locations in one share are never the same file. So the collapse depends only on
        shares that can overlap, which lets a partitioned scan collapse inside a group
        of shares and match a scan of every share at once.
        """
        by_hash: dict[str, list[dict]] = {}
        for record in records:
            digest = record.get("sha256")
            if digest and not record.get("is_dir"):
                by_hash.setdefault(str(digest), []).append(record)
        drop: set[tuple] = set()
        for group in by_hash.values():
            if len(group) < 2:
                continue
            # Shortest path first = the most-specific (nested) share -> the keeper.
            ordered = sorted(group, key=lambda r: len(self._norm_share_path(r.get("path"))))
            keeper_of: dict[int, dict] = {}
            for record in ordered:
                keeper = keeper_of.get(id(record), record)
                share = str(record.get("share") or "").strip("/")
                broad_path = self._norm_share_path(share + self._norm_share_path(record.get("path")))
                for other in ordered:
                    if other is record or other is keeper or id(other) in keeper_of:
                        continue
                    if other.get("share") == record.get("share"):
                        continue
                    if self._norm_share_path(other.get("path")) == broad_path:
                        keeper_of[id(other)] = keeper
                        drop.add((other.get("share"), other.get("path")))
                        keeper.setdefault("also_accessible_via", []).append(
                            {"share": other.get("share"), "path": other.get("path")}
                        )
        if not drop:
            return records
        self.last_scan_diagnostics["overlapping_share_duplicates_collapsed"] = len(drop)
        return [r for r in records if (r.get("share"), r.get("path")) not in drop]

    def _safe_list_shares(self) -> list[str]:
        if self.connection is None:
            return []
        return [
            share.name
            for share in self.connection.listShares()
            if not self._skip_share(share.name)
        ]

    def _skip_share(self, share_name: str) -> bool:
        """IPC$, print$ and ADMIN$ hold no data and are never walked. A drive's
        administrative share (C$) is walked only with ``include_admin_shares``. Any other
        hidden share - Payroll$, HR$, Finance$ - is walked with ``include_admin_shares`` or
        when the scan names it. Every such share used to be skipped whatever the scan
        said, named or not, and only ever showed up in shares_skipped."""
        if share_name.casefold() in {name.casefold() for name in SYSTEM_SHARES}:
            return True
        if not share_name.endswith("$"):
            return False
        if re.fullmatch(r"[A-Za-z]\$", share_name):
            return not self.config.include_admin_shares
        named = self.config.allowed_shares is not None and self._share_selected(share_name)
        return not (self.config.include_admin_shares or named)

    def _server_candidates(self) -> list[str]:
        server = self.config.server.strip()
        candidates: list[str] = []

        def add(value: str) -> None:
            value = value.strip().rstrip(".")
            if value and value not in candidates:
                candidates.append(value)

        try:
            ipaddress.ip_address(server)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            domain = (self.config.domain.strip() or "").strip(".")
            try:
                reverse_name = socket.gethostbyaddr(server)[0].strip().rstrip(".")
            except OSError:
                reverse_name = ""
            if reverse_name:
                if "." not in reverse_name and domain and domain.upper() != "WORKGROUP":
                    add(f"{reverse_name}.{domain}")
                add(reverse_name)
            add(server)
        else:
            add(server)

        return candidates

    def _target_gate(self):
        """This server's sessions, bandwidth and backoff, shared with every scan of it (W2.3)."""
        return smb_target.target_gate(self.config.server)

    def _offline(self, entry) -> bool:
        """Whether reading the entry would recall it from tiered storage - and it is not to be."""
        return smb_target.needs_recall(getattr(entry, "file_attributes", 0)) and not smb_target.read_offline_files()

    def _offline_data(self, share_name: str, path: str, size: int, modified_at: str, file_id: str) -> _SMBFileData:
        """An offline file's record data: named by its metadata whatever the hash policy -
        any byte read would recall it - and said to be not read."""
        self._target_gate().skipped_offline()
        self._bump_diag("content_skipped_offline")
        return _SMBFileData(
            content="", sha256=content_policy.meta_identity(size, modified_at, file_id),
            extraction_reason="offline_not_recalled",
            skip_reason="The file is offline in tiered storage; reading it would recall it, so its content "
                        "was not read (DSPM_SMB_READ_OFFLINE=1 reads it)")

    def _remember_credential(self, server: str, label: str) -> None:
        with _working_credentials_lock:
            _working_credentials[(str(server).lower(), self.config.username.strip().lower())] = label

    def _credential_candidates(self) -> list[tuple[str, str, str]]:
        candidates = self._credential_candidates_in_order()
        with _working_credentials_lock:
            remembered = _working_credentials.get(
                (str(self.config.server).lower(), self.config.username.strip().lower()))
        if remembered:
            candidates.sort(key=lambda candidate: candidate[2] != remembered)
        return candidates

    def _credential_candidates_in_order(self) -> list[tuple[str, str, str]]:
        username = self.config.username.strip()
        domain = (self.config.domain.strip() or "WORKGROUP").strip()
        server_name = self._server_short_name()
        candidates: list[tuple[str, str, str]] = []

        def add(user: str, dom: str) -> None:
            label = f"{dom}\\{user}" if dom else user
            if (user, dom, label) not in candidates:
                candidates.append((user, dom, label))

        if not username:
            add("", domain)
            return candidates

        if "\\" in username:
            raw_domain, raw_user = username.split("\\", 1)
            add(raw_user, raw_domain)
        elif "@" in username:
            add(username, domain)
        else:
            add(username, domain)
            if domain.upper() == "WORKGROUP" and server_name:
                add(username, server_name)
            if server_name and server_name.upper() != domain.upper():
                add(username, server_name)
            add(username, "")

        return candidates

    def _scope_path(self, share_name: str, remote_path: str) -> str:
        """A share-relative path in the scope's form: ``share/folder/file``."""
        return self._scope.path_of(f"{share_name}/{remote_path}")

    def _scope_skips_folder(self, share_name: str, folder: str) -> bool:
        """Whether a folder - or a whole share, at ``/`` - is out of scope; counted when it is."""
        if self._scope_tally is None:
            return False
        reason = self._scope.folder_reason(self._scope_path(share_name, folder))
        if reason:
            self._scope_tally.folder(reason)
        return bool(reason)

    def _scope_skips_file(self, share_name: str, remote_path: str, extension: str, entry) -> bool:
        """Whether a listed file is out of scope - by its path, extension, size or time, all
        of which the listing gives; counted when it is."""
        if self._scope_tally is None:
            return False
        reason = self._scope.file_reason(self._scope_path(share_name, remote_path), extension,
                                         int(getattr(entry, "file_size", 0) or 0),
                                         getattr(entry, "last_write_time", None))
        if reason:
            self._scope_tally.file(reason)
        return bool(reason)

    def _walk_share(self, share_name: str, folder: str, depth: int) -> list[dict]:
        if self._cancelled():
            raise RuntimeError("Scan cancelled")
        if self.connection is None or depth > self.config.max_depth:
            return []
        if self._skip_path(folder):
            return []
        if self._scope_skips_folder(share_name, folder):
            return []

        records: list[dict] = []
        try:
            entries = self.connection.listPath(share_name, folder)
        except Exception as exc:
            # pysmb's OperationFailure.__str__ embeds the full SMB message history
            # (raw packet hex dumps), which floods the console and leaks internal
            # path/handle bytes. Log only the concise first line.
            brief = str(exc).splitlines()[0][:200] if str(exc) else exc.__class__.__name__
            # A socket-level reset (WinError 10054 etc.) kills the whole session:
            # every later listPath would fail instantly on the dead socket. Signal
            # it so scan() can reconnect once and carry on, instead of logging one
            # misleading error per remaining share.
            if _is_connection_error(exc):
                raise _SmbConnectionLost(share_name, brief) from exc
            logger.warning("Could not list %s:%s: %s", share_name, folder, brief)
            with self._walk_lock:
                errors = self.last_scan_diagnostics.setdefault("list_errors", [])
                if isinstance(errors, list) and len(errors) < 20:
                    errors.append({"share": share_name, "path": folder, "error": brief})
            return records

        for entry in entries:
            if self._cancelled():
                raise RuntimeError("Scan cancelled")
            if entry.filename in {".", ".."}:
                continue

            remote_path = str(PurePosixPath(folder) / entry.filename)
            if self._skip_path(remote_path):
                continue
            is_dir = bool(entry.isDirectory)
            is_hidden = bool(getattr(entry, "isHidden", False))
            is_system = bool(getattr(entry, "isSystem", False))

            if is_dir:
                if is_hidden and not (self.config.include_hidden or self.config.hidden_filter_enabled):
                    continue
                if self._scope_skips_folder(share_name, remote_path):
                    continue
                records.extend(self._walk_share(share_name, remote_path, depth + 1))
                continue

            extension = detect_extension(remote_path)
            with self._walk_lock:
                self._progress_counters["visited"] += 1
            self._emit_collection_progress()
            if self._scope_skips_file(share_name, remote_path, extension, entry):
                continue
            include_top = matches_scan_filters(
                extension,
                is_hidden,
                is_system,
                self.extension_filter,
                self.config.extension_filter_enabled,
                self.config.include_hidden,
                self.config.include_system,
                self.config.hidden_filter_enabled,
                self.config.system_filter_enabled,
            )
            if not include_top and self.config.inspect_archives and self._should_scan_archive_entries(extension):
                records.extend(self._read_zip_entries(share_name, remote_path, is_hidden, is_system,
                                                      size=int(getattr(entry, "file_size", 0) or 0)))
                continue
            if not include_top:
                continue

            file_size = int(getattr(entry, "file_size", 0) or 0)
            modified_at = _format_smb_timestamp(getattr(entry, "last_write_time", None))
            created_at = _format_smb_timestamp(getattr(entry, "create_time", None))
            attributes = ", ".join([item for item in ["H" if is_hidden else "", "S" if is_system else ""] if item]) or "Normal"
            reuse_key = self._reuse_key(share_name, remote_path)

            # Metadata-first reuse: listPath already gave us size + mtime, so an
            # unchanged object can restore its analyzed snapshot (and archive
            # entry bundle) without remote content/hash/ACL work.
            if (
                self.config.reuse_probe is not None
                and modified_at
            ):
                snapshot = None
                try:
                    snapshot = self.config.reuse_probe(reuse_key, file_size, modified_at)
                except Exception:
                    snapshot = None
                if self.config.inspect_archives and extension == ".zip" and not bool((snapshot or {}).get("archive_bundle_complete")):
                    snapshot = None
                if isinstance(snapshot, dict):
                    records.append(
                        {
                            "source": "smb",
                            "share": share_name,
                            "path": remote_path,
                            "name": entry.filename,
                            "size": file_size,
                            "extension": extension,
                            "is_dir": False,
                            "is_hidden": is_hidden,
                            "is_system": is_system,
                            "content": "",
                            "acl": snapshot.get("acl") or {},
                            "scan_mode": scan_mode_for_extension(extension),
                            "content_status": str(snapshot.get("content_status") or "reused_from_cache"),
                            "content_scannable": bool(snapshot.get("content_scannable", (extension in CONTENT_EXTENSIONS or is_ocr_scannable(extension)))),
                            "protected": bool(snapshot.get("protected", False)),
                            "protection_type": str(snapshot.get("protection_type") or ""),
                            "scan_error": str(snapshot.get("scan_error") or ""),
                            "owner": str(snapshot.get("owner") or ""),
                            "created_at": created_at,
                            "modified_at": modified_at,
                            "attributes": attributes,
                            "sha256": str(snapshot.get("sha256") or ""),
                            "file_hash": str(snapshot.get("sha256") or ""),
                            "content_hash": str(snapshot.get("content_hash") or ""),
                            "scan_completeness": str(snapshot.get("scan_completeness") or "UNKNOWN"),
                            "bytes_scanned": int(snapshot.get("bytes_scanned") or 0),
                            "total_bytes": int(snapshot.get("total_bytes") or file_size),
                            "truncated": bool(snapshot.get("truncated", False)),
                            "cache_reused": True,
                            "incremental_reused": bool(snapshot.get("baseline_result")),
                            "reused_preview": snapshot.get("preview") if isinstance(snapshot.get("preview"), dict) else None,
                            "baseline_result": snapshot.get("baseline_result") if isinstance(snapshot.get("baseline_result"), dict) else None,
                            "reuse_key": reuse_key,
                        }
                    )
                    archive_records = snapshot.get("archive_records") if isinstance(snapshot.get("archive_records"), list) else []
                    for prior in archive_records:
                        if not isinstance(prior, dict):
                            continue
                        child_key = str(prior.get("reuse_key") or prior.get("path") or "")
                        records.append(apply_reuse_snapshot(prior, reuse_snapshot_from_result(prior), child_key))
                    with self._walk_lock:
                        self._progress_counters["matched"] += 1 + len(archive_records)
                        self._progress_counters["reused"] += 1 + len(archive_records)
                    self._emit_collection_progress()
                    continue

            offline = self._offline(entry)
            inspect_archive_entries = bool(
                self.config.inspect_archives and self._should_scan_archive_entries(extension) and not offline
            )
            if offline:
                acquired = self._offline_data(share_name, remote_path, file_size, modified_at,
                                              str(getattr(entry, "file_id", "") or ""))
            else:
                acquired = self._acquire_file_data(
                    share_name,
                    remote_path,
                    extension,
                    file_size,
                    inspect_archive_entries=inspect_archive_entries,
                    modified_at=modified_at,
                    file_id=str(getattr(entry, "file_id", "") or ""),
                )
            if inspect_archive_entries:
                records.extend(
                    self._read_zip_entries(
                        share_name,
                        remote_path,
                        is_hidden,
                        is_system,
                        archive_data=acquired.archive_bytes,
                        size=file_size,
                    )
                )
            archive_metadata = archive_protection_metadata(extension)
            zip_metadata = (
                self._inspect_zip_protection(
                    share_name,
                    remote_path,
                    archive_data=acquired.archive_bytes,
                    size=file_size,
                    directory_only=not inspect_archive_entries,
                )
                if extension == ".zip" and not offline
                else {}
            )
            protected_metadata = zip_metadata or archive_metadata
            sha256 = acquired.sha256
            self._note_unreadable(share_name, remote_path, acquired)
            acl = self._acl_for_path(share_name, remote_path)
            owner = str(acl.get("owner") or "")
            fields = self._content_fields(extension, file_size, acquired, protected_metadata)
            records.append(
                {
                    "source": "smb",
                    "share": share_name,
                    "path": remote_path,
                    "name": entry.filename,
                    "size": file_size,
                    "extension": extension,
                    "is_dir": False,
                    "is_hidden": is_hidden,
                    "is_system": is_system,
                    "content": fields["content"],
                    "acl": acl,
                    "scan_mode": scan_mode_for_extension(extension),
                    "content_status": fields["content_status"],
                    "content_scannable": fields["content_scannable"],
                    "protected": fields["protected"],
                    "protection_type": fields["protection_type"],
                    "scan_error": fields["scan_error"],
                    "owner": owner,
                    "created_at": created_at,
                    "modified_at": modified_at,
                    "attributes": attributes,
                    "sha256": sha256,
                    "file_hash": sha256,
                    "scan_completeness": fields["scan_completeness"],
                    "bytes_scanned": fields["bytes_scanned"],
                    "total_bytes": file_size,
                    "truncated": fields["truncated"],
                    "skip_reason": fields["skip_reason"],
                    "reuse_key": reuse_key,
                }
            )
            with self._walk_lock:
                self._progress_counters["matched"] += 1
            self._emit_collection_progress()

        return records

    def _should_scan_archive_entries(self, extension: str) -> bool:
        return extension == ".zip" and self.config.inspect_archives

    def _read_zip_entries(
        self,
        share_name: str,
        path: str,
        is_hidden: bool,
        is_system: bool,
        archive_data: bytes | None = None,
        size: int | None = None,
    ) -> list[dict]:
        if self.connection is None and archive_data is None:
            return []
        try:
            source = self._archive_source(share_name, path, archive_data, size)
            ranged = getattr(source, "raw", None)
            records: list[dict] = []
            with zipfile.ZipFile(source) as archive:
                entries = archive.infolist()[:MAX_ARCHIVE_ENTRIES]
                for entry in entries:
                    if entry.is_dir():
                        continue
                    if not self._safe_zip_entry(entry):
                        continue
                    extension = detect_extension(entry.filename)
                    if not matches_scan_filters(
                        extension,
                        is_hidden,
                        is_system,
                        self.extension_filter,
                        self.config.extension_filter_enabled,
                        self.config.include_hidden,
                        self.config.include_system,
                        self.config.hidden_filter_enabled,
                        self.config.system_filter_enabled,
                    ):
                        continue
                    content = ""
                    protected = False
                    content_status = content_status_for_extension(extension, content, self.config.read_content)
                    content_scannable = (extension in CONTENT_EXTENSIONS or is_ocr_scannable(extension))
                    protection_type = ""
                    scan_error = ""
                    if entry.flag_bits & 0x1:
                        protected = True
                        content_status = "password_protected"
                        content_scannable = False
                        protection_type = "zip_password"
                        scan_error = "ZIP entry is encrypted and requires a password"
                    elif archive_metadata := archive_protection_metadata(extension):
                        protected = bool(archive_metadata.get("protected", False))
                        content_status = str(archive_metadata.get("content_status") or content_status)
                        content_scannable = bool(archive_metadata.get("content_scannable", content_scannable))
                        protection_type = str(archive_metadata.get("protection_type") or "")
                        scan_error = str(archive_metadata.get("scan_error") or "")
                    if (not protected and self.config.read_content and extension in TEXT_EXTENSIONS
                            and isinstance(ranged, _SmbRangeFile)
                            and ranged.transferred + int(entry.compress_size or 0) + _RANGE_READ_BUFFER > ranged.budget):
                        # An archive read by range stops at the bytes a scan keeps of one
                        # file: what is past them is listed, not read.
                        content_status = "not_inspected"
                    elif not protected and self.config.read_content and extension in TEXT_EXTENSIONS:
                        try:
                            with archive.open(entry) as handle:
                                content = decode_text(handle.read(min(self.config.max_read_bytes, MAX_ARCHIVE_ENTRY_BYTES)))
                                content_status = content_status_for_extension(extension, content, self.config.read_content)
                        except (OSError, RuntimeError, zipfile.BadZipFile):
                            protected = True
                            content_status = "password_protected"
                            content_scannable = False
                            protection_type = "zip_password"
                            scan_error = "ZIP entry is encrypted or unreadable and requires review"
                            content = ""
                    acl = self._acl_for_path(share_name, path)
                    owner = str(acl.get("owner") or "")
                    records.append(
                        {
                            "source": "smb",
                            "share": share_name,
                            "path": f"{path}::{entry.filename}",
                            "name": PurePosixPath(entry.filename).name,
                            "size": int(entry.file_size or 0),
                            "extension": extension,
                            "is_dir": False,
                            "is_hidden": is_hidden,
                            "is_system": is_system,
                            "content": content,
                            "acl": acl,
                            "scan_mode": scan_mode_for_extension(extension),
                            "content_status": content_status,
                            "content_scannable": content_scannable,
                            "protected": protected,
                            "protection_type": protection_type,
                            "scan_error": scan_error,
                            "owner": owner,
                            "scan_completeness": "FULL" if content or int(entry.file_size or 0) == 0 else "NONE",
                            "bytes_scanned": min(int(entry.file_size or 0), MAX_ARCHIVE_ENTRY_BYTES) if content else 0,
                            "total_bytes": int(entry.file_size or 0),
                            "truncated": int(entry.file_size or 0) > MAX_ARCHIVE_ENTRY_BYTES,
                            "reuse_key": f"{self._reuse_key(share_name, path)}::{entry.filename}",
                        }
                    )
            return records
        except Exception as exc:
            if _is_connection_error(exc):
                raise _SmbConnectionLost(share_name, _brief(exc)) from exc
            logger.debug("Could not inspect archive entries for %s:%s: %s", share_name, path, _brief(exc))
            return []

    def _archive_source(self, share_name: str, path: str, archive_data: bytes | None, size: int | None,
                        directory_only: bool = False):
        """What zipfile opens the archive from: the bytes already captured when they are the
        whole file; the remote file read by range when it is larger than a scan keeps (its
        directory is at the end, past any prefix) or when only its directory is wanted (W2.2:
        a protection check reads the directory, not the archive); else the whole file."""
        if archive_data is not None and (size is None or len(archive_data) >= size):
            return io.BytesIO(archive_data)
        if size is not None and (size > MAX_ARCHIVE_TOTAL_BYTES or directory_only):
            ranged = _SmbRangeFile(self.connection, share_name, path, size, MAX_ARCHIVE_TOTAL_BYTES)
            return io.BufferedReader(ranged, buffer_size=_RANGE_READ_BUFFER)
        buffer = io.BytesIO()
        self.connection.retrieveFileFromOffset(
            share_name,
            path,
            buffer,
            offset=0,
            max_length=MAX_ARCHIVE_TOTAL_BYTES,
        )
        buffer.seek(0)
        return buffer

    def _inspect_zip_protection(
        self,
        share_name: str,
        path: str,
        archive_data: bytes | None = None,
        size: int | None = None,
        directory_only: bool = False,
    ) -> dict[str, str | bool]:
        if self.connection is None and archive_data is None:
            return {}
        try:
            with zipfile.ZipFile(self._archive_source(share_name, path, archive_data, size,
                                                      directory_only)) as archive:
                encrypted = any(bool(entry.flag_bits & 0x1) for entry in archive.infolist()[:2000])
                if encrypted:
                    return {
                        "protected": True,
                        "content_status": "password_protected",
                        "content_scannable": False,
                        "protection_type": "zip_password",
                        "scan_error": "ZIP archive has encrypted entries and needs a password",
                    }
        except _ArchiveTooLarge:
            # Its directory alone is more than a scan reads of one file: not inspected,
            # which is not the same as protected.
            return {
                "content_status": "not_inspected",
                "content_scannable": False,
                "scan_error": "ZIP archive is too large to inspect",
            }
        except Exception as exc:
            if _is_connection_error(exc):
                raise _SmbConnectionLost(share_name, _brief(exc)) from exc
            return {
                "protected": True,
                "content_status": "bad_archive",
                "content_scannable": False,
                "protection_type": "unreadable_archive",
                "scan_error": "ZIP archive could not be opened or parsed",
            }
        return {}

    def _safe_zip_entry(self, entry: zipfile.ZipInfo) -> bool:
        name = str(entry.filename or "")
        try:
            parts = PurePosixPath(name).parts
        except Exception:
            return False
        if name.startswith("/") or ".." in parts:
            return False
        file_size = int(entry.file_size or 0)
        compressed = max(1, int(entry.compress_size or 1))
        if file_size > MAX_ARCHIVE_ENTRY_BYTES or compressed > MAX_ARCHIVE_ENTRY_BYTES:
            return False
        return file_size / compressed <= 100

    def _skip_path(self, path: str) -> bool:
        normalized = path.replace("/", "\\").lower()
        if not normalized.endswith("\\"):
            normalized = f"{normalized}\\"
        skip_fragments = (
            "\\enterprise_test_data\\",
            "\\dspm_project-main\\",
            "\\.codex\\",
            "\\.git\\",
            "\\.vscode\\",
            "\\node_modules\\",
            "\\$recycle.bin\\",
            "\\system volume information\\",
            "\\$winreagent\\",
            "\\recovery\\",
            "\\config.msi\\",
            "\\perflogs\\",
            "\\msocache\\",
            "\\windows\\",
            "\\program files\\",
            "\\program files (x86)\\",
            "\\programdata\\",
            "\\appdata\\local\\temp\\",
            "\\appdata\\local\\microsoft\\edge\\",
            "\\appdata\\local\\google\\chrome\\",
            "\\appdata\\local\\packages\\",
            "\\appdata\\roaming\\microsoft\\windows\\recent\\",
        )
        return any(fragment in normalized for fragment in skip_fragments)

    def _unc_path(self, share_name: str, path: str) -> str:
        relative = path.replace("/", "\\").lstrip("\\")
        server = self.server_used or self.config.server
        return f"\\\\{server}\\{share_name}\\{relative}" if relative else f"\\\\{server}\\{share_name}"

    def _owner_for_path(self, share_name: str, path: str) -> str:
        return str(self._acl_for_path(share_name, path).get("owner") or "")

    def _add_diag_ms(self, key: str, elapsed_ms: float) -> None:
        with self._walk_lock:
            current = float(self.last_scan_diagnostics.get(key) or 0.0)
            self.last_scan_diagnostics[key] = round(current + max(0.0, elapsed_ms), 3)

    def _prefetch_acl_paths(self, share_name: str, paths: list[str]) -> None:
        """Populate the ACL cache with one PowerShell process for a path batch.

        A batch-level launch/parse failure falls back to the original per-file
        implementation. Item-level failures also fall back individually, keeping
        the batch fast for accessible paths without losing a second chance at
        full owner/principal/permission detail for a transient failure.
        """
        unique_paths = list(dict.fromkeys(str(path) for path in paths if str(path or "")))
        with self._acl_lock:
            pending = [
                path
                for path in unique_paths
                if self._unc_path(share_name, path) not in self._acl_cache
            ]
        if not pending:
            return

        # In-process first: this usually clears the whole batch without
        # launching anything.
        if win_security.available():
            still_pending = []
            for path in pending:
                # Only a resolved read counts as an attempt here; an unresolved
                # one falls through to _acl_for_path, which counts it itself.
                if self._acl_inproc(self._unc_path(share_name, path)) is None:
                    still_pending.append(path)
                else:
                    self._bump_diag("owner_read_attempts")
            pending = still_pending
            if not pending:
                return

        if not self._acl_batch_enabled():
            for path in pending:
                self._acl_for_path(share_name, path)
            return

        batched = self._acl_batch_for_paths(share_name, pending)
        if batched is None:
            self._bump_diag("acl_batch_fallback_paths", len(pending))
            for path in pending:
                self._acl_for_path(share_name, path)
            return

        completed_paths = [path for path in pending if path in batched]
        if completed_paths:
            self._bump_diag("owner_read_attempts", len(completed_paths))
            self._bump_diag("acl_batch_paths", len(completed_paths))
        for path in completed_paths:
            normalized_acl = batched[path]
            if not normalized_acl.get("owner"):
                self._bump_diag("owner_read_failed")
            if normalized_acl.get("principals"):
                self._bump_diag("acl_read_success")
            unc_path = self._unc_path(share_name, path)
            with self._acl_lock:
                self._owner_cache[unc_path] = str(normalized_acl.get("owner") or "")
                self._acl_cache[unc_path] = normalized_acl

        missing = [path for path in pending if path not in batched]
        if missing:
            self._bump_diag("acl_batch_fallback_paths", len(missing))
            for path in missing:
                self._acl_for_path(share_name, path)

    def _acl_batch_timeout_seconds(self, path_count: int) -> float:
        configured = os.getenv("DSPM_SMB_ACL_BATCH_TIMEOUT_SECONDS", "").strip()
        if configured:
            try:
                return max(12.0, min(float(configured), 1800.0))
            except ValueError:
                pass
        return max(12.0, min(15.0 + max(1, path_count) * 3.0, 600.0))

    def _acl_batch_for_paths(self, share_name: str, paths: list[str]) -> dict[str, dict] | None:
        """Read full Windows ACL detail for many paths in one PowerShell session.

        Credentials remain off argv: only the non-secret path/user payload is
        encoded into the command, while the password travels in the child
        environment exactly as in the legacy implementation.

        The payload rides in the command line, which Windows caps at 32,767
        characters. Encoded twice, 32 paths of 80 characters came to 41,536: the
        launch failed with an OSError and every path fell back to a PowerShell
        process of its own (E6). A batch whose command would not fit is halved until
        each half does; a single path that cannot fit falls back alone.
        """
        if not paths:
            return {}
        encoded_script = self._acl_batch_command(share_name, paths)
        if len(encoded_script) > ACL_BATCH_COMMAND_LIMIT:
            if len(paths) == 1:
                self._bump_diag("acl_batch_path_too_long")
                return {}
            self._bump_diag("acl_batch_splits")
            middle = len(paths) // 2
            merged: dict[str, dict] = {}
            for half in (paths[:middle], paths[middle:]):
                merged.update(self._acl_batch_for_paths(share_name, half) or {})
            return merged
        share_root = self._unc_path(share_name, "")
        started = time.perf_counter()
        self._bump_diag("acl_batch_processes")
        try:
            completed = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-EncodedCommand",
                    encoded_script,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=self._acl_batch_timeout_seconds(len(paths)),
                env={**os.environ, "DSPM_SMB_ACL_PW": self.config.password or ""},
            )
        except (OSError, subprocess.SubprocessError):
            self._bump_diag("acl_batch_failures")
            return None
        finally:
            self._add_diag_ms(
                "acl_batch_elapsed_ms",
                (time.perf_counter() - started) * 1000,
            )
        return self._parse_acl_batch(share_root, completed)

    def _acl_batch_command(self, share_name: str, paths: list[str]) -> str:
        """The ``-EncodedCommand`` argument that reads these paths' ACLs."""
        username, _domain = self._windows_credential()
        share_root = self._unc_path(share_name, "")
        items = [
            {
                "path": path,
                "unc_path": self._unc_path(share_name, path),
                "relative": path.replace("/", "\\").lstrip("\\"),
            }
            for path in paths
        ]
        payload = {
            "share_root": share_root,
            "username": username,
            "items": items,
        }
        encoded_payload = base64.b64encode(
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
        ).decode("ascii")
        script = r"""
        $ErrorActionPreference = 'Stop'
        $payload = [Text.Encoding]::UTF8.GetString(
          [Convert]::FromBase64String('__DSPM_PAYLOAD__')
        ) | ConvertFrom-Json
        $username = [string]$payload.username
        $password = [string]$env:DSPM_SMB_ACL_PW
        $driveName = $null
        if (-not [string]::IsNullOrWhiteSpace($username) -and
            -not [string]::IsNullOrWhiteSpace($password)) {
          try {
            $secure = ConvertTo-SecureString $password -AsPlainText -Force
            $credential = [pscredential]::new($username, $secure)
            $driveName = 'DSPM' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
            New-PSDrive -Name $driveName -PSProvider FileSystem -Root ([string]$payload.share_root) -Credential $credential -ErrorAction Stop | Out-Null
          } catch {
            $driveName = $null
          }
        }
        $results = New-Object System.Collections.Generic.List[object]
        try {
          foreach ($item in @($payload.items)) {
            $target = [string]$item.unc_path
            if ($driveName) {
              $relative = [string]$item.relative
              $target = if ([string]::IsNullOrWhiteSpace($relative)) {
                $driveName + ':\'
              } else {
                $driveName + ':\' + $relative
              }
            }
            try {
              $acl = Get-Acl -LiteralPath $target -ErrorAction Stop
              $results.Add([PSCustomObject]@{
                path = [string]$item.path
                ok = $true
                owner = [string]$acl.Owner
                principals = @($acl.Access | ForEach-Object {
                  $_.IdentityReference.Value
                })
                permissions = @($acl.Access | ForEach-Object {
                  $_.FileSystemRights.ToString()
                })
                types = @($acl.Access | ForEach-Object {
                  $_.AccessControlType.ToString()
                })
                error = ''
              }) | Out-Null
            } catch {
              $results.Add([PSCustomObject]@{
                path = [string]$item.path
                ok = $false
                owner = ''
                principals = @()
                permissions = @()
                types = @()
                error = [string]$_.Exception.GetType().Name
              }) | Out-Null
            }
          }
        } finally {
          if ($driveName) {
            Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
          }
        }
        [PSCustomObject]@{ results = @($results) } |
          ConvertTo-Json -Depth 5 -Compress
        """.replace("__DSPM_PAYLOAD__", encoded_payload)
        return base64.b64encode(script.encode("utf-16le")).decode("ascii")

    def _parse_acl_batch(self, share_root: str, completed) -> dict[str, dict] | None:
        if completed.returncode != 0:
            self._bump_diag("acl_batch_failures")
            logger.debug(
                "Could not batch-read SMB ACLs for %s: %s",
                share_root,
                completed.stderr.strip() or completed.stdout.strip(),
            )
            return None
        try:
            parsed = json.loads(completed.stdout.strip()) if completed.stdout.strip() else {}
        except json.JSONDecodeError:
            self._bump_diag("acl_batch_failures")
            return None
        rows = parsed.get("results") if isinstance(parsed, dict) else None
        if not isinstance(rows, list):
            self._bump_diag("acl_batch_failures")
            return None

        normalized: dict[str, dict] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path") or "")
            if not path:
                continue
            if row.get("ok") is False:
                self._bump_diag("acl_batch_item_failures")
                continue
            normalized[path] = normalize_acl(row.get("owner"), row.get("principals"), row.get("permissions"),
                                             row.get("types"))
        return normalized

    def _acl_inproc(self, unc_path: str) -> dict | None:
        """Security descriptor read in-process (GetNamedSecurityInfoW accepts
        UNC paths). Replaces a 0.5-1.5 s PowerShell spawn per file with a
        sub-millisecond call for a byte-identical result; returns None when the
        share needs the credential-mapped PowerShell path below."""
        if not win_security.available():
            return None
        acl = win_security.security_for_path(unc_path)
        owner = str(acl.get("owner") or "")
        if not owner:
            return None
        normalized = normalize_acl(owner, acl.get("principals"), acl.get("permissions"), entries=acl.get("entries"))
        if normalized["principals"]:
            self._bump_diag("acl_read_success")
        self._bump_diag("acl_inproc_paths")
        with self._acl_lock:
            self._owner_cache[unc_path] = normalized["owner"]
            self._acl_cache[unc_path] = normalized
        return normalized

    def _acl_for_path(self, share_name: str, path: str) -> dict:
        unc_path = self._unc_path(share_name, path)
        with self._acl_lock:
            cached_acl = self._acl_cache.get(unc_path)
        if cached_acl is not None:
            return cached_acl
        self._bump_diag("owner_read_attempts")
        fast = self._acl_inproc(unc_path)
        if fast is not None:
            return fast
        username, domain = self._windows_credential()
        # SC-6: the password is NOT embedded in the (base64) script/argv, which
        # is visible to any local process listing command lines. It is passed to
        # the child PowerShell process through an environment variable instead,
        # which does not appear on the command line.
        payload = {
            "unc_path": unc_path,
            "username": username,
        }
        encoded_payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        script = f"""
        $ErrorActionPreference = 'Stop'
        $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_payload}')) | ConvertFrom-Json
        $path = [string]$payload.unc_path
        $username = [string]$payload.username
        $password = [string]$env:DSPM_SMB_ACL_PW
        try {{
          $directAcl = Get-Acl -LiteralPath $path -ErrorAction Stop
          if ($directAcl) {{
            [PSCustomObject]@{{
              owner = [string]$directAcl.Owner
              principals = @($directAcl.Access | ForEach-Object {{ $_.IdentityReference.Value }})
              permissions = @($directAcl.Access | ForEach-Object {{ $_.FileSystemRights.ToString() }})
              types = @($directAcl.Access | ForEach-Object {{ $_.AccessControlType.ToString() }})
            }} | ConvertTo-Json -Compress
            exit 0
          }}
        }} catch {{
        }}
        if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password)) {{
          exit 1
        }}
        $parts = $path.TrimStart([char]92) -split [regex]::Escape('\\'), 3
        if ($parts.Count -lt 2) {{ throw 'Invalid UNC path' }}
        $root = '\\\\' + $parts[0] + '\\' + $parts[1]
        $relative = if ($parts.Count -ge 3) {{ $parts[2] }} else {{ '' }}
        $driveName = 'DSPM' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
        $secure = ConvertTo-SecureString $password -AsPlainText -Force
        $credential = [pscredential]::new($username, $secure)
        try {{
          New-PSDrive -Name $driveName -PSProvider FileSystem -Root $root -Credential $credential -ErrorAction Stop | Out-Null
          $drivePath = if ($relative) {{ $driveName + ':\\' + $relative }} else {{ $driveName + ':\\' }}
          $acl = Get-Acl -LiteralPath $drivePath -ErrorAction Stop
          [PSCustomObject]@{{
            owner = [string]$acl.Owner
            principals = @($acl.Access | ForEach-Object {{ $_.IdentityReference.Value }})
            permissions = @($acl.Access | ForEach-Object {{ $_.FileSystemRights.ToString() }})
            types = @($acl.Access | ForEach-Object {{ $_.AccessControlType.ToString() }})
          }} | ConvertTo-Json -Compress
        }} finally {{
          Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
        }}
        """
        encoded_script = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        try:
            completed = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-EncodedCommand",
                    encoded_script,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=12,
                env={**os.environ, "DSPM_SMB_ACL_PW": self.config.password or ""},
            )
        except (OSError, subprocess.SubprocessError):
            self._bump_diag("owner_read_failed")
            return {"owner": "", "principals": [], "permissions": []}

        if completed.returncode != 0:
            self._bump_diag("owner_read_failed")
            logger.debug("Could not read SMB owner for %s: %s", unc_path, completed.stderr.strip() or completed.stdout.strip())
            return {"owner": "", "principals": [], "permissions": []}
        try:
            acl = json.loads(completed.stdout.strip()) if completed.stdout.strip() else {}
        except json.JSONDecodeError:
            acl = {"owner": completed.stdout.strip().splitlines()[0] if completed.stdout.strip() else ""}
        normalized_acl = normalize_acl(acl.get("owner"), acl.get("principals"), acl.get("permissions"), acl.get("types"))
        if not normalized_acl["owner"]:
            self._bump_diag("owner_read_failed")
        if normalized_acl["principals"]:
            self._bump_diag("acl_read_success")
        with self._acl_lock:
            self._owner_cache[unc_path] = normalized_acl["owner"]
            self._acl_cache[unc_path] = normalized_acl
        return normalized_acl

    def _windows_credential(self) -> tuple[str, str]:
        username = self.config.username.strip()
        domain = (self.config.domain.strip() or "").strip()
        if not username:
            return "", domain
        if "\\" in username or "@" in username:
            return username, domain
        if domain and domain.upper() != "WORKGROUP":
            return f"{domain}\\{username}", domain
        server_name = self._server_short_name()
        return (f"{server_name}\\{username}" if server_name else username), domain

    def _hash_file(self, share_name: str, path: str, size: int, chunk_size: int = 1024 * 1024) -> str:
        if self.connection is None:
            return ""
        digest = hashlib.sha256()
        offset = 0
        try:
            while offset < size:
                buffer = io.BytesIO()
                self.connection.retrieveFileFromOffset(
                    share_name,
                    path,
                    buffer,
                    offset=offset,
                    max_length=min(chunk_size, size - offset),
                )
                chunk = buffer.getvalue()
                if not chunk:
                    break
                digest.update(chunk)
                offset += len(chunk)
            return digest.hexdigest() if offset == size else ""
        except Exception as exc:
            # A dropped session fails every later read on it too: the chunk retries on a
            # fresh one rather than hashing the rest of its files against a dead socket.
            if _is_connection_error(exc):
                raise _SmbConnectionLost(share_name, _brief(exc)) from exc
            logger.debug("Could not hash %s:%s: %s", share_name, path, _brief(exc))
            return ""

    @staticmethod
    def _preview_content_from_bytes(data: bytes, extension: str) -> str:
        """Apply the existing text/document/OCR extraction to acquired bytes."""
        return SMBScanner._preview_from_bytes(data, extension)[0]

    @staticmethod
    def _extract_from_bytes(data: bytes, extension: str) -> tuple[str, str, bool]:
        """(text, why there is none, whether it is cut short) for acquired bytes. A
        document is extracted from memory - its bytes no longer touch the disk."""
        if extension in BINARY_TEXT_EXTENSIONS:
            return extract_binary_bytes_detail(data, extension)
        text, reason = SMBScanner._preview_from_bytes(data, extension)
        return text, reason, False

    @staticmethod
    def _preview_from_bytes(data: bytes, extension: str) -> tuple[str, str]:
        """(text, why there is none) for acquired bytes - the document extractor's reason,
        or "" (collectors.binary_extractor.extract_binary_bytes_detail)."""
        if extension not in BINARY_TEXT_EXTENSIONS and not is_ocr_scannable(extension):
            # The file's encoding, from its byte-order mark (a UTF-16 export is not UTF-8).
            return decode_text(data), ""
        if extension in BINARY_TEXT_EXTENSIONS:
            text, reason, _truncated = extract_binary_bytes_detail(data, extension)
            return text, reason

        temp_path = None
        try:
            # SC-8: retrieved document bytes touch disk only briefly and under a
            # restrictive mode. On Windows the host ACL remains authoritative.
            with tempfile.NamedTemporaryFile(delete=False, suffix=extension) as temp_file:
                temp_path = temp_file.name
                try:
                    os.chmod(temp_path, 0o600)
                except OSError:
                    pass
                temp_file.write(data)
            from pathlib import Path

            return extract_text_from_image(Path(temp_path)), ""
        finally:
            if temp_path:
                from pathlib import Path

                # Best-effort secure delete: overwrite before unlinking so the
                # raw document bytes are not left recoverable in free space.
                try:
                    with open(temp_path, "r+b") as handle:
                        length = handle.seek(0, io.SEEK_END)
                        handle.seek(0)
                        handle.write(b"\x00" * length)
                        handle.flush()
                        os.fsync(handle.fileno())
                except OSError:
                    pass
                Path(temp_path).unlink(missing_ok=True)

    def _fetch_preview(self, share_name: str, path: str, extension: str, size: int | None = None) -> tuple[str, str, bool]:
        """(text, why there is none, cut short) for what the scan inspects of the file: a
        text file's first ``max_read_bytes``, a document whole (within its cap - the caller
        checked). Raises when the read fails."""
        from io import BytesIO

        document = extension in BINARY_TEXT_EXTENSIONS or is_ocr_scannable(extension)
        limit = int(size) if document and size is not None else self.config.max_read_bytes
        buffer = BytesIO()
        with capture_budget().take(limit):
            self.connection.retrieveFileFromOffset(
                share_name,
                path,
                buffer,
                offset=0,
                max_length=limit,
            )
            return self._extract_from_bytes(buffer.getvalue(), extension)

    def _read_file_preview(self, share_name: str, path: str, extension: str) -> str:
        if self.connection is None or not self._preview_requested(extension):
            return ""
        try:
            return self._fetch_preview(share_name, path, extension)[0]
        except Exception as exc:
            if _is_connection_error(exc):
                raise _SmbConnectionLost(share_name, _brief(exc)) from exc
            logger.debug("Could not read preview for %s:%s: %s", share_name, path, _brief(exc))
            return ""

def scan_smb(ip: str, username: str = "", password: str = "", domain: str = "WORKGROUP") -> list[dict]:
    return SMBScanner(SMBConfig(server=ip, username=username, password=password, domain=domain)).scan()
