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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
import re
from typing import Callable

from discovery.parallelism import host_admission_budget, resolve_parallelism

from collectors.binary_extractor import BINARY_TEXT_EXTENSIONS, extract_binary_text
from collectors.net_guard import TargetNotAllowed, resolve_and_pin
from collectors.ocr import extract_text_from_image, is_ocr_scannable
from discovery.incremental import apply_reuse_snapshot, reuse_snapshot_from_result
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


def _is_connection_error(exc: Exception) -> bool:
    """True for socket-level failures (connection reset/aborted/broken) as opposed
    to a clean protocol error like ACCESS_DENIED that leaves the session usable."""
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
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


@dataclass(slots=True)
class SMBConfig:
    server: str
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


class SMBScanner:
    def __init__(self, config: SMBConfig):
        self.config = config
        # P-B.2: the pysmb session is stateful and NOT thread-safe, so the live
        # connection is thread-local - each parallel share worker owns its own,
        # and the serial path (single thread) sees exactly one, unchanged.
        self._local = threading.local()
        self.extension_filter = normalize_extension_filter(config.allowed_extensions)
        self.credential_used = ""
        self.server_used = ""
        self._owner_cache: dict[str, str] = {}
        self._acl_cache: dict[str, dict] = {}
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
        try:
            from smb.SMBConnection import SMBConnection
        except ModuleNotFoundError as exc:
            raise RuntimeError("Missing dependency 'pysmb'. Install requirements.txt before SMB scans.") from exc

        reached_server = False
        self._target_refused = ""
        for server in self._server_candidates():
            remote_name = self._remote_name_for(server)
            # M12: resolve + validate the target ONCE and connect to the PINNED IP,
            # so a DNS-rebind flip (public -> loopback/private) between validation
            # and connect cannot turn the scanner into an SSRF primitive. The
            # NetBIOS remote_name (for auth) stays the hostname.
            try:
                pinned_ip = resolve_and_pin(server)
            except TargetNotAllowed as exc:
                logger.warning("Refusing SMB target %s: %s", server, exc)
                self._target_refused = str(exc)
                continue
            for username, domain, label in self._credential_candidates():
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
                        self.connection = conn
                        self.credential_used = label
                        self.server_used = server
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
        self._consecutive_resets = 0
        self._abort_event.clear()
        self._io_parallel_active = False
        if not self.connect():
            if getattr(self, "_target_refused", ""):
                raise ConnectionError(f"SMB target refused (network guard): {self._target_refused}")
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
                scanned_shares.append(share_name)

            # P-B.2: walk shares in parallel (each on its OWN isolated connection +
            # a process-wide admission slot) when there is more than one, else the
            # serial single-connection path. Both share _scan_one_share's retry-once
            # + reset circuit-breaker and emit only successfully-walked shares.
            budget = host_admission_budget()
            if self._should_parallelize(len(scanned_shares)):
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
                **({"scan_aborted_reason": aborted_reason} if aborted_reason else {}),
            }
            return records
        finally:
            self.close()

    # ------------------------------------------------------------------
    # P-B.2: per-share acquisition strategy (serial vs parallel).
    # ------------------------------------------------------------------

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
        with budget.slot():
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
            with budget.slot():
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
            keeper = ordered[0]
            keep_share = str(keeper.get("share") or "").strip("/")
            expected_broad = self._norm_share_path(keep_share + self._norm_share_path(keeper.get("path")))
            for other in ordered[1:]:
                if self._norm_share_path(other.get("path")) == expected_broad:
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
        if share_name in SYSTEM_SHARES:
            return True
        if share_name.endswith("$") and not self.config.include_admin_shares:
            return True
        if share_name.endswith("$") and not re.fullmatch(r"[A-Za-z]\$", share_name):
            return True
        return False

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

    def _credential_candidates(self) -> list[tuple[str, str, str]]:
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

    def _walk_share(self, share_name: str, folder: str, depth: int) -> list[dict]:
        if self._cancelled():
            raise RuntimeError("Scan cancelled")
        if self.connection is None or depth > self.config.max_depth:
            return []
        if self._skip_path(folder):
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
                records.extend(self._walk_share(share_name, remote_path, depth + 1))
                continue

            extension = detect_extension(remote_path)
            with self._walk_lock:
                self._progress_counters["visited"] += 1
            self._emit_collection_progress()
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
                records.extend(self._read_zip_entries(share_name, remote_path, is_hidden, is_system))
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

            if self.config.inspect_archives and self._should_scan_archive_entries(extension):
                records.extend(self._read_zip_entries(share_name, remote_path, is_hidden, is_system))
            content = self._read_file_preview(share_name, remote_path, extension)
            archive_metadata = archive_protection_metadata(extension)
            zip_metadata = self._inspect_zip_protection(share_name, remote_path) if extension == ".zip" else {}
            protected_metadata = zip_metadata or archive_metadata
            sha256 = self._hash_file(share_name, remote_path, file_size)
            acl = self._acl_for_path(share_name, remote_path)
            owner = str(acl.get("owner") or "")
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
                    "content": "" if protected_metadata else content,
                    "acl": acl,
                    "scan_mode": scan_mode_for_extension(extension),
                    "content_status": protected_metadata.get("content_status") or content_status_for_extension(extension, content, self.config.read_content),
                    "content_scannable": bool(protected_metadata.get("content_scannable", (extension in CONTENT_EXTENSIONS or is_ocr_scannable(extension)))),
                    "protected": bool(protected_metadata.get("protected", False)),
                    "protection_type": protected_metadata.get("protection_type", ""),
                    "scan_error": protected_metadata.get("scan_error", ""),
                    "owner": owner,
                    "created_at": created_at,
                    "modified_at": modified_at,
                    "attributes": attributes,
                    "sha256": sha256,
                    "file_hash": sha256,
                    "scan_completeness": "PARTIAL" if content and file_size > self.config.max_read_bytes else "FULL" if content or file_size == 0 else "NONE",
                    "bytes_scanned": min(file_size, self.config.max_read_bytes) if content else 0,
                    "total_bytes": file_size,
                    "truncated": bool(content and file_size > self.config.max_read_bytes),
                    "reuse_key": reuse_key,
                }
            )
            with self._walk_lock:
                self._progress_counters["matched"] += 1
            self._emit_collection_progress()

        return records

    def _should_scan_archive_entries(self, extension: str) -> bool:
        return extension == ".zip" and self.config.inspect_archives

    def _read_zip_entries(self, share_name: str, path: str, is_hidden: bool, is_system: bool) -> list[dict]:
        if self.connection is None:
            return []
        try:
            from io import BytesIO

            buffer = BytesIO()
            self.connection.retrieveFileFromOffset(share_name, path, buffer, offset=0, max_length=MAX_ARCHIVE_TOTAL_BYTES)
            buffer.seek(0)
            records: list[dict] = []
            with zipfile.ZipFile(buffer) as archive:
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
                    if not protected and self.config.read_content and extension in TEXT_EXTENSIONS:
                        try:
                            with archive.open(entry) as handle:
                                content = handle.read(min(self.config.max_read_bytes, MAX_ARCHIVE_ENTRY_BYTES)).decode("utf-8", errors="replace")
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
            logger.debug("Could not inspect archive entries for %s:%s: %s", share_name, path, exc)
            return []

    def _inspect_zip_protection(self, share_name: str, path: str) -> dict[str, str | bool]:
        if self.connection is None:
            return {}
        try:
            from io import BytesIO

            buffer = BytesIO()
            self.connection.retrieveFileFromOffset(share_name, path, buffer, offset=0, max_length=MAX_ARCHIVE_TOTAL_BYTES)
            buffer.seek(0)
            with zipfile.ZipFile(buffer) as archive:
                encrypted = any(bool(entry.flag_bits & 0x1) for entry in archive.infolist()[:2000])
                if encrypted:
                    return {
                        "protected": True,
                        "content_status": "password_protected",
                        "content_scannable": False,
                        "protection_type": "zip_password",
                        "scan_error": "ZIP archive has encrypted entries and needs a password",
                    }
        except Exception:
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

    def _acl_for_path(self, share_name: str, path: str) -> dict:
        unc_path = self._unc_path(share_name, path)
        if unc_path in self._acl_cache:
            return self._acl_cache[unc_path]
        self._bump_diag("owner_read_attempts")
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
        principals = acl.get("principals", [])
        permissions = acl.get("permissions", [])
        if isinstance(principals, str):
            principals = [principals]
        if isinstance(permissions, str):
            permissions = [permissions]
        normalized_acl = {
            "owner": str(acl.get("owner") or ""),
            "principals": [str(item) for item in principals if str(item or "").strip()],
            "permissions": [str(item) for item in permissions if str(item or "").strip()],
        }
        if not normalized_acl["owner"]:
            self._bump_diag("owner_read_failed")
        if normalized_acl["principals"]:
            self._bump_diag("acl_read_success")
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
            logger.debug("Could not hash %s:%s: %s", share_name, path, exc)
            return ""

    def _read_file_preview(self, share_name: str, path: str, extension: str) -> str:
        if self.connection is None or not self.config.read_content:
            return ""
        if (
            extension not in TEXT_EXTENSIONS
            and extension not in BINARY_TEXT_EXTENSIONS
            and not is_ocr_scannable(extension)
        ):
            return ""

        try:
            from io import BytesIO

            buffer = BytesIO()
            self.connection.retrieveFileFromOffset(
                share_name,
                path,
                buffer,
                offset=0,
                max_length=self.config.max_read_bytes,
            )
            data = buffer.getvalue()
            if extension in BINARY_TEXT_EXTENSIONS or is_ocr_scannable(extension):
                temp_path = None
                try:
                    # SC-8: retrieved document bytes touch disk only briefly and
                    # under a restrictive mode. On POSIX chmod 0600 keeps other
                    # local users out; on Windows it is a best-effort no-op and
                    # host ACLs govern access.
                    with tempfile.NamedTemporaryFile(delete=False, suffix=extension) as temp_file:
                        temp_path = temp_file.name
                        try:
                            os.chmod(temp_path, 0o600)
                        except OSError:
                            pass
                        temp_file.write(data)
                    from pathlib import Path

                    if is_ocr_scannable(extension):
                        return extract_text_from_image(Path(temp_path))
                    return extract_binary_text(Path(temp_path))
                finally:
                    if temp_path:
                        from pathlib import Path

                        # Best-effort secure delete: overwrite before unlinking so
                        # the raw document bytes are not left recoverable in free
                        # space.
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
            return data.decode("utf-8", errors="replace")
        except Exception as exc:
            logger.debug("Could not read preview for %s:%s: %s", share_name, path, exc)
            return ""


def scan_smb(ip: str, username: str = "", password: str = "", domain: str = "WORKGROUP") -> list[dict]:
    return SMBScanner(SMBConfig(server=ip, username=username, password=password, domain=domain)).scan()
