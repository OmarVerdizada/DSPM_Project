"""SMB 3.1.1 with encryption, behind the SMB collector (D1).

pysmb, the collector's transport, speaks SMB 1 and 2 and cannot encrypt: a server or share
that requires SMB 3 encryption resets its connection (WinError 10054), and every other
server's file bytes cross the network in the clear. This adapter gives the collector (and
the evidence re-read) the calls they make of pysmb - connect, listShares, listPath,
getAttributes, retrieveFileFromOffset, close - over smbprotocol, with the session encrypted (SMB 3.1.1, AES-GCM or CCM, as the
server negotiates) and REQUIRED: a server that cannot encrypt is refused, not read in the
clear. The walker, the filters, the ACL reading, archives, reuse, partitions and resume
are the collector's own code, unchanged - which is what makes the two paths the same scan.

What differs, and is said where it matters:
- Shares are named, not enumerated: smbprotocol has no share listing (it needs the
  SRVSVC RPC pysmb has). A scan in this mode names its shares (`smb_shares`); one that
  names none is refused with that reason.
- The connection is made to the address the workspace's scan targets allowed (resolved
  once and pinned, collectors.net_guard), so authentication is NTLM through the SSPI
  negotiation; Kerberos needs the server's name, which the pin replaces.
- An empty user name means the backend service's own Windows identity (SSPI, no password
  handled), only when DSPM_SMB_ALLOW_SERVICE_IDENTITY is on.
"""

from __future__ import annotations

import contextlib
import os
import uuid
from dataclasses import dataclass

DISK = 0  # pysmb's SharedDevice.DISK_TREE
_HIDDEN, _SYSTEM, _DIRECTORY, _READONLY = 0x2, 0x4, 0x10, 0x1
_NO_MORE_FILES = 0x80000006  # STATUS_NO_MORE_FILES


def service_identity_allowed() -> bool:
    return os.getenv("DSPM_SMB_ALLOW_SERVICE_IDENTITY", "0").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class SharedDevice:
    name: str
    type: int = DISK
    comments: str = ""
    isSpecial: bool = False
    isTemporary: bool = False


@dataclass
class SharedFile:
    """The fields of pysmb's SharedFile the collector reads."""
    filename: str
    file_size: int
    create_time: float
    last_write_time: float
    last_access_time: float
    file_attributes: int

    @property
    def isDirectory(self) -> bool:
        return bool(self.file_attributes & _DIRECTORY)

    @property
    def isHidden(self) -> bool:
        return bool(self.file_attributes & _HIDDEN)

    @property
    def isSystem(self) -> bool:
        return bool(self.file_attributes & _SYSTEM)

    @property
    def isReadOnly(self) -> bool:
        return bool(self.file_attributes & _READONLY)


class EncryptionUnavailable(ConnectionError):
    """The server did not negotiate SMB 3 encryption; nothing is read in the clear."""


def _epoch(value) -> float:
    try:
        return float(value.timestamp())
    except (AttributeError, TypeError, ValueError, OSError):
        return 0.0


class Smb3Connection:
    """pysmb's SMBConnection, as far as the SMB collector uses it, over smbprotocol."""

    def __init__(self, username: str, password: str, my_name: str, remote_name: str, domain: str = "",
                 *, shares: list[str] | None = None) -> None:
        self.username, self.password, self.domain = username or "", password or "", domain or ""
        self.remote_name = remote_name
        self.shares = [str(item).strip() for item in shares or [] if str(item).strip()]
        self.server = ""
        self._connection = None
        self._session = None
        self._trees: dict[str, object] = {}

    # -- connect ---------------------------------------------------------------------
    def connect(self, ip: str, port: int = 445, timeout: float = 30) -> bool:
        """Negotiate SMB 3, authenticate and require encryption. False when the server
        refused the credentials (as pysmb does); raises when it cannot encrypt."""
        from smbprotocol.connection import Connection, Dialects
        from smbprotocol.exceptions import SMBAuthenticationError
        from smbprotocol.session import Session

        if not self.username and not service_identity_allowed():
            raise PermissionError("Give an account to scan with; the service's own identity is used only when "
                                  "DSPM_SMB_ALLOW_SERVICE_IDENTITY is on.")
        self.server = ip
        connection = Connection(uuid.uuid4(), ip, port, require_signing=True)
        connection.connect(Dialects.SMB_3_1_1, timeout=timeout)
        if not connection.supports_encryption:
            connection.disconnect(True)
            raise EncryptionUnavailable(f"{self.remote_name} does not offer SMB 3 encryption; it is not read in the clear.")
        user = f"{self.domain}\\{self.username}" if self.domain and self.username and "\\" not in self.username \
            and "@" not in self.username and self.domain.upper() != "WORKGROUP" else self.username
        session = Session(connection, username=user or None, password=self.password or None, require_encryption=True,
                          auth_protocol="negotiate")
        try:
            session.connect()
        except SMBAuthenticationError:
            connection.disconnect(True)
            return False
        if not session.encrypt_data:
            connection.disconnect(True)
            raise EncryptionUnavailable(f"The session with {self.remote_name} is not encrypted; nothing is read.")
        self._connection, self._session = connection, session
        return True

    @property
    def encrypted(self) -> bool:
        return bool(self._session is not None and self._session.encrypt_data)

    @property
    def dialect(self) -> int:
        return int(getattr(self._connection, "dialect", 0) or 0)

    def close(self) -> None:
        connection, self._connection, self._session, self._trees = self._connection, None, None, {}
        if connection is not None:
            with contextlib.suppress(Exception):  # closing a dead connection is not an error worth raising
                connection.disconnect(True)

    # -- the collector's calls ------------------------------------------------------
    def listShares(self, timeout: float = 30) -> list[SharedDevice]:
        if not self.shares:
            raise PermissionError("SMB 3 encrypted scans name their shares (smbprotocol cannot list them): give "
                                  "the shares to scan.")
        return [SharedDevice(name) for name in self.shares]

    def _tree(self, share: str):
        from smbprotocol.tree import TreeConnect

        tree = self._trees.get(share.lower())
        if tree is None:
            if self._session is None:
                raise ConnectionError("not connected")
            tree = TreeConnect(self._session, rf"\\{self.remote_name}\{share}")
            tree.connect(require_secure_negotiate=True)
            self._trees[share.lower()] = tree
        return tree

    def _open(self, share: str, path: str, *, directory: bool):
        from smbprotocol.open import (
            CreateDisposition,
            CreateOptions,
            DirectoryAccessMask,
            FileAttributes,
            FilePipePrinterAccessMask,
            ImpersonationLevel,
            Open,
            ShareAccess,
        )

        handle = Open(self._tree(share), str(path or "").strip("/").replace("/", "\\"))
        access = (DirectoryAccessMask.FILE_LIST_DIRECTORY | DirectoryAccessMask.FILE_READ_ATTRIBUTES) if directory \
            else (FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES)
        handle.create(ImpersonationLevel.Impersonation, access,
                      FileAttributes.FILE_ATTRIBUTE_DIRECTORY if directory else FileAttributes.FILE_ATTRIBUTE_NORMAL,
                      ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
                      CreateDisposition.FILE_OPEN,
                      CreateOptions.FILE_DIRECTORY_FILE if directory else CreateOptions.FILE_NON_DIRECTORY_FILE)
        return handle

    def listPath(self, service_name: str, path: str, search: int = 0, pattern: str = "*",
                 timeout: float = 30) -> list[SharedFile]:
        from smbprotocol.exceptions import SMBResponseException
        from smbprotocol.file_info import FileInformationClass

        try:
            handle = self._open(service_name, path, directory=True)
        except SMBResponseException as exc:
            raise _translate(exc, service_name, path) from exc
        entries = []
        try:
            # One call returns what fits in one response; the server says when there is no more.
            while True:
                try:
                    batch = handle.query_directory(pattern, FileInformationClass.FILE_ID_FULL_DIRECTORY_INFORMATION,
                                                   max_output=65536)
                except SMBResponseException as exc:
                    if int(getattr(exc, "status", 0) or 0) == _NO_MORE_FILES:
                        break
                    raise
                if not batch:
                    break
                entries.extend(batch)
        except SMBResponseException as exc:
            raise _translate(exc, service_name, path) from exc
        finally:
            with contextlib.suppress(Exception):  # closing is best-effort; the read's result stands
                handle.close(False)
        files = []
        for entry in entries:
            name = entry["file_name"].get_value().decode("utf-16-le")
            files.append(SharedFile(
                filename=name, file_size=int(entry["end_of_file"].get_value()),
                create_time=_epoch(entry["creation_time"].get_value()),
                last_write_time=_epoch(entry["last_write_time"].get_value()),
                last_access_time=_epoch(entry["last_access_time"].get_value()),
                file_attributes=int(entry["file_attributes"].get_value())))
        return files

    def getAttributes(self, service_name: str, path: str, timeout: float = 30) -> SharedFile:
        """One file's attributes as they are now (the evidence re-read checks the size)."""
        from smbprotocol.exceptions import SMBResponseException

        try:
            handle = self._open(service_name, path, directory=False)
        except SMBResponseException as exc:
            raise _translate(exc, service_name, path) from exc
        try:
            return SharedFile(
                filename=str(path or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1],
                file_size=int(handle.end_of_file), create_time=_epoch(handle.creation_time),
                last_write_time=_epoch(handle.last_write_time), last_access_time=_epoch(handle.last_access_time),
                file_attributes=int(handle.file_attributes))
        finally:
            with contextlib.suppress(Exception):  # closing is best-effort; the read's result stands
                handle.close(False)

    def retrieveFileFromOffset(self, service_name: str, path: str, file_obj, offset: int = 0,
                               max_length: int = -1, timeout: float = 30) -> tuple[int, int]:
        from smbprotocol.exceptions import SMBResponseException

        try:
            handle = self._open(service_name, path, directory=False)
        except SMBResponseException as exc:
            raise _translate(exc, service_name, path) from exc
        written = 0
        try:
            size = int(handle.end_of_file)
            end = size if max_length is None or max_length < 0 else min(size, offset + max_length)
            position = offset
            chunk = max(65536, min(int(getattr(self._connection, "max_read_size", 1 << 20) or 1 << 20), 1 << 20))
            while position < end:
                data = handle.read(position, min(chunk, end - position))
                if not data:
                    break
                file_obj.write(data)
                position += len(data)
                written += len(data)
        except SMBResponseException as exc:
            raise _translate(exc, service_name, path) from exc
        finally:
            with contextlib.suppress(Exception):  # closing is best-effort; the read's result stands
                handle.close(False)
        return 0, written


class OperationFailure(Exception):
    """pysmb's OperationFailure, as the collector reads it (its message)."""


def _translate(exc, share: str, path: str) -> Exception:
    """The collector tells an access refusal from a dropped connection by the message."""
    status = int(getattr(exc, "status", 0) or 0)
    if status == 0xC0000022:  # STATUS_ACCESS_DENIED
        return OperationFailure(f"Access denied: unable to open directory {share}/{path} (0xc0000022)")
    return OperationFailure(f"SMB operation failed on {share}/{path} (0x{status:08x})")
