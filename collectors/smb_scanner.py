from __future__ import annotations

import socket
import tempfile
from dataclasses import dataclass
from pathlib import PurePosixPath

from collectors.binary_extractor import BINARY_TEXT_EXTENSIONS, extract_binary_text
from collectors.file_scanner import TEXT_EXTENSIONS, detect_extension, matches_scan_filters, normalize_extension_filter
from scripts.logger import get_logger

logger = get_logger(__name__)

SYSTEM_SHARES = {"print$", "IPC$", "ADMIN$"}


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
    max_read_bytes: int = 1024 * 256
    allowed_extensions: list[str] | None = None
    extension_filter_enabled: bool = False


class SMBScanner:
    def __init__(self, config: SMBConfig):
        self.config = config
        self.connection = None
        self.extension_filter = normalize_extension_filter(config.allowed_extensions)

    def connect(self) -> bool:
        try:
            from smb.SMBConnection import SMBConnection
        except ModuleNotFoundError as exc:
            raise RuntimeError("Missing dependency 'pysmb'. Install requirements.txt before SMB scans.") from exc

        conn = SMBConnection(
            self.config.username,
            self.config.password,
            self.config.client_name,
            socket.gethostname(),
            domain=self.config.domain,
            use_ntlm_v2=True,
            is_direct_tcp=True,
        )

        if not conn.connect(self.config.server, self.config.port):
            return False

        self.connection = conn
        return True

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def test_connection(self) -> dict:
        try:
            connected = self.connect()
            shares = self._safe_list_shares() if connected else []
            return {
                "connected": connected,
                "server": self.config.server,
                "domain": self.config.domain,
                "shares": shares,
                "message": "Connected successfully" if connected else "Connection failed",
            }
        except Exception as exc:
            logger.exception("SMB connection test failed")
            return {
                "connected": False,
                "server": self.config.server,
                "domain": self.config.domain,
                "shares": [],
                "message": str(exc),
            }
        finally:
            self.close()

    def scan(self) -> list[dict]:
        if not self.connect():
            raise ConnectionError(f"Could not connect to SMB server {self.config.server}:{self.config.port}")

        try:
            records: list[dict] = []
            for share in self.connection.listShares():
                share_name = share.name
                if share_name in SYSTEM_SHARES or share_name.endswith("$"):
                    continue

                records.extend(self._walk_share(share_name, "/", depth=0))

            return records
        finally:
            self.close()

    def _safe_list_shares(self) -> list[str]:
        if self.connection is None:
            return []
        return [
            share.name
            for share in self.connection.listShares()
            if share.name not in SYSTEM_SHARES and not share.name.endswith("$")
        ]

    def _walk_share(self, share_name: str, folder: str, depth: int) -> list[dict]:
        if self.connection is None or depth > self.config.max_depth:
            return []

        records: list[dict] = []
        try:
            entries = self.connection.listPath(share_name, folder)
        except Exception as exc:
            logger.warning("Could not list %s:%s: %s", share_name, folder, exc)
            return records

        for entry in entries:
            if entry.filename in {".", ".."}:
                continue

            remote_path = str(PurePosixPath(folder) / entry.filename)
            is_dir = bool(entry.isDirectory)
            is_hidden = bool(getattr(entry, "isHidden", False))
            is_system = bool(getattr(entry, "isSystem", False))

            if is_dir:
                if is_hidden and not (self.config.include_hidden or self.config.hidden_filter_enabled):
                    continue
                if is_system and not (self.config.include_system or self.config.system_filter_enabled):
                    continue
                records.extend(self._walk_share(share_name, remote_path, depth + 1))
                continue

            extension = detect_extension(remote_path)
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
            records.append(
                {
                    "source": "smb",
                    "share": share_name,
                    "path": remote_path,
                    "name": entry.filename,
                    "size": int(getattr(entry, "file_size", 0) or 0),
                    "extension": extension,
                    "is_dir": False,
                    "is_hidden": is_hidden,
                    "is_system": is_system,
                    "content": self._read_file_preview(share_name, remote_path, extension),
                    "acl": {},
                }
            )

        return records

    def _read_file_preview(self, share_name: str, path: str, extension: str) -> str:
        if self.connection is None or not self.config.read_content:
            return ""
        if extension not in TEXT_EXTENSIONS and extension not in BINARY_TEXT_EXTENSIONS:
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
            if extension in BINARY_TEXT_EXTENSIONS:
                temp_path = None
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=extension) as temp_file:
                        temp_file.write(data)
                        temp_path = temp_file.name
                    from pathlib import Path

                    return extract_binary_text(Path(temp_path))
                finally:
                    if temp_path:
                        from pathlib import Path

                        Path(temp_path).unlink(missing_ok=True)
            return data.decode("utf-8", errors="replace")
        except Exception as exc:
            logger.debug("Could not read preview for %s:%s: %s", share_name, path, exc)
            return ""


def scan_smb(ip: str, username: str = "", password: str = "", domain: str = "WORKGROUP") -> list[dict]:
    return SMBScanner(SMBConfig(server=ip, username=username, password=password, domain=domain)).scan()
