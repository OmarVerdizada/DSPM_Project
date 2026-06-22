from __future__ import annotations

import hashlib
import io
import base64
import ipaddress
import json
import socket
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
import re
from typing import Callable

from collectors.binary_extractor import BINARY_TEXT_EXTENSIONS, extract_binary_text
from collectors.file_scanner import (
    CONTENT_EXTENSIONS,
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
    include_admin_shares: bool = False
    inspect_archives: bool = False
    timeout: int = 10
    cancel_check: Callable[[], bool] | None = None


class SMBScanner:
    def __init__(self, config: SMBConfig):
        self.config = config
        self.connection = None
        self.extension_filter = normalize_extension_filter(config.allowed_extensions)
        self.credential_used = ""
        self.server_used = ""
        self._owner_cache: dict[str, str] = {}
        self._acl_cache: dict[str, dict] = {}
        self.last_scan_diagnostics: dict = {}

    def _cancelled(self) -> bool:
        return bool(self.config.cancel_check and self.config.cancel_check())

    def connect(self) -> bool:
        try:
            from smb.SMBConnection import SMBConnection
        except ModuleNotFoundError as exc:
            raise RuntimeError("Missing dependency 'pysmb'. Install requirements.txt before SMB scans.") from exc

        for server in self._server_candidates():
            remote_name = server.split(".")[0].strip() or server
            for username, domain, label in self._credential_candidates():
                conn = SMBConnection(
                    username,
                    self.config.password,
                    self.config.client_name,
                    remote_name,
                    domain=domain,
                    use_ntlm_v2=True,
                    is_direct_tcp=True,
                )
                try:
                    if conn.connect(server, self.config.port, timeout=self.config.timeout):
                        self.connection = conn
                        self.credential_used = label
                        self.server_used = server
                        return True
                except Exception:
                    conn.close()
                    continue
                conn.close()

        return False

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
        if not self.connect():
            raise ConnectionError(f"Could not connect to SMB server {self.config.server}:{self.config.port}")

        try:
            records: list[dict] = []
            for share in self.connection.listShares():
                if self._cancelled():
                    raise RuntimeError("Scan cancelled")
                share_name = share.name
                if self._skip_share(share_name):
                    continue

                records.extend(self._walk_share(share_name, "/", depth=0))

            owner_missing = sum(1 for record in records if not str(record.get("owner") or "").strip())
            self.last_scan_diagnostics = {
                **self.last_scan_diagnostics,
                "server_used": self.server_used or self.config.server,
                "records": len(records),
                "owner_missing": owner_missing,
                "owner_resolved": max(0, len(records) - owner_missing),
            }
            return records
        finally:
            self.close()

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
        server_name = self.config.server.split(".")[0].strip()
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
            logger.warning("Could not list %s:%s: %s", share_name, folder, exc)
            errors = self.last_scan_diagnostics.setdefault("list_errors", [])
            if isinstance(errors, list) and len(errors) < 20:
                errors.append({"share": share_name, "path": folder, "error": str(exc).splitlines()[0][:180]})
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
            if self.config.inspect_archives and self._should_scan_archive_entries(extension):
                records.extend(self._read_zip_entries(share_name, remote_path, is_hidden, is_system))
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
            content = self._read_file_preview(share_name, remote_path, extension)
            archive_metadata = archive_protection_metadata(extension)
            zip_metadata = self._inspect_zip_protection(share_name, remote_path) if extension == ".zip" else {}
            protected_metadata = zip_metadata or archive_metadata
            sha256 = self._hash_file(share_name, remote_path, int(getattr(entry, "file_size", 0) or 0))
            acl = self._acl_for_path(share_name, remote_path)
            owner = str(acl.get("owner") or "")
            created_at = _format_smb_timestamp(getattr(entry, "create_time", None))
            modified_at = _format_smb_timestamp(getattr(entry, "last_write_time", None))
            attributes = ", ".join([item for item in ["H" if is_hidden else "", "S" if is_system else ""] if item]) or "Normal"
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
                    "content": "" if protected_metadata else content,
                    "acl": acl,
                    "scan_mode": scan_mode_for_extension(extension),
                    "content_status": protected_metadata.get("content_status") or content_status_for_extension(extension, content, self.config.read_content),
                    "content_scannable": bool(protected_metadata.get("content_scannable", extension in CONTENT_EXTENSIONS)),
                    "protected": bool(protected_metadata.get("protected", False)),
                    "protection_type": protected_metadata.get("protection_type", ""),
                    "scan_error": protected_metadata.get("scan_error", ""),
                    "owner": owner,
                    "created_at": created_at,
                    "modified_at": modified_at,
                    "attributes": attributes,
                    "sha256": sha256,
                    "file_hash": sha256,
                }
            )

        return records

    def _should_scan_archive_entries(self, extension: str) -> bool:
        return extension == ".zip" and self.config.inspect_archives

    def _read_zip_entries(self, share_name: str, path: str, is_hidden: bool, is_system: bool) -> list[dict]:
        if self.connection is None:
            return []
        try:
            from io import BytesIO

            buffer = BytesIO()
            self.connection.retrieveFileFromOffset(share_name, path, buffer, offset=0, max_length=50 * 1024 * 1024)
            buffer.seek(0)
            records: list[dict] = []
            with zipfile.ZipFile(buffer) as archive:
                for entry in archive.infolist():
                    if entry.is_dir():
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
                    content_scannable = extension in CONTENT_EXTENSIONS
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
                                content = handle.read(self.config.max_read_bytes).decode("utf-8", errors="replace")
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
            self.connection.retrieveFileFromOffset(share_name, path, buffer, offset=0, max_length=50 * 1024 * 1024)
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
        self.last_scan_diagnostics["owner_read_attempts"] = int(self.last_scan_diagnostics.get("owner_read_attempts") or 0) + 1
        username, domain = self._windows_credential()
        payload = {
            "unc_path": unc_path,
            "username": username,
            "password": self.config.password,
        }
        encoded_payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        script = f"""
        $ErrorActionPreference = 'Stop'
        $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_payload}')) | ConvertFrom-Json
        $path = [string]$payload.unc_path
        $username = [string]$payload.username
        $password = [string]$payload.password
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
        $parts = $path.TrimStart([char]92) -split [regex]::Escape('\'), 3
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
            )
        except (OSError, subprocess.SubprocessError):
            self.last_scan_diagnostics["owner_read_failed"] = int(self.last_scan_diagnostics.get("owner_read_failed") or 0) + 1
            return {"owner": "", "principals": [], "permissions": []}

        if completed.returncode != 0:
            self.last_scan_diagnostics["owner_read_failed"] = int(self.last_scan_diagnostics.get("owner_read_failed") or 0) + 1
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
            self.last_scan_diagnostics["owner_read_failed"] = int(self.last_scan_diagnostics.get("owner_read_failed") or 0) + 1
        if normalized_acl["principals"]:
            self.last_scan_diagnostics["acl_read_success"] = int(self.last_scan_diagnostics.get("acl_read_success") or 0) + 1
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
        server_name = self.config.server.split(".")[0].strip()
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
