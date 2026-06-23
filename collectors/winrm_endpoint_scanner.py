from __future__ import annotations

import base64
import ipaddress
import json
import platform
import re
import socket
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path, PureWindowsPath
from uuid import uuid4

from collectors.binary_extractor import BINARY_TEXT_EXTENSIONS
from collectors.file_scanner import (
    CONTENT_EXTENSIONS,
    TEXT_EXTENSIONS,
    archive_protection_metadata,
    content_status_for_extension,
    detect_extension,
    normalize_extension_filter,
    normalize_records,
    scan_mode_for_extension,
)


DEFAULT_PROFILE_FOLDERS = {
    "desktop": "Desktop",
    "documents": "Documents",
    "downloads": "Downloads",
}

PROFILE_DATA_SCOPE_ALIASES = set(DEFAULT_PROFILE_FOLDERS) | {"all", "profile_standard", "onedrive"}
GLOBAL_ENDPOINT_SCOPE_ALIASES = {"all_profiles", "c_drive", "all_fixed_drives"}
ENDPOINT_PATH_ALIASES = PROFILE_DATA_SCOPE_ALIASES | GLOBAL_ENDPOINT_SCOPE_ALIASES


def endpoint_connection_hosts(host: str) -> list[str]:
    target = str(host or "").strip()
    if not target:
        return []
    candidates = [target]
    try:
        ipaddress.ip_address(target.strip("[]"))
    except ValueError:
        try:
            for _, _, _, _, sockaddr in socket.getaddrinfo(target, None):
                address = str(sockaddr[0]).strip()
                if address and address not in candidates:
                    candidates.append(address)
        except OSError:
            pass
    else:
        try:
            resolved, _, _ = socket.gethostbyaddr(target)
            resolved = resolved.rstrip(".")
            if resolved and resolved not in candidates:
                candidates.append(resolved)
        except OSError:
            pass
    return candidates


def resolve_endpoint_connection_host(host: str) -> str:
    candidates = endpoint_connection_hosts(host)
    if not candidates:
        return str(host or "").strip()
    try:
        ipaddress.ip_address(candidates[0].strip("[]"))
    except ValueError:
        return candidates[0]
    return candidates[1] if len(candidates) > 1 else candidates[0]


def normalize_endpoint_target_paths(paths: list[str], target_username: str = "") -> list[str]:
    profile = target_username.strip()
    base = f"C:\\Users\\{profile}" if profile else "C:\\Users"
    requested = [item.strip() for item in paths if item.strip()] or ["desktop", "documents", "downloads"]

    resolved: list[str] = []
    for item in requested:
        lowered = item.lower()
        if lowered == "profile_standard":
            resolved.append(f"__DSPM_PROFILE_STANDARD_FOR__:{profile}" if profile else "__DSPM_PROFILE_STANDARD__")
        elif lowered == "all_profiles":
            resolved.append("__DSPM_ALL_PROFILES__")
        elif lowered == "all":
            resolved.append(f"__DSPM_PROFILE_ROOT_FOR__:{profile}" if profile else "__DSPM_ALL_PROFILES__")
        elif lowered == "c_drive":
            resolved.append("C:\\")
        elif lowered == "onedrive":
            resolved.append(f"__DSPM_ONEDRIVE_FOR__:{profile}" if profile else "__DSPM_ALL_ONEDRIVE__")
        elif lowered == "all_fixed_drives":
            resolved.append("__DSPM_FIXED_DRIVES__")
        elif lowered in DEFAULT_PROFILE_FOLDERS:
            folder = DEFAULT_PROFILE_FOLDERS[lowered]
            resolved.append(f"__DSPM_PROFILE_FOLDER_FOR__:{profile}:{folder}" if profile else f"__DSPM_PROFILE_FOLDER__:{folder}")
        elif _is_windows_absolute_path(item):
            resolved.append(_normalize_windows_path(item))
        elif profile:
            resolved.append(f"__DSPM_PROFILE_RELATIVE_FOR__:{profile}:{_normalize_windows_relative_path(item)}")
        else:
            resolved.append(_join_windows_path(base, item))
    return list(dict.fromkeys(resolved))


def _is_windows_absolute_path(value: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:[\\/]", value) or value.startswith("\\\\"))


def _normalize_windows_path(value: str) -> str:
    normalized = value.replace("/", "\\")
    if re.fullmatch(r"[A-Za-z]:", normalized):
        return f"{normalized}\\"
    return normalized


def _normalize_windows_relative_path(value: str) -> str:
    return value.replace("/", "\\").strip("\\")


def _join_windows_path(root: str, suffix: str) -> str:
    clean_root = root.rstrip("\\")
    return f"{clean_root}\\{_normalize_windows_relative_path(suffix)}"


def activate_local_winrm(username: str = "", password: str = "", domain: str = "WORKGROUP") -> dict:
    if platform.system().lower() != "windows":
        raise RuntimeError("Local WinRM activation requires the DSPM backend to run on Windows.")

    activation = _run_local_activation_script(require_current_admin=True)
    if activation.get("activated") or not activation.get("requires_admin") or not username.strip() or not password:
        return activation

    scheduled = _activate_local_winrm_with_task(username.strip(), password, domain.strip() or "WORKGROUP")
    if scheduled.get("activated"):
        return scheduled
    scheduled["initial_message"] = activation.get("message", "")
    return scheduled


def _run_local_activation_script(require_current_admin: bool) -> dict:
    script = _local_activation_script(require_current_admin)
    result = _run_encoded_powershell(script)
    if result.returncode != 0:
        return {
            "activated": False,
            "message": _clean_error(result.stderr or result.stdout) or "Local WinRM activation failed.",
        }
    activation = _read_json(result.stdout)
    if isinstance(activation, dict):
        return activation
    return {"activated": False, "message": _clean_error(result.stdout) or "Local activation command completed."}


def _local_activation_script(require_current_admin: bool) -> str:
    admin_guard = """
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
      [PSCustomObject]@{
        activated = $false
        host = $env:COMPUTERNAME
        service_status = ""
        port_5985_open = $false
        requires_admin = $true
        message = "DSPM backend is not running with Administrator privileges. Start PowerShell as Administrator and run the backend again, or run Enable-PSRemoting manually on this server."
      } | ConvertTo-Json -Compress
      exit 0
    }
    """ if require_current_admin else ""
    return """
    $ProgressPreference = "SilentlyContinue"
    __ADMIN_GUARD__
    $ErrorActionPreference = "SilentlyContinue"
    Set-Service -Name WinRM -StartupType Automatic
    Start-Service -Name WinRM
    Enable-PSRemoting -Force -SkipNetworkProfileCheck
    winrm quickconfig -quiet
    Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Ole" -Name EnableDCOM -Type String -Value "Y" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name LocalAccountTokenFilterPolicy -Type DWord -Value 1 -Force
    winrm create "winrm/config/Listener?Address=*+Transport=HTTP" '@{Port="5985"}' 2>$null
    winrm set "winrm/config/service" '@{IPv4Filter="*";IPv6Filter="*"}'
    netsh advfirewall firewall set rule group="Windows Remote Management" new enable=yes | Out-Null
    netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=yes | Out-Null
    netsh advfirewall firewall set rule group="Remote Administration" new enable=yes | Out-Null
    netsh advfirewall firewall add rule name="DSPM WinRM HTTP 5985" dir=in action=allow protocol=TCP localport=5985 profile=any | Out-Null
    New-NetFirewallRule -DisplayName "DSPM WinRM HTTP" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
    $service = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    $portOpen = $false
    try {
      $client = New-Object Net.Sockets.TcpClient
      $async = $client.BeginConnect("127.0.0.1", 5985, $null, $null)
      $portOpen = $async.AsyncWaitHandle.WaitOne(3000, $false)
      if ($portOpen) { $client.EndConnect($async) }
      $client.Close()
    } catch {
      $portOpen = $false
    }
    [PSCustomObject]@{
      activated = [bool]($service -and $service.Status -eq "Running" -and $portOpen)
      host = $env:COMPUTERNAME
      service_status = if ($service) { $service.Status.ToString() } else { "Missing" }
      port_5985_open = [bool]$portOpen
      requires_admin = $false
      message = if ($service -and $service.Status -eq "Running" -and $portOpen) { "Local WinRM is running and port 5985 is reachable." } else { "Local activation command ran, but WinRM is not fully reachable. Run the backend as Administrator and check local firewall policy." }
    } | ConvertTo-Json -Compress
    """.replace("__ADMIN_GUARD__", admin_guard)


def _activate_local_winrm_with_task(username: str, password: str, domain: str) -> dict:
    task_name = f"DSPM_Activate_WinRM_{uuid4().hex}"
    run_at = (datetime.now() + timedelta(minutes=1)).strftime("%H:%M")
    private_tmp = Path(tempfile.gettempdir()) / "dspm-winrm"
    private_tmp.mkdir(parents=True, exist_ok=True)
    try:
        private_tmp.chmod(0o700)
    except OSError:
        pass
    script_path = private_tmp / f"{task_name}.ps1"
    script_path.write_text(_local_activation_script(False), encoding="utf-8")
    try:
        script_path.chmod(0o600)
    except OSError:
        pass
    task_command = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{script_path}"'
    run_as = _format_windows_username(username, domain)

    try:
        create = subprocess.run(
            [
                "schtasks.exe",
                "/Create",
                "/TN",
                task_name,
                "/SC",
                "ONCE",
                "/ST",
                run_at,
                "/RL",
                "HIGHEST",
                "/RU",
                run_as,
                "/RP",
                password,
                "/TR",
                task_command,
                "/F",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if create.returncode != 0:
            return {
                "activated": False,
                "requires_admin": True,
                "run_as": run_as,
                "message": _clean_error(create.stderr or create.stdout) or "Could not create elevated activation task with the supplied admin credential.",
            }

        run = subprocess.run(["schtasks.exe", "/Run", "/TN", task_name], capture_output=True, text=True, timeout=30, check=False)
        if run.returncode != 0:
            return {
                "activated": False,
                "requires_admin": True,
                "run_as": run_as,
                "message": _clean_error(run.stderr or run.stdout) or "Could not run elevated activation task.",
            }

        subprocess.run(["powershell.exe", "-NoProfile", "-Command", "Start-Sleep -Seconds 8"], capture_output=True, text=True, timeout=15, check=False)
        status = _run_local_activation_script(require_current_admin=False)
        status["run_as"] = run_as
        if status.get("activated"):
            status["message"] = "Local WinRM activated through the supplied admin credential."
        return status
    finally:
        _delete_task(task_name)
        try:
            script_path.unlink(missing_ok=True)
        except OSError:
            pass


def _run_encoded_powershell(script: str) -> subprocess.CompletedProcess:
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )


def _delete_task(task_name: str) -> None:
    subprocess.run(["schtasks.exe", "/Delete", "/TN", task_name, "/F"], capture_output=True, text=True, timeout=30, check=False)


def _format_windows_username(username: str, domain: str) -> str:
    if "\\" in username or "@" in username:
        return username
    if domain and domain.upper() != "WORKGROUP":
        return f"{domain}\\{username}"
    return username


@dataclass(slots=True)
class WinRMEndpointConfig:
    host: str
    username: str
    password: str
    domain: str = "WORKGROUP"
    target_username: str = ""
    paths: list[str] = field(default_factory=lambda: ["desktop", "documents", "downloads"])
    max_depth: int = 12
    read_content: bool = True
    max_read_bytes: int = 1024 * 256
    use_ssl: bool = False
    port: int | None = None
    allowed_extensions: list[str] | None = None
    extension_filter_enabled: bool = False
    include_hidden: bool = True
    include_system: bool = False
    hidden_filter_enabled: bool = False
    system_filter_enabled: bool = False
    read_acl: bool = False
    inspect_archives: bool = False


class WinRMEndpointScanner:
    def __init__(self, config: WinRMEndpointConfig):
        self.config = config
        self.last_scan_diagnostics: dict = {}
        self.last_connection_host = ""

    def activate_winrm(self) -> dict:
        if platform.system().lower() != "windows":
            raise RuntimeError("WinRM activation requires the DSPM backend to run on Windows with WMI tools available.")
        if not self.config.host.strip():
            raise ValueError("Endpoint host is required.")
        if not self.config.username.strip() or not self.config.password:
            raise ValueError("Admin username and password are required to activate WinRM.")

        existing_connection = self.test_connection()
        if existing_connection.get("connected"):
            return {
                "activated": True,
                "connected": True,
                "host": self.config.host,
                "user": existing_connection.get("user", ""),
                "computer": existing_connection.get("computer", self.config.host),
                "message": "WinRM is already reachable and connection verified.",
                "connection_message": existing_connection.get("message", "Connected successfully"),
                "skipped_wmi_activation": True,
            }

        script = _activation_script(
            {
                "host": self._connection_host(),
                "username": self.config.username.strip(),
                "password": self.config.password,
                "domain": self.config.domain.strip() or "WORKGROUP",
            }
        )
        result = _run_encoded_powershell(script)
        if result.returncode != 0:
            return {
                "activated": False,
                "host": self.config.host,
                "message": _clean_error(result.stderr) or "WinRM activation failed.",
            }

        activation = _read_json(result.stdout)
        if not isinstance(activation, dict):
            activation = {"activated": False, "message": _clean_error(result.stdout) or "Activation command completed."}

        if not activation.get("activated"):
            activation["connected"] = False
            activation["connection_message"] = activation.get("message", "")
            return activation

        connection = self.test_connection()
        activation["connected"] = bool(connection.get("connected"))
        activation["connection_message"] = connection.get("message", "")
        activation["user"] = connection.get("user", "")
        activation["computer"] = connection.get("computer", "")
        if activation["connected"]:
            activation["activated"] = True
            activation["message"] = "WinRM activated and connection verified."
        return activation

    def test_connection(self) -> dict:
        try:
            result = self._run_ps(
                """
                $ErrorActionPreference = "Stop"
                [PSCustomObject]@{
                  computer = $env:COMPUTERNAME
                  user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                  profileRoot = "C:\\Users"
                } | ConvertTo-Json -Compress
                """
            )
            info = _read_json(result.std_out) or {}
            return {
                "connected": result.status_code == 0,
                "host": self.config.host,
                "connection_host": self.last_connection_host or self._connection_host(),
                "connection_candidates": self._connection_hosts(),
                "user": info.get("user", ""),
                "computer": info.get("computer", self.config.host),
                "message": "Connected successfully" if result.status_code == 0 else _clean_error(result.std_err),
            }
        except Exception as exc:
            return {"connected": False, "host": self.config.host, "message": "WinRM connection test failed"}

    def scan(self) -> list[dict]:
        target_paths = self._target_paths()
        ps_script = _scan_script(
            target_paths,
            max_depth=self.config.max_depth,
            read_content=self.config.read_content,
            max_read_bytes=self.config.max_read_bytes,
            allowed_extensions=sorted(normalize_extension_filter(self.config.allowed_extensions)),
            extension_filter_enabled=self.config.extension_filter_enabled,
            include_hidden=self.config.include_hidden,
            include_system=self.config.include_system,
            hidden_filter_enabled=self.config.hidden_filter_enabled,
            system_filter_enabled=self.config.system_filter_enabled,
            read_acl=self.config.read_acl,
            inspect_archives=self.config.inspect_archives,
        )
        result = self._run_ps_file(ps_script)
        if result.status_code != 0:
            raise ConnectionError(_clean_error(result.std_err) or f"WinRM scan failed on {self.config.host}")

        raw_records = _read_json(result.std_out)
        if raw_records is None:
            self.last_scan_diagnostics = {}
            return []
        if isinstance(raw_records, dict) and isinstance(raw_records.get("records"), list):
            self.last_scan_diagnostics = raw_records.get("diagnostics") if isinstance(raw_records.get("diagnostics"), dict) else {}
            self.last_scan_diagnostics["connection_host"] = self.last_connection_host or self._connection_host()
            self.last_scan_diagnostics["connection_candidates"] = self._connection_hosts()
            raw_records = raw_records["records"]
        if isinstance(raw_records, dict):
            self.last_scan_diagnostics = {}
            raw_records = [raw_records]

        records = []
        filtered_wrong_profile = 0
        profile_scoped = self._is_profile_scoped_request()
        for item in raw_records:
            path = item.get("path", "")
            if profile_scoped and not self._path_matches_target_profile(path):
                filtered_wrong_profile += 1
                continue
            extension = item.get("extension") or detect_extension(path)
            content = item.get("content", "")
            content_scannable = item.get("content_scannable")
            if content_scannable is None:
                content_scannable = extension in CONTENT_EXTENSIONS
            archive_metadata = archive_protection_metadata(extension)
            records.append(
                {
                    "source": "endpoint-winrm",
                    "share": self.config.host,
                    "path": path,
                    "name": item.get("name") or PureWindowsPath(path).name,
                    "size": int(item.get("size") or 0),
                    "extension": extension,
                    "is_dir": False,
                    "is_hidden": bool(item.get("is_hidden", False)),
                    "is_system": bool(item.get("is_system", False)),
                    "content": "" if archive_metadata else content,
                    "acl": {
                        "owner": item.get("owner", ""),
                        "principals": item.get("principals", []),
                        "permissions": item.get("permissions", []),
                    },
                    "owner": item.get("owner", ""),
                    "scan_mode": item.get("scan_mode") or scan_mode_for_extension(extension),
                    "content_status": item.get("content_status")
                    or archive_metadata.get("content_status")
                    or content_status_for_extension(extension, content, self.config.read_content),
                    "content_scannable": bool(archive_metadata.get("content_scannable", content_scannable)),
                    "protected": bool(item.get("protected", False) or archive_metadata.get("protected", False)),
                    "protection_type": item.get("protection_type", "") or archive_metadata.get("protection_type", ""),
                    "scan_error": item.get("scan_error", "") or archive_metadata.get("scan_error", ""),
                    "created_at": item.get("created_at", ""),
                    "modified_at": item.get("modified_at", ""),
                    "accessed_at": item.get("accessed_at", ""),
                    "attributes": item.get("attributes", ""),
                    "sha256": item.get("sha256", ""),
                    "file_hash": item.get("sha256", ""),
                }
            )
        if filtered_wrong_profile:
            self.last_scan_diagnostics["filtered_wrong_profile"] = filtered_wrong_profile
        return normalize_records(records)

    def _is_profile_scoped_request(self) -> bool:
        if not self.config.target_username.strip():
            return False
        paths = [item.strip().lower() for item in self.config.paths if item.strip()]
        return bool(paths) and all(item in PROFILE_DATA_SCOPE_ALIASES for item in paths)

    def _path_matches_target_profile(self, path: str) -> bool:
        profile = self.config.target_username.strip().lower()
        if not profile:
            return True
        normalized = path.replace("/", "\\").lower()
        marker = "\\users\\"
        if marker not in normalized:
            return False
        after_users = normalized.split(marker, 1)[1]
        actual_profile = after_users.split("\\", 1)[0]
        return (
            actual_profile == profile
            or actual_profile.startswith(f"{profile}.")
            or actual_profile.startswith(f"{profile}_")
            or actual_profile.endswith(f".{profile}")
        )

    def _target_paths(self) -> list[str]:
        return normalize_endpoint_target_paths(self.config.paths, self.config.target_username)

    def _connection_host(self) -> str:
        return resolve_endpoint_connection_host(self.config.host)

    def _connection_hosts(self) -> list[str]:
        return endpoint_connection_hosts(self.config.host) or [self.config.host.strip()]

    def _username(self) -> str:
        username = self.config.username.strip()
        if self.config.domain.strip() and "\\" not in username and "@" not in username:
            username = f"{self.config.domain.strip()}\\{username}"
        return username

    def _endpoint_url(self, connection_host: str) -> str:
        port = self.config.port or (5986 if self.config.use_ssl else 5985)
        return f"http{'s' if self.config.use_ssl else ''}://{connection_host}:{port}/wsman"

    def _run_ps(self, script: str):
        try:
            import winrm
        except ModuleNotFoundError as exc:
            raise RuntimeError("Missing dependency 'pywinrm'. Install requirements.txt before WinRM endpoint scans.") from exc

        if not self.config.use_ssl and __import__("os").getenv("DSPM_REQUIRE_WINRM_SSL", "0") == "1":
            raise RuntimeError("WinRM over HTTP is disabled by configuration")
        last_error: Exception | None = None
        for connection_host in self._connection_hosts():
            try:
                session = winrm.Session(self._endpoint_url(connection_host), auth=(self._username(), self.config.password), transport="ntlm")
                result = session.run_ps(script)
                self.last_connection_host = connection_host
                return result
            except Exception as exc:
                last_error = exc
                continue
        if last_error:
            raise last_error
        raise RuntimeError("No endpoint host candidate was available for WinRM connection.")

    def _run_ps_file(self, script: str):
        try:
            import winrm
        except ModuleNotFoundError as exc:
            raise RuntimeError("Missing dependency 'pywinrm'. Install requirements.txt before WinRM endpoint scans.") from exc

        if not self.config.use_ssl and __import__("os").getenv("DSPM_REQUIRE_WINRM_SSL", "0") == "1":
            raise RuntimeError("WinRM over HTTP is disabled by configuration")
        last_error: Exception | None = None
        for connection_host in self._connection_hosts():
            try:
                session = winrm.Session(self._endpoint_url(connection_host), auth=(self._username(), self.config.password), transport="ntlm")
                result = self._run_ps_file_with_session(session, script)
                self.last_connection_host = connection_host
                return result
            except Exception as exc:
                last_error = exc
                continue
        if last_error:
            raise last_error
        raise RuntimeError("No endpoint host candidate was available for WinRM connection.")

    def _run_ps_file_with_session(self, session, script: str):

        token = uuid4().hex
        b64_name = f"dspm_{token}.b64"
        encoded_script = base64.b64encode(script.encode("utf-8")).decode("ascii")
        chunk_size = 1800

        def run_short(command: str):
            encoded_command = base64.b64encode(command.encode("utf-16le")).decode("ascii")
            return session.run_cmd(
                "powershell.exe",
                ["-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded_command],
            )

        temp_path = (
            "$tempRoot = $env:TEMP; "
            "if ([string]::IsNullOrWhiteSpace($tempRoot) -or -not (Test-Path -LiteralPath $tempRoot)) { $tempRoot = $env:TMP; } "
            "if ([string]::IsNullOrWhiteSpace($tempRoot) -or -not (Test-Path -LiteralPath $tempRoot)) { $tempRoot = 'C:\\Windows\\Temp'; } "
            "if (-not (Test-Path -LiteralPath $tempRoot)) { New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null; } "
            f"$p = Join-Path $tempRoot '{b64_name}'; "
        )
        init = run_short(temp_path + "Set-Content -LiteralPath $p -Value '' -Encoding ASCII")
        if init.status_code != 0:
            return init

        for index in range(0, len(encoded_script), chunk_size):
            chunk = encoded_script[index : index + chunk_size]
            append = run_short(temp_path + f"Add-Content -LiteralPath $p -Value '{chunk}' -Encoding ASCII")
            if append.status_code != 0:
                run_short(temp_path + "try { if ($p -and (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue } } catch { }")
                return append

        materialize = (
            "$ErrorActionPreference = 'Stop'; "
            "$tempRoot = $env:TEMP; "
            "if ([string]::IsNullOrWhiteSpace($tempRoot) -or -not (Test-Path -LiteralPath $tempRoot)) { $tempRoot = $env:TMP; } "
            "if ([string]::IsNullOrWhiteSpace($tempRoot) -or -not (Test-Path -LiteralPath $tempRoot)) { $tempRoot = 'C:\\Windows\\Temp'; } "
            f"$b64 = Join-Path $tempRoot '{b64_name}'; "
            "$raw = (Get-Content -LiteralPath $b64 -Raw).Trim(); "
            "$script = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($raw)); "
            "$null = [ScriptBlock]::Create($script)"
        )
        materialized = run_short(materialize)
        if materialized.status_code != 0:
            run_short(temp_path + "try { if ($p -and (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue } } catch { }")
            return materialized

        execute = (
            "$ErrorActionPreference = 'Stop'; "
            "$tempRoot = $env:TEMP; "
            "if ([string]::IsNullOrWhiteSpace($tempRoot) -or -not (Test-Path -LiteralPath $tempRoot)) { $tempRoot = $env:TMP; } "
            "if ([string]::IsNullOrWhiteSpace($tempRoot) -or -not (Test-Path -LiteralPath $tempRoot)) { $tempRoot = 'C:\\Windows\\Temp'; } "
            f"$b64 = Join-Path $tempRoot '{b64_name}'; "
            "$raw = (Get-Content -LiteralPath $b64 -Raw).Trim(); "
            "$script = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($raw)); "
            "$scriptBlock = [ScriptBlock]::Create($script); "
            "$exitCode = 0; "
            "try { "
            "& $scriptBlock; "
            "if ($LASTEXITCODE -ne $null) { $exitCode = $LASTEXITCODE } "
            "} catch { "
            "Write-Error $_; "
            "$exitCode = 1 "
            "} finally { "
            "try { if ($b64 -and (Test-Path -LiteralPath $b64 -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $b64 -Force -ErrorAction SilentlyContinue } } catch { } "
            "} "
            "exit $exitCode"
        )
        return run_short(execute)


def _scan_script(
    paths: list[str],
    max_depth: int,
    read_content: bool,
    max_read_bytes: int,
    allowed_extensions: list[str],
    extension_filter_enabled: bool,
    include_hidden: bool,
    include_system: bool,
    hidden_filter_enabled: bool,
    system_filter_enabled: bool,
    read_acl: bool,
    inspect_archives: bool,
) -> str:
    encoded_paths = base64.b64encode(json.dumps(paths).encode("utf-8")).decode("ascii")
    encoded_extensions = base64.b64encode(json.dumps(allowed_extensions).encode("utf-8")).decode("ascii")
    read_content_value = "$true" if read_content else "$false"
    extension_filter_value = "$true" if extension_filter_enabled else "$false"
    include_hidden_value = "$true" if include_hidden else "$false"
    include_system_value = "$true" if include_system else "$false"
    hidden_filter_value = "$true" if hidden_filter_enabled else "$false"
    system_filter_value = "$true" if system_filter_enabled else "$false"
    read_acl_value = "$true" if read_acl else "$false"
    inspect_archives_value = "$true" if inspect_archives else "$false"
    text_extensions = ",".join(f'"{item}"' for item in sorted(TEXT_EXTENSIONS))
    binary_extensions = ",".join(f'"{item}"' for item in sorted(BINARY_TEXT_EXTENSIONS))
    return f"""
    $ErrorActionPreference = "SilentlyContinue"
    $pathsJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{encoded_paths}"))
    $targetPaths = ConvertFrom-Json $pathsJson
    $extensionsJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{encoded_extensions}"))
    $rawAllowedExtensions = @(ConvertFrom-Json $extensionsJson)
    $allowedSet = @{{}}
    foreach ($rawExtension in $rawAllowedExtensions) {{
      foreach ($piece in (([string]$rawExtension) -split "[,;\\s]+")) {{
        $item = $piece.Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($item)) {{ continue }}
        if (-not $item.StartsWith(".")) {{ $item = ".$item" }}
        $allowedSet[$item] = $true
      }}
    }}
    $allowedExtensions = @($allowedSet.Keys | Sort-Object)
    $textExtensions = @({text_extensions})
    $binaryExtensions = @({binary_extensions})
    $archiveExtensions = @(".7z", ".bz2", ".cab", ".gz", ".jar", ".rar", ".tar", ".tgz", ".xz", ".zip")
    $scanArchiveEntries = {inspect_archives_value}
    $maxRecords = 5000
    $maxArchiveEntriesPerFile = 200
    $records = New-Object System.Collections.Generic.List[object]
    $extensionHistogram = @{{}}
    $diagnostics = [ordered]@{{
      requested_roots = @($targetPaths)
      resolved_roots = @()
      missing_roots = @()
      visited_files = 0
      matched_files = 0
      archive_files = 0
      archive_entries = 0
      archive_entries_skipped = 0
      archive_errors = @()
      record_limit_reached = $false
      skipped_dirs = 0
      unreadable_dirs = @()
      allowed_extensions = @($allowedExtensions)
      extension_histogram = @{{}}
      selected_extension_counts = @{{}}
      extension_filter_enabled = {extension_filter_value}
      hidden_filter_enabled = {hidden_filter_value}
      system_filter_enabled = {system_filter_value}
    }}

    function Get-RelativeDepth($root, $path) {{
      $relative = $path.Substring([Math]::Min($root.Length, $path.Length)).Trim("\\")
      if ([string]::IsNullOrWhiteSpace($relative)) {{ return 0 }}
      return ($relative -split "\\\\").Count
    }}

    function Get-DspmExtension($file) {{
      if ($file.Extension) {{ return $file.Extension.ToLowerInvariant() }}
      $name = $file.Name.ToLowerInvariant()
      if ($name.StartsWith(".")) {{ return $name }}
      if ($name -eq "dockerfile") {{ return ".dockerfile" }}
      return ""
    }}

    function Get-DspmExtensionFromName($name) {{
      $fileName = [System.IO.Path]::GetFileName([string]$name)
      $extension = [System.IO.Path]::GetExtension($fileName)
      if ($extension) {{ return $extension.ToLowerInvariant() }}
      $lower = $fileName.ToLowerInvariant()
      if ($lower.StartsWith(".")) {{ return $lower }}
      if ($lower -eq "dockerfile") {{ return ".dockerfile" }}
      return ""
    }}

    function Add-DspmExtensionStat($extension) {{
      $extensionKey = if ($extension) {{ $extension }} else {{ "no extension" }}
      if ($extensionHistogram.ContainsKey($extensionKey)) {{
        $extensionHistogram[$extensionKey] += 1
      }} else {{
        $extensionHistogram[$extensionKey] = 1
      }}
      if ({extension_filter_value} -and $extension -and $allowedSet.ContainsKey($extension.ToLowerInvariant())) {{
        $selectedKey = $extension.ToLowerInvariant()
        if ($diagnostics.selected_extension_counts.ContainsKey($selectedKey)) {{
          $diagnostics.selected_extension_counts[$selectedKey] += 1
        }} else {{
          $diagnostics.selected_extension_counts[$selectedKey] = 1
        }}
      }}
    }}

    function Test-DspmRecordIncluded($extension, $isHidden, $isSystem) {{
      if ({extension_filter_value} -and (-not $extension -or -not $allowedSet.ContainsKey($extension.ToLowerInvariant()))) {{ return $false }}
      if ({hidden_filter_value} -and -not $isHidden) {{ return $false }}
      if ((-not {hidden_filter_value}) -and $isHidden -and -not {include_hidden_value}) {{ return $false }}
      if ({system_filter_value} -and -not $isSystem) {{ return $false }}
      if ((-not {system_filter_value}) -and $isSystem -and -not {include_system_value}) {{ return $false }}
      return $true
    }}

    function Test-DspmSkippedPath($path) {{
      $normalized = $path.ToLowerInvariant()
      if (-not $normalized.EndsWith([string][char]92)) {{ $normalized = $normalized + [string][char]92 }}
      $skipFragments = @(
        '\\enterprise_test_data\\',
        '\\dspm_project-main\\',
        '\\.codex\\',
        '\\.git\\',
        '\\.vscode\\',
        '\\node_modules\\',
        '\\program files\\',
        '\\program files (x86)\\',
        '\\program files\\common files\\',
        '\\program files (x86)\\common files\\',
        '\\programdata\\',
        '\\programdata\\package cache\\',
        '\\programdata\\microsoft\\windows defender\\',
        '\\windows\\',
        '\\$winreagent\\',
        '\\recovery\\',
        '\\config.msi\\',
        '\\perflogs\\',
        '\\msocache\\',
        '\\$recycle.bin\\',
        '\\system volume information\\',
        '\\pagefile.sys\\',
        '\\swapfile.sys\\',
        '\\hiberfil.sys\\',
        '\\dumpstack.log',
        '\\appdata\\',
        '\\appdata\\local\\temp\\',
        '\\appdata\\local\\microsoft\\edge\\',
        '\\appdata\\local\\google\\chrome\\',
        '\\appdata\\local\\packages\\',
        '\\appdata\\local\\microsoft\\windows sidebar\\',
        '\\appdata\\roaming\\microsoft\\windows\\recent\\'
      )
      foreach ($fragment in $skipFragments) {{
        if ($normalized.Contains($fragment)) {{ return $true }}
      }}
      return $false
    }}

    function Test-DspmUserProfileDir($dir) {{
      if (-not $dir -or -not $dir.PSIsContainer) {{ return $false }}
      $name = $dir.Name.ToLowerInvariant()
      $skipNames = @(
        "all users",
        "default",
        "default user",
        "public",
        "defaultapppool",
        "administrator"
      )
      if ($skipNames -contains $name) {{ return $false }}
      if ($name.StartsWith("default.")) {{ return $false }}
      return $true
    }}

    function Test-DspmProfileNameMatch($candidateName, $profileName) {{
      if ([string]::IsNullOrWhiteSpace($candidateName) -or [string]::IsNullOrWhiteSpace($profileName)) {{ return $false }}
      $name = ([string]$candidateName).ToLowerInvariant()
      $profileNameLower = ([string]$profileName).ToLowerInvariant()
      return (
        $name -eq $profileNameLower -or
        $name.StartsWith("$profileNameLower.") -or
        $name.StartsWith("$profileNameLower_") -or
        $name.EndsWith(".$profileNameLower")
      )
    }}

    function Add-DspmRecord($record) {{
      if ($records.Count -ge $maxRecords) {{
        $diagnostics.record_limit_reached = $true
        return $false
      }}
      $records.Add($record) | Out-Null
      return $true
    }}

    function Add-DspmProfileFolderCandidates($roots, $profileRoot, $folderName) {{
      $candidatePaths = New-Object System.Collections.Generic.List[string]
      $candidatePaths.Add((Join-Path $profileRoot $folderName)) | Out-Null
      Get-ChildItem -LiteralPath $profileRoot -Directory -Force -ErrorAction SilentlyContinue | Where-Object {{
        $_.Name -eq "OneDrive" -or $_.Name.StartsWith("OneDrive - ")
      }} | ForEach-Object {{
        $candidatePaths.Add((Join-Path $_.FullName $folderName)) | Out-Null
      }}
      foreach ($candidatePath in $candidatePaths) {{
        if ((Test-Path -LiteralPath $candidatePath) -and -not $roots.Contains($candidatePath)) {{
          $roots.Add($candidatePath) | Out-Null
        }}
      }}
    }}

    function Add-DspmProfileStandardCandidates($roots, $profileRoot) {{
      $before = $roots.Count
      foreach ($folderName in @("Desktop", "Documents", "Downloads")) {{
        Add-DspmProfileFolderCandidates $roots $profileRoot $folderName
      }}
      if ($roots.Count -eq $before -and (Test-Path -LiteralPath $profileRoot)) {{
        $roots.Add($profileRoot) | Out-Null
      }}
    }}

    function Resolve-DspmRoot($root) {{
      $roots = New-Object System.Collections.Generic.List[string]
      if ($root -match "^[A-Za-z]:$") {{
        $root = ([string]$root) + [string][char]92
      }}
      if ($root -eq "__DSPM_ALL_PROFILES__" -or $root -eq "__DSPM_ALL_USER_PROFILES__") {{
        try {{
          Get-ChildItem -LiteralPath "C:\\Users" -Directory -Force -ErrorAction SilentlyContinue | Where-Object {{
            Test-DspmUserProfileDir $_
          }} | ForEach-Object {{
            if (Test-Path -LiteralPath $_.FullName) {{
              $roots.Add($_.FullName) | Out-Null
            }}
          }}
        }} catch {{
          return @()
        }}
        return @($roots.ToArray())
      }}
      if ($root -eq "__DSPM_FIXED_DRIVES__") {{
        try {{
          Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue | ForEach-Object {{
            $driveRoot = "$($_.DeviceID)\\"
            if (Test-Path -LiteralPath $driveRoot) {{
              $roots.Add($driveRoot) | Out-Null
            }}
          }}
        }} catch {{
          Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | ForEach-Object {{
            $driveRoot = "$($_.Name):\\"
            if (Test-Path -LiteralPath $driveRoot) {{
              $roots.Add($driveRoot) | Out-Null
            }}
          }}
        }}
        return @($roots.ToArray())
      }}
      if ($root -eq "__DSPM_ALL_ONEDRIVE__") {{
        try {{
          Get-ChildItem -LiteralPath "C:\\Users" -Directory -Force -ErrorAction SilentlyContinue | Where-Object {{
            Test-DspmUserProfileDir $_
          }} | ForEach-Object {{
            Get-ChildItem -LiteralPath $_.FullName -Directory -Force -ErrorAction SilentlyContinue | Where-Object {{
              $_.Name -eq "OneDrive" -or $_.Name.StartsWith("OneDrive - ")
            }} | ForEach-Object {{
              $roots.Add($_.FullName) | Out-Null
            }}
          }}
        }} catch {{
          return @()
        }}
        return @($roots.ToArray())
      }}
      if ($root.StartsWith("__DSPM_ONEDRIVE_FOR__:", [System.StringComparison]::OrdinalIgnoreCase)) {{
        $profileName = $root.Substring("__DSPM_ONEDRIVE_FOR__:".Length).Trim()
        if ([string]::IsNullOrWhiteSpace($profileName)) {{ return @() }}
        try {{
          $exactProfileRoot = Join-Path "C:\\Users" $profileName
          if (Test-Path -LiteralPath $exactProfileRoot) {{
            Get-ChildItem -LiteralPath $exactProfileRoot -Directory -Force -ErrorAction SilentlyContinue | Where-Object {{
              $_.Name -eq "OneDrive" -or $_.Name.StartsWith("OneDrive - ")
            }} | ForEach-Object {{
              $roots.Add($_.FullName) | Out-Null
            }}
            return @($roots.ToArray())
          }}
          Get-ChildItem -LiteralPath "C:\\Users" -Directory -Force -ErrorAction SilentlyContinue | Where-Object {{
            Test-DspmProfileNameMatch $_.Name $profileName
          }} | ForEach-Object {{
            Get-ChildItem -LiteralPath $_.FullName -Directory -Force -ErrorAction SilentlyContinue | Where-Object {{
              $_.Name -eq "OneDrive" -or $_.Name.StartsWith("OneDrive - ")
            }} | ForEach-Object {{
              $roots.Add($_.FullName) | Out-Null
            }}
          }}
        }} catch {{
          return @()
        }}
        return @($roots.ToArray())
      }}
      if ($root -eq "__DSPM_PROFILE_STANDARD__") {{
        try {{
          Get-ChildItem -LiteralPath "C:\\Users" -Directory -Force -ErrorAction SilentlyContinue | Where-Object {{
            Test-DspmUserProfileDir $_
          }} | ForEach-Object {{
            Add-DspmProfileStandardCandidates $roots $_.FullName
          }}
        }} catch {{
          return @()
        }}
        return @($roots.ToArray())
      }}
      if ($root.StartsWith("__DSPM_PROFILE_FOLDER__:", [System.StringComparison]::OrdinalIgnoreCase)) {{
        $folderName = $root.Substring("__DSPM_PROFILE_FOLDER__:".Length).Trim()
        if ([string]::IsNullOrWhiteSpace($folderName)) {{ return @() }}
        try {{
          Get-ChildItem -LiteralPath "C:\\Users" -Directory -Force -ErrorAction SilentlyContinue | Where-Object {{
            Test-DspmUserProfileDir $_
          }} | ForEach-Object {{
            Add-DspmProfileFolderCandidates $roots $_.FullName $folderName
          }}
        }} catch {{
          return @()
        }}
        return @($roots.ToArray())
      }}
      if ($root.StartsWith("__DSPM_PROFILE_STANDARD_FOR__:", [System.StringComparison]::OrdinalIgnoreCase)) {{
        $profileName = $root.Substring("__DSPM_PROFILE_STANDARD_FOR__:".Length).Trim()
        if ([string]::IsNullOrWhiteSpace($profileName)) {{ return @() }}
        try {{
          $exactProfileRoot = Join-Path "C:\\Users" $profileName
          if (Test-Path -LiteralPath $exactProfileRoot) {{
            Add-DspmProfileStandardCandidates $roots $exactProfileRoot
            return @($roots.ToArray())
          }}
          Get-ChildItem -LiteralPath "C:\\Users" -Directory -Force -ErrorAction SilentlyContinue | Where-Object {{
            Test-DspmProfileNameMatch $_.Name $profileName
          }} | ForEach-Object {{
            Add-DspmProfileStandardCandidates $roots $_.FullName
          }}
        }} catch {{
          return @()
        }}
        return @($roots.ToArray())
      }}
      if ($root.StartsWith("__DSPM_PROFILE_ROOT_FOR__:", [System.StringComparison]::OrdinalIgnoreCase)) {{
        $profileName = $root.Substring("__DSPM_PROFILE_ROOT_FOR__:".Length).Trim()
        if ([string]::IsNullOrWhiteSpace($profileName)) {{ return @() }}
        try {{
          $exactProfileRoot = Join-Path "C:\\Users" $profileName
          if (Test-Path -LiteralPath $exactProfileRoot) {{
            $roots.Add($exactProfileRoot) | Out-Null
            return @($roots.ToArray())
          }}
          Get-ChildItem -LiteralPath "C:\\Users" -Directory -Force -ErrorAction SilentlyContinue | Where-Object {{
            Test-DspmProfileNameMatch $_.Name $profileName
          }} | ForEach-Object {{
            if (Test-Path -LiteralPath $_.FullName) {{
              $roots.Add($_.FullName) | Out-Null
            }}
          }}
        }} catch {{
          return @()
        }}
        return @($roots.ToArray())
      }}
      if ($root.StartsWith("__DSPM_PROFILE_FOLDER_FOR__:", [System.StringComparison]::OrdinalIgnoreCase)) {{
        $payload = $root.Substring("__DSPM_PROFILE_FOLDER_FOR__:".Length)
        $parts = $payload -split ":", 2
        if ($parts.Count -ne 2) {{ return @() }}
        $profileName = $parts[0].Trim()
        $folderName = $parts[1].Trim()
        if ([string]::IsNullOrWhiteSpace($profileName) -or [string]::IsNullOrWhiteSpace($folderName)) {{ return @() }}
        try {{
          $exactProfileRoot = Join-Path "C:\\Users" $profileName
          if (Test-Path -LiteralPath $exactProfileRoot) {{
            Add-DspmProfileFolderCandidates $roots $exactProfileRoot $folderName
            return @($roots.ToArray())
          }}
          Get-ChildItem -LiteralPath "C:\\Users" -Directory -Force -ErrorAction SilentlyContinue | Where-Object {{
            Test-DspmProfileNameMatch $_.Name $profileName
          }} | ForEach-Object {{
            Add-DspmProfileFolderCandidates $roots $_.FullName $folderName
          }}
        }} catch {{
          return @()
        }}
        return @($roots.ToArray())
      }}
      if ($root.StartsWith("__DSPM_PROFILE_RELATIVE_FOR__:", [System.StringComparison]::OrdinalIgnoreCase)) {{
        $payload = $root.Substring("__DSPM_PROFILE_RELATIVE_FOR__:".Length)
        $parts = $payload -split ":", 2
        if ($parts.Count -ne 2) {{ return @() }}
        $profileName = $parts[0].Trim()
        $relativePath = $parts[1].Trim().Trim("\\")
        if ([string]::IsNullOrWhiteSpace($profileName) -or [string]::IsNullOrWhiteSpace($relativePath)) {{ return @() }}
        try {{
          $exactProfileRoot = Join-Path "C:\\Users" $profileName
          if (Test-Path -LiteralPath $exactProfileRoot) {{
            $candidatePath = Join-Path $exactProfileRoot $relativePath
            if (Test-Path -LiteralPath $candidatePath) {{
              $roots.Add($candidatePath) | Out-Null
            }}
            return @($roots.ToArray())
          }}
          Get-ChildItem -LiteralPath "C:\\Users" -Directory -Force -ErrorAction SilentlyContinue | Where-Object {{
            Test-DspmProfileNameMatch $_.Name $profileName
          }} | ForEach-Object {{
            $candidatePath = Join-Path $_.FullName $relativePath
            if (Test-Path -LiteralPath $candidatePath) {{
              $roots.Add($candidatePath) | Out-Null
            }}
          }}
        }} catch {{
          return @()
        }}
        return @($roots.ToArray())
      }}
      if (Test-Path -LiteralPath $root) {{
        $roots.Add($root) | Out-Null
        return @($roots.ToArray())
      }}

      try {{
        $usersRoot = "C:\\Users"
        if (-not $root.StartsWith($usersRoot, [System.StringComparison]::OrdinalIgnoreCase)) {{
          return @()
        }}
        $relative = $root.Substring($usersRoot.Length).Trim("\\")
        if ([string]::IsNullOrWhiteSpace($relative)) {{
          return @()
        }}
        $parts = $relative -split "\\\\"
        $profileName = $parts[0]
        $suffix = if ($parts.Count -gt 1) {{ ($parts[1..($parts.Count - 1)] -join "\\") }} else {{ "" }}
        $candidates = Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue | Where-Object {{
          Test-DspmProfileNameMatch $_.Name $profileName
        }}
        foreach ($candidate in $candidates) {{
          $candidatePath = if ($suffix) {{ Join-Path $candidate.FullName $suffix }} else {{ $candidate.FullName }}
          if (Test-Path -LiteralPath $candidatePath) {{
            $roots.Add($candidatePath) | Out-Null
          }}
        }}
      }} catch {{
        return @()
      }}
      return @($roots.ToArray())
    }}

    function Read-PlainText($path, $maxBytes) {{
      try {{
        $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {{
          $buffer = New-Object byte[] $maxBytes
          $read = $stream.Read($buffer, 0, $buffer.Length)
          return [Text.Encoding]::UTF8.GetString($buffer, 0, $read)
        }} finally {{
          $stream.Close()
        }}
      }} catch {{
        return ""
      }}
    }}

    function Read-ZipXmlText($path, $prefix) {{
      try {{
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($path)
        try {{
          $parts = New-Object System.Collections.Generic.List[string]
          foreach ($entry in $archive.Entries) {{
            if ($entry.FullName.StartsWith($prefix) -and $entry.FullName.EndsWith(".xml")) {{
              $reader = New-Object System.IO.StreamReader($entry.Open())
              try {{
                $xml = $reader.ReadToEnd()
                $clean = $xml -replace "<[^>]+>", " "
                $clean = $clean -replace "\\s+", " "
                $parts.Add($clean) | Out-Null
              }} finally {{
                $reader.Close()
              }}
            }}
          }}
          $joined = $parts -join "`n"
          return $joined.Substring(0, [Math]::Min(120000, $joined.Length))
        }} finally {{
          $archive.Dispose()
        }}
      }} catch {{
        return ""
      }}
    }}

    function Read-BinaryText($path, $extension, $maxBytes) {{
      if (@(".docm", ".docx", ".dotm", ".dotx") -contains $extension) {{ return Read-ZipXmlText $path "word/" }}
      if (@(".xlsm", ".xlsx") -contains $extension) {{ return Read-ZipXmlText $path "xl/" }}
      if (@(".pptm", ".pptx") -contains $extension) {{ return Read-ZipXmlText $path "ppt/slides/" }}
      if (@(".odp", ".ods", ".odt", ".otp") -contains $extension) {{ return Read-ZipXmlText $path "" }}
      if ($extension -eq ".pdf") {{
        try {{
          $bytes = [System.IO.File]::ReadAllBytes($path)
          $limit = [Math]::Min($bytes.Length, $maxBytes * 4)
          $text = [Text.Encoding]::GetEncoding("iso-8859-1").GetString($bytes, 0, $limit)
          return (($text | Select-String -Pattern "\\(([^()]*)\\)" -AllMatches).Matches | ForEach-Object {{ $_.Groups[1].Value }}) -join "`n"
        }} catch {{
          return ""
        }}
      }}
      return ""
    }}

    function Read-ZipEntryText($entry, $extension, $maxBytes) {{
      if (-not ($textExtensions -contains $extension)) {{ return "" }}
      try {{
        $stream = $entry.Open()
        try {{
          $buffer = New-Object byte[] $maxBytes
          $read = $stream.Read($buffer, 0, $buffer.Length)
          return [Text.Encoding]::UTF8.GetString($buffer, 0, $read)
        }} finally {{
          $stream.Close()
        }}
      }} catch {{
        return ""
      }}
    }}

    function Copy-ZipEntryToMemory($entry, $maxBytes) {{
      try {{
        $inputStream = $entry.Open()
        try {{
          $memory = New-Object System.IO.MemoryStream
          $buffer = New-Object byte[] 65536
          $total = 0
          while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {{
            $total += $read
            if ($total -gt $maxBytes) {{
              $memory.Dispose()
              return $null
            }}
            $memory.Write($buffer, 0, $read)
          }}
          $memory.Position = 0
          return $memory
        }} finally {{
          $inputStream.Close()
        }}
      }} catch {{
        return $null
      }}
    }}

    function Test-DspmZipProtection($path) {{
      $result = [ordered]@{{
        protected = $false
        content_status = ""
        protection_type = ""
        scan_error = ""
      }}
      try {{
        Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
        $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {{
          $archive = New-Object -TypeName System.IO.Compression.ZipArchive -ArgumentList $stream, ([System.IO.Compression.ZipArchiveMode]::Read), $false
          try {{
            foreach ($entry in @($archive.Entries | Select-Object -First 2000)) {{
              if ([string]::IsNullOrWhiteSpace($entry.Name)) {{ continue }}
              $entryStream = $null
              try {{
                $entryStream = $entry.Open()
                $null = $entryStream.ReadByte()
              }} catch {{
                $result.protected = $true
                $result.content_status = "password_protected"
                $result.protection_type = "zip_password"
                $result.scan_error = "ZIP archive has encrypted or unreadable entries and needs review"
                break
              }} finally {{
                if ($entryStream) {{ $entryStream.Dispose() }}
              }}
            }}
          }} finally {{
            $archive.Dispose()
          }}
        }} finally {{
          $stream.Dispose()
        }}
      }} catch {{
        $result.protected = $true
        $result.content_status = "bad_archive"
        $result.protection_type = "unreadable_archive"
        $result.scan_error = "ZIP archive could not be opened or parsed"
      }}
      return [PSCustomObject]$result
    }}

    function Add-ZipEntries($archive, $archivePath, $isHidden, $isSystem, $depth) {{
      if ($depth -gt 2) {{ return }}
      $entries = @($archive.Entries)
      if ($entries.Count -gt $maxArchiveEntriesPerFile) {{
        $diagnostics.archive_entries_skipped += ($entries.Count - $maxArchiveEntriesPerFile)
      }}
      foreach ($entry in @($entries | Select-Object -First $maxArchiveEntriesPerFile)) {{
        if ($records.Count -ge $maxRecords) {{ return }}
        if ([string]::IsNullOrWhiteSpace($entry.Name)) {{ continue }}
        $entryPath = "${{archivePath}}::$($entry.FullName)"
        $entryExtension = Get-DspmExtensionFromName $entry.FullName
        Add-DspmExtensionStat $entryExtension
        $includeEntry = Test-DspmRecordIncluded $entryExtension $isHidden $isSystem
        if ($includeEntry) {{
          $diagnostics.archive_entries += 1
          $diagnostics.matched_files += 1
          $entryContent = ""
          Add-DspmRecord ([PSCustomObject]@{{
            path = $entryPath
            name = $entry.Name
            size = $entry.Length
            extension = $entryExtension
            is_hidden = $isHidden
            is_system = $isSystem
            created_at = ""
            modified_at = if ($entry.LastWriteTime) {{ $entry.LastWriteTime.UtcDateTime.ToString("o") }} else {{ "" }}
            accessed_at = ""
            owner = ""
            principals = @()
            permissions = @()
            content = $entryContent
          }}) | Out-Null
        }}
        if ($entryExtension -eq ".zip") {{
          $memory = Copy-ZipEntryToMemory $entry 52428800
          if ($memory) {{
            try {{
              $nestedArchive = New-Object -TypeName System.IO.Compression.ZipArchive -ArgumentList $memory, ([System.IO.Compression.ZipArchiveMode]::Read)
              try {{
                Add-ZipEntries $nestedArchive $entryPath $isHidden $isSystem ($depth + 1)
              }} finally {{
                $nestedArchive.Dispose()
              }}
            }} catch {{
            }} finally {{
              $memory.Dispose()
            }}
          }}
        }}
      }}
    }}

    function Add-ZipFileEntries($path, $isHidden, $isSystem) {{
      $stream = $null
      $archive = $null
      try {{
        Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
        $diagnostics.archive_files += 1
        $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $archive = New-Object -TypeName System.IO.Compression.ZipArchive -ArgumentList $stream, ([System.IO.Compression.ZipArchiveMode]::Read), $false
        Add-ZipEntries $archive $path $isHidden $isSystem 0
      }} catch {{
        $diagnostics.archive_errors += "$($path): $($_.Exception.Message)"
      }} finally {{
        if ($archive) {{ $archive.Dispose() }}
        if ($stream) {{ $stream.Dispose() }}
      }}
    }}

    function Add-DspmFileRecord($file, $root) {{
      $diagnostics.visited_files += 1
      $extension = Get-DspmExtension $file
      $isHidden = [bool]($file.Attributes -band [IO.FileAttributes]::Hidden)
      $isSystem = [bool]($file.Attributes -band [IO.FileAttributes]::System)
      Add-DspmExtensionStat $extension
      $includeRecord = Test-DspmRecordIncluded $extension $isHidden $isSystem
      if ($scanArchiveEntries -and $extension -eq ".zip") {{ Add-ZipFileEntries $file.FullName $isHidden $isSystem }}
      if (-not $includeRecord) {{ return }}
      $diagnostics.matched_files += 1
      $zipProtection = if ($extension -eq ".zip") {{ Test-DspmZipProtection $file.FullName }} else {{ [PSCustomObject]@{{ protected = $false; content_status = ""; protection_type = ""; scan_error = "" }} }}
      $ownerAcl = Get-Acl -LiteralPath $file.FullName -ErrorAction SilentlyContinue
      $acl = if ({read_acl_value}) {{ $ownerAcl }} else {{ $null }}
      $content = ""
      if ({read_content_value} -and ($textExtensions -contains $extension)) {{
        $content = Read-PlainText $file.FullName {int(max_read_bytes)}
      }} elseif ({read_content_value} -and ($binaryExtensions -contains $extension)) {{
        $content = Read-BinaryText $file.FullName $extension {int(max_read_bytes)}
      }}
      $sha256 = ""
      try {{
        $sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName -ErrorAction Stop).Hash.ToLowerInvariant()
      }} catch {{
        $sha256 = ""
      }}
      Add-DspmRecord ([PSCustomObject]@{{
        path = $file.FullName
        name = $file.Name
        size = $file.Length
        extension = $extension
        is_hidden = $isHidden
        is_system = $isSystem
        created_at = $file.CreationTimeUtc.ToString("o")
        modified_at = $file.LastWriteTimeUtc.ToString("o")
        accessed_at = $file.LastAccessTimeUtc.ToString("o")
        attributes = $file.Attributes.ToString()
        sha256 = $sha256
        protected = [bool]$zipProtection.protected
        content_status = if ($zipProtection.content_status) {{ $zipProtection.content_status }} else {{ "" }}
        content_scannable = if ($zipProtection.protected) {{ $false }} else {{ $null }}
        protection_type = if ($zipProtection.protection_type) {{ $zipProtection.protection_type }} else {{ "" }}
        scan_error = if ($zipProtection.scan_error) {{ $zipProtection.scan_error }} else {{ "" }}
        owner = if ($ownerAcl) {{ $ownerAcl.Owner }} else {{ "" }}
        principals = if ($acl) {{ @($acl.Access | ForEach-Object {{ $_.IdentityReference.Value }}) }} else {{ @() }}
        permissions = if ($acl) {{ @($acl.Access | ForEach-Object {{ $_.FileSystemRights.ToString() }}) }} else {{ @() }}
        content = $content
      }}) | Out-Null
    }}

    function Walk-DspmDirectory($root, $current, $depth) {{
      if ($depth -gt {int(max_depth)}) {{ return }}
      if (Test-DspmSkippedPath $current) {{
        $diagnostics.skipped_dirs += 1
        return
      }}
      $dspmChildErrors = @()
      $entries = @(Get-ChildItem -LiteralPath $current -Force -ErrorAction SilentlyContinue -ErrorVariable dspmChildErrors)
      foreach ($dspmError in @($dspmChildErrors)) {{
        if ($diagnostics.unreadable_dirs.Count -lt 20) {{
          $diagnostics.unreadable_dirs += "$($current): $($dspmError.Exception.Message)"
        }}
      }}
      foreach ($entry in $entries) {{
        if ($entry.PSIsContainer) {{
          $dirHidden = [bool]($entry.Attributes -band [IO.FileAttributes]::Hidden)
          $dirReparse = [bool]($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)
          if ($dirReparse) {{
            $diagnostics.skipped_dirs += 1
            continue
          }}
          if (Test-DspmSkippedPath $entry.FullName) {{
            $diagnostics.skipped_dirs += 1
            continue
          }}
          if ($dirHidden -and -not ({include_hidden_value} -or {hidden_filter_value})) {{
            $diagnostics.skipped_dirs += 1
            continue
          }}
          Walk-DspmDirectory $root $entry.FullName ($depth + 1)
          continue
        }}
        Add-DspmFileRecord $entry $root
      }}
    }}

    foreach ($requestedRoot in $targetPaths) {{
      $resolvedRoots = @(Resolve-DspmRoot $requestedRoot)
      if (-not $resolvedRoots -or $resolvedRoots.Count -eq 0) {{
        $diagnostics.missing_roots += $requestedRoot
        continue
      }}
      foreach ($root in $resolvedRoots) {{
        $diagnostics.resolved_roots += $root
        if ((Get-Item -LiteralPath $root -ErrorAction SilentlyContinue).PSIsContainer) {{
          Walk-DspmDirectory $root $root 0
        }} else {{
          $file = Get-Item -LiteralPath $root -ErrorAction SilentlyContinue
          if ($file) {{ Add-DspmFileRecord $file $root }}
        }}
      }}
    }}
    $diagnostics.extension_histogram = $extensionHistogram
    [PSCustomObject]@{{
      records = @($records.ToArray())
      diagnostics = $diagnostics
    }} | ConvertTo-Json -Depth 6 -Compress
    """


def _activation_script(payload: dict) -> str:
    encoded_payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    remote_script = """
    $ProgressPreference = "SilentlyContinue"
    $ErrorActionPreference = "SilentlyContinue"
    Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Ole" -Name EnableDCOM -Type String -Value "Y" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name LocalAccountTokenFilterPolicy -Type DWord -Value 1 -Force
    Set-Service -Name WinRM -StartupType Automatic
    Start-Service -Name WinRM
    Enable-PSRemoting -Force -SkipNetworkProfileCheck
    winrm quickconfig -quiet
    winrm create "winrm/config/Listener?Address=*+Transport=HTTP" '@{Port="5985"}' 2>$null
    winrm set "winrm/config/service" '@{IPv4Filter="*";IPv6Filter="*"}'
    netsh advfirewall firewall set rule group="Windows Remote Management" new enable=yes | Out-Null
    netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=yes | Out-Null
    netsh advfirewall firewall set rule group="Remote Administration" new enable=yes | Out-Null
    netsh advfirewall firewall add rule name="DSPM WinRM HTTP 5985" dir=in action=allow protocol=TCP localport=5985 profile=any | Out-Null
    New-NetFirewallRule -DisplayName "DSPM WinRM HTTP" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
    """
    encoded_remote = base64.b64encode(remote_script.encode("utf-16le")).decode("ascii")
    remote_command = f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded_remote}"
    return f"""
    $ProgressPreference = "SilentlyContinue"
    $ErrorActionPreference = "Stop"
    $payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{encoded_payload}"))
    $payload = ConvertFrom-Json $payloadJson
    $securePassword = ConvertTo-SecureString ([string]$payload.password) -AsPlainText -Force
    $rawUsername = ([string]$payload.username).Trim()
    $domain = ([string]$payload.domain).Trim()
    $credentialNames = New-Object System.Collections.Generic.List[string]
    if ($rawUsername -match "\\\\" -or $rawUsername -match "@") {{
      $credentialNames.Add($rawUsername)
    }} elseif ($domain -and $domain -ne "WORKGROUP") {{
      $credentialNames.Add("$domain\\$rawUsername")
      if ($domain -match "\\.") {{
        $netbiosDomain = ($domain -split "\\.")[0].ToUpperInvariant()
        $credentialNames.Add("$netbiosDomain\\$rawUsername")
        $credentialNames.Add("$rawUsername@$domain")
      }}
      $credentialNames.Add($rawUsername)
      $credentialNames.Add(".\\$rawUsername")
      $credentialNames.Add("$($payload.host)\\$rawUsername")
    }} else {{
      $credentialNames.Add($rawUsername)
      $credentialNames.Add(".\\$rawUsername")
      $credentialNames.Add("$($payload.host)\\$rawUsername")
    }}

    $result = $null
    $credential = $null
    $credentialName = ""
    $activationErrors = New-Object System.Collections.Generic.List[string]
    foreach ($candidateName in @($credentialNames | Select-Object -Unique)) {{
      try {{
        $candidateCredential = New-Object System.Management.Automation.PSCredential($candidateName, $securePassword)
        $candidateResult = Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName ([string]$payload.host) -Credential $candidateCredential -ArgumentList @("{remote_command}") -ErrorAction Stop
        $result = $candidateResult
        $credential = $candidateCredential
        $credentialName = $candidateName
        break
      }} catch {{
        $activationErrors.Add("${{candidateName}}: $($_.Exception.Message)") | Out-Null
      }}
    }}
    if (-not $credential) {{
      [PSCustomObject]@{{
        activated = $false
        host = [string]$payload.host
        attempted_credentials = @($credentialNames | Select-Object -Unique)
        message = "Target rejected every admin credential format with Access denied. DSPM server preparation is complete, but Windows will not allow remote WMI/DCOM changes on this workstation. Use a credential that is in the target workstation's local Administrators group, or run the one-time WinRM bootstrap locally/on GPO for this target. Details: $($activationErrors -join ' | ')"
      }} | ConvertTo-Json -Compress
      exit 0
    }}
    $serviceState = ""
    $serviceStartReturnValue = $null
    $serviceChangeReturnValue = $null
    $serviceQueryError = ""
    try {{
      $service = Get-WmiObject -Class Win32_Service -ComputerName ([string]$payload.host) -Credential $credential -Filter "Name='WinRM'" -ErrorAction Stop
      if ($service) {{
        $serviceState = [string]$service.State
        if ($service.StartMode -ne "Auto") {{
          $serviceChangeReturnValue = $service.ChangeStartMode("Automatic").ReturnValue
        }}
        if ($service.State -ne "Running") {{
          $serviceStartReturnValue = $service.StartService().ReturnValue
          Start-Sleep -Seconds 5
          $service = Get-WmiObject -Class Win32_Service -ComputerName ([string]$payload.host) -Credential $credential -Filter "Name='WinRM'" -ErrorAction SilentlyContinue
          if ($service) {{ $serviceState = [string]$service.State }}
        }}
      }}
    }} catch {{
      $serviceQueryError = $_.Exception.Message
    }}

    $portOpen = $false
    for ($attempt = 0; $attempt -lt 10 -and -not $portOpen; $attempt++) {{
      Start-Sleep -Seconds 3
      try {{
        $client = New-Object Net.Sockets.TcpClient
        $async = $client.BeginConnect(([string]$payload.host), 5985, $null, $null)
        $portOpen = $async.AsyncWaitHandle.WaitOne(5000, $false)
        if ($portOpen) {{ $client.EndConnect($async) }}
        $client.Close()
      }} catch {{
        $portOpen = $false
      }}
    }}
    $message = if ($portOpen) {{
      "Activation command sent and WinRM port 5985 is reachable."
    }} elseif ($serviceState -eq "Running") {{
      "WinRM service is running on the target, but port 5985 is not reachable from the DSPM server. Check target firewall/GPO, network ACLs, or endpoint security blocking inbound TCP 5985."
    }} elseif ($serviceQueryError) {{
      "Activation command was sent, but WinRM port 5985 is not reachable. WMI service check also failed: $serviceQueryError"
    }} else {{
      "Activation command was sent, but WinRM service state is '$serviceState' and port 5985 is not reachable. Verify the credential has local administrator rights and target policy allows remote service changes."
    }}
    [PSCustomObject]@{{
      activated = [bool]$portOpen
      host = [string]$payload.host
      credential_used = $credentialName
      wmi_return_value = $result.ReturnValue
      process_id = $result.ProcessId
      service_state = $serviceState
      service_start_return_value = $serviceStartReturnValue
      service_change_return_value = $serviceChangeReturnValue
      service_query_error = $serviceQueryError
      message = $message
    }} | ConvertTo-Json -Compress
    """


def _read_json(output: bytes | str) -> object | None:
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else str(output)
    text = text.strip()
    if not text:
        return None
    text = "".join(" " if ord(char) < 32 else char for char in text)
    try:
        return json.loads(text)
    except json.JSONDecodeError as original_error:
        decoder = json.JSONDecoder()
        for index, char in enumerate(text):
            if char not in "[{":
                continue
            if index == 0:
                raise original_error
            try:
                value, _ = decoder.raw_decode(text[index:])
                return value
            except json.JSONDecodeError:
                continue
        raise original_error


def _clean_error(output: bytes | str) -> str:
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else str(output)
    text = text.strip()
    if not text:
        return "Request failed"
    text = re.sub(r"#< CLIXML.*", "", text, flags=re.DOTALL).strip() or text
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"_x000D__x000A_|&#xD;|&#xA;", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text or "Request failed"
