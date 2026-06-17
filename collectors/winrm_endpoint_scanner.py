from __future__ import annotations

import base64
import json
import platform
import re
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
                "host": self.config.host.strip(),
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
            raw_records = raw_records["records"]
        if isinstance(raw_records, dict):
            self.last_scan_diagnostics = {}
            raw_records = [raw_records]

        records = []
        for item in raw_records:
            path = item.get("path", "")
            extension = item.get("extension") or detect_extension(path)
            content = item.get("content", "")
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
                    "content": content,
                    "acl": {
                        "owner": item.get("owner", ""),
                        "principals": item.get("principals", []),
                        "permissions": item.get("permissions", []),
                    },
                    "scan_mode": item.get("scan_mode") or scan_mode_for_extension(extension),
                    "content_status": item.get("content_status")
                    or content_status_for_extension(extension, content, self.config.read_content),
                    "content_scannable": bool(item.get("content_scannable", extension in CONTENT_EXTENSIONS)),
                    "created_at": item.get("created_at", ""),
                    "modified_at": item.get("modified_at", ""),
                    "accessed_at": item.get("accessed_at", ""),
                    "attributes": item.get("attributes", ""),
                    "sha256": item.get("sha256", ""),
                    "file_hash": item.get("sha256", ""),
                }
            )
        return normalize_records(records)

    def _target_paths(self) -> list[str]:
        profile = self.config.target_username.strip()
        base = f"C:\\Users\\{profile}" if profile else "C:\\Users"
        paths = [item.strip() for item in self.config.paths if item.strip()]
        if not paths:
            paths = ["desktop", "documents", "downloads"]

        resolved: list[str] = []
        for item in paths:
            lowered = item.lower()
            if lowered == "all":
                resolved.append(base)
            elif lowered in {"c_drive", "system_drive"}:
                resolved.append("C:\\")
            elif lowered in {"all_fixed_drives", "fixed_drives", "all_drives"}:
                resolved.append("__DSPM_FIXED_DRIVES__")
            elif lowered in DEFAULT_PROFILE_FOLDERS:
                resolved.append(f"{base}\\{DEFAULT_PROFILE_FOLDERS[lowered]}")
            elif ":" in item or item.startswith("\\\\"):
                resolved.append(item)
            else:
                resolved.append(f"{base}\\{item}")
        return list(dict.fromkeys(resolved))

    def _run_ps(self, script: str):
        try:
            import winrm
        except ModuleNotFoundError as exc:
            raise RuntimeError("Missing dependency 'pywinrm'. Install requirements.txt before WinRM endpoint scans.") from exc

        endpoint = f"http{'s' if self.config.use_ssl else ''}://{self.config.host}:{self.config.port or (5986 if self.config.use_ssl else 5985)}/wsman"
        username = self.config.username.strip()
        if self.config.domain.strip() and "\\" not in username and "@" not in username:
            username = f"{self.config.domain.strip()}\\{username}"
        if not self.config.use_ssl and __import__("os").getenv("DSPM_REQUIRE_WINRM_SSL", "0") == "1":
            raise RuntimeError("WinRM over HTTP is disabled by configuration")
        session = winrm.Session(endpoint, auth=(username, self.config.password), transport="ntlm")
        return session.run_ps(script)

    def _run_ps_file(self, script: str):
        try:
            import winrm
        except ModuleNotFoundError as exc:
            raise RuntimeError("Missing dependency 'pywinrm'. Install requirements.txt before WinRM endpoint scans.") from exc

        endpoint = f"http{'s' if self.config.use_ssl else ''}://{self.config.host}:{self.config.port or (5986 if self.config.use_ssl else 5985)}/wsman"
        username = self.config.username.strip()
        if self.config.domain.strip() and "\\" not in username and "@" not in username:
            username = f"{self.config.domain.strip()}\\{username}"
        if not self.config.use_ssl and __import__("os").getenv("DSPM_REQUIRE_WINRM_SSL", "0") == "1":
            raise RuntimeError("WinRM over HTTP is disabled by configuration")
        session = winrm.Session(endpoint, auth=(username, self.config.password), transport="ntlm")

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
    $scanArchiveEntries = $false
    if ({inspect_archives_value} -and {extension_filter_value}) {{
      foreach ($allowedExtension in $allowedExtensions) {{
        if (-not ($archiveExtensions -contains $allowedExtension)) {{
          $scanArchiveEntries = $true
          break
        }}
      }}
    }}
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
      archive_errors = @()
      skipped_dirs = 0
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
      $hasActiveFilters = {extension_filter_value} -or {hidden_filter_value} -or {system_filter_value}
      if ($hasActiveFilters) {{
        $matchesExtension = {extension_filter_value} -and $extension -and $allowedSet.ContainsKey($extension.ToLowerInvariant())
        $matchesHidden = {hidden_filter_value} -and $isHidden
        $matchesSystem = {system_filter_value} -and $isSystem
        return ($matchesExtension -or $matchesHidden -or $matchesSystem)
      }}
      if ($isHidden -and -not {include_hidden_value}) {{ return $false }}
      if ($isSystem -and -not {include_system_value}) {{ return $false }}
      return $true
    }}

    function Test-DspmSkippedPath($path) {{
      $normalized = $path.ToLowerInvariant()
      if (-not $normalized.EndsWith([string][char]92)) {{ $normalized = $normalized + [string][char]92 }}
      $skipFragments = @(
        "\\.codex\\",
        "\\.git\\",
        "\\.vscode\\",
        "\\node_modules\\",
        "\\appdata\\local\\temp\\",
        "\\appdata\\local\\microsoft\\edge\\",
        "\\appdata\\local\\google\\chrome\\",
        "\\appdata\\local\\packages\\",
        "\\appdata\\roaming\\microsoft\\windows\\recent\\"
      )
      foreach ($fragment in $skipFragments) {{
        if ($normalized.Contains($fragment)) {{ return $true }}
      }}
      return $false
    }}

    function Resolve-DspmRoot($root) {{
      $roots = New-Object System.Collections.Generic.List[string]
      if ($root -match "^[A-Za-z]:$") {{
        $root = ([string]$root) + [string][char]92
      }}
      if ($root -eq "__DSPM_FIXED_DRIVES__") {{
        try {{
          $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
          foreach ($drive in $drives) {{
            if ($drive.DeviceID) {{
              $driveRoot = ([string]$drive.DeviceID) + [string][char]92
              if (Test-Path -LiteralPath $driveRoot) {{
                $roots.Add($driveRoot) | Out-Null
              }}
            }}
          }}
        }} catch {{
          Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | ForEach-Object {{
            $driveRoot = $_.Root
            if ($driveRoot -and (Test-Path -LiteralPath $driveRoot)) {{
              $roots.Add($driveRoot) | Out-Null
            }}
          }}
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
        $profileNameLower = $profileName.ToLowerInvariant()
        $candidates = Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue | Where-Object {{
          $name = $_.Name.ToLowerInvariant()
          $name -eq $profileNameLower -or
          $name.StartsWith("$profileNameLower.") -or
          $name.StartsWith("$profileNameLower_") -or
          $name.EndsWith(".$profileNameLower") -or
          $name -like "*$profileNameLower*"
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

    function Add-ZipEntries($archive, $archivePath, $isHidden, $isSystem, $depth) {{
      if ($depth -gt 2) {{ return }}
      foreach ($entry in $archive.Entries) {{
        if ([string]::IsNullOrWhiteSpace($entry.Name)) {{ continue }}
        $entryPath = "$archivePath::$($entry.FullName)"
        $entryExtension = Get-DspmExtensionFromName $entry.FullName
        Add-DspmExtensionStat $entryExtension
        $includeEntry = Test-DspmRecordIncluded $entryExtension $isHidden $isSystem
        if ($includeEntry) {{
          $diagnostics.archive_entries += 1
          $diagnostics.matched_files += 1
          $entryContent = ""
          if ({read_content_value}) {{
            $entryContent = Read-ZipEntryText $entry $entryExtension {int(max_read_bytes)}
          }}
          $records.Add([PSCustomObject]@{{
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
      $acl = if ({read_acl_value}) {{ Get-Acl -LiteralPath $file.FullName -ErrorAction SilentlyContinue }} else {{ $null }}
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
      $records.Add([PSCustomObject]@{{
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
        owner = if ($acl) {{ $acl.Owner }} else {{ "" }}
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
      $entries = @(Get-ChildItem -LiteralPath $current -Force -ErrorAction SilentlyContinue)
      foreach ($entry in $entries) {{
        if ($entry.PSIsContainer) {{
          $dirHidden = [bool]($entry.Attributes -band [IO.FileAttributes]::Hidden)
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
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        for index, char in enumerate(text):
            if char not in "[{":
                continue
            try:
                value, _ = decoder.raw_decode(text[index:])
                return value
            except json.JSONDecodeError:
                continue
        raise


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
