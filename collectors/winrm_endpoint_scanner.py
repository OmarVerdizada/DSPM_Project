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

from collectors.file_scanner import TEXT_EXTENSIONS, normalize_records


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
    script_path = Path(tempfile.gettempdir()) / f"{task_name}.ps1"
    script_path.write_text(_local_activation_script(False), encoding="utf-8")
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
    max_depth: int = 4
    read_content: bool = True
    max_read_bytes: int = 1024 * 256
    use_ssl: bool = False
    port: int | None = None


class WinRMEndpointScanner:
    def __init__(self, config: WinRMEndpointConfig):
        self.config = config

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
            return {"connected": False, "host": self.config.host, "message": str(exc)}

    def scan(self) -> list[dict]:
        target_paths = self._target_paths()
        ps_script = _scan_script(
            target_paths,
            max_depth=self.config.max_depth,
            read_content=self.config.read_content,
            max_read_bytes=self.config.max_read_bytes,
        )
        result = self._run_ps(ps_script)
        if result.status_code != 0:
            raise ConnectionError(_clean_error(result.std_err) or f"WinRM scan failed on {self.config.host}")

        raw_records = _read_json(result.std_out)
        if raw_records is None:
            return []
        if isinstance(raw_records, dict) and isinstance(raw_records.get("records"), list):
            raw_records = raw_records["records"]
        if isinstance(raw_records, dict):
            raw_records = [raw_records]

        records = []
        for item in raw_records:
            path = item.get("path", "")
            extension = PureWindowsPath(path).suffix.lower()
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
                    "content": item.get("content", ""),
                    "acl": {
                        "owner": item.get("owner", ""),
                        "principals": item.get("principals", []),
                        "permissions": item.get("permissions", []),
                    },
                    "created_at": item.get("created_at", ""),
                    "modified_at": item.get("modified_at", ""),
                    "accessed_at": item.get("accessed_at", ""),
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
        session = winrm.Session(endpoint, auth=(username, self.config.password), transport="ntlm")
        return session.run_ps(script)


def _scan_script(paths: list[str], max_depth: int, read_content: bool, max_read_bytes: int) -> str:
    encoded_paths = base64.b64encode(json.dumps(paths).encode("utf-8")).decode("ascii")
    read_content_value = "$true" if read_content else "$false"
    text_extensions = ",".join(f'"{item}"' for item in sorted(TEXT_EXTENSIONS))
    return f"""
    $ErrorActionPreference = "SilentlyContinue"
    $pathsJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{encoded_paths}"))
    $targetPaths = ConvertFrom-Json $pathsJson
    $textExtensions = @({text_extensions})
    $records = New-Object System.Collections.Generic.List[object]

    function Get-RelativeDepth($root, $path) {{
      $relative = $path.Substring([Math]::Min($root.Length, $path.Length)).Trim("\\")
      if ([string]::IsNullOrWhiteSpace($relative)) {{ return 0 }}
      return ($relative -split "\\\\").Count
    }}

    foreach ($root in $targetPaths) {{
      if (-not (Test-Path -LiteralPath $root)) {{ continue }}
      Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {{
        if ((Get-RelativeDepth $root $_.FullName) -gt {int(max_depth)}) {{ return }}
        $acl = Get-Acl -LiteralPath $_.FullName -ErrorAction SilentlyContinue
        $content = ""
        if ({read_content_value} -and ($textExtensions -contains $_.Extension.ToLowerInvariant())) {{
          try {{
            $stream = [System.IO.File]::Open($_.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {{
              $buffer = New-Object byte[] {int(max_read_bytes)}
              $read = $stream.Read($buffer, 0, $buffer.Length)
              $content = [Text.Encoding]::UTF8.GetString($buffer, 0, $read)
            }} finally {{
              $stream.Close()
            }}
          }} catch {{
            $content = ""
          }}
        }}
        $records.Add([PSCustomObject]@{{
          path = $_.FullName
          name = $_.Name
          size = $_.Length
          extension = $_.Extension.ToLowerInvariant()
          is_hidden = [bool]($_.Attributes -band [IO.FileAttributes]::Hidden)
          created_at = $_.CreationTimeUtc.ToString("o")
          modified_at = $_.LastWriteTimeUtc.ToString("o")
          accessed_at = $_.LastAccessTimeUtc.ToString("o")
          owner = if ($acl) {{ $acl.Owner }} else {{ "" }}
          principals = if ($acl) {{ @($acl.Access | ForEach-Object {{ $_.IdentityReference.Value }}) }} else {{ @() }}
          permissions = if ($acl) {{ @($acl.Access | ForEach-Object {{ $_.FileSystemRights.ToString() }}) }} else {{ @() }}
          content = $content
        }}) | Out-Null
      }}
    }}
    [PSCustomObject]@{{
      records = @($records.ToArray())
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
