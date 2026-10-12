from __future__ import annotations

import base64
import binascii
import functools
import gzip
import io
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from uuid import uuid4

from collectors.acl_powershell import ACL_FIELDS_PS, acl_from_fields, acl_read_stats
from collectors.binary_extractor import BINARY_TEXT_EXTENSIONS
from collectors.net_guard import resolve_and_pin
from discovery.parallelism import host_admission_budget, resolve_parallelism
from collectors import content_policy
from collectors.scan_scope import NOT_ENTERED_DEPTH, NOT_ENTERED_SYSTEM, ScopeTally
from collectors.file_scanner import (
    CONTENT_EXTENSIONS,
    DEFAULT_TEXT_SCAN_MAX_BYTES,
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
WINRM_GZIP_RESPONSE_PREFIX = b"DSPM-GZIP-BASE64-V1:"
DEFAULT_WINRM_RESPONSE_MAX_BYTES = 512 * 1024 * 1024
# One stdin slice must stay well inside the target's WS-Man MaxEnvelopeSize
# (default ~150 KB on older hosts) once SOAP/base64 framing is added.
_WINRM_STDIN_CHUNK_BYTES = 48 * 1024
# Primary delivery is one command. Keep a little protocol headroom while making
# the former 31-command upload fail a regression test immediately.
WINRM_FAST_DELIVERY_COMMAND_BUDGET = 3


def _is_stdin_capability_error(exc: BaseException) -> bool:
    """True when a stdin-delivery failure might be fixed by the legacy path.

    The legacy path re-dials the SAME session, so a dead socket, an expired
    timeout, or rejected credentials will fail there identically - retrying only
    doubles the time an unreachable endpoint takes to report failure. Only
    WS-Man/protocol-level refusals (a target that will not accept command input)
    are worth a second attempt; an unrecognised error is treated as capability
    related so genuinely odd targets keep the compatible path.
    """
    try:
        import requests.exceptions as request_errors

        if isinstance(
            exc,
            (
                request_errors.ConnectionError,
                request_errors.ConnectTimeout,
                request_errors.ReadTimeout,
                request_errors.Timeout,
                request_errors.SSLError,
                request_errors.ProxyError,
            ),
        ):
            return False
    except Exception:  # pragma: no cover - requests is a hard dependency
        pass
    try:
        from winrm import exceptions as winrm_errors

        if isinstance(
            exc,
            (
                winrm_errors.AuthenticationError,
                winrm_errors.BasicAuthDisabledError,
                winrm_errors.InvalidCredentialsError,
            ),
        ):
            return False
        if isinstance(exc, winrm_errors.WinRMTransportError):
            # 401/403 are credential/authorisation problems; other HTTP codes can
            # be a WS-Man configuration refusal that the legacy path survives.
            return int(getattr(exc, "code", 0) or 0) not in {401, 403}
    except Exception:  # pragma: no cover - pywinrm is a hard dependency
        pass
    if isinstance(exc, (OSError, TimeoutError)):
        return False
    return True


def _listed(value) -> list:
    # ConvertTo-Json sends a one-element list as the element itself, and none as null.
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _endpoint_identity(item: dict) -> str:
    """The endpoint file's identity: the SHA-256 the endpoint took, or - for a file the
    policy did not read whole (W2.2) - a meta identity of its size and modified time."""
    digest = str(item.get("sha256") or "")
    if digest or not item.get("hash_skipped"):
        return digest
    return content_policy.meta_identity(int(item.get("size") or 0), str(item.get("modified_at") or ""))


def _endpoint_skip_reason(item: dict) -> str:
    if str(item.get("content_status") or "") != "over_size_cap":
        return ""
    cap = content_policy.document_cap_bytes()
    return f"Larger than DSPM_DOCUMENT_SCAN_MAX_BYTES ({cap // (1024 * 1024)} MiB); its content was not read"


def _endpoint_acl(item: dict) -> dict:
    """A file's ACL as the endpoint sent it, in the shape the D7 analysis reads: the owner,
    the parallel principal/rights lists reports carry and - when the endpoint sent them -
    an entry per ACE with its SID, allow or deny, and whether it was inherited. Names and
    rights alone read every entry as an explicit Allow: "Everyone: Deny Read" was broad
    read access, and a broad group was recognised only by its English name."""
    fields = item.get("acl_fields")
    if isinstance(fields, dict):
        # The script's ConvertTo-DspmAclFields (collectors.acl_powershell): owner SID, masks,
        # inheritance flags, the DACL's protection and whether the read worked.
        return acl_from_fields(fields, with_access="sids" in fields or "principals" in fields)
    if "acl_fields" in item:
        return {"owner": "", "principals": [], "permissions": [], "state": "not_collected"}
    principals, permissions = _listed(item.get("principals")), _listed(item.get("permissions"))
    types, sids, inherited = _listed(item.get("types")), _listed(item.get("sids")), _listed(item.get("inherited"))
    acl: dict = {"owner": str(item.get("owner") or ""), "principals": [str(name) for name in principals],
                 "permissions": [str(rights) for rights in permissions]}
    if not types:
        return acl  # an older script's answer: names and rights only
    acl["types"] = [str(kind).lower() for kind in types]
    acl["entries"] = [
        {"principal": str(principal or ""),
         "sid": str(sids[index] or "") if index < len(sids) else "",
         "rights": str(permissions[index]) if index < len(permissions) else "",
         "type": str(types[index]).lower() if index < len(types) else "allow",
         "inherited": bool(inherited[index]) if index < len(inherited) else False}
        for index, principal in enumerate(principals)
    ]
    return acl


def _winrm_response_max_bytes() -> int:
    raw = os.getenv("DSPM_WINRM_RESPONSE_MAX_BYTES", "").strip()
    try:
        configured = int(raw) if raw else DEFAULT_WINRM_RESPONSE_MAX_BYTES
    except ValueError:
        configured = DEFAULT_WINRM_RESPONSE_MAX_BYTES
    return max(1024, min(configured, 2 * 1024 * 1024 * 1024))


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


def _in_production() -> bool:
    return os.getenv("DSPM_ENV", "local").strip().lower() in {"prod", "production"}


def _winrm_ssl_required() -> bool:
    """SC-7: refuse cleartext WinRM by default in production.

    Explicit DSPM_REQUIRE_WINRM_SSL wins ("1" always require, "0" always allow
    HTTP). When unset, SSL is required in production and HTTP is tolerated only
    in local/dev.
    """
    override = os.getenv("DSPM_REQUIRE_WINRM_SSL")
    if override is not None and override.strip() != "":
        return override.strip() == "1"
    return _in_production()


def _winrm_activation_allowed() -> bool:
    """SC-7: WinRM activation mutates the target (opens an HTTP listener and
    firewall, enables DCOM/WMI, runs ExecutionPolicy Bypass). Disabled in
    production unless an operator explicitly opts in, so a normal deployment
    never reconfigures scanned endpoints."""
    if _in_production():
        return os.getenv("DSPM_ALLOW_WINRM_ACTIVATION", "0").strip() == "1"
    return True


def _activation_disabled_result() -> dict:
    return {
        "activated": False,
        "requires_admin": False,
        "message": (
            "WinRM activation is disabled in production. Set "
            "DSPM_ALLOW_WINRM_ACTIVATION=1 to allow it through an explicit, "
            "audited admin workflow."
        ),
    }


def activate_local_winrm(username: str = "", password: str = "", domain: str = "WORKGROUP") -> dict:
    if platform.system().lower() != "windows":
        raise RuntimeError("Local WinRM activation requires the DSPM backend to run on Windows.")
    if not _winrm_activation_allowed():
        return _activation_disabled_result()

    activation = _run_local_activation_script(require_current_admin=True)
    if activation.get("activated") or not activation.get("requires_admin") or not username.strip() or not password:
        return activation

    scheduled = _activate_local_winrm_with_task(username.strip(), password, domain.strip() or "WORKGROUP")
    if scheduled.get("activated"):
        return scheduled
    scheduled["initial_message"] = activation.get("message", "")
    return scheduled


def deactivate_local_winrm() -> dict:
    """Revert the local WinRM changes activation made (roadmap 0.3): remove the
    DSPM firewall rule and HTTP listener and reset the WinRM service source
    filter. Idempotent. A remote target is reverted by running the same
    deactivation body on it (see the 0.3 runbook); that path is not wired here
    because the remote WMI mechanism cannot be validated without a live target."""
    if platform.system().lower() != "windows":
        raise RuntimeError("WinRM deactivation requires the DSPM backend to run on Windows.")
    result = _run_encoded_powershell(_deactivation_script())
    parsed = _read_json(result.stdout)
    if isinstance(parsed, dict):
        return parsed
    return {
        "deactivated": result.returncode == 0,
        "message": _clean_error(result.stdout or result.stderr) or "Deactivation command ran.",
    }


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
    __WINRM_CONFIG__
    $service = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    $portOpen = $false
    try {
      $client = New-Object Net.Sockets.TcpClient
      $async = $client.BeginConnect("127.0.0.1", __WINRM_PORT__, $null, $null)
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
      message = if ($service -and $service.Status -eq "Running" -and $portOpen) { "Local WinRM is running and port __WINRM_PORT__ is reachable." } else { "Local activation command ran, but WinRM is not fully reachable. Run the backend as Administrator and check local firewall policy." }
    } | ConvertTo-Json -Compress
    """.replace("__ADMIN_GUARD__", admin_guard).replace("__WINRM_CONFIG__", _winrm_hardening_config_ps("")).replace("__WINRM_PORT__", str(_winrm_active_port()))


def _activate_local_winrm_with_task(username: str, password: str, domain: str) -> dict:
    task_name = f"DSPM_Activate_WinRM_{uuid4().hex}"
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
    task_command = f'-NoProfile -ExecutionPolicy Bypass -File "{script_path}"'
    run_as = _format_windows_username(username, domain)

    try:
        create = _create_activation_task(task_name, run_as, password, task_command)
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


# FINDING 5: never place the admin password on a process command line. The old
# `schtasks /Create ... /RP <password>` exposed it to command-line auditing
# (Sysmon EventID 1, Security 4688 with cmdline capture) and to any
# Win32_Process/CommandLine reader for the life of the schtasks.exe process.
# Register-ScheduledTask receives the password - and every other dynamic value,
# so a crafted username/domain cannot inject PowerShell - through the child's
# *environment block* instead, which command-line auditing does not capture. The
# later /Run and /Delete carry no secret and stay on schtasks.exe.
_REGISTER_TASK_PS = (
    "$ErrorActionPreference='Stop';"
    "$pw=$env:DSPM_TASK_PW;$tn=$env:DSPM_TASK_TN;$ru=$env:DSPM_TASK_RU;$arg=$env:DSPM_TASK_ARG;"
    "if([string]::IsNullOrEmpty($pw)){throw 'missing credential'};"
    "$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg;"
    "$trigger=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1));"
    "$settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;"
    "Register-ScheduledTask -TaskName $tn -Action $action -Trigger $trigger "
    "-Settings $settings -User $ru -Password $pw -RunLevel Highest -Force | Out-Null"
)


def _create_activation_task(task_name: str, run_as: str, password: str, task_arg: str) -> subprocess.CompletedProcess:
    """Register the elevated activation task without the password ever touching a
    command line (see FINDING 5 note above). Secrets and injectable values are
    handed to the child powershell.exe via its environment block, not argv."""
    encoded = base64.b64encode(_REGISTER_TASK_PS.encode("utf-16le")).decode("ascii")
    child_env = {
        **os.environ,
        "DSPM_TASK_PW": password,
        "DSPM_TASK_TN": task_name,
        "DSPM_TASK_RU": run_as,
        "DSPM_TASK_ARG": task_arg,
    }
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        env=child_env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _run_encoded_powershell(script: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    # H1 / completes FINDING 5: `env` carries any secret (e.g. the activation
    # admin password) to the child through its environment block instead of the
    # command line. The script text is base64'd onto -EncodedCommand and IS
    # visible on the process command line (4688/Sysmon), so nothing sensitive
    # may be interpolated into it - callers pass secrets via `env` and read
    # them as $env:NAME in the script.
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    child_env = {**os.environ, **env} if env else None
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
        env=child_env,
    )


def _collector_source_ip(target_host: str) -> str:
    """Best-effort: the DSPM host's source IP toward ``target_host`` - the address
    the target sees the collector connect from. Used to scope the target's WinRM
    firewall rule and IPv4 source filter to the collector only. Returns "" if it
    cannot be determined (the caller then keeps the filter broad, but the firewall
    is still Domain/Private-scoped). Reliable on a flat on-prem LAN; if the
    collector is NAT'd relative to the target the operator must scope manually."""
    host = (target_host or "").strip()
    if not host:
        return ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(2.0)
            probe.connect((host, 135))  # UDP connect sends nothing; just resolves the source IP/route
            ip = str(probe.getsockname()[0] or "")
        return ip if ip and not ip.startswith("0.") else ""
    except OSError:
        return ""


def _winrm_activation_https() -> bool:
    """Whether activation provisions an HTTPS(5986) listener instead of HTTP 5985.
    Default OFF: the HTTPS switch requires a trusted cert + matching client cert
    handling and must be validated on a live target (0.3 runbook) before it
    replaces the working, already-hardened HTTP path."""
    return os.getenv("DSPM_WINRM_ACTIVATION_HTTPS", "0") == "1"


def _winrm_active_port() -> int:
    return 5986 if _winrm_activation_https() else 5985


def _winrm_listener_ps(use_https: bool) -> str:
    if use_https:
        # Provision an HTTPS(5986) listener and remove the HTTP one so the endpoint
        # is HTTPS-only. Reuses a matching machine cert if present, else creates a
        # self-signed one (a lab default - production should provision a CA-issued
        # cert and have the client trust it; see the 0.3 runbook).
        return (
            '\n    $dnsName = $env:COMPUTERNAME'
            '\n    $cert = Get-ChildItem Cert:\\LocalMachine\\My -ErrorAction SilentlyContinue | Where-Object { $_.Subject -eq "CN=$dnsName" -and $_.NotAfter -gt (Get-Date) } | Select-Object -First 1'
            '\n    if (-not $cert) { $cert = New-SelfSignedCertificate -DnsName $dnsName -CertStoreLocation Cert:\\LocalMachine\\My -NotAfter (Get-Date).AddYears(2) -ErrorAction SilentlyContinue }'
            '\n    Get-ChildItem WSMan:\\localhost\\Listener -ErrorAction SilentlyContinue | Where-Object { $_.Keys -contains "Transport=HTTPS" } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue'
            '\n    if ($cert) { New-Item -Path WSMan:\\localhost\\Listener -Address * -Transport HTTPS -CertificateThumbPrint $cert.Thumbprint -Force -ErrorAction SilentlyContinue | Out-Null }'
            '\n    winrm delete "winrm/config/Listener?Address=*+Transport=HTTP" 2>$null'
        )
    return '\n    winrm create "winrm/config/Listener?Address=*+Transport=HTTP" \'@{Port="5985"}\' 2>$null'


def _winrm_hardening_config_ps(collector_ip: str = "", use_https: bool | None = None) -> str:
    """Shared WinRM enable + harden PowerShell (M10/M11, roadmap 0.3).

    Security posture, deliberately different from the pre-0.3 script:
      * Does NOT set LocalAccountTokenFilterPolicy=1 - that registry value enables
        local-admin Pass-the-Hash remote elevation and must not be turned on.
      * Firewall rule is scoped to the Domain/Private profiles only (never Public
        / ``profile=any``) and, when the collector IP is known, to that source
        address; prior broad ``DSPM WinRM*`` rules are removed first.
      * WinRM service IPv4 source filter is pinned to the collector when known.
      * Listener is HTTP 5985 by default; HTTPS(5986) with a cert when use_https
        (DSPM_WINRM_ACTIVATION_HTTPS=1) - the live-validation-gated transport."""
    if use_https is None:
        use_https = _winrm_activation_https()
    ipv4_filter = collector_ip if collector_ip else "*"
    remote_addr = f" -RemoteAddress {collector_ip}" if collector_ip else ""
    port = 5986 if use_https else 5985
    rule_name = "DSPM WinRM HTTPS" if use_https else "DSPM WinRM HTTP"
    return (
        '\n    Set-Service -Name WinRM -StartupType Automatic'
        '\n    Start-Service -Name WinRM'
        '\n    Enable-PSRemoting -Force -SkipNetworkProfileCheck'
        '\n    winrm quickconfig -quiet'
        '\n    Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Ole" -Name EnableDCOM -Type String -Value "Y" -ErrorAction SilentlyContinue'
        + _winrm_listener_ps(use_https)
        + f'\n    winrm set "winrm/config/service" \'@{{IPv4Filter="{ipv4_filter}"}}\''
        + '\n    Remove-NetFirewallRule -DisplayName "DSPM WinRM*" -ErrorAction SilentlyContinue'
        + f'\n    New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound -Protocol TCP -LocalPort {port} -Action Allow -Profile Domain,Private{remote_addr} -ErrorAction SilentlyContinue | Out-Null'
    )


def _deactivation_script() -> str:
    """Revert what activation added (roadmap 0.3): remove the DSPM firewall rule
    and the HTTP listener, and reset the WinRM service source filter. Does NOT
    touch LocalAccountTokenFilterPolicy - 0.3 activation no longer sets it, so
    there is nothing to revert (and blindly clearing a policy we did not set could
    break an unrelated configuration)."""
    return (
        '\n    $ProgressPreference = "SilentlyContinue"'
        '\n    $ErrorActionPreference = "SilentlyContinue"'
        '\n    Remove-NetFirewallRule -DisplayName "DSPM WinRM*" -ErrorAction SilentlyContinue'
        '\n    winrm delete "winrm/config/Listener?Address=*+Transport=HTTP" 2>$null'
        '\n    winrm set "winrm/config/service" \'@{IPv4Filter=""}\''
        '\n    [PSCustomObject]@{ deactivated = $true; host = $env:COMPUTERNAME; message = "DSPM WinRM firewall rule and HTTP listener removed; WinRM service source filter reset." } | ConvertTo-Json -Compress'
    )


def _remote_deactivation_script(payload: dict) -> str:
    """Run the deactivation body on a remote target via WMI, mirroring activation
    (roadmap 0.3, Part C). The admin password is passed via the child env block
    (H1) - never in the payload or on a command line. Not live-validated here."""
    payload = {key: value for key, value in payload.items() if key != "password"}
    encoded_payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    encoded_inner = base64.b64encode(_deactivation_script().encode("utf-16le")).decode("ascii")
    remote_command = f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded_inner}"
    return f"""
    $ProgressPreference = "SilentlyContinue"
    $ErrorActionPreference = "Stop"
    $payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{encoded_payload}"))
    $payload = ConvertFrom-Json $payloadJson
    $securePassword = ConvertTo-SecureString ([string]$env:DSPM_ACTIVATION_PW) -AsPlainText -Force
    $rawUsername = ([string]$payload.username).Trim()
    $domain = ([string]$payload.domain).Trim()
    $credentialNames = New-Object System.Collections.Generic.List[string]
    if ($rawUsername -match "\\\\" -or $rawUsername -match "@") {{ $credentialNames.Add($rawUsername) }}
    elseif ($domain -and $domain -ne "WORKGROUP") {{ $credentialNames.Add("$domain\\$rawUsername"); $credentialNames.Add($rawUsername); $credentialNames.Add(".\\$rawUsername") }}
    else {{ $credentialNames.Add($rawUsername); $credentialNames.Add(".\\$rawUsername") }}
    $done = $false
    $errors = New-Object System.Collections.Generic.List[string]
    foreach ($candidateName in @($credentialNames | Select-Object -Unique)) {{
      try {{
        $cred = New-Object System.Management.Automation.PSCredential($candidateName, $securePassword)
        Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName ([string]$payload.host) -Credential $cred -ArgumentList @("{remote_command}") -ErrorAction Stop | Out-Null
        $done = $true; break
      }} catch {{ $errors.Add("${{candidateName}}: $($_.Exception.Message)") | Out-Null }}
    }}
    [PSCustomObject]@{{ deactivated = $done; host = [string]$payload.host; message = if ($done) {{ "Deactivation command sent to target." }} else {{ "Target rejected the admin credential for deactivation: $($errors -join ' | ')" }} }} | ConvertTo-Json -Compress
    """


def _delete_task(task_name: str) -> None:
    subprocess.run(["schtasks.exe", "/Delete", "/TN", task_name, "/F"], capture_output=True, text=True, timeout=30, check=False)


def _format_windows_username(username: str, domain: str) -> str:
    if "\\" in username or "@" in username:
        return username
    if domain and domain.upper() != "WORKGROUP":
        return f"{domain}\\{username}"
    return username


class EmptyCollectorOutput(RuntimeError):
    """The collector script answered with nothing at all (W3.2, roadmap N13).

    The script always prints its records and diagnostics, even for a folder with no files,
    so silence means it never ran to the end. Taken as an empty page it called itself
    complete, handed on none of its subfolders, and the scan pruned everything under them.
    It is the page's failure: tried again, and if it keeps happening the page is
    quarantined and the scan finishes incomplete."""


class WinRMCommandTimedOut(RuntimeError):
    """A remote command ran past its wall clock; its shell was closed, which stops it (W1.3)."""


def winrm_command_timeout_seconds() -> int:
    """How long one WinRM command may run (``DSPM_WINRM_COMMAND_TIMEOUT_SECONDS``; 0 = no limit).

    The output loop retried the WS-Man operation timeout for ever, so a remote command
    that hung held its scan for ever too. Past this the command is abandoned and its shell
    closed, which ends the process on the endpoint. Fifteen minutes by default: a page or
    a content batch takes seconds.
    """
    try:
        return max(0, min(int(os.getenv("DSPM_WINRM_COMMAND_TIMEOUT_SECONDS") or "900"), 86_400))
    except ValueError:
        return 900


class WinRMKerberosUnavailable(RuntimeError):
    """Kerberos was required and this install cannot provide it."""


class WinRMTransportRefused(RuntimeError):
    """The transport this scan asked for is one this install does not permit.

    Separate from a connection failure on purpose: nothing was attempted, and the
    message says which choice to change (C0.1).
    """


@functools.lru_cache(maxsize=1)
def _kerberos_transport_available() -> bool:
    """Whether pywinrm can actually negotiate Kerberos here.

    pywinrm imports requests_kerberos lazily inside build_session, so an absent
    dependency surfaces as a failed connection attempt rather than as anything
    that names the cause.
    """

    try:
        import requests_kerberos  # noqa: F401
    except Exception:
        return False
    return True


def normalize_certificate_thumbprint(value: str) -> str:
    """A certificate thumbprint as the operator will paste it, in one shape.

    Windows shows a thumbprint spaced (`certutil`), coloured (`Get-ChildItem
    Cert:\\`) or run together, and an operator will paste any of them. SHA-1 (40
    hex) is what the Windows certificate tools print; SHA-256 (64 hex) is what a
    modern tool prints. Anything else is rejected here rather than becoming a pin
    that silently never matches.
    """

    cleaned = re.sub(r"[\s:]+", "", str(value or "")).upper()
    if not cleaned:
        return ""
    if not re.fullmatch(r"[0-9A-F]{40}|[0-9A-F]{64}", cleaned):
        raise ValueError(
            "A certificate thumbprint must be 40 hex characters (SHA-1) or 64 (SHA-256); "
            "spaces and colons are ignored."
        )
    return cleaned


def _fingerprint_for_urllib3(thumbprint: str) -> str:
    """urllib3 takes the fingerprint as hex, and sizes the algorithm from its length."""
    return thumbprint.lower()


def _pinned_adapter(thumbprint: str):
    """A requests adapter that trusts exactly one certificate.

    The certificate an HTTPS activation creates is self-signed, so there is no CA
    to trust and `validate` can only fail. The choices are to stop checking
    (DSPM_WINRM_SSL_SKIP_CA_CHECK, which drops MITM protection entirely) or to pin
    the one certificate the operator has seen on the endpoint - which is what this
    does. urllib3 checks the fingerprint of the presented certificate and refuses
    the connection when it differs, so a swapped certificate fails closed.
    """

    from requests.adapters import HTTPAdapter

    fingerprint = _fingerprint_for_urllib3(thumbprint)

    class _PinnedCertificateAdapter(HTTPAdapter):
        def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
            pool_kwargs["assert_fingerprint"] = fingerprint
            # The pin replaces chain and hostname validation; urllib3 refuses to do
            # both, and a self-signed certificate has no chain to validate anyway.
            pool_kwargs["cert_reqs"] = "CERT_NONE"
            return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    return _PinnedCertificateAdapter()


@dataclass(slots=True)
class WinRMEndpointConfig:
    host: str
    username: str
    password: str
    # C5: the workspace whose scan targets decide whether `host` may be connected to.
    tenant_id: str = ""
    domain: str = "WORKGROUP"
    target_username: str = ""
    paths: list[str] = field(default_factory=lambda: ["desktop", "documents", "downloads"])
    # W3.6 (decision D4): no default limit - every folder under the paths is entered.
    max_depth: int | None = None
    read_content: bool = True
    max_read_bytes: int = DEFAULT_TEXT_SCAN_MAX_BYTES
    use_ssl: bool = False
    port: int | None = None
    allowed_extensions: list[str] | None = None
    extension_filter_enabled: bool = False
    include_hidden: bool = True
    include_system: bool = False
    hidden_filter_enabled: bool = False
    system_filter_enabled: bool = False
    read_acl: bool = True
    inspect_archives: bool = False
    hash_files: bool = True
    read_owner: bool = True
    # C0.1 - how this scan trusts the endpoint's certificate, per scan rather than
    # per install. Empty means the install default (the system trust store, or the
    # DSPM_WINRM_* environment settings). See _winrm_cert_validation.
    ca_bundle: str = ""
    cert_thumbprint: str = ""
    kerberos_mode: str = ""
    insecure_tls: bool = False
    # Advanced scan scope (collectors.scan_scope), canonical, absolute paths: applied on
    # the endpoint by the collector script, before a file's work is queued.
    scope: dict | None = None


@dataclass(slots=True)
class _WinRMSessionBinding:
    identity: tuple[object, ...]
    connection_host: str
    transport: str
    session: object


class WinRMEndpointScanner:
    def __init__(self, config: WinRMEndpointConfig):
        self.config = config
        self.last_scan_diagnostics: dict = {}
        self.last_connection_host = ""
        self.last_connection_transport = ""
        # How the last script reached the endpoint. Without this a silent demotion
        # to the legacy path - the exact regression this work removes - is
        # invisible in a saved report.
        self.last_delivery_diagnostics: dict = {}
        self._delivery_remote_commands_current = 0
        self._response_envelopes_current = 0
        self._delivery_total_ms = 0.0
        self._remote_commands_total = 0
        self._response_envelopes_total = 0
        self._delivery_invocations = 0
        # P4: a scanner is scoped to one API scan job. Keep the successfully
        # negotiated pywinrm Session on that job-local object so a metadata pass
        # and its content batches reuse the HTTP/authentication state. This is
        # deliberately not process-global: credentials and sessions do not
        # outlive the operation that supplied them.
        self._session_binding: _WinRMSessionBinding | None = None
        # W1.3: one WinRS shell for a block of commands (reusing_shell), and what a page left.
        self._shell_reuse = False
        self._reused_shell: tuple | None = None
        self._shells_opened = 0
        self._shells_reused = 0
        self.last_page: dict = {"folders": [], "continuation": []}
        self._session_creations = 0
        self._session_negotiations = 0
        self._session_reuse_count = 0
        self._session_failovers = 0
        self._last_session_reused = False
        self._connection_candidates_target = ""
        self._connection_candidates_cache: list[str] = []

    def activate_winrm(self) -> dict:
        if platform.system().lower() != "windows":
            raise RuntimeError("WinRM activation requires the DSPM backend to run on Windows with WMI tools available.")
        if not _winrm_activation_allowed():
            return _activation_disabled_result()
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

        # H1: build the script WITHOUT the password (host/username/domain only),
        # and hand the credential to the local powershell.exe via its environment
        # block - never on the command line. Mirrors _create_activation_task.
        # M10/M11 (0.3): scope the target's firewall/source-filter to the collector.
        connection_host = self._connection_host()
        script = _activation_script(
            {
                "host": connection_host,
                "username": self.config.username.strip(),
                "domain": self.config.domain.strip() or "WORKGROUP",
            },
            _collector_source_ip(connection_host),
        )
        result = _run_encoded_powershell(script, env={"DSPM_ACTIVATION_PW": self.config.password})
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

    def deactivate_winrm(self) -> dict:
        """Revert a remote target's WinRM changes activation made (roadmap 0.3,
        Part C): remove the DSPM firewall rule and HTTP listener and reset the
        service source filter, run on the target via the same WMI mechanism as
        activation. The admin password travels via the child env block (H1).
        NOT live-validated in this environment - see the 0.3 runbook."""
        if platform.system().lower() != "windows":
            raise RuntimeError("WinRM deactivation requires the DSPM backend to run on Windows with WMI tools available.")
        if not self.config.host.strip():
            raise ValueError("Endpoint host is required.")
        if not self.config.username.strip() or not self.config.password:
            raise ValueError("Admin username and password are required to deactivate WinRM.")
        script = _remote_deactivation_script(
            {
                "host": self._connection_host(),
                "username": self.config.username.strip(),
                "domain": self.config.domain.strip() or "WORKGROUP",
            }
        )
        result = _run_encoded_powershell(script, env={"DSPM_ACTIVATION_PW": self.config.password})
        parsed = _read_json(result.stdout)
        if isinstance(parsed, dict):
            return parsed
        return {
            "deactivated": result.returncode == 0,
            "host": self.config.host,
            "message": _clean_error(result.stdout or result.stderr) or "Deactivation command ran.",
        }

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
                **self._session_diagnostics(),
            }
        except Exception as exc:
            return {"connected": False, "host": self.config.host, "message": "WinRM connection test failed"}

    def check_access(self) -> dict:
        """What this credential can actually reach on this target.

        Scanning an endpoint does NOT require administrator: nothing in the scan
        path tests for it, the scripts only read, and the one thing they write
        is a base64 staging file under the connecting user's own $env:TEMP. Two
        Windows defaults are what make a domain admin the path of least
        resistance, and both are grantable without one:

          * only local Administrators may open a WinRM session, until the
            account is put in Remote Management Users. That group - not a
            PowerShell session configuration - is the grant that matters here,
            because pywinrm opens the WinRS `cmd` shell resource rather than
            Microsoft.PowerShell, so the WinRM service RootSDDL governs and
            Set-PSSessionConfiguration would not help;
          * another account's folder under the Users directory denies everyone
            but that account, SYSTEM and Administrators, so a non-admin reads
            its OWN profile and no more.

        Which means the answer to "will a low-privilege account do?" depends
        entirely on the scope, and an operator cannot see that until a scan has
        already half-failed. This asks the target instead, before anything is
        committed: who am I, am I an admin, which profiles can I list, and can I
        stage a file. It reads nothing but directory entries.
        """

        try:
            result = self._run_ps(
                r"""
                $ErrorActionPreference = "Stop"
                $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
                $isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
                  [Security.Principal.WindowsBuiltInRole]::Administrator)

                $temp = $env:TEMP
                $tempWritable = $false
                try {
                  $probe = Join-Path $temp ("dspm-preflight-" + [guid]::NewGuid().ToString("N") + ".tmp")
                  [IO.File]::WriteAllBytes($probe, [byte[]]@())
                  Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
                  $tempWritable = $true
                } catch { $tempWritable = $false }

                $profiles = @()
                try {
                  foreach ($dir in (Get-ChildItem -LiteralPath "C:\Users" -Directory -Force -ErrorAction SilentlyContinue)) {
                    $readable = $false
                    $denied = ""
                    try {
                      Get-ChildItem -LiteralPath $dir.FullName -Force -ErrorAction Stop | Out-Null
                      $readable = $true
                    } catch { $denied = $_.Exception.GetType().Name }
                    $profiles += [PSCustomObject]@{
                      name = $dir.Name
                      path = $dir.FullName
                      readable = $readable
                      denied = $denied
                    }
                  }
                } catch { }

                [PSCustomObject]@{
                  computer = $env:COMPUTERNAME
                  user = $identity.Name
                  isAdmin = $isAdmin
                  tempWritable = $tempWritable
                  temp = $temp
                  profiles = $profiles
                } | ConvertTo-Json -Compress -Depth 4
                """
            )
        except WinRMKerberosUnavailable:
            # Not a target problem and not something a retry fixes: the install
            # was told to require Kerberos and cannot. Reporting that as a
            # generic access failure is the exact silence this preflight exists
            # to remove, so it travels up to the API and gets its own hint.
            raise
        except Exception as exc:
            return {
                "ok": False,
                "host": self.config.host,
                "message": _clean_error(str(exc)) or "WinRM access check failed",
            }

        if result.status_code != 0:
            return {
                "ok": False,
                "host": self.config.host,
                "message": _clean_error(result.std_err) or "WinRM access check failed",
            }

        info = _read_json(result.std_out) or {}
        raw_profiles = info.get("profiles") or []
        if isinstance(raw_profiles, dict):
            raw_profiles = [raw_profiles]
        profiles = [
            {
                "name": str(item.get("name", "")),
                "path": str(item.get("path", "")),
                "readable": bool(item.get("readable")),
            }
            for item in raw_profiles
        ]
        readable = [item for item in profiles if item["readable"]]
        is_admin = bool(info.get("isAdmin"))
        return {
            "ok": True,
            "host": self.config.host,
            "computer": str(info.get("computer", "")),
            "user": str(info.get("user", "")),
            "is_admin": is_admin,
            "temp_writable": bool(info.get("tempWritable")),
            "channel_encrypted": True,
            "profiles": profiles,
            "profiles_readable": len(readable),
            "profiles_total": len(profiles),
            "verdict": _access_verdict(is_admin, len(readable), len(profiles), bool(info.get("tempWritable"))),
            **self._session_diagnostics(),
        }

    def _winrm_worker_count(self) -> int:
        """Runspace-pool worker count for the remote per-file work (content +
        SHA256 + ACL). ON by default; ``DSPM_WINRM_PARALLEL=0`` forces the serial
        single-runspace path. Bounded modestly (cap 8) because the pool runs on
        the ENDPOINT, whose core count is unknown - over-subscribing a small box
        would hurt; ``DSPM_WINRM_WORKERS`` overrides explicitly."""
        if os.getenv("DSPM_WINRM_PARALLEL", "1").strip().lower() in {"0", "false", "no", "off"}:
            return 1
        override = os.getenv("DSPM_WINRM_WORKERS", "").strip()
        if override.isdigit() and int(override) > 0:
            return min(int(override), 16)
        return max(1, min(int(resolve_parallelism().io_workers), 8))

    def scan(self, page: dict | None = None) -> list[dict]:
        """The collector's records. With ``page`` (W1.3), one level of the page's folders;
        the subfolders it met and where the next command takes over are left in
        ``last_page`` as ``{"folders": [...], "continuation": [...]}``."""
        self.last_page = {"folders": [], "continuation": []}
        target_paths = [] if page else self._target_paths()
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
            hash_files=self.config.hash_files,
            read_owner=self.config.read_owner,
            parallel_workers=self._winrm_worker_count(),
            page=page,
            scope=self.config.scope,
        )
        # P-B.2: the WinRM collector runs its whole walk as ONE remote PowerShell
        # session, but that session now parallelizes the expensive per-file work
        # (content + SHA256 + ACL) across a bounded runspace pool - one round-trip,
        # byte-identical output. It still holds a connection-equivalent for the
        # scan's duration, so it takes a process-wide admission slot: a burst of
        # concurrent endpoint scans cannot oversubscribe the shared collector-I/O
        # budget alongside the SMB share workers.
        budget = host_admission_budget()
        with budget.slot():
            result = self._run_ps_file(ps_script)
        admission_stats = budget.stats()
        if result.status_code != 0:
            raise ConnectionError(_clean_error(result.std_err) or f"WinRM scan failed on {self.config.host}")

        decoded_output, response_diagnostics = _decode_scan_response(result.std_out)
        response_diagnostics.update(self.last_delivery_diagnostics or {})
        # Already decoded above - parse the plain JSON directly rather than
        # re-scanning (and re-copying) a possibly multi-megabyte payload.
        raw_records = _parse_json_text(decoded_output)
        if raw_records is None:
            # No client-side parallelism (single remote session), but record the
            # admission posture for parity with the SMB collector's diagnostics.
            self.last_scan_diagnostics = {
                "io_parallel_active": False,
                "host_admission": admission_stats,
                **response_diagnostics,
            }
            self.last_scan_diagnostics.update(self._session_diagnostics())
            raise EmptyCollectorOutput(f"the endpoint {self.config.host or 'host'} returned no output")
        if isinstance(raw_records, dict) and isinstance(raw_records.get("records"), (list, dict)):
            if page:
                self.last_page = {
                    "folders": [item for item in _listed(raw_records.get("folders")) if isinstance(item, dict)],
                    "continuation": [item for item in _listed(raw_records.get("continuation")) if isinstance(item, dict)],
                }
            if isinstance(raw_records.get("records"), dict):
                raw_records["records"] = [raw_records["records"]]
            self.last_scan_diagnostics = raw_records.get("diagnostics") if isinstance(raw_records.get("diagnostics"), dict) else {}
            self._scope_diagnostics()
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
            acl = _endpoint_acl(item)
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
                    "acl": acl,
                    "owner": str(acl.get("owner") or item.get("owner") or ""),
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
                    "sha256": _endpoint_identity(item),
                    "file_hash": _endpoint_identity(item),
                    "skip_reason": _endpoint_skip_reason(item),
                    "scan_completeness": item.get("scan_completeness", "UNKNOWN"),
                    "bytes_scanned": int(item.get("bytes_scanned") or 0),
                    "total_bytes": int(item.get("total_bytes") or item.get("size") or 0),
                    "truncated": bool(item.get("truncated", False)),
                }
            )
        if filtered_wrong_profile:
            self.last_scan_diagnostics["filtered_wrong_profile"] = filtered_wrong_profile
        self.last_scan_diagnostics.update(response_diagnostics)
        # Revision 0055: what reading the permissions cost on the endpoint - one security
        # descriptor read a file, and each SID named once a command.
        self.last_scan_diagnostics["acl"] = acl_read_stats(item.get("acl_fields") for item in raw_records)
        self.last_scan_diagnostics.setdefault("io_parallel_active", False)
        self.last_scan_diagnostics["host_admission"] = admission_stats
        self.last_scan_diagnostics.update(self._session_diagnostics())
        return normalize_records(records)

    def _scope_diagnostics(self) -> None:
        """The script's per-reason counts as the scan's ``scope`` block (collectors.scan_scope):
        what scope rules left out, and - every scan, W3.6 - the folders it did not enter."""
        files = self.last_scan_diagnostics.pop("scope_excluded_by", None)
        folders = self.last_scan_diagnostics.pop("scope_skipped_folders_by", None)
        not_entered = {
            NOT_ENTERED_DEPTH: int(self.last_scan_diagnostics.pop("not_entered_depth", 0) or 0),
            NOT_ENTERED_SYSTEM: int(self.last_scan_diagnostics.pop("not_entered_system", 0) or 0),
        }
        tally = ScopeTally()
        if self.config.scope:
            tally.merge_counts(files if isinstance(files, dict) else {}, folders if isinstance(folders, dict) else {})
        tally.merge_counts(None, None, {reason: count for reason, count in not_entered.items() if count})
        self.last_scan_diagnostics["scope"] = tally.to_dict(self.config.scope or None,
                                                            depth_limit=self.config.max_depth)

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
        target = self.config.host.strip()
        if target != self._connection_candidates_target or not self._connection_candidates_cache:
            self._connection_candidates_cache = endpoint_connection_hosts(target) or [target]
            self._connection_candidates_target = target
        return list(self._connection_candidates_cache)

    def _username(self) -> str:
        username = self.config.username.strip()
        if self.config.domain.strip() and "\\" not in username and "@" not in username:
            username = f"{self.config.domain.strip()}\\{username}"
        return username

    def _endpoint_url(self, connection_host: str) -> str:
        port = self.config.port or (5986 if self.config.use_ssl else 5985)
        # M12: resolve + validate the target ONCE (raises TargetNotAllowed on a
        # loopback/private/metadata rebind, which the connect loop treats as a
        # failed candidate). Over HTTP we dial the PINNED IP so the validated
        # address is the dialed address; over HTTPS we keep the hostname in the URL
        # so certificate validation still applies (a rebind to loopback then fails
        # the cert), while still refusing a disallowed resolved address.
        pinned = resolve_and_pin(connection_host, tenant_id=self.config.tenant_id)
        host_for_url = connection_host if self.config.use_ssl else pinned
        if ":" in host_for_url and not host_for_url.startswith("["):
            host_for_url = f"[{host_for_url}]"  # bracket IPv6 literals for the URL
        return f"http{'s' if self.config.use_ssl else ''}://{host_for_url}:{port}/wsman"

    def _winrm_transports(self) -> list[str]:
        """Which authentication to offer, and in what order.

        Kerberos is preferred where it is asked for because it authenticates the
        SERVER as well as the client and cannot be relayed the way NTLM can.

        The subtlety is what to do when it was asked for and cannot be had. The
        old answer was to list it first and let the attempt fail into the NTLM
        entry behind it - which meant that with requests-kerberos absent (it is
        an optional pywinrm extra, and is not installed here) the flag did
        nothing at all, quietly, while the operator believed they had turned
        NTLM off. A security control that silently does not apply is worse than
        one that was never offered, so an unavailable Kerberos is now a
        configuration error and says how to fix itself.

        `DSPM_WINRM_KERBEROS=prefer` keeps the old behaviour for anyone who
        wants Kerberos where possible and NTLM where not - but it has to be
        chosen, and the transport actually used is reported either way in
        `connection_transport`.
        """

        # C0.1: a scan may choose its own policy; the install-wide variable is the
        # default for scans that do not. A pilot has one domain-joined host that
        # must use Kerberos and a workgroup laptop that cannot.
        mode = (self.config.kerberos_mode or os.getenv("DSPM_WINRM_KERBEROS", "0")).strip().lower()
        if mode in {"", "0", "false", "no", "off"}:
            return ["ntlm"]
        if not _kerberos_transport_available():
            if mode == "prefer":
                return ["ntlm"]
            raise WinRMKerberosUnavailable(
                "DSPM_WINRM_KERBEROS is set, but this install cannot speak Kerberos: "
                "pywinrm's kerberos transport needs requests-kerberos, which is not "
                "installed. Install it with `pip install pywinrm[kerberos]`, or set "
                "DSPM_WINRM_KERBEROS=prefer to allow NTLM where Kerberos is unavailable. "
                "Leaving it set without the dependency does not fall back safely - it "
                "would use NTLM while reporting nothing."
            )
        return ["kerberos"] if mode in {"1", "true", "yes", "on", "require", "strict"} else ["kerberos", "ntlm"]

    def _winrm_cert_validation(self) -> str:
        """Whether this connection checks the endpoint's certificate, and how.

        These are pywinrm's own two words, and they do not line up with what an
        operator chose. 'validate' is the default and covers both the system trust
        store and a CA bundle. A PINNED thumbprint also returns 'ignore', because
        urllib3 asserts the fingerprint itself and will not also walk a chain - the
        certificate is still checked, and transport_summary() reports that as
        'pinned' so a saved scan never reads as though nothing was checked. The one
        case where nothing is checked is the explicit opt-in
        (DSPM_WINRM_SSL_SKIP_CA_CHECK=1, or cert_trust='insecure') for the
        self-signed certificate an HTTPS activation creates on a trusted internal
        network: it still encrypts the channel but drops MITM protection entirely.

        C0.1: production refuses that opt-in. An install that has declared itself
        production has a certificate story - a CA bundle or a pinned thumbprint,
        both offered per scan - and 'trust anything' is not one of them. Refusing
        it here rather than at startup catches the operator who exports it later.
        """

        if not self.config.use_ssl:
            return "validate"
        if self.config.cert_thumbprint:
            # The pin IS the validation; urllib3 checks the fingerprint itself.
            return "ignore"
        if self.config.insecure_tls or os.getenv("DSPM_WINRM_SSL_SKIP_CA_CHECK", "0") == "1":
            if _in_production():
                raise WinRMTransportRefused(
                    "Scanning without checking the endpoint's certificate is refused when "
                    "DSPM_ENV=production (whether asked for by the scan or by "
                    "DSPM_WINRM_SSL_SKIP_CA_CHECK=1). Pin the endpoint's certificate "
                    "thumbprint, or point the scan at a CA bundle that signs it."
                )
            return "ignore"
        return "validate"

    def _winrm_ca_trust_path(self) -> str:
        """A CA bundle for this scan, if one was chosen.

        pywinrm hands this to requests as `session.verify`, so it replaces the
        system trust store for this connection only - which is what an internal PKI
        whose root the scanning host does not trust needs.
        """

        bundle = str(self.config.ca_bundle or "").strip()
        if not bundle or not self.config.use_ssl:
            return ""
        if not Path(bundle).is_file():
            raise WinRMTransportRefused(
                f"The CA bundle for this scan does not exist on the scanning host: {bundle}"
            )
        return bundle

    def transport_summary(self) -> dict:
        """How this scan reaches the endpoint, in the words an operator chose.

        C0.1: preflight and the saved scan both carry it, so 'it scanned' and 'it
        scanned over TLS with a validated certificate' stop being the same sentence.
        Never carries a credential - only the transport decisions.
        """

        try:
            pywinrm_validation = self._winrm_cert_validation()
            refused = ""
        except WinRMTransportRefused as exc:
            pywinrm_validation, refused = "refused", str(exc)
        if self.config.cert_thumbprint:
            trust, validation = "thumbprint", "pinned"
        elif str(self.config.ca_bundle or "").strip():
            trust, validation = "ca_bundle", "validate"
        elif pywinrm_validation == "ignore":
            # The one case where nothing about the certificate is checked.
            trust, validation = "insecure", "none"
        elif pywinrm_validation == "refused":
            trust, validation = "refused", "refused"
        else:
            trust, validation = "system", "validate"
        summary = {
            "ssl": bool(self.config.use_ssl),
            "port": self.config.port or (5986 if self.config.use_ssl else 5985),
            "scheme": "https" if self.config.use_ssl else "http",
            "certificate_trust": trust if self.config.use_ssl else "not_applicable",
            "certificate_validation": validation if self.config.use_ssl else "not_applicable",
            "certificate_thumbprint": self.config.cert_thumbprint or "",
            "message_encryption": self._winrm_message_encryption(),
            "authentication": self._authentication_policy(),
            "ssl_required": _winrm_ssl_required(),
        }
        if refused:
            summary["refused"] = refused
        return summary

    def _authentication_policy(self) -> str:
        """What this scan will accept, before anything is negotiated."""
        try:
            offered = self._winrm_transports()
        except WinRMKerberosUnavailable as exc:
            return f"unavailable: {exc}"[:200]
        if offered == ["kerberos"]:
            return "kerberos_only"
        if offered[:1] == ["kerberos"]:
            return "kerberos_preferred"
        return "ntlm"

    def _winrm_message_encryption(self) -> str:
        """Never carry a scan over an unencrypted channel.

        pywinrm's default is 'auto', which wraps the payload in NTLM/Kerberos
        message encryption only when the auth object happens to expose a
        session key - for NTLM that is `hasattr(session.auth,
        "session_security")` in winrm/transport.py. When it does not, 'auto'
        does not fail: it sends the request PLAINTEXT over http://...:5985 and
        says nothing. On this collector that payload is the customer's file
        content, which is the one thing a DSPM must never put on the wire in
        the clear.

        It happens to encrypt today because requests-ntlm 1.3.0 exposes that
        attribute - which is a property of the lockfile, not of the design. On
        HTTP the requirement is stated instead, so a transport that cannot
        encrypt raises WinRMError rather than quietly succeeding. Over HTTPS
        the channel is already encrypted and 'auto' leaves it to TLS rather
        than paying for a second wrapping.
        """

        return "auto" if self.config.use_ssl else "always"

    def _winrm_session(self, connection_host: str, transport: str):
        import winrm
        kwargs = {
            "auth": (self._username(), self.config.password),
            "transport": transport,
            "message_encryption": self._winrm_message_encryption(),
        }
        if self.config.use_ssl:
            kwargs["server_cert_validation"] = self._winrm_cert_validation()
            ca_trust_path = self._winrm_ca_trust_path()
            if ca_trust_path:
                kwargs["ca_trust_path"] = ca_trust_path
        session = winrm.Session(self._endpoint_url(connection_host), **kwargs)
        if self.config.use_ssl and self.config.cert_thumbprint:
            # pywinrm has no pinning option, so the pin is mounted on the requests
            # session underneath it. build_session() is what pywinrm itself calls
            # before the first request and returns the same session afterwards.
            underlying = session.protocol.transport.build_session()
            underlying.mount("https://", _pinned_adapter(self.config.cert_thumbprint))
        return session

    def _session_identity(self) -> tuple[object, ...]:
        """Network/auth fields that determine whether a session is reusable.

        Scan-only fields (paths, filters, read modes) intentionally do not take
        part: P4 changes those between the metadata and content scripts. A host,
        credential, SSL, port, validation, or transport-policy change forces a
        fresh security negotiation instead of borrowing an incompatible session.
        """

        return (
            self.config.host.strip().casefold(),
            self._username(),
            self.config.password,
            bool(self.config.use_ssl),
            self.config.port or (5986 if self.config.use_ssl else 5985),
            self._winrm_cert_validation(),
            str(self.config.ca_bundle or "").strip(),
            self.config.cert_thumbprint or "",
            bool(self.config.insecure_tls),
            self._winrm_message_encryption(),
            tuple(self._winrm_transports()),
        )

    def _session_diagnostics(self) -> dict:
        return {
            "session_reused": bool(self._last_session_reused),
            "session_reuse_count": int(self._session_reuse_count),
            "session_creations": int(self._session_creations),
            "session_negotiations": int(self._session_negotiations),
            "session_failovers": int(self._session_failovers),
            "shells_opened": int(self._shells_opened),
            "shells_reused": int(self._shells_reused),
            "connection_transport": self.last_connection_transport,
            # C0.1: what was asked for, beside what was negotiated. A saved scan can
            # then answer "was this carried over TLS, and was the certificate checked".
            "transport": self.transport_summary(),
        }

    def _run_with_session(self, operation):
        """Run against the working binding, negotiating only when necessary."""

        identity = self._session_identity()
        binding = self._session_binding
        last_error: Exception | None = None
        self._last_session_reused = False

        if binding is not None and binding.identity == identity:
            try:
                result = operation(binding.session)
            except WinRMCommandTimedOut:
                # The command reached the endpoint and ran too long. Another host or
                # transport would only run it again for as long.
                raise
            except Exception as exc:
                # A once-good connection can expire during a long scan. Drop it
                # and use the normal candidate/transport failover below. Scan
                # scripts are read-only, so a transport-level retry is safe.
                self._session_binding = None
                self._session_failovers += 1
                last_error = exc
            else:
                self.last_connection_host = binding.connection_host
                self.last_connection_transport = binding.transport
                self._session_reuse_count += 1
                self._last_session_reused = True
                return result
        elif binding is not None:
            # A caller changed a security-relevant config field. Never reuse a
            # binding across a host/credential/transport boundary.
            self._session_binding = None

        for connection_host in self._connection_hosts():
            for transport in self._winrm_transports():
                try:
                    session = self._winrm_session(connection_host, transport)
                    self._session_creations += 1
                    result = operation(session)
                    self._session_binding = _WinRMSessionBinding(
                        identity=identity,
                        connection_host=connection_host,
                        transport=transport,
                        session=session,
                    )
                    self._session_negotiations += 1
                    self.last_connection_host = connection_host
                    self.last_connection_transport = transport
                    return result
                except WinRMCommandTimedOut:
                    raise
                except Exception as exc:
                    last_error = exc
                    continue
        if last_error:
            raise last_error
        raise RuntimeError("No endpoint host candidate was available for WinRM connection.")

    def _refuse_a_transport_this_install_forbids(self) -> None:
        """Check the transport rules once, before the connect loop.

        The loop treats an exception as a failed candidate and tries the next host and
        transport, so a refusal raised from inside it became one failure per candidate
        and the operator waited through all of them for a verdict that could not change.
        """

        if not self.config.use_ssl and _winrm_ssl_required():
            raise WinRMTransportRefused(
                "This install requires WinRM over TLS and this scan asked for cleartext HTTP. "
                "Turn on TLS for the scan (port 5986 by default) and choose how its certificate "
                "is trusted, or set DSPM_REQUIRE_WINRM_SSL=0 to allow HTTP on a trusted network."
            )
        # Raises when the trust choice is not allowed here, or the bundle is gone.
        self._winrm_cert_validation()
        self._winrm_ca_trust_path()

    def _run_ps(self, script: str):
        try:
            import winrm  # noqa: F401 - dependency presence check
        except ModuleNotFoundError as exc:
            raise RuntimeError("Missing dependency 'pywinrm'. Install requirements.txt before WinRM endpoint scans.") from exc

        self._refuse_a_transport_this_install_forbids()
        return self._run_with_session(lambda session: session.run_ps(script))

    def _run_ps_file(self, script: str):
        try:
            import winrm  # noqa: F401 - dependency presence check
        except ModuleNotFoundError as exc:
            raise RuntimeError("Missing dependency 'pywinrm'. Install requirements.txt before WinRM endpoint scans.") from exc

        self._refuse_a_transport_this_install_forbids()
        return self._run_with_session(
            lambda session: self._run_ps_file_with_session(session, script)
        )

    def _run_ps_file_with_session(self, session, script: str):
        started = time.perf_counter()
        # Never let a previous candidate's outcome describe this attempt.
        self.last_delivery_diagnostics = {}
        self._delivery_remote_commands_current = 0
        self._response_envelopes_current = 0
        try:
            result = self._run_ps_file_over_stdin(session, script)
        except Exception as exc:
            if not _is_stdin_capability_error(exc):
                # A dead socket, a timeout, or rejected credentials will fail the
                # legacy path identically. Retrying it there doubled the wall
                # clock of every unreachable-endpoint failure (measured: 2x the
                # connect timeout per host/transport candidate), so those
                # propagate immediately and let the caller try the next
                # candidate.
                self._record_delivery_diagnostics(
                    mode="failed",
                    started=started,
                    fallback_reason=type(exc).__name__,
                )
                raise
            # Some older/restricted WS-Man targets reject command input even
            # though ordinary run_cmd calls work. Preserve compatibility without
            # making the legacy 31-PowerShell-spawn path the common case.
            fallback_reason = type(exc).__name__
            try:
                result = self._run_ps_file_legacy(session, script)
            except Exception:
                self._record_delivery_diagnostics(
                    mode="failed",
                    started=started,
                    fallback_reason=fallback_reason,
                )
                raise
            self._record_delivery_diagnostics(
                mode="legacy_disk_chunks",
                started=started,
                fallback_reason=fallback_reason,
            )
            return result
        self._record_delivery_diagnostics(mode="stdin_gzip", started=started)
        return result

    def _record_delivery_diagnostics(
        self,
        *,
        mode: str,
        started: float,
        fallback_reason: str = "",
    ) -> None:
        last_ms = round((time.perf_counter() - started) * 1000, 3)
        self._delivery_invocations += 1
        self._delivery_total_ms += last_ms
        self._remote_commands_total += self._delivery_remote_commands_current
        self._response_envelopes_total += self._response_envelopes_current
        self.last_delivery_diagnostics = {
            "delivery_mode": mode,
            # P5 job totals: on a warm scan these include metadata and every
            # content batch because P4 keeps all invocations on one scanner.
            "delivery_ms": round(self._delivery_total_ms, 3),
            "remote_commands": int(self._remote_commands_total),
            "response_envelopes": int(self._response_envelopes_total),
            "delivery_invocations": int(self._delivery_invocations),
            # Per-attempt detail remains available for fallback diagnosis and
            # the <=3-command primary-path guardrail.
            "delivery_last_ms": last_ms,
            "delivery_remote_commands": int(self._delivery_remote_commands_current),
            "delivery_response_envelopes": int(self._response_envelopes_current),
            "delivery_fallback_reason": fallback_reason,
        }

    def _run_ps_file_over_stdin(self, session, script: str):
        """Run one byte-identical script through a single WinRM command.

        The script is compressed locally, base64-wrapped so stdin remains ASCII,
        and expanded entirely in memory by a short PowerShell bootstrap. No
        script artifact is written to the endpoint.
        """
        from winrm import Response

        payload = base64.b64encode(gzip.compress(script.encode("utf-8"), mtime=0))
        bootstrap = (
            "$ErrorActionPreference='Stop';$exitCode=0;$memory=$null;$gzip=$null;$reader=$null;"
            "try{$payload=[Console]::In.ReadToEnd();"
            "$compressed=[Convert]::FromBase64String($payload);"
            "$memory=New-Object IO.MemoryStream(,$compressed);"
            "$gzip=New-Object IO.Compression.GZipStream($memory,[IO.Compression.CompressionMode]::Decompress);"
            "$reader=New-Object IO.StreamReader($gzip,[Text.Encoding]::UTF8);"
            "$scriptBlock=[ScriptBlock]::Create($reader.ReadToEnd());"
            "& $scriptBlock;if($null-ne $LASTEXITCODE){$exitCode=$LASTEXITCODE}}"
            "catch{Write-Error $_;$exitCode=1}finally{"
            "if($null-ne $reader){$reader.Dispose()}elseif($null-ne $gzip){$gzip.Dispose()}"
            "elseif($null-ne $memory){$memory.Dispose()}};exit $exitCode"
        )
        encoded_bootstrap = base64.b64encode(bootstrap.encode("utf-16le")).decode("ascii")
        protocol = session.protocol
        shell_id = ""
        command_id = ""
        keep_shell = False
        try:
            shell_id = self._shell_for(protocol)
            keep_shell = self._shell_reuse
            command_id = protocol.run_command(
                shell_id,
                "powershell.exe",
                ["-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded_bootstrap],
            )
            self._delivery_remote_commands_current += 1
            # Send in bounded slices: one oversized WS-Man envelope is refused by
            # the target (default MaxEnvelopeSize is ~150-500 KB), which would
            # silently demote a large scan - P2 batches up to 256 paths into one
            # script - onto the slow legacy path.
            for index in range(0, len(payload), _WINRM_STDIN_CHUNK_BYTES):
                slice_ = payload[index : index + _WINRM_STDIN_CHUNK_BYTES]
                protocol.send_command_input(
                    shell_id,
                    command_id,
                    slice_,
                    end=index + _WINRM_STDIN_CHUNK_BYTES >= len(payload),
                )
            return Response(self._get_command_output(protocol, shell_id, command_id))
        except BaseException:
            # A shell a command failed or timed out in is not trusted with the next one.
            keep_shell = False
            raise
        finally:
            # Preserve the delivery/output exception if cleanup also fails; the
            # caller then takes the compatible disk-based path on this session.
            if shell_id and command_id:
                try:
                    protocol.cleanup_command(shell_id, command_id)
                except Exception:
                    pass
            if shell_id and not keep_shell:
                if self._reused_shell is not None and self._reused_shell[1] == shell_id:
                    self._reused_shell = None
                try:
                    protocol.close_shell(shell_id)
                except Exception:
                    pass

    @contextmanager
    def reusing_shell(self):
        """Run every command of the block in one WinRS shell (W1.3).

        Each command opened and closed a shell of its own: a page, then every content
        batch, each paid for a shell. Inside this block the first command opens one and
        the rest use it; a command that fails or times out closes it, and the next opens
        another. The shell is closed when the block ends.
        """
        previous = self._shell_reuse
        self._shell_reuse = True
        try:
            yield self
        finally:
            self._shell_reuse = previous
            if not previous:
                self._close_reused_shell()

    def _shell_for(self, protocol) -> str:
        if self._shell_reuse and self._reused_shell is not None and self._reused_shell[0] is protocol:
            self._shells_reused += 1
            return self._reused_shell[1]
        self._close_reused_shell()
        shell_id = protocol.open_shell(codepage=65001)
        self._shells_opened += 1
        if self._shell_reuse:
            self._reused_shell = (protocol, shell_id)
        return shell_id

    def _close_reused_shell(self) -> None:
        held, self._reused_shell = self._reused_shell, None
        if held is not None:
            try:
                held[0].close_shell(held[1])
            except Exception:
                pass

    def _get_command_output(self, protocol, shell_id: str, command_id: str):
        """Collect output while counting the actual WS-Man Receive envelopes.

        pywinrm's high-level ``get_command_output`` hides this loop. Its public
        raw method exposes one Receive response at a time, including operation
        timeout responses, which lets P5 report a real envelope count. Minimal
        protocol fakes and older compatible clients retain the high-level path
        and conservatively report one envelope.
        """

        get_raw = getattr(protocol, "get_command_output_raw", None)
        if not callable(get_raw):
            output = protocol.get_command_output(shell_id, command_id)
            self._response_envelopes_current += 1
            return output

        from winrm.exceptions import WinRMOperationTimeoutError

        stdout_buffer: list[bytes] = []
        stderr_buffer: list[bytes] = []
        return_code = -1
        command_done = False
        limit = winrm_command_timeout_seconds()
        deadline = time.monotonic() + limit if limit else None
        while not command_done:
            if deadline is not None and time.monotonic() > deadline:
                raise WinRMCommandTimedOut(
                    f"a WinRM command on {self.config.host} ran past its {limit} s wall clock and was stopped"
                )
            self._response_envelopes_current += 1
            try:
                stdout, stderr, return_code, command_done = get_raw(shell_id, command_id)
            except WinRMOperationTimeoutError:
                continue
            stdout_buffer.append(stdout)
            stderr_buffer.append(stderr)
        return b"".join(stdout_buffer), b"".join(stderr_buffer), return_code

    def _run_cmd_with_session(self, session, command: str, arguments: list[str]):
        """pywinrm ``run_cmd`` with receive-envelope accounting when possible."""

        from winrm import Response

        protocol = getattr(session, "protocol", None)
        low_level = protocol is not None and all(
            callable(getattr(protocol, name, None))
            for name in (
                "open_shell",
                "run_command",
                "cleanup_command",
                "close_shell",
            )
        ) and (
            callable(getattr(protocol, "get_command_output_raw", None))
            or callable(getattr(protocol, "get_command_output", None))
        )
        if not low_level:
            self._delivery_remote_commands_current += 1
            result = session.run_cmd(command, arguments)
            self._response_envelopes_current += 1
            return result

        shell_id = ""
        command_id = ""
        try:
            shell_id = protocol.open_shell()
            command_id = protocol.run_command(shell_id, command, arguments)
            self._delivery_remote_commands_current += 1
            return Response(self._get_command_output(protocol, shell_id, command_id))
        finally:
            if shell_id and command_id:
                try:
                    protocol.cleanup_command(shell_id, command_id)
                except Exception:
                    pass
            if shell_id:
                try:
                    protocol.close_shell(shell_id)
                except Exception:
                    pass

    def _run_ps_file_legacy(self, session, script: str):
        """Compatible disk fallback with cheap cmd.exe chunk appends."""

        token = uuid4().hex
        b64_name = f"dspm_{token}.b64"
        encoded_script = base64.b64encode(script.encode("utf-8")).decode("ascii")
        chunk_size = 1800

        def run_short(command: str):
            encoded_command = base64.b64encode(command.encode("utf-16le")).decode("ascii")
            return self._run_cmd_with_session(
                session,
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
        init = run_short(
            temp_path
            + "[IO.File]::WriteAllBytes($p, [byte[]]@()); "
            "[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($p)))"
        )
        if init.status_code != 0:
            return init
        encoded_remote_temp_path = (
            init.std_out.decode("ascii") if isinstance(init.std_out, bytes) else str(init.std_out)
        )
        remote_temp_path = base64.b64decode(
            encoded_remote_temp_path.strip(), validate=True
        ).decode("utf-8")
        if not remote_temp_path or any(character in remote_temp_path for character in '\r\n"'):
            raise RuntimeError("WinRM legacy delivery returned an invalid temporary path.")

        def cleanup_temp_file() -> None:
            try:
                self._run_cmd_with_session(
                    session,
                    "cmd.exe",
                    ["/d", "/q", "/c", f'del /f /q "{remote_temp_path}" >nul 2>nul'],
                )
            except Exception:
                pass

        for index in range(0, len(encoded_script), chunk_size):
            chunk = encoded_script[index : index + chunk_size]
            append = self._run_cmd_with_session(
                session,
                "cmd.exe",
                ["/d", "/q", "/c", f'echo({chunk}>>"{remote_temp_path}"'],
            )
            if append.status_code != 0:
                cleanup_temp_file()
                return append

        encoded_temp_path = base64.b64encode(remote_temp_path.encode("utf-8")).decode("ascii")
        execute = (
            "$ErrorActionPreference = 'Stop'; "
            f"$b64 = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_temp_path}')); "
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
        try:
            return run_short(execute)
        except Exception:
            cleanup_temp_file()
            raise


def _scan_script(
    paths: list[str],
    max_depth: int | None,
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
    hash_files: bool = True,
    read_owner: bool = True,
    parallel_workers: int = 1,
    page: dict | None = None,
    scope: dict | None = None,
) -> str:
    """The collector script. With ``page`` (W1.3) it lists one level of the folders the page
    names - ``{"folders": [{"path", "depth", "after", "root"}], "page_size", "max_folders"}`` -
    instead of walking ``paths``: at most ``page_size`` file records and ``max_folders``
    folders, in ordinal case-insensitive name order, and returns the subfolders it met and
    where the next command takes over. Without it, the whole walk (capped at 5,000 records)."""
    encoded_paths = base64.b64encode(json.dumps(paths).encode("utf-8")).decode("ascii")
    encoded_page = base64.b64encode(json.dumps(page or {}).encode("utf-8")).decode("ascii")
    # Advanced scan scope (collectors.scan_scope): canonical rules, absolute paths in "/" form.
    encoded_scope = base64.b64encode(json.dumps(scope or {}).encode("utf-8")).decode("ascii")
    scope_active_value = "$true" if scope else "$false"
    page_mode_value = "$true" if page else "$false"
    # A page is bounded by page_size; the whole-walk cap is for the walk alone.
    max_records_value = 2147483647 if page else 5000
    encoded_extensions = base64.b64encode(json.dumps(allowed_extensions).encode("utf-8")).decode("ascii")
    read_content_value = "$true" if read_content else "$false"
    extension_filter_value = "$true" if extension_filter_enabled else "$false"
    include_hidden_value = "$true" if include_hidden else "$false"
    include_system_value = "$true" if include_system else "$false"
    hidden_filter_value = "$true" if hidden_filter_enabled else "$false"
    system_filter_value = "$true" if system_filter_enabled else "$false"
    read_acl_value = "$true" if read_acl else "$false"
    inspect_archives_value = "$true" if inspect_archives else "$false"
    hash_files_value = "$true" if hash_files else "$false"
    # W2.2 on the endpoint: the whole-file SHA-256 is taken of a file read whole for its
    # content - a text file within its cap, a document within the document cap - and of
    # every file only under DSPM_HASH_POLICY=full. Any other file is not read to name
    # it: the collector gives it a meta identity (sampled falls back to meta here).
    whole_hash_value = "$true" if content_policy.hash_policy() == "full" else "$false"
    document_cap = int(content_policy.document_cap_bytes())
    read_owner_value = "$true" if read_owner else "$false"
    text_extensions = ",".join(f'"{item}"' for item in sorted(TEXT_EXTENSIONS))
    binary_extensions = ",".join(f'"{item}"' for item in sorted(BINARY_TEXT_EXTENSIONS))
    parallel_workers_value = max(1, int(parallel_workers or 1))
    # P-B.2 WinRM parallelism: the config init + every helper function live in a
    # single reusable scriptblock ($dspmEngine). The main runspace dot-sources it
    # for the (serial) enumeration walk; each pooled worker runspace dot-sources
    # the SAME source once (guarded by Test-Path Function:) to run the expensive
    # per-file work (content + SHA256 + ACL) in parallel. Because every helper is
    # a pure function and every diagnostic tally is updated only during the serial
    # walk, the parallel result is byte-identical to the serial one.
    # W3.6: -1 is no limit - the script enters every folder under its paths.
    depth_limit = -1 if max_depth is None else int(max_depth)
    acl_fields_ps = ACL_FIELDS_PS
    return f"""
    $ErrorActionPreference = "SilentlyContinue"
    $dspmEngine = {{
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
    $scopeActive = {scope_active_value}
    $scopeJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{encoded_scope}"))
    $dspmScope = ConvertFrom-Json $scopeJson
    $scopeExcludeExtensions = @{{}}
    foreach ($scopeItem in @($dspmScope.exclude_extensions)) {{
      if ($scopeItem) {{ $scopeExcludeExtensions[([string]$scopeItem).ToLowerInvariant()] = $true }}
    }}
    $scopeExcludePaths = @(@($dspmScope.exclude_paths) | Where-Object {{ $_ }} | ForEach-Object {{ ([string]$_).ToLowerInvariant().TrimEnd('/') }})
    $scopeMinSize = if ($null -ne $dspmScope.min_size_bytes) {{ [int64]$dspmScope.min_size_bytes }} else {{ [int64]-1 }}
    $scopeMaxSize = if ($null -ne $dspmScope.max_size_bytes) {{ [int64]$dspmScope.max_size_bytes }} else {{ [int64]-1 }}
    $scopeModifiedAfter = $null
    if ($dspmScope.modified_after) {{
      $scopeModifiedAfter = [datetime]::SpecifyKind([datetime]::ParseExact([string]$dspmScope.modified_after, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture), [DateTimeKind]::Utc)
    }}
    $maxRecords = {max_records_value}
    $maxArchiveEntriesPerFile = 200
    $maxArchiveEntryBytes = 26214400
    $maxArchiveTotalBytes = 209715200
    $maxArchiveCompressionRatio = 100
    $records = New-Object System.Collections.Generic.List[object]
    $workItems = New-Object System.Collections.Generic.List[object]
    # The owner and the DACL, read once a file; each SID named once a command (collectors.acl_powershell).
    $dspmAclSections = if ({read_acl_value}) {{ [System.Security.AccessControl.AccessControlSections]'Owner, Access' }} else {{ [System.Security.AccessControl.AccessControlSections]'Owner' }}
{acl_fields_ps}
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
      worker_errors = @()
      unreadable_dirs = @()
      allowed_extensions = @($allowedExtensions)
      extension_histogram = @{{}}
      selected_extension_counts = @{{}}
      extension_filter_enabled = {extension_filter_value}
      hidden_filter_enabled = {hidden_filter_value}
      system_filter_enabled = {system_filter_value}
      scope_excluded_by = @{{}}
      scope_skipped_folders_by = @{{}}
      not_entered_depth = 0
      not_entered_system = 0
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

    function Add-DspmScopeCount($table, $reason) {{
      if ($table.ContainsKey($reason)) {{ $table[$reason] += 1 }} else {{ $table[$reason] = 1 }}
    }}

    function Test-DspmScopeExcludedPath($normalized) {{
      foreach ($excluded in $scopeExcludePaths) {{
        if ($normalized -eq $excluded -or $normalized.StartsWith($excluded + '/')) {{ return $true }}
      }}
      return $false
    }}

    # Advanced scope: why a folder is not listed ("" when it is).
    function Get-DspmScopeFolderReason($fullName) {{
      if (-not $scopeActive) {{ return "" }}
      $normalized = ([string]$fullName).ToLowerInvariant().Replace([string][char]92, '/').TrimEnd('/')
      if (Test-DspmScopeExcludedPath $normalized) {{ return "excluded_folder" }}
      return ""
    }}

    # Advanced scope: why a listed file is left before any work is queued for it - by its
    # path and extension, then by the size and time the listing already gives.
    function Get-DspmScopeFileReason($file, $extension) {{
      if (-not $scopeActive) {{ return "" }}
      $normalized = ([string]$file.FullName).ToLowerInvariant().Replace([string][char]92, '/')
      if (Test-DspmScopeExcludedPath $normalized) {{ return "excluded_folder" }}
      if ($extension -and $scopeExcludeExtensions.ContainsKey(([string]$extension).ToLowerInvariant())) {{ return "extension" }}
      if ($scopeMinSize -ge 0 -and [int64]$file.Length -lt $scopeMinSize) {{ return "smaller_than_minimum" }}
      if ($scopeMaxSize -ge 0 -and [int64]$file.Length -gt $scopeMaxSize) {{ return "larger_than_maximum" }}
      if ($scopeModifiedAfter -and $file.LastWriteTimeUtc -lt $scopeModifiedAfter) {{ return "modified_before_date" }}
      return ""
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

    # A file's bytes as text, in the file's own encoding - the rules of
    # collectors.text_decode: a byte-order mark (UTF-8, UTF-16 or UTF-32), else UTF-16
    # when the first 4 KB has a NUL in every other byte, else UTF-8. Read as UTF-8
    # whatever it was, a UTF-16 file (a regedit export, a PowerShell 5.1 log) came back
    # with a NUL between every character and was skipped as binary.
    function ConvertFrom-DspmTextBytes($buffer, $count) {{
      $start = 0
      $encoding = New-Object System.Text.UTF8Encoding($false)
      if ($count -ge 4 -and $buffer[0] -eq 0xFF -and $buffer[1] -eq 0xFE -and $buffer[2] -eq 0 -and $buffer[3] -eq 0) {{
        $encoding = New-Object System.Text.UTF32Encoding($false, $false); $start = 4
      }} elseif ($count -ge 4 -and $buffer[0] -eq 0 -and $buffer[1] -eq 0 -and $buffer[2] -eq 0xFE -and $buffer[3] -eq 0xFF) {{
        $encoding = New-Object System.Text.UTF32Encoding($true, $false); $start = 4
      }} elseif ($count -ge 3 -and $buffer[0] -eq 0xEF -and $buffer[1] -eq 0xBB -and $buffer[2] -eq 0xBF) {{
        $start = 3
      }} elseif ($count -ge 2 -and $buffer[0] -eq 0xFF -and $buffer[1] -eq 0xFE) {{
        $encoding = New-Object System.Text.UnicodeEncoding($false, $false); $start = 2
      }} elseif ($count -ge 2 -and $buffer[0] -eq 0xFE -and $buffer[1] -eq 0xFF) {{
        $encoding = New-Object System.Text.UnicodeEncoding($true, $false); $start = 2
      }} else {{
        $sniff = [Math]::Min($count, 4096)
        $units = [Math]::Floor($sniff / 2)
        # Counted only when there is a NUL at all: a UTF-8 text has none.
        if ($units -ge 4 -and [Array]::IndexOf($buffer, [byte]0, 0, $sniff) -ge 0) {{
          $evenNuls = 0
          $oddNuls = 0
          for ($index = 0; $index -lt $units; $index++) {{
            if ($buffer[2 * $index] -eq 0) {{ $evenNuls++ }}
            if ($buffer[2 * $index + 1] -eq 0) {{ $oddNuls++ }}
          }}
          if ($oddNuls -ge $units * 0.5 -and $evenNuls -le $units * 0.1) {{
            $encoding = New-Object System.Text.UnicodeEncoding($false, $false)
          }} elseif ($evenNuls -ge $units * 0.5 -and $oddNuls -le $units * 0.1) {{
            $encoding = New-Object System.Text.UnicodeEncoding($true, $false)
          }}
        }}
      }}
      return $encoding.GetString($buffer, $start, $count - $start)
    }}

    # Up to $limit bytes of a stream, as text. Read until the limit or the end: a zip
    # entry's stream returns a block at a time, not everything asked for.
    function Read-DspmStreamText($stream, $limit) {{
      $buffer = New-Object byte[] ([int]$limit)
      $read = 0
      while ($read -lt $buffer.Length) {{
        $got = $stream.Read($buffer, $read, $buffer.Length - $read)
        if ($got -le 0) {{ break }}
        $read += $got
      }}
      return (ConvertFrom-DspmTextBytes $buffer $read)
    }}

    function Read-PlainText($path, $maxBytes) {{
      return [string](Read-DspmTextFile $path $maxBytes $false).text
    }}

    # A text file read once (W5): up to $maxBytes of it as text and - when $wantHash and the
    # read reached the end of the file - the SHA-256 of those same bytes, which is the
    # whole-file hash. It was read a second time, whole, by Get-FileHash.
    function Read-DspmTextFile($path, $maxBytes, $wantHash) {{
      try {{
        $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {{
          $length = [int64]$stream.Length
          $buffer = New-Object byte[] ([int][Math]::Min([int64]$maxBytes, $length))
          $read = 0
          while ($read -lt $buffer.Length) {{
            $got = $stream.Read($buffer, $read, $buffer.Length - $read)
            if ($got -le 0) {{ break }}
            $read += $got
          }}
          $digest = ""
          if ($wantHash -and $read -eq $length -and $stream.Read((New-Object byte[] 1), 0, 1) -eq 0) {{
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {{
              $digest = ([BitConverter]::ToString($sha.ComputeHash($buffer, 0, $read))).Replace("-", "").ToLowerInvariant()
            }} finally {{
              $sha.Dispose()
            }}
          }}
          return [PSCustomObject]@{{ text = (ConvertFrom-DspmTextBytes $buffer $read); sha256 = $digest }}
        }} finally {{
          $stream.Close()
        }}
      }} catch {{
        return [PSCustomObject]@{{ text = ""; sha256 = "" }}
      }}
    }}

    function Read-ZipXmlText($path, $prefix) {{
      try {{
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        # M8: bound Office/ODT extraction so a hostile document cannot OOM the
        # target. Skip a part that is implausibly large or inflates implausibly
        # (zip-bomb guard), and cap the total decompressed across the document.
        $maxEntryBytes = 52428800
        $maxTotalBytes = 209715200
        $maxRatio = 200
        $archive = [System.IO.Compression.ZipFile]::OpenRead($path)
        try {{
          # The parts that hold the text, the shared strings first: a worksheet holds only
          # indices into sharedStrings.xml, and Excel writes the worksheets (and theme and
          # styles) before it, so a workbook of some 20,000 cells used every character of
          # the cap before its first text cell. Theme and styles hold no content.
          $selected = @($archive.Entries | Where-Object {{
            $_.FullName.StartsWith($prefix) -and $_.FullName.EndsWith(".xml") -and
            -not ($_.FullName -like "*/theme/*" -or ($prefix -and $_.FullName -eq ($prefix + "styles.xml")))
          }})
          $entries = @($selected | Where-Object {{ $_.FullName -eq "xl/sharedStrings.xml" }}) +
            @($selected | Where-Object {{ $_.FullName -ne "xl/sharedStrings.xml" }})
          $parts = New-Object System.Collections.Generic.List[string]
          $total = 0
          $truncated = $false
          for ($index = 0; $index -lt $entries.Count; $index++) {{
            $entry = $entries[$index]
            if ($entry.Length -gt $maxEntryBytes) {{ $truncated = $true; continue }}
            if ($entry.CompressedLength -gt 0 -and ($entry.Length / $entry.CompressedLength) -gt $maxRatio) {{ $truncated = $true; continue }}
            $reader = New-Object System.IO.StreamReader($entry.Open())
            try {{
              $xml = $reader.ReadToEnd()
              $clean = $xml -replace "<[^>]+>", " "
              $clean = $clean -replace "\\s+", " "
              $parts.Add($clean) | Out-Null
            }} finally {{
              $reader.Close()
            }}
            $total += $entry.Length
            if ($total -ge $maxTotalBytes) {{
              if ($index -lt $entries.Count - 1) {{ $truncated = $true }}
              break
            }}
          }}
          $joined = $parts -join "`n"
          if ($joined.Length -gt 120000) {{ $truncated = $true }}
          # Cut short is said: the record is PARTIAL, not FULL.
          return [PSCustomObject]@{{ text = $joined.Substring(0, [Math]::Min(120000, $joined.Length)); truncated = $truncated; status = "" }}
        }} finally {{
          $archive.Dispose()
        }}
      }} catch {{
        return [PSCustomObject]@{{ text = ""; truncated = $false; status = "not_extracted" }}
      }}
    }}

    function Read-BinaryText($path, $extension, $maxBytes) {{
      if (@(".docm", ".docx", ".dotm", ".dotx") -contains $extension) {{ return Read-ZipXmlText $path "word/" }}
      if (@(".xlsm", ".xlsx") -contains $extension) {{ return Read-ZipXmlText $path "xl/" }}
      if (@(".pptm", ".pptx") -contains $extension) {{ return Read-ZipXmlText $path "ppt/slides/" }}
      if (@(".odp", ".ods", ".odt", ".otp") -contains $extension) {{ return Read-ZipXmlText $path "" }}
      # A PDF's page text is compressed; there is no parser on the endpoint. A regex over
      # the raw bytes found only the uncompressed metadata (Title, Producer) and called
      # every PDF scanned and FULL. It is said to be not extracted until one runs here.
      return [PSCustomObject]@{{ text = ""; truncated = $false; status = "not_extracted" }}
    }}

    function Read-ZipEntryText($entry, $extension, $maxBytes) {{
      if (-not ($textExtensions -contains $extension)) {{ return "" }}
      try {{
        $stream = $entry.Open()
        try {{
          return (Read-DspmStreamText $stream ([Math]::Min([int64]$maxBytes, [int64]$entry.Length)))
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
      $inflatedTotal = 0
      foreach ($entry in @($entries | Select-Object -First $maxArchiveEntriesPerFile)) {{
        if ($records.Count -ge $maxRecords) {{ return }}
        if ([string]::IsNullOrWhiteSpace($entry.Name)) {{ continue }}
        $inflatedTotal += [int64]$entry.Length
        $compressedLength = [Math]::Max(1, [int64]$entry.CompressedLength)
        if ($entry.Length -gt $maxArchiveEntryBytes -or $compressedLength -gt $maxArchiveEntryBytes -or $inflatedTotal -gt $maxArchiveTotalBytes -or (($entry.Length / $compressedLength) -gt $maxArchiveCompressionRatio)) {{
          $diagnostics.archive_entries_skipped += 1
          continue
        }}
        $entryPath = "${{archivePath}}::$($entry.FullName)"
        $entryExtension = Get-DspmExtensionFromName $entry.FullName
        Add-DspmExtensionStat $entryExtension
        $includeEntry = Test-DspmRecordIncluded $entryExtension $isHidden $isSystem
        if ($includeEntry) {{
          $diagnostics.archive_entries += 1
          $diagnostics.matched_files += 1
          $entryContent = if ({read_content_value}) {{ Read-ZipEntryText $entry $entryExtension $maxArchiveEntryBytes }} else {{ "" }}
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
            scan_completeness = if ($entryContent -or $entry.Length -eq 0) {{ "FULL" }} else {{ "NONE" }}
            bytes_scanned = if ($entryContent) {{ [Math]::Min([int64]$entry.Length, [int64]$maxArchiveEntryBytes) }} else {{ 0 }}
            total_bytes = $entry.Length
            truncated = $entry.Length -gt $maxArchiveEntryBytes
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
      $scopeReason = Get-DspmScopeFileReason $file $extension
      if ($scopeReason) {{
        Add-DspmScopeCount $diagnostics.scope_excluded_by $scopeReason
        return
      }}
      $isHidden = [bool]($file.Attributes -band [IO.FileAttributes]::Hidden)
      $isSystem = [bool]($file.Attributes -band [IO.FileAttributes]::System)
      Add-DspmExtensionStat $extension
      $includeRecord = Test-DspmRecordIncluded $extension $isHidden $isSystem
      if ($scanArchiveEntries -and $extension -eq ".zip") {{ Add-ZipFileEntries $file.FullName $isHidden $isSystem }}
      if (-not $includeRecord) {{ return }}
      $diagnostics.matched_files += 1
      # Phase 1 (serial): reserve this file's ordered output slot (respecting the
      # global record cap deterministically, in enumeration order) and queue the
      # expensive per-file work. The slot is filled in phase 2 by index, so output
      # order is identical to the serial scan regardless of worker completion.
      if ($records.Count -ge $maxRecords) {{
        $diagnostics.record_limit_reached = $true
        return
      }}
      $records.Add($null) | Out-Null
      $workItems.Add([PSCustomObject]@{{
        Index = ($records.Count - 1)
        File = $file
        Extension = $extension
        IsHidden = $isHidden
        IsSystem = $isSystem
      }}) | Out-Null
    }}

    # Phase 2 (parallelizable): the expensive per-file work - ZIP protection probe,
    # owner/ACL read, content read, SHA256 - as a PURE function (no shared state),
    # so a runspace-pool worker can run it and return an identical record object.
    function Build-DspmFileRecord($file, $extension, $isHidden, $isSystem) {{
      $zipProtection = if ($extension -eq ".zip") {{ Test-DspmZipProtection $file.FullName }} else {{ [PSCustomObject]@{{ protected = $false; content_status = ""; protection_type = ""; scan_error = "" }} }}
      # The owner and DACL in one read of the security descriptor (FileInfo.GetAccessControl:
      # a tenth of Get-Acl's cost), and a read that failed says so - "no permissions" and
      # "permissions not read" are different answers.
      $aclFields = $null
      if ({read_owner_value} -or {read_acl_value}) {{
        $dspmSd = $null
        $aclError = ""
        try {{
          if ($file -is [System.IO.FileInfo]) {{ $dspmSd = $file.GetAccessControl($dspmAclSections) }}
          else {{ $dspmSd = Get-Acl -LiteralPath $file.FullName -ErrorAction Stop }}
        }} catch {{
          $aclError = Get-DspmAclErrorName $_
          if ($aclError -ne "access_denied") {{
            try {{ $dspmSd = Get-Acl -LiteralPath $file.FullName -ErrorAction Stop; $aclError = "" }} catch {{ $aclError = Get-DspmAclErrorName $_ }}
          }}
        }}
        if ($dspmSd) {{
          $aclFields = ConvertTo-DspmAclFields $dspmSd {read_acl_value}
        }} else {{
          $aclFields = [ordered]@{{ acl_state = "failed"; acl_error = $aclError }}
        }}
      }}
      $content = ""
      $contentStatus = ""
      $contentTruncated = $false
      $textHash = ""
      if ({read_content_value} -and ($textExtensions -contains $extension)) {{
        $textRead = Read-DspmTextFile $file.FullName {int(max_read_bytes)} ({hash_files_value} -and $file.Length -le {int(max_read_bytes)})
        $content = [string]$textRead.text
        $textHash = [string]$textRead.sha256
      }} elseif ({read_content_value} -and ($binaryExtensions -contains $extension)) {{
        if ($file.Length -gt {document_cap}) {{
          # Over the document cap: not read at all (W2.2) - said, not an error.
          $contentStatus = "over_size_cap"
        }} else {{
          $extracted = Read-BinaryText $file.FullName $extension {int(max_read_bytes)}
          $content = [string]$extracted.text
          $contentStatus = [string]$extracted.status
          $contentTruncated = [bool]$extracted.truncated
        }}
      }}
      $sha256 = ""
      $hashSkipped = $false
      if ({hash_files_value}) {{
        # Read whole for its content - a text file within the cap, a document whose text
        # was extracted - is named by its whole-file hash. A document the endpoint has no
        # extractor for (a PDF: not_extracted) was not read, and is named by the policy's
        # identity (W2.2) rather than read whole only to hash it.
        $readWhole = ({read_content_value}) -and (
          (($textExtensions -contains $extension) -and $file.Length -le {int(max_read_bytes)}) -or
          (($binaryExtensions -contains $extension) -and $file.Length -le {document_cap} -and $contentStatus -ne "not_extracted"))
        if ($textHash) {{
          $sha256 = $textHash
        }} elseif ({whole_hash_value} -or $readWhole) {{
          try {{
            $sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName -ErrorAction Stop).Hash.ToLowerInvariant()
          }} catch {{
            $sha256 = ""
          }}
        }} else {{
          $hashSkipped = $true
        }}
      }}
      return [PSCustomObject]@{{
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
        hash_skipped = $hashSkipped
        protected = [bool]$zipProtection.protected
        content_status = if ($zipProtection.content_status) {{ $zipProtection.content_status }} elseif ($contentStatus) {{ $contentStatus }} else {{ "" }}
        content_scannable = if ($zipProtection.protected) {{ $false }} else {{ $null }}
        protection_type = if ($zipProtection.protection_type) {{ $zipProtection.protection_type }} else {{ "" }}
        scan_error = if ($zipProtection.scan_error) {{ $zipProtection.scan_error }} else {{ "" }}
        # The ACL as collectors.acl_powershell sends it: owner and owner SID, per entry the
        # principal, SID, mask, allow/deny, inherited and inheritance flags, the DACL's
        # protection and whether the read worked. Rights names are rendered from the mask
        # by the console, not sent.
        acl_fields = $aclFields
        content = $content
        scan_completeness = if ((($textExtensions -contains $extension) -and $content -and $file.Length -gt {int(max_read_bytes)}) -or ($content -and $contentTruncated)) {{ "PARTIAL" }} elseif ($content -or $file.Length -eq 0) {{ "FULL" }} else {{ "NONE" }}
        bytes_scanned = if ($content) {{ [Math]::Min([int64]$file.Length, [int64]{int(max_read_bytes)}) }} else {{ 0 }}
        total_bytes = $file.Length
        truncated = [bool](($content -and ($file.Length -gt {int(max_read_bytes)})) -or ($content -and $contentTruncated))
      }}
    }}

    function Walk-DspmDirectory($root, $current, $depth) {{
      if ({depth_limit} -ge 0 -and $depth -gt {depth_limit}) {{
        $diagnostics.not_entered_depth += 1
        return
      }}
      if (Test-DspmSkippedPath $current) {{
        $diagnostics.skipped_dirs += 1
        $diagnostics.not_entered_system += 1
        return
      }}
      if ($depth -eq 0) {{
        $scopeReason = Get-DspmScopeFolderReason $current
        if ($scopeReason) {{
          Add-DspmScopeCount $diagnostics.scope_skipped_folders_by $scopeReason
          return
        }}
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
            $diagnostics.not_entered_system += 1
            continue
          }}
          if ($dirHidden -and -not ({include_hidden_value} -or {hidden_filter_value})) {{
            $diagnostics.skipped_dirs += 1
            continue
          }}
          $scopeReason = Get-DspmScopeFolderReason $entry.FullName
          if ($scopeReason) {{
            Add-DspmScopeCount $diagnostics.scope_skipped_folders_by $scopeReason
            continue
          }}
          Walk-DspmDirectory $root $entry.FullName ($depth + 1)
          continue
        }}
        Add-DspmFileRecord $entry $root
      }}
    }}

    }}
    . $dspmEngine

    # ---- W1.3 page mode: one level of the page's folders, in ordinal case-insensitive
    # name order, at most page_size file records and max_folders folders. A folder cut
    # short is handed on with the last name listed ("after"); the folders not reached are
    # handed on as they came. Subfolders met are returned for the backend's frontier. ----
    $dspmPageFolders = New-Object System.Collections.Generic.List[object]
    $dspmPageRest = New-Object System.Collections.Generic.List[object]
    function Read-DspmPageFolder($spec, $pageSize) {{
      $current = [string]$spec.path
      $depth = [int]$spec.depth
      $after = [string]$spec.after
      if ({depth_limit} -ge 0 -and $depth -gt {depth_limit}) {{
        $diagnostics.not_entered_depth += 1
        return $null
      }}
      if (Test-DspmSkippedPath $current) {{
        $diagnostics.skipped_dirs += 1
        $diagnostics.not_entered_system += 1
        return $null
      }}
      if ($depth -eq 0 -and -not $after) {{
        $scopeReason = Get-DspmScopeFolderReason $current
        if ($scopeReason) {{
          Add-DspmScopeCount $diagnostics.scope_skipped_folders_by $scopeReason
          return $null
        }}
      }}
      # W5: the folder's entries from .NET, every one (hidden and system too, as -Force):
      # the FileSystem provider took 156 ms for a folder of 1,321 that .NET lists in 17.
      $entries = @()
      try {{
        $entries = @(([IO.DirectoryInfo]::new($current)).GetFileSystemInfos())
      }} catch {{
        if ($diagnostics.unreadable_dirs.Count -lt 20) {{
          $dspmReason = if ($_.Exception.InnerException) {{ $_.Exception.InnerException.Message }} else {{ $_.Exception.Message }}
          $diagnostics.unreadable_dirs += "$($current): $dspmReason"
        }}
      }}
      if ($entries.Count -eq 0) {{ return $null }}
      $dspmKeys = [string[]]@($entries | ForEach-Object {{ [string]$_.Name }})
      $dspmSorted = [object[]]$entries
      [Array]::Sort($dspmKeys, $dspmSorted, [StringComparer]::OrdinalIgnoreCase)
      foreach ($entry in $dspmSorted) {{
        if ($after -and [StringComparer]::OrdinalIgnoreCase.Compare([string]$entry.Name, $after) -le 0) {{ continue }}
        if ($entry -is [IO.DirectoryInfo]) {{
          $dirHidden = [bool]($entry.Attributes -band [IO.FileAttributes]::Hidden)
          $dirReparse = [bool]($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)
          if ($dirReparse -or (Test-DspmSkippedPath $entry.FullName) -or ($dirHidden -and -not ({include_hidden_value} -or {hidden_filter_value}))) {{
            $diagnostics.skipped_dirs += 1
            if (-not $dirReparse -and (Test-DspmSkippedPath $entry.FullName)) {{ $diagnostics.not_entered_system += 1 }}
            continue
          }}
          $scopeReason = Get-DspmScopeFolderReason $entry.FullName
          if ($scopeReason) {{
            Add-DspmScopeCount $diagnostics.scope_skipped_folders_by $scopeReason
            continue
          }}
          if ({depth_limit} -lt 0 -or ($depth + 1) -le {depth_limit}) {{
            $dspmPageFolders.Add([PSCustomObject]@{{ path = $entry.FullName; depth = ($depth + 1); after = ""; root = $false }}) | Out-Null
          }} else {{
            $diagnostics.not_entered_depth += 1
          }}
          continue
        }}
        Add-DspmFileRecord $entry $current
        if ($records.Count -ge $pageSize) {{
          return [PSCustomObject]@{{ path = $current; depth = $depth; after = [string]$entry.Name; root = $false }}
        }}
      }}
      return $null
    }}
    if ({page_mode_value}) {{
      $dspmPage = ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{encoded_page}")))
      $dspmPageSize = [Math]::Max(1, [int]$dspmPage.page_size)
      $dspmMaxFolders = [Math]::Max(1, [int]$dspmPage.max_folders)
      $dspmListed = 0
      $dspmStopped = $false
      foreach ($spec in @($dspmPage.folders)) {{
        if ($dspmStopped -or $dspmListed -ge $dspmMaxFolders) {{
          $dspmPageRest.Add($spec) | Out-Null
          continue
        }}
        $dspmFolders = @()
        if ([bool]$spec.root) {{
          $resolvedRoots = @(Resolve-DspmRoot ([string]$spec.path))
          if (-not $resolvedRoots -or $resolvedRoots.Count -eq 0) {{
            $diagnostics.missing_roots += [string]$spec.path
            continue
          }}
          foreach ($root in $resolvedRoots) {{
            $diagnostics.resolved_roots += $root
            $rootItem = Get-Item -LiteralPath $root -ErrorAction SilentlyContinue
            if ($rootItem -and -not $rootItem.PSIsContainer) {{
              Add-DspmFileRecord $rootItem $root
            }} elseif ($rootItem) {{
              $dspmFolders += [PSCustomObject]@{{ path = $root; depth = 0; after = ""; root = $false }}
            }}
          }}
        }} else {{
          $dspmFolders = @($spec)
        }}
        foreach ($folder in $dspmFolders) {{
          if ($dspmStopped -or $dspmListed -ge $dspmMaxFolders) {{
            $dspmPageRest.Add($folder) | Out-Null
            continue
          }}
          $dspmListed += 1
          $handOn = Read-DspmPageFolder $folder $dspmPageSize
          if ($handOn) {{
            $dspmPageRest.Add($handOn) | Out-Null
            $dspmStopped = $true
          }}
        }}
      }}
      $targetPaths = @()
    }}

    # ---- Phase 1: serial enumeration walk (metadata only) - deterministic order,
    # filters, and the record cap. Populates $records with archive-entry records +
    # ordered $null placeholders, and $workItems with the per-file work to run. ----
    foreach ($requestedRoot in $targetPaths) {{
      # W5: a content command names files by their full paths - one FileInfo each. The
      # general path below asked the provider three times a file (Test-Path, then Get-Item
      # twice), about 7 ms a file; and Get-Item without -Force returns nothing for a hidden
      # file, so a hidden file the listing included never came back with its content.
      $dspmPath = [string]$requestedRoot
      if ($dspmPath -and -not $dspmPath.StartsWith("__DSPM_") -and [IO.Path]::IsPathRooted($dspmPath)) {{
        $dspmInfo = $null
        try {{ $dspmInfo = [IO.FileInfo]::new($dspmPath) }} catch {{ $dspmInfo = $null }}
        if ($dspmInfo -and $dspmInfo.Exists) {{
          $diagnostics.resolved_roots += $dspmPath
          Add-DspmFileRecord $dspmInfo $dspmPath
          continue
        }}
      }}
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

    # ---- Phase 2: fill each reserved slot with the expensive per-file work.
    # Parallel across a runspace pool on real fan-out (the engine is dot-sourced
    # once per pooled runspace, then reused); results are written back by their
    # reserved index, so output order is identical to the serial path. ----
    $dspmMaxWorkers = if ({page_mode_value}) {{ 1 }} else {{ {parallel_workers_value} }}
    if ($dspmMaxWorkers -gt 1 -and $workItems.Count -gt 1) {{
      $engineSrc = $dspmEngine.ToString()
      # Worker params are dspm-namespaced: dot-sourcing the engine runs its
      # top-level config init, which assigns common names like $item - those must
      # NOT clobber the worker's own arguments. Passed to AddScript as a STRING so
      # it compiles in the target runspace (no cross-runspace scriptblock affinity).
      $dspmWorkerText = @'
param($dspmSrc, $dspmItem)
if (-not (Test-Path Function:\\Build-DspmFileRecord)) {{ . ([scriptblock]::Create($dspmSrc)) }}
[PSCustomObject]@{{ Index = $dspmItem.Index; Record = (Build-DspmFileRecord $dspmItem.File $dspmItem.Extension $dspmItem.IsHidden $dspmItem.IsSystem) }}
'@
      $pool = [runspacefactory]::CreateRunspacePool(1, $dspmMaxWorkers)
      $pool.Open()
      $jobs = New-Object System.Collections.Generic.List[object]
      foreach ($workItem in $workItems) {{
        $psInstance = [powershell]::Create()
        $psInstance.RunspacePool = $pool
        [void]$psInstance.AddScript($dspmWorkerText).AddArgument($engineSrc).AddArgument($workItem)
        $jobs.Add([PSCustomObject]@{{ ps = $psInstance; handle = $psInstance.BeginInvoke() }}) | Out-Null
      }}
      foreach ($job in $jobs) {{
        try {{
          $completed = $job.ps.EndInvoke($job.handle)
          foreach ($entry in @($completed)) {{
            if ($entry -and $null -ne $entry.Record) {{ $records[$entry.Index] = $entry.Record }}
          }}
        }} catch {{
          if ($diagnostics.worker_errors.Count -lt 20) {{ $diagnostics.worker_errors += [string]$_.Exception.Message }}
        }} finally {{
          $job.ps.Dispose()
        }}
      }}
      $pool.Close()
      $pool.Dispose()
      $diagnostics.io_parallel_active = $true
    }} else {{
      foreach ($item in $workItems) {{
        $records[$item.Index] = Build-DspmFileRecord $item.File $item.Extension $item.IsHidden $item.IsSystem
      }}
      $diagnostics.io_parallel_active = $false
    }}
    $diagnostics.parallel_workers = $dspmMaxWorkers
    $diagnostics.extension_histogram = $extensionHistogram
    $dspmJson = [PSCustomObject]@{{
      records = @($records.ToArray() | Where-Object {{ $null -ne $_ }})
      diagnostics = $diagnostics
      folders = @($dspmPageFolders.ToArray())
      continuation = @($dspmPageRest.ToArray())
    }} | ConvertTo-Json -Depth 6 -Compress
    $dspmResponse = $dspmJson
    $dspmResponseStream = $null
    $dspmResponseGzip = $null
    try {{
      $dspmResponseBytes = [Text.Encoding]::UTF8.GetBytes($dspmJson)
      $dspmResponseStream = New-Object IO.MemoryStream
      $dspmResponseGzip = New-Object IO.Compression.GZipStream(
        $dspmResponseStream,
        [IO.Compression.CompressionMode]::Compress,
        $true
      )
      $dspmResponseGzip.Write($dspmResponseBytes, 0, $dspmResponseBytes.Length)
      $dspmResponseGzip.Dispose()
      $dspmResponseGzip = $null
      $dspmResponse = "DSPM-GZIP-BASE64-V1:" + [Convert]::ToBase64String($dspmResponseStream.ToArray())
    }} catch {{
      # Compatibility fallback: a target that cannot create the compressor still
      # returns the exact legacy JSON rather than failing an otherwise-good scan.
      $dspmResponse = $dspmJson
    }} finally {{
      if ($dspmResponseGzip) {{ $dspmResponseGzip.Dispose() }}
      if ($dspmResponseStream) {{ $dspmResponseStream.Dispose() }}
    }}
    [Console]::Out.Write($dspmResponse)
    """


def _activation_script(payload: dict, collector_ip: str = "") -> str:
    # H1: the password must NOT be part of `payload` - it would be base64'd into
    # the script and land on the powershell.exe command line. The caller passes
    # it via the child env block (DSPM_ACTIVATION_PW); this script reads it from
    # $env:DSPM_ACTIVATION_PW below. host/username/domain are non-secret
    # operational identifiers and stay in the encoded payload.
    payload = {key: value for key, value in payload.items() if key != "password"}
    encoded_payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    # M10/M11 (0.3): shared hardened config - no LocalAccountTokenFilterPolicy,
    # firewall scoped to Domain/Private + the collector, source filter pinned to
    # the collector when known.
    remote_script = (
        '\n    $ProgressPreference = "SilentlyContinue"'
        '\n    $ErrorActionPreference = "SilentlyContinue"'
        + _winrm_hardening_config_ps(collector_ip)
    )
    encoded_remote = base64.b64encode(remote_script.encode("utf-16le")).decode("ascii")
    remote_command = f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded_remote}"
    active_port = _winrm_active_port()
    return f"""
    $ProgressPreference = "SilentlyContinue"
    $ErrorActionPreference = "Stop"
    $activePort = {active_port}
    $payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{encoded_payload}"))
    $payload = ConvertFrom-Json $payloadJson
    $securePassword = ConvertTo-SecureString ([string]$env:DSPM_ACTIVATION_PW) -AsPlainText -Force
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
        $async = $client.BeginConnect(([string]$payload.host), $activePort, $null, $null)
        $portOpen = $async.AsyncWaitHandle.WaitOne(5000, $false)
        if ($portOpen) {{ $client.EndConnect($async) }}
        $client.Close()
      }} catch {{
        $portOpen = $false
      }}
    }}
    $message = if ($portOpen) {{
      "Activation command sent and WinRM port $activePort is reachable."
    }} elseif ($serviceState -eq "Running") {{
      "WinRM service is running on the target, but port $activePort is not reachable from the DSPM server. Check target firewall/GPO, network ACLs, or endpoint security blocking inbound TCP $activePort."
    }} elseif ($serviceQueryError) {{
      "Activation command was sent, but WinRM port $activePort is not reachable. WMI service check also failed: $serviceQueryError"
    }} else {{
      "Activation command was sent, but WinRM service state is '$serviceState' and port $activePort is not reachable. Verify the credential has local administrator rights and target policy allows remote service changes."
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


def _decode_scan_response(output: bytes | str) -> tuple[bytes, dict]:
    """Decode the P3 scan frame while retaining legacy plain-JSON support."""

    raw = output.encode("utf-8") if isinstance(output, str) else bytes(output)
    framed = raw.strip()
    wire_bytes = len(framed)
    if not framed.startswith(WINRM_GZIP_RESPONSE_PREFIX):
        return raw, {
            "response_encoding": "json",
            "response_wire_bytes": wire_bytes,
            "response_json_bytes": wire_bytes,
            "response_compressed_bytes": 0,
            "response_compression_ratio": 1.0,
        }

    encoded = framed[len(WINRM_GZIP_RESPONSE_PREFIX):]
    limit = _winrm_response_max_bytes()
    compressed_overhead = max(1024 * 1024, limit // 100)
    max_encoded = ((limit + compressed_overhead) * 4 + 2) // 3
    if not encoded or len(encoded) > max_encoded:
        raise ValueError("Compressed WinRM scan response exceeds the configured size limit")
    try:
        compressed = base64.b64decode(encoded, validate=True)
        with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as archive:
            decoded = archive.read(limit + 1)
    except (binascii.Error, EOFError, OSError) as exc:
        raise ValueError("Invalid compressed WinRM scan response") from exc
    if len(decoded) > limit:
        raise ValueError("Decompressed WinRM scan response exceeds the configured size limit")
    try:
        decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Compressed WinRM scan response is not valid UTF-8 JSON") from exc
    return decoded, {
        "response_encoding": "gzip+base64",
        "response_wire_bytes": wire_bytes,
        "response_json_bytes": len(decoded),
        "response_compressed_bytes": len(compressed),
        "response_compression_ratio": round(len(decoded) / max(wire_bytes, 1), 3),
    }


def _access_verdict(is_admin: bool, readable: int, total: int, temp_writable: bool) -> str:
    if not temp_writable:
        return ("This account cannot write to its own temp directory on the target, which the "
                "scan needs to stage file content. Check the profile is not mandatory or roaming-blocked.")
    if is_admin:
        return (f"This account is a local administrator, so it can read all {total} profiles. "
                "A scan does not need administrator: an account in Remote Management Users with "
                "read access to the folders you scan is enough.")
    if total and readable == total:
        return f"This account is not an administrator and can already read all {total} profiles."
    if readable:
        return (f"This account is not an administrator and can read {readable} of {total} profiles. "
                "That is enough to scan those; the rest need a read grant on their folders.")
    return ("This account is not an administrator and cannot read any user profile. It can still scan "
            "paths you grant it read access to.")


def _read_json(output: bytes | str) -> object | None:
    """Decode a possibly-compressed response frame, then parse it."""
    output, _ = _decode_scan_response(output)
    return _parse_json_text(output)


_CONTROL_TO_SPACE = {code: " " for code in range(32)}


def _parse_json_text(output: bytes | str) -> object | None:
    """Parse already-decoded (plain JSON) collector output."""
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else str(output)
    text = text.strip()
    if not text:
        return None
    # A control character the endpoint's JSON carries raw becomes a space - by a translate
    # table (W5), not a Python generator over every character: a 16 MiB content batch spent
    # seconds here, a fifth of an endpoint scan's main thread.
    text = text.translate(_CONTROL_TO_SPACE)
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
