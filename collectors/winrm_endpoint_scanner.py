from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import PureWindowsPath

from collectors.file_scanner import TEXT_EXTENSIONS, normalize_records


DEFAULT_PROFILE_FOLDERS = {
    "desktop": "Desktop",
    "documents": "Documents",
    "downloads": "Downloads",
}


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
    $records | ConvertTo-Json -Depth 5 -Compress
    """


def _read_json(output: bytes | str) -> object | None:
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else str(output)
    text = text.strip()
    if not text:
        return None
    return json.loads(text)


def _clean_error(output: bytes | str) -> str:
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else str(output)
    return text.strip() or "Request failed"
