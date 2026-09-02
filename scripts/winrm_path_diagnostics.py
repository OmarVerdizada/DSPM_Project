from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.winrm_endpoint_scanner import WinRMEndpointConfig, WinRMEndpointScanner, _read_json


def main() -> int:
    parser = argparse.ArgumentParser(description="List remote WinRM paths for endpoint scanner diagnostics.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--domain", default="WORKGROUP")
    parser.add_argument("--username", required=True)
    parser.add_argument("--target-username", required=True)
    args = parser.parse_args()

    password = getpass.getpass("Password: ")
    scanner = WinRMEndpointScanner(
        WinRMEndpointConfig(
            host=args.host,
            username=args.username,
            password=password,
            domain=args.domain,
            target_username=args.target_username,
            paths=["desktop"],
            max_depth=1,
            read_content=False,
        )
    )
    script = rf"""
    $ErrorActionPreference = "SilentlyContinue"
    function List-Path($path) {{
      $items = @()
      if (Test-Path -LiteralPath $path) {{
        $items = @(Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue | ForEach-Object {{
          [PSCustomObject]@{{
            name = $_.Name
            path = $_.FullName
            is_dir = [bool]$_.PSIsContainer
            extension = if ($_.Extension) {{ $_.Extension.ToLowerInvariant() }} else {{ "" }}
            attributes = $_.Attributes.ToString()
            size = if ($_.PSIsContainer) {{ 0 }} else {{ $_.Length }}
          }}
        }})
      }}
      [PSCustomObject]@{{ path = $path; exists = [bool](Test-Path -LiteralPath $path); count = $items.Count; items = $items }}
    }}
    $profile = "C:\Users\{args.target_username}"
    [PSCustomObject]@{{
      users = List-Path "C:\Users"
      profile = List-Path $profile
      desktop = List-Path (Join-Path $profile "Desktop")
      documents = List-Path (Join-Path $profile "Documents")
      downloads = List-Path (Join-Path $profile "Downloads")
      c_root = List-Path "C:\"
    }} | ConvertTo-Json -Depth 6 -Compress
    """
    result = scanner._run_ps(script)
    if result.status_code != 0:
        print(result.std_err)
        return 2
    data = _read_json(result.std_out)
    print(json.dumps(data, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
