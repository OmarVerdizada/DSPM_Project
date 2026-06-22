from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.winrm_endpoint_scanner import WinRMEndpointConfig, WinRMEndpointScanner, _scan_script


def main() -> int:
    parser = argparse.ArgumentParser(description="Dump raw WinRM scan stdout for parser diagnostics.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--domain", default="WORKGROUP")
    parser.add_argument("--username", required=True)
    parser.add_argument("--target-username", required=True)
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--inspect-archives", action="store_true")
    args = parser.parse_args()

    password = getpass.getpass("Password: ")
    config = WinRMEndpointConfig(
        host=args.host,
        username=args.username,
        password=password,
        domain=args.domain,
        target_username=args.target_username,
        paths=["downloads"],
        max_depth=args.depth,
        read_content=True,
        inspect_archives=args.inspect_archives,
        include_hidden=True,
        include_system=False,
        extension_filter_enabled=False,
    )
    scanner = WinRMEndpointScanner(config)
    script = _scan_script(
        scanner._target_paths(),
        max_depth=config.max_depth,
        read_content=config.read_content,
        max_read_bytes=config.max_read_bytes,
        allowed_extensions=[],
        extension_filter_enabled=False,
        include_hidden=True,
        include_system=False,
        hidden_filter_enabled=False,
        system_filter_enabled=False,
        read_acl=False,
        inspect_archives=args.inspect_archives,
    )
    result = scanner._run_ps_file(script)
    stdout = result.std_out.decode("utf-8", errors="replace") if isinstance(result.std_out, bytes) else str(result.std_out)
    stderr = result.std_err.decode("utf-8", errors="replace") if isinstance(result.std_err, bytes) else str(result.std_err)
    print(f"STATUS={result.status_code}")
    print(f"STDOUT_LEN={len(stdout)}")
    print(f"STDERR_LEN={len(stderr)}")
    try:
        parsed = json.loads(stdout.strip())
        records = parsed.get("records") if isinstance(parsed, dict) else []
        print(f"JSON_PARSE=ok records={len(records) if isinstance(records, list) else 'not-list'}")
    except json.JSONDecodeError as exc:
        print(f"JSON_PARSE=failed {type(exc).__name__}: {exc}")
        start = max(0, exc.pos - 500)
        end = min(len(stdout), exc.pos + 500)
        print("JSON_ERROR_CONTEXT_START")
        print(repr(stdout[start:end]))
        print("JSON_ERROR_CONTEXT_END")
    except Exception as exc:
        print(f"JSON_PARSE=failed {type(exc).__name__}: {exc}")
    print("STDOUT_HEAD_START")
    print(stdout[:5000])
    print("STDOUT_HEAD_END")
    print("STDOUT_TAIL_START")
    print(stdout[-5000:])
    print("STDOUT_TAIL_END")
    if stderr.strip():
        print("STDERR_START")
        print(stderr[:5000])
        print("STDERR_END")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
