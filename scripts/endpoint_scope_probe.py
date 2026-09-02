from __future__ import annotations

import argparse
import getpass
import json
import multiprocessing as mp
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from pathlib import PureWindowsPath

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.winrm_endpoint_scanner import WinRMEndpointConfig, WinRMEndpointScanner


SCOPES = {
    "quick": ["desktop", "documents", "downloads"],
    "downloads": ["downloads"],
    "target_profile": ["all"],
    "all_profiles": ["all_profiles"],
    "c_drive": ["c_drive"],
    "all_fixed_drives": ["all_fixed_drives"],
}


def _profile_from_path(path: str) -> str:
    normalized = path.replace("/", "\\")
    marker = "\\Users\\"
    if marker not in normalized:
        return ""
    after_users = normalized.split(marker, 1)[1]
    return after_users.split("\\", 1)[0]


def _run_scope(queue: mp.Queue, payload: dict) -> None:
    config = WinRMEndpointConfig(**payload["config"])
    scanner = WinRMEndpointScanner(config)
    try:
        records = scanner.scan()
        extension_counts = Counter((record.get("extension") or "no extension").lower() for record in records)
        profile_counts = Counter(_profile_from_path(record.get("path", "")) or "(non-profile)" for record in records)
        samples = [
            {
                "name": record.get("name") or PureWindowsPath(record.get("path", "")).name,
                "extension": record.get("extension") or "",
                "path": record.get("path") or "",
                "size": record.get("size") or 0,
            }
            for record in records[:15]
        ]
        queue.put(
            {
                "scope": payload["scope"],
                "ok": True,
                "count": len(records),
                "extensions": dict(extension_counts.most_common(12)),
                "profiles": dict(profile_counts.most_common(12)),
                "diagnostics": scanner.last_scan_diagnostics,
                "samples": samples,
            }
        )
    except Exception as exc:
        queue.put({"scope": payload["scope"], "ok": False, "error": str(exc)})


def run_with_timeout(scope: str, config: WinRMEndpointConfig, timeout_seconds: int) -> dict:
    queue: mp.Queue = mp.Queue()
    process = mp.Process(target=_run_scope, args=(queue, {"scope": scope, "config": asdict(config)}))
    process.start()
    process.join(timeout_seconds)
    if process.is_alive():
        process.terminate()
        process.join(10)
        return {"scope": scope, "ok": False, "timeout": True, "error": f"Timed out after {timeout_seconds}s"}
    if queue.empty():
        return {"scope": scope, "ok": False, "error": f"Worker exited with code {process.exitcode}"}
    return queue.get()


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe endpoint scan scopes without storing the password.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--target-username", required=True)
    parser.add_argument("--domain", default="WORKGROUP")
    parser.add_argument("--username", required=True)
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--scope", action="append", choices=sorted(SCOPES), help="Scope to run. Can be repeated.")
    parser.add_argument("--read-acl", action="store_true")
    parser.add_argument("--inspect-archives", action="store_true")
    args = parser.parse_args()

    password = getpass.getpass("Password: ")
    scopes = args.scope or ["quick", "downloads", "target_profile", "all_profiles", "c_drive", "all_fixed_drives"]

    connection_config = WinRMEndpointConfig(
        host=args.host,
        username=args.username,
        password=password,
        domain=args.domain,
        target_username=args.target_username,
        paths=["desktop"],
        max_depth=1,
        read_content=False,
    )
    connection = WinRMEndpointScanner(connection_config).test_connection()
    print(json.dumps({"connection": connection}, indent=2))
    if not connection.get("connected"):
        return 2

    for scope in scopes:
        config = WinRMEndpointConfig(
            host=args.host,
            username=args.username,
            password=password,
            domain=args.domain,
            target_username=args.target_username,
            paths=SCOPES[scope],
            max_depth=args.depth,
            read_content=True,
            read_acl=args.read_acl,
            inspect_archives=args.inspect_archives,
            allowed_extensions=[],
            extension_filter_enabled=False,
            include_hidden=True,
            include_system=False,
            hidden_filter_enabled=False,
            system_filter_enabled=False,
        )
        result = run_with_timeout(scope, config, args.timeout)
        print(json.dumps(result, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
