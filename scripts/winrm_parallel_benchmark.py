"""Track P-B.2 - local serial-vs-parallel benchmark for the WinRM remote scan
script's in-session runspace-pool parallelism.

The WinRM transport is separable from the generated PowerShell, so this runs the
script directly with the local powershell.exe against a synthetic corpus (no
endpoint needed) and reports wall-clock at several worker counts. It also asserts
parity at each worker count - a speedup that changed the findings would be a bug,
not a win. Windows + Windows PowerShell only.

    python scripts/winrm_parallel_benchmark.py [--files N] [--workers 1,2,4,8]

Local numbers understate a real endpoint: here Get-Acl/disk are fast and local,
so the per-file work parallelized is cheaper than over a real remote session.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.file_scanner import normalize_extension_filter  # noqa: E402
from collectors.winrm_endpoint_scanner import _scan_script  # noqa: E402

_POWERSHELL = shutil.which("powershell.exe")


def build_corpus(root: str, files: int) -> None:
    shutil.rmtree(root, ignore_errors=True)
    per_dir = 20
    dirs = max(1, files // per_dir)
    made = 0
    for d in range(dirs):
        sub = os.path.join(root, f"dept{d}", "docs")
        os.makedirs(sub, exist_ok=True)
        for i in range(per_dir):
            if made >= files:
                break
            size = [50, 200, 1000, 4000][(d + i) % 4]
            with open(os.path.join(sub, f"file_{i}.txt"), "w", encoding="utf-8") as f:
                f.write(("ssn 123-45-6789 email a@b.com secret hunter2 " * 6 + "\n") * size)
            made += 1


def gen(root: str, workers: int, latency_ms: float = 0.0) -> str:
    script = _scan_script(
        [root], max_depth=8, read_content=True, max_read_bytes=1_000_000,
        allowed_extensions=sorted(normalize_extension_filter([])),
        extension_filter_enabled=False, include_hidden=True, include_system=True,
        hidden_filter_enabled=False, system_filter_enabled=False, read_acl=True,
        inspect_archives=False, hash_files=True, read_owner=True, parallel_workers=workers,
    )
    if latency_ms > 0:
        # MODEL a NAS/WAN endpoint: give the per-file work a network-round-trip
        # delay. Injected here (benchmark only) so production _scan_script stays
        # clean. This is exactly the work the runspace pool parallelizes, so
        # serial ~= N*L and parallel ~= N*L/workers - the win GROWS with latency.
        anchor = "function Build-DspmFileRecord($file, $extension, $isHidden, $isSystem) {"
        assert anchor in script, "Build-DspmFileRecord anchor not found (script shape changed)"
        script = script.replace(anchor, anchor + f"\n      Start-Sleep -Milliseconds {int(latency_ms)}", 1)
    return script


def run(script: str) -> tuple[dict, float]:
    with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8-sig") as fh:
        fh.write(script)
        path = fh.name
    try:
        t0 = time.perf_counter()
        proc = subprocess.run(
            [_POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path],
            capture_output=True, timeout=600,
        )
        elapsed = time.perf_counter() - t0
        out = proc.stdout.decode("utf-8", errors="replace").strip()
        if proc.returncode != 0:
            raise SystemExit(f"script failed rc={proc.returncode}: {proc.stderr.decode('utf-8','replace')[:500]}")
        return (json.loads(out) if out else {}), elapsed
    finally:
        os.unlink(path)


def canon(records: list[dict]) -> dict:
    out = {}
    for r in records:
        r = dict(r)
        for k in ("principals", "permissions"):
            if isinstance(r.get(k), list):
                r[k] = sorted(str(x) for x in r[k])
        out[str(r.get("path"))] = r
    return out


def main() -> int:
    if os.name != "nt" or not _POWERSHELL:
        print("SKIP: needs Windows + powershell.exe")
        return 0
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", type=int, default=200)
    ap.add_argument("--workers", default="1,2,4,8")
    ap.add_argument("--latency-ms", type=float, default=0.0,
                    help="Model a NAS/WAN endpoint by delaying each per-file work this many ms.")
    args = ap.parse_args()
    workers = [int(w) for w in args.workers.split(",") if w.strip()]

    root = os.path.join("C:\\", f"dspm_winrm_bench_{os.getpid()}")
    build_corpus(root, args.files)
    try:
        total = sum(len(fs) for _, _, fs in os.walk(root))
        model = f", modeled per-file latency {args.latency_ms:g}ms" if args.latency_ms else ""
        print(f"corpus: {total} files at {root}{model}\n")
        baseline_recs = None
        base_time = None
        print(f"{'workers':>8} {'time(s)':>9} {'speedup':>8}  parity")
        for w in workers:
            parsed, elapsed = run(gen(root, w, args.latency_ms))
            recs = parsed.get("records", [])
            if baseline_recs is None:
                baseline_recs, base_time = canon(recs), elapsed
                parity = "baseline"
            else:
                parity = "OK" if canon(recs) == baseline_recs else "MISMATCH!"
            speedup = (base_time / elapsed) if base_time else 1.0
            active = parsed.get("diagnostics", {}).get("io_parallel_active")
            print(f"{w:>8} {elapsed:>9.3f} {speedup:>7.2f}x  {parity}  (io_parallel_active={active}, records={len(recs)})")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
