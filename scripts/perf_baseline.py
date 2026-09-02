"""Performance baseline harness for the local scan path (Phase 0 item 12).

Runs a local directory scan through the discovery engine and reports throughput
and peak Python memory. The LOCAL collector path is fully measurable here; the
same harness is the basis for the SMB/WinRM/NAS endpoint-impact certification
lab, which additionally needs a representative Windows file server plus OS-level
telemetry (ETW/PerfMon, disk latency, network) that this environment cannot
provide. That larger lab remains infrastructure-blocked; this gives the local
baseline and the reusable measurement tool.

Usage:
    python scripts/perf_baseline.py [--path DIR] [--files-per-share N] [--frameworks gdpr,pci_dss]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig


def ensure_dataset(path: Path, files_per_share: int) -> None:
    if path.exists() and any(path.rglob("*")):
        return
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [sys.executable, "scripts/generate_enterprise_test_data.py",
         "--output", str(path), "--files-per-share", str(files_per_share)],
        check=True,
    )


def run_baseline(path: str, frameworks: list[str], use_cache: bool = False) -> dict:
    """Scan `path` once and return throughput/memory metrics."""
    config = ScanConfig(
        local_path=path,
        compliance_enabled=bool(frameworks),
        compliance_frameworks=frameworks,
        persistent_cache_enabled=use_cache,
    )
    tracemalloc.start()
    start = time.perf_counter()
    report = DSPMDiscoveryEngine(config).run()
    elapsed = time.perf_counter() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    files = report.summary.total_files
    total_bytes = sum(int(item.get("size") or 0) for item in report.files)
    total_mb = total_bytes / 1_000_000
    return {
        "cache": "warm" if use_cache else "cold",
        "compliance": ",".join(frameworks) if frameworks else "off",
        "files": files,
        "total_mb": round(total_mb, 3),
        "elapsed_s": round(elapsed, 3),
        "files_per_s": round(files / elapsed, 1) if elapsed else 0.0,
        "mb_per_s": round(total_mb / elapsed, 3) if elapsed else 0.0,
        "peak_python_mem_mb": round(peak / 1_000_000, 2),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Local scan performance baseline.")
    parser.add_argument("--path", default="enterprise_test_data")
    parser.add_argument("--files-per-share", type=int, default=10)
    parser.add_argument("--frameworks", default="")
    args = parser.parse_args()

    frameworks = [f.strip() for f in args.frameworks.split(",") if f.strip()]
    ensure_dataset(Path(args.path), args.files_per_share)
    result = run_baseline(args.path, frameworks, use_cache=False)

    print("\n=== Sentro local-scan performance baseline (cold) ===")
    for key, value in result.items():
        print(f"  {key:20} {value}")
    print()


if __name__ == "__main__":
    main()
