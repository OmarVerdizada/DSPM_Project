"""Track P-E benchmark: single-engine scan vs a partitioned multi-process scan of
the same target, semantic-parity gated.

Local scans are collection-bound (a per-file Get-Acl subprocess), which threads
inside one process cannot parallelize past. Partitioning the namespace across
worker PROCESSES runs those collection streams concurrently. This measures the
wall-clock of one engine vs `run_partitioned`, and fails if the merged findings
differ from the single scan.

    python scripts/partition_benchmark.py [--path enterprise_test_data] [--workers 0] [--json]

Uses a throwaway database and never mutates operator data.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_VOLATILE = {
    "first_seen", "last_seen", "seen_at", "timestamp", "updated_at", "last_scanned_at",
    "detector_elapsed_ms", "detector_metrics", "incremental_scan_reason", "cache_reused",
    "incremental_reused", "sla_due", "triage_score",
}


def _semantic(value):
    if isinstance(value, dict):
        return {k: _semantic(v) for k, v in value.items() if k not in _VOLATILE}
    if isinstance(value, list):
        return [_semantic(v) for v in value]
    return value


def _accuracy(report: dict) -> dict:
    return {
        str(item.get("path") or ""): {
            "findings": _semantic(item.get("findings") or []),
            "risk": _semantic(item.get("risk") or {}),
            "permissions": _semantic(item.get("permissions") or {}),
        }
        for item in report.get("files") or []
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default="enterprise_test_data")
    ap.add_argument("--max-depth", type=int, default=4)
    ap.add_argument("--workers", type=int, default=0, help="0 = auto (~CPU-1)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    estate = Path(args.path).expanduser().resolve()
    if not estate.exists():
        raise SystemExit(f"path not found: {estate}")

    with tempfile.TemporaryDirectory(prefix="sentro-pe-benchmark-") as tmp:
        os.environ["DSPM_DB_PATH"] = str(Path(tmp) / "bench.sqlite")
        from backend import store
        from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
        from discovery.partition import plan_partitions, run_partitioned

        store.DB_PATH = Path(tmp) / "bench.sqlite"
        store.init_db()
        store.create_tenant("pe-benchmark", "P-E benchmark")

        config = ScanConfig(
            tenant_id="pe-benchmark", local_path=str(estate), max_depth=args.max_depth,
            use_sample_when_empty=True, persistent_cache_enabled=False, incremental_enabled=False,
        )
        parts = plan_partitions(config)
        if not parts:
            raise SystemExit(f"{estate} is not partitionable (needs >=2 top-level subdirs)")

        t0 = time.perf_counter()
        single = DSPMDiscoveryEngine(config).run().to_dict()
        single_s = time.perf_counter() - t0

        t0 = time.perf_counter()
        partitioned = run_partitioned(config, workers=args.workers)
        part_s = time.perf_counter() - t0

        parity = _accuracy(single) == _accuracy(partitioned)
        result = {
            "path": str(estate),
            "files": single["summary"]["total_files"],
            "partitions": len(parts),
            "worker_processes": partitioned.get("scan_diagnostics", {}).get("partitioned", {}).get("worker_processes"),
            "single": {"seconds": round(single_s, 2)},
            "partitioned": {
                "seconds": round(part_s, 2),
                "speedup": round(single_s / part_s, 2) if part_s else 0.0,
            },
            "parity_equal": parity,
            "summary_equal": single["summary"] == partitioned["summary"],
        }
        print(json.dumps(result, indent=None if args.json else 2, sort_keys=args.json))
        if not parity:
            print("PARITY MISMATCH", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
