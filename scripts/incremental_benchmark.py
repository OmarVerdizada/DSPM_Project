"""Track P-A reproducible local delta-scan benchmark.

Measures the same estate three ways:

1. explicit full scan (content/hash/owner/detectors),
2. unchanged incremental scan with the local L1 sidecar, and
3. unchanged incremental scan after deleting only that disposable L1 cache,
   proving reuse from the durable database baseline.

The benchmark uses a temporary database/cache and never mutates operator data.
It fails when the incremental results differ in findings, risk, permissions or
sanitized preview from the full scan.
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

# Track P shares one semantic-parity projection (discovery/parity.py) so the
# benchmarks and the perf gate can never drift on which fields count as "the
# result" vs per-run noise.
from discovery.parity import accuracy_projection as _accuracy_projection  # noqa: E402


def _timed_run(config) -> tuple[dict, float]:
    from discovery.discovery_engine import DSPMDiscoveryEngine

    started = time.perf_counter()
    report = DSPMDiscoveryEngine(config).run().to_dict()
    return report, time.perf_counter() - started


def _mismatch_summary(expected: dict, actual: dict) -> list[dict]:
    mismatches: list[dict] = []
    for path in sorted(set(expected) | set(actual)):
        left = expected.get(path, {})
        right = actual.get(path, {})
        fields = [field for field in sorted(set(left) | set(right)) if left.get(field) != right.get(field)]
        if fields:
            mismatches.append({
                "path": path,
                "fields": fields,
                "difference_paths": _difference_paths(left, right),
            })
        if len(mismatches) >= 20:
            break
    return mismatches


def _difference_paths(left, right, prefix: str = "", limit: int = 20) -> list[str]:
    if left == right:
        return []
    if isinstance(left, dict) and isinstance(right, dict):
        paths: list[str] = []
        for key in sorted(set(left) | set(right)):
            paths.extend(_difference_paths(left.get(key), right.get(key), f"{prefix}.{key}".strip("."), limit))
            if len(paths) >= limit:
                break
        return paths[:limit]
    if isinstance(left, list) and isinstance(right, list):
        paths = []
        if len(left) != len(right):
            paths.append(f"{prefix}.length")
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            paths.extend(_difference_paths(left_item, right_item, f"{prefix}[{index}]", limit))
            if len(paths) >= limit:
                break
        return paths[:limit]
    return [prefix or "value"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark full vs unchanged P-A delta scans")
    parser.add_argument("--path", default="enterprise_test_data")
    parser.add_argument("--max-depth", type=int, default=4)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON only")
    args = parser.parse_args()

    estate = Path(args.path).expanduser().resolve()
    if not estate.exists():
        raise SystemExit(f"Scan path does not exist: {estate}")

    with tempfile.TemporaryDirectory(prefix="sentro-pa-benchmark-") as temp_name:
        temp_root = Path(temp_name)
        os.environ["DSPM_DB_PATH"] = str(temp_root / "benchmark.sqlite")

        from backend import store
        from discovery.discovery_engine import ScanConfig
        from discovery.incremental import incremental_scope_key

        # store may already be imported by an instrumentation wrapper; pin its
        # live path as well as the environment before initializing.
        store.DB_PATH = temp_root / "benchmark.sqlite"
        store.init_db()
        tenant = "pa-benchmark"
        store.create_tenant(tenant, "P-A benchmark")
        cache_dir = temp_root / "cache"
        scope = incremental_scope_key("local", str(estate), {"max_depth": args.max_depth})

        common = dict(
            tenant_id=tenant,
            local_path=str(estate),
            max_depth=args.max_depth,
            use_sample_when_empty=True,
            persistent_cache_enabled=True,
            cache_dir=str(cache_dir),
            incremental_scope=scope,
            max_workers=1,
        )
        full, full_seconds = _timed_run(ScanConfig(**common, incremental_enabled=False))
        store.save_scan_history(tenant, full)

        probe = lambda key, size, mtime, version: store.probe_incremental_object(
            tenant, scope, key, size, mtime, version
        )
        warm_config = ScanConfig(**common, incremental_enabled=True, baseline_probe=probe)
        warm, warm_seconds = _timed_run(warm_config)

        # Remove only the disposable cache owned by this TemporaryDirectory.
        # The next pass must recover from the durable baseline.
        cache_root = cache_dir.resolve()
        if cache_root.is_relative_to(temp_root.resolve()):
            for cache_file in cache_root.glob("*"):
                if cache_file.is_file():
                    cache_file.unlink()
        durable, durable_seconds = _timed_run(warm_config)

        expected = _accuracy_projection(full)
        warm_accurate = _accuracy_projection(warm) == expected
        durable_accurate = _accuracy_projection(durable) == expected
        if not warm_accurate or not durable_accurate:
            print(json.dumps({
                "error": "accuracy_regression",
                "warm_mismatches": _mismatch_summary(expected, _accuracy_projection(warm)),
                "durable_mismatches": _mismatch_summary(expected, _accuracy_projection(durable)),
            }, ensure_ascii=False))
            raise SystemExit("Accuracy regression: incremental result differs from full scan")

        files = int((full.get("summary") or {}).get("total_files") or 0)
        metric = lambda seconds: round(files / seconds, 3) if seconds else 0.0
        result = {
            "path": str(estate),
            "files": files,
            "full": {
                "seconds": round(full_seconds, 3),
                "files_per_second": metric(full_seconds),
            },
            "warm_l1": {
                "seconds": round(warm_seconds, 3),
                "files_per_second": metric(warm_seconds),
                "speedup": round(full_seconds / warm_seconds, 2) if warm_seconds else 0.0,
                "delta_ratio": (warm.get("scan_diagnostics") or {}).get("incremental", {}).get("delta_ratio"),
                "accuracy_equal": warm_accurate,
            },
            "durable_restart": {
                "seconds": round(durable_seconds, 3),
                "files_per_second": metric(durable_seconds),
                "speedup": round(full_seconds / durable_seconds, 2) if durable_seconds else 0.0,
                "delta_ratio": (durable.get("scan_diagnostics") or {}).get("incremental", {}).get("delta_ratio"),
                "durable_baseline_hits": (durable.get("scan_diagnostics") or {}).get("incremental", {}).get("durable_baseline_hits"),
                "accuracy_equal": durable_accurate,
            },
        }
        if args.json:
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
