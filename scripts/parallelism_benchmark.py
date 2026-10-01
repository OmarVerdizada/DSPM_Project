"""Track P-B serial-vs-adaptive parallelism benchmark (semantic-parity gated).

Runs the REAL discovery engine over a local corpus two ways - serial
(`max_workers=1`, pipeline off) and adaptive (`max_workers=0` auto, bounded
collection->analysis pipeline on) - and reports wall-clock speedup. It fails if
the adaptive result differs from serial in findings, risk, permissions, or
sanitized preview (a faster scan that changed the answer is a bug, not a win).

Two dimensions:

* ``--latency-ms 0`` (default) measures the REAL, CPU-bound analysis-parallelism
  speedup - local disk is ~free, so this isolates the analysis pool.
* ``--latency-ms L`` MODELS network-attached storage / WAN by injecting an L-ms
  delay into each per-file collection read. This is the NAS/WAN case the
  hardware lab would measure: the adaptive pipeline overlaps analysis behind
  collection I/O (and the analysis pool drains the tail), so the win grows with
  latency. It is a MODEL, not a measurement on real NAS/WAN hardware.

    python scripts/parallelism_benchmark.py [--path enterprise_test_data] [--latency-ms 0] [--json]

Uses a throwaway database/cache and never mutates operator data.
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

from discovery.parity import accuracy_projection as _accuracy  # noqa: E402


def _install_latency(latency_ms: float) -> None:
    """Model per-file NAS/WAN read latency by delaying the local collector's
    content read. Patched at the module level, so scan_directory picks it up."""
    if latency_ms <= 0:
        return
    from collectors import file_scanner

    delay = latency_ms / 1000.0
    original = file_scanner.read_text_preview_and_sha256

    def slow(*args, **kwargs):
        time.sleep(delay)
        return original(*args, **kwargs)

    file_scanner.read_text_preview_and_sha256 = slow


def _run(make_config, db_path: Path) -> tuple[dict, float]:
    """Each run gets its OWN fresh database so no cross-scan state (occurrence
    counts, first/last-seen, asset versions) leaks from one run into the next -
    otherwise a serial-then-adaptive comparison would diff on accumulated state,
    not on the parallelism."""
    from backend import store
    from discovery.discovery_engine import DSPMDiscoveryEngine

    os.environ["DSPM_DB_PATH"] = str(db_path)
    store.DB_PATH = db_path
    store.init_db()
    store.create_tenant("pb-benchmark", "P-B benchmark")

    started = time.perf_counter()
    report = DSPMDiscoveryEngine(make_config()).run().to_dict()
    return report, time.perf_counter() - started


def _field_diffs(expected: dict, actual: dict, limit: int = 8) -> list[dict]:
    out = []
    for path in sorted(set(expected) | set(actual)):
        left, right = expected.get(path, {}), actual.get(path, {})
        fields = [f for f in sorted(set(left) | set(right)) if left.get(f) != right.get(f)]
        if fields:
            out.append({"path": path.rsplit("\\", 1)[-1], "fields": fields})
        if len(out) >= limit:
            break
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Serial vs adaptive parallelism benchmark")
    parser.add_argument("--path", default="enterprise_test_data")
    parser.add_argument("--max-depth", type=int, default=4)
    parser.add_argument("--latency-ms", type=float, default=0.0,
                        help="Model NAS/WAN by delaying each per-file read this many ms (0 = real local).")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    estate = Path(args.path).expanduser().resolve()
    if not estate.exists():
        raise SystemExit(f"Scan path does not exist: {estate}")

    # Deterministic pools: config forces serial; env auto-sizes the adaptive pool.
    os.environ.pop("DSPM_ANALYSIS_WORKERS", None)
    os.environ["DSPM_PIPELINE_ENABLED"] = "1"
    _install_latency(args.latency_ms)

    with tempfile.TemporaryDirectory(prefix="sentro-pb-benchmark-") as temp_name:
        temp_root = Path(temp_name)
        from discovery.discovery_engine import ScanConfig

        # Full, cache-free scans both times so every file is really analyzed
        # (isolates the parallelism, not incremental reuse).
        common = dict(
            tenant_id="pb-benchmark",
            local_path=str(estate),
            max_depth=args.max_depth,
            walk_local_path=True,
            persistent_cache_enabled=False,
            incremental_enabled=False,
        )
        serial, serial_s = _run(
            lambda: ScanConfig(**common, max_workers=1, pipeline_enabled=False),
            temp_root / "serial.sqlite",
        )
        adaptive, adaptive_s = _run(
            lambda: ScanConfig(**common, max_workers=0, pipeline_enabled=True),
            temp_root / "adaptive.sqlite",
        )

        expected = _accuracy(serial)
        actual = _accuracy(adaptive)
        parity = expected == actual
        if not parity:
            print(json.dumps({
                "error": "parity_regression",
                "differing_count": sum(1 for p in set(expected) | set(actual) if expected.get(p) != actual.get(p)),
                "field_diffs": _field_diffs(expected, actual),
            }, ensure_ascii=False, indent=2))
            raise SystemExit("Parity regression: adaptive result differs from serial")

        files = int((serial.get("summary") or {}).get("total_files") or 0)
        par = (adaptive.get("scan_diagnostics") or {}).get("parallelism") or {}
        pipe = (adaptive.get("scan_diagnostics") or {}).get("pipeline") or {}
        result = {
            "path": str(estate),
            "files": files,
            "latency_ms_modeled": args.latency_ms,
            "cpu_count": par.get("cpu_count"),
            "serial": {"seconds": round(serial_s, 3), "files_per_second": round(files / serial_s, 2) if serial_s else 0.0},
            "adaptive": {
                "seconds": round(adaptive_s, 3),
                "files_per_second": round(files / adaptive_s, 2) if adaptive_s else 0.0,
                "speedup": round(serial_s / adaptive_s, 2) if adaptive_s else 0.0,
                "analysis_workers_active": par.get("analysis_workers_active"),
                "pipeline_overlap_observed": pipe.get("collection_analysis_overlap"),
                "peak_in_flight": pipe.get("peak_in_flight"),
            },
            "parity_equal": parity,
        }
        print(json.dumps(result, ensure_ascii=False, indent=None if args.json else 2, sort_keys=args.json))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
