"""Track P-F: consolidated, parity-gated performance regression gate.

Turns the per-track benchmarks (P-A incremental, P-B parallelism, P-C triage, P-D
detector) into ONE gate that CI/nightly can run to keep "fastest" measured and
defend it against regressions. It fails on a PARITY break or a REGRESSION.

The regression checks are RELATIVE RATIOS rather than absolute files/sec, which would
flake between a 6-core Windows box and a 2-core CI VM. Two of them — the incremental
and prefilter speedups — still compare two wall-clock measurements, so a loaded
machine can fail them with nothing regressed: those are gated HERE, in the nightly
job that owns its runner, and reported but not gated in the per-PR suite that runs
alongside everything else. Parity and the delta-ratio are counted rather than timed
and are gated in both. Absolute throughput and latency are reported for tracking (and
compared to an optional per-host baseline with a loose tolerance), not hard-gated
across hosts.

Hard gates (exit 1 on failure):
  * PARITY   — an unchanged incremental re-scan yields identical findings to the
               full scan; the detector prefilter yields identical findings to
               running every rule.
  * INCREMENTAL — an unchanged re-scan reuses ~everything (delta_ratio small) and
               is materially faster than the full scan.
  * DETECTOR — the necessary-substring prefilter is faster than running the whole
               catalog.

Reported: files/sec, time-to-first-analyzed-record, findings, delta_ratio,
speedups. `--update-baseline` rewrites the per-host tracking baseline.

    python scripts/perf_gate.py [--json] [--update-baseline] [--strict]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from discovery.parity import accuracy_projection  # noqa: E402

_BASELINE_PATH = ROOT / "docs" / "perf_gate_baseline.json"

# Gate thresholds. The delta ratio is counted; the two speedups are timed (see _evaluate).
_MAX_DELTA_RATIO = 0.05      # unchanged re-scan must reuse >= 95% from the baseline
_MIN_INCREMENTAL_SPEEDUP = 1.5
_MIN_PREFILTER_SPEEDUP = 1.3
_BASELINE_TOLERANCE = 0.40   # informational: flag if throughput drops >40% vs stored baseline


def _build_corpus(root: Path) -> None:
    """A small, deterministic, sensitive corpus — fast enough for a per-PR gate."""
    shutil.rmtree(root, ignore_errors=True)
    samples = {
        "hr/employees.csv": "name,ssn\nAlice,123-45-6789\nBob,987-65-4321\n" * 20,
        "hr/notes.md": "salary review; confidential\ncontact hr@example.com\n" * 20,
        "eng/config.json": '{"password": "hunter2value", "token": "abcdef0123456789"}\n' * 20,
        "eng/keys.txt": "AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMIbK7MDENGbPxRfi\n" * 15,
        "finance/cards.txt": "card 4111 1111 1111 1111\niban GB82WEST12345698765432\n" * 20,
        "ops/readme.txt": "the quick brown fox jumps over the lazy dog by the river\n" * 60,
    }
    for rel, content in samples.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


def _corpus_root() -> Path:
    # The local scanner skips %TEMP% on Windows (it is under \AppData\), so use a
    # drive-root path there; /tmp is fine on Linux CI.
    base = "C:\\" if os.name == "nt" else tempfile.gettempdir()
    return Path(base) / f"dspm_perf_gate_{os.getpid()}"


def _timed_run(config, capture_ttff: bool = False):
    from discovery.discovery_engine import DSPMDiscoveryEngine

    first = {"t": None}
    start = time.perf_counter()
    if capture_ttff:
        def on_progress(stage, completed, total):
            if first["t"] is None and stage in ("pipelining", "analyzing") and completed >= 1:
                first["t"] = time.perf_counter() - start
        config.progress_callback = on_progress
    report = DSPMDiscoveryEngine(config).run().to_dict()
    return report, time.perf_counter() - start, first["t"]


def _scan_metrics(root: Path) -> dict:
    """Full scan, then an unchanged incremental re-scan against the saved baseline."""
    from backend import store
    from discovery.discovery_engine import ScanConfig
    from discovery.incremental import incremental_scope_key

    tenant = "perf-gate"
    store.create_tenant(tenant, tenant)
    scope = incremental_scope_key("local", str(root), {"max_depth": 6})
    common = dict(tenant_id=tenant, local_path=str(root), max_depth=6, walk_local_path=True,
                  persistent_cache_enabled=False, incremental_scope=scope)

    full, full_s, ttff = _timed_run(ScanConfig(**common, incremental_enabled=False), capture_ttff=True)
    store.save_scan_history(tenant, full)

    probe = lambda key, size, mtime, version: store.probe_incremental_object(tenant, scope, key, size, mtime, version)
    warm, warm_s, _ = _timed_run(ScanConfig(**common, incremental_enabled=True, baseline_probe=probe))

    files = int(full["summary"]["total_files"])
    delta = (warm.get("scan_diagnostics") or {}).get("incremental", {}).get("delta_ratio")
    return {
        "files": files,
        "sensitive_files": int(full["summary"]["sensitive_files"]),
        "files_per_s": round(files / full_s, 1) if full_s else 0.0,
        "time_to_first_finding_s": round(ttff, 3) if ttff is not None else None,
        "full_s": round(full_s, 3),
        "warm_s": round(warm_s, 3),
        "incremental_speedup": round(full_s / warm_s, 2) if warm_s else 0.0,
        "delta_ratio": delta,
        "_incremental_parity": accuracy_projection(full) == accuracy_projection(warm),
    }


def _detector_metrics() -> dict:
    from classification.regex_classifier import classify_content

    prose = "the quick brown fox jumps over the lazy dog by the river. " * 3000
    n = 15

    def timed(prefilter: bool) -> float:
        t0 = time.perf_counter()
        for _ in range(n):
            classify_content(prose, _prefilter=prefilter)
        return (time.perf_counter() - t0) / n

    on = timed(True)
    off = timed(False)
    return {
        "prefilter_speedup": round(off / on, 2) if on else 0.0,
        "_prefilter_parity": classify_content(prose) == classify_content(prose, _prefilter=False),
    }


def _evaluate(metrics: dict) -> tuple[list[str], list[str]]:
    """Split the gate's verdicts into what a loaded machine cannot change and what it can.

    Parity and the delta-ratio are counted, not timed: they hold on an idle laptop and
    on a CI runner with sixteen other jobs on it. The two speedups are wall-clock
    ratios of two runs of the same work, and a machine under load does not slow both
    halves equally - measured here at 1.31x against a 1.5x bound while passing at
    8.95s vs 8.97s when run alone (roadmap M0/Q3). Those belong to the nightly job,
    which owns a runner; a flaky red in the per-PR suite teaches people to re-run it.
    """
    correctness, timing = [], []
    s = metrics["scan"]
    d = metrics["detector"]
    if not s["_incremental_parity"]:
        correctness.append("PARITY: incremental re-scan findings differ from the full scan")
    if not d["_prefilter_parity"]:
        correctness.append("PARITY: detector prefilter findings differ from the full catalog")
    if s["delta_ratio"] is None or s["delta_ratio"] > _MAX_DELTA_RATIO:
        correctness.append(f"INCREMENTAL: delta_ratio {s['delta_ratio']} > {_MAX_DELTA_RATIO} (unchanged re-scan re-read too much)")
    if s["incremental_speedup"] < _MIN_INCREMENTAL_SPEEDUP:
        timing.append(f"INCREMENTAL: speedup {s['incremental_speedup']}x < {_MIN_INCREMENTAL_SPEEDUP}x")
    if d["prefilter_speedup"] < _MIN_PREFILTER_SPEEDUP:
        timing.append(f"DETECTOR: prefilter speedup {d['prefilter_speedup']}x < {_MIN_PREFILTER_SPEEDUP}x")
    return correctness, timing


def run_gate(*, enforce_timing: bool = True) -> dict:
    root = _corpus_root()
    _build_corpus(root)
    with tempfile.TemporaryDirectory(prefix="perf-gate-db-") as tmp:
        os.environ["DSPM_DB_PATH"] = str(Path(tmp) / "gate.sqlite")
        from backend import store

        store.DB_PATH = Path(tmp) / "gate.sqlite"
        store.init_db()
        try:
            scan = _scan_metrics(root)
            detector = _detector_metrics()
        finally:
            shutil.rmtree(root, ignore_errors=True)
    metrics = {"scan": scan, "detector": detector}
    correctness, timing = _evaluate(metrics)
    metrics["correctness_failures"] = correctness
    metrics["timing_failures"] = timing
    metrics["failures"] = correctness + timing if enforce_timing else correctness
    return metrics


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--strict", action="store_true", help="also fail if throughput regressed >40%% vs the stored per-host baseline")
    args = ap.parse_args()

    metrics = run_gate()
    failures = list(metrics["failures"])

    # Informational per-host baseline comparison for absolute throughput.
    baseline = {}
    if _BASELINE_PATH.exists():
        try:
            baseline = json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            baseline = {}
    fps = metrics["scan"]["files_per_s"]
    base_fps = baseline.get("files_per_s")
    if base_fps and fps < base_fps * (1 - _BASELINE_TOLERANCE):
        msg = f"THROUGHPUT: {fps} files/s is >40% below baseline {base_fps} files/s"
        (failures if args.strict else metrics.setdefault("warnings", [])).append(msg)

    if args.update_baseline:
        _BASELINE_PATH.write_text(json.dumps({"files_per_s": fps, "prefilter_speedup": metrics["detector"]["prefilter_speedup"]}, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps({**metrics, "passed": not failures}, indent=2, default=str))
    else:
        s, d = metrics["scan"], metrics["detector"]
        print("=== Sentro performance gate ===")
        print(f"  files={s['files']} sensitive={s['sensitive_files']} throughput={s['files_per_s']} files/s TTFF={s['time_to_first_finding_s']}s")
        print(f"  incremental: delta_ratio={s['delta_ratio']} speedup={s['incremental_speedup']}x parity={s['_incremental_parity']}")
        print(f"  detector:    prefilter_speedup={d['prefilter_speedup']}x parity={d['_prefilter_parity']}")
        for w in metrics.get("warnings", []):
            print(f"  WARN {w}")
        print("  RESULT:", "PASS" if not failures else "FAIL")
        for f in failures:
            print(f"    - {f}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
