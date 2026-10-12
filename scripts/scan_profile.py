"""Where a scan's time goes, by stage: a first scan and an unchanged rescan, profiled apart.

    python scripts/scan_profile.py run [--files 4000] [--out DIR]
    python scripts/scan_profile.py split PROFILE.txt [PROFILE.txt ...]

``run`` builds the amplification probe's small corpus in a throwaway install under the
project's ``tmp/`` and runs two scans, each in a process of its own under py-spy
(``--nonblocking --rate 10``: cProfile's attribution is unreliable with the threaded
engine, and py-spy does not pause the process it samples): ``first.txt`` is the first scan,
``rescan.txt`` the unchanged rescan, both collapsed stacks with idle threads left out. It
then prints the stage split of each.

``split`` attributes each sample to the first stage, in this order, whose marker any frame
of its stack contains:

- serialisation - JSON encoding and decoding, digests, compression and encryption of records,
  wherever they run;
- finalize - folding the units and saving the scan's record;
- persist - writing a unit's rows and its baselines;
- reuse cache - writing the local findings cache and its sidecar;
- classify - the detector stage;
- walk and probe - listing, reading and the reuse probe;
- other - everything else (planning, the engine's own bookkeeping, start-up).

The stages are a partition of the samples, so they add up to the scan.
"""
from __future__ import annotations

import argparse
import collections
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

STAGES = (
    ("serialisation", ("json/encoder.py", "json/decoder.py", "dumps (json/", "loads (json/", "zlib", "gzip.py",
                       "cryptography/", "pack_json_text", "unpack_json_text", "iter_json_array",
                       "iter_report_json", "_material_digest", "encrypt", "decrypt")),
    ("finalize", ("finalize_scan", "finalize_partitioned_scan", "_finalize (backend/partitioned_scan.py")),
    ("persist", ("persist_partition", "save_scan_history", "_write_incremental_baseline",
                 "_write_normalized_rows")),
    ("reuse cache", ("_store_cached_findings", "_write_meta_sidecar", "scan_cache.py", "meta_index")),
    ("classify", ("_run_detectors", "detector_stage", "detector_pool", "classification/")),
    ("walk and probe", ("scan_directory", "file_scanner.py", "_reuse_probe", "probe_incremental_object",
                        "content_policy.py")),
)


def stage_of(stack: str) -> str:
    # The root frame is the process and its command line: never a stage. py-spy prints the
    # code objects' own paths, Windows ones with backslashes.
    stack = stack.partition(";")[2].replace("\\", "/")
    for stage, markers in STAGES:
        if any(marker in stack for marker in markers):
            return stage
    return "other"


def split(paths: list[str]) -> dict[str, dict[str, float]]:
    report = {}
    for path in paths:
        counts: collections.Counter = collections.Counter()
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            stack, _, samples = line.rpartition(" ")
            if not stack or not samples.isdigit():
                continue
            counts[stage_of(stack)] += int(samples)
        total = sum(counts.values()) or 1
        report[Path(path).stem] = {"samples": total, **{stage: round(100.0 * counts.get(stage, 0) / total, 1)
                                                         for stage in [name for name, _ in STAGES] + ["other"]}}
    return report


def _phase(state: Path, files: int, phase: str) -> int:
    """One scan in this process: the corpus is built on the first."""
    from scripts import amplification_probe as probe

    probe.isolate(state)
    from backend import store

    estate = ROOT / "tmp" / f"{state.name}-estate"
    if phase == "first":
        probe.build_small(estate, files)
        store.create_tenant("profile", "scan profile")
    data, elapsed = probe.scan("profile", estate, "profile")
    print(json.dumps({"phase": phase, "files": int((data.get("summary") or {}).get("total_files") or 0),
                      "seconds": round(elapsed, 1), "files_per_second": round(files / max(elapsed, 0.001), 1)}),
          flush=True)
    return 0


def run(files: int, out: Path) -> int:
    py_spy = shutil.which("py-spy")
    if not py_spy:
        raise SystemExit("py-spy is not installed")
    out.mkdir(parents=True, exist_ok=True)
    (ROOT / "tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="scan-profile-", dir=str(ROOT / "tmp"), ignore_cleanup_errors=True) as temp:
        state = Path(temp)
        for phase, name in (("first", "first"), ("rescan", "rescan")):
            subprocess.run([py_spy, "record", "--nonblocking", "--rate", "10", "--format", "raw",
                            "--subprocesses", "-o", str(out / f"{name}.txt"), "--",
                            sys.executable, str(Path(__file__).resolve()), "_phase", str(state), str(files), phase],
                           check=True, cwd=str(ROOT))
        shutil.rmtree(ROOT / "tmp" / f"{state.name}-estate", ignore_errors=True)
    print(json.dumps(split([str(out / "first.txt"), str(out / "rescan.txt")]), indent=1))
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "_phase":
        return _phase(Path(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=("run", "split"))
    parser.add_argument("profiles", nargs="*")
    parser.add_argument("--files", type=int, default=4000)
    parser.add_argument("--out", default=str(ROOT / "tmp" / "scan-profile"))
    args = parser.parse_args()
    if args.mode == "split":
        print(json.dumps(split(args.profiles), indent=1))
        return 0
    return run(args.files, Path(args.out))


if __name__ == "__main__":
    sys.exit(main())
