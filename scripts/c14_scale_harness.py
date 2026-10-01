"""C14 scale harness: the measurements the scale gate is decided on, and the guard that
keeps them from filling a host's disk.

    python scripts/c14_scale_harness.py --files 200000 --root D:\\SentroScale --dashboard   # the gate
    python scripts/c14_scale_harness.py --files 200000 --plan-only                           # what it needs
    python scripts/c14_scale_harness.py --files 200000 --allow-below-reserve-mb 500 --dashboard

For one corpus it runs four scans, each in its own child process so the whole process tree
can be measured:

  full           an unpartitioned full scan, saved as the console saves it
  partitioned    the same corpus as a partitioned scan, the product's partition size
  incremental    the partitioned scan again, unchanged, with the persistent cache on
  compliance     an unpartitioned full scan with PCI DSS and GDPR

and records for each: wall time, files per second, and the peak COMBINED working set of
the scanning process and every child (detector pool, partition workers) - plus, with
--dashboard, the serving backend - sampled every 250 ms from the OS; and the database,
cache and artifact growth. Parity: the partitioned scan must report the same files and
the same findings per file as the unpartitioned one, no file twice and no finding id
twice. With --dashboard a real `main.py serve` answers /api/executive-dashboard and
/api/inventory/facets idle and then throughout the partitioned scan, and both latencies
are recorded.

Disk guard: before writing anything it projects the space the run needs and refuses unless
the volume keeps max(10 GiB, 20% of its size) free afterwards - the reserve the product
owner set. The projection starts from the quality audit's measured first-scan cost
(157 KB a file, four saved scans, a quarter again for margin). On a host already below its
reserve, --allow-below-reserve-mb N permits a bounded measurement instead: a 200-file
calibration run measures what a file really costs on this host, and the largest corpus
whose projected footprint stays within N MB (and 15% of what is free) is run. The report
then says HELD FOR SCALE HOST and projects to the requested size; a bounded run is never
reported as the gate. Everything written is removed at the end unless --keep.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GIB = 1024 ** 3
MIB = 1024 ** 2
# The quality audit measured 116-157 KB of database, cache and artifacts per file on a
# first scan. The harness saves four scans of the corpus; the projection uses the top of
# the range for each, and a quarter again for margin.
AUDIT_STATE_BYTES_PER_FILE_PER_SCAN = 157 * 1024
SAVED_SCANS = 4
MARGIN = 1.25
FREE_SHARE_CAP = 0.15
CALIBRATION_FILES = 200
GATE_FILES = 200_000
# backend.partitioned_scan.partition_max_files()'s default (DSPM_PARTITION_MAX_FILES); a
# test holds the two equal. Read here without importing the product, which would open a database.
PRODUCT_PARTITION_MAX_FILES = 2000
GATE_PEAK_BYTES = 2 * GIB
# The harness's own bound for "responsive": a console view answers within 2 s at the 95th
# percentile while a scan runs, and never fails. Stated here so a reader can disagree with it.
DASHBOARD_P95_BOUND_MS = 2000.0
MODES = (("full", "c14-full"), ("partitioned", "default"), ("incremental", "default"), ("compliance", "c14-comp"))

_TEMPLATES = (
    "Customer record {i}\nname: Ana Mammadova\nemail: user{i}@example.com\ncard: 4111 1111 1111 1111\n"
    "notes: quarterly summary for account {i}\n",
    "Payroll line {i}\nemployee id {i}\niban: DE89 3704 0044 0532 0130 00\nphone: +994 50 123 45 {j:02d}\n",
    "Meeting notes {i}\nagenda: roadmap, hiring, office move\nnothing sensitive here, only planning text.\n" * 3,
    "Server inventory {i}\nhost: srv{i}.corp.example\nowner: it-ops\nsupport contract until 2027\n",
)


# ---- the disk guard ----------------------------------------------------------------
def reserve_bytes(total: int) -> int:
    """What the volume must keep free: 10 GiB or a fifth of it, whichever is greater."""
    return max(10 * GIB, int(total * 0.20))


def corpus_bytes_per_file() -> int:
    # the text, and the cluster each small file occupies at least
    return sum(len(t.format(i=99999, j=99)) for t in _TEMPLATES) // len(_TEMPLATES) + 4096


def projected_bytes(files: int, state_bytes_per_file: int) -> int:
    return int((files * corpus_bytes_per_file() + files * state_bytes_per_file) * MARGIN)


def plan(files: int, root: Path, state_bytes_per_file: int | None = None) -> dict:
    measured = state_bytes_per_file is not None
    per_file = state_bytes_per_file if measured else AUDIT_STATE_BYTES_PER_FILE_PER_SCAN * SAVED_SCANS
    anchor = root if root.exists() else Path(root.anchor or Path.cwd().anchor)
    usage = shutil.disk_usage(anchor)
    projected = projected_bytes(files, per_file)
    reserve = reserve_bytes(usage.total)
    return {"files": files, "volume": str(Path(anchor).anchor), "total_gib": round(usage.total / GIB, 1),
            "free_gib": round(usage.free / GIB, 2), "reserve_gib": round(reserve / GIB, 2),
            "state_bytes_per_file": per_file, "basis": "measured on this host" if measured else "quality audit",
            "projected_gib": round(projected / GIB, 3), "free_after_gib": round((usage.free - projected) / GIB, 2),
            "within_reserve": usage.free - projected >= reserve, "projected_bytes": projected,
            "free_bytes": usage.free}


def bounded_cap(free_bytes: int, allow_mb: int) -> int:
    """The most a run below the reserve may write: what was allowed, and never more than
    a small share of what is left."""
    return max(0, min(allow_mb * MIB, int(free_bytes * FREE_SHARE_CAP)))


def largest_safe_files(state_bytes_per_file: int, cap: int, *, step: int = 500, ceiling: int | None = None) -> int:
    """The largest corpus, in whole steps, whose projected footprint fits under `cap`."""
    per_file = (corpus_bytes_per_file() + state_bytes_per_file) * MARGIN
    files = int(cap // per_file) // step * step
    return min(files, ceiling) if ceiling else files


# ---- the process-tree sampler (Windows, no dependencies) -----------------------------
if sys.platform == "win32":
    from ctypes import wintypes

    class _PMC(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

    class _PE32(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_char * 260)]


def _process_parents() -> dict[int, int]:
    kernel = ctypes.windll.kernel32
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snapshot = kernel.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    entry = _PE32()
    entry.dwSize = ctypes.sizeof(_PE32)
    parents: dict[int, int] = {}
    try:
        ok = kernel.Process32First(snapshot, ctypes.byref(entry))
        while ok:
            parents[entry.th32ProcessID] = entry.th32ParentProcessID
            ok = kernel.Process32Next(snapshot, ctypes.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)
    return parents


def working_set(pid: int) -> int:
    kernel, psapi = ctypes.windll.kernel32, ctypes.windll.psapi
    kernel.OpenProcess.restype = wintypes.HANDLE
    handle = kernel.OpenProcess(0x1000 | 0x0010, False, pid)  # QUERY_LIMITED_INFORMATION | VM_READ
    if not handle:
        return 0
    try:
        counters = _PMC()
        counters.cb = ctypes.sizeof(_PMC)
        if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return int(counters.WorkingSetSize)
        return 0
    finally:
        kernel.CloseHandle(handle)


def tree(root_pid: int) -> list[int]:
    """The process and every descendant alive now."""
    parents = _process_parents()
    members = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if parent in members and pid not in members and pid != parent:
                members.add(pid)
                changed = True
    return sorted(pid for pid in members if pid in parents)


class Sampler(threading.Thread):
    """The peak of the SUM of every tree's working set, sampled together, and each tree's own peak.

    `peak` is the scan's: once `marker` exists the scan has finished and the child is reading
    its report back for the parity checks - work the product does not do - so from then on
    only `peak_with_verification` moves."""

    def __init__(self, roots: dict[str, int], interval: float = 0.25, marker: Path | None = None) -> None:
        super().__init__(daemon=True)
        self.roots, self.interval, self.marker = roots, interval, marker
        self.peak, self.peak_processes, self.samples, self.peak_with_verification = 0, 0, 0, 0
        self.peak_by_root = {name: 0 for name in roots}
        self._halt = threading.Event()

    def sample(self) -> None:
        scanning = self.marker is None or not self.marker.exists()
        combined, processes, sizes = 0, 0, {}
        for name, pid in self.roots.items():
            members = tree(pid)
            sizes[name] = sum(working_set(member) for member in members)
            combined += sizes[name]
            processes += len(members)
        self.peak_with_verification = max(self.peak_with_verification, combined)
        if scanning:
            for name, size in sizes.items():
                self.peak_by_root[name] = max(self.peak_by_root[name], size)
            if combined > self.peak:
                self.peak, self.peak_processes = combined, processes
        self.samples += 1

    def run(self) -> None:
        while not self._halt.is_set():
            self.sample()
            self._halt.wait(self.interval)

    def stop(self) -> None:
        self._halt.set()
        self.join()


# ---- the corpus and the runs ---------------------------------------------------------
def write_corpus(folder: Path, files: int) -> int:
    written = 0
    for index in range(files):
        sub = folder / f"dept{index % 50:02d}" / f"team{index % 7}"
        sub.mkdir(parents=True, exist_ok=True)
        text = _TEMPLATES[index % len(_TEMPLATES)].format(i=index, j=index % 100)
        (sub / f"doc{index:06d}.txt").write_text(text, encoding="utf-8")
        written += len(text)
    return written


def folder_bytes(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file()) if path.exists() else 0


def state_bytes(state: Path) -> int:
    return folder_bytes(state) - folder_bytes(state / "keys")


def run_one_scan(mode: str, tenant: str, corpus: str) -> dict:
    """In the child process: one scan of the corpus, and what it reported."""
    sys.path.insert(0, str(ROOT))
    from backend import store
    from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

    try:
        store.create_tenant(tenant, tenant)
    except Exception:  # the tenant exists (default, or the incremental rerun)
        pass
    # walk_local_path is the engine's switch for walking local_path (the name is
    # historical); off, a local scan collects nothing - and "the corpus was scanned" says so.
    config = ScanConfig(tenant_id=tenant, local_path=corpus, walk_local_path=True,
                        persistent_cache_enabled=mode in ("partitioned", "incremental"),
                        cache_dir=os.environ["C14_CACHE"], incremental_enabled=mode == "incremental",
                        compliance_enabled=mode == "compliance",
                        compliance_frameworks=["pci_dss", "gdpr"] if mode == "compliance" else [])
    started = time.perf_counter()
    if mode in ("partitioned", "incremental"):
        from backend import partitioned_scan

        budget = int(os.environ.get("C14_PARTITION") or 0) or None
        compact = partitioned_scan.run_partitioned_scan(tenant, config, max_files=budget)
        if compact is None:
            raise SystemExit("the planner did not partition the corpus")
        report = store.read_scan_report(tenant, compact["scan_id"]) or {}
    else:
        report = DSPMDiscoveryEngine(config).run().to_dict()
        report["scan_id"] = f"{mode}-{tenant}"
        store.save_scan_history(tenant, report)
    seconds = time.perf_counter() - started
    if os.environ.get("C14_PHASE_FILE"):
        # the scan and its save are done; what follows is the harness reading the report back
        Path(os.environ["C14_PHASE_FILE"]).touch()
    files = report.get("files") or []
    paths = [str(item.get("path") or item.get("full_path") or "") for item in files]
    finding_ids = [str(finding.get("finding_id")) for item in files for finding in item.get("findings") or []
                   if finding.get("finding_id")]
    per_file = sorted((path, tuple(sorted((str(finding.get("type")), int(finding.get("count") or 1))
                                          for finding in item.get("findings") or [])))
                      for path, item in zip(paths, files))
    diagnostics = report.get("scan_diagnostics") or {}
    return {"mode": mode, "tenant": tenant, "seconds": round(seconds, 2), "files": len(files),
            "findings": sum(len(item.get("findings") or []) for item in files),
            "digest": hashlib.sha256(json.dumps(per_file).encode()).hexdigest(),
            "duplicate_files": len(paths) - len(set(paths)),
            "duplicate_finding_ids": len(finding_ids) - len(set(finding_ids)),
            "cache_reused_files": diagnostics.get("cache_reused_files"),
            "content_reads": (diagnostics.get("incremental") or {}).get("content_reads"),
            "partitions": (diagnostics.get("partitioned") or {}).get("partitions")}


class DashboardProbe(threading.Thread):
    """Reads the console's two heaviest views through a real server."""

    PATHS = ("/api/executive-dashboard", "/api/inventory/facets")

    def __init__(self, port: int, token: str) -> None:
        super().__init__(daemon=True)
        self.port, self.token = port, token
        self.latencies: dict[str, list[float]] = {path: [] for path in self.PATHS}
        self.errors = 0
        self._halt = threading.Event()

    def once(self) -> None:
        for path in self.PATHS:
            request = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}",
                                             headers={"Authorization": f"Bearer {self.token}"})
            started = time.perf_counter()
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    response.read()
                self.latencies[path].append(time.perf_counter() - started)
            except Exception:
                self.errors += 1

    def run(self) -> None:
        while not self._halt.is_set():
            self.once()
            self._halt.wait(0.5)

    def stop(self) -> None:
        self._halt.set()
        self.join()

    def summary(self) -> dict:
        out: dict = {"errors": self.errors}
        for path, values in self.latencies.items():
            if values:
                ordered = sorted(values)
                out[path] = {"requests": len(values), "p50_ms": round(statistics.median(ordered) * 1000, 1),
                             "p95_ms": round(ordered[max(0, -(-len(ordered) * 95 // 100) - 1)] * 1000, 1),
                             "max_ms": round(ordered[-1] * 1000, 1)}
        return out


def run_mode(mode: str, tenant: str, corpus: Path, env: dict, server: subprocess.Popen | None = None,
             probe_token: str | None = None, port: int | None = None) -> dict:
    marker = Path(env["C14_CACHE"]).parent / f"scanned-{mode}"
    marker.unlink(missing_ok=True)
    process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--run-mode", mode, tenant, str(corpus)],
                               env=dict(env, C14_PHASE_FILE=str(marker)), cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    roots = {"scan": process.pid}
    if server is not None:
        roots["backend"] = server.pid
    sampler = Sampler(roots, marker=marker)
    sampler.start()
    probe = DashboardProbe(port, probe_token) if (probe_token and port) else None
    if probe is not None:
        probe.start()
    out, err = process.communicate()
    sampler.stop()
    if probe is not None:
        probe.stop()
    line = next((line for line in out.splitlines() if line.startswith("C14RESULT ")), None)
    if process.returncode != 0 or line is None:
        raise SystemExit(f"{mode} run failed ({process.returncode}): {err[-1500:]}")
    result = json.loads(line[len("C14RESULT "):])
    marker.unlink(missing_ok=True)
    result.update({"peak_combined_mib": round(sampler.peak / MIB, 1), "peak_processes": sampler.peak_processes,
                   "peak_with_verification_mib": round(sampler.peak_with_verification / MIB, 1),
                   "peak_by_tree_mib": {name: round(value / MIB, 1) for name, value in sampler.peak_by_root.items()},
                   "samples": sampler.samples,
                   "files_per_second": round(result["files"] / max(result["seconds"], 0.001), 1)})
    if probe is not None:
        result["dashboard_under_scan"] = probe.summary()
    return result


def _harness_env(state: Path, partition: int | None) -> dict:
    env = {key: value for key, value in os.environ.items() if not key.startswith("DSPM_")}
    env.update({"C14_CACHE": str(state / "cache"), "C14_PARTITION": str(partition or ""),
                "DSPM_DB_PATH": str(state / "dspm.sqlite"), "DSPM_ARTIFACT_DIR": str(state / "artifacts"),
                "DSPM_SCAN_CACHE_DIR": str(state / "cache"), "DSPM_ENV": "local",
                "DSPM_REPORT_DIR": str(state / "reports"), "DSPM_BACKUP_DIR": str(state / "backups"),
                "DSPM_LOCAL_ARTIFACT_KEY_PATH": str(state / "keys" / "artifact"),
                "DSPM_LOCAL_JWT_SECRET_PATH": str(state / "keys" / "jwt"),
                "DSPM_LOCAL_VAULT_KEY_PATH": str(state / "keys" / "vault"),
                "DSPM_LOCAL_BACKUP_KEY_PATH": str(state / "keys" / "backup"),
                "DSPM_LOCAL_EVIDENCE_KEY_PATH": str(state / "keys" / "evidence"),
                # a throwaway install's own administrator; never typed, never printed
                "DSPM_DEV_ADMIN_PASSWORD": "C14-harness-" + hashlib.sha256(os.urandom(16)).hexdigest()[:16] + "9q"})
    return env


def _start_server(env: dict) -> tuple[subprocess.Popen, int, str]:
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = subprocess.Popen([sys.executable, str(ROOT / "main.py"), "serve", "--host", "127.0.0.1", "--port", str(port)],
                              env=env, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 180
    while True:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/ready", timeout=3) as response:
                if response.status == 200:
                    break
        except Exception:
            pass
        if time.monotonic() > deadline:
            server.terminate()
            raise SystemExit("the backend did not become ready")
        time.sleep(1)
    minted = subprocess.run([sys.executable, "-c",
                             "import sys; sys.path.insert(0, sys.argv[1]); from backend.security import create_token; "
                             "print(create_token('admin', 'admin', 'default', mfa_verified=True))", str(ROOT)],
                            env=env, cwd=ROOT, capture_output=True, text=True, check=True)
    return server, port, minted.stdout.strip().splitlines()[-1]


def partition_size(files: int, requested: int | None) -> tuple[int, str]:
    """The partition size a run uses: what was asked, else the product's - unless that would
    leave the corpus in one piece, which is no partitioned scan at all."""
    size = requested or PRODUCT_PARTITION_MAX_FILES
    if files > size:
        return size, "requested" if requested else "the product default"
    return max(1, files // 4), f"a quarter of the corpus: {size} would not split {files} files"


def parity(files: int, by_mode: dict) -> dict:
    """The partitioned scan against the unpartitioned one, and the unchanged rerun against both."""
    full, part, inc = by_mode["full"], by_mode["partitioned"], by_mode["incremental"]
    return {
        "the corpus was scanned": full["files"] == files,
        "partitioned reports the same files": part["files"] == full["files"],
        "partitioned reports the same findings per file": part["digest"] == full["digest"],
        "no finding lost or added": part["findings"] == full["findings"],
        "no file twice": part["duplicate_files"] == 0 and full["duplicate_files"] == 0,
        "no finding id twice": part["duplicate_finding_ids"] == 0,
        "unchanged incremental gives the same answer": inc["digest"] == part["digest"],
        "unchanged incremental reads no file again": inc["cache_reused_files"] == files and not inc["content_reads"],
    }


def measure(files: int, root: Path, partition: int | None, dashboard: bool, keep: bool) -> dict:
    """Write a corpus of `files` files under `root`, run the four scans, measure, clean up."""
    work = root / f"c14-{files}-{os.getpid()}"
    corpus, state = work / "corpus", work / "state"
    state.mkdir(parents=True, exist_ok=True)
    partition, why = partition_size(files, partition)
    result: dict = {"files": files, "partition_max_files": partition, "partition_size_is": why, "runs": []}
    server = None
    try:
        result["corpus_text_bytes"] = write_corpus(corpus, files)
        env = _harness_env(state, partition)
        token = port = None
        if dashboard:
            server, port, token = _start_server(env)
            idle = DashboardProbe(port, token)
            for _ in range(10):
                idle.once()
            result["dashboard_idle"] = idle.summary()
        for mode, tenant in MODES:
            before = state_bytes(state)
            run = run_mode(mode, tenant, corpus, env, server,
                           token if mode == "partitioned" else None, port if mode == "partitioned" else None)
            run["state_growth_bytes"] = state_bytes(state) - before
            result["runs"].append(run)
            print(json.dumps(run), flush=True)
        result["parity"] = parity(files, {run["mode"]: run for run in result["runs"]})
        db = state / "dspm.sqlite"
        result["disk"] = {"database_bytes": db.stat().st_size if db.exists() else 0,
                          "cache_bytes": folder_bytes(state / "cache"),
                          "artifact_bytes": folder_bytes(state / "artifacts"),
                          "corpus_bytes": folder_bytes(corpus), "state_bytes": state_bytes(state),
                          "state_bytes_per_file": round(state_bytes(state) / max(files, 1))}
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=30)
            except subprocess.TimeoutExpired:
                server.kill()
        if not keep:
            shutil.rmtree(work, ignore_errors=True)
    return result


def verdicts(measured: dict, requested: int) -> dict:
    """Each gate line: what was measured, and whether it can be called at the gate's size."""
    at_gate = measured["files"] >= GATE_FILES and requested >= GATE_FILES
    peak = max(run["peak_combined_mib"] for run in measured["runs"])
    under = (next(run for run in measured["runs"] if run["mode"] == "partitioned").get("dashboard_under_scan") or {})
    p95 = [under[path]["p95_ms"] for path in DashboardProbe.PATHS if path in under]
    lines = {
        "peak combined working set < 2 GiB": {"measured_mib": peak, "holds_here": peak * MIB < GATE_PEAK_BYTES},
        "parity with the unpartitioned result": {"holds_here": all(measured["parity"].values())},
        "responsive dashboard under scan": {
            "p95_ms": p95, "errors": under.get("errors"), "bound_ms": DASHBOARD_P95_BOUND_MS,
            "holds_here": bool(p95) and max(p95) <= DASHBOARD_P95_BOUND_MS and not under.get("errors"),
        } if under else {"holds_here": None, "note": "run with --dashboard"},
    }
    for line in lines.values():
        line["at_gate_size"] = at_gate
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--files", type=int, default=GATE_FILES)
    parser.add_argument("--root", type=Path, default=Path("C:/SentroScale"))
    parser.add_argument("--partition", type=int, default=None, help="files per partition (default: the product's)")
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--allow-below-reserve-mb", type=int, default=0)
    parser.add_argument("--dashboard", action="store_true")
    parser.add_argument("--json", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args(argv)

    def finish(report: dict, code: int) -> int:
        text = json.dumps(report, indent=2)
        print(text)
        if args.json:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(text + "\n", encoding="utf-8")
        return code

    if "\\appdata\\" in (str(args.root.resolve()).lower() + "\\").replace("/", "\\"):
        raise SystemExit("The corpus must not be under AppData: the collector skips it and the run would scan nothing.")
    projection = plan(args.files, args.root)
    report: dict = {"requested_files": args.files, "plan": projection, "host": {"cpus": os.cpu_count()}, "held": []}
    if projection["within_reserve"]:
        if args.plan_only:
            return finish(report, 0)
        measured = measure(args.files, args.root, args.partition, args.dashboard, args.keep)
        report.update({"measured": measured, "gate": verdicts(measured, args.files)})
        return finish(report, 0 if all(measured["parity"].values()) else 1)

    report["held"].append(
        f"HELD FOR SCALE HOST: {args.files:,} files need about {projection['projected_gib']} GiB "
        f"({projection['basis']}), and {projection['volume']} must keep {projection['reserve_gib']} GiB free; "
        f"it has {projection['free_gib']} GiB.")
    cap = bounded_cap(projection["free_bytes"], args.allow_below_reserve_mb)
    calibration_bytes = projected_bytes(CALIBRATION_FILES, projection["state_bytes_per_file"])
    if args.plan_only or not args.allow_below_reserve_mb or calibration_bytes > cap:
        if args.allow_below_reserve_mb and calibration_bytes > cap:
            report["held"].append(f"Not even the {CALIBRATION_FILES}-file calibration fits the "
                                  f"{round(cap / MIB)} MB a bounded run may write here.")
        return finish(report, 3)

    report["bounded"] = {"cap_mb": round(cap / MIB), "why": "the host is already below its reserve; this run's "
                         "projected footprint is capped, and it is a measurement, not the gate"}
    calibration = measure(CALIBRATION_FILES, args.root, args.partition, False, False)
    per_file = max(calibration["disk"]["state_bytes_per_file"], 1)
    report["calibration"] = {"files": CALIBRATION_FILES, "state_bytes_per_file": per_file,
                             "parity": calibration["parity"]}
    free_now = shutil.disk_usage(Path(projection["volume"])).free
    cap = bounded_cap(free_now, args.allow_below_reserve_mb)
    files = largest_safe_files(per_file, cap, ceiling=args.files)
    report["bounded"].update({"largest_safe_files": files, "cap_mb": round(cap / MIB)})
    measured = calibration
    if files > CALIBRATION_FILES:
        measured = measure(files, args.root, args.partition, args.dashboard, args.keep)
    report["measured"] = measured
    report["gate"] = verdicts(measured, args.files)
    report["plan_at_requested_size"] = plan(args.files, args.root, per_file)
    by_mode = {run["mode"]: run for run in measured["runs"]}
    report["projection_to_requested_size"] = {
        "files": args.files,
        "state_gib": round(measured["disk"]["state_bytes_per_file"] * args.files / GIB, 2),
        **{f"{mode}_hours": round(run["seconds"] / measured["files"] * args.files / 3600, 2)
           for mode, run in by_mode.items()},
        "note": "a linear projection from the bounded run; the peak at "
                f"{args.files:,} files is what the scale host must measure",
    }
    if measured is not calibration:
        # The unpartitioned scans hold the whole estate, so their scan-process peak grows with
        # it: the slope between the calibration and the measured run, carried to the requested
        # size. A partitioned scan's peak follows its partition size, not the corpus, so no
        # slope is drawn for it - two different partition sizes would make one up.
        before = {run["mode"]: run for run in calibration["runs"]}
        slopes = {}
        for mode in ("full", "compliance"):
            grew = by_mode[mode]["peak_by_tree_mib"]["scan"] - before[mode]["peak_by_tree_mib"]["scan"]
            per_file = grew / max(measured["files"] - CALIBRATION_FILES, 1)
            slopes[mode] = {"kib_per_file": round(per_file * 1024, 2),
                            "projected_scan_peak_gib": round((by_mode[mode]["peak_by_tree_mib"]["scan"]
                                                              + per_file * (args.files - measured["files"])) / 1024, 2)}
        report["projection_to_requested_size"]["unpartitioned_memory"] = slopes
    return finish(report, 3 if all(measured["parity"].values()) else 1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--run-mode":
        print("C14RESULT " + json.dumps(run_one_scan(*sys.argv[2:5])), flush=True)
        raise SystemExit(0)
    raise SystemExit(main())
