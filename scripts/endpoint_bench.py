"""The product's endpoint scan, measured on this host with the endpoint emulated locally.

    python scripts/endpoint_bench.py [--shape SHAPE.json] [--pngs 45000] [--rescan] [--json OUT]

An endpoint scan normally reaches a Windows machine over WinRM. Here the scan is the
product's own (``_run_endpoint_scan_payload``: the frontier pages, the content batches, the
analysis, the ledger, the finalize), and so is the collector's delivery code
(``WinRMEndpointScanner._run_ps_file_over_stdin``: the gzip+base64 script over stdin, the
reused shell, the Receive loop that counts envelopes). Only the WS-Man protocol object is
replaced: its commands start ``powershell.exe`` on THIS host, which runs the collector's real
script against a corpus under the project's ``tmp/`` (git-ignored; outside %TEMP%, which a
walk skips as a system location). So the endpoint-side work - process start, script
decode, enumeration, ACL reads, content reads, hashing, JSON, gzip, base64 - is real and
measured, on this host's CPU and disk; the network is not. The protocol object counts what
a real one would carry: commands, stdin and stdout bytes, and Receive envelopes of
``--envelope-bytes`` (153,600 is pywinrm's default request). ``--rtt-ms`` and
``--wire-mib-s`` add a modelled wire (a sleep per round trip and per byte) - EXTRAPOLATED
when used; 0 by default.

The corpus is the shape of a real workload (``--shape``: extension, size and folder depth of
each file, no names - scripts/endpoint_bench_shape.py exports one) or, without one, a
synthetic mix. Text files carry generated text with personal data up to the endpoint's read
cap and are sparse past it; documents the endpoint does not read are sparse. Disk used is
about the capped text bytes.

Reports, for the first scan and (``--rescan``) an unchanged rescan: wall time, files, bytes,
files/s and MiB/s of content inspected; CPU of this process and of the PowerShell processes;
per-core utilisation; peak RSS; disk read bytes of the PowerShell processes; commands,
envelopes and wire bytes; and the time in each stage - listing, content commands, decode,
analysis, persistence, finalize. The database is a scratch SQLite file unless
``DSPM_DB_URL`` names the disposable sentro_test.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import gzip
import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TEXT = {".txt", ".csv", ".xml", ".log", ".json", ".sql", ".rdp", ".ini", ".md", ".yaml", ".yml", ".tsv"}
# Selected types the endpoint does not read text from (documents and legacy Office): sparse.
DEFAULT_SHAPE = {"files": [
    *({"folder": 1, "depth": 2, "ext": ext, "size": size} for ext, size in
      [(".pdf", 700_000)] * 400 + [(".ppt", 9_000_000)] * 200 + [(".doc", 1_200_000)] * 150 +
      [(".txt", 600_000)] * 140 + [(".xls", 1_100_000)] * 120 + [(".xml", 260_000)] * 40 +
      [(".csv", 40_000_000)] * 30 + [(".log", 2_000_000)] * 15),
], "units": {}}
UNSELECTED = {".html": 400, ".jpg": 150, ".gz": 34, ".eps": 30, ".ps": 48, ".png": 12, ".pps": 12, ".unk": 20}


FLOOR_BYTES = 2048 * 1048576 + 512 * 1048576  # the product's disk floor, and room above it


def _kernel32():
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                         wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                         wintypes.LPVOID]
    kernel32.DeviceIoControl.restype = wintypes.BOOL
    kernel32.GetCompressedFileSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetCompressedFileSizeW.restype = wintypes.DWORD
    return kernel32


def _allocated(path: Path) -> int:
    """The bytes NTFS allocated for ``path`` (a sparse hole allocates none)."""
    from ctypes import wintypes

    high = wintypes.DWORD()
    low = _kernel32().GetCompressedFileSizeW(str(path), ctypes.byref(high))
    return (high.value << 32) | low


def _sparse(path: Path, size: int, head: bytes) -> None:
    """A file of ``size`` bytes whose first ``len(head)`` bytes are ``head`` and the rest a
    sparse hole: NTFS allocates no clusters for it. Refuses, rather than fill the disk, when
    the file system did not make it sparse."""
    if size <= len(head) + 65536:
        path.write_bytes(head + bytes(max(0, size - len(head))))
        return
    if os.name != "nt":
        raise RuntimeError("sparse files are made with NTFS's FSCTL_SET_SPARSE")
    import msvcrt
    from ctypes import wintypes

    kernel32 = _kernel32()
    kernel32.SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong),
                                          wintypes.DWORD]
    kernel32.SetFilePointerEx.restype = wintypes.BOOL
    kernel32.SetEndOfFile.argtypes = [wintypes.HANDLE]
    kernel32.SetEndOfFile.restype = wintypes.BOOL
    with open(path, "wb") as handle:
        native = msvcrt.get_osfhandle(handle.fileno())
        returned = wintypes.DWORD()
        if not kernel32.DeviceIoControl(native, 0x000900C4, None, 0, None, 0, ctypes.byref(returned), None):
            raise OSError(ctypes.get_last_error(), f"FSCTL_SET_SPARSE failed on {path}")
        handle.write(head)
        handle.flush()
        # Not handle.truncate(): the C runtime extends a file by writing zeros, which a
        # sparse file allocates. SetEndOfFile moves the end and leaves a hole.
        if not (kernel32.SetFilePointerEx(native, size, None, 0) and kernel32.SetEndOfFile(native)):
            raise OSError(ctypes.get_last_error(), f"SetEndOfFile failed on {path}")
    allocated = _allocated(path)
    if allocated > len(head) + max(1048576, size // 32):
        path.unlink()
        raise RuntimeError(f"{path} was not made sparse ({allocated} bytes allocated for {size})")


def _guard_disk(where: Path) -> None:
    free = shutil.disk_usage(where).free
    if free < FLOOR_BYTES:
        raise RuntimeError(f"stopping the corpus: {free // 1048576} MiB free, below the floor plus 512 MiB")


def _luhn(digits: str) -> str:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char) * (2 if index % 2 == 0 else 1)
        total += value - 9 if value > 9 else value
    return digits + str((10 - total % 10) % 10)


def _text(rng: random.Random, size: int, extension: str) -> bytes:
    """Generated text of about ``size`` bytes: words, with a person's data here and there."""
    words = ("report invoice quarterly budget customer meeting notes draft final review account balance "
             "shipment order contract renewal policy update summary project team schedule").split()
    lines: list[str] = []
    length = 0
    row = 0
    if extension == ".csv":
        lines.append("id,name,email,phone,city,amount,note")
    while length < size:
        row += 1
        if extension == ".csv":
            pii = rng.random() < 0.02
            line = (f"{row},Person {rng.randint(1, 99999)},"
                    f"{'user%d@example.com' % rng.randint(1, 10**6) if pii else 'n/a'},"
                    f"{'+1 555 %03d %04d' % (rng.randint(0, 999), rng.randint(0, 9999)) if pii else ''},"
                    f"City{rng.randint(1, 500)},{rng.randint(1, 99999)}.{rng.randint(0, 99):02d},"
                    f"{' '.join(rng.choice(words) for _ in range(6))}")
        else:
            line = " ".join(rng.choice(words) for _ in range(rng.randint(8, 16)))
            roll = rng.random()
            if roll < 0.01:
                line += f" contact jane.doe{rng.randint(1, 999)}@corp.example.com"
            elif roll < 0.012:
                line += f" card {_luhn('4' + ''.join(rng.choice('0123456789') for _ in range(14)))}"
            elif roll < 0.016:
                line += f" phone +1 555 {rng.randint(100, 999)} {rng.randint(1000, 9999)}"
        lines.append(line)
        length += len(line) + 1
    return ("\n".join(lines) + "\n").encode("utf-8")[:size]


def _xlsx(path: Path, rng: random.Random) -> None:
    strings = "".join(f"<si><t>customer {rng.randint(1, 9999)} jane.doe{index}@corp.example.com</t></si>"
                      for index in range(200))
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("xl/sharedStrings.xml", f"<sst>{strings}</sst>")
        archive.writestr("xl/worksheets/sheet1.xml", "<worksheet><sheetData/></worksheet>")


def build(corpus: Path, shape: dict, read_cap: int, pngs: int, seed: int = 7) -> dict:
    """The corpus for ``shape`` under ``corpus\\Desktop``; returns what it holds."""
    rng = random.Random(seed)
    desktop = corpus / "Desktop"
    if corpus.exists():
        shutil.rmtree(corpus)
    stats = {"files": 0, "bytes": 0, "text_bytes_on_disk": 0, "unselected": 0, "pngs": 0}
    folders: dict[int, Path] = {}
    for index, item in enumerate(shape["files"]):
        depth = max(1, int(item.get("depth") or 1))
        folder = folders.get(item["folder"])
        if folder is None:
            folder = desktop.joinpath(*[f"f{item['folder']}_{level}" for level in range(depth - 1)])
            folder.mkdir(parents=True, exist_ok=True)
            folders[item["folder"]] = folder
        extension, size = item["ext"], int(item["size"])
        path = folder / f"file{index:05d}{extension}"
        if index % 100 == 0:
            _guard_disk(folder)
        if extension in TEXT:
            head = _text(rng, min(size, read_cap + 4096), extension)
            _sparse(path, size, head)
            stats["text_bytes_on_disk"] += len(head)
        elif extension == ".xlsx":
            _xlsx(path, rng)
        else:
            _sparse(path, size, b"")
        stats["files"] += 1
        stats["bytes"] += size
    # Files the extension filter leaves out, beside the selected ones.
    first = next(iter(folders.values()), desktop)
    first.mkdir(parents=True, exist_ok=True)
    for extension, count in UNSELECTED.items():
        for index in range(count):
            _sparse(first / f"other{index:05d}{extension}", 64 * 1024, b"")
            stats["unselected"] += 1
    if pngs:
        images = first / "images"
        images.mkdir(parents=True, exist_ok=True)
        for index in range(pngs):
            _sparse(images / f"image{index:05d}.png", 120 * 1024, b"")
        stats["pngs"] = pngs
    return stats


class _Command:
    def __init__(self, args: list[str], meter: "_Meter") -> None:
        self.process = subprocess.Popen(["powershell.exe", *args[1:]] if args and args[0] == "powershell.exe"
                                        else args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
        self.meter = meter
        self.started = time.perf_counter()
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.done = threading.Event()
        self.cpu = 0.0
        self.read_bytes = 0
        self.lock = threading.Lock()
        self.cond = threading.Condition(self.lock)
        threading.Thread(target=self._drain, args=(self.process.stdout, self.stdout), daemon=True).start()
        threading.Thread(target=self._drain, args=(self.process.stderr, self.stderr), daemon=True).start()
        threading.Thread(target=self._watch, daemon=True).start()

    def _drain(self, stream, buffer: bytearray) -> None:
        for block in iter(lambda: stream.read1(65536) if hasattr(stream, "read1") else stream.read(65536), b""):
            with self.cond:
                buffer.extend(block)
                self.cond.notify_all()

    def _watch(self) -> None:
        import psutil

        try:
            handle = psutil.Process(self.process.pid)
            while self.process.poll() is None:
                try:
                    times = handle.cpu_times()
                    self.cpu = times.user + times.system
                    self.read_bytes = handle.io_counters().read_bytes
                except Exception:  # noqa: BLE001 - the process is ending
                    pass
                time.sleep(0.05)
        except Exception:  # noqa: BLE001 - it ended before it could be watched
            pass
        self.process.wait()
        time.sleep(0.05)
        with self.cond:
            self.done.set()
            self.cond.notify_all()


class _Meter:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.commands: list[dict] = []
        self.envelopes = 0
        self.stdin_bytes = 0
        self.stdout_bytes = 0
        self.wire_seconds = 0.0


class _Protocol:
    """The part of ``winrm.protocol.Protocol`` the collector uses, running commands here."""

    def __init__(self, meter: _Meter, envelope_bytes: int, rtt: float, wire_bytes_per_s: float) -> None:
        self.meter = meter
        # What one Receive can carry of stdout: the envelope, less the SOAP around it, base64.
        self.per_envelope = max(4096, int((envelope_bytes - 2048) * 3 / 4))
        self.rtt = rtt
        self.wire = wire_bytes_per_s
        self.commands: dict[str, _Command] = {}
        self.shells = 0

    def _trip(self, payload: int = 0) -> None:
        delay = self.rtt + (payload / self.wire if self.wire else 0.0)
        if delay:
            with self.meter.lock:
                self.meter.wire_seconds += delay
            time.sleep(delay)

    def open_shell(self, codepage=None, **_kwargs) -> str:
        self._trip()
        self.shells += 1
        return f"shell-{self.shells}"

    def close_shell(self, shell_id) -> None:
        self._trip()

    def run_command(self, shell_id, command, arguments=()) -> str:
        self._trip()
        command_id = uuid.uuid4().hex
        self.commands[command_id] = _Command([command, *arguments], self.meter)
        return command_id

    def send_command_input(self, shell_id, command_id, stdin_input, end=False) -> None:
        self._trip(len(stdin_input))
        command = self.commands[command_id]
        with self.meter.lock:
            self.meter.stdin_bytes += len(stdin_input)
        command.process.stdin.write(stdin_input if isinstance(stdin_input, bytes) else stdin_input.encode())
        if end:
            command.process.stdin.close()

    def get_command_output_raw(self, shell_id, command_id):
        command = self.commands[command_id]
        with command.cond:
            while not command.stdout and not command.done.is_set():
                command.cond.wait(20)
            chunk = bytes(command.stdout[: self.per_envelope])
            del command.stdout[: len(chunk)]
            done = command.done.is_set() and not command.stdout
            err = bytes(command.stderr) if done else b""
        self._trip(len(chunk))
        with self.meter.lock:
            self.meter.envelopes += 1
            self.meter.stdout_bytes += len(chunk)
        if done:
            with self.meter.lock:
                self.meter.commands.append({"seconds": round(time.perf_counter() - command.started, 3),
                                            "cpu_seconds": round(command.cpu, 3),
                                            "read_bytes": int(command.read_bytes)})
        return chunk, err, (command.process.returncode or 0) if done else -1, done

    def cleanup_command(self, shell_id, command_id) -> None:
        self._trip()
        command = self.commands.pop(command_id, None)
        if command is not None and command.process.poll() is None:
            command.process.kill()


class _Session:
    def __init__(self, protocol: _Protocol) -> None:
        self.protocol = protocol


class _Stages:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.seconds: dict[str, float] = {}
        self.calls: dict[str, int] = {}

    def wrap(self, owner, name: str, stage: str, pick=None):
        real = getattr(owner, name)
        stages = self

        def timed(*args, **kwargs):
            label = pick(args, kwargs) if pick else stage
            started = time.perf_counter()
            try:
                return real(*args, **kwargs)
            finally:
                with stages.lock:
                    stages.seconds[label] = stages.seconds.get(label, 0.0) + time.perf_counter() - started
                    stages.calls[label] = stages.calls.get(label, 0) + 1
        setattr(owner, name, timed)
        return real


def measure(corpus: Path, tenant: str, label: str, args) -> dict:
    import psutil

    from backend import app as app_module
    from backend import partitioned_scan, store
    from backend.security import Principal
    from collectors import winrm_endpoint_scanner as winrm

    meter = _Meter()
    protocol = _Protocol(meter, args.envelope_bytes, args.rtt_ms / 1000.0, args.wire_mib_s * 1048576)
    stages = _Stages()
    restore = []
    restore.append((winrm.WinRMEndpointScanner, "_run_with_session",
                    winrm.WinRMEndpointScanner._run_with_session))

    def run_with_session(scanner, operation):
        scanner.last_connection_host = "bench-endpoint"
        return operation(_Session(protocol))

    winrm.WinRMEndpointScanner._run_with_session = run_with_session
    restore.append((winrm.WinRMEndpointScanner, "scan", stages.wrap(
        winrm.WinRMEndpointScanner, "scan", "", pick=lambda a, k: "listing" if (k.get("page") or (len(a) > 1 and a[1]))
        else "content_commands")))
    restore.append((app_module, "_analyze_endpoint_records",
                    stages.wrap(app_module, "_analyze_endpoint_records", "analysis")))
    restore.append((winrm, "_decode_scan_response", stages.wrap(winrm, "_decode_scan_response", "decode")))
    restore.append((store, "persist_partition", stages.wrap(store, "persist_partition", "persistence")))
    restore.append((partitioned_scan, "_finalize", stages.wrap(partitioned_scan, "_finalize", "finalize")))

    process = psutil.Process()
    stop = threading.Event()
    peak = [process.memory_info().rss]
    per_core: list[list[float]] = []

    def sample() -> None:
        psutil.cpu_percent(percpu=True)
        while not stop.wait(0.5):
            peak[0] = max(peak[0], process.memory_info().rss)
            per_core.append(psutil.cpu_percent(percpu=True))

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    cpu_before = process.cpu_times()
    payload = app_module.EndpointScanRequest(
        host="bench-endpoint", username="svc_scan", credential_ref="", paths=[str(corpus / "Desktop")],
        read_content=True, read_acl=True, incremental_enabled=True, scan_label="endpoint-bench",
        extension_filter_enabled=True, allowed_extensions=sorted(args.extensions), include_hidden=True)
    principal = Principal(subject="bench", role="admin", tenant_id=tenant, auth_type="session")
    config = app_module._to_endpoint_config(payload, tenant)
    started = time.perf_counter()
    try:
        compact = app_module._run_endpoint_scan_payload(config, payload, principal)
    finally:
        elapsed = time.perf_counter() - started
        stop.set()
        sampler.join(2)
        for owner, name, real in restore:
            setattr(owner, name, real)
    cpu_after = process.cpu_times()
    report = store.read_scan_report(tenant, compact["scan_id"]) or {}
    summary = report.get("summary") or {}
    inspected = sum(int(f.get("bytes_scanned") or 0) for f in report.get("files") or [])
    files = int(summary.get("total_files") or compact.get("file_count") or 0)
    cores = [round(statistics.mean(column), 1) for column in zip(*per_core)] if per_core else []

    remote_cpu = sum(command["cpu_seconds"] for command in meter.commands)
    return {
        "scan": label, "seconds": round(elapsed, 1), "files": files,
        "content_mib": round(inspected / 1048576, 1),
        "files_per_second": round(files / max(elapsed, 0.001), 2),
        "mib_per_second": round(inspected / 1048576 / max(elapsed, 0.001), 2),
        "status": compact.get("status") or report.get("status"),
        "content_full": summary.get("content_full"), "content_partial": summary.get("content_partial"),
        "content_failed": summary.get("content_failed"), "content_metadata_only": summary.get("content_metadata_only"),
        "findings": sum(len(f.get("findings") or []) for f in report.get("files") or []),
        "scanner_cpu_seconds": round((cpu_after.user + cpu_after.system) - (cpu_before.user + cpu_before.system), 1),
        "endpoint_cpu_seconds": round(remote_cpu, 1),
        "endpoint_read_mib": round(sum(c["read_bytes"] for c in meter.commands) / 1048576, 1),
        "per_core_mean_percent": cores,
        "peak_rss_mib": round(peak[0] / 1048576, 1),
        "commands": len(meter.commands), "envelopes": meter.envelopes,
        "stdin_mib": round(meter.stdin_bytes / 1048576, 2), "stdout_mib": round(meter.stdout_bytes / 1048576, 2),
        "modelled_wire_seconds": round(meter.wire_seconds, 1),
        "command_seconds": round(sum(c["seconds"] for c in meter.commands), 1),
        "stages": {name: round(value, 1) for name, value in sorted(stages.seconds.items())},
        "stage_calls": dict(sorted(stages.calls.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--shape", help="a workload shape (scripts/endpoint_bench_shape.py)")
    parser.add_argument("--pngs", type=int, default=0, help="images the extension filter leaves out, in one folder")
    parser.add_argument("--rescan", action="store_true", help="also an unchanged rescan")
    parser.add_argument("--keep-corpus", action="store_true")
    parser.add_argument("--reuse-corpus", action="store_true", help="the corpus from a previous run, as it is")
    parser.add_argument("--work", default=str(ROOT / "tmp" / "endpoint_bench"))
    parser.add_argument("--envelope-bytes", type=int, default=153600)
    parser.add_argument("--rtt-ms", type=float, default=0.0)
    parser.add_argument("--wire-mib-s", type=float, default=0.0)
    parser.add_argument("--json", help="write the results here")
    args = parser.parse_args()
    from collectors.content_policy import text_cap_bytes  # noqa: F401 - import check

    shape = json.loads(Path(args.shape).read_text(encoding="utf-8")) if args.shape else DEFAULT_SHAPE
    args.extensions = {item["ext"] for item in shape["files"]}
    work = Path(args.work)
    corpus = work / "corpus"
    scratch = Path(tempfile.mkdtemp(prefix="epbench-"))
    if not os.getenv("DSPM_DB_URL"):
        os.environ["DSPM_DB_PATH"] = str(scratch / "bench.sqlite")
    for name in ("DSPM_ARTIFACT_DIR", "DSPM_SCAN_CACHE_DIR", "DSPM_REPORT_DIR", "DSPM_BACKUP_DIR"):
        os.environ[name] = str(scratch / name.lower())
    built = {}
    if not (args.reuse_corpus and corpus.exists()):
        started = time.perf_counter()
        from backend.app import endpoint_max_file_text_bytes

        built = build(corpus, shape, endpoint_max_file_text_bytes(), args.pngs)
        built["seconds"] = round(time.perf_counter() - started, 1)
        print(f"corpus: {json.dumps(built)}", flush=True)
    from backend import store

    tenant = f"epbench-{uuid.uuid4().hex[:6]}"
    store.create_tenant(tenant, "Endpoint bench")
    results = []
    try:
        for label in ("first scan", "unchanged rescan") if args.rescan else ("first scan",):
            result = measure(corpus, tenant, label, args)
            results.append(result)
            print(json.dumps(result), flush=True)
    finally:
        try:
            store.delete_tenant_with_data(tenant)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
            if not args.keep_corpus:
                shutil.rmtree(corpus, ignore_errors=True)
    if args.json:
        Path(args.json).write_text(json.dumps({"corpus": built, "results": results}, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
