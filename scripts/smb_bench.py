"""The product's SMB scan against a synthetic file server, with the network modelled.

    python scripts/smb_bench.py [--files 3000] [--rtt-ms 0.5] [--mib-s 110] [--json OUT]

The scan is the product's partitioned SMB scan (start_partitioned_scan + continue: the share
plan, the units, the single-pass reads, analysis, the ledger, finalize). Only the SMB session
is replaced: a connection serving a synthetic tree whose file bytes are generated on demand
(nothing on disk), which counts what a real server would be asked and sleeps for it -
``--rtt-ms`` per request round trip (pysmb: a create, one 64 KiB read per round trip, a close
for every retrieveFileFromOffset; one round trip per 400 entries of a listing) and
``--mib-s`` for the bytes (1 GbE is ~110 MiB/s). The sleeps release the interpreter, so the
scan's I/O parallelism behaves as it would against a server - EXTRAPOLATED: a real server's
latency and throughput are UNVERIFIED. ACL reads go through the product's own cache and
batching with the PowerShell processes stubbed and counted - the console modelled is one that
cannot read the share's ACLs in-process, which is when they are processes (on a real server,
Get-Acl over UNC from this host): ``acl_batches`` batch processes, ``acl_single_processes``
per-file ones, ``acl_cache_hits`` reads the batches had already answered.

Reports: wall time, files, MiB read, files/s and MiB/s, the scanner's CPU, peak RSS, and the
protocol counts - listings, opens (retrieveFileFromOffset calls), 64 KiB reads, round trips,
modelled network seconds, ACL batch calls and paths.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import random
import shutil
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

READ_SIZE = 64 * 1024
LISTING_PAGE = 400
LINES = (
    "quarterly report for the north region, figures attached\n",
    "contact jane.doe@corp.example.com about the renewal\n",
    "employee 4471 salary 91000 ssn 123-45-6789\n",
    "meeting notes: budget review, travel, offsite\n",
    "card 4111 1111 1111 1111 exp 09/29 cvv 123\n",
    "plain text with nothing sensitive in it at all\n",
)


def _block(seed: int) -> bytes:
    rng = random.Random(seed)
    return "".join(rng.choice(LINES) for _ in range(400)).encode("utf-8")


class Tree:
    """share -> folder -> [(name, size)]: a file server's shape, its bytes generated."""

    def __init__(self, files: int, seed: int = 5) -> None:
        rng = random.Random(seed)
        self.shares = {"Finance": {}, "HR": {}, "Projects": {}}
        self.sizes: dict[tuple[str, str], int] = {}
        shapes = ((".txt", 4_000, 600_000), (".csv", 200_000, 40_000_000), (".log", 20_000, 3_000_000),
                  (".docx", 30_000, 3_000_000), (".pdf", 50_000, 6_000_000), (".jpg", 50_000, 4_000_000))
        weights = (40, 8, 10, 15, 17, 10)
        for index in range(files):
            share = list(self.shares)[index % 3]
            # About 25 files a folder, as a department share holds them.
            folder = f"/dept{(index // 300) % 12:02d}/team{(index // 25) % 37:02d}"
            ext, low, high = rng.choices(shapes, weights)[0]
            size = int(min(high, max(low, rng.lognormvariate(0, 1.2) * low)))
            name = f"file{index:05d}{ext}"
            self.shares[share].setdefault(folder, []).append((name, size))
            self.sizes[(share, f"{folder}/{name}")] = size
        self.blocks = [_block(seed) for seed in range(8)]

    def bytes_of(self, share: str, path: str, offset: int, length: int) -> bytes:
        size = self.sizes[(share, path)]
        end = min(size, offset + length)
        block = self.blocks[int(hashlib.md5(path.encode()).hexdigest(), 16) % len(self.blocks)]
        out = bytearray()
        position = offset
        while position < end:
            start = position % len(block)
            take = min(end - position, len(block) - start)
            out += block[start:start + take]
            position += take
        return bytes(out)


class Meter:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.counts = {"listings": 0, "listing_round_trips": 0, "opens": 0, "reads": 0, "bytes": 0,
                       "round_trips": 0, "network_seconds": 0.0, "acl_batches": 0, "acl_paths": 0,
                       "acl_single_processes": 0, "acl_cache_hits": 0}

    def add(self, **values) -> None:
        with self.lock:
            for key, value in values.items():
                self.counts[key] += value


class Entry:
    def __init__(self, name: str, size: int = 0, is_dir: bool = False) -> None:
        self.filename = name
        self.isDirectory = is_dir
        self.isHidden = False
        self.isSystem = False
        self.isReadOnly = False
        self.file_size = size
        self.alloc_size = size
        self.create_time = 1_751_000_000.0
        self.last_write_time = 1_751_500_000.0
        self.last_access_time = 1_751_500_000.0
        self.file_attributes = 0x10 if is_dir else 0x20
        self.file_id = hash((name, size)) & 0xFFFFFFFF


class Share:
    """What pysmb's listShares gives: a disk share's name."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.type = 0
        self.isSpecial = False
        self.comments = ""


class Connection:
    def __init__(self, tree: Tree, meter: Meter, rtt: float, bandwidth: float) -> None:
        self.tree, self.meter, self.rtt, self.bandwidth = tree, meter, rtt, bandwidth

    def _wait(self, round_trips: int, data: int) -> None:
        seconds = round_trips * self.rtt + (data / self.bandwidth if self.bandwidth else 0.0)
        self.meter.add(round_trips=round_trips, network_seconds=seconds)
        if seconds:
            time.sleep(seconds)

    def listShares(self, *_args, **_kwargs):
        self._wait(2, 0)
        return [Share(name) for name in self.tree.shares]

    def listPath(self, share: str, folder: str, *_args, **_kwargs):
        folders = self.tree.shares.get(share)
        if folders is None:
            raise Exception(f"Failed to list {folder} on {share}: Unable to open directory")
        prefix = "" if folder in ("", "/") else folder.rstrip("/")
        entries = [Entry(".", is_dir=True), Entry("..", is_dir=True)]
        seen: set[str] = set()
        for path, files in folders.items():
            if path == prefix:
                entries.extend(Entry(name, size) for name, size in files)
            elif path.startswith(prefix + "/"):
                head = path[len(prefix) + 1:].split("/", 1)[0]
                if head not in seen:
                    seen.add(head)
                    entries.append(Entry(head, is_dir=True))
        pages = 2 + max(1, -(-len(entries) // LISTING_PAGE))  # open, the pages, close
        self.meter.add(listings=1, listing_round_trips=pages)
        self._wait(pages, len(entries) * 120)
        return entries

    def getAttributes(self, share: str, path: str, *_args, **_kwargs):
        size = self.tree.sizes.get((share, path), 0)
        self._wait(2, 0)
        return Entry(path.rsplit("/", 1)[-1], size)

    def retrieveFileFromOffset(self, share: str, path: str, buffer, offset: int = 0, max_length: int = -1, **_kwargs):
        size = self.tree.sizes[(share, path)]
        end = size if max_length is None or max_length < 0 else min(size, offset + max_length)
        length = max(0, end - offset)
        reads = max(1, -(-length // READ_SIZE))
        self.meter.add(opens=1, reads=reads, bytes=length)
        self._wait(2 + reads, length)  # create, the reads, close
        position = offset
        while position < end:
            take = min(1024 * 1024, end - position)
            buffer.write(self.tree.bytes_of(share, path, position, take))
            position += take
        return 0, length

    def close(self) -> None:
        return None


def measure(args) -> dict:
    import psutil

    from backend import partitioned_scan, store
    from collectors.smb_scanner import SMBScanner
    from discovery.discovery_engine import ScanConfig
    from discovery.parallelism import reset_host_admission_budget

    tree = Tree(args.files)
    meter = Meter()
    acl = {"owner": "CORP\\owner", "principals": ["CORP\\owner", "Everyone"], "permissions": ["FullControl", "Read"]}

    def connect(scanner) -> bool:
        scanner.connection = Connection(tree, meter, args.rtt_ms / 1000.0, args.mib_s * 1048576)
        scanner.server_used = "fs"
        return True

    def acl_batch(_self, _share, paths):
        meter.add(acl_batches=1, acl_paths=len(paths))
        return {path: dict(acl) for path in paths}

    def acl_one(self, share, path):
        # What the real _acl_for_path does first: the cache the batches filled. A miss is a
        # PowerShell process of its own on a real server.
        unc = self._unc_path(share, path)
        with self._acl_lock:
            cached = self._acl_cache.get(unc)
        if cached is not None:
            meter.add(acl_cache_hits=1)
            return cached
        meter.add(acl_single_processes=1, acl_paths=1)
        value = dict(acl)
        with self._acl_lock:
            self._acl_cache[unc] = value
        return value

    def no_inproc(_self, _unc_path):
        return None

    restore = [(SMBScanner, name, getattr(SMBScanner, name))
               for name in ("connect", "_acl_batch_for_paths", "_acl_for_path", "_acl_inproc")]
    SMBScanner.connect = connect
    SMBScanner._acl_batch_for_paths = acl_batch
    SMBScanner._acl_for_path = acl_one
    SMBScanner._acl_inproc = no_inproc
    reset_host_admission_budget(args.io_workers)
    tenant = f"smbbench-{uuid.uuid4().hex[:6]}"
    store.create_tenant(tenant, "SMB bench")
    config = ScanConfig(tenant_id=tenant, server="fs", username="svc", password="", domain="CORP", max_depth=8,
                        persistent_cache_enabled=False, incremental_enabled=True, max_workers=2,
                        cache_dir=str(Path(os.environ["DSPM_SCAN_CACHE_DIR"]) / "smb"))
    process = psutil.Process()
    stop = threading.Event()
    peak = [process.memory_info().rss]

    def sample() -> None:
        while not stop.wait(0.25):
            peak[0] = max(peak[0], process.memory_info().rss)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    cpu_before = process.cpu_times()
    started = time.perf_counter()
    try:
        record = partitioned_scan.start_partitioned_scan(
            tenant, config, request={"server": "fs", "username": "svc", "domain": "CORP"}, scan_label="fileserver")
        compact = partitioned_scan.continue_partitioned_scan(tenant, record["scan_id"], config)
        elapsed = time.perf_counter() - started
    finally:
        stop.set()
        for owner, name, real in restore:
            setattr(owner, name, real)
        reset_host_admission_budget()
    cpu_after = process.cpu_times()
    report = store.read_scan_report(tenant, compact["scan_id"]) or {}
    files = int((report.get("summary") or {}).get("total_files") or 0)
    findings = sum(len(item.get("findings") or []) for item in report.get("files") or [])
    store.delete_tenant_with_data(tenant)
    counts = dict(meter.counts)
    return {
        "files": files, "seconds": round(elapsed, 1), "files_per_second": round(files / max(elapsed, 0.001), 1),
        "mib_read": round(counts["bytes"] / 1048576, 1),
        "mib_per_second": round(counts["bytes"] / 1048576 / max(elapsed, 0.001), 2),
        "findings": findings,
        "scanner_cpu_seconds": round((cpu_after.user + cpu_after.system) - (cpu_before.user + cpu_before.system), 1),
        "peak_rss_mib": round(peak[0] / 1048576, 1),
        **{key: (round(value, 1) if isinstance(value, float) else value) for key, value in counts.items()},
        "opens_per_file": round(counts["opens"] / max(files, 1), 2),
        "round_trips_per_file": round(counts["round_trips"] / max(files, 1), 1),
        "acl_processes_per_file": round((counts["acl_batches"] + counts["acl_single_processes"]) / max(files, 1), 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--files", type=int, default=3000)
    parser.add_argument("--rtt-ms", type=float, default=0.5)
    parser.add_argument("--mib-s", type=float, default=110.0)
    parser.add_argument("--io-workers", type=int, default=8)
    parser.add_argument("--json", help="write the result here")
    args = parser.parse_args()
    scratch = Path(tempfile.mkdtemp(prefix="smbbench-"))
    if not os.getenv("DSPM_DB_URL"):
        os.environ["DSPM_DB_PATH"] = str(scratch / "bench.sqlite")
    for name in ("DSPM_ARTIFACT_DIR", "DSPM_SCAN_CACHE_DIR", "DSPM_REPORT_DIR", "DSPM_BACKUP_DIR"):
        os.environ[name] = str(scratch / name.lower())
    os.environ.setdefault("DSPM_SMB_ACL_BATCH", "1")
    try:
        result = measure(args)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    print(json.dumps(result))
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
