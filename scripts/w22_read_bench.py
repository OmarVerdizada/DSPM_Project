"""Bytes a local scan reads, before and after W2.2, on a synthetic estate.

    python scripts/w22_read_bench.py --root DIR [--code TREE] [--keep]

Builds (or reuses) an estate under DIR - small text files with personal data, large text
logs, large binaries (disk images), documents - and walks it twice with the collector of
the code tree given (default: this one): a first scan, then an unchanged rescan through
a reuse probe, the way a scan reuses unchanged files. For each it prints the bytes the
process read (the OS's own counter, so a tree without W2.2's counters measures the same
way), wall time, files/s, MB/s read, peak RSS growth and the coverage of the records.

Run it once with ``--code`` pointing at a checkout before W2.2 and once without to
compare. The estate takes about 1.5 GB; it is deleted at the end unless ``--keep``.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import sys
import threading
import time
import zipfile
from pathlib import Path

import psutil

SMALL_FILES = 2000
LARGE_TEXT = (10, 40 * 1024 * 1024)
BINARIES = (10, 100 * 1024 * 1024)
DOCUMENTS = 50
LINES = [
    "contact {n}@example.com about the invoice\n",
    "card 4111 1111 1111 1111 exp 09/29 for customer {n}\n",
    "quarterly budget notes, nothing sensitive {n}\n",
    "IBAN DE89370400440532013000 payroll {n}\n",
]


def build(root: Path) -> None:
    marker = root / ".built"
    if marker.exists():
        return
    rng = random.Random(7)
    for index in range(SMALL_FILES):
        folder = root / "shares" / f"dept{index % 20:02d}"
        folder.mkdir(parents=True, exist_ok=True)
        lines = "".join(LINES[(index + k) % 4].format(n=index) for k in range(rng.randint(40, 400)))
        (folder / f"note_{index:05d}.txt").write_text(lines, encoding="utf-8")
    logs = root / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    block = "".join(LINES[k % 4].format(n=k) for k in range(2000)).encode("utf-8")
    for index in range(LARGE_TEXT[0]):
        with (logs / f"app_{index:02d}.log").open("wb") as handle:
            written = 0
            while written < LARGE_TEXT[1]:
                handle.write(block)
                written += len(block)
    images = root / "images"
    images.mkdir(parents=True, exist_ok=True)
    chunk = os.urandom(1024 * 1024)
    for index in range(BINARIES[0]):
        with (images / f"vm_{index:02d}.vhdx").open("wb") as handle:
            for _ in range(BINARIES[1] // len(chunk)):
                handle.write(chunk)
    docs = root / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    for index in range(DOCUMENTS):
        with zipfile.ZipFile(docs / f"letter_{index:03d}.docx", "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            body = "".join(f"<w:p><w:r><w:t>{LINES[k % 4].format(n=index).strip()}</w:t></w:r></w:p>" for k in range(200))
            archive.writestr("word/document.xml", f'<w:document xmlns:w="w"><w:body>{body}</w:body></w:document>')
    marker.write_text("ok")


def measured(fn):
    process = psutil.Process()
    peak = [process.memory_info().rss]
    stop = threading.Event()

    def sample() -> None:
        while not stop.is_set():
            peak[0] = max(peak[0], process.memory_info().rss)
            time.sleep(0.02)

    base_rss = process.memory_info().rss
    base_read = process.io_counters().read_bytes
    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    started = time.perf_counter()
    result = fn()
    elapsed = time.perf_counter() - started
    stop.set()
    sampler.join()
    return result, elapsed, process.io_counters().read_bytes - base_read, (peak[0] - base_rss) / 1048576


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--code", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--label", default="")
    args = parser.parse_args()
    sys.path.insert(0, str(Path(args.code).resolve()))
    from unittest.mock import patch

    from collectors import file_scanner
    from discovery.incremental import reuse_snapshot_from_result

    root = Path(args.root)
    needed = 2 * 1024 ** 3
    if not (root / ".built").exists() and shutil.disk_usage(root.anchor or ".").free < needed + 2 * 1024 ** 3:
        print("refusing: not enough free disk for the estate", file=sys.stderr)
        return 3
    build(root)
    snapshots: dict[str, dict] = {}

    def probe(key: str, size: int, mtime: str):
        return snapshots.get(f"{key}|{size}|{mtime}")

    results = {}
    # The estate is under %TEMP%, which a real walk skips as a system location.
    with patch.object(file_scanner, "is_skipped_scan_path", return_value=False):
        for label, reuse in (("first scan", None), ("unchanged rescan", probe)):
            diagnostics: dict = {}
            records, elapsed, read, peak = measured(lambda reuse=reuse, diagnostics=diagnostics: [
                record.to_dict() if hasattr(record, "to_dict") else record
                for record in file_scanner.scan_directory(root, diagnostics=diagnostics, reuse_probe=reuse,
                                                          max_depth=8)])
            files = len(records)
            coverage: dict[str, int] = {}
            for record in records:
                state = record.get("content_coverage") or record.get("scan_completeness") or "?"
                coverage[state] = coverage.get(state, 0) + 1
                if reuse is None:
                    key = str(record.get("reuse_key") or record.get("path"))
                    snapshots[f"{key}|{record.get('size')}|{record.get('modified_at')}"] = (
                        reuse_snapshot_from_result(record))
            results[label] = {"files": files, "seconds": round(elapsed, 2), "files_per_s": round(files / elapsed),
                              "read_mib": round(read / 1048576, 1),
                              "read_mib_per_s": round(read / 1048576 / elapsed, 1),
                              "peak_rss_mib": round(peak, 1), "reused": diagnostics.get("reused_files", 0),
                              "coverage": coverage}
            print(f"{args.label} {label}: {json.dumps(results[label])}", flush=True)
    if not args.keep:
        shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
