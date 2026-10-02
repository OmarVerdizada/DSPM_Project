"""C0.2: what sealing the scan cache costs, measured before it is on by default.

    python scripts/scan_cache_cost.py [--files 3000] [--repeats 3] [--json]

Builds a throwaway estate of small text files - the shape that makes the cache's
per-entry work matter most - and scans it with the cache sealed (DSPM_SCAN_CACHE_ENCRYPT=1)
and in clear (=0): a cold scan that analyses and writes every entry, then a warm rescan
that reuses every entry. Reports the median wall time of each, the bytes the cache holds,
and the per-entry cost of sealing and opening the entries the scan actually wrote.

Everything it touches is in a temporary directory - the database, the artifact key, the
estate, the cache - and is removed when it finishes. Owner lookups are stubbed, as the
suite stubs them: they cost the same in both modes and are not what is measured.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_LINES = (
    "Customer {i}: contact name{i}@example.com, phone +44 20 7946 {n:04d}",
    "Payment card on file: 4111 1111 1111 1111 exp 12/29",
    "password=Winter{n}Secret!",
    "IBAN GB82 WEST 1234 5698 7654 32",
    "Meeting notes for quarter {n}: nothing sensitive in this line at all.",
    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCY{n:06d}",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.",
)


def _estate(root: Path, count: int) -> None:
    rng = random.Random(2026)
    for index in range(count):
        folder = root / f"dept{index % 12}" / f"team{index % 7}"
        folder.mkdir(parents=True, exist_ok=True)
        lines = [rng.choice(_LINES).format(i=index, n=rng.randrange(10_000)) for _ in range(rng.randrange(3, 20))]
        (folder / f"record-{index:05d}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _bytes_under(path: Path) -> tuple[int, int]:
    files = [item for item in path.rglob("*") if item.is_file()]
    return sum(item.stat().st_size for item in files), len(files)


def _scan_twice(estate: Path, cache: Path, *, sealed: bool) -> tuple[float, float, int, int, int]:
    """One cold scan into an empty cache, then one warm rescan that must reuse every file."""
    import shutil

    from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

    os.environ["DSPM_SCAN_CACHE_ENCRYPT"] = "1" if sealed else "0"
    if cache.exists():
        shutil.rmtree(cache)
    config = dict(tenant_id="cost", local_path=str(estate), persistent_cache_enabled=True,
                  cache_dir=str(cache), max_workers=1)
    started = time.perf_counter()
    first = DSPMDiscoveryEngine(ScanConfig(**config)).run().to_dict()
    cold = time.perf_counter() - started
    started = time.perf_counter()
    second = DSPMDiscoveryEngine(ScanConfig(**config)).run().to_dict()
    warm = time.perf_counter() - started
    reused = second["scan_diagnostics"]["cache_reused_files"]
    if reused != len(first["files"]):
        raise SystemExit(f"the warm scan reused {reused} of {len(first['files'])} files")
    size, count = _bytes_under(cache)
    return cold, warm, size, count, len(first["files"])


def _measure(estate: Path, base: Path, repeats: int) -> dict[str, dict]:
    """Both modes, interleaved and in alternating order, after one discarded warm-up, so
    neither pays for the first import, the detector pool's start or a cold disk cache."""
    _scan_twice(estate, base / "cache-warmup", sealed=True)
    runs: dict[str, list] = {"plain": [], "sealed": []}
    for repeat in range(repeats):
        order = ("plain", "sealed") if repeat % 2 == 0 else ("sealed", "plain")
        for mode in order:
            runs[mode].append(_scan_twice(estate, base / f"cache-{mode}", sealed=mode == "sealed"))
    return {mode: {"cold_seconds": round(statistics.median(run[0] for run in results), 3),
                   "warm_seconds": round(statistics.median(run[1] for run in results), 3),
                   "cache_bytes": results[-1][2], "cache_files": results[-1][3], "files": results[-1][4]}
            for mode, results in runs.items()}


def _codec_cost(cache: Path) -> dict:
    """Seal and open the entries the sealed scan wrote, one at a time, in both codecs."""
    import sqlite3

    from cryptography.fernet import Fernet

    from discovery import scan_cache

    os.environ["DSPM_SCAN_CACHE_ENCRYPT"] = "1"
    codec = scan_cache.codec_from_environment()
    directory = scan_cache.tenant_cache_dir(cache, "cost")
    plaintexts = [codec.open(path.read_bytes()) for path in sorted(directory.glob("*.enc"))]
    conn = sqlite3.connect(directory / "meta_index.sqlite")
    try:
        plaintexts += [codec.open(row[0]) for row in conn.execute("SELECT payload FROM entries")]
    finally:
        conn.close()  # Windows will not remove the directory while it is open
    plaintexts = [item for item in plaintexts if item]
    result = {"entries": len(plaintexts), "mean_plaintext_bytes": round(statistics.mean(map(len, plaintexts)))}
    for name, candidate in (("sealed", scan_cache.CacheCodec(Fernet(Fernet.generate_key()))),
                            ("plain", scan_cache.CacheCodec(None))):
        started = time.perf_counter()
        stored = [candidate.seal(item) for item in plaintexts]
        sealing = time.perf_counter() - started
        started = time.perf_counter()
        for item in stored:
            candidate.open(item)
        opening = time.perf_counter() - started
        result[name] = {"seal_us_per_entry": round(sealing / len(stored) * 1e6, 1),
                        "open_us_per_entry": round(opening / len(stored) * 1e6, 1),
                        "mean_stored_bytes": round(statistics.mean(map(len, stored)))}
    return result


def _has_scan_cache() -> bool:
    """False on a build before C0.2, so the same script measures the plaintext baseline."""
    import importlib.util

    return importlib.util.find_spec("discovery.scan_cache") is not None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--files", type=int, default=3000)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sentro-cache-cost-") as temp:
        base = Path(temp)
        # Before any product import: the store converges whatever database it is pointed at.
        os.environ.update({"DSPM_DB_PATH": str(base / "cost.sqlite"), "DSPM_ARTIFACT_DIR": str(base / "artifacts"),
                           "DSPM_LOCAL_ARTIFACT_KEY_PATH": str(base / "artifact_key")})
        os.environ.pop("DSPM_DB_URL", None)
        from unittest.mock import MagicMock, patch

        from collectors import file_scanner

        estate = base / "estate"
        _estate(estate, args.files)
        with patch.object(file_scanner, "is_skipped_scan_path", return_value=False), \
                patch.object(file_scanner, "file_owner", MagicMock(return_value="cost")):
            measured = _measure(estate, base, args.repeats)
        plain, sealed = measured["plain"], measured["sealed"]
        result = {"files": args.files, "repeats": args.repeats, "plain": plain, "sealed": sealed,
                  "cold_overhead": round(sealed["cold_seconds"] / plain["cold_seconds"] - 1, 4),
                  "warm_overhead": round(sealed["warm_seconds"] / plain["warm_seconds"] - 1, 4),
                  "disk_overhead": round(sealed["cache_bytes"] / plain["cache_bytes"] - 1, 4),
                  "codec": _codec_cost(base / "cache-sealed") if _has_scan_cache() else None}
    if args.json:
        print(json.dumps(result))
    else:
        print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
