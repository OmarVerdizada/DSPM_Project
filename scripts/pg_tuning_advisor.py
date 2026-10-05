"""Read-only PostgreSQL tuning advice for a Sentro database host.

    python scripts/pg_tuning_advisor.py [--ram-gb N] [--cpus N] [--ssd/--hdd] [--json]

Reads the running server's settings over DSPM_DB_URL (any role can read them; nothing is
changed) and the host's RAM and CPU count (or the values given, for a database host other
than this one), and prints what docs/database/POSTGRESQL_WAL_ARCHIVE_AND_TUNING_2026-10.md
recommends next to what is set. The output is advice for an operator to review and apply
with ALTER SYSTEM or postgresql.conf - this script never writes a setting.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_UNITS = {"kB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4, "B": 1}


def _bytes(value: str) -> int | None:
    match = re.fullmatch(r"\s*(\d+)\s*(B|kB|MB|GB|TB)?\s*", str(value or ""))
    if not match:
        return None
    return int(match.group(1)) * _UNITS.get(match.group(2) or "B", 1)


def _fmt(size: int) -> str:
    """Whole GB from 2 GB up (a host reports a little under its RAM), else whole MB."""
    if size >= 2 * _UNITS["GB"]:
        return f"{round(size / _UNITS['GB'])}GB"
    return f"{max(1, round(size / _UNITS['MB']))}MB"


# Settings where more than the recommendation is fine: only a lower value is flagged.
_AT_LEAST = {"max_connections", "max_worker_processes", "autovacuum_max_workers", "maintenance_work_mem",
             "max_wal_size", "min_wal_size", "wal_buffers", "work_mem"}


def _number(value: str) -> float | None:
    size = _bytes(value)
    if size is not None:
        return float(size)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _meets(name: str, current: str, recommended: str) -> bool:
    if current.lower() == recommended.lower():
        return True
    now, want = _number(current), _number(recommended)
    if now is None or want is None:
        return False
    return now >= want if name in _AT_LEAST else now == want


def recommend(ram_bytes: int, cpus: int, ssd: bool, pool_connections: int) -> dict[str, tuple[str, str]]:
    """setting -> (recommended value, why). Ratios of the host, not one host's numbers."""
    gb = 1024 ** 3
    shared = min(max(ram_bytes // 4, 128 * 1024 ** 2), 16 * gb)
    return {
        "shared_buffers": (_fmt(shared), "about 25% of RAM, at most 16 GB; the estate tables are read hot"),
        "effective_cache_size": (_fmt(ram_bytes * 3 // 4), "about 75% of RAM: what the OS cache can hold"),
        "maintenance_work_mem": (_fmt(min(max(ram_bytes // 32, 256 * 1024 ** 2), 2 * gb)),
                                 "index builds (revisions 0039/0040) and vacuum of large tables"),
        "work_mem": ("32MB", "per sort/hash node; facet GROUP BYs over a large estate"),
        "wal_compression": ("lz4", "full-page images dominate a scan's WAL; lz4 if the build has it, else pglz"),
        "max_wal_size": ("8GB", "checkpoints by time, not by WAL volume, during a scan's bulk writes"),
        "min_wal_size": ("1GB", "recycled segments instead of new files during a scan"),
        "checkpoint_timeout": ("15min", "fewer full-page images per scan"),
        "checkpoint_completion_target": ("0.9", "spread checkpoint writes"),
        "wal_buffers": ("16MB", "bulk writers"),
        "random_page_cost": ("1.1" if ssd else "4", "SSD storage" if ssd else "spinning storage"),
        "effective_io_concurrency": ("200" if ssd else "2", "SSD storage" if ssd else "spinning storage"),
        "max_connections": (str(max(50, pool_connections + 20)),
                            "at least every process's pool (DSPM_DB_POOL_MAX) plus admin headroom"),
        "max_worker_processes": (str(max(8, cpus)), "parallel index builds and autovacuum"),
        "autovacuum_max_workers": ("4", "the large Sentro tables vacuum in parallel"),
        "autovacuum_naptime": ("30s", "large tables are revisited sooner"),
        "track_io_timing": ("on", "I/O time in pg_stat_statements and EXPLAIN (ANALYZE, BUFFERS)"),
        "shared_preload_libraries": ("pg_stat_statements", "per-statement cost; the slow-query metrics read it"),
        "log_min_duration_statement": ("2000", "statements over 2 s land in the log"),
        "log_checkpoints": ("on", "checkpoint frequency and size are visible"),
        "log_autovacuum_min_duration": ("60s", "long vacuums are visible"),
        "archive_mode": ("on only with base backups",
                         "archived WAL restores nothing without a physical base backup, and nothing prunes it"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ram-gb", type=float, default=0.0, help="the database host's RAM (default: this host)")
    parser.add_argument("--cpus", type=int, default=0, help="the database host's CPUs (default: this host)")
    parser.add_argument("--hdd", action="store_true", help="the data directory is on spinning storage")
    parser.add_argument("--pool-connections", type=int, default=0,
                        help="sum of DSPM_DB_POOL_MAX over every backend and worker process")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    ram = int(args.ram_gb * 1024 ** 3) if args.ram_gb else 0
    if not ram:
        try:
            import psutil

            ram = int(psutil.virtual_memory().total)
        except (ImportError, OSError):  # pragma: no cover - psutil is a dependency
            ram = 16 * 1024 ** 3
    cpus = args.cpus or os.cpu_count() or 4
    pool = args.pool_connections or 4 * int(os.getenv("DSPM_DB_POOL_MAX") or "10")
    advice = recommend(ram, cpus, not args.hdd, pool)

    current: dict[str, str] = {}
    if os.getenv("DSPM_DB_URL"):
        import psycopg

        with psycopg.connect(os.environ["DSPM_DB_URL"], autocommit=True) as conn:
            for name in advice:
                try:
                    current[name] = str(conn.execute(f"SHOW {name}").fetchone()[0])
                except psycopg.Error:
                    current[name] = "(not readable by this role)"

    rows = [{"setting": name, "current": current.get(name, "(no DSPM_DB_URL)"), "recommended": value, "why": why}
            for name, (value, why) in advice.items()]
    if args.json:
        print(json.dumps({"ram_bytes": ram, "cpus": cpus, "ssd": not args.hdd, "settings": rows}, indent=2))
        return 0
    print(f"Host: {ram / 1024 ** 3:.0f} GB RAM, {cpus} CPUs, {'SSD' if not args.hdd else 'HDD'} "
          f"(advice only - nothing is changed)\n")
    width = max(len(row["setting"]) for row in rows)
    for row in rows:
        mark = "  " if _meets(row["setting"], row["current"], row["recommended"]) else "->"
        print(f"{mark} {row['setting']:<{width}}  now {row['current']:<16} recommend {row['recommended']:<22} {row['why']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
