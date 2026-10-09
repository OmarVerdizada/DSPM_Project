"""What one product scan writes and holds: per table, per store and per change rate.

    python scripts/amplification_probe.py rates [--files 6000] [--json]
    python scripts/amplification_probe.py unit-bytes [--files 120] [--mib 2] [--per-unit 60]

The scaling roadmap's Wave 4 attacks amplification: the rows, bytes and work a scan spends
on files that did not change, and the copies it keeps of each fact. This measures them on
the product's own partitioned scan - the request goes through the API's configuration
builder - over a small synthetic corpus, on a throwaway SQLite install under the project's
``tmp/`` (git-ignored; a walk skips %TEMP% as a system location). Everything it writes is
erased at the end.

``rates`` scans the corpus five times - first, unchanged, about 1% changed, about 10%
changed, unchanged again - and reports for each:

- files/s and the peak RSS of this process and its children;
- rows and logical payload bytes per table (the sum of the column lengths: SQLite has no
  ``dbstat`` here, so pages and indexes are not counted);
- row operations per table during the scan, from a statement trace on every SQLite
  connection, the reuse cache's included (an ``executemany`` counts once per row);
- bytes and file counts of the artifact store and the scan cache.

``unit-bytes`` scans text files of one size in units of a chosen file count and reports the
peak RSS: run it at two unit sizes to see whether memory follows the bytes a unit holds.

SQLite is not the production database. The row counts and row operations are the same
code path as PostgreSQL's; WAL and on-disk row sizes are PostgreSQL's own, measured with
``scripts/pg_write_bench.py`` and ``scripts/pg_scan_rehearsal.py``. Measured on 2026-10-05:
see the scaling roadmap, section 23.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import threading
import time
import uuid
from contextlib import suppress
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SENSITIVE = [
    "contact {n}@example.com about the invoice\n",
    "card 4111 1111 1111 1111 exp 09/29 for customer {n}\n",
    "IBAN DE89370400440532013000 payroll {n}\n",
]
BENIGN = [
    "quarterly budget notes, nothing sensitive {n}\n",
    "meeting minutes for project {n}, no personal data\n",
    "the team agreed the next milestone and the owners {n}\n",
]
PROSE = [
    "minutes of the planning meeting for work package {n}: the owners agreed the next milestone\n",
    "the budget note for cost centre {n} carries no personal data and no account numbers\n",
    "contact the project office about item {n} during working hours\n",
    "delivery {n} was accepted by the warehouse and filed under the usual reference\n",
]
STEPS = (("first scan", 0), ("unchanged rescan", 0), ("1% changed", 100), ("10% changed", 10), ("unchanged again", 0))
DETAIL_TABLES = ("assets", "findings", "finding_index", "finding_occurrences", "scan_object_baselines",
                 "asset_versions", "asset_access")

_ops: collections.Counter = collections.Counter()
_ops_lock = threading.Lock()
_WRITE = re.compile(r'^\s*(INSERT(?:\s+OR\s+\w+)?\s+INTO|UPDATE|DELETE\s+FROM|REPLACE\s+INTO)\s+"?([A-Za-z_][A-Za-z_0-9]*)',
                    re.IGNORECASE)
_real_connect = sqlite3.connect


def _traced_connect(database, *args, **kwargs):
    """``sqlite3.connect`` that counts the write statements each connection executes."""
    conn = _real_connect(database, *args, **kwargs)
    name = Path(str(database).split("?")[0].replace("file:", "")).name or "memory"

    def trace(statement: str) -> None:
        match = _WRITE.match(statement)
        if match:
            with _ops_lock:
                _ops[(name, match.group(2).lower(), match.group(1).split()[0].upper())] += 1

    conn.set_trace_callback(trace)
    return conn


def isolate(state: Path) -> None:
    """Point every DSPM setting at a throwaway install before the product is imported."""
    (state / "keys").mkdir(parents=True, exist_ok=True)
    for key in [name for name in os.environ if name.startswith("DSPM_")]:
        del os.environ[key]
    os.environ.update({
        "DSPM_DB_PATH": str(state / "dspm.sqlite"), "DSPM_ARTIFACT_DIR": str(state / "artifacts"),
        "DSPM_SCAN_CACHE_DIR": str(state / "cache"), "DSPM_ENV": "local",
        "DSPM_REPORT_DIR": str(state / "reports"), "DSPM_BACKUP_DIR": str(state / "backups"),
        "DSPM_LOCAL_ARTIFACT_KEY_PATH": str(state / "keys" / "artifact"),
        "DSPM_LOCAL_JWT_SECRET_PATH": str(state / "keys" / "jwt"),
        "DSPM_LOCAL_VAULT_KEY_PATH": str(state / "keys" / "vault"),
        "DSPM_LOCAL_BACKUP_KEY_PATH": str(state / "keys" / "backup"),
        "DSPM_LOCAL_EVIDENCE_KEY_PATH": str(state / "keys" / "evidence"),
        # a throwaway install's own administrator; never typed, never printed
        "DSPM_DEV_ADMIN_PASSWORD": "probe-" + hashlib.sha256(os.urandom(16)).hexdigest()[:16] + "9q",
    })
    sys.path.insert(0, str(ROOT))
    os.chdir(ROOT)


def small_body(index: int, salt: str = "") -> str:
    """Four files in ten carry sensitive lines; the rest carry none."""
    lines = SENSITIVE if index % 10 < 4 else BENIGN
    return "".join(lines[(index + k) % len(lines)].format(n=f"{index}{salt}") for k in range(12))


def small_path(estate: Path, index: int) -> Path:
    return estate / f"dept{index % 10}" / f"team{index % 50:02d}" / f"doc_{index:06d}.txt"


def build_small(estate: Path, files: int) -> None:
    for index in range(files):
        path = small_path(estate, index)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(small_body(index), encoding="utf-8")


def change(estate: Path, files: int, every: int, salt: str) -> int:
    """Rewrite every ``every``-th file with other content, so its size and mtime move."""
    changed = 0
    for index in range(0, files, every):
        small_path(estate, index).write_text(
            small_body(index, salt) + f"changed {salt}: reach owner{index}{salt}@example.org\n", encoding="utf-8")
        changed += 1
    return changed


def folder_stats(path: Path) -> dict:
    files = [item for item in path.rglob("*") if item.is_file()] if path.exists() else []
    return {"files": len(files), "bytes": sum(item.stat().st_size for item in files)}


def table_stats(db_path: Path) -> dict:
    """Rows and logical payload bytes per table."""
    out: dict = {}
    conn = _real_connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        tables = [row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")]
        for table in tables:
            columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]
            if not columns:
                continue
            length = " + ".join(f'COALESCE(LENGTH(CAST("{column}" AS BLOB)), 0)' for column in columns)
            rows, size = conn.execute(f'SELECT COUNT(*), COALESCE(SUM({length}), 0) FROM "{table}"').fetchone()
            if rows:
                out[table] = {"rows": int(rows), "bytes": int(size)}
    finally:
        conn.close()
    return out


def column_bytes(db_path: Path, table: str) -> dict:
    """Average bytes per row of each column that averages at least 8."""
    conn = _real_connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]
        select = ", ".join(f'COALESCE(SUM(LENGTH(CAST("{column}" AS BLOB))), 0)' for column in columns)
        sizes = conn.execute(f'SELECT COUNT(*), {select} FROM "{table}"').fetchone()
        rows = int(sizes[0]) or 1
        return {column: round(int(size) / rows, 1) for column, size in zip(columns, sizes[1:]) if int(size) / rows >= 8}
    finally:
        conn.close()


class Rss:
    """Peak RSS of this process and of this process plus its children, sampled every 100 ms."""

    def __init__(self) -> None:
        import psutil

        self._psutil = psutil
        self._process = psutil.Process()
        self._stop = threading.Event()
        self.own = self.tree = self._process.memory_info().rss
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self._stop.is_set():
            own = total = self._process.memory_info().rss
            for child in self._process.children(recursive=True):
                try:
                    total += child.memory_info().rss
                except self._psutil.Error:
                    pass
            self.own, self.tree = max(self.own, own), max(self.tree, total)
            time.sleep(0.1)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(2)


def scan(tenant: str, estate: Path, label: str, max_files: int | None = None) -> tuple[dict, float]:
    """One scan as a console scan runs: the API's own configuration, the partitioned path."""
    from backend import partitioned_scan
    from backend.app import ScanRequest, _to_config

    payload = ScanRequest(local_path=str(estate.relative_to(ROOT)), max_depth=8, incremental_enabled=True,
                          scan_label=label, async_scan=True)
    config = _to_config(payload, tenant)
    started = time.perf_counter()
    data = partitioned_scan.run_partitioned_scan(tenant, config, request=payload.model_dump(mode="json"),
                                                 scan_label=label, max_files=max_files)
    return data or {}, time.perf_counter() - started


def rates(files: int, state: Path, estate: Path) -> dict:
    from backend import partitioned_scan, store

    if files <= partitioned_scan.partition_max_files():
        raise SystemExit(f"refusing: {files} files is one partition's worth or less - the scan would run "
                         f"unpartitioned. Use more than {partitioned_scan.partition_max_files()}.")
    build_small(estate, files)
    tenant = "amplification"
    store.create_tenant(tenant, "amplification probe")
    results = []
    for label, every in STEPS:
        changed = change(estate, files, every, label[:2].strip().replace("%", "p")) if every else 0
        with _ops_lock:
            _ops.clear()
        rss = Rss()
        rss.start()
        data, elapsed = scan(tenant, estate, "amplification")
        rss.stop()
        diagnostics = data.get("scan_diagnostics") or {}
        with _ops_lock:
            operations = {f"{db}:{table}:{verb}": count for (db, table, verb), count in sorted(_ops.items())}
        results.append({
            "scan": label, "changed_files": changed, "files": int((data.get("summary") or {}).get("total_files") or 0),
            "seconds": round(elapsed, 1), "files_per_second": round(files / max(elapsed, 0.001), 1),
            "peak_rss_tree_mib": round(rss.tree / 1048576, 1),
            "content_reads": (diagnostics.get("incremental") or {}).get("content_reads"),
            "row_operations": operations, "tables": table_stats(state / "dspm.sqlite"),
            "database_file_bytes": sum(item.stat().st_size for item in state.glob("dspm.sqlite*")),
            "artifacts": folder_stats(state / "artifacts"), "scan_cache": folder_stats(state / "cache"),
        })
    present = results[-1]["tables"]
    return {"files": files, "results": results,
            "average_column_bytes": {table: column_bytes(state / "dspm.sqlite", table)
                                     for table in DETAIL_TABLES if table in present}}


def unit_bytes(files: int, mib: float, per_unit: int, estate: Path) -> dict:
    from backend import store

    estate.mkdir(parents=True, exist_ok=True)
    target = int(mib * 1024 * 1024)
    for index in range(files):
        block = "".join(PROSE[(index + k) % len(PROSE)].format(n=f"{index}-{k}") for k in range(400))
        (estate / f"doc_{index:04d}.txt").write_text((block * (target // len(block) + 1))[:target], encoding="utf-8")
    tenant = "unitbytes"
    store.create_tenant(tenant, "unit bytes probe")
    rss = Rss()
    base = rss.own
    rss.start()
    data, elapsed = scan(tenant, estate, "unitbytes", max_files=per_unit)
    rss.stop()
    partitions = ((data.get("scan_diagnostics") or {}).get("partitioned") or {}).get("partitions")
    return {"files": int((data.get("summary") or {}).get("total_files") or 0), "mib_per_file": mib,
            "files_per_unit": per_unit, "unit_mib": round(per_unit * mib, 1), "partitions": partitions,
            "seconds": round(elapsed, 1), "mib_per_second": round(files * mib / max(elapsed, 0.001), 2),
            "base_rss_mib": round(base / 1048576), "peak_rss_mib": round(rss.own / 1048576),
            "peak_rss_tree_mib": round(rss.tree / 1048576)}


def print_rates(report: dict) -> None:
    previous: dict = {}
    for result in report["results"]:
        print(f"{result['scan']}: {result['files']} files, {result['changed_files']} changed, {result['seconds']} s "
              f"({result['files_per_second']} files/s), peak RSS {result['peak_rss_tree_mib']} MiB, "
              f"content reads {result['content_reads']}, database {result['database_file_bytes'] / 1048576:.1f} MiB, "
              f"artifacts {result['artifacts']['files']} objects {result['artifacts']['bytes'] / 1048576:.1f} MiB, "
              f"scan cache {result['scan_cache']['files']} files {result['scan_cache']['bytes'] / 1048576:.1f} MiB")
        for table, now in sorted(result["tables"].items(), key=lambda item: -item[1]["bytes"]):
            before = previous.get(table, {"rows": 0, "bytes": 0})
            if now["bytes"] < 20_000 and now["rows"] == before["rows"]:
                continue
            print(f"    {table:<26} rows {now['rows']:>8} ({now['rows'] - before['rows']:>+7})  "
                  f"MiB {now['bytes'] / 1048576:>7.2f} ({(now['bytes'] - before['bytes']) / 1048576:>+6.2f})  "
                  f"bytes/row {now['bytes'] / max(now['rows'], 1):>6.0f}")
        operations: dict = {}
        for key, count in result["row_operations"].items():
            database, table, verb = key.split(":")
            operations.setdefault(f"{database.split('.')[0]}.{table}", {})[verb] = count
        busy = sorted(((name, verbs) for name, verbs in operations.items() if sum(verbs.values()) >= 20),
                      key=lambda item: -sum(item[1].values()))
        print("    row operations: " + "; ".join(
            f"{name} " + " ".join(f"{verb.lower()} {count}" for verb, count in sorted(verbs.items())) for name, verbs in busy))
        previous = result["tables"]
    for table, columns in report["average_column_bytes"].items():
        widest = sorted(columns.items(), key=lambda item: -item[1])[:6]
        print(f"{table}: " + ", ".join(f"{column} {size:.0f} B" for column, size in widest))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=("rates", "unit-bytes"))
    parser.add_argument("--files", type=int, default=0, help="corpus size (rates: 6000; unit-bytes: 120)")
    parser.add_argument("--mib", type=float, default=2.0, help="unit-bytes: size of each text file")
    parser.add_argument("--per-unit", type=int, default=60, help="unit-bytes: files per unit")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    work = ROOT / "tmp" / f"amplification-probe-{uuid.uuid4().hex[:6]}"
    isolate(work / "state")
    sqlite3.connect = _traced_connect  # type: ignore[assignment]
    try:
        if args.mode == "rates":
            report = rates(args.files or 6000, work / "state", work / "estate")
        else:
            report = unit_bytes(args.files or 120, args.mib, args.per_unit, work / "estate")
        if args.json or args.mode == "unit-bytes":
            print(json.dumps(report, indent=1))
        else:
            print_rates(report)
    finally:
        with suppress(Exception):  # the pool is not part of what is measured
            from discovery import detector_pool

            detector_pool.shutdown_shared_pool()
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
