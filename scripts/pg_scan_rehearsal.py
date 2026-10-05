"""A G1-style rehearsal on PostgreSQL: the product's own partitioned scan, first and unchanged.

    python scripts/pg_scan_rehearsal.py --files 20000 [--plan-only] [--force] [--json]

``scripts/c14_scale_harness.py`` measures scans on throwaway SQLite databases. This runs the
scan the way a console scan runs on PostgreSQL - the request goes through the API's own
configuration builder, so the incremental scope, baseline probe and suppression rules are
the product's - over a synthetic corpus under the project's ``tmp/`` (git-ignored; a walk
skips %TEMP% as a system location). For the first scan and an unchanged rescan it reports:

- wall time and files/s;
- peak RSS of this process, sampled every 100 ms (the G1 criterion compares it across sizes
  at the same unit size: run two sizes, both above ``DSPM_PARTITION_MAX_FILES``);
- WAL written and, per table, rows inserted/updated (HOT)/deleted and growth;
- the longest transaction any other session of the database held open meanwhile;
- the latency of four console reads asked together every 0.5 s during the scan
  (remediation summary and page, inventory facets and page) - a sum, so stricter than the
  G1 per-request API p95.

Everything it writes is erased at the end. It refuses any database but the disposable
``sentro_test`` (``--database NAME`` names another disposable one on a scale host), and it
refuses to start unless the volume keeps 2 GB free after the WAL the run will write and
the archive's copy of it - measured on the 2026-10 host at about 105 KiB of WAL per file on
a first scan and 45 KiB on an unchanged rescan, with ~8 findings per file (``--force``
overrides). Run on 2026-10-05 at 4,000 and 20,000 files: see the scaling roadmap, section 6.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import sys
import threading
import time
import uuid
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

FIRST_SCAN_WAL_PER_FILE = 110 * 1024
RESCAN_WAL_PER_FILE = 50 * 1024
KEEP_FREE_BYTES = 2 * 1024 ** 3
LINES = [
    "contact {n}@example.com about the invoice\n",
    "card 4111 1111 1111 1111 exp 09/29 for customer {n}\n",
    "IBAN DE89370400440532013000 payroll {n}\n",
    "quarterly budget notes, nothing sensitive {n}\n",
    "meeting minutes for project {n}, no personal data\n",
]


def plan(files: int) -> dict:
    """What the run will write: WAL twice (pg_wal and the archive's copy) and the corpus."""
    wal = files * (FIRST_SCAN_WAL_PER_FILE + RESCAN_WAL_PER_FILE)
    needed = 2 * wal + files * 1024
    free = shutil.disk_usage(ROOT.anchor or ".").free
    return {"files": files, "wal_bytes": wal, "needed_bytes": needed, "free_bytes": free,
            "fits": free - needed >= KEEP_FREE_BYTES}


def build(estate: Path, files: int) -> None:
    for index in range(files):
        folder = estate / f"dept{index % 10}" / f"team{index % 50:02d}"
        folder.mkdir(parents=True, exist_ok=True)
        body = "".join(LINES[(index + k) % 5].format(n=index) for k in range(12))
        (folder / f"doc_{index:06d}.txt").write_text(body, encoding="utf-8")


def measure(tenant: str, estate: Path, label: str) -> dict:
    from backend import db, partitioned_scan, store
    from backend.app import ScanRequest, _to_config
    from scripts.pg_write_bench import TABLES, database_state

    process = psutil.Process()
    stop = threading.Event()
    peak = [process.memory_info().rss]
    longest = [0.0]
    latencies: list[float] = []
    missed = {"transaction_samples": 0, "console_reads": 0}

    def sample_rss() -> None:
        while not stop.is_set():
            peak[0] = max(peak[0], process.memory_info().rss)
            time.sleep(0.1)

    def sample_transactions() -> None:
        while not stop.is_set():
            try:
                with store._connect() as conn:
                    row = conn.execute(
                        "SELECT COALESCE(MAX(EXTRACT(EPOCH FROM (clock_timestamp() - xact_start))), 0) AS s "
                        "FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid() "
                        "AND xact_start IS NOT NULL").fetchone()
                longest[0] = max(longest[0], float(row["s"] or 0))
            except Exception:  # noqa: BLE001 - a missed sample is counted, not measured
                missed["transaction_samples"] += 1
            time.sleep(0.5)

    def console() -> None:
        while not stop.is_set():
            started = time.perf_counter()
            try:
                with db.tenant_scope(tenant):
                    store.remediation_summary(tenant)
                    store.list_remediation_findings(tenant, limit=50)
                    store.inventory_facets(tenant)
                    store.list_inventory(tenant, limit=50)
                latencies.append((time.perf_counter() - started) * 1000)
            except Exception:  # noqa: BLE001 - a failed read is counted, not a latency
                missed["console_reads"] += 1
            time.sleep(0.5)

    threads = [threading.Thread(target=fn, daemon=True) for fn in (sample_rss, sample_transactions, console)]
    for thread in threads:
        thread.start()
    before = database_state(store)
    base_rss = process.memory_info().rss
    # The configuration a console scan gets - its incremental scope, baseline probe and
    # suppression rules - so the rescan reuses exactly as the product's would.
    payload = ScanRequest(local_path=str(estate.relative_to(ROOT)), max_depth=8, incremental_enabled=True,
                          scan_label="pg-rehearsal", async_scan=True)
    config = _to_config(payload, tenant)
    started = time.perf_counter()
    data = partitioned_scan.run_partitioned_scan(tenant, config, request=payload.model_dump(mode="json"),
                                                 scan_label="pg-rehearsal")
    elapsed = time.perf_counter() - started
    stop.set()
    for thread in threads:
        thread.join(5)
    time.sleep(1.0)  # the cumulative table counters are flushed at transaction end
    after = database_state(store)
    with store._connect() as conn:
        wal = int(conn.execute("SELECT pg_wal_lsn_diff(?, ?) AS d", (after["lsn"], before["lsn"])).fetchone()["d"])
    tables = {}
    for table in TABLES:
        first, last = before["tables"].get(table) or {}, after["tables"].get(table) or {}
        delta = {key: int(last.get(key) or 0) - int(first.get(key) or 0)
                 for key in ("n_tup_ins", "n_tup_upd", "n_tup_hot_upd", "n_tup_del", "bytes")}
        if any(delta.values()):
            tables[table] = delta
    files = int(((data or {}).get("summary") or {}).get("total_files") or 0)
    return {
        "scan": label, "files": files, "seconds": round(elapsed, 1),
        "files_per_second": round(files / max(elapsed, 0.001), 1),
        "peak_rss_mib": round(peak[0] / 1048576, 1), "rss_growth_mib": round((peak[0] - base_rss) / 1048576, 1),
        "wal_mib": round(wal / 1048576, 1), "wal_kib_per_file": round(wal / 1024 / max(files, 1), 1),
        "longest_transaction_seconds": round(longest[0], 1),
        "console_reads_p95_ms": round(statistics.quantiles(latencies, n=20)[-1], 1) if len(latencies) >= 20
        else (round(max(latencies), 1) if latencies else None),
        "console_samples": len(latencies), "missed": dict(missed), "tables": tables,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--files", type=int, default=20000)
    parser.add_argument("--database", default="sentro_test", help="the disposable database DSPM_DB_URL must name")
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--force", action="store_true", help="run even when the disk pre-flight refuses")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    projected = plan(args.files)
    if args.plan_only:
        print(json.dumps(projected, indent=2))
        return 0
    if not os.environ.get("DSPM_DB_URL", "").endswith(f"/{args.database}"):
        print(f"refusing: DSPM_DB_URL must name the disposable {args.database} database", file=sys.stderr)
        return 2
    if not projected["fits"] and not args.force:
        print(f"refusing: {projected['free_bytes'] / 1024 ** 3:.1f} GB free; the run writes about "
              f"{projected['needed_bytes'] / 1024 ** 3:.1f} GB (WAL, its archive copy, the corpus) and must "
              "leave 2 GB. Free space or pass --force.", file=sys.stderr)
        return 3
    from backend import partitioned_scan, store

    if args.files <= partitioned_scan.partition_max_files():
        print(f"refusing: {args.files} files is one partition's worth or less - the scan would run unpartitioned. "
              f"Use more than {partitioned_scan.partition_max_files()}.", file=sys.stderr)
        return 4
    work = ROOT / "tmp" / f"pg-rehearsal-{uuid.uuid4().hex[:6]}"
    work.mkdir(parents=True)
    tenant = f"rehearsal-{uuid.uuid4().hex[:6]}"
    store.create_tenant(tenant, "pg rehearsal")
    results = []
    try:
        build(work / "estate", args.files)
        for label in ("first scan", "unchanged rescan"):
            result = measure(tenant, work / "estate", label)
            results.append(result)
            if not args.json:
                print(f"{label}: {result['files']} files in {result['seconds']} s ({result['files_per_second']} files/s), "
                      f"peak RSS {result['peak_rss_mib']} MiB, WAL {result['wal_mib']} MiB "
                      f"({result['wal_kib_per_file']} KiB/file), longest transaction "
                      f"{result['longest_transaction_seconds']} s, console reads p95 {result['console_reads_p95_ms']} ms",
                      flush=True)
                for table, delta in result["tables"].items():
                    print(f"    {table:<22} ins {delta['n_tup_ins']:>8} upd {delta['n_tup_upd']:>8} "
                          f"(HOT {delta['n_tup_hot_upd']:>8}) del {delta['n_tup_del']:>8} "
                          f"growth {delta['bytes'] / 1048576:+9.2f} MiB", flush=True)
    finally:
        try:
            store.delete_tenant_with_data(tenant)
        finally:
            shutil.rmtree(work, ignore_errors=True)
    if args.json:
        print(json.dumps({"plan": projected, "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
