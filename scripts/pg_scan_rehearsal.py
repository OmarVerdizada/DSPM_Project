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
  G1 per-request API p95 - and each read's own p95 (W4.5's criterion). The reads run in
  this process, beside the scan's threads, as they do under inline execution (the
  default); under ``DSPM_SCAN_EXECUTION=queue`` the API is another process.

W4.5 adds ``--workers N`` (``DSPM_PARTITION_WORKERS``) and ``--unit-files N``
(``DSPM_PARTITION_MAX_FILES``), and reports for each scan: the units' persist throughput -
files written per second while any unit was writing (the union of their persist
intervals), and the persist seconds those intervals add up to; the longest wait for a lock
any other session showed (sampled every 0.25 s from ``pg_stat_activity``); and from
``pg_stat_wal`` the records and full-page images the scan wrote and the images' share.

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
from datetime import datetime, timezone
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Measured on this host: 110 and 50 KiB a file in 2026-10-05; since W4.1 and W4.2 a first scan
# writes 27.6 KiB a file (108 MiB at 4,000) and an unchanged one almost none. With margin:
FIRST_SCAN_WAL_PER_FILE = 48 * 1024
RESCAN_WAL_PER_FILE = 8 * 1024
KEEP_FREE_BYTES = 2 * 1024 ** 3
LINES = [
    "contact {n}@example.com about the invoice\n",
    "card 4111 1111 1111 1111 exp 09/29 for customer {n}\n",
    "IBAN DE89370400440532013000 payroll {n}\n",
    "quarterly budget notes, nothing sensitive {n}\n",
    "meeting minutes for project {n}, no personal data\n",
]


def plan(files: int, *, first_only: bool = False) -> dict:
    """What the run will write: WAL twice (pg_wal and the archive's copy) and the corpus."""
    wal = files * (FIRST_SCAN_WAL_PER_FILE + (0 if first_only else RESCAN_WAL_PER_FILE))
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
    lock_wait = [0.0]
    latencies: list[float] = []
    missed = {"transaction_samples": 0, "console_reads": 0}
    persists: list[tuple[float, float, int]] = []
    persist_lock = threading.Lock()
    real_persist = store.persist_partition

    def timed_persist(*args, **kwargs):
        started_at = time.perf_counter()
        try:
            return real_persist(*args, **kwargs)
        finally:
            records = args[5] if len(args) > 5 else kwargs.get("records") or []
            with persist_lock:
                persists.append((started_at, time.perf_counter(), len(records or [])))

    store.persist_partition = timed_persist

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
                with store._connect() as conn:
                    row = conn.execute(
                        "SELECT COALESCE(MAX(EXTRACT(EPOCH FROM (clock_timestamp() - state_change))), 0) AS s "
                        "FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid() "
                        "AND wait_event_type = 'Lock'").fetchone()
                lock_wait[0] = max(lock_wait[0], float(row["s"] or 0))
            except Exception:  # noqa: BLE001 - a missed sample is counted, not measured
                missed["transaction_samples"] += 1
            time.sleep(0.25)

    reads = {
        "remediation_summary": lambda: store.remediation_summary(tenant),
        "remediation_page": lambda: store.list_remediation_findings(tenant, limit=50),
        "inventory_facets": lambda: store.inventory_facets(tenant),
        "inventory_page": lambda: store.list_inventory(tenant, limit=50),
    }
    per_read: dict[str, list[float]] = {name: [] for name in reads}

    def console() -> None:
        while not stop.is_set():
            started = time.perf_counter()
            try:
                with db.tenant_scope(tenant):
                    for name, read in reads.items():
                        began = time.perf_counter()
                        read()
                        per_read[name].append((time.perf_counter() - began) * 1000)
                latencies.append((time.perf_counter() - started) * 1000)
            except Exception:  # noqa: BLE001 - a failed read is counted, not a latency
                missed["console_reads"] += 1
            time.sleep(0.5)

    threads = [threading.Thread(target=fn, daemon=True) for fn in (sample_rss, sample_transactions, console)]
    for thread in threads:
        thread.start()
    before = database_state(store)
    wal_before = _wal_stats(store)
    base_rss = process.memory_info().rss
    # The configuration a console scan gets - its incremental scope, baseline probe and
    # suppression rules - so the rescan reuses exactly as the product's would.
    payload = ScanRequest(local_path=str(estate.relative_to(ROOT)), max_depth=8, incremental_enabled=True,
                          scan_label="pg-rehearsal", async_scan=True)
    config = _to_config(payload, tenant)
    started = time.perf_counter()
    scan_started = datetime.now(timezone.utc)
    data = partitioned_scan.run_partitioned_scan(tenant, config, request=payload.model_dump(mode="json"),
                                                 scan_label="pg-rehearsal")
    elapsed = time.perf_counter() - started
    phases = _scan_phases(store, tenant, str((data or {}).get("scan_id") or ""), scan_started)
    stop.set()
    store.persist_partition = real_persist
    for thread in threads:
        thread.join(5)
    time.sleep(1.0)  # the cumulative table counters are flushed at transaction end
    after = database_state(store)
    wal_after = _wal_stats(store)
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
    busy = _union_seconds([(start, end) for start, end, _files in persists])
    persisted = sum(count for _start, _end, count in persists)
    records = int(wal_after.get("wal_records", 0)) - int(wal_before.get("wal_records", 0))
    images = int(wal_after.get("wal_fpi", 0)) - int(wal_before.get("wal_fpi", 0))
    return {
        "workers": int(os.getenv("DSPM_PARTITION_WORKERS") or 1),
        "units_persisted": len(persists), "files_persisted": persisted,
        "persist_busy_seconds": round(busy, 2),
        "persist_seconds_summed": round(sum(end - start for start, end, _files in persists), 2),
        "persist_files_per_busy_second": round(persisted / busy, 1) if busy else None,
        "longest_lock_wait_seconds": round(lock_wait[0], 2),
        "wal_records": records, "wal_full_page_images": images,
        "wal_full_page_image_share": round(images / records, 4) if records else None,
        "scan": label, "files": files, "seconds": round(elapsed, 1),
        # W5: where the time went, from the ledger - until the first unit started, the units,
        # and after the last one (finalize).
        "phases": phases,
        # The scan's WAL range, for pg_waldump (W5: the WAL by table and index).
        "lsn_start": before["lsn"], "lsn_end": after["lsn"],
        "files_per_second": round(files / max(elapsed, 0.001), 1),
        "peak_rss_mib": round(peak[0] / 1048576, 1), "rss_growth_mib": round((peak[0] - base_rss) / 1048576, 1),
        "wal_mib": round(wal / 1048576, 1), "wal_kib_per_file": round(wal / 1024 / max(files, 1), 1),
        "longest_transaction_seconds": round(longest[0], 1),
        "console_reads_p95_ms": _p95(latencies),
        # The W4.5 criterion: each request's own p95, and the worst of them.
        "console_request_p95_ms": {name: _p95(values) for name, values in per_read.items()},
        "console_request_worst_p95_ms": max((_p95(values) or 0.0) for values in per_read.values()),
        "console_samples": len(latencies), "missed": dict(missed), "tables": tables,
    }


def _scan_phases(store, tenant: str, scan_id: str, started) -> dict:
    """Seconds from the scan's start to its first unit's start, from there to the last unit's
    end, and from there to now (finalize), read from the ledger."""
    from backend import db

    if not scan_id:
        return {}
    with db.tenant_scope(tenant), store._connect() as conn:
        row = conn.execute("SELECT MIN(started_at) AS first, MAX(finished_at) AS last, COUNT(*) AS units "
                           "FROM scan_partitions WHERE tenant_id = ? AND scan_id = ?", (tenant, scan_id)).fetchone()
    if not row or not row["first"]:
        return {}
    first = datetime.fromisoformat(str(row["first"]))
    last = datetime.fromisoformat(str(row["last"]))
    now = datetime.now(timezone.utc)
    return {"units": int(row["units"] or 0), "until_first_unit_s": round((first - started).total_seconds(), 1),
            "units_s": round((last - first).total_seconds(), 1), "after_last_unit_s": round((now - last).total_seconds(), 1)}


def _start_queue_workers(count: int) -> list:
    """``count`` partition worker processes on the same database (W5): units run in processes,
    not in this process's threads, which share one interpreter lock. The scan is handed to
    them through the ledger (DSPM_SCAN_EXECUTION=queue) and this process only waits."""
    if count <= 0:
        return []
    import subprocess

    os.environ["DSPM_SCAN_EXECUTION"] = "queue"
    env = dict(os.environ, DSPM_PARTITION_WORKERS="1")
    return [subprocess.Popen([sys.executable, str(ROOT / "main.py"), "worker", "--worker-id", f"rehearsal-{index}"],
                             cwd=str(ROOT), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for index in range(count)]


def _stop_queue_workers(workers: list) -> None:
    for process in workers:
        process.terminate()
    for process in workers:
        try:
            process.wait(30)
        except Exception:  # noqa: BLE001 - a worker that does not stop is killed
            process.kill()
    os.environ.pop("DSPM_SCAN_EXECUTION", None)


def _p95(values: list[float]) -> float | None:
    """The 95th percentile in ms; the largest value under 20 samples."""
    if len(values) >= 20:
        return round(statistics.quantiles(values, n=20)[-1], 1)
    return round(max(values), 1) if values else None


def _wal_stats(store) -> dict:
    """``pg_stat_wal`` now: records, full-page images, bytes (readable without superuser)."""
    try:
        with store._connect() as conn:
            row = conn.execute("SELECT wal_records, wal_fpi, wal_bytes FROM pg_stat_wal").fetchone()
        return {key: int(row[key] or 0) for key in ("wal_records", "wal_fpi", "wal_bytes")}
    except Exception:  # noqa: BLE001 - reported as not measured
        return {}


def _union_seconds(intervals: list[tuple[float, float]]) -> float:
    """How long at least one of the intervals was open."""
    total, current_start, current_end = 0.0, None, None
    for start, end in sorted(intervals):
        if current_end is None or start > current_end:
            if current_end is not None:
                total += current_end - current_start
            current_start, current_end = start, end
        else:
            current_end = max(current_end, end)
    if current_end is not None:
        total += current_end - current_start
    return total


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--files", type=int, default=20000)
    parser.add_argument("--database", default="sentro_test", help="the disposable database DSPM_DB_URL must name")
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--force", action="store_true", help="run even when the disk pre-flight refuses")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--workers", type=int, default=0, help="DSPM_PARTITION_WORKERS for the scans (W4.5)")
    parser.add_argument("--unit-files", type=int, default=0, help="DSPM_PARTITION_MAX_FILES for the scans")
    parser.add_argument("--first-only", action="store_true", help="the first scan only")
    parser.add_argument("--queue-workers", type=int, default=0,
                        help="run the units in N worker processes (DSPM_SCAN_EXECUTION=queue, main.py worker) "
                             "instead of this process's threads (W5)")
    args = parser.parse_args()
    if args.workers:
        os.environ["DSPM_PARTITION_WORKERS"] = str(args.workers)
    if args.unit_files:
        os.environ["DSPM_PARTITION_MAX_FILES"] = str(args.unit_files)
    projected = plan(args.files, first_only=args.first_only)
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
        workers = _start_queue_workers(args.queue_workers)
        try:
            for label in ("first scan",) if args.first_only else ("first scan", "unchanged rescan"):
                result = measure(tenant, work / "estate", label)
                result["queue_workers"] = args.queue_workers
                results.append(result)
        finally:
            _stop_queue_workers(workers)
        for result in results:
            label = result["scan"]
            if not args.json:
                print(f"{label}: {result['files']} files in {result['seconds']} s ({result['files_per_second']} files/s), "
                      f"peak RSS {result['peak_rss_mib']} MiB, WAL {result['wal_mib']} MiB "
                      f"({result['wal_kib_per_file']} KiB/file), longest transaction "
                      f"{result['longest_transaction_seconds']} s, console reads p95 {result['console_reads_p95_ms']} ms",
                      flush=True)
                print(f"    workers {result['workers']}: {result['units_persisted']} units, persist busy "
                      f"{result['persist_busy_seconds']} s (summed {result['persist_seconds_summed']} s), "
                      f"{result['persist_files_per_busy_second']} files per busy second; longest lock wait "
                      f"{result['longest_lock_wait_seconds']} s; WAL records {result['wal_records']}, full-page "
                      f"images {result['wal_full_page_images']} ({result['wal_full_page_image_share']})", flush=True)
                print("    console request p95 (ms): " + ", ".join(
                    f"{name} {value}" for name, value in result["console_request_p95_ms"].items()), flush=True)
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
