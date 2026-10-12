"""PostgreSQL write cost of a scan save and of one finding click, on the disposable
sentro_test database only (scaling roadmap W1.4, W2.1).

    python scripts/pg_write_bench.py FILES FINDINGS_PER_FILE [--partitioned] [--clicks N] [--force]

Saves a synthetic report twice - a first scan, then an unchanged rescan - and prints for
each: wall time, files/s, peak RSS growth, WAL written, rows inserted/updated/deleted and
table growth. ``--partitioned`` writes the way a scan does by default since W1.1: one
partition of DSPM_PARTITION_MAX_FILES files at a time, then finalize. Then N lifecycle
clicks and one click through the old report re-save. The tenant is erased at the end.

Every run writes WAL, and with archive_mode on the archive keeps a copy: the run refuses
to start unless the system volume has room for about 3 x the estimated WAL plus 2 GB
(``--force`` overrides). BENCH_ANALYZE_BEFORE_PRUNE=1 refreshes statistics inside a save
before the prune, to compare against a plan that has them.
"""
from __future__ import annotations

import argparse
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

TYPES = ["email", "phone", "iban", "credit_card", "passport_number", "aws_access_key"]
TABLES = ("assets", "asset_versions", "asset_access", "findings", "finding_index", "finding_occurrences",
          "scan_object_baselines", "scan_reports", "scan_partitions",
          # W4.5: the small tables every unit or every second writes, and the counts (W4.4).
          "partitioned_scans", "scan_jobs", "tenants", "estate_counts", "estate_count_deltas")
# Measured before W2.1 (2026-10): about 56 KB of WAL per file of 2 findings on a first save.
WAL_BYTES_PER_FILE_ESTIMATE = 64 * 1024


def report(scan_id: str, files: int, per_file: int) -> dict:
    items = []
    for index in range(files):
        folder = f"\\\\fs01\\Finance\\Dept{index % 50:02d}\\Sub{index % 997:03d}"
        findings = [{
            "finding_id": f"f-{index}-{k}", "type": TYPES[(index + k) % len(TYPES)], "risk": "HIGH",
            "framework": "gdpr", "count": 3, "status": "OPEN", "confidence": 80,
            "samples": ["****1234"], "secure_value_fingerprints": [f"{index:08x}{k:02x}" * 4],
        } for k in range(per_file)]
        items.append({
            "path": f"{folder}\\file_{index:07d}.xlsx", "name": f"file_{index:07d}.xlsx", "extension": ".xlsx",
            "size": 40_000 + index, "owner": "CORP\\owner", "modified_at": "2026-09-01T00:00:00+00:00",
            "source": "smb", "share": "Finance", "sha256": f"{index:064x}", "content_status": "scanned",
            "risk": {"level": "HIGH", "score": 80}, "findings": findings,
        })
    return {"scan_id": scan_id, "source": "smb", "scan_label": "bench", "summary": {"total_files": files},
            "timestamp": "2026-10-02T00:00:00+00:00", "files": items}


def database_state(store) -> dict:
    """WAL position, cumulative row counters and table sizes - each readable without superuser."""
    with store._connect() as conn:
        lsn = str(conn.execute("SELECT pg_current_wal_lsn() AS lsn").fetchone()["lsn"])
        rows = conn.execute(
            "SELECT relname, n_tup_ins, n_tup_upd, n_tup_hot_upd, n_tup_del, "
            "pg_total_relation_size(relid) AS bytes FROM pg_stat_user_tables "
            f"WHERE relname IN ({', '.join('?' for _ in TABLES)})",
            TABLES,
        ).fetchall()
    return {"lsn": lsn, "tables": {row["relname"]: dict(row) for row in rows}}


def wal_between(store, before: str, after: str) -> int:
    with store._connect() as conn:
        return int(conn.execute("SELECT pg_wal_lsn_diff(?, ?) AS d", (after, before)).fetchone()["d"])


def describe(store, label: str, before: dict, after: dict, files: int, elapsed: float, peak_mib: float) -> None:
    wal = wal_between(store, before["lsn"], after["lsn"])
    inserted = updated = hot = deleted = 0
    growth = 0
    for table in TABLES:
        first, last = before["tables"].get(table) or {}, after["tables"].get(table) or {}
        inserted += int(last.get("n_tup_ins") or 0) - int(first.get("n_tup_ins") or 0)
        updated += int(last.get("n_tup_upd") or 0) - int(first.get("n_tup_upd") or 0)
        hot += int(last.get("n_tup_hot_upd") or 0) - int(first.get("n_tup_hot_upd") or 0)
        deleted += int(last.get("n_tup_del") or 0) - int(first.get("n_tup_del") or 0)
        growth += int(last.get("bytes") or 0) - int(first.get("bytes") or 0)
    print(f"{label}: {elapsed:.1f} s, {files / elapsed:.0f} files/s, peak RSS +{peak_mib:.0f} MiB | "
          f"WAL {wal / 1048576:.1f} MiB ({wal / max(files, 1) / 1024:.1f} KiB/file) | rows ins {inserted} "
          f"upd {updated} (HOT {hot}) del {deleted} | table growth {growth / 1048576:+.1f} MiB", flush=True)
    if os.environ.get("BENCH_PER_TABLE") == "1":
        for table in TABLES:
            first, last = before["tables"].get(table) or {}, after["tables"].get(table) or {}
            delta = {key: int(last.get(key) or 0) - int(first.get(key) or 0)
                     for key in ("n_tup_ins", "n_tup_upd", "n_tup_hot_upd", "n_tup_del", "bytes")}
            if any(delta.values()):
                print(f"    {table:<22} ins {delta['n_tup_ins']:>6} upd {delta['n_tup_upd']:>6} "
                      f"(HOT {delta['n_tup_hot_upd']:>6}) del {delta['n_tup_del']:>6} "
                      f"growth {delta['bytes'] / 1048576:+7.2f} MiB", flush=True)


def measured(fn) -> tuple[float, float]:
    process = psutil.Process()
    peak = [process.memory_info().rss]
    stop = threading.Event()

    def sample() -> None:
        while not stop.is_set():
            peak[0] = max(peak[0], process.memory_info().rss)
            time.sleep(0.05)

    base = process.memory_info().rss
    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    started = time.perf_counter()
    fn()
    elapsed = time.perf_counter() - started
    stop.set()
    sampler.join()
    return elapsed, (peak[0] - base) / 1048576


def save_partitioned(store, partitioned_scan, tenant: str, body: dict, unit_files: int) -> None:
    """The default scan write since W1.1: each unit persisted on its own, then finalize."""
    scan_id = body["scan_id"]
    files = body["files"]
    header = {k: v for k, v in body.items() if k != "files"}
    header["scan_diagnostics"] = {"incremental": {"complete": True}}
    store.register_partitioned_scan(tenant, scan_id, job_id="bench", request={}, header={
        "timestamp": body["timestamp"], "source": "smb", "scan_label": body["scan_label"]})
    units = [{"part": index} for index in range(0, len(files), unit_files)]
    store.create_scan_partitions(tenant, scan_id, "bench", units)
    for start in range(0, len(files), unit_files):
        unit = store.claim_next_partition(tenant, scan_id, worker_id="bench")
        store.persist_partition(tenant, scan_id, unit["partition_id"], unit["attempt"],
                                {**header, "summary": {"total_files": len(files[start:start + unit_files])}},
                                files[start:start + unit_files], write_estate=True)
    partitioned_scan.finalize_scan(tenant, scan_id, timestamp=body["timestamp"], source="smb",
                                   scan_label=body["scan_label"], write_estate=True)
    store.mark_partitioned_scan(tenant, scan_id, "done")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("files", type=int)
    parser.add_argument("per_file", type=int)
    parser.add_argument("--clicks", type=int, default=20)
    parser.add_argument("--partitioned", action="store_true")
    parser.add_argument("--force", action="store_true", help="run even when the disk pre-flight refuses")
    args = parser.parse_args()
    from backend import db

    if not db.is_disposable_test_url(os.environ.get("DSPM_DB_URL", "")):
        print("refusing: DSPM_DB_URL must name a disposable *_test database on this host", file=sys.stderr)
        return 2
    needed = 3 * 2 * args.files * WAL_BYTES_PER_FILE_ESTIMATE + 2 * 1024 ** 3
    free = shutil.disk_usage(Path(os.environ.get("SystemDrive", "C:") + "\\")).free
    if free < needed and not args.force:
        print(f"refusing: {free / 1024 ** 3:.1f} GB free, the run needs about {needed / 1024 ** 3:.1f} GB "
              "(WAL in pg_wal and the archive, both saves). Free space or pass --force.", file=sys.stderr)
        return 3

    from backend import db, partitioned_scan, store

    if os.environ.get("BENCH_ANALYZE_BEFORE_PRUNE") == "1":
        real_prune = store._prune_unseen_assets

        def prune_with_stats(conn, *rest):
            conn.execute("ANALYZE assets")
            conn.execute("ANALYZE findings")
            return real_prune(conn, *rest)

        store._prune_unseen_assets = prune_with_stats

    unit_files = partitioned_scan.partition_max_files()
    tenant = f"bench-{uuid.uuid4().hex[:6]}"
    store.create_tenant(tenant, "bench")
    try:
        for label, scan_id in (("first save", "bench-1"), ("unchanged rescan save", "bench-2")):
            body = report(scan_id, args.files, args.per_file)
            before = database_state(store)
            if args.partitioned:
                elapsed, peak = measured(lambda body=body: save_partitioned(store, partitioned_scan, tenant, body,
                                                                            unit_files))
            else:
                elapsed, peak = measured(lambda body=body: store.save_scan_history(tenant, body))
            time.sleep(1.0)  # the cumulative counters are flushed at transaction end, give them a moment
            describe(store, f"{label}{' (partitioned)' if args.partitioned else ''}", before, database_state(store),
                     args.files, elapsed, peak)
            body = None
        with db.tenant_scope(tenant), store._connect() as conn:
            ids = [row["id"] for row in conn.execute(
                "SELECT id FROM findings WHERE tenant_id = ? AND is_current = 1 ORDER BY id LIMIT ?",
                (tenant, args.clicks + 1)).fetchall()]
        timings = []
        for finding_id in ids[:args.clicks]:
            started = time.perf_counter()
            store.update_finding_lifecycle(tenant, finding_id, "comment", {"comment": "bench"}, "bench")
            timings.append((time.perf_counter() - started) * 1000)
        if timings:
            print(f"click (row path), {len(timings)} clicks: median {statistics.median(timings):.1f} ms, "
                  f"max {max(timings):.1f} ms", flush=True)
    finally:
        started = time.perf_counter()
        store.delete_tenant_with_data(tenant)
        print(f"erased tenant in {time.perf_counter() - started:.1f} s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
