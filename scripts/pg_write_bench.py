"""PostgreSQL write cost of one scan save and of one finding click, on the disposable
sentro_test database only (scaling roadmap W1.4).

    python scripts/pg_write_bench.py FILES FINDINGS_PER_FILE [--clicks N]

Saves a synthetic report twice (a first scan, then an unchanged rescan), then times N
lifecycle clicks through the row path and one through the report re-save that preceded
it. Prints wall time, files/s, peak RSS growth and row counts; erases its tenant at the end.

Every run writes WAL: on a cluster with archive_mode on, budget ~60 MB per 1,000 files.
BENCH_ANALYZE_BEFORE_PRUNE=1 refreshes statistics inside the save before the prune, to
compare against a plan that has them.
"""
from __future__ import annotations

import argparse
import os
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


def measured(label: str, files: int, fn) -> float:
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
    print(f"{label}: {elapsed:.1f} s, {files / elapsed:.0f} files/s, peak RSS +{(peak[0] - base) / 1048576:.0f} MiB",
          flush=True)
    return elapsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("files", type=int)
    parser.add_argument("per_file", type=int)
    parser.add_argument("--clicks", type=int, default=20)
    args = parser.parse_args()
    if not os.environ.get("DSPM_DB_URL", "").endswith("@127.0.0.1:5442/sentro_test"):
        print("refusing: DSPM_DB_URL must name the disposable sentro_test database", file=sys.stderr)
        return 2

    from backend import db, store

    if os.environ.get("BENCH_ANALYZE_BEFORE_PRUNE") == "1":
        real_prune = store._prune_unseen_assets

        def prune_with_stats(conn, *rest):
            conn.execute("ANALYZE assets")
            conn.execute("ANALYZE findings")
            return real_prune(conn, *rest)

        store._prune_unseen_assets = prune_with_stats

    tenant = f"bench-{uuid.uuid4().hex[:6]}"
    store.create_tenant(tenant, "bench")
    try:
        for label, scan_id in (("first save", "bench-1"), ("unchanged rescan save", "bench-2")):
            body = report(scan_id, args.files, args.per_file)
            measured(label, args.files, lambda body=body: store.save_scan_history(tenant, body))
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
        print(f"click (row path), {len(timings)} clicks: median {statistics.median(timings):.1f} ms, "
              f"max {max(timings):.1f} ms", flush=True)
        started = time.perf_counter()
        store._update_finding_lifecycle_in_report(tenant, ids[-1], "comment", {"comment": "bench"}, "bench")
        print(f"click (report re-save, the pre-W1.4 path): {(time.perf_counter() - started) * 1000:.0f} ms", flush=True)
    finally:
        started = time.perf_counter()
        store.delete_tenant_with_data(tenant)
        print(f"erased tenant in {time.perf_counter() - started:.1f} s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
