"""What the console's aggregates cost while a scan writes (scaling roadmap W4.4).

    python scripts/console_read_bench.py [--files 8000] [--seconds 60] [--no-writer] [--json OUT]

On the disposable sentro_test database only. It fills a tenant with ``--files`` files
through the product's own save (scripts/pg_index_census.py's synthetic estate), then for
``--seconds`` per mode reads what the console reads on every page of the remediation queue,
the inventory and the dashboard - the remediation summary and facets, the inventory facets,
the posture inputs - while a writer thread saves 400-file scans of another label as fast as
it can. Two modes, on the same rows:

- ``counted``: the maintained counts (backend/estate_counts.py, the default since W4.4);
- ``direct``: the aggregates over every row (``DSPM_MAINTAINED_COUNTS=0``), computed fresh
  each time - what each estate change cost before, with the shared cache taken out.

It prints p50, p95 and max per read and per mode, the writer's files/s, and checks that both
modes answer alike when the writes stop. The tenant is erased at the end. Disk: the census's
estimate per file written, twice (the WAL archive), is checked against free space first.
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

WAL_BYTES_PER_FILE = 64 * 1024
FLOOR_BYTES = 2 * 1024 ** 3


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1)))))]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--files", type=int, default=8000)
    parser.add_argument("--seconds", type=float, default=60.0)
    parser.add_argument("--no-writer", action="store_true")
    parser.add_argument("--json", default="")
    args = parser.parse_args()
    url = os.getenv("DSPM_DB_URL", "")
    if not url.endswith("/sentro_test"):
        raise SystemExit("refusing: only the disposable sentro_test database (DSPM_DB_URL)")
    writes = args.files + (0 if args.no_writer else int(args.seconds * 2 * 150))
    free = shutil.disk_usage(Path(ROOT.anchor)).free
    if free - writes * WAL_BYTES_PER_FILE * 2 < FLOOR_BYTES:
        raise SystemExit(f"refusing: about {writes * WAL_BYTES_PER_FILE * 2 // 2 ** 20} MB of WAL and archive "
                         f"would leave less than 2 GB of the {free // 2 ** 20} MB free")

    from backend import db, store
    from scripts.pg_index_census import LABELS, _report

    tenant = f"readbench-{uuid.uuid4().hex[:8]}"
    store.create_tenant(tenant, "console read bench")
    try:
        per_label = max(1, args.files // LABELS)
        started = time.perf_counter()
        for label in range(LABELS):
            store.save_scan_history(tenant, _report(f"rb-{label}", label, label * per_label, per_label,
                                                    f"2026-10-0{1 + label}T00:00:00+00:00", incremental=False))
        seed_seconds = time.perf_counter() - started
        with db.tenant_scope(tenant), store._connect() as conn:
            conn.execute("ANALYZE findings")
            conn.execute("ANALYZE assets")
            findings = int(conn.execute("SELECT COUNT(*) AS n FROM findings WHERE tenant_id = ?",
                                        (tenant,)).fetchone()["n"])

        def reads(mode: str) -> dict:
            with db.tenant_scope(tenant):
                if mode == "counted":
                    return {"summary": lambda: store._counted_remediation_summary(tenant, "current"),
                            "facets": lambda: store._counted_remediation_facets(tenant, "current"),
                            "inventory": lambda: store.inventory_facets(tenant),
                            "posture": lambda: store._counted_posture_inputs(tenant)}
                return {"summary": lambda: store._build_remediation_summary(tenant, "current"),
                        "facets": lambda: store._build_remediation_facets(tenant, "current"),
                        "inventory": lambda: _direct_inventory(store, tenant),
                        "posture": lambda: store._posture_inputs(tenant)}

        stop = threading.Event()
        written = {"files": 0, "seconds": 0.0}

        def writer() -> None:
            batch, round_ = 400, 0
            while not stop.is_set():
                t0 = time.perf_counter()
                store.save_scan_history(tenant, _report(f"rbw-{round_}", 9, 1_000_000 + (round_ % 3) * batch, batch,
                                                        f"2026-10-09T{round_ % 24:02d}:00:00+00:00", incremental=False))
                written["files"] += batch
                written["seconds"] += time.perf_counter() - t0
                round_ += 1

        results: dict = {"files": args.files, "findings": findings, "seed_seconds": round(seed_seconds, 1),
                         "writer": not args.no_writer, "modes": {}}
        for mode in ("counted", "direct"):
            stop.clear()
            thread = None if args.no_writer else threading.Thread(target=writer, daemon=True)
            if thread:
                thread.start()
            latencies: dict[str, list[float]] = {name: [] for name in ("summary", "facets", "inventory", "posture")}
            together: list[float] = []
            deadline = time.perf_counter() + args.seconds
            while time.perf_counter() < deadline:
                group = time.perf_counter()
                for name, read in reads(mode).items():
                    with db.tenant_scope(tenant):
                        t0 = time.perf_counter()
                        read()
                        latencies[name].append((time.perf_counter() - t0) * 1000)
                together.append((time.perf_counter() - group) * 1000)
            stop.set()
            if thread:
                thread.join(120)
            results["modes"][mode] = {
                name: {"n": len(values), "p50_ms": round(statistics.median(values), 1),
                       "p95_ms": round(_percentile(values, 0.95), 1), "max_ms": round(max(values), 1)}
                for name, values in latencies.items()}
            results["modes"][mode]["all_four"] = {"p50_ms": round(statistics.median(together), 1),
                                                  "p95_ms": round(_percentile(together, 0.95), 1),
                                                  "max_ms": round(max(together), 1)}
            results["modes"][mode]["writer_files_per_second"] = (
                round(written["files"] / written["seconds"], 1) if written["seconds"] else 0.0)
            written.update(files=0, seconds=0.0)
        with db.tenant_scope(tenant):
            results["same_answers_after_the_writes"] = (
                store._counted_remediation_summary(tenant, "current") == store._build_remediation_summary(tenant, "current"))
        print(json.dumps(results, indent=1))
        if args.json:
            Path(args.json).write_text(json.dumps(results, indent=1), encoding="utf-8")
    finally:
        store.delete_tenant_with_data(tenant)
    return 0


def _direct_inventory(store, tenant: str) -> dict:
    with store._connect() as conn:
        return store._inventory_facets_from(store._inventory_facet_rows(conn, tenant))


if __name__ == "__main__":
    raise SystemExit(main())
