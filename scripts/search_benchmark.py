"""S-F.2 disposable PostgreSQL pg_trgm vs Meilisearch certification harness.

The harness refuses to run unless the database name contains ``test`` or
``bench`` and DSPM_SEARCH_BENCHMARK_ALLOW_WRITE=1. It creates unique temporary
PostgreSQL table and Meilisearch index names and removes both in ``finally``.
No report evidence or production assets are read.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from backend.search import MeilisearchClient, SearchConfig, asset_document


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, math.ceil(len(ordered) * percentile) - 1))]


def _asset(index: int) -> dict:
    tenant = "bench-a" if index % 2 == 0 else "bench-b"
    marker = "sentroneedle" if index % 101 == 0 else "ordinary"
    department = f"dept-{index % 64:02d}"
    name = f"{marker}-{department}-{index:09d}.txt"
    path = f"/{department}/{name}"
    risk_score = (index * 37) % 101
    return {
        "id": f"asset-{index:012d}",
        "tenant_id": tenant,
        "source": "smb",
        "path": path,
        "name": name,
        "extension": ".txt",
        "share": department,
        "risk_level": "CRITICAL" if risk_score >= 90 else ("HIGH" if risk_score >= 70 else "LOW"),
        "risk_score": risk_score,
        "size": 1024 + index % 1_000_000,
        "owner": f"owner-{index % 1000:04d}",
        "modified_at": "2026-08-05T00:00:00Z",
        "finding_count": 1 if marker == "sentroneedle" else 0,
        "top_frameworks": "GDPR" if marker == "sentroneedle" else "",
        "is_hidden": False,
        "is_system": False,
        "is_protected": index % 211 == 0,
        "finding_types": '["Access Token"]' if marker == "sentroneedle" else "[]",
        "framework_keys": '["gdpr"]' if marker == "sentroneedle" else "[]",
        "search_text": f"{path} {name} owner-{index % 1000:04d} .txt".lower(),
    }


def _measure(operation, repeats: int) -> tuple[list[float], object]:
    timings: list[float] = []
    result = None
    for _ in range(repeats):
        started = time.perf_counter()
        result = operation()
        timings.append((time.perf_counter() - started) * 1000)
    return timings, result


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark pg_trgm and Meilisearch on a disposable corpus")
    parser.add_argument("--documents", type=int, default=1_000_000)
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=5_000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if os.getenv("DSPM_SEARCH_BENCHMARK_ALLOW_WRITE") != "1":
        parser.error("set DSPM_SEARCH_BENCHMARK_ALLOW_WRITE=1; this harness creates disposable data")
    if args.documents < 10_000 or args.repeats < 3:
        parser.error("documents must be >= 10000 and repeats >= 3")

    dsn = os.getenv("DSPM_DB_URL", "")
    search_url = os.getenv("DSPM_MEILISEARCH_URL", "").rstrip("/")
    if not dsn or not search_url:
        parser.error("DSPM_DB_URL and DSPM_MEILISEARCH_URL are required")
    try:
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import conninfo_to_dict
    except ImportError as exc:
        raise SystemExit("install requirements-postgres.txt before running the benchmark") from exc

    suffix = uuid.uuid4().hex[:12]
    table_name = f"sf_bench_{suffix}"
    index_uid = f"sentro_sf_bench_{suffix}"
    client = MeilisearchClient(SearchConfig(
        engine="meilisearch",
        url=search_url,
        api_key=os.getenv("DSPM_MEILISEARCH_API_KEY", ""),
        index_uid=index_uid,
        timeout_seconds=30,
        batch_size=args.batch_size,
        reconcile_interval_seconds=0,
    ))
    target_db = str(conninfo_to_dict(dsn).get("dbname") or "")
    if "test" not in target_db.lower() and "bench" not in target_db.lower():
        raise SystemExit(f"refusing benchmark writes to database {target_db!r}; name must contain test or bench")
    conn = psycopg.connect(dsn, autocommit=True)
    db_name = conn.info.dbname or ""
    if "test" not in db_name.lower() and "bench" not in db_name.lower():
        conn.close()
        raise SystemExit(f"refusing benchmark writes to database {db_name!r}; name must contain test or bench")

    ingest_started = time.perf_counter()
    pg_ingest_seconds = meili_ingest_seconds = 0.0
    try:
        conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
        conn.execute(sql.SQL("""
            CREATE TABLE {} (
                tenant_id TEXT NOT NULL, id TEXT NOT NULL PRIMARY KEY, search_text TEXT NOT NULL,
                risk_score INTEGER NOT NULL, source TEXT, extension TEXT, is_protected BOOLEAN
            )
        """).format(sql.Identifier(table_name)))
        pg_started = time.perf_counter()
        copy_sql = sql.SQL(
            "COPY {} (tenant_id,id,search_text,risk_score,source,extension,is_protected) FROM STDIN"
        ).format(sql.Identifier(table_name))
        with conn.cursor().copy(copy_sql) as copy:
            for index in range(args.documents):
                asset = _asset(index)
                copy.write_row((
                    asset["tenant_id"], asset["id"], asset["search_text"], asset["risk_score"],
                    asset["source"], asset["extension"], asset["is_protected"],
                ))
        conn.execute(sql.SQL(
            "CREATE INDEX {} ON {} USING GIN ((lower(COALESCE(search_text, ''))) gin_trgm_ops)"
        ).format(sql.Identifier(f"{table_name}_trgm"), sql.Identifier(table_name)))
        conn.execute(sql.SQL(
            "CREATE INDEX {} ON {} (tenant_id, risk_score, id)"
        ).format(sql.Identifier(f"{table_name}_risk_id"), sql.Identifier(table_name)))
        conn.execute(sql.SQL("ANALYZE {}").format(sql.Identifier(table_name)))
        pg_ingest_seconds = time.perf_counter() - pg_started

        meili_started = time.perf_counter()
        batch: list[dict] = []
        for index in range(args.documents):
            batch.append(asset_document(_asset(index)))
            if len(batch) >= args.batch_size:
                client.add_documents(batch, wait=True)
                batch = []
        if batch:
            client.add_documents(batch, wait=True)
        meili_ingest_seconds = time.perf_counter() - meili_started

        pg_query = sql.SQL(
            "SELECT id FROM {} WHERE tenant_id = %s AND lower(COALESCE(search_text, '')) LIKE %s "
            "ORDER BY risk_score DESC, id DESC LIMIT 100"
        ).format(sql.Identifier(table_name))

        def query_pg():
            return [row[0] for row in conn.execute(pg_query, ("bench-a", "%sentroneedle%")).fetchall()]

        def query_meili(term: str = "sentroneedle"):
            page = client.search(
                "bench-a",
                {"q": term, "source": "", "extension": "", "protected": None,
                 "finding_type": "", "frameworks": [], "risk": ""},
                "risk_score", "DESC", "", 100,
            )
            return [item["id"] for item in page["items"]]

        for _ in range(3):
            query_pg()
            query_meili()
        pg_times, pg_ids = _measure(query_pg, args.repeats)
        meili_times, meili_ids = _measure(query_meili, args.repeats)
        typo_ids = query_meili("sentronedle")
        cross_tenant = client.search(
            "tenant-that-does-not-exist",
            {"q": "sentroneedle", "source": "", "extension": "", "protected": None,
             "finding_type": "", "frameworks": [], "risk": ""},
            "risk_score", "DESC", "", 10,
        )["items"]
        pg_p95 = _percentile(pg_times, 0.95)
        meili_p95 = _percentile(meili_times, 0.95)
        parity = pg_ids == meili_ids
        gates = {
            "top_100_exact_parity": parity,
            "tenant_isolation": not cross_tenant,
            "typo_tolerance": bool(typo_ids),
            "postgres_p95_under_300ms": pg_p95 < 300,
            "meilisearch_p95_under_300ms": meili_p95 < 300,
        }
        result = {
            "track": "S-F.2",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "database": "postgresql",
            "documents": args.documents,
            "tenant_documents": args.documents // 2,
            "query_repeats": args.repeats,
            "corpus_build_seconds": round(time.perf_counter() - ingest_started, 3),
            "postgres_ingest_and_index_seconds": round(pg_ingest_seconds, 3),
            "meilisearch_ingest_and_index_seconds": round(meili_ingest_seconds, 3),
            "postgres_latency_ms": {
                "p50": round(statistics.median(pg_times), 3),
                "p95": round(pg_p95, 3),
                "max": round(max(pg_times), 3),
            },
            "meilisearch_latency_ms": {
                "p50": round(statistics.median(meili_times), 3),
                "p95": round(meili_p95, 3),
                "max": round(max(meili_times), 3),
            },
            "gates": gates,
            "decision": {
                "retain_as_optional_valve": all(gates.values()),
                "reason": "Retain only when parity, isolation, typo tolerance, and both p95 gates pass.",
            },
        }
        rendered = json.dumps(result, ensure_ascii=False, indent=2)
        print(rendered)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
        return 0 if all(gates.values()) else 2
    finally:
        try:
            client.delete_index(wait=True)
        except Exception:
            pass
        client.close()
        try:
            conn.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(sql.Identifier(table_name)))
        finally:
            conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
