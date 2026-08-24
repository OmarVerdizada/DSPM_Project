"""Track S database-only 5M-row inventory acceptance harness.

The harness writes only to a uniquely named PostgreSQL table, refuses databases
whose name does not contain `test` or `bench`, and drops the table in
`finally`. It never reads production assets or report evidence.
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


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[
        max(
            0,
            min(
                len(ordered) - 1,
                math.ceil(len(ordered) * percentile) - 1,
            ),
        )
    ]


def _row(index: int) -> tuple:
    tenant_id = "bench-a" if index % 2 == 0 else "bench-b"
    risk_score = (index * 37) % 101

    # Keep the search marker independent of the risk-score modulus so combined
    # risk+substring scenarios have real matches instead of an empty congruence.
    marker = "sentroneedle" if index % 97 == 0 else "ordinary"
    source = ("smb", "endpoint", "local")[index % 3]
    extension = (".txt", ".csv", ".xlsx", ".pdf")[index % 4]
    name = f"{marker}-asset-{index:012d}{extension}"
    path = f"/dept-{index % 64:02d}/{name}"

    return (
        tenant_id,
        f"{index:024x}",
        source,
        extension,
        "CRITICAL" if risk_score >= 90 else ("HIGH" if risk_score >= 70 else "LOW"),
        risk_score,
        1024 + index % 1_000_000,
        1 if marker == "sentroneedle" else 0,
        f"2026-08-{(index % 28) + 1:02d}T00:00:00Z",
        name,
        index % 211 == 0,
        f"{path} {name} owner-{index % 1000:04d} {source} {extension} {marker}".lower(),
    )


def _measure(operation, repeats: int) -> tuple[list[float], int]:
    timings: list[float] = []
    rows = 0
    for _ in range(repeats):
        started = time.perf_counter()
        rows = operation()
        timings.append((time.perf_counter() - started) * 1000)
    return timings, rows


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Certify Track S PostgreSQL inventory p95"
    )
    parser.add_argument("--documents", type=int, default=5_000_000)
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="allow a sub-5M non-certifying smoke run",
    )
    args = parser.parse_args()

    if os.getenv("DSPM_INVENTORY_BENCHMARK_ALLOW_WRITE") != "1":
        parser.error(
            "set DSPM_INVENTORY_BENCHMARK_ALLOW_WRITE=1; "
            "this harness creates disposable data"
        )
    if args.documents < 10_000 or args.repeats < 3:
        parser.error("documents must be >= 10000 and repeats >= 3")

    dsn = os.getenv("DSPM_DB_URL", "").strip()
    if not dsn:
        parser.error("DSPM_DB_URL is required")

    try:
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import conninfo_to_dict
    except ImportError as exc:
        raise SystemExit(
            "install requirements-postgres.txt before running the benchmark"
        ) from exc

    configured_db = str(conninfo_to_dict(dsn).get("dbname") or "")
    if "test" not in configured_db.lower() and "bench" not in configured_db.lower():
        raise SystemExit(
            f"refusing benchmark writes to database {configured_db!r}; "
            "name must contain test or bench"
        )

    # Autocommit is intentional: VACUUM cannot run inside a transaction block.
    conn = psycopg.connect(dsn, autocommit=True)
    live_db = str(conn.info.dbname or "")
    if "test" not in live_db.lower() and "bench" not in live_db.lower():
        conn.close()
        raise SystemExit(
            f"refusing benchmark writes to database {live_db!r}; "
            "name must contain test or bench"
        )

    table_name = f"track_s_bench_{uuid.uuid4().hex[:12]}"
    ingest_seconds = 0.0

    try:
        conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

        conn.execute(
            sql.SQL(
                """
                CREATE TABLE {} (
                    tenant_id TEXT NOT NULL,
                    id TEXT NOT NULL,
                    source TEXT,
                    extension TEXT,
                    risk_level TEXT,
                    risk_score INTEGER NOT NULL,
                    size BIGINT NOT NULL,
                    finding_count INTEGER NOT NULL,
                    modified_at TEXT,
                    name TEXT,
                    is_protected BOOLEAN NOT NULL,
                    search_text TEXT,
                    PRIMARY KEY (tenant_id, id)
                )
                """
            ).format(sql.Identifier(table_name))
        )

        ingest_started = time.perf_counter()

        copy_sql = sql.SQL(
            "COPY {} "
            "(tenant_id,id,source,extension,risk_level,risk_score,size,"
            "finding_count,modified_at,name,is_protected,search_text) "
            "FROM STDIN"
        ).format(sql.Identifier(table_name))

        with conn.cursor().copy(copy_sql) as copy:
            for index in range(args.documents):
                copy.write_row(_row(index))
                if index and index % 1_000_000 == 0:
                    print(
                        f"loaded {index:,}/{args.documents:,} rows",
                        flush=True,
                    )

        # Core keyset indexes plus the filter+sort composites required by the
        # 5M acceptance scenarios.
        indexes = (
            ("risk_id", "(tenant_id, risk_score, id)"),
            ("size_id", "(tenant_id, size, id)"),
            ("finding_id", "(tenant_id, finding_count, id)"),
            ("source", "(tenant_id, source)"),
            ("extension", "(tenant_id, extension)"),
            ("protected", "(tenant_id, is_protected)"),
            (
                "filtered_risk_id",
                "(tenant_id, risk_level, source, extension, risk_score, id)",
            ),
            (
                "protected_risk_id",
                "(tenant_id, is_protected, risk_score, id)",
            ),
            (
                "search_filter_risk_id",
                "(tenant_id, risk_level, source, risk_score, id)",
            ),
        )

        for suffix, definition in indexes:
            conn.execute(
                sql.SQL("CREATE INDEX {} ON {} " + definition).format(
                    sql.Identifier(f"{table_name}_{suffix}"),
                    sql.Identifier(table_name),
                )
            )

        conn.execute(
            sql.SQL(
                "CREATE INDEX {} ON {} USING GIN "
                "((lower(COALESCE(search_text, ''))) gin_trgm_ops)"
            ).format(
                sql.Identifier(f"{table_name}_trgm"),
                sql.Identifier(table_name),
            )
        )

        # Fresh COPY-loaded rows may still trigger heap visibility checks even
        # when PostgreSQL chooses an Index Only Scan. VACUUM marks pages
        # all-visible and ANALYZE refreshes planner statistics before timing.
        conn.execute(
            sql.SQL("VACUUM (ANALYZE) {}").format(
                sql.Identifier(table_name)
            )
        )

        ingest_seconds = time.perf_counter() - ingest_started

        scenarios = {
            "first_page": (
                "tenant_id = %s",
                ("bench-a",),
            ),
            "deep_keyset": (
                "tenant_id = %s AND (risk_score, id) < (%s, %s)",
                ("bench-a", 50, "ffffffffffffffffffffffff"),
            ),
            "filtered": (
                "tenant_id = %s AND risk_level = %s "
                "AND source = %s AND extension = %s",
                ("bench-a", "CRITICAL", "smb", ".txt"),
            ),
            "protected": (
                "tenant_id = %s AND is_protected = %s",
                ("bench-a", True),
            ),
            "filtered_search": (
                "tenant_id = %s AND risk_level = %s AND source = %s "
                "AND lower(COALESCE(search_text, '')) LIKE %s ESCAPE '\\'",
                ("bench-a", "CRITICAL", "smb", "%sentroneedle%"),
            ),
        }

        results: dict[str, dict] = {}
        all_under_target = True

        for name, (predicate, params) in scenarios.items():
            page_sql = sql.SQL(
                "SELECT id FROM {} WHERE "
                + predicate
                + " ORDER BY risk_score DESC, id DESC LIMIT 101"
            ).format(sql.Identifier(table_name))

            count_sql = sql.SQL(
                "SELECT COUNT(*) FROM "
                "(SELECT 1 FROM {} WHERE "
                + predicate
                + " LIMIT 10001) capped"
            ).format(sql.Identifier(table_name))

            def operation(
                page_sql=page_sql,
                count_sql=count_sql,
                params=params,
            ):
                page_rows = conn.execute(page_sql, params).fetchall()
                conn.execute(count_sql, params).fetchone()
                return len(page_rows)

            for _ in range(3):
                operation()

            timings, row_count = _measure(operation, args.repeats)
            p95 = _percentile(timings, 0.95)
            all_under_target = all_under_target and p95 < 300

            page_plan = conn.execute(
                sql.SQL("EXPLAIN " + page_sql.as_string(conn)),
                params,
            ).fetchall()

            count_plan = conn.execute(
                sql.SQL("EXPLAIN " + count_sql.as_string(conn)),
                params,
            ).fetchall()

            results[name] = {
                "rows": row_count,
                "p50_ms": round(statistics.median(timings), 3),
                "p95_ms": round(p95, 3),
                "max_ms": round(max(timings), 3),
                "under_300ms": p95 < 300,
                "plan": [str(row[0]) for row in page_plan],
                "count_plan": [str(row[0]) for row in count_plan],
            }

        result = {
            "track": "S-C.1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "database": "postgresql",
            "mode": "smoke" if args.smoke else "certification",
            "documents": args.documents,
            "tenant_documents": (args.documents + 1) // 2,
            "repeats": args.repeats,
            "ingest_and_index_seconds": round(ingest_seconds, 3),
            "scenarios": results,
            "gates": {
                "all_inventory_p95_under_300ms": all_under_target,
                "five_million_rows": args.documents >= 5_000_000,
            },
        }

        rendered = json.dumps(result, ensure_ascii=False, indent=2)
        print(rendered)

        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")

        return (
            0
            if all(result["gates"].values())
            or (args.smoke and all_under_target)
            else 2
        )

    finally:
        try:
            conn.execute(
                sql.SQL("DROP TABLE IF EXISTS {}").format(
                    sql.Identifier(table_name)
                )
            )
        finally:
            conn.close()


if __name__ == "__main__":
    raise SystemExit(main())